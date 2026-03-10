// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "nullsend.h"
#include "main.h"
#include "init.h"
#include "txdb.h"
#include "wallet.h"
#include "net.h"
#include "util.h"
#include "shielded.h"
#include "zkproof.h"
#include "lelantus.h"
#include "curvetree.h"

#include <algorithm>

#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

CNullSendPool nullSendPool;
CNullSendClient nullSendClient;
CCriticalSection cs_nullsend;
std::vector<CNullSendQueue> vecNullSendQueue;


void CNullSendSession::SetState(int newState)
{
    if (fDebug)
        printf("NullSend session %d: state %d -> %d\n", nSessionID, nState, newState);
    nState = newState;
    nStateChangeTime = GetTime();
}

bool CNullSendSession::AcceptEntry(const CNullSendEntry& entry, CNode* pfrom)
{
    if (nState != NULLSEND_STATE_ACCEPTING)
        return false;

    if ((int)vParticipants.size() >= nTargetParticipants)
        return false;

    if (entry.vMySpends.empty() || entry.vMyOutputs.empty())
        return false;

    if (entry.vMySpends.size() > 100 || entry.vMyOutputs.size() > 100)
        return false;

    if (!MoneyRange(entry.nMyValueBalance))
        return false;

    CNullSendParticipant participant;
    participant.nID = (int)vParticipants.size();
    participant.pnode = pfrom;
    participant.entry = entry;
    participant.nLastActivity = GetTime();
    vParticipants.push_back(participant);

    if (fDebug)
        printf("NullSend session %d: accepted participant %d (%d/%d)\n",
               nSessionID, participant.nID, (int)vParticipants.size(), nTargetParticipants);

    if (pfrom)
    {
        CNullSendAccept accept;
        accept.nSessionID = nSessionID;
        accept.nStatusCode = NULLSEND_ACCEPTED;
        accept.nParticipantID = participant.nID;
        accept.strMessage = "Accepted";
        pfrom->PushMessage("znsa", accept);
    }

    if ((int)vParticipants.size() >= nTargetParticipants)
    {
        SetState(NULLSEND_STATE_NONCE_COMMIT);
    }

    return true;
}

bool CNullSendSession::AllNoncesCommitted() const
{
    for (const CNullSendParticipant& p : vParticipants)
    {
        if (!p.fNonceCommitted)
            return false;
    }
    return true;
}

bool CNullSendSession::AllPartialSigsReceived() const
{
    for (const CNullSendParticipant& p : vParticipants)
    {
        if (!p.fPartialSigReceived)
            return false;
    }
    return true;
}

bool CNullSendSession::ProcessNonceCommit(int nParticipantID, const uint256& commitment)
{
    if (nState != NULLSEND_STATE_NONCE_COMMIT)
        return false;

    if (nParticipantID < 0 || nParticipantID >= (int)vParticipants.size())
        return false;

    CNullSendParticipant& p = vParticipants[nParticipantID];
    if (p.fNonceCommitted)
        return false;

    p.nonceCommitment = commitment;
    p.fNonceCommitted = true;
    p.nLastActivity = GetTime();

    if (fDebug)
        printf("NullSend session %d: nonce commit from participant %d\n", nSessionID, nParticipantID);

    if (AllNoncesCommitted())
    {
        bool fAssembled = fChaumian ? AssembleTransactionChaumian() : AssembleTransaction();
        if (!fAssembled)
        {
            Reset("Failed to assemble transaction");
            return false;
        }
        BroadcastChallenge();
        SetState(NULLSEND_STATE_PARTIAL_SIG);
    }

    return true;
}

bool CNullSendSession::AssembleTransaction()
{
    CTransaction txNew;

    bool fUseFCMP = (nBestHeight >= FORK_HEIGHT_FCMP_VALIDATION);
    txNew.nVersion = fUseFCMP ? SHIELDED_TX_VERSION_FCMP : SHIELDED_TX_VERSION_DSP;
    txNew.nTime = GetTime();
    txNew.nPrivacyMode = nPrivacyMode;

    int nSpendIdx = 0;
    int nOutputIdx = 0;
    int64_t nTotalValueBalance = 0;

    for (CNullSendParticipant& p : vParticipants)
    {
        p.nSpendOffset = nSpendIdx;
        for (const CShieldedSpendDescription& spend : p.entry.vMySpends)
        {
            txNew.vShieldedSpend.push_back(spend);
            nSpendIdx++;
        }

        p.nOutputOffset = nOutputIdx;
        for (const CShieldedOutputDescription& output : p.entry.vMyOutputs)
        {
            txNew.vShieldedOutput.push_back(output);
            nOutputIdx++;
        }

        if (!MoneyRange(p.entry.nMyValueBalance))
            return false;
        nTotalValueBalance += p.entry.nMyValueBalance;
        if (!MoneyRange(nTotalValueBalance))
            return false;
    }

    txNew.nValueBalance = nTotalValueBalance;

    std::vector<int> spendMap(txNew.vShieldedSpend.size());
    std::vector<int> outputMap(txNew.vShieldedOutput.size());
    for (size_t i = 0; i < spendMap.size(); i++) spendMap[i] = (int)i;
    for (size_t i = 0; i < outputMap.size(); i++) outputMap[i] = (int)i;

    for (size_t i = spendMap.size(); i > 1; i--)
        std::swap(spendMap[i-1], spendMap[GetRand((uint32_t)i)]);
    for (size_t i = outputMap.size(); i > 1; i--)
        std::swap(outputMap[i-1], outputMap[GetRand((uint32_t)i)]);

    std::vector<CShieldedSpendDescription> shuffledSpends(txNew.vShieldedSpend.size());
    for (size_t i = 0; i < spendMap.size(); i++)
        shuffledSpends[i] = txNew.vShieldedSpend[spendMap[i]];
    txNew.vShieldedSpend = shuffledSpends;

    std::vector<CShieldedOutputDescription> shuffledOutputs(txNew.vShieldedOutput.size());
    for (size_t i = 0; i < outputMap.size(); i++)
        shuffledOutputs[i] = txNew.vShieldedOutput[outputMap[i]];
    txNew.vShieldedOutput = shuffledOutputs;

    std::vector<int> spendRevMap(spendMap.size());
    std::vector<int> outputRevMap(outputMap.size());
    for (size_t i = 0; i < spendMap.size(); i++) spendRevMap[spendMap[i]] = (int)i;
    for (size_t i = 0; i < outputMap.size(); i++) outputRevMap[outputMap[i]] = (int)i;

    for (CNullSendParticipant& p : vParticipants)
    {
        int nOrigOffset = p.nSpendOffset;
        int nCount = (int)p.entry.vMySpends.size();
        if (nCount > 0)
            p.nSpendOffset = spendRevMap[nOrigOffset];

        nOrigOffset = p.nOutputOffset;
        nCount = (int)p.entry.vMyOutputs.size();
        if (nCount > 0)
            p.nOutputOffset = outputRevMap[nOrigOffset];
    }

    unsignedTx = txNew;
    sighash = txNew.GetBindingSigHash();

    return true;
}

void CNullSendSession::BroadcastChallenge()
{
    std::vector<std::vector<unsigned char>> vNoncePoints;
    for (const CNullSendParticipant& p : vParticipants)
    {
        uint256 expectedCommit = ComputeNonceCommitment(p.vchNoncePoint);
        if (expectedCommit != p.nonceCommitment)
        {
            Reset("Nonce commitment mismatch");
            return;
        }
        vNoncePoints.push_back(p.vchNoncePoint);
    }

    if (!AggregateNoncePoints(vNoncePoints, vchAggregateNonce))
    {
        Reset("Failed to aggregate nonce points");
        return;
    }

    std::vector<CPedersenCommitment> vInputCommits;
    std::vector<CPedersenCommitment> vOutputCommits;
    for (const CShieldedSpendDescription& spend : unsignedTx.vShieldedSpend)
        vInputCommits.push_back(spend.cv);
    for (const CShieldedOutputDescription& output : unsignedTx.vShieldedOutput)
        vOutputCommits.push_back(output.cv);

    if (!ComputeMuSigChallenge(vchAggregateNonce, vInputCommits, vOutputCommits,
                                unsignedTx.nValueBalance, sighash, vchChallenge))
    {
        Reset("Failed to compute challenge");
        return;
    }

    CNullSendChallenge challenge;
    challenge.nSessionID = nSessionID;
    challenge.vchAggregateNonce = vchAggregateNonce;
    challenge.vchChallenge = vchChallenge;
    challenge.vNoncePoints = vNoncePoints;
    challenge.unsignedTx = unsignedTx;
    challenge.sighash = sighash;

    for (const CNullSendParticipant& p : vParticipants)
    {
        if (p.pnode)
            p.pnode->PushMessage("znsch", challenge);
    }

    if (fDebug)
        printf("NullSend session %d: broadcast challenge to %d participants\n",
               nSessionID, (int)vParticipants.size());
}

bool CNullSendSession::ProcessPartialSig(int nParticipantID, const CNullSendPartialSig& msg)
{
    if (nState != NULLSEND_STATE_PARTIAL_SIG)
        return false;

    if (nParticipantID < 0 || nParticipantID >= (int)vParticipants.size())
        return false;

    CNullSendParticipant& p = vParticipants[nParticipantID];
    if (p.fPartialSigReceived)
        return false;

    if (msg.vchPartialSig.size() != 32)
        return false;

    p.vchPartialSig = msg.vchPartialSig;
    p.vSpendAuthSigs = msg.vSpendAuthSigs;
    p.vSpendRks = msg.vSpendRks;
    p.fPartialSigReceived = true;
    p.nLastActivity = GetTime();

    if (fDebug)
        printf("NullSend session %d: partial sig from participant %d\n", nSessionID, nParticipantID);

    if (AllPartialSigsReceived())
    {
        if (!FinalizeTransaction())
        {
            Reset("Failed to finalize transaction");
            return false;
        }
        BroadcastFinalTx();
        SetState(NULLSEND_STATE_SUCCESS);
    }

    return true;
}

bool CNullSendSession::FinalizeTransaction()
{
    std::vector<std::vector<unsigned char>> vPartialSigs;
    for (const CNullSendParticipant& p : vParticipants)
        vPartialSigs.push_back(p.vchPartialSig);

    std::vector<unsigned char> vchAggSig;
    if (!AggregatePartialSigs(vPartialSigs, vchAggSig))
        return false;

    CBindingSignature aggBindingSig;
    if (!AssembleBindingSignature(vchAggregateNonce, vchAggSig, aggBindingSig))
        return false;

    finalTx = unsignedTx;
    finalTx.bindingSig.bindingSig = aggBindingSig;

    for (const CNullSendParticipant& p : vParticipants)
    {
            const std::vector<CShieldedSpendDescription>& vSpends =
            fChaumian ? p.inputReg.vMySpends : p.entry.vMySpends;

        if (p.vSpendAuthSigs.size() != vSpends.size())
            return false;
        if (p.vSpendRks.size() != vSpends.size())
            return false;

        for (size_t i = 0; i < vSpends.size(); i++)
        {
            if (p.vSpendAuthSigs[i].size() != 64 || p.vSpendRks[i].size() != 33)
                return false;

            uint256 myNullifier = vSpends[i].nullifier;
            for (size_t j = 0; j < finalTx.vShieldedSpend.size(); j++)
            {
                if (finalTx.vShieldedSpend[j].nullifier == myNullifier)
                {
                    finalTx.vShieldedSpend[j].vchSpendAuthSig = p.vSpendAuthSigs[i];
                    finalTx.vShieldedSpend[j].vchRk = p.vSpendRks[i];
                    break;
                }
            }
        }
    }

    std::vector<CPedersenCommitment> vInputCommits;
    std::vector<CPedersenCommitment> vOutputCommits;
    for (const CShieldedSpendDescription& spend : finalTx.vShieldedSpend)
        vInputCommits.push_back(spend.cv);
    for (const CShieldedOutputDescription& output : finalTx.vShieldedOutput)
        vOutputCommits.push_back(output.cv);

    uint256 verifySighash = finalTx.GetBindingSigHash();
    if (!VerifyBindingSignature(vInputCommits, vOutputCommits, finalTx.nValueBalance,
                                 verifySighash, finalTx.bindingSig.bindingSig))
    {
        printf("NullSend session %d: binding signature verification FAILED\n", nSessionID);
        return false;
    }

    if (fDebug)
        printf("NullSend session %d: binding signature verified OK\n", nSessionID);

    return true;
}

void CNullSendSession::BroadcastFinalTx()
{
    CNullSendBroadcastTx broadcastMsg;
    broadcastMsg.nSessionID = nSessionID;
    broadcastMsg.tx = finalTx;

    for (const CNullSendParticipant& p : vParticipants)
    {
        if (p.pnode)
            p.pnode->PushMessage("znstx", broadcastMsg);
    }

    {
        CTxDB txdb("r");
        if (finalTx.AcceptToMemoryPool(txdb, true))
        {
            uint256 hash = finalTx.GetHash();
            RelayTransaction(finalTx, hash);
            if (fDebug)
                printf("NullSend session %d: transaction %s broadcast to network\n",
                       nSessionID, hash.ToString().c_str());
        }
        else
        {
            printf("NullSend session %d: transaction REJECTED by mempool\n", nSessionID);
        }
    }
}

void CNullSendSession::Reset(const std::string& strReason)
{
    if (fDebug)
        printf("NullSend session %d: RESET - %s\n", nSessionID, strReason.c_str());

    CNullSendAccept resetMsg;
    resetMsg.nSessionID = nSessionID;
    resetMsg.nStatusCode = NULLSEND_RESET;
    resetMsg.strMessage = strReason;

    for (const CNullSendParticipant& p : vParticipants)
    {
        if (p.pnode)
            p.pnode->PushMessage("znsa", resetMsg);
    }

    SetState(NULLSEND_STATE_ERROR);
}

bool CNullSendSession::CheckTimeout()
{
    int64_t nNow = GetTime();

    if (nState == NULLSEND_STATE_ACCEPTING && (nNow - nStartTime) > NULLSEND_QUEUE_TIMEOUT)
    {
        if ((int)vParticipants.size() >= NULLSEND_MIN_PARTICIPANTS)
        {
            nTargetParticipants = (int)vParticipants.size();
            SetState(NULLSEND_STATE_NONCE_COMMIT);
            return true;
        }
        Reset("Timeout waiting for participants");
        return false;
    }

    if (nState == NULLSEND_STATE_INPUT_REG && (nNow - nStartTime) > NULLSEND_QUEUE_TIMEOUT)
    {
        if ((int)vParticipants.size() >= NULLSEND_MIN_PARTICIPANTS)
        {
            nTargetParticipants = (int)vParticipants.size();
            SetState(NULLSEND_STATE_OUTPUT_REG);
            return true;
        }
        Reset("Timeout waiting for input registrations");
        return false;
    }

    if (nState == NULLSEND_STATE_OUTPUT_REG && (nNow - nStateChangeTime) > NULLSEND_OUTPUT_REG_TIMEOUT)
    {
        if ((int)vAnonymousOutputs.size() >= (int)vParticipants.size())
        {
            SetState(NULLSEND_STATE_NONCE_COMMIT);
            return true;
        }
        Reset("Timeout waiting for output registrations");
        return false;
    }

    if (nState == NULLSEND_STATE_NONCE_COMMIT && (nNow - nStateChangeTime) > NULLSEND_ROUND_TIMEOUT)
    {
        Reset("Timeout waiting for nonce commits");
        return false;
    }

    if (nState == NULLSEND_STATE_PARTIAL_SIG && (nNow - nStateChangeTime) > NULLSEND_ROUND_TIMEOUT)
    {
        Reset("Timeout waiting for partial signatures");
        return false;
    }

    return true;
}


static std::vector<unsigned char> NS_BNToVec(const BIGNUM* bn, int nPadLen = 0)
{
    int nLen = BN_num_bytes(bn);
    int nOutLen = (nPadLen > 0 && nLen <= nPadLen) ? nPadLen : nLen;
    std::vector<unsigned char> vch(nOutLen, 0);
    BN_bn2bin(bn, vch.data() + (nOutLen - nLen));
    return vch;
}

static BIGNUM* NS_VecToBN(const std::vector<unsigned char>& vch)
{
    return BN_bin2bn(vch.data(), (int)vch.size(), NULL);
}

bool CNullSendSession::GenerateSessionRSAKey()
{
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();
    BIGNUM* n = BN_new();
    BIGNUM* e = BN_new();
    BIGNUM* d = BN_new();
    BIGNUM* phi = BN_new();
    BIGNUM* p1 = BN_new();
    BIGNUM* q1 = BN_new();

    if (!ctx || !p || !q || !n || !e || !d || !phi || !p1 || !q1)
    {
        BN_CTX_free(ctx); BN_free(p); BN_free(q); BN_free(n);
        BN_free(e); BN_free(d); BN_free(phi); BN_free(p1); BN_free(q1);
        return false;
    }

    bool fOk = false;

    if (!BN_generate_prime_ex(p, NULLSEND_RSA_BITS / 2, 0, NULL, NULL, NULL))
        goto ns_rsa_cleanup;
    if (!BN_generate_prime_ex(q, NULLSEND_RSA_BITS / 2, 0, NULL, NULL, NULL))
        goto ns_rsa_cleanup;
    if (BN_cmp(p, q) == 0)
        goto ns_rsa_cleanup;
    if (!BN_mul(n, p, q, ctx))
        goto ns_rsa_cleanup;
    if (!BN_set_word(e, 65537))
        goto ns_rsa_cleanup;
    if (!BN_sub(p1, p, BN_value_one()))
        goto ns_rsa_cleanup;
    if (!BN_sub(q1, q, BN_value_one()))
        goto ns_rsa_cleanup;
    if (!BN_mul(phi, p1, q1, ctx))
        goto ns_rsa_cleanup;
    if (!BN_mod_inverse(d, e, phi, ctx))
        goto ns_rsa_cleanup;

    {
        int nKeyBytes = NULLSEND_RSA_BITS / 8;
        vchRSA_N = NS_BNToVec(n, nKeyBytes);
        vchRSA_E = NS_BNToVec(e);
        vchRSA_D = NS_BNToVec(d, nKeyBytes);
    }

    fOk = true;

ns_rsa_cleanup:
    BN_clear_free(p);
    BN_clear_free(q);
    BN_clear_free(d);
    BN_clear_free(phi);
    BN_clear_free(p1);
    BN_clear_free(q1);
    BN_free(n);
    BN_free(e);
    BN_CTX_free(ctx);

    if (fOk && fDebug)
        printf("NullSend session %d: RSA-%d key generated\n", nSessionID, NULLSEND_RSA_BITS);

    return fOk;
}

bool CNullSendSession::BlindSign(const std::vector<unsigned char>& vchBlinded,
                                  std::vector<unsigned char>& vchSignatureOut)
{
    if (vchRSA_D.empty() || vchRSA_N.empty())
        return false;

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* m = NS_VecToBN(vchBlinded);
    BIGNUM* d_bn = NS_VecToBN(vchRSA_D);
    BIGNUM* n_bn = NS_VecToBN(vchRSA_N);
    BIGNUM* s = BN_new();

    if (!ctx || !m || !d_bn || !n_bn || !s)
    {
        BN_CTX_free(ctx); BN_free(m); BN_clear_free(d_bn); BN_free(n_bn); BN_free(s);
        return false;
    }

    bool fOk = BN_mod_exp_mont_consttime(s, m, d_bn, n_bn, ctx, NULL) == 1;

    if (fOk)
        vchSignatureOut = NS_BNToVec(s, NULLSEND_RSA_BITS / 8);

    BN_free(m);
    BN_clear_free(d_bn);
    BN_free(n_bn);
    BN_free(s);
    BN_CTX_free(ctx);

    return fOk;
}

bool CNullSendSession::VerifyCredential(const std::vector<unsigned char>& vchCredential,
                                         const std::vector<unsigned char>& vchSignature)
{
    if (vchRSA_N.empty() || vchRSA_E.empty())
        return false;

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* s_bn = NS_VecToBN(vchSignature);
    BIGNUM* e_bn = NS_VecToBN(vchRSA_E);
    BIGNUM* n_bn = NS_VecToBN(vchRSA_N);
    BIGNUM* result = BN_new();

    if (!ctx || !s_bn || !e_bn || !n_bn || !result)
    {
        BN_CTX_free(ctx); BN_free(s_bn); BN_free(e_bn); BN_free(n_bn); BN_free(result);
        return false;
    }

    bool fOk = BN_mod_exp(result, s_bn, e_bn, n_bn, ctx) == 1;

    if (fOk)
    {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(vchCredential.data(), vchCredential.size(), hash);

        BIGNUM* expected = BN_bin2bn(hash, SHA256_DIGEST_LENGTH, NULL);
        BIGNUM* expected_mod = BN_new();
        if (expected && expected_mod)
        {
            BN_mod(expected_mod, expected, n_bn, ctx);
            fOk = (BN_cmp(result, expected_mod) == 0);
        }
        else
        {
            fOk = false;
        }
        BN_free(expected);
        BN_free(expected_mod);
    }

    BN_free(s_bn);
    BN_free(e_bn);
    BN_free(n_bn);
    BN_free(result);
    BN_CTX_free(ctx);

    return fOk;
}

bool CNullSendSession::AcceptInputReg(const CNullSendInputReg& reg, CNode* pfrom)
{
    if (nState != NULLSEND_STATE_INPUT_REG)
        return false;

    if ((int)vParticipants.size() >= nTargetParticipants)
        return false;

    if (reg.vMySpends.empty())
        return false;

    if (reg.nMyInputValue <= 0 || reg.nMyInputValue > MAX_MONEY)
        return false;

    if (reg.vchBlindedCredential.empty() || (int)reg.vchBlindedCredential.size() > NULLSEND_RSA_BITS / 8)
        return false;

    if (reg.vMySpends.size() > 100)
        return false;

    if (reg.vBlindedNullifiers.size() != reg.vMySpends.size())
        return false;

    for (size_t i = 0; i < reg.vMySpends.size(); i++)
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << reg.vMySpends[i].nullifier;
        ss << sessionNonce;
        uint256 expectedBlinded = ss.GetHash();
        if (expectedBlinded != reg.vBlindedNullifiers[i])
            return false;
    }

    for (const CShieldedSpendDescription& newSpend : reg.vMySpends)
    {
        for (const CNullSendParticipant& p : vParticipants)
        {
            for (const CShieldedSpendDescription& existingSpend : p.inputReg.vMySpends)
            {
                if (newSpend.nullifier == existingSpend.nullifier)
                    return false;
            }
        }
    }

    std::vector<unsigned char> vchBlindSig;
    if (!BlindSign(reg.vchBlindedCredential, vchBlindSig))
    {
        printf("NullSend session %d: blind sign failed\n", nSessionID);
        return false;
    }

    CNullSendParticipant participant;
    participant.nID = (int)vParticipants.size();
    participant.pnode = pfrom;
    participant.inputReg = reg;
    participant.nLastActivity = GetTime();
    vParticipants.push_back(participant);

    if (pfrom)
    {
        CNullSendInputAccept accept;
        accept.nSessionID = nSessionID;
        accept.nStatusCode = NULLSEND_ACCEPTED;
        accept.nParticipantID = participant.nID;
        accept.vchBlindSignature = vchBlindSig;
        accept.vchRSA_N = vchRSA_N;
        accept.vchRSA_E = vchRSA_E;
        accept.strMessage = "Input accepted";
        pfrom->PushMessage("znsia", accept);
    }

    if (fDebug)
        printf("NullSend session %d: accepted input reg from participant %d (%d/%d)\n",
               nSessionID, participant.nID, (int)vParticipants.size(), nTargetParticipants);

    if ((int)vParticipants.size() >= nTargetParticipants)
    {
        SetState(NULLSEND_STATE_OUTPUT_REG);
    }

    return true;
}

bool CNullSendSession::AcceptOutputReg(const CNullSendOutputReg& reg)
{
    if (nState != NULLSEND_STATE_OUTPUT_REG)
        return false;

    if ((int)vAnonymousOutputs.size() >= nTargetParticipants)
        return false;

    if (reg.vMyOutputs.empty() || reg.vMyOutputs.size() > 100)
        return false;

    if (reg.nMyOutputValue <= 0 || reg.nMyOutputValue > MAX_MONEY)
        return false;

    if (reg.vchCredentialHash.empty() || reg.vchCredentialSig.empty())
        return false;

    if ((int)reg.vchCredentialSig.size() > NULLSEND_RSA_BITS / 8)
        return false;

    if (!VerifyCredential(reg.vchCredentialHash, reg.vchCredentialSig))
    {
        printf("NullSend session %d: credential verification failed\n", nSessionID);
        return false;
    }

    uint256 credHash;
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss.write((const char*)reg.vchCredentialHash.data(), reg.vchCredentialHash.size());
        credHash = ss.GetHash();
    }
    if (setUsedCredentials.count(credHash))
    {
        printf("NullSend session %d: duplicate credential rejected\n", nSessionID);
        return false;
    }
    setUsedCredentials.insert(credHash);

    CNullSendAnonymousOutput anonOut;
    anonOut.vOutputs = reg.vMyOutputs;
    anonOut.nOutputValue = reg.nMyOutputValue;
    vAnonymousOutputs.push_back(anonOut);

    if (fDebug)
        printf("NullSend session %d: accepted anonymous output reg (%d/%d)\n",
               nSessionID, (int)vAnonymousOutputs.size(), (int)vParticipants.size());

    if ((int)vAnonymousOutputs.size() >= (int)vParticipants.size())
    {
        SetState(NULLSEND_STATE_NONCE_COMMIT);
    }

    return true;
}

bool CNullSendSession::AssembleTransactionChaumian()
{
    CTransaction txNew;

    bool fUseFCMP = (nBestHeight >= FORK_HEIGHT_FCMP_VALIDATION);
    txNew.nVersion = fUseFCMP ? SHIELDED_TX_VERSION_FCMP : SHIELDED_TX_VERSION_DSP;
    txNew.nTime = GetTime();
    txNew.nPrivacyMode = nPrivacyMode;

    int nSpendIdx = 0;
    int64_t nTotalInputValue = 0;

    for (CNullSendParticipant& p : vParticipants)
    {
        p.nSpendOffset = nSpendIdx;
        for (const CShieldedSpendDescription& spend : p.inputReg.vMySpends)
        {
            txNew.vShieldedSpend.push_back(spend);
            nSpendIdx++;
        }
        if (p.inputReg.nMyInputValue < 0 || p.inputReg.nMyInputValue > MAX_MONEY)
            return false;
        nTotalInputValue += p.inputReg.nMyInputValue;
        if (nTotalInputValue > MAX_MONEY)
            return false;
    }

    int64_t nTotalOutputValue = 0;
    for (const CNullSendAnonymousOutput& aout : vAnonymousOutputs)
    {
        for (const CShieldedOutputDescription& output : aout.vOutputs)
        {
            txNew.vShieldedOutput.push_back(output);
        }
        if (aout.nOutputValue < 0 || aout.nOutputValue > MAX_MONEY)
            return false;
        nTotalOutputValue += aout.nOutputValue;
        if (nTotalOutputValue > MAX_MONEY)
            return false;
    }

    int64_t nFee = (int64_t)vParticipants.size() * NULLSEND_FEE;
    int64_t nValueBalance = nTotalInputValue - nTotalOutputValue - nFee;
    if (!MoneyRange(nValueBalance))
        return false;
    txNew.nValueBalance = nValueBalance;

    std::vector<int> spendMap(txNew.vShieldedSpend.size());
    std::vector<int> outputMap(txNew.vShieldedOutput.size());
    for (size_t i = 0; i < spendMap.size(); i++) spendMap[i] = (int)i;
    for (size_t i = 0; i < outputMap.size(); i++) outputMap[i] = (int)i;

    for (size_t i = spendMap.size(); i > 1; i--)
        std::swap(spendMap[i-1], spendMap[GetRand((uint32_t)i)]);
    for (size_t i = outputMap.size(); i > 1; i--)
        std::swap(outputMap[i-1], outputMap[GetRand((uint32_t)i)]);

    std::vector<CShieldedSpendDescription> shuffledSpends(txNew.vShieldedSpend.size());
    for (size_t i = 0; i < spendMap.size(); i++)
        shuffledSpends[i] = txNew.vShieldedSpend[spendMap[i]];
    txNew.vShieldedSpend = shuffledSpends;

    std::vector<CShieldedOutputDescription> shuffledOutputs(txNew.vShieldedOutput.size());
    for (size_t i = 0; i < outputMap.size(); i++)
        shuffledOutputs[i] = txNew.vShieldedOutput[outputMap[i]];
    txNew.vShieldedOutput = shuffledOutputs;

    std::vector<int> spendRevMap(spendMap.size());
    for (size_t i = 0; i < spendMap.size(); i++) spendRevMap[spendMap[i]] = (int)i;

    for (CNullSendParticipant& p : vParticipants)
    {
        int nOrigOffset = p.nSpendOffset;
        int nCount = (int)p.inputReg.vMySpends.size();
        if (nCount > 0)
            p.nSpendOffset = spendRevMap[nOrigOffset];
    }

    unsignedTx = txNew;
    sighash = txNew.GetBindingSigHash();

    return true;
}


int CNullSendPool::NewSession(uint8_t nPrivacyMode, int nPoolSize)
{
    LOCK(cs_nullsend);

    if ((int)mapSessions.size() >= 100)
        return -1;

    CNullSendSession session;
    session.nSessionID = nNextSessionID++;
    session.nPrivacyMode = nPrivacyMode;
    session.nTargetParticipants = std::max(NULLSEND_MIN_PARTICIPANTS, std::min(nPoolSize, NULLSEND_MAX_PARTICIPANTS));
    session.nStartTime = GetTime();

    unsigned char nonceBytes[32];
    if (RAND_bytes(nonceBytes, 32) != 1)
        return -1;
    memcpy(session.sessionNonce.begin(), nonceBytes, 32);
    OPENSSL_cleanse(nonceBytes, 32);

    if (nBestHeight >= FORK_HEIGHT_CHAUMIAN_CJ)
    {
        session.fChaumian = true;

        if (!session.GenerateSessionRSAKey())
        {
            printf("NullSend: failed to generate RSA key for session %d\n", session.nSessionID);
            return -1;
        }

        session.SetState(NULLSEND_STATE_INPUT_REG);
    }
    else
    {
        session.SetState(NULLSEND_STATE_ACCEPTING);
    }

    mapSessions[session.nSessionID] = session;

    if (fDebug)
        printf("NullSend: new session %d (pool=%d, mode=%d, chaumian=%d)\n",
               session.nSessionID, session.nTargetParticipants, nPrivacyMode, session.fChaumian);

    return session.nSessionID;
}

void CNullSendPool::ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    LOCK(cs_nullsend);

    if (strCommand == "znse")
    {
        CNullSendEntry entry;
        vRecv >> entry;

        auto it = mapSessions.find(entry.nSessionID);
        if (it == mapSessions.end())
        {
            if (fDebug)
                printf("NullSend: entry for unknown session %d\n", entry.nSessionID);
            return;
        }

        if (it->second.fChaumian)
        {
            if (fDebug)
                printf("NullSend: legacy entry rejected for Chaumian session %d\n", entry.nSessionID);
            return;
        }

        it->second.AcceptEntry(entry, pfrom);
    }
    else if (strCommand == "znsir")
    {
        CNullSendInputReg reg;
        vRecv >> reg;

        auto it = mapSessions.find(reg.nSessionID);
        if (it == mapSessions.end())
        {
            if (fDebug)
                printf("NullSend: input reg for unknown session %d\n", reg.nSessionID);
            return;
        }

        if (!it->second.fChaumian)
        {
            if (fDebug)
                printf("NullSend: Chaumian input reg rejected for legacy session %d\n", reg.nSessionID);
            return;
        }

        it->second.AcceptInputReg(reg, pfrom);
    }
    else if (strCommand == "znsor")
    {
        CNullSendOutputReg reg;
        vRecv >> reg;

        auto it = mapSessions.find(reg.nSessionID);
        if (it == mapSessions.end())
        {
            if (fDebug)
                printf("NullSend: output reg for unknown session %d\n", reg.nSessionID);
            return;
        }

        if (!it->second.fChaumian)
        {
            if (fDebug)
                printf("NullSend: Chaumian output reg rejected for legacy session %d\n", reg.nSessionID);
            return;
        }

        it->second.AcceptOutputReg(reg);
    }
    else if (strCommand == "znsnc")
    {
        CNullSendNonceCommit msg;
        vRecv >> msg;

        auto it = mapSessions.find(msg.nSessionID);
        if (it == mapSessions.end()) return;

        std::vector<unsigned char> vchNoncePoint;
        vRecv >> vchNoncePoint;

        if (vchNoncePoint.size() != 33)
        {
            if (fDebug)
                printf("NullSend: invalid nonce point size %u from participant %d\n",
                       (unsigned)vchNoncePoint.size(), msg.nParticipantID);
            return;
        }

        uint256 expectedCommit = ComputeNonceCommitment(vchNoncePoint);
        if (expectedCommit != msg.nonceCommitment)
        {
            if (fDebug)
                printf("NullSend: nonce commitment mismatch from participant %d\n", msg.nParticipantID);
            return;
        }

        if (msg.nParticipantID < 0 || msg.nParticipantID >= (int)it->second.vParticipants.size())
            return;
        if (it->second.vParticipants[msg.nParticipantID].pnode != pfrom)
            return;

        it->second.vParticipants[msg.nParticipantID].vchNoncePoint = vchNoncePoint;
        it->second.ProcessNonceCommit(msg.nParticipantID, msg.nonceCommitment);
    }
    else if (strCommand == "znsps")
    {
        CNullSendPartialSig msg;
        vRecv >> msg;

        auto it = mapSessions.find(msg.nSessionID);
        if (it == mapSessions.end()) return;

        if (msg.nParticipantID < 0 || msg.nParticipantID >= (int)it->second.vParticipants.size())
            return;
        if (it->second.vParticipants[msg.nParticipantID].pnode != pfrom)
            return;

        it->second.ProcessPartialSig(msg.nParticipantID, msg);
    }
}

void CNullSendPool::CheckTimeouts()
{
    LOCK(cs_nullsend);

    std::vector<int> vToRemove;
    for (auto& pair : mapSessions)
    {
        pair.second.CheckTimeout();
        if (pair.second.nState == NULLSEND_STATE_SUCCESS || pair.second.nState == NULLSEND_STATE_ERROR)
        {
            if ((GetTime() - pair.second.nStateChangeTime) > 60)
                vToRemove.push_back(pair.first);
        }
    }

    for (int id : vToRemove)
        mapSessions.erase(id);
}


void CNullSendClient::Reset()
{
    if (!vchMyNonce.empty())
        OPENSSL_cleanse(vchMyNonce.data(), vchMyNonce.size());
    if (!vchBlindingFactor.empty())
        OPENSSL_cleanse(vchBlindingFactor.data(), vchBlindingFactor.size());
    vchMyNonce.clear();
    vchMyNoncePoint.clear();
    vMyInputBlinds.clear();
    vMyOutputBlinds.clear();
    myEntry = CNullSendEntry();
    nCurrentSession = 0;
    nParticipantID = -1;
    nState = NULLSEND_STATE_IDLE;
    pCoordinator = NULL;
    nTimeout = NULLSEND_QUEUE_TIMEOUT;
    nStartTime = 0;

    vchBlindingFactor.clear();
    vchCredentialHash.clear();
    vchBlindedCredential.clear();
    vchBlindSigFromCoord.clear();
    vchUnblindedSig.clear();
    vchSessionRSA_N.clear();
    vchSessionRSA_E.clear();
    vMyOutputsDeferred.clear();
    nMyOutputValue = 0;
}

bool CNullSendClient::JoinSession(const std::string& fromAddr,
                                    uint8_t nPrivacyMode, int nPoolSize, int nTimeoutSec)
{
    Reset();

    nTimeout = nTimeoutSec;
    nStartTime = GetTime();

    LOCK(cs_nullsend);

    int nSession = nullSendPool.NewSession(nPrivacyMode, nPoolSize);
    if (nSession < 0)
        return false;

    nCurrentSession = nSession;
    nState = NULLSEND_STATE_ACCEPTING;

    return true;
}

void CNullSendClient::ProcessAccept(const CNullSendAccept& msg, CNode* pfrom)
{
    LOCK(cs_nullsend);

    if (msg.nSessionID != nCurrentSession)
        return;

    if (msg.nStatusCode == NULLSEND_ACCEPTED)
    {
        nParticipantID = msg.nParticipantID;
        pCoordinator = pfrom;
        nState = NULLSEND_STATE_NONCE_COMMIT;

        if (!GenerateMuSigNonce(vchMyNonce, vchMyNoncePoint))
        {
            printf("NullSend client: failed to generate nonce\n");
            Reset();
            return;
        }

        uint256 commitment = ComputeNonceCommitment(vchMyNoncePoint);

        CNullSendNonceCommit commitMsg;
        commitMsg.nSessionID = nCurrentSession;
        commitMsg.nParticipantID = nParticipantID;
        commitMsg.nonceCommitment = commitment;

        if (pCoordinator)
        {
            pCoordinator->PushMessage("znsnc", commitMsg, vchMyNoncePoint);
        }

        if (fDebug)
            printf("NullSend client: accepted as participant %d, sent nonce commit\n", nParticipantID);
    }
    else if (msg.nStatusCode == NULLSEND_RESET)
    {
        if (fDebug)
            printf("NullSend client: session reset - %s\n", msg.strMessage.c_str());
        Reset();
    }
}

void CNullSendClient::ProcessChallenge(const CNullSendChallenge& msg)
{
    LOCK(cs_nullsend);

    if (msg.nSessionID != nCurrentSession)
        return;

    if (nState != NULLSEND_STATE_NONCE_COMMIT)
        return;

    if (msg.vchAggregateNonce.size() != 33)
    {
        printf("NullSend client: invalid aggregate nonce size %u\n", (unsigned)msg.vchAggregateNonce.size());
        Reset();
        return;
    }
    if (msg.vchChallenge.size() != 32)
    {
        printf("NullSend client: invalid challenge size %u\n", (unsigned)msg.vchChallenge.size());
        Reset();
        return;
    }
    for (const auto& rp : msg.vNoncePoints)
    {
        if (rp.size() != 33)
        {
            printf("NullSend client: invalid nonce point size %u\n", (unsigned)rp.size());
            Reset();
            return;
        }
    }

    std::vector<unsigned char> vchVerifyAgg;
    if (!AggregateNoncePoints(msg.vNoncePoints, vchVerifyAgg))
    {
        printf("NullSend client: failed to verify aggregate nonce\n");
        Reset();
        return;
    }

    if (vchVerifyAgg != msg.vchAggregateNonce)
    {
        printf("NullSend client: aggregate nonce mismatch!\n");
        Reset();
        return;
    }

    bool fFoundMyNonce = false;
    for (const auto& rp : msg.vNoncePoints)
    {
        if (rp == vchMyNoncePoint)
        {
            fFoundMyNonce = true;
            break;
        }
    }
    if (!fFoundMyNonce)
    {
        printf("NullSend client: my nonce point not in challenge!\n");
        Reset();
        return;
    }

    for (const CShieldedSpendDescription& mySpend : myEntry.vMySpends)
    {
        bool fFound = false;
        for (const CShieldedSpendDescription& txSpend : msg.unsignedTx.vShieldedSpend)
        {
            if (txSpend.nullifier == mySpend.nullifier)
            {
                fFound = true;
                break;
            }
        }
        if (!fFound)
        {
            printf("NullSend client: my spend not found in unsigned tx!\n");
            Reset();
            return;
        }
    }

    std::vector<unsigned char> vchPartialSig;
    if (!CreatePartialBindingSig(vchMyNonce, vMyInputBlinds, vMyOutputBlinds,
                                  msg.vchChallenge, vchPartialSig))
    {
        printf("NullSend client: failed to create partial signature\n");
        Reset();
        return;
    }

    CShieldedSpendingKey sk;
    {
        CWallet* pwallet = pwalletMain;
        if (!pwallet) { Reset(); return; }

        LOCK(pwallet->cs_shielded);
        bool fFoundKey = false;
        for (const auto& keypair : pwallet->mapShieldedSpendingKeys)
        {
            sk = keypair.second;
            fFoundKey = true;
            break;
        }
        if (!fFoundKey) { Reset(); return; }
    }

    CNullSendPartialSig sigMsg;
    sigMsg.nSessionID = nCurrentSession;
    sigMsg.nParticipantID = nParticipantID;
    sigMsg.vchPartialSig = vchPartialSig;

    uint256 spendSighash = msg.sighash;
    for (size_t i = 0; i < myEntry.vMySpends.size(); i++)
    {
        std::vector<unsigned char> vchRk, vchSig;
        if (!CreateSpendAuthSignature(sk.skSpend, spendSighash, vchRk, vchSig))
        {
            printf("NullSend client: failed to create spend auth sig %d\n", (int)i);
            Reset();
            return;
        }

        sigMsg.vSpendAuthSigs.push_back(vchSig);
        sigMsg.vSpendRks.push_back(vchRk);
    }

    OPENSSL_cleanse(vchMyNonce.data(), vchMyNonce.size());
    vchMyNonce.clear();

    if (pCoordinator)
        pCoordinator->PushMessage("znsps", sigMsg);

    nState = NULLSEND_STATE_PARTIAL_SIG;

    if (fDebug)
        printf("NullSend client: sent partial signature\n");
}

void CNullSendClient::ProcessFinalTx(const CNullSendBroadcastTx& msg)
{
    LOCK(cs_nullsend);

    if (msg.nSessionID != nCurrentSession)
        return;

    if (fDebug)
        printf("NullSend client: received final tx %s\n", msg.tx.GetHash().ToString().c_str());

    nState = NULLSEND_STATE_SUCCESS;
}


bool CNullSendClient::BlindOutputCredential(const std::vector<unsigned char>& vchN,
                                              const std::vector<unsigned char>& vchE)
{
    if (vchN.empty() || vchE.empty())
        return false;

    vchSessionRSA_N = vchN;
    vchSessionRSA_E = vchE;

    {
        CHashWriter ss(SER_GETHASH, 0);
        for (const CShieldedOutputDescription& output : vMyOutputsDeferred)
            ss << output;
        ss << nMyOutputValue;
        uint256 hash = ss.GetHash();
        vchCredentialHash.assign(hash.begin(), hash.end());
    }

    unsigned char mHash[SHA256_DIGEST_LENGTH];
    SHA256(vchCredentialHash.data(), vchCredentialHash.size(), mHash);

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* m = BN_bin2bn(mHash, SHA256_DIGEST_LENGTH, NULL);
    BIGNUM* n_bn = NS_VecToBN(vchN);
    BIGNUM* e_bn = NS_VecToBN(vchE);
    BIGNUM* r = BN_new();
    BIGNUM* r_e = BN_new();
    BIGNUM* blinded = BN_new();
    BIGNUM* m_mod = BN_new();

    if (!ctx || !m || !n_bn || !e_bn || !r || !r_e || !blinded || !m_mod)
    {
        BN_CTX_free(ctx); BN_free(m); BN_free(n_bn); BN_free(e_bn);
        BN_free(r); BN_free(r_e); BN_free(blinded); BN_free(m_mod);
        return false;
    }

    bool fOk = false;

    if (!BN_mod(m_mod, m, n_bn, ctx))
        goto ns_blind_cleanup;

    {
        int nBits = BN_num_bits(n_bn);
        for (int tries = 0; tries < 100; tries++)
        {
            if (!BN_rand(r, nBits - 1, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
                goto ns_blind_cleanup;

            BIGNUM* gcd = BN_new();
            if (!gcd) goto ns_blind_cleanup;
            BN_gcd(gcd, r, n_bn, ctx);
            bool fCoprime = BN_is_one(gcd);
            BN_free(gcd);
            if (fCoprime)
                break;
            if (tries == 99)
                goto ns_blind_cleanup;
        }
    }

    vchBlindingFactor = NS_BNToVec(r, (int)vchN.size());

    if (!BN_mod_exp(r_e, r, e_bn, n_bn, ctx))
        goto ns_blind_cleanup;

    if (!BN_mod_mul(blinded, m_mod, r_e, n_bn, ctx))
        goto ns_blind_cleanup;

    vchBlindedCredential = NS_BNToVec(blinded, (int)vchN.size());
    fOk = true;

ns_blind_cleanup:
    BN_free(m);
    BN_free(m_mod);
    BN_free(n_bn);
    BN_free(e_bn);
    BN_clear_free(r);
    BN_free(r_e);
    BN_free(blinded);
    BN_CTX_free(ctx);

    return fOk;
}

bool CNullSendClient::UnblindSignature(const std::vector<unsigned char>& vchBlindSig)
{
    if (vchBlindingFactor.empty() || vchSessionRSA_N.empty())
        return false;

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* s_prime = NS_VecToBN(vchBlindSig);
    BIGNUM* r_bn = NS_VecToBN(vchBlindingFactor);
    BIGNUM* n_bn = NS_VecToBN(vchSessionRSA_N);
    BIGNUM* r_inv = BN_new();
    BIGNUM* s = BN_new();

    if (!ctx || !s_prime || !r_bn || !n_bn || !r_inv || !s)
    {
        BN_CTX_free(ctx); BN_free(s_prime); BN_clear_free(r_bn);
        BN_free(n_bn); BN_free(r_inv); BN_free(s);
        return false;
    }

    bool fOk = false;

    if (!BN_mod_inverse(r_inv, r_bn, n_bn, ctx))
        goto ns_unblind_cleanup;

    if (!BN_mod_mul(s, s_prime, r_inv, n_bn, ctx))
        goto ns_unblind_cleanup;

    vchUnblindedSig = NS_BNToVec(s, (int)vchSessionRSA_N.size());
    fOk = true;

ns_unblind_cleanup:
    BN_free(s_prime);
    BN_clear_free(r_bn);
    BN_free(n_bn);
    BN_clear_free(r_inv);
    BN_clear_free(s);
    BN_CTX_free(ctx);

    if (!vchBlindingFactor.empty())
        OPENSSL_cleanse(vchBlindingFactor.data(), vchBlindingFactor.size());
    vchBlindingFactor.clear();

    return fOk;
}

bool CNullSendClient::SubmitOutputsAnonymously()
{
    if (vchUnblindedSig.empty() || vchCredentialHash.empty())
        return false;

    if (vMyOutputsDeferred.empty())
        return false;

    if (!pCoordinator)
        return false;

    CNullSendOutputReg outputReg;
    outputReg.nSessionID = nCurrentSession;
    outputReg.vMyOutputs = vMyOutputsDeferred;
    outputReg.nMyOutputValue = nMyOutputValue;
    outputReg.vchCredentialHash = vchCredentialHash;
    outputReg.vchCredentialSig = vchUnblindedSig;

    pCoordinator->PushMessage("znsor", outputReg);

    if (fDebug)
        printf("NullSend client: submitted outputs anonymously for session %d\n", nCurrentSession);

    return true;
}

void CNullSendClient::ProcessInputAccept(const CNullSendInputAccept& msg, CNode* pfrom)
{
    LOCK(cs_nullsend);

    if (msg.nSessionID != nCurrentSession)
        return;

    if (msg.nStatusCode == NULLSEND_ACCEPTED)
    {
        nParticipantID = msg.nParticipantID;
        pCoordinator = pfrom;

        vchBlindSigFromCoord = msg.vchBlindSignature;

        if (!UnblindSignature(msg.vchBlindSignature))
        {
            printf("NullSend client: failed to unblind signature\n");
            Reset();
            return;
        }

        if (!SubmitOutputsAnonymously())
        {
            printf("NullSend client: failed to submit outputs\n");
            Reset();
            return;
        }

        nState = NULLSEND_STATE_NONCE_COMMIT;

        if (!GenerateMuSigNonce(vchMyNonce, vchMyNoncePoint))
        {
            printf("NullSend client: failed to generate nonce\n");
            Reset();
            return;
        }

        uint256 commitment = ComputeNonceCommitment(vchMyNoncePoint);

        CNullSendNonceCommit commitMsg;
        commitMsg.nSessionID = nCurrentSession;
        commitMsg.nParticipantID = nParticipantID;
        commitMsg.nonceCommitment = commitment;

        if (pCoordinator)
            pCoordinator->PushMessage("znsnc", commitMsg, vchMyNoncePoint);

        if (fDebug)
            printf("NullSend client: Chaumian input accepted as %d, outputs submitted, nonce committed\n",
                   nParticipantID);
    }
    else
    {
        if (fDebug)
            printf("NullSend client: input registration rejected - %s\n", msg.strMessage.c_str());
        Reset();
    }
}


void ProcessMessageNullSend(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    if (strCommand.substr(0, 3) != "zns")
        return;

    if (nBestHeight < FORK_HEIGHT_NULLSEND)
        return;

    if (strCommand == "znsq")
    {
        CNullSendQueue queue;
        vRecv >> queue;

        if (!queue.IsExpired())
        {
            LOCK(cs_nullsend);
            if (vecNullSendQueue.size() < 1000)  // DoS protection
                vecNullSendQueue.push_back(queue);
        }
    }
    else if (strCommand == "znse" || strCommand == "znsnc" || strCommand == "znsps"
             || strCommand == "znsir" || strCommand == "znsor")
    {
        nullSendPool.ProcessMessage(pfrom, strCommand, vRecv);
    }
    else if (strCommand == "znsa")
    {
        CNullSendAccept msg;
        vRecv >> msg;
        nullSendClient.ProcessAccept(msg, pfrom);
    }
    else if (strCommand == "znsia")
    {
        CNullSendInputAccept msg;
        vRecv >> msg;
        nullSendClient.ProcessInputAccept(msg, pfrom);
    }
    else if (strCommand == "znsch")
    {
        CNullSendChallenge msg;
        vRecv >> msg;
        nullSendClient.ProcessChallenge(msg);
    }
    else if (strCommand == "znstx")
    {
        CNullSendBroadcastTx msg;
        vRecv >> msg;
        nullSendClient.ProcessFinalTx(msg);
    }
}


void ThreadNullSend(void* parg)
{
    printf("ThreadNullSend started\n");

    while (!fShutdown)
    {
        MilliSleep(1000);

        if (fShutdown)
            break;

        nullSendPool.CheckTimeouts();

        {
            LOCK(cs_nullsend);
            vecNullSendQueue.erase(
                std::remove_if(vecNullSendQueue.begin(), vecNullSendQueue.end(),
                    [](const CNullSendQueue& q) { return q.IsExpired(); }),
                vecNullSendQueue.end());
        }
    }

    printf("ThreadNullSend stopped\n");
}
