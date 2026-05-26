// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "finality.h"
#include "main.h"
#include "init.h"
#include "wallet.h"
#include "net.h"
#include "util.h"
#include "dag.h"
#include "txdb.h"
#include "base58.h"
#include "kernel.h"

#include <openssl/sha.h>
#include <algorithm>

CFinalityTracker g_finalityTracker;


// ---------------------------------------------------------------------------
// POEM Entropy
// ---------------------------------------------------------------------------

uint256 GetBlockEntropy(const uint256& hashValue)
{
    uint256 comp = ~hashValue;
    if (comp == 0)
        return 0;

    CBigNum bnComp(comp);
    unsigned int nBitSize = bnComp.bitSize();

    uint256 result = 0;
    result = (uint64_t)nBitSize << 32;

    if (nBitSize > 33)
    {
        uint256 shifted = comp >> (nBitSize - 33);
        uint32_t nFracBits = (uint32_t)(shifted.Get64(0) & 0xFFFFFFFF);
        result += nFracBits;
    }

    return result;
}

int64_t GetFinalityVoteReward(int64_t nVoteWeight, int nEpochInterval)
{
    if (nVoteWeight <= 0 || nEpochInterval <= 0)
        return 0;

    // Match the legacy PoS reward curve using coin-age generated during one
    // finality epoch. Integer truncation is intentional and deterministic.
    CBigNum bnCoinAge = CBigNum(nVoteWeight) * nEpochInterval / COIN / (24 * 60 * 60);
    uint64_t nCoinAge = bnCoinAge.getuint64();
    CBigNum bnReward = CBigNum(nCoinAge) * COIN_YEAR_REWARD / 365;
    uint64_t nReward = bnReward.getuint64();
    if (nReward > (uint64_t)MAX_MONEY)
        return MAX_MONEY;
    return (int64_t)nReward;
}

CScript BuildFinalityVoteScript(const CFinalityVote& vote)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << vote;

    std::vector<unsigned char> vchData;
    vchData.reserve(4 + ss.size());
    vchData.insert(vchData.end(), FINALITY_VOTE_TAG, FINALITY_VOTE_TAG + 4);
    vchData.insert(vchData.end(), ss.begin(), ss.end());

    CScript script;
    script << OP_RETURN << vchData;
    return script;
}

bool ExtractFinalityVote(const CScript& scriptPubKey, CFinalityVote& voteOut)
{
    CScript::const_iterator pc = scriptPubKey.begin();
    if (pc >= scriptPubKey.end())
        return false;

    opcodetype opcode;
    std::vector<unsigned char> vchData;
    if (!scriptPubKey.GetOp(pc, opcode, vchData))
        return false;
    if (opcode != OP_RETURN)
        return false;
    if (!scriptPubKey.GetOp(pc, opcode, vchData))
        return false;
    if (vchData.size() <= 4)
        return false;
    if (memcmp(vchData.data(), FINALITY_VOTE_TAG, 4) != 0)
        return false;

    try {
        std::vector<unsigned char> vPayload(vchData.begin() + 4, vchData.end());
        CDataStream ss(vPayload, SER_NETWORK, PROTOCOL_VERSION);
        ss >> voteOut;
    } catch (const std::exception& e) {
        return false;
    }
    return true;
}

std::vector<CFinalityVote> ExtractFinalityVotesFromBlock(const CBlock& block)
{
    std::vector<CFinalityVote> vVotes;
    if (block.vtx.empty())
        return vVotes;

    for (const CTxOut& out : block.vtx[0].vout)
    {
        CFinalityVote vote;
        if (ExtractFinalityVote(out.scriptPubKey, vote))
            vVotes.push_back(vote);
    }
    return vVotes;
}

CScript BuildFinalityTallyCertificateScript(const CFinalityTallyCertificate& cert)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << cert;

    std::vector<unsigned char> vchData;
    vchData.reserve(4 + ss.size());
    vchData.insert(vchData.end(), FINALITY_TALLY_CERT_TAG, FINALITY_TALLY_CERT_TAG + 4);
    vchData.insert(vchData.end(), ss.begin(), ss.end());

    CScript script;
    script << OP_RETURN << vchData;
    return script;
}

bool ExtractFinalityTallyCertificate(const CScript& scriptPubKey, CFinalityTallyCertificate& certOut)
{
    CScript::const_iterator pc = scriptPubKey.begin();
    if (pc >= scriptPubKey.end())
        return false;

    opcodetype opcode;
    std::vector<unsigned char> vchData;
    if (!scriptPubKey.GetOp(pc, opcode, vchData))
        return false;
    if (opcode != OP_RETURN)
        return false;
    if (!scriptPubKey.GetOp(pc, opcode, vchData))
        return false;
    if (vchData.size() <= 4)
        return false;
    if (memcmp(vchData.data(), FINALITY_TALLY_CERT_TAG, 4) != 0)
        return false;

    try {
        std::vector<unsigned char> vPayload(vchData.begin() + 4, vchData.end());
        CDataStream ss(vPayload, SER_NETWORK, PROTOCOL_VERSION);
        ss >> certOut;
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

std::vector<CFinalityTallyCertificate> ExtractFinalityTallyCertificatesFromBlock(const CBlock& block)
{
    std::vector<CFinalityTallyCertificate> vCerts;
    if (block.vtx.empty())
        return vCerts;

    for (const CTxOut& out : block.vtx[0].vout)
    {
        CFinalityTallyCertificate cert;
        if (ExtractFinalityTallyCertificate(out.scriptPubKey, cert))
            vCerts.push_back(cert);
    }
    return vCerts;
}


// ---------------------------------------------------------------------------
// Private finality proof and tally certificate envelopes
// ---------------------------------------------------------------------------

static bool FinalityReject(std::string* pstrError, const std::string& strReason)
{
    if (pstrError)
        *pstrError = strReason;
    return false;
}

static bool AddMoneySafe(int64_t a, int64_t b, int64_t& out)
{
    if (a < 0 || b < 0 || a > MAX_MONEY || b > MAX_MONEY || a > MAX_MONEY - b)
        return false;
    out = a + b;
    return true;
}

static bool VerifyFinalityThresholdTier(int nTier, int64_t nActiveWeight, int64_t nWinningWeight)
{
    if (nActiveWeight <= 0 || nWinningWeight < 0 || nWinningWeight > nActiveWeight)
        return nTier == FINALITY_NONE;
    if (nTier == FINALITY_HARD)
        return nWinningWeight * 3 >= nActiveWeight * 2;
    if (nTier == FINALITY_SOFT)
        return nWinningWeight * 2 >= nActiveWeight;
    if (nTier == FINALITY_TENTATIVE)
        return nWinningWeight * 3 >= nActiveWeight;
    return nTier == FINALITY_NONE;
}

static bool VerifyFinalityAggregateThresholdProof(const CFinalityTallyCertificate& cert,
                                                  int64_t nMatchedTransparentActiveWeight,
                                                  int64_t nMatchedTransparentWinningWeight,
                                                  int64_t& nPrivateActiveWeightOut,
                                                  int64_t& nPrivateWinningWeightOut,
                                                  std::string* pstrError)
{
    try {
        CDataStream ss(cert.vchAggregateThresholdProof, SER_NETWORK, PROTOCOL_VERSION);
        uint32_t nVersion = 0;
        int64_t nPrivateActiveWeight = 0;
        int64_t nPrivateWinningWeight = 0;
        std::vector<unsigned char> vchActiveBlind;
        std::vector<unsigned char> vchWinningBlind;
        ss >> nVersion;
        ss >> nPrivateActiveWeight;
        ss >> nPrivateWinningWeight;
        ss >> vchActiveBlind;
        ss >> vchWinningBlind;

        if (nVersion != 1)
            return FinalityReject(pstrError, "unsupported aggregate threshold proof version");
        if (nPrivateActiveWeight < 0 || nPrivateWinningWeight < 0 ||
            nPrivateWinningWeight > nPrivateActiveWeight ||
            nPrivateActiveWeight > MAX_MONEY || nPrivateWinningWeight > MAX_MONEY)
            return FinalityReject(pstrError, "aggregate threshold proof weight out of range");
        if (vchActiveBlind.size() != BLINDING_FACTOR_SIZE ||
            vchWinningBlind.size() != BLINDING_FACTOR_SIZE)
            return FinalityReject(pstrError, "aggregate threshold proof has invalid blind sizes");
        if (!VerifyPedersenCommitment(cert.activeWeightCommitment, nPrivateActiveWeight, vchActiveBlind))
            return FinalityReject(pstrError, "aggregate active weight commitment opening failed");
        if (!VerifyPedersenCommitment(cert.winningWeightCommitment, nPrivateWinningWeight, vchWinningBlind))
            return FinalityReject(pstrError, "aggregate winning weight commitment opening failed");

        int64_t nTotalActive = 0;
        int64_t nTotalWinning = 0;
        if (!AddMoneySafe(nMatchedTransparentActiveWeight, nPrivateActiveWeight, nTotalActive) ||
            !AddMoneySafe(nMatchedTransparentWinningWeight, nPrivateWinningWeight, nTotalWinning))
            return FinalityReject(pstrError, "aggregate threshold total overflow");
        if (!VerifyFinalityThresholdTier(cert.nTier, nTotalActive, nTotalWinning))
            return FinalityReject(pstrError, "aggregate threshold proof does not satisfy certificate tier");

        nPrivateActiveWeightOut = nPrivateActiveWeight;
        nPrivateWinningWeightOut = nPrivateWinningWeight;
        return true;
    } catch (const std::exception&) {
        return FinalityReject(pstrError, "aggregate threshold proof parse failed");
    }
}

static bool VerifyFinalityRewardBudgetProof(const CFinalityTallyCertificate& cert,
                                            int64_t nPrivateActiveWeight,
                                            int64_t nMatchedTransparentRewardBudget,
                                            std::string* pstrError)
{
    try {
        CDataStream ss(cert.vchRewardBudgetProof, SER_NETWORK, PROTOCOL_VERSION);
        uint32_t nVersion = 0;
        int64_t nPrivateRewardBudget = 0;
        std::vector<unsigned char> vchRewardBlind;
        ss >> nVersion;
        ss >> nPrivateRewardBudget;
        ss >> vchRewardBlind;

        if (nVersion != 1)
            return FinalityReject(pstrError, "unsupported reward-budget proof version");
        if (nPrivateRewardBudget < 0 || nPrivateRewardBudget > MAX_MONEY)
            return FinalityReject(pstrError, "reward-budget proof value out of range");
        if (vchRewardBlind.size() != BLINDING_FACTOR_SIZE)
            return FinalityReject(pstrError, "reward-budget proof has invalid blind size");
        if (!VerifyPedersenCommitment(cert.rewardBudgetCommitment, nPrivateRewardBudget, vchRewardBlind))
            return FinalityReject(pstrError, "reward-budget commitment opening failed");

        int64_t nExpectedPrivateReward = GetFinalityVoteReward(nPrivateActiveWeight, GetEpochInterval(cert.nHeight));
        if (nPrivateRewardBudget != nExpectedPrivateReward)
            return FinalityReject(pstrError, "private reward budget does not match aggregate vote weight schedule");
        if (cert.nTransparentRewardBudget != nMatchedTransparentRewardBudget)
            return FinalityReject(pstrError, "transparent reward budget mismatch");
        if (nMatchedTransparentRewardBudget > MAX_MONEY - nPrivateRewardBudget)
            return FinalityReject(pstrError, "reward-budget total overflow");
        return true;
    } catch (const std::exception&) {
        return FinalityReject(pstrError, "reward-budget proof parse failed");
    }
}

bool CPrivateFinalityVoteProof::IsNull() const
{
    return nProofMode == FINALITY_PROOF_TRANSPARENT || nullifier == 0;
}

bool CPrivateFinalityVoteProof::IsValidBasic(std::string* pstrError) const
{
    if (nVersion != 1)
        return FinalityReject(pstrError, "unsupported private finality proof version");
    if (nProofMode != FINALITY_PROOF_NULLSTAKE_V2 && nProofMode != FINALITY_PROOF_NULLSTAKE_V3_COLD)
        return FinalityReject(pstrError, "invalid private finality proof mode");
    if (nEpoch < 0)
        return FinalityReject(pstrError, "negative private finality epoch");
    if (hashEpochBlock == 0 || hashCurveRoot == 0 || hashNullifierRoot == 0 || nullifier == 0)
        return FinalityReject(pstrError, "private finality proof missing bound roots/nullifier");
    if (stakeWeightCommitment.IsNull())
        return FinalityReject(pstrError, "private finality proof missing weight commitment");
    if (rewardCommitment.IsNull())
        return FinalityReject(pstrError, "private finality proof missing reward commitment");
    if (fcmpProof.IsNull())
        return FinalityReject(pstrError, "private finality proof missing FCMP proof");
    if (vchRewardOutputCommitment.empty() || vchRewardOutputCommitment.size() > 128)
        return FinalityReject(pstrError, "private finality proof invalid reward output commitment");
    if (vchBindingProof.empty() || vchBindingProof.size() > BPAC_V3_MAX_PROOF_SIZE)
        return FinalityReject(pstrError, "private finality proof invalid binding proof");
    if (nProofMode == FINALITY_PROOF_NULLSTAKE_V2)
    {
        if (nullStakeV2Proof.IsNull())
            return FinalityReject(pstrError, "private finality proof missing NullStake V2 proof");
    }
    else if (nProofMode == FINALITY_PROOF_NULLSTAKE_V3_COLD)
    {
        if (nullStakeV3Proof.IsNull())
            return FinalityReject(pstrError, "private finality proof missing NullStake V3 cold proof");
    }
    return true;
}

uint256 CFinalityTallyShare::GetHash() const
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << nVersion;
    ss << nEpoch;
    ss << voteNullifier;
    ss << hashBlock;
    ss << stakeWeightCommitment;
    ss << rewardCommitment;
    ss << vchShareProof;
    return ss.GetHash();
}

bool CFinalityTallyShare::IsValidBasic() const
{
    if (nVersion != 1 || nEpoch < 0 || voteNullifier == 0 || hashBlock == 0)
        return false;
    if (stakeWeightCommitment.IsNull() || rewardCommitment.IsNull())
        return false;
    if (vchShareProof.empty() || vchShareProof.size() > BPAC_V3_MAX_PROOF_SIZE)
        return false;
    return true;
}

uint256 CFinalityTallyCertificate::GetHash() const
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << nVersion;
    ss << nEpoch;
    ss << hashBlock;
    ss << nHeight;
    ss << nTier;
    ss << nConsecutiveHardCount;
    ss << hashCurveRoot;
    ss << hashNullifierRoot;
    ss << activeWeightCommitment;
    ss << winningWeightCommitment;
    ss << rewardBudgetCommitment;
    ss << nTransparentActiveWeight;
    ss << nTransparentWinningWeight;
    ss << nTransparentRewardBudget;
    ss << vVoteNullifiers;
    ss << vTallyShareHashes;
    ss << vchAggregateThresholdProof;
    ss << vchRewardBudgetProof;
    return ss.GetHash();
}

bool CFinalityTallyCertificate::HasPrivateWeight() const
{
    return !activeWeightCommitment.IsNull() ||
           !winningWeightCommitment.IsNull() ||
           !rewardBudgetCommitment.IsNull() ||
           !vTallyShareHashes.empty();
}

bool CFinalityTallyCertificate::IsValidBasic(std::string* pstrError) const
{
    if (nVersion != 1)
        return FinalityReject(pstrError, "unsupported tally certificate version");
    if (nEpoch < 0 || nHeight < 0)
        return FinalityReject(pstrError, "invalid tally certificate epoch or height");
    if (hashBlock == 0)
        return FinalityReject(pstrError, "tally certificate missing block hash");
    if (nTier < FINALITY_NONE || nTier > FINALITY_HARD)
        return FinalityReject(pstrError, "invalid tally certificate tier");
    if (nTransparentActiveWeight < 0 || nTransparentWinningWeight < 0 || nTransparentRewardBudget < 0)
        return FinalityReject(pstrError, "negative transparent tally values");
    if (nTransparentActiveWeight > MAX_MONEY || nTransparentWinningWeight > MAX_MONEY || nTransparentRewardBudget > MAX_MONEY)
        return FinalityReject(pstrError, "transparent tally value out of range");
    if (nTransparentWinningWeight > nTransparentActiveWeight)
        return FinalityReject(pstrError, "winning transparent weight exceeds active transparent weight");
    if (vVoteNullifiers.empty() || vVoteNullifiers.size() > FINALITY_MAX_VOTES)
        return FinalityReject(pstrError, "invalid tally certificate vote set size");
    std::set<uint256> setNullifiers;
    for (const uint256& nf : vVoteNullifiers)
    {
        if (nf == 0 || !setNullifiers.insert(nf).second)
            return FinalityReject(pstrError, "duplicate or zero tally certificate nullifier");
    }

    if (HasPrivateWeight())
    {
        if (hashCurveRoot == 0 || hashNullifierRoot == 0)
            return FinalityReject(pstrError, "private tally certificate missing epoch roots");
        if (activeWeightCommitment.IsNull() || winningWeightCommitment.IsNull() || rewardBudgetCommitment.IsNull())
            return FinalityReject(pstrError, "private tally certificate missing aggregate commitments");
        if (vTallyShareHashes.empty())
            return FinalityReject(pstrError, "private tally certificate missing share hashes");
        if (vchAggregateThresholdProof.empty() || vchAggregateThresholdProof.size() > BPAC_V3_MAX_PROOF_SIZE)
            return FinalityReject(pstrError, "private tally certificate invalid aggregate threshold proof");
        if (vchRewardBudgetProof.empty() || vchRewardBudgetProof.size() > BPAC_V3_MAX_PROOF_SIZE)
            return FinalityReject(pstrError, "private tally certificate invalid reward budget proof");
    }
    else if (nTier != FINALITY_NONE)
    {
        if (nTransparentActiveWeight <= 0)
            return FinalityReject(pstrError, "transparent tally certificate has no active weight");
        if (nTier == FINALITY_HARD &&
            nTransparentWinningWeight * 3 < nTransparentActiveWeight * 2)
            return FinalityReject(pstrError, "transparent hard tally below 2/3 threshold");
        if (nTier == FINALITY_SOFT &&
            nTransparentWinningWeight * 2 < nTransparentActiveWeight)
            return FinalityReject(pstrError, "transparent soft tally below 1/2 threshold");
        if (nTier == FINALITY_TENTATIVE &&
            nTransparentWinningWeight * 3 < nTransparentActiveWeight)
            return FinalityReject(pstrError, "transparent tentative tally below 1/3 threshold");
    }
    return true;
}


// ---------------------------------------------------------------------------
// CFinalityVote
// ---------------------------------------------------------------------------

uint256 CFinalityVote::GetHash() const
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << nProofMode;
    ss << nEpoch;
    ss << hashBlock;
    ss << nHeight;
    ss << nTime;
    ss << nVoteWeight;
    ss << nReward;
    ss << nullifier;
    ss << vStakeProof;
    ss << vchPubKey;
    ss << privateProof;
    return ss.GetHash();
}

uint256 CFinalityVote::GetSignatureHash() const
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("Innova/FinalityVote/v2");
    ss << nProofMode;
    ss << nEpoch;
    ss << hashBlock;
    ss << nHeight;
    ss << nTime;
    ss << nVoteWeight;
    ss << nReward;
    ss << nullifier;
    ss << vStakeProof;
    if (IsPrivate())
        ss << privateProof;
    return ss.GetHash();
}

bool CFinalityVote::Sign(CKey& key)
{
    uint256 hash = GetSignatureHash();

    CPubKey pubkey = key.GetPubKey();
    vchPubKey = std::vector<unsigned char>(pubkey.begin(), pubkey.end());

    if (!key.Sign(hash, vchSig))
        return false;

    return true;
}

bool CFinalityVote::CheckSignature() const
{
    if (IsPrivate())
        return true;

    if (vchPubKey.empty() || vchSig.empty())
        return false;

    CPubKey pubkey(vchPubKey);
    if (!pubkey.IsValid())
        return false;

    uint256 hash = GetSignatureHash();
    if (!pubkey.Verify(hash, vchSig))
        return false;

    return true;
}

bool CFinalityVote::IsValid() const
{
    if (nProofMode != FINALITY_PROOF_TRANSPARENT &&
        nProofMode != FINALITY_PROOF_NULLSTAKE_V2 &&
        nProofMode != FINALITY_PROOF_NULLSTAKE_V3_COLD)
        return false;
    if (nEpoch < 0)
        return false;
    if (nHeight < 0)
        return false;
    if (nReward < 0)
        return false;
    if (hashBlock == 0)
        return false;
    if (nullifier == 0)
        return false;

    if (IsPrivate())
    {
        if (nVoteWeight != 0 || nReward != 0 || !vStakeProof.empty())
            return false;
        if (!vchPubKey.empty() || !vchSig.empty())
            return false;
        if (privateProof.nProofMode != nProofMode ||
            privateProof.nEpoch != nEpoch ||
            privateProof.hashEpochBlock != hashBlock ||
            privateProof.nullifier != nullifier)
            return false;
        if (!privateProof.IsValidBasic())
            return false;
    }
    else
    {
        if (nVoteWeight <= 0)
            return false;
        if (vStakeProof.empty() || vStakeProof.size() > FINALITY_MAX_STAKE_PROOFS)
            return false;
        if (vchPubKey.empty())
            return false;
    }
    if (!CheckSignature())
        return false;
    return true;
}

bool CFinalityVote::IsExpired(int64_t nNow) const
{
    return (nNow - nTime) > FINALITY_VOTE_MAX_AGE;
}


// ---------------------------------------------------------------------------
// CFinalityTracker
// ---------------------------------------------------------------------------

bool CFinalityTracker::CheckVote(const CFinalityVote& vote, CTxDB& txdb, std::string* pstrError) const
{
    auto reject = [&](const std::string& strReason) -> bool {
        if (pstrError)
            *pstrError = strReason;
        return false;
    };

    if (!vote.IsValid())
        return reject("invalid vote structure or signature");
    if (vote.nVoteWeight > MAX_MONEY)
        return reject("vote weight out of range");

    if (GetEpochForHeight(vote.nHeight) != vote.nEpoch ||
        GetEpochBoundaryHeight(vote.nEpoch, vote.nHeight) != vote.nHeight)
        return reject("vote height is not this epoch boundary");

    std::map<uint256, CBlockIndex*>::iterator miEpoch = mapBlockIndex.find(vote.hashBlock);
    if (miEpoch == mapBlockIndex.end())
        return reject("epoch block not found");
    CBlockIndex* pEpochBlock = miEpoch->second;
    if (pEpochBlock->nHeight != vote.nHeight)
        return reject("epoch block height mismatch");

    if (vote.IsPrivate())
    {
        if (pEpochBlock->nHeight < FORK_HEIGHT_DAG)
            return reject("private finality votes require DAG epoch mode");
        if (vote.privateProof.hashEpochBlock != vote.hashBlock ||
            vote.privateProof.nEpoch != vote.nEpoch ||
            vote.privateProof.nullifier != vote.nullifier)
            return reject("private finality proof binding mismatch");
        if (!vote.privateProof.IsValidBasic(pstrError))
            return false;

        int nFinalizedEpoch = GetEpochForHeight(GetFinalizedHeight());
        CEpochState finalizedEpochState;
        if (!g_dagManager.GetEpochState(nFinalizedEpoch, finalizedEpochState))
            return reject("private finality proof missing finalized epoch roots");
        if (vote.privateProof.hashCurveRoot != finalizedEpochState.hashCurveRoot ||
            vote.privateProof.hashNullifierRoot != finalizedEpochState.hashNullifierRoot)
            return reject("private finality proof not anchored to last finalized epoch root");

        CCurveTree finalizedCurveTree;
        if (!txdb.ReadCurveTreeAtEpoch(finalizedEpochState.nEpoch, finalizedCurveTree))
            return reject("private finality proof missing finalized epoch curve-tree snapshot");
        if (!finalizedCurveTree.IsEmpty())
            finalizedCurveTree.RebuildParentNodes();
        if (finalizedCurveTree.GetRoot() != finalizedEpochState.hashCurveRoot)
            return reject("private finality proof finalized epoch curve-tree root mismatch");
        if (!VerifyFCMPProof(finalizedCurveTree.GetRootNode(),
                             vote.privateProof.fcmpProof,
                             vote.privateProof.stakeWeightCommitment))
            return reject("private finality FCMP proof failed");
        if (vote.nProofMode == FINALITY_PROOF_NULLSTAKE_V2)
        {
            if (!VerifyNullStakeKernelProofV2(vote.privateProof.nullStakeV2Proof,
                                              vote.privateProof.stakeWeightCommitment,
                                              pEpochBlock->nBits))
                return reject("private finality NullStake V2 proof failed");
        }
        else if (vote.nProofMode == FINALITY_PROOF_NULLSTAKE_V3_COLD)
        {
            if (!VerifyNullStakeKernelProofV3(vote.privateProof.nullStakeV3Proof,
                                              vote.privateProof.stakeWeightCommitment,
                                              pEpochBlock->nBits))
                return reject("private finality NullStake V3 proof failed");
        }

        // Private votes are root-anchored and hidden-weight. Their exact
        // threshold/reward arithmetic is accepted only through an aggregate
        // tally certificate, so individual private votes must not expose clear
        // weight or clear reward.
        if (vote.nVoteWeight != 0 || vote.nReward != 0)
            return reject("private finality vote exposes clear weight or reward");
        return true;
    }

    CPubKey votePubKey(vote.vchPubKey);
    if (!votePubKey.IsValid())
        return reject("invalid vote pubkey");
    CKeyID keyID = votePubKey.GetID();

    CHashWriter expectedNullifier(SER_GETHASH, 0);
    expectedNullifier << vote.vchPubKey;
    expectedNullifier << vote.nEpoch;
    if (vote.nullifier != expectedNullifier.GetHash())
        return reject("nullifier mismatch");

    int64_t nExpectedReward = GetFinalityVoteReward(vote.nVoteWeight, GetEpochInterval(vote.nHeight));
    if (vote.nReward != nExpectedReward)
        return reject("vote reward mismatch");

    std::set<COutPoint> setSeenOutpoints;
    int64_t nVerifiedWeight = 0;

    for (const COutPoint& outpoint : vote.vStakeProof)
    {
        if (!setSeenOutpoints.insert(outpoint).second)
            return reject("duplicate stake proof outpoint");

        CTransaction txPrev;
        CTxIndex txindex;
        if (!txdb.ReadDiskTx(outpoint.hash, txPrev, txindex))
            return reject("stake proof transaction not found");
        if (outpoint.n >= txPrev.vout.size() || outpoint.n >= txindex.vSpent.size())
            return reject("stake proof outpoint out of range");
        if (!txindex.vSpent[outpoint.n].IsNull())
            return reject("stake proof outpoint is spent");

        const CTxOut& txout = txPrev.vout[outpoint.n];
        if (txout.nValue <= 0 || !MoneyRange(txout.nValue))
            return reject("stake proof value out of range");

        CTxDestination dest;
        if (!ExtractDestination(txout.scriptPubKey, dest))
            return reject("stake proof is not transparent P2PKH/P2PK");
        CKeyID outKeyID;
        if (!CBitcoinAddress(dest).GetKeyID(outKeyID))
            return reject("stake proof has no key id");
        if (outKeyID != keyID)
            return reject("stake proof key mismatch");

        CBlock blockFrom;
        if (!blockFrom.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
            return reject("stake proof block not readable");
        std::map<uint256, CBlockIndex*>::iterator miFrom = mapBlockIndex.find(blockFrom.GetHash());
        if (miFrom == mapBlockIndex.end())
            return reject("stake proof block index not found");
        CBlockIndex* pFrom = miFrom->second;
        if (pFrom->nHeight > vote.nHeight)
            return reject("stake proof created after epoch boundary");
        if (pFrom->GetBlockTime() + nStakeMinAge > pEpochBlock->GetBlockTime())
            return reject("stake proof is not mature at epoch boundary");

        if (nVerifiedWeight > MAX_MONEY - txout.nValue)
            nVerifiedWeight = MAX_MONEY;
        else
            nVerifiedWeight += txout.nValue;
    }

    if (nVerifiedWeight != vote.nVoteWeight)
        return reject("vote weight does not match stake proof value");

    return true;
}

bool CFinalityTracker::CheckTallyCertificate(const CFinalityTallyCertificate& cert, CTxDB& txdb, std::string* pstrError) const
{
    (void)txdb;

    auto reject = [&](const std::string& strReason) -> bool {
        if (pstrError)
            *pstrError = strReason;
        return false;
    };

    if (!cert.IsValidBasic(pstrError))
        return false;
    if (GetEpochForHeight(cert.nHeight) != cert.nEpoch ||
        GetEpochBoundaryHeight(cert.nEpoch, cert.nHeight) != cert.nHeight)
        return reject("tally certificate height is not this epoch boundary");

    std::map<uint256, CBlockIndex*>::iterator miEpoch = mapBlockIndex.find(cert.hashBlock);
    if (miEpoch == mapBlockIndex.end())
        return reject("tally certificate block not found");
    CBlockIndex* pEpochBlock = miEpoch->second;
    if (pEpochBlock->nHeight != cert.nHeight)
        return reject("tally certificate block height mismatch");
    if (cert.HasPrivateWeight() && pEpochBlock->nHeight < FORK_HEIGHT_DAG)
        return reject("private tally certificates require DAG epoch mode");
    if (cert.HasPrivateWeight())
    {
        int nFinalizedEpoch = GetEpochForHeight(GetFinalizedHeight());
        CEpochState finalizedEpochState;
        if (!g_dagManager.GetEpochState(nFinalizedEpoch, finalizedEpochState))
            return reject("private tally certificate missing finalized epoch roots");
        if (cert.hashCurveRoot != finalizedEpochState.hashCurveRoot ||
            cert.hashNullifierRoot != finalizedEpochState.hashNullifierRoot)
            return reject("private tally certificate not anchored to last finalized epoch root");
    }

    LOCK(cs_finality);

    int nMatchedVotes = 0;
    int nMatchedPrivateVotes = 0;
    int64_t nTransparentActiveWeight = 0;
    int64_t nTransparentWinningWeight = 0;
    int64_t nTransparentRewardBudget = 0;
    std::set<uint256> setExpectedTallyShareHashes;
    CPedersenCommitment privateActiveCommitment;
    CPedersenCommitment privateWinningCommitment;
    CPedersenCommitment privateRewardCommitment;
    bool fHavePrivateActiveCommitment = false;
    bool fHavePrivateWinningCommitment = false;
    bool fHavePrivateRewardCommitment = false;
    auto addCommitment = [](CPedersenCommitment& aggregate,
                            bool& fHaveAggregate,
                            const CPedersenCommitment& commitment) -> bool {
        if (commitment.IsNull())
            return false;
        if (!fHaveAggregate)
        {
            aggregate = commitment;
            fHaveAggregate = true;
            return true;
        }
        CPedersenCommitment combined;
        if (!AddCommitments(aggregate, commitment, combined))
            return false;
        aggregate = combined;
        return true;
    };

    for (const uint256& nf : cert.vVoteNullifiers)
    {
        CFinalityVote vote;
        auto itConnected = mapConnectedVotes.find(nf);
        if (itConnected != mapConnectedVotes.end())
            vote = itConnected->second;
        else
        {
            auto itPending = mapPendingVotes.find(nf);
            if (itPending == mapPendingVotes.end())
                return reject("tally certificate references unknown vote nullifier");
            vote = itPending->second;
        }

        if (vote.nEpoch != cert.nEpoch)
            return reject("tally certificate references vote from different epoch");
        if (vote.IsPrivate())
        {
            if (!cert.HasPrivateWeight())
                return reject("transparent tally certificate references private vote");
            if (vote.privateProof.hashCurveRoot != cert.hashCurveRoot ||
                vote.privateProof.hashNullifierRoot != cert.hashNullifierRoot)
                return reject("private tally certificate root mismatch");
            if (!addCommitment(privateActiveCommitment, fHavePrivateActiveCommitment,
                               vote.privateProof.stakeWeightCommitment))
                return reject("private active aggregate commitment failed");
            if (!addCommitment(privateRewardCommitment, fHavePrivateRewardCommitment,
                               vote.privateProof.rewardCommitment))
                return reject("private reward aggregate commitment failed");
            if (vote.hashBlock == cert.hashBlock &&
                !addCommitment(privateWinningCommitment, fHavePrivateWinningCommitment,
                               vote.privateProof.stakeWeightCommitment))
                return reject("private winning aggregate commitment failed");

            CFinalityTallyShare expectedShare;
            expectedShare.nVersion = 1;
            expectedShare.nEpoch = vote.nEpoch;
            expectedShare.voteNullifier = vote.nullifier;
            expectedShare.hashBlock = vote.hashBlock;
            expectedShare.stakeWeightCommitment = vote.privateProof.stakeWeightCommitment;
            expectedShare.rewardCommitment = vote.privateProof.rewardCommitment;
            expectedShare.vchShareProof = vote.privateProof.vchBindingProof;
            setExpectedTallyShareHashes.insert(expectedShare.GetHash());
        }
        if (vote.hashBlock == cert.hashBlock && !vote.IsPrivate())
        {
            if (nTransparentWinningWeight <= MAX_MONEY - vote.nVoteWeight)
                nTransparentWinningWeight += vote.nVoteWeight;
            else
                nTransparentWinningWeight = MAX_MONEY;
        }
        if (!vote.IsPrivate())
        {
            if (nTransparentActiveWeight <= MAX_MONEY - vote.nVoteWeight)
                nTransparentActiveWeight += vote.nVoteWeight;
            else
                nTransparentActiveWeight = MAX_MONEY;
            if (nTransparentRewardBudget <= MAX_MONEY - vote.nReward)
                nTransparentRewardBudget += vote.nReward;
            else
                nTransparentRewardBudget = MAX_MONEY;
        }
        else
        {
            nMatchedPrivateVotes++;
        }
        nMatchedVotes++;
    }

    if (nMatchedVotes == 0)
        return reject("tally certificate matched no votes");
    if (cert.HasPrivateWeight() && nMatchedPrivateVotes == 0)
        return reject("private tally certificate has no private votes");
    if (cert.nTransparentActiveWeight != nTransparentActiveWeight ||
        cert.nTransparentWinningWeight != nTransparentWinningWeight ||
        cert.nTransparentRewardBudget != nTransparentRewardBudget)
        return reject("tally certificate transparent aggregate mismatch");

    if (cert.HasPrivateWeight())
    {
        if (setExpectedTallyShareHashes.size() != cert.vTallyShareHashes.size())
            return reject("private tally certificate share set mismatch");
        for (const uint256& hashShare : cert.vTallyShareHashes)
        {
            if (!setExpectedTallyShareHashes.count(hashShare))
                return reject("private tally certificate references unknown tally share");
        }
        int64_t nPrivateActiveWeight = 0;
        int64_t nPrivateWinningWeight = 0;
        if (!VerifyFinalityAggregateThresholdProof(cert,
                                                   nTransparentActiveWeight,
                                                   nTransparentWinningWeight,
                                                   nPrivateActiveWeight,
                                                   nPrivateWinningWeight,
                                                   pstrError))
            return false;
        if (!fHavePrivateActiveCommitment ||
            !(cert.activeWeightCommitment == privateActiveCommitment))
            return reject("private active aggregate commitment does not match tallied votes");
        if (!fHavePrivateRewardCommitment ||
            !(cert.rewardBudgetCommitment == privateRewardCommitment))
            return reject("private reward aggregate commitment does not match tallied votes");
        if (fHavePrivateWinningCommitment)
        {
            if (!(cert.winningWeightCommitment == privateWinningCommitment))
                return reject("private winning aggregate commitment does not match tallied votes");
        }
        else if (nPrivateWinningWeight != 0)
        {
            return reject("private winning aggregate has no matching votes");
        }
        if (!VerifyFinalityRewardBudgetProof(cert,
                                             nPrivateActiveWeight,
                                             nTransparentRewardBudget,
                                             pstrError))
            return false;
    }
    else
    {
        if (!VerifyFinalityThresholdTier(cert.nTier, nTransparentActiveWeight, nTransparentWinningWeight))
            return reject("transparent tally certificate threshold mismatch");
    }
    return true;
}

bool CFinalityTracker::AddTallyCertificate(const CFinalityTallyCertificate& cert, bool fCheck, bool fRecordFinality)
{
    if (fCheck)
    {
        CTxDB txdb("r");
        std::string strError;
        if (!CheckTallyCertificate(cert, txdb, &strError))
        {
            if (fDebug)
                printf("AddTallyCertificate: rejected tally certificate: %s\n", strError.c_str());
            return false;
        }
    }

    LOCK(cs_finality);
    uint256 hashCert = cert.GetHash();

    if (!fRecordFinality)
    {
        mapPendingTallyCertificates[hashCert] = cert;
        return true;
    }

    if (mapConnectedTallyCertificates.count(hashCert))
        return true;

    mapConnectedTallyCertificates[hashCert] = cert;
    mapPendingTallyCertificates.erase(hashCert);
    mapEpochTallyCertificates[cert.nEpoch].push_back(cert);
    CheckFinalityThreshold(cert.nEpoch);
    return true;
}

bool CFinalityTracker::AddVote(const CFinalityVote& vote, bool fCheckStake, bool fRecordFinality)
{
    if (fCheckStake)
    {
        CTxDB txdb("r");
        std::string strError;
        if (!CheckVote(vote, txdb, &strError))
        {
            if (fDebug)
                printf("AddVote: rejected finality vote: %s\n", strError.c_str());
            return false;
        }
    }

    LOCK(cs_finality);

    uint256 hashVote = vote.GetHash();
    auto itNullifier = mapVoteHashByNullifier.find(vote.nullifier);
    if (itNullifier != mapVoteHashByNullifier.end() && itNullifier->second != hashVote)
        return false;

    CKeyID voterKeyID;
    bool fHasTransparentVoterKey = false;
    if (!vote.IsPrivate())
    {
        CPubKey regPubKey(vote.vchPubKey);
        if (!regPubKey.IsValid())
            return false;
        voterKeyID = regPubKey.GetID();
        fHasTransparentVoterKey = true;
    }

    if (itNullifier == mapVoteHashByNullifier.end())
    {
        // Reject votes for epochs far beyond current chain tip (DoS protection).
        if (!fRecordFinality)
        {
            int nCurrentEpoch = 0;
            CBlockIndex* pBest = pindexBest;
            if (pBest)
                nCurrentEpoch = GetEpochForHeight(pBest->nHeight);
            if (vote.nEpoch > nCurrentEpoch + 2)
                return false;
        }

        if (mapEpochVotes.count(vote.nEpoch) &&
            (int)mapEpochVotes[vote.nEpoch].size() >= FINALITY_MAX_VOTES)
            return false;

        mapVoteHashByNullifier[vote.nullifier] = hashVote;
        mapPendingVotes[vote.nullifier] = vote;
    }

    if (!fRecordFinality)
        return true;

    if (mapConnectedVotes.count(vote.nullifier))
        return true;

    if (fHasTransparentVoterKey &&
        mapEpochVoters.count(vote.nEpoch) && mapEpochVoters[vote.nEpoch].count(voterKeyID))
        return false;

    mapConnectedVotes[vote.nullifier] = vote;
    mapPendingVotes.erase(vote.nullifier);
    mapEpochVotes[vote.nEpoch].push_back(vote);
    if (fHasTransparentVoterKey)
        mapEpochVoters[vote.nEpoch].insert(voterKeyID);
    if (vote.IsPrivate())
        mapEpochPrivateVoteCount[vote.nEpoch]++;
    else
        mapEpochTransparentVoteCount[vote.nEpoch]++;

    int64_t nPrevWeight = mapEpochVoteWeight.count(vote.nEpoch)
                              ? mapEpochVoteWeight[vote.nEpoch]
                              : 0;
    if (!vote.IsPrivate() && vote.nVoteWeight > 0 && nPrevWeight <= MAX_MONEY - vote.nVoteWeight)
        mapEpochVoteWeight[vote.nEpoch] = nPrevWeight + vote.nVoteWeight;
    else if (!vote.IsPrivate())
        mapEpochVoteWeight[vote.nEpoch] = MAX_MONEY;

    CheckFinalityThreshold(vote.nEpoch);
    return true;
}

bool CFinalityTracker::IsFinalized(int nHeight) const
{
    LOCK(cs_finality);
    return nHeight <= nLastFinalizedHeight;
}

bool CFinalityTracker::CheckFinalityThreshold(int nEpoch)
{
    // Prefer aggregate tally certificates. They are the only consensus path
    // that can promote hidden-weight NullStake votes because individual
    // private votes intentionally reveal no clear stake or reward amounts.
    auto itCerts = mapEpochTallyCertificates.find(nEpoch);
    if (itCerts != mapEpochTallyCertificates.end() && !itCerts->second.empty())
    {
        const CFinalityTallyCertificate* pBestCert = NULL;
        for (const CFinalityTallyCertificate& cert : itCerts->second)
        {
            if (!pBestCert ||
                cert.nTier > pBestCert->nTier ||
                (cert.nTier == pBestCert->nTier && cert.GetHash() < pBestCert->GetHash()))
                pBestCert = &cert;
        }
        if (pBestCert)
        {
            int nVoterCount = (int)pBestCert->vVoteNullifiers.size();
            return ApplyFinalityDecision(nEpoch, pBestCert->hashBlock, pBestCert->nHeight,
                                         (FinalityTier)pBestCert->nTier, nVoterCount,
                                         pBestCert->nTransparentWinningWeight,
                                         pBestCert->nTransparentActiveWeight,
                                         true);
        }
    }

    int64_t nEpochVoteWeight = mapEpochVoteWeight.count(nEpoch) ? mapEpochVoteWeight[nEpoch] : 0;

    // Dynamic active-weight finality: the denominator is the active
    // committed vote weight included for this epoch. There is intentionally no
    // absolute stake floor after the DAG/finality fork.
    if (nEpochVoteWeight <= 0)
        return false;

    int nVoterCount = mapEpochVoters.count(nEpoch) ? (int)mapEpochVoters[nEpoch].size() : 0;
    if (nVoterCount < FINALITY_MIN_VOTERS)
    {
        nLastFinalityTier = FINALITY_NONE;
        return false;
    }

    if (!mapEpochVotes.count(nEpoch) || mapEpochVotes[nEpoch].empty())
        return false;

    // Select block with highest cumulative vote weight (deterministic tiebreaker by hash)
    std::map<uint256, int64_t> mapBlockVoteWeight;
    std::map<uint256, int> mapBlockHeight;
    for (const CFinalityVote& v : mapEpochVotes[nEpoch])
    {
        if (v.IsPrivate())
            continue;
        if (v.nVoteWeight > 0 && mapBlockVoteWeight[v.hashBlock] <= MAX_MONEY - v.nVoteWeight)
            mapBlockVoteWeight[v.hashBlock] += v.nVoteWeight;
        mapBlockHeight[v.hashBlock] = v.nHeight;
    }

    uint256 hashFinal = 0;
    int64_t nBestBlockWeight = 0;
    for (const auto& p : mapBlockVoteWeight)
    {
        if (p.second > nBestBlockWeight ||
            (p.second == nBestBlockWeight && (hashFinal == 0 || p.first < hashFinal)))
        {
            nBestBlockWeight = p.second;
            hashFinal = p.first;
        }
    }

    if (hashFinal == 0)
        return false;

    // Determine finality tier based on the winning block's weight vs total
    // active epoch vote weight.
    FinalityTier tier = FINALITY_NONE;
    if (nBestBlockWeight * 3 >= nEpochVoteWeight * 2)      // >= 2/3
        tier = FINALITY_HARD;
    else if (nBestBlockWeight * 2 >= nEpochVoteWeight)       // >= 1/2
        tier = FINALITY_SOFT;
    else if (nBestBlockWeight * 3 >= nEpochVoteWeight)       // >= 1/3
        tier = FINALITY_TENTATIVE;

    int nFinalHeight = mapBlockHeight.count(hashFinal) ? mapBlockHeight[hashFinal] : 0;
    return ApplyFinalityDecision(nEpoch, hashFinal, nFinalHeight, tier, nVoterCount,
                                 nBestBlockWeight, nEpochVoteWeight, false);
}

bool CFinalityTracker::ApplyFinalityDecision(int nEpoch, const uint256& hashFinal, int nFinalHeight,
                                             FinalityTier tier, int nVoterCount,
                                             int64_t nBestBlockWeight, int64_t nEpochVoteWeight,
                                             bool fFromCertificate)
{
    nLastFinalityTier = tier;

    if (tier >= FINALITY_HARD)
    {
        if (nLastHardEpoch == nEpoch)
        {
            // Same epoch was already counted; keep current streak.
        }
        else if (nLastHardEpoch >= 0 && nEpoch == nLastHardEpoch + 1)
        {
            nConsecutiveHardEpochs++;
            nLastHardEpoch = nEpoch;
        }
        else
        {
            nConsecutiveHardEpochs = 1;
            nLastHardEpoch = nEpoch;
        }

        if (nFinalHeight > nPendingFinalizedHeight)
        {
            nPendingFinalizedHeight = nFinalHeight;
            hashPendingFinalized = hashFinal;
        }

        if (nConsecutiveHardEpochs >= FINALITY_CONFIRMATION_EPOCHS &&
            nPendingFinalizedHeight > nLastFinalizedHeight)
        {
            nLastFinalizedHeight = nPendingFinalizedHeight;
            hashLastFinalized = hashPendingFinalized;
            printf("FINALITY: CONFIRMED at height %d after %d consecutive HARD epochs (hash=%s, voters=%d, source=%s)\n",
                   nLastFinalizedHeight, nConsecutiveHardEpochs,
                   hashLastFinalized.ToString().substr(0, 20).c_str(),
                   nVoterCount,
                   fFromCertificate ? "tally-certificate" : "transparent-votes");
        }
        else
        {
            printf("FINALITY: Epoch %d HARD (%d/%d confirmations) at height %d (block_weight=%s, epoch_weight=%s, voters=%d, source=%s)\n",
                   nEpoch, nConsecutiveHardEpochs, FINALITY_CONFIRMATION_EPOCHS,
                   nFinalHeight,
                   FormatMoney(nBestBlockWeight).c_str(),
                   FormatMoney(nEpochVoteWeight).c_str(),
                   nVoterCount,
                   fFromCertificate ? "tally-certificate" : "transparent-votes");
        }
        return nConsecutiveHardEpochs >= FINALITY_CONFIRMATION_EPOCHS;
    }
    else
    {
        // Non-HARD epoch breaks the consecutive streak
        nConsecutiveHardEpochs = 0;
        nLastHardEpoch = -1;

        if (tier >= FINALITY_SOFT)
        {
            printf("FINALITY: Epoch %d SOFT at height %d (block_weight=%s, epoch_weight=%s, voters=%d, source=%s)\n",
                   nEpoch, nFinalHeight,
                   FormatMoney(nBestBlockWeight).c_str(),
                   FormatMoney(nEpochVoteWeight).c_str(),
                   nVoterCount,
                   fFromCertificate ? "tally-certificate" : "transparent-votes");
        }
        else if (tier >= FINALITY_TENTATIVE && fDebug)
        {
            printf("FINALITY: Epoch %d tentative at height %d (voters=%d, source=%s)\n",
                   nEpoch, nFinalHeight, nVoterCount,
                   fFromCertificate ? "tally-certificate" : "transparent-votes");
        }
    }

    return false;
}

std::vector<CFinalityVote> CFinalityTracker::GetEpochVotes(int nEpoch) const
{
    LOCK(cs_finality);
    auto it = mapEpochVotes.find(nEpoch);
    if (it != mapEpochVotes.end())
        return it->second;
    return std::vector<CFinalityVote>();
}

int64_t CFinalityTracker::GetEpochVoteWeight(int nEpoch) const
{
    LOCK(cs_finality);
    auto it = mapEpochVoteWeight.find(nEpoch);
    if (it != mapEpochVoteWeight.end())
        return it->second;
    return 0;
}

int CFinalityTracker::GetEpochVoteCount(int nEpoch) const
{
    LOCK(cs_finality);
    auto it = mapEpochVotes.find(nEpoch);
    if (it != mapEpochVotes.end())
        return (int)it->second.size();
    return 0;
}

int CFinalityTracker::GetEpochVoterCount(int nEpoch) const
{
    LOCK(cs_finality);
    auto it = mapEpochVoters.find(nEpoch);
    if (it != mapEpochVoters.end())
        return (int)it->second.size();
    return 0;
}

void CFinalityTracker::GetEpochVoteModeCounts(int nEpoch, int& nTransparentVotes, int& nPrivateVotes) const
{
    LOCK(cs_finality);
    std::map<int, int>::const_iterator itTransparent = mapEpochTransparentVoteCount.find(nEpoch);
    std::map<int, int>::const_iterator itPrivate = mapEpochPrivateVoteCount.find(nEpoch);
    nTransparentVotes = (itTransparent != mapEpochTransparentVoteCount.end()) ? itTransparent->second : 0;
    nPrivateVotes = (itPrivate != mapEpochPrivateVoteCount.end()) ? itPrivate->second : 0;
}

std::vector<CFinalityTallyCertificate> CFinalityTracker::GetEpochTallyCertificates(int nEpoch) const
{
    LOCK(cs_finality);
    auto it = mapEpochTallyCertificates.find(nEpoch);
    if (it != mapEpochTallyCertificates.end())
        return it->second;
    return std::vector<CFinalityTallyCertificate>();
}

std::vector<CKeyID> CFinalityTracker::GetEpochVoters(int nEpoch) const
{
    LOCK(cs_finality);
    std::vector<CKeyID> vVoters;
    auto it = mapEpochVoters.find(nEpoch);
    if (it == mapEpochVoters.end())
        return vVoters;
    vVoters.insert(vVoters.end(), it->second.begin(), it->second.end());
    return vVoters;
}

int CFinalityTracker::GetPendingVoteCount() const
{
    LOCK(cs_finality);
    return (int)mapPendingVotes.size();
}

int64_t CFinalityTracker::GetPendingRewardTotal() const
{
    LOCK(cs_finality);
    int64_t nTotal = 0;
    for (const auto& pair : mapPendingVotes)
    {
        if (pair.second.nReward > 0 && nTotal <= MAX_MONEY - pair.second.nReward)
            nTotal += pair.second.nReward;
        else
            nTotal = MAX_MONEY;
    }
    return nTotal;
}

std::vector<CFinalityVote> CFinalityTracker::GetPendingVotesForBlock(int nBlockHeight, unsigned int nMaxVotes) const
{
    LOCK(cs_finality);

    std::vector<CFinalityVote> vVotes;
    int nBlockEpoch = GetEpochForHeight(nBlockHeight);
    for (const auto& pair : mapPendingVotes)
    {
        const CFinalityVote& vote = pair.second;
        if (vote.nEpoch > nBlockEpoch)
            continue;
        if (vote.nEpoch + 2 < nBlockEpoch)
            continue;
        vVotes.push_back(vote);
        if (vVotes.size() >= nMaxVotes)
            break;
    }
    return vVotes;
}

std::vector<CFinalityTallyCertificate> CFinalityTracker::GetPendingTallyCertificatesForBlock(int nBlockHeight, unsigned int nMaxCerts) const
{
    LOCK(cs_finality);

    std::vector<CFinalityTallyCertificate> vCerts;
    int nBlockEpoch = GetEpochForHeight(nBlockHeight);
    for (const auto& pair : mapPendingTallyCertificates)
    {
        const CFinalityTallyCertificate& cert = pair.second;
        if (cert.nEpoch > nBlockEpoch)
            continue;
        if (cert.nEpoch + 2 < nBlockEpoch)
            continue;
        vCerts.push_back(cert);
        if (vCerts.size() >= nMaxCerts)
            break;
    }
    return vCerts;
}

bool CFinalityTracker::ConnectBlockVotes(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityVote>& vVotes)
{
    if (vVotes.empty())
        return true;

    std::set<uint256> setBlockNullifiers;
    for (const CFinalityVote& vote : vVotes)
    {
        if (!setBlockNullifiers.insert(vote.nullifier).second)
            return false;

        std::string strError;
        if (!CheckVote(vote, txdb, &strError))
        {
            if (fDebug)
                printf("ConnectBlockVotes: rejected vote in block %s: %s\n",
                       hashBlock.ToString().substr(0,20).c_str(), strError.c_str());
            return false;
        }

        if (!AddVote(vote, false, true))
            return false;
        if (!txdb.WriteFinalityVote(vote.nullifier, vote))
            return false;
    }

    LOCK(cs_finality);
    std::vector<uint256>& vNullifiers = mapBlockConnectedVoteNullifiers[hashBlock];
    for (const CFinalityVote& vote : vVotes)
        vNullifiers.push_back(vote.nullifier);

    return true;
}

bool CFinalityTracker::DisconnectBlockVotes(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityVote>& vVotes)
{
    if (vVotes.empty())
        return true;

    LOCK(cs_finality);
    for (const CFinalityVote& vote : vVotes)
    {
        txdb.EraseFinalityVote(vote.nullifier);

        mapPendingVotes.erase(vote.nullifier);
        mapConnectedVotes.erase(vote.nullifier);
        mapVoteHashByNullifier.erase(vote.nullifier);
        if (vote.IsPrivate())
        {
            if (mapEpochPrivateVoteCount.count(vote.nEpoch) && mapEpochPrivateVoteCount[vote.nEpoch] > 0)
                mapEpochPrivateVoteCount[vote.nEpoch]--;
        }
        else
        {
            if (mapEpochTransparentVoteCount.count(vote.nEpoch) && mapEpochTransparentVoteCount[vote.nEpoch] > 0)
                mapEpochTransparentVoteCount[vote.nEpoch]--;
        }

        auto itVotes = mapEpochVotes.find(vote.nEpoch);
        if (itVotes != mapEpochVotes.end())
        {
            uint256 hashVote = vote.GetHash();
            auto& vEpochVotes = itVotes->second;
            vEpochVotes.erase(std::remove_if(vEpochVotes.begin(), vEpochVotes.end(),
                                             [&](const CFinalityVote& v) { return v.GetHash() == hashVote; }),
                              vEpochVotes.end());
            if (vEpochVotes.empty())
                mapEpochVotes.erase(itVotes);
        }

        CPubKey pubkey(vote.vchPubKey);
        if (!vote.IsPrivate() && pubkey.IsValid())
        {
            auto itVoters = mapEpochVoters.find(vote.nEpoch);
            if (itVoters != mapEpochVoters.end())
            {
                itVoters->second.erase(pubkey.GetID());
                if (itVoters->second.empty())
                    mapEpochVoters.erase(itVoters);
            }
        }

        int64_t nPrevWeight = mapEpochVoteWeight.count(vote.nEpoch) ? mapEpochVoteWeight[vote.nEpoch] : 0;
        if (nPrevWeight > vote.nVoteWeight)
            mapEpochVoteWeight[vote.nEpoch] = nPrevWeight - vote.nVoteWeight;
        else
            mapEpochVoteWeight.erase(vote.nEpoch);
    }
    mapBlockConnectedVoteNullifiers.erase(hashBlock);
    return true;
}

bool CFinalityTracker::ConnectBlockTallyCertificates(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityTallyCertificate>& vCerts)
{
    if (vCerts.empty())
        return true;

    std::set<uint256> setBlockCerts;
    for (const CFinalityTallyCertificate& cert : vCerts)
    {
        uint256 hashCert = cert.GetHash();
        if (!setBlockCerts.insert(hashCert).second)
            return false;

        std::string strError;
        if (!CheckTallyCertificate(cert, txdb, &strError))
        {
            if (fDebug)
                printf("ConnectBlockTallyCertificates: rejected cert in block %s: %s\n",
                       hashBlock.ToString().substr(0,20).c_str(), strError.c_str());
            return false;
        }

        if (!AddTallyCertificate(cert, false, true))
            return false;
        if (!txdb.WriteFinalityTallyCertificate(hashCert, cert))
            return false;
    }

    LOCK(cs_finality);
    std::vector<uint256>& vHashes = mapBlockConnectedTallyCertificates[hashBlock];
    for (const CFinalityTallyCertificate& cert : vCerts)
        vHashes.push_back(cert.GetHash());

    return true;
}

bool CFinalityTracker::DisconnectBlockTallyCertificates(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityTallyCertificate>& vCerts)
{
    if (vCerts.empty())
        return true;

    LOCK(cs_finality);
    for (const CFinalityTallyCertificate& cert : vCerts)
    {
        uint256 hashCert = cert.GetHash();
        txdb.EraseFinalityTallyCertificate(hashCert);
        mapPendingTallyCertificates.erase(hashCert);
        mapConnectedTallyCertificates.erase(hashCert);

        auto itCerts = mapEpochTallyCertificates.find(cert.nEpoch);
        if (itCerts != mapEpochTallyCertificates.end())
        {
            auto& vEpochCerts = itCerts->second;
            vEpochCerts.erase(std::remove_if(vEpochCerts.begin(), vEpochCerts.end(),
                                             [&](const CFinalityTallyCertificate& c) { return c.GetHash() == hashCert; }),
                              vEpochCerts.end());
            if (vEpochCerts.empty())
                mapEpochTallyCertificates.erase(itCerts);
        }
    }
    mapBlockConnectedTallyCertificates.erase(hashBlock);
    return true;
}

bool CFinalityTracker::LoadVotes(CTxDB& txdb)
{
    std::map<uint256, CFinalityVote> mapVotes;
    if (!txdb.IterateFinalityVotes(mapVotes))
        return false;

    for (const auto& pair : mapVotes)
        AddVote(pair.second, false, true);

    if (!mapVotes.empty())
        printf("LoadFinalityVotes: loaded %d connected finality votes\n", (int)mapVotes.size());
    return true;
}

bool CFinalityTracker::LoadTallyCertificates(CTxDB& txdb)
{
    std::map<uint256, CFinalityTallyCertificate> mapCerts;
    if (!txdb.IterateFinalityTallyCertificates(mapCerts))
        return false;

    for (const auto& pair : mapCerts)
        AddTallyCertificate(pair.second, false, true);

    if (!mapCerts.empty())
        printf("LoadFinalityTallyCertificates: loaded %d connected tally certificates\n", (int)mapCerts.size());
    return true;
}

void CFinalityTracker::PruneOldEpochs(int nCurrentEpoch)
{
    LOCK(cs_finality);
    int nMinEpoch = nCurrentEpoch - 10;
    if (nMinEpoch < 0)
        nMinEpoch = 0;

    for (auto it = mapEpochVotes.begin(); it != mapEpochVotes.end(); )
    {
        if (it->first < nMinEpoch)
        {
            for (const CFinalityVote& vote : it->second)
            {
                mapVoteHashByNullifier.erase(vote.nullifier);
                mapPendingVotes.erase(vote.nullifier);
                mapConnectedVotes.erase(vote.nullifier);
            }
            mapEpochVoteWeight.erase(it->first);
            mapEpochVoters.erase(it->first);
            mapEpochTransparentVoteCount.erase(it->first);
            mapEpochPrivateVoteCount.erase(it->first);
            mapEpochTallyCertificates.erase(it->first);
            it = mapEpochVotes.erase(it);
        }
        else
        {
            ++it;
        }
    }
}


// ---------------------------------------------------------------------------
// P2P Message Processing
// ---------------------------------------------------------------------------

bool ProcessMessageFinality(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv)
{
    if (strCommand == "fvote")
    {
        CFinalityVote vote;
        vRecv >> vote;

        // Cheap checks first (before expensive ECDSA signature verification)
        if (vote.nEpoch < 0 || vote.nHeight < 0)
            return false;
        if (vote.hashBlock == 0 || vote.nullifier == 0)
            return false;
        if (!vote.IsPrivate() && (vote.nVoteWeight <= 0 || vote.vchPubKey.empty()))
            return false;
        if (vote.IsPrivate() && (vote.nVoteWeight != 0 || vote.nReward != 0 || !vote.vchPubKey.empty()))
            return false;
        // Reject future-timestamped votes (prevents permanent nullifier squatting)
        if (vote.nTime > GetAdjustedTime() + 300)
            return false;
        if (vote.IsExpired(GetAdjustedTime()))
            return false;

        // Epoch range check (cheap: avoids ECDSA on far-future votes)
        {
            int nCurrentEpoch = 0;
            CBlockIndex* pBest = pindexBest;
            if (pBest)
                nCurrentEpoch = GetEpochForHeight(pBest->nHeight);
            if (vote.nEpoch > nCurrentEpoch + 2)
                return false;
        }

        // Now do expensive ECDSA signature verification
        if (!vote.IsValid())
        {
            printf("ProcessMessageFinality: invalid vote from peer %s\n",
                   pfrom->addr.ToString().c_str());
            return false;
        }

        if (g_finalityTracker.AddVote(vote))
        {
            LOCK(cs_vNodes);
            for (CNode* pnode : vNodes)
            {
                if (pnode == pfrom)
                    continue;
                pnode->PushMessage("fvote", vote);
            }
        }

        return true;
    }
    else if (strCommand == "ftcert")
    {
        CFinalityTallyCertificate cert;
        vRecv >> cert;

        if (cert.nEpoch < 0 || cert.nHeight < 0 || cert.hashBlock == 0)
            return false;
        if (!cert.IsValidBasic())
            return false;

        int nCurrentEpoch = 0;
        {
            CBlockIndex* pBest = pindexBest;
            if (pBest)
                nCurrentEpoch = GetEpochForHeight(pBest->nHeight);
        }
        if (cert.nEpoch > nCurrentEpoch + 2)
            return false;

        if (g_finalityTracker.AddTallyCertificate(cert))
        {
            LOCK(cs_vNodes);
            for (CNode* pnode : vNodes)
            {
                if (pnode == pfrom)
                    continue;
                pnode->PushMessage("ftcert", cert);
            }
        }

        return true;
    }
    else if (strCommand == "fvreq")
    {
        int nEpoch;
        vRecv >> nEpoch;

        // Validate epoch range (prevent amplification from arbitrary epoch requests)
        int nCurrentEpoch = 0;
        {
            CBlockIndex* pBest = pindexBest;
            if (pBest)
                nCurrentEpoch = GetEpochForHeight(pBest->nHeight);
        }
        if (nEpoch < 0 || nEpoch > nCurrentEpoch + 1)
            return false;

        // Rate limit: max 1 fvreq per 5 seconds per peer
        static std::map<CAddress, int64_t> mapLastFvreq;
        int64_t nNow = GetTimeMillis();
        if (mapLastFvreq.count(pfrom->addr) && nNow - mapLastFvreq[pfrom->addr] < 5000)
            return false;
        mapLastFvreq[pfrom->addr] = nNow;

        // Bound map size to prevent memory growth from many peers
        if (mapLastFvreq.size() > 1000)
            mapLastFvreq.clear();

        std::vector<CFinalityVote> votes = g_finalityTracker.GetEpochVotes(nEpoch);
        for (const CFinalityVote& vote : votes)
        {
            pfrom->PushMessage("fvote", vote);
        }
        std::vector<CFinalityTallyCertificate> certs = g_finalityTracker.GetEpochTallyCertificates(nEpoch);
        for (const CFinalityTallyCertificate& cert : certs)
        {
            pfrom->PushMessage("ftcert", cert);
        }

        return true;
    }

    return false;
}


// ---------------------------------------------------------------------------
// Finality Voter Thread
// ---------------------------------------------------------------------------

void ThreadFinalityVoter(void* parg)
{
    printf("ThreadFinalityVoter started\n");

    if (GetBoolArg("-nofinalityvoting", false))
    {
        printf("ThreadFinalityVoter: voting disabled\n");
        return;
    }

    int nLastEpochVoted = -1;

    while (!fShutdown)
    {
        MilliSleep(5000);

        if (fShutdown)
            break;

        if (IsInitialBlockDownload())
            continue;

        int nCurrentHeight = 0;
        {
            LOCK(cs_main);
            if (!pindexBest)
                continue;
            nCurrentHeight = pindexBest->nHeight;
        }

        if (nCurrentHeight < FORK_HEIGHT_FINALITY)
            continue;

        int nCurrentEpoch = GetEpochForHeight(nCurrentHeight);
        int nEpochHeight = GetEpochBoundaryHeight(nCurrentEpoch, nCurrentHeight);
        int nEpochProgress = nCurrentHeight - nEpochHeight;

        if (nEpochProgress >= FINALITY_VOTE_WINDOW)
            continue;

        if (nCurrentEpoch == nLastEpochVoted)
            continue;

        if (ProduceFinalityVote())
        {
            nLastEpochVoted = nCurrentEpoch;
            g_finalityTracker.PruneOldEpochs(nCurrentEpoch);
        }
    }

    printf("ThreadFinalityVoter stopped\n");
}

static std::string GetFinalityVoteModeArg()
{
    std::string strMode = GetArg("-finalityvotemode", "auto");
    std::transform(strMode.begin(), strMode.end(), strMode.begin(), ::tolower);
    if (strMode != "auto" && strMode != "transparent" &&
        strMode != "nullstake" && strMode != "nullstakecold")
    {
        printf("WARNING: Unknown -finalityvotemode '%s', using auto\n", strMode.c_str());
        strMode = "auto";
    }
    return strMode;
}

static bool SerializeBindingProof(const CBindingSignature& sig,
                                  std::vector<unsigned char>& vchOut)
{
    if (sig.IsNull())
        return false;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << sig;
    vchOut.assign(ss.begin(), ss.end());
    return !vchOut.empty();
}

static bool ProducePrivateNullStakeFinalityVote(CTxDB& txdb,
                                                CBlockIndex* pEpochBlock,
                                                int nCurrentEpoch,
                                                int nEpochHeight)
{
    if (!pEpochBlock)
        return false;

    CEpochState finalizedEpochState;
    if (!g_dagManager.GetLastFinalizedEpochState(finalizedEpochState))
        return false;

    CCurveTree finalizedCurveTree;
    if (!txdb.ReadCurveTreeAtEpoch(finalizedEpochState.nEpoch, finalizedCurveTree))
        return false;
    if (!finalizedCurveTree.IsEmpty())
        finalizedCurveTree.RebuildParentNodes();
    if (finalizedCurveTree.GetRoot() == 0 ||
        finalizedCurveTree.GetRoot() != finalizedEpochState.hashCurveRoot)
        return false;

    LOCK(pwalletMain->cs_shielded);
    if (pwalletMain->mapShieldedSpendingKeys.empty())
        return false;

    for (std::map<CShieldedPaymentAddress, CShieldedSpendingKey>::iterator itKey =
             pwalletMain->mapShieldedSpendingKeys.begin();
         itKey != pwalletMain->mapShieldedSpendingKeys.end(); ++itKey)
    {
        CShieldedFullViewingKey fvk;
        if (!DeriveShieldedFullViewingKey(itKey->second, fvk))
            continue;

        for (size_t i = 0; i < pwalletMain->vShieldedNotes.size(); i++)
        {
            CWallet::CShieldedWalletNote& wnote = pwalletMain->vShieldedNotes[i];
            if (wnote.fSpent || wnote.note.nValue <= 0 || wnote.nHeight <= 0)
                continue;

            CBlockIndex* pNoteBlock = pindexBest;
            while (pNoteBlock && pNoteBlock->nHeight > wnote.nHeight)
                pNoteBlock = pNoteBlock->pprev;
            if (!pNoteBlock || pNoteBlock->nHeight != wnote.nHeight)
                continue;

            unsigned int nBlockTimeFrom = pNoteBlock->GetBlockTime();
            if (nBlockTimeFrom + nStakeMinAge > (unsigned int)pEpochBlock->GetBlockTime())
                continue;

            if (wnote.note.vchBlind.empty())
                wnote.note.GenerateBlindingFactor();

            CPedersenCommitment stakeCommitment;
            if (!wnote.note.GetPedersenCommitment(stakeCommitment))
                continue;

            int64_t nLeafIdx = finalizedCurveTree.FindLeafIndex(stakeCommitment);
            if (nLeafIdx < 0)
                continue;

            CFCMPProof fcmpProof;
            if (!CreateFCMPProof(finalizedCurveTree, (uint64_t)nLeafIdx,
                                 wnote.note.vchBlind, wnote.note.nValue,
                                 stakeCommitment, fcmpProof))
                continue;

            uint64_t nStakeModifier = pEpochBlock->pprev ?
                                      pEpochBlock->pprev->nStakeModifier :
                                      pEpochBlock->nStakeModifier;
            unsigned int nTxPrevOffset = 0;
            unsigned int nVoutN = wnote.nPosition;
            unsigned int nTxTimePrev = pNoteBlock->nTime;
            unsigned int nBaseTime = (unsigned int)GetAdjustedTime();
            if (nBaseTime < (unsigned int)pEpochBlock->GetBlockTime())
                nBaseTime = (unsigned int)pEpochBlock->GetBlockTime();

            for (unsigned int n = 0; n < 60; n++)
            {
                unsigned int nTimeTx = nBaseTime + n;
                int64_t nWeight = GetWeight((int64_t)nBlockTimeFrom, (int64_t)nTimeTx);
                if (!CheckShieldedStakeKernelHashV2(pEpochBlock->nBits,
                                                    nStakeModifier,
                                                    nBlockTimeFrom,
                                                    nTxPrevOffset,
                                                    nTxTimePrev,
                                                    nVoutN,
                                                    nTimeTx,
                                                    wnote.note.nValue,
                                                    nWeight))
                    continue;

                CNullStakeKernelProofV2 nullStakeProof;
                if (!CreateNullStakeKernelProofV2(wnote.note.nValue,
                                                  wnote.note.vchBlind,
                                                  stakeCommitment,
                                                  pEpochBlock->nBits,
                                                  nStakeModifier,
                                                  nBlockTimeFrom,
                                                  nTxPrevOffset,
                                                  nTxTimePrev,
                                                  nVoutN,
                                                  nTimeTx,
                                                  nullStakeProof))
                    continue;

                std::vector<unsigned char> vchRewardBlind;
                if (!GenerateBlindingFactor(vchRewardBlind))
                    continue;

                int64_t nPrivateReward = GetFinalityVoteReward(wnote.note.nValue,
                                                                GetEpochInterval(nEpochHeight));
                CPedersenCommitment rewardCommitment;
                if (!CreatePedersenCommitment(nPrivateReward, vchRewardBlind, rewardCommitment))
                    continue;

                uint256 baseNullifier = wnote.note.GetNullifier(fvk.nk);
                CHashWriter nullifierHasher(SER_GETHASH, 0);
                nullifierHasher << std::string("Innova/Finality/PrivateNullifier/v1");
                nullifierHasher << baseNullifier;
                nullifierHasher << nCurrentEpoch;

                CFinalityVote vote;
                vote.nProofMode = FINALITY_PROOF_NULLSTAKE_V2;
                vote.nEpoch = nCurrentEpoch;
                vote.hashBlock = pEpochBlock->GetBlockHash();
                vote.nHeight = nEpochHeight;
                vote.nTime = nTimeTx;
                vote.nVoteWeight = 0;
                vote.nReward = 0;
                vote.nullifier = nullifierHasher.GetHash();

                vote.privateProof.nVersion = 1;
                vote.privateProof.nProofMode = FINALITY_PROOF_NULLSTAKE_V2;
                vote.privateProof.nEpoch = nCurrentEpoch;
                vote.privateProof.hashEpochBlock = vote.hashBlock;
                vote.privateProof.hashCurveRoot = finalizedEpochState.hashCurveRoot;
                vote.privateProof.hashNullifierRoot = finalizedEpochState.hashNullifierRoot;
                vote.privateProof.nullifier = vote.nullifier;
                vote.privateProof.stakeWeightCommitment = stakeCommitment;
                vote.privateProof.rewardCommitment = rewardCommitment;
                vote.privateProof.fcmpProof = fcmpProof;
                vote.privateProof.nullStakeV2Proof = nullStakeProof;
                vote.privateProof.vchRewardOutputCommitment = rewardCommitment.vchCommitment;

                CHashWriter bindingHasher(SER_GETHASH, 0);
                bindingHasher << std::string("Innova/Finality/PrivateRewardBinding/v1");
                bindingHasher << vote.nullifier;
                bindingHasher << rewardCommitment;
                CBindingSignature bindingSig;
                std::vector<std::vector<unsigned char> > vInputBlinds(1, wnote.note.vchBlind);
                std::vector<std::vector<unsigned char> > vOutputBlinds(1, vchRewardBlind);
                if (!CreateBindingSignature(vInputBlinds, vOutputBlinds,
                                            bindingHasher.GetHash(), bindingSig) ||
                    !SerializeBindingProof(bindingSig, vote.privateProof.vchBindingProof))
                {
                    vote.privateProof.vchBindingProof.resize(64);
                    GetRandBytes(vote.privateProof.vchBindingProof.data(),
                                 (int)vote.privateProof.vchBindingProof.size());
                }

                if (!g_finalityTracker.AddVote(vote))
                    continue;

                printf("ProduceFinalityVote: private nullstake epoch=%d height=%d note=%s\n",
                       nCurrentEpoch, nEpochHeight,
                       wnote.txhash.ToString().substr(0,10).c_str());

                LOCK(cs_vNodes);
                for (CNode* pnode : vNodes)
                {
                    pnode->PushMessage("fvote", vote);
                }
                return true;
            }
        }
    }

    return false;
}


bool ProduceFinalityVote()
{
    if (!pwalletMain)
        return false;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (!pindexBest)
        return false;

    int nCurrentHeight = pindexBest->nHeight;
    int nCurrentEpoch = GetEpochForHeight(nCurrentHeight);

    // IDAG Phase 2: If DAG is active, vote for DAG-selected best tip
    int nEpochHeight = GetEpochBoundaryHeight(nCurrentEpoch, nCurrentHeight);
    CBlockIndex* pEpochBlock = NULL;
    if (nCurrentHeight >= FORK_HEIGHT_DAG)
    {
        CBlockIndex* pDAGTip = g_dagManager.SelectBestDAGTip();
        if (pDAGTip)
        {
            // Walk back to epoch boundary on the DAG selected-parent chain.
            CBlockIndex* pWalk = pDAGTip;
            std::set<uint256> setVisited;
            while (pWalk && pWalk->nHeight > nEpochHeight && pWalk->phashBlock)
            {
                if (!setVisited.insert(pWalk->GetBlockHash()).second)
                    break;
                uint256 hashParent = g_dagManager.GetSelectedParent(pWalk->GetBlockHash());
                std::map<uint256, CBlockIndex*>::iterator miParent = mapBlockIndex.find(hashParent);
                if (miParent == mapBlockIndex.end())
                    break;
                pWalk = miParent->second;
            }
            if (pWalk && pWalk->nHeight == nEpochHeight)
                pEpochBlock = pWalk;
        }
    }
    if (!pEpochBlock)
        pEpochBlock = FindBlockByHeight(nEpochHeight);
    if (!pEpochBlock)
        return false;

    std::string strVoteMode = GetFinalityVoteModeArg();
    bool fAllowPrivateV2 = (strVoteMode == "auto" || strVoteMode == "nullstake");
    bool fAllowTransparent = (strVoteMode == "auto" || strVoteMode == "transparent");

    struct CFinalityVoteCoinGroup
    {
        int64_t nWeight;
        std::vector<COutPoint> vOutpoints;
        CKey key;
        bool fHaveKey;
        CFinalityVoteCoinGroup() : nWeight(0), fHaveKey(false) {}
    };

    std::map<CKeyID, CFinalityVoteCoinGroup> mapGroups;
    CTxDB txdb("r");
    if (fAllowPrivateV2 && ProducePrivateNullStakeFinalityVote(txdb, pEpochBlock,
                                                               nCurrentEpoch, nEpochHeight))
        return true;
    if (!fAllowTransparent)
        return false;

    std::vector<COutput> vCoins;
    pwalletMain->AvailableCoins(vCoins);

    for (const COutput& out : vCoins)
    {
        const CWalletTx* wtx = out.tx;
        unsigned int nOut = out.i;
        if (!wtx || nOut >= wtx->vout.size())
            continue;
        if ((int)out.nDepth <= 0)
            continue;

        const CTxOut& txout = wtx->vout[nOut];
        if (txout.nValue <= 0 || txout.nValue > MAX_MONEY)
            continue;

        CTxDestination dest;
        if (!ExtractDestination(txout.scriptPubKey, dest))
            continue;
        CKeyID keyID;
        if (!CBitcoinAddress(dest).GetKeyID(keyID))
            continue;

        CKey key;
        if (!pwalletMain->GetKey(keyID, key))
            continue;

        CTxIndex txindex;
        if (!txdb.ReadTxIndex(wtx->GetHash(), txindex))
            continue;
        if (nOut >= txindex.vSpent.size() || !txindex.vSpent[nOut].IsNull())
            continue;

        CBlock blockFrom;
        if (!blockFrom.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
            continue;
        if (blockFrom.GetBlockTime() + nStakeMinAge > pEpochBlock->GetBlockTime())
            continue;

        CFinalityVoteCoinGroup& group = mapGroups[keyID];
        if (group.vOutpoints.size() >= FINALITY_MAX_STAKE_PROOFS)
            continue;
        if (!group.fHaveKey)
        {
            group.key = key;
            group.fHaveKey = true;
        }
        group.vOutpoints.push_back(COutPoint(wtx->GetHash(), nOut));
        if (group.nWeight <= MAX_MONEY - txout.nValue)
            group.nWeight += txout.nValue;
        else
            group.nWeight = MAX_MONEY;
    }

    CFinalityVoteCoinGroup* pBestGroup = NULL;
    for (auto& pair : mapGroups)
    {
        if (!pair.second.fHaveKey || pair.second.vOutpoints.empty())
            continue;
        if (!pBestGroup || pair.second.nWeight > pBestGroup->nWeight)
            pBestGroup = &pair.second;
    }

    if (!pBestGroup || pBestGroup->nWeight <= 0)
        return false;

    CHashWriter nullifierHash(SER_GETHASH, 0);
    CPubKey pubkey = pBestGroup->key.GetPubKey();
    nullifierHash << std::vector<unsigned char>(pubkey.begin(), pubkey.end());
    nullifierHash << nCurrentEpoch;
    uint256 nullifier = nullifierHash.GetHash();

    CFinalityVote vote;
    vote.nEpoch = nCurrentEpoch;
    vote.hashBlock = pEpochBlock->GetBlockHash();
    vote.nHeight = nEpochHeight;
    vote.nTime = GetAdjustedTime();
    vote.nVoteWeight = pBestGroup->nWeight;
    vote.nReward = GetFinalityVoteReward(vote.nVoteWeight, GetEpochInterval(nEpochHeight));
    vote.nullifier = nullifier;
    vote.vStakeProof = pBestGroup->vOutpoints;

    if (!vote.Sign(pBestGroup->key))
        return false;

    if (!g_finalityTracker.AddVote(vote))
        return false;

    printf("ProduceFinalityVote: epoch=%d height=%d weight=%s\n",
           nCurrentEpoch, nEpochHeight, FormatMoney(pBestGroup->nWeight).c_str());

    {
        LOCK(cs_vNodes);
        for (CNode* pnode : vNodes)
        {
            pnode->PushMessage("fvote", vote);
        }
    }

    return true;
}
