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

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <algorithm>
#include <cstdlib>
#include <cctype>
#include <limits>

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

static std::string ToLowerASCII(std::string str)
{
    std::transform(str.begin(), str.end(), str.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return str;
}

static bool ParsePositiveIntStrict(const std::string& strValue, int& nOut)
{
    if (strValue.empty())
        return false;
    for (char ch : strValue)
    {
        if (!std::isdigit((unsigned char)ch))
            return false;
    }
    char* endp = NULL;
    long nParsed = std::strtol(strValue.c_str(), &endp, 10);
    if (!endp || *endp != '\0' || nParsed <= 0 || nParsed > FINALITY_MAX_TALLY_COMMITTEE)
        return false;
    nOut = (int)nParsed;
    return true;
}

static bool ParseCompressedTallyPubKey(const std::string& strKey, CPubKey& pubKeyOut)
{
    if (!IsHex(strKey))
        return false;
    std::vector<unsigned char> vchKey = ParseHex(strKey);
    if (vchKey.size() != 33)
        return false;
    CPubKey pubkey(vchKey);
    if (!pubkey.IsValid() || !pubkey.IsCompressed())
        return false;
    pubKeyOut = pubkey;
    return true;
}

bool GetFinalityTallyPrivateKey(CKey& keyOut)
{
    std::string strPrivKey = GetArg("-finalitytallyprivkey", "");
    if (strPrivKey.empty() || !IsHex(strPrivKey))
        return false;

    std::vector<unsigned char> vchSecret = ParseHex(strPrivKey);
    if (vchSecret.size() != 32)
        return false;

    CKey key;
    key.Set(vchSecret.begin(), vchSecret.end(), true);
    if (!key.IsValid())
        return false;

    keyOut = key;
    return true;
}

uint256 ComputeFinalityTallyCommitteeHash(int nM,
                                          const std::vector<CPubKey>& vPubKeys)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("Innova/Finality/TallyCommittee/v2");
    ss << nM;
    ss << (int)vPubKeys.size();
    for (const CPubKey& pubkey : vPubKeys)
        ss << std::vector<unsigned char>(pubkey.begin(), pubkey.end());
    return ss.GetHash();
}

bool VerifyMofNCommitteeSignatures(const std::vector<CPubKey>& vCommitteePubKeys,
                                   int nThreshold,
                                   const std::vector<uint16_t>& vSignerIndexes,
                                   const std::vector<std::vector<unsigned char> >& vSignerSigs,
                                   const uint256& hashDigest,
                                   std::string* pstrError)
{
    auto reject = [&](const std::string& s) -> bool {
        if (pstrError) *pstrError = s;
        return false;
    };
    const int nN = (int)vCommitteePubKeys.size();
    if (nThreshold <= 0 || nThreshold > nN)
        return reject("invalid committee threshold");
    if (vSignerIndexes.size() != vSignerSigs.size())
        return reject("signer index/signature count mismatch");
    if ((int)vSignerIndexes.size() < nThreshold)
        return reject("fewer than M committee signatures");
    if ((int)vSignerIndexes.size() > nN)
        return reject("more committee signatures than members");

    // Distinct, in-range, ascending (canonical ordering prevents duplicate-index
    // and reordering malleability).
    std::set<uint16_t> setSeen;
    uint16_t nPrev = 0;
    bool fFirst = true;
    for (size_t k = 0; k < vSignerIndexes.size(); k++)
    {
        uint16_t idx = vSignerIndexes[k];
        if (idx >= nN)
            return reject("committee signer index out of range");
        if (!fFirst && idx <= nPrev)
            return reject("committee signer indexes not strictly ascending/distinct");
        if (!setSeen.insert(idx).second)
            return reject("duplicate committee signer index");
        nPrev = idx;
        fFirst = false;
        const CPubKey& pub = vCommitteePubKeys[idx];
        if (!pub.IsValid() || !pub.Verify(hashDigest, vSignerSigs[k]))
            return reject("committee member signature invalid");
    }
    return true;
}

// ---- D2 self-governing committee: rotation record + canonical-set state ----

uint256 CFinalityCommitteeRotation::GetSignatureDigest() const
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("Innova/Finality/Rotate/v1");
    ss << nVersion;
    ss << nEffectiveEpoch;
    ss << hashPrevCommitteeSet;
    ss << (int)nNewThresholdM;
    ss << (int)vNewPubKeys.size();
    for (const std::vector<unsigned char>& pk : vNewPubKeys)
        ss << pk;
    return ss.GetHash();
}

uint256 CFinalityCommitteeRotation::GetHash() const
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << GetSignatureDigest();
    ss << vSignerIndexes;
    ss << vSignerSigs;
    return ss.GetHash();
}

bool CFinalityCommitteeRotation::IsValidBasic(std::string* pstrError) const
{
    auto reject = [&](const std::string& s) -> bool { if (pstrError) *pstrError = s; return false; };
    if (nVersion != 1)
        return reject("unsupported committee rotation version");
    if (nEffectiveEpoch < 0)
        return reject("committee rotation has negative effective epoch");
    if (nNewThresholdM < 1)
        return reject("committee rotation threshold below 1");
    if ((int)vNewPubKeys.size() < nNewThresholdM ||
        (int)vNewPubKeys.size() > FINALITY_MAX_TALLY_COMMITTEE)
        return reject("committee rotation new-set size out of range");
    std::set<std::vector<unsigned char> > setKeys;
    for (const std::vector<unsigned char>& pk : vNewPubKeys)
    {
        if (pk.size() != 33)
            return reject("committee rotation new key not compressed");
        CPubKey check(pk.begin(), pk.end());
        if (!check.IsValid() || !check.IsFullyValid())
            return reject("committee rotation new key invalid");
        if (!setKeys.insert(pk).second)
            return reject("committee rotation duplicate new key");
    }
    if (vSignerIndexes.size() != vSignerSigs.size())
        return reject("committee rotation signer index/sig count mismatch");
    if (vSignerIndexes.empty())
        return reject("committee rotation has no signers");
    return true;
}

bool CFinalityCommitteeRotation::GetNewCommittee(std::vector<CPubKey>& vOut,
                                                 int& nMOut,
                                                 uint256& setHashOut) const
{
    vOut.clear();
    for (const std::vector<unsigned char>& pk : vNewPubKeys)
    {
        CPubKey p(pk.begin(), pk.end());
        if (!p.IsValid() || !p.IsFullyValid() || !p.IsCompressed())
            return false;
        vOut.push_back(p);
    }
    nMOut = nNewThresholdM;
    setHashOut = ComputeFinalityTallyCommitteeHash(nMOut, vOut);
    return true;
}

bool CheckFinalityCommitteeRotation(const CFinalityCommitteeRotation& rot,
                                    const std::vector<CPubKey>& vPrevPubKeys,
                                    int nPrevThresholdM,
                                    const uint256& hashPrevSet,
                                    std::string* pstrError)
{
    auto reject = [&](const std::string& s) -> bool { if (pstrError) *pstrError = s; return false; };
    if (!rot.IsValidBasic(pstrError))
        return false;
    if (rot.hashPrevCommitteeSet != hashPrevSet)
        return reject("committee rotation does not chain to the current committee set");
    std::vector<CPubKey> vNew; int nNewM; uint256 newSetHash;
    if (!rot.GetNewCommittee(vNew, nNewM, newSetHash))
        return reject("committee rotation new set does not parse");
    // Authorized by >= M signatures from the CURRENT (prev) committee.
    return VerifyMofNCommitteeSignatures(vPrevPubKeys, nPrevThresholdM,
                                         rot.vSignerIndexes, rot.vSignerSigs,
                                         rot.GetSignatureDigest(), pstrError);
}

void CFinalityTracker::SetInitialFinalityCommittee(const std::vector<CPubKey>& vPubKeys, int nM)
{
    LOCK(cs_finality);
    vInitialCommittee = vPubKeys;
    nInitialCommitteeM = nM;
    hashInitialCommitteeSet = vPubKeys.empty() ? uint256(0)
                              : ComputeFinalityTallyCommitteeHash(nM, vPubKeys);
}

void CFinalityTracker::SetRecoveryFinalityCommittee(const std::vector<CPubKey>& vPubKeys, int nM)
{
    LOCK(cs_finality);
    vRecoveryCommittee = vPubKeys;
    nRecoveryCommitteeM = nM;
    hashRecoveryCommitteeSet = vPubKeys.empty() ? uint256(0)
                               : ComputeFinalityTallyCommitteeHash(nM, vPubKeys);
}

bool CFinalityTracker::GetRecoveryCommittee(std::vector<CPubKey>& vOut, int& nMOut, uint256& setHashOut) const
{
    LOCK(cs_finality);
    if (vRecoveryCommittee.empty())
        return false;
    vOut = vRecoveryCommittee;
    nMOut = nRecoveryCommitteeM;
    setHashOut = hashRecoveryCommitteeSet;
    return true;
}

bool GetRecoveryFinalityCommittee(std::vector<CPubKey>& vOut, int& nMOut, uint256& setHashOut)
{
    return g_finalityTracker.GetRecoveryCommittee(vOut, nMOut, setHashOut);
}

uint256 CFinalityCertSignature::GetHash() const
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << nVersion;
    ss << candidate.GetSignatureDigest();
    ss << nSignerIndex;
    ss << vchSig;
    return ss.GetHash();
}

bool AssembleCertificateFromSignatures(CFinalityTallyCertificate& cert,
                                       const std::map<uint16_t, std::vector<unsigned char> >& collected,
                                       const std::vector<CPubKey>& vCommittee,
                                       int nThreshold,
                                       const uint256& setHash)
{
    cert.nVersion = 3;
    cert.committeeSetHash = setHash;
    cert.vSignerIndexes.clear();
    cert.vSignerSigs.clear();
    uint256 digest = cert.GetSignatureDigest();
    // collected is std::map => keys already ascending; keep only valid sigs.
    for (std::map<uint16_t, std::vector<unsigned char> >::const_iterator it = collected.begin();
         it != collected.end(); ++it)
    {
        uint16_t idx = it->first;
        if (idx >= vCommittee.size())
            continue;
        if (!vCommittee[idx].IsValid() || !vCommittee[idx].Verify(digest, it->second))
            continue;
        cert.vSignerIndexes.push_back(idx);
        cert.vSignerSigs.push_back(it->second);
    }
    return (int)cert.vSignerIndexes.size() >= nThreshold &&
           CheckTallyCertificateCommitteeSignatures(cert, vCommittee, nThreshold, setHash, NULL);
}

bool CFinalityTracker::AddCertSignature(const CFinalityCertSignature& msg, CTxDB& txdb,
                                        CFinalityTallyCertificate* pAssembledOut, bool* pfAssembled,
                                        std::string* pstrError)
{
    auto reject = [&](const std::string& s) -> bool { if (pstrError) *pstrError = s; return false; };
    if (pfAssembled) *pfAssembled = false;

    const CFinalityTallyCertificate& cand = msg.candidate;
    if (!cand.HasPrivateWeight())
        return reject("cert-signature candidate is not a private certificate");

    // Validate the candidate's CONTENT (tally/coverage/proofs) — everything
    // except the committee signer-set, which is what we are collecting.
    std::string strErr;
    if (!CheckTallyCertificate(cand, txdb, &strErr, NULL, true, -1, true))
        return reject(std::string("cert-signature candidate invalid: ") + strErr);

    // Resolve the committee that must authorize this epoch (canonical, or the
    // recovery committee inside the recovery window), then verify the signature.
    std::vector<CPubKey> vCommittee; int nM = 0; uint256 setHash;
    if (!GetCommitteeForEpoch(cand.nEpoch, vCommittee, nM, setHash))
        return reject("no canonical committee for candidate epoch");
    if (cand.committeeSetHash != setHash)
    {
        std::vector<CPubKey> vRec; int nRecM = 0; uint256 recSet;
        if (GetRecoveryCommittee(vRec, nRecM, recSet) && cand.committeeSetHash == recSet &&
            FinalityCertInRecoveryWindow(cand.nEpoch, GetFinalizedHeight()))
        {
            vCommittee = vRec; nM = nRecM; setHash = recSet;
        }
        else
            return reject("cert-signature candidate committee-set mismatch");
    }

    uint256 digest = cand.GetSignatureDigest();
    if (msg.nSignerIndex >= vCommittee.size())
        return reject("cert-signature signer index out of range");
    if (!vCommittee[msg.nSignerIndex].IsValid() ||
        !vCommittee[msg.nSignerIndex].Verify(digest, msg.vchSig))
        return reject("cert-signature invalid");

    LOCK(cs_finality);
    mapCandidateCerts[digest] = cand;
    std::map<uint16_t, std::vector<unsigned char> >& sigs = mapCollectedCertSigs[digest];
    std::map<uint16_t, std::vector<unsigned char> >::iterator itS = sigs.find(msg.nSignerIndex);
    if (itS != sigs.end())
    {
        // A member must not sign two different candidates' content under the same
        // index/digest; identical resends are benign duplicates (do not relay).
        if (itS->second != msg.vchSig)
            return reject("cert-signature equivocation for signer index");
        return false; // duplicate: valid but nothing new to relay
    }
    sigs[msg.nSignerIndex] = msg.vchSig;

    if ((int)sigs.size() >= nM)
    {
        CFinalityTallyCertificate assembled = cand;
        if (AssembleCertificateFromSignatures(assembled, sigs, vCommittee, nM, setHash))
        {
            if (pAssembledOut) *pAssembledOut = assembled;
            if (pfAssembled) *pfAssembled = true;
        }
    }
    return true; // newly stored
}

bool FinalityCertInRecoveryWindow(int nCertEpoch, int nFinalizedHeight)
{
    // The recovery committee is authorized only once HARD finality has lagged the
    // cert's epoch by more than the gap. nFinalizedHeight==0 means nothing has
    // ever finalized — recovery is available once the chain is itself past the
    // gap (epoch 0 + gap), so a committee that never bootstraps can be recovered.
    int nFinalizedEpoch = GetEpochForHeight(nFinalizedHeight);
    return nCertEpoch > nFinalizedEpoch + FINALITY_RECOVERY_GAP_EPOCHS;
}

bool CFinalityTracker::GetCommitteeForEpoch(int nEpoch, std::vector<CPubKey>& vOut,
                                            int& nMOut, uint256& setHashOut) const
{
    LOCK(cs_finality);
    if (vInitialCommittee.empty())
        return false;
    vOut = vInitialCommittee;
    nMOut = nInitialCommitteeM;
    setHashOut = hashInitialCommitteeSet;
    // Apply connected rotations in effective-epoch order; each must chain to the
    // set active immediately before it (else it is ignored — it could not have
    // been Connected without chaining, this is defense in depth).
    for (std::map<int, CFinalityCommitteeRotation>::const_iterator it = mapConnectedRotations.begin();
         it != mapConnectedRotations.end(); ++it)
    {
        if (it->first > nEpoch)
            break;
        const CFinalityCommitteeRotation& rot = it->second;
        if (rot.hashPrevCommitteeSet != setHashOut)
            continue;
        std::vector<CPubKey> vNew; int nNewM; uint256 newSetHash;
        if (!rot.GetNewCommittee(vNew, nNewM, newSetHash))
            continue;
        vOut = vNew; nMOut = nNewM; setHashOut = newSetHash;
    }
    return true;
}

bool CFinalityTracker::ConnectCommitteeRotation(const CFinalityCommitteeRotation& rot, std::string* pstrError)
{
    auto reject = [&](const std::string& s) -> bool { if (pstrError) *pstrError = s; return false; };
    LOCK(cs_finality);
    if (vInitialCommittee.empty())
        return reject("no canonical committee pinned");

    // The committee active immediately before this rotation's effective epoch.
    std::vector<CPubKey> vPrev; int nPrevM; uint256 prevSetHash;
    if (!GetCommitteeForEpoch(rot.nEffectiveEpoch - 1, vPrev, nPrevM, prevSetHash))
        return reject("no committee resolvable before rotation effective epoch");

    if (!CheckFinalityCommitteeRotation(rot, vPrev, nPrevM, prevSetHash, pstrError))
        return false;

    // A2 determinism: at most one rotation per effective epoch; deterministic
    // lowest-hash tie-break so all nodes converge on the same chain.
    std::map<int, CFinalityCommitteeRotation>::iterator it = mapConnectedRotations.find(rot.nEffectiveEpoch);
    if (it != mapConnectedRotations.end())
    {
        if (it->second.GetHash() == rot.GetHash())
            return true; // idempotent: same rotation re-applied (load/reorg)
        if (it->second.GetHash() < rot.GetHash())
            return reject("committee rotation superseded by lower-hash rotation at same epoch");
        it->second = rot;
        return true;
    }
    mapConnectedRotations[rot.nEffectiveEpoch] = rot;
    return true;
}

void CFinalityTracker::DisconnectCommitteeRotation(int nEffectiveEpoch)
{
    LOCK(cs_finality);
    mapConnectedRotations.erase(nEffectiveEpoch);
}

bool CFinalityTracker::AddPendingCommitteeRotation(const CFinalityCommitteeRotation& rot, std::string* pstrError)
{
    auto reject = [&](const std::string& s) -> bool { if (pstrError) *pstrError = s; return false; };
    LOCK(cs_finality);
    if (vInitialCommittee.empty())
        return reject("no canonical committee pinned");
    // Validate exactly as ConnectCommitteeRotation will at connect time: authorized
    // by >= M signatures from the committee active immediately before the effective
    // epoch (cs_finality is recursive, so GetCommitteeForEpoch can re-lock).
    std::vector<CPubKey> vPrev; int nPrevM = 0; uint256 prevSetHash;
    if (!GetCommitteeForEpoch(rot.nEffectiveEpoch - 1, vPrev, nPrevM, prevSetHash))
        return reject("no committee resolvable before rotation effective epoch");
    if (!CheckFinalityCommitteeRotation(rot, vPrev, nPrevM, prevSetHash, pstrError))
        return false;
    if (mapConnectedRotations.count(rot.nEffectiveEpoch))
        return reject("a rotation is already connected at that effective epoch");
    mapPendingRotations[rot.nEffectiveEpoch] = rot;
    return true;
}

std::vector<CFinalityCommitteeRotation> CFinalityTracker::GetPendingCommitteeRotationsForBlock(int nBlockHeight, unsigned int nMax) const
{
    LOCK(cs_finality);
    std::vector<CFinalityCommitteeRotation> vOut;
    int nBlockEpoch = GetEpochForHeight(nBlockHeight);
    for (std::map<int, CFinalityCommitteeRotation>::const_iterator it = mapPendingRotations.begin();
         it != mapPendingRotations.end(); ++it)
    {
        const CFinalityCommitteeRotation& rot = it->second;
        // A2: future effective epoch, within the lookahead, not already connected.
        if (rot.nEffectiveEpoch <= nBlockEpoch ||
            rot.nEffectiveEpoch > nBlockEpoch + FINALITY_ROTATION_MAX_LOOKAHEAD ||
            mapConnectedRotations.count(rot.nEffectiveEpoch))
            continue;
        // Re-validate against the current canonical set (it may have advanced).
        std::vector<CPubKey> vPrev; int nPrevM = 0; uint256 prevSetHash;
        if (!GetCommitteeForEpoch(rot.nEffectiveEpoch - 1, vPrev, nPrevM, prevSetHash))
            continue;
        if (!CheckFinalityCommitteeRotation(rot, vPrev, nPrevM, prevSetHash, NULL))
            continue;
        vOut.push_back(rot);
        if (vOut.size() >= nMax)
            break;
    }
    return vOut;
}

bool CFinalityTracker::HasPendingCommitteeRotation() const
{
    LOCK(cs_finality);
    return !mapPendingRotations.empty();
}

std::map<int, CFinalityCommitteeRotation> CFinalityTracker::GetConnectedRotations() const
{
    LOCK(cs_finality);
    return mapConnectedRotations;
}

// Testnet pinned 2-of-3 finality committee over the well-known secp256k1 test
// keys (private scalars 0x01/0x02/0x03 -> P0/P1/P2, in this fixed order). Each of
// the three committee seeds holds one matching finalitytallyprivkey, so the live
// testnet can assemble M-of-N private-finality certificates and exercise committee
// self-rotation and recovery end-to-end. The set hash is order-sensitive, so the
// seed -finalitytallypubkey config must list these in the same order. Testnet only:
// these keys are public, which is acceptable off mainnet (committee-key secrecy is
// not the certificate trust boundary).
static const char* TESTNET_FINALITY_COMMITTEE_PUBKEYS[] = {
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
};
static const int TESTNET_FINALITY_COMMITTEE_M = 2;

void PinFinalityCommitteeConstants()
{
    extern bool fRegTest;
    extern bool fTestNet;

    if (fTestNet)
    {
        std::vector<CPubKey> vPubKeys;
        for (const char* hex : TESTNET_FINALITY_COMMITTEE_PUBKEYS)
        {
            std::vector<unsigned char> vch = ParseHex(hex);
            CPubKey pk(vch.begin(), vch.end());
            if (!pk.IsValid() || !pk.IsFullyValid() || !pk.IsCompressed())
            {
                printf("PinFinalityCommitteeConstants: WARNING invalid testnet committee pubkey\n");
                return;
            }
            vPubKeys.push_back(pk);
        }
        g_finalityTracker.SetInitialFinalityCommittee(vPubKeys, TESTNET_FINALITY_COMMITTEE_M);
        printf("PinFinalityCommitteeConstants: pinned testnet committee %d-of-%d\n",
               TESTNET_FINALITY_COMMITTEE_M, (int)vPubKeys.size());
        return;
    }

    if (!fRegTest)
    {
        // Mainnet: the launch committee is pinned here before the mainnet
        // governance fork (8,250,000). Left unpinned until decided — the
        // signer-set rule is inert without a pinned committee.
        return;
    }

    // Regtest: pin from the locally-configured committee so end-to-end tests can
    // drive a committee with a known private key.
    CFinalityTallyConfig cfg = GetFinalityTallyConfig();
    if (cfg.fCommitteeValid && !cfg.vCommitteePubKeys.empty())
        g_finalityTracker.SetInitialFinalityCommittee(cfg.vCommitteePubKeys, cfg.nThresholdM);
}

bool GetCanonicalFinalityCommittee(int nEpoch,
                                   std::vector<CPubKey>& vCommitteeOut,
                                   int& nMOut,
                                   uint256& setHashOut)
{
    // The canonical committee is consensus state: the fork-pinned initial set
    // advanced by connected M-of-N self-rotations (CFinalityTracker). Returns
    // false if no committee is pinned for nEpoch yet (pre-activation), in which
    // case the signer-set rule in CheckTallyCertificate stays inert — this is
    // consensus-uniform because the pinned set is a network constant.
    return g_finalityTracker.GetCommitteeForEpoch(nEpoch, vCommitteeOut, nMOut, setHashOut);
}

bool CheckTallyCertificateCommitteeSignatures(const CFinalityTallyCertificate& cert,
                                              const std::vector<CPubKey>& vCommittee,
                                              int nThreshold,
                                              const uint256& setHash,
                                              std::string* pstrError)
{
    auto reject = [&](const std::string& s) -> bool {
        if (pstrError) *pstrError = s;
        return false;
    };
    if (cert.nVersion < 3)
        return reject("tally certificate predates committee signer-set (version < 3)");
    if (cert.committeeSetHash != setHash)
        return reject("tally certificate committee-set hash does not match canonical committee");
    return VerifyMofNCommitteeSignatures(vCommittee, nThreshold,
                                         cert.vSignerIndexes, cert.vSignerSigs,
                                         cert.GetSignatureDigest(), pstrError);
}

bool ParseFinalityTallyThreshold(const std::string& strThreshold, int& nMOut, int& nNOut)
{
    nMOut = 0;
    nNOut = 0;
    size_t nSep = strThreshold.find("-of-");
    if (nSep == std::string::npos)
        return false;

    int nM = 0;
    int nN = 0;
    if (!ParsePositiveIntStrict(strThreshold.substr(0, nSep), nM) ||
        !ParsePositiveIntStrict(strThreshold.substr(nSep + 4), nN))
        return false;
    if (nM > nN)
        return false;

    nMOut = nM;
    nNOut = nN;
    return true;
}

CFinalityTallyConfig GetFinalityTallyConfig()
{
    CFinalityTallyConfig config;
    config.strMode = ToLowerASCII(GetArg("-finalitytallymode", "off"));
    if (config.strMode == "off")
    {
        config.fEnabled = false;
    }
    else if (config.strMode == "committee" || config.strMode == "auto")
    {
        config.fEnabled = true;
    }
    else
    {
        config.fModeValid = false;
        config.strMode = "off";
        config.fEnabled = false;
    }

    std::vector<std::string> vPubKeyArgs;
    std::map<std::string, std::vector<std::string> >::const_iterator itPubKeys =
        mapMultiArgs.find("-finalitytallypubkey");
    if (itPubKeys != mapMultiArgs.end())
        vPubKeyArgs = itPubKeys->second;
    else
    {
        std::string strSinglePubKey = GetArg("-finalitytallypubkey", "");
        if (!strSinglePubKey.empty())
            vPubKeyArgs.push_back(strSinglePubKey);
    }

    config.fPubKeyConfigured = !vPubKeyArgs.empty();
    std::set<CPubKey> setPubKeys;
    bool fPubKeysValid = config.fPubKeyConfigured;
    for (const std::string& strPubKey : vPubKeyArgs)
    {
        CPubKey pubkey;
        if (!ParseCompressedTallyPubKey(strPubKey, pubkey) ||
            !setPubKeys.insert(pubkey).second)
        {
            fPubKeysValid = false;
            break;
        }
        config.vCommitteePubKeys.push_back(pubkey);
    }

    std::string strPrivKey = GetArg("-finalitytallyprivkey", "");
    config.fPrivKeyConfigured = !strPrivKey.empty();
    config.fThresholdValid = ParseFinalityTallyThreshold(
        ToLowerASCII(GetArg("-finalitytallythreshold", "")),
        config.nThresholdM,
        config.nThresholdN);
    if (config.fThresholdValid &&
        fPubKeysValid &&
        config.nThresholdN == (int)config.vCommitteePubKeys.size())
    {
        config.fCommitteeValid = true;
        config.committeeSetHash = ComputeFinalityTallyCommitteeHash(config.nThresholdM,
                                                                    config.vCommitteePubKeys);
    }

    if (config.fPrivKeyConfigured)
    {
        CKey key;
        if (GetFinalityTallyPrivateKey(key))
        {
            CPubKey pubkey = key.GetPubKey();
            if (pubkey.IsValid())
            {
                config.fPrivKeyValid = true;
                for (size_t i = 0; i < config.vCommitteePubKeys.size(); i++)
                {
                    if (config.vCommitteePubKeys[i] == pubkey)
                    {
                        config.nLocalCommitteeIndex = (int)i;
                        break;
                    }
                }
            }
        }
    }

    config.fEncryptedTallyReady = config.fCommitteeValid;
    return config;
}

static uint256 FinalityScalarFromBytesBE(const std::vector<unsigned char>& vch)
{
    uint256 out = 0;
    if (vch.empty())
        return out;
    unsigned char be[32];
    memset(be, 0, sizeof(be));
    size_t nCopy = std::min(vch.size(), sizeof(be));
    memcpy(be + sizeof(be) - nCopy, &vch[vch.size() - nCopy], nCopy);
    unsigned char* le = out.begin();
    for (int i = 0; i < 32; i++)
        le[i] = be[31 - i];
    return FieldReduce(out);
}

static uint256 FieldNeg(const uint256& value)
{
    return FieldSub(FieldFromUint64(0), value);
}

static void FinalityScalarToBytesBE(const uint256& scalar,
                                    std::vector<unsigned char>& vchOut)
{
    vchOut.assign(32, 0);
    const unsigned char* le = scalar.begin();
    for (int i = 0; i < 32; i++)
        vchOut[i] = le[31 - i];
}

static bool FinalityScalarToMoney(const uint256& scalar, int64_t& nOut)
{
    const unsigned char* le = scalar.begin();
    for (int i = 8; i < 32; i++)
    {
        if (le[i] != 0)
            return false;
    }

    uint64_t nValue = 0;
    for (int i = 0; i < 8; i++)
        nValue |= ((uint64_t)le[i]) << (8 * i);
    if (nValue > (uint64_t)MAX_MONEY)
        return false;
    nOut = (int64_t)nValue;
    return true;
}

static bool FinalityRandomScalar(uint256& scalarOut)
{
    unsigned char buf[32];
    if (RAND_bytes(buf, sizeof(buf)) != 1)
        return false;
    std::vector<unsigned char> vch(buf, buf + sizeof(buf));
    scalarOut = FinalityScalarFromBytesBE(vch);
    OPENSSL_cleanse(buf, sizeof(buf));
    return true;
}

static bool FinalityBuildShamirPolynomial(const uint256& secret,
                                          int nDegree,
                                          std::vector<uint256>& vCoeffOut)
{
    if (nDegree < 0)
        return false;
    vCoeffOut.assign(nDegree + 1, uint256(0));
    vCoeffOut[0] = secret;
    for (int i = 1; i <= nDegree; i++)
    {
        if (!FinalityRandomScalar(vCoeffOut[i]))
            return false;
    }
    return true;
}

static bool FinalityEvaluatePolynomial(const std::vector<uint256>& vCoeff,
                                       int nX,
                                       uint256& yOut)
{
    if (vCoeff.empty() || nX <= 0)
        return false;
    uint256 x = FieldFromUint64((uint64_t)nX);
    uint256 power = FieldFromUint64(1);
    yOut = vCoeff[0];
    for (size_t i = 1; i < vCoeff.size(); i++)
    {
        power = FieldMul(power, x);
        yOut = FieldAdd(yOut, FieldMul(vCoeff[i], power));
    }
    return true;
}

static bool FinalityDeriveECDHKey(const CKey& keyPrivate,
                                  const CPubKey& pubECDHPeer,
                                  const CPubKey& pubRecipient,
                                  const CPubKey& pubEphemeral,
                                  int nRecipientIndex,
                                  const uint256& committeeSetHash,
                                  std::vector<unsigned char>& vchKeyOut)
{
    if (!keyPrivate.IsValid() ||
        !pubECDHPeer.IsValid() || !pubECDHPeer.IsCompressed() ||
        !pubRecipient.IsValid() || !pubRecipient.IsCompressed() ||
        !pubEphemeral.IsValid() || !pubEphemeral.IsCompressed())
        return false;

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group)
        return false;
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx)
    {
        EC_GROUP_free(group);
        return false;
    }

    BIGNUM* bnPriv = BN_bin2bn(keyPrivate.begin(), 32, NULL);
    EC_POINT* peerPoint = EC_POINT_new(group);
    EC_POINT* sharedPoint = EC_POINT_new(group);
    bool fOk = false;
    unsigned char sharedBytes[33];
    memset(sharedBytes, 0, sizeof(sharedBytes));

    if (bnPriv && peerPoint && sharedPoint &&
        EC_POINT_oct2point(group, peerPoint, pubECDHPeer.begin(), pubECDHPeer.size(), ctx) == 1 &&
        EC_POINT_is_on_curve(group, peerPoint, ctx) == 1 &&
        !EC_POINT_is_at_infinity(group, peerPoint) &&
        EC_POINT_mul(group, sharedPoint, NULL, peerPoint, bnPriv, ctx) == 1 &&
        !EC_POINT_is_at_infinity(group, sharedPoint) &&
        EC_POINT_point2oct(group, sharedPoint, POINT_CONVERSION_COMPRESSED,
                           sharedBytes, sizeof(sharedBytes), ctx) == sizeof(sharedBytes))
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << std::string("Innova/Finality/TallyShareECDH/v2");
        for (size_t i = 0; i < sizeof(sharedBytes); i++)
            ss << sharedBytes[i];
        ss << std::vector<unsigned char>(pubEphemeral.begin(), pubEphemeral.end());
        ss << std::vector<unsigned char>(pubRecipient.begin(), pubRecipient.end());
        ss << committeeSetHash;
        ss << nRecipientIndex;
        uint256 hashKey = ss.GetHash();
        vchKeyOut.assign(hashKey.begin(), hashKey.begin() + 32);
        fOk = true;
    }

    OPENSSL_cleanse(sharedBytes, sizeof(sharedBytes));
    if (sharedPoint) EC_POINT_free(sharedPoint);
    if (peerPoint) EC_POINT_free(peerPoint);
    if (bnPriv) BN_clear_free(bnPriv);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    return fOk;
}

static std::vector<unsigned char> BuildFinalityTallyShareAAD(const CFinalityTallyShare& share,
                                                             int nRecipientIndex,
                                                             const CPubKey& pubEphemeral)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << std::string("Innova/Finality/TallyShareAAD/v2");
    ss << share.nEpoch;
    ss << share.voteNullifier;
    ss << share.hashBlock;
    ss << share.hashCurveRoot;
    ss << share.hashNullifierRoot;
    ss << share.stakeWeightCommitment;
    ss << share.rewardCommitment;
    ss << share.committeeSetHash;
    ss << nRecipientIndex;
    ss << std::vector<unsigned char>(pubEphemeral.begin(), pubEphemeral.end());
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

static std::vector<unsigned char> BuildFinalityTallyAggregatePartialAAD(const CFinalityTallyAggregatePartial& partial,
                                                                        int nRecipientIndex,
                                                                        const CPubKey& pubEphemeral)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << std::string("Innova/Finality/TallyAggregatePartialAAD/v2");
    ss << partial.nEpoch;
    ss << partial.hashBlock;
    ss << partial.hashCurveRoot;
    ss << partial.hashNullifierRoot;
    ss << partial.committeeSetHash;
    ss << partial.nSourceIndex;
    ss << partial.vTallyShareHashes;
    ss << nRecipientIndex;
    ss << std::vector<unsigned char>(pubEphemeral.begin(), pubEphemeral.end());
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

bool BuildEncryptedFinalityTallyShares(CFinalityTallyShare& share,
                                       int64_t nWeight,
                                       int64_t nReward,
                                       const std::vector<unsigned char>& vchWeightBlind,
                                       const std::vector<unsigned char>& vchRewardBlind,
                                       const CFinalityTallyConfig& config)
{
    if (!config.fCommitteeValid ||
        config.nThresholdM <= 0 ||
        config.nThresholdM > (int)config.vCommitteePubKeys.size() ||
        vchWeightBlind.size() != BLINDING_FACTOR_SIZE ||
        vchRewardBlind.size() != BLINDING_FACTOR_SIZE ||
        nWeight < 0 || nReward < 0 ||
        share.nVersion != 2 ||
        share.nEpoch < 0 ||
        share.voteNullifier == 0 ||
        share.hashBlock == 0 ||
        share.hashCurveRoot == 0 ||
        share.hashNullifierRoot == 0 ||
        share.committeeSetHash != config.committeeSetHash ||
        share.stakeWeightCommitment.IsNull() ||
        share.rewardCommitment.IsNull())
        return false;

    uint256 weightSecret = FieldFromUint64((uint64_t)nWeight);
    uint256 rewardSecret = FieldFromUint64((uint64_t)nReward);
    uint256 weightBlindSecret = FinalityScalarFromBytesBE(vchWeightBlind);
    uint256 rewardBlindSecret = FinalityScalarFromBytesBE(vchRewardBlind);

    share.vEncryptedRecipientShares.clear();
    share.vEncryptedRecipientShares.reserve(config.vCommitteePubKeys.size());
    int nDegree = config.nThresholdM - 1;
    std::vector<uint256> vWeightPoly;
    std::vector<uint256> vRewardPoly;
    std::vector<uint256> vWeightBlindPoly;
    std::vector<uint256> vRewardBlindPoly;
    if (!FinalityBuildShamirPolynomial(weightSecret, nDegree, vWeightPoly) ||
        !FinalityBuildShamirPolynomial(rewardSecret, nDegree, vRewardPoly) ||
        !FinalityBuildShamirPolynomial(weightBlindSecret, nDegree, vWeightBlindPoly) ||
        !FinalityBuildShamirPolynomial(rewardBlindSecret, nDegree, vRewardBlindPoly))
        return false;

    for (size_t i = 0; i < config.vCommitteePubKeys.size(); i++)
    {
        int nRecipientIndex = (int)i;
        int nX = nRecipientIndex + 1;
        uint256 evalWeight, evalReward, evalWeightBlind, evalRewardBlind;
        if (!FinalityEvaluatePolynomial(vWeightPoly, nX, evalWeight) ||
            !FinalityEvaluatePolynomial(vRewardPoly, nX, evalReward) ||
            !FinalityEvaluatePolynomial(vWeightBlindPoly, nX, evalWeightBlind) ||
            !FinalityEvaluatePolynomial(vRewardBlindPoly, nX, evalRewardBlind))
            return false;

        CKey ephemeralKey;
        ephemeralKey.MakeNewKey(true);
        CPubKey ephemeralPubKey = ephemeralKey.GetPubKey();
        if (!ephemeralKey.IsValid() || !ephemeralPubKey.IsValid() || !ephemeralPubKey.IsCompressed())
            return false;

        std::vector<unsigned char> vchKey;
        if (!FinalityDeriveECDHKey(ephemeralKey, config.vCommitteePubKeys[i],
                                   config.vCommitteePubKeys[i],
                                   ephemeralPubKey, nRecipientIndex,
                                   config.committeeSetHash, vchKey))
            return false;

        CDataStream ssPlain(SER_NETWORK, PROTOCOL_VERSION);
        ssPlain << (uint32_t)2;
        ssPlain << nRecipientIndex;
        ssPlain << nX;
        ssPlain << evalWeight;
        ssPlain << evalReward;
        ssPlain << evalWeightBlind;
        ssPlain << evalRewardBlind;
        std::vector<unsigned char> vchPlain(ssPlain.begin(), ssPlain.end());
        std::vector<unsigned char> vchAAD = BuildFinalityTallyShareAAD(share, nRecipientIndex, ephemeralPubKey);
        std::vector<unsigned char> vchCiphertext;
        if (!ChaCha20Poly1305Encrypt(vchKey, vchPlain, vchAAD, vchCiphertext))
        {
            OPENSSL_cleanse(vchKey.data(), vchKey.size());
            return false;
        }
        OPENSSL_cleanse(vchKey.data(), vchKey.size());

        CDataStream ssOut(SER_NETWORK, PROTOCOL_VERSION);
        ssOut << (uint32_t)2;
        ssOut << nRecipientIndex;
        ssOut << std::vector<unsigned char>(ephemeralPubKey.begin(), ephemeralPubKey.end());
        ssOut << vchCiphertext;
        share.vEncryptedRecipientShares.push_back(std::vector<unsigned char>(ssOut.begin(), ssOut.end()));
    }

    return share.vEncryptedRecipientShares.size() == config.vCommitteePubKeys.size();
}

static bool ParseEncryptedRecipientShare(const std::vector<unsigned char>& vchEncrypted,
                                         uint32_t& nVersionOut,
                                         int& nRecipientIndexOut,
                                         CPubKey& pubEphemeralOut,
                                         std::vector<unsigned char>& vchCiphertextOut)
{
    try {
        CDataStream ss(vchEncrypted, SER_NETWORK, PROTOCOL_VERSION);
        std::vector<unsigned char> vchEphemeral;
        ss >> nVersionOut;
        ss >> nRecipientIndexOut;
        ss >> vchEphemeral;
        ss >> vchCiphertextOut;
        if (nVersionOut != 2 ||
            nRecipientIndexOut < 0 ||
            vchEphemeral.size() != 33 ||
            vchCiphertextOut.size() < 28)
            return false;
        pubEphemeralOut = CPubKey(vchEphemeral);
        return pubEphemeralOut.IsValid() && pubEphemeralOut.IsCompressed();
    } catch (const std::exception&) {
        return false;
    }
}

bool DecryptFinalityTallyShareForRecipient(const CFinalityTallyShare& share,
                                           const CFinalityTallyConfig& config,
                                           const CKey& keyRecipient,
                                           int nRecipientIndex,
                                           CFinalityTallyPlainShare& plainOut)
{
    if (nRecipientIndex < 0 ||
        nRecipientIndex >= (int)config.vCommitteePubKeys.size() ||
        nRecipientIndex >= (int)share.vEncryptedRecipientShares.size() ||
        share.nVersion != 2 ||
        share.committeeSetHash != config.committeeSetHash ||
        !keyRecipient.IsValid())
        return false;

    CPubKey pubRecipient = keyRecipient.GetPubKey();
    if (!pubRecipient.IsValid() || !pubRecipient.IsCompressed() ||
        pubRecipient != config.vCommitteePubKeys[nRecipientIndex])
        return false;

    uint32_t nEnvelopeVersion = 0;
    int nEnvelopeRecipient = -1;
    CPubKey pubEphemeral;
    std::vector<unsigned char> vchCiphertext;
    if (!ParseEncryptedRecipientShare(share.vEncryptedRecipientShares[nRecipientIndex],
                                      nEnvelopeVersion,
                                      nEnvelopeRecipient,
                                      pubEphemeral,
                                      vchCiphertext))
        return false;
    if (nEnvelopeRecipient != nRecipientIndex)
        return false;

    std::vector<unsigned char> vchKey;
    if (!FinalityDeriveECDHKey(keyRecipient, pubEphemeral,
                               pubRecipient, pubEphemeral,
                               nRecipientIndex, config.committeeSetHash,
                               vchKey))
        return false;

    std::vector<unsigned char> vchAAD = BuildFinalityTallyShareAAD(share, nRecipientIndex, pubEphemeral);
    std::vector<unsigned char> vchPlain;
    bool fOk = ChaCha20Poly1305Decrypt(vchCiphertext, vchKey, vchAAD, vchPlain);
    OPENSSL_cleanse(vchKey.data(), vchKey.size());
    if (!fOk)
        return false;

    try {
        CDataStream ss(vchPlain, SER_NETWORK, PROTOCOL_VERSION);
        uint32_t nPlainVersion = 0;
        ss >> nPlainVersion;
        ss >> plainOut.nRecipientIndex;
        ss >> plainOut.nX;
        ss >> plainOut.evalWeight;
        ss >> plainOut.evalReward;
        ss >> plainOut.evalWeightBlind;
        ss >> plainOut.evalRewardBlind;
        if (nPlainVersion != 2 ||
            plainOut.nRecipientIndex != nRecipientIndex ||
            plainOut.nX != nRecipientIndex + 1)
            return false;
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

bool AggregateFinalityTallyPlainShares(const std::vector<CFinalityTallyPlainShare>& vShares,
                                       CFinalityTallyPlainShare& aggregateOut)
{
    if (vShares.empty())
        return false;

    aggregateOut = CFinalityTallyPlainShare();
    aggregateOut.nRecipientIndex = vShares[0].nRecipientIndex;
    aggregateOut.nX = vShares[0].nX;
    for (const CFinalityTallyPlainShare& share : vShares)
    {
        if (share.nRecipientIndex != aggregateOut.nRecipientIndex ||
            share.nX != aggregateOut.nX ||
            share.nRecipientIndex < 0 ||
            share.nX <= 0)
            return false;
        aggregateOut.evalWeight = FieldAdd(aggregateOut.evalWeight, share.evalWeight);
        aggregateOut.evalReward = FieldAdd(aggregateOut.evalReward, share.evalReward);
        aggregateOut.evalWeightBlind = FieldAdd(aggregateOut.evalWeightBlind, share.evalWeightBlind);
        aggregateOut.evalRewardBlind = FieldAdd(aggregateOut.evalRewardBlind, share.evalRewardBlind);
    }
    return true;
}

static bool FinalityInterpolateAtZero(const std::vector<int>& vX,
                                      const std::vector<uint256>& vY,
                                      int nThreshold,
                                      uint256& secretOut)
{
    if (nThreshold <= 0 ||
        (int)vX.size() < nThreshold ||
        vX.size() != vY.size())
        return false;

    std::set<int> setX;
    secretOut = uint256(0);
    for (int i = 0; i < nThreshold; i++)
    {
        if (vX[i] <= 0 || !setX.insert(vX[i]).second)
            return false;

        uint256 xi = FieldFromUint64((uint64_t)vX[i]);
        uint256 coeff = FieldFromUint64(1);
        for (int j = 0; j < nThreshold; j++)
        {
            if (i == j)
                continue;
            uint256 xj = FieldFromUint64((uint64_t)vX[j]);
            uint256 denominator = FieldSub(xi, xj);
            if (denominator == uint256(0))
                return false;
            coeff = FieldMul(coeff, FieldMul(FieldNeg(xj), FieldInv(denominator)));
        }
        secretOut = FieldAdd(secretOut, FieldMul(vY[i], coeff));
    }
    return true;
}

bool RecoverFinalityTallySecrets(const std::vector<CFinalityTallyPlainShare>& vShares,
                                 int nThreshold,
                                 uint256& weightOut,
                                 uint256& rewardOut,
                                 uint256& weightBlindOut,
                                 uint256& rewardBlindOut)
{
    if (nThreshold <= 0 || (int)vShares.size() < nThreshold)
        return false;

    std::vector<int> vX;
    std::vector<uint256> vWeight;
    std::vector<uint256> vReward;
    std::vector<uint256> vWeightBlind;
    std::vector<uint256> vRewardBlind;
    vX.reserve(vShares.size());
    vWeight.reserve(vShares.size());
    vReward.reserve(vShares.size());
    vWeightBlind.reserve(vShares.size());
    vRewardBlind.reserve(vShares.size());

    for (const CFinalityTallyPlainShare& share : vShares)
    {
        if (share.nX <= 0)
            return false;
        vX.push_back(share.nX);
        vWeight.push_back(share.evalWeight);
        vReward.push_back(share.evalReward);
        vWeightBlind.push_back(share.evalWeightBlind);
        vRewardBlind.push_back(share.evalRewardBlind);
    }

    return FinalityInterpolateAtZero(vX, vWeight, nThreshold, weightOut) &&
           FinalityInterpolateAtZero(vX, vReward, nThreshold, rewardOut) &&
           FinalityInterpolateAtZero(vX, vWeightBlind, nThreshold, weightBlindOut) &&
           FinalityInterpolateAtZero(vX, vRewardBlind, nThreshold, rewardBlindOut);
}

bool BuildEncryptedFinalityTallyAggregatePartial(CFinalityTallyAggregatePartial& partial,
                                                 const CFinalityTallyPlainShare& aggregateShare,
                                                 const CFinalityTallyConfig& config,
                                                 const CKey& keySource)
{
    if (!config.fCommitteeValid ||
        config.nThresholdM <= 0 ||
        config.nThresholdM > (int)config.vCommitteePubKeys.size() ||
        aggregateShare.nRecipientIndex < 0 ||
        aggregateShare.nRecipientIndex >= (int)config.vCommitteePubKeys.size() ||
        aggregateShare.nX != aggregateShare.nRecipientIndex + 1 ||
        partial.nVersion != 2 ||
        partial.nEpoch < 0 ||
        partial.hashBlock == 0 ||
        partial.hashCurveRoot == 0 ||
        partial.hashNullifierRoot == 0 ||
        partial.committeeSetHash != config.committeeSetHash ||
        partial.vTallyShareHashes.empty() ||
        partial.vTallyShareHashes.size() > FINALITY_MAX_VOTES ||
        !keySource.IsValid())
        return false;

    std::set<uint256> setShareHashes;
    for (const uint256& hashShare : partial.vTallyShareHashes)
    {
        if (hashShare == 0 || !setShareHashes.insert(hashShare).second)
            return false;
    }

    CPubKey pubSource = keySource.GetPubKey();
    if (!pubSource.IsValid() || !pubSource.IsCompressed() ||
        pubSource != config.vCommitteePubKeys[aggregateShare.nRecipientIndex])
        return false;

    partial.nVersion = 3; // D1.1: signed partials
    partial.nSourceIndex = aggregateShare.nRecipientIndex;
    partial.vEncryptedRecipientPartials.clear();
    partial.vEncryptedRecipientPartials.reserve(config.vCommitteePubKeys.size());

    for (size_t i = 0; i < config.vCommitteePubKeys.size(); i++)
    {
        int nRecipientIndex = (int)i;
        CKey ephemeralKey;
        ephemeralKey.MakeNewKey(true);
        CPubKey ephemeralPubKey = ephemeralKey.GetPubKey();
        if (!ephemeralKey.IsValid() || !ephemeralPubKey.IsValid() || !ephemeralPubKey.IsCompressed())
            return false;

        std::vector<unsigned char> vchKey;
        if (!FinalityDeriveECDHKey(ephemeralKey, config.vCommitteePubKeys[i],
                                   config.vCommitteePubKeys[i],
                                   ephemeralPubKey, nRecipientIndex,
                                   config.committeeSetHash, vchKey))
            return false;

        CDataStream ssPlain(SER_NETWORK, PROTOCOL_VERSION);
        ssPlain << (uint32_t)2;
        ssPlain << aggregateShare.nRecipientIndex;
        ssPlain << aggregateShare.nX;
        ssPlain << aggregateShare.evalWeight;
        ssPlain << aggregateShare.evalReward;
        ssPlain << aggregateShare.evalWeightBlind;
        ssPlain << aggregateShare.evalRewardBlind;
        std::vector<unsigned char> vchPlain(ssPlain.begin(), ssPlain.end());
        std::vector<unsigned char> vchAAD = BuildFinalityTallyAggregatePartialAAD(partial,
                                                                                  nRecipientIndex,
                                                                                  ephemeralPubKey);
        std::vector<unsigned char> vchCiphertext;
        if (!ChaCha20Poly1305Encrypt(vchKey, vchPlain, vchAAD, vchCiphertext))
        {
            OPENSSL_cleanse(vchKey.data(), vchKey.size());
            return false;
        }
        OPENSSL_cleanse(vchKey.data(), vchKey.size());

        CDataStream ssOut(SER_NETWORK, PROTOCOL_VERSION);
        ssOut << (uint32_t)2;
        ssOut << nRecipientIndex;
        ssOut << std::vector<unsigned char>(ephemeralPubKey.begin(), ephemeralPubKey.end());
        ssOut << vchCiphertext;
        partial.vEncryptedRecipientPartials.push_back(std::vector<unsigned char>(ssOut.begin(), ssOut.end()));
    }

    if (partial.vEncryptedRecipientPartials.size() != config.vCommitteePubKeys.size())
        return false;

    // D1.1: authenticate the source member over the partial content.
    if (!keySource.Sign(partial.GetContentDigest(), partial.vchSourceSig) ||
        partial.vchSourceSig.empty())
        return false;
    return true;
}

bool DecryptFinalityTallyAggregatePartialForRecipient(const CFinalityTallyAggregatePartial& partial,
                                                      const CFinalityTallyConfig& config,
                                                      const CKey& keyRecipient,
                                                      int nRecipientIndex,
                                                      CFinalityTallyPlainShare& plainOut)
{
    if (nRecipientIndex < 0 ||
        nRecipientIndex >= (int)config.vCommitteePubKeys.size() ||
        nRecipientIndex >= (int)partial.vEncryptedRecipientPartials.size() ||
        (partial.nVersion != 2 && partial.nVersion != 3) ||
        partial.committeeSetHash != config.committeeSetHash ||
        partial.nSourceIndex < 0 ||
        partial.nSourceIndex >= (int)config.vCommitteePubKeys.size() ||
        !keyRecipient.IsValid())
        return false;

    CPubKey pubRecipient = keyRecipient.GetPubKey();
    if (!pubRecipient.IsValid() || !pubRecipient.IsCompressed() ||
        pubRecipient != config.vCommitteePubKeys[nRecipientIndex])
        return false;

    uint32_t nEnvelopeVersion = 0;
    int nEnvelopeRecipient = -1;
    CPubKey pubEphemeral;
    std::vector<unsigned char> vchCiphertext;
    if (!ParseEncryptedRecipientShare(partial.vEncryptedRecipientPartials[nRecipientIndex],
                                      nEnvelopeVersion,
                                      nEnvelopeRecipient,
                                      pubEphemeral,
                                      vchCiphertext))
        return false;
    if (nEnvelopeRecipient != nRecipientIndex)
        return false;

    std::vector<unsigned char> vchKey;
    if (!FinalityDeriveECDHKey(keyRecipient, pubEphemeral,
                               pubRecipient, pubEphemeral,
                               nRecipientIndex, config.committeeSetHash,
                               vchKey))
        return false;

    std::vector<unsigned char> vchAAD = BuildFinalityTallyAggregatePartialAAD(partial,
                                                                              nRecipientIndex,
                                                                              pubEphemeral);
    std::vector<unsigned char> vchPlain;
    bool fOk = ChaCha20Poly1305Decrypt(vchCiphertext, vchKey, vchAAD, vchPlain);
    OPENSSL_cleanse(vchKey.data(), vchKey.size());
    if (!fOk)
        return false;

    try {
        CDataStream ss(vchPlain, SER_NETWORK, PROTOCOL_VERSION);
        uint32_t nPlainVersion = 0;
        ss >> nPlainVersion;
        ss >> plainOut.nRecipientIndex;
        ss >> plainOut.nX;
        ss >> plainOut.evalWeight;
        ss >> plainOut.evalReward;
        ss >> plainOut.evalWeightBlind;
        ss >> plainOut.evalRewardBlind;
        if (nPlainVersion != 2 ||
            plainOut.nRecipientIndex != partial.nSourceIndex ||
            plainOut.nX != partial.nSourceIndex + 1)
            return false;
    } catch (const std::exception&) {
        return false;
    }
    return true;
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

static bool ExtractTaggedOpReturnPayload(const CScript& scriptPubKey,
                                         const unsigned char* pchTag,
                                         std::vector<unsigned char>& vPayloadOut)
{
    vPayloadOut.clear();
    if (scriptPubKey.size() > MAX_SCRIPT_SIZE)
        return false;

    CScript::const_iterator pc = scriptPubKey.begin();
    if (pc == scriptPubKey.end() || *pc++ != OP_RETURN)
        return false;
    if (pc == scriptPubKey.end())
        return false;

    unsigned int nSize = 0;
    opcodetype opcode = (opcodetype)*pc++;
    if (opcode < OP_PUSHDATA1)
    {
        nSize = opcode;
    }
    else if (opcode == OP_PUSHDATA1)
    {
        if (scriptPubKey.end() - pc < 1)
            return false;
        nSize = *pc++;
    }
    else if (opcode == OP_PUSHDATA2)
    {
        if (scriptPubKey.end() - pc < 2)
            return false;
        nSize = (unsigned int)pc[0] | ((unsigned int)pc[1] << 8);
        pc += 2;
    }
    else if (opcode == OP_PUSHDATA4)
    {
        if (scriptPubKey.end() - pc < 4)
            return false;
        nSize = (unsigned int)pc[0] |
                ((unsigned int)pc[1] << 8) |
                ((unsigned int)pc[2] << 16) |
                ((unsigned int)pc[3] << 24);
        pc += 4;
    }
    else
    {
        return false;
    }

    if (nSize <= 4 || nSize > MAX_SCRIPT_SIZE)
        return false;
    if ((unsigned int)(scriptPubKey.end() - pc) != nSize)
        return false;
    if (memcmp(&pc[0], pchTag, 4) != 0)
        return false;

    vPayloadOut.assign(pc + 4, pc + nSize);
    return !vPayloadOut.empty();
}

bool ExtractFinalityVote(const CScript& scriptPubKey, CFinalityVote& voteOut)
{
    std::vector<unsigned char> vPayload;
    if (!ExtractTaggedOpReturnPayload(scriptPubKey, FINALITY_VOTE_TAG, vPayload))
        return false;

    try {
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
    std::vector<unsigned char> vPayload;
    if (!ExtractTaggedOpReturnPayload(scriptPubKey, FINALITY_TALLY_CERT_TAG, vPayload))
        return false;

    try {
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

CScript BuildFinalityCommitteeRotationScript(const CFinalityCommitteeRotation& rot)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << rot;
    std::vector<unsigned char> vchData;
    vchData.reserve(4 + ss.size());
    vchData.insert(vchData.end(), FINALITY_COMMITTEE_ROTATION_TAG, FINALITY_COMMITTEE_ROTATION_TAG + 4);
    vchData.insert(vchData.end(), ss.begin(), ss.end());
    CScript script;
    script << OP_RETURN << vchData;
    return script;
}

bool ExtractFinalityCommitteeRotation(const CScript& scriptPubKey, CFinalityCommitteeRotation& rotOut)
{
    std::vector<unsigned char> vPayload;
    if (!ExtractTaggedOpReturnPayload(scriptPubKey, FINALITY_COMMITTEE_ROTATION_TAG, vPayload))
        return false;
    try {
        CDataStream ss(vPayload, SER_NETWORK, PROTOCOL_VERSION);
        ss >> rotOut;
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

std::vector<CFinalityCommitteeRotation> ExtractFinalityCommitteeRotationsFromBlock(const CBlock& block)
{
    std::vector<CFinalityCommitteeRotation> vRots;
    if (block.vtx.empty())
        return vRots;
    for (const CTxOut& out : block.vtx[0].vout)
    {
        CFinalityCommitteeRotation rot;
        if (ExtractFinalityCommitteeRotation(out.scriptPubKey, rot))
            vRots.push_back(rot);
    }
    return vRots;
}

CScript BuildFinalityTallyShareScript(const CFinalityTallyShare& share)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << share;

    std::vector<unsigned char> vchData;
    vchData.reserve(4 + ss.size());
    vchData.insert(vchData.end(), FINALITY_TALLY_SHARE_TAG, FINALITY_TALLY_SHARE_TAG + 4);
    vchData.insert(vchData.end(), ss.begin(), ss.end());

    CScript script;
    script << OP_RETURN << vchData;
    return script;
}

bool ExtractFinalityTallyShare(const CScript& scriptPubKey, CFinalityTallyShare& shareOut)
{
    std::vector<unsigned char> vPayload;
    if (!ExtractTaggedOpReturnPayload(scriptPubKey, FINALITY_TALLY_SHARE_TAG, vPayload))
        return false;

    try {
        CDataStream ss(vPayload, SER_NETWORK, PROTOCOL_VERSION);
        ss >> shareOut;
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

std::vector<CFinalityTallyShare> ExtractFinalityTallySharesFromBlock(const CBlock& block)
{
    std::vector<CFinalityTallyShare> vShares;
    if (block.vtx.empty())
        return vShares;

    for (const CTxOut& out : block.vtx[0].vout)
    {
        CFinalityTallyShare share;
        if (ExtractFinalityTallyShare(out.scriptPubKey, share))
            vShares.push_back(share);
    }
    return vShares;
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

struct CFinalityTallyGroupKey
{
    int nEpoch;
    uint256 hashBlock;
    uint256 hashCurveRoot;
    uint256 hashNullifierRoot;
    uint256 committeeSetHash;

    CFinalityTallyGroupKey()
        : nEpoch(0)
    {
    }

    bool operator<(const CFinalityTallyGroupKey& other) const
    {
        if (nEpoch != other.nEpoch) return nEpoch < other.nEpoch;
        if (hashCurveRoot != other.hashCurveRoot) return hashCurveRoot < other.hashCurveRoot;
        if (hashNullifierRoot != other.hashNullifierRoot) return hashNullifierRoot < other.hashNullifierRoot;
        if (committeeSetHash != other.committeeSetHash) return committeeSetHash < other.committeeSetHash;
        return hashBlock < other.hashBlock;
    }
};

struct CFinalityTallyCohortKey
{
    int nEpoch;
    uint256 hashCurveRoot;
    uint256 hashNullifierRoot;
    uint256 committeeSetHash;

    CFinalityTallyCohortKey()
        : nEpoch(0)
    {
    }

    bool operator<(const CFinalityTallyCohortKey& other) const
    {
        if (nEpoch != other.nEpoch) return nEpoch < other.nEpoch;
        if (hashCurveRoot != other.hashCurveRoot) return hashCurveRoot < other.hashCurveRoot;
        if (hashNullifierRoot != other.hashNullifierRoot) return hashNullifierRoot < other.hashNullifierRoot;
        return committeeSetHash < other.committeeSetHash;
    }
};

struct CFinalityTallyGroupWork
{
    CFinalityTallyGroupKey key;
    std::vector<CFinalityTallyShare> vShares;
    std::vector<uint256> vShareHashes;
    std::vector<CFinalityTallyPlainShare> vLocalPlainShares;
    bool fRecovered;
    int64_t nWeight;
    int64_t nReward;
    uint256 weightBlind;
    uint256 rewardBlind;
    CPedersenCommitment weightCommitment;
    CPedersenCommitment rewardCommitment;

    CFinalityTallyGroupWork()
        : fRecovered(false),
          nWeight(0),
          nReward(0)
    {
    }
};

static bool FinalitySameHashVector(std::vector<uint256> a, std::vector<uint256> b)
{
    std::sort(a.begin(), a.end());
    std::sort(b.begin(), b.end());
    return a == b;
}

static bool FinalityAddCommitment(CPedersenCommitment& aggregate,
                                  bool& fHaveAggregate,
                                  const CPedersenCommitment& commitment)
{
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
}

static bool FinalityAggregateCommitments(const std::vector<CFinalityTallyShare>& vShares,
                                         bool fRewardCommitment,
                                         CPedersenCommitment& aggregateOut)
{
    bool fHaveAggregate = false;
    for (const CFinalityTallyShare& share : vShares)
    {
        const CPedersenCommitment& commitment =
            fRewardCommitment ? share.rewardCommitment : share.stakeWeightCommitment;
        if (!FinalityAddCommitment(aggregateOut, fHaveAggregate, commitment))
            return false;
    }
    return fHaveAggregate;
}

static FinalityTier FinalityDetermineTier(int64_t nActiveWeight, int64_t nWinningWeight)
{
    if (nActiveWeight <= 0 || nWinningWeight < 0 || nWinningWeight > nActiveWeight)
        return FINALITY_NONE;
    if (nWinningWeight * 3 >= nActiveWeight * 2)
        return FINALITY_HARD;
    if (nWinningWeight * 2 >= nActiveWeight)
        return FINALITY_SOFT;
    if (nWinningWeight * 3 >= nActiveWeight)
        return FINALITY_TENTATIVE;
    return FINALITY_NONE;
}

static uint256 FinalityAutomationContextHash(const std::string& strDomain,
                                             const CFinalityTallyGroupKey& key,
                                             int nSourceIndex,
                                             const std::vector<uint256>& vShareHashes)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << strDomain;
    ss << key.nEpoch;
    ss << key.hashBlock;
    ss << key.hashCurveRoot;
    ss << key.hashNullifierRoot;
    ss << key.committeeSetHash;
    ss << nSourceIndex;
    ss << vShareHashes;
    return ss.GetHash();
}

static uint256 FinalityCertificateAutomationContextHash(const CFinalityTallyCertificate& cert)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("Innova/Finality/TallyCertificateAutomation/v2");
    ss << cert.nEpoch;
    ss << cert.hashBlock;
    ss << cert.nHeight;
    ss << cert.nTier;
    ss << cert.hashCurveRoot;
    ss << cert.hashNullifierRoot;
    ss << cert.committeeSetHash;
    ss << cert.activeWeightCommitment;
    ss << cert.winningWeightCommitment;
    ss << cert.rewardBudgetCommitment;
    ss << cert.nTransparentActiveWeight;
    ss << cert.nTransparentWinningWeight;
    ss << cert.nTransparentRewardBudget;
    ss << cert.vVoteNullifiers;
    ss << cert.vTallyShareHashes;
    return ss.GetHash();
}

static bool FinalityTallyCertificateContextExists(
    const CFinalityTallyCertificate& cert,
    const std::map<uint256, CFinalityTallyCertificate>& mapCerts,
    uint256& hashExisting)
{
    uint256 hashContext = FinalityCertificateAutomationContextHash(cert);
    for (const std::pair<const uint256, CFinalityTallyCertificate>& pair : mapCerts)
    {
        if (FinalityCertificateAutomationContextHash(pair.second) == hashContext)
        {
            hashExisting = pair.first;
            return true;
        }
    }
    return false;
}

static void FinalityEraseTallyCertificateContext(
    const CFinalityTallyCertificate& cert,
    std::map<uint256, CFinalityTallyCertificate>& mapCerts)
{
    uint256 hashContext = FinalityCertificateAutomationContextHash(cert);
    for (std::map<uint256, CFinalityTallyCertificate>::iterator it = mapCerts.begin();
         it != mapCerts.end(); )
    {
        if (FinalityCertificateAutomationContextHash(it->second) == hashContext)
            mapCerts.erase(it++);
        else
            ++it;
    }
}

static bool FinalityPartialMatchesGroup(const CFinalityTallyAggregatePartial& partial,
                                        const CFinalityTallyGroupWork& group)
{
    // Partials are built as v3 (D1.1 source-signed); v2 is the pre-signature
    // wire form. Accept both — the source signature is validated separately in
    // AddTallyAggregatePartial, this predicate only tests group membership.
    return (partial.nVersion == 2 || partial.nVersion == 3) &&
           partial.nEpoch == group.key.nEpoch &&
           partial.hashBlock == group.key.hashBlock &&
           partial.hashCurveRoot == group.key.hashCurveRoot &&
           partial.hashNullifierRoot == group.key.hashNullifierRoot &&
           partial.committeeSetHash == group.key.committeeSetHash &&
           FinalitySameHashVector(partial.vTallyShareHashes, group.vShareHashes);
}

static void RelayFinalityTallyAggregatePartial(const CFinalityTallyAggregatePartial& partial)
{
    LOCK(cs_vNodes);
    for (CNode* pnode : vNodes)
        pnode->PushMessage("ftpart", partial);
}

static void RelayFinalityTallyCertificate(const CFinalityTallyCertificate& cert)
{
    LOCK(cs_vNodes);
    for (CNode* pnode : vNodes)
        pnode->PushMessage("ftcert", cert);
}

static void RelayFinalityCertSignature(const CFinalityCertSignature& msg)
{
    LOCK(cs_vNodes);
    for (CNode* pnode : vNodes)
        pnode->PushMessage("ftcsig", msg);
}

// Non-static (declared in finality.h): the committee-rotation RPC gossips a
// fully-signed pending rotation so any miner can embed it.
void RelayFinalityCommitteeRotation(const CFinalityCommitteeRotation& rot)
{
    LOCK(cs_vNodes);
    for (CNode* pnode : vNodes)
        pnode->PushMessage("ftrot", rot);
}

static bool FinalityRecoverGroupFromPartials(CFinalityTallyGroupWork& group,
                                             const std::vector<CFinalityTallyAggregatePartial>& vPartials,
                                             const CFinalityTallyConfig& config,
                                             const CKey& keyLocal)
{
    std::vector<CFinalityTallyPlainShare> vDecrypted;
    std::set<int> setX;
    for (const CFinalityTallyAggregatePartial& partial : vPartials)
    {
        if (!FinalityPartialMatchesGroup(partial, group))
            continue;

        CFinalityTallyPlainShare plain;
        if (!DecryptFinalityTallyAggregatePartialForRecipient(partial,
                                                              config,
                                                              keyLocal,
                                                              config.nLocalCommitteeIndex,
                                                              plain))
            continue;
        if (plain.nX <= 0 || !setX.insert(plain.nX).second)
            continue;
        vDecrypted.push_back(plain);
        if ((int)vDecrypted.size() >= config.nThresholdM)
            break;
    }

    uint256 weight, reward, weightBlind, rewardBlind;
    if (!RecoverFinalityTallySecrets(vDecrypted, config.nThresholdM,
                                     weight, reward, weightBlind, rewardBlind))
        return false;

    int64_t nWeight = 0;
    int64_t nReward = 0;
    if (!FinalityScalarToMoney(weight, nWeight) ||
        !FinalityScalarToMoney(reward, nReward))
        return false;
    if (!FinalityAggregateCommitments(group.vShares, false, group.weightCommitment) ||
        !FinalityAggregateCommitments(group.vShares, true, group.rewardCommitment))
        return false;

    group.fRecovered = true;
    group.nWeight = nWeight;
    group.nReward = nReward;
    group.weightBlind = weightBlind;
    group.rewardBlind = rewardBlind;
    return true;
}

static bool FinalityBuildAndRelayCertificateForCohort(
    int nEpoch,
    const CFinalityTallyCohortKey& cohort,
    const std::vector<CFinalityTallyGroupKey>& vGroupKeys,
    const std::map<CFinalityTallyGroupKey, CFinalityTallyGroupWork>& mapGroups)
{
    std::map<uint256, CFinalityVote> mapVotesByNullifier;
    std::vector<CFinalityVote> vVotes = g_finalityTracker.GetConnectedEpochVotes(nEpoch);
    for (const CFinalityVote& vote : vVotes)
        mapVotesByNullifier[vote.nullifier] = vote;

    int64_t nTransparentActiveWeight = 0;
    int64_t nTransparentRewardBudget = 0;
    int64_t nPrivateActiveWeight = 0;
    int64_t nPrivateRewardBudget = 0;
    uint256 activeBlind = uint256(0);
    uint256 rewardBlind = uint256(0);
    CPedersenCommitment activeCommitment;
    CPedersenCommitment rewardCommitment;
    bool fHaveActiveCommitment = false;
    bool fHaveRewardCommitment = false;
    std::set<uint256> setVoteNullifiers;
    std::vector<uint256> vTallyShareHashes;
    std::map<uint256, int64_t> mapBlockWeight;
    std::map<uint256, int> mapBlockHeight;

    for (const CFinalityVote& vote : vVotes)
    {
        if (vote.IsPrivate())
            continue;
        setVoteNullifiers.insert(vote.nullifier);
        if (nTransparentActiveWeight <= MAX_MONEY - vote.nVoteWeight)
            nTransparentActiveWeight += vote.nVoteWeight;
        else
            nTransparentActiveWeight = MAX_MONEY;
        if (nTransparentRewardBudget <= MAX_MONEY - vote.nReward)
            nTransparentRewardBudget += vote.nReward;
        else
            nTransparentRewardBudget = MAX_MONEY;
        if (mapBlockWeight[vote.hashBlock] <= MAX_MONEY - vote.nVoteWeight)
            mapBlockWeight[vote.hashBlock] += vote.nVoteWeight;
        else
            mapBlockWeight[vote.hashBlock] = MAX_MONEY;
        mapBlockHeight[vote.hashBlock] = vote.nHeight;
    }

    for (const CFinalityTallyGroupKey& key : vGroupKeys)
    {
        std::map<CFinalityTallyGroupKey, CFinalityTallyGroupWork>::const_iterator itGroup =
            mapGroups.find(key);
        if (itGroup == mapGroups.end() || !itGroup->second.fRecovered)
            return false;
        const CFinalityTallyGroupWork& group = itGroup->second;

        if (nPrivateActiveWeight > MAX_MONEY - group.nWeight ||
            nPrivateRewardBudget > MAX_MONEY - group.nReward)
            return false;
        nPrivateActiveWeight += group.nWeight;
        nPrivateRewardBudget += group.nReward;
        activeBlind = FieldAdd(activeBlind, group.weightBlind);
        rewardBlind = FieldAdd(rewardBlind, group.rewardBlind);
        if (!FinalityAddCommitment(activeCommitment, fHaveActiveCommitment, group.weightCommitment) ||
            !FinalityAddCommitment(rewardCommitment, fHaveRewardCommitment, group.rewardCommitment))
            return false;

        if (mapBlockWeight[group.key.hashBlock] <= MAX_MONEY - group.nWeight)
            mapBlockWeight[group.key.hashBlock] += group.nWeight;
        else
            mapBlockWeight[group.key.hashBlock] = MAX_MONEY;

        std::map<uint256, CBlockIndex*>::iterator miBlock = mapBlockIndex.find(group.key.hashBlock);
        if (miBlock == mapBlockIndex.end())
            return false;
        mapBlockHeight[group.key.hashBlock] = miBlock->second->nHeight;

        for (const CFinalityTallyShare& share : group.vShares)
        {
            std::map<uint256, CFinalityVote>::const_iterator itVote =
                mapVotesByNullifier.find(share.voteNullifier);
            if (itVote == mapVotesByNullifier.end() ||
                !itVote->second.IsPrivate() ||
                itVote->second.hashBlock != share.hashBlock ||
                itVote->second.privateProof.hashCurveRoot != cohort.hashCurveRoot ||
                itVote->second.privateProof.hashNullifierRoot != cohort.hashNullifierRoot)
                return false;
            setVoteNullifiers.insert(share.voteNullifier);
        }

        vTallyShareHashes.insert(vTallyShareHashes.end(),
                                 group.vShareHashes.begin(),
                                 group.vShareHashes.end());
    }

    if (!fHaveActiveCommitment || !fHaveRewardCommitment ||
        nPrivateActiveWeight <= 0 ||
        vTallyShareHashes.empty() ||
        setVoteNullifiers.empty())
        return false;

    uint256 hashBest = 0;
    int64_t nBestWeight = 0;
    for (const std::pair<const uint256, int64_t>& pair : mapBlockWeight)
    {
        if (pair.second > nBestWeight ||
            (pair.second == nBestWeight && (hashBest == 0 || pair.first < hashBest)))
        {
            hashBest = pair.first;
            nBestWeight = pair.second;
        }
    }
    if (hashBest == 0 || !mapBlockHeight.count(hashBest))
        return false;

    int64_t nTotalActive = nTransparentActiveWeight + nPrivateActiveWeight;
    if (nTotalActive <= 0 || nTotalActive > MAX_MONEY)
        return false;
    FinalityTier tier = FinalityDetermineTier(nTotalActive, nBestWeight);
    if (tier == FINALITY_NONE)
        return false;

    uint256 winningBlind = uint256(0);
    CPedersenCommitment winningCommitment;
    int64_t nPrivateWinningWeight = 0;
    bool fHavePrivateWinning = false;
    for (const CFinalityTallyGroupKey& key : vGroupKeys)
    {
        if (key.hashBlock != hashBest)
            continue;
        const CFinalityTallyGroupWork& group = mapGroups.find(key)->second;
        nPrivateWinningWeight = group.nWeight;
        winningBlind = group.weightBlind;
        winningCommitment = group.weightCommitment;
        fHavePrivateWinning = true;
        break;
    }
    std::vector<unsigned char> vchWinningBlind;
    if (!fHavePrivateWinning)
    {
        if (!GenerateBlindingFactor(vchWinningBlind) ||
            !CreatePedersenCommitment(0, vchWinningBlind, winningCommitment))
            return false;
    }
    else
    {
        FinalityScalarToBytesBE(winningBlind, vchWinningBlind);
    }

    std::vector<unsigned char> vchActiveBlind;
    std::vector<unsigned char> vchRewardBlind;
    FinalityScalarToBytesBE(activeBlind, vchActiveBlind);
    FinalityScalarToBytesBE(rewardBlind, vchRewardBlind);

    CFinalityTallyCertificate cert;
    cert.nVersion = 2;
    cert.nEpoch = nEpoch;
    cert.hashBlock = hashBest;
    cert.nHeight = mapBlockHeight[hashBest];
    cert.nTier = (int)tier;
    cert.hashCurveRoot = cohort.hashCurveRoot;
    cert.hashNullifierRoot = cohort.hashNullifierRoot;
    cert.committeeSetHash = cohort.committeeSetHash;
    cert.activeWeightCommitment = activeCommitment;
    cert.winningWeightCommitment = winningCommitment;
    cert.rewardBudgetCommitment = rewardCommitment;
    cert.nTransparentActiveWeight = nTransparentActiveWeight;
    cert.nTransparentWinningWeight = 0;
    for (const CFinalityVote& vote : vVotes)
    {
        if (!vote.IsPrivate() && vote.hashBlock == hashBest)
        {
            if (cert.nTransparentWinningWeight <= MAX_MONEY - vote.nVoteWeight)
                cert.nTransparentWinningWeight += vote.nVoteWeight;
            else
                cert.nTransparentWinningWeight = MAX_MONEY;
        }
    }
    cert.nTransparentRewardBudget = nTransparentRewardBudget;
    cert.vVoteNullifiers.assign(setVoteNullifiers.begin(), setVoteNullifiers.end());
    std::sort(vTallyShareHashes.begin(), vTallyShareHashes.end());
    vTallyShareHashes.erase(std::unique(vTallyShareHashes.begin(), vTallyShareHashes.end()),
                            vTallyShareHashes.end());
    cert.vTallyShareHashes = vTallyShareHashes;

    // The threshold/reward BPAC proofs bind cert.nVersion and cert.committeeSetHash
    // into their Fiat-Shamir transcript (FinalityCertificateProofContextHash), so the
    // cert's FINAL version and committee binding must be fixed BEFORE the proofs are
    // built — otherwise the verifier rebuilds a different transcript and the proof
    // fails. From the governance fork a private cert is v3, bound to the canonical
    // committee that authorizes its epoch; resolve that here, ahead of proof creation.
    static std::set<uint256> setProducedCertificateContexts;
    CFinalityTallyConfig cfg = GetFinalityTallyConfig();
    std::vector<CPubKey> vCommittee; int nCommitteeM = 0; uint256 committeeSetHashCanon;
    CKey memberKey;
    bool fSignAsCommittee = (cert.nHeight >= FORK_HEIGHT_TALLY_GOVERNANCE) &&
                            cfg.nLocalCommitteeIndex >= 0 &&
                            GetFinalityTallyPrivateKey(memberKey) &&
                            GetCanonicalFinalityCommittee(cert.nEpoch, vCommittee, nCommitteeM, committeeSetHashCanon);
    if (fSignAsCommittee)
    {
        cert.nVersion = 3;
        cert.committeeSetHash = committeeSetHashCanon;
        cert.vSignerIndexes.clear();
        cert.vSignerSigs.clear();
    }

    if (!CreateFinalityAggregateThresholdProofV2(cert,
                                                 nPrivateActiveWeight,
                                                 nPrivateWinningWeight,
                                                 vchActiveBlind,
                                                 vchWinningBlind,
                                                 !fHavePrivateWinning,
                                                 cert.vchAggregateThresholdProof) ||
        !CreateFinalityRewardBudgetProofV2(cert,
                                           nPrivateActiveWeight,
                                           nPrivateRewardBudget,
                                           vchActiveBlind,
                                           vchRewardBlind,
                                           cert.vchRewardBudgetProof))
        return false;

    // D2: from the governance fork, a committee member signs the v3 candidate and
    // submits its signature to the collection. A 1-of-1 committee assembles
    // immediately; for M-of-N the signature is relayed so members can gather M and
    // assemble. Pre-fork (or with no pinned committee) the cert stays v2 (below).
    if (fSignAsCommittee)
    {
        uint256 hashContext = FinalityCertificateAutomationContextHash(cert);
        if (setProducedCertificateContexts.count(hashContext))
            return false;

        CFinalityCertSignature sigMsg;
        sigMsg.candidate = cert;
        sigMsg.nSignerIndex = (uint16_t)cfg.nLocalCommitteeIndex;
        if (!memberKey.Sign(cert.GetSignatureDigest(), sigMsg.vchSig) || sigMsg.vchSig.empty())
            return false;

        CTxDB txdb("r");
        CFinalityTallyCertificate assembled;
        bool fAssembled = false;
        g_finalityTracker.AddCertSignature(sigMsg, txdb, &assembled, &fAssembled, NULL);
        RelayFinalityCertSignature(sigMsg);
        setProducedCertificateContexts.insert(hashContext);

        if (fAssembled && g_finalityTracker.AddTallyCertificate(assembled))
            RelayFinalityTallyCertificate(assembled);
        return true;
    }

    uint256 hashContext = FinalityCertificateAutomationContextHash(cert);
    if (setProducedCertificateContexts.count(hashContext))
        return false;

    if (!g_finalityTracker.AddTallyCertificate(cert))
        return false;

    setProducedCertificateContexts.insert(hashContext);
    RelayFinalityTallyCertificate(cert);
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

static const uint32_t FINALITY_BPAC_PROOF_V2 = 2;
static const int FINALITY_MONEY_BITS = 63;
static const int FINALITY_TIER_SLACK_BITS = 63;
static const int FINALITY_Q64_BITS = 64;
static const int FINALITY_COIN_REMAINDER_BITS = 27;
static const int FINALITY_SECONDS_REMAINDER_BITS = 17;
static const int FINALITY_REWARD_REMAINDER_BITS = 9;

static std::vector<CSparseEntry>* FinalitySelectWire(std::vector<CSparseEntry>& wl,
                                                     std::vector<CSparseEntry>& wr,
                                                     std::vector<CSparseEntry>& wo,
                                                     char wire)
{
    if (wire == 'L') return &wl;
    if (wire == 'R') return &wr;
    if (wire == 'O') return &wo;
    return NULL;
}

static void FinalityAddWireEqualityConstraint(CR1CSCircuit& circuit,
                                              int lhsGate,
                                              char lhsWire,
                                              int rhsGate,
                                              char rhsWire)
{
    std::vector<CSparseEntry> wl, wr, wo, wv;
    std::vector<CSparseEntry>* pLhs = FinalitySelectWire(wl, wr, wo, lhsWire);
    std::vector<CSparseEntry>* pRhs = FinalitySelectWire(wl, wr, wo, rhsWire);
    if (!pLhs || !pRhs)
        return;
    pLhs->push_back(CSparseEntry(lhsGate, FieldFromUint64(1)));
    pRhs->push_back(CSparseEntry(rhsGate, FieldNeg(FieldFromUint64(1))));
    circuit.AddLinearConstraint(wl, wr, wo, wv, FieldFromUint64(0));
}

static void FinalityAddBooleanRangeConstraints(CR1CSCircuit& circuit, int nStart, int nCount)
{
    for (int i = 0; i < nCount; i++)
    {
        FinalityAddWireEqualityConstraint(circuit, nStart + i, 'L', nStart + i, 'O');
        FinalityAddWireEqualityConstraint(circuit, nStart + i, 'R', nStart + i, 'O');
    }
}

static void FinalityAddBitSumTerms(std::vector<CSparseEntry>& entries,
                                   int nStart,
                                   int nCount,
                                   const uint256& coeff)
{
    uint256 pow2 = FieldFromUint64(1);
    uint256 two = FieldFromUint64(2);
    for (int i = 0; i < nCount; i++)
    {
        entries.push_back(CSparseEntry(nStart + i, FieldMul(coeff, pow2)));
        pow2 = FieldMul(pow2, two);
    }
}

static void FinalityAddBitDecompositionConstraint(CR1CSCircuit& circuit,
                                                  int nBitStart,
                                                  int nBits,
                                                  int nHighVar)
{
    std::vector<CSparseEntry> wl, wr, wo, wv;
    FinalityAddBitSumTerms(wo, nBitStart, nBits, FieldFromUint64(1));
    wv.push_back(CSparseEntry(nHighVar, FieldNeg(FieldFromUint64(1))));
    circuit.AddLinearConstraint(wl, wr, wo, wv, FieldFromUint64(0));
}

static int FinalityAddBitGates(CR1CSCircuit& circuit, int nBits)
{
    int nStart = circuit.nMultConstraints;
    for (int i = 0; i < nBits; i++)
        circuit.AddMultGate();
    return nStart;
}

static uint256 FinalityBlindScalarRaw(const std::vector<unsigned char>& vchBlind)
{
    uint256 out;
    memset(out.begin(), 0, 32);
    if (vchBlind.size() != BLINDING_FACTOR_SIZE)
        return out;
    for (int i = 0; i < 32; i++)
        out.begin()[i] = vchBlind[31 - i];
    return out;
}

static void FinalityInitWitness(const CR1CSCircuit& circuit, CR1CSWitness& witness)
{
    int n = circuit.nPaddedSize;
    witness.aL.assign(n, FieldFromUint64(0));
    witness.aR.assign(n, FieldFromUint64(0));
    witness.aO.assign(n, FieldFromUint64(0));
    witness.v.assign(circuit.nHighLevelVars, FieldFromUint64(0));
    witness.vBlinds.assign(circuit.nHighLevelVars, FieldFromUint64(0));
}

static bool FinalitySetBits(CR1CSWitness& witness, int nStart, int nBits, uint64_t nValue)
{
    if (nBits < 0 || nBits > 64)
        return false;
    if (nBits < 64 && (nValue >> nBits) != 0)
        return false;
    for (int i = 0; i < nBits; i++)
    {
        uint256 bit = FieldFromUint64((nValue >> i) & 1);
        witness.aL[nStart + i] = bit;
        witness.aR[nStart + i] = bit;
        witness.aO[nStart + i] = bit;
    }
    return true;
}

static bool FinalityTierCoefficients(int nTier, uint64_t& nWinningCoeffOut, uint64_t& nActiveCoeffOut)
{
    if (nTier == FINALITY_HARD)
    {
        nWinningCoeffOut = 3;
        nActiveCoeffOut = 2;
        return true;
    }
    if (nTier == FINALITY_SOFT)
    {
        nWinningCoeffOut = 2;
        nActiveCoeffOut = 1;
        return true;
    }
    if (nTier == FINALITY_TENTATIVE)
    {
        nWinningCoeffOut = 3;
        nActiveCoeffOut = 1;
        return true;
    }
    return false;
}

static bool FinalityMulUint64(uint64_t a, uint64_t b, uint64_t& out)
{
    if (b != 0 && a > std::numeric_limits<uint64_t>::max() / b)
        return false;
    out = a * b;
    return true;
}

static uint256 FinalityCertificateProofContextHash(const CFinalityTallyCertificate& cert,
                                                   const std::string& strDomain)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << strDomain;
    ss << cert.nVersion;
    ss << cert.nEpoch;
    ss << cert.hashBlock;
    ss << cert.nHeight;
    ss << cert.nTier;
    ss << cert.nConsecutiveHardCount;
    ss << cert.hashCurveRoot;
    ss << cert.hashNullifierRoot;
    ss << cert.committeeSetHash;
    ss << cert.nTransparentActiveWeight;
    ss << cert.nTransparentWinningWeight;
    ss << cert.nTransparentRewardBudget;
    ss << cert.vVoteNullifiers;
    ss << cert.vTallyShareHashes;
    return FieldReduce(ss.GetHash());
}

static void FinalityAddTranscriptBinding(CR1CSCircuit& circuit, const uint256& binding)
{
    if (circuit.nMultConstraints <= 0)
        return;

    std::vector<CSparseEntry> wl, wr, wo, wv;
    wl.push_back(CSparseEntry(0, binding));
    wl.push_back(CSparseEntry(0, FieldNeg(binding)));
    circuit.AddLinearConstraint(wl, wr, wo, wv, FieldFromUint64(0));
}

struct CFinalityThresholdCircuitLayout
{
    int nActiveBits;
    int nWinningBits;
    int nDiffBits;
    int nActiveCapSlackBits;
    int nWinningCapSlackBits;
    int nTierSlackBits;
};

static CR1CSCircuit BuildFinalityAggregateThresholdCircuit(const CFinalityTallyCertificate& cert,
                                                           bool fRequireZeroPrivateWinning,
                                                           CFinalityThresholdCircuitLayout& layout)
{
    CR1CSCircuit circuit;
    circuit.nHighLevelVars = 2; // private active, private winning

    layout.nActiveBits = FinalityAddBitGates(circuit, FINALITY_MONEY_BITS);
    layout.nWinningBits = FinalityAddBitGates(circuit, FINALITY_MONEY_BITS);
    layout.nDiffBits = FinalityAddBitGates(circuit, FINALITY_MONEY_BITS);
    layout.nActiveCapSlackBits = FinalityAddBitGates(circuit, FINALITY_MONEY_BITS);
    layout.nWinningCapSlackBits = FinalityAddBitGates(circuit, FINALITY_MONEY_BITS);
    layout.nTierSlackBits = -1;
    if (cert.nTier != FINALITY_NONE)
        layout.nTierSlackBits = FinalityAddBitGates(circuit, FINALITY_TIER_SLACK_BITS);

    circuit.PadToNextPow2();
    FinalityAddTranscriptBinding(circuit,
        FinalityCertificateProofContextHash(cert, "Innova/Finality/AggregateThreshold/v2"));

    FinalityAddBooleanRangeConstraints(circuit, layout.nActiveBits, FINALITY_MONEY_BITS);
    FinalityAddBooleanRangeConstraints(circuit, layout.nWinningBits, FINALITY_MONEY_BITS);
    FinalityAddBooleanRangeConstraints(circuit, layout.nDiffBits, FINALITY_MONEY_BITS);
    FinalityAddBooleanRangeConstraints(circuit, layout.nActiveCapSlackBits, FINALITY_MONEY_BITS);
    FinalityAddBooleanRangeConstraints(circuit, layout.nWinningCapSlackBits, FINALITY_MONEY_BITS);
    if (layout.nTierSlackBits >= 0)
        FinalityAddBooleanRangeConstraints(circuit, layout.nTierSlackBits, FINALITY_TIER_SLACK_BITS);

    FinalityAddBitDecompositionConstraint(circuit, layout.nActiveBits, FINALITY_MONEY_BITS, 0);
    FinalityAddBitDecompositionConstraint(circuit, layout.nWinningBits, FINALITY_MONEY_BITS, 1);

    {
        std::vector<CSparseEntry> wl, wr, wo, wv;
        wv.push_back(CSparseEntry(0, FieldFromUint64(1)));
        wv.push_back(CSparseEntry(1, FieldNeg(FieldFromUint64(1))));
        FinalityAddBitSumTerms(wo, layout.nDiffBits, FINALITY_MONEY_BITS,
                               FieldNeg(FieldFromUint64(1)));
        circuit.AddLinearConstraint(wl, wr, wo, wv, FieldFromUint64(0));
    }

    {
        std::vector<CSparseEntry> wl, wr, wo, wv;
        wv.push_back(CSparseEntry(0, FieldFromUint64(1)));
        FinalityAddBitSumTerms(wo, layout.nActiveCapSlackBits, FINALITY_MONEY_BITS,
                               FieldFromUint64(1));
        uint64_t nCap = (uint64_t)(MAX_MONEY - cert.nTransparentActiveWeight);
        circuit.AddLinearConstraint(wl, wr, wo, wv, FieldNeg(FieldFromUint64(nCap)));
    }

    {
        std::vector<CSparseEntry> wl, wr, wo, wv;
        wv.push_back(CSparseEntry(1, FieldFromUint64(1)));
        FinalityAddBitSumTerms(wo, layout.nWinningCapSlackBits, FINALITY_MONEY_BITS,
                               FieldFromUint64(1));
        uint64_t nCap = (uint64_t)(MAX_MONEY - cert.nTransparentWinningWeight);
        circuit.AddLinearConstraint(wl, wr, wo, wv, FieldNeg(FieldFromUint64(nCap)));
    }

    if (fRequireZeroPrivateWinning)
    {
        std::vector<CSparseEntry> wl, wr, wo, wv;
        wv.push_back(CSparseEntry(1, FieldFromUint64(1)));
        circuit.AddLinearConstraint(wl, wr, wo, wv, FieldFromUint64(0));
    }

    if (cert.nTier != FINALITY_NONE)
    {
        uint64_t nWinningCoeff = 0;
        uint64_t nActiveCoeff = 0;
        if (FinalityTierCoefficients(cert.nTier, nWinningCoeff, nActiveCoeff))
        {
            std::vector<CSparseEntry> wl, wr, wo, wv;
            wv.push_back(CSparseEntry(1, FieldFromUint64(nWinningCoeff)));
            wv.push_back(CSparseEntry(0, FieldNeg(FieldFromUint64(nActiveCoeff))));
            FinalityAddBitSumTerms(wo, layout.nTierSlackBits, FINALITY_TIER_SLACK_BITS,
                                   FieldNeg(FieldFromUint64(1)));
            uint256 c = FieldSub(FieldFromUint64((uint64_t)cert.nTransparentWinningWeight * nWinningCoeff),
                                 FieldFromUint64((uint64_t)cert.nTransparentActiveWeight * nActiveCoeff));
            circuit.AddLinearConstraint(wl, wr, wo, wv, c);
        }
    }

    return circuit;
}

struct CFinalityRewardCircuitLayout
{
    int nActiveBits;
    int nRewardBits;
    int nQ1Bits;
    int nR1Bits;
    int nCoinAgeBits;
    int nR2Bits;
    int nR3Bits;
    int nR1SlackBits;
    int nR2SlackBits;
    int nR3SlackBits;
    int nRewardCapSlackBits;
};

static CR1CSCircuit BuildFinalityRewardBudgetCircuit(const CFinalityTallyCertificate& cert,
                                                     CFinalityRewardCircuitLayout& layout)
{
    CR1CSCircuit circuit;
    circuit.nHighLevelVars = 2; // private active, private reward

    layout.nActiveBits = FinalityAddBitGates(circuit, FINALITY_MONEY_BITS);
    layout.nRewardBits = FinalityAddBitGates(circuit, FINALITY_MONEY_BITS);
    layout.nQ1Bits = FinalityAddBitGates(circuit, FINALITY_Q64_BITS);
    layout.nR1Bits = FinalityAddBitGates(circuit, FINALITY_COIN_REMAINDER_BITS);
    layout.nCoinAgeBits = FinalityAddBitGates(circuit, FINALITY_Q64_BITS);
    layout.nR2Bits = FinalityAddBitGates(circuit, FINALITY_SECONDS_REMAINDER_BITS);
    layout.nR3Bits = FinalityAddBitGates(circuit, FINALITY_REWARD_REMAINDER_BITS);
    layout.nR1SlackBits = FinalityAddBitGates(circuit, FINALITY_COIN_REMAINDER_BITS);
    layout.nR2SlackBits = FinalityAddBitGates(circuit, FINALITY_SECONDS_REMAINDER_BITS);
    layout.nR3SlackBits = FinalityAddBitGates(circuit, FINALITY_REWARD_REMAINDER_BITS);
    layout.nRewardCapSlackBits = FinalityAddBitGates(circuit, FINALITY_MONEY_BITS);

    circuit.PadToNextPow2();
    FinalityAddTranscriptBinding(circuit,
        FinalityCertificateProofContextHash(cert, "Innova/Finality/RewardBudget/v2"));

    FinalityAddBooleanRangeConstraints(circuit, layout.nActiveBits, FINALITY_MONEY_BITS);
    FinalityAddBooleanRangeConstraints(circuit, layout.nRewardBits, FINALITY_MONEY_BITS);
    FinalityAddBooleanRangeConstraints(circuit, layout.nQ1Bits, FINALITY_Q64_BITS);
    FinalityAddBooleanRangeConstraints(circuit, layout.nR1Bits, FINALITY_COIN_REMAINDER_BITS);
    FinalityAddBooleanRangeConstraints(circuit, layout.nCoinAgeBits, FINALITY_Q64_BITS);
    FinalityAddBooleanRangeConstraints(circuit, layout.nR2Bits, FINALITY_SECONDS_REMAINDER_BITS);
    FinalityAddBooleanRangeConstraints(circuit, layout.nR3Bits, FINALITY_REWARD_REMAINDER_BITS);
    FinalityAddBooleanRangeConstraints(circuit, layout.nR1SlackBits, FINALITY_COIN_REMAINDER_BITS);
    FinalityAddBooleanRangeConstraints(circuit, layout.nR2SlackBits, FINALITY_SECONDS_REMAINDER_BITS);
    FinalityAddBooleanRangeConstraints(circuit, layout.nR3SlackBits, FINALITY_REWARD_REMAINDER_BITS);
    FinalityAddBooleanRangeConstraints(circuit, layout.nRewardCapSlackBits, FINALITY_MONEY_BITS);

    FinalityAddBitDecompositionConstraint(circuit, layout.nActiveBits, FINALITY_MONEY_BITS, 0);
    FinalityAddBitDecompositionConstraint(circuit, layout.nRewardBits, FINALITY_MONEY_BITS, 1);

    int nEpochInterval = GetEpochInterval(cert.nHeight);
    {
        std::vector<CSparseEntry> wl, wr, wo, wv;
        FinalityAddBitSumTerms(wo, layout.nQ1Bits, FINALITY_Q64_BITS,
                               FieldFromUint64((uint64_t)COIN));
        FinalityAddBitSumTerms(wo, layout.nR1Bits, FINALITY_COIN_REMAINDER_BITS,
                               FieldFromUint64(1));
        wv.push_back(CSparseEntry(0, FieldNeg(FieldFromUint64((uint64_t)nEpochInterval))));
        circuit.AddLinearConstraint(wl, wr, wo, wv, FieldFromUint64(0));
    }

    {
        std::vector<CSparseEntry> wl, wr, wo, wv;
        FinalityAddBitSumTerms(wo, layout.nCoinAgeBits, FINALITY_Q64_BITS,
                               FieldFromUint64(86400));
        FinalityAddBitSumTerms(wo, layout.nR2Bits, FINALITY_SECONDS_REMAINDER_BITS,
                               FieldFromUint64(1));
        FinalityAddBitSumTerms(wo, layout.nQ1Bits, FINALITY_Q64_BITS,
                               FieldNeg(FieldFromUint64(1)));
        circuit.AddLinearConstraint(wl, wr, wo, wv, FieldFromUint64(0));
    }

    {
        std::vector<CSparseEntry> wl, wr, wo, wv;
        wv.push_back(CSparseEntry(1, FieldFromUint64(365)));
        FinalityAddBitSumTerms(wo, layout.nR3Bits, FINALITY_REWARD_REMAINDER_BITS,
                               FieldFromUint64(1));
        FinalityAddBitSumTerms(wo, layout.nCoinAgeBits, FINALITY_Q64_BITS,
                               FieldNeg(FieldFromUint64((uint64_t)COIN_YEAR_REWARD)));
        circuit.AddLinearConstraint(wl, wr, wo, wv, FieldFromUint64(0));
    }

    {
        std::vector<CSparseEntry> wl, wr, wo, wv;
        FinalityAddBitSumTerms(wo, layout.nR1Bits, FINALITY_COIN_REMAINDER_BITS, FieldFromUint64(1));
        FinalityAddBitSumTerms(wo, layout.nR1SlackBits, FINALITY_COIN_REMAINDER_BITS, FieldFromUint64(1));
        circuit.AddLinearConstraint(wl, wr, wo, wv, FieldNeg(FieldFromUint64((uint64_t)COIN - 1)));
    }

    {
        std::vector<CSparseEntry> wl, wr, wo, wv;
        FinalityAddBitSumTerms(wo, layout.nR2Bits, FINALITY_SECONDS_REMAINDER_BITS, FieldFromUint64(1));
        FinalityAddBitSumTerms(wo, layout.nR2SlackBits, FINALITY_SECONDS_REMAINDER_BITS, FieldFromUint64(1));
        circuit.AddLinearConstraint(wl, wr, wo, wv, FieldNeg(FieldFromUint64(86400 - 1)));
    }

    {
        std::vector<CSparseEntry> wl, wr, wo, wv;
        FinalityAddBitSumTerms(wo, layout.nR3Bits, FINALITY_REWARD_REMAINDER_BITS, FieldFromUint64(1));
        FinalityAddBitSumTerms(wo, layout.nR3SlackBits, FINALITY_REWARD_REMAINDER_BITS, FieldFromUint64(1));
        circuit.AddLinearConstraint(wl, wr, wo, wv, FieldNeg(FieldFromUint64(365 - 1)));
    }

    {
        std::vector<CSparseEntry> wl, wr, wo, wv;
        wv.push_back(CSparseEntry(1, FieldFromUint64(1)));
        FinalityAddBitSumTerms(wo, layout.nRewardCapSlackBits, FINALITY_MONEY_BITS,
                               FieldFromUint64(1));
        circuit.AddLinearConstraint(wl, wr, wo, wv, FieldNeg(FieldFromUint64((uint64_t)MAX_MONEY)));
    }

    return circuit;
}

static bool FinalitySerializeBPACProofV2(const CBulletproofACProof& proof,
                                         std::vector<unsigned char>& vchProofOut)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << FINALITY_BPAC_PROOF_V2;
    ss << proof;
    vchProofOut.assign(ss.begin(), ss.end());
    return !vchProofOut.empty() && vchProofOut.size() <= BPAC_V3_MAX_PROOF_SIZE;
}

static bool FinalityParseBPACProofV2(const std::vector<unsigned char>& vchProof,
                                     const std::string& strLegacyError,
                                     CBulletproofACProof& proofOut,
                                     std::string* pstrError)
{
    try {
        CDataStream ss(vchProof, SER_NETWORK, PROTOCOL_VERSION);
        uint32_t nVersion = 0;
        ss >> nVersion;
        if (nVersion == 1)
            return FinalityReject(pstrError, strLegacyError);
        if (nVersion != FINALITY_BPAC_PROOF_V2)
            return FinalityReject(pstrError, "unsupported private tally BPAC proof version");
        ss >> proofOut;
        return true;
    } catch (const std::exception&) {
        return FinalityReject(pstrError, "private tally BPAC proof parse failed");
    }
}

bool CreateFinalityAggregateThresholdProofV2(const CFinalityTallyCertificate& cert,
                                             int64_t nPrivateActiveWeight,
                                             int64_t nPrivateWinningWeight,
                                             const std::vector<unsigned char>& vchActiveBlind,
                                             const std::vector<unsigned char>& vchWinningBlind,
                                             bool fRequireZeroPrivateWinning,
                                             std::vector<unsigned char>& vchProofOut)
{
    if (nPrivateActiveWeight < 0 || nPrivateWinningWeight < 0 ||
        nPrivateActiveWeight > MAX_MONEY || nPrivateWinningWeight > MAX_MONEY ||
        nPrivateWinningWeight > nPrivateActiveWeight ||
        vchActiveBlind.size() != BLINDING_FACTOR_SIZE ||
        vchWinningBlind.size() != BLINDING_FACTOR_SIZE)
        return false;
    if (fRequireZeroPrivateWinning && nPrivateWinningWeight != 0)
        return false;
    if (cert.nTransparentActiveWeight < 0 || cert.nTransparentWinningWeight < 0 ||
        cert.nTransparentActiveWeight > MAX_MONEY || cert.nTransparentWinningWeight > MAX_MONEY)
        return false;
    if (nPrivateActiveWeight > MAX_MONEY - cert.nTransparentActiveWeight ||
        nPrivateWinningWeight > MAX_MONEY - cert.nTransparentWinningWeight)
        return false;

    uint64_t nWinningCoeff = 0;
    uint64_t nActiveCoeff = 0;
    if (cert.nTier != FINALITY_NONE)
    {
        if (!FinalityTierCoefficients(cert.nTier, nWinningCoeff, nActiveCoeff))
            return false;
        uint64_t lhs = 0;
        uint64_t rhs = 0;
        if (!FinalityMulUint64(nWinningCoeff,
                               (uint64_t)cert.nTransparentWinningWeight + (uint64_t)nPrivateWinningWeight,
                               lhs) ||
            !FinalityMulUint64(nActiveCoeff,
                               (uint64_t)cert.nTransparentActiveWeight + (uint64_t)nPrivateActiveWeight,
                               rhs))
            return false;
        if (lhs < rhs)
            return false;
    }

    CFinalityThresholdCircuitLayout layout;
    CR1CSCircuit circuit = BuildFinalityAggregateThresholdCircuit(cert,
                                                                  fRequireZeroPrivateWinning,
                                                                  layout);
    CR1CSWitness witness;
    FinalityInitWitness(circuit, witness);
    witness.v[0] = FieldFromUint64((uint64_t)nPrivateActiveWeight);
    witness.v[1] = FieldFromUint64((uint64_t)nPrivateWinningWeight);
    witness.vBlinds[0] = FinalityBlindScalarRaw(vchActiveBlind);
    witness.vBlinds[1] = FinalityBlindScalarRaw(vchWinningBlind);

    uint64_t nDiff = (uint64_t)(nPrivateActiveWeight - nPrivateWinningWeight);
    uint64_t nActiveCapSlack = (uint64_t)(MAX_MONEY - cert.nTransparentActiveWeight - nPrivateActiveWeight);
    uint64_t nWinningCapSlack = (uint64_t)(MAX_MONEY - cert.nTransparentWinningWeight - nPrivateWinningWeight);
    if (!FinalitySetBits(witness, layout.nActiveBits, FINALITY_MONEY_BITS, (uint64_t)nPrivateActiveWeight) ||
        !FinalitySetBits(witness, layout.nWinningBits, FINALITY_MONEY_BITS, (uint64_t)nPrivateWinningWeight) ||
        !FinalitySetBits(witness, layout.nDiffBits, FINALITY_MONEY_BITS, nDiff) ||
        !FinalitySetBits(witness, layout.nActiveCapSlackBits, FINALITY_MONEY_BITS, nActiveCapSlack) ||
        !FinalitySetBits(witness, layout.nWinningCapSlackBits, FINALITY_MONEY_BITS, nWinningCapSlack))
        return false;

    if (layout.nTierSlackBits >= 0)
    {
        uint64_t lhs = 0;
        uint64_t rhs = 0;
        if (!FinalityMulUint64(nWinningCoeff,
                               (uint64_t)cert.nTransparentWinningWeight + (uint64_t)nPrivateWinningWeight,
                               lhs) ||
            !FinalityMulUint64(nActiveCoeff,
                               (uint64_t)cert.nTransparentActiveWeight + (uint64_t)nPrivateActiveWeight,
                               rhs) ||
            lhs < rhs)
            return false;
        uint64_t nTierSlack = lhs - rhs;
        if (!FinalitySetBits(witness, layout.nTierSlackBits, FINALITY_TIER_SLACK_BITS, nTierSlack))
            return false;
    }

    std::vector<std::vector<unsigned char> > vCommitments;
    vCommitments.push_back(cert.activeWeightCommitment.vchCommitment);
    vCommitments.push_back(cert.winningWeightCommitment.vchCommitment);

    CBulletproofACProof proof;
    if (!CreateBulletproofACProof(circuit, witness, vCommitments, proof))
        return false;
    return FinalitySerializeBPACProofV2(proof, vchProofOut);
}

bool CreateFinalityRewardBudgetProofV2(const CFinalityTallyCertificate& cert,
                                       int64_t nPrivateActiveWeight,
                                       int64_t nPrivateRewardBudget,
                                       const std::vector<unsigned char>& vchActiveBlind,
                                       const std::vector<unsigned char>& vchRewardBlind,
                                       std::vector<unsigned char>& vchProofOut)
{
    if (nPrivateActiveWeight < 0 || nPrivateRewardBudget < 0 ||
        nPrivateActiveWeight > MAX_MONEY || nPrivateRewardBudget > MAX_MONEY ||
        vchActiveBlind.size() != BLINDING_FACTOR_SIZE ||
        vchRewardBlind.size() != BLINDING_FACTOR_SIZE)
        return false;

    int nEpochInterval = GetEpochInterval(cert.nHeight);
    uint64_t nProduct = 0;
    if (!FinalityMulUint64((uint64_t)nPrivateActiveWeight, (uint64_t)nEpochInterval, nProduct))
        return false;
    uint64_t nQ1 = nProduct / (uint64_t)COIN;
    uint64_t nR1 = nProduct % (uint64_t)COIN;
    uint64_t nCoinAge = nQ1 / 86400;
    uint64_t nR2 = nQ1 % 86400;
    uint64_t nRewardProduct = 0;
    if (!FinalityMulUint64(nCoinAge, (uint64_t)COIN_YEAR_REWARD, nRewardProduct))
        return false;
    uint64_t nReward = nRewardProduct / 365;
    uint64_t nR3 = nRewardProduct % 365;
    if (nReward > (uint64_t)MAX_MONEY ||
        nPrivateRewardBudget != (int64_t)nReward ||
        nPrivateRewardBudget != GetFinalityVoteReward(nPrivateActiveWeight, nEpochInterval))
        return false;

    CFinalityRewardCircuitLayout layout;
    CR1CSCircuit circuit = BuildFinalityRewardBudgetCircuit(cert, layout);
    CR1CSWitness witness;
    FinalityInitWitness(circuit, witness);
    witness.v[0] = FieldFromUint64((uint64_t)nPrivateActiveWeight);
    witness.v[1] = FieldFromUint64((uint64_t)nPrivateRewardBudget);
    witness.vBlinds[0] = FinalityBlindScalarRaw(vchActiveBlind);
    witness.vBlinds[1] = FinalityBlindScalarRaw(vchRewardBlind);

    if (!FinalitySetBits(witness, layout.nActiveBits, FINALITY_MONEY_BITS, (uint64_t)nPrivateActiveWeight) ||
        !FinalitySetBits(witness, layout.nRewardBits, FINALITY_MONEY_BITS, (uint64_t)nPrivateRewardBudget) ||
        !FinalitySetBits(witness, layout.nQ1Bits, FINALITY_Q64_BITS, nQ1) ||
        !FinalitySetBits(witness, layout.nR1Bits, FINALITY_COIN_REMAINDER_BITS, nR1) ||
        !FinalitySetBits(witness, layout.nCoinAgeBits, FINALITY_Q64_BITS, nCoinAge) ||
        !FinalitySetBits(witness, layout.nR2Bits, FINALITY_SECONDS_REMAINDER_BITS, nR2) ||
        !FinalitySetBits(witness, layout.nR3Bits, FINALITY_REWARD_REMAINDER_BITS, nR3) ||
        !FinalitySetBits(witness, layout.nR1SlackBits, FINALITY_COIN_REMAINDER_BITS, (uint64_t)COIN - 1 - nR1) ||
        !FinalitySetBits(witness, layout.nR2SlackBits, FINALITY_SECONDS_REMAINDER_BITS, 86400 - 1 - nR2) ||
        !FinalitySetBits(witness, layout.nR3SlackBits, FINALITY_REWARD_REMAINDER_BITS, 365 - 1 - nR3) ||
        !FinalitySetBits(witness, layout.nRewardCapSlackBits, FINALITY_MONEY_BITS, (uint64_t)(MAX_MONEY - nPrivateRewardBudget)))
        return false;

    std::vector<std::vector<unsigned char> > vCommitments;
    vCommitments.push_back(cert.activeWeightCommitment.vchCommitment);
    vCommitments.push_back(cert.rewardBudgetCommitment.vchCommitment);

    CBulletproofACProof proof;
    if (!CreateBulletproofACProof(circuit, witness, vCommitments, proof))
        return false;
    return FinalitySerializeBPACProofV2(proof, vchProofOut);
}

bool VerifyFinalityAggregateThresholdProofV2(const CFinalityTallyCertificate& cert,
                                             int64_t nMatchedTransparentActiveWeight,
                                             int64_t nMatchedTransparentWinningWeight,
                                             bool fRequireZeroPrivateWinning,
                                             std::string* pstrError)
{
    if (cert.nTransparentActiveWeight != nMatchedTransparentActiveWeight ||
        cert.nTransparentWinningWeight != nMatchedTransparentWinningWeight)
        return FinalityReject(pstrError, "aggregate threshold transparent input mismatch");

    CBulletproofACProof proof;
    if (!FinalityParseBPACProofV2(cert.vchAggregateThresholdProof,
                                  "legacy aggregate threshold opening proof rejected for private certificate",
                                  proof, pstrError))
        return false;

    CFinalityThresholdCircuitLayout layout;
    CR1CSCircuit circuit = BuildFinalityAggregateThresholdCircuit(cert,
                                                                  fRequireZeroPrivateWinning,
                                                                  layout);
    std::vector<std::vector<unsigned char> > vCommitments;
    vCommitments.push_back(cert.activeWeightCommitment.vchCommitment);
    vCommitments.push_back(cert.winningWeightCommitment.vchCommitment);
    if (!VerifyBulletproofACProof(circuit, vCommitments, proof))
        return FinalityReject(pstrError, "aggregate threshold BPAC proof failed");
    return true;
}

bool VerifyFinalityRewardBudgetProofV2(const CFinalityTallyCertificate& cert,
                                       int64_t nMatchedTransparentRewardBudget,
                                       std::string* pstrError)
{
    if (cert.nTransparentRewardBudget != nMatchedTransparentRewardBudget)
        return FinalityReject(pstrError, "transparent reward budget mismatch");

    CBulletproofACProof proof;
    if (!FinalityParseBPACProofV2(cert.vchRewardBudgetProof,
                                  "legacy reward-budget opening proof rejected for private certificate",
                                  proof, pstrError))
        return false;

    CFinalityRewardCircuitLayout layout;
    CR1CSCircuit circuit = BuildFinalityRewardBudgetCircuit(cert, layout);
    std::vector<std::vector<unsigned char> > vCommitments;
    vCommitments.push_back(cert.activeWeightCommitment.vchCommitment);
    vCommitments.push_back(cert.rewardBudgetCommitment.vchCommitment);
    if (!VerifyBulletproofACProof(circuit, vCommitments, proof))
        return FinalityReject(pstrError, "reward-budget BPAC proof failed");
    return true;
}

static bool DeserializeFinalityBindingProof(const std::vector<unsigned char>& vchProof,
                                            CBindingSignature& sigOut)
{
    if (vchProof.empty() || vchProof.size() > BPAC_V3_MAX_PROOF_SIZE)
        return false;
    try {
        CDataStream ss(vchProof, SER_NETWORK, PROTOCOL_VERSION);
        ss >> sigOut;
    } catch (const std::exception&) {
        return false;
    }
    return !sigOut.IsNull() && sigOut.vchSignature.size() == BINDING_SIGNATURE_SIZE;
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
    {
        CBindingSignature bindingSig;
        if (!DeserializeFinalityBindingProof(vchBindingProof, bindingSig))
            return FinalityReject(pstrError, "private finality proof invalid binding proof");
    }
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
    ss << hashCurveRoot;
    ss << hashNullifierRoot;
    ss << committeeSetHash;
    ss << stakeWeightCommitment;
    ss << rewardCommitment;
    ss << vEncryptedRecipientShares;
    ss << vchShareProof;
    return ss.GetHash();
}

bool CFinalityTallyShare::IsValidBasic() const
{
    if (nVersion != 2 || nEpoch < 0 || voteNullifier == 0 || hashBlock == 0)
        return false;
    if (hashCurveRoot == 0 || hashNullifierRoot == 0 || committeeSetHash == 0)
        return false;
    if (stakeWeightCommitment.IsNull() || rewardCommitment.IsNull())
        return false;
    if (vEncryptedRecipientShares.empty() ||
        vEncryptedRecipientShares.size() > FINALITY_MAX_TALLY_COMMITTEE)
        return false;
    for (const std::vector<unsigned char>& vchCiphertext : vEncryptedRecipientShares)
    {
        if (vchCiphertext.empty() || vchCiphertext.size() > BPAC_V3_MAX_PROOF_SIZE)
            return false;
    }
    if (vchShareProof.empty() || vchShareProof.size() > BPAC_V3_MAX_PROOF_SIZE)
        return false;
    return true;
}

uint256 CFinalityTallyAggregatePartial::GetContentDigest() const
{
    // Everything that identifies the partial's content, EXCLUDING vchSourceSig.
    // This is what the source member signs (D1.1) and the equivocation key.
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("Innova/Finality/PartialAuth/v1");
    ss << nVersion;
    ss << nEpoch;
    ss << hashBlock;
    ss << hashCurveRoot;
    ss << hashNullifierRoot;
    ss << committeeSetHash;
    ss << nSourceIndex;
    ss << vTallyShareHashes;
    ss << vEncryptedRecipientPartials;
    return ss.GetHash();
}

uint256 CFinalityTallyAggregatePartial::GetHash() const
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << nVersion;
    ss << nEpoch;
    ss << hashBlock;
    ss << hashCurveRoot;
    ss << hashNullifierRoot;
    ss << committeeSetHash;
    ss << nSourceIndex;
    ss << vTallyShareHashes;
    ss << vEncryptedRecipientPartials;
    if (nVersion >= 3)
        ss << vchSourceSig;
    return ss.GetHash();
}

bool CFinalityTallyAggregatePartial::IsValidBasic() const
{
    if ((nVersion != 2 && nVersion != 3) || nEpoch < 0 || hashBlock == 0 ||
        hashCurveRoot == 0 || hashNullifierRoot == 0 || committeeSetHash == 0)
        return false;
    if (nVersion >= 3 && (vchSourceSig.empty() || vchSourceSig.size() > 80))
        return false;
    if (nSourceIndex < 0 || nSourceIndex >= FINALITY_MAX_TALLY_COMMITTEE)
        return false;
    if (vTallyShareHashes.empty() || vTallyShareHashes.size() > FINALITY_MAX_VOTES)
        return false;
    std::set<uint256> setShareHashes;
    for (const uint256& hashShare : vTallyShareHashes)
    {
        if (hashShare == 0 || !setShareHashes.insert(hashShare).second)
            return false;
    }
    if (vEncryptedRecipientPartials.empty() ||
        vEncryptedRecipientPartials.size() > FINALITY_MAX_TALLY_COMMITTEE)
        return false;
    if (nSourceIndex >= (int)vEncryptedRecipientPartials.size())
        return false;
    for (const std::vector<unsigned char>& vchCiphertext : vEncryptedRecipientPartials)
    {
        if (vchCiphertext.empty() || vchCiphertext.size() > BPAC_V3_MAX_PROOF_SIZE)
            return false;
    }
    return true;
}

uint256 CFinalityTallyCertificate::GetSignatureDigest() const
{
    // Everything the committee members sign — the full tally result EXCLUDING
    // the signer-set vectors (so signatures cannot affect the digest they
    // commit to). Domain-separated.
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("Innova/Finality/CertAuth/v1");
    ss << nVersion;
    ss << nEpoch;
    ss << hashBlock;
    ss << nHeight;
    ss << nTier;
    ss << nConsecutiveHardCount;
    ss << hashCurveRoot;
    ss << hashNullifierRoot;
    ss << committeeSetHash;
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
    if (nVersion >= 2)
        ss << committeeSetHash;
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
    if (nVersion >= 3)
    {
        ss << vSignerIndexes;
        ss << vSignerSigs;
    }
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
    if (nVersion < 1 || nVersion > 3)
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

    // v3 (D2) carries a committee signer-set. Structural checks only here;
    // signature verification against the canonical committee for nEpoch happens
    // in CheckTallyCertificate (it needs chain context). v1/v2 must not carry one.
    if (nVersion >= 3)
    {
        if (vSignerIndexes.size() != vSignerSigs.size())
            return FinalityReject(pstrError, "tally certificate signer index/sig count mismatch");
        // An empty signer-set is a structurally-valid in-collection candidate (a
        // member validates the candidate's content before adding its own
        // signature). The lower bound (>= M) is a semantic committee rule
        // enforced in CheckTallyCertificate's committee-signature verification
        // (VerifyMofNCommitteeSignatures), which every block/finality path runs
        // for private v3 certs; only the structural upper bound belongs here.
        if (vSignerIndexes.size() > FINALITY_MAX_TALLY_COMMITTEE)
            return FinalityReject(pstrError, "tally certificate signer-set size out of range");
        uint16_t nPrev = 0; bool fFirst = true;
        for (size_t k = 0; k < vSignerIndexes.size(); k++)
        {
            uint16_t idx = vSignerIndexes[k];
            if (idx >= FINALITY_MAX_TALLY_COMMITTEE)
                return FinalityReject(pstrError, "tally certificate signer index out of range");
            if (!fFirst && idx <= nPrev)
                return FinalityReject(pstrError, "tally certificate signer indexes not strictly ascending");
            nPrev = idx; fFirst = false;
            if (vSignerSigs[k].empty() || vSignerSigs[k].size() > 80)
                return FinalityReject(pstrError, "tally certificate signer signature malformed");
        }
    }
    else if (!vSignerIndexes.empty() || !vSignerSigs.empty())
    {
        return FinalityReject(pstrError, "pre-v3 tally certificate must not carry a signer-set");
    }

    if (HasPrivateWeight())
    {
        if (nVersion < 2)
            return FinalityReject(pstrError, "private tally certificates require version >= 2");
        if (hashCurveRoot == 0 || hashNullifierRoot == 0)
            return FinalityReject(pstrError, "private tally certificate missing epoch roots");
        if (committeeSetHash == 0)
            return FinalityReject(pstrError, "private tally certificate missing committee set hash");
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

// Note- and epoch-bound nullifier tag for a private vote: folding the epoch in
// lets a stake vote once per epoch but not twice within one.
uint256 FinalityNullifierTag(const std::vector<unsigned char>& vchNullifierPoint, int nEpoch)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("Innova/Finality/NfTag/v1");
    ss << vchNullifierPoint;
    ss << nEpoch;
    return ss.GetHash();
}

// Context the vote nullifier binding proof commits to (no replay across epochs).
uint256 FinalityNullifierBindContext(int nEpoch, const uint256& hashEpochBlock)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("Innova/Finality/NfBindCtx/v1");
    ss << nEpoch;
    ss << hashEpochBlock;
    return ss.GetHash();
}

bool CFinalityTracker::CheckVote(const CFinalityVote& vote, CTxDB& txdb, std::string* pstrError,
                                 int nContextHeight) const
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

    // R1: connect-time vote-inclusion window (fork-gated). An epoch-E vote is
    // block-valid only in a containing block within [H_E, H_E + K). vote.nHeight
    // is the epoch BOUNDARY (the vote's target), not the containing block, so the
    // window must be checked against nContextHeight. nContextHeight < 0 is a
    // relay/pre-check context and skips the window. Freezing the connected vote
    // set this way makes the certificate coverage rule (R3) satisfiable and
    // closes the late-"drip"-vote liveness griefing vector.
    if (nContextHeight >= 0 && nContextHeight >= FORK_HEIGHT_VOTESET_ROOT)
    {
        int nBoundary = GetEpochBoundaryHeight(vote.nEpoch, nContextHeight);
        if (nContextHeight < nBoundary ||
            nContextHeight >= nBoundary + FINALITY_VOTE_INCLUSION_WINDOW)
            return reject("finality vote outside epoch vote-inclusion window");
    }

    std::map<uint256, CBlockIndex*>::iterator miEpoch = mapBlockIndex.find(vote.hashBlock);
    if (miEpoch == mapBlockIndex.end())
        return reject("epoch block not found");
    CBlockIndex* pEpochBlock = miEpoch->second;
    if (pEpochBlock->nHeight != vote.nHeight)
        return reject("epoch block height mismatch");
    if (pEpochBlock->nHeight < FORK_HEIGHT_DAG)
        return reject("finality votes require DAG epoch mode");
    if (!pEpochBlock->IsProofOfWork())
        return reject("finality votes must target proof-of-work epoch blocks");

    if (vote.IsPrivate())
    {
        if (vote.privateProof.hashEpochBlock != vote.hashBlock ||
            vote.privateProof.nEpoch != vote.nEpoch ||
            vote.privateProof.nullifier != vote.nullifier)
            return reject("private finality proof binding mismatch");
        if (!vote.privateProof.IsValidBasic(pstrError))
            return false;

        // Anchor to the finalized epoch DETERMINISTICALLY from the including block's
        // chain context (nContextHeight), not the node-local live finalization tip.
        // This is what keeps ConnectBlock deterministic across nodes. Relay-time checks
        // (nContextHeight < 0) fall back to the live tip (lenient; not consensus).
        CEpochState finalizedEpochState;
        bool fHaveFinalized = (nContextHeight >= 0)
            ? g_dagManager.GetFinalizedEpochStateAsOf(nContextHeight, finalizedEpochState)
            : g_dagManager.GetLastFinalizedEpochState(finalizedEpochState);
        if (!fHaveFinalized)
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

        // B2-e: a half-aggregated M-of-N (V3_COLD) vote carries the J-free value commitment cv_plain in
        // stakeWeightCommitment (so the whole tally + nullifier-binding + share path is byte-identical to
        // V2 and the J term never enters a persisted tally artifact). The real curve-tree leaf is
        // cv3 = cv_plain + delegationHash*J; reconstruct it here so the FCMP membership and the V3 kernel
        // proof verify against the actual leaf. delegationHash is consensus-bound to cv3 by the kernel
        // proof below (SetHash recompute + value-link + range), so a wrong delegationHash fails membership
        // or the kernel proof. V2 (and the 1-of-1 nThresholdM==0 case) keep cv_plain as the leaf directly.
        CPedersenCommitment membershipLeaf = vote.privateProof.stakeWeightCommitment;
        if (vote.nProofMode == FINALITY_PROOF_NULLSTAKE_V3_COLD)
        {
            if (!NullStakeMofNReconstructLeaf(vote.privateProof.stakeWeightCommitment,
                                              vote.privateProof.nullStakeV3Proof.delegationHash,
                                              membershipLeaf))
                return reject("private finality V3 vote leaf reconstruction failed");
        }
        if (!VerifyFCMPProof(finalizedCurveTree.GetRootNode(),
                             vote.privateProof.fcmpProof,
                             membershipLeaf))
            return reject("private finality FCMP proof failed");
        if (vote.nProofMode == FINALITY_PROOF_NULLSTAKE_V2)
        {
            // The kernel circuit takes its public inputs from the proof itself,
            // so every unpinned field is an offline grinding dimension. Pin the
            // modifier and timestamp to the epoch block and the metadata to the
            // synthetic constants: eligibility then reduces to one deterministic
            // value-weighted lottery per note per epoch.
            if (pEpochBlock->nHeight >= FORK_HEIGHT_KERNEL_PINNING)
            {
                const CNullStakeKernelProofV2& kp = vote.privateProof.nullStakeV2Proof;
                uint64_t nExpectedModifier = pEpochBlock->pprev ?
                                             pEpochBlock->pprev->nStakeModifier :
                                             pEpochBlock->nStakeModifier;
                if (kp.nStakeModifier != nExpectedModifier)
                    return reject("private finality vote kernel stake modifier not pinned to epoch block");
                if (kp.nTimeTx != pEpochBlock->nTime)
                    return reject("private finality vote kernel nTimeTx not pinned to epoch block time");
                if (!CheckNullStakeKernelPinning(kp.nBlockTimeFrom, kp.nTxPrevOffset,
                                                 kp.nTxTimePrev, kp.nVoutN, kp.nTimeTx))
                    return reject("private finality vote kernel metadata not pinned");
            }
            if (!VerifyNullStakeKernelProofV2(vote.privateProof.nullStakeV2Proof,
                                              vote.privateProof.stakeWeightCommitment,
                                              pEpochBlock->nBits))
                return reject("private finality NullStake V2 proof failed");
        }
        else if (vote.nProofMode == FINALITY_PROOF_NULLSTAKE_V3_COLD)
        {
            // B2-e: half-aggregated M-of-N (nThresholdM > 0) private votes activate only at the
            // DELEGSET fork; before it, only the legacy 1-of-1 (nThresholdM == 0) is valid.
            if (vote.privateProof.nullStakeV3Proof.nThresholdM > 0 &&
                pEpochBlock->nHeight < FORK_HEIGHT_NULLSTAKE_DELEGSET)
                return reject("private finality M-of-N NullStake vote before DELEGSET fork height");

            if (pEpochBlock->nHeight >= FORK_HEIGHT_KERNEL_PINNING)
            {
                const CNullStakeKernelProofV3& kp = vote.privateProof.nullStakeV3Proof;
                uint64_t nExpectedModifier = pEpochBlock->pprev ?
                                             pEpochBlock->pprev->nStakeModifier :
                                             pEpochBlock->nStakeModifier;
                if (kp.nStakeModifier != nExpectedModifier)
                    return reject("private finality vote kernel stake modifier not pinned to epoch block");
                if (kp.nTimeTx != pEpochBlock->nTime)
                    return reject("private finality vote kernel nTimeTx not pinned to epoch block time");
                if (!CheckNullStakeKernelPinning(kp.nBlockTimeFrom, kp.nTxPrevOffset,
                                                 kp.nTxTimePrev, kp.nVoutN, kp.nTimeTx))
                    return reject("private finality vote kernel metadata not pinned");
            }
            // cv3 (the reconstructed leaf), NOT the cv_plain field: VerifyNullStakeKernelProofV3 takes the
            // 3-generator leaf and re-derives cv_plain = cv3 - delegationHash*J internally for its range/link.
            if (!VerifyNullStakeKernelProofV3(vote.privateProof.nullStakeV3Proof,
                                              membershipLeaf,
                                              pEpochBlock->nBits))
                return reject("private finality NullStake V3 proof failed");
        }

        // Vote nullifier must be bound to the staked note (no double-voting an
        // epoch under different nullifiers to inflate hidden weight).
        if (pEpochBlock->nHeight >= FORK_HEIGHT_NULLIFIER_BINDING)
        {
            const std::vector<unsigned char>& nf = vote.privateProof.vchNullifierPoint;
            if (nf.size() != NULLIFIER_POINT_SIZE ||
                vote.privateProof.vchNullifierBindingProof.size() != NULLIFIER_BINDING_PROOF_SIZE)
                return reject("private finality vote missing nullifier binding proof");
            if (vote.nullifier != FinalityNullifierTag(nf, vote.nEpoch))
                return reject("private finality vote nullifier not bound to staked note");
            uint256 nfCtx = FinalityNullifierBindContext(vote.nEpoch, vote.hashBlock);
            if (!VerifyNullifierBindingProof(vote.privateProof.stakeWeightCommitment, nf, nfCtx,
                                             vote.privateProof.vchNullifierBindingProof))
                return reject("private finality vote nullifier binding proof failed");
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

bool CFinalityTracker::CheckTallyCertificate(const CFinalityTallyCertificate& cert, CTxDB& txdb, std::string* pstrError,
                                             const std::vector<CFinalityVote>* pvBlockVotes,
                                             bool fAllowPendingVotes,
                                             int nContextHeight,
                                             bool fSkipCommitteeSigs) const
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

    // D2: from the governance fork, a private tally certificate must carry the
    // canonical committee's M-of-N signatures over its content. Gated on the
    // cert's (consensus-validated) epoch-boundary height so the rule is
    // deterministic. The resolver is consensus-uniform; while no committee is
    // pinned for the epoch it is inert (certs validate as pre-fork).
    if (!fSkipCommitteeSigs && cert.HasPrivateWeight() && cert.nHeight >= FORK_HEIGHT_TALLY_GOVERNANCE)
    {
        std::vector<CPubKey> vCommittee;
        int nM = 0;
        uint256 setHash;
        if (GetCanonicalFinalityCommittee(cert.nEpoch, vCommittee, nM, setHash))
        {
            // A1 recovery (union): if the cert is signed by the pinned recovery
            // committee AND HARD finality has stalled past the gap for this
            // epoch, accept it from the recovery set — a dead/sub-threshold
            // primary committee cannot otherwise be unstuck. The slow-but-alive
            // primary still works via the canonical path.
            std::vector<CPubKey> vRec; int nRecM = 0; uint256 recSetHash;
            // Recovery-window gate uses the deterministic finalized height as of the
            // including block (relay-time: live tip), so the recovery-committee path is
            // accepted/rejected identically on every node.
            int nRecoveryFinalizedHeight = (nContextHeight >= 0)
                ? g_dagManager.GetDeterministicFinalizedHeight(GetEpochForHeight(nContextHeight) - 1)
                : GetFinalizedHeight();
            if (cert.committeeSetHash != setHash &&
                GetRecoveryFinalityCommittee(vRec, nRecM, recSetHash) &&
                cert.committeeSetHash == recSetHash &&
                FinalityCertInRecoveryWindow(cert.nEpoch, nRecoveryFinalizedHeight))
            {
                std::string strSig;
                if (!CheckTallyCertificateCommitteeSignatures(cert, vRec, nRecM, recSetHash, &strSig))
                    return reject(strSig);
            }
            else
            {
                std::string strSig;
                if (!CheckTallyCertificateCommitteeSignatures(cert, vCommittee, nM, setHash, &strSig))
                    return reject(strSig);
            }
        }
    }

    // R2: connect-time cert-position floor + staleness (fork-gated). A cert for
    // epoch E is block-valid only at containing height >= H_E + K (after the
    // vote-inclusion window closes, so the covered vote set is frozen) and may
    // finalize only the current or immediately-preceding epoch (keeps pruned
    // epochs consensus-irrelevant). nContextHeight < 0 (relay/RPC) skips this.
    if (nContextHeight >= 0 && nContextHeight >= FORK_HEIGHT_VOTESET_ROOT)
    {
        int nCertBoundary = GetEpochBoundaryHeight(cert.nEpoch, nContextHeight);
        if (nContextHeight < nCertBoundary + FINALITY_VOTE_INCLUSION_WINDOW)
            return reject("tally certificate before epoch vote-inclusion window close");
        int nContextEpoch = GetEpochForHeight(nContextHeight);
        if (cert.nEpoch > nContextEpoch)
            return reject("tally certificate finalizes a future epoch");
        // Staleness bound matches the HARD-confirmation streak depth so a cert
        // delayed within the streak window can still finalize its epoch (a tighter
        // bound would permanently strand a late cert and reset the streak). The
        // bound stays well inside the prune horizon (current-10), so mapEpochVotes
        // for the covered epoch is never pruned out from under R3.
        if (cert.nEpoch + FINALITY_CONFIRMATION_EPOCHS < nContextEpoch)
            return reject("tally certificate finalizes a stale epoch");
    }

    std::map<uint256, CBlockIndex*>::iterator miEpoch = mapBlockIndex.find(cert.hashBlock);
    if (miEpoch == mapBlockIndex.end())
        return reject("tally certificate block not found");
    CBlockIndex* pEpochBlock = miEpoch->second;
    if (pEpochBlock->nHeight != cert.nHeight)
        return reject("tally certificate block height mismatch");
    if (pEpochBlock->nHeight < FORK_HEIGHT_DAG)
        return reject("tally certificates require DAG epoch mode");
    if (!pEpochBlock->IsProofOfWork())
        return reject("tally certificates must target proof-of-work epoch blocks");
    if (cert.HasPrivateWeight())
    {
        // Deterministic anchor from the including block's chain context (see CheckVote).
        CEpochState finalizedEpochState;
        bool fHaveFinalized = (nContextHeight >= 0)
            ? g_dagManager.GetFinalizedEpochStateAsOf(nContextHeight, finalizedEpochState)
            : g_dagManager.GetLastFinalizedEpochState(finalizedEpochState);
        if (!fHaveFinalized)
            return reject("private tally certificate missing finalized epoch roots");
        if (cert.hashCurveRoot != finalizedEpochState.hashCurveRoot ||
            cert.hashNullifierRoot != finalizedEpochState.hashNullifierRoot)
            return reject("private tally certificate not anchored to last finalized epoch root");
    }

    LOCK(cs_finality);

    // Fork-gated connect-time rules. fEnforceVoteSet drives R3 coverage equality.
    // fStrictConnectedShares additionally requires consensus mode (no pending
    // relay state), so cert validity resolves shares only from the chain-connected
    // set (restored from LevelDB on restart) and cannot diverge between nodes.
    bool fEnforceVoteSet = (nContextHeight >= 0 && nContextHeight >= FORK_HEIGHT_VOTESET_ROOT);
    bool fStrictConnectedShares = (fEnforceVoteSet && !fAllowPendingVotes);

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
        bool fHaveVote = false;
        auto itConnected = mapConnectedVotes.find(nf);
        if (itConnected != mapConnectedVotes.end())
        {
            vote = itConnected->second;
            fHaveVote = true;
        }
        if (!fHaveVote && pvBlockVotes)
        {
            for (const CFinalityVote& blockVote : *pvBlockVotes)
            {
                if (blockVote.nullifier == nf)
                {
                    vote = blockVote;
                    fHaveVote = true;
                    break;
                }
            }
        }
        if (!fHaveVote && fAllowPendingVotes)
        {
            auto itPending = mapPendingVotes.find(nf);
            if (itPending != mapPendingVotes.end())
            {
                vote = itPending->second;
                fHaveVote = true;
            }
        }
        if (!fHaveVote)
            return reject("tally certificate references unknown vote nullifier");

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

            bool fFoundShare = false;
            for (std::map<uint256, CFinalityTallyShare>::const_iterator itShare = mapTallyShares.begin();
                 itShare != mapTallyShares.end(); ++itShare)
            {
                const CFinalityTallyShare& share = itShare->second;
                // Consensus mode resolves shares only from the chain-connected
                // set, never node-local relay/gossip state, so an extra gossiped
                // committee share cannot inflate the expected-share set on one
                // node and flip cert validity (chain split). Relay/miner/RPC
                // (fAllowPendingVotes) still consult the full pool.
                if (fStrictConnectedShares && !setConnectedTallyShares.count(itShare->first))
                    continue;
                if (share.nVersion != 2 ||
                    share.nEpoch != vote.nEpoch ||
                    share.voteNullifier != vote.nullifier ||
                    share.hashBlock != vote.hashBlock ||
                    share.hashCurveRoot != cert.hashCurveRoot ||
                    share.hashNullifierRoot != cert.hashNullifierRoot ||
                    share.committeeSetHash != cert.committeeSetHash ||
                    !(share.stakeWeightCommitment == vote.privateProof.stakeWeightCommitment) ||
                    !(share.rewardCommitment == vote.privateProof.rewardCommitment))
                    continue;
                setExpectedTallyShareHashes.insert(itShare->first);
                fFoundShare = true;
            }
            if (!fFoundShare)
                return reject("private tally certificate missing v2 tally share for vote");
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

    // R3: connect-time coverage equality (fork-gated). The certificate must
    // reference EXACTLY the epoch-E votes connected on this chain (mapEpochVotes,
    // a deterministic, reorg-stable function of the selected chain). Omitting any
    // connected vote is rejected, which forecloses denominator-deflation
    // censorship and minority-block finalization: the winning partition is
    // re-derived above from each vote's public hashBlock, so against the full
    // connected denominator a minority block cannot clear the 2/3 tier. R1/R2
    // guarantee the window has closed and no further epoch-E vote can connect, so
    // the set is frozen. Every cert nullifier was resolved above to a connected
    // epoch-E vote and cert.vVoteNullifiers is dedup-checked in IsValidBasic, so
    // equal size plus full containment of the connected set is exact set-equality.
    if (fEnforceVoteSet)
    {
        std::map<int, std::vector<CFinalityVote> >::const_iterator itEpoch = mapEpochVotes.find(cert.nEpoch);
        size_t nConnected = (itEpoch != mapEpochVotes.end()) ? itEpoch->second.size() : 0;
        if (cert.vVoteNullifiers.size() != nConnected)
            return reject("tally certificate does not cover the full connected epoch vote set");
        if (itEpoch != mapEpochVotes.end())
        {
            std::set<uint256> setCertNullifiers(cert.vVoteNullifiers.begin(), cert.vVoteNullifiers.end());
            for (const CFinalityVote& v : itEpoch->second)
                if (!setCertNullifiers.count(v.nullifier))
                    return reject("tally certificate omits a connected epoch vote");
        }
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
        for (const uint256& hashShare : cert.vTallyShareHashes)
        {
            CFinalityTallyShare share;
            std::map<uint256, CFinalityTallyShare>::const_iterator itShare = mapTallyShares.find(hashShare);
            if (itShare == mapTallyShares.end())
                return reject("private tally certificate references unknown tally share");
            if (fStrictConnectedShares && !setConnectedTallyShares.count(hashShare))
                return reject("private tally certificate references unconnected tally share");
            share = itShare->second;
            if (share.committeeSetHash != cert.committeeSetHash)
                return reject("private tally certificate share committee mismatch");
            if (share.hashCurveRoot != cert.hashCurveRoot ||
                share.hashNullifierRoot != cert.hashNullifierRoot)
                return reject("private tally certificate share root mismatch");
        }
        if (setExpectedTallyShareHashes.size() != cert.vTallyShareHashes.size())
            return reject("private tally certificate share set mismatch");
        for (const uint256& hashShare : cert.vTallyShareHashes)
        {
            if (!setExpectedTallyShareHashes.count(hashShare))
                return reject("private tally certificate references unknown tally share");
        }
        bool fRequireZeroPrivateWinning = !fHavePrivateWinningCommitment;
        if (!VerifyFinalityAggregateThresholdProofV2(cert,
                                                     nTransparentActiveWeight,
                                                     nTransparentWinningWeight,
                                                     fRequireZeroPrivateWinning,
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
        if (!VerifyFinalityRewardBudgetProofV2(cert,
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

bool CFinalityTracker::CheckTallyShare(const CFinalityTallyShare& share,
                                       std::string* pstrError,
                                       const std::vector<CFinalityVote>* pvBlockVotes,
                                       bool fAllowPendingVotes,
                                       int nContextHeight) const
{
    auto reject = [&](const std::string& strReason) -> bool {
        if (pstrError)
            *pstrError = strReason;
        return false;
    };

    if (!share.IsValidBasic())
        return reject("invalid tally share structure");
    CBindingSignature bindingSig;
    if (!DeserializeFinalityBindingProof(share.vchShareProof, bindingSig))
        return reject("invalid tally share proof encoding");

    int nCurrentEpoch = 0;
    if (nContextHeight >= 0)
    {
        nCurrentEpoch = GetEpochForHeight(nContextHeight);
    }
    else
    {
        CBlockIndex* pBest = pindexBest;
        if (pBest)
            nCurrentEpoch = GetEpochForHeight(pBest->nHeight);
    }
    if (share.nEpoch > nCurrentEpoch + 2)
        return reject("tally share is too far in the future");

    LOCK(cs_finality);
    CFinalityVote vote;
    bool fHaveVote = false;
    auto itConnected = mapConnectedVotes.find(share.voteNullifier);
    if (itConnected != mapConnectedVotes.end())
    {
        vote = itConnected->second;
        fHaveVote = true;
    }
    else if (fAllowPendingVotes)
    {
        auto itPending = mapPendingVotes.find(share.voteNullifier);
        if (itPending != mapPendingVotes.end())
        {
            vote = itPending->second;
            fHaveVote = true;
        }
    }
    if (!fHaveVote && pvBlockVotes)
    {
        for (const CFinalityVote& blockVote : *pvBlockVotes)
        {
            if (blockVote.nullifier == share.voteNullifier)
            {
                vote = blockVote;
                fHaveVote = true;
                break;
            }
        }
    }

    if (!fHaveVote)
        return reject("tally share references unknown vote");
    if (!vote.IsPrivate())
        return reject("tally share references a transparent vote");
    if (vote.nEpoch != share.nEpoch || vote.hashBlock != share.hashBlock)
        return reject("tally share vote binding mismatch");
    if (vote.privateProof.hashCurveRoot != share.hashCurveRoot ||
        vote.privateProof.hashNullifierRoot != share.hashNullifierRoot)
        return reject("tally share root mismatch");
    if (!(vote.privateProof.stakeWeightCommitment == share.stakeWeightCommitment) ||
        !(vote.privateProof.rewardCommitment == share.rewardCommitment))
        return reject("tally share commitment mismatch");
    if (vote.privateProof.vchBindingProof != share.vchShareProof)
        return reject("tally share proof mismatch");

    return true;
}

bool CFinalityTracker::AddTallyShare(const CFinalityTallyShare& share, bool fCheck)
{
    if (fCheck)
    {
        std::string strError;
        if (!CheckTallyShare(share, &strError))
        {
            if (fDebug)
                printf("AddTallyShare: rejected tally share: %s\n", strError.c_str());
            return false;
        }
    }

    LOCK(cs_finality);
    uint256 hashShare = share.GetHash();
    if (mapTallyShares.count(hashShare))
        return false;
    mapTallyShares[hashShare] = share;
    return true;
}

bool CFinalityTracker::CheckTallyAggregatePartial(const CFinalityTallyAggregatePartial& partial,
                                                  std::string* pstrError) const
{
    auto reject = [&](const std::string& strReason) -> bool {
        if (pstrError)
            *pstrError = strReason;
        return false;
    };

    if (!partial.IsValidBasic())
        return reject("invalid tally aggregate partial structure");

    int nCurrentEpoch = 0;
    CBlockIndex* pBest = pindexBest;
    if (pBest)
        nCurrentEpoch = GetEpochForHeight(pBest->nHeight);
    if (partial.nEpoch > nCurrentEpoch + 2)
        return reject("tally aggregate partial is too far in the future");

    // D1.1: when we know the committee set this partial claims (our local
    // config matches its committeeSetHash), authenticate the source member's
    // signature so nSourceIndex is attributable. Partials for an unknown
    // committee skip the signature check (we lack the pubkeys to verify) but
    // still undergo the share-binding checks below.
    {
        CFinalityTallyConfig config = GetFinalityTallyConfig();
        if (config.committeeSetHash == partial.committeeSetHash &&
            !config.vCommitteePubKeys.empty())
        {
            if (partial.nVersion < 3)
                return reject("tally aggregate partial missing source signature");
            if (partial.nSourceIndex >= (int)config.vCommitteePubKeys.size())
                return reject("tally aggregate partial source index out of committee range");
            const CPubKey& pubSource = config.vCommitteePubKeys[partial.nSourceIndex];
            if (!pubSource.IsValid() ||
                !pubSource.Verify(partial.GetContentDigest(), partial.vchSourceSig))
                return reject("tally aggregate partial source signature invalid");
        }
    }

    LOCK(cs_finality);
    for (const uint256& hashShare : partial.vTallyShareHashes)
    {
        std::map<uint256, CFinalityTallyShare>::const_iterator itShare = mapTallyShares.find(hashShare);
        if (itShare == mapTallyShares.end())
            return reject("tally aggregate partial references unknown tally share");
        const CFinalityTallyShare& share = itShare->second;
        if (share.nEpoch != partial.nEpoch ||
            share.hashBlock != partial.hashBlock ||
            share.hashCurveRoot != partial.hashCurveRoot ||
            share.hashNullifierRoot != partial.hashNullifierRoot ||
            share.committeeSetHash != partial.committeeSetHash)
            return reject("tally aggregate partial share binding mismatch");
    }

    // Equivocation detection: a member must not sign two different partial
    // contents for the same (committee, epoch, source). A second, conflicting
    // signed partial is a publishable equivocation; reject the duplicate.
    if (partial.nVersion >= 3)
    {
        std::pair<uint256, std::pair<int,int> > key(partial.committeeSetHash,
            std::make_pair(partial.nEpoch, partial.nSourceIndex));
        std::map<std::pair<uint256, std::pair<int,int> >, uint256>::const_iterator itEq =
            mapTallyPartialBySource.find(key);
        if (itEq != mapTallyPartialBySource.end() && itEq->second != partial.GetContentDigest())
            return reject("tally aggregate partial equivocation: source already signed a different partial");
    }

    return true;
}

bool CFinalityTracker::AddTallyAggregatePartial(const CFinalityTallyAggregatePartial& partial,
                                                bool fCheck)
{
    if (fCheck)
    {
        std::string strError;
        if (!CheckTallyAggregatePartial(partial, &strError))
        {
            if (fDebug)
                printf("AddTallyAggregatePartial: rejected partial: %s\n", strError.c_str());
            return false;
        }
    }

    LOCK(cs_finality);
    uint256 hashPartial = partial.GetHash();
    if (mapTallyAggregatePartials.count(hashPartial))
        return false;
    mapTallyAggregatePartials[hashPartial] = partial;
    if (partial.nVersion >= 3)
    {
        std::pair<uint256, std::pair<int,int> > key(partial.committeeSetHash,
            std::make_pair(partial.nEpoch, partial.nSourceIndex));
        mapTallyPartialBySource[key] = partial.GetContentDigest();
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
        if (mapPendingTallyCertificates.count(hashCert) ||
            mapConnectedTallyCertificates.count(hashCert))
        {
            if (GetBoolArg("-debugfinalityrelay", false))
                printf("FINALITY relay-duplicate ftcert=%s\n",
                       hashCert.ToString().substr(0, 10).c_str());
            return false;
        }

        uint256 hashExisting = 0;
        if (FinalityTallyCertificateContextExists(cert, mapPendingTallyCertificates, hashExisting) ||
            FinalityTallyCertificateContextExists(cert, mapConnectedTallyCertificates, hashExisting))
        {
            if (GetBoolArg("-debugfinalityrelay", false))
                printf("FINALITY relay-duplicate-context ftcert=%s existing=%s\n",
                       hashCert.ToString().substr(0, 10).c_str(),
                       hashExisting.ToString().substr(0, 10).c_str());
            return false;
        }
        mapPendingTallyCertificates[hashCert] = cert;
        return true;
    }

    if (mapConnectedTallyCertificates.count(hashCert))
        return true;

    uint256 hashExisting = 0;
    if (FinalityTallyCertificateContextExists(cert, mapConnectedTallyCertificates, hashExisting))
    {
        if (GetBoolArg("-debugfinalityrelay", false))
            printf("FINALITY connect-duplicate-context ftcert=%s existing=%s\n",
                   hashCert.ToString().substr(0, 10).c_str(),
                   hashExisting.ToString().substr(0, 10).c_str());
        FinalityEraseTallyCertificateContext(cert, mapPendingTallyCertificates);
        return true;
    }

    mapConnectedTallyCertificates[hashCert] = cert;
    FinalityEraseTallyCertificateContext(cert, mapPendingTallyCertificates);
    for (const uint256& hashShare : cert.vTallyShareHashes)
        setConnectedTallyShares.insert(hashShare);
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
    if (itNullifier != mapVoteHashByNullifier.end() && itNullifier->second == hashVote && !fRecordFinality)
    {
        if (GetBoolArg("-debugfinalityrelay", false))
            printf("FINALITY relay-duplicate fvote=%s nullifier=%s\n",
                   hashVote.ToString().substr(0, 10).c_str(),
                   vote.nullifier.ToString().substr(0, 10).c_str());
        return false;
    }
    if (itNullifier != mapVoteHashByNullifier.end() && itNullifier->second != hashVote)
    {
        if (!fRecordFinality)
            return false;

        if (mapConnectedVotes.count(vote.nullifier))
            return false;

        auto itPending = mapPendingVotes.find(vote.nullifier);
        if (itPending == mapPendingVotes.end())
            return false;

        // A block-connected vote is authoritative over an unconnected relay
        // candidate with the same nullifier. This keeps local pending state
        // from making otherwise-valid blocks node-order dependent.
        mapPendingVotes.erase(itPending);
        itNullifier->second = hashVote;
    }

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

bool CFinalityTracker::ComputeDeterministicEpochTier(int nEpoch, int& nTierOut, uint256& hashWinnerOut,
                                                     int& nWinnerHeightOut, int& nVoterCountOut) const
{
    // PURE: identical inputs (this epoch's connected votes / tally certificate) yield
    // identical outputs on every node. Does NOT touch the live finalization streak.
    LOCK(cs_finality);
    nTierOut = FINALITY_NONE; hashWinnerOut = 0; nWinnerHeightOut = 0; nVoterCountOut = 0;

    // Prefer an in-chain aggregate tally certificate (the only path that can promote
    // hidden-weight NullStake votes); its tier is fixed by the certificate itself.
    std::map<int, std::vector<CFinalityTallyCertificate> >::const_iterator itCerts =
        mapEpochTallyCertificates.find(nEpoch);
    if (itCerts != mapEpochTallyCertificates.end() && !itCerts->second.empty())
    {
        const CFinalityTallyCertificate* pBestCert = NULL;
        for (const CFinalityTallyCertificate& cert : itCerts->second)
        {
            if (!pBestCert || cert.nTier > pBestCert->nTier ||
                (cert.nTier == pBestCert->nTier && cert.GetHash() < pBestCert->GetHash()))
                pBestCert = &cert;
        }
        if (pBestCert)
        {
            nTierOut = pBestCert->nTier;
            hashWinnerOut = pBestCert->hashBlock;
            nWinnerHeightOut = pBestCert->nHeight;
            nVoterCountOut = (int)pBestCert->vVoteNullifiers.size();
            return nTierOut != FINALITY_NONE;
        }
    }

    std::map<int, int64_t>::const_iterator itW = mapEpochVoteWeight.find(nEpoch);
    int64_t nEpochVoteWeight = (itW != mapEpochVoteWeight.end()) ? itW->second : 0;
    if (nEpochVoteWeight <= 0)
        return false;

    std::map<int, std::set<CKeyID> >::const_iterator itV = mapEpochVoters.find(nEpoch);
    nVoterCountOut = (itV != mapEpochVoters.end()) ? (int)itV->second.size() : 0;
    if (nVoterCountOut < FINALITY_MIN_VOTERS)
        return false;

    std::map<int, std::vector<CFinalityVote> >::const_iterator itVotes = mapEpochVotes.find(nEpoch);
    if (itVotes == mapEpochVotes.end() || itVotes->second.empty())
        return false;

    std::map<uint256, int64_t> mapBlockVoteWeight;
    std::map<uint256, int> mapBlockHeightLocal;
    for (const CFinalityVote& v : itVotes->second)
    {
        if (v.IsPrivate())
            continue;
        if (v.nVoteWeight > 0 && mapBlockVoteWeight[v.hashBlock] <= MAX_MONEY - v.nVoteWeight)
            mapBlockVoteWeight[v.hashBlock] += v.nVoteWeight;
        mapBlockHeightLocal[v.hashBlock] = v.nHeight;
    }

    int64_t nBestBlockWeight = 0;
    for (const std::pair<const uint256, int64_t>& p : mapBlockVoteWeight)
    {
        if (p.second > nBestBlockWeight ||
            (p.second == nBestBlockWeight && (hashWinnerOut == 0 || p.first < hashWinnerOut)))
        {
            nBestBlockWeight = p.second;
            hashWinnerOut = p.first;
        }
    }
    if (hashWinnerOut == 0)
        return false;

    if (nBestBlockWeight * 3 >= nEpochVoteWeight * 2)
        nTierOut = FINALITY_HARD;
    else if (nBestBlockWeight * 2 >= nEpochVoteWeight)
        nTierOut = FINALITY_SOFT;
    else if (nBestBlockWeight * 3 >= nEpochVoteWeight)
        nTierOut = FINALITY_TENTATIVE;

    nWinnerHeightOut = mapBlockHeightLocal.count(hashWinnerOut) ? mapBlockHeightLocal[hashWinnerOut] : 0;
    return nTierOut != FINALITY_NONE;
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

std::vector<CFinalityVote> CFinalityTracker::GetConnectedEpochVotes(int nEpoch) const
{
    LOCK(cs_finality);
    std::vector<CFinalityVote> vVotes;
    std::set<uint256> setNullifiers;

    // Connected (on-chain) votes ONLY. The cert producer must cover exactly the
    // connected set the validator checks under R3; unioning mapPendingVotes (relay
    // state) here would let a single relayed-but-unconnected vote force every cert
    // to over-cover and be rejected at connect -> finality stall.
    std::map<int, std::vector<CFinalityVote> >::const_iterator itEpoch =
        mapEpochVotes.find(nEpoch);
    if (itEpoch != mapEpochVotes.end())
    {
        for (const CFinalityVote& vote : itEpoch->second)
        {
            if (setNullifiers.insert(vote.nullifier).second)
                vVotes.push_back(vote);
        }
    }

    return vVotes;
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

std::vector<CFinalityTallyShare> CFinalityTracker::GetEpochTallyShares(int nEpoch) const
{
    LOCK(cs_finality);
    std::vector<CFinalityTallyShare> vShares;
    for (const auto& pair : mapTallyShares)
    {
        if (pair.second.nEpoch == nEpoch)
            vShares.push_back(pair.second);
    }
    return vShares;
}

std::vector<CFinalityTallyAggregatePartial> CFinalityTracker::GetEpochTallyAggregatePartials(int nEpoch) const
{
    LOCK(cs_finality);
    std::vector<CFinalityTallyAggregatePartial> vPartials;
    for (const auto& pair : mapTallyAggregatePartials)
    {
        if (pair.second.nEpoch == nEpoch)
            vPartials.push_back(pair.second);
    }
    return vPartials;
}

int CFinalityTracker::GetEpochTallyShareCount(int nEpoch) const
{
    LOCK(cs_finality);
    int nCount = 0;
    for (const auto& pair : mapTallyShares)
    {
        if (pair.second.nEpoch == nEpoch)
            nCount++;
    }
    return nCount;
}

int CFinalityTracker::GetEpochTallyAggregatePartialCount(int nEpoch) const
{
    LOCK(cs_finality);
    int nCount = 0;
    for (const auto& pair : mapTallyAggregatePartials)
    {
        if (pair.second.nEpoch == nEpoch)
            nCount++;
    }
    return nCount;
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

bool CFinalityTracker::HasVoteNullifier(const uint256& nullifier) const
{
    LOCK(cs_finality);
    return mapVoteHashByNullifier.count(nullifier) != 0;
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
        // R1: only offer a vote whose inclusion window [H_E, H_E+K) covers this
        // block height, so the produced block passes connect-time CheckVote.
        if (nBlockHeight >= FORK_HEIGHT_VOTESET_ROOT)
        {
            int nBoundary = GetEpochBoundaryHeight(vote.nEpoch, nBlockHeight);
            if (nBlockHeight < nBoundary || nBlockHeight >= nBoundary + FINALITY_VOTE_INCLUSION_WINDOW)
                continue;
        }
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
        // Staleness bound aligned with the connect-time R2 rule (and the HARD
        // streak depth) so the miner offers exactly the certs a block can embed.
        if (cert.nEpoch + FINALITY_CONFIRMATION_EPOCHS < nBlockEpoch)
            continue;
        // R2: only offer a cert at/after its vote-inclusion window close, matching
        // connect-time CheckTallyCertificate so the produced block validates
        // everywhere.
        if (nBlockHeight >= FORK_HEIGHT_VOTESET_ROOT)
        {
            int nBoundary = GetEpochBoundaryHeight(cert.nEpoch, nBlockHeight);
            if (nBlockHeight < nBoundary + FINALITY_VOTE_INCLUSION_WINDOW)
                continue;
        }
        vCerts.push_back(cert);
        if (vCerts.size() >= nMaxCerts)
            break;
    }
    return vCerts;
}

std::vector<CFinalityTallyShare> CFinalityTracker::GetPendingTallySharesForBlock(int nBlockHeight, unsigned int nMaxShares,
                                                                                 const std::vector<CFinalityVote>* pvBlockVotes) const
{
    LOCK(cs_finality);

    std::vector<CFinalityTallyShare> vShares;
    int nBlockEpoch = GetEpochForHeight(nBlockHeight);
    for (const auto& pair : mapTallyShares)
    {
        if (setConnectedTallyShares.count(pair.first))
            continue;
        const CFinalityTallyShare& share = pair.second;
        if (share.nEpoch > nBlockEpoch)
            continue;
        if (share.nEpoch + 2 < nBlockEpoch)
            continue;
        // Only offer shares the block will be able to validate on every
        // node: the vote must be connected or embedded in this same block.
        // Shares referencing votes that exist only in local pending relay
        // state would make the produced block invalid under block-context
        // CheckTallyShare.
        std::string strError;
        if (!CheckTallyShare(share, &strError, pvBlockVotes, false, nBlockHeight))
        {
            if (fDebug)
                printf("GetPendingTallySharesForBlock: skipping share %s: %s\n",
                       pair.first.ToString().substr(0,20).c_str(), strError.c_str());
            continue;
        }
        vShares.push_back(share);
        if (vShares.size() >= nMaxShares)
            break;
    }
    return vShares;
}

bool CFinalityTracker::ConnectBlockVotes(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityVote>& vVotes, int nBlockHeight)
{
    if (vVotes.empty())
        return true;

    std::set<uint256> setBlockNullifiers;
    for (const CFinalityVote& vote : vVotes)
    {
        if (!setBlockNullifiers.insert(vote.nullifier).second)
            return false;

        std::string strError;
        if (!CheckVote(vote, txdb, &strError, nBlockHeight))
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
    vNullifiers.clear();   // idempotent: never append to a stale/reloaded entry
    for (const CFinalityVote& vote : vVotes)
        vNullifiers.push_back(vote.nullifier);
    // Persist the per-block connected-carrier index so the still-connected-elsewhere
    // teardown (DisconnectBlockVotes) and the connect-time coverage rule (R3) stay a
    // pure function of the connected chain across restart: without it a post-restart
    // reorg would mis-tear-down a vote carried by multiple connected DAG blocks and
    // diverge mapEpochVotes from a fresh-sync node.
    txdb.WriteFinalityConnectedVoteBlock(hashBlock, vNullifiers);

    return true;
}

bool CFinalityTracker::DisconnectBlockVotes(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityVote>& vVotes)
{
    if (vVotes.empty())
        return true;

    LOCK(cs_finality);
    for (const CFinalityVote& vote : vVotes)
    {
        // A vote nullifier may be carried by more than one connected block (the same
        // vote re-embedded across DAG branches/siblings). AddVote records it once and
        // no-ops on the duplicate, so the connected-vote accounting reflects a single
        // recording. Tear it down only when the LAST block carrying this nullifier is
        // disconnected; otherwise a partial reorg dropping one carrier would lose a
        // vote a surviving block still legitimately carries, diverging this node's
        // connected-vote set from a fresh-sync node. Mirrors DisconnectBlockTallyShares.
        bool fStillConnected = false;
        for (const auto& pair : mapBlockConnectedVoteNullifiers)
        {
            if (pair.first == hashBlock)
                continue;
            if (std::find(pair.second.begin(), pair.second.end(), vote.nullifier) != pair.second.end())
            {
                fStillConnected = true;
                break;
            }
        }
        if (fStillConnected)
            continue;

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
    txdb.EraseFinalityConnectedVoteBlock(hashBlock);
    return true;
}

bool CFinalityTracker::ConnectBlockTallyCertificates(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityTallyCertificate>& vCerts, int nBlockHeight)
{
    if (vCerts.empty())
        return true;

    std::set<uint256> setBlockCerts;
    for (const CFinalityTallyCertificate& cert : vCerts)
    {
        uint256 hashCert = cert.GetHash();
        if (!setBlockCerts.insert(hashCert).second)
            return false;

        // Strict vote resolution: ConnectBlockVotes has already connected
        // this block's votes, so pending relay state must not be consulted.
        // nBlockHeight drives the fork-gated position/coverage rules (R2/R3).
        std::string strError;
        if (!CheckTallyCertificate(cert, txdb, &strError, NULL, false, nBlockHeight))
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
    vHashes.clear();   // idempotent: never append to a stale/reloaded entry
    for (const CFinalityTallyCertificate& cert : vCerts)
        vHashes.push_back(cert.GetHash());
    if (!txdb.WriteFinalityConnectedCertBlock(hashBlock, vHashes))
        return false;

    return true;
}

bool CFinalityTracker::ConnectBlockCommitteeRotations(CTxDB& txdb, const uint256& hashBlock,
                                                      const std::vector<CFinalityCommitteeRotation>& vRots,
                                                      int nBlockHeight)
{
    if (vRots.empty())
        return true;

    int nBlockEpoch = GetEpochForHeight(nBlockHeight);
    std::set<int> setEffEpochs;
    for (const CFinalityCommitteeRotation& rot : vRots)
    {
        // A2 lookahead bound: a rotation must take effect strictly after the
        // connecting block's epoch and within the bounded window (no pre-dating,
        // no far-future scheduling). One rotation per effective epoch in a block.
        if (rot.nEffectiveEpoch <= nBlockEpoch ||
            rot.nEffectiveEpoch > nBlockEpoch + FINALITY_ROTATION_MAX_LOOKAHEAD)
            return error("ConnectBlockCommitteeRotations: rotation effective epoch %d out of window (block epoch %d)",
                         rot.nEffectiveEpoch, nBlockEpoch);
        if (!setEffEpochs.insert(rot.nEffectiveEpoch).second)
            return error("ConnectBlockCommitteeRotations: duplicate effective epoch in block");

        std::string strError;
        if (!ConnectCommitteeRotation(rot, &strError))
            return error("ConnectBlockCommitteeRotations: rejected rotation in block %s: %s",
                         hashBlock.ToString().substr(0,20).c_str(), strError.c_str());
        if (!txdb.WriteFinalityCommitteeRotation(rot.nEffectiveEpoch, rot))
            return false;
    }

    LOCK(cs_finality);
    std::vector<int>& vEpochs = mapBlockConnectedRotations[hashBlock];
    vEpochs.clear();
    for (const CFinalityCommitteeRotation& rot : vRots)
        vEpochs.push_back(rot.nEffectiveEpoch);
    if (!txdb.WriteFinalityConnectedRotationBlock(hashBlock, vEpochs))
        return false;
    return true;
}

bool CFinalityTracker::DisconnectBlockCommitteeRotations(CTxDB& txdb, const uint256& hashBlock,
                                                         const std::vector<CFinalityCommitteeRotation>& vRots)
{
    if (vRots.empty())
        return true;

    LOCK(cs_finality);
    for (const CFinalityCommitteeRotation& rot : vRots)
    {
        DisconnectCommitteeRotation(rot.nEffectiveEpoch);
        txdb.EraseFinalityCommitteeRotation(rot.nEffectiveEpoch);
    }
    mapBlockConnectedRotations.erase(hashBlock);
    txdb.EraseFinalityConnectedRotationBlock(hashBlock);
    return true;
}

bool CFinalityTracker::LoadCommitteeRotations(CTxDB& txdb)
{
    std::map<int, CFinalityCommitteeRotation> mapRots;
    if (!txdb.IterateFinalityCommitteeRotations(mapRots))
        return false;
    // Apply in ascending effective-epoch order so each chains onto the prior set.
    for (std::map<int, CFinalityCommitteeRotation>::const_iterator it = mapRots.begin();
         it != mapRots.end(); ++it)
    {
        std::string strError;
        if (!ConnectCommitteeRotation(it->second, &strError))
        {
            if (fDebug)
                printf("LoadCommitteeRotations: skipped epoch %d: %s\n", it->first, strError.c_str());
        }
    }
    // Restore the reorg-safe per-block carrier index.
    {
        std::map<uint256, std::vector<int> > mapRotBlocks;
        if (txdb.IterateFinalityConnectedRotationBlocks(mapRotBlocks))
        {
            LOCK(cs_finality);
            for (std::map<uint256, std::vector<int> >::const_iterator it = mapRotBlocks.begin();
                 it != mapRotBlocks.end(); ++it)
                mapBlockConnectedRotations[it->first] = it->second;
        }
    }
    if (!mapRots.empty())
        printf("LoadCommitteeRotations: loaded %d connected committee rotations\n", (int)mapRots.size());
    return true;
}

bool CFinalityTracker::ConnectBlockTallyShares(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityTallyShare>& vShares, int nBlockHeight)
{
    if (vShares.empty())
        return true;

    std::set<uint256> setBlockShares;
    for (const CFinalityTallyShare& share : vShares)
    {
        if (!setBlockShares.insert(share.GetHash()).second)
            return false;
    }

    for (const CFinalityTallyShare& share : vShares)
    {
        uint256 hashShare = share.GetHash();

        // Strict vote resolution: ConnectBlockVotes has already connected
        // this block's votes, so pending relay state must not be consulted.
        std::string strError;
        if (!CheckTallyShare(share, &strError, NULL, false, nBlockHeight))
        {
            if (fDebug)
                printf("ConnectBlockTallyShares: rejected share in block %s: %s\n",
                       hashBlock.ToString().substr(0,20).c_str(), strError.c_str());
            return false;
        }

        bool fHaveShare = false;
        {
            LOCK(cs_finality);
            fHaveShare = mapTallyShares.count(hashShare) != 0;
        }
        if (!fHaveShare && !AddTallyShare(share, false))
            return false;
        if (!txdb.WriteFinalityTallyShare(hashShare, share))
            return false;
    }

    LOCK(cs_finality);
    std::vector<uint256>& vHashes = mapBlockConnectedTallyShares[hashBlock];
    vHashes.clear();   // idempotent: never append to a stale/reloaded entry
    for (const CFinalityTallyShare& share : vShares)
    {
        uint256 hashShare = share.GetHash();
        vHashes.push_back(hashShare);
        setConnectedTallyShares.insert(hashShare);
    }
    // Persist the per-block connected-share index so setConnectedTallyShares and the
    // still-connected-elsewhere teardown survive restart; the connect-time cert
    // share-resolution gate depends on this being a pure function of the chain.
    txdb.WriteFinalityConnectedShareBlock(hashBlock, vHashes);

    return true;
}

bool CFinalityTracker::DisconnectBlockTallyShares(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityTallyShare>& vShares)
{
    if (vShares.empty())
        return true;

    LOCK(cs_finality);
    for (const CFinalityTallyShare& share : vShares)
    {
        uint256 hashShare = share.GetHash();
        bool fStillConnected = false;
        for (const auto& pair : mapBlockConnectedTallyShares)
        {
            if (pair.first == hashBlock)
                continue;
            if (std::find(pair.second.begin(), pair.second.end(), hashShare) != pair.second.end())
            {
                fStillConnected = true;
                break;
            }
        }
        if (!fStillConnected)
        {
            txdb.EraseFinalityTallyShare(hashShare);
            mapTallyShares.erase(hashShare);
            setConnectedTallyShares.erase(hashShare);
        }
    }
    mapBlockConnectedTallyShares.erase(hashBlock);
    txdb.EraseFinalityConnectedShareBlock(hashBlock);
    return true;
}

bool CFinalityTracker::DisconnectBlockTallyCertificates(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityTallyCertificate>& vCerts)
{
    if (vCerts.empty())
        return true;

    LOCK(cs_finality);
    auto eraseConnectedCertFromMemory = [&](const CFinalityTallyCertificate& certToErase,
                                            const uint256& hashToErase) {
        mapPendingTallyCertificates.erase(hashToErase);
        mapConnectedTallyCertificates.erase(hashToErase);

        auto itCerts = mapEpochTallyCertificates.find(certToErase.nEpoch);
        if (itCerts != mapEpochTallyCertificates.end())
        {
            auto& vEpochCerts = itCerts->second;
            vEpochCerts.erase(std::remove_if(vEpochCerts.begin(), vEpochCerts.end(),
                                             [&](const CFinalityTallyCertificate& c) { return c.GetHash() == hashToErase; }),
                              vEpochCerts.end());
            if (vEpochCerts.empty())
                mapEpochTallyCertificates.erase(itCerts);
        }
    };

    auto addConnectedCertToMemory = [&](const CFinalityTallyCertificate& certToAdd,
                                        const uint256& hashToAdd) {
        if (mapConnectedTallyCertificates.count(hashToAdd))
            return;

        mapConnectedTallyCertificates[hashToAdd] = certToAdd;
        FinalityEraseTallyCertificateContext(certToAdd, mapPendingTallyCertificates);
        for (const uint256& hashShare : certToAdd.vTallyShareHashes)
            setConnectedTallyShares.insert(hashShare);
        mapEpochTallyCertificates[certToAdd.nEpoch].push_back(certToAdd);
    };

    for (const CFinalityTallyCertificate& cert : vCerts)
    {
        uint256 hashCert = cert.GetHash();
        uint256 hashContext = FinalityCertificateAutomationContextHash(cert);
        bool fSameHashStillConnected = false;
        bool fHaveReplacementContext = false;
        uint256 hashReplacement = 0;
        CFinalityTallyCertificate certReplacement;

        for (const auto& pair : mapBlockConnectedTallyCertificates)
        {
            if (pair.first == hashBlock)
                continue;

            for (const uint256& hashOther : pair.second)
            {
                if (hashOther == hashCert)
                {
                    fSameHashStillConnected = true;
                    break;
                }

                if (fHaveReplacementContext)
                    continue;

                CFinalityTallyCertificate certOther;
                auto itConnected = mapConnectedTallyCertificates.find(hashOther);
                if (itConnected != mapConnectedTallyCertificates.end())
                    certOther = itConnected->second;
                else if (!txdb.ReadFinalityTallyCertificate(hashOther, certOther))
                    continue;

                if (FinalityCertificateAutomationContextHash(certOther) == hashContext)
                {
                    certReplacement = certOther;
                    hashReplacement = hashOther;
                    fHaveReplacementContext = true;
                }
            }

            if (fSameHashStillConnected)
                break;
        }

        if (fSameHashStillConnected)
            continue;

        bool fWasCanonical = mapConnectedTallyCertificates.count(hashCert) != 0;
        txdb.EraseFinalityTallyCertificate(hashCert);
        eraseConnectedCertFromMemory(cert, hashCert);

        if (fWasCanonical && fHaveReplacementContext)
            addConnectedCertToMemory(certReplacement, hashReplacement);
    }
    mapBlockConnectedTallyCertificates.erase(hashBlock);
    txdb.EraseFinalityConnectedCertBlock(hashBlock);
    return true;
}

bool CFinalityTracker::LoadVotes(CTxDB& txdb)
{
    std::map<uint256, CFinalityVote> mapVotes;
    if (!txdb.IterateFinalityVotes(mapVotes))
        return false;

    for (const auto& pair : mapVotes)
        AddVote(pair.second, false, true);

    RebuildFinalityState();

    if (!mapVotes.empty())
        printf("LoadFinalityVotes: loaded %d connected finality votes\n", (int)mapVotes.size());
    return true;
}

bool CFinalityTracker::LoadTallyShares(CTxDB& txdb)
{
    std::map<uint256, CFinalityTallyShare> mapShares;
    if (!txdb.IterateFinalityTallyShares(mapShares))
        return false;

    for (const auto& pair : mapShares)
        AddTallyShare(pair.second, false);

    if (!mapShares.empty())
        printf("LoadFinalityTallyShares: loaded %d relayed tally shares\n", (int)mapShares.size());
    return true;
}

void CFinalityTracker::PurgeUnresolvableTallyShares(CTxDB& txdb)
{
    LOCK(cs_finality);

    int nPurged = 0;
    for (auto it = mapTallyShares.begin(); it != mapTallyShares.end(); )
    {
        // Never purge a block-connected share: it is backed by a connected block
        // (and the persisted finalityconnsb index), so dropping it from
        // mapTallyShares/finalityshare while setConnectedTallyShares + the block
        // index still reference it would, after a restart, leave a hash in
        // setConnectedTallyShares with no backing share and diverge cert validity.
        if (setConnectedTallyShares.count(it->first))
        {
            ++it;
            continue;
        }
        std::string strError;
        if (!CheckTallyShare(it->second, &strError, NULL, false))
        {
            printf("PurgeUnresolvableTallyShares: dropping tally share %s: %s\n",
                   it->first.ToString().substr(0,20).c_str(), strError.c_str());
            txdb.EraseFinalityTallyShare(it->first);
            setConnectedTallyShares.erase(it->first);
            it = mapTallyShares.erase(it);
            nPurged++;
        }
        else
        {
            ++it;
        }
    }

    if (nPurged > 0)
        printf("PurgeUnresolvableTallyShares: purged %d unresolvable tally shares\n", nPurged);
}

bool CFinalityTracker::LoadTallyCertificates(CTxDB& txdb)
{
    std::map<uint256, CFinalityTallyCertificate> mapCerts;
    if (!txdb.IterateFinalityTallyCertificates(mapCerts))
        return false;

    for (const auto& pair : mapCerts)
        AddTallyCertificate(pair.second, false, true);

    RebuildFinalityState();

    if (!mapCerts.empty())
        printf("LoadFinalityTallyCertificates: loaded %d connected tally certificates\n", (int)mapCerts.size());
    return true;
}

void CFinalityTracker::RebuildFinalityState()
{
    LOCK(cs_finality);

    // FCMP-spend and private-vote validity anchor to the finalization state,
    // so it must be a pure function of the chain's CONNECTED votes and
    // certificates. The in-memory epoch maps are pruned over time
    // (PruneOldEpochs); replaying only the retained window would silently
    // regress finalization after a restart or reorg-triggered rebuild and
    // diverge from freshly-synced nodes. Re-merge the persisted connected set
    // (LevelDB is append-on-connect / erase-on-disconnect, never pruned)
    // before replaying.
    ReloadConnectedFinalityFromDB();

    nLastFinalizedHeight = 0;
    hashLastFinalized = 0;
    nLastFinalityTier = FINALITY_NONE;
    nConsecutiveHardEpochs = 0;
    nLastHardEpoch = -1;
    nPendingFinalizedHeight = 0;
    hashPendingFinalized = 0;

    std::set<int> setEpochs;
    for (const auto& pair : mapEpochVotes)
        setEpochs.insert(pair.first);
    for (const auto& pair : mapEpochTallyCertificates)
        setEpochs.insert(pair.first);

    for (int nEpoch : setEpochs)
        CheckFinalityThreshold(nEpoch);
}

void CFinalityTracker::ReloadConnectedFinalityFromDB()
{
    AssertLockHeld(cs_finality);

    CTxDB txdb("r");

    // The LevelDB finality stores only ever hold CONNECTED (on-chain) votes and
    // certificates (written on connect, erased on disconnect), so re-merge them
    // as connected finality (fRecordFinality=true) — the same path LoadVotes /
    // LoadTallyCertificates use. fCheck=false: these were validated when first
    // connected and re-validating mid-rebuild can spuriously fail on the
    // not-yet-rebuilt finalized-epoch anchor.
    std::map<uint256, CFinalityVote> mapVotes;
    if (txdb.IterateFinalityVotes(mapVotes))
    {
        for (const auto& pair : mapVotes)
        {
            if (mapVoteHashByNullifier.count(pair.second.nullifier))
                continue; // still in the retained window
            AddVote(pair.second, false, true);
        }
    }

    std::map<uint256, CFinalityTallyCertificate> mapCerts;
    if (txdb.IterateFinalityTallyCertificates(mapCerts))
    {
        for (const auto& pair : mapCerts)
        {
            if (mapConnectedTallyCertificates.count(pair.first))
                continue; // still in the retained window
            AddTallyCertificate(pair.second, false, true);
        }
    }

    // Restore the per-block connected-carrier indexes (append-on-connect /
    // erase-on-disconnect, never pruned, like the vote/cert stores) so the
    // still-connected-elsewhere teardown checks and the connect-time coverage /
    // share-resolution rules remain a pure function of the connected chain across
    // restart. setConnectedTallyShares is rebuilt from the share index here: it is
    // otherwise only re-seeded from connected certs' share hashes, which omits
    // shares connected in a block not yet referenced by any connected cert, so a
    // restart in that window would reject a cert a non-restarted node accepts.
    std::map<uint256, std::vector<uint256> > mapVoteBlocks;
    if (txdb.IterateFinalityConnectedVoteBlocks(mapVoteBlocks))
    {
        for (const auto& pair : mapVoteBlocks)
            mapBlockConnectedVoteNullifiers[pair.first] = pair.second;
    }

    std::map<uint256, std::vector<uint256> > mapShareBlocks;
    if (txdb.IterateFinalityConnectedShareBlocks(mapShareBlocks))
    {
        for (const auto& pair : mapShareBlocks)
        {
            mapBlockConnectedTallyShares[pair.first] = pair.second;
            for (const uint256& hashShare : pair.second)
                setConnectedTallyShares.insert(hashShare);
        }
    }

    std::map<uint256, std::vector<uint256> > mapCertBlocks;
    if (txdb.IterateFinalityConnectedCertBlocks(mapCertBlocks))
    {
        for (const auto& pair : mapCertBlocks)
            mapBlockConnectedTallyCertificates[pair.first] = pair.second;
    }
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

    for (auto it = mapTallyShares.begin(); it != mapTallyShares.end(); )
    {
        if (it->second.nEpoch < nMinEpoch)
        {
            setConnectedTallyShares.erase(it->first);
            it = mapTallyShares.erase(it);
        }
        else
            ++it;
    }

    for (auto it = mapTallyAggregatePartials.begin(); it != mapTallyAggregatePartials.end(); )
    {
        if (it->second.nEpoch < nMinEpoch)
            it = mapTallyAggregatePartials.erase(it);
        else
            ++it;
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
    else if (strCommand == "ftshare")
    {
        CFinalityTallyShare share;
        vRecv >> share;

        if (!share.IsValidBasic())
            return false;

        int nCurrentEpoch = 0;
        {
            CBlockIndex* pBest = pindexBest;
            if (pBest)
                nCurrentEpoch = GetEpochForHeight(pBest->nHeight);
        }
        if (share.nEpoch > nCurrentEpoch + 2)
            return false;

        if (g_finalityTracker.AddTallyShare(share))
        {
            CTxDB txdb("r+");
            txdb.WriteFinalityTallyShare(share.GetHash(), share);

            LOCK(cs_vNodes);
            for (CNode* pnode : vNodes)
            {
                if (pnode == pfrom)
                    continue;
                pnode->PushMessage("ftshare", share);
            }
        }

        return true;
    }
    else if (strCommand == "ftpart")
    {
        CFinalityTallyAggregatePartial partial;
        vRecv >> partial;

        if (!partial.IsValidBasic())
            return false;

        int nCurrentEpoch = 0;
        {
            CBlockIndex* pBest = pindexBest;
            if (pBest)
                nCurrentEpoch = GetEpochForHeight(pBest->nHeight);
        }
        if (partial.nEpoch > nCurrentEpoch + 2)
            return false;

        if (g_finalityTracker.AddTallyAggregatePartial(partial))
        {
            LOCK(cs_vNodes);
            for (CNode* pnode : vNodes)
            {
                if (pnode == pfrom)
                    continue;
                pnode->PushMessage("ftpart", partial);
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
    else if (strCommand == "ftcsig")
    {
        // 2c-4b: a committee member's signature over a candidate certificate.
        CFinalityCertSignature msg;
        vRecv >> msg;

        if (msg.candidate.nEpoch < 0 || msg.candidate.nHeight < 0)
            return false;
        int nCurrentEpoch = 0;
        {
            CBlockIndex* pBest = pindexBest;
            if (pBest)
                nCurrentEpoch = GetEpochForHeight(pBest->nHeight);
        }
        if (msg.candidate.nEpoch > nCurrentEpoch + 2)
            return false;

        CTxDB txdb("r");
        CFinalityTallyCertificate assembled;
        bool fAssembled = false;
        // AddCertSignature validates the candidate + signature and returns true
        // only when it stored a NEW signature (so we gossip each sig once).
        if (g_finalityTracker.AddCertSignature(msg, txdb, &assembled, &fAssembled, NULL))
        {
            {
                LOCK(cs_vNodes);
                for (CNode* pnode : vNodes)
                {
                    if (pnode == pfrom)
                        continue;
                    pnode->PushMessage("ftcsig", msg);
                }
            }

            // If we are a committee member that has not yet signed this candidate,
            // co-sign it and relay our signature (drives the M-of-N collection).
            CFinalityTallyConfig cfg = GetFinalityTallyConfig();
            CKey memberKey;
            if (cfg.nLocalCommitteeIndex >= 0 && GetFinalityTallyPrivateKey(memberKey))
            {
                CFinalityCertSignature mine;
                mine.candidate = msg.candidate;
                mine.nSignerIndex = (uint16_t)cfg.nLocalCommitteeIndex;
                if (memberKey.Sign(msg.candidate.GetSignatureDigest(), mine.vchSig) && !mine.vchSig.empty())
                {
                    CFinalityTallyCertificate assembled2;
                    bool fAssembled2 = false;
                    if (g_finalityTracker.AddCertSignature(mine, txdb, &assembled2, &fAssembled2, NULL))
                    {
                        RelayFinalityCertSignature(mine);
                        if (fAssembled2) { assembled = assembled2; fAssembled = true; }
                    }
                }
            }

            if (fAssembled && g_finalityTracker.AddTallyCertificate(assembled))
                RelayFinalityTallyCertificate(assembled);
        }

        return true;
    }
    else if (strCommand == "ftrot")
    {
        // D2 self-governance: a fully-signed committee rotation, gossiped so any
        // miner can embed it. AddPendingCommitteeRotation re-verifies the >= M
        // signatures against the committee active before its effective epoch.
        CFinalityCommitteeRotation rot;
        vRecv >> rot;
        if (g_finalityTracker.AddPendingCommitteeRotation(rot, NULL))
        {
            LOCK(cs_vNodes);
            for (CNode* pnode : vNodes)
                if (pnode != pfrom)
                    pnode->PushMessage("ftrot", rot);
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
        std::vector<CFinalityTallyShare> shares = g_finalityTracker.GetEpochTallyShares(nEpoch);
        for (const CFinalityTallyShare& share : shares)
        {
            pfrom->PushMessage("ftshare", share);
        }
        std::vector<CFinalityTallyAggregatePartial> partials =
            g_finalityTracker.GetEpochTallyAggregatePartials(nEpoch);
        for (const CFinalityTallyAggregatePartial& partial : partials)
        {
            pfrom->PushMessage("ftpart", partial);
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

static bool ProcessFinalityTallyCommitteeEpoch(int nEpoch,
                                               const CFinalityTallyConfig& config,
                                               const CKey& keyLocal)
{
    if (nEpoch < 0)
        return false;

    bool fDidWork = false;
    std::map<CFinalityTallyGroupKey, CFinalityTallyGroupWork> mapGroups;
    std::vector<CFinalityTallyShare> vShares = g_finalityTracker.GetEpochTallyShares(nEpoch);
    for (const CFinalityTallyShare& share : vShares)
    {
        if (share.nVersion != 2 ||
            share.committeeSetHash != config.committeeSetHash ||
            !share.IsValidBasic())
            continue;

        CFinalityTallyGroupKey key;
        key.nEpoch = share.nEpoch;
        key.hashBlock = share.hashBlock;
        key.hashCurveRoot = share.hashCurveRoot;
        key.hashNullifierRoot = share.hashNullifierRoot;
        key.committeeSetHash = share.committeeSetHash;
        CFinalityTallyGroupWork& group = mapGroups[key];
        group.key = key;
        group.vShares.push_back(share);
        group.vShareHashes.push_back(share.GetHash());

        CFinalityTallyPlainShare plain;
        if (DecryptFinalityTallyShareForRecipient(share,
                                                  config,
                                                  keyLocal,
                                                  config.nLocalCommitteeIndex,
                                                  plain))
            group.vLocalPlainShares.push_back(plain);
    }

    std::vector<CFinalityTallyAggregatePartial> vPartials =
        g_finalityTracker.GetEpochTallyAggregatePartials(nEpoch);
    static std::set<uint256> setProducedPartialContexts;

    for (std::pair<const CFinalityTallyGroupKey, CFinalityTallyGroupWork>& pair : mapGroups)
    {
        CFinalityTallyGroupWork& group = pair.second;
        std::sort(group.vShareHashes.begin(), group.vShareHashes.end());
        group.vShareHashes.erase(std::unique(group.vShareHashes.begin(), group.vShareHashes.end()),
                                 group.vShareHashes.end());
        if (group.vLocalPlainShares.empty())
            continue;

        bool fHaveLocalPartial = false;
        for (const CFinalityTallyAggregatePartial& partial : vPartials)
        {
            if (partial.nSourceIndex == config.nLocalCommitteeIndex &&
                FinalityPartialMatchesGroup(partial, group))
            {
                fHaveLocalPartial = true;
                break;
            }
        }

        uint256 hashPartialContext = FinalityAutomationContextHash(
            "Innova/Finality/TallyPartialAutomation/v2",
            group.key,
            config.nLocalCommitteeIndex,
            group.vShareHashes);
        if (!fHaveLocalPartial && !setProducedPartialContexts.count(hashPartialContext))
        {
            CFinalityTallyPlainShare aggregate;
            if (AggregateFinalityTallyPlainShares(group.vLocalPlainShares, aggregate))
            {
                CFinalityTallyAggregatePartial partial;
                partial.nVersion = 2;
                partial.nEpoch = group.key.nEpoch;
                partial.hashBlock = group.key.hashBlock;
                partial.hashCurveRoot = group.key.hashCurveRoot;
                partial.hashNullifierRoot = group.key.hashNullifierRoot;
                partial.committeeSetHash = group.key.committeeSetHash;
                partial.vTallyShareHashes = group.vShareHashes;
                if (BuildEncryptedFinalityTallyAggregatePartial(partial,
                                                                 aggregate,
                                                                 config,
                                                                 keyLocal) &&
                    g_finalityTracker.AddTallyAggregatePartial(partial))
                {
                    setProducedPartialContexts.insert(hashPartialContext);
                    vPartials.push_back(partial);
                    RelayFinalityTallyAggregatePartial(partial);
                    fDidWork = true;
                }
            }
        }
    }

    std::map<CFinalityTallyCohortKey, std::vector<CFinalityTallyGroupKey> > mapCohorts;
    for (std::pair<const CFinalityTallyGroupKey, CFinalityTallyGroupWork>& pair : mapGroups)
    {
        CFinalityTallyGroupWork& group = pair.second;
        if (!FinalityRecoverGroupFromPartials(group, vPartials, config, keyLocal))
            continue;

        CFinalityTallyCohortKey cohort;
        cohort.nEpoch = group.key.nEpoch;
        cohort.hashCurveRoot = group.key.hashCurveRoot;
        cohort.hashNullifierRoot = group.key.hashNullifierRoot;
        cohort.committeeSetHash = group.key.committeeSetHash;
        mapCohorts[cohort].push_back(group.key);
    }

    for (const std::pair<const CFinalityTallyCohortKey, std::vector<CFinalityTallyGroupKey> >& pair : mapCohorts)
    {
        if (FinalityBuildAndRelayCertificateForCohort(nEpoch,
                                                      pair.first,
                                                      pair.second,
                                                      mapGroups))
            fDidWork = true;
    }

    return fDidWork;
}

bool ProcessFinalityTallyCommittee()
{
    CFinalityTallyConfig config = GetFinalityTallyConfig();
    if (!config.CanProduceCertificates())
        return false;

    CKey keyLocal;
    if (!GetFinalityTallyPrivateKey(keyLocal))
        return false;

    int nCurrentEpoch = -1;
    int nTipHeight = -1;
    {
        LOCK(cs_main);
        if (!pindexBest || pindexBest->nHeight < FORK_HEIGHT_DAG)
            return false;
        nTipHeight = pindexBest->nHeight;
        nCurrentEpoch = GetEpochForHeight(nTipHeight);
    }

    bool fDidWork = false;
    // The previous epoch's vote-inclusion window is always closed (we are a full
    // epoch past it), so its connected vote set is frozen and a cert built from it
    // satisfies the connect-time coverage rule (R3).
    if (nCurrentEpoch > 0)
        fDidWork |= ProcessFinalityTallyCommitteeEpoch(nCurrentEpoch - 1, config, keyLocal);
    // Build the current epoch's cert only once its window has closed
    // (tip >= H_E + K). Before that the connected set is still growing, and any
    // cert would be rejected at connect by the coverage rule (R3) and the cert
    // position floor (R2). Pre-fork, retain the prior unconditional behavior.
    bool fCurrentWindowClosed = (nTipHeight < FORK_HEIGHT_VOTESET_ROOT) ||
        (nTipHeight >= GetEpochBoundaryHeight(nCurrentEpoch, nTipHeight) + FINALITY_VOTE_INCLUSION_WINDOW);
    if (fCurrentWindowClosed)
        fDidWork |= ProcessFinalityTallyCommitteeEpoch(nCurrentEpoch, config, keyLocal);
    return fDidWork;
}

int CountDecryptableFinalityTallyShares(int nEpoch)
{
    CFinalityTallyConfig config = GetFinalityTallyConfig();
    if (!config.CanProduceCertificates())
        return 0;

    CKey keyLocal;
    if (!GetFinalityTallyPrivateKey(keyLocal))
        return 0;

    int nCount = 0;
    std::vector<CFinalityTallyShare> vShares = g_finalityTracker.GetEpochTallyShares(nEpoch);
    for (const CFinalityTallyShare& share : vShares)
    {
        if (share.committeeSetHash != config.committeeSetHash)
            continue;
        CFinalityTallyPlainShare plain;
        if (DecryptFinalityTallyShareForRecipient(share,
                                                  config,
                                                  keyLocal,
                                                  config.nLocalCommitteeIndex,
                                                  plain))
            nCount++;
    }
    return nCount;
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
    std::string strMode = ToLowerASCII(GetArg("-finalityvotemode", "auto"));
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
                                                int nEpochHeight,
                                                const CFinalityTallyConfig& tallyConfig)
{
    if (!pEpochBlock)
        return false;
    if (!tallyConfig.CanRelayPrivateVotes())
        return false;

    // Anchor to the SAME deterministic finalized epoch the including block (the next
    // block on the tip) will validate against -- not the live tip -- so the produced
    // private vote is accepted by every node (matches CheckVote's GetFinalizedEpochStateAsOf).
    CEpochState finalizedEpochState;
    int nIncludingHeight = (pindexBest ? pindexBest->nHeight + 1 : nEpochHeight);
    if (!g_dagManager.GetFinalizedEpochStateAsOf(nIncludingHeight, finalizedEpochState))
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

        std::vector<size_t> vNoteOrder;
        vNoteOrder.reserve(pwalletMain->vShieldedNotes.size());
        for (size_t i = 0; i < pwalletMain->vShieldedNotes.size(); i++)
            vNoteOrder.push_back(i);
        std::sort(vNoteOrder.begin(), vNoteOrder.end(),
                  [](size_t a, size_t b) {
                      return pwalletMain->vShieldedNotes[a].note.nValue >
                             pwalletMain->vShieldedNotes[b].note.nValue;
                  });

        for (size_t nNoteIndex : vNoteOrder)
        {
            CWallet::CShieldedWalletNote& wnote = pwalletMain->vShieldedNotes[nNoteIndex];
            if (wnote.fSpent || wnote.note.nValue <= 0 || wnote.nHeight <= 0)
                continue;

            CBlockIndex* pNoteBlock = pindexBest;
            while (pNoteBlock && pNoteBlock->nHeight > wnote.nHeight)
                pNoteBlock = pNoteBlock->pprev;
            if (!pNoteBlock || pNoteBlock->nHeight != wnote.nHeight)
                continue;

            const bool fPinnedKernel = pEpochBlock->nHeight >= FORK_HEIGHT_KERNEL_PINNING;

            unsigned int nBlockTimeFrom = pNoteBlock->GetBlockTime();
            if (fPinnedKernel)
            {
                // Pinned kernels claim the synthetic age for every note; real
                // note age is unprovable in-circuit and must not leak here.
                nBlockTimeFrom = (unsigned int)((int64_t)pEpochBlock->nTime - NULLSTAKE_PINNED_AGE);
            }
            else if (nBlockTimeFrom + nStakeMinAge > (unsigned int)pEpochBlock->GetBlockTime())
                continue;

            if (wnote.note.vchBlind.empty())
                wnote.note.GenerateBlindingFactor();

            // Note-bound nullifier point; the proof (attached below) ties it to
            // stakeWeightCommitment.
            std::vector<unsigned char> vchNfPoint;
            if (!ComputeNullifierPoint(wnote.note.vchBlind, vchNfPoint))
                continue;
            uint256 voteNullifier = FinalityNullifierTag(vchNfPoint, nCurrentEpoch);
            if (g_finalityTracker.HasVoteNullifier(voteNullifier))
                continue;

            CPedersenCommitment stakeCommitment;
            if (!wnote.note.GetPedersenCommitment(stakeCommitment))
                continue;

            // B2-e: detect whether this note is an M-of-N cold-stake note -- its curve-tree leaf is
            // cv3 = cv_plain + D*J for some delegation D this wallet minted -- and whether this wallet
            // holds >= M of that delegation's staker-set member secret keys (needed to co-produce the
            // half-aggregated vote). membershipLeaf is the REAL leaf (cv3 for M-of-N, cv_plain for the
            // 1-of-1/V2 case); the vote's stakeWeightCommitment stays cv_plain either way, so the J term
            // never enters the tally. The note carries no D, so trial-match the wallet's delegations.
            bool fIsMofN = false;
            CPedersenCommitment membershipLeaf = stakeCommitment;
            uint256 mofnD;
            std::vector<std::vector<unsigned char> > mofnSet;
            unsigned int mofnM = 0;
            std::vector<unsigned char> mofnOwner;
            std::vector<uint256> mofnSecrets;
            for (std::map<uint256, CWallet::CMofNDelegation>::const_iterator itD =
                     pwalletMain->mapMofNDelegations.begin();
                 itD != pwalletMain->mapMofNDelegations.end(); ++itD)
            {
                if (itD->second.nThresholdM == 0)
                    continue;
                CPedersenCommitment cv3try;
                if (!CreateNullStakeMofNCommitment(wnote.note.nValue, wnote.note.vchBlind,
                                                   itD->first, cv3try))
                    continue;
                if (finalizedCurveTree.FindLeafIndex(cv3try) < 0)
                    continue;
                std::vector<uint256> secrets;
                for (size_t s = 0; s < itD->second.vStakerSet.size(); s++)
                {
                    std::map<std::vector<unsigned char>, uint256>::const_iterator itK =
                        pwalletMain->mapMofNMemberKeys.find(itD->second.vStakerSet[s]);
                    if (itK != pwalletMain->mapMofNMemberKeys.end())
                        secrets.push_back(itK->second);
                }
                if (secrets.size() < itD->second.nThresholdM)
                    continue;
                secrets.resize(itD->second.nThresholdM);
                fIsMofN = true;
                membershipLeaf = cv3try;
                mofnD = itD->first;
                mofnSet = itD->second.vStakerSet;
                mofnM = itD->second.nThresholdM;
                mofnOwner = itD->second.vchPkOwner;
                mofnSecrets = secrets;
                break;
            }

            int64_t nLeafIdx = finalizedCurveTree.FindLeafIndex(membershipLeaf);
            if (nLeafIdx < 0)
                continue;

            CFCMPProof fcmpProof;
            if (!CreateFCMPProof(finalizedCurveTree, (uint64_t)nLeafIdx,
                                 wnote.note.vchBlind, wnote.note.nValue,
                                 membershipLeaf, fcmpProof))
                continue;

            uint64_t nStakeModifier = pEpochBlock->pprev ?
                                      pEpochBlock->pprev->nStakeModifier :
                                      pEpochBlock->nStakeModifier;
            unsigned int nTxPrevOffset = 0;
            unsigned int nVoutN = fPinnedKernel ? 0 : wnote.nPosition;
            unsigned int nTxTimePrev = fPinnedKernel ? nBlockTimeFrom : (unsigned int)pNoteBlock->nTime;
            unsigned int nBaseTime = (unsigned int)GetAdjustedTime();
            if (nBaseTime < (unsigned int)pEpochBlock->GetBlockTime())
                nBaseTime = (unsigned int)pEpochBlock->GetBlockTime();

            // Pinned mode: nTimeTx is fixed to the epoch block time, so there is
            // exactly one kernel evaluation per note per epoch (no time search).
            unsigned int nSearchInterval = fPinnedKernel ? 1 : FINALITY_PRIVATE_VOTE_SEARCH_INTERVAL;
            for (unsigned int n = 0; n < nSearchInterval; n++)
            {
                unsigned int nTimeTx = fPinnedKernel ? pEpochBlock->nTime : (nBaseTime + n);
                int64_t nWeight = GetWeight((int64_t)nBlockTimeFrom, (int64_t)nTimeTx);
                bool fKernelOk = fIsMofN
                    ? CheckShieldedStakeKernelHashV3(pEpochBlock->nBits, nStakeModifier, nBlockTimeFrom,
                                                     nTxPrevOffset, nTxTimePrev, nVoutN, nTimeTx,
                                                     wnote.note.nValue, nWeight)
                    : CheckShieldedStakeKernelHashV2(pEpochBlock->nBits, nStakeModifier, nBlockTimeFrom,
                                                     nTxPrevOffset, nTxTimePrev, nVoutN, nTimeTx,
                                                     wnote.note.nValue, nWeight);
                if (!fKernelOk)
                    continue;

                // M-of-N builds the half-aggregated V3 kernel proof over the cv3 leaf (it re-derives
                // cv_plain internally); the 1-of-1 path builds the V2 proof over cv_plain. Either way the
                // vote's stakeWeightCommitment below is cv_plain.
                CNullStakeKernelProofV2 nullStakeProof;
                CNullStakeKernelProofV3 nullStakeProofV3;
                if (fIsMofN)
                {
                    if (!CreateNullStakeMofNKernelProofV3(wnote.note.nValue,
                                                          wnote.note.vchBlind,
                                                          membershipLeaf,
                                                          pEpochBlock->nBits,
                                                          nStakeModifier,
                                                          nBlockTimeFrom,
                                                          nTxPrevOffset,
                                                          nTxTimePrev,
                                                          nVoutN,
                                                          nTimeTx,
                                                          mofnSet,
                                                          mofnM,
                                                          mofnOwner,
                                                          mofnD,
                                                          mofnSecrets,
                                                          nullStakeProofV3))
                        continue;
                }
                else if (!CreateNullStakeKernelProofV2(wnote.note.nValue,
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

                int nVoteMode = fIsMofN ? FINALITY_PROOF_NULLSTAKE_V3_COLD
                                        : FINALITY_PROOF_NULLSTAKE_V2;
                CFinalityVote vote;
                vote.nProofMode = nVoteMode;
                vote.nEpoch = nCurrentEpoch;
                vote.hashBlock = pEpochBlock->GetBlockHash();
                vote.nHeight = nEpochHeight;
                vote.nTime = nTimeTx;
                vote.nVoteWeight = 0;
                vote.nReward = 0;
                vote.nullifier = voteNullifier;

                vote.privateProof.nVersion = 1;
                vote.privateProof.nProofMode = nVoteMode;
                vote.privateProof.nEpoch = nCurrentEpoch;
                vote.privateProof.hashEpochBlock = vote.hashBlock;
                vote.privateProof.hashCurveRoot = finalizedEpochState.hashCurveRoot;
                vote.privateProof.hashNullifierRoot = finalizedEpochState.hashNullifierRoot;
                vote.privateProof.nullifier = vote.nullifier;
                // cv_plain (J-free) for BOTH modes: keeps the whole tally + nullifier-binding + share path
                // identical to V2 for M-of-N. The cv3 leaf is reconstructed only at verify-time membership.
                vote.privateProof.stakeWeightCommitment = stakeCommitment;
                vote.privateProof.rewardCommitment = rewardCommitment;
                vote.privateProof.fcmpProof = fcmpProof;
                if (fIsMofN)
                    vote.privateProof.nullStakeV3Proof = nullStakeProofV3;
                else
                    vote.privateProof.nullStakeV2Proof = nullStakeProof;
                vote.privateProof.vchRewardOutputCommitment = rewardCommitment.vchCommitment;

                // Bind the nullifier to the staked note (NF tied to stakeCommitment).
                vote.privateProof.vchNullifierPoint = vchNfPoint;
                uint256 nfCtx = FinalityNullifierBindContext(nCurrentEpoch, vote.hashBlock);
                if (!CreateNullifierBindingProof(wnote.note.nValue, wnote.note.vchBlind,
                                                 stakeCommitment, vchNfPoint, nfCtx,
                                                 vote.privateProof.vchNullifierBindingProof))
                    continue;

                CHashWriter bindingHasher(SER_GETHASH, 0);
                bindingHasher << std::string("Innova/Finality/PrivateRewardBinding/v1");
                bindingHasher << vote.nullifier;
                bindingHasher << rewardCommitment;
                uint256 hashBinding = bindingHasher.GetHash();
                CBindingSignature bindingSig;
                std::vector<std::vector<unsigned char> > vInputBlinds(1, wnote.note.vchBlind);
                std::vector<std::vector<unsigned char> > vOutputBlinds(1, vchRewardBlind);
                if (!CreateBindingSignature(vInputBlinds, vOutputBlinds,
                                            hashBinding, bindingSig) ||
                    !VerifyBindingSignature(std::vector<CPedersenCommitment>(1, stakeCommitment),
                                            std::vector<CPedersenCommitment>(1, rewardCommitment),
                                            wnote.note.nValue - nPrivateReward,
                                            hashBinding,
                                            bindingSig) ||
                    !SerializeBindingProof(bindingSig, vote.privateProof.vchBindingProof))
                    continue;

                CFinalityTallyShare share;
                share.nVersion = 2;
                share.nEpoch = vote.nEpoch;
                share.voteNullifier = vote.nullifier;
                share.hashBlock = vote.hashBlock;
                share.hashCurveRoot = vote.privateProof.hashCurveRoot;
                share.hashNullifierRoot = vote.privateProof.hashNullifierRoot;
                share.committeeSetHash = tallyConfig.committeeSetHash;
                share.stakeWeightCommitment = vote.privateProof.stakeWeightCommitment;
                share.rewardCommitment = vote.privateProof.rewardCommitment;
                share.vchShareProof = vote.privateProof.vchBindingProof;
                if (!BuildEncryptedFinalityTallyShares(share,
                                                       wnote.note.nValue,
                                                       nPrivateReward,
                                                       wnote.note.vchBlind,
                                                       vchRewardBlind,
                                                       tallyConfig))
                    continue;

                if (!g_finalityTracker.AddVote(vote))
                    continue;

                if (g_finalityTracker.AddTallyShare(share, false))
                {
                    CTxDB txdbWrite("r+");
                    txdbWrite.WriteFinalityTallyShare(share.GetHash(), share);
                }

                printf("ProduceFinalityVote: private nullstake epoch=%d height=%d note=%s\n",
                       nCurrentEpoch, nEpochHeight,
                       wnote.txhash.ToString().substr(0,10).c_str());

                LOCK(cs_vNodes);
                for (CNode* pnode : vNodes)
                {
                    pnode->PushMessage("fvote", vote);
                    pnode->PushMessage("ftshare", share);
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

    // If DAG is active, vote for the DAG-selected best tip
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
    CFinalityTallyConfig tallyConfig = GetFinalityTallyConfig();
    // Cold-start: a private (hidden-weight) vote cannot bootstrap finality because it
    // must anchor to an ALREADY-finalized epoch root. So in auto mode, only begin
    // casting private votes once finality has bootstrapped (finalized height > 0, which
    // transparent votes establish). After that we cast BOTH a transparent vote (keeps
    // finality advancing, using transparent coins) AND a private vote (drives the v3
    // tally certificate, using shielded notes) -- different stake, no double-count.
    bool fFinalityBootstrapped =
        (g_dagManager.GetDeterministicFinalizedHeight(GetEpochForHeight(nCurrentHeight)) > 0);
    bool fAllowPrivateV2 = ((strVoteMode == "nullstake") ||
                            (strVoteMode == "auto" && fFinalityBootstrapped)) &&
                           tallyConfig.CanRelayPrivateVotes();
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
    // Cast the FAST transparent vote FIRST so it lands within the epoch inclusion
    // window [H_E, H_E+K) and keeps finality advancing; cast the slower private (FCMP)
    // vote afterwards. The private vote's proof generation can otherwise push the
    // transparent vote past the window on heavily-loaded nodes, stalling finalization.
    if (!fAllowTransparent)
        return (fAllowPrivateV2 && ProducePrivateNullStakeFinalityVote(
                    txdb, pEpochBlock, nCurrentEpoch, nEpochHeight, tallyConfig));

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
        return (fAllowPrivateV2 && ProducePrivateNullStakeFinalityVote(
                    txdb, pEpochBlock, nCurrentEpoch, nEpochHeight, tallyConfig));

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
        return (fAllowPrivateV2 && ProducePrivateNullStakeFinalityVote(
                    txdb, pEpochBlock, nCurrentEpoch, nEpochHeight, tallyConfig));

    if (!g_finalityTracker.AddVote(vote))
        return (fAllowPrivateV2 && ProducePrivateNullStakeFinalityVote(
                    txdb, pEpochBlock, nCurrentEpoch, nEpochHeight, tallyConfig));

    printf("ProduceFinalityVote: epoch=%d height=%d weight=%s\n",
           nCurrentEpoch, nEpochHeight, FormatMoney(pBestGroup->nWeight).c_str());

    {
        LOCK(cs_vNodes);
        for (CNode* pnode : vNodes)
        {
            pnode->PushMessage("fvote", vote);
        }
    }

    // Transparent vote is in; now cast the private (hidden-weight) vote for the v3
    // tally certificate. Done last so its slower FCMP proof can't delay the
    // finality-advancing transparent vote past the inclusion window.
    if (fAllowPrivateV2)
        ProducePrivateNullStakeFinalityVote(txdb, pEpochBlock, nCurrentEpoch,
                                            nEpochHeight, tallyConfig);
    return true;
}
