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
#include "subsidy.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <algorithm>
#include <cstdlib>
#include <cctype>
#include <limits>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/mutex.hpp>

CFinalityTracker g_finalityTracker;

static bool ReturnFinalityResult(FinalityResult* pResult,
                                 FinalityResult result,
                                 bool fReturn)
{
    if (pResult)
        *pResult = result;
    return fReturn;
}

bool ExtractFinalityStakeKeyID(const CScript& scriptPubKey,
                               CKeyID& keyIDOut)
{
    // ExtractDestination historically exposes the owner branch of P2CS.  That
    // is correct for wallet ownership/spending, but finality follows delegated
    // staking authority and must therefore select the staker branch explicitly.
    if (IsPayToColdStaking(scriptPubKey))
    {
        CKeyID ownerKeyID;
        return ExtractColdStakeKeys(scriptPubKey, keyIDOut, ownerKeyID);
    }

    CTxDestination dest;
    if (!ExtractDestination(scriptPubKey, dest))
        return false;
    return CBitcoinAddress(dest).GetKeyID(keyIDOut);
}

int GetFinalizedEpochForHeight(int nFinalizedHeight)
{
    if (nFinalizedHeight < 0 || nFinalizedHeight == std::numeric_limits<int>::max())
        return -1;
    return GetEpochForHeight(nFinalizedHeight + 1) - 1;
}

/** Resolve the finalized epoch anchor. Nothing finalized yet is a deterministic premature
 * verdict; only an unrecoverable expected record is a transient local failure. */
// fRequireCurveRoot: an IV5-root caller must not skip epochs with an empty legacy curve root.
static FinalityResult ResolveFinalityAnchorForContext(
    CTxDB& txdb, int nContextHeight, int nLiveFinalizedHeight,
    CEpochState& stateOut, bool fRequireCurveRoot = true,
    bool fAllowDeepUnfinalizedAnchor = false)
{
    int nFinalizedHeight = 0;
    if (nContextHeight >= 0)
    {
        const int nAsOfEpoch = GetEpochForHeight(nContextHeight) - 1;
        const bool fHaveProgress =
            nContextHeight >= FORK_HEIGHT_EPOCH_STATE_V2
                ? g_dagManager.TryGetDeterministicFinalizedHeight(
                      txdb, nAsOfEpoch, nFinalizedHeight)
                : g_dagManager.TryGetDeterministicFinalizedHeight(
                      nAsOfEpoch, nFinalizedHeight);
        if (!fHaveProgress)
            return FINALITY_RESULT_LOCAL_STATE;
        if (nFinalizedHeight <= 0)
            return FINALITY_RESULT_INVALID;

        const bool fHaveState =
            nContextHeight >= FORK_HEIGHT_EPOCH_STATE_V2
                ? g_dagManager.GetFinalizedEpochStateAsOf(
                      txdb, nContextHeight, stateOut)
                : g_dagManager.GetFinalizedEpochStateAsOf(
                      nContextHeight, stateOut);
        if (!fHaveState)
            return FINALITY_RESULT_LOCAL_STATE;
        // The finalized epoch is the last one ending at or below the finalized boundary.
        const int nFinalizedEpoch = GetFinalizedEpochForHeight(nFinalizedHeight);
        if (stateOut.nEpoch == nFinalizedEpoch)
        {
            if (stateOut.nHeightEnd > nFinalizedHeight)
                return FINALITY_RESULT_LOCAL_STATE;
            return FINALITY_RESULT_OK;
        }
        // Newer than the finalized epoch: GetFinalizedEpochStateAsOf also accepts an
        // epoch deep enough to stand without finality, so this is the answer, not a
        // mismatch. Pinning to the finalized epoch would stall voting while finality lags.
        if (!fAllowDeepUnfinalizedAnchor ||
            stateOut.nEpoch < nFinalizedEpoch ||
            stateOut.nHeightEnd <= 0 ||
            nContextHeight - stateOut.nHeightEnd <
                EPOCHSTATE_VNEXT_MIN_UNFINALIZED_ANCHOR_DEPTH)
            return FINALITY_RESULT_LOCAL_STATE;
        return FINALITY_RESULT_OK;
    }

    if (nLiveFinalizedHeight <= 0)
        return FINALITY_RESULT_INVALID;
    if (!g_dagManager.GetLastFinalizedEpochState(stateOut, fRequireCurveRoot) ||
        stateOut.nEpoch != GetFinalizedEpochForHeight(nLiveFinalizedHeight))
        return FINALITY_RESULT_LOCAL_STATE;
    return FINALITY_RESULT_OK;
}


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

// Coin-age over nEpochUnits at nRatePerCoinYear. Integer truncation is deterministic: the
// note and certificate proofs reproduce these exact quotients and remainders.
int64_t GetFinalityVoteReward(int64_t nVoteWeight, int nEpochUnits, int64_t nRatePerCoinYear)
{
    if (nVoteWeight <= 0 || nEpochUnits <= 0 || nRatePerCoinYear <= 0)
        return 0;

    CBigNum bnCoinAge = CBigNum(nVoteWeight) * nEpochUnits / COIN / (24 * 60 * 60);
    uint64_t nCoinAge = bnCoinAge.getuint64();
    CBigNum bnReward = CBigNum(nCoinAge) * nRatePerCoinYear / 365;
    uint64_t nReward = bnReward.getuint64();
    if (nReward > (uint64_t)MAX_MONEY)
        return MAX_MONEY;
    return (int64_t)nReward;
}

int64_t GetFinalityVoteRewardAtHeight(int64_t nVoteWeight, int nHeight)
{
    return GetFinalityVoteReward(nVoteWeight, GetFinalityRewardUnits(nHeight),
                                 GetFinalityVoteRate(nHeight));
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
    // v3 is the FLOOR the signer-set needs, not the version. A v4 note certificate's
    // signature digest covers its note fields, so forcing 3 here would compute a digest
    // nobody signed and discard every collected signature.
    if (cert.nVersion < 3)
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
    // A v4 note certificate collects signatures here too: its range proofs are
    // entropy-bearing and cannot be rebuilt byte-for-byte, so the M-of-N signature set is
    // the only thing that authorizes its note side.
    if (!cand.HasPrivateWeight() && !cand.HasNoteWeight())
        return reject("cert-signature candidate carries no weight a committee authorizes");

    // Validate the candidate's CONTENT (tally/coverage/proofs) — everything
    // except the committee signer-set, which is what we are collecting.
    std::string strErr;
    if (!CheckTallyCertificate(cand, txdb, &strErr, NULL, true, -1, true))
        return reject(std::string("cert-signature candidate invalid: ") + strErr);

    // Resolve the committee that must authorize this epoch, then verify the signature.
    std::vector<CPubKey> vCommittee; int nM = 0; uint256 setHash;
    if (!GetCommitteeForEpoch(txdb, cand.nEpoch, vCommittee, nM, setHash))
        return reject("no canonical committee for candidate epoch");
    if (cand.committeeSetHash != setHash)
        return reject("cert-signature candidate committee-set mismatch");

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


// ---------------------------------------------------------------------------
// Stake-derived finality committee
// ---------------------------------------------------------------------------

int GetFinalityCommitteeSeats()
{
    extern bool fRegTest;
    return fRegTest ? 3 : FINALITY_COMMITTEE_SEATS;
}

int GetFinalityCommitteeThresholdM()
{
    extern bool fRegTest;
    return fRegTest ? 2 : FINALITY_COMMITTEE_THRESHOLD_M;
}

int GetFinalityCommitteeTermEpochs()
{
    extern bool fRegTest;
    return fRegTest ? 2 : FINALITY_COMMITTEE_TERM_EPOCHS;
}

// The seed for one term's draw.
//
// Binds the shape as well as the entropy: a build that changed the seat count or the
// threshold would otherwise draw from the same seed as one that did not, and the two
// would disagree about a committee while agreeing about the seed that produced it.
//
// The entropy is the anchor epoch's canonical end block alone. It cannot come earlier
// than the registration cutoff: a seed already public by then is one a registrant
// grinds a key image against offline, without bound. So the last word belongs to some
// producer after the cutoff either way, and the only question is how many.
//
// vBlockHashes made that many. It is the epoch's whole DAG order, including merge and
// sibling blocks, which never had to win a height race -- so a miner could hold one,
// evaluate the seed it would produce, and release it only if favourable. The end block
// carries the same entropy over one block at one height, and the order is derived from
// it anyway. Grinding is reduced, not removed: that block's producer can still resample
// by discarding a solution it could have published.
static uint256 FinalityCommitteeDrawSeed(int nTermEpoch, int nSeats, int nThresholdM,
                                         const CEpochState& anchorState)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("Innova/Finality/CommitteeDraw/v2");
    ss << nTermEpoch;
    ss << nSeats;
    ss << nThresholdM;
    ss << anchorState.nEpoch;
    ss << anchorState.hashBoundaryBlock;
    return ss.GetHash();
}

// A registration's position in the draw. Keyed on the key image, which is the one
// part of a registration its holder cannot choose after the fact.
static uint256 FinalityCommitteeSeatOrder(const uint256& seed, const uint256& keyImage)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("Innova/Finality/CommitteeSeat/v1");
    ss << seed;
    ss << keyImage;
    return ss.GetHash();
}

bool DrawFinalityCommitteeForTerm(CTxDB& txdbEpoch, CTxDB& txdbRegistry,
                                  int nTermEpoch,
                                  CFinalityCommitteeDraw& drawOut,
                                  bool& fLocalFailureOut,
                                  std::string& strError)
{
    drawOut = CFinalityCommitteeDraw();
    fLocalFailureOut = false;
    strError.clear();

    const int nSeats = GetFinalityCommitteeSeats();
    const int nThresholdM = GetFinalityCommitteeThresholdM();
    const int nAnchorEpoch = nTermEpoch - FINALITY_COMMITTEE_DRAW_LAG_EPOCHS;

    drawOut.nTermEpoch = nTermEpoch;
    drawOut.nAnchorEpoch = nAnchorEpoch;
    drawOut.nThresholdM = nThresholdM;

    if (nTermEpoch < 0 || nAnchorEpoch < 0)
        return true;   // no chain behind the term yet; seat nothing

    const int nAnchorHeight = GetEpochBoundaryHeight(nAnchorEpoch, 0);
    drawOut.nAnchorHeight = nAnchorHeight;

    // The seed's entropy. Read through the caller's handle so a staged record is
    // visible: the epoch that carries the draw is built in the same batch.
    CEpochState anchorState;
    if (!txdbEpoch.ReadEpochState(nAnchorEpoch, anchorState) ||
        anchorState.nEpoch != nAnchorEpoch)
        return true;   // the chain has not produced that epoch's state; seat nothing

    // An epoch record with no end block never named the block the seed is taken from,
    // and seeding from zero would hand every such term one predictable draw. Seating
    // nothing is the answer every node reaches, because the field is part of the
    // record's digest and so is the same on all of them.
    if (anchorState.hashBoundaryBlock == 0)
        return true;

    // What makes the registry read below safe to take from a batch-free handle.
    //
    // The registry enumeration cannot see an in-flight write batch, so it is only the
    // right answer if no in-flight batch is adding to or rolling back a registration
    // at or below the anchor height. Reading the anchor epoch's record through both
    // handles decides exactly that: if the caller's transaction had rebuilt any part
    // of the anchor epoch -- which is what a reorg reaching down to the anchor height
    // necessarily does -- the staged record would differ from the committed one. Equal
    // records mean the transaction's fork point is past the anchor epoch's end, so
    // every row this reads was committed before the transaction opened and is the same
    // row on every node.
    //
    // A disagreement is reported as a local failure, never as "seat nothing": seating
    // a different committee than a peer is a split, whereas refusing the transaction
    // leaves this node on its current chain to try again a block at a time.
    CEpochState anchorCommitted;
    if (!txdbRegistry.ReadEpochState(nAnchorEpoch, anchorCommitted) ||
        anchorCommitted.GetDigest() != anchorState.GetDigest())
    {
        fLocalFailureOut = true;
        strError = strprintf(
            "epoch %d is being rebuilt in this transaction, so its committee draw "
            "cannot read a settled registration snapshot", nAnchorEpoch);
        return false;
    }

    drawOut.seed = FinalityCommitteeDrawSeed(nTermEpoch, nSeats, nThresholdM, anchorState);

    std::vector<CPrivacyVNextRegistryEntry> vRegistry;
    bool fRegistryLocalFailure = false;
    std::string strRegistryError;
    if (!GetPrivacyVNextCollateralSnapshot(txdbRegistry, nAnchorHeight, true /* members only */,
                                           vRegistry, fRegistryLocalFailure, strRegistryError))
    {
        fLocalFailureOut = fRegistryLocalFailure;
        strError = strRegistryError;
        return false;
    }
    drawOut.nRegistrySize = vRegistry.size();

    // Thin-registry rule. Seating a committee that is most of the registry tells
    // everyone who the members are and leaves almost no one to have been a candidate.
    if ((int)vRegistry.size() < nSeats * FINALITY_COMMITTEE_MIN_REGISTRY_MULTIPLE)
        return true;

    std::vector<std::pair<std::pair<uint256, uint256>, size_t> > vOrder;
    vOrder.reserve(vRegistry.size());
    for (size_t i = 0; i < vRegistry.size(); ++i)
    {
        // The key image is the tie-break, and it is unique per row, so the order is
        // total without appealing to the input sequence.
        vOrder.push_back(std::make_pair(
            std::make_pair(FinalityCommitteeSeatOrder(drawOut.seed, vRegistry[i].keyImage),
                           vRegistry[i].keyImage),
            i));
    }
    std::sort(vOrder.begin(), vOrder.end());

    // One seat per member key. Two seats behind one key would seal two Shamir shares
    // to the same recipient, which is one share for threshold purposes while counting
    // as two, so M-of-N would open on fewer parties than it names.
    std::set<std::vector<unsigned char> > setSeated;
    for (size_t i = 0; i < vOrder.size() && (int)drawOut.vSeats.size() < nSeats; ++i)
    {
        const CPrivacyVNextRegistryEntry& entry = vRegistry[vOrder[i].second];
        if (!setSeated.insert(entry.vchMemberKey).second)
            continue;
        CPubKey pubkey(entry.vchMemberKey);
        if (!pubkey.IsValid() || !pubkey.IsFullyValid() || !pubkey.IsCompressed())
            continue;   // the registration decoder already refused these; belt and braces
        drawOut.vSeats.push_back(pubkey);
        drawOut.vSeatKeyImages.push_back(entry.keyImage);
    }

    if ((int)drawOut.vSeats.size() < nSeats)
        return true;   // too few distinct member keys to fill the seats

    drawOut.setHash = ComputeFinalityTallyCommitteeHash(nThresholdM, drawOut.vSeats);
    drawOut.fSeated = true;
    return true;
}

bool SeatFinalityCommitteeForEpochState(CTxDB& txdb, CEpochState& state,
                                        bool& fLocalFailureOut, std::string& strError)
{
    fLocalFailureOut = false;
    strError.clear();
    state.vFinalityCommittee.clear();
    state.nFinalityCommitteeM = 0;

    if (state.nSerVersion < EPOCHSTATE_SER_VERSION_V6)
        return true;   // below FORK_HEIGHT_IV5_NOTE_VOTE there is no committee to carry

    // Exactly one epoch per term carries the draw: the one that ends immediately
    // before it. Drawing here rather than on demand is what makes the committee a
    // term constant — registrations keep arriving and collateral keeps being spent,
    // and a resolver that redrew per block would answer differently as they did.
    const int nTermEpoch = state.nEpoch + 1;
    if (nTermEpoch != GetFinalityCommitteeTermEpoch(nTermEpoch))
        return true;

    // A batch-free handle for the registry iterator. The block being connected owns
    // txdb's write batch; an iterator cannot see it, and the snapshot's spent-index
    // point reads beside it would answer from committed state anyway, so mixing the
    // two is what would make the two halves disagree.
    CTxDB txdbRegistry("r");
    CFinalityCommitteeDraw draw;
    if (!DrawFinalityCommitteeForTerm(txdb, txdbRegistry, nTermEpoch, draw,
                                      fLocalFailureOut, strError))
        return false;
    if (!draw.fSeated)
        return true;

    for (size_t i = 0; i < draw.vSeats.size(); ++i)
        state.vFinalityCommittee.push_back(
            std::vector<unsigned char>(draw.vSeats[i].begin(), draw.vSeats[i].end()));
    state.nFinalityCommitteeM = draw.nThresholdM;
    return true;
}

bool CFinalityTracker::GetCommitteeForEpoch(CTxDB& txdb, int nEpoch,
                                            std::vector<CPubKey>& vOut,
                                            int& nMOut, uint256& setHashOut,
                                            bool* pfLocalFailure) const
{
    if (pfLocalFailure)
        *pfLocalFailure = false;
    vOut.clear();
    nMOut = 0;
    setHashOut = 0;

    const int nTermEpoch = GetFinalityCommitteeTermEpoch(nEpoch);
    if (nTermEpoch <= 0)
        return false;   // the first term has no epoch behind it to carry a draw

    // The draw lives in the epoch state that ends the term's lead-in. Reading it back
    // makes the committee a pure function of a record every node on this chain holds
    // byte-identically, rather than of whatever each node's registry looks like now.
    CEpochState carrier;
    if (!txdb.ReadEpochState(nTermEpoch - 1, carrier) || carrier.nEpoch != nTermEpoch - 1)
        return false;
    if (carrier.vFinalityCommittee.empty() || carrier.nFinalityCommitteeM <= 0)
        return false;   // that term seated nothing: transparent-only certification

    std::vector<CPubKey> vSeats;
    for (size_t i = 0; i < carrier.vFinalityCommittee.size(); ++i)
    {
        CPubKey pubkey(carrier.vFinalityCommittee[i]);
        if (!pubkey.IsValid() || !pubkey.IsFullyValid() || !pubkey.IsCompressed())
        {
            // A record this node cannot decode is this node's problem, not the
            // chain's: calling it a consensus outcome would reject blocks every
            // healthy peer accepts.
            if (pfLocalFailure)
                *pfLocalFailure = true;
            return false;
        }
        vSeats.push_back(pubkey);
    }
    if (carrier.nFinalityCommitteeM > (int)vSeats.size())
    {
        if (pfLocalFailure)
            *pfLocalFailure = true;
        return false;
    }

    vOut = vSeats;
    nMOut = carrier.nFinalityCommitteeM;
    setHashOut = ComputeFinalityTallyCommitteeHash(nMOut, vOut);
    return true;
}

bool GetCanonicalFinalityCommittee(CTxDB& txdb, int nEpoch,
                                   std::vector<CPubKey>& vCommitteeOut,
                                   int& nMOut,
                                   uint256& setHashOut,
                                   bool* pfLocalFailure)
{
    return g_finalityTracker.GetCommitteeForEpoch(txdb, nEpoch, vCommitteeOut, nMOut,
                                                  setHashOut, pfLocalFailure);
}

// A committee signature is part of a certificate's identity, so an unenforced
// encoding lets a third party re-encode it and change the certificate hash
// without its signers. Our own signer already emits low-S DER.
static bool IsCanonicalCommitteeSignature(const std::vector<unsigned char>& vchSig)
{
    if (!IsDERSignature(vchSig, false))
        return false;
    const unsigned int nLenR = vchSig[3];
    if (vchSig.size() < (size_t)6 + nLenR)
        return false;
    const unsigned int nLenS = vchSig[5 + nLenR];
    if (vchSig.size() < (size_t)6 + nLenR + nLenS)
        return false;
    return CKey::CheckSignatureElement(&vchSig[6 + nLenR], nLenS, true);
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
    if (cert.nHeight >= FORK_HEIGHT_COMMITTEE_SIG_CANONICAL)
    {
        for (size_t i = 0; i < cert.vSignerSigs.size(); i++)
        {
            if (!IsCanonicalCommitteeSignature(cert.vSignerSigs[i]))
                return reject("tally certificate carries a non-canonical committee signature");
        }
    }
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

static bool CanonicalVoteHasExactEmptyPrivateProof(const CFinalityVote& vote)
{
    CDataStream actual(SER_NETWORK, PROTOCOL_VERSION);
    CDataStream expected(SER_NETWORK, PROTOCOL_VERSION);
    actual << vote.privateProof;
    expected << CPrivateFinalityVoteProof();
    return actual.size() == expected.size() &&
           std::equal(actual.begin(), actual.end(), expected.begin());
}

// The legacy-private fields a canonical certificate never carries. fAllowSignerSet
// keeps the schema-1 rule byte-for-byte (no signer-set at all) while letting the F2
// schema carry the M-of-N signatures that authorize its note tally.
static bool CanonicalCertificateHasExactEmptyOmittedFields(
    const CFinalityTallyCertificate& cert, bool fAllowSignerSet = false)
{
    CFinalityTallyCertificate empty;
    CDataStream actual(SER_NETWORK, PROTOCOL_VERSION);
    CDataStream expected(SER_NETWORK, PROTOCOL_VERSION);
    actual << cert.activeWeightCommitment << cert.winningWeightCommitment
           << cert.rewardBudgetCommitment << cert.vTallyShareHashes
           << cert.vchAggregateThresholdProof << cert.vchRewardBudgetProof;
    expected << empty.activeWeightCommitment << empty.winningWeightCommitment
             << empty.rewardBudgetCommitment << empty.vTallyShareHashes
             << empty.vchAggregateThresholdProof << empty.vchRewardBudgetProof;
    if (!fAllowSignerSet)
    {
        actual << cert.vSignerIndexes << cert.vSignerSigs;
        expected << empty.vSignerIndexes << empty.vSignerSigs;
    }
    return actual.size() == expected.size() &&
           std::equal(actual.begin(), actual.end(), expected.begin());
}

bool CCanonicalFinalityVoteEnvelope::FromLogical(const CFinalityVote& vote)
{
    if (!vote.IsCanonicalEnvelope() ||
        vote.nProofMode != FINALITY_PROOF_TRANSPARENT ||
        !CanonicalVoteHasExactEmptyPrivateProof(vote) ||
        vote.vStakeProof.size() > FINALITY_MAX_STAKE_PROOFS ||
        vote.vchPubKey.size() > 65 || vote.vchSig.size() > 80)
        return false;

    nLogicalVersion = FINALITY_CANONICAL_VOTE_VERSION;
    nEpoch = vote.nEpoch;
    hashBlock = vote.hashBlock;
    nHeight = vote.nHeight;
    nTime = vote.nTime;
    nVoteWeight = vote.nVoteWeight;
    nReward = vote.nReward;
    nullifier = vote.nullifier;
    vStakeProof = vote.vStakeProof;
    vchPubKey = vote.vchPubKey;
    vchSig = vote.vchSig;
    return true;
}

bool CCanonicalFinalityVoteEnvelope::ToLogical(CFinalityVote& voteOut) const
{
    if (nLogicalVersion != FINALITY_CANONICAL_VOTE_VERSION ||
        vStakeProof.size() > FINALITY_MAX_STAKE_PROOFS ||
        vchPubKey.size() > 65 || vchSig.size() > 80)
        return false;

    CFinalityVote vote;
    vote.nProofMode = FINALITY_PROOF_TRANSPARENT;
    vote.nEpoch = nEpoch;
    vote.hashBlock = hashBlock;
    vote.nHeight = nHeight;
    vote.nTime = nTime;
    vote.nVoteWeight = nVoteWeight;
    vote.nReward = nReward;
    vote.nullifier = nullifier;
    vote.vStakeProof = vStakeProof;
    vote.vchPubKey = vchPubKey;
    vote.vchSig = vchSig;
    vote.MarkCanonicalEnvelope();
    voteOut = vote;
    return true;
}

bool CCanonicalFinalityTallyCertificateEnvelope::FromLogical(
    const CFinalityTallyCertificate& cert)
{
    // Schema 2 exists only for a note-bearing v4 certificate; everything else keeps
    // schema 1 exactly, so no pre-F2 certificate changes its encoding.
    const bool fNoteSchema = (cert.nVersion == FINALITY_NOTE_CERT_VERSION);
    if (!cert.IsCanonicalEnvelope() || cert.HasPrivateWeight() ||
        cert.vVoteNullifiers.size() > FINALITY_CANONICAL_CERT_MAX_NULLIFIERS)
        return false;
    if (fNoteSchema)
    {
        if (!cert.HasNoteWeight() ||
            !CanonicalCertificateHasExactEmptyOmittedFields(cert, true))
            return false;
    }
    else
    {
        if (cert.nVersion < 1 || cert.nVersion > 2 ||
            !CanonicalCertificateHasExactEmptyOmittedFields(cert) ||
            !cert.vSignerIndexes.empty() || !cert.vSignerSigs.empty() ||
            cert.HasNoteWeight() || !cert.vNoteComplaints.empty())
            return false;
    }

    nLogicalVersion = fNoteSchema ? FINALITY_CANONICAL_TALLY_CERT_VERSION_NOTE
                                  : FINALITY_CANONICAL_TALLY_CERT_VERSION;
    nCertificateVersion = cert.nVersion;
    vSignerIndexes = cert.vSignerIndexes;
    vSignerSigs = cert.vSignerSigs;
    vNoteVoteTags = cert.vNoteVoteTags;
    vNoteComplaints = cert.vNoteComplaints;
    noteTierProofs = cert.noteTierProofs;
    nEpoch = cert.nEpoch;
    hashBlock = cert.hashBlock;
    nHeight = cert.nHeight;
    nTier = cert.nTier;
    nConsecutiveHardCount = cert.nConsecutiveHardCount;
    hashCurveRoot = cert.hashCurveRoot;
    hashNullifierRoot = cert.hashNullifierRoot;
    committeeSetHash = cert.committeeSetHash;
    nTransparentActiveWeight = cert.nTransparentActiveWeight;
    nTransparentWinningWeight = cert.nTransparentWinningWeight;
    nTransparentRewardBudget = cert.nTransparentRewardBudget;
    vVoteNullifiers = cert.vVoteNullifiers;
    return true;
}

bool CCanonicalFinalityTallyCertificateEnvelope::ToLogical(
    CFinalityTallyCertificate& certOut) const
{
    if (vVoteNullifiers.size() > FINALITY_CANONICAL_CERT_MAX_NULLIFIERS)
        return false;
    // Each schema admits exactly one certificate version, so a note-bearing cert can
    // never arrive under schema 1 and a transparent one can never arrive under 2.
    if (nLogicalVersion == FINALITY_CANONICAL_TALLY_CERT_VERSION)
    {
        if (nCertificateVersion < 1 || nCertificateVersion > 2)
            return false;
        // Schema 1 does not serialize these, so a non-empty one can only come from an
        // in-memory envelope; it must not smuggle a note side into a schema-1 cert.
        if (!vSignerIndexes.empty() || !vSignerSigs.empty() || !vNoteVoteTags.empty() ||
            !vNoteComplaints.empty() || !noteTierProofs.IsNull())
            return false;
    }
    else if (nLogicalVersion == FINALITY_CANONICAL_TALLY_CERT_VERSION_NOTE)
    {
        if (nCertificateVersion != FINALITY_NOTE_CERT_VERSION)
            return false;
        // The schema is only readable once note votes are live. IsValidBasic repeats
        // this on the decoded certificate; refusing it here keeps a pre-fork block
        // from carrying a well-formed object at all.
        if (!IsIV5NoteVoteActiveAtHeight(nHeight))
            return false;
    }
    else
        return false;

    CFinalityTallyCertificate cert;
    cert.nVersion = nCertificateVersion;
    cert.vSignerIndexes = vSignerIndexes;
    cert.vSignerSigs = vSignerSigs;
    cert.vNoteVoteTags = vNoteVoteTags;
    cert.vNoteComplaints = vNoteComplaints;
    cert.noteTierProofs = noteTierProofs;
    cert.nEpoch = nEpoch;
    cert.hashBlock = hashBlock;
    cert.nHeight = nHeight;
    cert.nTier = nTier;
    cert.nConsecutiveHardCount = nConsecutiveHardCount;
    cert.hashCurveRoot = hashCurveRoot;
    cert.hashNullifierRoot = hashNullifierRoot;
    cert.committeeSetHash = committeeSetHash;
    cert.nTransparentActiveWeight = nTransparentActiveWeight;
    cert.nTransparentWinningWeight = nTransparentWinningWeight;
    cert.nTransparentRewardBudget = nTransparentRewardBudget;
    cert.vVoteNullifiers = vVoteNullifiers;
    cert.MarkCanonicalEnvelope();
    certOut = cert;
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

static bool ExtractCanonicalTaggedOpReturnPayload(
    const CScript& scriptPubKey, const unsigned char* pchTag,
    std::vector<unsigned char>& vPayloadOut)
{
    if (!ExtractTaggedOpReturnPayload(scriptPubKey, pchTag, vPayloadOut))
        return false;

    const unsigned int nDataSize = (unsigned int)vPayloadOut.size() + 4;
    CScript::const_iterator pc = scriptPubKey.begin();
    ++pc; // OP_RETURN was checked by ExtractTaggedOpReturnPayload.
    const opcodetype opcode = (opcodetype)*pc;
    if (nDataSize < OP_PUSHDATA1)
        return opcode == (opcodetype)nDataSize;
    if (nDataSize <= 0xff)
        return opcode == OP_PUSHDATA1;
    if (nDataSize <= 0xffff)
        return opcode == OP_PUSHDATA2;
    return opcode == OP_PUSHDATA4;
}

static bool ScriptCarriesFinalityTag(const CScript& scriptPubKey,
                                     const unsigned char* pchTag)
{
    if (scriptPubKey.size() > MAX_SCRIPT_SIZE)
        return false;
    CScript::const_iterator pc = scriptPubKey.begin();
    if (pc == scriptPubKey.end() || *pc++ != OP_RETURN ||
        pc == scriptPubKey.end())
        return false;

    unsigned int nSize = 0;
    const opcodetype opcode = (opcodetype)*pc++;
    if (opcode < OP_PUSHDATA1)
        nSize = opcode;
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
        return false;

    if (nSize < 4 || nSize > MAX_SCRIPT_SIZE ||
        (unsigned int)(scriptPubKey.end() - pc) != nSize)
        return false;
    return memcmp(&pc[0], pchTag, 4) == 0;
}

// Wire-only readers for historical IFVT/IFTC carriers: they keep the legacy rule of
// decoding oversized objects and rejecting them in IsValid, rather than ignoring them.
// Input is capped to MAX_SCRIPT_SIZE by ExtractTaggedOpReturnPayload.
class CLegacyPrivateFinalityVoteProofWire
{
public:
    int nVersion;
    int nProofMode;
    int nEpoch;
    uint256 hashEpochBlock;
    uint256 hashCurveRoot;
    uint256 hashNullifierRoot;
    uint256 nullifier;
    CPedersenCommitment stakeWeightCommitment;
    CPedersenCommitment rewardCommitment;
    CFCMPProof fcmpProof;
    CNullStakeKernelProofV2 nullStakeV2Proof;
    CNullStakeKernelProofV3 nullStakeV3Proof;
    std::vector<unsigned char> vchRewardOutputCommitment;
    std::vector<unsigned char> vchBindingProof;
    std::vector<unsigned char> vchNullifierPoint;
    std::vector<unsigned char> vchNullifierBindingProof;

    CLegacyPrivateFinalityVoteProofWire()
        : nVersion(1), nProofMode(FINALITY_PROOF_TRANSPARENT), nEpoch(0) {}

    IMPLEMENT_SERIALIZE
    (
        CLegacyPrivateFinalityVoteProofWire* pthis =
            const_cast<CLegacyPrivateFinalityVoteProofWire*>(this);
        READWRITE(pthis->nVersion);
        READWRITE(pthis->nProofMode);
        READWRITE(pthis->nEpoch);
        READWRITE(pthis->hashEpochBlock);
        READWRITE(pthis->hashCurveRoot);
        READWRITE(pthis->hashNullifierRoot);
        READWRITE(pthis->nullifier);
        READWRITE(pthis->stakeWeightCommitment);
        READWRITE(pthis->rewardCommitment);
        READWRITE(pthis->fcmpProof);
        READWRITE(pthis->nullStakeV2Proof);
        READWRITE(pthis->nullStakeV3Proof);
        READWRITE(pthis->vchRewardOutputCommitment);
        READWRITE(pthis->vchBindingProof);
        unsigned char fHasNfBind =
            (pthis->vchNullifierPoint.empty() &&
             pthis->vchNullifierBindingProof.empty()) ? 0 : 1;
        READWRITE(fHasNfBind);
        if (fHasNfBind)
        {
            READWRITE(pthis->vchNullifierPoint);
            READWRITE(pthis->vchNullifierBindingProof);
        }
    )

    void ToLogical(CPrivateFinalityVoteProof& proof) const
    {
        proof = CPrivateFinalityVoteProof();
        proof.nVersion = nVersion;
        proof.nProofMode = nProofMode;
        proof.nEpoch = nEpoch;
        proof.hashEpochBlock = hashEpochBlock;
        proof.hashCurveRoot = hashCurveRoot;
        proof.hashNullifierRoot = hashNullifierRoot;
        proof.nullifier = nullifier;
        proof.stakeWeightCommitment = stakeWeightCommitment;
        proof.rewardCommitment = rewardCommitment;
        proof.fcmpProof = fcmpProof;
        proof.nullStakeV2Proof = nullStakeV2Proof;
        proof.nullStakeV3Proof = nullStakeV3Proof;
        proof.vchRewardOutputCommitment = vchRewardOutputCommitment;
        proof.vchBindingProof = vchBindingProof;
        proof.vchNullifierPoint = vchNullifierPoint;
        proof.vchNullifierBindingProof = vchNullifierBindingProof;
    }
};

class CLegacyFinalityVoteWire
{
public:
    int nProofMode;
    int nEpoch;
    uint256 hashBlock;
    int nHeight;
    int64_t nTime;
    int64_t nVoteWeight;
    int64_t nReward;
    uint256 nullifier;
    std::vector<COutPoint> vStakeProof;
    std::vector<unsigned char> vchPubKey;
    std::vector<unsigned char> vchSig;
    CLegacyPrivateFinalityVoteProofWire privateProof;

    CLegacyFinalityVoteWire()
        : nProofMode(FINALITY_PROOF_TRANSPARENT), nEpoch(0), nHeight(0),
          nTime(0), nVoteWeight(0), nReward(0) {}

    IMPLEMENT_SERIALIZE
    (
        CLegacyFinalityVoteWire* pthis =
            const_cast<CLegacyFinalityVoteWire*>(this);
        READWRITE(pthis->nProofMode);
        READWRITE(pthis->nEpoch);
        READWRITE(pthis->hashBlock);
        READWRITE(pthis->nHeight);
        READWRITE(VARINT(pthis->nTime));
        READWRITE(VARINT(pthis->nVoteWeight));
        READWRITE(VARINT(pthis->nReward));
        READWRITE(pthis->nullifier);
        READWRITE(pthis->vStakeProof);
        READWRITE(pthis->vchPubKey);
        READWRITE(pthis->vchSig);
        READWRITE(pthis->privateProof);
    )

    void ToLogical(CFinalityVote& vote) const
    {
        vote = CFinalityVote();
        vote.nProofMode = nProofMode;
        vote.nEpoch = nEpoch;
        vote.hashBlock = hashBlock;
        vote.nHeight = nHeight;
        vote.nTime = nTime;
        vote.nVoteWeight = nVoteWeight;
        vote.nReward = nReward;
        vote.nullifier = nullifier;
        vote.vStakeProof = vStakeProof;
        vote.vchPubKey = vchPubKey;
        vote.vchSig = vchSig;
        privateProof.ToLogical(vote.privateProof);
        vote.fCanonicalEnvelope = false;
    }
};

class CLegacyFinalityCertificateWire
{
public:
    int nVersion;
    int nEpoch;
    uint256 hashBlock;
    int nHeight;
    int nTier;
    int nConsecutiveHardCount;
    uint256 hashCurveRoot;
    uint256 hashNullifierRoot;
    uint256 committeeSetHash;
    CPedersenCommitment activeWeightCommitment;
    CPedersenCommitment winningWeightCommitment;
    CPedersenCommitment rewardBudgetCommitment;
    int64_t nTransparentActiveWeight;
    int64_t nTransparentWinningWeight;
    int64_t nTransparentRewardBudget;
    std::vector<uint256> vVoteNullifiers;
    std::vector<uint256> vTallyShareHashes;
    std::vector<unsigned char> vchAggregateThresholdProof;
    std::vector<unsigned char> vchRewardBudgetProof;
    std::vector<uint16_t> vSignerIndexes;
    std::vector<std::vector<unsigned char> > vSignerSigs;

    CLegacyFinalityCertificateWire()
        : nVersion(2), nEpoch(0), nHeight(0), nTier(FINALITY_NONE),
          nConsecutiveHardCount(0), nTransparentActiveWeight(0),
          nTransparentWinningWeight(0), nTransparentRewardBudget(0) {}

    IMPLEMENT_SERIALIZE
    (
        CLegacyFinalityCertificateWire* pthis =
            const_cast<CLegacyFinalityCertificateWire*>(this);
        READWRITE(pthis->nVersion);
        READWRITE(pthis->nEpoch);
        READWRITE(pthis->hashBlock);
        READWRITE(pthis->nHeight);
        READWRITE(pthis->nTier);
        READWRITE(pthis->nConsecutiveHardCount);
        READWRITE(pthis->hashCurveRoot);
        READWRITE(pthis->hashNullifierRoot);
        if (pthis->nVersion >= 2)
            READWRITE(pthis->committeeSetHash);
        READWRITE(pthis->activeWeightCommitment);
        READWRITE(pthis->winningWeightCommitment);
        READWRITE(pthis->rewardBudgetCommitment);
        READWRITE(VARINT(pthis->nTransparentActiveWeight));
        READWRITE(VARINT(pthis->nTransparentWinningWeight));
        READWRITE(VARINT(pthis->nTransparentRewardBudget));
        READWRITE(pthis->vVoteNullifiers);
        READWRITE(pthis->vTallyShareHashes);
        READWRITE(pthis->vchAggregateThresholdProof);
        READWRITE(pthis->vchRewardBudgetProof);
        if (pthis->nVersion >= 3)
        {
            READWRITE(pthis->vSignerIndexes);
            READWRITE(pthis->vSignerSigs);
        }
    )

    void ToLogical(CFinalityTallyCertificate& cert) const
    {
        cert = CFinalityTallyCertificate();
        cert.nVersion = nVersion;
        cert.nEpoch = nEpoch;
        cert.hashBlock = hashBlock;
        cert.nHeight = nHeight;
        cert.nTier = nTier;
        cert.nConsecutiveHardCount = nConsecutiveHardCount;
        cert.hashCurveRoot = hashCurveRoot;
        cert.hashNullifierRoot = hashNullifierRoot;
        cert.committeeSetHash = committeeSetHash;
        cert.activeWeightCommitment = activeWeightCommitment;
        cert.winningWeightCommitment = winningWeightCommitment;
        cert.rewardBudgetCommitment = rewardBudgetCommitment;
        cert.nTransparentActiveWeight = nTransparentActiveWeight;
        cert.nTransparentWinningWeight = nTransparentWinningWeight;
        cert.nTransparentRewardBudget = nTransparentRewardBudget;
        cert.vVoteNullifiers = vVoteNullifiers;
        cert.vTallyShareHashes = vTallyShareHashes;
        cert.vchAggregateThresholdProof = vchAggregateThresholdProof;
        cert.vchRewardBudgetProof = vchRewardBudgetProof;
        cert.vSignerIndexes = vSignerIndexes;
        cert.vSignerSigs = vSignerSigs;
        cert.fCanonicalEnvelope = false;
    }
};

bool ExtractFinalityVote(const CScript& scriptPubKey, CFinalityVote& voteOut)
{
    std::vector<unsigned char> vPayload;
    if (!ExtractTaggedOpReturnPayload(scriptPubKey, FINALITY_VOTE_TAG, vPayload))
        return false;

    try {
        CDataStream ss(vPayload, SER_NETWORK, PROTOCOL_VERSION);
        CLegacyFinalityVoteWire wire;
        ss >> wire;
        wire.ToLogical(voteOut);
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

//
// Per-epoch finality-reward settlement.
//

bool CheckFinalityVoteCommitments(const CBlock& block, const std::vector<CFinalityVote>& vVotes,
                                  std::string* pstrError)
{
    auto reject = [&](const std::string& strReason) -> bool {
        if (pstrError)
            *pstrError = strReason;
        return false;
    };

    if (vVotes.empty())
        return true;
    if (vVotes.size() > FINALITY_MAX_BLOCK_VOTES)
        return reject("too many finality votes in block");
    if (block.vtx.empty())
        return reject("block has no coinbase");

    std::set<uint256> setNullifiers;
    for (const CFinalityVote& vote : vVotes)
    {
        if (!setNullifiers.insert(vote.nullifier).second)
            return reject("duplicate finality vote nullifier");
        if (vote.IsPrivate())
            continue;
        if (vote.nReward < 0 || !MoneyRange(vote.nReward))
            return reject("finality reward out of range");
        CPubKey pubkey(vote.vchPubKey);
        if (!pubkey.IsValid())
            return reject("finality vote pubkey invalid");
    }

    // Deliberately no payment accounting: a carrying block's coinbase allowance is the
    // block subsidy alone, so re-embedding a vote across several canonical blocks buys
    // the carrier nothing. All finality reward is minted at the epoch settlement height.
    return true;
}

void CollectFinalitySettlementVotes(const std::vector<std::vector<CFinalityVote> >& vWindowBlockVotes,
                                    int nEpoch,
                                    std::vector<CFinalityVote>& vVotesOut)
{
    vVotesOut.clear();
    std::set<uint256> setSeen;
    // vWindowBlockVotes is in ascending window-block order; within a block, coinbase
    // vout order. That total order is what makes the settlement reproducible.
    for (const std::vector<CFinalityVote>& vBlockVotes : vWindowBlockVotes)
    {
        for (const CFinalityVote& vote : vBlockVotes)
        {
            if (vote.nEpoch != nEpoch)
                continue;
            // One payment per counted vote: a vote re-embedded by several window blocks
            // pays only at its first occurrence, so producer and validator agree on order.
            if (!setSeen.insert(vote.nullifier).second)
                continue;
            vVotesOut.push_back(vote);
        }
    }
}

CFinalityVoteContext CFinalityVoteContext::Connect(const CBlockIndex* pindexCarrier)
{
    if (!pindexCarrier)
        return CFinalityVoteContext(NULL, 0);
    return CFinalityVoteContext(pindexCarrier, pindexCarrier->nHeight);
}

CFinalityVoteContext CFinalityVoteContext::Build(const CBlockIndex* pindexPrev)
{
    if (!pindexPrev)
        return CFinalityVoteContext(NULL, 0);
    return CFinalityVoteContext(pindexPrev, pindexPrev->nHeight + 1);
}

const CBlockIndex* GetFinalityAncestorOnChain(const CBlockIndex* pindexTip, int nHeight,
                                              int nMaxWalk)
{
    if (!pindexTip || nHeight < 0 || pindexTip->nHeight < nHeight)
        return NULL;
    const CBlockIndex* p = pindexTip;
    for (int i = 0; p && p->nHeight > nHeight && i < nMaxWalk; i++)
        p = p->pprev;
    if (!p || p->nHeight != nHeight)
        return NULL;
    return p;
}

bool GatherFinalitySettlementVotes(const CBlockIndex* pindexPrev, int nEpoch,
                                   std::vector<CFinalityVote>& vVotesOut,
                                   std::string* pstrError, bool* pfLocalFailure)
{
    if (pfLocalFailure)
        *pfLocalFailure = false;
    auto reject = [&](const std::string& strReason) -> bool {
        if (pstrError)
            *pstrError = strReason;
        vVotesOut.clear();
        return false;
    };

    vVotesOut.clear();
    if (!pindexPrev)
        return reject("settlement has no parent block");

    const int nBoundary = GetEpochBoundaryHeight(nEpoch, pindexPrev->nHeight);
    const int nWindowTop = nBoundary + FINALITY_VOTE_INCLUSION_WINDOW - 1;
    if (pindexPrev->nHeight != nWindowTop)
        return reject("settlement parent is not the top of the epoch vote-inclusion window");

    // Walk the ancestor chain down to the epoch boundary. This is the canonical
    // (selected-parent) chain of the settlement block, so the window it covers is
    // exactly the set of blocks whose votes ConnectBlock validated on this chain.
    std::vector<const CBlockIndex*> vWindow;
    vWindow.reserve(FINALITY_VOTE_INCLUSION_WINDOW);
    for (const CBlockIndex* p = pindexPrev; p && p->nHeight >= nBoundary; p = p->pprev)
        vWindow.push_back(p);
    if (vWindow.empty() || vWindow.back()->nHeight != nBoundary)
        return reject("settlement vote-inclusion window is incomplete");

    std::vector<std::vector<CFinalityVote> > vWindowBlockVotes;
    vWindowBlockVotes.reserve(vWindow.size());
    for (int i = (int)vWindow.size() - 1; i >= 0; i--)   // ascending height
    {
        CBlock blockWindow;
        if (!blockWindow.ReadFromDisk(vWindow[i], true))
        {
            // This node's block file, not the chain: the only refusal here that a
            // peer holding the same ancestors does not share.
            if (pfLocalFailure)
                *pfLocalFailure = true;
            return reject("settlement window block not readable");
        }

        // Decode at the window block's own height (envelope encoding changes at
        // Boundary A). Votes live in the coinbase, which is never DAG-skipped, so the
        // raw block and its DAG-active view carry the same vote set.
        std::vector<CFinalityVote> vBlockVotes;
        if (!ExtractFinalityVotesFromBlockForHeight(blockWindow, vWindow[i]->nHeight, vBlockVotes))
            return reject("settlement window block carries an undecodable vote envelope");
        vWindowBlockVotes.push_back(vBlockVotes);
    }

    CollectFinalitySettlementVotes(vWindowBlockVotes, nEpoch, vVotesOut);
    return true;
}

int64_t GetClampedFinalitySettlementBudget(const CBlockIndex* pindexPrev,
                                           int nSettlementEpoch)
{
    const int64_t nBudget = GetFinalityEpochBudget(nSettlementEpoch);
    if (nBudget <= 0)
        return 0;

    // Headroom is read from the parent before the subsidy. The settlement takes its share first
    // and the subsidy takes the rest, so both stay within the headroom.
    const int64_t nHeadroom = GetRemainingIssuance(pindexPrev, 0);
    if (nHeadroom <= 0)
        return 0;
    return (nBudget > nHeadroom) ? nHeadroom : nBudget;
}

bool BuildFinalitySettlementOutputs(const std::vector<CFinalityVote>& vCountedVotes,
                                    int64_t nEpochBudget,
                                    std::vector<CTxOut>& vOutputsOut,
                                    int64_t& nTotalOut,
                                    std::string* pstrError)
{
    auto reject = [&](const std::string& strReason) -> bool {
        if (pstrError)
            *pstrError = strReason;
        vOutputsOut.clear();
        nTotalOut = 0;
        return false;
    };

    vOutputsOut.clear();
    nTotalOut = 0;

    // Canonical order by nullifier, so the settlement coinbase is byte-reproducible
    // by any producer from the same frozen set.
    std::vector<const CFinalityVote*> vTransparent;
    std::set<uint256> setNullifiers;
    for (const CFinalityVote& vote : vCountedVotes)
    {
        if (!setNullifiers.insert(vote.nullifier).second)
            return reject("duplicate nullifier in settlement vote set");
        if (vote.IsPrivate())
            continue;
        vTransparent.push_back(&vote);
    }
    std::sort(vTransparent.begin(), vTransparent.end(),
              [](const CFinalityVote* a, const CFinalityVote* b) { return a->nullifier < b->nullifier; });

    // Fixed budget split equally among counted voters (B/V each), independent of stake.
    // vote.nReward is the weight-derived entitlement, not the amount paid; a vote with
    // zero entitlement is not a payee, so dust stake cannot dilute the split.
    std::vector<CScript> vPayees;
    std::set<CScript> setPayees;
    for (const CFinalityVote* pvote : vTransparent)
    {
        if (pvote->nReward < 0 || !MoneyRange(pvote->nReward))
            return reject("settlement reward out of range");

        CPubKey pubkey(pvote->vchPubKey);
        if (!pubkey.IsValid())
            return reject("settlement payee pubkey invalid");
        CScript scriptPayee = GetScriptForDestination(pubkey.GetID());
        // The nullifier is consensus-bound to H(pubkey || epoch), so distinct counted
        // votes in one epoch always have distinct payees. Fail closed if that ever
        // breaks rather than pay one payee twice out of one allowance.
        if (!setPayees.insert(scriptPayee).second)
            return reject("duplicate settlement payee");

        if (pvote->nReward == 0)
            continue;   // zero-entitlement voter: counted for finality, not a payee
        vPayees.push_back(scriptPayee);
    }

    if (nEpochBudget < 0 || !MoneyRange(nEpochBudget))
        return reject("settlement epoch budget out of range");

    if (!vPayees.empty() && nEpochBudget > 0)
    {
        const int64_t nPerVoter = nEpochBudget / (int64_t)vPayees.size();
        if (nPerVoter > 0)
        {
            for (const CScript& scriptPayee : vPayees)
                vOutputsOut.push_back(CTxOut(nPerVoter, scriptPayee));
            nTotalOut = nPerVoter * (int64_t)vPayees.size();
        }
    }

    // Unspent reserve (truncation remainder, or the whole budget when V is 0) is not
    // minted: not rolled forward (unbounded accrual) and not paid to the producer
    // (would reward censoring voters). The cap headroom keeps it for later blocks.

    // PRIVATE-TIER PLUG-IN POINT.
    // The note tier settles from the note votes, not from vCountedVotes: a note vote is
    // not a CFinalityVote and its amount lives in the vote's own reward commitment R
    // rather than in any int64 field. It adds a second output shape -- reward notes,
    // whose value lives in a commitment -- so it contributes to the block's shielded-pool
    // delta instead of to nTotalOut here.
    //
    // NOT wired. What is in place: R is authenticated (share coefficient L_0 == R, the
    // reward evaluations check against L_k, the aggregate opens strictly to sum R_i).
    // What is missing before any of it may mint:
    //   - a carrier for CNoteVoteRewardProof, which the vote names by hash but cannot
    //     hold: 4.7 KB of range proofs on top of a 7 KB membership proof does not fit
    //     MAX_SCRIPT_SIZE. Without a carried proof, R is a number the voter chose, and
    //     minting it would be an unbounded issue.
    //   - a sealed payout descriptor on the vote, so a mint has an owner to pay.
    //   - the mint itself in BOTH ConnectBlock and BuildEpochState, since the note tree
    //     and the pool balance are epoch-state and the coinbase allowance is not.
    // R2 also puts epoch E's certificate no earlier than H_E + 24, which is this very
    // height, so the note leg cannot settle here at all: it belongs one settlement later,
    // at H_{E+1} + 24, minting for E only if a v4 certificate for E connected in between.

    return true;
}

bool CheckFinalitySettlementOutputs(const CBlock& block,
                                    const std::vector<CFinalityVote>& vCountedVotes,
                                    int64_t nEpochBudget,
                                    int64_t& nTotalOut,
                                    std::string* pstrError)
{
    auto reject = [&](const std::string& strReason) -> bool {
        if (pstrError)
            *pstrError = strReason;
        nTotalOut = 0;
        return false;
    };

    nTotalOut = 0;
    std::vector<CTxOut> vRequired;
    if (!BuildFinalitySettlementOutputs(vCountedVotes, nEpochBudget, vRequired, nTotalOut, pstrError))
    {
        nTotalOut = 0;
        return false;
    }
    if (vRequired.empty())
        return true;
    if (block.vtx.empty())
        return reject("settlement block has no coinbase");

    // Payees are unique (see BuildFinalitySettlementOutputs), so an exact
    // script -> amount match is unambiguous and order-independent.
    std::map<CScript, int64_t> mapRequired;
    for (const CTxOut& out : vRequired)
        mapRequired[out.scriptPubKey] = out.nValue;

    std::set<CScript> setMatched;
    for (const CTxOut& out : block.vtx[0].vout)
    {
        std::map<CScript, int64_t>::const_iterator it = mapRequired.find(out.scriptPubKey);
        if (it == mapRequired.end() || out.nValue != it->second)
            continue;
        setMatched.insert(out.scriptPubKey);
    }
    if (setMatched.size() != mapRequired.size())
        return reject("missing finality settlement output for counted voter");

    return true;
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
        CLegacyFinalityCertificateWire wire;
        ss >> wire;
        wire.ToLogical(certOut);
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

static bool BuildCanonicalTaggedFinalityScript(
    const unsigned char* pchTag,
    const std::vector<unsigned char>& vPayload,
    CScript& scriptOut)
{
    scriptOut.clear();
    if (vPayload.empty() || vPayload.size() > MAX_SCRIPT_SIZE - 4)
        return false;

    std::vector<unsigned char> vchData;
    vchData.reserve(4 + vPayload.size());
    vchData.insert(vchData.end(), pchTag, pchTag + 4);
    vchData.insert(vchData.end(), vPayload.begin(), vPayload.end());

    CScript script;
    script << OP_RETURN << vchData;
    if (script.size() > MAX_SCRIPT_SIZE)
        return false;
    scriptOut = script;
    return true;
}

bool BuildCanonicalFinalityVoteScript(const CFinalityVote& vote,
                                       CScript& scriptOut)
{
    CCanonicalFinalityVoteEnvelope envelope;
    if (!envelope.FromLogical(vote))
    {
        scriptOut.clear();
        return false;
    }
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << envelope;
    return BuildCanonicalTaggedFinalityScript(
        FINALITY_CANONICAL_VOTE_TAG,
        std::vector<unsigned char>(ss.begin(), ss.end()), scriptOut);
}

bool ExtractCanonicalFinalityVote(const CScript& scriptPubKey,
                                  CFinalityVote& voteOut)
{
    std::vector<unsigned char> vPayload;
    if (!ExtractCanonicalTaggedOpReturnPayload(scriptPubKey,
                                               FINALITY_CANONICAL_VOTE_TAG,
                                               vPayload))
        return false;
    try {
        CDataStream ss(vPayload, SER_NETWORK, PROTOCOL_VERSION);
        CCanonicalFinalityVoteEnvelope envelope;
        ss >> envelope;
        if (!ss.empty())
            return false;
        return envelope.ToLogical(voteOut);
    } catch (const std::exception&) {
        return false;
    }
}

bool BuildCanonicalFinalityTallyCertificateScript(
    const CFinalityTallyCertificate& cert, CScript& scriptOut)
{
    CCanonicalFinalityTallyCertificateEnvelope envelope;
    if (!envelope.FromLogical(cert))
    {
        scriptOut.clear();
        return false;
    }
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << envelope;
    return BuildCanonicalTaggedFinalityScript(
        FINALITY_CANONICAL_TALLY_CERT_TAG,
        std::vector<unsigned char>(ss.begin(), ss.end()), scriptOut);
}

bool ExtractCanonicalFinalityTallyCertificate(
    const CScript& scriptPubKey, CFinalityTallyCertificate& certOut)
{
    std::vector<unsigned char> vPayload;
    if (!ExtractCanonicalTaggedOpReturnPayload(
            scriptPubKey, FINALITY_CANONICAL_TALLY_CERT_TAG, vPayload))
        return false;
    try {
        CDataStream ss(vPayload, SER_NETWORK, PROTOCOL_VERSION);
        CCanonicalFinalityTallyCertificateEnvelope envelope;
        ss >> envelope;
        if (!ss.empty())
            return false;
        return envelope.ToLogical(certOut);
    } catch (const std::exception&) {
        return false;
    }
}

bool BuildFinalityVoteScriptForHeight(const CFinalityVote& vote, int nHeight,
                                      CScript& scriptOut)
{
    if (IsBoundaryAActiveAtHeight(nHeight))
        return BuildCanonicalFinalityVoteScript(vote, scriptOut);
    if (vote.IsCanonicalEnvelope())
    {
        scriptOut.clear();
        return false;
    }
    scriptOut = BuildFinalityVoteScript(vote);
    return true;
}

bool BuildFinalityTallyCertificateScriptForHeight(
    const CFinalityTallyCertificate& cert, int nHeight, CScript& scriptOut)
{
    if (IsBoundaryAActiveAtHeight(nHeight))
        return BuildCanonicalFinalityTallyCertificateScript(cert, scriptOut);
    if (cert.IsCanonicalEnvelope())
    {
        scriptOut.clear();
        return false;
    }
    scriptOut = BuildFinalityTallyCertificateScript(cert);
    return true;
}

FinalityEnvelopeDecodeResult ExtractFinalityVoteForHeight(
    const CScript& scriptPubKey, int nHeight, CFinalityVote& voteOut)
{
    // Before Boundary A only a decoded IFVT carrier is a vote; other OP_RETURN data stays
    // ignored so replay does not invalidate historical blocks.
    if (!IsBoundaryAActiveAtHeight(nHeight))
        return ExtractFinalityVote(scriptPubKey, voteOut)
            ? FINALITY_ENVELOPE_VALID : FINALITY_ENVELOPE_NO_MATCH;

    const bool fLegacy = ScriptCarriesFinalityTag(
        scriptPubKey, FINALITY_VOTE_TAG);
    const bool fCanonical = ScriptCarriesFinalityTag(
        scriptPubKey, FINALITY_CANONICAL_VOTE_TAG);
    if (fLegacy)
        return FINALITY_ENVELOPE_LEGACY_AFTER_BOUNDARY;
    if (!fCanonical)
        return FINALITY_ENVELOPE_NO_MATCH;
    return ExtractCanonicalFinalityVote(scriptPubKey, voteOut)
        ? FINALITY_ENVELOPE_VALID : FINALITY_ENVELOPE_INVALID;
}

FinalityEnvelopeDecodeResult ExtractFinalityTallyCertificateForHeight(
    const CScript& scriptPubKey, int nHeight,
    CFinalityTallyCertificate& certOut)
{
    // Preserve the exact pre-A decoder contract for historical block replay;
    // IFCC was unknown data and malformed IFTC carriers were ignored.
    if (!IsBoundaryAActiveAtHeight(nHeight))
        return ExtractFinalityTallyCertificate(scriptPubKey, certOut)
            ? FINALITY_ENVELOPE_VALID : FINALITY_ENVELOPE_NO_MATCH;

    const bool fLegacy = ScriptCarriesFinalityTag(
        scriptPubKey, FINALITY_TALLY_CERT_TAG);
    const bool fCanonical = ScriptCarriesFinalityTag(
        scriptPubKey, FINALITY_CANONICAL_TALLY_CERT_TAG);
    if (fLegacy)
        return FINALITY_ENVELOPE_LEGACY_AFTER_BOUNDARY;
    if (!fCanonical)
        return FINALITY_ENVELOPE_NO_MATCH;
    return ExtractCanonicalFinalityTallyCertificate(scriptPubKey, certOut)
        ? FINALITY_ENVELOPE_VALID : FINALITY_ENVELOPE_INVALID;
}

bool BuildNoteFinalityVoteScript(const CNoteFinalityVote& vote, CScript& scriptOut)
{
    scriptOut.clear();
    if (!vote.IsValidBasic())
        return false;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << vote;
    return BuildCanonicalTaggedFinalityScript(
        FINALITY_NOTE_VOTE_TAG,
        std::vector<unsigned char>(ss.begin(), ss.end()), scriptOut);
}

bool ExtractNoteFinalityVote(const CScript& scriptPubKey, CNoteFinalityVote& voteOut)
{
    std::vector<unsigned char> vPayload;
    if (!ExtractCanonicalTaggedOpReturnPayload(scriptPubKey, FINALITY_NOTE_VOTE_TAG,
                                               vPayload))
        return false;
    try {
        CDataStream ss(vPayload, SER_NETWORK, PROTOCOL_VERSION);
        CNoteFinalityVote vote;
        ss >> vote;
        if (!ss.empty())
            return false;
        voteOut = vote;
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

FinalityEnvelopeDecodeResult ExtractNoteFinalityVoteForHeight(
    const CScript& scriptPubKey, int nHeight, CNoteFinalityVote& voteOut)
{
    if (!IsIV5NoteVoteActiveAtHeight(nHeight))
        return FINALITY_ENVELOPE_NO_MATCH;
    if (!ScriptCarriesFinalityTag(scriptPubKey, FINALITY_NOTE_VOTE_TAG))
        return FINALITY_ENVELOPE_NO_MATCH;
    return ExtractNoteFinalityVote(scriptPubKey, voteOut)
        ? FINALITY_ENVELOPE_VALID : FINALITY_ENVELOPE_INVALID;
}

bool ExtractNoteFinalityVotesFromBlockForHeight(
    const CBlock& block, int nHeight, std::vector<CNoteFinalityVote>& vVotesOut,
    FinalityEnvelopeDecodeResult* pFailure)
{
    vVotesOut.clear();
    if (pFailure)
        *pFailure = FINALITY_ENVELOPE_NO_MATCH;
    if (block.vtx.empty())
        return true;
    for (const CTxOut& out : block.vtx[0].vout)
    {
        CNoteFinalityVote vote;
        FinalityEnvelopeDecodeResult result = ExtractNoteFinalityVoteForHeight(
            out.scriptPubKey, nHeight, vote);
        if (result == FINALITY_ENVELOPE_NO_MATCH)
            continue;
        if (result != FINALITY_ENVELOPE_VALID)
        {
            vVotesOut.clear();
            if (pFailure)
                *pFailure = result;
            return false;
        }
        vVotesOut.push_back(vote);
    }
    return true;
}

uint256 GetNoteVoteSemanticIdentity(const CNoteFinalityVote& vote)
{
    // Everything the tally reads. Proof bytes are deliberately absent: a second encoding
    // of the same statement is a re-carry, not an equivocation, so a relaying peer cannot
    // manufacture a conflict out of a vote it merely forwarded.
    CHashWriter ss(SER_GETHASH, 0);
    ss << vote.nVersion;
    ss << vote.nEpoch;
    ss << vote.hashBlock;
    ss << vote.nHeight;
    ss << vote.hashCurveRoot;
    ss << vote.hashNullifierRoot;
    ss << vote.committeeSetHash;
    ss << vote.vchTag;
    ss << vote.share.GetHash();
    // R and the proof it names decide what this tag is paid, so two carriers that
    // disagree about either are two different votes and the tag counts for neither.
    // Leaving them out would make a redirected payout look like a re-carry.
    ss << vote.vchRewardCommitment;
    ss << vote.hashRewardProof;
    PrivacyVNextDigest cTilde;
    cTilde.fill(0);
    vote.GetCTilde(cTilde);
    ss << std::vector<unsigned char>(cTilde.begin(), cTilde.end());
    return ss.GetHash();
}

void ResolveNoteVoteCounting(
    const std::vector<const CNoteFinalityVote*>& vCarried,
    std::map<uint256, const CNoteFinalityVote*>& mapCountedOut,
    std::set<uint256>& setEquivocatedOut)
{
    mapCountedOut.clear();
    setEquivocatedOut.clear();

    std::map<uint256, uint256> mapIdentityByTag;
    for (size_t i = 0; i < vCarried.size(); i++)
    {
        const CNoteFinalityVote* pvote = vCarried[i];
        if (pvote == NULL)
            continue;
        const uint256 tag = pvote->GetVoteTag();
        if (tag == 0)
            continue;
        const uint256 identity = GetNoteVoteSemanticIdentity(*pvote);

        std::map<uint256, uint256>::iterator itSeen = mapIdentityByTag.find(tag);
        if (itSeen == mapIdentityByTag.end())
        {
            mapIdentityByTag.insert(std::make_pair(tag, identity));
            mapCountedOut[tag] = pvote;
            continue;
        }
        if (itSeen->second == identity)
            continue;   // the same vote re-carried by another block
        // A second identity retires the tag for the epoch. Dropping the first one too is
        // what makes the outcome independent of the order carriers connected in.
        setEquivocatedOut.insert(tag);
        mapCountedOut.erase(tag);
    }
}

bool ExtractFinalityVotesFromBlockForHeight(
    const CBlock& block, int nHeight, std::vector<CFinalityVote>& vVotesOut,
    FinalityEnvelopeDecodeResult* pFailure)
{
    vVotesOut.clear();
    if (pFailure)
        *pFailure = FINALITY_ENVELOPE_NO_MATCH;
    if (block.vtx.empty())
        return true;
    for (const CTxOut& out : block.vtx[0].vout)
    {
        CFinalityVote vote;
        FinalityEnvelopeDecodeResult result = ExtractFinalityVoteForHeight(
            out.scriptPubKey, nHeight, vote);
        if (result == FINALITY_ENVELOPE_NO_MATCH)
            continue;
        if (result != FINALITY_ENVELOPE_VALID)
        {
            vVotesOut.clear();
            if (pFailure)
                *pFailure = result;
            return false;
        }
        vVotesOut.push_back(vote);
    }
    return true;
}

bool ExtractFinalityTallyCertificatesFromBlockForHeight(
    const CBlock& block, int nHeight,
    std::vector<CFinalityTallyCertificate>& vCertsOut,
    FinalityEnvelopeDecodeResult* pFailure)
{
    vCertsOut.clear();
    if (pFailure)
        *pFailure = FINALITY_ENVELOPE_NO_MATCH;
    if (block.vtx.empty())
        return true;
    for (const CTxOut& out : block.vtx[0].vout)
    {
        CFinalityTallyCertificate cert;
        FinalityEnvelopeDecodeResult result =
            ExtractFinalityTallyCertificateForHeight(
                out.scriptPubKey, nHeight, cert);
        if (result == FINALITY_ENVELOPE_NO_MATCH)
            continue;
        if (result != FINALITY_ENVELOPE_VALID)
        {
            vCertsOut.clear();
            if (pFailure)
                *pFailure = result;
            return false;
        }
        vCertsOut.push_back(cert);
    }
    return true;
}

const char* GetFinalityVoteCommandForHeight(int nHeight)
{
    return IsBoundaryAActiveAtHeight(nHeight)
        ? FINALITY_CANONICAL_VOTE_COMMAND : "fvote";
}

const char* GetFinalityTallyCertificateCommandForHeight(int nHeight)
{
    return IsBoundaryAActiveAtHeight(nHeight)
        ? FINALITY_CANONICAL_TALLY_CERT_COMMAND : "ftcert";
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
    // Strict majority: `2W > A`. `2W >= A` would admit two blocks at an exact even split.
    if (nWinningWeight * 2 > nActiveWeight)
        return FINALITY_SOFT;
    if (nWinningWeight * 3 >= nActiveWeight)
        return FINALITY_TENTATIVE;
    return FINALITY_NONE;
}

bool BuildCanonicalTransparentFinalityCertificate(
    const std::vector<CFinalityVote>& vVotes,
    CFinalityTallyCertificate& certOut,
    std::string* pstrError,
    size_t nOtherLegVoters)
{
    certOut = CFinalityTallyCertificate();
    const auto reject = [&](const std::string& strReason) -> bool {
        if (pstrError)
            *pstrError = strReason;
        return false;
    };
    if (pstrError)
        pstrError->clear();
    // The floor counts all of the epoch's voters, including a second (note) leg; the skeleton
    // is still a pure function of the transparent votes.
    if (vVotes.size() + nOtherLegVoters < (size_t)FINALITY_MIN_VOTERS)
        return reject("canonical transparent certificate has too few voters");
    // The winner and every transparent field come from these votes, so there has to be
    // at least one. An epoch with none takes the note-only skeleton instead.
    if (vVotes.empty())
        return reject("canonical transparent certificate has no transparent vote");
    if (vVotes.size() > FINALITY_CANONICAL_CERT_MAX_NULLIFIERS)
        return reject("canonical transparent certificate exceeds its vote-set bound");

    const int nEpoch = vVotes[0].nEpoch;
    std::set<uint256> setNullifiers;
    std::map<uint256, int64_t> mapBlockWeight;
    std::map<uint256, int> mapBlockHeight;
    int64_t nActiveWeight = 0;
    int64_t nRewardBudget = 0;
    for (std::vector<CFinalityVote>::const_iterator it = vVotes.begin();
         it != vVotes.end(); ++it)
    {
        const CFinalityVote& vote = *it;
        if (vote.IsPrivate())
            return reject("canonical transparent certificate contains a private vote");
        if (vote.nEpoch != nEpoch || vote.nEpoch < 0 || vote.nHeight < 0 ||
            vote.hashBlock == 0 || vote.nullifier == 0 ||
            vote.nVoteWeight <= 0 || vote.nVoteWeight > MAX_MONEY ||
            vote.nReward < 0 || vote.nReward > MAX_MONEY)
            return reject("canonical transparent certificate contains an invalid vote");
        if (!setNullifiers.insert(vote.nullifier).second)
            return reject("canonical transparent certificate contains a duplicate nullifier");

        std::map<uint256, int>::iterator hit = mapBlockHeight.find(vote.hashBlock);
        if (hit != mapBlockHeight.end() && hit->second != vote.nHeight)
            return reject("canonical transparent certificate has inconsistent target heights");
        mapBlockHeight[vote.hashBlock] = vote.nHeight;

        int64_t& nBlockWeight = mapBlockWeight[vote.hashBlock];
        nBlockWeight = nBlockWeight <= MAX_MONEY - vote.nVoteWeight
            ? nBlockWeight + vote.nVoteWeight : MAX_MONEY;
        nActiveWeight = nActiveWeight <= MAX_MONEY - vote.nVoteWeight
            ? nActiveWeight + vote.nVoteWeight : MAX_MONEY;
        nRewardBudget = nRewardBudget <= MAX_MONEY - vote.nReward
            ? nRewardBudget + vote.nReward : MAX_MONEY;
    }

    uint256 hashWinner;
    int64_t nWinningWeight = 0;
    for (std::map<uint256, int64_t>::const_iterator it = mapBlockWeight.begin();
         it != mapBlockWeight.end(); ++it)
    {
        if (it->second > nWinningWeight ||
            (it->second == nWinningWeight &&
             (hashWinner == 0 || it->first < hashWinner)))
        {
            hashWinner = it->first;
            nWinningWeight = it->second;
        }
    }
    const FinalityTier tier = FinalityDetermineTier(nActiveWeight,
                                                     nWinningWeight);
    if (hashWinner == 0 || tier == FINALITY_NONE)
        return reject("canonical transparent vote set has no finality decision");

    CFinalityTallyCertificate cert;
    cert.nVersion = 2;
    cert.nEpoch = nEpoch;
    cert.hashBlock = hashWinner;
    cert.nHeight = mapBlockHeight[hashWinner];
    cert.nTier = (int)tier;
    cert.nTransparentActiveWeight = nActiveWeight;
    cert.nTransparentWinningWeight = nWinningWeight;
    cert.nTransparentRewardBudget = nRewardBudget;
    cert.vVoteNullifiers.assign(setNullifiers.begin(), setNullifiers.end());
    cert.MarkCanonicalEnvelope();
    std::string strBasicError;
    if (!cert.IsValidBasic(&strBasicError, nOtherLegVoters))
        return reject("canonical transparent certificate is invalid: " +
                      strBasicError);
    certOut = cert;
    return true;
}

bool BuildNoteOnlyFinalitySkeleton(
    int nEpoch,
    const std::vector<CNoteFinalityVote>& vCountedNoteVotes,
    CFinalityTallyCertificate& certOut,
    std::string* pstrError)
{
    certOut = CFinalityTallyCertificate();
    const auto reject = [&](const std::string& strReason) -> bool {
        if (pstrError)
            *pstrError = strReason;
        return false;
    };
    if (pstrError)
        pstrError->clear();
    if (nEpoch < 0)
        return reject("note-only skeleton has no epoch");

    // The covered set can only shrink from the counted set, so a counted set already
    // below the floor can never produce a certificate that clears it.
    std::map<uint256, size_t> mapBlockVotes;
    std::map<uint256, int> mapBlockHeight;
    size_t nEpochVotes = 0;
    for (size_t i = 0; i < vCountedNoteVotes.size(); i++)
    {
        const CNoteFinalityVote& vote = vCountedNoteVotes[i];
        if (vote.nEpoch != nEpoch)
            continue;
        if (vote.hashBlock == 0 || vote.nHeight < 0)
            return reject("note-only skeleton has a vote with no target block");
        std::map<uint256, int>::const_iterator hit = mapBlockHeight.find(vote.hashBlock);
        if (hit != mapBlockHeight.end() && hit->second != vote.nHeight)
            return reject("note-only skeleton has inconsistent target heights");
        mapBlockHeight[vote.hashBlock] = vote.nHeight;
        mapBlockVotes[vote.hashBlock]++;
        nEpochVotes++;
    }
    if (nEpochVotes < (size_t)FINALITY_MIN_VOTERS)
        return reject("note-only skeleton has too few voters");

    // The winner has to be chosen from data every committee member can see, because a
    // member that picks a different candidate sums a different polynomial and its
    // partial cannot be interpolated with the rest. Note weights are hidden, so the
    // public rule is vote count with a hash tie-break. Consensus does not take this
    // rule on trust: it accepts the named winner only if the tier proof opens for it,
    // and only at SOFT or better, where the share is exclusive.
    uint256 hashWinner = 0;
    size_t nWinnerVotes = 0;
    for (std::map<uint256, size_t>::const_iterator it = mapBlockVotes.begin();
         it != mapBlockVotes.end(); ++it)
    {
        if (it->second > nWinnerVotes ||
            (it->second == nWinnerVotes && (hashWinner == 0 || it->first < hashWinner)))
        {
            hashWinner = it->first;
            nWinnerVotes = it->second;
        }
    }
    if (hashWinner == 0)
        return reject("note-only skeleton has no candidate winner");

    const int nWinnerHeight = mapBlockHeight[hashWinner];
    // Pin the epoch-boundary rule the validator applies, so a producer working from a
    // vote set that names a non-boundary block emits nothing instead of a certificate
    // that is rejected at connect.
    if (GetEpochForHeight(nWinnerHeight) != nEpoch ||
        GetEpochBoundaryHeight(nEpoch, nWinnerHeight) != nWinnerHeight)
        return reject("note-only skeleton winner is not this epoch's boundary block");

    // Exactly the fields the fNoteOnly branch of CheckTallyCertificate pins: an empty
    // transparent skeleton, zero transparent weights, no nullifiers, no streak.
    CFinalityTallyCertificate cert;
    cert.nVersion = 2;
    cert.nEpoch = nEpoch;
    cert.hashBlock = hashWinner;
    cert.nHeight = nWinnerHeight;
    cert.nTier = FINALITY_NONE;
    cert.nTransparentActiveWeight = 0;
    cert.nTransparentWinningWeight = 0;
    cert.nTransparentRewardBudget = 0;
    cert.MarkCanonicalEnvelope();
    certOut = cert;
    return true;
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
    ss << std::string("Innova/Finality/TallyCertificateAutomation/v3");
    // Legacy and Boundary-A certificates may have the same logical tally but
    // are authenticated and persisted in different envelope/hash domains.
    // Never let one suppress or replace the other during the transition.
    ss << (unsigned char)(cert.IsCanonicalEnvelope() ? 1 : 0);
    ss << cert.nVersion;
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
    // The note side names which votes the tally counted. Two v4 certificates over
    // different covered sets are different decisions, and only one of them can satisfy
    // the connect-time coverage rule, so they must not dedup each other out of the
    // pending map on arrival order.
    ss << cert.vNoteVoteTags;
    for (size_t i = 0; i < cert.vNoteComplaints.size(); i++)
        ss << cert.vNoteComplaints[i].voteTag;
    return ss.GetHash();
}

static bool FinalityVotesHaveSameSemanticIdentity(const CFinalityVote& a,
                                                  const CFinalityVote& b)
{
    // ECDSA may have more than one valid byte representation for the same
    // signed object. Compare the provenance/domain and both signature-free
    // identities, then independently require each signature to verify.
    return a.IsCanonicalEnvelope() == b.IsCanonicalEnvelope() &&
           a.nullifier == b.nullifier && a.GetHash() == b.GetHash() &&
           a.GetSignatureHash() == b.GetSignatureHash() &&
           a.IsValid() && b.IsValid();
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

static bool LegacyPrivateFinalityTrafficDisabledAtTip()
{
    const int nNextHeight = nBestHeight == std::numeric_limits<int>::max()
        ? nBestHeight : nBestHeight + 1;
    return IsLegacyPrivacyPolicyDisabled() ||
           IsBoundaryAActiveAtHeight(nNextHeight);
}

bool UseCanonicalFinalityTrafficForTip(int nTipHeight)
{
    // Relay traffic targets the next candidate block, so the envelope switches one
    // block before Boundary A; the activation block holds only canonical-envelope objects.
    const int nNextHeight = nTipHeight == std::numeric_limits<int>::max()
        ? nTipHeight : nTipHeight + 1;
    return IsBoundaryAActiveAtHeight(nNextHeight);
}

bool IsFinalityVoteWindowClosedForTip(int nEpoch, int nTipHeight)
{
    const int nCandidateHeight =
        nTipHeight == std::numeric_limits<int>::max()
            ? nTipHeight : nTipHeight + 1;
    if (nCandidateHeight < FORK_HEIGHT_VOTESET_ROOT)
        return true;
    const int64_t nFirstCertificateHeight =
        (int64_t)GetEpochBoundaryHeight(nEpoch, nCandidateHeight) +
        FINALITY_VOTE_INCLUSION_WINDOW;
    return (int64_t)nCandidateHeight >= nFirstCertificateHeight;
}

static bool CanonicalFinalityTrafficAtTip()
{
    return UseCanonicalFinalityTrafficForTip(nBestHeight);
}

bool OwnVoteNeedsRebroadcast(const CFinalityVote& vote, int nCurrentHeight, bool fConnected,
                             int64_t nNowMs, int64_t nLastRelayMs)
{
    if (fConnected)
        return false;
    if (nCurrentHeight < vote.nHeight ||
        nCurrentHeight >= vote.nHeight + FINALITY_VOTE_INCLUSION_WINDOW)
        return false;
    return nNowMs - nLastRelayMs >= FINALITY_VOTE_REBROADCAST_MS;
}

// The last identity vote this node produced, kept so it can be relayed again: a vote is
// one-shot and pending sets are memory-only, so a miner that restarted inside the
// inclusion window would otherwise never carry it and the epoch goes SOFT.
static CCriticalSection cs_ownFinalityVote;
static CFinalityVote voteOwnLast;
static bool fHaveOwnVote = false;
static int64_t nOwnVoteLastRelayMs = 0;

static bool PushFinalityVoteMessage(CNode* pnode, const CFinalityVote& vote)
{
    if (CanonicalFinalityTrafficAtTip())
    {
        CCanonicalFinalityVoteEnvelope envelope;
        if (!envelope.FromLogical(vote))
            return false;
        pnode->PushMessage(FINALITY_CANONICAL_VOTE_COMMAND, envelope);
        return true;
    }
    if (vote.IsCanonicalEnvelope())
        return false;
    pnode->PushMessage("fvote", vote);
    return true;
}

// Note-vote relay guards. A note vote is the most expensive object on this wire (a
// membership proof plus two range-proof verifications) and the cheapest to fabricate a
// near-duplicate of, so relay pays for verification at most once per envelope and each
// peer gets a budget sized to what a whole epoch could legitimately carry.
static CCriticalSection cs_noteVoteRelay;
static std::map<uint256, bool> mapNoteVoteVerifyCache;
static std::map<NodeId, std::pair<int64_t, int> > mapNoteVotePeerBudget;

static const size_t NOTE_VOTE_VERIFY_CACHE_MAX = 4096;
static const int NOTE_VOTE_PEER_BUDGET_SECONDS = 60;
static const int NOTE_VOTE_PEER_BUDGET =
    (int)FINALITY_CANONICAL_CERT_MAX_NULLIFIERS * 2;

static bool NoteVotePeerBudgetAllows(NodeId id, int64_t nNow)
{
    LOCK(cs_noteVoteRelay);
    std::pair<int64_t, int>& budget = mapNoteVotePeerBudget[id];
    if (nNow - budget.first >= NOTE_VOTE_PEER_BUDGET_SECONDS)
    {
        budget.first = nNow;
        budget.second = 0;
    }
    if (budget.second >= NOTE_VOTE_PEER_BUDGET)
        return false;
    budget.second++;
    return true;
}

static bool NoteVoteVerifyCacheLookup(const uint256& hashVote, bool& fValidOut)
{
    LOCK(cs_noteVoteRelay);
    std::map<uint256, bool>::const_iterator it = mapNoteVoteVerifyCache.find(hashVote);
    if (it == mapNoteVoteVerifyCache.end())
        return false;
    fValidOut = it->second;
    return true;
}

static void NoteVoteVerifyCacheStore(const uint256& hashVote, bool fValid)
{
    LOCK(cs_noteVoteRelay);
    if (mapNoteVoteVerifyCache.size() >= NOTE_VOTE_VERIFY_CACHE_MAX)
        mapNoteVoteVerifyCache.clear();
    mapNoteVoteVerifyCache[hashVote] = fValid;
}

static bool PushFinalityTallyCertificateMessage(
    CNode* pnode, const CFinalityTallyCertificate& cert)
{
    if (CanonicalFinalityTrafficAtTip())
    {
        CCanonicalFinalityTallyCertificateEnvelope envelope;
        if (!envelope.FromLogical(cert))
            return false;
        pnode->PushMessage(FINALITY_CANONICAL_TALLY_CERT_COMMAND, envelope);
        return true;
    }
    if (cert.IsCanonicalEnvelope())
        return false;
    pnode->PushMessage("ftcert", cert);
    return true;
}

static void RelayFinalityTallyAggregatePartial(const CFinalityTallyAggregatePartial& partial)
{
    if (LegacyPrivateFinalityTrafficDisabledAtTip())
        return;
    LOCK(cs_vNodes);
    for (CNode* pnode : vNodes)
        pnode->PushMessage("ftpart", partial);
}

// The note tally rides its own fork gate, not the retired legacy-private one. Folding it
// into LegacyPrivateFinalityTrafficDisabledAtTip() would silence the whole note path from
// Boundary A onward, which is exactly the confusion HasNoteWeight() exists to prevent.
static bool NoteFinalityTrafficActiveAtTip()
{
    const int nNextHeight = nBestHeight == std::numeric_limits<int>::max()
        ? nBestHeight : nBestHeight + 1;
    return IsIV5NoteVoteActiveAtHeight(nNextHeight);
}

static void RelayNoteTallyAggregatePartial(const CNoteTallyAggregatePartial& partial)
{
    if (!NoteFinalityTrafficActiveAtTip())
        return;
    LOCK(cs_vNodes);
    for (CNode* pnode : vNodes)
        pnode->PushMessage(FINALITY_NOTE_TALLY_PARTIAL_COMMAND, partial);
}

void RelayFinalityTallyCertificate(const CFinalityTallyCertificate& cert)
{
    if (cert.HasPrivateWeight() &&
        LegacyPrivateFinalityTrafficDisabledAtTip())
        return;
    LOCK(cs_vNodes);
    for (CNode* pnode : vNodes)
        PushFinalityTallyCertificateMessage(pnode, cert);
}

// One line per note certificate that reaches its threshold, from either assembly site:
// the producer's own signature can complete a 1-of-1 committee, but for M-of-N the set
// completes in the signature handler when the last member's signature arrives.
static void LogAssembledNoteCertificate(const CFinalityTallyCertificate& cert)
{
    if (!cert.HasNoteWeight())
        return;
    printf("FinalityNoteTally: epoch %d note certificate %s assembled tier=%d "
           "note_votes=%u transparent_votes=%u signers=%u\n",
           cert.nEpoch, cert.GetHash().ToString().c_str(), cert.nTier,
           (unsigned int)cert.vNoteVoteTags.size(),
           (unsigned int)cert.vVoteNullifiers.size(),
           (unsigned int)cert.vSignerIndexes.size());
}

static void RelayFinalityCertSignature(const CFinalityCertSignature& msg)
{
    if (msg.candidate.HasNoteWeight()
            ? !NoteFinalityTrafficActiveAtTip()
            : LegacyPrivateFinalityTrafficDisabledAtTip())
        return;
    LOCK(cs_vNodes);
    for (CNode* pnode : vNodes)
        pnode->PushMessage("ftcsig", msg);
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
    // Production-side, so a batch-free handle is both available and correct.
    CTxDB txdbCommittee("r");
    bool fSignAsCommittee = (cert.nHeight >= FORK_HEIGHT_TALLY_GOVERNANCE) &&
                            cfg.nLocalCommitteeIndex >= 0 &&
                            GetFinalityTallyPrivateKey(memberKey) &&
                            GetCanonicalFinalityCommittee(txdbCommittee, cert.nEpoch, vCommittee,
                                                          nCommitteeM, committeeSetHashCanon);
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
        return nWinningWeight * 2 > nActiveWeight;   // strict majority; see FinalityDetermineTier
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

    int nEpochInterval = GetFinalityRewardUnits(cert.nHeight);
    const int64_t nVoteRate = GetFinalityVoteRate(cert.nHeight);
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
                               FieldNeg(FieldFromUint64((uint64_t)nVoteRate)));
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

    int nEpochInterval = GetFinalityRewardUnits(cert.nHeight);
    const int64_t nVoteRate = GetFinalityVoteRate(cert.nHeight);
    uint64_t nProduct = 0;
    if (!FinalityMulUint64((uint64_t)nPrivateActiveWeight, (uint64_t)nEpochInterval, nProduct))
        return false;
    uint64_t nQ1 = nProduct / (uint64_t)COIN;
    uint64_t nR1 = nProduct % (uint64_t)COIN;
    uint64_t nCoinAge = nQ1 / 86400;
    uint64_t nR2 = nQ1 % 86400;
    uint64_t nRewardProduct = 0;
    if (!FinalityMulUint64(nCoinAge, (uint64_t)nVoteRate, nRewardProduct))
        return false;
    uint64_t nReward = nRewardProduct / 365;
    uint64_t nR3 = nRewardProduct % 365;
    if (nReward > (uint64_t)MAX_MONEY ||
        nPrivateRewardBudget != (int64_t)nReward ||
        nPrivateRewardBudget != GetFinalityVoteReward(nPrivateActiveWeight, nEpochInterval, nVoteRate))
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

// Note-tally fields, appended to both the identity and the signed content. The
// complaint set changes the covered set, so both must commit to it (by complaint hash).
static void FinalityAppendNoteCertFields(CHashWriter& ss,
                                         const std::vector<uint256>& vNoteVoteTags,
                                         const std::vector<CNoteVoteComplaint>& vNoteComplaints,
                                         const CNoteTallyTierProofs& noteTierProofs)
{
    ss << vNoteVoteTags;
    std::vector<uint256> vComplaintHashes;
    vComplaintHashes.reserve(vNoteComplaints.size());
    for (size_t i = 0; i < vNoteComplaints.size(); i++)
        vComplaintHashes.push_back(vNoteComplaints[i].GetHash());
    ss << vComplaintHashes;
    ss << noteTierProofs.vchTierSlack;
    ss << noteTierProofs.vchWinningCap;
    ss << noteTierProofs.vchActiveCap;
}

uint256 CFinalityTallyCertificate::GetSignatureDigest() const
{
    if (fCanonicalEnvelope)
    {
        CHashWriter canonical(SER_GETHASH, 0);
        canonical << std::string("Innova/Finality/CanonicalTransparentCertificate/v1");
        canonical << (uint32_t)FINALITY_CANONICAL_TALLY_CERT_VERSION;
        canonical << nVersion;
        canonical << nEpoch;
        canonical << hashBlock;
        canonical << nHeight;
        canonical << nTier;
        canonical << nConsecutiveHardCount;
        canonical << hashCurveRoot;
        canonical << hashNullifierRoot;
        canonical << committeeSetHash;
        canonical << nTransparentActiveWeight;
        canonical << nTransparentWinningWeight;
        canonical << nTransparentRewardBudget;
        canonical << vVoteNullifiers;
        if (nVersion >= FINALITY_NOTE_CERT_VERSION)
            FinalityAppendNoteCertFields(canonical, vNoteVoteTags, vNoteComplaints,
                                         noteTierProofs);
        return canonical.GetHash();
    }

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
    if (nVersion >= FINALITY_NOTE_CERT_VERSION)
        FinalityAppendNoteCertFields(ss, vNoteVoteTags, vNoteComplaints, noteTierProofs);
    return ss.GetHash();
}

uint256 CFinalityTallyCertificate::GetHash() const
{
    if (fCanonicalEnvelope)
    {
        CHashWriter canonical(SER_GETHASH, 0);
        canonical << std::string("Innova/Finality/CanonicalTransparentCertificateIdentity/v1");
        canonical << (uint32_t)FINALITY_CANONICAL_TALLY_CERT_VERSION;
        canonical << nVersion;
        canonical << nEpoch;
        canonical << hashBlock;
        canonical << nHeight;
        canonical << nTier;
        canonical << nConsecutiveHardCount;
        canonical << hashCurveRoot;
        canonical << hashNullifierRoot;
        canonical << committeeSetHash;
        canonical << nTransparentActiveWeight;
        canonical << nTransparentWinningWeight;
        canonical << nTransparentRewardBudget;
        canonical << vVoteNullifiers;
        if (nVersion >= FINALITY_NOTE_CERT_VERSION)
        {
            FinalityAppendNoteCertFields(canonical, vNoteVoteTags, vNoteComplaints,
                                         noteTierProofs);
            canonical << vSignerIndexes;
            canonical << vSignerSigs;
        }
        return canonical.GetHash();
    }

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
    if (nVersion >= FINALITY_NOTE_CERT_VERSION)
        FinalityAppendNoteCertFields(ss, vNoteVoteTags, vNoteComplaints, noteTierProofs);
    return ss.GetHash();
}

bool CFinalityTallyCertificate::HasPrivateWeight() const
{
    return !activeWeightCommitment.IsNull() ||
           !winningWeightCommitment.IsNull() ||
           !rewardBudgetCommitment.IsNull() ||
           !vTallyShareHashes.empty();
}

bool CFinalityTallyCertificate::HasNoteWeight() const
{
    return !vNoteVoteTags.empty() || !noteTierProofs.IsNull();
}

bool CFinalityTallyCertificate::IsValidBasic(std::string* pstrError,
                                             size_t nOtherLegVoters) const
{
    if (nVersion < 1 || nVersion > FINALITY_NOTE_CERT_VERSION)
        return FinalityReject(pstrError, "unsupported tally certificate version");
    // F2 gate on cert.nHeight, pinned to cert.nEpoch, so the rule depends only on the
    // certificate bytes. Rejects v4 where the note-vote fork is unconfigured.
    if (nVersion >= FINALITY_NOTE_CERT_VERSION && !IsIV5NoteVoteActiveAtHeight(nHeight))
        return FinalityReject(pstrError,
                              "note tally certificate version before note-vote activation");
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
    // The nullifier set is the TRANSPARENT leg only. A v4 certificate may stand
    // entirely on note votes: vNoteVoteTags carries the note leg and supplies the
    // same three guarantees this set provides -- per-epoch uniqueness (the tag is a
    // sigma-proved linking tag over the epoch and the note's spend scalar, deduped
    // below), coverage equality against the connected counted set
    // (ResolveNoteTallyCoverage), and resolution of every covered tag to a connected
    // vote whose proofs were checked at connect. Requiring a nullifier here made an
    // epoch in which every staker voted privately permanently uncertifiable.
    const bool fNoteLeg = (nVersion >= FINALITY_NOTE_CERT_VERSION) &&
                          !vNoteVoteTags.empty();
    if (vVoteNullifiers.size() > FINALITY_MAX_VOTES)
        return FinalityReject(pstrError, "invalid tally certificate vote set size");
    if (vVoteNullifiers.empty() && !fNoteLeg)
        return FinalityReject(pstrError, "invalid tally certificate vote set size");
    std::set<uint256> setNullifiers;
    for (const uint256& nf : vVoteNullifiers)
    {
        if (nf == 0 || !setNullifiers.insert(nf).second)
            return FinalityReject(pstrError, "duplicate or zero tally certificate nullifier");
    }
    // The voter floor counts voters, not transparent voters. Note tags are deduped in
    // the v4 block below and are disjoint from nullifiers by construction (different
    // domains), so the sum is the unique-voter count. Checking only the transparent
    // leg here would let a note-only certificate finalize on one voter.
    if (fCanonicalEnvelope &&
        vVoteNullifiers.size() + (fNoteLeg ? vNoteVoteTags.size() : 0) + nOtherLegVoters <
            (size_t)FINALITY_MIN_VOTERS)
        return FinalityReject(pstrError,
                              "canonical tally certificate has too few voters");

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

    // v4 (F2) carries the note-vote tally. Structural bounds only; coverage and the
    // range proofs need the connected vote set and are checked in CheckTallyCertificate.
    if (nVersion >= FINALITY_NOTE_CERT_VERSION)
    {
        if (vNoteVoteTags.size() > FINALITY_MAX_VOTES ||
            vNoteComplaints.size() > FINALITY_MAX_VOTES)
            return FinalityReject(pstrError, "tally certificate note set size out of range");

        std::set<uint256> setTags;
        for (size_t i = 0; i < vNoteVoteTags.size(); i++)
        {
            if (vNoteVoteTags[i] == 0 || !setTags.insert(vNoteVoteTags[i]).second)
                return FinalityReject(pstrError,
                                      "duplicate or zero tally certificate note vote tag");
        }

        // One complaint per tag: two complaints naming one vote would let a producer
        // pad the set without changing what it actually excludes.
        std::set<uint256> setComplaintTags;
        for (size_t i = 0; i < vNoteComplaints.size(); i++)
        {
            if (!vNoteComplaints[i].IsValidBasic(pstrError))
                return false;
            if (!setComplaintTags.insert(vNoteComplaints[i].voteTag).second)
                return FinalityReject(pstrError,
                                      "tally certificate complains of one vote twice");
            if (setTags.count(vNoteComplaints[i].voteTag))
                return FinalityReject(pstrError,
                                      "tally certificate both covers and complains of a vote");
        }

        // The note side is either wholly absent or wholly present. A cert that names
        // tags but proves no tier, or complains without proving one, would otherwise
        // reach the tally with a claim nothing backs.
        const bool fNoteSideEmpty = vNoteVoteTags.empty() && vNoteComplaints.empty() &&
                                    noteTierProofs.IsNull();
        if (!fNoteSideEmpty)
        {
            if (vNoteVoteTags.empty() && vNoteComplaints.empty())
                return FinalityReject(pstrError,
                                      "tally certificate proves a note tier over no votes");
            const std::vector<unsigned char>* vProofs[3] = {
                &noteTierProofs.vchTierSlack, &noteTierProofs.vchWinningCap,
                &noteTierProofs.vchActiveCap
            };
            for (int i = 0; i < 3; i++)
            {
                if (vProofs[i]->empty() ||
                    vProofs[i]->size() > FINALITY_NOTE_MAX_RANGE_PROOF_BYTES)
                    return FinalityReject(pstrError,
                                          "tally certificate note tier proof has an unusable length");
            }
        }
        // The two rules above give HasNoteWeight() its meaning: a certificate that
        // passes here has either no note fields at all, or all three tier proofs
        // present -- so the predicate the gates key on is true exactly when there is
        // a note tally to gate, including for a certificate that only complains.

        // The retired secp aggregate and the note tally are different tallies; one
        // certificate must not claim both.
        if (HasNoteWeight() && HasPrivateWeight())
            return FinalityReject(pstrError,
                                  "tally certificate carries both legacy private and note weight");
    }
    else if (!vNoteVoteTags.empty() || !vNoteComplaints.empty() || !noteTierProofs.IsNull())
    {
        return FinalityReject(pstrError, "pre-v4 tally certificate must not carry note fields");
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
    else if (HasNoteWeight())
    {
        // A note tally's weight is in the covered votes' commitments, not in these
        // fields, so the transparent threshold below is not its threshold. The tier
        // claim is proved by noteTierProofs against recomputed aggregates in
        // CheckTallyCertificate; there is nothing structural to check here.
        if (committeeSetHash == 0)
            return FinalityReject(pstrError, "note tally certificate missing committee set hash");
    }
    else if (nTier != FINALITY_NONE)
    {
        if (nTransparentActiveWeight <= 0)
            return FinalityReject(pstrError, "transparent tally certificate has no active weight");
        if (nTier == FINALITY_HARD &&
            nTransparentWinningWeight * 3 < nTransparentActiveWeight * 2)
            return FinalityReject(pstrError, "transparent hard tally below 2/3 threshold");
        if (nTier == FINALITY_SOFT &&
            nTransparentWinningWeight * 2 <= nTransparentActiveWeight)
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
    if (fCanonicalEnvelope)
    {
        CHashWriter canonical(SER_GETHASH, 0);
        canonical << std::string("Innova/Finality/CanonicalTransparentVoteIdentity/v1");
        canonical << (uint32_t)FINALITY_CANONICAL_VOTE_VERSION;
        canonical << nEpoch;
        canonical << hashBlock;
        canonical << nHeight;
        canonical << nTime;
        canonical << nVoteWeight;
        canonical << nReward;
        canonical << nullifier;
        canonical << vStakeProof;
        canonical << vchPubKey;
        return canonical.GetHash();
    }

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
    if (fCanonicalEnvelope)
    {
        CHashWriter canonical(SER_GETHASH, 0);
        canonical << std::string("Innova/Finality/CanonicalTransparentVote/v1");
        canonical << (uint32_t)FINALITY_CANONICAL_VOTE_VERSION;
        canonical << nEpoch;
        canonical << hashBlock;
        canonical << nHeight;
        canonical << nTime;
        canonical << nVoteWeight;
        canonical << nReward;
        canonical << nullifier;
        canonical << vStakeProof;
        return canonical.GetHash();
    }

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

bool CFinalityTracker::CheckVote(const CFinalityVote& vote, CTxDB& txdb,
                                 std::string* pstrError, const CFinalityVoteContext& ctx,
                                 FinalityResult* pResult) const
{
    const int nContextHeight = ctx.Height();
    auto reject = [&](const std::string& strReason) -> bool {
        if (pstrError)
            *pstrError = strReason;
        return ReturnFinalityResult(pResult, FINALITY_RESULT_INVALID, false);
    };
    auto localState = [&](const std::string& strReason) -> bool {
        if (pstrError)
            *pstrError = strReason;
        return ReturnFinalityResult(pResult, FINALITY_RESULT_LOCAL_STATE, false);
    };

    if (pResult)
        *pResult = FINALITY_RESULT_INVALID;

    if (!vote.IsValid())
        return reject("invalid vote structure or signature");
    if (vote.nVoteWeight > MAX_MONEY)
        return reject("vote weight out of range");

    if (GetEpochForHeight(vote.nHeight) != vote.nEpoch ||
        GetEpochBoundaryHeight(vote.nEpoch, vote.nHeight) != vote.nHeight)
        return reject("vote height is not this epoch boundary");

    const int nEffectiveContextHeight = nContextHeight >= 0
        ? nContextHeight
        : (nBestHeight == std::numeric_limits<int>::max()
               ? nBestHeight : nBestHeight + 1);
    // The membership layer the legacy private-finality proof was checked
    // against is gone, so no private vote encoding can be established on any
    // network at any height. It still decodes, so historical objects parse.
    if (vote.IsPrivate())
        return reject("legacy private-finality proofs have no verifiable membership and are permanently invalid");

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

    // Relay only: a missing named block is local state. In a chain context the named
    // block must be an ancestor of the carrier, so absence is invalid, not retryable.
    std::map<uint256, CBlockIndex*>::iterator miEpoch = mapBlockIndex.find(vote.hashBlock);
    if (miEpoch == mapBlockIndex.end())
        return ctx.IsRelay() ? localState("epoch block is not known")
                             : reject("epoch block is not known");
    // A null index entry is this node's own corruption in either context, and no peer
    // can induce it, so it stays transient rather than condemning a block.
    if (miEpoch->second == NULL)
        return localState("epoch block index entry is corrupt");
    CBlockIndex* pEpochBlock = miEpoch->second;
    if (pEpochBlock->nHeight != vote.nHeight)
        return reject("epoch block height mismatch");
    if (pEpochBlock->nHeight < FORK_HEIGHT_DAG)
        return reject("finality votes require DAG epoch mode");
    if (!pEpochBlock->IsProofOfWork())
        return reject("finality votes must target proof-of-work epoch blocks");
    // The lookup above is global: it says some block with this hash is indexed, not that
    // it is the epoch boundary of the chain being extended, so a vote naming a
    // sibling-branch boundary block passed it. Bind it to the carrier's own ancestors.
    if (const CBlockIndex* pAnchor = ctx.AnchorTip())
    {
        if (GetFinalityAncestorOnChain(pAnchor, vote.nHeight,
                                       FINALITY_ANCESTOR_MAX_WALK) != pEpochBlock)
            return reject("epoch block is not an ancestor of the including block");
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

    // A transparent vote states its weight in the clear, so the floor is a direct
    // comparison. Gated on the note-vote fork because it retires votes that were valid
    // before it, and both sides of the tally have to move at the same height.
    if (IsIV5NoteVoteActiveAtHeight(nEffectiveContextHeight) &&
        vote.nVoteWeight < FINALITY_MIN_VOTE_WEIGHT)
        return reject("vote weight is below the minimum vote weight");

    int64_t nExpectedReward = GetFinalityVoteRewardAtHeight(vote.nVoteWeight, vote.nHeight);
    if (vote.nReward != nExpectedReward)
        return reject("vote reward mismatch");

    std::set<COutPoint> setSeenOutpoints;
    int64_t nVerifiedWeight = 0;

    for (const COutPoint& outpoint : vote.vStakeProof)
    {
        if (!setSeenOutpoints.insert(outpoint).second)
            return reject("duplicate stake proof outpoint");

        CTxIndex txindex;
        const TxDBReadStatus txIndexStatus =
            txdb.ReadTxIndexStatus(outpoint.hash, txindex);
        if (txIndexStatus == TXDB_READ_NOT_FOUND)
            return reject("stake proof transaction is not known");
        if (txIndexStatus != TXDB_READ_FOUND)
            return localState("stake proof transaction index is corrupt or unreadable");
        CTransaction txPrev;
        if (!txPrev.ReadFromDisk(txindex.pos) || txPrev.GetHash() != outpoint.hash)
            return localState("indexed stake proof transaction body is corrupt or unreadable");
        if (outpoint.n >= txPrev.vout.size() || outpoint.n >= txindex.vSpent.size())
            return reject("stake proof outpoint out of range");
        if (!txindex.vSpent[outpoint.n].IsNull())
            return reject("stake proof outpoint is spent");

        const CTxOut& txout = txPrev.vout[outpoint.n];
        if (txout.nValue <= 0 || !MoneyRange(txout.nValue))
            return reject("stake proof value out of range");

        CKeyID outKeyID;
        if (!ExtractFinalityStakeKeyID(txout.scriptPubKey, outKeyID))
            return reject("stake proof is not transparent P2PKH/P2PK/P2CS");
        if (outKeyID != keyID)
            return reject("stake proof key mismatch");

        CBlock blockFrom;
        if (!blockFrom.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
            return localState("stake proof block is unavailable in local block storage");
        std::map<uint256, CBlockIndex*>::iterator miFrom = mapBlockIndex.find(blockFrom.GetHash());
        if (miFrom == mapBlockIndex.end() || miFrom->second == NULL)
            return localState("stake proof block is unavailable in the local block index");
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

    return ReturnFinalityResult(pResult, FINALITY_RESULT_OK, true);
}

bool CFinalityTracker::CheckTallyCertificate(
    const CFinalityTallyCertificate& cert, CTxDB& txdb,
    std::string* pstrError, const std::vector<CFinalityVote>* pvBlockVotes,
    bool fAllowPendingVotes, int nContextHeight, bool fSkipCommitteeSigs,
    FinalityResult* pResult, const CBlockIndex* pindexAnchor) const
{
    auto reject = [&](const std::string& strReason) -> bool {
        if (pstrError)
            *pstrError = strReason;
        return ReturnFinalityResult(pResult, FINALITY_RESULT_INVALID, false);
    };
    auto localState = [&](const std::string& strReason) -> bool {
        if (pstrError)
            *pstrError = strReason;
        return ReturnFinalityResult(pResult, FINALITY_RESULT_LOCAL_STATE, false);
    };

    if (pResult)
        *pResult = FINALITY_RESULT_INVALID;

    if (!cert.IsValidBasic(pstrError))
        return false;
    const int nEffectiveContextHeight = nContextHeight >= 0
        ? nContextHeight
        : (nBestHeight == std::numeric_limits<int>::max()
               ? nBestHeight : nBestHeight + 1);
    if (cert.HasPrivateWeight() &&
        (IsLegacyPrivacyPolicyDisabled() ||
         IsBoundaryAActiveAtHeight(nEffectiveContextHeight)))
        return reject("legacy private tally certificates are disabled pending privacy vNext");
    // The note tally is the live private path, so it is gated on its own fork rather
    // than the retired-secp disable above. IsValidBasic already gated on the cert's
    // own boundary height; this pins the containing context too.
    if ((cert.nVersion >= FINALITY_NOTE_CERT_VERSION || cert.HasNoteWeight()) &&
        !IsIV5NoteVoteActiveAtHeight(nEffectiveContextHeight))
        return reject("note tally certificates are not active at this height");
    if (GetEpochForHeight(cert.nHeight) != cert.nEpoch ||
        GetEpochBoundaryHeight(cert.nEpoch, cert.nHeight) != cert.nHeight)
        return reject("tally certificate height is not this epoch boundary");

    // D2: from the governance fork, a private tally certificate must carry the
    // canonical committee's M-of-N signatures over its content. Gated on the
    // cert's (consensus-validated) epoch-boundary height so the rule is
    // deterministic. The resolver is consensus-uniform; while no committee is
    // pinned for the epoch it is inert (certs validate as pre-fork).
    // A note certificate's authorization IS its signer-set: the covered set and the
    // tier proofs are only trustworthy because >= M of the canonical committee signed
    // the digest that now covers them. So it takes the same path, unconditionally --
    // note votes exist only after their own fork, well past governance.
    if (!fSkipCommitteeSigs &&
        ((cert.HasPrivateWeight() && cert.nHeight >= FORK_HEIGHT_TALLY_GOVERNANCE) ||
         cert.HasNoteWeight()))
    {
        std::vector<CPubKey> vCommittee;
        int nM = 0;
        uint256 setHash;
        bool fCommitteeLocalFailure = false;
        if (!GetCanonicalFinalityCommittee(txdb, cert.nEpoch, vCommittee, nM, setHash,
                                           &fCommitteeLocalFailure))
        {
            // No committee is seated for this epoch's term, so the epoch certifies
            // transparent-only and a certificate claiming committee authorization has
            // none to claim. A record this node cannot read is a different thing and
            // must not become a verdict on the peer's certificate.
            if (fCommitteeLocalFailure)
                return localState("finality committee record cannot be read; -reindex/resync required");
            if (nContextHeight >= 0)
                return reject("no finality committee is seated for this certificate's term");
        }
        else
        {
            std::string strSig;
            if (!CheckTallyCertificateCommitteeSignatures(cert, vCommittee, nM, setHash, &strSig))
                return reject(strSig);
        }
    }

    // R2 (fork-gated): a cert for epoch E is block-valid only at height >= H_E + K
    // (vote window closed) and only for the current or preceding epoch.
    // nContextHeight < 0 (relay/RPC) skips this.
    if (nContextHeight >= 0 && nContextHeight >= FORK_HEIGHT_VOTESET_ROOT)
    {
        int nCertBoundary = GetEpochBoundaryHeight(cert.nEpoch, nContextHeight);
        if (nContextHeight < nCertBoundary + FINALITY_VOTE_INCLUSION_WINDOW)
            return reject("tally certificate before epoch vote-inclusion window close");
        int nContextEpoch = GetEpochForHeight(nContextHeight);
        if (cert.nEpoch > nContextEpoch)
            return reject("tally certificate finalizes a future epoch");
        // Staleness bound matches the HARD-confirmation streak depth and stays inside
        // the prune horizon (current-10), so R3's mapEpochVotes is still present.
        if (cert.nEpoch + FINALITY_CONFIRMATION_EPOCHS < nContextEpoch)
            return reject("tally certificate finalizes a stale epoch");
    }

    std::map<uint256, CBlockIndex*>::iterator miEpoch = mapBlockIndex.find(cert.hashBlock);
    if (miEpoch == mapBlockIndex.end())
        return reject("tally certificate block is not known");
    if (miEpoch->second == NULL)
        return localState("tally certificate block index entry is corrupt");
    CBlockIndex* pEpochBlock = miEpoch->second;
    if (pEpochBlock->nHeight != cert.nHeight)
        return reject("tally certificate block height mismatch");
    if (pEpochBlock->nHeight < FORK_HEIGHT_DAG)
        return reject("tally certificates require DAG epoch mode");
    if (!pEpochBlock->IsProofOfWork())
        return reject("tally certificates must target proof-of-work epoch blocks");
    // The lookup above is global; bind the named block to the carrier's ancestors, as
    // CheckVote does. A valid certificate is within (FINALITY_CONFIRMATION_EPOCHS + 1)
    // epochs of its boundary, inside the walk bound.
    if (pindexAnchor &&
        GetFinalityAncestorOnChain(pindexAnchor, cert.nHeight,
                                   FINALITY_ANCESTOR_MAX_WALK) != pEpochBlock)
        return reject("tally certificate block is not an ancestor of the including block");
    if (cert.HasPrivateWeight())
    {
        // Deterministic anchor from the including block's chain context (see CheckVote).
        CEpochState finalizedEpochState;
        const FinalityResult anchorResult = ResolveFinalityAnchorForContext(
            txdb, nContextHeight, GetFinalizedHeight(), finalizedEpochState);
        if (anchorResult == FINALITY_RESULT_INVALID)
            return reject("private tally certificate requires an already-finalized epoch");
        if (anchorResult == FINALITY_RESULT_LOCAL_STATE)
            return localState("private tally certificate requires unavailable finalized epoch state");
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
    std::vector<CFinalityVote> vMatchedVotes;
    vMatchedVotes.reserve(cert.vVoteNullifiers.size());
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
        vMatchedVotes.push_back(vote);
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

    // R3 (fork-gated): the certificate must reference exactly the epoch-E votes
    // connected on this chain (mapEpochVotes). Nullifiers are deduped and resolved
    // above, so equal size plus containment is set equality.
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

    // An all-private epoch matches no transparent vote. The note leg is counted
    // instead, and its own coverage equality is enforced against the connected
    // counted set below; complaints alone are not a tally, so tags must be present.
    if (nMatchedVotes == 0 && cert.vNoteVoteTags.empty())
        return reject("tally certificate matched no votes");
    if (cert.HasPrivateWeight() && nMatchedPrivateVotes == 0)
        return reject("private tally certificate has no private votes");
    if (cert.nTransparentActiveWeight != nTransparentActiveWeight ||
        cert.nTransparentWinningWeight != nTransparentWinningWeight ||
        cert.nTransparentRewardBudget != nTransparentRewardBudget)
        return reject("tally certificate transparent aggregate mismatch");

    // Boundary-A certificates must equal the one canonical transparent result rebuilt from the
    // frozen connected vote set; no alternative tier, root or order is a valid representation.
    if (cert.IsCanonicalEnvelope())
    {
        const bool fNoteCert = cert.HasNoteWeight();
        if (!CanonicalCertificateHasExactEmptyOmittedFields(cert, fNoteCert))
            return reject("canonical tally certificate has non-empty omitted fields");
        // An all-private epoch has no transparent skeleton to rebuild: there are no
        // transparent votes to derive a winner, weights or roots from. Pin the fields
        // the rebuild would otherwise have pinned to their empty values, and leave the
        // winner to the note tier proof below -- that proof only verifies for a block
        // holding at least the tier's share of the covered note weight, and at most one
        // block per epoch can hold a 2/3 share, so the winner stays unique.
        const bool fNoteOnly = fNoteCert && vMatchedVotes.empty();
        if (fNoteOnly)
        {
            if (cert.hashCurveRoot != 0 || cert.hashNullifierRoot != 0 ||
                cert.nConsecutiveHardCount != 0 || !cert.vVoteNullifiers.empty())
                return reject("canonical note-only tally certificate has non-empty transparent skeleton");
            // Note-only certificates need a strict majority for a unique winner:
            // TENTATIVE (1/3) could be held by up to three blocks at once.
            if (cert.nTier < FINALITY_SOFT)
                return reject("canonical note-only tally certificate below the unique-winner tier");
        }
        CFinalityTallyCertificate expected;
        std::string strCanonicalError;
        // The note tags count toward the rebuild's voter floor. They are deduped and
        // bounded in IsValidBasic above, and CheckNoteTallyCertificate below resolves
        // every one of them to a connected counted note vote and requires coverage
        // equality with that set, so a tag cannot be invented to buy a floor. Without
        // this an epoch with one transparent voter and the rest voting privately had
        // no rebuildable skeleton and no certificate at all.
        if (!fNoteOnly &&
            !BuildCanonicalTransparentFinalityCertificate(
                vMatchedVotes, expected, &strCanonicalError,
                fNoteCert ? cert.vNoteVoteTags.size() : 0))
            return reject("canonical tally certificate cannot be rebuilt: " +
                          strCanonicalError);
        if (!fNoteCert)
        {
            if (cert.GetHash() != expected.GetHash() ||
                cert.GetSignatureDigest() != expected.GetSignatureDigest())
                return reject("canonical tally certificate is not the exact deterministic result");
        }
        else if (!fNoteOnly)
        {
            // A note certificate cannot be rebuilt byte-for-byte: its range proofs are
            // entropy-bearing, so two honest committees produce different valid proofs
            // over the same votes. The transparent skeleton is still exactly one value
            // and is compared field-by-field here; the note side is authorized instead
            // by the M-of-N signatures checked above and proved below.
            if (cert.hashBlock != expected.hashBlock ||
                cert.nHeight != expected.nHeight ||
                cert.nEpoch != expected.nEpoch ||
                cert.hashCurveRoot != expected.hashCurveRoot ||
                cert.hashNullifierRoot != expected.hashNullifierRoot ||
                cert.nConsecutiveHardCount != expected.nConsecutiveHardCount ||
                cert.nTransparentActiveWeight != expected.nTransparentActiveWeight ||
                cert.nTransparentWinningWeight != expected.nTransparentWinningWeight ||
                cert.nTransparentRewardBudget != expected.nTransparentRewardBudget ||
                cert.vVoteNullifiers != expected.vVoteNullifiers)
                return reject("canonical note tally certificate transparent skeleton is not the deterministic result");
        }
    }

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
    else if (cert.HasNoteWeight())
    {
        // F2 note tally. Every input below is a pure function of the connected chain
        // plus the certificate bytes: the counted note-vote view is rebuilt in full on
        // connect/disconnect/load, the committee is the epoch's consensus committee,
        // and the transparent weights are the ones recomputed above -- never the
        // values the certificate supplied.
        std::vector<CPubKey> vNoteCommittee;
        int nNoteM = 0;
        uint256 noteSetHash;
        bool fNoteCommitteeLocalFailure = false;
        if (!GetCommitteeForEpoch(txdb, cert.nEpoch, vNoteCommittee, nNoteM, noteSetHash,
                                  &fNoteCommitteeLocalFailure))
            return fNoteCommitteeLocalFailure
                       ? localState("finality committee record cannot be read; -reindex/resync required")
                       : reject("no finality committee is seated for this certificate's term");
        if (cert.committeeSetHash != noteSetHash)
            return reject("note tally certificate does not name the canonical committee for its epoch");

        CFinalityTallyConfig noteConfig;
        noteConfig.fCommitteeValid = true;
        noteConfig.fEnabled = true;
        noteConfig.nThresholdM = nNoteM;
        noteConfig.nThresholdN = (int)vNoteCommittee.size();
        noteConfig.committeeSetHash = noteSetHash;
        noteConfig.vCommitteePubKeys = vNoteCommittee;

        // The COUNTED view, not the raw carried votes. An equivocated tag appears
        // twice among the carried votes, and ResolveNoteTallyCoverage hard-fails on a
        // repeated tag -- so feeding it the raw set would let one anonymous
        // equivocator make every epoch permanently uncertifiable.
        const std::vector<CNoteFinalityVote> vCounted =
            GetCountedEpochNoteVotes(cert.nEpoch);
        std::vector<const CNoteFinalityVote*> vCountedPtrs;
        vCountedPtrs.reserve(vCounted.size());
        for (size_t i = 0; i < vCounted.size(); i++)
            vCountedPtrs.push_back(&vCounted[i]);

        std::string strNoteError;
        if (!CheckNoteTallyCertificate(cert.nTier, cert.hashBlock, vCountedPtrs,
                                       cert.vNoteVoteTags, cert.vNoteComplaints,
                                       noteConfig, nTransparentActiveWeight,
                                       nTransparentWinningWeight, cert.noteTierProofs,
                                       &strNoteError))
            return reject(strNoteError);
    }
    else
    {
        if (!VerifyFinalityThresholdTier(cert.nTier, nTransparentActiveWeight, nTransparentWinningWeight))
            return reject("transparent tally certificate threshold mismatch");
    }
    return ReturnFinalityResult(pResult, FINALITY_RESULT_OK, true);
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
    const int nEffectiveContextHeight = nContextHeight >= 0
        ? nContextHeight
        : (nBestHeight == std::numeric_limits<int>::max()
               ? nBestHeight : nBestHeight + 1);
    if (IsLegacyPrivacyPolicyDisabled() ||
        IsBoundaryAActiveAtHeight(nEffectiveContextHeight))
        return reject("legacy private tally shares are disabled pending privacy vNext");
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

// Defined with the note-vote production code below; the relay checks here need the same
// consensus committee a note vote had to share to.
static bool GetNoteVoteCommitteeConfig(int nEpoch, CFinalityTallyConfig& configOut);

// This node's seat in the CANONICAL committee for an epoch, resolved from the tally
// private key rather than from the local -finalitytallypubkey ordering: the note path's
// committee is consensus state, and a seat read from local configuration would sign under
// an index the verifier resolves to someone else's key.
static bool NoteTallyLocalCommitteeSeat(const CFinalityTallyConfig& config, CKey& keyOut,
                                        int& nIndexOut)
{
    nIndexOut = -1;
    if (!GetFinalityTallyPrivateKey(keyOut) || !keyOut.IsValid())
        return false;
    const CPubKey pub = keyOut.GetPubKey();
    if (!pub.IsValid())
        return false;
    for (size_t i = 0; i < config.vCommitteePubKeys.size(); i++)
    {
        if (config.vCommitteePubKeys[i] == pub)
        {
            nIndexOut = (int)i;
            return true;
        }
    }
    return false;
}

// Relay/automation state, so the bound that matters is how much of it one epoch can hold.
// A committee has at most FINALITY_MAX_TALLY_COMMITTEE members, and convergence lets each
// republish over a shrinking covered set a bounded number of times.
static const size_t FINALITY_MAX_EPOCH_NOTE_TALLY_PARTIALS =
    (size_t)FINALITY_MAX_TALLY_COMMITTEE * 4;

bool CFinalityTracker::CheckNoteTallyAggregatePartial(
    const CNoteTallyAggregatePartial& partial, std::string* pstrError) const
{
    auto reject = [&](const std::string& strReason) -> bool {
        if (pstrError)
            *pstrError = strReason;
        return false;
    };

    if (!partial.IsValidBasic(pstrError))
        return false;

    int nCurrentEpoch = 0;
    CBlockIndex* pBest = pindexBest;
    if (pBest)
        nCurrentEpoch = GetEpochForHeight(pBest->nHeight);
    if (partial.nEpoch > nCurrentEpoch + 1 ||
        partial.nEpoch + FINALITY_CONFIRMATION_EPOCHS < nCurrentEpoch)
        return reject("note tally partial is outside the epochs still being tallied");

    CFinalityTallyConfig config;
    if (!GetNoteVoteCommitteeConfig(partial.nEpoch, config))
        return reject("note tally partial names an epoch with no canonical committee");
    if (partial.committeeSetHash != config.committeeSetHash)
        return reject("note tally partial does not name the canonical committee for its epoch");
    if (partial.vEncryptedRecipientPartials.size() != config.vCommitteePubKeys.size())
        return reject("note tally partial envelope count does not match its committee");
    if (!CheckNoteTallyAggregatePartialSignature(partial, config, pstrError))
        return false;

    LOCK(cs_finality);
    std::map<int, std::map<uint256, uint256> >::const_iterator itEpoch =
        mapEpochCountedNoteVotes.find(partial.nEpoch);
    if (itEpoch == mapEpochCountedNoteVotes.end())
        return reject("note tally partial covers an epoch with no counted note votes");

    // The counted view, never the raw carried votes: an equivocated tag is absent from it
    // by construction, so nothing a partial names can reintroduce one.
    const auto resolve = [&](const uint256& tag) -> const CNoteFinalityVote* {
        std::map<uint256, uint256>::const_iterator itTag = itEpoch->second.find(tag);
        if (itTag == itEpoch->second.end())
            return NULL;
        std::map<uint256, CNoteFinalityVote>::const_iterator itVote =
            mapNoteVotesByHash.find(itTag->second);
        return itVote == mapNoteVotesByHash.end() ? NULL : &itVote->second;
    };

    for (size_t i = 0; i < partial.vAcceptedTags.size(); i++)
    {
        if (resolve(partial.vAcceptedTags[i]) == NULL)
            return reject("note tally partial covers a vote this node has not counted");
    }
    for (size_t i = 0; i < partial.vComplaints.size(); i++)
    {
        const CNoteFinalityVote* pvote = resolve(partial.vComplaints[i].voteTag);
        if (pvote == NULL)
            return reject("note tally partial complains of a vote this node has not counted");
        if (!CheckNoteVoteComplaint(partial.vComplaints[i], *pvote, config, pstrError))
            return false;
    }

    std::map<uint256, uint256>::const_iterator itSlot =
        mapNoteTallyPartialBySlot.find(partial.GetSourceSlot());
    if (itSlot != mapNoteTallyPartialBySlot.end() &&
        itSlot->second != partial.GetContentDigest())
        return reject("note tally partial equivocation: source already signed this slot");

    return true;
}

bool CFinalityTracker::AddNoteTallyAggregatePartial(const CNoteTallyAggregatePartial& partial,
                                                    bool fCheck)
{
    if (fCheck)
    {
        std::string strError;
        if (!CheckNoteTallyAggregatePartial(partial, &strError))
        {
            if (fDebug)
                printf("AddNoteTallyAggregatePartial: rejected partial: %s\n",
                       strError.c_str());
            return false;
        }
    }

    LOCK(cs_finality);
    const uint256 hashPartial = partial.GetHash();
    if (mapNoteTallyPartials.count(hashPartial))
        return false;

    size_t nEpochCount = 0;
    for (const auto& pair : mapNoteTallyPartials)
    {
        if (pair.second.nEpoch == partial.nEpoch)
            nEpochCount++;
    }
    if (nEpochCount >= FINALITY_MAX_EPOCH_NOTE_TALLY_PARTIALS)
        return false;

    mapNoteTallyPartials[hashPartial] = partial;
    mapNoteTallyPartialBySlot[partial.GetSourceSlot()] = partial.GetContentDigest();
    return true;
}

std::vector<CNoteTallyAggregatePartial>
CFinalityTracker::GetEpochNoteTallyPartials(int nEpoch) const
{
    LOCK(cs_finality);
    std::vector<CNoteTallyAggregatePartial> vPartials;
    for (const auto& pair : mapNoteTallyPartials)
    {
        if (pair.second.nEpoch == nEpoch)
            vPartials.push_back(pair.second);
    }
    return vPartials;
}

int CFinalityTracker::GetEpochNoteTallyPartialCount(int nEpoch) const
{
    LOCK(cs_finality);
    int nCount = 0;
    for (const auto& pair : mapNoteTallyPartials)
    {
        if (pair.second.nEpoch == nEpoch)
            nCount++;
    }
    return nCount;
}

bool CFinalityTracker::AddTallyCertificate(const CFinalityTallyCertificate& cert, bool fCheck, bool fRecordFinality)
{
    const uint256 hashContext =
        FinalityCertificateAutomationContextHash(cert);
    // Relay-DoS mitigation: on the relay path, reject an already-known certificate (by hash or by
    // automation-context) BEFORE the expensive CheckTallyCertificate (which runs the uncached bulletproof
    // threshold+budget verification). Otherwise a replayed cert forces a full verification on every
    // delivery. The authoritative dedup + add still run under the lock below; this is a cheap early-out.
    if (fCheck && !fRecordFinality)
    {
        LOCK(cs_finality);
        uint256 hashKnown = cert.GetHash();
        uint256 hashCtx = 0;
        if (mapPendingTallyCertificates.count(hashKnown) ||
            mapConnectedTallyCertificates.count(hashKnown) ||
            FinalityTallyCertificateContextExists(cert, mapPendingTallyCertificates, hashCtx) ||
            mapConnectedTallyCertificateByContext.count(hashContext))
            return false;
    }

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
        const bool fPendingContext = FinalityTallyCertificateContextExists(
            cert, mapPendingTallyCertificates, hashExisting);
        std::map<uint256, uint256>::const_iterator connectedContext =
            mapConnectedTallyCertificateByContext.find(hashContext);
        if (fPendingContext ||
            connectedContext != mapConnectedTallyCertificateByContext.end())
        {
            if (!fPendingContext)
                hashExisting = connectedContext->second;
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
    std::map<uint256, uint256>::const_iterator contextExisting =
        mapConnectedTallyCertificateByContext.find(hashContext);
    if (contextExisting != mapConnectedTallyCertificateByContext.end())
    {
        hashExisting = contextExisting->second;
        if (GetBoolArg("-debugfinalityrelay", false))
            printf("FINALITY connect-duplicate-context ftcert=%s existing=%s\n",
                   hashCert.ToString().substr(0, 10).c_str(),
                   hashExisting.ToString().substr(0, 10).c_str());
        FinalityEraseTallyCertificateContext(cert, mapPendingTallyCertificates);
        // Context-equivalent certificates can differ in proof or signature bytes; pick one by a
        // rule independent of connect order, iteration order, restart or reorg.
        if (!(hashCert < hashExisting))
            return true;

        std::map<uint256, CFinalityTallyCertificate>::iterator itExisting =
            mapConnectedTallyCertificates.find(hashExisting);
        if (itExisting != mapConnectedTallyCertificates.end())
        {
            const int nExistingEpoch = itExisting->second.nEpoch;
            mapConnectedTallyCertificates.erase(itExisting);
            std::map<int, std::vector<CFinalityTallyCertificate> >::iterator eit =
                mapEpochTallyCertificates.find(nExistingEpoch);
            if (eit != mapEpochTallyCertificates.end())
            {
                std::vector<CFinalityTallyCertificate>& vEpoch = eit->second;
                vEpoch.erase(std::remove_if(
                    vEpoch.begin(), vEpoch.end(),
                    [&](const CFinalityTallyCertificate& existing) {
                        return existing.GetHash() == hashExisting;
                    }), vEpoch.end());
                if (vEpoch.empty())
                    mapEpochTallyCertificates.erase(eit);
            }
        }
    }

    mapConnectedTallyCertificates[hashCert] = cert;
    mapConnectedTallyCertificateByContext[hashContext] = hashCert;
    FinalityEraseTallyCertificateContext(cert, mapPendingTallyCertificates);
    for (const uint256& hashShare : cert.vTallyShareHashes)
        setConnectedTallyShares.insert(hashShare);
    mapEpochTallyCertificates[cert.nEpoch].push_back(cert);
    MarkFinalitySummaryDirty(cert.nEpoch);
    return true;
}

void CFinalityTracker::RecordConflictingNullifierVote(const CFinalityVote& vote)
{
    AssertLockHeld(cs_finality);
    // Observability only. Counted when the held vote for this nullifier names a
    // different block; a re-encoding of the same choice is not an equivocation.
    const CFinalityVote* pHeld = NULL;
    std::map<uint256, CFinalityVote>::const_iterator itHeld = mapConnectedVotes.find(vote.nullifier);
    if (itHeld != mapConnectedVotes.end())
        pHeld = &itHeld->second;
    else if ((itHeld = mapPendingVotes.find(vote.nullifier)) != mapPendingVotes.end())
        pHeld = &itHeld->second;
    if (!pHeld || pHeld->hashBlock == vote.hashBlock)
        return;
    std::set<uint256>& setEpoch = mapEpochEquivocatedVoteNullifiers[pHeld->nEpoch];
    if (setEpoch.size() < (size_t)FINALITY_MAX_VOTES)
        setEpoch.insert(vote.nullifier);
    if (fDebug)
        printf("FINALITY equivocation: epoch=%d nullifier=%s held=%s offered=%s connected=%d\n",
               pHeld->nEpoch,
               vote.nullifier.ToString().substr(0, 10).c_str(),
               pHeld->hashBlock.ToString().substr(0, 10).c_str(),
               vote.hashBlock.ToString().substr(0, 10).c_str(),
               mapConnectedVotes.count(vote.nullifier) ? 1 : 0);
}

bool CFinalityTracker::AddVote(const CFinalityVote& vote, bool fCheckStake, bool fRecordFinality)
{
    if (fCheckStake)
    {
        CTxDB txdb("r");
        std::string strError;
        if (!CheckVote(vote, txdb, &strError, CFinalityVoteContext::Relay()))
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
        RecordConflictingNullifierVote(vote);

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

    MarkFinalitySummaryDirty(vote.nEpoch);
    return true;
}

bool CFinalityTracker::IsFinalized(int nHeight) const
{
    LOCK(cs_finality);
    return nHeight <= nLastFinalizedHeight;
}

bool CFinalityTracker::CheckFinalityThreshold(int nEpoch, bool fLog)
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
                (cert.nTier == pBestCert->nTier && cert.GetSignatureDigest() < pBestCert->GetSignatureDigest()))
                pBestCert = &cert;
        }
        // A NONE-tier certificate is treated as absent, as in
        // ComputeDeterministicEpochTier; the vote path below decides.
        if (pBestCert && pBestCert->nTier != FINALITY_NONE)
        {
            // Note tags are voters the certificate counted, exactly as
            // ComputeDeterministicEpochTier counts them; reading only the
            // transparent leg reports an all-private epoch as having no voters.
            int nVoterCount = (int)pBestCert->vVoteNullifiers.size() +
                              (int)pBestCert->vNoteVoteTags.size();
            return ApplyFinalityDecision(nEpoch, pBestCert->hashBlock, pBestCert->nHeight,
                                         (FinalityTier)pBestCert->nTier, nVoterCount,
                                         pBestCert->nTransparentWinningWeight,
                                         pBestCert->nTransparentActiveWeight,
                                         true, fLog);
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
    else if (nBestBlockWeight * 2 > nEpochVoteWeight)        // > 1/2, strict
        tier = FINALITY_SOFT;
    else if (nBestBlockWeight * 3 >= nEpochVoteWeight)       // >= 1/3
        tier = FINALITY_TENTATIVE;

    int nFinalHeight = mapBlockHeight.count(hashFinal) ? mapBlockHeight[hashFinal] : 0;
    return ApplyFinalityDecision(nEpoch, hashFinal, nFinalHeight, tier, nVoterCount,
                                 nBestBlockWeight, nEpochVoteWeight, false, fLog);
}

bool CFinalityTracker::ComputeDeterministicEpochTier(int nEpoch, bool fHaveEpochCert,
                                                     const CFinalityTallyCertificate& epochBestCert,
                                                     int& nTierOut, uint256& hashWinnerOut,
                                                     int& nWinnerHeightOut, int& nVoterCountOut) const
{
    // Pure and deterministic: derived only from the epoch's own committed blocks
    // [H_E, H_E+K). Does not touch the live streak or the global certificate map.
    LOCK(cs_finality);
    nTierOut = FINALITY_NONE; hashWinnerOut = 0; nWinnerHeightOut = 0; nVoterCountOut = 0;

    // Prefer the epoch's own-block tally certificate (not the global map, so a late
    // cert in a later block cannot change the tier on one path only). A NONE-tier
    // certificate is treated as absent.
    if (fHaveEpochCert && epochBestCert.nEpoch == nEpoch &&
        epochBestCert.nTier != FINALITY_NONE)
    {
        nTierOut = epochBestCert.nTier;
        hashWinnerOut = epochBestCert.hashBlock;
        nWinnerHeightOut = epochBestCert.nHeight;
        // A note vote is a voter the certificate counted; leaving it out would report an
        // epoch as having fewer voters than the tier it carries was computed from.
        nVoterCountOut = (int)epochBestCert.vVoteNullifiers.size() +
                         (int)epochBestCert.vNoteVoteTags.size();
        return nTierOut != FINALITY_NONE;
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
    else if (nBestBlockWeight * 2 > nEpochVoteWeight)
        nTierOut = FINALITY_SOFT;
    else if (nBestBlockWeight * 3 >= nEpochVoteWeight)
        nTierOut = FINALITY_TENTATIVE;

    nWinnerHeightOut = mapBlockHeightLocal.count(hashWinnerOut) ? mapBlockHeightLocal[hashWinnerOut] : 0;
    return nTierOut != FINALITY_NONE;
}

bool CFinalityTracker::ApplyFinalityDecision(int nEpoch, const uint256& hashFinal, int nFinalHeight,
                                             FinalityTier tier, int nVoterCount,
                                             int64_t nBestBlockWeight, int64_t nEpochVoteWeight,
                                             bool fFromCertificate, bool fLog)
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
            if (fLog)
                printf("FINALITY: CONFIRMED at height %d after %d consecutive HARD epochs (hash=%s, voters=%d, source=%s)\n",
                       nLastFinalizedHeight, nConsecutiveHardEpochs,
                       hashLastFinalized.ToString().substr(0, 20).c_str(),
                       nVoterCount,
                       fFromCertificate ? "tally-certificate" : "transparent-votes");
        }
        else
        {
            if (fLog)
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

        if (tier >= FINALITY_SOFT && fLog)
        {
            printf("FINALITY: Epoch %d SOFT at height %d (block_weight=%s, epoch_weight=%s, voters=%d, source=%s)\n",
                   nEpoch, nFinalHeight,
                   FormatMoney(nBestBlockWeight).c_str(),
                   FormatMoney(nEpochVoteWeight).c_str(),
                   nVoterCount,
                   fFromCertificate ? "tally-certificate" : "transparent-votes");
        }
        else if (tier >= FINALITY_TENTATIVE && fDebug && fLog)
        {
            printf("FINALITY: Epoch %d tentative at height %d (voters=%d, source=%s)\n",
                   nEpoch, nFinalHeight, nVoterCount,
                   fFromCertificate ? "tally-certificate" : "transparent-votes");
        }
    }

    return false;
}

std::vector<CFinalityVote> CFinalityTracker::GetPendingVotes(int nEpoch) const
{
    LOCK(cs_finality);
    std::vector<CFinalityVote> vOut;
    for (std::map<uint256, CFinalityVote>::const_iterator it = mapPendingVotes.begin();
         it != mapPendingVotes.end(); ++it)
        if (it->second.nEpoch == nEpoch)
            vOut.push_back(it->second);
    return vOut;
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
    if (IsBoundaryAActiveAtHeight(nBlockHeight))
    {
        std::map<int, std::vector<CFinalityVote> >::const_iterator itConnected =
            mapEpochVotes.find(nBlockEpoch);
        const size_t nConnected = itConnected == mapEpochVotes.end()
            ? 0 : itConnected->second.size();
        if (nConnected >= FINALITY_CANONICAL_CERT_MAX_NULLIFIERS)
            return vVotes;
        nMaxVotes = std::min<unsigned int>(
            nMaxVotes,
            FINALITY_CANONICAL_CERT_MAX_NULLIFIERS - nConnected);
    }
    for (const auto& pair : mapPendingVotes)
    {
        const CFinalityVote& vote = pair.second;
        if (vote.IsCanonicalEnvelope() !=
            IsBoundaryAActiveAtHeight(nBlockHeight))
            continue;
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

bool CFinalityTracker::CheckCanonicalVoteSetCapacity(
    const std::vector<CFinalityVote>& vBlockVotes, int nBlockHeight,
    std::string* pstrError) const
{
    if (pstrError)
        pstrError->clear();
    if (!IsBoundaryAActiveAtHeight(nBlockHeight))
        return true;

    LOCK(cs_finality);
    std::map<int, std::set<uint256> > mapEpochNullifiers;
    for (std::vector<CFinalityVote>::const_iterator it = vBlockVotes.begin();
         it != vBlockVotes.end(); ++it)
    {
        std::map<int, std::set<uint256> >::iterator cached =
            mapEpochNullifiers.find(it->nEpoch);
        if (cached == mapEpochNullifiers.end())
        {
            std::set<uint256>& setExisting =
                mapEpochNullifiers[it->nEpoch];
            std::map<int, std::vector<CFinalityVote> >::const_iterator eit =
                mapEpochVotes.find(it->nEpoch);
            if (eit != mapEpochVotes.end())
                for (std::vector<CFinalityVote>::const_iterator vit =
                         eit->second.begin(); vit != eit->second.end(); ++vit)
                    setExisting.insert(vit->nullifier);
            cached = mapEpochNullifiers.find(it->nEpoch);
        }
        std::set<uint256>& setEpoch = cached->second;
        setEpoch.insert(it->nullifier);
        if (setEpoch.size() > FINALITY_CANONICAL_CERT_MAX_NULLIFIERS)
        {
            if (pstrError)
                *pstrError = strprintf(
                    "epoch %d canonical vote set exceeds %u entries",
                    it->nEpoch, FINALITY_CANONICAL_CERT_MAX_NULLIFIERS);
            return false;
        }
    }
    return true;
}

std::vector<CFinalityTallyCertificate> CFinalityTracker::GetPendingTallyCertificatesForBlock(int nBlockHeight, unsigned int nMaxCerts) const
{
    LOCK(cs_finality);

    std::vector<CFinalityTallyCertificate> vCerts;
    int nBlockEpoch = GetEpochForHeight(nBlockHeight);
    for (const auto& pair : mapPendingTallyCertificates)
    {
        const CFinalityTallyCertificate& cert = pair.second;
        if (cert.IsCanonicalEnvelope() !=
            IsBoundaryAActiveAtHeight(nBlockHeight))
            continue;
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
        // Only offer shares whose vote is connected or embedded in this block;
        // relay-only votes would fail block-context CheckTallyShare.
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

bool CFinalityTracker::ConnectBlockVotes(CTxDB& txdb, const uint256& hashBlock,
                                        const std::vector<CFinalityVote>& vVotes,
                                        const CFinalityVoteContext& ctx,
                                        FinalityResult* pResult)
{
    const int nBlockHeight = ctx.Height();
    if (pResult)
        *pResult = FINALITY_RESULT_INVALID;
    if (vVotes.empty())
        return ReturnFinalityResult(pResult, FINALITY_RESULT_OK, true);

    std::set<uint256> setBlockNullifiers;
    if (!CheckCanonicalVoteSetCapacity(vVotes, nBlockHeight))
        return ReturnFinalityResult(pResult, FINALITY_RESULT_INVALID, false);

    // Complete deterministic preflight before mutating tracker state.  In
    // particular, a bad later vote must not leave earlier votes from the same
    // rejected block visible until the outer transaction-abort recovery runs.
    for (const CFinalityVote& vote : vVotes)
    {
        if (!setBlockNullifiers.insert(vote.nullifier).second)
            return false;

        // An alternative carrier must not overwrite the value already committed for a
        // nullifier. The point read observes the active batch, covering multi-block reorgs.
        bool fExistingCarrier = false;
        {
            LOCK(cs_finality);
            fExistingCarrier =
                mapConnectedVotes.count(vote.nullifier) != 0;
        }
        if (fExistingCarrier)
        {
            CFinalityVote persisted;
            if (!txdb.ReadFinalityVote(vote.nullifier, persisted))
                return ReturnFinalityResult(
                    pResult, FINALITY_RESULT_LOCAL_STATE, false);
            if (!FinalityVotesHaveSameSemanticIdentity(vote, persisted))
                return ReturnFinalityResult(
                    pResult, FINALITY_RESULT_INVALID, false);
        }

        std::string strError;
        FinalityResult checkResult = FINALITY_RESULT_INVALID;
        if (!CheckVote(vote, txdb, &strError, ctx, &checkResult))
        {
            if (fDebug)
                printf("ConnectBlockVotes: rejected vote in block %s: %s\n",
                       hashBlock.ToString().substr(0,20).c_str(), strError.c_str());
            return ReturnFinalityResult(pResult, checkResult, false);
        }
    }

    for (const CFinalityVote& vote : vVotes)
    {
        if (!AddVote(vote, false, true))
            return ReturnFinalityResult(pResult, FINALITY_RESULT_INVALID, false);
        if (!txdb.WriteFinalityVote(vote.nullifier, vote))
            return ReturnFinalityResult(pResult, FINALITY_RESULT_LOCAL_STATE, false);
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
    if (!txdb.WriteFinalityConnectedVoteBlock(hashBlock, vNullifiers))
    {
        mapBlockConnectedVoteNullifiers.erase(hashBlock);
        return ReturnFinalityResult(pResult, FINALITY_RESULT_LOCAL_STATE, false);
    }
    int nEarliestEpoch = vVotes[0].nEpoch;
    for (std::vector<CFinalityVote>::const_iterator it = vVotes.begin();
         it != vVotes.end(); ++it)
        nEarliestEpoch = std::min(nEarliestEpoch, it->nEpoch);
    if (!RecomputeFinalityStateFromEpoch(nEarliestEpoch))
        return ReturnFinalityResult(pResult, FINALITY_RESULT_LOCAL_STATE, false);

    return ReturnFinalityResult(pResult, FINALITY_RESULT_OK, true);
}

bool CFinalityTracker::DisconnectBlockVotes(CTxDB& txdb, const uint256& hashBlock, const std::vector<CFinalityVote>& vVotes)
{
    if (vVotes.empty())
        return true;

    LOCK(cs_finality);
    for (const CFinalityVote& vote : vVotes)
    {
        // A vote may be carried by several connected blocks but is recorded once; tear
        // it down only when the last carrier disconnects. Mirrors DisconnectBlockTallyShares.
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

        if (!txdb.EraseFinalityVote(vote.nullifier))
            return false;

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
        MarkFinalitySummaryDirty(vote.nEpoch);
    }
    mapBlockConnectedVoteNullifiers.erase(hashBlock);
    if (!txdb.EraseFinalityConnectedVoteBlock(hashBlock))
        return false;
    int nEarliestEpoch = vVotes[0].nEpoch;
    for (std::vector<CFinalityVote>::const_iterator it = vVotes.begin();
         it != vVotes.end(); ++it)
        nEarliestEpoch = std::min(nEarliestEpoch, it->nEpoch);
    return RecomputeFinalityStateFromEpoch(nEarliestEpoch);
}

bool CFinalityTracker::CheckNoteVoteForContext(const CNoteFinalityVote& vote, CTxDB& txdb,
                                               std::string* pstrError,
                                               const CFinalityVoteContext& ctx,
                                               FinalityResult* pResult) const
{
    const int nContextHeight = ctx.Height();
    auto reject = [&](const std::string& strReason) -> bool {
        if (pstrError)
            *pstrError = strReason;
        return ReturnFinalityResult(pResult, FINALITY_RESULT_INVALID, false);
    };
    auto localState = [&](const std::string& strReason) -> bool {
        if (pstrError)
            *pstrError = strReason;
        return ReturnFinalityResult(pResult, FINALITY_RESULT_LOCAL_STATE, false);
    };

    if (pResult)
        *pResult = FINALITY_RESULT_INVALID;

    const int nEffectiveContextHeight = nContextHeight >= 0
        ? nContextHeight
        : (nBestHeight == std::numeric_limits<int>::max()
               ? nBestHeight : nBestHeight + 1);
    if (!IsIV5NoteVoteActiveAtHeight(nEffectiveContextHeight))
        return reject("note finality votes are not active at this height");

    if (GetEpochForHeight(vote.nHeight) != vote.nEpoch ||
        GetEpochBoundaryHeight(vote.nEpoch, vote.nHeight) != vote.nHeight)
        return reject("note vote height is not this epoch boundary");

    // R1: an epoch-E vote is block-valid only inside E's own [H_E, H_E+K) blocks, which is
    // what freezes the connected vote set a certificate has to cover.
    if (nContextHeight >= 0)
    {
        int nBoundary = GetEpochBoundaryHeight(vote.nEpoch, nContextHeight);
        if (nContextHeight < nBoundary ||
            nContextHeight >= nBoundary + FINALITY_VOTE_INCLUSION_WINDOW)
            return reject("note finality vote outside epoch vote-inclusion window");
    }

    // At relay, a missing named block is node-local state, not invalidity. In a chain
    // context the named block must be an indexed ancestor on every node, so a miss is
    // invalid everywhere and must not map to a transient failure.
    std::map<uint256, CBlockIndex*>::iterator miEpoch = mapBlockIndex.find(vote.hashBlock);
    if (miEpoch == mapBlockIndex.end())
        return ctx.IsRelay() ? localState("note vote epoch block is not known")
                             : reject("note vote epoch block is not known");
    // Local corruption in either context, and unreachable by a peer, so it stays transient.
    if (miEpoch->second == NULL)
        return localState("note vote epoch block index entry is corrupt");
    CBlockIndex* pEpochBlock = miEpoch->second;
    if (pEpochBlock->nHeight != vote.nHeight)
        return reject("note vote epoch block height mismatch");
    if (!pEpochBlock->IsProofOfWork())
        return reject("note finality votes must target proof-of-work epoch blocks");
    // Presence in the global index is not membership of this chain: a boundary block from
    // a sibling branch is indexed too.
    if (const CBlockIndex* pAnchor = ctx.AnchorTip())
    {
        if (GetFinalityAncestorOnChain(pAnchor, vote.nHeight,
                                       FINALITY_ANCESTOR_MAX_WALK) != pEpochBlock)
            return reject("note vote epoch block is not an ancestor of the including block");
    }

    // The committee the vote shared to is consensus state, not the voter's choice: a share
    // split to some other set is one no quorum can ever open.
    std::vector<CPubKey> vCommittee;
    int nThresholdM = 0;
    uint256 committeeSetHash = 0;
    bool fCommitteeLocalFailure = false;
    if (!GetCommitteeForEpoch(txdb, vote.nEpoch, vCommittee, nThresholdM, committeeSetHash,
                              &fCommitteeLocalFailure))
        return fCommitteeLocalFailure
                   ? localState("finality committee record cannot be read; -reindex/resync required")
                   : reject("no finality committee is seated for this vote's term");
    if (vote.committeeSetHash != committeeSetHash)
        return reject("note vote does not name the canonical committee for its epoch");

    // Anchor deterministically from the including block's context. Reading the node-local
    // finalized tip in a connect path is the ConnectBlock-split class.
    CEpochState finalizedEpochState;
    // A note vote anchors to the IV5 root, so an empty legacy curve root is not a
    // reason to skip an epoch. Requiring one refused every vote on a chain with no
    // legacy shielded history -- which is every IV5 chain.
    const FinalityResult anchorResult = ResolveFinalityAnchorForContext(
        txdb, nContextHeight, GetFinalizedHeight(), finalizedEpochState,
        false /* fRequireCurveRoot */,
        true /* fAllowDeepUnfinalizedAnchor */);
    if (anchorResult == FINALITY_RESULT_INVALID)
        return reject("note vote requires an already-finalized epoch");
    if (anchorResult == FINALITY_RESULT_LOCAL_STATE)
        return localState("note vote requires unavailable finalized epoch state");
    // A note vote's membership proof is over the IV5 note tree, and IsValidBasic pins the
    // proof's own root field to the anchor the vote declares. That anchor is therefore the
    // epoch's IV5 root, not CEpochState::hashCurveRoot, which is the retired
    // ring-signature curve tree and is zero on a chain that never carried one.
    if (finalizedEpochState.vchVNextRoot.size() != EPOCHSTATE_VNEXT_DIGEST_SIZE)
        return localState("note vote anchor epoch carries no IV5 tree root");
    uint256 hashAnchorRoot = 0;
    memcpy(hashAnchorRoot.begin(), &finalizedEpochState.vchVNextRoot[0],
           EPOCHSTATE_VNEXT_DIGEST_SIZE);
    if (vote.hashCurveRoot != hashAnchorRoot ||
        vote.hashNullifierRoot != finalizedEpochState.hashNullifierRoot)
        return reject("note vote not anchored to last finalized epoch root");

    std::string strError;
    if (!CheckNoteVote(vote, nThresholdM, (int)vCommittee.size(), &strError))
        return reject(strError);

    return ReturnFinalityResult(pResult, FINALITY_RESULT_OK, true);
}

void CFinalityTracker::RecomputeNoteVoteCounting()
{
    mapEpochCountedNoteVotes.clear();
    mapEpochEquivocatedNoteVotes.clear();

    std::map<int, std::vector<const CNoteFinalityVote*> > mapEpochCarried;
    for (const auto& pair : mapBlockConnectedNoteVotes)
    {
        for (const uint256& hashVote : pair.second)
        {
            std::map<uint256, CNoteFinalityVote>::const_iterator it =
                mapNoteVotesByHash.find(hashVote);
            if (it == mapNoteVotesByHash.end())
                continue;
            mapEpochCarried[it->second.nEpoch].push_back(&it->second);
        }
    }

    for (const auto& pair : mapEpochCarried)
    {
        std::map<uint256, const CNoteFinalityVote*> mapCounted;
        std::set<uint256> setEquivocated;
        ResolveNoteVoteCounting(pair.second, mapCounted, setEquivocated);
        std::map<uint256, uint256>& mapEpoch = mapEpochCountedNoteVotes[pair.first];
        for (const auto& counted : mapCounted)
            mapEpoch[counted.first] = counted.second->GetHash();
        if (!setEquivocated.empty())
            mapEpochEquivocatedNoteVotes[pair.first] = setEquivocated;
        if (mapEpoch.empty())
            mapEpochCountedNoteVotes.erase(pair.first);
    }
}

bool CFinalityTracker::ConnectBlockNoteVotes(CTxDB& txdb, const uint256& hashBlock,
                                             const std::vector<CNoteFinalityVote>& vVotes,
                                             const CFinalityVoteContext& ctx,
                                             FinalityResult* pResult,
                                             bool fCheckVotes)
{
    if (pResult)
        *pResult = FINALITY_RESULT_INVALID;
    if (vVotes.empty())
        return ReturnFinalityResult(pResult, FINALITY_RESULT_OK, true);

    if (vVotes.size() > (size_t)FINALITY_MAX_BLOCK_NOTE_VOTES)
        return ReturnFinalityResult(pResult, FINALITY_RESULT_INVALID, false);

    // In-block tag uniqueness. Unlike a cross-block conflict this is entirely the
    // producer's doing, so it stays block-invalidating.
    std::set<uint256> setBlockTags;
    for (const CNoteFinalityVote& vote : vVotes)
    {
        const uint256 tag = vote.GetVoteTag();
        if (tag == 0 || !setBlockTags.insert(tag).second)
            return ReturnFinalityResult(pResult, FINALITY_RESULT_INVALID, false);
    }

    if (fCheckVotes)
    {
        for (const CNoteFinalityVote& vote : vVotes)
        {
            std::string strError;
            FinalityResult checkResult = FINALITY_RESULT_INVALID;
            if (!CheckNoteVoteForContext(vote, txdb, &strError, ctx, &checkResult))
            {
                if (fDebug)
                    printf("ConnectBlockNoteVotes: rejected vote in block %s: %s\n",
                           hashBlock.ToString().substr(0,20).c_str(), strError.c_str());
                return ReturnFinalityResult(pResult, checkResult, false);
            }
        }
    }

    LOCK(cs_finality);

    // Epoch capacity is measured over distinct tags the epoch has seen at all, counted or
    // dropped: an equivocator must not be able to buy extra slots by conflicting itself.
    {
        std::map<int, std::set<uint256> > mapEpochTags;
        for (const auto& pair : mapBlockConnectedNoteVotes)
        {
            if (pair.first == hashBlock)
                continue;
            for (const uint256& hashVote : pair.second)
            {
                std::map<uint256, CNoteFinalityVote>::const_iterator it =
                    mapNoteVotesByHash.find(hashVote);
                if (it == mapNoteVotesByHash.end())
                    continue;
                mapEpochTags[it->second.nEpoch].insert(it->second.GetVoteTag());
            }
        }
        for (const CNoteFinalityVote& vote : vVotes)
        {
            std::set<uint256>& setEpoch = mapEpochTags[vote.nEpoch];
            setEpoch.insert(vote.GetVoteTag());
            if (setEpoch.size() > FINALITY_CANONICAL_CERT_MAX_NULLIFIERS)
                return ReturnFinalityResult(pResult, FINALITY_RESULT_INVALID, false);
        }
    }

    std::vector<uint256> vHashes;
    vHashes.reserve(vVotes.size());
    for (const CNoteFinalityVote& vote : vVotes)
    {
        const uint256 hashVote = vote.GetHash();
        if (!txdb.WriteNoteFinalityVote(hashVote, vote))
            return ReturnFinalityResult(pResult, FINALITY_RESULT_LOCAL_STATE, false);
        mapNoteVotesByHash[hashVote] = vote;
        mapPendingNoteVotes.erase(hashVote);
        vHashes.push_back(hashVote);
    }

    std::vector<uint256>& vCarried = mapBlockConnectedNoteVotes[hashBlock];
    vCarried = vHashes;   // idempotent: never append to a stale/reloaded entry
    if (!txdb.WriteFinalityConnectedNoteVoteBlock(hashBlock, vCarried))
    {
        mapBlockConnectedNoteVotes.erase(hashBlock);
        return ReturnFinalityResult(pResult, FINALITY_RESULT_LOCAL_STATE, false);
    }

    RecomputeNoteVoteCounting();
    return ReturnFinalityResult(pResult, FINALITY_RESULT_OK, true);
}

bool CFinalityTracker::DisconnectBlockNoteVotes(CTxDB& txdb, const uint256& hashBlock,
                                                const std::vector<CNoteFinalityVote>& vVotes)
{
    if (vVotes.empty())
        return true;

    LOCK(cs_finality);
    mapBlockConnectedNoteVotes.erase(hashBlock);
    if (!txdb.EraseFinalityConnectedNoteVoteBlock(hashBlock))
        return false;

    for (const CNoteFinalityVote& vote : vVotes)
    {
        const uint256 hashVote = vote.GetHash();
        // The same vote may be carried by several connected DAG blocks; drop the object
        // only when the last of them is gone, or a partial reorg would lose a vote a
        // surviving block still legitimately carries.
        bool fStillConnected = false;
        for (const auto& pair : mapBlockConnectedNoteVotes)
        {
            if (std::find(pair.second.begin(), pair.second.end(), hashVote) !=
                pair.second.end())
            {
                fStillConnected = true;
                break;
            }
        }
        if (fStillConnected)
            continue;
        if (!txdb.EraseNoteFinalityVote(hashVote))
            return false;
        mapNoteVotesByHash.erase(hashVote);
    }

    RecomputeNoteVoteCounting();
    return true;
}

bool CFinalityTracker::LoadNoteVotes(CTxDB& txdb)
{
    LOCK(cs_finality);
    mapNoteVotesByHash.clear();
    mapBlockConnectedNoteVotes.clear();
    if (!txdb.IterateNoteFinalityVotes(mapNoteVotesByHash))
        return false;
    if (!txdb.IterateFinalityConnectedNoteVoteBlocks(mapBlockConnectedNoteVotes))
        return false;
    RecomputeNoteVoteCounting();
    return true;
}

bool CFinalityTracker::AddPendingNoteVote(const CNoteFinalityVote& vote, CTxDB& txdb,
                                          std::string* pstrError, FinalityResult* pResult)
{
    if (pResult)
        *pResult = FINALITY_RESULT_INVALID;
    const uint256 hashVote = vote.GetHash();
    {
        LOCK(cs_finality);
        if (mapNoteVotesByHash.count(hashVote) || mapPendingNoteVotes.count(hashVote))
        {
            // Already held. Local state, so a caller that caches verdicts must not
            // cache this one as a refusal.
            if (pResult)
                *pResult = FINALITY_RESULT_LOCAL_STATE;
            return false;
        }
    }
    // Relay-time context only: the window is a connect-time rule and a relayed vote may
    // legitimately arrive before the block that will carry it.
    if (!CheckNoteVoteForContext(vote, txdb, pstrError, CFinalityVoteContext::Relay(),
                                 pResult))
        return false;

    LOCK(cs_finality);
    mapPendingNoteVotes[hashVote] = vote;
    if (pResult)
        *pResult = FINALITY_RESULT_OK;
    return true;
}

// Tip height for the hold bounds. Reads the plain height global rather than
// dereferencing pindexBest: these run under cs_finality, which ConnectBlock takes while
// holding cs_main, so this side must never reach for cs_main. A stale read only delays a
// purge by a block, and the sentinel means "no chain yet", which disables the bound.
static int DeferredNoteVoteTipHeight()
{
    return nBestHeight == std::numeric_limits<int>::max() ? -1 : nBestHeight;
}

unsigned int CFinalityTracker::PurgeDeferredNoteVotesLocked(int nTipHeight, int64_t nNow)
{
    unsigned int nDropped = 0;
    std::map<uint256, std::map<uint256, CDeferredNoteVote> >::iterator it =
        mapDeferredNoteVotes.begin();
    while (it != mapDeferredNoteVotes.end())
    {
        std::map<uint256, CDeferredNoteVote>::iterator itVote = it->second.begin();
        while (itVote != it->second.end())
        {
            // Un-carriable: the chain is already past the last block that could have
            // included this vote (R1), so releasing it could never produce a valid
            // carrier. Dropping it therefore loses nothing that was still winnable.
            const bool fWindowClosed =
                nTipHeight >= 0 &&
                nTipHeight > itVote->second.vote.nHeight + FINALITY_VOTE_INCLUSION_WINDOW;
            // Backstop for a hold the height rule can never reach -- a fabricated block
            // at a height the chain has not got to. The age is orders of magnitude above
            // the window, so a hold this old had no carrier left either.
            const bool fAgedOut =
                itVote->second.nTimeHeld > 0 &&
                nNow - itVote->second.nTimeHeld > FINALITY_MAX_DEFERRED_NOTE_VOTE_AGE;
            if (fWindowClosed || fAgedOut)
            {
                it->second.erase(itVote++);
                nDropped++;
            }
            else
                ++itVote;
        }
        if (it->second.empty())
            mapDeferredNoteVotes.erase(it++);
        else
            ++it;
    }
    return nDropped;
}

unsigned int CFinalityTracker::PurgeDeferredNoteVotes(int nTipHeight, int64_t nNow)
{
    LOCK(cs_finality);
    return PurgeDeferredNoteVotesLocked(nTipHeight, nNow);
}

void CFinalityTracker::DeferNoteVoteForUnknownBlock(const CNoteFinalityVote& vote)
{
    const uint256 hashVote = vote.GetHash();
    LOCK(cs_finality);
    if (mapNoteVotesByHash.count(hashVote) || mapPendingNoteVotes.count(hashVote))
        return;
    // Reclaim slots the bound has already retired before consulting the cap, so a
    // spammer's stale holds cannot squat on capacity an arriving honest vote needs.
    PurgeDeferredNoteVotesLocked(DeferredNoteVoteTipHeight(), GetTime());
    unsigned int nHeld = 0;
    for (const auto& pair : mapDeferredNoteVotes)
        nHeld += (unsigned int)pair.second.size();
    // Full: refuse the NEW hold rather than evict an existing one. The sender of this
    // vote still holds it and its inv will come round again; an evicted hold has no
    // second sender, because a note vote is cast once per epoch and never re-emitted.
    if (nHeld >= FINALITY_MAX_DEFERRED_NOTE_VOTES)
        return;
    CDeferredNoteVote held;
    held.vote = vote;
    held.nTimeHeld = GetTime();
    mapDeferredNoteVotes[vote.hashBlock][hashVote] = held;
}

std::vector<uint256> CFinalityTracker::GetDeferredNoteVoteBlockHashes() const
{
    LOCK(cs_finality);
    std::vector<uint256> vBlocks;
    vBlocks.reserve(mapDeferredNoteVotes.size());
    for (const auto& pair : mapDeferredNoteVotes)
        vBlocks.push_back(pair.first);
    return vBlocks;
}

unsigned int CFinalityTracker::GetDeferredNoteVoteCount() const
{
    LOCK(cs_finality);
    unsigned int nHeld = 0;
    for (const auto& pair : mapDeferredNoteVotes)
        nHeld += (unsigned int)pair.second.size();
    return nHeld;
}

std::vector<CNoteFinalityVote> CFinalityTracker::TakeDeferredNoteVotes(
    const std::set<uint256>& setArrivedBlocks, int nCurrentEpoch)
{
    LOCK(cs_finality);
    std::vector<CNoteFinalityVote> vTaken;
    // Height and age bounds first: both retire only holds no carrier could still take.
    PurgeDeferredNoteVotesLocked(DeferredNoteVoteTipHeight(), GetTime());
    std::map<uint256, std::map<uint256, CDeferredNoteVote> >::iterator it =
        mapDeferredNoteVotes.begin();
    while (it != mapDeferredNoteVotes.end())
    {
        if (setArrivedBlocks.count(it->first))
        {
            for (const auto& pair : it->second)
                vTaken.push_back(pair.second.vote);
            mapDeferredNoteVotes.erase(it++);
            continue;
        }
        // An epoch the chain has left behind can no longer carry the vote, so holding
        // it would only grow the map until the cap starved a live one.
        std::map<uint256, CDeferredNoteVote>::iterator itVote = it->second.begin();
        while (itVote != it->second.end())
        {
            if (itVote->second.vote.nEpoch < nCurrentEpoch - 1)
                it->second.erase(itVote++);
            else
                ++itVote;
        }
        if (it->second.empty())
            mapDeferredNoteVotes.erase(it++);
        else
            ++it;
    }
    return vTaken;
}

bool CFinalityTracker::HaveNoteVote(const uint256& hashVote) const
{
    LOCK(cs_finality);
    return mapNoteVotesByHash.count(hashVote) || mapPendingNoteVotes.count(hashVote);
}

std::vector<CNoteFinalityVote> CFinalityTracker::GetPendingNoteVotesForBlock(
    int nBlockHeight, unsigned int nMaxVotes) const
{
    LOCK(cs_finality);

    std::vector<CNoteFinalityVote> vVotes;
    if (!IsIV5NoteVoteActiveAtHeight(nBlockHeight))
        return vVotes;
    const int nBlockEpoch = GetEpochForHeight(nBlockHeight);

    // Offer only what the epoch still has room for, or the produced block would fail the
    // same capacity rule at connect on every node that receives it.
    {
        std::set<uint256> setEpochTags;
        for (const auto& pair : mapBlockConnectedNoteVotes)
            for (const uint256& hashVote : pair.second)
            {
                std::map<uint256, CNoteFinalityVote>::const_iterator it =
                    mapNoteVotesByHash.find(hashVote);
                if (it != mapNoteVotesByHash.end() && it->second.nEpoch == nBlockEpoch)
                    setEpochTags.insert(it->second.GetVoteTag());
            }
        if (setEpochTags.size() >= FINALITY_CANONICAL_CERT_MAX_NULLIFIERS)
            return vVotes;
        nMaxVotes = std::min<unsigned int>(
            nMaxVotes,
            (unsigned int)(FINALITY_CANONICAL_CERT_MAX_NULLIFIERS - setEpochTags.size()));
    }

    for (const auto& pair : mapPendingNoteVotes)
    {
        const CNoteFinalityVote& vote = pair.second;
        if (vote.nEpoch != nBlockEpoch)
            continue;
        const int nBoundary = GetEpochBoundaryHeight(vote.nEpoch, nBlockHeight);
        if (nBlockHeight < nBoundary ||
            nBlockHeight >= nBoundary + FINALITY_VOTE_INCLUSION_WINDOW)
            continue;
        // A tag already retired for this epoch can never count again, so offering it
        // would only spend block space.
        std::map<int, std::set<uint256> >::const_iterator itEquiv =
            mapEpochEquivocatedNoteVotes.find(vote.nEpoch);
        if (itEquiv != mapEpochEquivocatedNoteVotes.end() &&
            itEquiv->second.count(vote.GetVoteTag()))
            continue;
        vVotes.push_back(vote);
        if (vVotes.size() >= nMaxVotes)
            break;
    }
    return vVotes;
}

std::vector<CNoteFinalityVote> CFinalityTracker::GetCountedEpochNoteVotes(int nEpoch) const
{
    LOCK(cs_finality);
    std::vector<CNoteFinalityVote> vVotes;
    std::map<int, std::map<uint256, uint256> >::const_iterator it =
        mapEpochCountedNoteVotes.find(nEpoch);
    if (it == mapEpochCountedNoteVotes.end())
        return vVotes;
    for (const auto& pair : it->second)
    {
        std::map<uint256, CNoteFinalityVote>::const_iterator itVote =
            mapNoteVotesByHash.find(pair.second);
        if (itVote != mapNoteVotesByHash.end())
            vVotes.push_back(itVote->second);
    }
    return vVotes;
}

int CFinalityTracker::GetEpochNoteVoteCount(int nEpoch) const
{
    LOCK(cs_finality);
    std::map<int, std::map<uint256, uint256> >::const_iterator it =
        mapEpochCountedNoteVotes.find(nEpoch);
    return it == mapEpochCountedNoteVotes.end() ? 0 : (int)it->second.size();
}

int CFinalityTracker::GetEpochEquivocatedNoteVoteCount(int nEpoch) const
{
    LOCK(cs_finality);
    std::map<int, std::set<uint256> >::const_iterator it =
        mapEpochEquivocatedNoteVotes.find(nEpoch);
    return it == mapEpochEquivocatedNoteVotes.end() ? 0 : (int)it->second.size();
}

int CFinalityTracker::GetEpochEquivocatedVoteCount(int nEpoch) const
{
    LOCK(cs_finality);
    std::map<int, std::set<uint256> >::const_iterator it =
        mapEpochEquivocatedVoteNullifiers.find(nEpoch);
    return it == mapEpochEquivocatedVoteNullifiers.end() ? 0 : (int)it->second.size();
}

NoteVoteCountingState CFinalityTracker::GetNoteVoteCountingState(
    int nEpoch, const uint256& tag) const
{
    LOCK(cs_finality);
    std::map<int, std::set<uint256> >::const_iterator itEquiv =
        mapEpochEquivocatedNoteVotes.find(nEpoch);
    if (itEquiv != mapEpochEquivocatedNoteVotes.end() && itEquiv->second.count(tag))
        return NOTE_VOTE_EQUIVOCATED;
    std::map<int, std::map<uint256, uint256> >::const_iterator itCounted =
        mapEpochCountedNoteVotes.find(nEpoch);
    if (itCounted != mapEpochCountedNoteVotes.end() && itCounted->second.count(tag))
        return NOTE_VOTE_COUNTED;
    return NOTE_VOTE_UNSEEN;
}

bool CFinalityTracker::ConnectBlockTallyCertificates(
    CTxDB& txdb, const uint256& hashBlock,
    const std::vector<CFinalityTallyCertificate>& vCerts, int nBlockHeight,
    FinalityResult* pResult)
{
    if (pResult)
        *pResult = FINALITY_RESULT_INVALID;
    if (vCerts.empty())
        return ReturnFinalityResult(pResult, FINALITY_RESULT_OK, true);

    // ConnectBlock indexes the carrier before it runs, so its own ancestor chain is
    // the one every certificate here must name its boundary block on. A carrier this
    // node has not indexed (unit fixtures) has no chain to bind to.
    const CBlockIndex* pindexCarrier = NULL;
    {
        std::map<uint256, CBlockIndex*>::const_iterator itCarrier =
            mapBlockIndex.find(hashBlock);
        if (itCarrier != mapBlockIndex.end())
            pindexCarrier = itCarrier->second;
    }

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
        FinalityResult checkResult = FINALITY_RESULT_INVALID;
        if (!CheckTallyCertificate(cert, txdb, &strError, NULL, false,
                                   nBlockHeight, false, &checkResult, pindexCarrier))
        {
            if (fDebug)
                printf("ConnectBlockTallyCertificates: rejected cert in block %s: %s\n",
                       hashBlock.ToString().substr(0,20).c_str(), strError.c_str());
            return ReturnFinalityResult(pResult, checkResult, false);
        }

        if (!AddTallyCertificate(cert, false, true))
            return ReturnFinalityResult(pResult, FINALITY_RESULT_LOCAL_STATE, false);
        if (!txdb.WriteFinalityTallyCertificate(hashCert, cert))
            return ReturnFinalityResult(pResult, FINALITY_RESULT_LOCAL_STATE, false);
    }

    LOCK(cs_finality);
    std::vector<uint256>& vHashes = mapBlockConnectedTallyCertificates[hashBlock];
    vHashes.clear();   // idempotent: never append to a stale/reloaded entry
    for (const CFinalityTallyCertificate& cert : vCerts)
        vHashes.push_back(cert.GetHash());
    if (!txdb.WriteFinalityConnectedCertBlock(hashBlock, vHashes))
        return ReturnFinalityResult(pResult, FINALITY_RESULT_LOCAL_STATE, false);
    int nEarliestEpoch = vCerts[0].nEpoch;
    for (std::vector<CFinalityTallyCertificate>::const_iterator it =
             vCerts.begin(); it != vCerts.end(); ++it)
        nEarliestEpoch = std::min(nEarliestEpoch, it->nEpoch);
    if (!RecomputeFinalityStateFromEpoch(nEarliestEpoch))
        return ReturnFinalityResult(pResult, FINALITY_RESULT_LOCAL_STATE, false);

    return ReturnFinalityResult(pResult, FINALITY_RESULT_OK, true);
}

bool CFinalityTracker::ConnectBlockTallyShares(
    CTxDB& txdb, const uint256& hashBlock,
    const std::vector<CFinalityTallyShare>& vShares, int nBlockHeight,
    FinalityResult* pResult)
{
    if (pResult)
        *pResult = FINALITY_RESULT_INVALID;
    if (vShares.empty())
        return ReturnFinalityResult(pResult, FINALITY_RESULT_OK, true);

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
            return ReturnFinalityResult(pResult, FINALITY_RESULT_LOCAL_STATE, false);
        if (!txdb.WriteFinalityTallyShare(hashShare, share))
            return ReturnFinalityResult(pResult, FINALITY_RESULT_LOCAL_STATE, false);
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
    if (!txdb.WriteFinalityConnectedShareBlock(hashBlock, vHashes))
    {
        mapBlockConnectedTallyShares.erase(hashBlock);
        return ReturnFinalityResult(pResult, FINALITY_RESULT_LOCAL_STATE, false);
    }

    return ReturnFinalityResult(pResult, FINALITY_RESULT_OK, true);
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
            if (!txdb.EraseFinalityTallyShare(hashShare))
                return false;
            mapTallyShares.erase(hashShare);
            setConnectedTallyShares.erase(hashShare);
        }
    }
    mapBlockConnectedTallyShares.erase(hashBlock);
    if (!txdb.EraseFinalityConnectedShareBlock(hashBlock))
        return false;
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
        const uint256 hashContext =
            FinalityCertificateAutomationContextHash(certToErase);
        std::map<uint256, uint256>::iterator context =
            mapConnectedTallyCertificateByContext.find(hashContext);
        if (context != mapConnectedTallyCertificateByContext.end() &&
            context->second == hashToErase)
            mapConnectedTallyCertificateByContext.erase(context);

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
        mapConnectedTallyCertificateByContext[
            FinalityCertificateAutomationContextHash(certToAdd)] = hashToAdd;
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

                CFinalityTallyCertificate certOther;
                auto itConnected = mapConnectedTallyCertificates.find(hashOther);
                if (itConnected != mapConnectedTallyCertificates.end())
                    certOther = itConnected->second;
                else if (!txdb.ReadFinalityTallyCertificate(hashOther, certOther))
                    continue;

                if (FinalityCertificateAutomationContextHash(certOther) == hashContext)
                {
                    if (!fHaveReplacementContext || hashOther < hashReplacement)
                    {
                        certReplacement = certOther;
                        hashReplacement = hashOther;
                        fHaveReplacementContext = true;
                    }
                }
            }

            if (fSameHashStillConnected)
                break;
        }

        if (fSameHashStillConnected)
            continue;

        bool fWasCanonical = mapConnectedTallyCertificates.count(hashCert) != 0;
        if (!txdb.EraseFinalityTallyCertificate(hashCert))
            return false;
        eraseConnectedCertFromMemory(cert, hashCert);

        if (fWasCanonical && fHaveReplacementContext)
            addConnectedCertToMemory(certReplacement, hashReplacement);
        MarkFinalitySummaryDirty(cert.nEpoch);
    }
    mapBlockConnectedTallyCertificates.erase(hashBlock);
    if (!txdb.EraseFinalityConnectedCertBlock(hashBlock))
        return false;
    int nEarliestEpoch = vCerts[0].nEpoch;
    for (std::vector<CFinalityTallyCertificate>::const_iterator it =
             vCerts.begin(); it != vCerts.end(); ++it)
        nEarliestEpoch = std::min(nEarliestEpoch, it->nEpoch);
    return RecomputeFinalityStateFromEpoch(nEarliestEpoch);
}

bool CFinalityTracker::LoadVotes(CTxDB& txdb)
{
    std::map<uint256, CFinalityVote> mapVotes;
    if (!txdb.IterateFinalityVotes(mapVotes))
        return false;

    for (const auto& pair : mapVotes)
        if (!AddVote(pair.second, false, true))
            return error("LoadFinalityVotes: FATAL persisted vote could not be restored -- "
                         "-reindex/resync required");

    if (!RebuildFinalityState())
        return false;

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
        if (!AddTallyShare(pair.second, false))
            return error("LoadFinalityTallyShares: FATAL persisted share could not be "
                         "restored -- -reindex/resync required");

    if (!mapShares.empty())
        printf("LoadFinalityTallyShares: loaded %d relayed tally shares\n", (int)mapShares.size());
    return true;
}

bool CFinalityTracker::PurgeUnresolvableTallyShares(CTxDB& txdb)
{
    LOCK(cs_finality);

    int nPurged = 0;
    for (auto it = mapTallyShares.begin(); it != mapTallyShares.end(); )
    {
        // Never purge a block-connected share: setConnectedTallyShares and the
        // finalityconnsb index still reference it across restart.
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
            if (!txdb.EraseFinalityTallyShare(it->first))
                return false;
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
    return true;
}

bool CFinalityTracker::LoadTallyCertificates(CTxDB& txdb)
{
    std::map<uint256, CFinalityTallyCertificate> mapCerts;
    if (!txdb.IterateFinalityTallyCertificates(mapCerts))
        return false;

    for (const auto& pair : mapCerts)
        if (!AddTallyCertificate(pair.second, false, true))
            return error("LoadFinalityTallyCertificates: FATAL persisted certificate could "
                         "not be restored -- -reindex/resync required");

    if (!RebuildFinalityState())
        return false;

    if (!mapCerts.empty())
        printf("LoadFinalityTallyCertificates: loaded %d connected tally certificates\n", (int)mapCerts.size());
    return true;
}

void CFinalityTracker::MarkFinalitySummaryDirty(int nEpoch)
{
    AssertLockHeld(cs_finality);
    if (nFinalitySummaryDirtyFromEpoch < 0 ||
        nEpoch < nFinalitySummaryDirtyFromEpoch)
        nFinalitySummaryDirtyFromEpoch = nEpoch;
}

void CFinalityTracker::ResetFinalitySummary()
{
    AssertLockHeld(cs_finality);
    nLastFinalizedHeight = 0;
    hashLastFinalized = 0;
    nLastFinalityTier = FINALITY_NONE;
    nConsecutiveHardEpochs = 0;
    nLastHardEpoch = -1;
    nPendingFinalizedHeight = 0;
    hashPendingFinalized = 0;
}

void CFinalityTracker::CaptureFinalitySummary(
    CFinalitySummarySnapshot& snapshot) const
{
    AssertLockHeld(cs_finality);
    snapshot.nFinalizedHeight = nLastFinalizedHeight;
    snapshot.hashFinalized = hashLastFinalized;
    snapshot.nTier = nLastFinalityTier;
    snapshot.nConsecutiveHardEpochs = nConsecutiveHardEpochs;
    snapshot.nLastHardEpoch = nLastHardEpoch;
    snapshot.nPendingFinalizedHeight = nPendingFinalizedHeight;
    snapshot.hashPendingFinalized = hashPendingFinalized;
}

void CFinalityTracker::RestoreFinalitySummary(
    const CFinalitySummarySnapshot& snapshot)
{
    AssertLockHeld(cs_finality);
    nLastFinalizedHeight = snapshot.nFinalizedHeight;
    hashLastFinalized = snapshot.hashFinalized;
    nLastFinalityTier = snapshot.nTier;
    nConsecutiveHardEpochs = snapshot.nConsecutiveHardEpochs;
    nLastHardEpoch = snapshot.nLastHardEpoch;
    nPendingFinalizedHeight = snapshot.nPendingFinalizedHeight;
    hashPendingFinalized = snapshot.hashPendingFinalized;
}

bool CFinalityTracker::RecomputeFinalityStateFromEpoch(int nRequestedEpoch)
{
    AssertLockHeld(cs_finality);

    int nReplayFrom = nRequestedEpoch;
    if (nFinalitySummaryDirtyFromEpoch >= 0)
        nReplayFrom = std::min(nReplayFrom,
                               nFinalitySummaryDirtyFromEpoch);

    std::map<int, CFinalitySummarySnapshot>::iterator eraseFrom =
        mapFinalitySummaryAfterEpoch.lower_bound(nReplayFrom);
    if (eraseFrom == mapFinalitySummaryAfterEpoch.begin())
        ResetFinalitySummary();
    else
    {
        std::map<int, CFinalitySummarySnapshot>::iterator previous = eraseFrom;
        --previous;
        RestoreFinalitySummary(previous->second);
    }
    mapFinalitySummaryAfterEpoch.erase(eraseFrom,
                                       mapFinalitySummaryAfterEpoch.end());

    std::set<int> setEpochs;
    for (std::map<int, std::vector<CFinalityVote> >::const_iterator it =
             mapEpochVotes.lower_bound(nReplayFrom);
         it != mapEpochVotes.end(); ++it)
        setEpochs.insert(it->first);
    for (std::map<int, std::vector<CFinalityTallyCertificate> >::const_iterator it =
             mapEpochTallyCertificates.lower_bound(nReplayFrom);
         it != mapEpochTallyCertificates.end(); ++it)
        setEpochs.insert(it->first);

    for (std::set<int>::const_iterator it = setEpochs.begin();
         it != setEpochs.end(); ++it)
    {
        CheckFinalityThreshold(*it, false);
        CaptureFinalitySummary(mapFinalitySummaryAfterEpoch[*it]);
    }
    nFinalitySummaryDirtyFromEpoch = -1;
    return true;
}

bool CFinalityTracker::RebuildFinalityState()
{
    LOCK(cs_finality);

    // Finalization state must be a pure function of the connected votes and
    // certificates; re-merge the persisted carrier-backed set before replaying.
    if (!ReloadConnectedFinalityFromDB())
        return false;

    mapFinalitySummaryAfterEpoch.clear();
    int nFirstEpoch = std::numeric_limits<int>::max();
    if (!mapEpochVotes.empty())
        nFirstEpoch = std::min(nFirstEpoch, mapEpochVotes.begin()->first);
    if (!mapEpochTallyCertificates.empty())
        nFirstEpoch = std::min(nFirstEpoch,
                               mapEpochTallyCertificates.begin()->first);
    if (nFirstEpoch == std::numeric_limits<int>::max())
    {
        ResetFinalitySummary();
        nFinalitySummaryDirtyFromEpoch = -1;
        return true;
    }
    nFinalitySummaryDirtyFromEpoch = nFirstEpoch;
    return RecomputeFinalityStateFromEpoch(nFirstEpoch);
}

bool CFinalityTracker::ReloadConnectedFinalityFromDB()
{
    AssertLockHeld(cs_finality);

    CTxDB txdb("r");

    // The LevelDB stores hold only connected objects, so re-merge with
    // fRecordFinality=true as LoadVotes does. fCheck=false: the finalized-epoch
    // anchor is not yet rebuilt.
    std::map<uint256, CFinalityVote> mapVotes;
    if (!txdb.IterateFinalityVotes(mapVotes))
        return false;

    std::map<uint256, CFinalityTallyCertificate> mapCerts;
    if (!txdb.IterateFinalityTallyCertificates(mapCerts))
        return false;

    std::map<uint256, std::vector<uint256> > mapVoteBlocks;
    if (!txdb.IterateFinalityConnectedVoteBlocks(mapVoteBlocks))
        return false;
    std::map<uint256, CFinalityTallyShare> mapPersistedShares;
    if (!txdb.IterateFinalityTallyShares(mapPersistedShares))
        return false;
    std::map<uint256, std::vector<uint256> > mapShareBlocks;
    if (!txdb.IterateFinalityConnectedShareBlocks(mapShareBlocks))
        return false;
    std::map<uint256, std::vector<uint256> > mapCertBlocks;
    if (!txdb.IterateFinalityConnectedCertBlocks(mapCertBlocks))
        return false;

    std::set<uint256> setCanonicalBlocks;
    if (!mapVoteBlocks.empty() || !mapShareBlocks.empty() ||
        !mapCertBlocks.empty())
    {
        uint256 hashBest;
        if (!txdb.ReadHashBestChain(hashBest))
            return error("ReloadConnectedFinalityFromDB: best-chain pointer is missing; "
                         "-reindex/resync required");
        std::map<uint256, CBlockIndex*>::const_iterator itBest =
            mapBlockIndex.find(hashBest);
        if (itBest == mapBlockIndex.end() || itBest->second == NULL)
            return error("ReloadConnectedFinalityFromDB: best-chain block %s is missing; "
                         "-reindex/resync required",
                         hashBest.ToString().substr(0,20).c_str());
        for (const CBlockIndex* pindex = itBest->second; pindex != NULL;
             pindex = pindex->pprev)
        {
            if (!setCanonicalBlocks.insert(pindex->GetBlockHash()).second)
                return error("ReloadConnectedFinalityFromDB: cycle in persisted best chain; "
                             "-reindex/resync required");
        }
    }

    // Replay each recorded carrier through the connect-time decoder, or a paired but wrong
    // index becomes trusted after restart.
    const auto loadActiveCarrier = [&](const uint256& hashBlock,
                                       CBlock& activeOut,
                                       int& nHeightOut) -> bool {
        std::map<uint256, CBlockIndex*>::const_iterator mi =
            mapBlockIndex.find(hashBlock);
        if (!setCanonicalBlocks.count(hashBlock) ||
            mi == mapBlockIndex.end() || mi->second == NULL ||
            mi->second->nHeight < FORK_HEIGHT_DAG ||
            !mi->second->IsProofOfWork())
            return error("ReloadConnectedFinalityFromDB: carrier block %s is missing "
                         "from the post-DAG block index; -reindex/resync required",
                         hashBlock.ToString().substr(0,20).c_str());
        CBlock block;
        if (!block.ReadFromDisk(mi->second, true))
            return error("ReloadConnectedFinalityFromDB: carrier block %s cannot be read; "
                         "-reindex/resync required",
                         hashBlock.ToString().substr(0,20).c_str());
        // Finality carriers live only in vtx[0], identical in every DAG active view,
        // so decode the original coinbase without requiring the active-set marker.
        activeOut = block;
        nHeightOut = mi->second->nHeight;
        return true;
    };
    const auto sameCert = [](const CFinalityTallyCertificate& a,
                             const CFinalityTallyCertificate& b) -> bool {
        if (a.IsCanonicalEnvelope() != b.IsCanonicalEnvelope())
            return false;
        CDataStream sa(SER_DISK, CLIENT_VERSION);
        CDataStream sb(SER_DISK, CLIENT_VERSION);
        sa << a;
        sb << b;
        return sa.size() == sb.size() &&
               std::equal(sa.begin(), sa.end(), sb.begin());
    };
    const auto sameShare = [](const CFinalityTallyShare& a,
                              const CFinalityTallyShare& b) -> bool {
        CDataStream sa(SER_DISK, CLIENT_VERSION);
        CDataStream sb(SER_DISK, CLIENT_VERSION);
        sa << a;
        sb << b;
        return sa.size() == sb.size() &&
               std::equal(sa.begin(), sa.end(), sb.begin());
    };

    // Restore the per-block connected-carrier indexes so teardown and coverage rules
    // survive restart. setConnectedTallyShares comes from the share index, which also
    // covers shares not yet referenced by a connected cert.
    std::set<uint256> setReferencedVotes;
    for (const auto& pair : mapVoteBlocks)
    {
        CBlock activeBlock;
        int nCarrierHeight = -1;
        if (!loadActiveCarrier(pair.first, activeBlock, nCarrierHeight))
            return false;
        std::vector<CFinalityVote> vExtracted;
        FinalityEnvelopeDecodeResult failure = FINALITY_ENVELOPE_NO_MATCH;
        if (!ExtractFinalityVotesFromBlockForHeight(
                activeBlock, nCarrierHeight, vExtracted, &failure))
            return error("ReloadConnectedFinalityFromDB: vote carrier %s has an invalid "
                         "height-selected envelope (decode=%d); -reindex/resync required",
                         pair.first.ToString().substr(0,20).c_str(), (int)failure);
        std::vector<uint256> vExtractedNullifiers;
        for (std::vector<CFinalityVote>::const_iterator it = vExtracted.begin();
             it != vExtracted.end(); ++it)
            vExtractedNullifiers.push_back(it->nullifier);
        if (vExtractedNullifiers != pair.second)
            return error("ReloadConnectedFinalityFromDB: vote carrier %s index does not "
                         "match its active block; -reindex/resync required",
                         pair.first.ToString().substr(0,20).c_str());
        for (std::vector<uint256>::const_iterator it = pair.second.begin();
             it != pair.second.end(); ++it)
        {
            std::map<uint256, CFinalityVote>::const_iterator persisted =
                mapVotes.find(*it);
            if (persisted == mapVotes.end())
                return error("ReloadConnectedFinalityFromDB: vote carrier references "
                             "missing vote; -reindex/resync required");
            const size_t n = it - pair.second.begin();
            if (!FinalityVotesHaveSameSemanticIdentity(
                    vExtracted[n], persisted->second))
                return error("ReloadConnectedFinalityFromDB: vote carrier logical value/"
                             "provenance mismatch; -reindex/resync required");
            setReferencedVotes.insert(*it);
        }
    }
    if (setReferencedVotes.size() != mapVotes.size())
        return error("ReloadConnectedFinalityFromDB: unpaired vote/carrier records; "
                     "-reindex/resync required");

    std::set<uint256> setConnectedSharesNew = setConnectedTallyShares;
    for (const auto& pair : mapShareBlocks)
    {
        CBlock activeBlock;
        int nCarrierHeight = -1;
        if (!loadActiveCarrier(pair.first, activeBlock, nCarrierHeight))
            return false;
        const std::vector<CFinalityTallyShare> vExtracted =
            ExtractFinalityTallySharesFromBlock(activeBlock);
        std::vector<uint256> vExtractedHashes;
        for (std::vector<CFinalityTallyShare>::const_iterator it =
                 vExtracted.begin(); it != vExtracted.end(); ++it)
            vExtractedHashes.push_back(it->GetHash());
        if (vExtractedHashes != pair.second)
            return error("ReloadConnectedFinalityFromDB: tally-share carrier %s index "
                         "does not match its active block; -reindex/resync required",
                         pair.first.ToString().substr(0,20).c_str());
        for (std::vector<uint256>::const_iterator it = pair.second.begin();
             it != pair.second.end(); ++it)
        {
            std::map<uint256, CFinalityTallyShare>::const_iterator persisted =
                mapPersistedShares.find(*it);
            if (persisted == mapPersistedShares.end())
                return error("ReloadConnectedFinalityFromDB: share carrier references "
                             "missing share; -reindex/resync required");
            const size_t n = it - pair.second.begin();
            if (!sameShare(vExtracted[n], persisted->second))
                return error("ReloadConnectedFinalityFromDB: share carrier logical "
                             "value mismatch; -reindex/resync required");
            setConnectedSharesNew.insert(*it);
        }
    }

    std::set<uint256> setReferencedCerts;
    for (const auto& pair : mapCertBlocks)
    {
        CBlock activeBlock;
        int nCarrierHeight = -1;
        if (!loadActiveCarrier(pair.first, activeBlock, nCarrierHeight))
            return false;
        std::vector<CFinalityTallyCertificate> vExtracted;
        FinalityEnvelopeDecodeResult failure = FINALITY_ENVELOPE_NO_MATCH;
        if (!ExtractFinalityTallyCertificatesFromBlockForHeight(
                activeBlock, nCarrierHeight, vExtracted, &failure))
            return error("ReloadConnectedFinalityFromDB: certificate carrier %s has an "
                         "invalid height-selected envelope (decode=%d); -reindex/resync required",
                         pair.first.ToString().substr(0,20).c_str(), (int)failure);
        std::vector<uint256> vExtractedHashes;
        for (std::vector<CFinalityTallyCertificate>::const_iterator it =
                 vExtracted.begin(); it != vExtracted.end(); ++it)
            vExtractedHashes.push_back(it->GetHash());
        if (vExtractedHashes != pair.second)
            return error("ReloadConnectedFinalityFromDB: certificate carrier %s index "
                         "does not match its active block; -reindex/resync required",
                         pair.first.ToString().substr(0,20).c_str());
        for (std::vector<uint256>::const_iterator it = pair.second.begin();
             it != pair.second.end(); ++it)
        {
            std::map<uint256, CFinalityTallyCertificate>::const_iterator persisted =
                mapCerts.find(*it);
            if (persisted == mapCerts.end())
                return error("ReloadConnectedFinalityFromDB: certificate carrier references "
                             "missing certificate; -reindex/resync required");
            const size_t n = it - pair.second.begin();
            if (!sameCert(vExtracted[n], persisted->second))
                return error("ReloadConnectedFinalityFromDB: certificate carrier logical "
                             "value/provenance mismatch; -reindex/resync required");
            setReferencedCerts.insert(*it);
        }
    }
    if (setReferencedCerts.size() != mapCerts.size())
        return error("ReloadConnectedFinalityFromDB: unpaired certificate/carrier records; "
                     "-reindex/resync required");

    // Merge only after every persisted record has been tied back to its exact
    // active carrier.  A failed integrity check leaves no additional tracker
    // state synthesized from corrupt disk records.
    for (const auto& pair : mapVotes)
    {
        if (mapVoteHashByNullifier.count(pair.second.nullifier))
            continue;
        if (!AddVote(pair.second, false, true))
            return false;
    }
    for (const auto& pair : mapCerts)
    {
        if (mapConnectedTallyCertificates.count(pair.first))
            continue;
        if (!AddTallyCertificate(pair.second, false, true))
            return false;
    }
    mapBlockConnectedVoteNullifiers = mapVoteBlocks;
    mapBlockConnectedTallyShares = mapShareBlocks;
    mapBlockConnectedTallyCertificates = mapCertBlocks;
    setConnectedTallyShares.swap(setConnectedSharesNew);
    return true;
}

bool CFinalityTracker::RestoreCommittedStateAfterAbort()
{
    {
        LOCK(cs_finality);
        nLastFinalizedHeight = 0;
        hashLastFinalized = 0;
        nLastFinalityTier = FINALITY_NONE;
        nConsecutiveHardEpochs = 0;
        nLastHardEpoch = -1;
        nPendingFinalizedHeight = 0;
        hashPendingFinalized = 0;
        mapFinalitySummaryAfterEpoch.clear();
        nFinalitySummaryDirtyFromEpoch = -1;

        mapEpochVotes.clear();
        mapEpochVoteWeight.clear();
        mapVoteHashByNullifier.clear();
        mapPendingVotes.clear();
        mapConnectedVotes.clear();
        mapBlockConnectedVoteNullifiers.clear();
        mapNoteVotesByHash.clear();
        mapBlockConnectedNoteVotes.clear();
        mapEpochCountedNoteVotes.clear();
        mapEpochEquivocatedNoteVotes.clear();
        mapEpochEquivocatedVoteNullifiers.clear();
        mapPendingNoteVotes.clear();
        mapEpochVoters.clear();
        mapEpochTransparentVoteCount.clear();
        mapEpochPrivateVoteCount.clear();
        mapTallyShares.clear();
        setConnectedTallyShares.clear();
        mapTallyAggregatePartials.clear();
        mapTallyPartialBySource.clear();
        mapNoteTallyPartials.clear();
        mapNoteTallyPartialBySlot.clear();
        mapBlockConnectedTallyShares.clear();
        mapCandidateCerts.clear();
        mapCollectedCertSigs.clear();
        mapPendingTallyCertificates.clear();
        mapConnectedTallyCertificates.clear();
        mapConnectedTallyCertificateByContext.clear();
        mapEpochTallyCertificates.clear();
        mapBlockConnectedTallyCertificates.clear();
    }

    CTxDB txdb("r");
    if (!LoadVotes(txdb) || !LoadNoteVotes(txdb) || !LoadTallyShares(txdb) ||
        !LoadTallyCertificates(txdb))
        return error("RestoreCommittedStateAfterAbort: committed finality state could not "
                     "be reconstructed; restart with -reindex/resync");
    return true;
}

void CFinalityTracker::PruneOldEpochs(int nCurrentEpoch)
{
    LOCK(cs_finality);
    int nMinEpoch = nCurrentEpoch - 10;
    if (nMinEpoch < 0)
        nMinEpoch = 0;

    // Connected finality is consensus/reorg state: prune only relay/automation
    // objects with no block carrier.
    for (std::map<uint256, CFinalityVote>::iterator it =
             mapPendingVotes.begin(); it != mapPendingVotes.end(); )
    {
        if (it->second.nEpoch < nMinEpoch)
        {
            std::map<uint256, uint256>::iterator hit =
                mapVoteHashByNullifier.find(it->first);
            if (hit != mapVoteHashByNullifier.end() &&
                hit->second == it->second.GetHash() &&
                !mapConnectedVotes.count(it->first))
                mapVoteHashByNullifier.erase(hit);
            mapPendingVotes.erase(it++);
        }
        else
            ++it;
    }

    for (auto it = mapPendingNoteVotes.begin(); it != mapPendingNoteVotes.end(); )
    {
        if (it->second.nEpoch < nMinEpoch && !mapNoteVotesByHash.count(it->first))
            it = mapPendingNoteVotes.erase(it);
        else
            ++it;
    }

    for (auto it = mapEpochEquivocatedVoteNullifiers.begin();
         it != mapEpochEquivocatedVoteNullifiers.end(); )
    {
        if (it->first < nMinEpoch)
            it = mapEpochEquivocatedVoteNullifiers.erase(it);
        else
            ++it;
    }

    for (auto it = mapTallyShares.begin(); it != mapTallyShares.end(); )
    {
        if (it->second.nEpoch < nMinEpoch &&
            !setConnectedTallyShares.count(it->first))
        {
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

    for (std::map<uint256, CFinalityTallyCertificate>::iterator it =
             mapPendingTallyCertificates.begin();
         it != mapPendingTallyCertificates.end(); )
    {
        if (it->second.nEpoch < nMinEpoch)
            mapPendingTallyCertificates.erase(it++);
        else
            ++it;
    }
}


// ---------------------------------------------------------------------------
// P2P Message Processing
// ---------------------------------------------------------------------------

bool ProcessMessageFinality(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv)
{
    if (strCommand == "fvote" || strCommand == FINALITY_CANONICAL_VOTE_COMMAND)
    {
        const bool fCanonicalCommand =
            strCommand == FINALITY_CANONICAL_VOTE_COMMAND;
        if (fCanonicalCommand != CanonicalFinalityTrafficAtTip())
            return false;

        CFinalityVote vote;
        if (fCanonicalCommand)
        {
            CCanonicalFinalityVoteEnvelope envelope;
            try {
                vRecv >> envelope;
            } catch (const std::exception&) {
                return false;
            }
            if (!vRecv.empty() || !envelope.ToLogical(vote))
                return false;
        }
        else
        {
            vRecv >> vote;
            vote.fCanonicalEnvelope = false;
        }

        if (vote.IsPrivate() &&
            LegacyPrivateFinalityTrafficDisabledAtTip())
            return false;

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
                PushFinalityVoteMessage(pnode, vote);
            }
        }

        return true;
    }
    else if (strCommand == FINALITY_NOTE_VOTE_COMMAND)
    {
        if (!IsIV5NoteVoteActiveAtHeight(nBestHeight + 1))
            return false;
        if (!NoteVotePeerBudgetAllows(pfrom->GetId(), GetTime()))
            return false;

        CNoteFinalityVote vote;
        try {
            vRecv >> vote;
        } catch (const std::exception&) {
            return false;
        }
        if (!vRecv.empty())
            return false;

        const uint256 hashVote = vote.GetHash();
        if (g_finalityTracker.HaveNoteVote(hashVote))
            return true;

        // The cache exists to stop a rejected envelope being re-proved once per peer;
        // an accepted one is already short-circuited by HaveNoteVote above.
        bool fCachedValid = false;
        if (NoteVoteVerifyCacheLookup(hashVote, fCachedValid) && !fCachedValid)
            return false;

        // Cheap structure first: the proofs behind it are the expensive part.
        if (!vote.IsValidBasic())
        {
            NoteVoteVerifyCacheStore(hashVote, false);
            return false;
        }
        int nCurrentEpoch = 0;
        CBlockIndex* pBest = pindexBest;
        if (pBest)
            nCurrentEpoch = GetEpochForHeight(pBest->nHeight);
        if (vote.nEpoch > nCurrentEpoch + 1 || vote.nEpoch + 2 < nCurrentEpoch)
            return false;

        CTxDB txdb("r");
        std::string strError;
        FinalityResult noteResult = FINALITY_RESULT_INVALID;
        const bool fValid =
            g_finalityTracker.AddPendingNoteVote(vote, txdb, &strError, &noteResult);
        if (!fValid && noteResult == FINALITY_RESULT_LOCAL_STATE)
        {
            // Nothing here says the vote is bad; this node just cannot check it yet,
            // normally because the block it names is still a getdata behind its header.
            // Caching that as a refusal would burn the vote for good: a note vote is
            // single-shot, so its producer will never send another.
            g_finalityTracker.DeferNoteVoteForUnknownBlock(vote);
            if (fDebug)
                printf("ProcessMessageFinality: holding note vote from peer %s: %s\n",
                       pfrom->addr.ToString().c_str(), strError.c_str());
            return true;
        }
        NoteVoteVerifyCacheStore(hashVote, fValid);
        if (!fValid)
        {
            if (fDebug)
                printf("ProcessMessageFinality: rejected note vote from peer %s: %s\n",
                       pfrom->addr.ToString().c_str(), strError.c_str());
            return false;
        }

        LOCK(cs_vNodes);
        for (CNode* pnode : vNodes)
        {
            if (pnode == pfrom)
                continue;
            pnode->PushMessage(FINALITY_NOTE_VOTE_COMMAND, vote);
        }
        return true;
    }
    else if (strCommand == "ftshare")
    {
        if (LegacyPrivateFinalityTrafficDisabledAtTip())
            return false;
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
        if (LegacyPrivateFinalityTrafficDisabledAtTip())
            return false;
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
    else if (strCommand == FINALITY_NOTE_TALLY_PARTIAL_COMMAND)
    {
        if (!NoteFinalityTrafficActiveAtTip())
            return false;

        CNoteTallyAggregatePartial partial;
        try {
            vRecv >> partial;
        } catch (const std::exception&) {
            return false;
        }
        if (!vRecv.empty())
            return false;

        if (g_finalityTracker.AddNoteTallyAggregatePartial(partial))
        {
            LOCK(cs_vNodes);
            for (CNode* pnode : vNodes)
            {
                if (pnode == pfrom)
                    continue;
                pnode->PushMessage(FINALITY_NOTE_TALLY_PARTIAL_COMMAND, partial);
            }
        }

        return true;
    }
    else if (strCommand == "ftcert" ||
             strCommand == FINALITY_CANONICAL_TALLY_CERT_COMMAND)
    {
        const bool fCanonicalCommand =
            strCommand == FINALITY_CANONICAL_TALLY_CERT_COMMAND;
        if (fCanonicalCommand != CanonicalFinalityTrafficAtTip())
            return false;

        CFinalityTallyCertificate cert;
        if (fCanonicalCommand)
        {
            CCanonicalFinalityTallyCertificateEnvelope envelope;
            try {
                vRecv >> envelope;
            } catch (const std::exception&) {
                return false;
            }
            if (!vRecv.empty() || !envelope.ToLogical(cert))
                return false;
        }
        else
        {
            vRecv >> cert;
            cert.fCanonicalEnvelope = false;
        }

        if (cert.HasPrivateWeight() &&
            LegacyPrivateFinalityTrafficDisabledAtTip())
            return false;

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
                PushFinalityTallyCertificateMessage(pnode, cert);
            }
        }

        return true;
    }
    else if (strCommand == "ftcsig")
    {
        // 2c-4b: a committee member's signature over a candidate certificate.
        CFinalityCertSignature msg;
        vRecv >> msg;

        // A v4 note candidate is not the retired legacy-private path, and its whole
        // authorization is the M-of-N signature collected here, so it rides its own gate.
        if (msg.candidate.HasNoteWeight()
                ? !NoteFinalityTrafficActiveAtTip()
                : LegacyPrivateFinalityTrafficDisabledAtTip())
            return false;

        // Canonical-envelope provenance is runtime state the certificate serializer
        // deliberately drops, and a v4 certificate exists only at heights where every
        // certificate is a canonical-envelope one. Without restoring it here the
        // collected signatures would assemble an object the miner's pending filter
        // refuses and no block ever carries.
        if (msg.candidate.HasNoteWeight() &&
            IsBoundaryAActiveAtHeight(msg.candidate.nHeight))
            msg.candidate.MarkCanonicalEnvelope();

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
            // co-sign it and relay our signature (drives the M-of-N collection). This
            // is also the only thing that makes a note certificate assemblable at all:
            // its range proofs are entropy-bearing, so two members never produce the
            // same candidate and the set has to converge on one member's.
            CFinalityTallyConfig cfg = GetFinalityTallyConfig();
            CKey memberKey;
            int nLocalSeat = cfg.nLocalCommitteeIndex;
            if (msg.candidate.HasNoteWeight())
            {
                CFinalityTallyConfig noteCfg;
                CKey noteKey;
                int nNoteSeat = -1;
                nLocalSeat =
                    (GetNoteVoteCommitteeConfig(msg.candidate.nEpoch, noteCfg) &&
                     NoteTallyLocalCommitteeSeat(noteCfg, noteKey, nNoteSeat))
                        ? nNoteSeat : -1;
            }
            if (nLocalSeat >= 0 && GetFinalityTallyPrivateKey(memberKey))
            {
                CFinalityCertSignature mine;
                mine.candidate = msg.candidate;
                mine.nSignerIndex = (uint16_t)nLocalSeat;
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
            {
                LogAssembledNoteCertificate(assembled);
                RelayFinalityTallyCertificate(assembled);
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

        // Connected votes, then the relayed ones no block has carried yet: a peer that
        // restarted inside an inclusion window lost its pending set, and if it is the
        // only miner those votes reach no block unless it asks for them again.
        std::vector<CFinalityVote> votes = g_finalityTracker.GetEpochVotes(nEpoch);
        std::set<uint256> setServed;
        for (const CFinalityVote& vote : votes)
        {
            if (vote.IsPrivate() &&
                LegacyPrivateFinalityTrafficDisabledAtTip())
                continue;
            setServed.insert(vote.nullifier);
            PushFinalityVoteMessage(pfrom, vote);
        }
        std::vector<CFinalityVote> pending = g_finalityTracker.GetPendingVotes(nEpoch);
        for (const CFinalityVote& vote : pending)
        {
            if (setServed.count(vote.nullifier))
                continue;
            if (vote.IsPrivate() &&
                LegacyPrivateFinalityTrafficDisabledAtTip())
                continue;
            PushFinalityVoteMessage(pfrom, vote);
        }
        if (!LegacyPrivateFinalityTrafficDisabledAtTip())
        {
            std::vector<CFinalityTallyShare> shares =
                g_finalityTracker.GetEpochTallyShares(nEpoch);
            for (const CFinalityTallyShare& share : shares)
                pfrom->PushMessage("ftshare", share);
            std::vector<CFinalityTallyAggregatePartial> partials =
                g_finalityTracker.GetEpochTallyAggregatePartials(nEpoch);
            for (const CFinalityTallyAggregatePartial& partial : partials)
                pfrom->PushMessage("ftpart", partial);
        }
        if (NoteFinalityTrafficActiveAtTip())
        {
            std::vector<CNoteTallyAggregatePartial> noteParts =
                g_finalityTracker.GetEpochNoteTallyPartials(nEpoch);
            for (const CNoteTallyAggregatePartial& partial : noteParts)
                pfrom->PushMessage(FINALITY_NOTE_TALLY_PARTIAL_COMMAND, partial);
        }
        std::vector<CFinalityTallyCertificate> certs = g_finalityTracker.GetEpochTallyCertificates(nEpoch);
        for (const CFinalityTallyCertificate& cert : certs)
        {
            if (cert.HasPrivateWeight() &&
                LegacyPrivateFinalityTrafficDisabledAtTip())
                continue;
            PushFinalityTallyCertificateMessage(pfrom, cert);
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

// --- F2 note tally automation -----------------------------------------------------
//
// Everything below is PRODUCTION side. Partials, complaint gossip and candidate
// certificates are node-local relay state and never reach a validation decision: the
// only thing consensus reads is the certificate that lands in a block, and every input
// it re-derives (counted note votes, canonical committee, transparent weights) comes
// from the connected chain. A producer working from a stale view therefore builds a
// certificate that fails the connect-time recompute and stays pending. That is a
// liveness hiccup, not a chain split, and it must stay that way.
static bool ProcessNoteTallyCommitteeEpoch(int nEpoch)
{
    if (nEpoch < 0)
        return false;

    CFinalityTallyConfig config;
    if (!GetNoteVoteCommitteeConfig(nEpoch, config))
        return false;
    CKey keyLocal;
    int nLocalSeat = -1;
    if (!NoteTallyLocalCommitteeSeat(config, keyLocal, nLocalSeat))
        return false;
    config.nLocalCommitteeIndex = nLocalSeat;

    // The COUNTED view, never the raw carried votes: an equivocated tag appears twice
    // among the carried set and every coverage routine hard-fails on a repeated tag, so
    // feeding the raw set would let one anonymous equivocator make the epoch permanently
    // uncertifiable. The counted view holds one identity per tag by construction.
    const std::vector<CNoteFinalityVote> vCounted =
        g_finalityTracker.GetCountedEpochNoteVotes(nEpoch);
    if (vCounted.empty())
        return false;

    // The winner and both transparent weights are the canonical transparent result,
    // which every member derives from the connected vote set without opening anything.
    // A note tally only boosts that winner's tier; it never selects a different winner.
    CFinalityTallyCertificate skeleton;
    std::string strError;
    const std::vector<CFinalityVote> vConnectedTransparent =
        g_finalityTracker.GetConnectedEpochVotes(nEpoch);
    bool fNoteOnly = false;
    // The note leg supplies voters too. Counting them here is what lets an epoch with
    // one transparent voter and the rest private build a skeleton: the transparent leg
    // alone is under the floor, the epoch is not. The winner still comes from the
    // transparent votes, so the validator rebuilds exactly this.
    size_t nNoteVoters = 0;
    for (size_t i = 0; i < vCounted.size(); i++)
        if (vCounted[i].nEpoch == nEpoch)
            nNoteVoters++;
    if (!BuildCanonicalTransparentFinalityCertificate(vConnectedTransparent, skeleton,
                                                      &strError, nNoteVoters))
    {
        // An epoch with transparent votes that still has no canonical result is a
        // transparent problem (too few voters, no decision); it keeps the old
        // behaviour exactly. Only an epoch with NO transparent vote at all falls
        // through to the note leg, which is the case that had no producer.
        if (!vConnectedTransparent.empty())
        {
            if (fDebug)
                printf("ProcessNoteTallyCommitteeEpoch: epoch %d has no transparent "
                       "skeleton: %s\n", nEpoch, strError.c_str());
            return false;
        }
        if (!BuildNoteOnlyFinalitySkeleton(nEpoch, vCounted, skeleton, &strError))
        {
            if (fDebug)
                printf("ProcessNoteTallyCommitteeEpoch: epoch %d has no note-only "
                       "skeleton: %s\n", nEpoch, strError.c_str());
            return false;
        }
        fNoteOnly = true;
    }
    const uint256 hashWinner = skeleton.hashBlock;

    std::map<uint256, const CNoteFinalityVote*> mapCountedByTag;
    for (size_t i = 0; i < vCounted.size(); i++)
        mapCountedByTag[vCounted[i].GetVoteTag()] = &vCounted[i];

    std::vector<CNoteTallyAggregatePartial> vPartials;
    {
        const std::vector<CNoteTallyAggregatePartial> vAll =
            g_finalityTracker.GetEpochNoteTallyPartials(nEpoch);
        for (size_t i = 0; i < vAll.size(); i++)
        {
            if (vAll[i].committeeSetHash == config.committeeSetHash &&
                vAll[i].hashWinner == hashWinner)
                vPartials.push_back(vAll[i]);
        }
    }

    // Convergence: complaints ride inside partials, so the covered set is the counted
    // set minus the union of every valid complaint anyone has published. Complaints only
    // ever shrink the set, so this terminates.
    std::map<uint256, CNoteVoteComplaint> mapComplaints;
    for (size_t i = 0; i < vPartials.size(); i++)
    {
        for (size_t j = 0; j < vPartials[i].vComplaints.size(); j++)
        {
            const CNoteVoteComplaint& complaint = vPartials[i].vComplaints[j];
            if (mapComplaints.count(complaint.voteTag))
                continue;
            std::map<uint256, const CNoteFinalityVote*>::const_iterator itVote =
                mapCountedByTag.find(complaint.voteTag);
            if (itVote == mapCountedByTag.end())
                continue;
            if (!CheckNoteVoteComplaint(complaint, *itVote->second, config, NULL))
                continue;
            mapComplaints[complaint.voteTag] = complaint;
        }
    }

    // Re-running the pass over the reduced set is what makes this member's summed
    // evaluations agree with everyone else's about which votes they cover. It is cheap:
    // one symmetric decryption per vote.
    std::vector<const CNoteFinalityVote*> vInput;
    for (std::map<uint256, const CNoteFinalityVote*>::const_iterator it =
             mapCountedByTag.begin(); it != mapCountedByTag.end(); ++it)
    {
        if (!mapComplaints.count(it->first))
            vInput.push_back(it->second);
    }
    if (vInput.empty())
        return false;

    CNoteTallyCommitteePass pass;
    if (!RunNoteTallyCommitteePass(vInput, hashWinner, config, keyLocal, nLocalSeat,
                                   pass, &strError))
    {
        if (fDebug)
            printf("ProcessNoteTallyCommitteeEpoch: epoch %d committee pass failed: %s\n",
                   nEpoch, strError.c_str());
        return false;
    }
    // This member's own complaints join the union. The pass already excluded the votes
    // they name from vAcceptedTags, so the accepted set is already the covered set.
    for (size_t i = 0; i < pass.vComplaints.size(); i++)
        mapComplaints[pass.vComplaints[i].voteTag] = pass.vComplaints[i];

    std::vector<uint256> vCoveredTags = pass.vAcceptedTags;
    std::sort(vCoveredTags.begin(), vCoveredTags.end());
    if (vCoveredTags.empty())
        return false;
    // The floor IsValidBasic applies is on the two legs together, and complaints can
    // shrink the covered set below the counted set the skeleton was built against.
    // Re-check it on the sets that actually go into the certificate, here rather than
    // after the proving run, so no candidate the validator would refuse is ever emitted.
    if (skeleton.vVoteNullifiers.size() + vCoveredTags.size() <
        (size_t)FINALITY_MIN_VOTERS)
        return false;

    bool fDidWork = false;

    // Publish this member's partial for the covered set it just summed. The slot folds
    // the covered set in, so a re-run over a shrunken set is a new slot rather than a
    // suppressed duplicate.
    static std::set<uint256> setProducedNotePartialSlots;
    bool fHaveLocalPartial = false;
    for (size_t i = 0; i < vPartials.size(); i++)
    {
        if (vPartials[i].nSourceIndex == nLocalSeat &&
            vPartials[i].vAcceptedTags == vCoveredTags)
        {
            fHaveLocalPartial = true;
            break;
        }
    }
    if (!fHaveLocalPartial)
    {
        CNoteTallyAggregatePartial mine;
        mine.nEpoch = nEpoch;
        mine.committeeSetHash = config.committeeSetHash;
        mine.hashWinner = hashWinner;
        mine.nSourceIndex = nLocalSeat;
        if (BuildEncryptedNoteTallyAggregatePartial(mine, pass, config, keyLocal,
                                                    &strError))
        {
            const uint256 slot = mine.GetSourceSlot();
            if (!setProducedNotePartialSlots.count(slot) &&
                g_finalityTracker.AddNoteTallyAggregatePartial(mine))
            {
                setProducedNotePartialSlots.insert(slot);
                vPartials.push_back(mine);
                RelayNoteTallyAggregatePartial(mine);
                fDidWork = true;
            }
        }
        else if (fDebug)
        {
            printf("ProcessNoteTallyCommitteeEpoch: epoch %d partial not built: %s\n",
                   nEpoch, strError.c_str());
        }
    }

    // Only partials that agree on the final covered set can be interpolated together:
    // two members summing different sets evaluate different polynomials.
    std::vector<const CNoteFinalityVote*> vCovered;
    bool fWinnerHasNoteVotes = false;
    for (size_t i = 0; i < vCoveredTags.size(); i++)
    {
        const CNoteFinalityVote* pvote = mapCountedByTag[vCoveredTags[i]];
        vCovered.push_back(pvote);
        if (pvote->hashBlock == hashWinner)
            fWinnerHasNoteVotes = true;
    }

    std::vector<CNoteTallyPlainShare> vActiveShares;
    std::vector<CNoteTallyPlainShare> vWinningShares;
    std::set<int> setSeenX;
    for (size_t i = 0; i < vPartials.size(); i++)
    {
        if (vPartials[i].vAcceptedTags != vCoveredTags)
            continue;
        CNoteTallyPlainShare active, winning;
        bool fHaveActive = false;
        bool fHaveWinning = false;
        if (!DecryptNoteTallyAggregatePartialForRecipient(vPartials[i], config, keyLocal,
                                                          nLocalSeat, active, fHaveActive,
                                                          winning, fHaveWinning))
            continue;
        if (!fHaveActive || fHaveWinning != fWinnerHasNoteVotes)
            continue;
        if (active.nX <= 0 || !setSeenX.insert(active.nX).second)
            continue;
        vActiveShares.push_back(active);
        if (fHaveWinning)
            vWinningShares.push_back(winning);
        if ((int)vActiveShares.size() >= config.nThresholdM)
            break;
    }
    if ((int)vActiveShares.size() < config.nThresholdM)
        return fDidWork;

    // Both aggregate points come from the covered votes' own C~, exactly as the
    // validator recomputes them; the interpolation is only accepted if it opens them.
    PrivacyVNextDigest activePoint;
    PrivacyVNextDigest winningPoint;
    PrivacyVNextDigest rewardPoint;
    activePoint.fill(0);
    winningPoint.fill(0);
    rewardPoint.fill(0);
    if (!DeriveNoteTallyAggregates(vCovered, hashWinner, activePoint, winningPoint,
                                   rewardPoint, &strError))
        return fDidWork;

    int64_t nPrivateActive = 0;
    int64_t nPrivateReward = 0;
    uint256 activeBlind = 0;
    uint256 activeRewardBlind = 0;
    if (!OpenNoteTallyAggregate(vActiveShares, config.nThresholdM, activePoint, rewardPoint,
                                nPrivateActive, activeBlind, nPrivateReward,
                                activeRewardBlind, &strError))
    {
        if (fDebug)
            printf("ProcessNoteTallyCommitteeEpoch: epoch %d active aggregate did not "
                   "open: %s\n", nEpoch, strError.c_str());
        return fDidWork;
    }

    int64_t nPrivateWinning = 0;
    uint256 winningBlind = 0;
    if (fWinnerHasNoteVotes)
    {
        // The winning subset's reward aggregate is over the same subset, which is not the
        // set anything is paid over; derive it here so the strict open has a point to
        // check against rather than weakening the open for one caller.
        std::vector<const CNoteFinalityVote*> vWinnersOnly;
        for (size_t i = 0; i < vCovered.size(); i++)
            if (vCovered[i]->hashBlock == hashWinner)
                vWinnersOnly.push_back(vCovered[i]);
        PrivacyVNextDigest winningActive;
        PrivacyVNextDigest winningWinning;
        PrivacyVNextDigest winningReward;
        winningActive.fill(0);
        winningWinning.fill(0);
        winningReward.fill(0);
        if (!DeriveNoteTallyAggregates(vWinnersOnly, hashWinner, winningActive,
                                       winningWinning, winningReward, &strError))
            return fDidWork;

        int64_t nWinningReward = 0;
        uint256 winningRewardBlind = 0;
        if (!OpenNoteTallyAggregate(vWinningShares, config.nThresholdM, winningPoint,
                                    winningReward, nPrivateWinning, winningBlind,
                                    nWinningReward, winningRewardBlind, &strError))
        {
            if (fDebug)
                printf("ProcessNoteTallyCommitteeEpoch: epoch %d winning aggregate did "
                       "not open: %s\n", nEpoch, strError.c_str());
            return fDidWork;
        }
    }

    if (nPrivateActive < 0 || nPrivateWinning < 0 ||
        skeleton.nTransparentActiveWeight > MAX_MONEY - nPrivateActive ||
        skeleton.nTransparentWinningWeight > MAX_MONEY - nPrivateWinning)
        return fDidWork;
    const int64_t nTotalActive = skeleton.nTransparentActiveWeight + nPrivateActive;
    const int64_t nTotalWinning = skeleton.nTransparentWinningWeight + nPrivateWinning;
    const FinalityTier tier = FinalityDetermineTier(nTotalActive, nTotalWinning);
    if (tier == FINALITY_NONE)
        return fDidWork;
    // A note-only certificate names a winner nothing rebuilds, so consensus only takes
    // one whose share is exclusive. Mirror that floor here: a TENTATIVE candidate would
    // be proved, signed, relayed and then rejected at connect.
    if (fNoteOnly && tier < FINALITY_SOFT)
        return fDidWork;

    PrivacyVNextDigest entropy;
    {
        const uint256 hashEntropy = GetRandHash();
        memcpy(&entropy[0], hashEntropy.begin(), entropy.size());
    }
    CNoteTallyTierProofs proofs;
    if (!BuildNoteTallyTierProofs((int)tier, nPrivateActive, activeBlind, nPrivateWinning,
                                  winningBlind, skeleton.nTransparentActiveWeight,
                                  skeleton.nTransparentWinningWeight, entropy, proofs,
                                  &strError))
    {
        if (fDebug)
            printf("ProcessNoteTallyCommitteeEpoch: epoch %d tier proofs failed: %s\n",
                   nEpoch, strError.c_str());
        return fDidWork;
    }

    CFinalityTallyCertificate cert = skeleton;
    cert.nVersion = FINALITY_NOTE_CERT_VERSION;
    cert.committeeSetHash = config.committeeSetHash;
    cert.nTier = (int)tier;
    cert.vNoteVoteTags = vCoveredTags;
    cert.vNoteComplaints.clear();
    for (std::map<uint256, CNoteVoteComplaint>::const_iterator it = mapComplaints.begin();
         it != mapComplaints.end(); ++it)
        cert.vNoteComplaints.push_back(it->second);
    cert.noteTierProofs = proofs;
    cert.vSignerIndexes.clear();
    cert.vSignerSigs.clear();
    if (!cert.IsValidBasic(&strError))
    {
        if (fDebug)
            printf("ProcessNoteTallyCommitteeEpoch: epoch %d certificate is invalid: %s\n",
                   nEpoch, strError.c_str());
        return fDidWork;
    }

    static std::set<uint256> setProducedNoteCertContexts;
    const uint256 hashContext = FinalityCertificateAutomationContextHash(cert);
    if (setProducedNoteCertContexts.count(hashContext))
        return fDidWork;

    CFinalityCertSignature sigMsg;
    sigMsg.candidate = cert;
    sigMsg.nSignerIndex = (uint16_t)nLocalSeat;
    if (!keyLocal.Sign(cert.GetSignatureDigest(), sigMsg.vchSig) || sigMsg.vchSig.empty())
        return fDidWork;

    CTxDB txdb("r");
    CFinalityTallyCertificate assembled;
    bool fAssembled = false;
    if (!g_finalityTracker.AddCertSignature(sigMsg, txdb, &assembled, &fAssembled,
                                            &strError) && fDebug)
        printf("ProcessNoteTallyCommitteeEpoch: epoch %d candidate refused: %s\n",
               nEpoch, strError.c_str());
    RelayFinalityCertSignature(sigMsg);
    setProducedNoteCertContexts.insert(hashContext);
    if (fDebug)
        printf("ProcessNoteTallyCommitteeEpoch: epoch %d tier=%d covered=%u "
               "complaints=%u note_active=%s note_winning=%s transparent_active=%s "
               "transparent_winning=%s reward=%s assembled=%d\n",
               nEpoch, (int)tier, (unsigned int)vCoveredTags.size(),
               (unsigned int)cert.vNoteComplaints.size(),
               FormatMoney(nPrivateActive).c_str(),
               FormatMoney(nPrivateWinning).c_str(),
               FormatMoney(skeleton.nTransparentActiveWeight).c_str(),
               FormatMoney(skeleton.nTransparentWinningWeight).c_str(),
               FormatMoney(nPrivateReward).c_str(), fAssembled ? 1 : 0);

    if (fAssembled && g_finalityTracker.AddTallyCertificate(assembled))
    {
        LogAssembledNoteCertificate(assembled);
        RelayFinalityTallyCertificate(assembled);
    }
    return true;
}

bool ProcessFinalityTallyCommittee()
{
    // Called from the staking loop and the finality voter; one writer at a time. A cycle that
    // finds the pass running waits for the next one.
    static CCriticalSection cs_tallyAutomation;
    TRY_LOCK(cs_tallyAutomation, lockAutomation);
    if (!lockAutomation)
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

    // At A-1 the next candidate requires the new domain: build a transparent
    // certificate from the frozen connected vote set, and publish it only after
    // construction and validation both succeed.
    if (UseCanonicalFinalityTrafficForTip(nTipHeight))
    {
        const auto produce = [](int nEpoch) -> bool {
            CFinalityTallyCertificate cert;
            std::string strError;
            if (!BuildCanonicalTransparentFinalityCertificate(
                    g_finalityTracker.GetConnectedEpochVotes(nEpoch), cert,
                    &strError))
            {
                if (fDebug && !strError.empty())
                    printf("ProcessFinalityTallyCommittee: canonical epoch %d not ready: %s\n",
                           nEpoch, strError.c_str());
                return false;
            }
            if (!g_finalityTracker.AddTallyCertificate(cert))
                return false;
            RelayFinalityTallyCertificate(cert);
            return true;
        };

        bool fDidWork = false;
        if (nCurrentEpoch > 0)
            fDidWork |= produce(nCurrentEpoch - 1);
        const bool fCurrentWindowClosed =
            IsFinalityVoteWindowClosedForTip(nCurrentEpoch, nTipHeight);
        if (fCurrentWindowClosed)
            fDidWork |= produce(nCurrentEpoch);

        // F2 note tally, on the same freeze points as the transparent pass and the
        // reward settlement: the previous epoch's inclusion window is a whole epoch
        // behind, and the current one is only tallied once R1 guarantees no further
        // epoch-E note vote can connect. Before that the counted set still grows and
        // any certificate would fail the connect-time coverage rule.
        if (IsIV5NoteVoteActiveAtHeight(nTipHeight + 1))
        {
            if (nCurrentEpoch > 0)
                fDidWork |= ProcessNoteTallyCommitteeEpoch(nCurrentEpoch - 1);
            if (fCurrentWindowClosed)
                fDidWork |= ProcessNoteTallyCommitteeEpoch(nCurrentEpoch);
        }
        return fDidWork;
    }

    if (LegacyPrivateFinalityTrafficDisabledAtTip())
        return false;
    CFinalityTallyConfig config = GetFinalityTallyConfig();
    if (!config.CanProduceCertificates())
        return false;

    CKey keyLocal;
    if (!GetFinalityTallyPrivateKey(keyLocal))
        return false;

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
    bool fCurrentWindowClosed =
        IsFinalityVoteWindowClosedForTip(nCurrentEpoch, nTipHeight);
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
// Vote scheduling
// ---------------------------------------------------------------------------

static CFinalityVoteSchedule g_finalityVoteSchedule;
static boost::mutex g_mutexFinalityVoteWake;
static boost::condition_variable g_condFinalityVoteWake;
// Edge-triggered and consumed by the waiter; a level would spin for the rest of the epoch.
static bool g_fFinalityVoteWakePending = false;
// Sticky, set once by the shutdown path under the same mutex. Unlike fShutdown
// it is read under that mutex, so a waiter cannot miss it and re-enter the wait.
static bool g_fFinalityVoteStop = false;

CFinalityVoteSchedule& GetFinalityVoteSchedule()
{
    return g_finalityVoteSchedule;
}

void NotifyFinalityTipChanged(int nHeight)
{
    if (nHeight < FORK_HEIGHT_FINALITY)
        return;

    int nEpoch = GetEpochForHeight(nHeight);
    int nBoundary = GetEpochBoundaryHeight(nEpoch, nHeight);

    bool fWake = false;
    {
        boost::unique_lock<boost::mutex> lock(g_mutexFinalityVoteWake);
        if (g_finalityVoteSchedule.OnTipChanged(nHeight, nEpoch, nBoundary,
                                                GetFinalityVoteProducerWindow(nHeight),
                                                GetFinalityVoteEmitOffset(nHeight)))
        {
            g_fFinalityVoteWakePending = true;
            fWake = true;
        }
    }
    if (fWake)
        g_condFinalityVoteWake.notify_all();
}

void WaitForFinalityVoteWork(int64_t nTimeoutMs)
{
    boost::unique_lock<boost::mutex> lock(g_mutexFinalityVoteWake);
    // Never wait once shutdown is latched: the static condition variable would be destroyed
    // under the waiter and boost aborts.
    if (g_fFinalityVoteStop || g_fFinalityVoteWakePending)
    {
        g_fFinalityVoteWakePending = false;
        return;
    }
    g_condFinalityVoteWake.timed_wait(lock,
        boost::posix_time::milliseconds(nTimeoutMs));
    g_fFinalityVoteWakePending = false;
}

bool FinalityVoterShouldStop()
{
    boost::unique_lock<boost::mutex> lock(g_mutexFinalityVoteWake);
    return g_fFinalityVoteStop;
}

void StopFinalityVoter()
{
    {
        boost::unique_lock<boost::mutex> lock(g_mutexFinalityVoteWake);
        g_fFinalityVoteStop = true;
    }
    // Both waiters on this variable: the voter loop, and post-DAG the staking loop.
    g_condFinalityVoteWake.notify_all();

    // Called before Finalise() takes cs_main, so a pass already inside cs_main
    // can finish and reach the stop check at the top of its loop.
    int64_t nStart = GetTimeMillis();
    while (vnThreadsRunning[THREAD_FINALITY_VOTER] > 0)
    {
        if (GetTimeMillis() - nStart > FINALITY_VOTER_STOP_TIMEOUT_MS)
        {
            printf("StopFinalityVoter : ThreadFinalityVoter still running after "
                   "%d ms\n", (int)FINALITY_VOTER_STOP_TIMEOUT_MS);
            return;
        }
        MilliSleep(20);
    }
}

FinalityVoteClaim ClaimFinalityVote(int nTipHeight, int& nEpochOut)
{
    boost::unique_lock<boost::mutex> lock(g_mutexFinalityVoteWake);
    return g_finalityVoteSchedule.Claim(nTipHeight,
                                        GetFinalityVoteProducerWindow(nTipHeight),
                                        FINALITY_VOTE_ATTEMPTS_PER_EPOCH,
                                        nEpochOut,
                                        GetFinalityVoteEmitOffset(nTipHeight));
}

void ReleaseFinalityVote(int nEpoch, bool fProduced)
{
    boost::unique_lock<boost::mutex> lock(g_mutexFinalityVoteWake);
    g_finalityVoteSchedule.Release(nEpoch, fProduced);
}

// ---------------------------------------------------------------------------
// Finality Voter Thread
// ---------------------------------------------------------------------------

// Reconsider note votes that arrived ahead of the block they name, once that block is
// here. Run on the voter loop rather than from the connect path: re-checking a note
// vote verifies its proofs, which is far too much work to do while cs_main is held for
// a block, and the inclusion window is 24 blocks against a 1s poll.
static void ProcessDeferredNoteVotes(int nCurrentHeight)
{
    std::vector<uint256> vBlocks = g_finalityTracker.GetDeferredNoteVoteBlockHashes();
    if (vBlocks.empty())
        return;

    std::set<uint256> setArrived;
    {
        LOCK(cs_main);
        for (const uint256& hashBlock : vBlocks)
            if (mapBlockIndex.count(hashBlock))
                setArrived.insert(hashBlock);
    }

    std::vector<CNoteFinalityVote> vReady = g_finalityTracker.TakeDeferredNoteVotes(
        setArrived, GetEpochForHeight(nCurrentHeight));
    if (vReady.empty())
        return;

    CTxDB txdb("r");
    for (const CNoteFinalityVote& vote : vReady)
    {
        std::string strError;
        FinalityResult result = FINALITY_RESULT_INVALID;
        if (!g_finalityTracker.AddPendingNoteVote(vote, txdb, &strError, &result))
        {
            // Dropped, not re-held: the block it was waiting on is here, so any
            // remaining local-state failure is a node-level fault that re-holding
            // would only turn into a re-verification loop.
            if (fDebug)
                printf("ProcessDeferredNoteVotes: dropped a held note vote: %s\n",
                       strError.c_str());
            continue;
        }
        printf("ProcessDeferredNoteVotes: accepted a note vote held for epoch block %s\n",
               vote.hashBlock.ToString().substr(0, 10).c_str());
        LOCK(cs_vNodes);
        for (CNode* pnode : vNodes)
            pnode->PushMessage(FINALITY_NOTE_VOTE_COMMAND, vote);
    }
}

static void RebroadcastOwnVoteIfUncarried(int nCurrentHeight)
{
    CFinalityVote vote;
    int64_t nLastRelayMs = 0;
    {
        LOCK(cs_ownFinalityVote);
        if (!fHaveOwnVote)
            return;
        vote = voteOwnLast;
        nLastRelayMs = nOwnVoteLastRelayMs;
    }
    bool fConnected = false;
    const std::vector<CFinalityVote> vConnected = g_finalityTracker.GetEpochVotes(vote.nEpoch);
    for (size_t i = 0; i < vConnected.size() && !fConnected; i++)
        fConnected = vConnected[i].nullifier == vote.nullifier;
    if (!OwnVoteNeedsRebroadcast(vote, nCurrentHeight, fConnected, GetTimeMillis(), nLastRelayMs))
        return;
    {
        LOCK(cs_vNodes);
        for (CNode* pnode : vNodes)
            PushFinalityVoteMessage(pnode, vote);
    }
    {
        LOCK(cs_ownFinalityVote);
        nOwnVoteLastRelayMs = GetTimeMillis();
    }
    printf("FinalityVoter: re-relayed the epoch %d vote; no block has carried it yet (height %d)\n",
           vote.nEpoch, nCurrentHeight);
}

static void FinalityVoterLoop()
{
    if (GetBoolArg("-nofinalityvoting", false))
    {
        printf("ThreadFinalityVoter: voting disabled\n");
        return;
    }

    int64_t nPollMs = FINALITY_VOTER_POLL_MS_PRE_DAG;
    int64_t nLastTallyPassMs = 0;

    while (!fShutdown && !FinalityVoterShouldStop())
    {
        // Woken by the tip hook. The timeout only bounds the tally pass and shutdown check; the
        // latch decides whether this node owes a vote.
        WaitForFinalityVoteWork(nPollMs);

        if (fShutdown || FinalityVoterShouldStop())
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

        nPollMs = GetFinalityVoterPollMs(nCurrentHeight);

        if (nCurrentHeight < FORK_HEIGHT_FINALITY)
            continue;

        // Tally ahead of the vote-window gates (a certificate is built once the window
        // closes) so a vote-only node without -staking still tallies; rate-limited
        // separately from the vote poll.
        if (nCurrentHeight >= FORK_HEIGHT_DAG &&
            GetTimeMillis() - nLastTallyPassMs >= FINALITY_VOTER_POLL_MS_PRE_DAG)
        {
            nLastTallyPassMs = GetTimeMillis();
            ProcessFinalityTallyCommittee();
        }

        // Ahead of the claim: a vote this node held for a block that has since arrived
        // still has to reach the pending set inside the same inclusion window.
        ProcessDeferredNoteVotes(nCurrentHeight);

        // A tip advance may have arrived while this pass was busy; the latch
        // carries it, so claim against the tip as it stands now.
        NotifyFinalityTipChanged(nCurrentHeight);

        RebroadcastOwnVoteIfUncarried(nCurrentHeight);

        int nClaimedEpoch = -1;
        if (ClaimFinalityVote(nCurrentHeight, nClaimedEpoch) != FINALITY_VOTE_CLAIM_OK)
            continue;

        bool fProduced = ProduceFinalityVote();
        ReleaseFinalityVote(nClaimedEpoch, fProduced);
        if (fProduced)
            g_finalityTracker.PruneOldEpochs(nClaimedEpoch);
    }
}

void ThreadFinalityVoter(void* parg)
{
    printf("ThreadFinalityVoter started\n");
    // Accounted so StopFinalityVoter can prove the waiter is gone before the
    // static condition variable it sleeps on is destroyed.
    try
    {
        vnThreadsRunning[THREAD_FINALITY_VOTER]++;
        FinalityVoterLoop();
        // Logged before the count drops, so a debug.log that reports the voter
        // stopped is proof it was gone before shutdown continued.
        printf("ThreadFinalityVoter stopped\n");
        vnThreadsRunning[THREAD_FINALITY_VOTER]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[THREAD_FINALITY_VOTER]--;
        PrintException(&e, "ThreadFinalityVoter()");
    } catch (...) {
        vnThreadsRunning[THREAD_FINALITY_VOTER]--;
        PrintException(NULL, "ThreadFinalityVoter()");
    }
}

static std::string GetFinalityVoteModeArg()
{
    std::string strMode = ToLowerASCII(GetArg("-finalityvotemode", "auto"));
    if (strMode != "auto" && strMode != "transparent" && strMode != "note" &&
        strMode != "nullstake" && strMode != "nullstakecold")
    {
        printf("WARNING: Unknown -finalityvotemode '%s', using auto\n", strMode.c_str());
        strMode = "auto";
    }
    return strMode;
}

FinalityVoteLane GetFinalityVoteLaneForMode(const std::string& strVoteMode)
{
    if (strVoteMode == "note" || strVoteMode == "nullstake" ||
        strVoteMode == "nullstakecold")
        return FINALITY_VOTE_LANE_ANONYMOUS;
    // auto takes the identity lane: the tally counts only transparent voters, so an anonymous
    // default would stop HARD finality. The anonymous lane is opt-in.
    return FINALITY_VOTE_LANE_IDENTITY;
}

FinalityVoteLane GetConfiguredFinalityVoteLane()
{
    return GetFinalityVoteLaneForMode(GetFinalityVoteModeArg());
}

// The lane latch.  Configuration already pins one lane, so this only ever catches
// a caller that reached an emission site it had no business reaching; it is here
// because the cost of the leak is the whole anonymity of the note tier.
static CCriticalSection cs_voteEmissionLane;
static FinalityVoteLane g_emittedVoteLane = FINALITY_VOTE_LANE_NONE;
static int g_nEmittedVoteLaneEpoch = -1;

static bool VoteLaneAllowsLocked(FinalityVoteLane lane)
{
    if (lane == FINALITY_VOTE_LANE_NONE)
        return false;
    if (lane != GetConfiguredFinalityVoteLane())
        return false;
    return g_emittedVoteLane == FINALITY_VOTE_LANE_NONE || g_emittedVoteLane == lane;
}

bool FinalityVoteEmissionLaneAllows(FinalityVoteLane lane)
{
    LOCK(cs_voteEmissionLane);
    return VoteLaneAllowsLocked(lane);
}

bool RecordFinalityVoteEmission(FinalityVoteLane lane, int nEpoch)
{
    LOCK(cs_voteEmissionLane);
    if (!VoteLaneAllowsLocked(lane))
    {
        printf("FINALITY vote emission refused: lane=%d epoch=%d configured=%d "
               "already-emitted=%d\n", (int)lane, nEpoch,
               (int)GetConfiguredFinalityVoteLane(), (int)g_emittedVoteLane);
        return false;
    }
    if (g_emittedVoteLane == FINALITY_VOTE_LANE_NONE)
    {
        g_emittedVoteLane = lane;
        g_nEmittedVoteLaneEpoch = nEpoch;
        printf("FINALITY vote lane latched: lane=%s epoch=%d\n",
               lane == FINALITY_VOTE_LANE_ANONYMOUS ? "anonymous" : "identity",
               nEpoch);
    }
    return true;
}

FinalityVoteLane GetEmittedFinalityVoteLane()
{
    LOCK(cs_voteEmissionLane);
    return g_emittedVoteLane;
}

int GetEmittedFinalityVoteEpoch()
{
    LOCK(cs_voteEmissionLane);
    return g_nEmittedVoteLaneEpoch;
}

void ResetFinalityVoteEmissionLane()
{
    LOCK(cs_voteEmissionLane);
    g_emittedVoteLane = FINALITY_VOTE_LANE_NONE;
    g_nEmittedVoteLaneEpoch = -1;
}

bool FinalityVoteModeAllowsPrivateNote(const std::string& strVoteMode,
                                       bool fIsMofN)
{
    if (strVoteMode == "nullstake")
        return !fIsMofN;
    if (strVoteMode == "nullstakecold")
        return fIsMofN;
    return false;
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
                                                const CFinalityTallyConfig& tallyConfig,
                                                const std::string& strVoteMode)
{
    if (!pEpochBlock)
        return false;
    if (LegacyPrivateFinalityTrafficDisabledAtTip())
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
            for (std::map<uint256, CMofNDelegation>::const_iterator itD =
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

            // Explicit modes select exactly one proof generation: NullStake
            // uses a plain shielded note and V2, while NullStake cold uses an
            // M-of-N delegated note and V3. Auto may select either note kind.
            if (!FinalityVoteModeAllowsPrivateNote(strVoteMode, fIsMofN))
                continue;

            int64_t nLeafIdx = finalizedCurveTree.FindLeafIndex(membershipLeaf);
            if (nLeafIdx < 0)
                continue;

            CFCMPProof fcmpProof;
            // Retired: a private vote carried a legacy path proof and that layer
            // is gone, so the vote can no longer be produced over a legacy note.
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
                    // B2-c hidden-signer tier: opt-in (-b2chidden) once the chain is past the B2C fork.
                    // mofnSecrets already holds exactly mofnM member secrets (resized above).
                    bool fB2CHidden = GetBoolArg("-b2chidden", false) &&
                                      pEpochBlock->nHeight >= FORK_HEIGHT_NULLSTAKE_B2C;
                    bool fBuilt = fB2CHidden
                        ? CreateNullStakeB2CHiddenKernelProofV3(wnote.note.nValue, wnote.note.vchBlind,
                              membershipLeaf, pEpochBlock->nBits, nStakeModifier, nBlockTimeFrom,
                              nTxPrevOffset, nTxTimePrev, nVoutN, nTimeTx, mofnSet, mofnM, mofnOwner,
                              mofnD, mofnSecrets, nullStakeProofV3)
                        : CreateNullStakeMofNKernelProofV3(wnote.note.nValue, wnote.note.vchBlind,
                              membershipLeaf, pEpochBlock->nBits, nStakeModifier, nBlockTimeFrom,
                              nTxPrevOffset, nTxTimePrev, nVoutN, nTimeTx, mofnSet, mofnM, mofnOwner,
                              mofnD, mofnSecrets, nullStakeProofV3);
                    if (!fBuilt)
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

                int64_t nPrivateReward = GetFinalityVoteRewardAtHeight(wnote.note.nValue,
                                                                       nEpochHeight);
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
                    PushFinalityVoteMessage(pnode, vote);
                    pnode->PushMessage("ftshare", share);
                }
                return true;
            }
        }
    }

    return false;
}


// ---------------------------------------------------------------------------
// IV5 Note Finality Votes
// ---------------------------------------------------------------------------

// The committee an epoch's note votes must share to. It is consensus state, so the local
// -finalitytally* configuration has no say in it: a share split to any other set is one no
// quorum can ever open, and CheckNoteVoteForContext rejects the vote that carries it.
static bool GetNoteVoteCommitteeConfig(int nEpoch, CFinalityTallyConfig& configOut)
{
    std::vector<CPubKey> vCommittee;
    int nThresholdM = 0;
    uint256 committeeSetHash = 0;
    // Production-side, so a batch-free handle is both available and correct.
    CTxDB txdb("r");
    if (!GetCanonicalFinalityCommittee(txdb, nEpoch, vCommittee, nThresholdM, committeeSetHash))
        return false;
    if (nThresholdM < 2 || nThresholdM > (int)vCommittee.size() ||
        vCommittee.size() > FINALITY_NOTE_MAX_VSS_COEFFICIENTS || committeeSetHash == 0)
        return false;

    configOut = CFinalityTallyConfig();
    configOut.fCommitteeValid = true;
    configOut.fThresholdValid = true;
    configOut.nThresholdM = nThresholdM;
    configOut.nThresholdN = (int)vCommittee.size();
    configOut.committeeSetHash = committeeSetHash;
    configOut.vCommitteePubKeys = vCommittee;
    return true;
}

// Notes this process has already voted with, per epoch.
//
// The tag T_e = x*U_e is one note's single identity for one epoch, and two votes under one
// tag count for neither: re-proving a note in the same epoch destroys the vote it already
// cast. The tag is only reachable by proving, so the note's key image stands in for it
// here, and it is recorded before the first proof rather than after the last, which makes
// the rule at-most-once rather than at-least-once. Guarded by cs_main, which every caller
// already holds.
static std::map<int, std::set<uint256> > mapNoteVotesCastByEpoch;

static bool ProduceNoteFinalityVote(CTxDB& txdb, CBlockIndex* pEpochBlock,
                                    int nCurrentEpoch, int nEpochHeight,
                                    const std::string& strVoteMode)
{
    if (!pwalletMain || !pEpochBlock)
        return false;
    // The note vote is the anonymous lane. A node whose configured lane is the identity
    // one never casts it: the two emitted together from one node let any directly
    // connected peer read the tag as the transparent voter's, whatever the tag algebra
    // does. The latch is the second check, for a caller that got here anyway.
    if (GetFinalityVoteLaneForMode(strVoteMode) != FINALITY_VOTE_LANE_ANONYMOUS)
        return false;
    if (!FinalityVoteEmissionLaneAllows(FINALITY_VOTE_LANE_ANONYMOUS))
        return false;
    // A note vote must target a proof-of-work epoch block, so proving against any other
    // kind only produces something every peer rejects.
    if (!pEpochBlock->IsProofOfWork())
        return false;

    const int nIncludingHeight = pindexBest ? pindexBest->nHeight + 1 : nEpochHeight;
    if (!IsIV5NoteVoteActiveAtHeight(nIncludingHeight))
        return false;

    // Outside the epoch's inclusion window no block may carry the vote, so proving one
    // only spends time. This is the same window ConnectBlockNoteVotes enforces.
    const int nBoundary = GetEpochBoundaryHeight(nCurrentEpoch, nIncludingHeight);
    if (nIncludingHeight < nBoundary ||
        nIncludingHeight >= nBoundary + FINALITY_VOTE_INCLUSION_WINDOW)
        return false;

    // The cast set lives in memory, and a vote that is pending but not yet connected
    // leaves no record a restart can read. Voting again in that epoch would put a
    // second identity under one tag and retire both, so the epoch already open when
    // this process started is skipped. It costs at most one epoch after a restart.
    static int nFirstEpochSeen = -1;
    if (nFirstEpochSeen < 0)
        nFirstEpochSeen = (nIncludingHeight > nBoundary) ? nCurrentEpoch : -2;
    if (nFirstEpochSeen == nCurrentEpoch)
    {
        if (fDebug)
            printf("ProduceNoteFinalityVote: skipping epoch %d, already open at "
                   "startup and any earlier vote is unrecorded\n", nCurrentEpoch);
        return false;
    }

    CFinalityTallyConfig config;
    if (!GetNoteVoteCommitteeConfig(nCurrentEpoch, config))
    {
        if (fDebug)
            printf("ProduceNoteFinalityVote: epoch %d has no canonical committee a note "
                   "vote can share to\n", nCurrentEpoch);
        return false;
    }

    // Anchor to the finalized epoch the including block will resolve, never to this
    // node's live finalized tip: a proof against node-local finality is valid on some
    // nodes and invalid on others, which is a chain split.
    CEpochState anchorState;
    const FinalityResult anchorResult = ResolveFinalityAnchorForContext(
        txdb, nIncludingHeight, g_finalityTracker.GetFinalizedHeight(), anchorState,
        true /* fRequireCurveRoot */,
        true /* fAllowDeepUnfinalizedAnchor */);
    if (anchorResult != FINALITY_RESULT_OK)
    {
        if (fDebug)
            printf("ProduceNoteFinalityVote: no finalized anchor for height %d "
                   "(result=%d); not voting\n", nIncludingHeight, (int)anchorResult);
        return false;
    }
    if (anchorState.vchVNextRoot.size() != EPOCHSTATE_VNEXT_DIGEST_SIZE ||
        anchorState.vchVNextTreeState.empty() || anchorState.nVNextTreeSize == 0)
    {
        if (fDebug)
            printf("ProduceNoteFinalityVote: finalized epoch %d carries no IV5 tree to "
                   "prove against\n", anchorState.nEpoch);
        return false;
    }

    std::set<uint256>& setCast = mapNoteVotesCastByEpoch[nCurrentEpoch];

    CPrivacyVNextWalletNote note;
    std::vector<unsigned char> vchWitnessRecord;
    std::string strError;
    if (!pwalletMain->SelectPrivacyVNextVoteNote(
            txdb, anchorState.vchVNextTreeState, anchorState.vchVNextRoot,
            anchorState.nVNextTreeSize, pindexBest ? pindexBest->nHeight : nEpochHeight,
            FINALITY_MIN_VOTE_WEIGHT, setCast, note, vchWitnessRecord, strError))
    {
        if (fDebug)
            printf("ProduceNoteFinalityVote: no eligible note for epoch %d: %s\n",
                   nCurrentEpoch, strError.c_str());
        return false;
    }

    uint256 keyImage = 0;
    memcpy(keyImage.begin(), &note.vchKeyImage[0], 32);
    // The note is recorded as cast only once a vote is actually pending, further down.
    // Equivocation needs a vote that was relayed; a failure before that relayed nothing,
    // so retrying is safe. Recording it here instead burned a note per attempt, and a
    // wallet whose stake is entirely shielded has no other vote to set nLastEpochVoted,
    // so the voter retries through the whole window and drains every eligible note.

    CNoteVoteBuildContext ctx;
    ctx.nEpoch = nCurrentEpoch;
    ctx.nHeight = nEpochHeight;
    ctx.hashBlock = pEpochBlock->GetBlockHash();
    memcpy(ctx.hashAnchorRoot.begin(), &anchorState.vchVNextRoot[0],
           EPOCHSTATE_VNEXT_DIGEST_SIZE);
    ctx.hashNullifierRoot = anchorState.hashNullifierRoot;
    ctx.nAmount = (int64_t)note.nAmount;

    PrivacyVNextDigest noteMask;
    PrivacyVNextSpendInput input;
    memcpy(noteMask.data(), &note.vchMask[0], 32);
    memcpy(input.spendScalar.data(), &note.vchSpendSecret[0], 32);
    memcpy(input.commitmentScalar.data(), &note.vchY[0], 32);
    memcpy(input.leaf.owner.data(), &note.vchOwner[0], 32);
    memcpy(input.leaf.nullifierBase.data(), &note.vchNullifierBase[0], 32);
    memcpy(input.leaf.commitment.data(), &note.vchCommitment[0], 32);
    input.vchWitnessRecord = vchWitnessRecord;

    CNoteFinalityVote vote;
    // The reward proof does not fit the vote's script, so it comes back beside the vote.
    // Nothing carries it yet -- the settlement leg that spends it is not wired -- so it is
    // built and checked here and goes no further; a vote whose proof could not be built
    // is refused rather than cast unpayable.
    CNoteVoteRewardProof rewardProof;
    const bool fBuilt = BuildNoteFinalityVote(ctx, input, noteMask, config, vote,
                                              rewardProof, &strError);
    OPENSSL_cleanse(noteMask.data(), noteMask.size());
    if (!fBuilt)
    {
        printf("ProduceNoteFinalityVote: could not build a note vote for epoch %d: %s\n",
               nCurrentEpoch, strError.c_str());
        return false;
    }

    // A restart clears the cast set, so the tracker is the second guard: a tag this epoch
    // already counts is this note's own earlier vote, and a byte-distinct twin under it
    // would retire both.
    const uint256 tag = vote.GetVoteTag();
    if (g_finalityTracker.GetNoteVoteCountingState(nCurrentEpoch, tag) !=
        NOTE_VOTE_UNSEEN)
    {
        if (fDebug)
            printf("ProduceNoteFinalityVote: epoch %d already carries this note's tag; "
                   "not casting a second\n", nCurrentEpoch);
        return false;
    }

    // Latch the lane before the note is spent on this epoch, so a refusal costs
    // nothing.
    if (!RecordFinalityVoteEmission(FINALITY_VOTE_LANE_ANONYMOUS, nCurrentEpoch))
        return false;

    if (!g_finalityTracker.AddPendingNoteVote(vote, txdb, &strError))
    {
        printf("ProduceNoteFinalityVote: epoch %d vote was refused locally: %s\n",
               nCurrentEpoch, strError.c_str());
        return false;
    }

    // Pending now, so a second vote on this note would be a second identity under one
    // tag and retire both.
    setCast.insert(keyImage);

    printf("ProduceNoteFinalityVote: epoch=%d height=%d anchor=%s tag=%s\n",
           nCurrentEpoch, nEpochHeight,
           ctx.hashAnchorRoot.ToString().substr(0, 10).c_str(),
           tag.ToString().substr(0, 10).c_str());

    LOCK(cs_vNodes);
    for (CNode* pnode : vNodes)
        pnode->PushMessage(FINALITY_NOTE_VOTE_COMMAND, vote);
    return true;
}

// Drop the cast record for epochs the chain has left behind, so a long-running node does
// not accumulate one set per epoch forever.
static void PruneNoteVotesCast(int nCurrentEpoch)
{
    std::map<int, std::set<uint256> >::iterator it = mapNoteVotesCastByEpoch.begin();
    while (it != mapNoteVotesCastByEpoch.end())
    {
        if (it->first < nCurrentEpoch - 1)
            mapNoteVotesCastByEpoch.erase(it++);
        else
            ++it;
    }
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

    // Name the boundary block on the tip's own pprev chain, the chain the carrier is validated
    // against; a DAG-score pick could name a sibling branch and lose the single-shot note vote.
    int nEpochHeight = GetEpochBoundaryHeight(nCurrentEpoch, nCurrentHeight);
    CBlockIndex* pEpochBlock = FindBlockByHeight(nEpochHeight);
    if (!pEpochBlock || pEpochBlock->nHeight != nEpochHeight)
        return false;

    std::string strVoteMode = GetFinalityVoteModeArg();
    CFinalityTallyConfig tallyConfig = GetFinalityTallyConfig();
    // One lane per node: an identity vote and a note vote from one node link the tag to the
    // wallet. The tally counts identity votes only, so the anonymous lane relies on
    // FINALITY_MIN_VOTERS identity voters elsewhere.
    const FinalityVoteLane lane = GetFinalityVoteLaneForMode(strVoteMode);
    bool fAllowPrivate = (lane == FINALITY_VOTE_LANE_ANONYMOUS) &&
                           FinalityVoteEmissionLaneAllows(FINALITY_VOTE_LANE_ANONYMOUS) &&
                           !LegacyPrivateFinalityTrafficDisabledAtTip() &&
                           ((strVoteMode == "nullstake") ||
                            (strVoteMode == "nullstakecold")) &&
                           tallyConfig.CanRelayPrivateVotes();
    bool fAllowTransparent = (lane == FINALITY_VOTE_LANE_IDENTITY) &&
                             FinalityVoteEmissionLaneAllows(FINALITY_VOTE_LANE_IDENTITY);

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

    // Both anonymous tiers in one place: the legacy nullstake vote where it is still
    // allowed, and the IV5 note vote that replaces it. Each gates itself, so a node
    // holding stake for only one of them casts only that. Reached from the single
    // anonymous-lane exit below and nowhere else.
    PruneNoteVotesCast(nCurrentEpoch);
    auto castPrivateVotes = [&]() -> bool {
        bool fCast = fAllowPrivate && ProducePrivateNullStakeFinalityVote(
                         txdb, pEpochBlock, nCurrentEpoch, nEpochHeight,
                         tallyConfig, strVoteMode);
        if (ProduceNoteFinalityVote(txdb, pEpochBlock, nCurrentEpoch, nEpochHeight,
                                    strVoteMode))
            fCast = true;
        return fCast;
    };

    // The one branch point between the lanes. Everything below this line is the
    // identity lane and returns without touching the anonymous one.
    if (!fAllowTransparent)
        return castPrivateVotes();

    std::vector<COutput> vCoins;
    pwalletMain->AvailableCoins(vCoins);
    // Heaviest outputs first: a stake proof holds at most FINALITY_MAX_STAKE_PROOFS
    // outpoints. Weights are read once up front, not per comparison.
    std::vector<std::pair<int64_t, size_t> > vByWeight;
    vByWeight.reserve(vCoins.size());
    for (size_t nCoin = 0; nCoin < vCoins.size(); nCoin++)
    {
        const COutput& coin = vCoins[nCoin];
        const int64_t nValue = (coin.tx && coin.i >= 0 && (unsigned int)coin.i < coin.tx->vout.size())
                                   ? coin.tx->vout[coin.i].nValue
                                   : 0;
        vByWeight.push_back(std::make_pair(nValue, nCoin));
    }
    std::stable_sort(vByWeight.begin(), vByWeight.end(),
                     [](const std::pair<int64_t, size_t>& a, const std::pair<int64_t, size_t>& b) {
                         return a.first > b.first;
                     });

    for (const std::pair<int64_t, size_t>& weighted : vByWeight)
    {
        const COutput& out = vCoins[weighted.second];
        const CWalletTx* wtx = out.tx;
        unsigned int nOut = out.i;
        if (!wtx || nOut >= wtx->vout.size())
            continue;
        if ((int)out.nDepth <= 0)
            continue;

        const CTxOut& txout = wtx->vout[nOut];
        if (txout.nValue <= 0 || txout.nValue > MAX_MONEY)
            continue;

        CKeyID keyID;
        if (!ExtractFinalityStakeKeyID(txout.scriptPubKey, keyID))
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
        // Mirror the validator's boundary rule: a proof minted after the epoch
        // boundary rejects the whole vote, so never group one in.
        std::map<uint256, CBlockIndex*>::iterator miFrom = mapBlockIndex.find(blockFrom.GetHash());
        if (miFrom == mapBlockIndex.end() || miFrom->second == NULL)
            continue;
        if (miFrom->second->nHeight > nEpochHeight)
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
    vote.nReward = GetFinalityVoteRewardAtHeight(vote.nVoteWeight, nEpochHeight);
    vote.nullifier = nullifier;
    vote.vStakeProof = pBestGroup->vOutpoints;

    // Authenticate the Boundary-A logical schema itself.  The runtime marker
    // is deliberately set before signing and is not part of legacy bytes.
    if (IsBoundaryAActiveAtHeight(nCurrentHeight + 1))
        vote.MarkCanonicalEnvelope();

    if (!vote.Sign(pBestGroup->key))
        return false;

    // Latch the lane before the vote enters the tracker: an fvreq serves tracker
    // votes, so a vote this node must not emit must not be recorded either.
    if (!RecordFinalityVoteEmission(FINALITY_VOTE_LANE_IDENTITY, nCurrentEpoch))
        return false;

    if (!g_finalityTracker.AddVote(vote))
        return false;

    printf("ProduceFinalityVote: epoch=%d height=%d weight=%s\n",
           nCurrentEpoch, nEpochHeight, FormatMoney(pBestGroup->nWeight).c_str());

    {
        LOCK(cs_vNodes);
        for (CNode* pnode : vNodes)
        {
            PushFinalityVoteMessage(pnode, vote);
        }
    }
    {
        LOCK(cs_ownFinalityVote);
        voteOwnLast = vote;
        fHaveOwnVote = true;
        nOwnVoteLastRelayMs = GetTimeMillis();
    }

    return true;
}
