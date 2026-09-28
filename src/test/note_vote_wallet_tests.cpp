// Wallet and producer halves of the note finality vote (IV5 operation 10). Chains are
// synthetic; epoch records, spent-key entries and mempool reservations are restored.

#include <boost/test/unit_test.hpp>

#include <cstdio>
#include <cstring>
#include <limits>
#include <set>
#include <string>
#include <vector>

#include "../privacy_vnext/rust/include/innova_privacy_vnext.h"
#include "../dag.h"
#include "../finality.h"
#include "../finality_note.h"
#include "../subsidy.h"
#include "../main.h"
#include "../miner.h"
#include "../ed25519_zk.h"
#include "../privacy_vnext_builder.h"
#include "../privacy_vnext_ffi.h"
#include "../verifycache.h"
#include "../privacy_vnext_store.h"
#include "../shielded.h"
#include "../txdb.h"
#include "../util.h"
#include "../wallet.h"
#include "synthetic_chain.h"

#include <algorithm>

extern bool fRegTest;
extern bool fTestNet;

// Defined in miner.cpp. Declared here rather than in miner.h so the producer's own header
// stays as it is; a signature that drifted would fail to link, loudly.
bool AdmitPrivacyVNextNoteVote(const CTransaction& tx,
                               const CBlockIndex* pindexPrev,
                               int nCandidateHeight,
                               unsigned int nBlockNoteVotes,
                               unsigned int& nPriorNoteVotes,
                               bool& fHavePriorNoteVotes,
                               bool& fIsNoteVoteOut,
                               std::string& strErrorOut);
void ApplyPrivacyVNextNoteVoteSelectionOrder(const CTransaction& tx,
                                             double& dPriority,
                                             double& dFeePerKb);

namespace
{

// A note at the finality stake floor (500 INN), the note a vote spends.
const uint64_t kVoteNote = 500ULL * 100000000ULL;

// The post-DAG epoch the votes name; E-1 is the epoch state they anchor to.
const int kEpoch = 5;

int BoundaryHeight()
{
    return GetEpochBoundaryHeight(kEpoch, 0);
}

PrivacyVNextDigest FilledDigest(unsigned char fill)
{
    PrivacyVNextDigest d;
    d.fill(fill);
    return d;
}

PrivacyVNextDigest LowScalar(unsigned char low)
{
    PrivacyVNextDigest d;
    d.fill(0);
    d[0] = low;
    return d;
}

PrivacyVNextDigest LocalGenesis()
{
    PrivacyVNextDigest d;
    PrivacyVNextLocalGenesis(d.data());
    return d;
}

uint8_t LocalNetwork()
{
    return PrivacyVNextLocalNetworkId();
}

// The binding of a transaction with no transparent side at all, which is what a vote is.
PrivacyVNextDigest NoTransparentSide()
{
    PrivacyVNextDigest d;
    const uint256 binding = GetPrivacyVNextTransparentBinding(CTransaction());
    std::memcpy(d.data(), binding.begin(), 32);
    return d;
}

// The input context of a shield with no transparent side. Notes funded by hand below are
// grown straight into the tree, never carried by a payload, so encrypt and scan only have
// to agree on it.
PrivacyVNextDigest FundingContext()
{
    PrivacyVNextDigest context;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextInputContext(iv5::NOTE_SHIELD, NoTransparentSide(),
                                       std::vector<PrivacyVNextDigest>(), context,
                                       error),
        error);
    return context;
}

uint256 AsUint256(const PrivacyVNextDigest& d)
{
    uint256 out;
    std::memcpy(out.begin(), d.data(), d.size());
    return out;
}

std::vector<unsigned char> DigestBytes(const PrivacyVNextDigest& d)
{
    return std::vector<unsigned char>(d.begin(), d.end());
}

PrivacyVNextDigest BlockDigest(const CBlockIndex* pindex)
{
    PrivacyVNextDigest d;
    const uint256 hash = pindex->GetBlockHash();
    std::memcpy(d.data(), hash.begin(), 32);
    return d;
}

// The contract digest this build was compiled against; the decoder carries it and never
// judges it, so any value the chain record also carries serves here.
PrivacyVNextDigest ContractDigest()
{
    PrivacyVNextDigest d;
    BOOST_REQUIRE(iv5::DecodeDigestHex(iv5::PROTOCOL_CONTRACT_SHA256, d.data()));
    return d;
}

// One note of a chosen amount, placed in a fresh tree and reopened by its owner, with the
// membership witness a proof over it needs and the key image the owner's scan recorded.
struct FundedNote
{
    PrivacyVNextDigest seed;
    PrivacyVNextDerivedKeys keys;
    PrivacyVNextEncryptedOutput encrypted;
    PrivacyVNextSpendNote spend;
    PrivacyVNextDigest keyImage;
    std::vector<unsigned char> vchTreeState;
    PrivacyVNextDigest finalizedRoot;
    uint64_t nTreeSize;

    FundedNote() : nTreeSize(0)
    {
        seed.fill(0);
        keyImage.fill(0);
        finalizedRoot.fill(0);
    }
};

bool FundNote(CTxDB& txdb, unsigned char nSeed, uint64_t nAmount, FundedNote& out,
              std::string& error)
{
    const PrivacyVNextDigest genesis = LocalGenesis();
    out.seed = FilledDigest(nSeed);
    if (!DerivePrivacyVNextKeys(out.seed, genesis, 0, LocalNetwork(), 0, out.keys,
                                error))
        return false;
    if (!EncryptPrivacyVNextNote(
            LocalNetwork(), 0, 0, genesis, out.keys.spendPublic, out.keys.viewPublic,
            out.keys.outgoingViewSecret, LowScalar(nSeed + 1), LowScalar(nSeed + 2),
            nAmount, LowScalar(nSeed + 3), LowScalar(nSeed + 4), FundingContext(),
            out.encrypted, error))
        return false;

    PrivacyVNextEpochSeed epochSeed;
    if (!LoadPrivacyVNextEpochSeed(epochSeed, error))
        return false;
    out.vchTreeState = epochSeed.vchTreeState;
    if (!TrimPrivacyVNextTreeStore(txdb, 0, out.vchTreeState, error))
        return false;
    std::vector<PrivacyVNextOutputLeaf> vLeaves;
    vLeaves.push_back(out.encrypted.leaf);
    if (!GrowPrivacyVNextTreeStore(txdb, vLeaves, out.vchTreeState, error))
        return false;

    std::vector<unsigned char> vchRoot;
    if (!DecodePrivacyVNextTreeState(out.vchTreeState, vchRoot, out.nTreeSize, error))
        return false;
    std::memcpy(out.finalizedRoot.data(), &vchRoot[0], 32);

    std::vector<uint64_t> vTargets(1, 0);
    std::vector<unsigned char> vchPaths;
    if (!ReadPrivacyVNextTreePaths(txdb, out.nTreeSize, out.vchTreeState, vTargets,
                                   vchPaths, error))
        return false;
    std::vector<PrivacyVNextMembershipWitness> vWitnesses;
    PrivacyVNextDigest treeRoot;
    if (!BuildPrivacyVNextWitnessesFromPaths(out.vchTreeState, vTargets, vchPaths,
                                             vWitnesses, treeRoot, error))
        return false;

    PrivacyVNextEncryptedNote onChain;
    onChain.nOutputIndex = 0;
    onChain.genesis = genesis;
    onChain.leafO = out.encrypted.leaf.owner;
    onChain.leafC = out.encrypted.leaf.commitment;
    onChain.noteEphemeral = out.encrypted.noteEphemeral;
    onChain.tweakEphemeral = out.encrypted.tweakEphemeral;
    onChain.vchCiphertext = out.encrypted.vchRecipientCiphertext;
    onChain.inputContext = FundingContext();
    PrivacyVNextScannedNote scanned;
    if (!ScanPrivacyVNextNote(PRIVACY_VNEXT_SCAN_FULL, LocalNetwork(), 0, onChain,
                              out.keys.viewSecret, out.keys.spendSecret, scanned,
                              error))
        return false;

    out.spend.spendSecret = scanned.spendSecret;
    out.spend.y = scanned.y;
    out.spend.mask = scanned.mask;
    out.spend.nAmount = scanned.nAmount;
    out.spend.leaf = out.encrypted.leaf;
    out.spend.vchWitnessRecord = vWitnesses[0].vchRecord;
    out.keyImage = scanned.keyImage;
    return true;
}

void Fund(CTxDB& txdb, unsigned char nSeed, FundedNote& note)
{
    std::string error;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, nSeed, kVoteNote, note, error), error);
}

// The wallet record a scan would have produced for a funded note.
CPrivacyVNextWalletNote WalletNoteOf(const FundedNote& note, int nHeight)
{
    CPrivacyVNextWalletNote out;
    out.txhash = uint256(0x9901);
    out.nOutputIndex = 0;
    out.nHeight = nHeight;
    out.fSpent = false;
    out.fLeafIndexKnown = true;
    out.nAmount = note.spend.nAmount;
    out.nLeafIndex = 0;
    out.vchOwner = DigestBytes(note.spend.leaf.owner);
    out.vchNullifierBase = DigestBytes(note.spend.leaf.nullifierBase);
    out.vchCommitment = DigestBytes(note.spend.leaf.commitment);
    out.vchSpendSecret = DigestBytes(note.spend.spendSecret);
    out.vchY = DigestBytes(note.spend.y);
    out.vchMask = DigestBytes(note.spend.mask);
    out.vchKeyImage = DigestBytes(note.keyImage);
    return out;
}

// A wallet holding exactly that note, with the same seed the note derives from, so the
// reissue's self-pay keys come out of the same tree the note did.
void LoadWallet(CWallet& wallet, const FundedNote& note, int nNoteHeight)
{
    wallet.privacyVNextSeedRecord.nGeneration = PRIVACY_VNEXT_WALLET_SEED_GENERATION;
    wallet.vchPrivacyVNextSeed.assign(note.seed.begin(), note.seed.end());
    wallet.vPrivacyVNextNotes.clear();
    wallet.vPrivacyVNextNotes.push_back(WalletNoteOf(note, nNoteHeight));
}

// A transaction that carries a payload, which is all the consensus transitions read.
CTransaction CarryingTx(const std::vector<unsigned char>& payload, uint32_t nTime)
{
    CTransaction tx;
    tx.nVersion = INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION;
    tx.nTime = nTime;
    tx.privacyVNext.vchPayload = payload;
    return tx;
}

// Regtest fork height for the note-vote lane, restored on scope exit.
struct ScopedNoteVoteHeight
{
    int nSaved;
    explicit ScopedNoteVoteHeight(int nHeight) : nSaved(nRegtestIV5NoteVoteHeight)
    {
        nRegtestIV5NoteVoteHeight = nHeight;
    }
    ~ScopedNoteVoteHeight() { nRegtestIV5NoteVoteHeight = nSaved; }
};

// The carrier chain: a main branch through H_E to the end of the inclusion window, and a
// sibling branch opening its own H_E on the same parent.
struct VoteChain
{
    CSyntheticChain chain;
    CBlockIndex* pParent;
    CBlockIndex* pBoundary;
    CBlockIndex* pTip;
    CBlockIndex* pSiblingBoundary;

    explicit VoteChain(unsigned int nTag) : chain(nTag)
    {
        pParent = chain.Linear(BoundaryHeight() - 1);
        BOOST_REQUIRE(pParent != NULL);
        pBoundary = chain.Extend(pParent, 1);
        BOOST_REQUIRE(pBoundary != NULL);
        pTip = chain.Extend(pBoundary, FINALITY_NOTE_VOTE_INCLUSION_WINDOW);
        BOOST_REQUIRE(pTip != NULL);
        pSiblingBoundary = chain.Extend(pParent, 1);
        BOOST_REQUIRE(pSiblingBoundary != NULL);
    }

    const CBlockIndex* At(int nHeight) const
    {
        const CBlockIndex* p =
            GetFinalityAncestorOnChain(pTip, nHeight, FINALITY_ANCESTOR_MAX_WALK);
        BOOST_REQUIRE(p != NULL);
        return p;
    }
};

// Epoch state E-1 as the epoch build leaves it for a chain whose H_E is pBoundary.
CEpochState AnchorRecord(const FundedNote& note, const CBlockIndex* pBoundary)
{
    CEpochState s;
    s.nEpoch = kEpoch - 1;
    s.nHeightStart = GetEpochBoundaryHeight(kEpoch - 1, 0);
    s.nHeightEnd = pBoundary->nHeight - 1;
    s.hashBoundaryBlock = pBoundary->pprev->GetBlockHash();
    s.nSerVersion = EPOCHSTATE_SER_VERSION;
    s.vchVNextTreeState = note.vchTreeState;
    s.vchVNextRoot = DigestBytes(note.finalizedRoot);
    s.nVNextTreeSize = note.nTreeSize;
    s.vchVNextParameterDigest = DigestBytes(ContractDigest());
    return s;
}

// One epoch number's record for the length of a case, put back exactly at the end.
struct ScopedEpochRecord
{
    CTxDB& txdb;
    int nEpoch;
    bool fHadPrior;
    CEpochState prior;

    ScopedEpochRecord(CTxDB& txdbIn, int nEpochIn, const CEpochState& install)
        : txdb(txdbIn), nEpoch(nEpochIn), fHadPrior(false)
    {
        if (txdb.ProbeEpochState(nEpoch) == TXDB_READ_FOUND)
        {
            fHadPrior = true;
            BOOST_REQUIRE(txdb.ReadEpochState(nEpoch, prior));
        }
        Set(install);
    }
    void Set(const CEpochState& s) { BOOST_REQUIRE(txdb.WriteEpochState(nEpoch, s)); }
    void Remove() { BOOST_REQUIRE(txdb.EraseEpochState(nEpoch)); }
    ~ScopedEpochRecord()
    {
        if (fHadPrior)
            txdb.WriteEpochState(nEpoch, prior);
        else
            txdb.EraseEpochState(nEpoch);
    }
};

// Spent-key entries a case may write, erased when it ends.
struct ScopedSpentKeys
{
    CTxDB& txdb;
    std::vector<uint256> vKeys;

    explicit ScopedSpentKeys(CTxDB& txdbIn) : txdb(txdbIn) {}
    void Track(const uint256& keyImage) { vKeys.push_back(keyImage); }
    ~ScopedSpentKeys()
    {
        for (size_t i = 0; i < vKeys.size(); ++i)
            txdb.ErasePrivacyVNextNullifier(vKeys[i]);
    }
};

// Key-image reservations a case puts in the mempool, removed when it ends. Never touches
// mapTx, so no transaction is left behind for another suite to select.
struct ScopedMempoolReservation
{
    std::vector<uint256> vKeys;

    void Reserve(const uint256& keyImage, const uint256& hashTx)
    {
        LOCK(mempool.cs);
        mempool.mapPrivacyVNextNullifier[keyImage] =
            CShieldedNullifierSpent(hashTx, 0);
        vKeys.push_back(keyImage);
    }
    ~ScopedMempoolReservation()
    {
        LOCK(mempool.cs);
        for (size_t i = 0; i < vKeys.size(); ++i)
            mempool.mapPrivacyVNextNullifier.erase(vKeys[i]);
    }
};

// A vote built by the wallet builder, decoded into the effects consensus judges.
struct BuiltVote
{
    std::vector<unsigned char> payload;
    PrivacyVNextDigest keyImage;
    PrivacyVNextStateEffects effects;
    CTransaction tx;
};

bool BuildVote(const FundedNote& note, const PrivacyVNextDigest& reissueSpend,
               const PrivacyVNextDigest& reissueView,
               const PrivacyVNextDigest& outgoingViewSecret,
               const PrivacyVNextDigest& boundaryHash, int nBoundaryHeight,
               std::vector<unsigned char>& vchPayloadOut,
               PrivacyVNextDigest& keyImageOut, std::string& error)
{
    PrivacyVNextAddressComponents reissueTo;
    reissueTo.nNetwork = LocalNetwork();
    reissueTo.nAddressType = 0;
    reissueTo.spendPublic = reissueSpend;
    reissueTo.viewPublic = reissueView;

    const std::vector<unsigned char> vchParameterDigest =
        DigestBytes(ContractDigest());
    return BuildPrivacyVNextNoteVotePayload(
        LocalNetwork(), LocalGenesis(), outgoingViewSecret, note.finalizedRoot,
        note.nTreeSize, NoTransparentSide(), boundaryHash,
        (uint32_t)nBoundaryHeight,
        GetFinalityNoteVoteReward(GetEpochForHeight(nBoundaryHeight)),
        note.spend, reissueTo, vchPayloadOut, keyImageOut,
        error, &vchParameterDigest);
}

// The vote a wallet paying itself would build: the reissue goes to the rotated self-pay
// index this payload's own key image draws.
void CastVote(const FundedNote& note, const CBlockIndex* pNamed, uint32_t nTime,
              BuiltVote& out)
{
    std::string error;
    std::vector<PrivacyVNextDigest> vKeyImages(1, note.keyImage);
    const uint32_t nIndex = PrivacyVNextChangeIndexFor(
        LocalGenesis(), LocalNetwork(), NoTransparentSide(), vKeyImages);
    PrivacyVNextDerivedKeys reissueKeys;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextChangeKeys(note.seed, LocalGenesis(), LocalNetwork(),
                                     nIndex, reissueKeys, error),
        error);
    BOOST_REQUIRE_MESSAGE(
        BuildVote(note, reissueKeys.spendPublic, reissueKeys.viewPublic,
                  reissueKeys.outgoingViewSecret, BlockDigest(pNamed),
                  pNamed->nHeight, out.payload, out.keyImage, error),
        error);
    const PrivacyVNextPayloadValidation extracted =
        ExtractPrivacyVNextPayloadEffects(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                          out.payload, out.effects);
    BOOST_REQUIRE_MESSAGE(extracted.IsValid(), extracted.strError);
    out.tx = CarryingTx(out.payload, nTime);
}

struct ContextVerdict
{
    bool fOK;
    bool fLocalFailure;
    bool fUnavailable;
    std::string strError;
};

ContextVerdict JudgeVote(CTxDB& txdb, const VoteChain& chain, int nHeight,
                         const PrivacyVNextStateEffects& effects)
{
    ContextVerdict v;
    v.fLocalFailure = false;
    v.fUnavailable = false;
    v.fOK = ValidatePrivacyVNextNoteVoteContext(txdb, chain.At(nHeight), nHeight,
                                                effects, v.fLocalFailure,
                                                v.fUnavailable, v.strError);
    return v;
}

bool Mentions(const std::string& strError, const char* what)
{
    return strError.find(what) != std::string::npos;
}

// The scan keys a wallet derives for one payload: its issued indices, then the rotated
// self-pay index this payload's own key images draw. Mirrors
// ExtendPrivacyVNextScanKeysForPayload, which is the path a block scan takes.
std::vector<PrivacyVNextScanKey> ScanKeysForPayload(
    const PrivacyVNextDigest& seed, const std::vector<unsigned char>& payload,
    bool fIncludeRotated)
{
    std::vector<PrivacyVNextScanKey> vKeys;
    std::string error;

    PrivacyVNextDerivedKeys issued;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextKeys(seed, LocalGenesis(), 0, LocalNetwork(), 0, issued,
                               error),
        error);
    PrivacyVNextScanKey key;
    key.scanSecret = issued.viewSecret;
    key.spendMaterial = issued.spendSecret;
    vKeys.push_back(key);
    if (!fIncludeRotated)
        return vKeys;

    // The key images are read back out of the payload, exactly as the wallet does: the
    // index is a function of what the payload publishes, so nothing has to be stored.
    std::vector<PrivacyVNextScanMatch> vIgnored;
    std::vector<PrivacyVNextDigest> vKeyImages;
    uint8_t nOutputCount = 0;
    const std::vector<PrivacyVNextScanKey> vNoKeys(1);
    BOOST_REQUIRE_MESSAGE(
        ScanPrivacyVNextPayload(PRIVACY_VNEXT_SCAN_VIEW_ONLY, LocalNetwork(), 0,
                                INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload,
                                vNoKeys, vIgnored, vKeyImages, nOutputCount, error),
        error);
    const uint32_t nIndex = PrivacyVNextChangeIndexFor(
        LocalGenesis(), LocalNetwork(), NoTransparentSide(), vKeyImages);
    PrivacyVNextDerivedKeys rotated;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextChangeKeys(seed, LocalGenesis(), LocalNetwork(), nIndex,
                                     rotated, error),
        error);
    PrivacyVNextScanKey rotatedKey;
    rotatedKey.scanSecret = rotated.viewSecret;
    rotatedKey.spendMaterial = rotated.spendSecret;
    vKeys.push_back(rotatedKey);
    return vKeys;
}

} // namespace

BOOST_AUTO_TEST_SUITE(note_vote_wallet_tests)

// The positive control: the builder's payload is shaped the way the decoder pins it, and
// the connect-time rules increment 2 enforces accept it inside its window, on its own
// chain, against epoch state E-1.
BOOST_AUTO_TEST_CASE(the_builder_makes_a_vote_the_connect_rules_accept)
{
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    VoteChain chain(0x6E770100U);
    const int nBoundary = BoundaryHeight();

    FundedNote note;
    Fund(txdb, 0x21, note);
    BuiltVote vote;
    CastVote(note, chain.pBoundary, 1500001001, vote);
    ScopedEpochRecord anchor(txdb, kEpoch - 1, AnchorRecord(note, chain.pBoundary));

    // The shape the decoder pins before any proof runs: one note in, one note out,
    // no fee, the boundary the vote names, and a balance that may enter the pool but
    // never leave it.
    BOOST_CHECK(vote.effects.HasVoteBoundary());
    BOOST_CHECK_EQUAL((int)vote.effects.nVoteBoundaryHeight, nBoundary);
    BOOST_CHECK(vote.effects.voteBoundaryHash == BlockDigest(chain.pBoundary));
    BOOST_REQUIRE_EQUAL(vote.effects.keyImages.size(), 1U);
    BOOST_CHECK(vote.effects.keyImages[0] == vote.keyImage);
    BOOST_CHECK(vote.effects.keyImages[0] == note.keyImage);
    BOOST_CHECK_EQUAL(vote.effects.outputLeaves.size(), 1U);
    // A vote carries its own epoch's entitlement in, so the balance is the mint and
    // not zero; the decoder allows any non-negative figure and the caller pins this one.
    int64_t nMint = 0;
    std::string strMint;
    BOOST_REQUIRE_MESSAGE(GetPrivacyVNextNoteVoteMint(vote.effects, nMint, strMint),
                          strMint);
    BOOST_CHECK_EQUAL(nMint, GetFinalityNoteVoteReward(kEpoch));
    BOOST_CHECK_EQUAL(vote.effects.nTransparentValueBalance, nMint);
    BOOST_CHECK_EQUAL(vote.effects.nFee, 0U);
    BOOST_CHECK(vote.effects.attestationKeyImages.empty());

    // A vote rides bare, and the miner and mempool recognise it as the zero-fee shape.
    BOOST_CHECK(IsPrivacyVNextNoteVoteShape(vote.tx));
    BOOST_CHECK(IsPrivacyVNextFeeExemptShape(vote.tx));
    std::string error;
    BOOST_CHECK_MESSAGE(CheckPrivacyVNextNoteVoteCarrier(vote.tx, vote.effects, error),
                        error);

    const int nConnect = nBoundary + 1;
    const ContextVerdict v = JudgeVote(txdb, chain, nConnect, vote.effects);
    BOOST_CHECK_MESSAGE(v.fOK, v.strError);
    BOOST_CHECK(!v.fLocalFailure);
    BOOST_CHECK(!v.fUnavailable);
    BOOST_CHECK_MESSAGE(
        CheckPrivacyVNextFinalizedAnchor(txdb, chain.At(nConnect), nConnect, vote.tx,
                                         error),
        error);

    // The window's far edge holds too, and the block after it does not.
    const ContextVerdict vLast =
        JudgeVote(txdb, chain, nBoundary + FINALITY_NOTE_VOTE_INCLUSION_WINDOW - 1,
                  vote.effects);
    BOOST_CHECK_MESSAGE(vLast.fOK, vLast.strError);
    const ContextVerdict vPast =
        JudgeVote(txdb, chain, nBoundary + FINALITY_NOTE_VOTE_INCLUSION_WINDOW,
                  vote.effects);
    BOOST_CHECK(!vPast.fOK);
    BOOST_CHECK(Mentions(vPast.strError, "outside its inclusion window"));
}


// Consensus stake floor: the range proof is over the output commitment shifted down by
// the floor and the entering value, so it bounds the staked note, not note plus reward.
// Pins the boundary and the refusals.
BOOST_AUTO_TEST_CASE(a_vote_proves_the_staked_note_cleared_the_floor)
{
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    VoteChain chain(0x6E770900U);
    const int nBoundary = BoundaryHeight();
    std::string error;

    // Exactly at the floor is admitted: the shifted opening is zero, which is in range.
    BOOST_CHECK_EQUAL((int64_t)kVoteNote, GetFinalityMinVoteWeight(nBoundary));
    FundedNote atFloor;
    Fund(txdb, 0x31, atFloor);
    BuiltVote vote;
    CastVote(atFloor, chain.pBoundary, 1500002001, vote);
    BOOST_CHECK(!vote.payload.empty());

    // One atomic unit short cannot be built at all: the shifted amount would be negative,
    // so there is no opening to prove and the builder refuses before the network sees it.
    FundedNote below;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0x32, kVoteNote - 1, below, error), error);
    std::vector<PrivacyVNextDigest> vBelowImages(1, below.keyImage);
    const uint32_t nBelowIndex = PrivacyVNextChangeIndexFor(
        LocalGenesis(), LocalNetwork(), NoTransparentSide(), vBelowImages);
    PrivacyVNextDerivedKeys belowKeys;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextChangeKeys(below.seed, LocalGenesis(), LocalNetwork(),
                                     nBelowIndex, belowKeys, error), error);
    std::vector<unsigned char> vchBelow;
    PrivacyVNextDigest belowImage;
    std::string strBelow;
    BOOST_CHECK(!BuildVote(below, belowKeys.spendPublic, belowKeys.viewPublic,
                           belowKeys.outgoingViewSecret, BlockDigest(chain.pBoundary),
                           chain.pBoundary->nHeight, vchBelow, belowImage, strBelow));
    BOOST_CHECK(Mentions(strBelow, "below the minimum vote weight"));

    // A vote whose floor proof does not verify is refused by the decoder. The payload ends
    // with the operation proof and then an empty disclosure vector, so the last byte of the
    // proof is the byte before that terminator.
    BOOST_REQUIRE(vote.payload.size() > 2);
    BOOST_REQUIRE_EQUAL((int)vote.payload.back(), 0);
    std::vector<unsigned char> vchCorrupt = vote.payload;
    vchCorrupt[vchCorrupt.size() - 2] ^= 0x01;
    PrivacyVNextStateEffects corruptEffects;
    const PrivacyVNextPayloadValidation corrupt =
        ExtractPrivacyVNextPayloadEffects(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                          vchCorrupt, corruptEffects);
    BOOST_CHECK(!corrupt.IsValid());
}

// The reissue's one-time key and self-pay index both derive from the key image, so a
// block scan finds it from the payload alone.
BOOST_AUTO_TEST_CASE(the_wallet_finds_its_own_reissue_from_the_payload_alone)
{
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    VoteChain chain(0x6E770200U);

    FundedNote note;
    Fund(txdb, 0x23, note);
    BuiltVote vote;
    CastVote(note, chain.pBoundary, 1500001101, vote);

    std::string error;
    std::vector<PrivacyVNextScanMatch> vMatches;
    std::vector<PrivacyVNextDigest> vKeyImages;
    uint8_t nOutputCount = 0;
    const std::vector<PrivacyVNextScanKey> vFull =
        ScanKeysForPayload(note.seed, vote.payload, true);
    BOOST_REQUIRE_MESSAGE(
        ScanPrivacyVNextPayload(PRIVACY_VNEXT_SCAN_FULL, LocalNetwork(), 0,
                                INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                vote.payload, vFull, vMatches, vKeyImages,
                                nOutputCount, error),
        error);
    BOOST_REQUIRE_EQUAL(vMatches.size(), 1U);
    // The note plus the epoch's entitlement: the reward is minted into the reissue, so a
    // wallet reads it back out of the ordinary scan and nowhere else.
    const uint64_t nExpectedReissue =
        kVoteNote +
        (uint64_t)GetFinalityNoteVoteReward(GetEpochForHeight(BoundaryHeight()));
    BOOST_CHECK_EQUAL(vMatches[0].nAmount, nExpectedReissue);
    BOOST_CHECK_EQUAL((unsigned int)vMatches[0].nOutputIndex, 0U);
    // Found under the rotated key, not an issued one.
    BOOST_CHECK_EQUAL((unsigned int)vMatches[0].nKeyIndex, 1U);
    // The reissue is a different note from the one spent: a fresh key image, so it can
    // vote again next epoch.
    BOOST_CHECK(!(vMatches[0].keyImage == note.keyImage));

    // Without the rotated index the same payload opens nothing: the reissue is genuinely
    // reachable only through the derivation the scan performs, never through a stored
    // record.
    std::vector<PrivacyVNextScanMatch> vIssuedOnly;
    std::vector<PrivacyVNextDigest> vIgnoredImages;
    const std::vector<PrivacyVNextScanKey> vIssued =
        ScanKeysForPayload(note.seed, vote.payload, false);
    BOOST_REQUIRE_MESSAGE(
        ScanPrivacyVNextPayload(PRIVACY_VNEXT_SCAN_FULL, LocalNetwork(), 0,
                                INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                vote.payload, vIssued, vIssuedOnly, vIgnoredImages,
                                nOutputCount, error),
        error);
    BOOST_CHECK(vIssuedOnly.empty());

    // The context the outputs were encrypted under is the vote's own, not a transfer's:
    // scanning with a transfer's context finds nothing, which is what binds the reissue
    // to operation 10.
    std::vector<PrivacyVNextDigest> vSpent(1, note.keyImage);
    PrivacyVNextDigest voteContext;
    PrivacyVNextDigest transferContext;
    BOOST_REQUIRE(DerivePrivacyVNextInputContext(iv5::NOTE_FINALITY_VOTE,
                                                 NoTransparentSide(), vSpent,
                                                 voteContext, error));
    BOOST_REQUIRE(DerivePrivacyVNextInputContext(iv5::NOTE_TRANSFER,
                                                 NoTransparentSide(), vSpent,
                                                 transferContext, error));
    BOOST_CHECK(!(voteContext == transferContext));
}

// One vote per note: the mempool reservation and spent-key index are the only
// authorities, the same two that decide whether a second vote could connect.
BOOST_AUTO_TEST_CASE(a_wallet_votes_once_per_note_and_refuses_the_second)
{
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    VoteChain chain(0x6E770300U);
    const int nBoundary = BoundaryHeight();
    const int nConnect = nBoundary + 1;

    FundedNote note;
    Fund(txdb, 0x25, note);
    const CEpochState anchor = AnchorRecord(note, chain.pBoundary);
    ScopedEpochRecord record(txdb, kEpoch - 1, anchor);

    CWallet wallet;
    LoadWallet(wallet, note, nBoundary - MIN_SHIELDED_SPEND_DEPTH - 1);

    CWalletTx wtx;
    uint256 keyImage = 0;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        wallet.CreatePrivacyVNextNoteVote(
            txdb, anchor, chain.pBoundary->GetBlockHash(), nBoundary, nConnect - 1,
            GetFinalityMinVoteWeight(nBoundary), false /* do not commit */, wtx,
            keyImage, error),
        error);
    BOOST_CHECK(keyImage == AsUint256(note.keyImage));
    BOOST_CHECK(wtx.vin.empty());
    BOOST_CHECK(wtx.vout.empty());
    BOOST_CHECK(IsPrivacyVNextNoteVoteShape(wtx));

    // What the wallet built is what the connect rules accept.
    PrivacyVNextStateEffects effects;
    const PrivacyVNextPayloadValidation extracted =
        ExtractPrivacyVNextPayloadEffects((uint32_t)wtx.nVersion,
                                          wtx.privacyVNext.vchPayload, effects);
    BOOST_REQUIRE_MESSAGE(extracted.IsValid(), extracted.strError);
    const ContextVerdict v = JudgeVote(txdb, chain, nConnect, effects);
    BOOST_CHECK_MESSAGE(v.fOK, v.strError);
    BOOST_CHECK_EQUAL((int)effects.nVoteBoundaryHeight, nBoundary);

    // A vote pending in the mempool holds the note. fSpent is only set when the carrier
    // connects, so without this the wallet would pay for a second proof the mempool
    // refuses as a reserved key image.
    {
        ScopedMempoolReservation reserved;
        reserved.Reserve(keyImage, wtx.GetHash());
        CWalletTx second;
        uint256 secondKeyImage = 0;
        std::string strSecond;
        BOOST_CHECK(!wallet.CreatePrivacyVNextNoteVote(
            txdb, anchor, chain.pBoundary->GetBlockHash(), nBoundary, nConnect - 1,
            GetFinalityMinVoteWeight(nBoundary), false, second, secondKeyImage, strSecond));
        BOOST_CHECK(Mentions(strSecond, "no unspent IV5 note"));
    }

    // Once the vote has connected, the spent-key index holds it for good, and this is the
    // same read that makes a second vote of the note a double spend on chain.
    {
        ScopedSpentKeys spent(txdb);
        spent.Track(keyImage);
        CPrivacyVNextNullifierSpent entry;
        entry.txnHash = wtx.GetHash();
        entry.nIndex = 0;
        entry.nHeight = nConnect;
        BOOST_REQUIRE(txdb.WritePrivacyVNextNullifier(keyImage, entry));
        CWalletTx third;
        uint256 thirdKeyImage = 0;
        std::string strThird;
        BOOST_CHECK(!wallet.CreatePrivacyVNextNoteVote(
            txdb, anchor, chain.pBoundary->GetBlockHash(), nBoundary, nConnect - 1,
            GetFinalityMinVoteWeight(nBoundary), false, third, thirdKeyImage, strThird));
        BOOST_CHECK(Mentions(strThird, "no unspent IV5 note"));
    }

    // A note below the stake floor is never selected, whatever else holds.
    CWalletTx below;
    uint256 belowKeyImage = 0;
    std::string strBelow;
    BOOST_CHECK(!wallet.CreatePrivacyVNextNoteVote(
        txdb, anchor, chain.pBoundary->GetBlockHash(), nBoundary, nConnect - 1,
        (int64_t)kVoteNote + 1, false, below, belowKeyImage, strBelow));
    BOOST_CHECK(Mentions(strBelow, "no unspent IV5 note"));
}

// The anchor is epoch state E-1 and it is identified by its own boundary block before its
// root is used. A record left for another branch, or one whose leaves this node cannot
// serve, is refused here rather than paid for in proving time.
BOOST_AUTO_TEST_CASE(the_wallet_anchors_to_epoch_state_e_minus_1_of_its_own_branch)
{
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    VoteChain chain(0x6E770400U);
    const int nBoundary = BoundaryHeight();

    FundedNote note;
    Fund(txdb, 0x27, note);
    const uint256 hashParent = chain.pBoundary->pprev->GetBlockHash();
    ScopedEpochRecord record(txdb, kEpoch - 1, AnchorRecord(note, chain.pBoundary));

    CEpochState anchor;
    std::string error;
    BOOST_CHECK_MESSAGE(
        LoadPrivacyVNextNoteVoteAnchor(txdb, kEpoch, hashParent, nBoundary, anchor,
                                       error),
        error);
    BOOST_CHECK_EQUAL(anchor.nEpoch, kEpoch - 1);
    BOOST_CHECK_EQUAL(anchor.nHeightEnd, nBoundary - 1);
    BOOST_CHECK_EQUAL(anchor.nVNextTreeSize, note.nTreeSize);

    // The sibling branch opens its own H_E on the same parent, so its H_E - 1 is a
    // different block. The record installed is not that branch's, and the wallet says so
    // before it reads a root.
    BOOST_CHECK(!LoadPrivacyVNextNoteVoteAnchor(
        txdb, kEpoch, chain.pSiblingBoundary->GetBlockHash(), nBoundary, anchor,
        error));
    BOOST_CHECK(Mentions(error, "is not the voting chain's"));

    // A boundary one block off names a record whose nHeightEnd cannot match.
    BOOST_CHECK(!LoadPrivacyVNextNoteVoteAnchor(txdb, kEpoch, hashParent,
                                                nBoundary + 1, anchor, error));
    BOOST_CHECK(Mentions(error, "is not the voting chain's"));

    // Epoch 1 back is the only anchor a vote takes; the epoch itself is not one.
    BOOST_CHECK(!LoadPrivacyVNextNoteVoteAnchor(txdb, kEpoch + 1, hashParent,
                                                nBoundary, anchor, error));

    // An anchor whose tree the local store cannot serve witnesses from is this node's
    // state, not a reason to prove: the witness would fold onto nothing.
    CEpochState ahead = AnchorRecord(note, chain.pBoundary);
    ahead.nVNextTreeSize = note.nTreeSize + 1000;
    record.Set(ahead);
    BOOST_CHECK(!LoadPrivacyVNextNoteVoteAnchor(txdb, kEpoch, hashParent, nBoundary,
                                                anchor, error));
    BOOST_CHECK(Mentions(error, "tree store"));

    // No record at all is a plain absence, never a claim about the vote.
    record.Remove();
    BOOST_CHECK(!LoadPrivacyVNextNoteVoteAnchor(txdb, kEpoch, hashParent, nBoundary,
                                                anchor, error));
    BOOST_CHECK(Mentions(error, "not available"));
}

// The producer admits votes to a template up to the per-block cap and stops, and counts
// what the branch already connected against the per-window cap. A candidate that is not a
// vote consumes no slot.
BOOST_AUTO_TEST_CASE(the_producer_admits_the_block_cap_and_stops)
{
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    const int nBoundary = BoundaryHeight();

    FundedNote note;
    Fund(txdb, 0x29, note);
    VoteChain chain(0x6E770500U);
    BuiltVote vote;
    CastVote(note, chain.pBoundary, 1500001301, vote);
    BOOST_REQUIRE(IsPrivacyVNextNoteVoteShape(vote.tx));

    // pindexPrev NULL is a template on an empty branch: the window walk reads no block,
    // so nothing is connected yet and the per-block cap is the only one biting.
    unsigned int nBlockNoteVotes = 0;
    unsigned int nPriorNoteVotes = 0;
    bool fHavePrior = false;
    unsigned int nAdmitted = 0;
    for (int i = 0; i < FINALITY_MAX_BLOCK_NOTE_VOTES + 8; ++i)
    {
        bool fIsNoteVote = false;
        std::string error;
        if (!AdmitPrivacyVNextNoteVote(vote.tx, NULL, nBoundary + 1, nBlockNoteVotes,
                                       nPriorNoteVotes, fHavePrior, fIsNoteVote,
                                       error))
        {
            BOOST_CHECK(Mentions(error, "in one block"));
            continue;
        }
        BOOST_CHECK(fIsNoteVote);
        ++nBlockNoteVotes;
        ++nAdmitted;
    }
    BOOST_CHECK_EQUAL(nAdmitted, (unsigned int)FINALITY_MAX_BLOCK_NOTE_VOTES);
    BOOST_CHECK_EQUAL(nPriorNoteVotes, 0U);
    BOOST_CHECK(fHavePrior);

    // With the window nearly full the per-epoch cap bites first, whatever the block has
    // room for.
    nBlockNoteVotes = 0;
    nAdmitted = 0;
    fHavePrior = true;
    nPriorNoteVotes = FINALITY_MAX_EPOCH_NOTE_VOTES - 8;
    for (int i = 0; i < FINALITY_MAX_BLOCK_NOTE_VOTES; ++i)
    {
        bool fIsNoteVote = false;
        std::string error;
        if (!AdmitPrivacyVNextNoteVote(vote.tx, NULL, nBoundary + 1, nBlockNoteVotes,
                                       nPriorNoteVotes, fHavePrior, fIsNoteVote,
                                       error))
        {
            BOOST_CHECK(Mentions(error, "inclusion window"));
            continue;
        }
        ++nBlockNoteVotes;
        ++nAdmitted;
    }
    BOOST_CHECK_EQUAL(nAdmitted, 8U);

    // Everything that is not a vote passes through untouched and takes no slot.
    nBlockNoteVotes = (unsigned int)FINALITY_MAX_BLOCK_NOTE_VOTES;
    fHavePrior = false;
    nPriorNoteVotes = 0;
    bool fIsNoteVote = true;
    std::string error;
    BOOST_CHECK(AdmitPrivacyVNextNoteVote(CTransaction(), NULL, nBoundary + 1,
                                          nBlockNoteVotes, nPriorNoteVotes,
                                          fHavePrior, fIsNoteVote, error));
    BOOST_CHECK(!fIsNoteVote);
    BOOST_CHECK(!fHavePrior);
}

// A vote pays no fee and would sort last, so it is ordered first; the caps keep it
// from crowding a block out.
BOOST_AUTO_TEST_CASE(a_note_vote_is_ordered_ahead_of_fee_paying_traffic)
{
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    VoteChain chain(0x6E770600U);

    FundedNote note;
    Fund(txdb, 0x2b, note);
    BuiltVote vote;
    CastVote(note, chain.pBoundary, 1500001401, vote);

    double dVotePriority = 0.0;
    double dVoteFeePerKb = 0.0;
    ApplyPrivacyVNextNoteVoteSelectionOrder(vote.tx, dVotePriority, dVoteFeePerKb);
    BOOST_CHECK_EQUAL(dVotePriority, std::numeric_limits<double>::max());
    BOOST_CHECK_EQUAL(dVoteFeePerKb, std::numeric_limits<double>::max());

    // Nothing else is touched, including the other zero-fee payload shape.
    double dOtherPriority = 12.5;
    double dOtherFeePerKb = 7.5;
    ApplyPrivacyVNextNoteVoteSelectionOrder(CTransaction(), dOtherPriority,
                                            dOtherFeePerKb);
    BOOST_CHECK_EQUAL(dOtherPriority, 12.5);
    BOOST_CHECK_EQUAL(dOtherFeePerKb, 7.5);

    // The producer's own comparator, mirrored: a max-heap keyed on fee-per-kb when the
    // template has gone over to fee ordering and on priority before that. The vote must
    // come out first either way, or the window closes on it.
    const double dRichPriority = 1e12;
    const double dRichFeePerKb = 1e9;
    BOOST_CHECK(dVoteFeePerKb > dRichFeePerKb);
    BOOST_CHECK(dVotePriority > dRichPriority);
}

// Inertness. Under the lane's fork height the producer returns on its outermost check,
// before it reads a wallet, a note or a chain record.
BOOST_AUTO_TEST_CASE(the_lane_is_inert_while_its_fork_height_is_unset)
{
    const bool fRegTestSaved = fRegTest;
    const bool fTestNetSaved = fTestNet;

    fRegTest = false;
    fTestNet = false;
    BOOST_CHECK(IsIV5NoteVoteConfigured());
    BOOST_CHECK(!IsIV5NoteVoteActiveAtHeight(0));
    BOOST_CHECK(!IsIV5NoteVoteActiveAtHeight(GetForkHeightIV5NoteVote() - 1));
    BOOST_CHECK(IsIV5NoteVoteActiveAtHeight(std::numeric_limits<int>::max()));

    fTestNet = true;
    BOOST_CHECK(IsIV5NoteVoteConfigured());
    BOOST_CHECK(!IsIV5NoteVoteActiveAtHeight(GetForkHeightIV5NoteVote() - 1));
    BOOST_CHECK(IsIV5NoteVoteActiveAtHeight(std::numeric_limits<int>::max()));

    fRegTest = fRegTestSaved;
    fTestNet = fTestNetSaved;

    // On regtest the knob is unset by default too, and the producer refuses on the gate
    // rather than on anything downstream of it.
    {
        ScopedNoteVoteHeight unset(PRIVACY_VNEXT_HEIGHT_UNSET);
        BOOST_CHECK(!IsIV5NoteVoteConfigured());
        CTxDB txdb("r");
        uint256 keyImage = 0;
        std::string error;
        BOOST_CHECK(!ProducePrivacyVNextNoteVote(txdb, NULL, BoundaryHeight(),
                                                 keyImage, error));
        BOOST_CHECK(Mentions(error, "not active at this height"));
        BOOST_CHECK(keyImage == 0);
    }

    // With the lane open the gate stops being the answer, and the next rule speaks.
    {
        ScopedNoteVoteHeight open(0);
        CTxDB txdb("r");
        uint256 keyImage = 0;
        std::string error;
        BOOST_CHECK(!ProducePrivacyVNextNoteVote(txdb, NULL, BoundaryHeight(),
                                                 keyImage, error));
        BOOST_CHECK(!Mentions(error, "not active at this height"));
    }
}

// Vote build time against FINALITY_NOTE_VOTE_INCLUSION_WINDOW at post-DAG spacing, after
// GetFinalityVoteEmitOffset. The builder proves membership twice; the single-prove figure
// is printed alongside.
BOOST_AUTO_TEST_CASE(a_vote_builds_inside_its_inclusion_window)
{
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    VoteChain chain(0x6E770700U);

    FundedNote note;
    Fund(txdb, 0x2d, note);

    std::vector<PrivacyVNextSpendInput> vInputs(1);
    vInputs[0].spendScalar = note.spend.spendSecret;
    vInputs[0].commitmentScalar = note.spend.y;
    vInputs[0].leaf = note.spend.leaf;
    vInputs[0].vchWitnessRecord = note.spend.vchWitnessRecord;
    std::vector<PrivacyVNextSpendConstruction> vProved;
    std::vector<unsigned char> vchProof;
    std::string error;
    const int64_t nProveStart = GetTimeMillis();
    BOOST_REQUIRE_MESSAGE(
        ProvePrivacyVNextMembership(note.finalizedRoot, LowScalar(1),
                                    LowScalar(0x5c), vInputs, vProved, vchProof,
                                    error),
        error);
    const int64_t nProveMs = GetTimeMillis() - nProveStart;

    BuiltVote vote;
    const int64_t nBuildStart = GetTimeMillis();
    CastVote(note, chain.pBoundary, 1500001501, vote);
    const int64_t nBuildMs = GetTimeMillis() - nBuildStart;

    // Verification cost paid by every other voter and validator: the membership proof,
    // verified as the mix verifies its segments, with the proof cache cleared.
    PrivacyVNextStateEffects verifyEffects;
    const PrivacyVNextPayloadValidation verifyResult =
        ExtractPrivacyVNextPayloadEffects(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                          vote.payload, verifyEffects);
    BOOST_CHECK_MESSAGE(verifyResult.nResult == INNOVA_PRIVACY_VNEXT_VALID,
                        verifyResult.strError);
    BOOST_REQUIRE(!vProved.empty());
    PrivacyVNextDigest verifyKeyImage;
    std::memcpy(verifyKeyImage.data(), vote.keyImage.data(), 32);
    std::string strVerify;
    VerifyProofCacheClear();
    const int64_t nVerifyStart = GetTimeMillis();
    const bool fVerified = VerifyPrivacyVNextInputMembership(
        note.finalizedRoot, LowScalar(1), vProved[0].pseudoOut, verifyKeyImage, vchProof,
        strVerify);
    const int64_t nVerifyMs = GetTimeMillis() - nVerifyStart;
    BOOST_CHECK_MESSAGE(fVerified, strVerify);
    const int64_t nWarmStart = GetTimeMillis();
    VerifyPrivacyVNextInputMembership(note.finalizedRoot, LowScalar(1), vProved[0].pseudoOut,
                                      verifyKeyImage, vchProof, strVerify);
    const int64_t nWarmMs = GetTimeMillis() - nWarmStart;

    const int64_t nWindowMs =
        (int64_t)(FINALITY_NOTE_VOTE_INCLUSION_WINDOW -
                  GetFinalityVoteEmitOffset(BoundaryHeight())) *
        1000;
    // util.h redirects printf into debug.log, so the number a reader of the test run needs
    // goes to stderr as well.
    std::fprintf(stderr,
                 "note vote build: %" PRId64 " ms (one membership prove %" PRId64
                 " ms) against a %" PRId64 " ms window, payload %u bytes\n",
                 nBuildMs, nProveMs, nWindowMs,
                 (unsigned int)vote.payload.size());
    std::fprintf(stderr,
                 "note vote membership verify: %" PRId64 " ms cold, %" PRId64 " ms again; "
                 "an epoch costs a voter one build plus one cold verify per other voter\n",
                 nVerifyMs, nWarmMs);
    printf("note vote build: %" PRId64 " ms (one membership prove %" PRId64 " ms) "
           "against a %" PRId64 " ms window, payload %u bytes\n",
           nBuildMs, nProveMs, nWindowMs, (unsigned int)vote.payload.size());
    printf("note vote membership verify: %" PRId64 " ms cold, %" PRId64 " ms again\n",
           nVerifyMs, nWarmMs);

    // The consensus deadline, not a comfort margin. A build that does not fit means the
    // lane cannot cast a vote on this hardware and the two-phase prove is required.
    BOOST_CHECK_MESSAGE(nBuildMs < nWindowMs,
                        "an IV5 note vote took " << nBuildMs
                        << " ms to build, which does not fit the " << nWindowMs
                        << " ms inclusion window");
    // The size the design costed. A payload materially over it would not be the shape the
    // block and window caps were sized against.
    BOOST_CHECK_LT(vote.payload.size(), (size_t)10000);
}

// The producer proves only inside the note lane's own window, not the transparent one.
BOOST_AUTO_TEST_CASE(the_producer_window_is_the_note_vote_window)
{
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    VoteChain chain(0x6E770900U);
    const int nBoundary = BoundaryHeight();
    const char* strClosed = "the epoch's inclusion window is not open at this height";
    uint256 keyImage = 0;
    std::string error;
    ProducePrivacyVNextNoteVote(txdb, chain.pBoundary,
                                nBoundary + FINALITY_VOTE_INCLUSION_WINDOW, keyImage, error);
    BOOST_CHECK_MESSAGE(!Mentions(error, strClosed), error);
    error.clear();
    BOOST_CHECK(!ProducePrivacyVNextNoteVote(txdb, chain.pBoundary,
                                             nBoundary + FINALITY_NOTE_VOTE_INCLUSION_WINDOW,
                                             keyImage, error));
    BOOST_CHECK_MESSAGE(Mentions(error, strClosed), error);
}

BOOST_AUTO_TEST_SUITE_END()
