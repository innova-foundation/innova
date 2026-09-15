// Note finality vote reward (a mint), bounded by block connect and epoch build. Entitlement
// is GetFinalityNoteVoteReward(E); also covers the stake floor and emission neutrality.

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <limits>
#include <set>
#include <string>
#include <vector>

#include "../privacy_vnext/rust/include/innova_privacy_vnext.h"
#include "../dag.h"
#include "../finality.h"
#include "../finality_note.h"
#include "../main.h"
#include "../privacy_vnext_builder.h"
#include "../privacy_vnext_ffi.h"
#include "../privacy_vnext_store.h"
#include "../shielded.h"
#include "../subsidy.h"
#include "../txdb.h"
#include "../wallet.h"
#include "synthetic_chain.h"

extern bool fRegTest;
extern bool fTestNet;

BOOST_AUTO_TEST_SUITE(note_vote_reward_tests)

namespace
{

// A note comfortably over the stake floor, so no case here fails for the floor's reason.
uint64_t VoteNoteAmount()
{
    return (uint64_t)GetFinalityMinVoteWeight(0);
}

// The post-DAG epoch the connect-path cases name. Its boundary is 1211 on regtest.
const int kEpoch = 5;

int BoundaryHeight()
{
    return GetEpochBoundaryHeight(kEpoch, 0);
}

PrivacyVNextDigest FillDigest(unsigned char fill)
{
    PrivacyVNextDigest d;
    d.fill(fill);
    return d;
}

PrivacyVNextDigest ScalarDigest(unsigned char low)
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

// Read at use: the fixture sets fRegTest after this unit's globals are constructed.
uint8_t LocalNetwork()
{
    return PrivacyVNextLocalNetworkId();
}

PrivacyVNextDigest NoTransparentSide()
{
    PrivacyVNextDigest d;
    const uint256 binding = GetPrivacyVNextTransparentBinding(CTransaction());
    std::memcpy(d.data(), binding.begin(), 32);
    return d;
}

std::vector<unsigned char> DigestBytes(const PrivacyVNextDigest& d)
{
    return std::vector<unsigned char>(d.begin(), d.end());
}

uint256 AsUint256(const PrivacyVNextDigest& d)
{
    uint256 out;
    std::memcpy(out.begin(), d.data(), d.size());
    return out;
}

PrivacyVNextDigest BlockDigest(const CBlockIndex* pindex)
{
    PrivacyVNextDigest d;
    const uint256 hash = pindex->GetBlockHash();
    std::memcpy(d.data(), hash.begin(), 32);
    return d;
}

// The contract digest this build was compiled against. The decoder carries it and never
// judges it; consensus judges it against the digest the chain's epoch record carries.
PrivacyVNextDigest ContractDigest()
{
    PrivacyVNextDigest d;
    BOOST_REQUIRE(iv5::DecodeDigestHex(iv5::PROTOCOL_CONTRACT_SHA256, d.data()));
    return d;
}

// The digest a chain's FIRST IV5 epoch stamps, which is what the epoch-build cases run
// under: their epoch is the chain's first, so the seed's digest is the chain's.
PrivacyVNextDigest GenesisParameterDigest()
{
    PrivacyVNextEpochSeed seed;
    std::string error;
    BOOST_REQUIRE_MESSAGE(LoadPrivacyVNextEpochSeed(seed, error), error);
    BOOST_REQUIRE_EQUAL(seed.vchParameterDigest.size(), (size_t)32);
    PrivacyVNextDigest d;
    std::memcpy(d.data(), &seed.vchParameterDigest[0], 32);
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
                                       std::vector<PrivacyVNextDigest>(), context, error),
        error);
    return context;
}

// One note of a chosen amount in a fresh tree, reopened by its owner, with the membership
// witness a proof over it needs.
struct FundedNote
{
    PrivacyVNextDerivedKeys keys;
    PrivacyVNextDigest seed;
    PrivacyVNextSpendNote spend;
    PrivacyVNextDigest keyImage;
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
    out.seed = FillDigest(nSeed);
    if (!DerivePrivacyVNextKeys(out.seed, genesis, 0, LocalNetwork(), 0, out.keys, error))
        return false;

    PrivacyVNextEncryptedOutput encrypted;
    if (!EncryptPrivacyVNextNote(
            LocalNetwork(), 0, 0, genesis, out.keys.spendPublic, out.keys.viewPublic,
            out.keys.outgoingViewSecret, ScalarDigest(nSeed + 1), ScalarDigest(nSeed + 2),
            nAmount, ScalarDigest(nSeed + 3), ScalarDigest(nSeed + 4), FundingContext(),
            encrypted, error))
        return false;

    PrivacyVNextEpochSeed epochSeed;
    if (!LoadPrivacyVNextEpochSeed(epochSeed, error))
        return false;
    std::vector<unsigned char> treeState = epochSeed.vchTreeState;
    if (!TrimPrivacyVNextTreeStore(txdb, 0, treeState, error))
        return false;
    std::vector<PrivacyVNextOutputLeaf> vLeaves;
    vLeaves.push_back(encrypted.leaf);
    if (!GrowPrivacyVNextTreeStore(txdb, vLeaves, treeState, error))
        return false;

    std::vector<unsigned char> vchRoot;
    if (!DecodePrivacyVNextTreeState(treeState, vchRoot, out.nTreeSize, error))
        return false;
    std::memcpy(out.finalizedRoot.data(), &vchRoot[0], 32);

    std::vector<uint64_t> vTargets(1, 0);
    std::vector<unsigned char> vchPaths;
    if (!ReadPrivacyVNextTreePaths(txdb, out.nTreeSize, treeState, vTargets, vchPaths,
                                   error))
        return false;
    std::vector<PrivacyVNextMembershipWitness> vWitnesses;
    PrivacyVNextDigest treeRoot;
    if (!BuildPrivacyVNextWitnessesFromPaths(treeState, vTargets, vchPaths, vWitnesses,
                                             treeRoot, error))
        return false;

    PrivacyVNextEncryptedNote onChain;
    onChain.nOutputIndex = 0;
    onChain.genesis = genesis;
    onChain.leafO = encrypted.leaf.owner;
    onChain.leafC = encrypted.leaf.commitment;
    onChain.noteEphemeral = encrypted.noteEphemeral;
    onChain.tweakEphemeral = encrypted.tweakEphemeral;
    onChain.vchCiphertext = encrypted.vchRecipientCiphertext;
    onChain.inputContext = FundingContext();
    PrivacyVNextScannedNote scanned;
    if (!ScanPrivacyVNextNote(PRIVACY_VNEXT_SCAN_FULL, LocalNetwork(), 0, onChain,
                              out.keys.viewSecret, out.keys.spendSecret, scanned, error))
        return false;

    out.spend.spendSecret = scanned.spendSecret;
    out.spend.y = scanned.y;
    out.spend.mask = scanned.mask;
    out.spend.nAmount = scanned.nAmount;
    out.spend.leaf = encrypted.leaf;
    out.spend.vchWitnessRecord = vWitnesses[0].vchRecord;
    out.keyImage = scanned.keyImage;
    return true;
}

// A transaction that carries a payload and nothing else, which is all a vote is.
CTransaction CarryingTx(const std::vector<unsigned char>& payload, uint32_t nTime)
{
    CTransaction tx;
    tx.nVersion = INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION;
    tx.nTime = nTime;
    tx.privacyVNext.vchPayload = payload;
    return tx;
}

// A vote built by the production builder, which is what the wallet calls. The reward is
// passed in so a case can claim more or less than its epoch owes it.
struct BuiltVote
{
    std::vector<unsigned char> payload;
    PrivacyVNextDigest keyImage;
    PrivacyVNextStateEffects effects;
    CTransaction tx;
};

bool BuildVote(const FundedNote& note, const PrivacyVNextDigest& parameterDigest,
               const PrivacyVNextDigest& boundaryHash, int nBoundaryHeight,
               int64_t nClaimedReward, uint32_t nTime, BuiltVote& out,
               std::string& error)
{
    // The reissue's self-pay index is drawn from the key image, so the key image has to be
    // known first. The scan reported the note's own, which is what the proof publishes.
    std::vector<PrivacyVNextDigest> vKeyImages(1, note.keyImage);
    const uint32_t nIndex = PrivacyVNextChangeIndexFor(LocalGenesis(), LocalNetwork(),
                                                       NoTransparentSide(), vKeyImages);
    PrivacyVNextDerivedKeys reissueKeys;
    if (!DerivePrivacyVNextChangeKeys(note.seed, LocalGenesis(), LocalNetwork(), nIndex,
                                      reissueKeys, error))
        return false;

    PrivacyVNextAddressComponents reissueTo;
    reissueTo.nNetwork = LocalNetwork();
    reissueTo.nAddressType = 0;
    reissueTo.spendPublic = reissueKeys.spendPublic;
    reissueTo.viewPublic = reissueKeys.viewPublic;

    const std::vector<unsigned char> vchDigest = DigestBytes(parameterDigest);
    if (!BuildPrivacyVNextNoteVotePayload(
            LocalNetwork(), LocalGenesis(), reissueKeys.outgoingViewSecret,
            note.finalizedRoot, note.nTreeSize, NoTransparentSide(), boundaryHash,
            (uint32_t)nBoundaryHeight, nClaimedReward, note.spend, reissueTo,
            out.payload, out.keyImage, error, &vchDigest))
        return false;

    const PrivacyVNextPayloadValidation extracted =
        ExtractPrivacyVNextPayloadEffects(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                          out.payload, out.effects);
    if (!extracted.IsValid())
    {
        error = extracted.strError;
        return false;
    }
    out.tx = CarryingTx(out.payload, nTime);
    return true;
}

void CastVote(const FundedNote& note, const CBlockIndex* pNamed, int64_t nClaimedReward,
              uint32_t nTime, BuiltVote& out)
{
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        BuildVote(note, ContractDigest(), BlockDigest(pNamed), pNamed->nHeight,
                  nClaimedReward, nTime, out, error),
        error);
    BOOST_REQUIRE(out.effects.HasVoteBoundary());
    BOOST_REQUIRE_EQUAL(out.effects.keyImages.size(), 1U);
}

// The network selection, restored on scope exit even if an assertion throws.
struct ScopedNetwork
{
    bool fSavedRegTest;
    bool fSavedTestNet;
    ScopedNetwork(bool fRegTestIn, bool fTestNetIn)
        : fSavedRegTest(fRegTest), fSavedTestNet(fTestNet)
    {
        fRegTest = fRegTestIn;
        fTestNet = fTestNetIn;
    }
    ~ScopedNetwork()
    {
        fRegTest = fSavedRegTest;
        fTestNet = fSavedTestNet;
    }
};

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
        BOOST_REQUIRE(txdb.WriteEpochState(nEpoch, install));
    }
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
    void Track(const PrivacyVNextDigest& keyImage) { vKeys.push_back(AsUint256(keyImage)); }
    ~ScopedSpentKeys()
    {
        for (size_t i = 0; i < vKeys.size(); ++i)
            txdb.ErasePrivacyVNextNullifier(vKeys[i]);
    }
};

// The carrier chain: the epoch boundary and its inclusion window.
struct VoteChain
{
    CSyntheticChain chain;
    CBlockIndex* pParent;
    CBlockIndex* pBoundary;
    CBlockIndex* pTip;

    explicit VoteChain(unsigned int nTag) : chain(nTag)
    {
        pParent = chain.Linear(BoundaryHeight() - 1);
        BOOST_REQUIRE(pParent != NULL);
        pBoundary = chain.Extend(pParent, 1);
        BOOST_REQUIRE(pBoundary != NULL);
        pTip = chain.Extend(pBoundary, FINALITY_VOTE_INCLUSION_WINDOW);
        BOOST_REQUIRE(pTip != NULL);
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
    s.vchVNextRoot = DigestBytes(note.finalizedRoot);
    s.nVNextTreeSize = note.nTreeSize;
    s.vchVNextParameterDigest = DigestBytes(ContractDigest());
    return s;
}

bool Mentions(const std::string& strError, const char* what)
{
    return strError.find(what) != std::string::npos;
}

// The value-flow reading ConnectInputs, the mempool, the miner and ConnectBlock's own fee
// accounting all take, from the one derivation they share.
struct Flow
{
    bool fOK;
    int64_t nAbsorbed;
    int64_t nReleased;
    int64_t nDeclaredFee;
    int64_t nDeclaredBalance;
    int64_t nMint;
    bool fLocalFailure;
    std::string strError;
};

Flow FlowOf(const CTransaction& tx)
{
    Flow f;
    f.nAbsorbed = 0;
    f.nReleased = 0;
    f.nDeclaredFee = 0;
    f.nDeclaredBalance = 0;
    f.nMint = 0;
    f.fLocalFailure = false;
    f.fOK = GetPrivacyVNextTransparentFlow(tx, f.nAbsorbed, f.nReleased, f.fLocalFailure,
                                           f.strError, &f.nDeclaredFee,
                                           &f.nDeclaredBalance, &f.nMint);
    return f;
}

} // namespace

// ---------------------------------------------------------------------------
// The entitlement
// ---------------------------------------------------------------------------

// R_E is the epoch's withheld reserve over the epoch's slot cap, and the cap is the one
// ConnectBlock enforces on the inclusion window. Dividing by the cap rather than by the
// turnout is what makes votes * R_E <= budget hold at every turnout.
BOOST_AUTO_TEST_CASE(the_entitlement_is_the_epoch_budget_over_the_slot_cap)
{
    BOOST_REQUIRE(fRegTest);
    const int64_t nBudget = GetFinalityEpochBudget(kEpoch);
    BOOST_REQUIRE_MESSAGE(nBudget > 0,
                          "epoch " << kEpoch << " withholds nothing, so the mint under "
                          "test would be zero and every case below vacuous");
    BOOST_CHECK_EQUAL(GetFinalityNoteVoteReward(kEpoch),
                      nBudget / (int64_t)FINALITY_MAX_EPOCH_NOTE_VOTES);

    // An epoch with no accrual owes nothing, and the pre-DAG epochs are all of them.
    BOOST_CHECK_EQUAL(GetFinalityNoteVoteReward(0), 0);
    BOOST_CHECK_EQUAL(GetFinalityNoteVoteReward(-1), 0);
}

// The lane cannot issue more than the epoch reserved, at any turnout up to the cap. This
// is the whole reason the divisor is the cap: with the turnout as divisor a single vote
// would take the entire budget and the transparent settlement would have nothing left.
BOOST_AUTO_TEST_CASE(the_note_lane_can_never_mint_more_than_the_epoch_reserved)
{
    BOOST_REQUIRE(fRegTest);
    for (int nEpoch = kEpoch; nEpoch < kEpoch + 6; ++nEpoch)
    {
        const int64_t nBudget = GetFinalityEpochBudget(nEpoch);
        const int64_t nReward = GetFinalityNoteVoteReward(nEpoch);
        BOOST_REQUIRE(nReward >= 0);
        BOOST_CHECK_MESSAGE(
            nReward * (int64_t)FINALITY_MAX_EPOCH_NOTE_VOTES <= nBudget,
            "epoch " << nEpoch << " could mint more than it reserved");
    }
}

// ---------------------------------------------------------------------------
// The connect path
// ---------------------------------------------------------------------------

// A vote that claims exactly what its epoch owes it passes every connect-time rule, and
// the value it brings in is reported as a mint rather than as absorbed value some
// transparent input owes -- which is what keeps the carrier block's producer whole.
BOOST_AUTO_TEST_CASE(a_correctly_claiming_vote_mints_its_entitlement_and_connects)
{
    BOOST_REQUIRE(fRegTest);
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    VoteChain chain(0x6E765200U);

    const int64_t nReward = GetFinalityNoteVoteReward(kEpoch);
    BOOST_REQUIRE(nReward > 0);

    FundedNote note;
    std::string error;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0x31, VoteNoteAmount(), note, error), error);

    BuiltVote vote;
    CastVote(note, chain.pBoundary, nReward, 1500002101, vote);

    // What the payload declares is what the epoch owes, and the decoder reports it.
    BOOST_CHECK_EQUAL(vote.effects.nTransparentValueBalance, nReward);
    BOOST_CHECK_EQUAL((int64_t)vote.effects.nFee, 0);

    // The pin itself: the ConnectBlock privacy loop's own call.
    int64_t nMint = -1;
    std::string strMintError;
    BOOST_CHECK_MESSAGE(GetPrivacyVNextNoteVoteMint(vote.effects, nMint, strMintError),
                        strMintError);
    BOOST_CHECK_EQUAL(nMint, nReward);

    // The shared value-flow derivation, which is what ConnectInputs, the mempool, the
    // miner and ConnectBlock's fee accounting all read.
    const Flow flow = FlowOf(vote.tx);
    BOOST_CHECK_MESSAGE(flow.fOK, flow.strError);
    BOOST_CHECK_EQUAL(flow.nAbsorbed, nReward);
    BOOST_CHECK_EQUAL(flow.nReleased, 0);
    BOOST_CHECK_EQUAL(flow.nDeclaredFee, 0);
    BOOST_CHECK_EQUAL(flow.nDeclaredBalance, nReward);
    BOOST_CHECK_EQUAL(flow.nMint, nReward);
    // The credit and the charge are the same number, so the vote's fee is exactly zero
    // and no producer pays for the epoch's own reserve.
    BOOST_CHECK_EQUAL(flow.nMint - flow.nAbsorbed, 0);
    BOOST_CHECK(IsPrivacyVNextFeeExemptShape(vote.tx));

    // And it connects: the carrier shape, the anchor and window rules, and the spend.
    std::string strCarrierError;
    BOOST_CHECK_MESSAGE(
        CheckPrivacyVNextNoteVoteCarrier(vote.tx, vote.effects, strCarrierError),
        strCarrierError);

    ScopedEpochRecord record(txdb, kEpoch - 1, AnchorRecord(note, chain.pBoundary));
    bool fLocalFailure = false;
    bool fUnavailable = false;
    std::string strContextError;
    BOOST_CHECK_MESSAGE(
        ValidatePrivacyVNextNoteVoteContext(txdb, chain.pBoundary, chain.pBoundary->nHeight,
                                            vote.effects, fLocalFailure, fUnavailable,
                                            strContextError),
        strContextError);

    ScopedSpentKeys spent(txdb);
    spent.Track(vote.keyImage);
    std::set<uint256> setBlock;
    std::string strSpendError;
    BOOST_CHECK_EQUAL(
        (int)ConnectPrivacyVNextSpentKeys(txdb, vote.tx, vote.effects,
                                          chain.pBoundary->nHeight, false, setBlock,
                                          strSpendError),
        (int)PRIVACY_VNEXT_SPEND_OK);
}

// One satoshi over the entitlement is refused, on the connect path, by both of the calls
// ConnectBlock makes: the value-flow derivation its fee accounting reads, and the pin the
// privacy loop applies immediately before the pool absorbs the value.
BOOST_AUTO_TEST_CASE(connect_refuses_a_vote_claiming_over_its_entitlement)
{
    BOOST_REQUIRE(fRegTest);
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    VoteChain chain(0x6E765201U);

    const int64_t nReward = GetFinalityNoteVoteReward(kEpoch);
    BOOST_REQUIRE(nReward > 0);

    FundedNote note;
    std::string error;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0x32, VoteNoteAmount(), note, error), error);

    BuiltVote over;
    CastVote(note, chain.pBoundary, nReward + 1, 1500002201, over);
    // The payload is well-formed and every proof in it verifies: the decoder admits value
    // entering because only the chain knows how much is owed. What refuses it is the pin.
    BOOST_CHECK_EQUAL(over.effects.nTransparentValueBalance, nReward + 1);

    int64_t nMint = -1;
    std::string strMintError;
    BOOST_CHECK(!GetPrivacyVNextNoteVoteMint(over.effects, nMint, strMintError));
    BOOST_CHECK_EQUAL(nMint, 0);
    BOOST_CHECK(Mentions(strMintError, "against an entitlement of"));

    const Flow flow = FlowOf(over.tx);
    BOOST_CHECK(!flow.fOK);
    BOOST_CHECK(!flow.fLocalFailure);
    BOOST_CHECK(Mentions(flow.strError, "against an entitlement of"));
    BOOST_CHECK_EQUAL(flow.nMint, 0);
    BOOST_CHECK_EQUAL(flow.nAbsorbed, 0);

    // Under-claiming is refused by the same equality, so the rule cannot be satisfied by
    // building a vote that merely takes less than it is owed and banking the difference
    // somewhere the settlement no longer looks.
    BuiltVote under;
    CastVote(note, chain.pBoundary, nReward - 1, 1500002202, under);
    BOOST_CHECK(!GetPrivacyVNextNoteVoteMint(under.effects, nMint, strMintError));
    BOOST_CHECK(Mentions(strMintError, "against an entitlement of"));
    BOOST_CHECK(!FlowOf(under.tx).fOK);

    // A vote naming a height that opens no post-DAG epoch has no entitlement to compute,
    // so it is refused rather than defaulted to zero.
    BuiltVote offBoundary;
    BOOST_REQUIRE_MESSAGE(
        BuildVote(note, ContractDigest(), BlockDigest(chain.pBoundary),
                  chain.pBoundary->nHeight + 1, nReward, 1500002203, offBoundary, error),
        error);
    BOOST_CHECK(!GetPrivacyVNextNoteVoteMint(offBoundary.effects, nMint, strMintError));
    BOOST_CHECK(Mentions(strMintError, "opens no post-DAG epoch"));
}

// ---------------------------------------------------------------------------
// The stake floor
// ---------------------------------------------------------------------------

// The floor is 500 INN and it is read by height, not restated as a constant at each site.
// One rung today, so every height answers alike; what the shape buys is that changing it
// later is a table row rather than a change to what "the floor" means at a given height.
BOOST_AUTO_TEST_CASE(the_stake_floor_is_five_hundred_inn_and_is_read_by_height)
{
    BOOST_CHECK_EQUAL(GetFinalityMinVoteWeight(0), 500 * COIN);
    BOOST_CHECK_EQUAL(GetFinalityMinVoteWeight(FORK_HEIGHT_DAG), 500 * COIN);
    BOOST_CHECK_EQUAL(GetFinalityMinVoteWeight(BoundaryHeight()), 500 * COIN);
    BOOST_CHECK_EQUAL(GetFinalityMinVoteWeight(std::numeric_limits<int>::max()),
                      500 * COIN);
    // A height below genesis is no chain position; it answers with the first rung rather
    // than reading past the table.
    BOOST_CHECK_EQUAL(GetFinalityMinVoteWeight(-1), 500 * COIN);
}

// ---------------------------------------------------------------------------
// Supply
// ---------------------------------------------------------------------------

// The settlement pays the budget less the note lane's mint, so total epoch emission is the
// schedule's with the lane on or off.
BOOST_AUTO_TEST_CASE(the_settlement_pays_the_budget_less_what_the_note_lane_minted)
{
    BOOST_REQUIRE(fRegTest);
    const int64_t nBudget = GetFinalityEpochBudget(kEpoch);
    const int64_t nReward = GetFinalityNoteVoteReward(kEpoch);
    BOOST_REQUIRE(nBudget > 0 && nReward > 0);

    // Headroom to spare, so the clamp is not what is under test here.
    CBlockIndex idx;
    idx.nHeight = GetFinalitySettlementHeight(kEpoch, BoundaryHeight()) - 1;
    idx.nMoneySupply = 0;

    BOOST_CHECK_EQUAL(GetClampedFinalitySettlementBudget(&idx, kEpoch, 0), nBudget);

    for (int nVotes = 0; nVotes <= (int)FINALITY_MAX_EPOCH_NOTE_VOTES; ++nVotes)
    {
        const int64_t nMinted = (int64_t)nVotes * nReward;
        const int64_t nRemainder =
            GetClampedFinalitySettlementBudget(&idx, kEpoch, nMinted);
        BOOST_REQUIRE_MESSAGE(nRemainder >= 0,
                              "settlement remainder went negative at " << nVotes
                              << " note votes");
        BOOST_CHECK_MESSAGE(nMinted + nRemainder <= nBudget,
                            "the epoch issued more than it reserved at " << nVotes
                            << " note votes");
        if (nMinted < nBudget)
            BOOST_CHECK_EQUAL(nRemainder, nBudget - nMinted);
        else
            BOOST_CHECK_EQUAL(nRemainder, 0);
    }
}

// The reserve is a closed sum over a height range, so an epoch's whole issuance is the
// schedule's share of it however it is split. Stated here because the note lane is the
// first channel that mints outside a coinbase.
BOOST_AUTO_TEST_CASE(total_epoch_issuance_is_unchanged_by_the_note_lane)
{
    BOOST_REQUIRE(fRegTest);
    int nBegin = 0;
    int nEnd = 0;
    BOOST_REQUIRE(GetFinalityAccrualRange(kEpoch, nBegin, nEnd));
    const int64_t nAccrued = SumFinalityReserve(nBegin, nEnd);
    BOOST_REQUIRE_EQUAL(nAccrued, GetFinalityEpochBudget(kEpoch));

    // What every block over the range withheld from its own coinbase is exactly what the
    // two legs may pay out, and no more.
    int64_t nWithheld = 0;
    for (int nHeight = nBegin; nHeight < nEnd; ++nHeight)
        nWithheld += GetFinalityReservePerBlock(nHeight);
    BOOST_CHECK_EQUAL(nWithheld, nAccrued);

    CBlockIndex idx;
    idx.nHeight = GetFinalitySettlementHeight(kEpoch, BoundaryHeight()) - 1;
    idx.nMoneySupply = 0;
    const int64_t nReward = GetFinalityNoteVoteReward(kEpoch);
    const int64_t nFullTurnout = nReward * (int64_t)FINALITY_MAX_EPOCH_NOTE_VOTES;
    BOOST_CHECK(nFullTurnout <= nWithheld);
    BOOST_CHECK(nFullTurnout +
                    GetClampedFinalitySettlementBudget(&idx, kEpoch, nFullTurnout) <=
                nWithheld);
}

// ---------------------------------------------------------------------------
// Inertness
// ---------------------------------------------------------------------------

// Below the lane's fork height no op-10 payload connects and no settlement reads a window
// block for one.
BOOST_AUTO_TEST_CASE(the_reward_path_is_inert_while_the_lane_is_unconfigured)
{
    {
        ScopedNetwork mainnet(false, false);
        BOOST_CHECK(IsIV5NoteVoteConfigured());
        BOOST_CHECK(!IsIV5NoteVoteActiveAtHeight(GetForkHeightIV5NoteVote() - 1));
        BOOST_CHECK(IsIV5NoteVoteActiveAtHeight(GetForkHeightIV5NoteVote()));
    }
    {
        ScopedNetwork testnet(false, true);
        BOOST_CHECK(IsIV5NoteVoteConfigured());
        BOOST_CHECK(!IsIV5NoteVoteActiveAtHeight(GetForkHeightIV5NoteVote() - 1));
        BOOST_CHECK(IsIV5NoteVoteActiveAtHeight(GetForkHeightIV5NoteVote()));
    }

    // With the lane off, the settlement's deduction is zero and no window block is read
    // for it -- a settlement block on a network without the lane costs what it always did.
    ScopedNoteVoteHeight fork(PRIVACY_VNEXT_HEIGHT_UNSET);
    CSyntheticChain chain(0x6E765202U);
    CBlockIndex* pTop = chain.Linear(BoundaryHeight() + FINALITY_VOTE_INCLUSION_WINDOW - 1);
    BOOST_REQUIRE(pTop != NULL);

    int64_t nTotal = -1;
    bool fLocalFailure = true;
    std::string strError;
    BOOST_CHECK(GetPrivacyVNextNoteVoteMintTotal(pTop, kEpoch, nTotal, fLocalFailure,
                                                 strError));
    BOOST_CHECK_EQUAL(nTotal, 0);
    BOOST_CHECK(!fLocalFailure);
    BOOST_CHECK(strError.empty());

    // A null parent is the genesis case and is not a failure either.
    BOOST_CHECK(GetPrivacyVNextNoteVoteMintTotal(NULL, kEpoch, nTotal, fLocalFailure,
                                                 strError));
    BOOST_CHECK_EQUAL(nTotal, 0);
}

// ---------------------------------------------------------------------------
// The epoch build
// ---------------------------------------------------------------------------

namespace
{

// Post-DAG proof-of-work block indexes with real block data on disk, which is what the
// epoch build reads. Boundary B sits at the epoch-state V3 height so the epoch under test
// is the chain's FIRST IV5 epoch and stamps the seed's own parameter digest.
struct EpochBuildHarness
{
    std::vector<uint256>      hashes;
    std::vector<CBlockIndex*> blocks;
    CBlockIndex*              oldBest;
    bool                      oldRegTest;
    bool                      oldTestNet;
    int                       oldBoundaryB;
    CBigNum                   oldProofOfWorkLimit;

    EpochBuildHarness()
    {
        oldRegTest = fRegTest;
        oldTestNet = fTestNet;
        fRegTest = true;
        fTestNet = false;
        oldProofOfWorkLimit = bnProofOfWorkLimit;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        oldBest = pindexBest;
        oldBoundaryB = nRegtestBoundaryBHeight;
        nRegtestBoundaryBHeight = FORK_HEIGHT_EPOCH_STATE_V3;
    }

    ~EpochBuildHarness()
    {
        for (size_t i = 0; i < hashes.size(); ++i)
        {
            g_dagManager.RemoveBlockDAGData(hashes[i]);
            mapBlockIndex.erase(hashes[i]);
            delete blocks[i];
        }
        hashes.clear();
        blocks.clear();
        pindexBest = oldBest;
        nRegtestBoundaryBHeight = oldBoundaryB;
        bnProofOfWorkLimit = oldProofOfWorkLimit;
        fRegTest = oldRegTest;
        fTestNet = oldTestNet;
    }

    CBlockIndex* Add(unsigned int nSeed, int nHeight, CBlockIndex* pprev,
                     const std::vector<CTransaction>* pvtx)
    {
        CBlock block;
        block.nVersion = 1;
        block.hashPrevBlock = pprev ? pprev->GetBlockHash() : uint256(0);
        block.nTime = (unsigned int)(1700000000 + nHeight);
        block.nBits = bnProofOfWorkLimit.GetCompact();
        block.nNonce = nSeed;
        if (pvtx && !pvtx->empty())
        {
            block.vtx = *pvtx;
            block.hashMerkleRoot = block.BuildMerkleTree();
        }
        else
        {
            block.hashMerkleRoot = uint256(nSeed);
        }
        while (!CheckProofOfWork(block.GetHash(), block.nBits))
            ++block.nNonce;

        unsigned int nFile = 0;
        unsigned int nBlockPos = 0;
        BOOST_REQUIRE(block.WriteToDisk(nFile, nBlockPos));

        const uint256 h = block.GetHash();
        CBlockIndex* pindex = new CBlockIndex(nFile, nBlockPos, block);
        pindex->nHeight = nHeight;
        pindex->pprev = pprev;
        std::pair<std::map<uint256, CBlockIndex*>::iterator, bool> ins =
            mapBlockIndex.insert(std::make_pair(h, pindex));
        BOOST_REQUIRE(ins.second);
        pindex->phashBlock = &ins.first->first;
        std::vector<uint256> parents;
        if (pprev)
            parents.push_back(pprev->GetBlockHash());
        g_dagManager.InitBlockDAGData(pindex, parents);
        if (nHeight >= FORK_HEIGHT_DAGKNIGHT)
            BOOST_REQUIRE(g_dagManager.ColorBlockDAGKnight(pindex));
        else
            g_dagManager.ColorBlock(pindex);
        pindex->nChainTrust = g_dagManager.ComputeDAGScore(pindex);
        hashes.push_back(h);
        blocks.push_back(pindex);
        return pindex;
    }
};

int EpochUnderTest()   { return GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3); }
int EpochStartHeight() { return GetEpochBoundaryHeight(EpochUnderTest(),
                                                       FORK_HEIGHT_EPOCH_STATE_V3); }
int EpochEndHeight()   { return GetEpochBoundaryHeight(EpochUnderTest() + 1,
                                                       FORK_HEIGHT_EPOCH_STATE_V3) - 1; }

// The predecessor the epoch under test needs: its finalized height is the block before
// the epoch, which is what gives the walk somewhere to stop.
CEpochState PredecessorFor(const CBlockIndex* pBefore)
{
    CEpochState prev;
    prev.nEpoch = EpochUnderTest() - 1;
    prev.hashBoundaryBlock = pBefore->GetBlockHash();
    prev.nHeightStart = GetEpochBoundaryHeight(EpochUnderTest() - 1, EpochStartHeight());
    prev.nHeightEnd = EpochStartHeight() - 1;
    prev.hashCurveRoot = 0;
    prev.nFinalizedHeightAsOf = EpochStartHeight() - 1;
    return prev;
}

// One epoch of blocks, the second of which carries a note finality vote claiming
// nClaimedReward. Returns the boundary block the epoch is built at.
CBlockIndex* BuildEpochCarryingVote(EpochBuildHarness& h, unsigned int nSeedBase,
                                    const FundedNote& note, int64_t nClaimedReward,
                                    CBlockIndex*& pBeforeOut, BuiltVote& voteOut)
{
    const int hStart = EpochStartHeight();
    const int hEnd = EpochEndHeight();

    std::string error;
    PrivacyVNextDigest boundaryHash;
    boundaryHash.fill(0);
    boundaryHash[0] = 0x11;   // any nonzero hash: the epoch build judges no ancestry
    BOOST_REQUIRE_MESSAGE(
        BuildVote(note, GenesisParameterDigest(), boundaryHash, hStart, nClaimedReward,
                  1500003101, voteOut, error),
        error);

    pBeforeOut = h.Add(nSeedBase + 0, hStart - 1, NULL, NULL);
    CBlockIndex* p = h.Add(nSeedBase + 1, hStart, pBeforeOut, NULL);
    std::vector<CTransaction> vVote(1, voteOut.tx);
    p = h.Add(nSeedBase + 2, hStart + 1, p, &vVote);
    for (int nHeight = hStart + 2; nHeight <= hEnd; ++nHeight)
        p = h.Add(nSeedBase + 3 + (unsigned int)(nHeight - hStart), nHeight, p, NULL);
    return p;
}

} // namespace

// The epoch build applies the payload's pool delta from the payload itself, so it is the
// second path that can issue the mint and it bounds it on its own. The correct claim is
// built first: without it the refusal below would prove nothing about the entitlement.
BOOST_AUTO_TEST_CASE(the_epoch_build_bounds_the_mint_it_applies)
{
    CTxDB txdb("r+");
    FundedNote note;
    std::string error;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0x41, VoteNoteAmount(), note, error), error);

    {
        EpochBuildHarness h;
        const int64_t nReward = GetFinalityNoteVoteReward(EpochUnderTest());
        BOOST_REQUIRE_MESSAGE(nReward > 0,
                              "the epoch under test withholds nothing, so this case "
                              "could not tell a bounded mint from an unbounded one");

        CBlockIndex* pBefore = NULL;
        BuiltVote vote;
        CBlockIndex* pEnd =
            BuildEpochCarryingVote(h, 0xA1000000, note, nReward, pBefore, vote);
        BOOST_REQUIRE(pEnd != NULL);

        CEpochState prev = PredecessorFor(pBefore);
        CCurveTree prevTree;
        CEpochState state;
        CCurveTree tree;
        std::string strError;
        pindexBest = pEnd;
        BOOST_REQUIRE_MESSAGE(
            g_dagManager.BuildEpochState(EpochUnderTest(),
                                         EpochEndHeight() - EpochStartHeight() + 1,
                                         pEnd, state, tree, strError, &prev, &prevTree),
            strError);

        // The pool holds exactly the entitlement: value the vote minted, nothing else.
        BOOST_CHECK_EQUAL(state.nVNextPoolBalance, nReward);
        BOOST_CHECK_EQUAL(state.vVNextEpochNullifiers.size(), 1U);
        BOOST_CHECK_EQUAL(state.nVNextTreeSize, 1U);
    }

    {
        EpochBuildHarness h;
        const int64_t nReward = GetFinalityNoteVoteReward(EpochUnderTest());
        BOOST_REQUIRE(nReward > 0);

        CBlockIndex* pBefore = NULL;
        BuiltVote vote;
        CBlockIndex* pEnd =
            BuildEpochCarryingVote(h, 0xA2000000, note, nReward + 1, pBefore, vote);
        BOOST_REQUIRE(pEnd != NULL);

        CEpochState prev = PredecessorFor(pBefore);
        CCurveTree prevTree;
        CEpochState state;
        CCurveTree tree;
        std::string strError;
        pindexBest = pEnd;
        BOOST_CHECK_MESSAGE(
            !g_dagManager.BuildEpochState(EpochUnderTest(),
                                          EpochEndHeight() - EpochStartHeight() + 1,
                                          pEnd, state, tree, strError, &prev, &prevTree),
            "the epoch build applied a mint one satoshi over the entitlement");
        BOOST_CHECK(Mentions(strError, "against an entitlement of"));
    }
}

BOOST_AUTO_TEST_SUITE_END()
