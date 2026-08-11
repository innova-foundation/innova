// Tests for the stake-derived finality committee: the per-term draw over the IV5
// collateral registry, and the resolver that reads the drawn set back out of the
// epoch state that carries it.
//
// The property under test throughout is determinism. Every input the draw consumes
// has to be a function of the connected chain, and the answer has to stay the same
// for a whole term no matter what the registry does in the meantime, because a
// committee that moves under a certificate is a chain split.

#include <boost/test/unit_test.hpp>

#include "../dag.h"
#include "../finality.h"
#include "../key.h"
#include "../main.h"
#include "../shielded.h"
#include "../txdb.h"

#include <algorithm>
#include <set>
#include <vector>

namespace {

// Regtest shape, which is what test_innova runs under.
int Seats()      { return GetFinalityCommitteeSeats(); }
int ThresholdM() { return GetFinalityCommitteeThresholdM(); }
int TermEpochs() { return GetFinalityCommitteeTermEpochs(); }

uint256 KeyImageFor(int n)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("committee-draw-test-key-image");
    ss << n;
    return ss.GetHash();
}

// Everything one case writes into the shared test database, undone on the way out so
// cases stay independent of each other's registry.
struct ScopedRegistry
{
    CTxDB& txdb;
    std::vector<uint256> vKeyImages;
    std::vector<uint256> vSpent;
    std::vector<int> vEpochStates;
    std::map<int, CEpochState> mapOriginalEpochStates;

    explicit ScopedRegistry(CTxDB& txdbIn) : txdb(txdbIn) {}

    void AddMember(const uint256& keyImage, const CPubKey& pubkey, int nHeight)
    {
        CPrivacyVNextCollateralAttestation attested;
        attested.txnHash = keyImage;
        attested.contextDigest = keyImage;
        attested.nHeight = nHeight;
        attested.vchMemberKey =
            std::vector<unsigned char>(pubkey.begin(), pubkey.end());
        BOOST_REQUIRE(txdb.WritePrivacyVNextCollateral(keyImage, attested));
        vKeyImages.push_back(keyImage);
    }

    void Spend(const uint256& keyImage)
    {
        CShieldedNullifierSpent spent;
        spent.txnHash = keyImage;
        spent.nIndex = 0;
        BOOST_REQUIRE(txdb.WritePrivacyVNextNullifier(keyImage, spent));
        vSpent.push_back(keyImage);
    }

    void PutEpochState(const CEpochState& state)
    {
        if (!mapOriginalEpochStates.count(state.nEpoch))
        {
            CEpochState original;
            if (txdb.ReadEpochState(state.nEpoch, original))
                mapOriginalEpochStates[state.nEpoch] = original;
            vEpochStates.push_back(state.nEpoch);
        }
        BOOST_REQUIRE(txdb.WriteEpochState(state.nEpoch, state));
    }

    ~ScopedRegistry()
    {
        for (size_t i = 0; i < vSpent.size(); ++i)
            txdb.ErasePrivacyVNextNullifier(vSpent[i]);
        for (size_t i = 0; i < vKeyImages.size(); ++i)
            txdb.ErasePrivacyVNextCollateral(vKeyImages[i]);
        for (size_t i = 0; i < vEpochStates.size(); ++i)
        {
            std::map<int, CEpochState>::const_iterator it =
                mapOriginalEpochStates.find(vEpochStates[i]);
            if (it != mapOriginalEpochStates.end())
                txdb.WriteEpochState(it->first, it->second);
            else
                txdb.EraseEpochState(vEpochStates[i]);
        }
    }
};

// An anchor epoch state that is complete enough for the draw: the block hashes the
// seed is taken from, and a finalized height that reaches the snapshot.
CEpochState AnchorState(int nAnchorEpoch, int nFinalizedHeightAsOf, unsigned char tag)
{
    CEpochState state;
    state.nEpoch = nAnchorEpoch;
    state.nHeightStart = GetEpochBoundaryHeight(nAnchorEpoch, 0);
    state.nHeightEnd = GetEpochBoundaryHeight(nAnchorEpoch + 1, 0) - 1;
    state.nFinalizedHeightAsOf = nFinalizedHeightAsOf;
    state.nSerVersion = EPOCHSTATE_SER_VERSION_V6;
    for (int i = 0; i < 4; i++)
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << std::string("committee-draw-test-block");
        ss << (int)tag << i;
        state.vBlockHashes.push_back(ss.GetHash());
    }
    return state;
}

// Independent re-derivation of the expected seat order, written out longhand so a
// change to the draw rule has to be matched here rather than silently agreed with.
std::vector<uint256> ExpectedSeatOrder(const uint256& seed,
                                       const std::vector<uint256>& vKeyImages,
                                       int nSeats)
{
    std::vector<std::pair<std::pair<uint256, uint256>, uint256> > v;
    for (size_t i = 0; i < vKeyImages.size(); ++i)
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << std::string("Innova/Finality/CommitteeSeat/v1");
        ss << seed;
        ss << vKeyImages[i];
        v.push_back(std::make_pair(std::make_pair(ss.GetHash(), vKeyImages[i]),
                                   vKeyImages[i]));
    }
    std::sort(v.begin(), v.end());
    std::vector<uint256> vOut;
    for (size_t i = 0; i < v.size() && (int)vOut.size() < nSeats; ++i)
        vOut.push_back(v[i].second);
    return vOut;
}

struct DrawFixture
{
    CTxDB txdb;
    ScopedRegistry registry;
    std::vector<CKey> vKeys;
    std::vector<uint256> vKeyImages;
    int nTermEpoch;
    int nAnchorEpoch;
    int nAnchorHeight;

    // nRows member registrations, all recorded at or before the anchor height, plus a
    // finalized anchor epoch state. The term is chosen well past the DAG fork so the
    // epoch arithmetic is the post-DAG one a real chain uses.
    explicit DrawFixture(int nRows)
        : txdb("r+"), registry(txdb)
    {
        // Far from every other suite's epoch numbering: these records live in the
        // shared test database and a collision would be an accident, not a test.
        nTermEpoch = 100000 * TermEpochs();
        nAnchorEpoch = nTermEpoch - FINALITY_COMMITTEE_DRAW_LAG_EPOCHS;
        nAnchorHeight = GetEpochBoundaryHeight(nAnchorEpoch, 0);
        BOOST_REQUIRE(nAnchorEpoch > 0);

        for (int i = 0; i < nRows; i++)
        {
            CKey key;
            key.MakeNewKey(true);
            vKeys.push_back(key);
            const uint256 keyImage = KeyImageFor(i);
            vKeyImages.push_back(keyImage);
            registry.AddMember(keyImage, key.GetPubKey(), nAnchorHeight - 1);
        }

        registry.PutEpochState(AnchorState(nAnchorEpoch, nAnchorHeight, 0x01));
    }

    CFinalityCommitteeDraw Draw()
    {
        CFinalityCommitteeDraw draw;
        bool fLocalFailure = false;
        std::string strError;
        BOOST_REQUIRE_MESSAGE(
            DrawFinalityCommitteeForTerm(txdb, txdb, nTermEpoch, draw,
                                          fLocalFailure, strError),
            strError);
        BOOST_REQUIRE(!fLocalFailure);
        return draw;
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(finality_committee_draw_tests)

// Two nodes at the same height hold the same registry and the same anchor epoch
// state, and nothing else enters the draw, so they must seat the same members in the
// same order -- the order IS the member index voters share against.
//
// Mutation proving this: make FinalityCommitteeSeatOrder ignore the seed and order by
// key image alone, and the independently recomputed order stops matching.
BOOST_AUTO_TEST_CASE(the_same_chain_state_draws_the_same_committee_everywhere)
{
    DrawFixture f(4 * Seats());

    const CFinalityCommitteeDraw a = f.Draw();
    const CFinalityCommitteeDraw b = f.Draw();

    BOOST_REQUIRE(a.fSeated);
    BOOST_CHECK_EQUAL((int)a.vSeats.size(), Seats());
    BOOST_CHECK_EQUAL(a.nThresholdM, ThresholdM());
    BOOST_CHECK(a.nAnchorHeight == f.nAnchorHeight);

    BOOST_CHECK(b.fSeated);
    BOOST_CHECK(a.seed == b.seed);
    BOOST_CHECK(a.setHash == b.setHash);
    BOOST_CHECK(a.vSeatKeyImages == b.vSeatKeyImages);
    for (size_t i = 0; i < a.vSeats.size(); ++i)
        BOOST_CHECK(a.vSeats[i] == b.vSeats[i]);

    // The seats are the top N by H(seed || keyImage), in that order.
    const std::vector<uint256> vExpected =
        ExpectedSeatOrder(a.seed, f.vKeyImages, Seats());
    BOOST_CHECK(a.vSeatKeyImages == vExpected);

    // The set hash is the one every consumer compares a certificate against.
    BOOST_CHECK(a.setHash ==
                ComputeFinalityTallyCommitteeHash(a.nThresholdM, a.vSeats));
}

// The seed is the anchor epoch's own block hashes, so a different anchor epoch state
// draws a different committee. This is what stops a registrant grinding a key image
// against a seed that does not exist yet when registration closes.
//
// Mutation proving this: drop anchorState.vBlockHashes from
// FinalityCommitteeDrawSeed, and both chains produce the same seed and the same seats.
BOOST_AUTO_TEST_CASE(the_seed_comes_from_the_anchor_epochs_own_blocks)
{
    DrawFixture f(4 * Seats());
    const CFinalityCommitteeDraw a = f.Draw();
    BOOST_REQUIRE(a.fSeated);

    f.registry.PutEpochState(AnchorState(f.nAnchorEpoch, f.nAnchorHeight, 0x02));
    const CFinalityCommitteeDraw b = f.Draw();
    BOOST_REQUIRE(b.fSeated);

    BOOST_CHECK(a.seed != b.seed);
    BOOST_CHECK(a.vSeatKeyImages != b.vSeatKeyImages || a.setHash != b.setHash);
    BOOST_CHECK(b.vSeatKeyImages == ExpectedSeatOrder(b.seed, f.vKeyImages, Seats()));
}

// Registration closes at the anchor height. A registration recorded after it is not a
// candidate for this term, so a miner who can influence the seed cannot also inject
// rows into the set the seed is applied to.
//
// Mutation proving this: delete the `attested.nHeight > nAnchorHeight` skip in
// GetPrivacyVNextCollateralSnapshot, and the late registration joins the draw.
BOOST_AUTO_TEST_CASE(a_registration_after_the_snapshot_height_does_not_change_the_draw)
{
    DrawFixture f(4 * Seats());
    const CFinalityCommitteeDraw before = f.Draw();
    BOOST_REQUIRE(before.fSeated);

    // A row that would win a seat if it were a candidate at all: keep adding late
    // registrations until one of them outranks the last seated row.
    bool fWouldHaveWon = false;
    for (int i = 0; i < 64 && !fWouldHaveWon; i++)
    {
        CKey key;
        key.MakeNewKey(true);
        const uint256 keyImage = KeyImageFor(10000 + i);
        f.registry.AddMember(keyImage, key.GetPubKey(), f.nAnchorHeight + 1);

        std::vector<uint256> vWithLate = f.vKeyImages;
        vWithLate.push_back(keyImage);
        const std::vector<uint256> vHypothetical =
            ExpectedSeatOrder(before.seed, vWithLate, Seats());
        fWouldHaveWon = std::find(vHypothetical.begin(), vHypothetical.end(),
                                  keyImage) != vHypothetical.end();
    }
    BOOST_REQUIRE(fWouldHaveWon);

    const CFinalityCommitteeDraw after = f.Draw();
    BOOST_CHECK(after.fSeated);
    BOOST_CHECK(after.seed == before.seed);
    BOOST_CHECK(after.vSeatKeyImages == before.vSeatKeyImages);
    BOOST_CHECK(after.setHash == before.setHash);
}

// Collateral is what a seat is made of. Spending the note deregisters it, and the seat
// goes to the next row in draw order rather than staying with a member who no longer
// holds anything.
//
// Mutation proving this: skip the ReadPrivacyVNextNullifierStatus check in
// GetPrivacyVNextCollateralSnapshot, and the spent registration keeps its seat.
BOOST_AUTO_TEST_CASE(a_spent_registration_loses_its_seat)
{
    DrawFixture f(4 * Seats());
    const CFinalityCommitteeDraw before = f.Draw();
    BOOST_REQUIRE(before.fSeated);

    const uint256 spentSeat = before.vSeatKeyImages[0];
    f.registry.Spend(spentSeat);

    const CFinalityCommitteeDraw after = f.Draw();
    BOOST_REQUIRE(after.fSeated);
    BOOST_CHECK_EQUAL((int)after.vSeats.size(), Seats());
    BOOST_CHECK(std::find(after.vSeatKeyImages.begin(), after.vSeatKeyImages.end(),
                          spentSeat) == after.vSeatKeyImages.end());
    BOOST_CHECK(after.setHash != before.setHash);

    // The remaining seats keep their relative order: removing a row promotes the rows
    // below the cut, it does not reshuffle the ones above it.
    std::vector<uint256> vRemaining = f.vKeyImages;
    vRemaining.erase(std::find(vRemaining.begin(), vRemaining.end(), spentSeat));
    BOOST_CHECK(after.vSeatKeyImages ==
                ExpectedSeatOrder(before.seed, vRemaining, Seats()));
}

// A committee drawn from a registry barely larger than itself names most of the
// registry, so seating it would publish who the members are. Seat nothing and let the
// epoch certify transparent-only instead.
//
// Mutation proving this: change the threshold to
// `< nSeats` instead of `< nSeats * FINALITY_COMMITTEE_MIN_REGISTRY_MULTIPLE`, and a
// registry of exactly N rows seats a full committee.
BOOST_AUTO_TEST_CASE(a_thin_registry_seats_nothing)
{
    {
        DrawFixture thin(Seats() * FINALITY_COMMITTEE_MIN_REGISTRY_MULTIPLE - 1);
        const CFinalityCommitteeDraw draw = thin.Draw();
        BOOST_CHECK(!draw.fSeated);
        BOOST_CHECK(draw.vSeats.empty());
        BOOST_CHECK(draw.setHash == 0);
        BOOST_CHECK_EQUAL((int)draw.nRegistrySize,
                          Seats() * FINALITY_COMMITTEE_MIN_REGISTRY_MULTIPLE - 1);
    }
    {
        DrawFixture exact(Seats() * FINALITY_COMMITTEE_MIN_REGISTRY_MULTIPLE);
        const CFinalityCommitteeDraw draw = exact.Draw();
        BOOST_CHECK(draw.fSeated);
        BOOST_CHECK_EQUAL((int)draw.vSeats.size(), Seats());
    }
}

// An anchor epoch the chain has not produced yet is a consensus outcome: every node
// sees the same absence, so seating nothing is an answer they agree on.
//
// Mutation proving this: set fLocalFailureOut on the missing-anchor path, and a chain
// that is simply too young starts reporting local corruption.
BOOST_AUTO_TEST_CASE(a_missing_anchor_epoch_seats_nothing)
{
    DrawFixture f(4 * Seats());
    BOOST_REQUIRE(f.Draw().fSeated);

    BOOST_REQUIRE(f.txdb.EraseEpochState(f.nAnchorEpoch));
    CFinalityCommitteeDraw draw;
    bool fLocalFailure = false;
    std::string strError;
    BOOST_REQUIRE(DrawFinalityCommitteeForTerm(f.txdb, f.txdb, f.nTermEpoch, draw,
                                                fLocalFailure, strError));
    BOOST_CHECK(!fLocalFailure);
    BOOST_CHECK(!draw.fSeated);
}

// The registry enumeration cannot see an in-flight write batch, so it is only the
// right answer if no in-flight batch reaches the rows it reads. A transaction that is
// rebuilding the anchor epoch -- which is what a reorg down to the anchor height does
// -- shows up as a staged anchor record that differs from the committed one, and the
// draw must refuse rather than seat a committee off a stale snapshot.
//
// Refusing is a LOCAL failure, not "seat nothing": seating a different committee than
// a peer is a split, whereas failing the transaction leaves this node where it was.
//
// Mutation proving this: delete the anchorCommitted/anchorState digest comparison in
// DrawFinalityCommitteeForTerm, and the draw runs off the committed snapshot while the
// transaction holds a different one.
BOOST_AUTO_TEST_CASE(a_staged_anchor_epoch_refuses_the_draw)
{
    DrawFixture f(4 * Seats());
    BOOST_REQUIRE(f.Draw().fSeated);

    // A second handle standing in for the block-connection transaction: its batch
    // holds a rebuilt anchor epoch that the committed store has never seen.
    CTxDB txdbStaged("r+");
    BOOST_REQUIRE(txdbStaged.TxnBegin());
    BOOST_REQUIRE(txdbStaged.WriteEpochState(
        f.nAnchorEpoch, AnchorState(f.nAnchorEpoch, f.nAnchorHeight, 0x7f)));

    CFinalityCommitteeDraw draw;
    bool fLocalFailure = false;
    std::string strError;
    BOOST_CHECK(!DrawFinalityCommitteeForTerm(txdbStaged, f.txdb, f.nTermEpoch, draw,
                                               fLocalFailure, strError));
    BOOST_CHECK(fLocalFailure);
    BOOST_CHECK(!draw.fSeated);
    txdbStaged.TxnAbort();

    // With the transaction gone, the same two handles agree and the draw proceeds.
    CFinalityCommitteeDraw settled;
    BOOST_REQUIRE(DrawFinalityCommitteeForTerm(txdbStaged, f.txdb, f.nTermEpoch,
                                                settled, fLocalFailure, strError));
    BOOST_CHECK(!fLocalFailure);
    BOOST_CHECK(settled.fSeated);
}

// Two seats behind one member key would seal two Shamir shares to one recipient: the
// set would name N members and open on fewer.
//
// Mutation proving this: remove the setSeated insert guard in
// DrawFinalityCommitteeForTerm, and the duplicated key takes two seats.
BOOST_AUTO_TEST_CASE(one_member_key_gets_one_seat)
{
    CTxDB txdb("r+");
    ScopedRegistry registry(txdb);

    const int nTermEpoch = 100000 * TermEpochs();
    const int nAnchorEpoch = nTermEpoch - FINALITY_COMMITTEE_DRAW_LAG_EPOCHS;
    const int nAnchorHeight = GetEpochBoundaryHeight(nAnchorEpoch, 0);

    // Every row registers the SAME key except the last few, so a draw without the
    // dedup would seat that one key repeatedly.
    const int nRows = 4 * Seats();
    CKey shared;
    shared.MakeNewKey(true);
    std::vector<CKey> vDistinct;
    for (int i = 0; i < nRows; i++)
    {
        CPubKey pubkey;
        if (i < nRows - Seats())
            pubkey = shared.GetPubKey();
        else
        {
            CKey key;
            key.MakeNewKey(true);
            vDistinct.push_back(key);
            pubkey = key.GetPubKey();
        }
        registry.AddMember(KeyImageFor(20000 + i), pubkey, nAnchorHeight - 1);
    }
    registry.PutEpochState(AnchorState(nAnchorEpoch, nAnchorHeight, 0x03));

    CFinalityCommitteeDraw draw;
    bool fLocalFailure = false;
    std::string strError;
    BOOST_REQUIRE(DrawFinalityCommitteeForTerm(txdb, txdb, nTermEpoch, draw,
                                                fLocalFailure, strError));
    BOOST_REQUIRE(draw.fSeated);
    BOOST_CHECK_EQUAL((int)draw.vSeats.size(), Seats());

    std::set<std::vector<unsigned char> > setSeen;
    for (size_t i = 0; i < draw.vSeats.size(); ++i)
        BOOST_CHECK(setSeen.insert(std::vector<unsigned char>(draw.vSeats[i].begin(),
                                                              draw.vSeats[i].end()))
                        .second);
}

// Below FORK_HEIGHT_IV5_NOTE_VOTE an epoch state is written at the pre-committee
// serialization version, and nothing seats a committee into it -- the fork changes
// nothing about any epoch that precedes it.
//
// Mutation proving this: delete the
// `state.nSerVersion < EPOCHSTATE_SER_VERSION_V6` early return in
// SeatFinalityCommitteeForEpochState, and a pre-fork epoch record grows a committee.
BOOST_AUTO_TEST_CASE(nothing_is_seated_below_the_note_vote_fork)
{
    DrawFixture f(4 * Seats());
    BOOST_REQUIRE(f.Draw().fSeated);

    const int nCarrierEpoch = f.nTermEpoch - 1;
    bool fLocalFailure = false;
    std::string strError;

    CEpochState preFork;
    preFork.nEpoch = nCarrierEpoch;
    preFork.nSerVersion = EPOCHSTATE_SER_VERSION_V5;
    BOOST_REQUIRE(SeatFinalityCommitteeForEpochState(f.txdb, preFork, fLocalFailure,
                                                      strError));
    BOOST_CHECK(preFork.vFinalityCommittee.empty());
    BOOST_CHECK_EQUAL(preFork.nFinalityCommitteeM, 0);

    // The same epoch at the post-fork version does seat, so the version is what
    // refused it.
    CEpochState postFork;
    postFork.nEpoch = nCarrierEpoch;
    postFork.nSerVersion = EPOCHSTATE_SER_VERSION_V6;
    BOOST_REQUIRE(SeatFinalityCommitteeForEpochState(f.txdb, postFork, fLocalFailure,
                                                      strError));
    BOOST_CHECK_EQUAL((int)postFork.vFinalityCommittee.size(), Seats());
    BOOST_CHECK_EQUAL(postFork.nFinalityCommitteeM, ThresholdM());
}

// Only the epoch that ends a term's lead-in carries a draw. Any other epoch carries
// none, which is what makes "the committee for this epoch" a single lookup rather
// than a search.
//
// Mutation proving this: change the carrier from `state.nEpoch + 1` to
// `state.nEpoch`, and the epoch that should carry the draw stops carrying it while
// the one after it starts.
BOOST_AUTO_TEST_CASE(only_the_epoch_before_a_term_carries_the_draw)
{
    DrawFixture f(4 * Seats());
    bool fLocalFailure = false;
    std::string strError;

    // Only this fixture's own term has an anchor epoch state, so it is the one epoch
    // in the run that both leads a term and can draw.
    for (int nEpoch = f.nTermEpoch - 3; nEpoch <= f.nTermEpoch + 1; nEpoch++)
    {
        CEpochState state;
        state.nEpoch = nEpoch;
        state.nSerVersion = EPOCHSTATE_SER_VERSION_V6;
        BOOST_REQUIRE(SeatFinalityCommitteeForEpochState(f.txdb, state, fLocalFailure,
                                                          strError));
        BOOST_CHECK_EQUAL(!state.vFinalityCommittee.empty(),
                          nEpoch == f.nTermEpoch - 1);
        if (nEpoch != f.nTermEpoch - 1)
            BOOST_CHECK_EQUAL(state.nFinalityCommitteeM, 0);
    }
}

// The resolver is a lookup into the carrier record, not a fresh draw, so the answer is
// the same for every epoch of the term however much the registry moves underneath it.
// A committee that changed mid-term would invalidate certificates its own peers had
// already accepted.
//
// Mutation proving this: have GetCommitteeForEpoch call
// DrawFinalityCommitteeForTerm instead of reading the carrier, and the mid-term
// registrations below change the resolved set.
BOOST_AUTO_TEST_CASE(the_committee_is_fixed_for_the_whole_term)
{
    DrawFixture f(4 * Seats());
    const CFinalityCommitteeDraw draw = f.Draw();
    BOOST_REQUIRE(draw.fSeated);

    CEpochState carrier;
    carrier.nEpoch = f.nTermEpoch - 1;
    carrier.nSerVersion = EPOCHSTATE_SER_VERSION_V6;
    bool fLocalFailure = false;
    std::string strError;
    BOOST_REQUIRE(SeatFinalityCommitteeForEpochState(f.txdb, carrier, fLocalFailure,
                                                      strError));
    f.registry.PutEpochState(carrier);

    std::vector<CPubKey> vSeats;
    int nM = 0;
    uint256 setHash;
    for (int nEpoch = f.nTermEpoch; nEpoch < f.nTermEpoch + TermEpochs(); nEpoch++)
    {
        BOOST_REQUIRE(GetCanonicalFinalityCommittee(f.txdb, nEpoch, vSeats, nM,
                                                     setHash));
        BOOST_CHECK_EQUAL(nM, ThresholdM());
        BOOST_CHECK(setHash == draw.setHash);
        BOOST_REQUIRE_EQUAL((int)vSeats.size(), Seats());
        for (size_t i = 0; i < vSeats.size(); ++i)
            BOOST_CHECK(vSeats[i] == draw.vSeats[i]);
    }

    // Registrations keep arriving during the term. The resolved committee does not
    // move, because the term's answer was settled before the term began.
    for (int i = 0; i < 4 * Seats(); i++)
    {
        CKey key;
        key.MakeNewKey(true);
        f.registry.AddMember(KeyImageFor(30000 + i), key.GetPubKey(),
                             f.nAnchorHeight - 1);
    }
    BOOST_REQUIRE(GetCanonicalFinalityCommittee(f.txdb, f.nTermEpoch, vSeats, nM,
                                                 setHash));
    BOOST_CHECK(setHash == draw.setHash);

    // The next term resolves from its own carrier, which this fixture never wrote:
    // no carrier, no committee, and the epoch certifies transparent-only.
    const int nNextTerm = f.nTermEpoch + TermEpochs();
    CEpochState emptyNextCarrier;
    emptyNextCarrier.nEpoch = nNextTerm - 1;
    emptyNextCarrier.nSerVersion = EPOCHSTATE_SER_VERSION_V6;
    f.registry.PutEpochState(emptyNextCarrier);
    BOOST_CHECK(!GetCanonicalFinalityCommittee(f.txdb, nNextTerm, vSeats, nM, setHash));
}

// A carrier record this node cannot decode is this node's problem. Reporting it as
// "no committee" would make one node reject blocks every healthy peer accepts.
//
// Mutation proving this: return plain false without setting *pfLocalFailure on the
// malformed-key path, and the caller attributes local corruption to the peer.
BOOST_AUTO_TEST_CASE(a_corrupt_carrier_is_local_state_not_a_verdict)
{
    DrawFixture f(4 * Seats());
    CEpochState carrier;
    carrier.nEpoch = f.nTermEpoch - 1;
    carrier.nSerVersion = EPOCHSTATE_SER_VERSION_V6;
    bool fLocalFailure = false;
    std::string strError;
    BOOST_REQUIRE(SeatFinalityCommitteeForEpochState(f.txdb, carrier, fLocalFailure,
                                                      strError));
    carrier.vFinalityCommittee[0].assign(33, 0x05);   // 33 bytes, no valid header
    f.registry.PutEpochState(carrier);

    std::vector<CPubKey> vSeats;
    int nM = 0;
    uint256 setHash;
    bool fResolveLocalFailure = false;
    BOOST_CHECK(!GetCanonicalFinalityCommittee(f.txdb, f.nTermEpoch, vSeats, nM,
                                                setHash, &fResolveLocalFailure));
    BOOST_CHECK(fResolveLocalFailure);
}

// The drawn set is covered by the epoch record's digest from V6 on, so two nodes that
// disagreed about a draw would disagree about the record instead of accepting each
// other's blocks and splitting later on a certificate. V5 records hash as before.
//
// Mutation proving this: drop the V6 clause from CEpochState::GetDigest, and a
// committee change stops changing the digest.
BOOST_AUTO_TEST_CASE(the_epoch_digest_covers_the_drawn_committee)
{
    CEpochState a;
    a.nEpoch = 7;
    a.nSerVersion = EPOCHSTATE_SER_VERSION_V6;
    a.vFinalityCommittee.push_back(std::vector<unsigned char>(33, 0x02));
    a.nFinalityCommitteeM = 2;

    CEpochState b = a;
    b.vFinalityCommittee[0].assign(33, 0x03);
    BOOST_CHECK(a.GetDigest() != b.GetDigest());

    CEpochState c = a;
    c.nFinalityCommitteeM = 3;
    BOOST_CHECK(a.GetDigest() != c.GetDigest());

    // A V5 record hashes exactly as it did before the field existed.
    CEpochState v5 = a;
    v5.nSerVersion = EPOCHSTATE_SER_VERSION_V5;
    CEpochState v5NoCommittee = v5;
    v5NoCommittee.vFinalityCommittee.clear();
    v5NoCommittee.nFinalityCommitteeM = 0;
    BOOST_CHECK(v5.GetDigest() == v5NoCommittee.GetDigest());
}

BOOST_AUTO_TEST_SUITE_END()
