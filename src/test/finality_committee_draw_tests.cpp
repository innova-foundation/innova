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

    void Spend(const uint256& keyImage, int nHeight)
    {
        CPrivacyVNextNullifierSpent spent;
        spent.txnHash = keyImage;
        spent.nIndex = 0;
        spent.nHeight = nHeight;
        BOOST_REQUIRE(txdb.WritePrivacyVNextNullifier(keyImage, spent));
        vSpent.push_back(keyImage);
    }

    void Unspend(const uint256& keyImage)
    {
        BOOST_REQUIRE(txdb.ErasePrivacyVNextNullifier(keyImage));
        vSpent.erase(std::remove(vSpent.begin(), vSpent.end(), keyImage),
                     vSpent.end());
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

// An anchor epoch state that is complete enough for the draw: the end block the seed
// is taken from, the DAG order that ends on it, and a finalized height that reaches
// the snapshot. As on a real chain, the end block is the last entry in the order.
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
    state.hashBoundaryBlock = state.vBlockHashes.back();
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

// The seed is the anchor epoch's own end block, so a different anchor epoch state
// draws a different committee. This is what stops a registrant grinding a key image
// against a seed that does not exist yet when registration closes.
//
// Mutation proving this: drop anchorState.hashBoundaryBlock from
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
    f.registry.Spend(spentSeat, f.nAnchorHeight);

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

// A release above the anchor height is not part of the chain the draw is taken over,
// and the draw must not see it. This is the chain-split case, driven the way the two
// nodes actually differ.
//
// A node reorganising X -> Y stages the epoch suffix BEFORE it disconnects X, so the
// registry handle it reads still holds X's writes -- including a collateral release
// that happened on X, inside the term's lead-in, above the anchor height. A node
// syncing Y from nothing never wrote that record. Both are at the same height on the
// same chain. Unbounded membership makes the first drop the row and promote the next,
// and the second keep it: two committees, two epoch-state digests, and no self-heal,
// because the draw is stored rather than rederived on restart.
//
// Mutation proving this: drop the `spent.nHeight <= nAnchorHeight` clause in
// GetPrivacyVNextCollateralSnapshot and the two draws stop matching -- reorganising
// loses the seat, fresh-syncing keeps it.
BOOST_AUTO_TEST_CASE(a_release_above_the_anchor_does_not_move_the_committee)
{
    DrawFixture f(4 * Seats());

    // The fresh-sync node: it has connected Y and never held X's release.
    const CFinalityCommitteeDraw fresh = f.Draw();
    BOOST_REQUIRE(fresh.fSeated);
    const uint256 seatedOnY = fresh.vSeatKeyImages[0];

    // The reorganising node: X released that seat's collateral inside the lead-in,
    // above the anchor height, and the record is still committed while the draw runs.
    f.registry.Spend(seatedOnY, f.nAnchorHeight + 1);
    const CFinalityCommitteeDraw reorganised = f.Draw();

    BOOST_REQUIRE(reorganised.fSeated);
    BOOST_CHECK(reorganised.seed == fresh.seed);
    BOOST_CHECK(reorganised.vSeatKeyImages == fresh.vSeatKeyImages);
    BOOST_CHECK(reorganised.setHash == fresh.setHash);
    BOOST_CHECK_EQUAL((int)reorganised.nRegistrySize, (int)fresh.nRegistrySize);

    // The same divergence has to be absent from the record the chain actually
    // compares, which is where a disagreement would have become a split.
    bool fLocalFailure = false;
    std::string strError;
    CEpochState carrierReorg;
    carrierReorg.nEpoch = f.nTermEpoch - 1;
    carrierReorg.nSerVersion = EPOCHSTATE_SER_VERSION_V6;
    BOOST_REQUIRE(SeatFinalityCommitteeForEpochState(f.txdb, carrierReorg,
                                                      fLocalFailure, strError));
    f.registry.Unspend(seatedOnY);
    CEpochState carrierFresh;
    carrierFresh.nEpoch = f.nTermEpoch - 1;
    carrierFresh.nSerVersion = EPOCHSTATE_SER_VERSION_V6;
    BOOST_REQUIRE(SeatFinalityCommitteeForEpochState(f.txdb, carrierFresh,
                                                      fLocalFailure, strError));
    BOOST_CHECK(carrierReorg.vFinalityCommittee == carrierFresh.vFinalityCommittee);
    BOOST_CHECK(carrierReorg.GetDigest() == carrierFresh.GetDigest());
}

// The bound is a bound, not a blanket exemption: a release at or below the anchor
// height is on the ancestry every node syncing this chain replays, so it still takes
// the seat away. The boundary itself belongs to the anchor.
//
// Mutation proving this: change the clause to `spent.nHeight < nAnchorHeight` and the
// release exactly at the anchor height stops deregistering; change it to
// `spent.nHeight <= nAnchorHeight + 1` and the release one above it starts to.
BOOST_AUTO_TEST_CASE(a_release_at_or_below_the_anchor_still_takes_the_seat)
{
    DrawFixture f(4 * Seats());
    const CFinalityCommitteeDraw before = f.Draw();
    BOOST_REQUIRE(before.fSeated);
    const uint256 seat = before.vSeatKeyImages[0];

    f.registry.Spend(seat, f.nAnchorHeight);
    const CFinalityCommitteeDraw atAnchor = f.Draw();
    BOOST_REQUIRE(atAnchor.fSeated);
    BOOST_CHECK(std::find(atAnchor.vSeatKeyImages.begin(),
                          atAnchor.vSeatKeyImages.end(), seat) ==
                atAnchor.vSeatKeyImages.end());
    f.registry.Unspend(seat);

    f.registry.Spend(seat, f.nAnchorHeight - 1);
    const CFinalityCommitteeDraw belowAnchor = f.Draw();
    BOOST_REQUIRE(belowAnchor.fSeated);
    BOOST_CHECK(std::find(belowAnchor.vSeatKeyImages.begin(),
                          belowAnchor.vSeatKeyImages.end(), seat) ==
                belowAnchor.vSeatKeyImages.end());
    f.registry.Unspend(seat);

    // One above, and the seat stays: the two cases are decided by the height alone.
    f.registry.Spend(seat, f.nAnchorHeight + 1);
    const CFinalityCommitteeDraw aboveAnchor = f.Draw();
    BOOST_REQUIRE(aboveAnchor.fSeated);
    BOOST_CHECK(std::find(aboveAnchor.vSeatKeyImages.begin(),
                          aboveAnchor.vSeatKeyImages.end(), seat) !=
                aboveAnchor.vSeatKeyImages.end());
}

// A spent-key record that cannot be placed on a chain is local corruption, not a
// verdict about the registry: answering "unspent" would seat a member whose collateral
// may be gone, and answering "spent" would unseat one whose collateral is not.
//
// Mutation proving this: drop the `spent.nHeight < 0` clause from
// ReadPrivacyVNextNullifierStatus, and a heightless record is read as an ordinary
// spend at height -1, which no anchor bound can exclude.
BOOST_AUTO_TEST_CASE(a_heightless_spent_record_is_corruption)
{
    DrawFixture f(4 * Seats());
    const CFinalityCommitteeDraw before = f.Draw();
    BOOST_REQUIRE(before.fSeated);

    CPrivacyVNextNullifierSpent heightless;
    heightless.txnHash = before.vSeatKeyImages[0];
    heightless.nIndex = 0;
    heightless.nHeight = -1;
    BOOST_REQUIRE(f.txdb.WritePrivacyVNextNullifier(before.vSeatKeyImages[0],
                                                     heightless));
    f.registry.vSpent.push_back(before.vSeatKeyImages[0]);

    CPrivacyVNextNullifierSpent readBack;
    BOOST_CHECK_EQUAL(
        f.txdb.ReadPrivacyVNextNullifierStatus(before.vSeatKeyImages[0], readBack),
        TXDB_READ_ERROR);

    CFinalityCommitteeDraw draw;
    bool fLocalFailure = false;
    std::string strError;
    BOOST_CHECK(!DrawFinalityCommitteeForTerm(f.txdb, f.txdb, f.nTermEpoch, draw,
                                               fLocalFailure, strError));
    BOOST_CHECK(fLocalFailure);
    BOOST_CHECK(!draw.fSeated);
}

// The seed is the anchor epoch's canonical END block and nothing else in the epoch.
//
// The epoch's DAG order carries merge and sibling blocks, which never had to win a
// height race. Seeding from that order let a miner mine such blocks at leisure, hold
// them, compute the seat list each one would produce, and release only a favourable
// one to be merged before the epoch closed -- one free resample per block mined
// anywhere in the epoch. Seeding from the end block alone leaves exactly one block,
// at one height, whose producer can regrind, and only by discarding a solution it
// could have published.
//
// Mutation proving this: put anchorState.vBlockHashes back into
// FinalityCommitteeDrawSeed, and the withheld sibling below changes the seed and the
// seats.
BOOST_AUTO_TEST_CASE(a_late_sibling_in_the_anchor_epoch_cannot_regrind_the_seed)
{
    DrawFixture f(4 * Seats());
    const CFinalityCommitteeDraw before = f.Draw();
    BOOST_REQUIRE(before.fSeated);

    // A block merged into the anchor epoch's order just before it closed. The end
    // block, and so the whole registration snapshot, is untouched.
    CEpochState withSibling = AnchorState(f.nAnchorEpoch, f.nAnchorHeight, 0x01);
    const uint256 hashEnd = withSibling.hashBoundaryBlock;
    CHashWriter ssSibling(SER_GETHASH, 0);
    ssSibling << std::string("committee-draw-test-withheld-sibling");
    withSibling.vBlockHashes.insert(withSibling.vBlockHashes.end() - 1,
                                    ssSibling.GetHash());
    BOOST_REQUIRE(withSibling.hashBoundaryBlock == hashEnd);
    BOOST_REQUIRE(withSibling.vBlockHashes.back() == hashEnd);
    f.registry.PutEpochState(withSibling);

    const CFinalityCommitteeDraw after = f.Draw();
    BOOST_REQUIRE(after.fSeated);
    BOOST_CHECK(after.seed == before.seed);
    BOOST_CHECK(after.vSeatKeyImages == before.vSeatKeyImages);
    BOOST_CHECK(after.setHash == before.setHash);

    // Regrinding the end block itself does still move the draw -- that residual is
    // the one block a producer must forfeit to resample, and it is not claimed gone.
    CEpochState reground = AnchorState(f.nAnchorEpoch, f.nAnchorHeight, 0x01);
    CHashWriter ssEnd(SER_GETHASH, 0);
    ssEnd << std::string("committee-draw-test-reground-end-block");
    reground.hashBoundaryBlock = ssEnd.GetHash();
    reground.vBlockHashes.back() = reground.hashBoundaryBlock;
    f.registry.PutEpochState(reground);
    BOOST_CHECK(f.Draw().seed != before.seed);
}

// An anchor epoch record that never named an end block cannot seed a draw, and seeding
// from zero would give every such term the same predictable one. Every node reads the
// same record -- the field is inside its digest -- so seating nothing is agreed.
//
// Mutation proving this: delete the `anchorState.hashBoundaryBlock == 0` early return
// in DrawFinalityCommitteeForTerm, and the draw seats a full committee off a zero seed.
BOOST_AUTO_TEST_CASE(an_anchor_epoch_with_no_end_block_seats_nothing)
{
    DrawFixture f(4 * Seats());
    BOOST_REQUIRE(f.Draw().fSeated);

    CEpochState headless = AnchorState(f.nAnchorEpoch, f.nAnchorHeight, 0x01);
    headless.hashBoundaryBlock = 0;
    f.registry.PutEpochState(headless);

    CFinalityCommitteeDraw draw;
    bool fLocalFailure = false;
    std::string strError;
    BOOST_REQUIRE(DrawFinalityCommitteeForTerm(f.txdb, f.txdb, f.nTermEpoch, draw,
                                                fLocalFailure, strError));
    BOOST_CHECK(!fLocalFailure);
    BOOST_CHECK(!draw.fSeated);
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
