// Day-one epoch finality at the mainnet DAG gate: with no finalized height only
// transparent votes can bootstrap, and private paths stay unreachable before their committee.

#include <boost/test/unit_test.hpp>

#include <limits>

#include "../main.h"
#include "../finality.h"
#include "../finality_note.h"
#include "../v5activation.h"

extern bool fRegTest;
extern bool fTestNet;

namespace {

struct MainnetFinalityGuard
{
    bool fRegTestSaved;
    bool fTestNetSaved;
    MainnetFinalityGuard()
        : fRegTestSaved(fRegTest), fTestNetSaved(fTestNet)
    {
        fRegTest = false;
        fTestNet = false;
    }
    ~MainnetFinalityGuard()
    {
        fRegTest = fRegTestSaved;
        fTestNet = fTestNetSaved;
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(finality_coldstart_tests)

// A finality vote must target an epoch boundary block at or above the DAG
// fork. If the fork were not itself a boundary, the first votable epoch would
// start up to a full epoch late.
BOOST_AUTO_TEST_CASE(the_dag_fork_is_itself_the_first_post_dag_epoch_boundary)
{
    MainnetFinalityGuard guard;

    const int nFork = FORK_HEIGHT_DAG;
    BOOST_CHECK_EQUAL(nFork % FINALITY_EPOCH_INTERVAL_PRE_DAG, 0);

    const int nForkEpoch = GetEpochForHeight(nFork);
    BOOST_CHECK_EQUAL(GetEpochBoundaryHeight(nForkEpoch, nFork), nFork);

    // Epoch numbering is continuous across the fork: the last pre-DAG epoch
    // ends exactly at nFork - 1.
    BOOST_CHECK_EQUAL(GetEpochForHeight(nFork - 1), nForkEpoch - 1);
    BOOST_CHECK_EQUAL(GetEpochBoundaryHeight(nForkEpoch - 1, nFork - 1),
                      nFork - FINALITY_EPOCH_INTERVAL_PRE_DAG);

    // Finality activates before the DAG gate, so nothing else has to be
    // scheduled for the first epoch to be votable.
    BOOST_CHECK(FORK_HEIGHT_FINALITY < nFork);
}

// Earliest possible first finalized height, and therefore the earliest a
// private (root-anchored) vote or an IV5 spend can exist.
BOOST_AUTO_TEST_CASE(first_finalized_height_is_three_epochs_past_the_fork)
{
    MainnetFinalityGuard guard;

    BOOST_CHECK_EQUAL(FINALITY_CONFIRMATION_EPOCHS, 3);
    BOOST_CHECK_EQUAL(FINALITY_MIN_VOTERS, 2);
    BOOST_CHECK_EQUAL(GetEpochInterval(FORK_HEIGHT_DAG), 300);

    const int nFirstFinalized =
        FORK_HEIGHT_DAG +
        FINALITY_CONFIRMATION_EPOCHS * FINALITY_EPOCH_INTERVAL_POST_DAG;
    BOOST_CHECK_EQUAL(nFirstFinalized, FORK_HEIGHT_DAG + 900);

    // 900 blocks at 1s: 15 minutes, and only if two distinct voters land a
    // vote in each of the three epochs.
    BOOST_CHECK_EQUAL((nFirstFinalized - FORK_HEIGHT_DAG) *
                          POST_DAG_TARGET_SPACING,
                      900);
}

// At 1s blocks the producer window must be sampled many times per epoch, or a node
// can phase-lock out of voting and one missed voter resets the HARD streak.
BOOST_AUTO_TEST_CASE(producer_window_is_sampled_many_times_post_dag)
{
    MainnetFinalityGuard guard;

    const int nWindow = GetFinalityVoteProducerWindow(FORK_HEIGHT_DAG);
    const int64_t nPollMs = GetFinalityVoterPollMs(FORK_HEIGHT_DAG);

    // Never wider than what consensus will include (R1), with margin left for
    // signing and relay.
    BOOST_CHECK(nWindow < FINALITY_VOTE_INCLUSION_WINDOW);
    BOOST_CHECK_EQUAL(nWindow, 18);
    BOOST_CHECK_EQUAL(FINALITY_VOTE_INCLUSION_WINDOW, 24);

    // The window is at least eight polls wide, so no phase can miss it.
    const int64_t nWindowMs = (int64_t)nWindow * POST_DAG_TARGET_SPACING * 1000;
    BOOST_CHECK(nWindowMs / nPollMs >= 8);

    // Pre-DAG behaviour is unchanged.
    BOOST_CHECK_EQUAL(GetFinalityVoteProducerWindow(FORK_HEIGHT_DAG - 1),
                      FINALITY_VOTE_WINDOW);
    BOOST_CHECK_EQUAL(GetFinalityVoterPollMs(FORK_HEIGHT_DAG - 1),
                      FINALITY_VOTER_POLL_MS_PRE_DAG);

    BOOST_CHECK(FINALITY_VOTE_ATTEMPTS_PER_EPOCH >= 2);
}

// Private tally certs need M-of-N signatures from FORK_HEIGHT_TALLY_GOVERNANCE, which
// co-activates with the DAG fork; transparent certs are a pure threshold check.
BOOST_AUTO_TEST_CASE(private_cert_paths_cannot_predate_their_committee)
{
    MainnetFinalityGuard guard;

    // The first height a private certificate can exist is the first height its
    // committee requirement is in force.
    BOOST_CHECK_EQUAL(FORK_HEIGHT_TALLY_GOVERNANCE, FORK_HEIGHT_DAG);

    // The note tally is unconfigured at the DAG fork, so day one is transparent-only; the
    // ordering is checked against the height this case sets.
    BOOST_CHECK(!IsIV5NoteVoteActiveAtHeight(FORK_HEIGHT_DAG));
    if (IsIV5NoteVoteConfigured())
        BOOST_CHECK(FORK_HEIGHT_IV5_NOTE_VOTE > FORK_HEIGHT_BOUNDARY_B);

    // The vote-weight floor is keyed by height, not by the fork gate.
    BOOST_CHECK_EQUAL(GetFinalityMinVoteWeight(0), 500 * COIN);
    BOOST_CHECK_EQUAL(GetFinalityMinVoteWeight(FORK_HEIGHT_DAG), 500 * COIN);
    BOOST_CHECK_EQUAL(GetFinalityMinVoteWeight(std::numeric_limits<int>::max()),
                      500 * COIN);
}

// The per-epoch vote-set cap is Boundary-A gated and Boundary A is one epoch
// past the fork, so the very first post-DAG epoch is uncapped. Recorded here
// so the gap is deliberate rather than discovered.
BOOST_AUTO_TEST_CASE(vote_set_cap_starts_one_epoch_after_the_fork)
{
    MainnetFinalityGuard guard;

    BOOST_CHECK_EQUAL(FORK_HEIGHT_BOUNDARY_A,
                      FORK_HEIGHT_DAG + FINALITY_EPOCH_INTERVAL_POST_DAG);
    BOOST_CHECK(IsBoundaryAConfigured());
    BOOST_CHECK(!IsBoundaryAActiveAtHeight(FORK_HEIGHT_DAG));
    BOOST_CHECK(IsBoundaryAActiveAtHeight(FORK_HEIGHT_BOUNDARY_A));
    BOOST_CHECK_EQUAL(FINALITY_CANONICAL_CERT_MAX_NULLIFIERS, 128u);
    BOOST_CHECK_EQUAL(FINALITY_MAX_BLOCK_VOTES, 32);
}

BOOST_AUTO_TEST_SUITE_END()
