// Tests for the finality-vote emission lane. A transparent CFinalityVote names its voter
// while a CNoteFinalityVote carries only a per-epoch tag; emitting both links them at the
// network layer. The mode selects one lane and the latch holds it for the process lifetime.

#include <boost/test/unit_test.hpp>

#include "../finality.h"
#include "../util.h"

#include <map>
#include <string>

namespace {

// GetArg keys off presence, so a restore has to remove a key that was never set
// rather than leave it as the empty string.
struct VoteLaneGuard
{
    bool fHadMode;
    std::string strSavedMode;

    VoteLaneGuard()
    {
        fHadMode = mapArgs.count("-finalityvotemode") > 0;
        if (fHadMode)
            strSavedMode = mapArgs["-finalityvotemode"];
        ResetFinalityVoteEmissionLane();
    }

    ~VoteLaneGuard()
    {
        if (fHadMode)
            mapArgs["-finalityvotemode"] = strSavedMode;
        else
            mapArgs.erase("-finalityvotemode");
        ResetFinalityVoteEmissionLane();
    }

    void SetMode(const std::string& strMode) { mapArgs["-finalityvotemode"] = strMode; }
    void ClearMode() { mapArgs.erase("-finalityvotemode"); }
};

} // namespace

BOOST_AUTO_TEST_SUITE(finality_vote_lane_tests)

// Every mode resolves to exactly one lane. A mode that could select both is the
// defect itself, so this is the property the rest of the suite rests on.
BOOST_AUTO_TEST_CASE(every_mode_selects_exactly_one_lane)
{
    const char* pszModes[] = { "auto", "transparent", "note",
                               "nullstake", "nullstakecold", "banana" };
    for (size_t i = 0; i < sizeof(pszModes) / sizeof(pszModes[0]); i++)
    {
        const FinalityVoteLane lane = GetFinalityVoteLaneForMode(pszModes[i]);
        BOOST_CHECK_MESSAGE(lane == FINALITY_VOTE_LANE_IDENTITY ||
                            lane == FINALITY_VOTE_LANE_ANONYMOUS,
                            std::string("mode has no lane: ") + pszModes[i]);
    }

    BOOST_CHECK(GetFinalityVoteLaneForMode("transparent") == FINALITY_VOTE_LANE_IDENTITY);
    BOOST_CHECK(GetFinalityVoteLaneForMode("note") == FINALITY_VOTE_LANE_ANONYMOUS);
    BOOST_CHECK(GetFinalityVoteLaneForMode("nullstake") == FINALITY_VOTE_LANE_ANONYMOUS);
    BOOST_CHECK(GetFinalityVoteLaneForMode("nullstakecold") == FINALITY_VOTE_LANE_ANONYMOUS);

    // An unrecognised mode is normalised to auto upstream; resolve it the same way
    // rather than leaving it laneless.
    BOOST_CHECK(GetFinalityVoteLaneForMode("banana") == FINALITY_VOTE_LANE_IDENTITY);
}

// auto is the default, so this is what an unconfigured node does. It must be the
// identity lane only: the deterministic tally counts transparent voters, so an
// auto node that also cast an anonymous vote would be leaking for no liveness gain.
BOOST_AUTO_TEST_CASE(auto_is_the_identity_lane_and_never_the_anonymous_one)
{
    VoteLaneGuard guard;
    guard.ClearMode();

    BOOST_CHECK(GetFinalityVoteLaneForMode("auto") == FINALITY_VOTE_LANE_IDENTITY);
    BOOST_CHECK(GetConfiguredFinalityVoteLane() == FINALITY_VOTE_LANE_IDENTITY);
    BOOST_CHECK(FinalityVoteEmissionLaneAllows(FINALITY_VOTE_LANE_IDENTITY));
    BOOST_CHECK(!FinalityVoteEmissionLaneAllows(FINALITY_VOTE_LANE_ANONYMOUS));

    // The legacy private selector agrees: auto never enters private proof generation.
    BOOST_CHECK(!FinalityVoteModeAllowsPrivateNote("auto", false));
    BOOST_CHECK(!FinalityVoteModeAllowsPrivateNote("auto", true));
}

// The mode string is normalised before the lane is read, so case cannot smuggle a
// node into a lane it did not ask for.
BOOST_AUTO_TEST_CASE(configured_lane_reads_the_normalised_mode)
{
    VoteLaneGuard guard;

    guard.SetMode("NOTE");
    BOOST_CHECK(GetConfiguredFinalityVoteLane() == FINALITY_VOTE_LANE_ANONYMOUS);

    guard.SetMode("Transparent");
    BOOST_CHECK(GetConfiguredFinalityVoteLane() == FINALITY_VOTE_LANE_IDENTITY);

    guard.SetMode("not-a-mode");
    BOOST_CHECK(GetConfiguredFinalityVoteLane() == FINALITY_VOTE_LANE_IDENTITY);
}

// The lane a node is not configured for never emits, whichever way round it is.
BOOST_AUTO_TEST_CASE(the_unconfigured_lane_never_emits)
{
    {
        VoteLaneGuard guard;
        guard.SetMode("transparent");
        BOOST_CHECK(!FinalityVoteEmissionLaneAllows(FINALITY_VOTE_LANE_ANONYMOUS));
        BOOST_CHECK(!RecordFinalityVoteEmission(FINALITY_VOTE_LANE_ANONYMOUS, 12));
        BOOST_CHECK(GetEmittedFinalityVoteLane() == FINALITY_VOTE_LANE_NONE);
    }
    {
        VoteLaneGuard guard;
        guard.SetMode("note");
        BOOST_CHECK(!FinalityVoteEmissionLaneAllows(FINALITY_VOTE_LANE_IDENTITY));
        BOOST_CHECK(!RecordFinalityVoteEmission(FINALITY_VOTE_LANE_IDENTITY, 12));
        BOOST_CHECK(GetEmittedFinalityVoteLane() == FINALITY_VOTE_LANE_NONE);
    }
}

// The correlation this exists to stop: one node, one epoch, both objects on the
// wire. The identity vote goes first, so the anonymous one must be refused.
BOOST_AUTO_TEST_CASE(identity_emission_locks_out_the_anonymous_lane_in_the_same_epoch)
{
    VoteLaneGuard guard;
    guard.SetMode("auto");

    BOOST_REQUIRE(RecordFinalityVoteEmission(FINALITY_VOTE_LANE_IDENTITY, 7));
    BOOST_CHECK(GetEmittedFinalityVoteLane() == FINALITY_VOTE_LANE_IDENTITY);
    BOOST_CHECK_EQUAL(GetEmittedFinalityVoteEpoch(), 7);

    BOOST_CHECK(!FinalityVoteEmissionLaneAllows(FINALITY_VOTE_LANE_ANONYMOUS));
    BOOST_CHECK(!RecordFinalityVoteEmission(FINALITY_VOTE_LANE_ANONYMOUS, 7));

    // The refusal leaves the latch where it was; the identity lane keeps working.
    BOOST_CHECK(GetEmittedFinalityVoteLane() == FINALITY_VOTE_LANE_IDENTITY);
    BOOST_CHECK(RecordFinalityVoteEmission(FINALITY_VOTE_LANE_IDENTITY, 7));
}

// The same epoch, the other order: the anonymous vote goes first and the identity
// vote is refused. A tag already on the wire must not be followed by the name.
BOOST_AUTO_TEST_CASE(anonymous_emission_locks_out_the_identity_lane_in_the_same_epoch)
{
    VoteLaneGuard guard;
    guard.SetMode("note");

    BOOST_REQUIRE(RecordFinalityVoteEmission(FINALITY_VOTE_LANE_ANONYMOUS, 7));
    BOOST_CHECK(GetEmittedFinalityVoteLane() == FINALITY_VOTE_LANE_ANONYMOUS);
    BOOST_CHECK_EQUAL(GetEmittedFinalityVoteEpoch(), 7);

    BOOST_CHECK(!FinalityVoteEmissionLaneAllows(FINALITY_VOTE_LANE_IDENTITY));
    BOOST_CHECK(!RecordFinalityVoteEmission(FINALITY_VOTE_LANE_IDENTITY, 7));
    BOOST_CHECK(GetEmittedFinalityVoteLane() == FINALITY_VOTE_LANE_ANONYMOUS);
}

// Per-epoch is not enough. A peer that saw the name in epoch 7 reads every tag
// from that connection afterwards as the same wallet's, so the latch holds for
// the life of the process and a mid-run mode change cannot lift it.
BOOST_AUTO_TEST_CASE(the_lane_latch_holds_across_epochs_and_mode_changes)
{
    VoteLaneGuard guard;
    guard.SetMode("note");

    BOOST_REQUIRE(RecordFinalityVoteEmission(FINALITY_VOTE_LANE_ANONYMOUS, 7));
    BOOST_CHECK(RecordFinalityVoteEmission(FINALITY_VOTE_LANE_ANONYMOUS, 8));
    BOOST_CHECK(RecordFinalityVoteEmission(FINALITY_VOTE_LANE_ANONYMOUS, 9));

    // The first epoch stays recorded: the latch is the lane, not the last epoch.
    BOOST_CHECK_EQUAL(GetEmittedFinalityVoteEpoch(), 7);

    // Switching the configured lane under a running node does not release it.
    guard.SetMode("transparent");
    BOOST_CHECK(GetConfiguredFinalityVoteLane() == FINALITY_VOTE_LANE_IDENTITY);
    BOOST_CHECK(!FinalityVoteEmissionLaneAllows(FINALITY_VOTE_LANE_IDENTITY));
    BOOST_CHECK(!RecordFinalityVoteEmission(FINALITY_VOTE_LANE_IDENTITY, 10));
    BOOST_CHECK(GetEmittedFinalityVoteLane() == FINALITY_VOTE_LANE_ANONYMOUS);
}

// Whatever the mode and whatever has emitted, the two lanes are never both open.
BOOST_AUTO_TEST_CASE(the_two_lanes_are_never_open_together)
{
    const char* pszModes[] = { "auto", "transparent", "note",
                               "nullstake", "nullstakecold", "banana" };
    for (size_t i = 0; i < sizeof(pszModes) / sizeof(pszModes[0]); i++)
    {
        VoteLaneGuard guard;
        guard.SetMode(pszModes[i]);

        const bool fIdentity = FinalityVoteEmissionLaneAllows(FINALITY_VOTE_LANE_IDENTITY);
        const bool fAnonymous = FinalityVoteEmissionLaneAllows(FINALITY_VOTE_LANE_ANONYMOUS);
        BOOST_CHECK_MESSAGE(!(fIdentity && fAnonymous),
                            std::string("both lanes open for mode ") + pszModes[i]);
        BOOST_CHECK_MESSAGE(fIdentity || fAnonymous,
                            std::string("no lane open for mode ") + pszModes[i]);

        // And once one has emitted, the other is shut for that mode too.
        const FinalityVoteLane open = fIdentity ? FINALITY_VOTE_LANE_IDENTITY
                                                : FINALITY_VOTE_LANE_ANONYMOUS;
        const FinalityVoteLane other = fIdentity ? FINALITY_VOTE_LANE_ANONYMOUS
                                                 : FINALITY_VOTE_LANE_IDENTITY;
        BOOST_REQUIRE(RecordFinalityVoteEmission(open, 3));
        BOOST_CHECK(!FinalityVoteEmissionLaneAllows(other));
        BOOST_CHECK(!RecordFinalityVoteEmission(other, 3));
    }
}

// The empty lane is not a lane; nothing emits under it.
BOOST_AUTO_TEST_CASE(the_none_lane_never_emits)
{
    VoteLaneGuard guard;
    guard.SetMode("auto");

    BOOST_CHECK(!FinalityVoteEmissionLaneAllows(FINALITY_VOTE_LANE_NONE));
    BOOST_CHECK(!RecordFinalityVoteEmission(FINALITY_VOTE_LANE_NONE, 4));
    BOOST_CHECK(GetEmittedFinalityVoteLane() == FINALITY_VOTE_LANE_NONE);
}

BOOST_AUTO_TEST_SUITE_END()
