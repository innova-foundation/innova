// A vote producer cannot be phase-locked out of every epoch: CFinalityVoteSchedule
// latches the epoch on the boundary block instead of relying on a wall-clock poll.
// Each simulation runs one event stream through the poll-based and latched producers.

#include <boost/test/unit_test.hpp>

#include "../finality_schedule.h"

#include <algorithm>
#include <map>
#include <utility>
#include <vector>

namespace {

// Post-DAG epoch geometry (FINALITY_EPOCH_INTERVAL_POST_DAG). Held locally so the
// simulation is a pure function of its parameters and does not depend on which
// network's fork heights the test binary happens to be configured for.
const int EPOCH_LEN = 300;

int EpochOf(int nHeight) { return nHeight / EPOCH_LEN; }
int BoundaryOf(int nEpoch) { return nEpoch * EPOCH_LEN; }

// The producer as it was: wake on a free-running clock, sample the tip, test the
// window as a level. Returns the number of epochs it managed to vote in.
int LegacyPolledVotes(int64_t nSpacingMs,
                      int64_t nPollMs,
                      int64_t nPhaseMs,
                      int nWindow,
                      int nEpochs)
{
    const int64_t nEndMs = (int64_t)nEpochs * EPOCH_LEN * nSpacingMs;
    int nLastEpochVoted = -1;
    int nVotes = 0;
    for (int64_t t = nPhaseMs; t < nEndMs; t += nPollMs)
    {
        int nTip = (int)(t / nSpacingMs);
        int nEpoch = EpochOf(nTip);
        if (nTip - BoundaryOf(nEpoch) >= nWindow)
            continue;
        if (nEpoch == nLastEpochVoted)
            continue;
        nLastEpochVoted = nEpoch;  // ProduceFinalityVote() succeeds
        nVotes++;
    }
    return nVotes;
}

// The producer as it is: the same backstop poll, plus a wake from the chain event that
// publishes each tip. nWakeLatencyMs is how long after the boundary block connects the
// producer thread actually gets to run.
int ScheduledVotes(int64_t nSpacingMs,
                   int64_t nPollMs,
                   int64_t nPhaseMs,
                   int nWindow,
                   int nEpochs,
                   int64_t nWakeLatencyMs,
                   int nMaxAttempts = 4)
{
    const int nBlocks = nEpochs * EPOCH_LEN;
    const int64_t nEndMs = (int64_t)nBlocks * nSpacingMs;

    // key = (time, kind); kind 0 = block connect, observed before a wake at a tie.
    std::multimap<std::pair<int64_t, int>, int> mapEvents;
    for (int h = 0; h < nBlocks; h++)
    {
        int64_t t = (int64_t)h * nSpacingMs;
        mapEvents.insert(std::make_pair(std::make_pair(t, 0), h));
        if (h == BoundaryOf(EpochOf(h)))  // the block that signals the producer
            mapEvents.insert(std::make_pair(std::make_pair(t + nWakeLatencyMs, 1), h));
    }
    for (int64_t t = nPhaseMs; t < nEndMs; t += nPollMs)
        mapEvents.insert(std::make_pair(std::make_pair(t, 1), 0));

    CFinalityVoteSchedule sched;
    int nVotes = 0;
    for (std::multimap<std::pair<int64_t, int>, int>::const_iterator it = mapEvents.begin();
         it != mapEvents.end(); ++it)
    {
        if (it->first.second == 0)
        {
            int h = it->second;
            sched.OnTipChanged(h, EpochOf(h), BoundaryOf(EpochOf(h)));
            continue;
        }
        int nTip = (int)(it->first.first / nSpacingMs);
        if (nTip >= nBlocks)
            nTip = nBlocks - 1;
        sched.OnTipChanged(nTip, EpochOf(nTip), BoundaryOf(EpochOf(nTip)));
        int nEpoch = -1;
        if (sched.Claim(nTip, nWindow, nMaxAttempts, nEpoch) != FINALITY_VOTE_CLAIM_OK)
            continue;
        sched.Release(nEpoch, true);  // ProduceFinalityVote() succeeds
        nVotes++;
    }
    return nVotes;
}

// The same schedule without NotifyFinalityTipChanged, so the producer sees the chain
// only through its own poll.
int ScheduledVotesWithoutChainEvents(int64_t nSpacingMs,
                                     int64_t nPollMs,
                                     int64_t nPhaseMs,
                                     int nWindow,
                                     int nEpochs)
{
    const int nBlocks = nEpochs * EPOCH_LEN;
    const int64_t nEndMs = (int64_t)nBlocks * nSpacingMs;
    CFinalityVoteSchedule sched;
    int nVotes = 0;
    for (int64_t t = nPhaseMs; t < nEndMs; t += nPollMs)
    {
        int nTip = (int)(t / nSpacingMs);
        sched.OnTipChanged(nTip, EpochOf(nTip), BoundaryOf(EpochOf(nTip)));
        int nEpoch = -1;
        if (sched.Claim(nTip, nWindow, 4, nEpoch) != FINALITY_VOTE_CLAIM_OK)
            continue;
        sched.Release(nEpoch, true);
        nVotes++;
    }
    return nVotes;
}

// Phases sampled across one poll period.
std::vector<int64_t> PhaseSweep(int64_t nPollMs, int nSamples)
{
    std::vector<int64_t> v;
    for (int i = 0; i < nSamples; i++)
        v.push_back((nPollMs * i) / nSamples);
    return v;
}

// Phases on which the polled producer votes in no epoch at all.
int LegacyDeadPhases(int64_t nSpacingMs, int64_t nPollMs, int nWindow,
                     int nEpochs, int nSamples)
{
    std::vector<int64_t> vPhases = PhaseSweep(nPollMs, nSamples);
    int nDead = 0;
    for (size_t i = 0; i < vPhases.size(); i++)
    {
        if (LegacyPolledVotes(nSpacingMs, nPollMs, vPhases[i], nWindow, nEpochs) == 0)
            nDead++;
    }
    return nDead;
}

} // namespace

BOOST_AUTO_TEST_SUITE(finality_vote_schedule_tests)

// ---------------------------------------------------------------------------
// The poll-sampling failure, as arithmetic
// ---------------------------------------------------------------------------

// The general law. When the stride divides the epoch the lattice phase is frozen, and
// the fraction of phases that never see the window is exactly (stride - window)/stride.
// Checked against strides 6, 10, 15 and 20 -- all divisors of the 300-block epoch.
BOOST_AUTO_TEST_CASE(phase_lock_is_permanent_when_the_stride_divides_the_epoch)
{
    const int nWindow = 5, nEpochs = 60, nSamples = 60;
    const int vStrides[] = { 6, 10, 15, 20 };

    for (size_t i = 0; i < sizeof(vStrides) / sizeof(vStrides[0]); i++)
    {
        const int nStride = vStrides[i];
        BOOST_REQUIRE_EQUAL(EPOCH_LEN % nStride, 0);
        BOOST_REQUIRE_GT(nStride, nWindow);

        const int64_t nSpacingMs = 1000;
        const int64_t nPollMs = nSpacingMs * nStride;
        int nDead = LegacyDeadPhases(nSpacingMs, nPollMs, nWindow, nEpochs, nSamples);

        // (stride - window) / stride of all phases, exactly.
        BOOST_CHECK_EQUAL(nDead, (nSamples * (nStride - nWindow)) / nStride);

        // And a dead phase is dead for good, not merely unlucky: nEpochs is 60.
        std::vector<int64_t> vPhases = PhaseSweep(nPollMs, nSamples);
        for (size_t p = 0; p < vPhases.size(); p++)
        {
            int nVotes = LegacyPolledVotes(nSpacingMs, nPollMs, vPhases[p], nWindow, nEpochs);
            BOOST_CHECK(nVotes == 0 || nVotes == nEpochs);
        }
    }
}

// The concrete instance that matters for the 500ms spacing under evaluation: on the
// original constants it halves the effective voter set, permanently, at random.
BOOST_AUTO_TEST_CASE(half_ms_spacing_mutes_half_the_phases_on_the_original_constants)
{
    // 5-block window, 5s poll. 500ms blocks make the stride 10, and 10 divides 300.
    BOOST_CHECK_EQUAL(LegacyDeadPhases(500, 5000, 5, 60, 40), 20);
    // The same constants at 1s blocks put the stride at exactly the window width,
    // which is the only reason they have survived so far.
    BOOST_CHECK_EQUAL(LegacyDeadPhases(1000, 5000, 5, 60, 40), 0);
    // A loop body costing one second is enough to break that tie at 1s blocks too.
    BOOST_CHECK_EQUAL(LegacyDeadPhases(1000, 6000, 5, 60, 60), 10);
}

// The shipped mitigation -- an 18-block window sampled at 1s -- buys margin down to
// about 55ms spacing and then fails in exactly the same way. It is a tuning of the
// threshold, not a removal of the failure mode.
BOOST_AUTO_TEST_CASE(widened_window_only_moves_the_threshold)
{
    const int nWindow = 18;
    const int64_t nPollMs = 1000;

    // Stride stays under the window: no dead phase at any spacing down to 55ms.
    BOOST_CHECK_EQUAL(LegacyDeadPhases(1000, nPollMs, nWindow, 60, 20), 0);
    BOOST_CHECK_EQUAL(LegacyDeadPhases(500, nPollMs, nWindow, 60, 20), 0);
    BOOST_CHECK_EQUAL(LegacyDeadPhases(100, nPollMs, nWindow, 60, 20), 0);
    BOOST_CHECK_EQUAL(LegacyDeadPhases(55, nPollMs, nWindow, 60, 20), 0);

    // 50ms: stride 20, divides 300, exceeds 18 -- the phase lock is back, at the
    // predicted (20-18)/20 of phases.
    BOOST_CHECK_EQUAL(LegacyDeadPhases(50, nPollMs, nWindow, 60, 40), 4);
    // 40ms: stride 25, (25-18)/25 of phases.
    BOOST_CHECK_EQUAL(LegacyDeadPhases(40, nPollMs, nWindow, 60, 50), 14);
}

// ---------------------------------------------------------------------------
// The fix
// ---------------------------------------------------------------------------

// Every configuration above, run through the schedule on the same event stream. The
// producer keeps the ORIGINAL 5-block window and its slow backstop poll throughout:
// nothing here is retuned, the trigger is simply the boundary block instead of a clock.
BOOST_AUTO_TEST_CASE(scheduled_producer_survives_every_case_the_poll_dies_in)
{
    struct Case { int64_t nSpacingMs; int64_t nPollMs; int nWindow; };
    const Case vCases[] = {
        { 500,  5000, 5  },   // 500ms spacing, original constants: 50% of phases dead
        { 1000, 6000, 5  },   // 1s spacing, 1s of loop body:       17% dead
        { 1000, 10000, 5 },   // 1s spacing, slow poll:             50% dead
        { 1000, 15000, 5 },   // 1s spacing, slower still:          67% dead
        { 50,   1000, 18 },   // 50ms spacing, shipped mitigation:  10% dead
    };
    const int nEpochs = 60, nSamples = 40;

    for (size_t c = 0; c < sizeof(vCases) / sizeof(vCases[0]); c++)
    {
        const Case& cs = vCases[c];
        // Each case really is a failure for the polled producer.
        BOOST_REQUIRE_GT(LegacyDeadPhases(cs.nSpacingMs, cs.nPollMs, cs.nWindow,
                                          nEpochs, nSamples), 0);

        std::vector<int64_t> vPhases = PhaseSweep(cs.nPollMs, nSamples);
        for (size_t p = 0; p < vPhases.size(); p++)
        {
            BOOST_CHECK_EQUAL(
                ScheduledVotes(cs.nSpacingMs, cs.nPollMs, vPhases[p], cs.nWindow,
                               nEpochs, cs.nSpacingMs / 2),
                nEpochs);
        }
    }
}

// The latch alone is still phase-locked; liveness comes from NotifyFinalityTipChanged
// on the tip-publication path (PublishDurablyCommittedBest).
BOOST_AUTO_TEST_CASE(chain_event_wake_is_what_defeats_the_lattice)
{
    const int64_t nSpacingMs = 500, nPollMs = 5000;  // stride 10, divides 300
    const int nWindow = 5, nEpochs = 60, nSamples = 40;

    std::vector<int64_t> vPhases = PhaseSweep(nPollMs, nSamples);
    int nDeadWithoutEvents = 0;
    for (size_t p = 0; p < vPhases.size(); p++)
    {
        if (ScheduledVotesWithoutChainEvents(nSpacingMs, nPollMs, vPhases[p],
                                             nWindow, nEpochs) == 0)
            nDeadWithoutEvents++;
        // Wired to the chain, the same phase votes in every epoch.
        BOOST_CHECK_EQUAL(
            ScheduledVotes(nSpacingMs, nPollMs, vPhases[p], nWindow, nEpochs,
                           nSpacingMs / 2),
            nEpochs);
    }
    // Unwired, the schedule inherits the polled producer's dead fraction exactly.
    BOOST_CHECK_EQUAL(nDeadWithoutEvents,
                      LegacyDeadPhases(nSpacingMs, nPollMs, nWindow, nEpochs, nSamples));
    BOOST_CHECK_GT(nDeadWithoutEvents, 0);
}

// The schedule is driven by the boundary block, so it does not depend on block spacing.
BOOST_AUTO_TEST_CASE(scheduled_producer_is_independent_of_block_spacing)
{
    const int64_t vSpacings[] = { 2000, 1000, 500, 250, 100, 50, 25 };
    const int64_t nPollMs = 5000;
    const int nWindow = 5, nEpochs = 20, nSamples = 12;

    std::vector<int64_t> vPhases = PhaseSweep(nPollMs, nSamples);
    for (size_t s = 0; s < sizeof(vSpacings) / sizeof(vSpacings[0]); s++)
    {
        for (size_t p = 0; p < vPhases.size(); p++)
        {
            BOOST_CHECK_EQUAL(
                ScheduledVotes(vSpacings[s], nPollMs, vPhases[p], nWindow, nEpochs,
                               vSpacings[s] / 2),
                nEpochs);
        }
    }
}

// Wake latency is the only thing that can still cost an epoch, and it does so only once
// it exceeds the window in wall-clock terms: a monotone dependence with no phase term,
// which is what makes it an operational limit rather than a lottery.
BOOST_AUTO_TEST_CASE(scheduled_producer_degrades_only_with_wake_latency)
{
    const int64_t nSpacingMs = 1000, nPollMs = 5000;
    const int nWindow = 5, nEpochs = 20;

    BOOST_CHECK_EQUAL(ScheduledVotes(nSpacingMs, nPollMs, 0, nWindow, nEpochs, 0), nEpochs);
    BOOST_CHECK_EQUAL(ScheduledVotes(nSpacingMs, nPollMs, 0, nWindow, nEpochs, 3500), nEpochs);
    BOOST_CHECK_LE(ScheduledVotes(nSpacingMs, nPollMs, 0, nWindow, nEpochs, 20000), nEpochs);
}

// ---------------------------------------------------------------------------
// Why it cannot alias: dwell
// ---------------------------------------------------------------------------

// The legacy predicate is true at nWindow of the epoch's EPOCH_LEN heights; the latch is
// true at all of them. That ratio is the entire difference between the two designs, and
// it is why no stride can step over the latch while still observing the chain.
BOOST_AUTO_TEST_CASE(latched_epoch_dwells_the_whole_epoch)
{
    const int nWindow = 5, nEpoch = 4, nBoundary = BoundaryOf(nEpoch);

    int nLegacyTrue = 0, nLatchTrue = 0;
    for (int h = nBoundary; h < nBoundary + EPOCH_LEN; h++)
    {
        if (h - nBoundary < nWindow)
            nLegacyTrue++;
        // Observing the epoch for the first time at height h still latches it.
        CFinalityVoteSchedule sched;
        sched.OnTipChanged(h, EpochOf(h), BoundaryOf(EpochOf(h)));
        if (sched.HasWork())
            nLatchTrue++;
    }
    BOOST_CHECK_EQUAL(nLegacyTrue, nWindow);
    BOOST_CHECK_EQUAL(nLatchTrue, EPOCH_LEN);
}

// A burst that carries the tip past the window between two producer runs is the one case
// the schedule still cannot vote in -- the vote would not be includable. It has to say
// so rather than look idle: "nothing to do" and "too late" call for different responses.
BOOST_AUTO_TEST_CASE(late_observation_is_reported_not_silently_dropped)
{
    CFinalityVoteSchedule sched;
    const int nEpoch = 7, nBoundary = BoundaryOf(nEpoch), nWindow = 5;

    int nOut = -1;
    BOOST_CHECK_EQUAL((int)sched.Claim(nBoundary, nWindow, 4, nOut),
                      (int)FINALITY_VOTE_CLAIM_IDLE);

    BOOST_CHECK(sched.OnTipChanged(nBoundary, nEpoch, nBoundary));
    BOOST_CHECK(sched.HasWork());
    BOOST_CHECK_EQUAL(sched.LatchedEpoch(), nEpoch);
    BOOST_CHECK_EQUAL((int)sched.Claim(nBoundary + 50, nWindow, 4, nOut),
                      (int)FINALITY_VOTE_CLAIM_LATE);
    BOOST_CHECK_EQUAL(nOut, -1);
    // A late epoch costs no attempt, so it cannot burn the next epoch's budget.
    BOOST_CHECK_EQUAL(sched.Attempts(), 0);
}

// ---------------------------------------------------------------------------
// Schedule state machine
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(claim_is_exclusive_between_the_two_producer_loops)
{
    CFinalityVoteSchedule sched;
    const int nEpoch = 3, nBoundary = BoundaryOf(nEpoch);
    BOOST_CHECK(sched.OnTipChanged(nBoundary, nEpoch, nBoundary));

    int nFirst = -1, nSecond = -1;
    BOOST_CHECK_EQUAL((int)sched.Claim(nBoundary, 18, 4, nFirst), (int)FINALITY_VOTE_CLAIM_OK);
    BOOST_CHECK_EQUAL(nFirst, nEpoch);
    // ThreadFinalityVoter and StakeMiner share one schedule; the second must not
    // produce a duplicate vote for the same epoch.
    BOOST_CHECK_EQUAL((int)sched.Claim(nBoundary + 1, 18, 4, nSecond),
                      (int)FINALITY_VOTE_CLAIM_BUSY);

    sched.Release(nFirst, false);  // production failed; the epoch stays outstanding
    BOOST_CHECK(sched.HasWork());
    BOOST_CHECK_EQUAL((int)sched.Claim(nBoundary + 2, 18, 4, nSecond),
                      (int)FINALITY_VOTE_CLAIM_OK);
    sched.Release(nSecond, true);
    BOOST_CHECK(!sched.HasWork());
    BOOST_CHECK_EQUAL((int)sched.Claim(nBoundary + 3, 18, 4, nSecond),
                      (int)FINALITY_VOTE_CLAIM_IDLE);
}

BOOST_AUTO_TEST_CASE(attempt_budget_is_per_epoch_and_resets_at_the_next_boundary)
{
    CFinalityVoteSchedule sched;
    const int nEpoch = 2, nBoundary = BoundaryOf(nEpoch), nMax = 3;
    BOOST_CHECK(sched.OnTipChanged(nBoundary, nEpoch, nBoundary));

    for (int i = 0; i < nMax; i++)
    {
        int nOut = -1;
        BOOST_CHECK_EQUAL((int)sched.Claim(nBoundary, 18, nMax, nOut),
                          (int)FINALITY_VOTE_CLAIM_OK);
        sched.Release(nOut, false);
    }
    int nOut = -1;
    BOOST_CHECK_EQUAL((int)sched.Claim(nBoundary, 18, nMax, nOut),
                      (int)FINALITY_VOTE_CLAIM_SPENT);

    const int nNext = nEpoch + 1, nNextBoundary = BoundaryOf(nNext);
    BOOST_CHECK(sched.OnTipChanged(nNextBoundary, nNext, nNextBoundary));
    BOOST_CHECK_EQUAL(sched.Attempts(), 0);
    BOOST_CHECK_EQUAL((int)sched.Claim(nNextBoundary, 18, nMax, nOut),
                      (int)FINALITY_VOTE_CLAIM_OK);
    BOOST_CHECK_EQUAL(nOut, nNext);
}

BOOST_AUTO_TEST_CASE(reorg_back_into_a_voted_epoch_reopens_it)
{
    CFinalityVoteSchedule sched;
    const int nEpoch = 5, nBoundary = BoundaryOf(nEpoch);
    const int nNext = nEpoch + 1, nNextBoundary = BoundaryOf(nNext);

    BOOST_CHECK(sched.OnTipChanged(nBoundary, nEpoch, nBoundary));
    int nOut = -1;
    BOOST_CHECK_EQUAL((int)sched.Claim(nBoundary, 18, 4, nOut), (int)FINALITY_VOTE_CLAIM_OK);
    sched.Release(nOut, true);

    BOOST_CHECK(sched.OnTipChanged(nNextBoundary, nNext, nNextBoundary));
    BOOST_CHECK_EQUAL((int)sched.Claim(nNextBoundary, 18, 4, nOut), (int)FINALITY_VOTE_CLAIM_OK);
    sched.Release(nOut, true);

    // A reorg drops the tip back into the earlier epoch: outstanding again, with a
    // fresh budget, exactly as the old sampler's != test allowed.
    BOOST_CHECK(sched.OnTipChanged(nBoundary + 3, nEpoch, nBoundary));
    BOOST_CHECK(sched.HasWork());
    BOOST_CHECK_EQUAL(sched.Attempts(), 0);
    BOOST_CHECK_EQUAL((int)sched.Claim(nBoundary + 3, 18, 4, nOut), (int)FINALITY_VOTE_CLAIM_OK);
    BOOST_CHECK_EQUAL(nOut, nEpoch);
}

// The wake is edge-triggered: exactly one wake per epoch, or the producer loops spin
// for the rest of the epoch.
BOOST_AUTO_TEST_CASE(wake_is_edge_triggered_once_per_epoch)
{
    CFinalityVoteSchedule sched;
    const int nEpoch = 9, nBoundary = BoundaryOf(nEpoch);

    int nWakes = 0;
    for (int h = nBoundary; h < nBoundary + EPOCH_LEN; h++)
    {
        if (sched.OnTipChanged(h, EpochOf(h), BoundaryOf(EpochOf(h))))
            nWakes++;
    }
    BOOST_CHECK_EQUAL(nWakes, 1);

    // Still one per epoch after the attempt budget is spent and the epoch is stuck
    // outstanding -- the case that would otherwise spin.
    int nOut = -1;
    for (int i = 0; i < 4; i++)
    {
        if (sched.Claim(nBoundary, 18, 4, nOut) == FINALITY_VOTE_CLAIM_OK)
            sched.Release(nOut, false);
    }
    BOOST_CHECK(sched.HasWork());
    nWakes = 0;
    for (int h = nBoundary + 1; h < nBoundary + EPOCH_LEN; h++)
    {
        if (sched.OnTipChanged(h, EpochOf(h), BoundaryOf(EpochOf(h))))
            nWakes++;
    }
    BOOST_CHECK_EQUAL(nWakes, 0);
}

BOOST_AUTO_TEST_CASE(nonsense_tip_reports_are_ignored)
{
    CFinalityVoteSchedule sched;
    BOOST_CHECK(!sched.OnTipChanged(100, -1, 0));
    BOOST_CHECK(!sched.OnTipChanged(100, 0, -1));
    // A height below its own boundary cannot be a tip in that epoch.
    BOOST_CHECK(!sched.OnTipChanged(BoundaryOf(3) - 1, 3, BoundaryOf(3)));
    BOOST_CHECK(!sched.HasWork());
    BOOST_CHECK_EQUAL(sched.LatchedEpoch(), -1);
}

// ---------------------------------------------------------------------------
// Emission ordering margin: votes are emitted a margin (in blocks) after the boundary.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(emit_offset_holds_the_claim_until_the_tip_has_moved_on)
{
    CFinalityVoteSchedule sched;
    const int nEpoch = 6, nBoundary = BoundaryOf(nEpoch), nWindow = 18, nOffset = 2;
    BOOST_CHECK(sched.OnTipChanged(nBoundary, nEpoch, nBoundary));  // no margin declared

    int nOut = -1;
    for (int nAhead = 0; nAhead < nOffset; nAhead++)
    {
        BOOST_CHECK_EQUAL(
            (int)sched.Claim(nBoundary + nAhead, nWindow, 4, nOut, nOffset),
            (int)FINALITY_VOTE_CLAIM_EARLY);
        BOOST_CHECK_EQUAL(nOut, -1);
    }
    // Held, not lost: the latch is what carries the epoch, so the margin delays the
    // vote and never costs it.
    BOOST_CHECK(sched.HasWork());
    BOOST_CHECK_EQUAL(sched.LatchedEpoch(), nEpoch);
    // And it spends no attempt, or a margin of N would eat N of the retry budget.
    BOOST_CHECK_EQUAL(sched.Attempts(), 0);

    BOOST_CHECK_EQUAL((int)sched.Claim(nBoundary + nOffset, nWindow, 4, nOut, nOffset),
                      (int)FINALITY_VOTE_CLAIM_OK);
    BOOST_CHECK_EQUAL(nOut, nEpoch);
    BOOST_CHECK_EQUAL(sched.Attempts(), 1);
}

// The node-local margin is clamped below the producer window so it can never cost an epoch.
BOOST_AUTO_TEST_CASE(emit_offset_can_never_empty_the_emission_band)
{
    for (int nWindow = 1; nWindow <= 24; nWindow++)
    {
        for (int nOffset = 0; nOffset <= 30; nOffset++)
        {
            const int nEpoch = 5, nBoundary = BoundaryOf(nEpoch);
            CFinalityVoteSchedule sched;
            BOOST_CHECK(sched.OnTipChanged(nBoundary, nEpoch, nBoundary));

            // Walk the tip across the whole window and record where a claim lands.
            int nClaimedAt = -1;
            for (int nAhead = 0; nAhead < nWindow; nAhead++)
            {
                int nOut = -1;
                if (sched.Claim(nBoundary + nAhead, nWindow, 4, nOut, nOffset) ==
                    FINALITY_VOTE_CLAIM_OK)
                {
                    nClaimedAt = nAhead;
                    BOOST_CHECK_EQUAL(nOut, nEpoch);
                    break;
                }
            }
            // Some height inside the window always claims, for every offset.
            BOOST_CHECK_MESSAGE(nClaimedAt >= 0,
                                "no claim inside window " << nWindow
                                << " at offset " << nOffset);
            // And it is inside the window, which is what keeps the vote includable:
            // the consensus rule accepts [boundary, boundary + inclusion window).
            BOOST_CHECK(nClaimedAt < nWindow);
            BOOST_CHECK(nClaimedAt <= nOffset);
        }
    }
}

// The margin is a block count off the latched boundary, so replaying an epoch at
// several spacings must give the same emission height.
BOOST_AUTO_TEST_CASE(emit_offset_is_independent_of_block_spacing)
{
    const int nEpoch = 9, nBoundary = BoundaryOf(nEpoch), nWindow = 18, nOffset = 2;

    int nFirstEmission = -1;
    // Blocks per producer poll: 1 block/poll at 1s spacing and a 1s poll, 5 at 200ms,
    // and a fractional rate the other way is just a poll that sees no new block.
    const int vStride[] = { 1, 2, 3, 5, 8 };
    for (unsigned int i = 0; i < sizeof(vStride) / sizeof(vStride[0]); i++)
    {
        CFinalityVoteSchedule sched;
        BOOST_CHECK(sched.OnTipChanged(nBoundary, nEpoch, nBoundary));

        int nEmission = -1;
        for (int nAhead = 0; nAhead < nWindow; nAhead += vStride[i])
        {
            int nOut = -1;
            if (sched.Claim(nBoundary + nAhead, nWindow, 4, nOut, nOffset) ==
                FINALITY_VOTE_CLAIM_OK)
            {
                nEmission = nAhead;
                break;
            }
        }
        // Every spacing emits, and never before the margin has actually elapsed.
        BOOST_CHECK_MESSAGE(nEmission >= 0, "no emission at stride " << vStride[i]);
        BOOST_CHECK(nEmission >= nOffset);
        BOOST_CHECK(nEmission < nWindow);
        if (i == 0)
            nFirstEmission = nEmission;
    }
    BOOST_CHECK_EQUAL(nFirstEmission, nOffset);
}

// A reorg that moves the boundary moves both terms of the margin together, because
// both are counted off the boundary the latch is holding. The margin therefore cannot
// be satisfied by height carried over from the chain the reorg replaced.
BOOST_AUTO_TEST_CASE(emit_offset_is_measured_against_the_relatched_boundary)
{
    CFinalityVoteSchedule sched;
    const int nEpoch = 8, nBoundary = BoundaryOf(nEpoch), nWindow = 18, nOffset = 2;
    const int nPrev = nEpoch - 1, nPrevBoundary = BoundaryOf(nPrev);

    BOOST_CHECK(sched.OnTipChanged(nBoundary + 5, nEpoch, nBoundary));
    int nOut = -1;
    BOOST_CHECK_EQUAL((int)sched.Claim(nBoundary + 5, nWindow, 4, nOut, nOffset),
                      (int)FINALITY_VOTE_CLAIM_OK);
    sched.Release(nOut, true);

    // The reorg lands the tip back in the previous epoch, which reopens it.
    BOOST_CHECK(sched.OnTipChanged(nPrevBoundary, nPrev, nPrevBoundary));
    BOOST_CHECK_EQUAL(sched.LatchedEpoch(), nPrev);
    // The margin restarts from the boundary now latched, not from the height the
    // node had already reached before the reorg.
    BOOST_CHECK_EQUAL((int)sched.Claim(nPrevBoundary, nWindow, 4, nOut, nOffset),
                      (int)FINALITY_VOTE_CLAIM_EARLY);
    BOOST_CHECK_EQUAL((int)sched.Claim(nPrevBoundary + nOffset, nWindow, 4, nOut, nOffset),
                      (int)FINALITY_VOTE_CLAIM_OK);
    BOOST_CHECK_EQUAL(nOut, nPrev);
}

// Offset 0 is the default and claims at the boundary. The margin must also move the
// wake, or the producer sleeps through the window after refusing its own claim.
BOOST_AUTO_TEST_CASE(the_wake_edge_moves_with_the_margin)
{
    CFinalityVoteSchedule sched;
    const int nEpoch = 12, nBoundary = BoundaryOf(nEpoch), nWindow = 18, nOffset = 2;

    // The boundary itself is not the edge any more.
    BOOST_CHECK(!sched.OnTipChanged(nBoundary, nEpoch, nBoundary, nWindow, nOffset));
    BOOST_CHECK(sched.HasWork());
    BOOST_CHECK(!sched.OnTipChanged(nBoundary + 1, nEpoch, nBoundary, nWindow, nOffset));

    // Reaching the margin is, and a claim there succeeds -- the two agree, which is
    // the whole point: the producer is woken exactly when it can act.
    BOOST_CHECK(sched.OnTipChanged(nBoundary + nOffset, nEpoch, nBoundary, nWindow, nOffset));
    int nOut = -1;
    BOOST_CHECK_EQUAL((int)sched.Claim(nBoundary + nOffset, nWindow, 4, nOut, nOffset),
                      (int)FINALITY_VOTE_CLAIM_OK);
    BOOST_CHECK_EQUAL(nOut, nEpoch);

    // Still one wake per epoch: the margin makes the edge a level for a couple of
    // blocks, and re-waking on each of them would stop the producer ever sleeping.
    for (int nAhead = nOffset + 1; nAhead < nWindow; nAhead++)
        BOOST_CHECK(!sched.OnTipChanged(nBoundary + nAhead, nEpoch, nBoundary,
                                        nWindow, nOffset));
}

// A margin wider than the window must still wake, or clamping the claim while leaving
// the wake unclamped would strand the producer asleep for the whole epoch.
BOOST_AUTO_TEST_CASE(the_wake_edge_survives_a_margin_wider_than_the_window)
{
    for (int nWindow = 1; nWindow <= 6; nWindow++)
    {
        CFinalityVoteSchedule sched;
        const int nEpoch = 13, nBoundary = BoundaryOf(nEpoch), nOffset = 30;
        int nWokeAt = -1;
        for (int nAhead = 0; nAhead < nWindow; nAhead++)
        {
            if (sched.OnTipChanged(nBoundary + nAhead, nEpoch, nBoundary, nWindow, nOffset))
            {
                nWokeAt = nAhead;
                break;
            }
        }
        BOOST_CHECK_MESSAGE(nWokeAt >= 0, "never woke for window " << nWindow);
        int nOut = -1;
        BOOST_CHECK_EQUAL((int)sched.Claim(nBoundary + nWokeAt, nWindow, 4, nOut, nOffset),
                          (int)FINALITY_VOTE_CLAIM_OK);
    }
}

BOOST_AUTO_TEST_CASE(emit_offset_defaults_to_no_margin)
{
    CFinalityVoteSchedule sched;
    const int nEpoch = 11, nBoundary = BoundaryOf(nEpoch);
    BOOST_CHECK(sched.OnTipChanged(nBoundary, nEpoch, nBoundary));
    int nOut = -1;
    BOOST_CHECK_EQUAL((int)sched.Claim(nBoundary, 18, 4, nOut),
                      (int)FINALITY_VOTE_CLAIM_OK);
    BOOST_CHECK_EQUAL(nOut, nEpoch);
}

BOOST_AUTO_TEST_SUITE_END()
