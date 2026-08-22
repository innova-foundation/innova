// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Coverage for R-FIN-001: the reorg finality guard in Reorganize and
// CBlock::SetBestChain.
//
// The guard's anchor is the deterministic finalized height as of epoch(tip)-1, and
// the epoch selector reads the evaluating node's own tip. Two honest nodes whose
// tips sit one block apart across an epoch boundary therefore select different
// epochs and evaluate the same candidate branch against different finalized
// heights. Because a rejection sets pfPermanentInvalid, which AddToBlockIndex turns
// into BLOCK_FAILED_VALID, and that flag is serialized and cleared only by
// reconsiderblock, a disagreement here is permanent and persisted -- a chain split
// that does not heal.
//
// The anchor cannot be moved onto the candidate or the fork point: finalization
// evidence lives on the chain being abandoned, so an anchor taken from at or below
// the fork point cannot condemn anything, and a candidate-derived anchor is both
// attacker-selectable and unavailable when the candidate has crossed a boundary the
// node has not completed. What is corrected instead is verdict severity, via a
// second anchor one epoch older that gates persistence.
//
// The invariant these tests pin is NOT that two straddling nodes return the same
// verdict -- inside the one-epoch band a laggard may still follow a branch its
// neighbour transiently refuses, which self-heals because nothing is written down.
// It is the strictly stronger-where-it-matters property:
//
//   no honest node PERMANENTLY condemns a branch that another honest node FOLLOWS.
//
// forbidden_pair below is that property stated directly.

#include <boost/test/unit_test.hpp>

#include "../dag.h"
#include "../finality.h"
#include "../main.h"

#include <map>
#include <vector>

extern bool fRegTest;
extern bool fTestNet;

BOOST_AUTO_TEST_SUITE(reorg_finality_anchor_tests)

namespace {

// Forces regtest fork heights (finality 10, DAG 11, epoch-state V3 311) for the
// lifetime of a test and restores the network flags afterwards.
struct RegTestNetwork
{
    bool oldRegTest;
    bool oldTestNet;
    RegTestNetwork()
    {
        oldRegTest = fRegTest;
        oldTestNet = fTestNet;
        fRegTest = true;
        fTestNet = false;
    }
    ~RegTestNetwork()
    {
        fRegTest = oldRegTest;
        fTestNet = oldTestNet;
    }
};

// Mainnet fork heights, for the checks that regtest's tiny heights cannot express.
struct MainNetNetwork
{
    bool oldRegTest;
    bool oldTestNet;
    MainNetNetwork()
    {
        oldRegTest = fRegTest;
        oldTestNet = fTestNet;
        fRegTest = false;
        fTestNet = false;
    }
    ~MainNetNetwork()
    {
        fRegTest = oldRegTest;
        fTestNet = oldTestNet;
    }
};

// Epoch states carry nothing here but their epoch number and finalized height:
// the guard reads only nFinalizedHeightAsOf. An empty curve tree pairs with a zero
// curve root, which is what ValidateEpochStateBatch requires.
void InstallFinalizedHeights(CDAGManager& dag, int nFirstEpoch,
                             const std::vector<int>& vFinalized)
{
    std::map<int, CEpochState> states;
    std::map<int, CCurveTree> trees;
    for (size_t i = 0; i < vFinalized.size(); i++)
    {
        const int nEpoch = nFirstEpoch + (int)i;
        CEpochState state;
        state.nEpoch = nEpoch;
        state.hashCurveRoot = 0;
        state.nFinalizedHeightAsOf = vFinalized[i];
        states[nEpoch] = state;
        trees[nEpoch] = CCurveTree();
    }
    BOOST_REQUIRE(dag.InstallEpochStateBatch(nFirstEpoch, states, trees));
}

ReorgFinalityVerdict Verdict(const CDAGManager& dag, int nBestHeight, int nForkHeight)
{
    int nCur = 0, nLatch = 0, nEpoch = 0;
    return CheckReorgAgainstFinality(dag, nBestHeight, nForkHeight, nCur, nLatch, nEpoch);
}

bool IsPermanent(ReorgFinalityVerdict v) { return v == REORG_FINALITY_REJECT_PERMANENT; }
bool IsAllow(ReorgFinalityVerdict v) { return v == REORG_FINALITY_ALLOW; }

// The one thing that must never happen between two honest nodes: one writes a
// permanent condemnation of a branch the other extends.
bool ForbiddenPair(ReorgFinalityVerdict a, ReorgFinalityVerdict b)
{
    return (IsPermanent(a) && IsAllow(b)) || (IsPermanent(b) && IsAllow(a));
}

// Regtest epoch layout, recomputed here rather than imported so a change to the
// epoch arithmetic shows up as a failure in this suite instead of silently
// re-pointing the fixtures.
const int EPOCH_A_BOUNDARY = 911;   // first block of epoch 4
const int TIP_LEADER       = EPOCH_A_BOUNDARY;       // node A: just crossed
const int TIP_LAGGARD      = EPOCH_A_BOUNDARY - 1;   // node B: one block behind

const int FINAL_E1 = 300;
const int FINAL_E2 = 600;
const int FINAL_E3 = 900;

// Installs epochs 1..3 so that:
//   node A (tip 911, epoch 4) -> cur = finalH(3) = 900, latch = finalH(2) = 600
//   node B (tip 910, epoch 3) -> cur = finalH(2) = 600, latch = finalH(1) = 300
void InstallStraddleFixture(CDAGManager& dag)
{
    std::vector<int> finalized;
    finalized.push_back(FINAL_E1);
    finalized.push_back(FINAL_E2);
    finalized.push_back(FINAL_E3);
    InstallFinalizedHeights(dag, 1, finalized);
}

} // namespace

// The fixture must actually straddle a boundary, or every assertion below is
// vacuous. Pin the epoch selection itself.
BOOST_AUTO_TEST_CASE(fixture_tips_straddle_an_epoch_boundary)
{
    RegTestNetwork net;
    BOOST_CHECK_EQUAL(FORK_HEIGHT_FINALITY, 10);
    BOOST_CHECK_EQUAL(FORK_HEIGHT_DAG, 11);
    BOOST_CHECK_EQUAL(FORK_HEIGHT_EPOCH_STATE_V3, 311);
    BOOST_REQUIRE_EQUAL(GetEpochForHeight(TIP_LEADER), 4);
    BOOST_REQUIRE_EQUAL(GetEpochForHeight(TIP_LAGGARD), 3);
    BOOST_REQUIRE(TIP_LEADER - TIP_LAGGARD == 1);
    BOOST_REQUIRE(TIP_LEADER >= FORK_HEIGHT_EPOCH_STATE_V3);
}

// The anchors the two nodes actually compute. This is the divergence itself,
// recorded so the following tests read against known numbers.
BOOST_AUTO_TEST_CASE(straddling_tips_select_different_anchors)
{
    RegTestNetwork net;
    CDAGManager dag;
    InstallStraddleFixture(dag);

    int nCurA = 0, nLatchA = 0, nEpochA = 0;
    CheckReorgAgainstFinality(dag, TIP_LEADER, 0, nCurA, nLatchA, nEpochA);
    int nCurB = 0, nLatchB = 0, nEpochB = 0;
    CheckReorgAgainstFinality(dag, TIP_LAGGARD, 0, nCurB, nLatchB, nEpochB);

    BOOST_CHECK_EQUAL(nEpochA, 3);
    BOOST_CHECK_EQUAL(nEpochB, 2);
    BOOST_CHECK_EQUAL(nCurA, FINAL_E3);
    BOOST_CHECK_EQUAL(nLatchA, FINAL_E2);
    BOOST_CHECK_EQUAL(nCurB, FINAL_E2);
    BOOST_CHECK_EQUAL(nLatchB, FINAL_E1);

    // The laggard's rejection anchor IS the leader's permanence anchor. That
    // identity is what makes the forbidden pair unreachable, so pin it.
    BOOST_CHECK_EQUAL(nLatchA, nCurB);
}

// R-FIN-001, the property under test. One block of honest tip skew across an
// epoch boundary must never produce a permanent condemnation on one node and an
// acceptance on the other.
BOOST_AUTO_TEST_CASE(no_permanent_condemnation_of_a_branch_the_peer_follows)
{
    RegTestNetwork net;
    CDAGManager dag;
    InstallStraddleFixture(dag);

    for (int nFork = 0; nFork <= 1000; nFork++)
    {
        const ReorgFinalityVerdict a = Verdict(dag, TIP_LEADER, nFork);
        const ReorgFinalityVerdict b = Verdict(dag, TIP_LAGGARD, nFork);
        BOOST_REQUIRE_MESSAGE(!ForbiddenPair(a, b),
                              "fork height " << nFork << ": leader verdict " << (int)a
                              << " vs laggard verdict " << (int)b);
    }
}

// The same property across every tip pair within one epoch of each other, not just
// the single-block straddle -- honest nodes skew by more than one block.
BOOST_AUTO_TEST_CASE(no_forbidden_pair_across_a_full_epoch_of_tip_skew)
{
    RegTestNetwork net;
    CDAGManager dag;
    InstallStraddleFixture(dag);

    // Tips spanning epochs 3 and 4, i.e. any two honest nodes within one epoch.
    for (int nTipA = 611; nTipA <= 1210; nTipA += 7)
        for (int nTipB = 611; nTipB <= 1210; nTipB += 7)
        {
            if (nTipA - nTipB > FINALITY_EPOCH_INTERVAL_POST_DAG ||
                nTipB - nTipA > FINALITY_EPOCH_INTERVAL_POST_DAG)
                continue;
            for (int nFork = 0; nFork <= 1000; nFork += 13)
            {
                const ReorgFinalityVerdict a = Verdict(dag, nTipA, nFork);
                const ReorgFinalityVerdict b = Verdict(dag, nTipB, nFork);
                BOOST_REQUIRE_MESSAGE(!ForbiddenPair(a, b),
                                      "tips " << nTipA << "/" << nTipB << " fork " << nFork);
            }
        }
}

// The band case, stated concretely: a fork between the two nodes' rejection
// anchors. The leader refuses it, the laggard follows it, and crucially NOTHING is
// written down, so the disagreement resolves as soon as the laggard crosses the
// boundary. This is the exact input that produced a persisted split before the fix.
BOOST_AUTO_TEST_CASE(fork_inside_the_hysteresis_band_is_refused_but_never_latched)
{
    RegTestNetwork net;
    CDAGManager dag;
    InstallStraddleFixture(dag);

    const int nFork = 700;   // FINAL_E2 (600) <= 700 < FINAL_E3 (900)
    const ReorgFinalityVerdict a = Verdict(dag, TIP_LEADER, nFork);
    const ReorgFinalityVerdict b = Verdict(dag, TIP_LAGGARD, nFork);

    BOOST_CHECK_EQUAL((int)a, (int)REORG_FINALITY_REJECT_TRANSIENT);
    BOOST_CHECK_EQUAL((int)b, (int)REORG_FINALITY_ALLOW);
    BOOST_CHECK(!IsPermanent(a));
    BOOST_CHECK(!IsPermanent(b));
    BOOST_CHECK(!ForbiddenPair(a, b));

    // Once the laggard crosses the boundary it holds the leader's anchors and the
    // two agree exactly; the verdict hardens on its own an epoch later.
    BOOST_CHECK_EQUAL((int)Verdict(dag, TIP_LEADER, nFork),
                      (int)Verdict(dag, EPOCH_A_BOUNDARY + 5, nFork));
}

// The guard must still bite. A fork below every node's lagged anchor is condemned
// permanently by both, which is the case the persisted flag exists for.
BOOST_AUTO_TEST_CASE(deep_fork_below_the_lagged_anchor_is_permanent_on_both_nodes)
{
    RegTestNetwork net;
    CDAGManager dag;
    InstallStraddleFixture(dag);

    const int nFork = 100;   // below FINAL_E1
    BOOST_CHECK_EQUAL((int)Verdict(dag, TIP_LEADER, nFork),
                      (int)REORG_FINALITY_REJECT_PERMANENT);
    BOOST_CHECK_EQUAL((int)Verdict(dag, TIP_LAGGARD, nFork),
                      (int)REORG_FINALITY_REJECT_PERMANENT);
}

// A fork at or above the rejection anchor is a normal reorg and must be allowed.
BOOST_AUTO_TEST_CASE(fork_at_or_above_the_rejection_anchor_is_allowed)
{
    RegTestNetwork net;
    CDAGManager dag;
    InstallStraddleFixture(dag);

    BOOST_CHECK_EQUAL((int)Verdict(dag, TIP_LEADER, FINAL_E3), (int)REORG_FINALITY_ALLOW);
    BOOST_CHECK_EQUAL((int)Verdict(dag, TIP_LEADER, FINAL_E3 + 1), (int)REORG_FINALITY_ALLOW);
    BOOST_CHECK_EQUAL((int)Verdict(dag, TIP_LEADER, FINAL_E3 - 1),
                      (int)REORG_FINALITY_REJECT_TRANSIENT);
    BOOST_CHECK_EQUAL((int)Verdict(dag, TIP_LAGGARD, FINAL_E2), (int)REORG_FINALITY_ALLOW);
}

// The permanence anchor may never exceed the rejection anchor: a branch can never
// be condemned permanently without also being rejected.
BOOST_AUTO_TEST_CASE(lagged_anchor_never_exceeds_the_rejection_anchor)
{
    RegTestNetwork net;
    CDAGManager dag;
    InstallStraddleFixture(dag);

    for (int nTip = 311; nTip <= 1500; nTip += 3)
    {
        int nCur = 0, nLatch = 0, nEpoch = 0;
        const ReorgFinalityVerdict v =
            CheckReorgAgainstFinality(dag, nTip, 0, nCur, nLatch, nEpoch);
        if (v == REORG_FINALITY_STATE_MISSING)
            continue;
        BOOST_REQUIRE_MESSAGE(nLatch <= nCur,
                              "tip " << nTip << " latch " << nLatch << " cur " << nCur);
    }
}

// Even with a non-monotone record on disk -- which LoadEpochStates rejects, but the
// clamp must not depend on that -- the latch cannot outrun the rejection anchor and
// produce a permanent verdict on a fork that is otherwise allowed.
BOOST_AUTO_TEST_CASE(non_monotone_records_cannot_invert_the_two_anchors)
{
    RegTestNetwork net;
    CDAGManager dag;
    std::vector<int> finalized;
    finalized.push_back(900);   // epoch 1: higher than its successor
    finalized.push_back(600);   // epoch 2
    finalized.push_back(300);   // epoch 3
    InstallFinalizedHeights(dag, 1, finalized);

    for (int nFork = 0; nFork <= 1000; nFork += 11)
    {
        int nCur = 0, nLatch = 0, nEpoch = 0;
        const ReorgFinalityVerdict v =
            CheckReorgAgainstFinality(dag, TIP_LEADER, nFork, nCur, nLatch, nEpoch);
        BOOST_REQUIRE(nLatch <= nCur);
        if (v == REORG_FINALITY_REJECT_PERMANENT)
            BOOST_REQUIRE_MESSAGE(nFork < nCur,
                                  "permanent verdict on an allowed fork " << nFork);
    }
}

// Bottom edge of epoch-state history. LoadEpochStates permits a non-zero lowest
// epoch (pre-fork epochs never had records) while rejecting interior holes, so an
// absent lagged record means "nothing latchable yet", not corruption. Failing
// closed here would brick every node for one epoch after the V3 gate.
BOOST_AUTO_TEST_CASE(missing_lagged_record_degrades_instead_of_failing_closed)
{
    RegTestNetwork net;
    CDAGManager dag;
    // Only epoch 3 exists; epoch 2 (the lagged anchor for tip 911) is absent.
    std::vector<int> finalized;
    finalized.push_back(FINAL_E3);
    InstallFinalizedHeights(dag, 3, finalized);

    int nCur = 0, nLatch = 0, nEpoch = 0;
    const ReorgFinalityVerdict v =
        CheckReorgAgainstFinality(dag, TIP_LEADER, 100, nCur, nLatch, nEpoch);

    BOOST_CHECK(v != REORG_FINALITY_STATE_MISSING);
    BOOST_CHECK_EQUAL(nCur, FINAL_E3);
    BOOST_CHECK_EQUAL(nLatch, 0);
    // Rejected, but with no lagged anchor nothing may be persisted.
    BOOST_CHECK_EQUAL((int)v, (int)REORG_FINALITY_REJECT_TRANSIENT);
}

// The pre-existing fail-closed on a missing CURRENT record is unchanged: that one
// is a real hole and the caller must refuse to run.
BOOST_AUTO_TEST_CASE(missing_current_record_still_fails_closed)
{
    RegTestNetwork net;
    CDAGManager dag;   // no epoch states at all
    int nCur = 0, nLatch = 0, nEpoch = 0;
    BOOST_CHECK_EQUAL(
        (int)CheckReorgAgainstFinality(dag, TIP_LEADER, 100, nCur, nLatch, nEpoch),
        (int)REORG_FINALITY_STATE_MISSING);
    BOOST_CHECK_EQUAL(nEpoch, 3);
}

// Below the finality gate the guard is inert on every network, and it must stay
// inert between the finality gate and the first epoch-state record rather than
// failing closed on the states that do not exist yet.
BOOST_AUTO_TEST_CASE(guard_is_inert_below_the_finality_gate)
{
    RegTestNetwork net;
    CDAGManager dag;   // deliberately empty

    BOOST_CHECK_EQUAL((int)Verdict(dag, FORK_HEIGHT_FINALITY - 1, 0),
                      (int)REORG_FINALITY_ALLOW);
    BOOST_CHECK_EQUAL((int)Verdict(dag, 0, 0), (int)REORG_FINALITY_ALLOW);

    // Finality gate reached, epoch-state V3 not yet: the pre-V3 lookup scans down
    // and returns 0, which must read as "nothing finalized", not as an error.
    for (int nTip = FORK_HEIGHT_FINALITY; nTip < FORK_HEIGHT_EPOCH_STATE_V3; nTip += 17)
        BOOST_REQUIRE_EQUAL((int)Verdict(dag, nTip, 0), (int)REORG_FINALITY_ALLOW);
}

// The persistence rule itself. Both reorg sites delegate to ApplyReorgFinalityGuard
// rather than deciding for themselves, because a site that persisted the transient
// verdict would rebuild R-FIN-001 on its own: a fork inside the band would be written
// down as BLOCK_FAILED_VALID on the leader while the laggard extends it.
BOOST_AUTO_TEST_CASE(only_the_permanent_verdict_is_persisted)
{
    RegTestNetwork net;
    CDAGManager dag;
    InstallStraddleFixture(dag);

    int nCur = 0, nLatch = 0, nEpoch = 0;

    // Deep fork: condemned, and written down.
    bool fPermanent = false;
    BOOST_CHECK_EQUAL((int)ApplyReorgFinalityGuard(dag, TIP_LEADER, 100, &fPermanent,
                                                   nCur, nLatch, nEpoch),
                      (int)REORG_FINALITY_REJECT_PERMANENT);
    BOOST_CHECK(fPermanent);

    // Inside the band: refused, but nothing may be written down.
    fPermanent = false;
    BOOST_CHECK_EQUAL((int)ApplyReorgFinalityGuard(dag, TIP_LEADER, 700, &fPermanent,
                                                   nCur, nLatch, nEpoch),
                      (int)REORG_FINALITY_REJECT_TRANSIENT);
    BOOST_CHECK(!fPermanent);

    // Allowed, and a missing current record: neither may latch.
    fPermanent = false;
    BOOST_CHECK_EQUAL((int)ApplyReorgFinalityGuard(dag, TIP_LEADER, FINAL_E3, &fPermanent,
                                                   nCur, nLatch, nEpoch),
                      (int)REORG_FINALITY_ALLOW);
    BOOST_CHECK(!fPermanent);

    CDAGManager empty;
    fPermanent = false;
    BOOST_CHECK_EQUAL((int)ApplyReorgFinalityGuard(empty, TIP_LEADER, 100, &fPermanent,
                                                   nCur, nLatch, nEpoch),
                      (int)REORG_FINALITY_STATE_MISSING);
    BOOST_CHECK(!fPermanent);

    // A null flag pointer is the Reorganize-without-a-caller case; it must not crash.
    BOOST_CHECK_EQUAL((int)ApplyReorgFinalityGuard(dag, TIP_LEADER, 100, NULL,
                                                   nCur, nLatch, nEpoch),
                      (int)REORG_FINALITY_REJECT_PERMANENT);
}

// Every verdict the guard rejects on must also be a verdict the laggard does not
// accept -- restated over the persist flag rather than the enum, since the flag is the
// half that survives a restart.
BOOST_AUTO_TEST_CASE(nothing_is_persisted_that_a_straddling_peer_would_accept)
{
    RegTestNetwork net;
    CDAGManager dag;
    InstallStraddleFixture(dag);

    for (int nFork = 0; nFork <= 1000; nFork++)
    {
        int nCur = 0, nLatch = 0, nEpoch = 0;
        bool fPermanentLeader = false;
        ApplyReorgFinalityGuard(dag, TIP_LEADER, nFork, &fPermanentLeader,
                                nCur, nLatch, nEpoch);
        bool fPermanentLaggard = false;
        const ReorgFinalityVerdict laggard = ApplyReorgFinalityGuard(
            dag, TIP_LAGGARD, nFork, &fPermanentLaggard, nCur, nLatch, nEpoch);

        if (fPermanentLeader)
            BOOST_REQUIRE_MESSAGE(laggard != REORG_FINALITY_ALLOW,
                                  "fork " << nFork << " persisted on the leader but "
                                  "accepted by the laggard");
        if (fPermanentLaggard)
        {
            bool fUnused = false;
            int a = 0, b = 0, c = 0;
            BOOST_REQUIRE_MESSAGE(
                ApplyReorgFinalityGuard(dag, TIP_LEADER, nFork, &fUnused, a, b, c)
                    != REORG_FINALITY_ALLOW,
                "fork " << nFork << " persisted on the laggard but accepted by the leader");
        }
    }
}

// Mainnet parameters: the finality gate sits far from epoch 0, so this is the only place
// the guard's inertness below the gate is observable.
BOOST_AUTO_TEST_CASE(guard_is_inert_below_the_mainnet_finality_gate)
{
    MainNetNetwork net;

    const int nGate = FORK_HEIGHT_FINALITY;
    const int nTip = nGate - 1;
    const int nAsOf = GetEpochForHeight(nTip) - 1;

    // The fixture must be non-trivial, or the assertion below proves nothing: on
    // regtest this same tip sits in epoch 0 and the lookup returns 0 regardless.
    BOOST_REQUIRE_EQUAL(nGate, 8215000);
    BOOST_REQUIRE_GT(nAsOf, 0);

    CDAGManager dag;
    std::vector<int> finalized;
    finalized.push_back(nGate - 200000);
    finalized.push_back(nGate - 100000);
    InstallFinalizedHeights(dag, nAsOf - 1, finalized);

    int nCur = 0, nLatch = 0, nEpoch = 0;
    const ReorgFinalityVerdict v =
        CheckReorgAgainstFinality(dag, nTip, 0, nCur, nLatch, nEpoch);

    BOOST_CHECK_EQUAL((int)v, (int)REORG_FINALITY_ALLOW);
    BOOST_CHECK_EQUAL(nCur, 0);
}

BOOST_AUTO_TEST_SUITE_END()
