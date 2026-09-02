// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Coverage for R-FIN-001: the reorg finality guard in Reorganize and
// CBlock::SetBestChain.
//
// The guard's anchor is the deterministic finalized height as of epoch(tip)-1, and
// the epoch selector reads the evaluating node's own tip. Two honest nodes whose
// tips sit apart across an epoch boundary therefore select different epochs and
// evaluate the same candidate branch against different finalized heights. Because a
// rejection sets pfPermanentInvalid, which AddToBlockIndex turns into
// BLOCK_FAILED_VALID, and that flag is serialized and cleared only by
// reconsiderblock, a disagreement here is permanent and persisted.
//
// The anchor cannot be moved onto the candidate or the fork point: finalization
// evidence lives on the chain being abandoned, so an anchor taken from at or below
// the fork point cannot condemn anything, and a candidate-derived anchor is both
// attacker-selectable and unavailable when the candidate has crossed a boundary the
// node has not completed. What is corrected instead is verdict severity, via a
// second anchor REORG_LATCH_ANCHOR_LAG_EPOCHS-1 epochs older that gates persistence.
//
// The invariant these tests pin is NOT that two skewed nodes return the same
// verdict -- inside the band a laggard may still follow a branch its neighbour
// transiently refuses, which self-heals because nothing is written down. It is the
// strictly stronger-where-it-matters property:
//
//   no honest node PERMANENTLY condemns a branch that another honest node FOLLOWS.
//
// ForbiddenPair below is that property stated directly.
//
// The property is quantitative, and the suite states its exact limit rather than
// filtering around it. With F(k) the finalized height as of epoch k and L the latch
// lag, node A latches only when fork < F(e(A)-L) and node B allows only when
// fork >= F(e(B)-1); F is non-decreasing in epoch, so a forbidden pair needs
// e(A)-e(B) > L-1. Tolerated skew is therefore exactly L-1 epochs, and
// tolerance_is_exactly_the_latch_lag pins both halves of "exactly".

#include <boost/test/unit_test.hpp>

#include <boost/preprocessor/stringize.hpp>

#include "../dag.h"
#include "../finality.h"
#include "../main.h"

#include <fstream>
#include <map>
#include <sstream>
#include <string>
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

// Is there ANY fork height on which the two tips form a forbidden pair? Sweeping the
// fork axis turns "these two verdicts agree" into "no input separates them".
bool ForbiddenPairExists(const CDAGManager& dag, int nTipA, int nTipB, int nForkMax)
{
    for (int nFork = 0; nFork <= nForkMax; nFork++)
        if (ForbiddenPair(Verdict(dag, nTipA, nFork), Verdict(dag, nTipB, nFork)))
            return true;
    return false;
}

// Epoch boundaries read the network flags, so this may only be called from inside a
// test that has installed one -- not at namespace scope, where fRegTest is still
// whatever the process started with.
int FirstHeightOfEpoch(int nEpoch) { return (int)GetEpochBoundaryHeight64(nEpoch); }

// Regtest epoch k >= 1 starts at FORK_HEIGHT_DAG + (k-1)*300. The tips are literals
// (needed at namespace scope); fixture_tips_sit_where_the_layout_says re-derives them
// from the production boundary helper.
const int LEADER_EPOCH = 5;

const int TIP_LEADER    = 1211;   // first block of epoch 5: just crossed
const int TIP_LAGGARD   = 1210;   // last block of epoch 4: one block behind
// Two epochs behind: the far edge of the tolerated band at L = 3.
const int TIP_LAGGARD_2 = 910;    // last block of epoch 3
// Three epochs behind: one past the band, where the pair returns.
const int TIP_LAGGARD_3 = 610;    // last block of epoch 2

const int FINAL_E1 = 300;
const int FINAL_E2 = 600;
const int FINAL_E3 = 900;
const int FINAL_E4 = 1200;

// Every fork height any test sweeps, comfortably above FINAL_E4.
const int FORK_SWEEP_MAX = 1300;

// Installs epochs 1..4 so that, at L = 3:
//   leader (tip 1211) cur 1200 latch 600; laggard (1210) 900/300;
//   laggard_2 (910) 600/0; laggard_3 (610) 300/0
void InstallStraddleFixture(CDAGManager& dag)
{
    std::vector<int> finalized;
    finalized.push_back(FINAL_E1);
    finalized.push_back(FINAL_E2);
    finalized.push_back(FINAL_E3);
    finalized.push_back(FINAL_E4);
    InstallFinalizedHeights(dag, 1, finalized);
}

// Tips for which the fixture holds the epoch record the rejection anchor needs.
// Outside this range the guard returns STATE_MISSING, which is neither a latch nor an
// acceptance and would make a sweep vacuous rather than wrong.
const int SWEEP_TIP_MIN = 311;    // first block of epoch 2
const int SWEEP_TIP_MAX = 1510;   // last block of epoch 5

// Reads a file under src/ by the path compiled in for the test data directory,
// so the resolution does not depend on the caller's working directory.
std::string ReadMainSource()
{
    const std::string strPath =
        std::string(BOOST_PP_STRINGIZE(TEST_DATA_DIR)) + "/../../main.cpp";
    std::ifstream in(strPath.c_str());
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

size_t CountOccurrences(const std::string& strHaystack, const std::string& strNeedle)
{
    size_t nCount = 0;
    for (size_t nPos = strHaystack.find(strNeedle); nPos != std::string::npos;
         nPos = strHaystack.find(strNeedle, nPos + strNeedle.size()))
        nCount++;
    return nCount;
}

} // namespace

// The fixture must actually straddle boundaries, or every assertion below is
// vacuous. Pin the epoch selection itself.
BOOST_AUTO_TEST_CASE(fixture_tips_sit_where_the_layout_says)
{
    RegTestNetwork net;
    BOOST_CHECK_EQUAL(FORK_HEIGHT_FINALITY, 10);
    BOOST_CHECK_EQUAL(FORK_HEIGHT_DAG, 11);
    BOOST_CHECK_EQUAL(FORK_HEIGHT_EPOCH_STATE_V3, 311);

    // Every fixture height re-derived from the production boundary helper.
    BOOST_REQUIRE_EQUAL(TIP_LEADER, FirstHeightOfEpoch(LEADER_EPOCH));
    BOOST_REQUIRE_EQUAL(TIP_LAGGARD, FirstHeightOfEpoch(LEADER_EPOCH) - 1);
    BOOST_REQUIRE_EQUAL(TIP_LAGGARD_2, FirstHeightOfEpoch(LEADER_EPOCH - 1) - 1);
    BOOST_REQUIRE_EQUAL(TIP_LAGGARD_3, FirstHeightOfEpoch(LEADER_EPOCH - 2) - 1);
    BOOST_REQUIRE_EQUAL(SWEEP_TIP_MIN, FirstHeightOfEpoch(2));
    BOOST_REQUIRE_EQUAL(SWEEP_TIP_MAX, FirstHeightOfEpoch(LEADER_EPOCH + 1) - 1);

    BOOST_REQUIRE_EQUAL(GetEpochForHeight(TIP_LEADER), 5);
    BOOST_REQUIRE_EQUAL(GetEpochForHeight(TIP_LAGGARD), 4);
    BOOST_REQUIRE_EQUAL(GetEpochForHeight(TIP_LAGGARD_2), 3);
    BOOST_REQUIRE_EQUAL(GetEpochForHeight(TIP_LAGGARD_3), 2);
    BOOST_REQUIRE(TIP_LEADER - TIP_LAGGARD == 1);
    BOOST_REQUIRE(TIP_LEADER >= FORK_HEIGHT_EPOCH_STATE_V3);
    BOOST_REQUIRE(SWEEP_TIP_MIN >= FORK_HEIGHT_EPOCH_STATE_V3);
}

// The lag is the guard's only tuning knob; check the arithmetic behind its stated
// wall-clock tolerance.
BOOST_AUTO_TEST_CASE(latch_lag_constant_matches_the_documented_tolerance)
{
    BOOST_CHECK_EQUAL(REORG_LATCH_ANCHOR_LAG_EPOCHS, 3);
    BOOST_REQUIRE_GE(REORG_LATCH_ANCHOR_LAG_EPOCHS, 2);   // L = 1 latches its own anchor

    const int nToleratedEpochs = REORG_LATCH_ANCHOR_LAG_EPOCHS - 1;
    BOOST_CHECK_EQUAL(nToleratedEpochs * FINALITY_EPOCH_INTERVAL_POST_DAG, 600);
    BOOST_CHECK_EQUAL(nToleratedEpochs * FINALITY_EPOCH_INTERVAL_POST_DAG *
                          (int)POST_DAG_TARGET_SPACING, 600);   // seconds: 10 minutes
    BOOST_CHECK_EQUAL(nToleratedEpochs * FINALITY_EPOCH_INTERVAL_PRE_DAG *
                          (int)PRE_DAG_TARGET_SPACING, 1800);   // seconds: 30 minutes
}

// The anchors the tips actually compute. This is the divergence itself, recorded so
// the following tests read against known numbers.
BOOST_AUTO_TEST_CASE(skewed_tips_select_different_anchors)
{
    RegTestNetwork net;
    CDAGManager dag;
    InstallStraddleFixture(dag);

    int nCurA = 0, nLatchA = 0, nEpochA = 0;
    CheckReorgAgainstFinality(dag, TIP_LEADER, 0, nCurA, nLatchA, nEpochA);
    int nCurB = 0, nLatchB = 0, nEpochB = 0;
    CheckReorgAgainstFinality(dag, TIP_LAGGARD, 0, nCurB, nLatchB, nEpochB);
    int nCurC = 0, nLatchC = 0, nEpochC = 0;
    CheckReorgAgainstFinality(dag, TIP_LAGGARD_2, 0, nCurC, nLatchC, nEpochC);

    BOOST_CHECK_EQUAL(nEpochA, 4);
    BOOST_CHECK_EQUAL(nEpochB, 3);
    BOOST_CHECK_EQUAL(nEpochC, 2);

    // The latch trails the rejection anchor by REORG_LATCH_ANCHOR_LAG_EPOCHS-1 epochs.
    BOOST_CHECK_EQUAL(nCurA, FINAL_E4);
    BOOST_CHECK_EQUAL(nLatchA, FINAL_E2);
    BOOST_CHECK_EQUAL(nCurB, FINAL_E3);
    BOOST_CHECK_EQUAL(nLatchB, FINAL_E1);
    BOOST_CHECK_EQUAL(nCurC, FINAL_E2);
    BOOST_CHECK_EQUAL(nLatchC, 0);
}

// Why L-1 epochs of skew are safe and L are not, in one identity: the leader's
// permanence anchor is the rejection anchor of a node exactly L-1 epochs behind. At
// that skew the thresholds touch -- everything the leader latches is strictly below
// everything that laggard would accept -- and one epoch further back the laggard's
// rejection anchor drops below the leader's latch, opening the gap.
BOOST_AUTO_TEST_CASE(max_skew_pair_anchors_touch_exactly)
{
    RegTestNetwork net;
    CDAGManager dag;
    InstallStraddleFixture(dag);

    int nCurLead = 0, nLatchLead = 0, nEpochLead = 0;
    CheckReorgAgainstFinality(dag, TIP_LEADER, 0, nCurLead, nLatchLead, nEpochLead);

    int nCurEdge = 0, nLatchEdge = 0, nEpochEdge = 0;
    CheckReorgAgainstFinality(dag, TIP_LAGGARD_2, 0, nCurEdge, nLatchEdge, nEpochEdge);
    BOOST_REQUIRE_EQUAL(GetEpochForHeight(TIP_LEADER) - GetEpochForHeight(TIP_LAGGARD_2),
                        REORG_LATCH_ANCHOR_LAG_EPOCHS - 1);
    BOOST_CHECK_EQUAL(nLatchLead, nCurEdge);

    int nCurPast = 0, nLatchPast = 0, nEpochPast = 0;
    CheckReorgAgainstFinality(dag, TIP_LAGGARD_3, 0, nCurPast, nLatchPast, nEpochPast);
    BOOST_REQUIRE_EQUAL(GetEpochForHeight(TIP_LEADER) - GetEpochForHeight(TIP_LAGGARD_3),
                        REORG_LATCH_ANCHOR_LAG_EPOCHS);
    BOOST_CHECK_LT(nCurPast, nLatchLead);
}

// R-FIN-001, the property under test. One block of honest tip skew across an epoch
// boundary must never produce a permanent condemnation on one node and an acceptance
// on the other.
BOOST_AUTO_TEST_CASE(no_permanent_condemnation_of_a_branch_the_peer_follows)
{
    RegTestNetwork net;
    CDAGManager dag;
    InstallStraddleFixture(dag);

    for (int nFork = 0; nFork <= FORK_SWEEP_MAX; nFork++)
    {
        const ReorgFinalityVerdict a = Verdict(dag, TIP_LEADER, nFork);
        const ReorgFinalityVerdict b = Verdict(dag, TIP_LAGGARD, nFork);
        BOOST_REQUIRE_MESSAGE(!ForbiddenPair(a, b),
                              "fork height " << nFork << ": leader verdict " << (int)a
                              << " vs laggard verdict " << (int)b);
    }
}

// The same property across every tip pair inside the tolerated band
// (REORG_LATCH_ANCHOR_LAG_EPOCHS-1 epochs). The filter is the invariant's own
// condition, so raising the lag widens the sweep.
BOOST_AUTO_TEST_CASE(no_forbidden_pair_across_the_tolerated_epoch_skew)
{
    RegTestNetwork net;
    CDAGManager dag;
    InstallStraddleFixture(dag);

    int nPairsChecked = 0;
    int nMaxSkewChecked = 0;
    for (int nTipA = SWEEP_TIP_MIN; nTipA <= SWEEP_TIP_MAX; nTipA += 7)
        for (int nTipB = SWEEP_TIP_MIN; nTipB <= SWEEP_TIP_MAX; nTipB += 7)
        {
            const int nSkew = GetEpochForHeight(nTipA) - GetEpochForHeight(nTipB);
            const int nAbsSkew = nSkew < 0 ? -nSkew : nSkew;
            if (nAbsSkew > REORG_LATCH_ANCHOR_LAG_EPOCHS - 1)
                continue;
            if (nAbsSkew > nMaxSkewChecked)
                nMaxSkewChecked = nAbsSkew;
            nPairsChecked++;
            for (int nFork = 0; nFork <= FORK_SWEEP_MAX; nFork += 13)
            {
                const ReorgFinalityVerdict a = Verdict(dag, nTipA, nFork);
                const ReorgFinalityVerdict b = Verdict(dag, nTipB, nFork);
                BOOST_REQUIRE_MESSAGE(!ForbiddenPair(a, b),
                                      "tips " << nTipA << "/" << nTipB << " (epoch skew "
                                      << nAbsSkew << ") fork " << nFork);
            }
        }

    // The sweep must reach the far edge of the band.
    BOOST_CHECK_GT(nPairsChecked, 0);
    BOOST_CHECK_EQUAL(nMaxSkewChecked, REORG_LATCH_ANCHOR_LAG_EPOCHS - 1);
}

// The band in height terms: a tip difference of at most (L-1) full epochs spans at most
// L-1 boundaries. Post-DAG that is 600 blocks, ten minutes at one-second spacing.
BOOST_AUTO_TEST_CASE(no_forbidden_pair_across_the_tolerated_height_skew)
{
    RegTestNetwork net;
    CDAGManager dag;
    InstallStraddleFixture(dag);

    const int nMaxHeightSkew =
        (REORG_LATCH_ANCHOR_LAG_EPOCHS - 1) * FINALITY_EPOCH_INTERVAL_POST_DAG;
    BOOST_REQUIRE_EQUAL(nMaxHeightSkew, 600);

    for (int nTipA = SWEEP_TIP_MIN; nTipA <= SWEEP_TIP_MAX; nTipA += 7)
        for (int nTipB = nTipA; nTipB <= SWEEP_TIP_MAX && nTipB - nTipA <= nMaxHeightSkew;
             nTipB += 7)
        {
            // The height bound must imply the epoch bound, or the sweep is testing a
            // different band than the invariant names.
            const int nSkew = GetEpochForHeight(nTipB) - GetEpochForHeight(nTipA);
            BOOST_REQUIRE_LE(nSkew, REORG_LATCH_ANCHOR_LAG_EPOCHS - 1);

            for (int nFork = 0; nFork <= FORK_SWEEP_MAX; nFork += 13)
                BOOST_REQUIRE_MESSAGE(
                    !ForbiddenPair(Verdict(dag, nTipA, nFork), Verdict(dag, nTipB, nFork)),
                    "tips " << nTipA << "/" << nTipB << " fork " << nFork);
        }

    // The far edge of the band at the smallest height skew: one block past a full epoch
    // already puts two tips L-1 epochs apart, since the pair straddles two boundaries.
    // Hence the band is stated in epochs, not blocks.
    BOOST_CHECK_EQUAL(TIP_LEADER - TIP_LAGGARD_2, FINALITY_EPOCH_INTERVAL_POST_DAG + 1);
    BOOST_CHECK_EQUAL(GetEpochForHeight(TIP_LEADER) - GetEpochForHeight(TIP_LAGGARD_2),
                      REORG_LATCH_ANCHOR_LAG_EPOCHS - 1);
    BOOST_CHECK(!ForbiddenPairExists(dag, TIP_LEADER, TIP_LAGGARD_2, FORK_SWEEP_MAX));
}

// Tightness: at L-1 epochs no fork height separates the two nodes, at L one does. The
// second half is a known residual, pinned so a lag change must update this test.
BOOST_AUTO_TEST_CASE(tolerance_is_exactly_the_latch_lag)
{
    RegTestNetwork net;
    CDAGManager dag;
    InstallStraddleFixture(dag);

    BOOST_REQUIRE_EQUAL(GetEpochForHeight(TIP_LEADER) - GetEpochForHeight(TIP_LAGGARD_2),
                        REORG_LATCH_ANCHOR_LAG_EPOCHS - 1);
    BOOST_CHECK(!ForbiddenPairExists(dag, TIP_LEADER, TIP_LAGGARD_2, FORK_SWEEP_MAX));

    BOOST_REQUIRE_EQUAL(GetEpochForHeight(TIP_LEADER) - GetEpochForHeight(TIP_LAGGARD_3),
                        REORG_LATCH_ANCHOR_LAG_EPOCHS);
    BOOST_CHECK(ForbiddenPairExists(dag, TIP_LEADER, TIP_LAGGARD_3, FORK_SWEEP_MAX));

    // Where it reopens: the leader latches below its own latch anchor, the node L
    // epochs back accepts from its own rejection anchor up, and between the two the
    // verdicts are condemn-versus-follow.
    BOOST_CHECK_EQUAL((int)Verdict(dag, TIP_LEADER, FINAL_E1),
                      (int)REORG_FINALITY_REJECT_PERMANENT);
    BOOST_CHECK_EQUAL((int)Verdict(dag, TIP_LAGGARD_3, FINAL_E1),
                      (int)REORG_FINALITY_ALLOW);
}

// The band case, stated concretely: a fork between the two nodes' rejection anchors.
// The leader refuses it, the laggard follows it, and crucially NOTHING is written
// down, so the disagreement resolves as soon as the laggard crosses the boundary.
// This is the exact input that produced a persisted split before the fix.
BOOST_AUTO_TEST_CASE(fork_inside_the_hysteresis_band_is_refused_but_never_latched)
{
    RegTestNetwork net;
    CDAGManager dag;
    InstallStraddleFixture(dag);

    const int nFork = 1000;   // FINAL_E3 (900) <= 1000 < FINAL_E4 (1200)
    const ReorgFinalityVerdict a = Verdict(dag, TIP_LEADER, nFork);
    const ReorgFinalityVerdict b = Verdict(dag, TIP_LAGGARD, nFork);

    BOOST_CHECK_EQUAL((int)a, (int)REORG_FINALITY_REJECT_TRANSIENT);
    BOOST_CHECK_EQUAL((int)b, (int)REORG_FINALITY_ALLOW);
    BOOST_CHECK(!IsPermanent(a));
    BOOST_CHECK(!IsPermanent(b));
    BOOST_CHECK(!ForbiddenPair(a, b));

    // Once the laggard crosses the boundary it holds the leader's anchors and the two
    // agree exactly; the verdict hardens on its own once the latch advances.
    BOOST_CHECK_EQUAL((int)Verdict(dag, TIP_LEADER, nFork),
                      (int)Verdict(dag, TIP_LEADER + 5, nFork));
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

    BOOST_CHECK_EQUAL((int)Verdict(dag, TIP_LEADER, FINAL_E4), (int)REORG_FINALITY_ALLOW);
    BOOST_CHECK_EQUAL((int)Verdict(dag, TIP_LEADER, FINAL_E4 + 1), (int)REORG_FINALITY_ALLOW);
    BOOST_CHECK_EQUAL((int)Verdict(dag, TIP_LEADER, FINAL_E4 - 1),
                      (int)REORG_FINALITY_REJECT_TRANSIENT);
    BOOST_CHECK_EQUAL((int)Verdict(dag, TIP_LAGGARD, FINAL_E3), (int)REORG_FINALITY_ALLOW);
}

// The permanence anchor may never exceed the rejection anchor: a branch can never be
// condemned permanently without also being rejected.
BOOST_AUTO_TEST_CASE(lagged_anchor_never_exceeds_the_rejection_anchor)
{
    RegTestNetwork net;
    CDAGManager dag;
    InstallStraddleFixture(dag);

    for (int nTip = FORK_HEIGHT_EPOCH_STATE_V3; nTip <= 1800; nTip += 3)
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
    finalized.push_back(1200);   // epoch 1: higher than its successors
    finalized.push_back(900);    // epoch 2
    finalized.push_back(600);    // epoch 3
    finalized.push_back(300);    // epoch 4
    InstallFinalizedHeights(dag, 1, finalized);

    for (int nFork = 0; nFork <= FORK_SWEEP_MAX; nFork += 11)
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

// Bottom edge of epoch-state history. LoadEpochStates permits a non-zero lowest epoch
// (pre-fork epochs never had records) while rejecting interior holes, so an absent
// lagged record means "nothing latchable yet", not corruption. Failing closed here
// would brick every node for the first epochs after the V3 gate.
BOOST_AUTO_TEST_CASE(missing_lagged_record_degrades_instead_of_failing_closed)
{
    RegTestNetwork net;
    CDAGManager dag;
    // Only epoch 4 exists; epoch 2, the lagged anchor for tip 1211, is absent.
    std::vector<int> finalized;
    finalized.push_back(FINAL_E4);
    InstallFinalizedHeights(dag, 4, finalized);

    int nCur = 0, nLatch = 0, nEpoch = 0;
    const ReorgFinalityVerdict v =
        CheckReorgAgainstFinality(dag, TIP_LEADER, 100, nCur, nLatch, nEpoch);

    BOOST_CHECK(v != REORG_FINALITY_STATE_MISSING);
    BOOST_CHECK_EQUAL(nCur, FINAL_E4);
    BOOST_CHECK_EQUAL(nLatch, 0);
    // Rejected, but with no lagged anchor nothing may be persisted.
    BOOST_CHECK_EQUAL((int)v, (int)REORG_FINALITY_REJECT_TRANSIENT);

    // The widened lag reaches one epoch further back, so a run of records that would
    // have satisfied the pre-widening anchor must still degrade rather than latch.
    CDAGManager dagNearEdge;
    std::vector<int> nearEdge;
    nearEdge.push_back(FINAL_E3);
    nearEdge.push_back(FINAL_E4);
    InstallFinalizedHeights(dagNearEdge, 3, nearEdge);   // epochs 3 and 4 only

    int nCur2 = 0, nLatch2 = 0, nEpoch2 = 0;
    const ReorgFinalityVerdict v2 =
        CheckReorgAgainstFinality(dagNearEdge, TIP_LEADER, 100, nCur2, nLatch2, nEpoch2);
    BOOST_CHECK_EQUAL(nCur2, FINAL_E4);
    BOOST_CHECK_EQUAL(nLatch2, 0);
    BOOST_CHECK_EQUAL((int)v2, (int)REORG_FINALITY_REJECT_TRANSIENT);
}

// A missing CURRENT record is a real hole: fail closed and the caller must refuse to run.
BOOST_AUTO_TEST_CASE(missing_current_record_still_fails_closed)
{
    RegTestNetwork net;
    CDAGManager dag;   // no epoch states at all
    int nCur = 0, nLatch = 0, nEpoch = 0;
    BOOST_CHECK_EQUAL(
        (int)CheckReorgAgainstFinality(dag, TIP_LEADER, 100, nCur, nLatch, nEpoch),
        (int)REORG_FINALITY_STATE_MISSING);
    BOOST_CHECK_EQUAL(nEpoch, 4);
}

// Below the finality gate the guard is inert on every network, and it must stay inert
// between the finality gate and the first epoch-state record rather than failing
// closed on the states that do not exist yet.
BOOST_AUTO_TEST_CASE(guard_is_inert_below_the_finality_gate)
{
    RegTestNetwork net;
    CDAGManager dag;   // deliberately empty

    BOOST_CHECK_EQUAL((int)Verdict(dag, FORK_HEIGHT_FINALITY - 1, 0),
                      (int)REORG_FINALITY_ALLOW);
    BOOST_CHECK_EQUAL((int)Verdict(dag, 0, 0), (int)REORG_FINALITY_ALLOW);

    // Finality gate reached, epoch-state V3 not yet: the pre-V3 lookup scans down and
    // returns 0, which must read as "nothing finalized", not as an error.
    for (int nTip = FORK_HEIGHT_FINALITY; nTip < FORK_HEIGHT_EPOCH_STATE_V3; nTip += 17)
        BOOST_REQUIRE_EQUAL((int)Verdict(dag, nTip, 0), (int)REORG_FINALITY_ALLOW);
}

// The pre-V3 lookup scans down from the requested epoch and must apply the same lag.
// Only observable on mainnet, where the finality gate is 5,300 blocks below the
// epoch-state V3 gate; on regtest the pre-V3 window is epoch 0 or 1.
BOOST_AUTO_TEST_CASE(pre_v3_scanning_path_uses_the_same_lag)
{
    MainNetNetwork net;

    const int nTip = FORK_HEIGHT_EPOCH_STATE_V3 - 1;
    BOOST_REQUIRE_GE(nTip, FORK_HEIGHT_FINALITY);
    BOOST_REQUIRE_LT(nTip, FORK_HEIGHT_EPOCH_STATE_V3);
    const int nAsOf = GetEpochForHeight(nTip) - 1;
    BOOST_REQUIRE_GT(nAsOf, 2);

    CDAGManager dag;
    std::vector<int> finalized;
    finalized.push_back(1000);   // epoch nAsOf-2, the lagged anchor
    finalized.push_back(2000);   // epoch nAsOf-1, the pre-widening anchor
    finalized.push_back(3000);   // epoch nAsOf, the rejection anchor
    InstallFinalizedHeights(dag, nAsOf - 2, finalized);

    int nCur = 0, nLatch = 0, nEpoch = 0;
    CheckReorgAgainstFinality(dag, nTip, 0, nCur, nLatch, nEpoch);
    BOOST_CHECK_EQUAL(nEpoch, nAsOf);
    BOOST_CHECK_EQUAL(nCur, 3000);
    BOOST_CHECK_EQUAL(nLatch, 1000);   // not 2000, which is F(nAsOf-1)

    // The scan itself, with the lagged epoch below the lowest record: it walks down,
    // finds nothing, and reports nothing latchable. The pre-widening lag would have
    // stopped on epoch nAsOf-1 and latched 2000 here, so this pins the reach.
    CDAGManager dagEdge;
    std::vector<int> edge;
    edge.push_back(2000);   // epoch nAsOf-1
    edge.push_back(3000);   // epoch nAsOf
    InstallFinalizedHeights(dagEdge, nAsOf - 1, edge);

    int nCurE = 0, nLatchE = 0, nEpochE = 0;
    CheckReorgAgainstFinality(dagEdge, nTip, 0, nCurE, nLatchE, nEpochE);
    BOOST_CHECK_EQUAL(nCurE, 3000);
    BOOST_CHECK_EQUAL(nLatchE, 0);
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
    BOOST_CHECK_EQUAL((int)ApplyReorgFinalityGuard(dag, TIP_LEADER, 1000, &fPermanent,
                                                   nCur, nLatch, nEpoch),
                      (int)REORG_FINALITY_REJECT_TRANSIENT);
    BOOST_CHECK(!fPermanent);

    // The widened part of the band: a fork the pre-widening latch (F(nAsOf-1) =
    // FINAL_E3) would have written down must now be refused without latching.
    fPermanent = false;
    BOOST_CHECK_EQUAL((int)ApplyReorgFinalityGuard(dag, TIP_LEADER, FINAL_E2, &fPermanent,
                                                   nCur, nLatch, nEpoch),
                      (int)REORG_FINALITY_REJECT_TRANSIENT);
    BOOST_CHECK(!fPermanent);
    fPermanent = false;
    BOOST_CHECK_EQUAL((int)ApplyReorgFinalityGuard(dag, TIP_LEADER, FINAL_E3 - 1, &fPermanent,
                                                   nCur, nLatch, nEpoch),
                      (int)REORG_FINALITY_REJECT_TRANSIENT);
    BOOST_CHECK(!fPermanent);

    // Allowed, and a missing current record: neither may latch.
    fPermanent = false;
    BOOST_CHECK_EQUAL((int)ApplyReorgFinalityGuard(dag, TIP_LEADER, FINAL_E4, &fPermanent,
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

// Every verdict the guard persists must also be a verdict no node inside the band
// accepts -- restated over the persist flag rather than the enum, since the flag is
// the half that survives a restart.
BOOST_AUTO_TEST_CASE(nothing_is_persisted_that_a_skewed_peer_would_accept)
{
    RegTestNetwork net;
    CDAGManager dag;
    InstallStraddleFixture(dag);

    const int vTips[3] = { TIP_LAGGARD, TIP_LAGGARD_2, TIP_LEADER };

    for (int nFork = 0; nFork <= FORK_SWEEP_MAX; nFork++)
    {
        int nCur = 0, nLatch = 0, nEpoch = 0;
        bool fPermanentLeader = false;
        ApplyReorgFinalityGuard(dag, TIP_LEADER, nFork, &fPermanentLeader,
                                nCur, nLatch, nEpoch);

        for (int i = 0; i < 3; i++)
        {
            bool fPermanentPeer = false;
            const ReorgFinalityVerdict peer = ApplyReorgFinalityGuard(
                dag, vTips[i], nFork, &fPermanentPeer, nCur, nLatch, nEpoch);

            if (fPermanentLeader)
                BOOST_REQUIRE_MESSAGE(peer != REORG_FINALITY_ALLOW,
                                      "fork " << nFork << " persisted on the leader but "
                                      "accepted by tip " << vTips[i]);
            if (fPermanentPeer)
            {
                bool fUnused = false;
                int a = 0, b = 0, c = 0;
                BOOST_REQUIRE_MESSAGE(
                    ApplyReorgFinalityGuard(dag, TIP_LEADER, nFork, &fUnused, a, b, c)
                        != REORG_FINALITY_ALLOW,
                    "fork " << nFork << " persisted on tip " << vTips[i]
                            << " but accepted by the leader");
            }
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
    finalized.push_back(nGate - 300000);
    finalized.push_back(nGate - 200000);
    finalized.push_back(nGate - 100000);
    InstallFinalizedHeights(dag, nAsOf - 2, finalized);

    int nCur = 0, nLatch = 0, nEpoch = 0;
    const ReorgFinalityVerdict v =
        CheckReorgAgainstFinality(dag, nTip, 0, nCur, nLatch, nEpoch);

    BOOST_CHECK_EQUAL((int)v, (int)REORG_FINALITY_ALLOW);
    BOOST_CHECK_EQUAL(nCur, 0);

    // One block above the gate the same records are read, on production fork heights:
    // the latch must land REORG_LATCH_ANCHOR_LAG_EPOCHS-1 epochs behind the rejection
    // anchor, not one. The gate and the block below it share an epoch, so the anchors
    // are the ones installed above.
    BOOST_REQUIRE_EQUAL(GetEpochForHeight(nGate) - 1, nAsOf);
    int nCurAt = 0, nLatchAt = 0, nEpochAt = 0;
    CheckReorgAgainstFinality(dag, nGate, 0, nCurAt, nLatchAt, nEpochAt);
    BOOST_CHECK_EQUAL(nEpochAt, nAsOf);
    BOOST_CHECK_EQUAL(nCurAt, nGate - 100000);
    BOOST_CHECK_EQUAL(nLatchAt, nGate - 300000);
}


// Source-text check that both reorg sites still call the guard and act on its verdict.
// The cases above drive the guard directly and cannot see the wiring; no unit test
// builds a heavier branch forking below the anchor.
BOOST_AUTO_TEST_CASE(both_reorg_sites_still_route_through_the_shared_guard)
{
    const std::string strMain = ReadMainSource();
    BOOST_REQUIRE_MESSAGE(!strMain.empty(), "could not read src/main.cpp");

    // Reorganize and CBlock::SetBestChain, plus the two overloads and the
    // forwarding call between them.
    BOOST_CHECK_EQUAL(CountOccurrences(strMain, "ApplyReorgFinalityGuard("), 5u);

    // Both sites fail closed on missing state and refuse every non-ALLOW verdict.
    BOOST_CHECK_EQUAL(
        CountOccurrences(strMain, "if (verdict == REORG_FINALITY_STATE_MISSING)"), 2u);
    BOOST_CHECK_EQUAL(
        CountOccurrences(strMain, "if (verdict != REORG_FINALITY_ALLOW)"), 2u);

    // One comparison of a fork point against the anchor, inside the guard. A
    // second copy at a call site is how the two sites drift apart.
    BOOST_CHECK_EQUAL(CountOccurrences(strMain, "nForkHeight >= nFinalCurOut"), 1u);

    // Selection sites read the verdict through BestChainSwitchVerdict, which must stay
    // persistence-free.
    BOOST_CHECK_EQUAL(CountOccurrences(strMain, "BestChainSwitchVerdict("), 4u);
    const size_t nSwitch = strMain.find("ReorgFinalityVerdict BestChainSwitchVerdict(");
    BOOST_REQUIRE(nSwitch != std::string::npos);
    const size_t nSwitchEnd = strMain.find("\n}\n", nSwitch);
    BOOST_REQUIRE(nSwitchEnd != std::string::npos);
    const std::string strSwitch = strMain.substr(nSwitch, nSwitchEnd - nSwitch);
    BOOST_CHECK_MESSAGE(strSwitch.find("SetFailedValid") == std::string::npos &&
                        strSwitch.find("pfPermanentInvalid") == std::string::npos &&
                        strSwitch.find("ApplyReorgFinalityGuard") == std::string::npos,
                        "BestChainSwitchVerdict persists or latches a verdict");

    // The node-local live streak must not reach the decision. It stalls below the
    // deterministic value on out-of-order vote arrival and differs between nodes,
    // so folding it in puts path-dependent state back into a consensus reorg --
    // which is the defect the deterministic anchor was introduced to close.
    const size_t nGuard = strMain.find("ReorgFinalityVerdict CheckReorgAgainstFinality(const CDAGManager& dag,");
    BOOST_REQUIRE(nGuard != std::string::npos);
    const size_t nGuardEnd = strMain.find("\nReorgFinalityVerdict CheckReorgAgainstFinality(int nBestHeight,", nGuard);
    BOOST_REQUIRE(nGuardEnd != std::string::npos);
    const std::string strBody = strMain.substr(nGuard, nGuardEnd - nGuard);
    BOOST_CHECK_MESSAGE(strBody.find("GetFinalizedHeight()") == std::string::npos,
                        "the guard reads the node-local live finalized height");
    BOOST_CHECK_MESSAGE(strBody.find("REORG_LATCH_ANCHOR_LAG_EPOCHS") != std::string::npos,
                        "the guard no longer derives the latch epoch from the lag");
}

BOOST_AUTO_TEST_SUITE_END()
