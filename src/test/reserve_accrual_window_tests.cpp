// Width of the finality reserve's accrual window (GetFinalityAccrualRange): equal to the
// epoch interval in force at its start, except the short epoch at a DAG fork off the pre-DAG
// grid. The grid is re-derived from the interval constants.

#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../finality.h"
#include "../subsidy.h"

#include <vector>

extern bool fRegTest;
extern bool fTestNet;

namespace {

struct NetGuard
{
    bool fRegTestSaved;
    bool fTestNetSaved;
    NetGuard() : fRegTestSaved(fRegTest), fTestNetSaved(fTestNet) {}
    ~NetGuard() { fRegTest = fRegTestSaved; fTestNet = fTestNetSaved; }
    void Select(int i)
    {
        fRegTest = (i == 0);
        fTestNet = (i == 1);
    }
};

const char* NetName(int i)
{
    if (i == 0) return "regtest";
    if (i == 1) return "testnet";
    return "mainnet";
}

int TransitionEpoch(int nDAGFork)
{
    return (nDAGFork + FINALITY_EPOCH_INTERVAL_PRE_DAG - 1) / FINALITY_EPOCH_INTERVAL_PRE_DAG;
}

// The epoch grid from the two interval constants and the fork height alone.
int ExpectedBoundary(int nEpoch, int nDAGFork)
{
    const int nPreDAGEpochs = TransitionEpoch(nDAGFork);
    if (nEpoch >= nPreDAGEpochs)
        return nDAGFork + (nEpoch - nPreDAGEpochs) * FINALITY_EPOCH_INTERVAL_POST_DAG;
    return nEpoch * FINALITY_EPOCH_INTERVAL_PRE_DAG;
}

// Every early epoch, the transition epoch and its neighbours, and a long
// post-DAG run past it.
std::vector<int> EpochsToWalk(int nDAGFork)
{
    const int nTransition = TransitionEpoch(nDAGFork);
    const int nLast = nTransition + 2000;
    std::vector<int> v;
    for (int e = 1; e <= nLast; e++)
    {
        if (e <= 5000 || e >= nTransition - 5 || (e % 97) == 0)
            v.push_back(e);
    }
    return v;
}

} // namespace

BOOST_AUTO_TEST_SUITE(reserve_accrual_window_tests)

// The grid itself, against the constants it is supposed to be built from. If
// this drifts, every case below is measuring the wrong geometry.
BOOST_AUTO_TEST_CASE(epoch_grid_follows_the_two_interval_constants)
{
    NetGuard guard;
    for (int net = 0; net < 3; net++)
    {
        guard.Select(net);
        const int nDAGFork = GetForkHeightDAG();
        const std::vector<int> vEpochs = EpochsToWalk(nDAGFork);
        BOOST_REQUIRE(!vEpochs.empty());
        for (size_t i = 0; i < vEpochs.size(); i++)
        {
            const int e = vEpochs[i];
            BOOST_CHECK_MESSAGE(GetEpochBoundaryHeight(e, 0) == ExpectedBoundary(e, nDAGFork),
                                NetName(net) << " epoch " << e << ": boundary "
                                             << GetEpochBoundaryHeight(e, 0)
                                             << " != derived " << ExpectedBoundary(e, nDAGFork));
        }
    }
}

// The window the budget walks, read from GetFinalityAccrualRange, is never wider than the
// interval in force where it begins.
BOOST_AUTO_TEST_CASE(accrual_window_never_exceeds_its_epoch_interval)
{
    NetGuard guard;
    for (int net = 0; net < 3; net++)
    {
        guard.Select(net);
        const int nDAGFork = GetForkHeightDAG();
        const std::vector<int> vEpochs = EpochsToWalk(nDAGFork);
        for (size_t i = 0; i < vEpochs.size(); i++)
        {
            const int e = vEpochs[i];
            int nBegin = -1;
            int nEnd = -1;
            if (!GetFinalityAccrualRange(e, nBegin, nEnd))
                continue;
            const int nWindow = nEnd - nBegin;
            const int nInterval = GetEpochInterval(nBegin);
            BOOST_CHECK_MESSAGE(nWindow <= nInterval,
                                NetName(net) << " epoch " << e << ": window " << nWindow
                                             << " exceeds interval " << nInterval);
        }
    }
}

// The exact half: equality everywhere except the single short epoch a fork
// height off the pre-DAG grid creates. The short epoch is located, not assumed,
// and its width is pinned to the remainder that causes it.
BOOST_AUTO_TEST_CASE(accrual_window_equals_the_interval_off_the_ragged_epoch)
{
    NetGuard guard;
    for (int net = 0; net < 3; net++)
    {
        guard.Select(net);
        const int nDAGFork = GetForkHeightDAG();
        const int nTransition = TransitionEpoch(nDAGFork);
        const int nRemainder = nDAGFork % FINALITY_EPOCH_INTERVAL_PRE_DAG;
        const std::vector<int> vEpochs = EpochsToWalk(nDAGFork);

        int nRagged = 0;
        for (size_t i = 0; i < vEpochs.size(); i++)
        {
            const int e = vEpochs[i];
            int nBegin = -1;
            int nEnd = -1;
            if (!GetFinalityAccrualRange(e, nBegin, nEnd))
                continue;
            const int nWindow = nEnd - nBegin;
            if (nWindow == GetEpochInterval(nBegin))
                continue;
            nRagged++;
            BOOST_CHECK_MESSAGE(e == nTransition,
                                NetName(net) << ": short epoch " << e << " is not the fork epoch "
                                             << nTransition);
            BOOST_CHECK_MESSAGE(nWindow == nRemainder,
                                NetName(net) << " epoch " << e << ": width " << nWindow
                                             << " != fork remainder " << nRemainder);
        }

        // A remainder of zero means the fork lands on the pre-DAG grid and no
        // epoch is short at all.
        const int nExpectedRagged = (nRemainder == 0) ? 0 : 1;
        BOOST_CHECK_MESSAGE(nRagged == nExpectedRagged,
                            NetName(net) << ": " << nRagged << " short epochs, expected "
                                         << nExpectedRagged);
    }
}

// The widest window each regime reaches equals its declared interval constant.
BOOST_AUTO_TEST_CASE(the_widest_window_each_regime_reaches_is_its_interval_constant)
{
    NetGuard guard;
    for (int net = 0; net < 3; net++)
    {
        guard.Select(net);
        const int nDAGFork = GetForkHeightDAG();
        const int nTransition = TransitionEpoch(nDAGFork);
        const std::vector<int> vEpochs = EpochsToWalk(nDAGFork);

        int nWidestPre = 0, nWidestPost = 0;
        for (size_t i = 0; i < vEpochs.size(); i++)
        {
            const int e = vEpochs[i];
            // The fork epoch is the one epoch allowed to be short, so it says
            // nothing either way about the width the regime can reach.
            if (e == nTransition)
                continue;
            int nBegin = -1;
            int nEnd = -1;
            if (!GetFinalityAccrualRange(e, nBegin, nEnd))
                continue;
            const int nWindow = nEnd - nBegin;
            if (nBegin >= nDAGFork)
            {
                if (nWindow > nWidestPost) nWidestPost = nWindow;
            }
            else
            {
                if (nWindow > nWidestPre) nWidestPre = nWindow;
            }
        }

        BOOST_CHECK_MESSAGE(nWidestPost == FINALITY_EPOCH_INTERVAL_POST_DAG,
                            NetName(net) << ": widest post-DAG window " << nWidestPost
                                         << " != " << FINALITY_EPOCH_INTERVAL_POST_DAG);

        // regtest forks at height 11, so its only pre-DAG-anchored window is the
        // short fork epoch skipped above and there is nothing left to measure.
        if (nWidestPre > 0)
            BOOST_CHECK_MESSAGE(nWidestPre == FINALITY_EPOCH_INTERVAL_PRE_DAG,
                                NetName(net) << ": widest pre-DAG window " << nWidestPre
                                             << " != " << FINALITY_EPOCH_INTERVAL_PRE_DAG);
    }
}

// The money clause: the budget is the reserve accrued over that window and
// nothing else. The range comes from the derived grid, so this measures what the
// budget walks rather than restating the call.
BOOST_AUTO_TEST_CASE(budget_is_the_reserve_accrued_over_exactly_that_window)
{
    NetGuard guard;
    guard.Select(2); // mainnet: the only ladder where the reserve is non-zero
    const int nDAGFork = GetForkHeightDAG();
    const int nTransition = TransitionEpoch(nDAGFork);

    for (int e = nTransition; e <= nTransition + 6; e++)
    {
        const int nBegin = ExpectedBoundary(e - 1, nDAGFork);
        const int nEnd = ExpectedBoundary(e, nDAGFork);
        BOOST_REQUIRE(nBegin < nEnd);

        int64_t nSum = 0;
        for (int h = nBegin; h < nEnd; h++)
            nSum += GetFinalityReservePerBlock(h);

        BOOST_CHECK_MESSAGE(GetFinalityEpochBudget(e) == nSum,
                            "mainnet epoch " << e << " [" << nBegin << "," << nEnd << "): budget "
                                             << GetFinalityEpochBudget(e)
                                             << " != accrued " << nSum);
    }

    // The first post-DAG settlement pays nothing: its predecessor accrued at the
    // pre-DAG rate, which is zero at every height.
    BOOST_CHECK_EQUAL(GetFinalityEpochBudget(nTransition), 0);
    BOOST_CHECK(GetFinalityEpochBudget(nTransition + 1) > 0);
}

BOOST_AUTO_TEST_SUITE_END()
