// Walks the post-DAG PoW emission schedule on regtest and testnet (emission_curve_tests
// covers mainnet). The literals are golden: they are what a mined block must pay.

#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../v5activation.h"
#include "../subsidy.h"

extern bool fRegTest;
extern bool fTestNet;

namespace {

// Evaluate rewards as a given network, restored on scope exit.
struct NetworkGuard
{
    bool fRegTestSaved;
    bool fTestNetSaved;
    NetworkGuard(bool fRegTestWanted, bool fTestNetWanted)
        : fRegTestSaved(fRegTest), fTestNetSaved(fTestNet)
    {
        fRegTest = fRegTestWanted;
        fTestNet = fTestNetWanted;
    }
    ~NetworkGuard()
    {
        fRegTest = fRegTestSaved;
        fTestNet = fTestNetSaved;
    }
};

// One rung as a mined chain sees it: the last height that pays it, and the
// per-block reward after the spacing divisor.
struct WalkTier
{
    int nLastHeight;
    int64_t nSubsidy;
};

// Regtest, fork height 11. Rung lengths are 20/40/60/80/100/120 pre-DAG-cadence
// blocks past the fork, stretched by 15.
static const WalkTier vRegtestLadder[] = {
    {  311,  5000000000LL },   //  50 INN
    {  611,  2500000000LL },   //  25
    {  911,   500000000LL },   //   5
    { 1211,  2500000000LL },   //  25
    { 1511,  5000000000LL },   //  50
    { 1811, 10000000000LL },   // 100
};
static const size_t nRegtestTiers = ARRAYLEN(vRegtestLadder);
static const int64_t nRegtestTail = 5000000LL;     // 0.05 INN

// Testnet, fork height 60. Rung lengths are a hundredth of mainnet's, so the
// rewards -- and the truncation the divisor introduces -- are mainnet's exactly.
static const WalkTier vTestnetLadder[] = {
    {  30060,  666666LL },
    {  67560,  333333LL },
    { 105060,   66666LL },
    { 142560,  333333LL },
    { 180060,  666666LL },
    { 217560, 1333333LL },
};
static const size_t nTestnetTiers = ARRAYLEN(vTestnetLadder);
static const int64_t nTestnetTail = 666LL;

int64_t Subsidy(int nHeight)
{
    return GetProofOfWorkReward(nHeight, 0);
}

// What the ladder pays at nHeight, read off the golden table.
int64_t LadderSubsidy(int nHeight, const WalkTier* pLadder, size_t nCount,
                      int64_t nTail)
{
    for (size_t i = 0; i < nCount; i++)
        if (nHeight <= pLadder[i].nLastHeight)
            return pLadder[i].nSubsidy;
    return nTail;
}

// The split a produced block performs: 65% to the collateralnode, remainder to
// the miner. Checks the pair is exact and neither side is starved.
void CheckSplit(int nHeight, int64_t nBlockValue)
{
    const int64_t nCN = CBlockSubsidySplit::CollateralnodeShareOfBase(nBlockValue);
    const int64_t nMiner = nBlockValue - nCN;

    BOOST_CHECK(nCN >= 0);
    BOOST_CHECK(nCN <= nBlockValue);
    BOOST_CHECK_EQUAL(nCN + nMiner, nBlockValue);

    // 65% to within the integer rounding the split performs.
    BOOST_CHECK(nCN * 100 <= nBlockValue * 65);
    BOOST_CHECK(nBlockValue * 65 - nCN * 100 < 100);

    // A paid block pays both sides something.
    if (nBlockValue > 0)
    {
        BOOST_CHECK(nMiner > 0);
        if (nBlockValue >= 100)
            BOOST_CHECK(nCN > 0);
    }
}

} // namespace

BOOST_AUTO_TEST_SUITE(emission_schedule_walk_tests)

// The fork heights this walk is written against. Moving one moves every
// stretched boundary below, so the literals fail here first.
BOOST_AUTO_TEST_CASE(runnable_networks_fork_where_the_walk_expects)
{
    {
        NetworkGuard guard(true, false);
        BOOST_CHECK_EQUAL(FORK_HEIGHT_DAG, 11);
        BOOST_CHECK_EQUAL((int)GetTargetSpacingForHeight(FORK_HEIGHT_DAG), 1);
    }
    {
        NetworkGuard guard(false, true);
        BOOST_CHECK_EQUAL(FORK_HEIGHT_DAG, 60);
        BOOST_CHECK_EQUAL((int)GetTargetSpacingForHeight(FORK_HEIGHT_DAG), 1);
    }
    BOOST_CHECK_EQUAL(PRE_DAG_TARGET_SPACING, 15);
    BOOST_CHECK_EQUAL(POST_DAG_TARGET_SPACING, 1);
}

// Regtest pre-DAG: genesis pays nothing, every other block below the fork pays 50 INN.
BOOST_AUTO_TEST_CASE(regtest_pre_dag_emission_is_unchanged)
{
    NetworkGuard guard(true, false);

    BOOST_CHECK_EQUAL(Subsidy(0), 0LL);
    for (int nHeight = 1; nHeight < FORK_HEIGHT_DAG; nHeight++)
        BOOST_CHECK_EQUAL(Subsidy(nHeight), 50 * COIN);

    // Fees still ride on top.
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(5, 12345LL), 50 * COIN + 12345LL);
}

// Every height from genesis past the last stretched boundary, with the split checked.
BOOST_AUTO_TEST_CASE(regtest_post_dag_schedule_walk)
{
    NetworkGuard guard(true, false);

    const int nEnd = vRegtestLadder[nRegtestTiers - 1].nLastHeight + 200;
    for (int nHeight = FORK_HEIGHT_DAG; nHeight <= nEnd; nHeight++)
    {
        const int64_t nExpected =
            LadderSubsidy(nHeight, vRegtestLadder, nRegtestTiers, nRegtestTail);
        BOOST_CHECK_EQUAL(Subsidy(nHeight), nExpected);
        CheckSplit(nHeight, nExpected);
    }
}

// The reward is continuous across the regtest fork, but the fork block is paid by
// the post-DAG path.
BOOST_AUTO_TEST_CASE(regtest_reward_is_continuous_across_the_fork)
{
    NetworkGuard guard(true, false);

    BOOST_CHECK_EQUAL(Subsidy(FORK_HEIGHT_DAG - 1), 5000000000LL);
    BOOST_CHECK_EQUAL(Subsidy(FORK_HEIGHT_DAG),     5000000000LL);
    BOOST_CHECK_EQUAL(GetPostDagProofOfWorkSubsidy(FORK_HEIGHT_DAG), 5000000000LL);

    // The rung the fork opens into is 750 INN before the divisor; the block
    // below the fork is paid by the flat pre-DAG branch, not by the ladder.
    BOOST_CHECK_EQUAL(GetPostDagProofOfWorkSubsidy(FORK_HEIGHT_DAG) * 15,
                      75000000000LL);
}

// Each stretched boundary steps exactly once, at exactly its height. Mining one
// block past 311 must halve the reward; 311 itself must not.
BOOST_AUTO_TEST_CASE(regtest_stretched_boundaries_step_exactly_once)
{
    NetworkGuard guard(true, false);

    for (size_t i = 0; i < nRegtestTiers; i++)
    {
        const int nLast = vRegtestLadder[i].nLastHeight;
        const int64_t nHere = vRegtestLadder[i].nSubsidy;
        const int64_t nNext = (i + 1 < nRegtestTiers)
                                  ? vRegtestLadder[i + 1].nSubsidy
                                  : nRegtestTail;

        BOOST_CHECK_EQUAL(Subsidy(nLast - 1), nHere);
        BOOST_CHECK_EQUAL(Subsidy(nLast),     nHere);
        BOOST_CHECK_EQUAL(Subsidy(nLast + 1), nNext);
        BOOST_CHECK(nNext != nHere);

        // Boundaries strictly increase.
        if (i > 0)
            BOOST_CHECK(nLast > vRegtestLadder[i - 1].nLastHeight);
    }

    // Each boundary is its pre-DAG-cadence offset stretched by the spacing ratio.
    const int nOffsets[] = { 20, 40, 60, 80, 100, 120 };
    for (size_t i = 0; i < nRegtestTiers; i++)
        BOOST_CHECK_EQUAL(vRegtestLadder[i].nLastHeight,
                          FORK_HEIGHT_DAG + nOffsets[i] * 15);
}

// Exact collateralnode and miner satoshi on one block of each regtest rung.
BOOST_AUTO_TEST_CASE(regtest_collateralnode_split_is_pinned)
{
    NetworkGuard guard(true, false);

    struct { int nHeight; int64_t nBlock; int64_t nCN; int64_t nMiner; } vCases[] = {
        {   11, 5000000000LL, 3250000000LL, 1750000000LL },  //  50 INN rung
        {  312, 2500000000LL, 1625000000LL,  875000000LL },  //  25
        {  900,  500000000LL,  325000000LL,  175000000LL },  //   5
        { 1512, 10000000000LL, 6500000000LL, 3500000000LL }, // 100
    };

    for (size_t i = 0; i < ARRAYLEN(vCases); i++)
    {
        const int64_t nBlock = Subsidy(vCases[i].nHeight);
        BOOST_CHECK_EQUAL(nBlock, vCases[i].nBlock);
        const int64_t nCN = CBlockSubsidySplit::CollateralnodeShareOfBase(nBlock);
        BOOST_CHECK_EQUAL(nCN, vCases[i].nCN);
        BOOST_CHECK_EQUAL(nBlock - nCN, vCases[i].nMiner);
    }

    // The tail below the last rung still pays both sides.
    const int64_t nTail = Subsidy(1812);
    BOOST_CHECK_EQUAL(nTail, nRegtestTail);
    BOOST_CHECK_EQUAL(CBlockSubsidySplit::CollateralnodeShareOfBase(nTail), 3250000LL);
    BOOST_CHECK_EQUAL(nTail - CBlockSubsidySplit::CollateralnodeShareOfBase(nTail), 1750000LL);
}

// Testnet pre-DAG: premine at height 1 and the fair-launch half coin below the fork.
BOOST_AUTO_TEST_CASE(testnet_pre_dag_emission_is_unchanged)
{
    NetworkGuard guard(false, true);

    BOOST_CHECK_EQUAL(Subsidy(1), 1000000LL * COIN);
    for (int nHeight = 2; nHeight < FORK_HEIGHT_DAG; nHeight++)
        BOOST_CHECK_EQUAL(Subsidy(nHeight), COIN / 2);
    BOOST_CHECK_EQUAL(Subsidy(0), COIN / 2);
}

// Every post-DAG testnet height pays, and pays the integers mainnet will pay.
BOOST_AUTO_TEST_CASE(testnet_post_dag_subsidy_is_never_zero)
{
    NetworkGuard guard(false, true);

    const int nProbes[] = { 60, 61, 5000, 5001, 10000, 30060, 30061, 67560,
                            105060, 142560, 180060, 217560, 217561, 5000000 };
    for (size_t i = 0; i < ARRAYLEN(nProbes); i++)
    {
        const int64_t nBlock = Subsidy(nProbes[i]);
        BOOST_CHECK(nBlock > 0);
        BOOST_CHECK_EQUAL(nBlock, LadderSubsidy(nProbes[i], vTestnetLadder,
                                                nTestnetTiers, nTestnetTail));
        CheckSplit(nProbes[i], nBlock);
    }

    // The first post-DAG testnet block pays the same satoshi the first post-DAG
    // mainnet block will: same rung reward, same divisor, same truncation.
    BOOST_CHECK_EQUAL(Subsidy(FORK_HEIGHT_DAG), 666666LL);
}

// Testnet boundaries step exactly once, at their stretched heights.
BOOST_AUTO_TEST_CASE(testnet_stretched_boundaries_step_exactly_once)
{
    NetworkGuard guard(false, true);

    const int nOffsets[] = { 2000, 4500, 7000, 9500, 12000, 14500 };
    for (size_t i = 0; i < nTestnetTiers; i++)
    {
        const int nLast = vTestnetLadder[i].nLastHeight;
        BOOST_CHECK_EQUAL(nLast, FORK_HEIGHT_DAG + nOffsets[i] * 15);

        const int64_t nHere = vTestnetLadder[i].nSubsidy;
        const int64_t nNext = (i + 1 < nTestnetTiers)
                                  ? vTestnetLadder[i + 1].nSubsidy
                                  : nTestnetTail;
        BOOST_CHECK_EQUAL(Subsidy(nLast), nHere);
        BOOST_CHECK_EQUAL(Subsidy(nLast + 1), nNext);
        BOOST_CHECK(nNext != nHere);
    }
}

// Every rung keeps its pre-DAG wall-clock span and payout, to within per-block
// truncation, on both runnable networks.
BOOST_AUTO_TEST_CASE(runnable_ladders_keep_their_duration_and_payout)
{
    const int nRegOffsets[] = { 20, 40, 60, 80, 100, 120 };
    const int64_t nRegBefore[] = { 75000000000LL, 37500000000LL, 7500000000LL,
                                   37500000000LL, 75000000000LL, 150000000000LL };
    {
        NetworkGuard guard(true, false);
        int nPrevLast = FORK_HEIGHT_DAG;
        int nPrevOffset = 0;
        for (size_t i = 0; i < nRegtestTiers; i++)
        {
            const int64_t nBlocks = vRegtestLadder[i].nLastHeight - nPrevLast;
            const int64_t nOrigBlocks = nRegOffsets[i] - nPrevOffset;
            BOOST_CHECK_EQUAL(nBlocks * POST_DAG_TARGET_SPACING,
                              nOrigBlocks * PRE_DAG_TARGET_SPACING);

            const int64_t nPaid = nBlocks * Subsidy(vRegtestLadder[i].nLastHeight);
            const int64_t nIntended = nOrigBlocks * nRegBefore[i];
            BOOST_CHECK(nPaid <= nIntended);
            BOOST_CHECK(nIntended - nPaid < nBlocks);

            nPrevLast = vRegtestLadder[i].nLastHeight;
            nPrevOffset = nRegOffsets[i];
        }
    }

    const int nTestOffsets[] = { 2000, 4500, 7000, 9500, 12000, 14500 };
    const int64_t nTestBefore[] = { 10000000LL, 5000000LL, 1000000LL,
                                    5000000LL, 10000000LL, 20000000LL };
    {
        NetworkGuard guard(false, true);
        int nPrevLast = FORK_HEIGHT_DAG;
        int nPrevOffset = 0;
        for (size_t i = 0; i < nTestnetTiers; i++)
        {
            const int64_t nBlocks = vTestnetLadder[i].nLastHeight - nPrevLast;
            const int64_t nOrigBlocks = nTestOffsets[i] - nPrevOffset;
            BOOST_CHECK_EQUAL(nBlocks * POST_DAG_TARGET_SPACING,
                              nOrigBlocks * PRE_DAG_TARGET_SPACING);

            const int64_t nPaid = nBlocks * Subsidy(vTestnetLadder[i].nLastHeight);
            const int64_t nIntended = nOrigBlocks * nTestBefore[i];
            BOOST_CHECK(nPaid <= nIntended);
            BOOST_CHECK(nIntended - nPaid < nBlocks);

            nPrevLast = vTestnetLadder[i].nLastHeight;
            nPrevOffset = nTestOffsets[i];
        }
    }
}

// Every reward the runnable ladders can produce stays inside MoneyRange, on both
// sides of the split, so no height on either network can build a block the value
// checks reject.
BOOST_AUTO_TEST_CASE(runnable_ladder_rewards_stay_in_money_range)
{
    {
        NetworkGuard guard(true, false);
        for (int nHeight = 0; nHeight <= 2100; nHeight++)
        {
            const int64_t nBlock = Subsidy(nHeight);
            BOOST_CHECK(MoneyRange(nBlock));
            BOOST_CHECK(MoneyRange(CBlockSubsidySplit::CollateralnodeShareOfBase(nBlock)));
        }
    }
    {
        NetworkGuard guard(false, true);
        const int nProbes[] = { 0, 1, 2, 59, 60, 30060, 217560, 217561, 100000000 };
        for (size_t i = 0; i < ARRAYLEN(nProbes); i++)
        {
            const int64_t nBlock = Subsidy(nProbes[i]);
            BOOST_CHECK(MoneyRange(nBlock));
            BOOST_CHECK(MoneyRange(CBlockSubsidySplit::CollateralnodeShareOfBase(nBlock)));
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
