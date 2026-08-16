// Pins the mainnet PoW emission curve across the DAG fork: post-DAG rewards are divided
// by the 15x spacing ratio and tier boundaries stretched by it. Any change to the ladder,
// divisor, spacing constants or activation shift must update these tests.

#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../finality.h"
#include "../v5activation.h"

#include <vector>

extern bool fRegTest;
extern bool fTestNet;

namespace {

// Mainnet reward evaluation, restored on scope exit.
struct MainnetEmissionGuard
{
    bool fRegTestSaved;
    bool fTestNetSaved;
    MainnetEmissionGuard()
        : fRegTestSaved(fRegTest), fTestNetSaved(fTestNet)
    {
        fRegTest = false;
        fTestNet = false;
    }
    ~MainnetEmissionGuard()
    {
        fRegTest = fRegTestSaved;
        fTestNet = fTestNetSaved;
    }
};

// One rung: the last height paid at nSubsidy, and the pre-divisor per-block
// reward the 15s schedule assigns it.
struct EmissionTier
{
    int nLastHeight;
    int64_t nSubsidyBeforeSpacingScale;
};

// The tail beyond the last finite rung.
static const int64_t TAIL_SUBSIDY_BEFORE_SCALE = 10000; // 0.0001 INN

// The post-DAG rungs, in ladder order, with the 15s-cadence height each was
// stretched from. Golden values: they are the literals in main.cpp.
struct StretchedTier
{
    int nLastHeight;
    int nOriginal15sHeight;
    int64_t nSubsidyBeforeSpacingScale;
};

static const StretchedTier vStretched[] = {
    {  9790000,  8250000,  20000000 },  // 0.2
    { 13540000,  8500000,  15000000 },  // 0.15
    { 17290000,  8750000,  10000000 },  // 0.1
    { 21040000,  9000000,   5000000 },  // 0.05
    { 24790000,  9250000,   1000000 },  // 0.01
    { 28540000,  9500000,   5000000 },  // 0.05
    { 32290000,  9750000,  10000000 },  // 0.1
    { 36040000, 10000000,  20000000 },  // 0.2
};
static const size_t nStretchedCount = sizeof(vStretched) / sizeof(vStretched[0]);

// The rungs the fork does not stretch, ending with the last one below it.
// Which rungs live here is itself a function of the fork: a re-base that moves
// FORK_HEIGHT_DAG below a 15s boundary moves that boundary into vStretched.
static const EmissionTier vPreFork[] = {
    { 7500000, 50000000 },
    { 7525000, 100000000 },
    { 7750000, 50000000 },
    { 8000000, 25000000 },
};
static const size_t nPreForkCount = sizeof(vPreFork) / sizeof(vPreFork[0]);

int64_t Subsidy(int nHeight)
{
    return GetProofOfWorkReward(nHeight, 0);
}

// What the ladder pays at nHeight once the post-DAG divisor is applied.
int64_t ExpectedSubsidy(int nHeight, int64_t nBeforeScale)
{
    if (nHeight < FORK_HEIGHT_DAG)
        return nBeforeScale;
    return nBeforeScale * (int64_t)POST_DAG_TARGET_SPACING / PRE_DAG_TARGET_SPACING;
}

} // namespace

BOOST_AUTO_TEST_SUITE(emission_curve_tests)

// The stretch is only well-formed if the fork lands strictly inside the gap
// between the last unstretched rung and the first stretched rung's original.
// A shift that pushes FORK_HEIGHT_DAG past 8,750,000 silently reinstates the
// full 15s reward on hundreds of thousands of 1s blocks.
BOOST_AUTO_TEST_CASE(dag_fork_sits_inside_the_stretch_window)
{
    MainnetEmissionGuard guard;

    BOOST_CHECK_EQUAL(MAINNET_V5_ACTIVATION_SHIFT, 190000);
    BOOST_CHECK_EQUAL(FORK_HEIGHT_DAG, 8140000);
    BOOST_CHECK_EQUAL(PRE_DAG_TARGET_SPACING, 15);
    BOOST_CHECK_EQUAL(POST_DAG_TARGET_SPACING, 1);
    BOOST_CHECK_EQUAL((int)GetTargetSpacingForHeight(FORK_HEIGHT_DAG),
                      (int)POST_DAG_TARGET_SPACING);

    BOOST_CHECK(vPreFork[nPreForkCount - 1].nLastHeight < FORK_HEIGHT_DAG);
    BOOST_CHECK(vStretched[0].nOriginal15sHeight > FORK_HEIGHT_DAG);
}

// Every stretched boundary must be exactly its 15s height mapped through the
// fork. This is the check that fails when the activation shift is re-based.
BOOST_AUTO_TEST_CASE(stretched_boundaries_are_the_documented_mapping)
{
    MainnetEmissionGuard guard;

    const int64_t nRatio = PRE_DAG_TARGET_SPACING / POST_DAG_TARGET_SPACING;
    BOOST_CHECK_EQUAL(nRatio, 15);

    for (size_t i = 0; i < nStretchedCount; i++)
    {
        const int64_t nExpected =
            (int64_t)FORK_HEIGHT_DAG +
            nRatio * ((int64_t)vStretched[i].nOriginal15sHeight - FORK_HEIGHT_DAG);
        BOOST_CHECK_EQUAL((int64_t)vStretched[i].nLastHeight, nExpected);
    }
}

// Boundaries strictly increase and each rung changes the reward exactly at its
// last height: no rung is skipped, none overlaps its neighbour.
BOOST_AUTO_TEST_CASE(tier_transitions_neither_skip_nor_double_count)
{
    MainnetEmissionGuard guard;

    std::vector<int> vBoundaries;
    std::vector<int64_t> vBefore;
    for (size_t i = 0; i < nPreForkCount; i++)
    {
        vBoundaries.push_back(vPreFork[i].nLastHeight);
        vBefore.push_back(vPreFork[i].nSubsidyBeforeSpacingScale);
    }
    for (size_t i = 0; i < nStretchedCount; i++)
    {
        vBoundaries.push_back(vStretched[i].nLastHeight);
        vBefore.push_back(vStretched[i].nSubsidyBeforeSpacingScale);
    }

    for (size_t i = 1; i < vBoundaries.size(); i++)
        BOOST_CHECK(vBoundaries[i] > vBoundaries[i - 1]);

    for (size_t i = 0; i < vBoundaries.size(); i++)
    {
        const int nLast = vBoundaries[i];
        const int64_t nHere = ExpectedSubsidy(nLast, vBefore[i]);
        BOOST_CHECK_EQUAL(Subsidy(nLast), nHere);

        // One block earlier still pays this rung (every rung is wider than 1).
        BOOST_CHECK_EQUAL(Subsidy(nLast - 1),
                          ExpectedSubsidy(nLast - 1, vBefore[i]));

        // One block later pays the next rung, and pays something different.
        const int64_t nNextBefore = (i + 1 < vBefore.size())
                                        ? vBefore[i + 1]
                                        : TAIL_SUBSIDY_BEFORE_SCALE;
        BOOST_CHECK_EQUAL(Subsidy(nLast + 1),
                          ExpectedSubsidy(nLast + 1, nNextBefore));
        BOOST_CHECK(Subsidy(nLast + 1) != nHere);
    }
}

// The divisor applies from FORK_HEIGHT_DAG and not one block early or late,
// and the emission RATE is continuous across it: the same rung pays 15x less
// per block at 15x the block rate, up to one truncated satoshi per block.
BOOST_AUTO_TEST_CASE(reward_rate_is_continuous_across_the_dag_fork)
{
    MainnetEmissionGuard guard;

    // Both sides of the fork sit in the same (0.1 INN) rung.
    const int64_t nBefore = vStretched[0].nSubsidyBeforeSpacingScale;
    BOOST_CHECK(FORK_HEIGHT_DAG - 1 > vPreFork[nPreForkCount - 1].nLastHeight);
    BOOST_CHECK(FORK_HEIGHT_DAG <= vStretched[0].nLastHeight);

    const int64_t nPre = Subsidy(FORK_HEIGHT_DAG - 1);
    const int64_t nPost = Subsidy(FORK_HEIGHT_DAG);
    BOOST_CHECK_EQUAL(nPre, nBefore);
    BOOST_CHECK_EQUAL(nPost, nBefore / 15);
    BOOST_CHECK_EQUAL(nPost, 1333333);

    // Per-second emission matches on both sides to within the truncation.
    BOOST_CHECK(nPost * PRE_DAG_TARGET_SPACING <= nPre * POST_DAG_TARGET_SPACING);
    BOOST_CHECK(nPre * POST_DAG_TARGET_SPACING -
                    nPost * PRE_DAG_TARGET_SPACING < PRE_DAG_TARGET_SPACING);

    // The last pre-fork block is not yet scaled.
    BOOST_CHECK(Subsidy(FORK_HEIGHT_DAG - 1) > Subsidy(FORK_HEIGHT_DAG));
}

// The exact per-block reward on every post-DAG rung. Truncation is part of the
// consensus value, so these are the integers, not a formula.
BOOST_AUTO_TEST_CASE(post_dag_per_block_rewards_are_pinned)
{
    MainnetEmissionGuard guard;

    BOOST_CHECK_EQUAL(Subsidy(FORK_HEIGHT_DAG),  1333333);   // 0.2  / 15
    BOOST_CHECK_EQUAL(Subsidy(9790000),          1333333);
    BOOST_CHECK_EQUAL(Subsidy(9790001),          1000000);   // 0.15 / 15
    BOOST_CHECK_EQUAL(Subsidy(13540000),         1000000);
    BOOST_CHECK_EQUAL(Subsidy(13540001),          666666);   // 0.1  / 15
    BOOST_CHECK_EQUAL(Subsidy(17290000),          666666);
    BOOST_CHECK_EQUAL(Subsidy(17290001),          333333);   // 0.05 / 15
    BOOST_CHECK_EQUAL(Subsidy(21040000),          333333);
    BOOST_CHECK_EQUAL(Subsidy(21040001),           66666);   // 0.01 / 15
    BOOST_CHECK_EQUAL(Subsidy(24790000),           66666);
    BOOST_CHECK_EQUAL(Subsidy(24790001),          333333);   // 0.05 / 15
    BOOST_CHECK_EQUAL(Subsidy(28540000),          333333);
    BOOST_CHECK_EQUAL(Subsidy(28540001),          666666);   // 0.1  / 15
    BOOST_CHECK_EQUAL(Subsidy(32290000),          666666);
    BOOST_CHECK_EQUAL(Subsidy(32290001),         1333333);   // 0.2  / 15
    BOOST_CHECK_EQUAL(Subsidy(36040000),         1333333);
    BOOST_CHECK_EQUAL(Subsidy(36040001),             666);   // tail 0.0001 / 15
    BOOST_CHECK_EQUAL(Subsidy(60000000),             666);
}

// Each stretched rung keeps the 15s schedule's duration and payout over half-open
// spans (prev_last, last], within one satoshi per block of truncation.
BOOST_AUTO_TEST_CASE(each_stretched_tier_keeps_its_duration_and_payout)
{
    MainnetEmissionGuard guard;

    int nPrevLast = FORK_HEIGHT_DAG;
    int nPrevOrig = FORK_HEIGHT_DAG;
    for (size_t i = 0; i < nStretchedCount; i++)
    {
        const int64_t nBlocks = (int64_t)vStretched[i].nLastHeight - nPrevLast;
        const int64_t nOrigBlocks =
            (int64_t)vStretched[i].nOriginal15sHeight - nPrevOrig;

        // Wall clock: 1s per stretched block vs 15s per original block.
        BOOST_CHECK_EQUAL(nBlocks * POST_DAG_TARGET_SPACING,
                          nOrigBlocks * PRE_DAG_TARGET_SPACING);

        const int64_t nPaid = nBlocks * Subsidy(vStretched[i].nLastHeight);
        const int64_t nIntended =
            nOrigBlocks * vStretched[i].nSubsidyBeforeSpacingScale;
        BOOST_CHECK(nPaid <= nIntended);
        BOOST_CHECK(nIntended - nPaid < nBlocks);

        nPrevLast = vStretched[i].nLastHeight;
        nPrevOrig = vStretched[i].nOriginal15sHeight;
    }
}

// Total proof-of-work emission from the DAG fork to the end of the ladder,
// summed block by block from the function itself. Any edit to a boundary, a
// rung reward, the divisor or the activation shift moves this integer.
BOOST_AUTO_TEST_CASE(terminal_pow_supply_after_the_dag_fork_is_pinned)
{
    MainnetEmissionGuard guard;

    const int nLast = vStretched[nStretchedCount - 1].nLastHeight;
    const int64_t nBlockCount = (int64_t)nLast - FORK_HEIGHT_DAG + 1;
    BOOST_CHECK_EQUAL(nBlockCount, 27900001LL);

    int64_t nTotal = 0;
    for (int nHeight = FORK_HEIGHT_DAG; nHeight <= nLast; nHeight++)
        nTotal += Subsidy(nHeight);

    // 186,999.89533333 INN over 27,900,001 blocks (~322.9 days at 1s). This
    // figure grew when the gate was re-based to 8,140,000 only because an
    // earlier fork leaves more of the schedule on the post-fork side of it;
    // total emission over the whole schedule is unchanged. The invariant that
    // states that is the per-tier one below, not this sum.
    BOOST_CHECK_EQUAL(nTotal, 18699989533333LL);

    // 15s-schedule payout over the half-open span (FORK, nLast], so the fork block is not
    // counted on both sides.
    const int64_t nSpanBlocks = (int64_t)nLast - FORK_HEIGHT_DAG;
    BOOST_CHECK_EQUAL(nSpanBlocks, 27900000LL);

    int64_t nSpanTotal = 0;
    for (int nHeight = FORK_HEIGHT_DAG + 1; nHeight <= nLast; nHeight++)
        nSpanTotal += Subsidy(nHeight);
    BOOST_CHECK_EQUAL(nSpanTotal, 18699988200000LL);

    int64_t nIntended = 0;
    int nPrevOrig = FORK_HEIGHT_DAG;
    for (size_t i = 0; i < nStretchedCount; i++)
    {
        nIntended += ((int64_t)vStretched[i].nOriginal15sHeight - nPrevOrig) *
                     vStretched[i].nSubsidyBeforeSpacingScale;
        nPrevOrig = vStretched[i].nOriginal15sHeight;
    }
    // Exactly the INN the 15s tier comments promise over this span: the fork
    // lands inside the 0.2 rung, so that one contributes its remainder
    // (8,250,000 - 8,140,000 = 110,000 blocks -> 22,000 INN) and the seven full
    // rungs above it contribute 37,500 + 25,000 + 12,500 + 2,500 + 12,500 +
    // 25,000 + 50,000 = 165,000 INN. Total 187,000 INN.
    BOOST_CHECK_EQUAL(nIntended, 18700000000000LL);
    BOOST_CHECK(nSpanTotal <= nIntended);
    BOOST_CHECK_EQUAL(nIntended - nSpanTotal, 11800000LL);
    BOOST_CHECK(nIntended - nSpanTotal < nSpanBlocks);

    // Terminal PoW subsidy is reached ~322.9 days after the fork.
    BOOST_CHECK_EQUAL(nSpanBlocks * POST_DAG_TARGET_SPACING / 86400, 322LL);

    // The tail: 666 satoshi per 1s block is ~210.03 INN/year, the rate the 15s
    // schedule's 0.0001 INN per block produced (210.24 INN/year).
    const int64_t nSecondsPerYear = 31536000LL;
    const int64_t nTailPerYear =
        Subsidy(nLast + 1) * (nSecondsPerYear / POST_DAG_TARGET_SPACING);
    const int64_t nOriginalTailPerYear =
        TAIL_SUBSIDY_BEFORE_SCALE * (nSecondsPerYear / PRE_DAG_TARGET_SPACING);
    BOOST_CHECK_EQUAL(nTailPerYear, 21002976000LL);
    BOOST_CHECK_EQUAL(nOriginalTailPerYear, 21024000000LL);
    BOOST_CHECK(nTailPerYear <= nOriginalTailPerYear);
    BOOST_CHECK(nOriginalTailPerYear - nTailPerYear < nSecondsPerYear);
}

// Finality-vote rewards are a second post-DAG mint (nFinalityRewardOut) at the legacy
// 6%/yr rate on voting weight, so the rate is pinned too.
BOOST_AUTO_TEST_CASE(finality_vote_reward_rate_is_pinned)
{
    MainnetEmissionGuard guard;

    BOOST_CHECK_EQUAL(COIN_YEAR_REWARD, 6000000LL);        // 0.06 INN per coin-year
    BOOST_CHECK_EQUAL(FINALITY_EPOCH_INTERVAL_POST_DAG, 300);
    BOOST_CHECK_EQUAL(GetEpochInterval(FORK_HEIGHT_DAG), 300);

    // A post-DAG epoch is 300 blocks at 1s, so the interval doubles as its
    // duration in seconds and the coin-age arithmetic comes out right.
    BOOST_CHECK_EQUAL((int64_t)FINALITY_EPOCH_INTERVAL_POST_DAG *
                          POST_DAG_TARGET_SPACING,
                      300LL);

    // Truncation floor: below 288 INN of weight an epoch generates less than
    // one whole coin-day and the vote is paid nothing.
    const int64_t nFloor = 288LL * COIN;
    BOOST_CHECK_EQUAL(GetFinalityVoteReward(nFloor - COIN, 300), 0LL);
    BOOST_CHECK_EQUAL(GetFinalityVoteReward(nFloor, 300), COIN_YEAR_REWARD / 365);
    BOOST_CHECK_EQUAL(GetFinalityVoteReward(nFloor, 300), 16438LL);

    // At scale the channel is 6%/yr of the weight that votes: 105,120 epochs
    // per year at 300s each.
    const int64_t nEpochsPerYear = 31536000LL / 300LL;
    BOOST_CHECK_EQUAL(nEpochsPerYear, 105120LL);
    const int64_t nWeight = 1000000LL * COIN;               // 1,000,000 INN
    const int64_t nYearly = GetFinalityVoteReward(nWeight, 300) * nEpochsPerYear;
    BOOST_CHECK(nYearly > 59000LL * COIN);                  // ~6% of 1,000,000
    BOOST_CHECK(nYearly < 61000LL * COIN);

    // Per-epoch head count is bounded from Boundary A, which is one epoch past
    // the DAG fork. The bound on the mint is that count times the per-voter
    // reward, so this cap is part of the emission story.
    BOOST_CHECK_EQUAL(FINALITY_CANONICAL_CERT_MAX_NULLIFIERS, 128u);
    BOOST_CHECK_EQUAL(FORK_HEIGHT_BOUNDARY_A, FORK_HEIGHT_DAG + 300);
    BOOST_CHECK_EQUAL(FINALITY_MAX_STAKE_PROOFS, 8);
}

BOOST_AUTO_TEST_SUITE_END()
