// Display reward figures (GetBlockRewardSummary in subsidy.cpp) must match the
// consensus schedule; checked here without building Qt.

#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../subsidy.h"
#include "../util.h"
#include "../v5activation.h"

#include <string>
#include <vector>

extern bool fRegTest;
extern bool fTestNet;
extern unsigned int nTargetSpacing;

namespace {

// Mainnet reward evaluation, restored on scope exit.
struct MainnetRewardGuard
{
    bool fRegTestSaved;
    bool fTestNetSaved;
    MainnetRewardGuard()
        : fRegTestSaved(fRegTest), fTestNetSaved(fTestNet)
    {
        fRegTest = false;
        fTestNet = false;
    }
    ~MainnetRewardGuard()
    {
        fRegTest = fRegTestSaved;
        fTestNet = fTestNetSaved;
    }
};

// A NULL parent puts the supply clamp out of reach, so these compare the
// schedule itself rather than a clamped tail.
CBlockRewardSummary SummaryAt(int nHeight)
{
    return GetBlockRewardSummary(nHeight, NULL);
}

// The per-block figure the page prints, as it appears in the string.
std::string PerBlockField(const CBlockRewardSummary& s)
{
    const std::string str = FormatBlockRewardPerBlock(s);
    const size_t nSpace = str.find(' ');
    BOOST_REQUIRE(nSpace != std::string::npos);
    return str.substr(0, nSpace);
}

} // namespace

BOOST_AUTO_TEST_SUITE(reward_display_tests)

// Windows where consensus pays 0.75 / 0.5 / 1 INN.
BOOST_AUTO_TEST_CASE(the_windows_the_literal_table_reported_wrongly)
{
    MainnetRewardGuard guard;

    BOOST_CHECK_EQUAL(SummaryAt(7100000).nSubsidy, 75000000); // 0.75
    BOOST_CHECK_EQUAL(SummaryAt(7400000).nSubsidy, 50000000); // 0.5, page said 1
    BOOST_CHECK_EQUAL(SummaryAt(7510000).nSubsidy, 100000000); // 1, page said 0.75

    // FormatMoney keeps two decimals at minimum.
    BOOST_CHECK_EQUAL(PerBlockField(SummaryAt(7400000)), "0.50");
    BOOST_CHECK_EQUAL(PerBlockField(SummaryAt(7510000)), "1.00");
}

// The formatter agrees with GetProofOfWorkReward across the whole range, so a re-base
// cannot move consensus without moving the display.
BOOST_AUTO_TEST_CASE(formatter_agrees_with_consensus_across_a_sweep)
{
    MainnetRewardGuard guard;

    // Dense near every boundary the ladder has, sparse in between.
    for (int nHeight = 1; nHeight < 40000000; nHeight += 4999)
    {
        const CBlockRewardSummary summary = SummaryAt(nHeight);
        const int64_t nConsensus = GetProofOfWorkReward(nHeight, 0, NULL, 0);

        BOOST_REQUIRE_EQUAL(summary.nSubsidy, nConsensus);
        BOOST_REQUIRE_EQUAL(PerBlockField(summary), FormatMoney(nConsensus));
    }

    // Every tier boundary in the pre-DAG ladder and either side of it.
    static const int vBoundary[] = {
        490, 5000, 10000, 50000, 2000000, 2080000, 2700000, 7000000,
        7250000, 7500000, 7525000, 7750000, 8000000
    };
    for (size_t i = 0; i < sizeof(vBoundary) / sizeof(vBoundary[0]); i++)
    {
        for (int nDelta = -1; nDelta <= 1; nDelta++)
        {
            const int nHeight = vBoundary[i] + nDelta;
            if (nHeight < 1)
                continue;
            BOOST_REQUIRE_EQUAL(SummaryAt(nHeight).nSubsidy,
                                GetProofOfWorkReward(nHeight, 0, NULL, 0));
        }
    }
}

// The fork boundary and the post-DAG spacing divisor.
BOOST_AUTO_TEST_CASE(post_dag_reports_the_divided_reward)
{
    MainnetRewardGuard guard;

    const CBlockRewardSummary before = SummaryAt(FORK_HEIGHT_DAG - 1);
    const CBlockRewardSummary after = SummaryAt(FORK_HEIGHT_DAG);

    BOOST_CHECK(!before.fPostDag);
    BOOST_CHECK(after.fPostDag);
    BOOST_CHECK_EQUAL(before.nTargetSpacing, (int)PRE_DAG_TARGET_SPACING);
    BOOST_CHECK_EQUAL(after.nTargetSpacing, (int)POST_DAG_TARGET_SPACING);

    // The first post-DAG rung is 0.2 INN of 15s reward, divided by 15.
    const int64_t nRatio = PRE_DAG_TARGET_SPACING / POST_DAG_TARGET_SPACING;
    BOOST_CHECK_EQUAL(after.nSubsidy, 20000000 / nRatio);
    BOOST_CHECK(after.nSubsidy < before.nSubsidy);

    // And the string carries it, rather than the pre-fork figure.
    BOOST_CHECK_EQUAL(PerBlockField(after), FormatMoney(20000000 / nRatio));
    BOOST_CHECK(FormatBlockRewardPerBlock(after) != FormatBlockRewardPerBlock(before));
}

// Per-block reward falls 15x at the fork while blocks arrive 15x faster, so only the
// daily figure is comparable across it. The divisor truncates, so the two are close,
// not equal.
BOOST_AUTO_TEST_CASE(daily_issuance_is_continuous_across_the_fork)
{
    MainnetRewardGuard guard;

    const CBlockRewardSummary before = SummaryAt(FORK_HEIGHT_DAG - 1);
    const CBlockRewardSummary after = SummaryAt(FORK_HEIGHT_DAG);

    // 0.25 INN every 15s = 1440 INN/day; 0.0133... every 1s = ~1152 INN/day.
    BOOST_CHECK_EQUAL(before.nPerDay, before.nSubsidy * 86400 / PRE_DAG_TARGET_SPACING);
    BOOST_CHECK_EQUAL(after.nPerDay, after.nSubsidy * 86400 / POST_DAG_TARGET_SPACING);

    // Same order of magnitude, which is the whole point of the divisor.
    BOOST_CHECK(after.nPerDay * 2 > before.nPerDay);
    BOOST_CHECK(after.nPerDay < before.nPerDay * 2);

    BOOST_CHECK(FormatBlockRewardPerBlock(after).find("INN/day") != std::string::npos);
}

// The split shown to a collateralnode operator comes out of CBlockSubsidySplit,
// so the rate cannot drift from the one that is paid.
BOOST_AUTO_TEST_CASE(collateralnode_figure_derives_from_the_split)
{
    MainnetRewardGuard guard;

    static const int vHeight[] = { 7400000, 7510000, 8000000 };
    for (size_t i = 0; i < sizeof(vHeight) / sizeof(vHeight[0]); i++)
    {
        const CBlockRewardSummary summary = SummaryAt(vHeight[i]);

        // Nothing is minted outside the subsidy and nothing is lost in it.
        BOOST_REQUIRE_EQUAL(summary.nProducer + summary.nCollateralnode +
                                summary.nFinalityReserve,
                            summary.nSubsidy);

        const int64_t nPaid = summary.nProducer + summary.nCollateralnode;
        BOOST_REQUIRE_EQUAL(summary.nCollateralnode,
                            CBlockSubsidySplit::CollateralnodeShareOfBase(nPaid));

        const std::string str = FormatCollateralnodeReward(summary);
        BOOST_CHECK(str.find("65% of the block reward") == 0);
        BOOST_CHECK(str.find(FormatMoney(summary.nCollateralnode)) != std::string::npos);
    }

    // Pre-DAG there is no finality reserve, so the split is the arithmetic that
    // has always run.
    BOOST_CHECK_EQUAL(SummaryAt(FORK_HEIGHT_DAG - 1).nFinalityReserve, 0);
    BOOST_CHECK(SummaryAt(FORK_HEIGHT_DAG).nFinalityReserve > 0);
}

// GetTargetSpacingForHeight reads the mutable nTargetSpacing global below the fork,
// which LoadBlockIndex reassigns. The summary uses the compile-time constant, so the
// figure is a pure function of height.
BOOST_AUTO_TEST_CASE(per_day_does_not_depend_on_the_mutable_spacing_global)
{
    MainnetRewardGuard guard;
    const unsigned int nSaved = nTargetSpacing;

    nTargetSpacing = 1;
    const CBlockRewardSummary a = SummaryAt(FORK_HEIGHT_DAG - 1);
    nTargetSpacing = 15;
    const CBlockRewardSummary b = SummaryAt(FORK_HEIGHT_DAG - 1);
    nTargetSpacing = 600;
    const CBlockRewardSummary c = SummaryAt(FORK_HEIGHT_DAG - 1);

    nTargetSpacing = nSaved;

    BOOST_CHECK_EQUAL(a.nTargetSpacing, (int)PRE_DAG_TARGET_SPACING);
    BOOST_CHECK_EQUAL(a.nPerDay, b.nPerDay);
    BOOST_CHECK_EQUAL(b.nPerDay, c.nPerDay);
}

// Every height has a non-empty reward figure.
BOOST_AUTO_TEST_CASE(no_height_renders_an_empty_reward)
{
    MainnetRewardGuard guard;

    static const int vHeight[] = { 1, 10250001, 20000000, 40000000, 100000000 };
    for (size_t i = 0; i < sizeof(vHeight) / sizeof(vHeight[0]); i++)
    {
        const std::string str = FormatBlockRewardPerBlock(SummaryAt(vHeight[i]));
        BOOST_CHECK(!str.empty());
        BOOST_CHECK(str.find("INN per block") != std::string::npos);
        BOOST_CHECK(str.find("-") == std::string::npos); // never a negative figure
    }
}

BOOST_AUTO_TEST_SUITE_END()
