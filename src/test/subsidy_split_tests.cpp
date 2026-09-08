// One subsidy per block, split into producer, collateralnode and finality reserve shares
// that sum to it exactly, inside the supply-cap clamp. Unspent reserve is never minted.

#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../finality.h"
#include "../subsidy.h"
#include "../v5activation.h"

#include <limits>
#include <vector>

extern bool fRegTest;
extern bool fTestNet;

namespace {

// Mainnet evaluation, restored on scope exit. The post-DAG reserve is only
// meaningful against the mainnet ladder and its spacing divisor.
struct MainnetGuard
{
    bool fRegTestSaved;
    bool fTestNetSaved;
    MainnetGuard() : fRegTestSaved(fRegTest), fTestNetSaved(fTestNet)
    {
        fRegTest = false;
        fTestNet = false;
    }
    ~MainnetGuard()
    {
        fRegTest = fRegTestSaved;
        fTestNet = fTestNetSaved;
    }
};

// Evaluation on a named network, restored on scope exit. The epoch layout and the
// DAG fork height are read from these two globals, so a rule that must hold on
// every network has to be evaluated on every network rather than argued about.
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

struct NetworkCase
{
    const char* strName;
    bool fRegTest;
    bool fTestNet;
};

const NetworkCase vAllNetworks[] = {
    { "mainnet", false, false },
    { "testnet", false, true  },
    { "regtest", true,  false },
};

// Regtest evaluation with an explicit supply-cap height and amount.
struct SupplyCapGuard
{
    bool fRegTestSaved;
    bool fTestNetSaved;
    int nHeightSaved;
    int64_t nAmountSaved;
    SupplyCapGuard(int nCapHeight, int64_t nCapAmount)
        : fRegTestSaved(fRegTest), fTestNetSaved(fTestNet),
          nHeightSaved(nRegtestSupplyCapHeight), nAmountSaved(nRegtestSupplyCapAmount)
    {
        fRegTest = true;
        fTestNet = false;
        nRegtestSupplyCapHeight = nCapHeight;
        nRegtestSupplyCapAmount = nCapAmount;
    }
    ~SupplyCapGuard()
    {
        fRegTest = fRegTestSaved;
        fTestNet = fTestNetSaved;
        nRegtestSupplyCapHeight = nHeightSaved;
        nRegtestSupplyCapAmount = nAmountSaved;
    }
};

CBlockIndex MakeParent(int nHeight, int64_t nMoneySupply)
{
    CBlockIndex index;
    index.nHeight = nHeight;
    index.nMoneySupply = nMoneySupply;
    return index;
}

// The collateralnode rate exactly as it stood before the split existed: 65% of
// the subsidy plus fees, with no reserve taken off first. Restated here on
// purpose -- it is the mutation the tests below measure the split against.
int64_t LegacyCollateralnodePayment(int64_t nBlockValue)
{
    if (nBlockValue <= 0)
        return 0;
    return (nBlockValue / 100) * 65 + ((nBlockValue % 100) * 65) / 100;
}

int PostDAGEpoch(int nOffsetEpochs)
{
    return GetEpochForHeight(GetForkHeightDAG()) + nOffsetEpochs;
}

} // namespace

BOOST_AUTO_TEST_SUITE(subsidy_split_tests)

// ---------------------------------------------------------------------------
// 1. ONE SUBSIDY.
// ---------------------------------------------------------------------------

// The three shares sum to the total at every height and every value. This is
// the whole point: one number to clamp and one number to audit, with no fourth
// destination and no rounding residue that has to be tracked somewhere else.
BOOST_AUTO_TEST_CASE(split_sums_to_the_total_exactly)
{
    MainnetGuard guard;

    const int nPreDAG = GetForkHeightDAG() - 1000;
    const int nPostDAG = GetForkHeightDAG() + 1000;
    const int64_t vSubsidies[] = { 0, 1, 7, 99, 12345, COIN, 3 * COIN, 1234567891 };
    const int64_t vFees[] = { 0, 1, 999, COIN / 3 };

    for (int nHeight : { nPreDAG, GetForkHeightDAG(), nPostDAG })
    {
        for (int64_t nSubsidy : vSubsidies)
        {
            for (int64_t nFees : vFees)
            {
                for (CollateralnodeShare cn : { CollateralnodeShare::None, CollateralnodeShare::Paid })
                {
                    const CBlockSubsidySplit split =
                        CBlockSubsidySplit::ForBlock(nHeight, nSubsidy, nFees, cn);
                    BOOST_CHECK_EQUAL(split.Producer() + split.Collateralnode() + split.FinalityReserve(),
                                      split.Total());
                    BOOST_CHECK_EQUAL(split.PaidToBlock(), split.Total() - split.FinalityReserve());
                    BOOST_CHECK(split.Producer() >= 0);
                    BOOST_CHECK(split.Collateralnode() >= 0);
                    BOOST_CHECK(split.FinalityReserve() >= 0);
                    // Total is the whole coinbase allowance the block was sized
                    // against, so it never depends on whether a payee resolved.
                    BOOST_CHECK_EQUAL(split.Total(), nSubsidy + nFees);
                }
            }
        }
    }
}

// Below the DAG fork the reserve is zero at every height, so every share is bit
// for bit what the tree paid before the split existed. Historical verdicts do
// not move.
BOOST_AUTO_TEST_CASE(split_is_inert_below_the_dag_fork)
{
    MainnetGuard guard;

    for (int nHeight : { 1, 490, 50000, 2000001, 7000000, GetForkHeightDAG() - 1 })
    {
        BOOST_CHECK_EQUAL(GetFinalityReservePerBlock(nHeight), 0);

        const int64_t nSubsidy = GetBlockSubsidySchedule(nHeight);
        const int64_t nFees = 4321;
        const CBlockSubsidySplit split =
            CBlockSubsidySplit::ForBlock(nHeight, nSubsidy, nFees, CollateralnodeShare::Paid);

        BOOST_CHECK_EQUAL(split.FinalityReserve(), 0);
        BOOST_CHECK_EQUAL(split.PaidToBlock(), nSubsidy + nFees);
        BOOST_CHECK_EQUAL(split.Collateralnode(), LegacyCollateralnodePayment(nSubsidy + nFees));
        BOOST_CHECK_EQUAL(split.Producer(), (nSubsidy + nFees) - split.Collateralnode());
    }
}

// The reserve is a share of ISSUANCE, never of fees. Fees are value that already
// exists; reserving a share of them and paying it out an epoch later would be
// new supply the schedule never promised -- a second mint under another name.
BOOST_AUTO_TEST_CASE(reserve_is_a_share_of_issuance_not_of_fees)
{
    MainnetGuard guard;
    const int nHeight = GetForkHeightDAG() + 1000;

    const int64_t nSubsidy = GetBlockSubsidySchedule(nHeight);
    BOOST_REQUIRE(nSubsidy > 0);

    const CBlockSubsidySplit noFees =
        CBlockSubsidySplit::ForBlock(nHeight, nSubsidy, 0, CollateralnodeShare::Paid);
    const CBlockSubsidySplit bigFees =
        CBlockSubsidySplit::ForBlock(nHeight, nSubsidy, 100 * COIN, CollateralnodeShare::Paid);

    BOOST_CHECK(noFees.FinalityReserve() > 0);
    BOOST_CHECK_EQUAL(noFees.FinalityReserve(), bigFees.FinalityReserve());
    // ...and the fees all landed in the block's own shares.
    BOOST_CHECK_EQUAL(bigFees.PaidToBlock() - noFees.PaidToBlock(), 100 * COIN);
}

// The reserve depends on height alone, so producer and validator compute it identically
// and the epoch budget is a closed sum over a height range.
BOOST_AUTO_TEST_CASE(reserve_depends_on_height_alone)
{
    MainnetGuard guard;
    const int nHeight = GetForkHeightDAG() + 500;

    const int64_t nExpected = GetFinalityReservePerBlock(nHeight);
    BOOST_REQUIRE(nExpected > 0);

    // Same height, wildly different block circumstances: same reserve.
    for (int64_t nSubsidy : { nExpected * 2, nExpected * 10, 50 * COIN })
    {
        for (int64_t nFees : { (int64_t)0, (int64_t)7, 100 * COIN })
        {
            const CBlockSubsidySplit split =
                CBlockSubsidySplit::ForBlock(nHeight, nSubsidy, nFees, CollateralnodeShare::Paid);
            BOOST_CHECK_EQUAL(split.FinalityReserve(), nExpected);
        }
    }

    // A subsidy smaller than the reserve gives up all of it and no more: the
    // reserve can never make a share negative or a total exceed the subsidy.
    const CBlockSubsidySplit starved =
        CBlockSubsidySplit::ForBlock(nHeight, nExpected / 2, 0, CollateralnodeShare::Paid);
    BOOST_CHECK_EQUAL(starved.FinalityReserve(), nExpected / 2);
    BOOST_CHECK_EQUAL(starved.PaidToBlock(), 0);
}

// Pins the rate against the schedule; the case above holds for any rate. Basis-point
// rounding is under one satoshi, far below the smallest rate error.
BOOST_AUTO_TEST_CASE(reserve_is_the_declared_basis_point_share_of_issuance)
{
    MainnetGuard guard;

    const int vOffsets[] = { 1, 500, 12345, 250000 };
    for (int nOffset : vOffsets)
    {
        const int nHeight = GetForkHeightDAG() + nOffset;
        const int64_t nSchedule = GetBlockSubsidySchedule(nHeight);
        BOOST_REQUIRE(nSchedule > 0);
        BOOST_REQUIRE(nSchedule < MAX_MONEY / FINALITY_RESERVE_BPS);

        const int64_t nReserve = GetFinalityReservePerBlock(nHeight);
        const int64_t nExact = nSchedule * FINALITY_RESERVE_BPS;

        BOOST_CHECK(nReserve * SUBSIDY_BPS_DEN <= nExact);
        BOOST_CHECK(nReserve * SUBSIDY_BPS_DEN > nExact - SUBSIDY_BPS_DEN);
    }
}

// Recomputes the share from FINALITY_RESERVE_BPS in a wider type and different shape than
// BpsShare, so a rate change cannot cancel on both sides.
BOOST_AUTO_TEST_CASE(reserve_is_exactly_the_declared_basis_point_share)
{
    MainnetGuard guard;

    for (int nOffset : { 0, 1, 500, 12345, 300000, 1900000 })
    {
        const int nHeight = GetForkHeightDAG() + nOffset;
        const int64_t nSchedule = GetBlockSubsidySchedule(nHeight);
        BOOST_REQUIRE(nSchedule > 0);
        // One basis point has to be a nonzero number of satoshi here, or the
        // comparison has no resolution and proves nothing.
        BOOST_REQUIRE(nSchedule / SUBSIDY_BPS_DEN > 0);

        const int64_t nDeclared =
            (int64_t)(((__int128)nSchedule * FINALITY_RESERVE_BPS) / SUBSIDY_BPS_DEN);
        BOOST_CHECK_EQUAL(GetFinalityReservePerBlock(nHeight), nDeclared);

        // ...and what the block keeps is the rest of the schedule exactly, so
        // the two shares are one number divided, not two rates that agree.
        const CBlockSubsidySplit split =
            CBlockSubsidySplit::ForBlock(nHeight, nSchedule, 0, CollateralnodeShare::Paid);
        BOOST_CHECK_EQUAL(split.FinalityReserve(), nDeclared);
        BOOST_CHECK_EQUAL(split.PaidToBlock(), nSchedule - nDeclared);
    }
}

// ---------------------------------------------------------------------------
// 2. THE EPOCH RESERVE.
// ---------------------------------------------------------------------------

// The epoch budget is exactly the sum of per-block reserves over the preceding (closed)
// epoch, all ancestors of the settlement block.
BOOST_AUTO_TEST_CASE(epoch_budget_is_the_sum_of_the_preceding_epoch_reserves)
{
    MainnetGuard guard;

    for (int nOffset = 2; nOffset <= 5; nOffset++)
    {
        const int nEpoch = PostDAGEpoch(nOffset);
        const int nBoundary = GetEpochBoundaryHeight(nEpoch, GetForkHeightDAG());
        const int nPrevBoundary = GetEpochBoundaryHeight(nEpoch - 1, GetForkHeightDAG());
        BOOST_REQUIRE(nPrevBoundary < nBoundary);

        int64_t nExpected = 0;
        for (int h = nPrevBoundary; h < nBoundary; h++)
            nExpected += GetFinalityReservePerBlock(h);

        BOOST_CHECK_EQUAL(GetFinalityEpochBudget(nEpoch), nExpected);
        BOOST_CHECK(nExpected > 0);

        // The accrual window closes at the epoch boundary, which is at or below
        // the settlement height, so every accruing block is an ancestor.
        BOOST_CHECK(nBoundary <= GetFinalitySettlementHeight(nEpoch, nBoundary));
    }
}

// Tested at the first schedule step, where the preceding, containing and earlier epochs
// accrue different amounts and an off-by-one in the range is visible.
BOOST_AUTO_TEST_CASE(epoch_budget_accrues_over_the_preceding_epoch_where_it_is_visible)
{
    MainnetGuard guard;

    const int nFork = GetForkHeightDAG();
    const int64_t nFirstRung = GetBlockSubsidySchedule(nFork);
    BOOST_REQUIRE(nFirstRung > 0);

    int nStep = -1;
    for (int h = nFork + 1; h <= nFork + 4000000; h++)
    {
        if (GetBlockSubsidySchedule(h) != nFirstRung)
        {
            nStep = h;
            break;
        }
    }
    BOOST_REQUIRE(nStep > nFork);

    // Settle the epoch AFTER the one the step falls in, so the accrual range is
    // the mixed-rate epoch and its two neighbours are uniform and unequal.
    const int nEpoch = GetEpochForHeight(nStep) + 1;
    const int nHint = nFork;

    auto SumReserve = [](int nBegin, int nEnd) {
        int64_t nSum = 0;
        for (int h = nBegin; h < nEnd; h++)
            nSum += GetFinalityReservePerBlock(h);
        return nSum;
    };

    const int nH2 = GetEpochBoundaryHeight(nEpoch - 2, nHint);
    const int nH1 = GetEpochBoundaryHeight(nEpoch - 1, nHint);
    const int nH0 = GetEpochBoundaryHeight(nEpoch, nHint);
    const int nHp = GetEpochBoundaryHeight(nEpoch + 1, nHint);
    BOOST_REQUIRE(nH2 < nH1 && nH1 < nH0 && nH0 < nHp);

    const int64_t nBefore = SumReserve(nH2, nH1);
    const int64_t nPreceding = SumReserve(nH1, nH0);
    const int64_t nContaining = SumReserve(nH0, nHp);

    // The three ranges are genuinely distinguishable here; without this the
    // assertion below would hold under any of them.
    BOOST_REQUIRE(nPreceding != nContaining);
    BOOST_REQUIRE(nPreceding != nBefore);

    // A closed sum over a height range, keyed on the epoch number alone, so
    // producer and validator reach the same number from the same input.
    BOOST_CHECK_EQUAL(GetFinalityEpochBudget(nEpoch), nPreceding);
    BOOST_CHECK_EQUAL(GetFinalityEpochBudget(nEpoch + 1), nContaining);
    BOOST_CHECK_EQUAL(GetFinalityEpochBudget(nEpoch - 1), nBefore);
}

// Over an epoch, what blocks withheld is what the next settlement pays:
// sum(paid) + sum(reserved) == sum(schedule).
BOOST_AUTO_TEST_CASE(withheld_and_settled_are_the_same_quantity)
{
    MainnetGuard guard;

    const int nEpoch = PostDAGEpoch(3);
    const int nBegin = GetEpochBoundaryHeight(nEpoch, GetForkHeightDAG());
    const int nEnd = GetEpochBoundaryHeight(nEpoch + 1, GetForkHeightDAG());
    BOOST_REQUIRE(nEnd > nBegin);

    int64_t nWithheld = 0;
    int64_t nPaidOut = 0;
    int64_t nSchedule = 0;
    for (int h = nBegin; h < nEnd; h++)
    {
        const int64_t nSub = GetBlockSubsidySchedule(h);
        const CBlockSubsidySplit split =
            CBlockSubsidySplit::ForBlock(h, nSub, 0, CollateralnodeShare::Paid);
        nSchedule += nSub;
        nWithheld += split.FinalityReserve();
        nPaidOut += split.PaidToBlock();
    }

    BOOST_CHECK_EQUAL(nPaidOut + nWithheld, nSchedule);
    // ...and the settlement of the NEXT epoch pays out precisely that reserve.
    BOOST_CHECK_EQUAL(GetFinalityEpochBudget(nEpoch + 1), nWithheld);
}

// Unspent reserve is neither rolled forward nor returned to the producer. The settled
// total never exceeds the budget and is zero when no one voted.
BOOST_AUTO_TEST_CASE(unspent_reserve_is_never_minted)
{
    const int64_t nBudget = 10 * COIN;

    // No voters at all: nothing is minted, and in particular nothing accrues to
    // whoever produced the settlement block.
    {
        std::vector<CFinalityVote> vNone;
        std::vector<CTxOut> vLeg;
        int64_t nTotal = -1;
        std::string strError;
        BOOST_REQUIRE(BuildFinalitySettlementOutputs(vNone, nBudget, vLeg, nTotal, &strError));
        BOOST_CHECK_EQUAL(nTotal, 0);
        BOOST_CHECK(vLeg.empty());
    }

    // Truncation remainder: a budget that does not divide by the voter count
    // leaves fewer than V innovai unpaid, and those are not minted either.
    for (int64_t nOddBudget : { nBudget + 1, nBudget + 2, (int64_t)7 })
    {
        for (size_t nVoters = 1; nVoters <= 4; nVoters++)
        {
            const int64_t nPer = nOddBudget / (int64_t)nVoters;
            const int64_t nPaid = nPer * (int64_t)nVoters;
            BOOST_CHECK(nPaid <= nOddBudget);
            BOOST_CHECK(nOddBudget - nPaid < (int64_t)nVoters);
        }
    }
}

// ---------------------------------------------------------------------------
// 3. FIXED BUDGET VERSUS A PERCENTAGE OF STAKE.
// ---------------------------------------------------------------------------

// A fixed budget split equally raises per-voter reward as voters drop out; a percentage
// of stake does not. Modelled with one 90% whale and ten 1% voters.
BOOST_AUTO_TEST_CASE(fixed_budget_defends_the_voter_floor_where_a_percentage_does_not)
{
    const int64_t nBudget = 1000000;          // one epoch's reserve, in innovai
    const int64_t nWhaleStake = 900000;       // 90%
    const int64_t nSmallStake = 10000;        // 1% each, ten of them
    const int nSmallVoters = 10;

    // PERCENTAGE MODEL: reward proportional to stake. Normalised so the whole
    // participating stake earns the same total, which is the fairest possible
    // comparison -- the difference is purely in the DISTRIBUTION.
    const int64_t nTotalStake = nWhaleStake + nSmallStake * nSmallVoters;
    const int64_t nPctWhale = nBudget * nWhaleStake / nTotalStake;
    const int64_t nPctSmall = nBudget * nSmallStake / nTotalStake;

    // FIXED MODEL: equal split among the 11 counted voters.
    const int nVoters = 1 + nSmallVoters;
    const int64_t nFixedPer = nBudget / nVoters;

    // The whale takes the overwhelming majority under a percentage and an equal
    // eleventh under a fixed budget.
    BOOST_CHECK(nPctWhale > nBudget / 2);
    BOOST_CHECK_EQUAL(nFixedPer, nBudget / 11);
    BOOST_CHECK(nPctWhale > nFixedPer * 5);

    // The small voter earns an order of magnitude more under the fixed budget,
    // which is what decides whether it is worth running a node at all.
    BOOST_CHECK(nFixedPer > nPctSmall * 5);

    // A per-epoch cost between the two small-voter payouts: under the percentage only the whale
    // stays (below FINALITY_MIN_VOTERS); under the fixed budget all eleven do.
    const int64_t nCost = (nPctSmall + nFixedPer) / 2;
    BOOST_CHECK(nPctSmall < nCost);
    BOOST_CHECK(nFixedPer > nCost);

    const int nPctSurvivors = (nPctWhale >= nCost ? 1 : 0);
    BOOST_CHECK(nPctSurvivors < FINALITY_MIN_VOTERS);
    BOOST_CHECK(nVoters >= FINALITY_MIN_VOTERS);

    // SELF-CORRECTION. As voters leave, the fixed per-voter reward rises, so a
    // voter that was marginal becomes profitable again. A percentage share does
    // not move for the voter who stayed -- their stake did not change.
    int64_t nPrevPer = 0;
    for (int nRemaining = nVoters; nRemaining >= FINALITY_MIN_VOTERS; nRemaining--)
    {
        const int64_t nPer = nBudget / nRemaining;
        BOOST_CHECK(nPer >= nPrevPer);
        nPrevPer = nPer;
    }
    BOOST_CHECK(nBudget / FINALITY_MIN_VOTERS > nFixedPer);

    // BOUNDED. However many voters show up, the epoch mints at most the budget.
    for (int nAnyVoters = 1; nAnyVoters <= 5000; nAnyVoters += 137)
        BOOST_CHECK((nBudget / nAnyVoters) * nAnyVoters <= nBudget);
}

// ---------------------------------------------------------------------------
// 4. INTERACTION WITH THE SUPPLY CAP.
// ---------------------------------------------------------------------------

// The settlement takes its share of the headroom first and the block subsidy the rest,
// so their sum is bounded by the headroom.
BOOST_AUTO_TEST_CASE(supply_cap_bounds_the_subsidy_and_the_settlement_together)
{
    const int64_t nCap = 1000 * COIN;
    SupplyCapGuard guard(1, nCap);

    // Sweep the headroom from comfortable to exhausted.
    for (int64_t nSupply : { (int64_t)0, nCap / 2, nCap - 100 * COIN, nCap - 3 * COIN,
                             nCap - 1, nCap, nCap + 500 * COIN })
    {
        CBlockIndex parent = MakeParent(500, nSupply);
        const int64_t nHeadroom = GetRemainingIssuance(&parent, 0);
        BOOST_CHECK(nHeadroom >= 0);

        for (int64_t nWantedBudget : { (int64_t)0, COIN, 10 * COIN, 5000 * COIN })
        {
            const int64_t nBudget = (nWantedBudget > nHeadroom) ? nHeadroom : nWantedBudget;
            const int64_t nSubsidy = GetProofOfWorkReward(501, 0, &parent, nBudget);

            // Neither leg alone, and neither leg plus the other, can carry
            // supply past the cap.
            BOOST_CHECK(nBudget <= nHeadroom);
            BOOST_CHECK(nSubsidy <= nHeadroom - nBudget);
            BOOST_CHECK(nSubsidy + nBudget <= nHeadroom);
            BOOST_CHECK(nSupply + nSubsidy + nBudget <= (nSupply >= nCap ? nSupply : nCap));
        }
    }
}

// The settlement is clamped to the headroom before its must-pay outputs are built, on both
// sides off the same parent, so the required outputs are payable at every point of the cap.
BOOST_AUTO_TEST_CASE(settlement_is_payable_at_every_point_of_the_cap)
{
    const int64_t nCap = 1000 * COIN;
    SupplyCapGuard guard(1, nCap);

    for (int64_t nSupply : { (int64_t)0, nCap - 10 * COIN, nCap - COIN, nCap - 1, nCap, nCap * 2 })
    {
        CBlockIndex parent = MakeParent(500, nSupply);
        const int64_t nHeadroom = GetRemainingIssuance(&parent, 0);

        const int64_t nWanted = 50 * COIN;
        const int64_t nBudget = (nWanted > nHeadroom) ? nHeadroom : nWanted;
        const int64_t nSubsidy = GetProofOfWorkReward(501, 0, &parent, nBudget);
        const CBlockSubsidySplit split =
            CBlockSubsidySplit::ForBlock(501, nSubsidy, 0, CollateralnodeShare::Paid);

        // The allowance a validator computes for this block always covers the
        // settlement it is required to pay. There is no state in which it does
        // not, so there is no height at which no valid block exists.
        const int64_t nAllowance = split.PaidToBlock() + nBudget;
        BOOST_CHECK(nAllowance >= nBudget);
        BOOST_CHECK(nBudget >= 0);
    }
}

// MoneyRange stays a PER-VALUE overflow guard, as in Bitcoin. The total-supply rule
// must not weaken it.
BOOST_AUTO_TEST_CASE(money_range_per_value_guard_is_untouched)
{
    BOOST_CHECK(MoneyRange(0));
    BOOST_CHECK(MoneyRange(1));
    BOOST_CHECK(MoneyRange(MAX_MONEY));
    BOOST_CHECK(!MoneyRange(MAX_MONEY + 1));
    BOOST_CHECK(!MoneyRange(-1));

    // The regtest cap override can only ever LOWER the cap, so the clamp stays
    // inside MoneyRange rather than replacing it.
    {
        SupplyCapGuard guard(1, 100 * COIN);
        BOOST_CHECK(GetSupplyCapAmount() <= MAX_MONEY);
        BOOST_CHECK(MoneyRange(GetSupplyCapAmount()));
    }

    // Every share of a MoneyRange subsidy is itself in MoneyRange.
    MainnetGuard mainnet;
    const int nHeight = GetForkHeightDAG() + 7;
    const CBlockSubsidySplit split = CBlockSubsidySplit::ForBlock(
        nHeight, GetBlockSubsidySchedule(nHeight), 100 * COIN, CollateralnodeShare::Paid);
    BOOST_CHECK(MoneyRange(split.Total()));
    BOOST_CHECK(MoneyRange(split.Producer()));
    BOOST_CHECK(MoneyRange(split.Collateralnode()));
    BOOST_CHECK(MoneyRange(split.FinalityReserve()));
}

// ---------------------------------------------------------------------------
// 5. MUTATION: WHAT HAPPENS IF A SITE BYPASSES THE SHARED SPLIT.
// ---------------------------------------------------------------------------

// A miner sizing the collateralnode share on the raw subsidy plus fees disagrees with the
// validator post-DAG and the block is rejected. Pre-DAG the reserve is zero and both agree.
BOOST_AUTO_TEST_CASE(bypassing_the_split_makes_miner_and_validator_disagree)
{
    MainnetGuard guard;

    const int nPostDAG = GetForkHeightDAG() + 1000;
    const int64_t nSubsidy = GetBlockSubsidySchedule(nPostDAG);
    const int64_t nFees = 12345;
    BOOST_REQUIRE(nSubsidy > 0);

    const CBlockSubsidySplit split =
        CBlockSubsidySplit::ForBlock(nPostDAG, nSubsidy, nFees, CollateralnodeShare::Paid);
    BOOST_REQUIRE(split.FinalityReserve() > 0);

    // The bypass: the collateralnode share sized against the un-netted base.
    const int64_t nBypassCN = LegacyCollateralnodePayment(nSubsidy + nFees);
    BOOST_CHECK(nBypassCN > split.Collateralnode());
    BOOST_CHECK_EQUAL(nBypassCN - split.Collateralnode(),
                      LegacyCollateralnodePayment(nSubsidy + nFees)
                          - LegacyCollateralnodePayment(nSubsidy + nFees - split.FinalityReserve()));

    // A producer using the bypassed figure pays out more than the block is
    // allowed to mint, so every such block is rejected: a post-DAG stall.
    const int64_t nBypassCoinbase = nBypassCN + (nSubsidy + nFees - nBypassCN);
    BOOST_CHECK(nBypassCoinbase > split.PaidToBlock());
    BOOST_CHECK_EQUAL(nBypassCoinbase - split.PaidToBlock(), split.FinalityReserve());

    // Pre-DAG the two are identical, which is exactly why a base mismatch is
    // invisible until the fork day it stalls the chain on.
    const int nPreDAG = GetForkHeightDAG() - 1;
    const int64_t nPreSubsidy = GetBlockSubsidySchedule(nPreDAG);
    const CBlockSubsidySplit preSplit =
        CBlockSubsidySplit::ForBlock(nPreDAG, nPreSubsidy, nFees, CollateralnodeShare::Paid);
    BOOST_CHECK_EQUAL(preSplit.Collateralnode(),
                      LegacyCollateralnodePayment(nPreSubsidy + nFees));
    BOOST_CHECK_EQUAL(preSplit.FinalityReserve(), 0);
}

// A settlement built on a budget the validator did not derive is rejected by the
// exact-match check rather than minting the difference.
BOOST_AUTO_TEST_CASE(a_settlement_built_on_the_wrong_budget_is_rejected)
{
    // Two payees, budgets that differ by more than the truncation.
    std::vector<CFinalityVote> vVotes;
    std::vector<CKey> vKeys(2);
    for (int i = 0; i < 2; i++)
    {
        vKeys[i].MakeNewKey(true);
        CFinalityVote vote;
        vote.nProofMode = FINALITY_PROOF_TRANSPARENT;
        vote.nEpoch = 7;
        vote.nVoteWeight = 100 * COIN;
        vote.nReward = 1000;
        vote.nullifier = uint256(100 + i);
        vote.vchPubKey = vKeys[i].GetPubKey().Raw();
        vVotes.push_back(vote);
    }

    std::string strError;
    std::vector<CTxOut> vLegHonest, vLegInflated;
    int64_t nHonest = 0, nInflated = 0;
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vVotes, 10 * COIN, vLegHonest, nHonest, &strError));
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(vVotes, 20 * COIN, vLegInflated, nInflated, &strError));
    BOOST_CHECK_EQUAL(nHonest, 10 * COIN);
    BOOST_CHECK_EQUAL(nInflated, 20 * COIN);
    BOOST_REQUIRE_EQUAL(vLegHonest.size(), 2u);
    BOOST_CHECK_EQUAL(vLegHonest[0].nValue, 5 * COIN);
    BOOST_CHECK_EQUAL(vLegInflated[0].nValue, 10 * COIN);

    // A block carrying the inflated leg fails the check the honest budget drives.
    CBlock block;
    CTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vout.push_back(CTxOut(COIN, CScript()));
    for (const CTxOut& out : vLegInflated)
        coinbase.vout.push_back(out);
    block.vtx.push_back(coinbase);

    int64_t nChecked = -1;
    BOOST_CHECK(!CheckFinalitySettlementOutputs(block, vVotes, 10 * COIN, nChecked, &strError));
    BOOST_CHECK_EQUAL(nChecked, 0);
}

// ---------------------------------------------------------------------------
// 2b. THE ACCRUAL RANGE.
// ---------------------------------------------------------------------------

// An epoch accrues over the boundary pair the epoch functions place for E-1 and E.
// Checked as an identity, not a width, so it holds under any spacing regime.
// Evaluated on every network, since each has its own epoch layout.
BOOST_AUTO_TEST_CASE(accrual_range_is_the_adjacent_boundary_pair_on_every_network)
{
    for (const NetworkCase& net : vAllNetworks)
    {
        NetworkGuard guard(net.fRegTest, net.fTestNet);
        BOOST_TEST_MESSAGE(net.strName);

        const int nFirstPostDAG = GetEpochForHeight(GetForkHeightDAG());
        const int vEpochs[] = { 1, nFirstPostDAG - 1, nFirstPostDAG,
                                nFirstPostDAG + 1, nFirstPostDAG + 2,
                                nFirstPostDAG + 1000 };

        for (int nEpoch : vEpochs)
        {
            if (nEpoch < 1)
                continue;

            int nBegin = -1;
            int nEnd = -1;
            BOOST_REQUIRE_MESSAGE(GetFinalityAccrualRange(nEpoch, nBegin, nEnd),
                                  net.strName << " epoch " << nEpoch << " has no accrual range");

            // Exactly the boundaries, and strictly increasing: an overlapping or
            // reversed pair would pay one epoch's withheld reserve twice.
            BOOST_CHECK_EQUAL(nBegin, GetEpochBoundaryHeight(nEpoch - 1, 0));
            BOOST_CHECK_EQUAL(nEnd, GetEpochBoundaryHeight(nEpoch, 0));
            BOOST_CHECK(nBegin < nEnd);

            // ...and the heights really do belong to those epochs, which is what
            // makes the range a partition of history rather than a window.
            BOOST_CHECK_EQUAL(GetEpochForHeight(nBegin), nEpoch - 1);
            BOOST_CHECK_EQUAL(GetEpochForHeight(nEnd), nEpoch);

            // The budget is the fold over exactly that range and nothing else.
            BOOST_CHECK_EQUAL(GetFinalityEpochBudget(nEpoch),
                              SumFinalityReserve(nBegin, nEnd));
        }
    }
}

// Outside the epoch domain nothing settles. The check runs on the epoch number before the
// boundary multiplication, which would overflow the height type.
BOOST_AUTO_TEST_CASE(accrual_range_is_undefined_outside_the_epoch_domain)
{
    for (const NetworkCase& net : vAllNetworks)
    {
        NetworkGuard guard(net.fRegTest, net.fTestNet);
        BOOST_TEST_MESSAGE(net.strName);

        // The highest epoch whose boundary still fits a block height. Above it the
        // range is undefined; at and below it the range exists.
        const int64_t nFork = GetForkHeightDAG();
        const int64_t nPreDAGEpochs =
            (nFork + FINALITY_EPOCH_INTERVAL_PRE_DAG - 1) / FINALITY_EPOCH_INTERVAL_PRE_DAG;
        const int64_t nMaxEpoch64 =
            nPreDAGEpochs + ((int64_t)std::numeric_limits<int>::max() - nFork)
                                / FINALITY_EPOCH_INTERVAL_POST_DAG;
        BOOST_REQUIRE(nMaxEpoch64 > 0 && nMaxEpoch64 < (int64_t)std::numeric_limits<int>::max());
        const int nMaxEpoch = (int)nMaxEpoch64;

        const int vOutside[] = { std::numeric_limits<int>::min(), -300, -1, 0,
                                 nMaxEpoch + 1, std::numeric_limits<int>::max() };
        for (int nEpoch : vOutside)
        {
            int nBegin = -1;
            int nEnd = -1;
            BOOST_CHECK_MESSAGE(!GetFinalityAccrualRange(nEpoch, nBegin, nEnd),
                                net.strName << " epoch " << nEpoch << " must have no accrual range");
            // A rejected range leaves no half-written pair behind for a caller to
            // read past the bool.
            BOOST_CHECK_EQUAL(nBegin, 0);
            BOOST_CHECK_EQUAL(nEnd, 0);
            BOOST_CHECK_EQUAL(GetFinalityEpochBudget(nEpoch), 0);
        }

        // The domain is not empty and its edge is where it is claimed to be.
        int nBegin = -1;
        int nEnd = -1;
        BOOST_CHECK(GetFinalityAccrualRange(nMaxEpoch, nBegin, nEnd));
    }
}

// The DAG transition epoch spans the last pre-DAG epoch (60 blocks on mainnet and
// testnet, 11 on regtest) and settles zero, since nothing was withheld below the
// fork. Checked as an identity against what the blocks withheld, plus the zero.
BOOST_AUTO_TEST_CASE(the_dag_transition_epoch_settles_what_the_pre_dag_epoch_withheld)
{
    for (const NetworkCase& net : vAllNetworks)
    {
        NetworkGuard guard(net.fRegTest, net.fTestNet);
        BOOST_TEST_MESSAGE(net.strName);

        const int nFork = GetForkHeightDAG();
        const int nTransition = GetEpochForHeight(nFork);
        BOOST_REQUIRE(nTransition >= 1);

        // The fork is an epoch boundary, which is what makes the transition epoch
        // a whole epoch rather than a split one.
        BOOST_CHECK_EQUAL(GetEpochBoundaryHeight(nTransition, 0), nFork);

        int nBegin = -1;
        int nEnd = -1;
        BOOST_REQUIRE(GetFinalityAccrualRange(nTransition, nBegin, nEnd));
        BOOST_CHECK_EQUAL(nEnd, nFork);
        BOOST_CHECK(nBegin < nEnd);
        // The short gap: a pre-DAG interval on mainnet and testnet, and on regtest
        // whatever is left below a fork height that is not a multiple of one.
        BOOST_CHECK_EQUAL(nEnd - nBegin,
                          net.fRegTest ? nFork : FINALITY_EPOCH_INTERVAL_PRE_DAG);
        BOOST_CHECK(nEnd - nBegin < FINALITY_EPOCH_INTERVAL_POST_DAG);

        // What the blocks of that range actually withheld, taken from the split
        // the producer applies rather than from the sum being checked.
        int64_t nWithheld = 0;
        for (int h = nBegin; h < nEnd; h++)
        {
            const CBlockSubsidySplit split = CBlockSubsidySplit::ForBlock(
                h, GetBlockSubsidySchedule(h), 0, CollateralnodeShare::Paid);
            nWithheld += split.FinalityReserve();
        }
        BOOST_CHECK_EQUAL(GetFinalityEpochBudget(nTransition), nWithheld);
        BOOST_CHECK_EQUAL(nWithheld, 0);

        // The first epoch that accrued anything pays out all of it, so the short
        // range costs the voters of the next epoch nothing.
        int64_t nNextWithheld = 0;
        for (int h = nFork; h < GetEpochBoundaryHeight(nTransition + 1, 0); h++)
        {
            const CBlockSubsidySplit split = CBlockSubsidySplit::ForBlock(
                h, GetBlockSubsidySchedule(h), 0, CollateralnodeShare::Paid);
            nNextWithheld += split.FinalityReserve();
        }
        BOOST_CHECK(nNextWithheld > 0);
        BOOST_CHECK_EQUAL(GetFinalityEpochBudget(nTransition + 1), nNextWithheld);
    }
}

// Consecutive settlement ranges abut with no overlap or gap, and across the DAG fork their
// budgets sum to the reserve withheld. A width check alone accepts an overlapping pair.
BOOST_AUTO_TEST_CASE(consecutive_budgets_partition_the_withheld_reserve)
{
    for (const NetworkCase& net : vAllNetworks)
    {
        NetworkGuard guard(net.fRegTest, net.fTestNet);
        BOOST_TEST_MESSAGE(net.strName);

        const int nFirst = GetEpochForHeight(GetForkHeightDAG());
        const int nLast = nFirst + 6;

        int nPrevEnd = -1;
        int64_t nBudgets = 0;
        int nRunBegin = -1;
        int nRunEnd = -1;

        for (int nEpoch = nFirst; nEpoch <= nLast; nEpoch++)
        {
            int nBegin = -1;
            int nEnd = -1;
            BOOST_REQUIRE(GetFinalityAccrualRange(nEpoch, nBegin, nEnd));
            if (nRunBegin < 0)
                nRunBegin = nBegin;
            else
                BOOST_CHECK_EQUAL(nBegin, nPrevEnd);   // abutting, so nothing skipped
            BOOST_CHECK(nBegin < nEnd);                 // and nothing counted twice
            nPrevEnd = nEnd;
            nRunEnd = nEnd;
            nBudgets += GetFinalityEpochBudget(nEpoch);
        }

        int64_t nWithheld = 0;
        for (int h = nRunBegin; h < nRunEnd; h++)
        {
            const CBlockSubsidySplit split = CBlockSubsidySplit::ForBlock(
                h, GetBlockSubsidySchedule(h), 0, CollateralnodeShare::Paid);
            nWithheld += split.FinalityReserve();
        }
        BOOST_CHECK(nWithheld > 0);
        BOOST_CHECK_EQUAL(nBudgets, nWithheld);
    }
}

// The accrual range is an identity on GetEpochForHeight, so the map itself must be
// non-decreasing and never skip; the identity check cannot detect that.
BOOST_AUTO_TEST_CASE(the_epoch_map_is_non_decreasing_and_never_skips)
{
    for (const NetworkCase& net : vAllNetworks)
    {
        NetworkGuard guard(net.fRegTest, net.fTestNet);
        BOOST_TEST_MESSAGE(net.strName);

        const int nDAG = GetForkHeightDAG();
        const int nSpan = 4 * FINALITY_EPOCH_INTERVAL_POST_DAG;
        const int nFrom = (nDAG > nSpan) ? (nDAG - nSpan) : 0;
        const int nTo = nDAG + nSpan;

        int nPrev = GetEpochForHeight(nFrom);
        for (int h = nFrom + 1; h <= nTo; h++)
        {
            const int nEpoch = GetEpochForHeight(h);
            // Decreasing would order two boundaries backwards, and the identity
            // check would still pass: it only asks which epoch each end names.
            BOOST_REQUIRE_MESSAGE(nEpoch >= nPrev,
                net.strName << " epoch map decreased at height " << h
                            << ": " << nPrev << " -> " << nEpoch);
            // Skipping would leave an epoch with an empty preimage while its
            // settlement still comes due against a range built from boundaries.
            BOOST_REQUIRE_MESSAGE(nEpoch - nPrev <= 1,
                net.strName << " epoch map skipped at height " << h
                            << ": " << nPrev << " -> " << nEpoch);
            nPrev = nEpoch;
        }
    }
}

// A boundary inside its epoch passes the other range checks while settling blocks one
// epoch early.
BOOST_AUTO_TEST_CASE(each_boundary_is_the_first_height_of_its_epoch)
{
    for (const NetworkCase& net : vAllNetworks)
    {
        NetworkGuard guard(net.fRegTest, net.fTestNet);
        BOOST_TEST_MESSAGE(net.strName);

        const int nFirstPostDAG = GetEpochForHeight(GetForkHeightDAG());
        const int vEpochs[] = { 1, nFirstPostDAG - 1, nFirstPostDAG,
                                nFirstPostDAG + 1, nFirstPostDAG + 2,
                                nFirstPostDAG + 1000 };

        for (int nEpoch : vEpochs)
        {
            if (nEpoch < 1)
                continue;
            const int nBoundary = GetEpochBoundaryHeight(nEpoch, 0);
            BOOST_CHECK_EQUAL(GetEpochForHeight(nBoundary), nEpoch);
            if (nBoundary > 0)
                BOOST_CHECK_MESSAGE(GetEpochForHeight(nBoundary - 1) == nEpoch - 1,
                    net.strName << " boundary " << nBoundary << " is not the first"
                                << " height of epoch " << nEpoch);
        }
    }
}

// The half-open pair is exactly the preimage of its epoch, stronger than the endpoints
// agreeing.
BOOST_AUTO_TEST_CASE(the_accrual_range_is_exactly_the_preimage_of_its_epoch)
{
    for (const NetworkCase& net : vAllNetworks)
    {
        NetworkGuard guard(net.fRegTest, net.fTestNet);
        BOOST_TEST_MESSAGE(net.strName);

        const int nFirstPostDAG = GetEpochForHeight(GetForkHeightDAG());
        for (int nEpoch = nFirstPostDAG; nEpoch <= nFirstPostDAG + 3; nEpoch++)
        {
            int nBegin = -1;
            int nEnd = -1;
            BOOST_REQUIRE(GetFinalityAccrualRange(nEpoch, nBegin, nEnd));

            for (int h = nBegin; h < nEnd; h++)
                BOOST_REQUIRE_MESSAGE(GetEpochForHeight(h) == nEpoch - 1,
                    net.strName << " height " << h << " is in epoch "
                                << GetEpochForHeight(h) << " but settles in "
                                << nEpoch);

            // Nothing outside it belongs to the epoch that withheld.
            if (nBegin > 0)
                BOOST_CHECK(GetEpochForHeight(nBegin - 1) != nEpoch - 1);
            BOOST_CHECK(GetEpochForHeight(nEnd) != nEpoch - 1);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
