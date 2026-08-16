// Total-supply cap: the v5 clamp of block subsidy to the headroom under MAX_MONEY.
// Pins: inert below the fork, exact remainder at the boundary, zero past it, fees
// unaffected, history unchanged; driven from a synthetic parent index, not the tip.

#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../v5activation.h"

#include <limits>
#include <vector>

extern bool fRegTest;
extern bool fTestNet;

namespace {

// Regtest evaluation with an explicit cap height and cap amount, all restored on
// scope exit so suites that run after this one see the shipped configuration.
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

// Mainnet evaluation, restored on scope exit.
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

// A parent block index carrying nothing but the two fields the clamp reads.
// Built standalone, never linked into the global index: the point of the rule is
// that it needs no chain state beyond its own parent.
CBlockIndex MakeParent(int nHeight, int64_t nMoneySupply)
{
    CBlockIndex index;
    index.nHeight = nHeight;
    index.nMoneySupply = nMoneySupply;
    return index;
}

const int64_t REGTEST_POW_SUBSIDY = 50 * COIN;   // flat regtest ladder value

} // namespace

BOOST_AUTO_TEST_SUITE(supply_cap_tests)

// The rule must change no historical verdict: below the fork height the clamp
// reports unbounded headroom no matter how far over the cap the parent already
// is, so the schedule value is returned untouched.
BOOST_AUTO_TEST_CASE(inert_below_fork_height)
{
    SupplyCapGuard guard(1000, 500 * COIN);

    // A parent already past the cap, at every height below activation.
    const int64_t nOverCap = 900 * COIN;
    const int vHeights[] = { 0, 1, 10, 500, 998 };
    for (size_t i = 0; i < sizeof(vHeights) / sizeof(vHeights[0]); i++)
    {
        CBlockIndex parent = MakeParent(vHeights[i], nOverCap);
        BOOST_CHECK_EQUAL(GetRemainingIssuance(&parent, 0),
                          std::numeric_limits<int64_t>::max());
        BOOST_CHECK_EQUAL(ClampSubsidyToSupplyCap(REGTEST_POW_SUBSIDY, &parent, 0),
                          REGTEST_POW_SUBSIDY);
        BOOST_CHECK_EQUAL(GetProofOfWorkReward(vHeights[i] + 1, 0, &parent),
                          REGTEST_POW_SUBSIDY);
    }

    // The parent one below the boundary pays a full subsidy; its child, the
    // first block AT the fork height, is the first one clamped.
    CBlockIndex parentBelow = MakeParent(998, nOverCap);
    CBlockIndex parentAt = MakeParent(999, nOverCap);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(999, 0, &parentBelow), REGTEST_POW_SUBSIDY);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(1000, 0, &parentAt), 0);
}

// At the boundary the subsidy is clamped to the exact remainder -- not to zero,
// and not to the full schedule value.
BOOST_AUTO_TEST_CASE(clamps_to_exact_remainder_at_boundary)
{
    const int64_t nCap = 500 * COIN;
    SupplyCapGuard guard(10, nCap);

    // Headroom smaller than one subsidy: pay exactly the headroom.
    const int64_t vPartial[] = { 1, COIN, 7 * COIN, REGTEST_POW_SUBSIDY - 1 };
    for (size_t i = 0; i < sizeof(vPartial) / sizeof(vPartial[0]); i++)
    {
        CBlockIndex parent = MakeParent(100, nCap - vPartial[i]);
        BOOST_CHECK_EQUAL(GetRemainingIssuance(&parent, 0), vPartial[i]);
        BOOST_CHECK_EQUAL(GetProofOfWorkReward(101, 0, &parent), vPartial[i]);
        // Connecting that block lands the supply exactly on the cap.
        BOOST_CHECK_EQUAL(parent.nMoneySupply + vPartial[i], nCap);
    }

    // Headroom of exactly one subsidy: still a full payment, nothing clipped.
    CBlockIndex parentExact = MakeParent(100, nCap - REGTEST_POW_SUBSIDY);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(101, 0, &parentExact), REGTEST_POW_SUBSIDY);

    // One satoshi more headroom than a subsidy: schedule value, cap not binding.
    CBlockIndex parentSlack = MakeParent(100, nCap - REGTEST_POW_SUBSIDY - 1);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(101, 0, &parentSlack), REGTEST_POW_SUBSIDY);
}

// Past the cap the subsidy is zero, and stays zero however far past it the
// supply already sits.
BOOST_AUTO_TEST_CASE(zero_subsidy_past_the_cap)
{
    const int64_t nCap = 500 * COIN;
    SupplyCapGuard guard(10, nCap);

    const int64_t vSupply[] = { nCap, nCap + 1, nCap + 1000 * COIN, MAX_MONEY };
    for (size_t i = 0; i < sizeof(vSupply) / sizeof(vSupply[0]); i++)
    {
        CBlockIndex parent = MakeParent(100, vSupply[i]);
        BOOST_CHECK_EQUAL(GetRemainingIssuance(&parent, 0), 0);
        BOOST_CHECK_EQUAL(GetProofOfWorkReward(101, 0, &parent), 0);
        BOOST_CHECK_EQUAL(GetProofOfStakeReward(1000000, 0, &parent), 0);
    }
}

// Only issuance stops. Fees are added after the clamp, so they pay in full at
// the boundary and past it -- a cap that stopped fees would end the chain's
// security budget rather than its inflation.
BOOST_AUTO_TEST_CASE(fees_still_pay_at_and_past_the_cap)
{
    const int64_t nCap = 500 * COIN;
    const int64_t nFees = 3 * COIN;
    SupplyCapGuard guard(10, nCap);

    // Past the cap: the whole reward is the fees.
    CBlockIndex parentPast = MakeParent(100, nCap);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(101, nFees, &parentPast), nFees);
    BOOST_CHECK_EQUAL(GetProofOfStakeReward(1000000, nFees, &parentPast), nFees);

    // Exactly at the boundary: partial subsidy plus the full fees.
    const int64_t nHeadroom = 2 * COIN;
    CBlockIndex parentEdge = MakeParent(100, nCap - nHeadroom);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(101, nFees, &parentEdge), nHeadroom + nFees);

    // Fees are never themselves clamped: a fee larger than the remaining
    // headroom still pays in full, because fees are recycled value and add
    // nothing to supply.
    CBlockIndex parentTiny = MakeParent(100, nCap - 1);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(101, 100 * COIN, &parentTiny), 1 + 100 * COIN);
}

// The stake subsidy has no height bound of its own -- its "9000 years" cutoff
// compares an int height against 18,934,128,000 and can never fire -- so the cap
// is the only thing that ever stops it. Coin age must not be able to buy past it.
BOOST_AUTO_TEST_CASE(stake_reward_is_capped_regardless_of_coin_age)
{
    const int64_t nCap = 500 * COIN;
    SupplyCapGuard guard(10, nCap);

    // The dead cutoff: no int height can exceed it.
    BOOST_CHECK((int64_t)std::numeric_limits<int>::max() <= (int64_t)2103792 * 9000);

    // Headroom well below what any of these coin ages would otherwise pay.
    const int64_t nHeadroom = 1000;
    CBlockIndex parent = MakeParent(100, nCap - nHeadroom);

    // Coin age spanning six orders of magnitude, all clamped to the headroom.
    const int64_t vCoinAge[] = { 1000, 1000000, 1000000000, 100000000000LL };
    for (size_t i = 0; i < sizeof(vCoinAge) / sizeof(vCoinAge[0]); i++)
    {
        const int64_t nReward = GetProofOfStakeReward(vCoinAge[i], 0, &parent);
        BOOST_CHECK_EQUAL(nReward, nHeadroom);
    }

    // Below the fork the same coin age is unbounded, which is the defect the
    // rule closes: the reward there is strictly larger than the whole cap.
    SupplyCapGuard guardHigh(1000000, nCap);
    CBlockIndex parentLow = MakeParent(100, 0);
    BOOST_CHECK(GetProofOfStakeReward(100000000000LL, 0, &parentLow) > nCap);
}

// Issuance already committed elsewhere comes off the headroom before the subsidy; a
// commitment at or past the headroom drives the subsidy to zero, never negative.
BOOST_AUTO_TEST_CASE(committed_issuance_is_deducted_first)
{
    const int64_t nCap = 500 * COIN;
    SupplyCapGuard guard(10, nCap);

    const int64_t nHeadroom = 10 * COIN;
    CBlockIndex parent = MakeParent(100, nCap - nHeadroom);

    BOOST_CHECK_EQUAL(GetRemainingIssuance(&parent, 4 * COIN), 6 * COIN);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(101, 0, &parent, 4 * COIN), 6 * COIN);

    // Commitment equal to the headroom, and beyond it: zero, never negative.
    BOOST_CHECK_EQUAL(GetRemainingIssuance(&parent, nHeadroom), 0);
    BOOST_CHECK_EQUAL(GetRemainingIssuance(&parent, nHeadroom + 1000 * COIN), 0);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(101, 0, &parent, nHeadroom + 1000 * COIN), 0);

    // Fees still pay with a commitment in place.
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(101, 7 * COIN, &parent, nHeadroom), 7 * COIN);
}

// The clamp reads only its parent: same height, different supplies, different subsidies;
// the node's own tip is never consulted.
BOOST_AUTO_TEST_CASE(clamp_reads_only_the_parent)
{
    const int64_t nCap = 500 * COIN;
    SupplyCapGuard guard(10, nCap);

    CBlockIndex parentA = MakeParent(100, nCap - 3 * COIN);
    CBlockIndex parentB = MakeParent(100, nCap - 40 * COIN);

    // Same height, same schedule value, different headroom -> different subsidy.
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(101, 0, &parentA), 3 * COIN);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(101, 0, &parentB), 40 * COIN);

    // Repeated evaluation is stable: no cache, no clock, no tip.
    for (int i = 0; i < 8; i++)
        BOOST_CHECK_EQUAL(GetProofOfWorkReward(101, 0, &parentA), 3 * COIN);

    // A NULL parent is the genesis/no-chain case: height 0, rule inert.
    BOOST_CHECK_EQUAL(GetRemainingIssuance(NULL, 0), std::numeric_limits<int64_t>::max());
}

// Mainnet: every height below the DAG fork keeps its historical subsidy exactly, under any
// MAINNET_V5_ACTIVATION_SHIFT.
BOOST_AUTO_TEST_CASE(mainnet_history_is_unchanged)
{
    MainnetGuard guard;

    BOOST_CHECK_EQUAL(FORK_HEIGHT_SUPPLY_CAP, FORK_HEIGHT_DAG);
    BOOST_CHECK_EQUAL(GetSupplyCapAmount(), MAX_MONEY);

    // A parent sitting at the full cap, at a spread of historical heights.
    // Every one of them must still pay its ladder value.
    const int vHeights[] = { 1, 490, 5000, 50000, 2000001, 2700000,
                             4025000, 7500000, FORK_HEIGHT_DAG - 2 };
    for (size_t i = 0; i < sizeof(vHeights) / sizeof(vHeights[0]); i++)
    {
        const int nHeight = vHeights[i];
        CBlockIndex parentAtCap = MakeParent(nHeight - 1, MAX_MONEY);
        CBlockIndex parentEmpty = MakeParent(nHeight - 1, 0);
        const int64_t nWithSupply = GetProofOfWorkReward(nHeight, 0, &parentAtCap);
        const int64_t nWithout = GetProofOfWorkReward(nHeight, 0, &parentEmpty);
        const int64_t nNoParent = GetProofOfWorkReward(nHeight, 0, NULL);
        BOOST_CHECK_EQUAL(nWithSupply, nWithout);
        BOOST_CHECK_EQUAL(nWithSupply, nNoParent);
    }

    // The first block at the DAG fork is the first one the cap can touch.
    CBlockIndex parentPre = MakeParent(FORK_HEIGHT_DAG - 1, MAX_MONEY);
    BOOST_CHECK_EQUAL(GetRemainingIssuance(&parentPre, 0), 0);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(FORK_HEIGHT_DAG, 0, &parentPre), 0);

    // And one height earlier it is still unbounded.
    CBlockIndex parentPre2 = MakeParent(FORK_HEIGHT_DAG - 2, MAX_MONEY);
    BOOST_CHECK_EQUAL(GetRemainingIssuance(&parentPre2, 0),
                      std::numeric_limits<int64_t>::max());
}

// The cap override may only lower the cap. A regtest amount at or above
// MAX_MONEY is ignored so the clamp can never sit outside MoneyRange.
BOOST_AUTO_TEST_CASE(cap_amount_override_only_lowers)
{
    SupplyCapGuard guard(10, MAX_MONEY);
    BOOST_CHECK_EQUAL(GetSupplyCapAmount(), MAX_MONEY);

    nRegtestSupplyCapAmount = MAX_MONEY + 1;
    BOOST_CHECK_EQUAL(GetSupplyCapAmount(), MAX_MONEY);

    nRegtestSupplyCapAmount = 0;
    BOOST_CHECK_EQUAL(GetSupplyCapAmount(), MAX_MONEY);

    nRegtestSupplyCapAmount = 123 * COIN;
    BOOST_CHECK_EQUAL(GetSupplyCapAmount(), 123 * COIN);
    BOOST_CHECK(MoneyRange(GetSupplyCapAmount()));
}

// Walking a chain to the cap: the supply is monotone up to MAX_MONEY, lands on
// it exactly, and never crosses it. This is the property the whole rule exists
// to provide, driven through the same function ConnectBlock calls.
BOOST_AUTO_TEST_CASE(chain_walk_lands_exactly_on_the_cap)
{
    // Deliberately not a multiple of the flat regtest subsidy, so the last
    // funded block has to pay a partial remainder.
    const int64_t nCap = 1005 * COIN + 1;
    SupplyCapGuard guard(5, nCap);

    int64_t nSupply = 0;
    int64_t nPrevSupply = -1;
    bool fSawPartial = false;
    for (int nHeight = 1; nHeight <= 40; nHeight++)
    {
        CBlockIndex parent = MakeParent(nHeight - 1, nSupply);
        const int64_t nSubsidy = GetProofOfWorkReward(nHeight, 0, &parent);
        BOOST_CHECK(nSubsidy >= 0);
        BOOST_CHECK(nSubsidy <= REGTEST_POW_SUBSIDY);
        if (nSubsidy > 0 && nSubsidy < REGTEST_POW_SUBSIDY && nHeight >= 5)
            fSawPartial = true;
        nSupply += nSubsidy;
        BOOST_CHECK(nSupply >= nPrevSupply);
        nPrevSupply = nSupply;
        BOOST_CHECK(nSupply <= nCap);
    }
    BOOST_CHECK_EQUAL(nSupply, nCap);
    BOOST_CHECK(fSawPartial);   // the boundary block paid a partial remainder
}

BOOST_AUTO_TEST_SUITE_END()
