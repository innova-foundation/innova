// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Settlement payout clamp (R-RSV-004); the headroom is read from the block's parent.

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

#include "../finality.h"
#include "../key.h"
#include "../main.h"
#include "../subsidy.h"

BOOST_AUTO_TEST_SUITE(settlement_headroom_clamp_tests)

namespace {

// The cap is MAX_MONEY everywhere except regtest, where these two knobs lower
// it far enough for a fixture to sit on the boundary.
struct SupplyCapGuard
{
    int nHeightSaved;
    int64_t nAmountSaved;
    SupplyCapGuard(int nHeight, int64_t nAmount)
        : nHeightSaved(nRegtestSupplyCapHeight), nAmountSaved(nRegtestSupplyCapAmount)
    {
        nRegtestSupplyCapHeight = nHeight;
        nRegtestSupplyCapAmount = nAmount;
    }
    ~SupplyCapGuard()
    {
        nRegtestSupplyCapHeight = nHeightSaved;
        nRegtestSupplyCapAmount = nAmountSaved;
    }
};

// A settlement epoch whose budget is non-zero. A zero budget makes every arm
// below vacuous: the clamp returns 0 before it ever reads the headroom.
bool FindFundedSettlementEpoch(int& nEpochOut, int& nSettlementHeightOut,
                               int64_t& nBudgetOut)
{
    const int nFirstEpoch = GetEpochForHeight(GetForkHeightDAG());
    for (int i = 0; i < 8; i++)
    {
        const int nEpoch = nFirstEpoch + i;
        const int64_t nBudget = GetFinalityEpochBudget(nEpoch);
        if (nBudget <= 0)
            continue;
        const int nBoundary = GetEpochBoundaryHeight(nEpoch, GetForkHeightDAG());
        nEpochOut = nEpoch;
        nSettlementHeightOut = GetFinalitySettlementHeight(nEpoch, nBoundary);
        nBudgetOut = nBudget;
        return true;
    }
    return false;
}

// A bare index carrying only what the clamp reads: its height and the money
// supply folded over its ancestors.
CBlockIndex MakeIndex(int nHeight, int64_t nMoneySupply)
{
    CBlockIndex index;
    index.nHeight = nHeight;
    index.nMoneySupply = nMoneySupply;
    return index;
}

} // namespace

// Headroom above the budget pays the budget; headroom below it pays the
// headroom; no headroom pays nothing.
BOOST_AUTO_TEST_CASE(the_settlement_budget_is_clamped_to_the_issuance_headroom)
{
    BOOST_REQUIRE(fRegTest);

    int nEpoch = 0, nSettlementHeight = 0;
    int64_t nBudget = 0;
    BOOST_REQUIRE_MESSAGE(FindFundedSettlementEpoch(nEpoch, nSettlementHeight, nBudget),
                          "no post-DAG epoch in the first eight carries a non-zero "
                          "finality budget, so the clamp has nothing to clamp");
    BOOST_TEST_MESSAGE("settlement epoch " << nEpoch << " at height " << nSettlementHeight
                       << " with budget " << nBudget);

    const int64_t nCap = nBudget * 1000;
    SupplyCapGuard capGuard(0, nCap);
    BOOST_REQUIRE_EQUAL(GetSupplyCapAmount(), nCap);
    BOOST_REQUIRE(IsSupplyCapActiveAtHeight(nSettlementHeight));

    // Room to spare: the whole budget is payable.
    CBlockIndex idxRoomy = MakeIndex(nSettlementHeight - 1, 0);
    BOOST_CHECK_EQUAL(GetClampedFinalitySettlementBudget(&idxRoomy, nEpoch, 0), nBudget);

    // Less headroom than budget: the headroom is the answer, and the block's own
    // subsidy then has nothing left to take, which is what keeps the total inside
    // the cap.
    const int64_t nTight = nBudget / 3;
    BOOST_REQUIRE(nTight > 0);
    CBlockIndex idxTight = MakeIndex(nSettlementHeight - 1, nCap - nTight);
    BOOST_CHECK_EQUAL(GetClampedFinalitySettlementBudget(&idxTight, nEpoch, 0), nTight);

    // At the cap: nothing is payable and nothing is minted.
    CBlockIndex idxFull = MakeIndex(nSettlementHeight - 1, nCap);
    BOOST_CHECK_EQUAL(GetClampedFinalitySettlementBudget(&idxFull, nEpoch, 0), 0);

    // Past the cap, which a historical chain can be after the cap is lowered.
    CBlockIndex idxOver = MakeIndex(nSettlementHeight - 1, nCap + nBudget);
    BOOST_CHECK_EQUAL(GetClampedFinalitySettlementBudget(&idxOver, nEpoch, 0), 0);
}

// The clamp is not inert: the amount it returns is what each counted voter is
// paid, so clamping the budget clamps the settlement outputs the block must
// carry exactly.
BOOST_AUTO_TEST_CASE(the_clamped_budget_is_what_the_settlement_outputs_pay)
{
    BOOST_REQUIRE(fRegTest);

    int nEpoch = 0, nSettlementHeight = 0;
    int64_t nBudget = 0;
    BOOST_REQUIRE(FindFundedSettlementEpoch(nEpoch, nSettlementHeight, nBudget));

    const int nBoundary = GetEpochBoundaryHeight(nEpoch, GetForkHeightDAG());
    std::vector<CFinalityVote> vVotes;
    for (int i = 0; i < 2; i++)
    {
        CKey key;
        key.MakeNewKey(true);
        CPubKey pubkey = key.GetPubKey();

        CFinalityVote vote;
        vote.nProofMode = FINALITY_PROOF_TRANSPARENT;
        vote.nEpoch = nEpoch;
        vote.nHeight = nBoundary;
        vote.nVoteWeight = 100000 * COIN;
        vote.nReward = GetFinalityVoteRewardAtHeight(vote.nVoteWeight, nBoundary);
        vote.vchPubKey = std::vector<unsigned char>(pubkey.begin(), pubkey.end());
        CHashWriter nf(SER_GETHASH, 0);
        nf << vote.vchPubKey;
        nf << nEpoch;
        vote.nullifier = nf.GetHash();
        BOOST_REQUIRE_MESSAGE(vote.nReward > 0,
                              "a zero-entitlement voter is not a payee, so the split "
                              "below would have nothing to divide");
        vVotes.push_back(vote);
    }

    const int64_t nCap = nBudget * 1000;
    SupplyCapGuard capGuard(0, nCap);

    CBlockIndex idxRoomy = MakeIndex(nSettlementHeight - 1, 0);
    const int64_t nTight = nBudget / 3;
    BOOST_REQUIRE(nTight > 0);
    CBlockIndex idxTight = MakeIndex(nSettlementHeight - 1, nCap - nTight);

    std::vector<CTxOut> vRoomy, vTight;
    int64_t nRoomyTotal = 0, nTightTotal = 0;
    std::string strError;
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(
        vVotes, GetClampedFinalitySettlementBudget(&idxRoomy, nEpoch, 0),
        vRoomy, nRoomyTotal, &strError));
    BOOST_REQUIRE(BuildFinalitySettlementOutputs(
        vVotes, GetClampedFinalitySettlementBudget(&idxTight, nEpoch, 0),
        vTight, nTightTotal, &strError));

    BOOST_CHECK_EQUAL(vRoomy.size(), vVotes.size());
    BOOST_CHECK_EQUAL(nRoomyTotal, (nBudget / 2) * 2);
    BOOST_CHECK_EQUAL(nTightTotal, (nTight / 2) * 2);
    BOOST_CHECK_MESSAGE(nTightTotal < nRoomyTotal,
                        "the clamped budget paid the same as the unclamped one ("
                        << nTightTotal << "), so the clamp moved no money and the "
                        "arms above cannot see it");
}

// Which index the headroom is read from. The parent and the settlement block
// itself carry different money supplies, so the two answers differ: this is the
// assertion a caller that read the block's own index would fail.
BOOST_AUTO_TEST_CASE(the_headroom_is_read_from_the_settlement_block_parent)
{
    BOOST_REQUIRE(fRegTest);

    int nEpoch = 0, nSettlementHeight = 0;
    int64_t nBudget = 0;
    BOOST_REQUIRE(FindFundedSettlementEpoch(nEpoch, nSettlementHeight, nBudget));

    const int64_t nCap = nBudget * 1000;
    SupplyCapGuard capGuard(0, nCap);

    // The parent is near the cap; the settlement block's own index carries the
    // supply a block still being connected carries, which is not yet its own.
    const int64_t nTight = nBudget / 4;
    BOOST_REQUIRE(nTight > 0);
    CBlockIndex idxParent = MakeIndex(nSettlementHeight - 1, nCap - nTight);
    CBlockIndex idxSelf = MakeIndex(nSettlementHeight, 0);

    const int64_t nFromParent = GetClampedFinalitySettlementBudget(&idxParent, nEpoch, 0);
    const int64_t nFromSelf = GetClampedFinalitySettlementBudget(&idxSelf, nEpoch, 0);

    BOOST_CHECK_EQUAL(nFromParent, nTight);
    BOOST_CHECK_EQUAL(nFromSelf, nBudget);
    BOOST_CHECK_MESSAGE(nFromParent != nFromSelf,
                        "the parent and the settlement block answer the same, so this "
                        "case cannot tell which index the clamp reads");
}

BOOST_AUTO_TEST_SUITE_END()
