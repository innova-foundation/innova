// A heavier chain this node may not switch to.
//
// The reorg finality guard refuses a switch whose fork with the tip lies below the
// deterministic finalized height. The verdict is relative to this node's tip: a node
// further along reaches a different one for the same block, and a synced node never
// evaluates it at all because its tip outweighs the block. So it cannot become a
// statement about the block. AddToBlockIndex decides eligibility before it attempts
// SetBestChain and keeps an ineligible heavier block as a side block -- not erased
// (re-requested forever), not flagged (condemned on one node only). The selection
// sites -- ReselectBestValidChain and the miner's template parent -- pass such a
// block over instead of failing on it or building on it.
//
// The heavier branch is built with the node's own machinery: the tip's next block is
// solved and held, the tip is rolled back with InvalidateBlock, a sibling branch of
// equal length is mined and its next block held too, then both branches are restored.
// Block trust carries a small hash-dependent term, so the two equal-length branches
// never tie: the heavier one is the tip and the held block that extends the other is
// heavier than the tip by one block. Finality anchors are then installed above the
// fork, and that held block arrives.
//
// Mines past Boundary A on the shared regtest fixture; linked last in TEST_OBJS.

#include <boost/test/unit_test.hpp>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "../bignum.h"
#include "../dag.h"
#include "../finality.h"
#include "../init.h"
#include "../main.h"
#include "../miner.h"
#include "../txdb.h"
#include "../uint256.h"
#include "../wallet.h"

extern bool fRegTest;

BOOST_AUTO_TEST_SUITE(finality_switch_gate_tests)

namespace
{

bool SolveBlock(CBlock* pblock)
{
    CBigNum target;
    target.SetCompact(pblock->nBits);
    const uint256 hashTarget = target.getuint256();
    unsigned int nHashes = 0;
    while (pblock->GetPoWHash() > hashTarget)
    {
        ++pblock->nNonce;
        if (pblock->nNonce == 0)
            ++pblock->nTime;
        if (++nHashes > 4000000U)
            return false;
    }
    return true;
}

CBlockIndex* BestIndex()
{
    LOCK(cs_main);
    return pindexBest;
}

// Solved on the current tip, not processed.
std::unique_ptr<CBlock> BuildBlockOnTip()
{
    unsigned int nExtraNonce = 0;
    CBlockIndex* pindexPrev = BestIndex();
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblock.get() != NULL);
    IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);
    BOOST_REQUIRE(SolveBlock(pblock.get()));
    BOOST_REQUIRE(pblock->hashPrevBlock == pindexPrev->GetBlockHash());
    return pblock;
}

CBlockIndex* MineOne()
{
    std::unique_ptr<CBlock> pblock = BuildBlockOnTip();
    const uint256 hash = pblock->GetHash();
    BOOST_REQUIRE(ProcessBlock(NULL, pblock.get()));
    LOCK(cs_main);
    BOOST_REQUIRE(mapBlockIndex.count(hash) != 0);
    return mapBlockIndex[hash];
}

void MineTo(int nTarget)
{
    while (BestIndex()->nHeight < nTarget)
        MineOne();
}

CBlockIndex* AncestorAt(CBlockIndex* pindex, int nHeight)
{
    while (pindex && pindex->nHeight > nHeight)
        pindex = pindex->pprev;
    return pindex;
}

bool Invalidate(CBlockIndex* pindex)
{
    LOCK(cs_main);
    CTxDB txdb;
    std::string strError;
    const bool fOK = InvalidateBlock(txdb, pindex, strError);
    BOOST_CHECK_MESSAGE(fOK, strError);
    return fOK;
}

bool Reconsider(CBlockIndex* pindex)
{
    LOCK(cs_main);
    CTxDB txdb;
    std::string strError;
    const bool fOK = ReconsiderBlock(txdb, pindex, strError);
    BOOST_CHECK_MESSAGE(fOK, strError);
    return fOK;
}

// Finalized heights for consecutive epochs from nFirstEpoch, over the records the
// chain produced (the fixture never votes, so they say 0). Only the finalized height
// changes; the curve root is emptied to match the empty tree installed with it.
void InstallFinalizedHeights(int nFirstEpoch, const std::vector<int>& vFinalized)
{
    std::map<int, CEpochState> states;
    std::map<int, CCurveTree> trees;
    for (size_t i = 0; i < vFinalized.size(); i++)
    {
        const int nEpoch = nFirstEpoch + (int)i;
        CEpochState state;
        if (!g_dagManager.GetEpochState(nEpoch, state))
            state.nEpoch = nEpoch;
        state.hashCurveRoot = 0;
        state.nFinalizedHeightAsOf = vFinalized[i];
        states[nEpoch] = state;
        trees[nEpoch] = CCurveTree();
    }
    BOOST_REQUIRE_MESSAGE(g_dagManager.InstallEpochStateBatch(nFirstEpoch, states, trees),
                          "could not install the finalized-height records");
}

struct HeavierSideBranch
{
    CBlockIndex* pFork = NULL;
    CBlockIndex* pTipA = NULL;   // the chain this node stays on (the heavier of the two)
    CBlockIndex* pTipB = NULL;   // the sibling branch, equal length, indexed
    std::unique_ptr<CBlock> pHeld; // B's next block: heavier than A's tip, not processed
};

// Two branches of equal length above the fork, both restored; the heavier is the tip
// and the next block of the other is held.
void BuildBranches(HeavierSideBranch& s, int nLength)
{
    s.pFork = BestIndex();
    MineTo(s.pFork->nHeight + nLength);
    CBlockIndex* pTipFirst = BestIndex();
    std::unique_ptr<CBlock> pHeldFirst = BuildBlockOnTip();
    CBlockIndex* pA1 = AncestorAt(pTipFirst, s.pFork->nHeight + 1);
    BOOST_REQUIRE(pA1 && pA1->pprev == s.pFork);

    BOOST_REQUIRE(Invalidate(pA1));
    BOOST_REQUIRE(BestIndex() == s.pFork);
    MineTo(s.pFork->nHeight + nLength);
    CBlockIndex* pTipSecond = BestIndex();
    BOOST_REQUIRE(pTipSecond != pTipFirst);
    std::unique_ptr<CBlock> pHeldSecond = BuildBlockOnTip();
    CBlockIndex* pB1 = AncestorAt(pTipSecond, s.pFork->nHeight + 1);
    BOOST_REQUIRE(pB1 && pB1->pprev == s.pFork);

    BOOST_REQUIRE(Invalidate(pB1));
    BOOST_REQUIRE(BestIndex() == s.pFork);
    BOOST_REQUIRE(Reconsider(pA1));
    BOOST_REQUIRE(BestIndex() == pTipFirst);
    BOOST_REQUIRE(Reconsider(pB1));
    BOOST_REQUIRE(!pTipFirst->IsInvalid() && !pTipSecond->IsInvalid());
    BOOST_REQUIRE(pTipFirst->nChainTrust != pTipSecond->nChainTrust);
    const bool fFirstIsTip = pTipFirst->nChainTrust > pTipSecond->nChainTrust;
    BOOST_REQUIRE(BestIndex() == (fFirstIsTip ? pTipFirst : pTipSecond));
    s.pTipA = fFirstIsTip ? pTipFirst : pTipSecond;
    s.pTipB = fFirstIsTip ? pTipSecond : pTipFirst;
    s.pHeld = std::move(fFirstIsTip ? pHeldSecond : pHeldFirst);
    BOOST_REQUIRE(s.pHeld->hashPrevBlock == s.pTipB->GetBlockHash());
}

void CheckHeldBlockIsKeptAsSideBlock(HeavierSideBranch& s, ReorgFinalityVerdict expected)
{
    int nForkHeight = 0, nFinalCur = 0, nFinalLatch = 0, nAsOfEpoch = 0;
    BOOST_REQUIRE_EQUAL((int)BestChainSwitchVerdict(s.pTipB, nForkHeight, nFinalCur, nFinalLatch,
                                                    nAsOfEpoch),
                        (int)expected);
    BOOST_REQUIRE_EQUAL(nForkHeight, s.pFork->nHeight);

    const uint256 hash = s.pHeld->GetHash();
    s.pHeld->nDoS = 0;
    BOOST_CHECK_MESSAGE(ProcessBlock(NULL, s.pHeld.get()), "the heavier side block was refused");
    BOOST_CHECK_EQUAL(s.pHeld->nDoS, 0);

    LOCK(cs_main);
    BOOST_REQUIRE_MESSAGE(mapBlockIndex.count(hash) != 0,
                          "the heavier side block was erased (re-request loop)");
    const CBlockIndex* pindex = mapBlockIndex[hash];
    BOOST_CHECK_MESSAGE(!pindex->IsInvalid(), "a finality verdict was persisted as invalidity");
    BOOST_CHECK(pindex->nChainTrust > s.pTipA->nChainTrust);
    BOOST_CHECK(g_dagManager.HasDAGData(hash));
    CTxDB txdb("r");
    CBlockDAGData data;
    BOOST_CHECK(txdb.ReadDAGLinks(hash, data));
    BOOST_CHECK_MESSAGE(pindexBest == s.pTipA, "the tip moved to a chain below the finality anchor");
}

HeavierSideBranch g_transient;

} // namespace

// Fork above the latch anchor, below the rejection anchor: the verdict is retryable.
BOOST_AUTO_TEST_CASE(a_heavier_branch_below_the_anchor_is_kept_as_a_side_block)
{
    BOOST_REQUIRE(fRegTest);
    MineTo(FORK_HEIGHT_EPOCH_STATE_V3 + 20);
    BuildBranches(g_transient, 13);

    const int nAsOf = GetEpochForHeight(g_transient.pTipA->nHeight) - 1;
    InstallFinalizedHeights(nAsOf, std::vector<int>(1, g_transient.pFork->nHeight + 3));
    CheckHeldBlockIsKeptAsSideBlock(g_transient, REORG_FINALITY_REJECT_TRANSIENT);
}

// With the heavier ineligible side block indexed, the recovery RPC's reselection must
// pass over it rather than fail on it: the observed post-reconsider failure.
BOOST_AUTO_TEST_CASE(reselection_passes_over_the_ineligible_heavier_tip)
{
    BOOST_REQUIRE(g_transient.pTipA != NULL);
    BOOST_REQUIRE(BestIndex() == g_transient.pTipA);
    BOOST_CHECK(Reconsider(g_transient.pTipA));
    BOOST_CHECK(BestIndex() == g_transient.pTipA);
}

// The miner keeps building on the tip it may extend; its solved blocks connect.
BOOST_AUTO_TEST_CASE(the_miner_builds_on_the_switchable_tip)
{
    BOOST_REQUIRE(g_transient.pTipA != NULL);
    BOOST_REQUIRE(BestIndex() == g_transient.pTipA);
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblock.get() != NULL);
    BOOST_CHECK_MESSAGE(pblock->hashPrevBlock == g_transient.pTipA->GetBlockHash(),
                        "the template builds on a tip this node may not switch to");

    CBlockIndex* pindexNext = MineOne();
    BOOST_CHECK(pindexNext->pprev == g_transient.pTipA);
    BOOST_CHECK(BestIndex() == pindexNext);
    CBlockIndex* pindexAfter = MineOne();
    BOOST_CHECK(BestIndex() == pindexAfter);
    BOOST_CHECK(AncestorAt(pindexAfter, g_transient.pTipA->nHeight) == g_transient.pTipA);
}

// Fork below the latch anchor: the verdict is permanent on this node. Before the gate
// this flagged the block BLOCK_FAILED_VALID and stripped its vertex, on this node only.
BOOST_AUTO_TEST_CASE(a_permanently_refused_branch_is_kept_as_a_side_block_too)
{
    BOOST_REQUIRE(fRegTest);
    // The latch epoch has to be a V3 epoch with a record of its own.
    const int nV3Epoch = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3);
    while (GetEpochForHeight(BestIndex()->nHeight) - REORG_LATCH_ANCHOR_LAG_EPOCHS <= nV3Epoch)
        MineTo(BestIndex()->nHeight + 50);
    HeavierSideBranch s;
    BuildBranches(s, 13);

    const int nAsOf = GetEpochForHeight(s.pTipA->nHeight) - 1;
    const int nLatch = nAsOf - (REORG_LATCH_ANCHOR_LAG_EPOCHS - 1);
    std::vector<int> vFinalized;
    for (int e = nLatch; e <= nAsOf; e++)
        vFinalized.push_back(s.pFork->nHeight + 1 + (e - nLatch));
    InstallFinalizedHeights(nLatch, vFinalized);
    CheckHeldBlockIsKeptAsSideBlock(s, REORG_FINALITY_REJECT_PERMANENT);
    BOOST_CHECK(Reconsider(s.pTipA));
    BOOST_CHECK(BestIndex() == s.pTipA);
}

BOOST_AUTO_TEST_SUITE_END()
