// A heavier chain forking below the finalized height stays a side block, and neither
// ReselectBestValidChain nor the miner builds on it. Mines past Boundary A; linked last
// in TEST_OBJS; synthetic g_dagManager anchors are restored by the last case.

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

// The tip a node would hold. With the anchors gone, a held block that outweighs the tip
// is eligible and the next reselection switches to it; later suites inherit that tip.
void ReselectTip()
{
    CBlockIndex* pTip = BestIndex();
    BOOST_REQUIRE(Invalidate(pTip));
    BOOST_REQUIRE(Reconsider(pTip));
}

// The epoch builder carries the previous record's finalized height into the next record
// and persists it, so an epoch must not complete while a synthetic anchor is in force.
// Mines to the next boundary when fewer than nBlocks remain before it.
void KeepEpochClearFor(int nBlocks)
{
    const int nTip = BestIndex()->nHeight;
    const int nNext = GetEpochBoundaryHeight(GetEpochForHeight(nTip) + 1, nTip);
    if (nNext - nTip < nBlocks)
        MineTo(nNext);
}

// Finalized heights for consecutive epochs from nFirstEpoch, over the chain's own records.
// Only the finalized height and its block change; the curve root is emptied to match the
// empty tree. Restore puts back the displaced records and any above them.
struct InstalledFinalizedHeights
{
    int nFirstEpoch;
    std::map<int, CEpochState> saved;
    std::map<int, CCurveTree> savedTrees;

    InstalledFinalizedHeights() : nFirstEpoch(-1) {}

    void Install(int nFirst, const std::vector<int>& vFinalized)
    {
        Restore();
        nFirstEpoch = nFirst;
        const int nLast = GetEpochForHeight(BestIndex()->nHeight) + 1;
        CTxDB txdb("r");
        for (int e = nFirst; e <= nLast; e++)
        {
            CEpochState state;
            if (!g_dagManager.GetEpochState(e, state))
                continue;
            // The tree the record was written with, so the root goes back as it was.
            CCurveTree tree;
            if (txdb.ReadCurveTreeAtEpoch(e, tree) && tree.nLeafCount != 0)
                savedTrees[e] = tree;
            else
            {
                state.hashCurveRoot = 0;
                savedTrees[e] = CCurveTree();
            }
            saved[e] = state;
        }

        std::map<int, CEpochState> states;
        std::map<int, CCurveTree> trees;
        for (size_t i = 0; i < vFinalized.size(); i++)
        {
            const int nEpoch = nFirst + (int)i;
            CEpochState state;
            if (!g_dagManager.GetEpochState(nEpoch, state))
                state.nEpoch = nEpoch;
            state.hashCurveRoot = 0;
            state.nFinalizedHeightAsOf = vFinalized[i];
            state.hashVNextFinalizedAnchor = 0;
            if (vFinalized[i] > 0)
            {
                CBlockIndex* pAttested = AncestorAt(BestIndex(), vFinalized[i]);
                BOOST_REQUIRE(pAttested && pAttested->nHeight == vFinalized[i]);
                state.hashVNextFinalizedAnchor = pAttested->GetBlockHash();
            }
            states[nEpoch] = state;
            trees[nEpoch] = CCurveTree();
        }
        BOOST_REQUIRE_MESSAGE(g_dagManager.InstallEpochStateBatch(nFirst, states, trees),
                              "could not install the finalized-height records");
    }

    void Restore()
    {
        if (nFirstEpoch < 0)
            return;
        BOOST_CHECK_MESSAGE(g_dagManager.InstallEpochStateBatch(nFirstEpoch, saved, savedTrees),
                            "could not put the displaced epoch records back");
        nFirstEpoch = -1;
        saved.clear();
        savedTrees.clear();
    }
};

// For a single case: put back on exit, including an aborted one.
struct ScopedFinalizedHeights : public InstalledFinalizedHeights
{
    ~ScopedFinalizedHeights() { Restore(); }
};

// Every epoch record in memory is one the chain could have built, and the disk copy agrees.
// Catches an anchor this suite installed and did not restore.
void CheckEpochRecordsAreTheChains(const char* pszWhen)
{
    CBlockIndex* pTip = BestIndex();
    const int nLast = GetEpochForHeight(pTip->nHeight) + 1;
    CTxDB txdb("r");
    int nSeen = 0;
    for (int e = 0; e <= nLast; e++)
    {
        CEpochState state;
        if (!g_dagManager.GetEpochState(e, state))
        {
            BOOST_CHECK_MESSAGE(txdb.ProbeEpochState(e) == TXDB_READ_NOT_FOUND,
                                pszWhen << ": epoch " << e << " is on disk but not in memory");
            continue;
        }
        nSeen++;
        const int nFin = state.nFinalizedHeightAsOf;
        BOOST_CHECK_MESSAGE(nFin == 0 || (IsEpochBoundaryHeight(nFin) && nFin <= state.nHeightEnd),
                            pszWhen << ": epoch " << e << " names finalized height " << nFin
                            << ", which is not a boundary at or below its end " << state.nHeightEnd);
        if (nFin != 0)
        {
            const CBlockIndex* pAt = AncestorAt(pTip, nFin);
            BOOST_CHECK_MESSAGE(pAt && pAt->nHeight == nFin &&
                                pAt->GetBlockHash() == state.FinalizedAnchorHash(),
                                pszWhen << ": epoch " << e << " names a finalized block at "
                                << nFin << " that the tip's chain does not carry");
        }
        CEpochState onDisk;
        BOOST_CHECK_MESSAGE(txdb.ReadEpochState(e, onDisk) && onDisk.nEpoch == e &&
                            onDisk.nFinalizedHeightAsOf == nFin &&
                            onDisk.hashBoundaryBlock == state.hashBoundaryBlock,
                            pszWhen << ": epoch " << e << " differs between memory and disk");
    }
    BOOST_CHECK_MESSAGE(nSeen > 0, pszWhen << ": no epoch record in memory");
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
// The anchors the first three cases share; the third puts them back.
InstalledFinalizedHeights g_anchors;

} // namespace

// Fork above the latch anchor, below the rejection anchor: the verdict is retryable.
BOOST_AUTO_TEST_CASE(a_heavier_branch_below_the_anchor_is_kept_as_a_side_block)
{
    BOOST_REQUIRE(fRegTest);
    MineTo(FORK_HEIGHT_EPOCH_STATE_V3 + 20);
    // The branches, the held block and the two blocks the third case mines all stay
    // inside the current epoch.
    KeepEpochClearFor(20);
    BuildBranches(g_transient, 13);

    const int nAsOf = GetEpochForHeight(g_transient.pTipA->nHeight) - 1;
    g_anchors.Install(nAsOf, std::vector<int>(1, g_transient.pFork->nHeight + 3));
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
    g_anchors.Restore();
}

// Fork below the latch anchor: the verdict is permanent on this node. Before the gate
// this flagged the block BLOCK_FAILED_VALID and stripped its vertex, on this node only.
BOOST_AUTO_TEST_CASE(a_permanently_refused_branch_is_kept_as_a_side_block_too)
{
    BOOST_REQUIRE(fRegTest);
    g_anchors.Restore(); // in case the third case did not reach it
    // The latch epoch has to be a V3 epoch with a record of its own.
    const int nV3Epoch = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3);
    while (GetEpochForHeight(BestIndex()->nHeight) - REORG_LATCH_ANCHOR_LAG_EPOCHS <= nV3Epoch)
        MineTo(BestIndex()->nHeight + 50);
    KeepEpochClearFor(20);
    HeavierSideBranch s;
    BuildBranches(s, 13);

    const int nAsOf = GetEpochForHeight(s.pTipA->nHeight) - 1;
    const int nLatch = nAsOf - (REORG_LATCH_ANCHOR_LAG_EPOCHS - 1);
    std::vector<int> vFinalized;
    for (int e = nLatch; e <= nAsOf; e++)
        vFinalized.push_back(s.pFork->nHeight + 1 + (e - nLatch));
    ScopedFinalizedHeights anchors;
    anchors.Install(nLatch, vFinalized);
    CheckHeldBlockIsKeptAsSideBlock(s, REORG_FINALITY_REJECT_PERMANENT);
    BOOST_CHECK(Reconsider(s.pTipA));
    BOOST_CHECK(BestIndex() == s.pTipA);
}

// Whatever ran above, the records this suite leaves are the chain's.
BOOST_AUTO_TEST_CASE(epoch_records_leave_as_the_chain_built_them)
{
    BOOST_REQUIRE(fRegTest);
    g_anchors.Restore();
    ReselectTip();
    CheckEpochRecordsAreTheChains("on exit");
}

BOOST_AUTO_TEST_SUITE_END()
