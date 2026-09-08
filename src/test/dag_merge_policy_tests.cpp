// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Which DAG tips a template may merge: not one forked deeper than DAG_MERGE_DEPTH, nor
// one on a refused finality branch. Linked after finality_switch_gate_tests.

#include <boost/test/unit_test.hpp>

#include <algorithm>
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

BOOST_AUTO_TEST_SUITE(dag_merge_policy_tests)

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

// The parent is whatever the template chose: on a fixture other suites have left side
// branches in, SelectBestDAGTip does not always return pindexBest.
CBlockIndex* MineOne()
{
    unsigned int nExtraNonce = 0;
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblock.get() != NULL);
    CBlockIndex* pindexPrev = NULL;
    {
        LOCK(cs_main);
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(pblock->hashPrevBlock);
        BOOST_REQUIRE(mi != mapBlockIndex.end());
        pindexPrev = mi->second;
    }
    IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);
    BOOST_REQUIRE(SolveBlock(pblock.get()));
    const uint256 hash = pblock->GetHash();
    BOOST_REQUIRE(ProcessBlock(NULL, pblock.get()));
    LOCK(cs_main);
    BOOST_REQUIRE(mapBlockIndex.count(hash) != 0);
    return mapBlockIndex[hash];
}

// Mine until the template builds on the node's own best chain, past any side branches
// left by other suites.
void SettleOnMainChain()
{
    for (int i = 0; i < 300; i++)
    {
        CBlockIndex* pBefore = BestIndex();
        std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
        BOOST_REQUIRE(pblock.get() != NULL);
        if (pblock->hashPrevBlock == pBefore->GetBlockHash())
            return;
        MineOne();
    }
    BOOST_FAIL("the template never settled on the node's own best chain");
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

// A side branch of nSide blocks against a main branch of nMain, both above the same fork,
// with the main branch left as the tip. The side tip is indexed, unflagged, and carries a
// DAG vertex, so it is a merge candidate on every count but the two under test.
struct SideBranch
{
    CBlockIndex* pFork = NULL;
    CBlockIndex* pSideTip = NULL;
    CBlockIndex* pMainTip = NULL;
};

void BuildSideBranch(SideBranch& s, int nSide, int nMain)
{
    BOOST_REQUIRE(nMain > nSide);
    SettleOnMainChain();
    s.pFork = BestIndex();
    MineTo(s.pFork->nHeight + nSide);
    s.pSideTip = BestIndex();
    CBlockIndex* pSide1 = AncestorAt(s.pSideTip, s.pFork->nHeight + 1);
    BOOST_REQUIRE(pSide1 && pSide1->pprev == s.pFork);

    BOOST_REQUIRE(Invalidate(pSide1));
    BOOST_REQUIRE(BestIndex() == s.pFork);
    SettleOnMainChain();
    BOOST_REQUIRE_MESSAGE(BestIndex() == s.pFork, "the template left the fork point");
    MineTo(s.pFork->nHeight + nMain);
    // Chain trust on a DAG counts merged parents, so a longer branch is not automatically
    // the heavier one. Outgrow the side branch by trust, not by height, or reconsidering it
    // hands it the tip.
    int nGuard = 0;
    while (BestIndex()->nChainTrust <= s.pSideTip->nChainTrust)
    {
        MineOne();
        BOOST_REQUIRE_MESSAGE(++nGuard < 500, "the main branch could not outgrow the side branch");
    }
    s.pMainTip = BestIndex();

    BOOST_REQUIRE(Reconsider(pSide1));
    BOOST_REQUIRE_MESSAGE(BestIndex() == s.pMainTip,
                          "the side branch took the tip: main=" +
                              std::to_string(s.pMainTip->nHeight) + " now=" +
                              std::to_string(BestIndex()->nHeight));
    BOOST_REQUIRE_MESSAGE(!s.pSideTip->IsInvalid(), "the side tip stayed flagged");
    BOOST_REQUIRE(!s.pSideTip->IsInMainChain());

    LOCK2(cs_main, g_dagManager.cs_dag);
    std::vector<uint256> vTips = g_dagManager.GetDAGTips();
    BOOST_REQUIRE_MESSAGE(std::find(vTips.begin(), vTips.end(), s.pSideTip->GetBlockHash()) !=
                              vTips.end(),
                          "the side tip is not a DAG tip: there is nothing to merge");
}

// The parent set a produced template commits to, read with the decoder its height selects --
// the same one the validity gate and the fetch paths use.
std::vector<uint256> DAGParentsOf(const CBlock& block, int nHeight)
{
    std::vector<uint256> vParents;
    if (block.vtx.empty())
        return vParents;
    std::vector<CScript> vScripts;
    for (std::vector<CTxOut>::const_iterator it = block.vtx[0].vout.begin();
         it != block.vtx[0].vout.end(); ++it)
        vScripts.push_back(it->scriptPubKey);
    std::string strError;
    if (!ReadDAGParentCommitmentAtHeight(vScripts, nHeight, vParents, strError))
        vParents.clear();
    return vParents;
}

// The merge parents of a freshly produced template. Also asserts the parent cap did not
// bind, so an absent tip is a policy decision and not a full set.
std::vector<uint256> TemplateMergeParents()
{
    CBlockIndex* pPrev = BestIndex();
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblock.get() != NULL);
    std::vector<uint256> vParents = DAGParentsOf(*pblock, pPrev->nHeight + 1);
    BOOST_REQUIRE_MESSAGE(!vParents.empty(), "the template committed no DAG parents at all");
    BOOST_REQUIRE_MESSAGE(vParents.size() < MaxDAGParentsAtHeight(pPrev->nHeight + 1),
                          "the parent cap bound the set, so an absent tip proves nothing");
    return std::vector<uint256>(vParents.begin() + 1, vParents.end());
}

bool TemplateMerges(const uint256& hashTip)
{
    std::vector<uint256> v = TemplateMergeParents();
    return std::find(v.begin(), v.end(), hashTip) != v.end();
}

// Replaces the epoch-state suffix from nFirstEpoch and restores it, re-installing the
// captured finalized heights against empty trees (only those heights feed the verdict).
struct ScopedFinalizedHeights
{
    int nFirstEpoch;
    std::map<int, CEpochState> savedStates;
    std::map<int, CCurveTree> savedTrees;

    // vFinalized empty installs an empty suffix, i.e. removes the records: the missing-state
    // case.
    ScopedFinalizedHeights(int nFirst, const std::vector<int>& vFinalized) : nFirstEpoch(nFirst)
    {
        const int nLast = GetEpochForHeight(BestIndex()->nHeight) + 2;
        for (int e = nFirstEpoch; e <= nLast; e++)
        {
            CEpochState state;
            if (!g_dagManager.GetEpochState(e, state))
                continue;
            state.hashCurveRoot = 0;
            savedStates[e] = state;
            savedTrees[e] = CCurveTree();
        }

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
            // The record names the tip's block at that height, as a real record would.
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
        BOOST_REQUIRE_MESSAGE(g_dagManager.InstallEpochStateBatch(nFirstEpoch, states, trees),
                              "could not install the finalized-height records");
    }

    ~ScopedFinalizedHeights()
    {
        g_dagManager.InstallEpochStateBatch(nFirstEpoch, savedStates, savedTrees);
    }
};

// The chain has to be deep enough that the latch epoch is a V3 epoch with a record of its
// own, or the permanent verdict is unreachable.
void MineForPermanentVerdict()
{
    const int nV3Epoch = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3);
    MineTo(FORK_HEIGHT_EPOCH_STATE_V3 + 20);
    while (GetEpochForHeight(BestIndex()->nHeight) - REORG_LATCH_ANCHOR_LAG_EPOCHS < nV3Epoch)
        MineTo(BestIndex()->nHeight + 50);
}

} // namespace

// A tip whose fork with the template parent is deeper than DAG_MERGE_DEPTH is not merged; one
// within it still is. The pre-existing height filter does not cover this: it measures the
// tip's own height, which a long branch keeps close to the tip while its fork stays far below.
BOOST_AUTO_TEST_CASE(a_tip_forking_deeper_than_the_merge_depth_is_not_merged)
{
    BOOST_REQUIRE(fRegTest);
    MineTo(FORK_HEIGHT_DAG + 5);

    SideBranch deep;
    BuildSideBranch(deep, DAG_MERGE_DEPTH + 4, DAG_MERGE_DEPTH + 6);
    const uint256 hashDeep = deep.pSideTip->GetBlockHash();

    // Asserted on the very next template, before anything further is mined: without the
    // filter the next block merges this tip, and that block then stops it being a DAG tip,
    // so a later template would show it absent for the wrong reason.
    CBlockIndex* pPrev = BestIndex();
    BOOST_REQUIRE(deep.pSideTip->nHeight >= pPrev->nHeight - DAG_MERGE_DEPTH);
    BOOST_REQUIRE(deep.pSideTip->nHeight < pPrev->nHeight + 1);
    BOOST_REQUIRE(deep.pSideTip->nChainTrust <= pPrev->nChainTrust);
    BOOST_REQUIRE(pPrev->nHeight - deep.pFork->nHeight > DAG_MERGE_DEPTH);
    BOOST_CHECK_MESSAGE(!TemplateMerges(hashDeep),
                        "the template merged a tip whose fork lies deeper than the merge depth");

    // Control on the same filter: a tip forking within the depth is still merged.
    SideBranch near;
    BuildSideBranch(near, 3, 5);
    const uint256 hashNear = near.pSideTip->GetBlockHash();
    CBlockIndex* pPrev2 = BestIndex();
    BOOST_REQUIRE(pPrev2->nHeight - near.pFork->nHeight <= DAG_MERGE_DEPTH);
    BOOST_CHECK_MESSAGE(TemplateMerges(hashNear),
                        "the fork-depth filter also refused a tip forking within the depth");
}

// A branch this node may never switch to is not merged: the block that merges it cannot be
// served past to any peer that lacks the branch, and no node inside the tolerated skew can
// adopt it either.
BOOST_AUTO_TEST_CASE(a_permanently_refused_branch_tip_is_not_merged)
{
    BOOST_REQUIRE(fRegTest);
    MineForPermanentVerdict();

    SideBranch s;
    BuildSideBranch(s, 3, 5);
    const uint256 hashSide = s.pSideTip->GetBlockHash();

    // Without an anchor above the fork the tip is ordinary and is merged.
    BOOST_REQUIRE_MESSAGE(TemplateMerges(hashSide),
                          "the tip was already unmergeable before any anchor was installed");

    const int nAsOf = GetEpochForHeight(BestIndex()->nHeight) - 1;
    const int nLatch = nAsOf - (REORG_LATCH_ANCHOR_LAG_EPOCHS - 1);
    BOOST_REQUIRE(nLatch >= GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3));
    std::vector<int> vFinalized(nAsOf - nLatch + 1, s.pFork->nHeight + 1);
    ScopedFinalizedHeights anchors(nLatch, vFinalized);

    int nForkHeight = 0, nFinalCur = 0, nFinalLatch = 0, nAsOfEpoch = 0;
    BOOST_REQUIRE_EQUAL((int)BestChainSwitchVerdict(s.pSideTip, nForkHeight, nFinalCur,
                                                    nFinalLatch, nAsOfEpoch),
                        (int)REORG_FINALITY_REJECT_PERMANENT);

    BOOST_CHECK_MESSAGE(!TemplateMerges(hashSide),
                        "the template merged the tip of a branch this node may never adopt");
}

// A missing epoch state must not stop merging. Parent selection sweeps the whole block index
// first and finds every candidate ineligible, so a memo shared between it and the merge loop
// decides merging too unless it holds the raw verdict rather than either predicate's answer.
BOOST_AUTO_TEST_CASE(a_missing_epoch_state_does_not_stop_the_miner_merging)
{
    BOOST_REQUIRE(fRegTest);
    MineForPermanentVerdict();

    SideBranch s;
    BuildSideBranch(s, 3, 5);
    const uint256 hashSide = s.pSideTip->GetBlockHash();
    BOOST_REQUIRE_MESSAGE(TemplateMerges(hashSide),
                          "the tip was already unmergeable before the state gap");

    const int nAsOf = GetEpochForHeight(BestIndex()->nHeight) - 1;
    ScopedFinalizedHeights gap(nAsOf, std::vector<int>());

    int nForkHeight = 0, nFinalCur = 0, nFinalLatch = 0, nAsOfEpoch = 0;
    BOOST_REQUIRE_EQUAL((int)BestChainSwitchVerdict(s.pSideTip, nForkHeight, nFinalCur,
                                                    nFinalLatch, nAsOfEpoch),
                        (int)REORG_FINALITY_STATE_MISSING);
    // The tip itself draws the same verdict, which is what empties parent selection's result
    // and makes it sweep and memoise every index entry.
    BOOST_REQUIRE_EQUAL((int)BestChainSwitchVerdict(BestIndex(), nForkHeight, nFinalCur,
                                                    nFinalLatch, nAsOfEpoch),
                        (int)REORG_FINALITY_STATE_MISSING);

    BOOST_CHECK_MESSAGE(TemplateMerges(hashSide),
                        "DAG merging stopped during an epoch-state gap");
}

// The bound is a closed interval on the fork depth. The floor has to be tested before either
// side of the walk steps: two distinct blocks already at the floor can only meet below it,
// which is a fork one deeper than the bound.
BOOST_AUTO_TEST_CASE(the_merge_depth_bound_is_closed_at_the_depth_and_open_one_past_it)
{
    BOOST_REQUIRE(fRegTest);
    MineTo(FORK_HEIGHT_DAG + 5);

    // Exactly at the bound: merged. The side tip is held out of the DAG tip set while the
    // main chain climbs, so the climb cannot merge it before the template under test.
    SideBranch atDepth;
    BuildSideBranch(atDepth, 2, 4);
    const uint256 hashAtDepth = atDepth.pSideTip->GetBlockHash();
    BOOST_REQUIRE(Invalidate(atDepth.pSideTip));
    MineTo(atDepth.pFork->nHeight + DAG_MERGE_DEPTH);
    BOOST_REQUIRE(Reconsider(atDepth.pSideTip));
    BOOST_REQUIRE_EQUAL(BestIndex()->nHeight - atDepth.pFork->nHeight, DAG_MERGE_DEPTH);
    BOOST_REQUIRE_MESSAGE(BestIndex()->nHeight - DAG_MERGE_DEPTH <= atDepth.pSideTip->nHeight,
                          "the pre-existing height filter already excludes this tip, so the "
                          "fork-depth filter is not what the case measures");
    BOOST_CHECK_MESSAGE(TemplateMerges(hashAtDepth),
                        "a tip forking at exactly the merge depth was refused");

    // One deeper: refused.
    SideBranch pastDepth;
    BuildSideBranch(pastDepth, 2, 4);
    const uint256 hashPastDepth = pastDepth.pSideTip->GetBlockHash();
    BOOST_REQUIRE(Invalidate(pastDepth.pSideTip));
    MineTo(pastDepth.pFork->nHeight + DAG_MERGE_DEPTH + 1);
    BOOST_REQUIRE(Reconsider(pastDepth.pSideTip));
    BOOST_REQUIRE_EQUAL(BestIndex()->nHeight - pastDepth.pFork->nHeight, DAG_MERGE_DEPTH + 1);
    BOOST_REQUIRE_MESSAGE(BestIndex()->nHeight - DAG_MERGE_DEPTH <= pastDepth.pSideTip->nHeight,
                          "the pre-existing height filter already excludes this tip, so the "
                          "fork-depth filter is not what the case measures");
    BOOST_CHECK_MESSAGE(!TemplateMerges(hashPastDepth),
                        "a tip forking one block deeper than the merge depth was merged");
}

// The verdict cache is keyed on the finality state a verdict was measured against, not on the
// template that asked. cs_main is released between a template's parent selection and its merge
// loop, so a cache that is not re-checked decides the merge loop from a superseded anchor.
BOOST_AUTO_TEST_CASE(a_cached_verdict_does_not_outlive_the_anchor_it_was_measured_against)
{
    BOOST_REQUIRE(fRegTest);
    MineForPermanentVerdict();

    SideBranch s;
    BuildSideBranch(s, 3, 5);
    const uint256 hashSide = s.pSideTip->GetBlockHash();

    // Fills the cache with this tip's verdict against the current anchor.
    BOOST_REQUIRE_MESSAGE(TemplateMerges(hashSide),
                          "the tip was already unmergeable before any anchor was installed");

    const int nAsOf = GetEpochForHeight(BestIndex()->nHeight) - 1;
    const int nLatch = nAsOf - (REORG_LATCH_ANCHOR_LAG_EPOCHS - 1);
    BOOST_REQUIRE(nLatch >= GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3));
    std::vector<int> vFinalized(nAsOf - nLatch + 1, s.pFork->nHeight + 1);
    const uint256 hashTipBefore = BestIndex()->GetBlockHash();
    {
        // The anchors move while the tip does not: nothing but the cache key can notice.
        ScopedFinalizedHeights anchors(nLatch, vFinalized);
        BOOST_REQUIRE_EQUAL(BestIndex()->GetBlockHash().ToString(), hashTipBefore.ToString());
        BOOST_CHECK_MESSAGE(!TemplateMerges(hashSide),
                            "a verdict cached against the previous anchor was reused after "
                            "the anchor moved under an unchanged tip");
    }

    // And back: the cache must not pin the refusal either.
    BOOST_REQUIRE_EQUAL(BestIndex()->GetBlockHash().ToString(), hashTipBefore.ToString());
    BOOST_CHECK_MESSAGE(TemplateMerges(hashSide),
                        "the refusal outlived the anchor that produced it");
}

// Template parent differs from the DAG tip: the depth filter measures against the
// template parent, which AcceptBlock validates the parent set against.
BOOST_AUTO_TEST_CASE(the_depth_filter_measures_against_the_template_parent_not_the_dag_tip)
{
    BOOST_REQUIRE(fRegTest);
    MineForPermanentVerdict();
    SettleOnMainChain();

    CBlockIndex* pFork = BestIndex();
    MineTo(pFork->nHeight + 8);
    CBlockIndex* pHeavy = BestIndex();
    CBlockIndex* pSide1 = AncestorAt(pHeavy, pFork->nHeight + 1);
    BOOST_REQUIRE(pSide1 && pSide1->pprev == pFork);

    BOOST_REQUIRE(Invalidate(pSide1));
    BOOST_REQUIRE(BestIndex() == pFork);
    SettleOnMainChain();
    BOOST_REQUIRE_MESSAGE(BestIndex() == pFork, "the template left the fork point");
    MineTo(pFork->nHeight + 3);
    CBlockIndex* pLight = BestIndex();
    BOOST_REQUIRE(pLight->nChainTrust < pHeavy->nChainTrust);

    // Anchored above the fork before the branch is restored, so restoring it is a switch this
    // node may never make and the lighter chain keeps the tip.
    const int nAsOf = GetEpochForHeight(BestIndex()->nHeight) - 1;
    const int nLatch = nAsOf - (REORG_LATCH_ANCHOR_LAG_EPOCHS - 1);
    BOOST_REQUIRE(nLatch >= GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3));
    std::vector<int> vFinalized(nAsOf - nLatch + 1, pFork->nHeight + 1);
    ScopedFinalizedHeights anchors(nLatch, vFinalized);

    Reconsider(pSide1);
    BOOST_REQUIRE_MESSAGE(BestIndex() == pLight,
                          "the node switched to the branch the finality anchor forbids");

    int nForkHeight = 0, nFinalCur = 0, nFinalLatch = 0, nAsOfEpoch = 0;
    BOOST_REQUIRE_EQUAL((int)BestChainSwitchVerdict(pHeavy, nForkHeight, nFinalCur,
                                                    nFinalLatch, nAsOfEpoch),
                        (int)REORG_FINALITY_REJECT_PERMANENT);

    uint256 hashDAGTip;
    {
        LOCK2(cs_main, g_dagManager.cs_dag);
        CBlockIndex* pDAGTip = g_dagManager.SelectBestDAGTip();
        BOOST_REQUIRE(pDAGTip != NULL);
        hashDAGTip = pDAGTip->GetBlockHash();
    }

    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblock.get() != NULL);
    BOOST_REQUIRE_MESSAGE(pblock->hashPrevBlock != hashDAGTip,
                          "the template parent is the DAG tip, so this case is not in the "
                          "configuration it exists to cover");
    BOOST_CHECK_MESSAGE(pblock->hashPrevBlock == pLight->GetBlockHash(),
                        "the template built on something other than the chain this node may "
                        "actually extend");
    std::vector<uint256> vParents = DAGParentsOf(*pblock, pLight->nHeight + 1);
    BOOST_REQUIRE(!vParents.empty());
    BOOST_CHECK_MESSAGE(vParents[0] == pLight->GetBlockHash(),
                        "the committed primary parent is not the template parent");
    BOOST_CHECK_MESSAGE(std::find(vParents.begin(), vParents.end(), pHeavy->GetBlockHash()) ==
                            vParents.end(),
                        "the template merged the tip of a branch it may never adopt, in the "
                        "configuration where the two halves of the policy measure against "
                        "different chains");
}

BOOST_AUTO_TEST_SUITE_END()
