// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Reorg-determinism harness for the epoch-state finality anchor (HIGH #2).
//
// The consensus finality anchor is CDAGManager::ComputeEpochState(): it derives an
// epoch's canonical block set + DAG order and, from those, the curve/nullifier/vote-set
// roots that CheckVote / CheckTallyCertificate compare against during block validation.
// The audit finding (increments-1-4 sweep) is that this state is
//   (a) derived from SelectBestDAGTip() -- the node-local LIVE best tip -- rather than a
//       canonical anchor, and
//   (b) computed once at the epoch boundary and NEVER recomputed on reorg,
// so two nodes that cross a boundary at different transient DAG states, or that take a
// reorg, can hold different frozen roots -> a private vote/cert anchored to the canonical
// root passes on one node and is rejected on another -> permanent ConnectBlock split.
//
// This suite is the deterministic (CI-able) unit-level half of the validation harness:
//   - anchor_purity:  proves the fix's FOUNDATION -- GetDAGLinearOrder(anchor) is a pure
//                     function of its anchor (blocks not reachable from the anchor cannot
//                     change the order), which is what makes a canonical-anchor fix sound.
//   - reorg_staleness: REPRODUCES the bug -- after a reorg replaces an epoch's blocks, the
//                     stored epoch state is still the pre-reorg (stale) block set, and only
//                     an explicit recompute reflects the new canonical chain.
//
// The multi-node regtest reorg e2e (integration half) is tracked separately; it exercises
// the actual Reorganize recompute hook that a unit test cannot.
//
// FLIP-WHEN-FIXED markers below call out the exact assertions that must invert once HIGH #2
// (deterministic anchor + recompute-on-reorg) lands: the stale-state checks become
// reflects-new-chain checks.

#include <boost/test/unit_test.hpp>

#include "../dag.h"
#include "../finality.h"
#include "../main.h"

#include <algorithm>
#include <vector>

// Global consensus flag (defined in util.cpp). Declared at file scope so references from the
// anonymous namespace below bind to the global symbol, not an internal-linkage placeholder.
extern bool fRegTest;

BOOST_AUTO_TEST_SUITE(epoch_state_determinism_tests)

namespace {

// Builds throwaway post-DAG PoW CBlockIndex nodes wired into the global mapBlockIndex + the
// DAG manager, and tears them all down (plus restoring pindexBest / fRegTest) on destruction.
// fRegTest is forced on so the fork heights are small (GetForkHeightDAG()==11) and, once the
// HIGH #2 fix lands, FORK_HEIGHT_EPOCH_STATE_V2 is active in-test.
struct DAGHarness
{
    std::vector<uint256>      hashes;
    std::vector<CBlockIndex*> blocks;
    CBlockIndex*              oldBest;
    bool                      oldRegTest;

    DAGHarness()
    {
        oldRegTest = fRegTest;
        fRegTest = true;
        oldBest = pindexBest;
    }

    ~DAGHarness() { cleanup(); }

    // seed -> the block's uint256 hash; parents[0] is the primary (selected) parent.
    CBlockIndex* add(unsigned int seed, int height,
                     const std::vector<uint256>& parents, CBlockIndex* pprev)
    {
        uint256 h(seed);
        CBlockIndex* idx = new CBlockIndex();
        idx->nHeight = height;
        idx->pprev = pprev;
        std::pair<std::map<uint256, CBlockIndex*>::iterator, bool> ins =
            mapBlockIndex.insert(std::make_pair(h, idx));
        idx->phashBlock = &ins.first->first;
        g_dagManager.InitBlockDAGData(idx, parents);
        g_dagManager.ColorBlock(idx);
        hashes.push_back(h);
        blocks.push_back(idx);
        return idx;
    }

    // Detach a block from the DAG + index (simulate it being disconnected by a reorg).
    void remove(unsigned int seed)
    {
        uint256 h(seed);
        g_dagManager.RemoveBlockDAGData(h);
        mapBlockIndex.erase(h);
        for (size_t i = 0; i < hashes.size(); i++)
            if (hashes[i] == h) { delete blocks[i]; blocks[i] = NULL; }
    }

    void cleanup()
    {
        for (size_t i = 0; i < hashes.size(); i++)
        {
            g_dagManager.RemoveBlockDAGData(hashes[i]);
            mapBlockIndex.erase(hashes[i]);
            delete blocks[i];
        }
        hashes.clear();
        blocks.clear();
        pindexBest = oldBest;
        fRegTest = oldRegTest;
    }
};

bool contains(const std::vector<uint256>& v, const uint256& h)
{
    return std::find(v.begin(), v.end(), h) != v.end();
}

} // namespace

// FOUNDATION: GetDAGLinearOrder(anchor) must be a pure function of the anchor's committed
// structure -- a block that is not reachable from the anchor cannot change the order. This is
// precisely the property that lets ComputeEpochState be made deterministic by anchoring to a
// canonical boundary block instead of SelectBestDAGTip().
BOOST_AUTO_TEST_CASE(dag_linear_order_is_anchor_pure)
{
    DAGHarness h;

    const int hStart = GetEpochBoundaryHeight(GetEpochForHeight(FORK_HEIGHT_DAG), FORK_HEIGHT_DAG);

    std::vector<uint256> none;
    CBlockIndex* pE0  = h.add(0xE0000001, hStart,     none,                              NULL);
    std::vector<uint256> p0(1, uint256(0xE0000001));
    CBlockIndex* pMid = h.add(0xE0000002, hStart + 1, p0,                                pE0);
    std::vector<uint256> pMidP(1, uint256(0xE0000002));
    CBlockIndex* pTip = h.add(0xE0000003, hStart + 2, pMidP,                             pMid);

    uint256 hTip = pTip->GetBlockHash();
    std::vector<uint256> orderBefore = g_dagManager.GetDAGLinearOrder(hTip);

    // A sibling that descends from pE0 but is NOT an ancestor of pTip: it must not perturb the
    // order computed from pTip (the transient "other node saw an extra block" case).
    h.add(0xE00000FF, hStart + 1, p0, pE0);

    std::vector<uint256> orderAfter = g_dagManager.GetDAGLinearOrder(hTip);

    BOOST_CHECK(orderBefore == orderAfter);
    BOOST_CHECK(contains(orderAfter, pE0->GetBlockHash()));
    BOOST_CHECK(contains(orderAfter, pMid->GetBlockHash()));
    BOOST_CHECK(!contains(orderAfter, uint256(0xE00000FF)));  // unreachable sibling excluded
}

// BUG REPRODUCTION: an epoch's stored state is frozen at first computation and is NOT
// recomputed when a reorg replaces that epoch's blocks. Chain A and chain B carry different
// blocks at the same in-epoch height; after "reorging" A->B the stored epoch state still
// lists chain A's block, and only an explicit recompute reflects chain B.
BOOST_AUTO_TEST_CASE(epoch_state_frozen_not_recomputed_on_reorg)
{
    DAGHarness h;

    const int E      = GetEpochForHeight(FORK_HEIGHT_DAG);
    const int hStart = GetEpochBoundaryHeight(E, FORK_HEIGHT_DAG);
    const int hEnd   = GetEpochBoundaryHeight(E + 1, FORK_HEIGHT_DAG) - 1;
    const int interval = hEnd - hStart + 1;

    const uint256 hA(0x0A000012);  // chain A's in-epoch block
    const uint256 hB(0x0B000012);  // chain B's in-epoch block (competing, same height)

    std::vector<uint256> none;
    CBlockIndex* pE0 = h.add(0xE0000000, hStart, none, NULL);
    std::vector<uint256> pe0(1, uint256(0xE0000000));

    // ---- Phase 1: chain A is canonical ----
    CBlockIndex* pA    = h.add(0x0A000012, hStart + 1, pe0,                              pE0);
    std::vector<uint256> pAp(1, hA);
    CBlockIndex* pEndA = h.add(0x0A000310, hEnd,       pAp,                              pA);
    std::vector<uint256> pEndAp(1, uint256(0x0A000310));
    CBlockIndex* pTipA = h.add(0x0A000311, hEnd + 1,   pEndAp,                           pEndA);
    pindexBest = pTipA;

    BOOST_REQUIRE(g_dagManager.ComputeEpochState(E, interval));
    CEpochState sA;
    BOOST_REQUIRE(g_dagManager.GetEpochState(E, sA));
    BOOST_CHECK(contains(sA.vBlockHashes, hA));    // chain A's block is in the epoch
    BOOST_CHECK(!contains(sA.vBlockHashes, hB));

    // ---- Phase 2: reorg A -> B (disconnect A's branch, connect B's) ----
    h.remove(0x0A000012);
    h.remove(0x0A000310);
    h.remove(0x0A000311);
    CBlockIndex* pB    = h.add(0x0B000012, hStart + 1, pe0,                              pE0);
    std::vector<uint256> pBp(1, hB);
    CBlockIndex* pEndB = h.add(0x0B000310, hEnd,       pBp,                              pB);
    std::vector<uint256> pEndBp(1, uint256(0x0B000310));
    CBlockIndex* pTipB = h.add(0x0B000311, hEnd + 1,   pEndBp,                           pEndB);
    pindexBest = pTipB;

    // THE BUG: the reorg changed the canonical chain, but nothing recomputed the epoch state.
    CEpochState sStale;
    BOOST_REQUIRE(g_dagManager.GetEpochState(E, sStale));
    // FLIP-WHEN-FIXED: once HIGH #2 (recompute-on-reorg) lands, the stored state must already
    // reflect chain B here -- i.e. contains(sStale.vBlockHashes, hB) && !contains(..., hA).
    BOOST_CHECK(contains(sStale.vBlockHashes, hA));    // stale: still chain A
    BOOST_CHECK(!contains(sStale.vBlockHashes, hB));   // stale: chain B absent

    // ---- Phase 3: explicit recompute (what the fix's reorg hook must do) yields chain B ----
    BOOST_REQUIRE(g_dagManager.ComputeEpochState(E, interval));
    CEpochState sB;
    BOOST_REQUIRE(g_dagManager.GetEpochState(E, sB));
    BOOST_CHECK(contains(sB.vBlockHashes, hB));        // recomputed: now chain B
    BOOST_CHECK(!contains(sB.vBlockHashes, hA));
    BOOST_CHECK(sA.vBlockHashes != sB.vBlockHashes);   // the reorg genuinely changes epoch E
}

BOOST_AUTO_TEST_SUITE_END()
