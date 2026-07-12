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
#include "../txdb.h"

#include <algorithm>
#include <vector>

// Global consensus flag (defined in util.cpp). Declared at file scope so references from the
// anonymous namespace below bind to the global symbol, not an internal-linkage placeholder.
extern bool fRegTest;
extern bool fTestNet;

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
    std::map<unsigned int, uint256> hashesBySeed;
    CBlockIndex*              oldBest;
    bool                      oldRegTest;
    bool                      oldTestNet;
    CBigNum                   oldProofOfWorkLimit;

    explicit DAGHarness(bool fPublicTestnet = false)
    {
        oldRegTest = fRegTest;
        oldTestNet = fTestNet;
        fRegTest = !fPublicTestnet;
        fTestNet = fPublicTestnet;
        oldProofOfWorkLimit = bnProofOfWorkLimit;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        oldBest = pindexBest;
    }

    ~DAGHarness() { cleanup(); }

    // seed supplies deterministic header entropy and a removal lookup key;
    // parents[0] is the primary parent and contains the actual mined block hash.
    CBlockIndex* add(unsigned int seed, int height,
                     const std::vector<uint256>& parents, CBlockIndex* pprev,
                     bool fWriteBlock = true)
    {
        CBlock block;
        block.nVersion = 1;
        block.hashPrevBlock = pprev ? pprev->GetBlockHash() : uint256(0);
        block.hashMerkleRoot = uint256(seed);
        block.nTime = (unsigned int)(1700000000 + height);
        block.nBits = bnProofOfWorkLimit.GetCompact();
        block.nNonce = seed;
        while (!CheckProofOfWork(block.GetHash(), block.nBits))
            ++block.nNonce;

        unsigned int nFile = 0;
        unsigned int nBlockPos = 0;
        if (fWriteBlock)
            BOOST_REQUIRE(block.WriteToDisk(nFile, nBlockPos));

        const uint256 h = block.GetHash();
        CBlockIndex* idx = new CBlockIndex(nFile, nBlockPos, block);
        idx->nHeight = height;
        idx->pprev = pprev;
        std::pair<std::map<uint256, CBlockIndex*>::iterator, bool> ins =
            mapBlockIndex.insert(std::make_pair(h, idx));
        BOOST_REQUIRE(ins.second);
        idx->phashBlock = &ins.first->first;
        if (fWriteBlock)
        {
            CBlock check;
            BOOST_REQUIRE_MESSAGE(check.ReadFromDisk(idx),
                                  "failed to reread harness block seed " << seed <<
                                  " at " << idx->nFile << ":" << idx->nBlockPos);
        }
        g_dagManager.InitBlockDAGData(idx, parents);
        g_dagManager.ColorBlock(idx);
        hashes.push_back(h);
        blocks.push_back(idx);
        hashesBySeed[seed] = h;
        return idx;
    }

    // Detach a block from the DAG + index (simulate it being disconnected by a reorg).
    void remove(unsigned int seed)
    {
        std::map<unsigned int, uint256>::const_iterator sit = hashesBySeed.find(seed);
        BOOST_REQUIRE(sit != hashesBySeed.end());
        const uint256 h = sit->second;
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
        hashesBySeed.clear();
        pindexBest = oldBest;
        bnProofOfWorkLimit = oldProofOfWorkLimit;
        fRegTest = oldRegTest;
        fTestNet = oldTestNet;
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
    std::vector<uint256> p0(1, pE0->GetBlockHash());
    CBlockIndex* pMid = h.add(0xE0000002, hStart + 1, p0,                                pE0);
    std::vector<uint256> pMidP(1, pMid->GetBlockHash());
    CBlockIndex* pTip = h.add(0xE0000003, hStart + 2, pMidP,                             pMid);

    uint256 hTip = pTip->GetBlockHash();
    std::vector<uint256> orderBefore = g_dagManager.GetDAGLinearOrder(hTip);

    // A sibling that descends from pE0 but is NOT an ancestor of pTip: it must not perturb the
    // order computed from pTip (the transient "other node saw an extra block" case).
    CBlockIndex* pSibling = h.add(0xE00000FF, hStart + 1, p0, pE0);

    std::vector<uint256> orderAfter = g_dagManager.GetDAGLinearOrder(hTip);

    BOOST_CHECK(orderBefore == orderAfter);
    BOOST_CHECK(contains(orderAfter, pE0->GetBlockHash()));
    BOOST_CHECK(contains(orderAfter, pMid->GetBlockHash()));
    BOOST_CHECK(!contains(orderAfter, pSibling->GetBlockHash()));  // unreachable sibling excluded
}

BOOST_AUTO_TEST_CASE(v3_dag_score_survives_pruned_history_and_rebuild)
{
    DAGHarness h;
    const int hV3 = FORK_HEIGHT_EPOCH_STATE_V3;

    std::vector<uint256> none;
    CBlockIndex* pLegacy = h.add(0xD3000000, hV3 - 1, none, NULL);
    std::vector<uint256> legacyParent(1, pLegacy->GetBlockHash());
    CBlockIndex* pBase = h.add(0xD3000001, hV3, legacyParent, pLegacy);
    const uint256 nBaseScore = g_dagManager.ComputeDAGScore(pBase);
    BOOST_REQUIRE(nBaseScore != 0);
    pBase->nChainTrust = nBaseScore;

    std::vector<uint256> baseParent(1, pBase->GetBlockHash());
    CBlockIndex* pChild = h.add(0xD3000002, hV3 + 1, baseParent, pBase);
    const uint256 nChildScore = g_dagManager.ComputeDAGScore(pChild);
    BOOST_CHECK(nChildScore == nBaseScore + pChild->GetBlockTrust());
    pChild->nChainTrust = nChildScore;

    // Simulate the primary history below the retained frontier having been
    // pruned. A new descendant must extend the retained deterministic score,
    // and an incremental restart rebuild must preserve both scores exactly.
    h.remove(0xD3000000);
    std::vector<uint256> childParent(1, pChild->GetBlockHash());
    CBlockIndex* pGrandchild = h.add(0xD3000003, hV3 + 2, childParent, pChild);
    const uint256 nGrandchildScore = g_dagManager.ComputeDAGScore(pGrandchild);
    BOOST_CHECK(nGrandchildScore == nChildScore + pGrandchild->GetBlockTrust());
    pGrandchild->nChainTrust = nGrandchildScore;

    g_dagManager.RebuildDAGOrderIncremental(hV3);
    BOOST_CHECK(pChild->nChainTrust == nChildScore);
    BOOST_CHECK(pGrandchild->nChainTrust == nGrandchildScore);
}

// THE FIX (HIGH #2): ComputeEpochState anchored to a canonical tip must be a PURE function of
// that anchor -- the epoch it produces reflects the anchor's selected-parent chain, NOT the
// node-local live best tip. Two competing branches coexist in the DAG; anchoring to each tip
// yields that branch's epoch, and flipping pindexBest to the OTHER branch does not change the
// result. This is exactly what removes the frozen-live-tip cross-node divergence: every node
// validating a block anchors the epoch to that block's chain and computes identical roots.
//
// Pre-fork (legacy path) ComputeEpochState ignores the anchor and reads SelectBestDAGTip(), so
// this property would NOT hold; the DAGHarness forces fRegTest on, which activates
// FORK_HEIGHT_EPOCH_STATE_V2 in-test so the anchored path runs.
BOOST_AUTO_TEST_CASE(epoch_state_is_deterministic_per_anchor)
{
    DAGHarness h;

    const int E      = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3);
    const int hStart = GetEpochBoundaryHeight(E, FORK_HEIGHT_EPOCH_STATE_V3);
    const int hEnd   = GetEpochBoundaryHeight(E + 1, FORK_HEIGHT_EPOCH_STATE_V3) - 1;
    const int interval = hEnd - hStart + 1;

    std::vector<uint256> none;
    CBlockIndex* pBefore = h.add(0xE00000F0, hStart - 1, none, NULL);
    std::vector<uint256> pBeforeHash(1, pBefore->GetBlockHash());
    CBlockIndex* pE0 = h.add(0xE0000000, hStart, pBeforeHash, pBefore);

    // Two competing branches from the shared base pE0, BOTH present in the DAG at once.
    CBlockIndex* pA = pE0;
    CBlockIndex* pB = pE0;
    uint256 hA;
    uint256 hB;
    for (int nHeight = hStart + 1; nHeight <= hEnd; ++nHeight)
    {
        std::vector<uint256> pAp(1, pA->GetBlockHash());
        std::vector<uint256> pBp(1, pB->GetBlockHash());
        pA = h.add(0x0A000000U + (unsigned int)(nHeight - hStart), nHeight, pAp, pA);
        pB = h.add(0x0B000000U + (unsigned int)(nHeight - hStart), nHeight, pBp, pB);
        if (nHeight == hStart + 1)
        {
            hA = pA->GetBlockHash();
            hB = pB->GetBlockHash();
        }
    }
    CBlockIndex* pEndA = pA;
    CBlockIndex* pEndB = pB;
    std::vector<uint256> pEndAp(1, pEndA->GetBlockHash());
    CBlockIndex* pTipA = h.add(0x0A000311, hEnd + 1,   pEndAp,                           pEndA);
    std::vector<uint256> pEndBp(1, pEndB->GetBlockHash());
    CBlockIndex* pTipB = h.add(0x0B000311, hEnd + 1,   pEndBp,                           pEndB);

    CEpochState prev;
    prev.nEpoch = E - 1;
    prev.hashBoundaryBlock = pBefore->GetBlockHash();
    prev.nHeightStart = GetEpochBoundaryHeight(E - 1, hStart);
    prev.nHeightEnd = hStart - 1;
    prev.hashCurveRoot = 0;
    prev.hashNullifierRoot = uint256(0x0E000001);
    CCurveTree prevTree;

    // Anchor to chain A's exact epoch-end block while the live best tip is deliberately chain B:
    // the epoch must be chain A's regardless (and must not include pTipA from the later epoch).
    // chain A's regardless (anchor-pure, no SelectBestDAGTip dependency).
    pindexBest = pTipB;
    CEpochState sA;
    CCurveTree tA;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(g_dagManager.BuildEpochState(E, interval, pEndA, sA, tA,
                                                       strError, &prev, &prevTree), strError);
    BOOST_CHECK(contains(sA.vBlockHashes, hA));
    BOOST_CHECK(!contains(sA.vBlockHashes, hB));
    BOOST_CHECK(!contains(sA.vBlockHashes, pTipA->GetBlockHash()));

    // Anchor to chain B's exact boundary while the live best tip is deliberately chain A.
    pindexBest = pTipA;
    CEpochState sB;
    CCurveTree tB;
    BOOST_REQUIRE_MESSAGE(g_dagManager.BuildEpochState(E, interval, pEndB, sB, tB,
                                                       strError, &prev, &prevTree), strError);
    BOOST_CHECK(contains(sB.vBlockHashes, hB));
    BOOST_CHECK(!contains(sB.vBlockHashes, hA));

    // The two anchors yield genuinely different canonical epochs (the reorg case), and the epoch
    // is a pure function of the anchor -- the HIGH #2 frozen-live-tip divergence is gone.
    BOOST_CHECK(sA.vBlockHashes != sB.vBlockHashes);

    // Later-tip arrival and a simulated restart serialization round-trip cannot change A.
    h.add(0x0A0003FF, hEnd + 2, pEndAp, pTipA);
    CEpochState sAAfter;
    CCurveTree tAAfter;
    BOOST_REQUIRE_MESSAGE(g_dagManager.BuildEpochState(E, interval, pEndA, sAAfter, tAAfter,
                                                       strError, &prev, &prevTree), strError);
    BOOST_CHECK_EQUAL(sA.GetDigest().GetHex(), sAAfter.GetDigest().GetHex());
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << sA;
    CEpochState sRestarted;
    ss >> sRestarted;
    BOOST_CHECK_EQUAL(sA.GetDigest().GetHex(), sRestarted.GetDigest().GetHex());
}

BOOST_AUTO_TEST_CASE(v3_migration_base_is_staged_from_exact_boundary)
{
    DAGHarness h;
    const int E = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3) - 1;
    const int hStart = GetEpochBoundaryHeight(E, FORK_HEIGHT_EPOCH_STATE_V3);
    const int hEnd = FORK_HEIGHT_EPOCH_STATE_V3 - 1;
    const int interval = hEnd - hStart + 1;

    std::vector<uint256> none;
    CBlockIndex* pBefore = h.add(0xD4000000, hStart - 1, none, NULL);
    std::vector<uint256> beforeParent(1, pBefore->GetBlockHash());
    CBlockIndex* pMain = h.add(0xD4000002, hStart, beforeParent, pBefore);

    // A reachable merge block makes the ordering assertion meaningful: the
    // migration build must use the forced V3 primary-parent/height/hash order,
    // even though its exact boundary is one block below V3 activation.
    std::vector<uint256> firstParent(1, pMain->GetBlockHash());
    CBlockIndex* pSide = h.add(0xD4000001, hStart + 1, firstParent, pMain);
    CBlockIndex* pNext = h.add(0xD4000003, hStart + 1, firstParent, pMain);
    std::vector<uint256> mergeParents;
    mergeParents.push_back(pNext->GetBlockHash());
    mergeParents.push_back(pSide->GetBlockHash());
    pMain = h.add(0xD4000004, hStart + 2, mergeParents, pNext);
    for (int nHeight = hStart + 3; nHeight <= hEnd; ++nHeight)
    {
        std::vector<uint256> parents(1, pMain->GetBlockHash());
        pMain = h.add(0xD4000000U + (unsigned int)(nHeight - hStart + 3),
                      nHeight, parents, pMain);
    }

    CEpochState prev;
    prev.nEpoch = E - 1;
    prev.hashBoundaryBlock = pBefore->GetBlockHash();
    prev.nHeightStart = GetEpochBoundaryHeight(E - 1, hStart);
    prev.nHeightEnd = hStart - 1;
    CCurveTree prevTree;
    CEpochState state;
    CCurveTree tree;
    std::string strError;

    CEpochState wrongPrev = prev;
    wrongPrev.hashBoundaryBlock = uint256(0xD4FFFFFF);
    BOOST_CHECK(!g_dagManager.BuildEpochState(E, interval, pMain, state, tree,
                                              strError, &wrongPrev, &prevTree));
    BOOST_CHECK(strError.find("does not match canonical") != std::string::npos);

    BOOST_REQUIRE_MESSAGE(g_dagManager.BuildEpochState(E, interval, pMain, state, tree,
                                                       strError, &prev, &prevTree), strError);
    BOOST_CHECK_EQUAL(state.nEpoch, E);
    BOOST_CHECK_EQUAL(state.nHeightEnd, hEnd);
    BOOST_CHECK(state.hashBoundaryBlock == pMain->GetBlockHash());

    const std::vector<uint256> fullForcedOrder =
        g_dagManager.GetDAGLinearOrder(pMain->GetBlockHash(), 0, true);
    std::vector<uint256> expectedEpochOrder;
    for (const uint256& hash : fullForcedOrder)
    {
        std::map<uint256, CBlockIndex*>::const_iterator it = mapBlockIndex.find(hash);
        if (it != mapBlockIndex.end() && it->second &&
            it->second->nHeight >= hStart && it->second->nHeight <= hEnd)
            expectedEpochOrder.push_back(hash);
    }
    BOOST_CHECK(state.vBlockHashes == expectedEpochOrder);
}

BOOST_AUTO_TEST_CASE(v3_reorg_suffix_includes_changed_migration_base)
{
    const int nActivationEpoch = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3);
    const int nMigrationEpoch = nActivationEpoch - 1;
    const int nMigrationStart =
        GetEpochBoundaryHeight(nMigrationEpoch, FORK_HEIGHT_EPOCH_STATE_V3);
    const int nMigrationEnd = FORK_HEIGHT_EPOCH_STATE_V3 - 1;

    BOOST_CHECK_EQUAL(GetFirstV3EpochStateRebuildEpoch(nMigrationStart + 10),
                      nMigrationEpoch);
    BOOST_CHECK_EQUAL(GetFirstV3EpochStateRebuildEpoch(nMigrationEnd),
                      nActivationEpoch);
    BOOST_CHECK_EQUAL(GetFirstV3EpochStateRebuildEpoch(
                          GetEpochBoundaryHeight(nActivationEpoch + 1,
                                                 FORK_HEIGHT_EPOCH_STATE_V3) - 1),
                      nActivationEpoch + 1);
}

BOOST_AUTO_TEST_CASE(v2_testnet_linear_and_reorg_paths_are_byte_identical)
{
    CEpochState linearState;
    CCurveTree linearTree;
    CEpochState reorgState;
    CCurveTree reorgTree;
    CEpochState oldBranchState;
    CCurveTree oldBranchTree;

    // First derive the public-testnet V2 bytes through a clean linear arrival.
    {
        DAGHarness h(true);
        BOOST_REQUIRE(FORK_HEIGHT_EPOCH_STATE_V3 ==
                      TESTNET_EPOCH_STATE_V3_HEIGHT_UNSET);
        const int E = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V2);
        const int hStart = GetEpochBoundaryHeight(E, FORK_HEIGHT_EPOCH_STATE_V2);
        const int hEnd = GetEpochBoundaryHeight(E + 1,
                                                FORK_HEIGHT_EPOCH_STATE_V2) - 1;

        std::vector<uint256> none;
        CBlockIndex* pBefore = h.add(0xC2000F00, hStart - 1, none, NULL);
        CBlockIndex* pTip = pBefore;
        for (int nHeight = hStart; nHeight <= hEnd; ++nHeight)
        {
            std::vector<uint256> parents(1, pTip->GetBlockHash());
            pTip = h.add(0xC2000000U +
                             (unsigned int)(nHeight - hStart + 1),
                         nHeight, parents, pTip);
        }
        std::vector<uint256> crossingParents(1, pTip->GetBlockHash());
        CBlockIndex* pCrossing =
            h.add(0xC2000FFF, hEnd + 1, crossingParents, pTip);

        CEpochState prev;
        prev.nEpoch = E - 1;
        prev.hashBoundaryBlock = pBefore->GetBlockHash();
        prev.nHeightStart = GetEpochBoundaryHeight(E - 1, hStart);
        prev.nHeightEnd = hStart - 1;
        CCurveTree prevTree;
        std::string strError;
        BOOST_REQUIRE_MESSAGE(g_dagManager.BuildEpochStateV2Compat(
                                  E, hEnd - hStart + 1, pCrossing,
                                  linearState, linearTree, strError,
                                  &prev, &prevTree), strError);
    }

    // Recreate the same canonical branch after a competing branch has already
    // supplied the cached/live DAG arrival history. Reorg recomputation must use
    // B's exact crossing block and reproduce B's clean-linear bytes.
    {
        DAGHarness h(true);
        const int E = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V2);
        const int hStart = GetEpochBoundaryHeight(E, FORK_HEIGHT_EPOCH_STATE_V2);
        const int hEnd = GetEpochBoundaryHeight(E + 1,
                                                FORK_HEIGHT_EPOCH_STATE_V2) - 1;

        std::vector<uint256> none;
        CBlockIndex* pBefore = h.add(0xC2000F00, hStart - 1, none, NULL);
        CEpochState prev;
        prev.nEpoch = E - 1;
        prev.hashBoundaryBlock = pBefore->GetBlockHash();
        prev.nHeightStart = GetEpochBoundaryHeight(E - 1, hStart);
        prev.nHeightEnd = hStart - 1;
        CCurveTree prevTree;
        std::string strError;

        CBlockIndex* pOld = pBefore;
        for (int nHeight = hStart; nHeight <= hEnd; ++nHeight)
        {
            std::vector<uint256> parents(1, pOld->GetBlockHash());
            pOld = h.add(0xC1000000U +
                             (unsigned int)(nHeight - hStart + 1),
                         nHeight, parents, pOld);
        }
        std::vector<uint256> oldCrossingParents(1, pOld->GetBlockHash());
        CBlockIndex* pOldCrossing =
            h.add(0xC1000FFF, hEnd + 1, oldCrossingParents, pOld);
        BOOST_REQUIRE_MESSAGE(g_dagManager.BuildEpochStateV2Compat(
                                  E, hEnd - hStart + 1, pOldCrossing,
                                  oldBranchState, oldBranchTree, strError,
                                  &prev, &prevTree), strError);

        CBlockIndex* pNew = pBefore;
        for (int nHeight = hStart; nHeight <= hEnd; ++nHeight)
        {
            std::vector<uint256> parents(1, pNew->GetBlockHash());
            pNew = h.add(0xC2000000U +
                             (unsigned int)(nHeight - hStart + 1),
                         nHeight, parents, pNew);
        }
        std::vector<uint256> newCrossingParents(1, pNew->GetBlockHash());
        CBlockIndex* pNewCrossing =
            h.add(0xC2000FFF, hEnd + 1, newCrossingParents, pNew);
        BOOST_REQUIRE_MESSAGE(g_dagManager.BuildEpochStateV2Compat(
                                  E, hEnd - hStart + 1, pNewCrossing,
                                  reorgState, reorgTree, strError,
                                  &prev, &prevTree), strError);

        BOOST_CHECK(linearState.vBlockHashes == reorgState.vBlockHashes);
        BOOST_CHECK(linearState.hashBoundaryBlock == reorgState.hashBoundaryBlock);
        BOOST_CHECK(linearState.hashCurveRoot == reorgState.hashCurveRoot);
        BOOST_CHECK(linearState.hashNullifierRoot == reorgState.hashNullifierRoot);
        BOOST_CHECK(linearState.hashVoteSetRoot == reorgState.hashVoteSetRoot);
        BOOST_CHECK(linearState.GetDigest() == reorgState.GetDigest());
        BOOST_CHECK(oldBranchState.vBlockHashes != reorgState.vBlockHashes);

        // Persist the reorg result exactly as the best-chain transaction does,
        // then rebuild a fresh manager from LevelDB to exercise restart/load
        // equivalence under public-testnet epoch geometry.
        CTxDB txdb("rw");
        BOOST_REQUIRE(txdb.TxnBegin());
        BOOST_REQUIRE(g_dagManager.WriteEpochState(txdb, reorgState, reorgTree));
        BOOST_REQUIRE(txdb.WriteEpochStateSchema(EPOCHSTATE_SCHEMA_V2));
        BOOST_REQUIRE(txdb.TxnCommit());
        CDAGManager restarted;
        BOOST_REQUIRE(restarted.LoadEpochStates(txdb));
        CEpochState restartedState;
        BOOST_REQUIRE(restarted.GetEpochState(E, restartedState));
        BOOST_CHECK(restartedState.vBlockHashes == reorgState.vBlockHashes);
        BOOST_CHECK(restartedState.GetDigest() == reorgState.GetDigest());
        BOOST_REQUIRE(txdb.TxnBegin());
        BOOST_REQUIRE(txdb.EraseEpochState(E));
        BOOST_REQUIRE(txdb.EraseCurveTreeAtEpoch(E));
        BOOST_REQUIRE(txdb.TxnCommit());

        // A fork on an epoch's final block changes its V2 crossing anchor; a fork
        // on the crossing block itself begins affecting the following epoch.
        BOOST_CHECK_EQUAL(GetFirstV2EpochStateRebuildEpoch(hEnd), E);
        BOOST_CHECK_EQUAL(GetFirstV2EpochStateRebuildEpoch(hEnd + 1), E + 1);
    }

    // Installing a shortened suffix must remove every stale later record while
    // retaining the last completed canonical V2 state.
    const int E = linearState.nEpoch;
    CEpochState staleFuture = oldBranchState;
    staleFuture.nEpoch = E + 1;
    std::map<int, CEpochState> states;
    std::map<int, CCurveTree> trees;
    states[E] = reorgState;
    states[E + 1] = staleFuture;
    trees[E] = reorgTree;
    trees[E + 1] = oldBranchTree;
    CDAGManager manager;
    BOOST_REQUIRE(manager.InstallEpochStateBatch(E, states, trees));

    states.clear();
    trees.clear();
    BOOST_REQUIRE(manager.InstallEpochStateBatch(E + 1, states, trees));
    CEpochState loaded;
    BOOST_CHECK(manager.GetEpochState(E, loaded));
    BOOST_CHECK(loaded.GetDigest() == reorgState.GetDigest());
    BOOST_CHECK(!manager.GetEpochState(E + 1, loaded));
}

BOOST_AUTO_TEST_CASE(epoch_state_v3_fails_closed_on_missing_inputs)
{
    DAGHarness h;
    const int E = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3);
    const int hStart = GetEpochBoundaryHeight(E, FORK_HEIGHT_EPOCH_STATE_V3);
    const int hEnd = GetEpochBoundaryHeight(E + 1, FORK_HEIGHT_EPOCH_STATE_V3) - 1;
    const int interval = hEnd - hStart + 1;

    std::vector<uint256> none;
    CBlockIndex* pBefore = h.add(0x0C000000, hStart - 1, none, NULL);
    std::vector<uint256> pBeforeHash(1, pBefore->GetBlockHash());
    CBlockIndex* pEnd = h.add(0x0C000001, hStart, pBeforeHash, pBefore);
    CBlockIndex* pMissing = NULL;
    for (int nHeight = hStart + 1; nHeight <= hEnd; ++nHeight)
    {
        std::vector<uint256> parents(1, pEnd->GetBlockHash());
        const bool fWrite = nHeight != hStart + 1;
        pEnd = h.add(0x0C000000U + (unsigned int)(nHeight - hStart + 1),
                     nHeight, parents, pEnd, fWrite);
        if (!fWrite)
            pMissing = pEnd;
    }
    BOOST_REQUIRE(pMissing != NULL);

    CEpochState prev;
    prev.nEpoch = E - 1;
    prev.hashBoundaryBlock = pBefore->GetBlockHash();
    prev.nHeightStart = GetEpochBoundaryHeight(E - 1, hStart);
    prev.nHeightEnd = hStart - 1;
    CCurveTree prevTree;
    CEpochState state;
    CCurveTree tree;
    std::string strError;
    BOOST_CHECK(!g_dagManager.BuildEpochState(E, interval, pEnd, state, tree,
                                              strError, &prev, &prevTree));
    BOOST_CHECK(strError.find("cannot read ordered block") != std::string::npos);

    // The exact boundary and the immediate predecessor pair are independently mandatory.
    BOOST_CHECK(!g_dagManager.BuildEpochState(E, interval, pMissing, state, tree,
                                              strError, &prev, &prevTree));
    BOOST_CHECK(strError.find("exact boundary height") != std::string::npos);

    CBlock recoveredBlock = pMissing->GetBlockHeader();
    BOOST_REQUIRE(recoveredBlock.WriteToDisk(pMissing->nFile, pMissing->nBlockPos));
    BOOST_CHECK(!g_dagManager.BuildEpochState(E, interval, pEnd, state, tree, strError));
    BOOST_CHECK(strError.find("immediate predecessor") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(deterministic_finalized_height_distinguishes_missing_from_zero)
{
    CDAGManager manager;
    int nHeight = 999;
    BOOST_CHECK(!manager.TryGetDeterministicFinalizedHeight(7, nHeight));
    BOOST_CHECK_EQUAL(nHeight, 0);

    CEpochState state;
    state.nEpoch = 7;
    state.hashBoundaryBlock = uint256(0x70000001);
    state.nFinalizedHeightAsOf = 0; // valid, present state with nothing finalized
    state.nBlockCount = 0;
    CCurveTree tree;
    std::map<int, CEpochState> states;
    std::map<int, CCurveTree> trees;
    states[7] = state;
    trees[7] = tree;

    // A staged DB write/abort must never leak the candidate into memory.
    CTxDB txdb("rw");
    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(manager.WriteEpochState(txdb, state, tree));
    BOOST_CHECK(manager.TryGetDeterministicFinalizedHeight(txdb, 7, nHeight));
    BOOST_CHECK_EQUAL(nHeight, 0);
    txdb.TxnAbort();
    BOOST_CHECK(!manager.TryGetDeterministicFinalizedHeight(7, nHeight));

    BOOST_REQUIRE(manager.InstallEpochStateBatch(7, states, trees));
    BOOST_CHECK(manager.TryGetDeterministicFinalizedHeight(7, nHeight));
    BOOST_CHECK_EQUAL(nHeight, 0);
    BOOST_CHECK(!manager.TryGetDeterministicFinalizedHeight(6, nHeight));

    // Empty replacement is the post-commit shortened-reorg cleanup path.
    states.clear();
    trees.clear();
    BOOST_REQUIRE(manager.InstallEpochStateBatch(7, states, trees));
    BOOST_CHECK(!manager.TryGetDeterministicFinalizedHeight(7, nHeight));
}

BOOST_AUTO_TEST_CASE(v3_startup_requires_exact_highest_completed_epoch)
{
    DAGHarness h;
    const int nActivationEpoch = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3);
    const int nMigrationEpoch = nActivationEpoch - 1;
    const int nActivationEnd =
        GetEpochBoundaryHeight(nActivationEpoch + 1,
                               FORK_HEIGHT_EPOCH_STATE_V3) - 1;

    std::vector<uint256> none;
    CBlockIndex* pTip = h.add(0xD5000000, FORK_HEIGHT_EPOCH_STATE_V3 - 1,
                              none, NULL, false);
    CBlockIndex* pMigrationBoundary = pTip;
    for (int nHeight = FORK_HEIGHT_EPOCH_STATE_V3;
         nHeight <= nActivationEnd; ++nHeight)
    {
        std::vector<uint256> parents(1, pTip->GetBlockHash());
        pTip = h.add(0xD5000000U +
                         (unsigned int)(nHeight - FORK_HEIGHT_EPOCH_STATE_V3 + 1),
                     nHeight, parents, pTip, false);
    }

    CEpochState migration;
    migration.nEpoch = nMigrationEpoch;
    migration.nHeightStart =
        GetEpochBoundaryHeight(nMigrationEpoch, FORK_HEIGHT_EPOCH_STATE_V3);
    migration.nHeightEnd = FORK_HEIGHT_EPOCH_STATE_V3 - 1;
    migration.hashBoundaryBlock = pMigrationBoundary->GetBlockHash();
    CEpochState activation;
    activation.nEpoch = nActivationEpoch;
    activation.nHeightStart = FORK_HEIGHT_EPOCH_STATE_V3;
    activation.nHeightEnd = nActivationEnd;
    activation.hashBoundaryBlock = pTip->GetBlockHash();
    CCurveTree emptyTree;

    std::map<int, CEpochState> states;
    std::map<int, CCurveTree> trees;
    states[nMigrationEpoch] = migration;
    states[nActivationEpoch] = activation;
    trees[nMigrationEpoch] = emptyTree;
    trees[nActivationEpoch] = emptyTree;

    std::string strError;
    CDAGManager complete;
    BOOST_REQUIRE(complete.InstallEpochStateBatch(nMigrationEpoch, states, trees));
    BOOST_CHECK_MESSAGE(complete.ValidateEpochStateTip(pTip, strError), strError);

    CDAGManager truncated;
    states.erase(nActivationEpoch);
    trees.erase(nActivationEpoch);
    BOOST_REQUIRE(truncated.InstallEpochStateBatch(nMigrationEpoch, states, trees));
    BOOST_CHECK(!truncated.ValidateEpochStateTip(pTip, strError));
    BOOST_CHECK(strError.find("requires highest completed epoch") != std::string::npos);

    CDAGManager wrongBoundary;
    states[nActivationEpoch] = activation;
    states[nActivationEpoch].hashBoundaryBlock = uint256(0xD5FFFFFF);
    trees[nActivationEpoch] = emptyTree;
    BOOST_REQUIRE(wrongBoundary.InstallEpochStateBatch(nMigrationEpoch, states, trees));
    BOOST_CHECK(!wrongBoundary.ValidateEpochStateTip(pTip, strError));
    BOOST_CHECK(strError.find("does not match hashBestChain") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(epoch_state_persistence_load_fails_closed)
{
    CTxDB txdb("rw");
    const int E = 900001;

    CEpochState mismatched;
    mismatched.nEpoch = E + 1;
    mismatched.hashBoundaryBlock = uint256(0x90000101);
    mismatched.nHeightStart = GetEpochBoundaryHeight(E, FORK_HEIGHT_DAG);
    mismatched.nHeightEnd = GetEpochBoundaryHeight(E + 1, FORK_HEIGHT_DAG) - 1;
    CCurveTree emptyTree;
    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.WriteEpochState(E, mismatched));
    BOOST_REQUIRE(txdb.WriteCurveTreeAtEpoch(E, emptyTree));
    BOOST_REQUIRE(txdb.TxnCommit());

    CDAGManager loader;
    BOOST_CHECK(!loader.LoadEpochStates(txdb));

    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.EraseEpochState(E));
    BOOST_REQUIRE(txdb.EraseCurveTreeAtEpoch(E));
    BOOST_REQUIRE(txdb.TxnCommit());

    CEpochState missingPair = mismatched;
    missingPair.nEpoch = E;
    BOOST_REQUIRE(txdb.WriteEpochState(E, missingPair));
    BOOST_CHECK(!loader.LoadEpochStates(txdb));
    BOOST_REQUIRE(txdb.EraseEpochState(E));

    CEpochState rootMismatch;
    rootMismatch.nEpoch = E;
    rootMismatch.hashBoundaryBlock = uint256(0x90000102);
    rootMismatch.nHeightStart = GetEpochBoundaryHeight(E, FORK_HEIGHT_DAG);
    rootMismatch.nHeightEnd = GetEpochBoundaryHeight(E + 1, FORK_HEIGHT_DAG) - 1;
    rootMismatch.hashCurveRoot = uint256(1);
    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.WriteEpochState(E, rootMismatch));
    BOOST_REQUIRE(txdb.WriteCurveTreeAtEpoch(E, emptyTree));
    BOOST_REQUIRE(txdb.TxnCommit());
    BOOST_CHECK(!loader.LoadEpochStates(txdb));

    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.EraseEpochState(E));
    BOOST_REQUIRE(txdb.EraseCurveTreeAtEpoch(E));
    BOOST_REQUIRE(txdb.TxnCommit());

    CEpochState gapA;
    gapA.nEpoch = E;
    gapA.hashBoundaryBlock = uint256(0x90000103);
    gapA.nHeightStart = GetEpochBoundaryHeight(E, FORK_HEIGHT_DAG);
    gapA.nHeightEnd = GetEpochBoundaryHeight(E + 1, FORK_HEIGHT_DAG) - 1;
    CEpochState gapB;
    gapB.nEpoch = E + 2;
    gapB.hashBoundaryBlock = uint256(0x90000104);
    gapB.nHeightStart = GetEpochBoundaryHeight(E + 2, FORK_HEIGHT_DAG);
    gapB.nHeightEnd = GetEpochBoundaryHeight(E + 3, FORK_HEIGHT_DAG) - 1;
    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.WriteEpochState(E, gapA));
    BOOST_REQUIRE(txdb.WriteCurveTreeAtEpoch(E, emptyTree));
    BOOST_REQUIRE(txdb.WriteEpochState(E + 2, gapB));
    BOOST_REQUIRE(txdb.WriteCurveTreeAtEpoch(E + 2, emptyTree));
    BOOST_REQUIRE(txdb.TxnCommit());
    BOOST_CHECK(!loader.LoadEpochStates(txdb));
    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.EraseEpochState(E));
    BOOST_REQUIRE(txdb.EraseCurveTreeAtEpoch(E));
    BOOST_REQUIRE(txdb.EraseEpochState(E + 2));
    BOOST_REQUIRE(txdb.EraseCurveTreeAtEpoch(E + 2));
    BOOST_REQUIRE(txdb.TxnCommit());
}

BOOST_AUTO_TEST_SUITE_END()
