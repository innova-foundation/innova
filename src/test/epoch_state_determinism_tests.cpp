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
#include "../privacy_vnext_ffi.h"
#include "../txdb.h"

#include <algorithm>
#include <vector>

// Global consensus flag (defined in util.cpp). Declared at file scope so references from the
// anonymous namespace below bind to the global symbol, not an internal-linkage placeholder.
extern bool fRegTest;
extern bool fTestNet;

BOOST_AUTO_TEST_SUITE(epoch_state_determinism_tests)

namespace {

class EpochStateRestartTestDB : public CTxDB
{
public:
    EpochStateRestartTestDB() : CTxDB("r+") {}
    bool EraseEpochStateSchemaForTest()
    {
        return Erase(std::string("epochstateschema"));
    }
};

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
                     bool fWriteBlock = true,
                     const CScript* pCarrierScript = NULL,
                     const CScript* pSecondCarrierScript = NULL)
    {
        CBlock block;
        block.nVersion = 1;
        block.hashPrevBlock = pprev ? pprev->GetBlockHash() : uint256(0);
        block.nTime = (unsigned int)(1700000000 + height);
        block.nBits = bnProofOfWorkLimit.GetCompact();
        block.nNonce = seed;
        if (pCarrierScript || pSecondCarrierScript)
        {
            CTransaction carrier;
            carrier.nTime = block.nTime;
            if (pCarrierScript)
                carrier.vout.push_back(CTxOut(0, *pCarrierScript));
            if (pSecondCarrierScript)
                carrier.vout.push_back(CTxOut(0, *pSecondCarrierScript));
            block.vtx.push_back(carrier);
            block.hashMerkleRoot = block.BuildMerkleTree();
        }
        else
        {
            block.hashMerkleRoot = uint256(seed);
        }
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
        if (height >= FORK_HEIGHT_DAGKNIGHT)
            BOOST_REQUIRE(g_dagManager.ColorBlockDAGKnight(idx));
        else
            g_dagManager.ColorBlock(idx);
        idx->nChainTrust = g_dagManager.ComputeDAGScore(idx);
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

CFinalityVote BuildV2CarrierVote(int nEpoch, int nHeight,
                                 const uint256& hashChoice,
                                 const uint256& nullifier)
{
    CFinalityVote vote;
    vote.nProofMode = FINALITY_PROOF_TRANSPARENT;
    vote.nEpoch = nEpoch;
    vote.hashBlock = hashChoice;
    vote.nHeight = nHeight;
    vote.nTime = 1700000000 + nHeight;
    vote.nVoteWeight = 1000;
    vote.nReward = 0;
    vote.nullifier = nullifier;
    return vote;
}

CFinalityTallyCertificate BuildV2CarrierCertificate(
    int nEpoch, int nHeight, const uint256& hashChoice, int nTier,
    const uint256& voteNullifier)
{
    CFinalityTallyCertificate cert;
    cert.nVersion = 2;
    cert.nEpoch = nEpoch;
    cert.hashBlock = hashChoice;
    cert.nHeight = nHeight;
    cert.nTier = nTier;
    cert.nConsecutiveHardCount =
        nTier >= FINALITY_HARD ? FINALITY_CONFIRMATION_EPOCHS : 0;
    cert.nTransparentActiveWeight = 1000;
    cert.nTransparentWinningWeight = 1000;
    cert.vVoteNullifiers.push_back(voteNullifier);
    return cert;
}

uint256 BuildExpectedV2VoteSetRoot(
    int nEpoch, const std::map<uint256, uint256>& mapLeaves)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("Innova/IDAG/EpochVoteSetRoot/v1");
    ss << nEpoch;
    for (std::map<uint256, uint256>::const_iterator it = mapLeaves.begin();
         it != mapLeaves.end(); ++it)
    {
        ss << it->first;
        ss << it->second;
    }
    return ss.GetHash();
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

BOOST_AUTO_TEST_CASE(dagknight_v3_arrival_restart_and_tip_are_anchor_pure)
{
    struct Snapshot
    {
        std::vector<uint256> order;
        std::vector<std::pair<uint256, bool> > colors;
        uint256 selectedParent;
        uint256 score;
        uint256 tip;
        int inferredK;
    };

    const auto run = [](bool fReverseSiblings) -> Snapshot {
        DAGHarness h;
        const int nBaseHeight =
            std::max(FORK_HEIGHT_EPOCH_STATE_V3,
                     FORK_HEIGHT_DAGKNIGHT) + 10;
        std::vector<uint256> none;
        CBlockIndex* base = h.add(0xDA600001, nBaseHeight,
                                  none, NULL);
        std::vector<uint256> baseParent(1, base->GetBlockHash());
        CBlockIndex* a = NULL;
        CBlockIndex* b = NULL;
        if (fReverseSiblings)
        {
            b = h.add(0xDA600003, nBaseHeight + 1, baseParent, base);
            a = h.add(0xDA600002, nBaseHeight + 1, baseParent, base);
        }
        else
        {
            a = h.add(0xDA600002, nBaseHeight + 1, baseParent, base);
            b = h.add(0xDA600003, nBaseHeight + 1, baseParent, base);
        }

        std::vector<uint256> mergeParents;
        mergeParents.push_back(a->GetBlockHash());
        mergeParents.push_back(b->GetBlockHash());
        CScript carrier = BuildDAGParentScript(mergeParents);
        CBlockIndex* merge = h.add(0xDA600004, nBaseHeight + 2,
                                   mergeParents, a, true, &carrier);

        Snapshot snapshot;
        BOOST_REQUIRE(g_dagManager.GetDAGKnightAnchorMetrics(
            merge->GetBlockHash(), snapshot.selectedParent,
            snapshot.inferredK, snapshot.score, snapshot.colors));
        snapshot.order =
            g_dagManager.GetDAGLinearOrder(merge->GetBlockHash(), 0, true);
        CBlockIndex* best = g_dagManager.SelectBestDAGTip();
        BOOST_REQUIRE(best != NULL);
        snapshot.tip = best->GetBlockHash();

        g_dagManager.RebuildDAGOrder();
        uint256 rebuiltParent;
        uint256 rebuiltScore;
        int rebuiltK = 0;
        std::vector<std::pair<uint256, bool> > rebuiltColors;
        BOOST_REQUIRE(g_dagManager.GetDAGKnightAnchorMetrics(
            merge->GetBlockHash(), rebuiltParent, rebuiltK,
            rebuiltScore, rebuiltColors));
        BOOST_CHECK(snapshot.order ==
                    g_dagManager.GetDAGLinearOrder(
                        merge->GetBlockHash(), 0, true));
        BOOST_CHECK(snapshot.colors == rebuiltColors);
        BOOST_CHECK(snapshot.selectedParent == rebuiltParent);
        BOOST_CHECK(snapshot.score == rebuiltScore);
        BOOST_CHECK_EQUAL(snapshot.inferredK, rebuiltK);
        return snapshot;
    };

    const Snapshot forward = run(false);
    const Snapshot reverse = run(true);
    BOOST_CHECK(forward.order == reverse.order);
    BOOST_CHECK(forward.colors == reverse.colors);
    BOOST_CHECK(forward.selectedParent == reverse.selectedParent);
    BOOST_CHECK(forward.score == reverse.score);
    BOOST_CHECK(forward.tip == reverse.tip);
    BOOST_CHECK_EQUAL(forward.inferredK, reverse.inferredK);
    BOOST_CHECK_GE(forward.inferredK, DAGKNIGHT_K_FLOOR);
    BOOST_CHECK_LE(forward.inferredK, DAGKNIGHT_K_CEILING);
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

BOOST_AUTO_TEST_CASE(v3_ignores_unconnected_merge_finality_carriers)
{
    DAGHarness h;
    const int E = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3);
    const int hStart = GetEpochBoundaryHeight(E, FORK_HEIGHT_EPOCH_STATE_V3);
    const int hEnd = GetEpochBoundaryHeight(E + 1,
                                            FORK_HEIGHT_EPOCH_STATE_V3) - 1;
    const int interval = hEnd - hStart + 1;

    // This certificate is canonically encoded but deliberately has never
    // passed CheckTallyCertificate/ConnectBlock. A merge sibling may carry it
    // as ordinary transaction data, but it cannot influence finality state.
    CFinalityTallyCertificate unvalidated;
    unvalidated.nVersion = 2;
    unvalidated.nEpoch = E;
    unvalidated.hashBlock = uint256(0xFA110001);
    unvalidated.nHeight = hStart + 1;
    unvalidated.nTier = FINALITY_HARD;
    unvalidated.nConsecutiveHardCount = FINALITY_CONFIRMATION_EPOCHS;
    unvalidated.nTransparentActiveWeight = 3;
    unvalidated.nTransparentWinningWeight = 3;
    unvalidated.MarkCanonicalEnvelope();
    CScript carrierScript;
    BOOST_REQUIRE(BuildCanonicalFinalityTallyCertificateScript(
        unvalidated, carrierScript));

    std::vector<uint256> none;
    CBlockIndex* pBefore = h.add(0xFA110000, hStart - 1, none, NULL);
    std::vector<uint256> beforeParent(1, pBefore->GetBlockHash());
    CBlockIndex* pBase = h.add(0xFA110010, hStart, beforeParent, pBefore);
    std::vector<uint256> baseParent(1, pBase->GetBlockHash());
    CBlockIndex* pSide = h.add(0xFA110011, hStart + 1, baseParent,
                               pBase, true, &carrierScript);
    CBlockIndex* pMain = h.add(0xFA110012, hStart + 1, baseParent, pBase);
    std::vector<uint256> mergeParents;
    mergeParents.push_back(pMain->GetBlockHash());
    mergeParents.push_back(pSide->GetBlockHash());
    pMain = h.add(0xFA110013, hStart + 2, mergeParents, pMain);
    for (int nHeight = hStart + 3; nHeight <= hEnd; ++nHeight)
    {
        std::vector<uint256> parents(1, pMain->GetBlockHash());
        pMain = h.add(0xFA110000U +
                          (unsigned int)(nHeight - hStart + 0x20),
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
    BOOST_REQUIRE_MESSAGE(g_dagManager.BuildEpochState(
                              E, interval, pMain, state, tree, strError,
                              &prev, &prevTree), strError);
    BOOST_CHECK(contains(state.vBlockHashes, pSide->GetBlockHash()));
    BOOST_CHECK_EQUAL(state.nFinalityTier, FINALITY_NONE);
    BOOST_CHECK(state.hashFinalityCertificate == 0);
}

BOOST_AUTO_TEST_CASE(v2_preserves_pre_fork_merge_finality_carrier_bytes)
{
    DAGHarness h;
    const int nCarrierFork = FORK_HEIGHT_CONNECTED_FINALITY_CARRIER;
    const int E = GetEpochForHeight(nCarrierFork);
    const int hStart = GetEpochBoundaryHeight(E, nCarrierFork);
    const int hEnd = GetEpochBoundaryHeight(E + 1, nCarrierFork) - 1;
    const int hCarrier = nCarrierFork - 1;
    BOOST_REQUIRE_EQUAL(nCarrierFork, FORK_HEIGHT_DAG + 2);
    BOOST_REQUIRE(hCarrier >= hStart);
    BOOST_REQUIRE(hEnd < FORK_HEIGHT_EPOCH_STATE_V3);

    const uint256 hashChoice(0xC2F10001);
    const uint256 nullifier(0xC2F10002);
    const CFinalityVote vote = BuildV2CarrierVote(
        E, hCarrier, hashChoice, nullifier);
    const CFinalityTallyCertificate cert = BuildV2CarrierCertificate(
        E, hCarrier, hashChoice, FINALITY_HARD, nullifier);
    const CScript voteScript = BuildFinalityVoteScript(vote);
    const CScript certScript = BuildFinalityTallyCertificateScript(cert);

    std::vector<uint256> none;
    CBlockIndex* pBefore = h.add(0xC2F10010, hStart - 1, none, NULL);
    std::vector<uint256> beforeParent(1, pBefore->GetBlockHash());
    CBlockIndex* pBase = h.add(0xC2F10011, hStart, beforeParent, pBefore);
    std::vector<uint256> baseParent(1, pBase->GetBlockHash());
    CBlockIndex* pSide = h.add(0xC2F10012, hCarrier, baseParent,
                               pBase, true, &certScript, &voteScript);
    CBlockIndex* pMain = h.add(0xC2F10013, hCarrier, baseParent, pBase);
    std::vector<uint256> mergeParents;
    mergeParents.push_back(pMain->GetBlockHash());
    mergeParents.push_back(pSide->GetBlockHash());
    pMain = h.add(0xC2F10014, nCarrierFork, mergeParents, pMain);
    for (int nHeight = nCarrierFork + 1; nHeight <= hEnd; ++nHeight)
    {
        std::vector<uint256> parents(1, pMain->GetBlockHash());
        pMain = h.add(0xC2F11000U +
                          (unsigned int)(nHeight - nCarrierFork),
                      nHeight, parents, pMain);
    }
    std::vector<uint256> crossingParents(1, pMain->GetBlockHash());
    CBlockIndex* pCrossing = h.add(0xC2F1FFFF, hEnd + 1,
                                    crossingParents, pMain);

    CEpochState prev;
    prev.nEpoch = E - 1;
    prev.hashBoundaryBlock = pBefore->GetBlockHash();
    prev.nHeightStart = GetEpochBoundaryHeight(E - 1, hStart);
    prev.nHeightEnd = hStart - 1;
    CCurveTree prevTree;
    CEpochState state;
    CCurveTree tree;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(g_dagManager.BuildEpochStateV2Compat(
                              E, hEnd - hStart + 1, pCrossing,
                              state, tree, strError, &prev, &prevTree),
                          strError);

    std::map<uint256, uint256> expectedLeaves;
    expectedLeaves[nullifier] = hashChoice;
    BOOST_CHECK(contains(state.vBlockHashes, pSide->GetBlockHash()));
    BOOST_CHECK_EQUAL(state.nFinalityTier, FINALITY_HARD);
    BOOST_CHECK(state.hashFinalityCertificate == cert.GetHash());
    BOOST_CHECK(state.hashVoteSetRoot ==
                BuildExpectedV2VoteSetRoot(E, expectedLeaves));
}

BOOST_AUTO_TEST_CASE(v2_ignores_post_fork_merge_finality_carriers)
{
    DAGHarness h;
    const int nCarrierFork = FORK_HEIGHT_CONNECTED_FINALITY_CARRIER;
    const int E = GetEpochForHeight(nCarrierFork);
    const int hStart = GetEpochBoundaryHeight(E, nCarrierFork);
    const int hEnd = GetEpochBoundaryHeight(E + 1, nCarrierFork) - 1;
    BOOST_REQUIRE_EQUAL(nCarrierFork, FORK_HEIGHT_DAG + 2);
    BOOST_REQUIRE(nCarrierFork >= hStart);
    BOOST_REQUIRE(hEnd < FORK_HEIGHT_EPOCH_STATE_V3);

    const uint256 hashCanonicalChoice(0xC2F20001);
    const uint256 canonicalNullifier(0xC2F20002);
    const CFinalityVote canonicalVote = BuildV2CarrierVote(
        E, nCarrierFork, hashCanonicalChoice, canonicalNullifier);
    const CFinalityTallyCertificate canonicalCert =
        BuildV2CarrierCertificate(E, nCarrierFork,
                                  hashCanonicalChoice, FINALITY_SOFT,
                                  canonicalNullifier);
    const CScript canonicalVoteScript =
        BuildFinalityVoteScript(canonicalVote);
    const CScript canonicalCertScript =
        BuildFinalityTallyCertificateScript(canonicalCert);

    // These parse as legacy V2 carriers but have never passed ConnectBlock's
    // contextual vote/certificate validation.  Their stronger tier and
    // distinct vote leaf make accidental inclusion directly observable.
    const uint256 hashMergeChoice(0xC2F20011);
    const uint256 mergeNullifier(0xC2F20012);
    const CFinalityVote mergeVote = BuildV2CarrierVote(
        E, nCarrierFork, hashMergeChoice, mergeNullifier);
    const CFinalityTallyCertificate mergeCert =
        BuildV2CarrierCertificate(E, nCarrierFork,
                                  hashMergeChoice, FINALITY_HARD,
                                  mergeNullifier);
    const CScript mergeVoteScript = BuildFinalityVoteScript(mergeVote);
    const CScript mergeCertScript =
        BuildFinalityTallyCertificateScript(mergeCert);

    std::vector<uint256> none;
    CBlockIndex* pBefore = h.add(0xC2F20020, hStart - 1, none, NULL);
    CBlockIndex* pMain = pBefore;
    for (int nHeight = hStart; nHeight < nCarrierFork; ++nHeight)
    {
        std::vector<uint256> parents(1, pMain->GetBlockHash());
        pMain = h.add(0xC2F20020U +
                          (unsigned int)(nHeight - hStart + 1),
                      nHeight, parents, pMain);
    }
    std::vector<uint256> forkParent(1, pMain->GetBlockHash());
    CBlockIndex* pSide = h.add(0xC2F20030, nCarrierFork, forkParent,
                               pMain, true, &mergeCertScript,
                               &mergeVoteScript);
    CBlockIndex* pCanonical = h.add(
        0xC2F20031, nCarrierFork, forkParent, pMain, true,
        &canonicalCertScript, &canonicalVoteScript);
    std::vector<uint256> mergeParents;
    mergeParents.push_back(pCanonical->GetBlockHash());
    mergeParents.push_back(pSide->GetBlockHash());
    pMain = h.add(0xC2F20032, nCarrierFork + 1,
                  mergeParents, pCanonical);
    for (int nHeight = nCarrierFork + 2; nHeight <= hEnd; ++nHeight)
    {
        std::vector<uint256> parents(1, pMain->GetBlockHash());
        pMain = h.add(0xC2F21000U +
                          (unsigned int)(nHeight - nCarrierFork),
                      nHeight, parents, pMain);
    }
    std::vector<uint256> crossingParents(1, pMain->GetBlockHash());
    CBlockIndex* pCrossing = h.add(0xC2F2FFFF, hEnd + 1,
                                    crossingParents, pMain);

    CEpochState prev;
    prev.nEpoch = E - 1;
    prev.hashBoundaryBlock = pBefore->GetBlockHash();
    prev.nHeightStart = GetEpochBoundaryHeight(E - 1, hStart);
    prev.nHeightEnd = hStart - 1;
    CCurveTree prevTree;
    CEpochState state;
    CCurveTree tree;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(g_dagManager.BuildEpochStateV2Compat(
                              E, hEnd - hStart + 1, pCrossing,
                              state, tree, strError, &prev, &prevTree),
                          strError);

    std::map<uint256, uint256> expectedLeaves;
    expectedLeaves[canonicalNullifier] = hashCanonicalChoice;
    BOOST_CHECK(contains(state.vBlockHashes, pSide->GetBlockHash()));
    BOOST_CHECK(contains(state.vBlockHashes, pCanonical->GetBlockHash()));
    BOOST_CHECK_EQUAL(state.nFinalityTier, FINALITY_SOFT);
    BOOST_CHECK(state.hashFinalityCertificate == canonicalCert.GetHash());
    BOOST_CHECK(state.hashFinalityCertificate != mergeCert.GetHash());
    BOOST_CHECK(state.hashVoteSetRoot ==
                BuildExpectedV2VoteSetRoot(E, expectedLeaves));
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

// A spend may anchor to a recent root rather than only the newest, so the accessor that
// names those roots must reach back a fixed number of epochs and no further. The epoch it
// resolves is derived from the chain, so every node offers a spend the same set.
BOOST_AUTO_TEST_CASE(finalized_epoch_state_walks_back_a_bounded_number_of_epochs)
{
    CDAGManager manager;
    CTxDB txdb("rw");
    BOOST_REQUIRE(txdb.TxnBegin());

    // Derive the epoch the height resolves to rather than assuming an interval, then pick
    // a finalized height inside it so the resolved epoch is that same one.
    int nHeight = 0;
    for (int h = 1; h <= 1000000; ++h)
    {
        if (GetEpochForHeight(h) - 1 >= 3)
        {
            nHeight = h;
            break;
        }
    }
    BOOST_REQUIRE(nHeight > 0);
    const int nAsOfEpoch = GetEpochForHeight(nHeight) - 1;
    BOOST_REQUIRE(nAsOfEpoch >= 3);
    int nFinalizedHeight = -1;
    for (int h = nHeight; h >= 0; --h)
    {
        if (GetEpochForHeight(h) == nAsOfEpoch)
        {
            nFinalizedHeight = h;
            break;
        }
    }
    BOOST_REQUIRE(nFinalizedHeight >= 0);

    for (int i = 0; i < 3; ++i)
    {
        CEpochState state;
        state.nEpoch = nAsOfEpoch - i;
        state.hashBoundaryBlock = uint256(0x80000001 + i);
        state.nFinalizedHeightAsOf = (i == 0) ? nFinalizedHeight : 0;
        state.nBlockCount = 0;
        CCurveTree tree;
        BOOST_REQUIRE(manager.WriteEpochState(txdb, state, tree));
    }

    // Each step back must name exactly one earlier epoch.
    CEpochState resolved;
    for (int nBack = 0; nBack < 3; ++nBack)
    {
        BOOST_REQUIRE(manager.GetFinalizedEpochStateAsOf(txdb, nHeight, nBack,
                                                         resolved));
        BOOST_CHECK_EQUAL(resolved.nEpoch, nAsOfEpoch - nBack);
    }

    // Past what the chain holds, and below epoch zero, there is nothing to offer.
    BOOST_CHECK(!manager.GetFinalizedEpochStateAsOf(txdb, nHeight, 3, resolved));
    BOOST_CHECK(!manager.GetFinalizedEpochStateAsOf(txdb, nHeight, -1, resolved));
    BOOST_CHECK(!manager.GetFinalizedEpochStateAsOf(txdb, nHeight, nAsOfEpoch + 1,
                                                    resolved));

    // The zero-step form must agree with the accessor that takes no age at all.
    CEpochState latest;
    BOOST_REQUIRE(manager.GetFinalizedEpochStateAsOf(txdb, nHeight, latest));
    BOOST_REQUIRE(manager.GetFinalizedEpochStateAsOf(txdb, nHeight, 0, resolved));
    BOOST_CHECK_EQUAL(latest.nEpoch, resolved.nEpoch);
    BOOST_CHECK(latest.hashBoundaryBlock == resolved.hashBoundaryBlock);

    txdb.TxnAbort();
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

BOOST_AUTO_TEST_CASE(v3_restart_accepts_v2_prefix_but_checks_strict_migration_suffix)
{
    DAGHarness h;
    const int nFirstStrictEpoch =
        GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3) - 1;
    BOOST_REQUIRE_EQUAL(nFirstStrictEpoch, 1);
    const int nPrefixEpoch = nFirstStrictEpoch - 1;

    // Regtest's mixed-generation shape: epoch 0 from the V2 compatibility path
    // (nBlockCount 0), epoch 1 rebuilt as the V3 migration base, schema marker V3.
    CEpochState prefix;
    prefix.nEpoch = nPrefixEpoch;
    prefix.nHeightStart =
        GetEpochBoundaryHeight(nPrefixEpoch, FORK_HEIGHT_EPOCH_STATE_V3);
    prefix.nHeightEnd =
        GetEpochBoundaryHeight(nPrefixEpoch + 1,
                               FORK_HEIGHT_EPOCH_STATE_V3) - 1;
    prefix.hashBoundaryBlock = uint256(0xe3000001);
    prefix.vBlockHashes.push_back(prefix.hashBoundaryBlock);
    prefix.nBlockCount = 0;
    prefix.nTxCount = -1;

    const int nMigrationEnd =
        GetEpochBoundaryHeight(nFirstStrictEpoch + 1,
                               FORK_HEIGHT_EPOCH_STATE_V3) - 1;
    std::vector<uint256> noParents;
    CBlockIndex* pMigrationBoundary =
        h.add(0xE3000002, nMigrationEnd, noParents, NULL, false);
    CEpochState migration;
    migration.nEpoch = nFirstStrictEpoch;
    migration.nHeightStart =
        GetEpochBoundaryHeight(nFirstStrictEpoch,
                               FORK_HEIGHT_EPOCH_STATE_V3);
    migration.nHeightEnd = nMigrationEnd;
    migration.hashBoundaryBlock = pMigrationBoundary->GetBlockHash();
    migration.vBlockHashes.push_back(migration.hashBoundaryBlock);
    migration.nBlockCount = 1;
    migration.nTxCount = -1;

    CCurveTree emptyTree;
    EpochStateRestartTestDB txdb;
    int nOldSchema = 0;
    const bool fHadOldSchema = txdb.ReadEpochStateSchema(nOldSchema);
    CEpochState oldState;
    CCurveTree oldTree;
    BOOST_REQUIRE(!txdb.ReadEpochState(nPrefixEpoch, oldState));
    BOOST_REQUIRE(!txdb.ReadCurveTreeAtEpoch(nPrefixEpoch, oldTree));
    BOOST_REQUIRE(!txdb.ReadEpochState(nFirstStrictEpoch, oldState));
    BOOST_REQUIRE(!txdb.ReadCurveTreeAtEpoch(nFirstStrictEpoch, oldTree));
    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.WriteEpochState(nPrefixEpoch, prefix));
    BOOST_REQUIRE(txdb.WriteCurveTreeAtEpoch(nPrefixEpoch, emptyTree));
    BOOST_REQUIRE(txdb.WriteEpochState(nFirstStrictEpoch, migration));
    BOOST_REQUIRE(txdb.WriteCurveTreeAtEpoch(nFirstStrictEpoch, emptyTree));
    BOOST_REQUIRE(txdb.WriteEpochStateSchema(EPOCHSTATE_SCHEMA_V3));
    BOOST_REQUIRE(txdb.TxnCommit());

    CDAGManager restarted;
    BOOST_REQUIRE(restarted.InitBlockDAGData(pMigrationBoundary, noParents));
    BOOST_CHECK(restarted.LoadEpochStates(txdb));
    CEpochState loadedPrefix;
    BOOST_REQUIRE(restarted.GetEpochState(nPrefixEpoch, loadedPrefix));
    BOOST_CHECK_EQUAL(loadedPrefix.nBlockCount, 0);
    BOOST_CHECK_EQUAL(loadedPrefix.vBlockHashes.size(), 1U);

    // The compatibility exception is prefix-only.  The exact same mismatch
    // in the strict migration epoch remains fatal, preserving fail-closed
    // recovery for the V3 suffix.
    migration.nBlockCount = 0;
    BOOST_REQUIRE(txdb.WriteEpochState(nFirstStrictEpoch, migration));
    CDAGManager corruptRestart;
    BOOST_REQUIRE(corruptRestart.InitBlockDAGData(pMigrationBoundary, noParents));
    BOOST_CHECK(!corruptRestart.LoadEpochStates(txdb));

    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.EraseEpochState(nPrefixEpoch));
    BOOST_REQUIRE(txdb.EraseCurveTreeAtEpoch(nPrefixEpoch));
    BOOST_REQUIRE(txdb.EraseEpochState(nFirstStrictEpoch));
    BOOST_REQUIRE(txdb.EraseCurveTreeAtEpoch(nFirstStrictEpoch));
    if (fHadOldSchema)
        BOOST_REQUIRE(txdb.WriteEpochStateSchema(nOldSchema));
    else
        BOOST_REQUIRE(txdb.EraseEpochStateSchemaForTest());
    BOOST_REQUIRE(txdb.TxnCommit());
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

BOOST_AUTO_TEST_CASE(v4_frontiers_and_active_transaction_set_serialize_exactly)
{
    PrivacyVNextEpochSeed seed;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(LoadPrivacyVNextEpochSeed(seed, strError), strError);

    PrivacyVNextDigest keyImage;
    keyImage.fill(0x66);
    keyImage[0] = 0x58;
    std::vector<PrivacyVNextDigest> keyImages(1, keyImage);
    std::vector<unsigned char> nullifierState;
    std::vector<unsigned char> nullifierRoot;
    uint64_t nullifierCount = 0;
    BOOST_REQUIRE_MESSAGE(ApplyPrivacyVNextNullifiers(
                              seed.vchNullifierState, keyImages,
                              nullifierState, nullifierRoot,
                              nullifierCount, strError),
                          strError);

    CEpochState state;
    state.nEpoch = 910001;
    state.nHeightStart = 1;
    state.nHeightEnd = 1;
    state.hashBoundaryBlock = uint256(0x91000101);
    state.vBlockHashes.push_back(state.hashBoundaryBlock);
    state.nBlockCount = 1;
    state.nTxCount = 1;
    state.nSerVersion = EPOCHSTATE_SER_VERSION_V4;
    state.vchVNextTreeState = seed.vchTreeState;
    state.vchVNextRoot = seed.vchRoot;
    state.nVNextTreeSize = seed.nTreeSize;
    state.vchVNextNullifierState = nullifierState;
    state.hashVNextNullifierRoot = uint256(nullifierRoot);
    state.nVNextNullifierCount = nullifierCount;
    state.vVNextEpochNullifiers.push_back(uint256(
        std::vector<unsigned char>(keyImage.begin(), keyImage.end())));
    state.vchVNextParameterDigest = seed.vchParameterDigest;
    state.hashVNextFinalizedAnchor = uint256(0x91000102);
    state.nVNextFinalizedHeight = 0;
    state.vVNextActiveBlockTxCounts.push_back(1);
    state.vVNextActiveTxIds.push_back(uint256(0x91000103));
    CHashWriter activeSetHasher(SER_GETHASH, 0);
    activeSetHasher << std::string("Innova/IV5/ActiveDAGTransactionSet/v1");
    activeSetHasher << state.hashBoundaryBlock << state.vBlockHashes;
    activeSetHasher << state.vVNextActiveBlockTxCounts;
    activeSetHasher << state.vVNextActiveTxIds;
    state.hashVNextActiveTxSet = activeSetHasher.GetHash();

    CDataStream encoded(SER_DISK, CLIENT_VERSION);
    encoded << state;
    CEpochState decoded;
    encoded >> decoded;
    BOOST_CHECK(encoded.empty());
    BOOST_CHECK_EQUAL(decoded.nSerVersion, EPOCHSTATE_SER_VERSION_V4);
    BOOST_CHECK(decoded.GetDigest() == state.GetDigest());
    BOOST_CHECK(decoded.vchVNextNullifierState == nullifierState);
    BOOST_CHECK(decoded.vVNextEpochNullifiers == state.vVNextEpochNullifiers);
    BOOST_CHECK(decoded.vVNextActiveBlockTxCounts ==
                state.vVNextActiveBlockTxCounts);
    BOOST_CHECK(decoded.vVNextActiveTxIds == state.vVNextActiveTxIds);

    CDAGManager manager;
    CCurveTree emptyTree;
    CTxDB txdb("rw");
    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(manager.WriteEpochState(txdb, state, emptyTree));
    txdb.TxnAbort();

    CEpochState corrupt = state;
    corrupt.vchVNextNullifierState[12] ^= 1;
    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_CHECK(!manager.WriteEpochState(txdb, corrupt, emptyTree));
    txdb.TxnAbort();

    corrupt = state;
    corrupt.vVNextActiveBlockTxCounts[0] = 2;
    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_CHECK(!manager.WriteEpochState(txdb, corrupt, emptyTree));
    txdb.TxnAbort();

    corrupt = state;
    corrupt.hashVNextActiveTxSet = uint256(0x91000104);
    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_CHECK(!manager.WriteEpochState(txdb, corrupt, emptyTree));
    txdb.TxnAbort();
}

BOOST_AUTO_TEST_CASE(v4_exact_nullifier_index_tracks_atomic_batches)
{
    const uint256 keyImage = uint256(
        "42a1186f1c89f79361a76f5fe270c92c5c82f879f19512d62f6f46f2f6ef3108");
    CShieldedNullifierSpent spent;
    spent.txnHash = uint256(
        "75f9f96e0e5a12341c547f1c3389cd55906f2fcedec4727a8989b95388b60401");
    spent.nIndex = 3;

    CTxDB txdb("r+");
    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.ErasePrivacyVNextNullifier(keyImage));
    BOOST_REQUIRE(txdb.TxnCommit(true));

    uint64_t nBaselineCount = 0;
    std::string strCountError;
    BOOST_REQUIRE(txdb.CountPrivacyVNextNullifiers(
        nBaselineCount, strCountError));

    CShieldedNullifierSpent observed;
    BOOST_CHECK_EQUAL(txdb.ReadPrivacyVNextNullifierStatus(keyImage, observed),
                      TXDB_READ_NOT_FOUND);

    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.WritePrivacyVNextNullifier(keyImage, spent));
    BOOST_REQUIRE_EQUAL(
        txdb.ReadPrivacyVNextNullifierStatus(keyImage, observed),
        TXDB_READ_FOUND);
    BOOST_CHECK(observed.txnHash == spent.txnHash);
    BOOST_CHECK_EQUAL(observed.nIndex, spent.nIndex);
    BOOST_REQUIRE(txdb.TxnAbort());
    BOOST_CHECK_EQUAL(txdb.ReadPrivacyVNextNullifierStatus(keyImage, observed),
                      TXDB_READ_NOT_FOUND);

    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.WritePrivacyVNextNullifier(keyImage, spent));
    BOOST_REQUIRE(txdb.TxnCommit(true));

    CTxDB reopened("r+");
    BOOST_REQUIRE_EQUAL(
        reopened.ReadPrivacyVNextNullifierStatus(keyImage, observed),
        TXDB_READ_FOUND);
    BOOST_CHECK(observed.txnHash == spent.txnHash);
    BOOST_CHECK_EQUAL(observed.nIndex, spent.nIndex);
    uint64_t nCommittedCount = 0;
    BOOST_REQUIRE(reopened.CountPrivacyVNextNullifiers(
        nCommittedCount, strCountError));
    BOOST_CHECK_EQUAL(nCommittedCount, nBaselineCount + 1);

    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.ErasePrivacyVNextNullifier(keyImage));
    BOOST_REQUIRE(txdb.TxnAbort());
    BOOST_REQUIRE_EQUAL(
        reopened.ReadPrivacyVNextNullifierStatus(keyImage, observed),
        TXDB_READ_FOUND);

    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.ErasePrivacyVNextNullifier(keyImage));
    BOOST_REQUIRE(txdb.TxnCommit(true));
    BOOST_CHECK_EQUAL(
        reopened.ReadPrivacyVNextNullifierStatus(keyImage, observed),
        TXDB_READ_NOT_FOUND);
    uint64_t nFinalCount = 0;
    BOOST_REQUIRE(reopened.CountPrivacyVNextNullifiers(
        nFinalCount, strCountError));
    BOOST_CHECK_EQUAL(nFinalCount, nBaselineCount);
}

BOOST_AUTO_TEST_CASE(v4_restart_conflict_reorg_and_shortening_converge_exactly)
{
    PrivacyVNextEpochSeed seed;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(LoadPrivacyVNextEpochSeed(seed, strError), strError);

    const int E = 910002;
    CEpochState branchA;
    CEpochState branchB;
    uint256 keyImageA;
    uint256 keyImageB;

    const auto buildBranch = [&](const PrivacyVNextDigest& keyImage,
                                 const uint256& boundary,
                                 const uint256& activeTx,
                                 CEpochState& state,
                                 uint256& keyImageOut) {
        std::vector<PrivacyVNextDigest> keyImages(1, keyImage);
        std::vector<unsigned char> nullifierState;
        std::vector<unsigned char> nullifierRoot;
        uint64_t nullifierCount = 0;
        strError.clear();
        BOOST_REQUIRE_MESSAGE(ApplyPrivacyVNextNullifiers(
                                  seed.vchNullifierState, keyImages,
                                  nullifierState, nullifierRoot,
                                  nullifierCount, strError),
                              strError);

        state.nEpoch = E;
        state.nHeightStart = 1;
        state.nHeightEnd = 1;
        state.hashBoundaryBlock = boundary;
        state.vBlockHashes.push_back(boundary);
        state.nBlockCount = 1;
        state.nTxCount = 1;
        state.nSerVersion = EPOCHSTATE_SER_VERSION_V4;
        state.vchVNextTreeState = seed.vchTreeState;
        state.vchVNextRoot = seed.vchRoot;
        state.nVNextTreeSize = seed.nTreeSize;
        state.vchVNextNullifierState = nullifierState;
        state.hashVNextNullifierRoot = uint256(nullifierRoot);
        state.nVNextNullifierCount = nullifierCount;
        keyImageOut = uint256(std::vector<unsigned char>(
            keyImage.begin(), keyImage.end()));
        state.vVNextEpochNullifiers.push_back(keyImageOut);
        state.vchVNextParameterDigest = seed.vchParameterDigest;
        state.hashVNextFinalizedAnchor = boundary;
        state.nVNextFinalizedHeight = 0;
        state.vVNextActiveBlockTxCounts.push_back(1);
        state.vVNextActiveTxIds.push_back(activeTx);
        CHashWriter activeSetHasher(SER_GETHASH, 0);
        activeSetHasher << std::string("Innova/IV5/ActiveDAGTransactionSet/v1");
        activeSetHasher << state.hashBoundaryBlock << state.vBlockHashes;
        activeSetHasher << state.vVNextActiveBlockTxCounts;
        activeSetHasher << state.vVNextActiveTxIds;
        state.hashVNextActiveTxSet = activeSetHasher.GetHash();
    };

    PrivacyVNextDigest vectorA;
    vectorA.fill(0x66);
    vectorA[0] = 0x58;
    PrivacyVNextDigest vectorB = vectorA;
    vectorB[31] = 0xe6;
    buildBranch(vectorA, uint256(0x910002a1), uint256(0x910002a2),
                branchA, keyImageA);
    buildBranch(vectorB, uint256(0x910002b1), uint256(0x910002b2),
                branchB, keyImageB);
    BOOST_REQUIRE(keyImageA != keyImageB);
    BOOST_REQUIRE(branchA.hashVNextNullifierRoot !=
                  branchB.hashVNextNullifierRoot);
    BOOST_REQUIRE(branchA.hashVNextActiveTxSet !=
                  branchB.hashVNextActiveTxSet);
    BOOST_REQUIRE(branchA.GetDigest() != branchB.GetDigest());

    const auto checkExactState = [](const CEpochState& actual,
                                    const CEpochState& expected) {
        BOOST_CHECK_EQUAL(actual.nSerVersion, EPOCHSTATE_SER_VERSION_V4);
        BOOST_CHECK_EQUAL(actual.nEpoch, expected.nEpoch);
        BOOST_CHECK(actual.hashBoundaryBlock == expected.hashBoundaryBlock);
        BOOST_CHECK_EQUAL(actual.nHeightStart, expected.nHeightStart);
        BOOST_CHECK_EQUAL(actual.nHeightEnd, expected.nHeightEnd);
        BOOST_CHECK(actual.vBlockHashes == expected.vBlockHashes);
        BOOST_CHECK_EQUAL(actual.nBlockCount, expected.nBlockCount);
        BOOST_CHECK_EQUAL(actual.nTxCount, expected.nTxCount);
        BOOST_CHECK(actual.vchVNextTreeState == expected.vchVNextTreeState);
        BOOST_CHECK(actual.vchVNextRoot == expected.vchVNextRoot);
        BOOST_CHECK_EQUAL(actual.nVNextTreeSize, expected.nVNextTreeSize);
        BOOST_CHECK(actual.vchVNextNullifierState ==
                    expected.vchVNextNullifierState);
        BOOST_CHECK(actual.hashVNextNullifierRoot ==
                    expected.hashVNextNullifierRoot);
        BOOST_CHECK_EQUAL(actual.nVNextNullifierCount,
                          expected.nVNextNullifierCount);
        BOOST_CHECK(actual.vVNextEpochNullifiers ==
                    expected.vVNextEpochNullifiers);
        BOOST_CHECK(actual.vchVNextParameterDigest ==
                    expected.vchVNextParameterDigest);
        BOOST_CHECK(actual.hashVNextFinalizedAnchor ==
                    expected.hashVNextFinalizedAnchor);
        BOOST_CHECK_EQUAL(actual.nVNextFinalizedHeight,
                          expected.nVNextFinalizedHeight);
        BOOST_CHECK(actual.vVNextActiveBlockTxCounts ==
                    expected.vVNextActiveBlockTxCounts);
        BOOST_CHECK(actual.vVNextActiveTxIds == expected.vVNextActiveTxIds);
        BOOST_CHECK(actual.hashVNextActiveTxSet ==
                    expected.hashVNextActiveTxSet);
        BOOST_CHECK(actual.GetDigest() == expected.GetDigest());
    };

    CShieldedNullifierSpent ownerA;
    ownerA.txnHash = branchA.vVNextActiveTxIds[0];
    ownerA.nIndex = 0;
    CShieldedNullifierSpent ownerB;
    ownerB.txnHash = branchB.vVNextActiveTxIds[0];
    ownerB.nIndex = 0;
    CCurveTree emptyTree;
    CDAGManager manager;
    CTxDB txdb("r+");

    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.EraseEpochState(E));
    BOOST_REQUIRE(txdb.EraseCurveTreeAtEpoch(E));
    BOOST_REQUIRE(txdb.ErasePrivacyVNextNullifier(keyImageA));
    BOOST_REQUIRE(txdb.ErasePrivacyVNextNullifier(keyImageB));
    BOOST_REQUIRE(txdb.TxnCommit(true));

    uint64_t baselineCount = 0;
    BOOST_REQUIRE(txdb.CountPrivacyVNextNullifiers(baselineCount, strError));

    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(manager.WriteEpochState(txdb, branchA, emptyTree));
    BOOST_REQUIRE(txdb.WritePrivacyVNextNullifier(keyImageA, ownerA));
    BOOST_REQUIRE(txdb.TxnCommit(true));

    CTxDB restartedA("r+");
    CEpochState loaded;
    CCurveTree loadedTree;
    BOOST_REQUIRE(restartedA.ReadEpochState(E, loaded));
    BOOST_REQUIRE(restartedA.ReadCurveTreeAtEpoch(E, loadedTree));
    BOOST_CHECK(loadedTree.IsEmpty());
    checkExactState(loaded, branchA);
    CShieldedNullifierSpent observed;
    BOOST_REQUIRE_EQUAL(
        restartedA.ReadPrivacyVNextNullifierStatus(keyImageA, observed),
        TXDB_READ_FOUND);
    BOOST_CHECK(observed.txnHash == ownerA.txnHash);
    BOOST_CHECK_EQUAL(observed.nIndex, ownerA.nIndex);
    uint64_t branchCount = 0;
    BOOST_REQUIRE(restartedA.CountPrivacyVNextNullifiers(
        branchCount, strError));
    BOOST_CHECK_EQUAL(branchCount, baselineCount + 1);

    // Model the single LevelDB transaction used by a conflict reorg: remove
    // the old suffix and exact spent-key owner, then install the replacement.
    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(manager.EraseEpochStateSuffix(txdb, E));
    BOOST_REQUIRE(txdb.ErasePrivacyVNextNullifier(keyImageA));
    BOOST_REQUIRE(manager.WriteEpochState(txdb, branchB, emptyTree));
    BOOST_REQUIRE(txdb.WritePrivacyVNextNullifier(keyImageB, ownerB));
    BOOST_REQUIRE(txdb.TxnCommit(true));

    CTxDB restartedB("r+");
    BOOST_REQUIRE(restartedB.ReadEpochState(E, loaded));
    BOOST_REQUIRE(restartedB.ReadCurveTreeAtEpoch(E, loadedTree));
    BOOST_CHECK(loadedTree.IsEmpty());
    checkExactState(loaded, branchB);
    BOOST_CHECK_EQUAL(
        restartedB.ReadPrivacyVNextNullifierStatus(keyImageA, observed),
        TXDB_READ_NOT_FOUND);
    BOOST_REQUIRE_EQUAL(
        restartedB.ReadPrivacyVNextNullifierStatus(keyImageB, observed),
        TXDB_READ_FOUND);
    BOOST_CHECK(observed.txnHash == ownerB.txnHash);
    BOOST_CHECK_EQUAL(observed.nIndex, ownerB.nIndex);
    BOOST_REQUIRE(restartedB.CountPrivacyVNextNullifiers(
        branchCount, strError));
    BOOST_CHECK_EQUAL(branchCount, baselineCount + 1);

    // A shortening reorg removes the entire replacement suffix and its exact
    // spent-key owner. A fresh wrapper must observe the pre-branch baseline.
    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(manager.EraseEpochStateSuffix(txdb, E));
    BOOST_REQUIRE(txdb.ErasePrivacyVNextNullifier(keyImageB));
    BOOST_REQUIRE(txdb.TxnCommit(true));

    CTxDB restartedShort("r+");
    BOOST_CHECK(!restartedShort.ReadEpochState(E, loaded));
    BOOST_CHECK(!restartedShort.ReadCurveTreeAtEpoch(E, loadedTree));
    BOOST_CHECK_EQUAL(
        restartedShort.ReadPrivacyVNextNullifierStatus(keyImageA, observed),
        TXDB_READ_NOT_FOUND);
    BOOST_CHECK_EQUAL(
        restartedShort.ReadPrivacyVNextNullifierStatus(keyImageB, observed),
        TXDB_READ_NOT_FOUND);
    BOOST_REQUIRE(restartedShort.CountPrivacyVNextNullifiers(
        branchCount, strError));
    BOOST_CHECK_EQUAL(branchCount, baselineCount);
}

BOOST_AUTO_TEST_SUITE_END()
