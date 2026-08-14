// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// DAGKNIGHT anchor-cache differential harness.
//
// The anchor cache is disposable, but which entries a DAG change drops is not: dropping
// too few leaves a stale state that a later block inherits, and the block then colours,
// scores and orders differently from a node that dropped everything. That is a chain
// split, so the narrow invalidation is only admissible if it is indistinguishable from
// the wide one on every chain shape.
//
// Each generated shape is replayed twice against the same event sequence -- once dropping
// the whole cache on every change, once dropping only the reachable descendants -- and the
// two runs must agree on every observable: per-block colour, score, inferred k, the
// anchor-derived order/colour vector, the linear order from every anchor, and the selected
// best tip. Each run is then re-derived from scratch with RebuildDAGOrder and must still
// agree, which pins both paths to a full recomputation rather than only to each other.

#include <boost/test/unit_test.hpp>

#include "../dag.h"
#include "../main.h"

#include <algorithm>
#include <sstream>
#include <string>
#include <vector>

extern bool fRegTest;
extern bool fTestNet;

BOOST_AUTO_TEST_SUITE(dagknight_anchor_cache_tests)

namespace {

// One block of a generated shape. nPrev is an index into the shape (-1 for the base
// block); vMerge holds the extra committed DAG parents, also as shape indices.
struct ShapeNode
{
    int nHeight;
    int nPrev;
    std::vector<int> vMerge;

    ShapeNode() : nHeight(0), nPrev(-1) {}
};

// Event sequence: vAttachOrder permutes node indices; vDetach/vReattach remove and
// restore nodes after the paired attach step.
struct Shape
{
    std::string strName;
    std::vector<ShapeNode> vNodes;
    std::vector<int> vAttachOrder;
    std::vector<std::pair<int, int> > vDetach;    // (attach step, node)
    std::vector<std::pair<int, int> > vReattach;  // (attach step, node)
};

struct Rng
{
    uint64_t nState;
    explicit Rng(uint64_t nSeed) : nState(nSeed ? nSeed : 0x9e3779b97f4a7c15ULL) {}
    uint32_t Next()
    {
        nState ^= nState << 13;
        nState ^= nState >> 7;
        nState ^= nState << 17;
        return (uint32_t)(nState >> 32);
    }
    uint32_t Below(uint32_t n) { return n ? Next() % n : 0; }
};

// Mines every block of a shape before any DAG link is committed, so an arrival order can
// reference a parent that has not arrived yet -- the case that produces a late parent.
struct Harness
{
    std::vector<uint256>      vHashes;
    std::vector<CBlockIndex*> vBlocks;
    CBlockIndex*              pOldBest;
    bool                      fOldRegTest;
    bool                      fOldTestNet;
    CBigNum                   bnOldLimit;

    Harness()
    {
        fOldRegTest = fRegTest;
        fOldTestNet = fTestNet;
        bnOldLimit = bnProofOfWorkLimit;
        pOldBest = pindexBest;
        fRegTest = true;
        fTestNet = false;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        pindexBest = NULL;
    }

    ~Harness()
    {
        // Children first, so the second replay does not take a late-parent path.
        for (size_t i = vHashes.size(); i-- > 0; )
        {
            g_dagManager.RemoveBlockDAGData(vHashes[i]);
            mapBlockIndex.erase(vHashes[i]);
            delete vBlocks[i];
        }
        pindexBest = pOldBest;
        bnProofOfWorkLimit = bnOldLimit;
        fRegTest = fOldRegTest;
        fTestNet = fOldTestNet;
    }

    void MineAll(const Shape& shape)
    {
        for (size_t i = 0; i < shape.vNodes.size(); i++)
        {
            const ShapeNode& node = shape.vNodes[i];
            CBlockIndex* pprev = node.nPrev >= 0 ? vBlocks[node.nPrev] : NULL;

            CBlock block;
            block.nVersion = 1;
            block.hashPrevBlock = pprev ? pprev->GetBlockHash() : uint256(0);
            block.nTime = (unsigned int)(1700000000 + node.nHeight);
            block.nBits = bnProofOfWorkLimit.GetCompact();
            block.nNonce = (unsigned int)(i + 1);
            block.hashMerkleRoot = uint256((unsigned int)(i + 1));
            while (!CheckProofOfWork(block.GetHash(), block.nBits))
                ++block.nNonce;

            const uint256 hash = block.GetHash();
            CBlockIndex* pindex = new CBlockIndex(0, 0, block);
            pindex->nHeight = node.nHeight;
            pindex->pprev = pprev;
            std::pair<std::map<uint256, CBlockIndex*>::iterator, bool> ins =
                mapBlockIndex.insert(std::make_pair(hash, pindex));
            BOOST_REQUIRE(ins.second);
            pindex->phashBlock = &ins.first->first;

            vHashes.push_back(hash);
            vBlocks.push_back(pindex);
        }
    }

    std::vector<uint256> ParentsOf(const Shape& shape, int i) const
    {
        const ShapeNode& node = shape.vNodes[i];
        std::vector<uint256> vParents;
        if (node.nPrev >= 0)
            vParents.push_back(vHashes[node.nPrev]);
        for (size_t m = 0; m < node.vMerge.size(); m++)
        {
            const uint256& h = vHashes[node.vMerge[m]];
            if (std::find(vParents.begin(), vParents.end(), h) == vParents.end())
                vParents.push_back(h);
        }
        return vParents;
    }

    // Returns the consensus result so accept/reject divergence lands in the digest.
    bool Attach(const Shape& shape, int i)
    {
        const std::vector<uint256> vParents = ParentsOf(shape, i);
        if (!g_dagManager.InitBlockDAGData(vBlocks[i], vParents))
            return false;
        if (!g_dagManager.ColorBlockDAGKnight(vBlocks[i]))
            return false;
        vBlocks[i]->nChainTrust = g_dagManager.ComputeDAGScore(vBlocks[i]);
        return true;
    }

    void Detach(int i) { g_dagManager.RemoveBlockDAGData(vHashes[i]); }
};

// Every observable the colouring feeds: per-block colour/score/k, the anchor-derived
// order and colours, the linear order from each anchor, and the selected tip. nDAGOrder is
// excluded because only an explicit rebuild assigns it.
std::string StateDigest(const Harness& harness)
{
    std::vector<uint256> vSorted = harness.vHashes;
    std::sort(vSorted.begin(), vSorted.end());

    std::ostringstream out;
    for (size_t i = 0; i < vSorted.size(); i++)
    {
        const uint256& hash = vSorted[i];
        out << hash.ToString().substr(0, 16);

        CBlockDAGData data;
        if (!g_dagManager.GetDAGData(hash, data))
        {
            out << " absent\n";
            continue;
        }
        out << " blue=" << (data.fBlue ? 1 : 0)
            << " score=" << data.nDAGScore.ToString()
            << " k=" << data.nInferredK
            << " parents=";
        for (size_t p = 0; p < data.vDAGParents.size(); p++)
            out << data.vDAGParents[p].ToString().substr(0, 8) << ",";

        uint256 hashSelectedParent = 0;
        uint256 nScore = 0;
        int nInferredK = 0;
        std::vector<std::pair<uint256, bool> > vOrderColors;
        if (g_dagManager.GetDAGKnightAnchorMetrics(hash, hashSelectedParent, nInferredK,
                                                   nScore, vOrderColors))
        {
            out << " sp=" << hashSelectedParent.ToString().substr(0, 8)
                << " mk=" << nInferredK
                << " ms=" << nScore.ToString()
                << " colors=";
            for (size_t c = 0; c < vOrderColors.size(); c++)
                out << vOrderColors[c].first.ToString().substr(0, 8) << ":"
                    << (vOrderColors[c].second ? 1 : 0) << ",";
        }
        else
            out << " metrics=unavailable";

        out << " order=";
        const std::vector<uint256> vOrder = g_dagManager.GetDAGLinearOrder(hash, 0, true);
        for (size_t o = 0; o < vOrder.size(); o++)
            out << vOrder[o].ToString().substr(0, 8) << ".";
        out << "\n";
    }

    CBlockIndex* pBest = g_dagManager.SelectBestDAGTip();
    out << "best=" << (pBest ? pBest->GetBlockHash().ToString().substr(0, 16) : "none")
        << "\n";
    return out.str();
}

struct RunResult
{
    std::string strAccepts;   // per-step accept/reject, so a divergence there is caught
    std::string strCached;    // observables as the incremental cache left them
    std::string strRebuilt;   // observables after a from-scratch recolour
};

RunResult Run(const Shape& shape, bool fFullInvalidation)
{
    const bool fSaved = fDAGKnightFullAnchorCacheInvalidation;
    fDAGKnightFullAnchorCacheInvalidation = fFullInvalidation;

    RunResult result;
    {
        Harness harness;
        harness.MineAll(shape);

        std::ostringstream accepts;
        for (size_t step = 0; step < shape.vAttachOrder.size(); step++)
        {
            const int i = shape.vAttachOrder[step];
            accepts << (harness.Attach(shape, i) ? '1' : '0');

            for (size_t d = 0; d < shape.vDetach.size(); d++)
                if (shape.vDetach[d].first == (int)step)
                    harness.Detach(shape.vDetach[d].second);
            for (size_t r = 0; r < shape.vReattach.size(); r++)
                if (shape.vReattach[r].first == (int)step)
                    accepts << (harness.Attach(shape, shape.vReattach[r].second) ? 'R' : 'r');
        }
        result.strAccepts = accepts.str();
        result.strCached = StateDigest(harness);

        g_dagManager.RebuildDAGOrder();
        result.strRebuilt = StateDigest(harness);
    }

    fDAGKnightFullAnchorCacheInvalidation = fSaved;
    return result;
}

void CheckShapeIsIndistinguishable(const Shape& shape)
{
    const RunResult full = Run(shape, true);
    const RunResult targeted = Run(shape, false);

    BOOST_CHECK_MESSAGE(full.strAccepts == targeted.strAccepts,
                        shape.strName << ": acceptance diverged");
    BOOST_CHECK_MESSAGE(full.strCached == targeted.strCached,
                        shape.strName << ": cached ordering diverged");
    BOOST_CHECK_MESSAGE(full.strRebuilt == targeted.strRebuilt,
                        shape.strName << ": rebuilt ordering diverged");
    BOOST_CHECK_MESSAGE(targeted.strCached == targeted.strRebuilt,
                        shape.strName << ": cached ordering differs from a full recompute");
}

int BaseHeight()
{
    return std::max(FORK_HEIGHT_EPOCH_STATE_V3, FORK_HEIGHT_DAGKNIGHT) + 4;
}

// A linear spine with siblings, merge blocks, out-of-order arrival and removals, drawn
// from one seed so a failure names a reproducible shape.
Shape GenerateShape(uint32_t nSeed, int nBlocks)
{
    Rng rng(0x5bd1e995ULL * (nSeed + 1));
    Shape shape;
    std::ostringstream name;
    name << "generated/seed=" << nSeed << "/n=" << nBlocks;
    shape.strName = name.str();

    ShapeNode base;
    base.nHeight = BaseHeight();
    base.nPrev = -1;
    shape.vNodes.push_back(base);

    // Height of each node, so a merge parent can be kept inside the merge depth.
    std::vector<int> vHeight(1, base.nHeight);
    std::vector<int> vTips(1, 0);

    for (int i = 1; i < nBlocks; i++)
    {
        ShapeNode node;
        const int nTip = vTips[rng.Below((uint32_t)vTips.size())];
        node.nPrev = nTip;
        node.nHeight = vHeight[nTip] + 1;

        // Merge parents: recent blocks that are not the primary parent.
        const uint32_t nMerges = rng.Below(100) < 35 ? 1 + rng.Below(3) : 0;
        for (uint32_t m = 0; m < nMerges; m++)
        {
            const int cand = (int)rng.Below((uint32_t)i);
            if (cand == nTip)
                continue;
            if (node.nHeight - vHeight[cand] > DAG_MERGE_DEPTH / 2)
                continue;
            if (vHeight[cand] >= node.nHeight)
                continue;
            node.vMerge.push_back(cand);
        }

        shape.vNodes.push_back(node);
        vHeight.push_back(node.nHeight);

        // Keep a small tip set so siblings and merges both occur.
        if (rng.Below(100) < 70)
            vTips.assign(1, i);
        else
        {
            vTips.push_back(i);
            if (vTips.size() > 4)
                vTips.erase(vTips.begin());
        }
    }

    // Arrival order: index order with local windows reversed, which is what makes a
    // committed merge parent arrive after the block that committed to it.
    for (int i = 0; i < nBlocks; i++)
        shape.vAttachOrder.push_back(i);
    for (int i = 1; i + 1 < nBlocks; i++)
    {
        if (rng.Below(100) < 25)
        {
            const int nSpan = 1 + (int)rng.Below(3);
            const int j = std::min(i + nSpan, nBlocks - 1);
            std::reverse(shape.vAttachOrder.begin() + i, shape.vAttachOrder.begin() + j + 1);
            i = j;
        }
    }

    // Removals: a block dropped mid-sequence, sometimes returned later.
    for (int i = 2; i < nBlocks - 2; i++)
    {
        if (rng.Below(100) < 8)
        {
            const int nVictim = shape.vAttachOrder[i];
            shape.vDetach.push_back(std::make_pair(i, nVictim));
            if (rng.Below(100) < 50 && i + 2 < nBlocks)
                shape.vReattach.push_back(std::make_pair(i + 2, nVictim));
        }
    }

    return shape;
}

Shape LinearShape(int nBlocks)
{
    Shape shape;
    shape.strName = "linear";
    for (int i = 0; i < nBlocks; i++)
    {
        ShapeNode node;
        node.nHeight = BaseHeight() + i;
        node.nPrev = i == 0 ? -1 : i - 1;
        shape.vNodes.push_back(node);
        shape.vAttachOrder.push_back(i);
    }
    return shape;
}

Shape SiblingsAndMergeShape()
{
    Shape shape;
    shape.strName = "siblings+merge";
    ShapeNode base;
    base.nHeight = BaseHeight();
    base.nPrev = -1;
    shape.vNodes.push_back(base);            // 0

    ShapeNode a;
    a.nHeight = BaseHeight() + 1;
    a.nPrev = 0;
    shape.vNodes.push_back(a);               // 1

    ShapeNode b;
    b.nHeight = BaseHeight() + 1;
    b.nPrev = 0;
    shape.vNodes.push_back(b);               // 2 sibling of 1

    ShapeNode merge;
    merge.nHeight = BaseHeight() + 2;
    merge.nPrev = 1;
    merge.vMerge.push_back(2);
    shape.vNodes.push_back(merge);           // 3 merges both siblings

    ShapeNode tip;
    tip.nHeight = BaseHeight() + 3;
    tip.nPrev = 3;
    shape.vNodes.push_back(tip);             // 4

    for (int i = 0; i < 5; i++)
        shape.vAttachOrder.push_back(i);
    return shape;
}

// The merge block commits to a sibling that has not arrived yet, so the sibling lands as a
// late parent and rewrites the committed past of a block already coloured.
Shape LateMergeParentShape()
{
    Shape shape = SiblingsAndMergeShape();
    shape.strName = "late-merge-parent";
    shape.vAttachOrder.clear();
    shape.vAttachOrder.push_back(0);
    shape.vAttachOrder.push_back(1);
    shape.vAttachOrder.push_back(3);   // merge arrives before the sibling it commits to
    shape.vAttachOrder.push_back(4);
    shape.vAttachOrder.push_back(2);   // late parent
    return shape;
}

Shape ReorgShape()
{
    Shape shape = SiblingsAndMergeShape();
    shape.strName = "reorg";
    shape.vDetach.push_back(std::make_pair(3, 3));   // drop the merge after the tip lands
    shape.vReattach.push_back(std::make_pair(4, 3));
    return shape;
}

} // namespace

BOOST_AUTO_TEST_CASE(linear_chain_ordering_is_invalidation_independent)
{
    CheckShapeIsIndistinguishable(LinearShape(40));
}

BOOST_AUTO_TEST_CASE(sibling_and_merge_ordering_is_invalidation_independent)
{
    CheckShapeIsIndistinguishable(SiblingsAndMergeShape());
}

BOOST_AUTO_TEST_CASE(late_merge_parent_ordering_is_invalidation_independent)
{
    CheckShapeIsIndistinguishable(LateMergeParentShape());
}

BOOST_AUTO_TEST_CASE(reorg_ordering_is_invalidation_independent)
{
    CheckShapeIsIndistinguishable(ReorgShape());
}

BOOST_AUTO_TEST_CASE(generated_chain_shapes_are_invalidation_independent)
{
    for (uint32_t nSeed = 0; nSeed < 60; nSeed++)
        CheckShapeIsIndistinguishable(GenerateShape(nSeed, 24));
}

BOOST_AUTO_TEST_CASE(wide_generated_chain_shapes_are_invalidation_independent)
{
    for (uint32_t nSeed = 100; nSeed < 120; nSeed++)
        CheckShapeIsIndistinguishable(GenerateShape(nSeed, 48));
}

BOOST_AUTO_TEST_SUITE_END()
