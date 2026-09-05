// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// After DAG pruning, the first retained vertex seeds its DAGKNIGHT anchor state from its
// own persisted score/k; a vertex missing above the prune boundary is corruption.

#include <boost/test/unit_test.hpp>

#include "../bignum.h"
#include "../dag.h"
#include "../main.h"

#include <vector>

extern bool fRegTest;
extern bool fTestNet;

BOOST_AUTO_TEST_SUITE(dagknight_prune_frontier_tests)

namespace {

struct Chain
{
    std::vector<uint256>      vHashes;
    std::vector<CBlockIndex*> vBlocks;
    CBlockIndex*              pOldBest;
    bool                      fOldRegTest;
    bool                      fOldTestNet;
    CBigNum                   bnOldLimit;
    int                       nOldPruneBelow;

    Chain()
    {
        fOldRegTest = fRegTest;
        fOldTestNet = fTestNet;
        bnOldLimit = bnProofOfWorkLimit;
        pOldBest = pindexBest;
        nOldPruneBelow = g_dagManager.GetPrunedBelowHeight();
        fRegTest = true;
        fTestNet = false;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        pindexBest = NULL;
    }

    ~Chain()
    {
        for (size_t i = vHashes.size(); i-- > 0; )
        {
            g_dagManager.RemoveBlockDAGData(vHashes[i]);
            mapBlockIndex.erase(vHashes[i]);
            delete vBlocks[i];
        }
        g_dagManager.SetPrunedBelowHeight(nOldPruneBelow);
        pindexBest = pOldBest;
        bnProofOfWorkLimit = bnOldLimit;
        fRegTest = fOldRegTest;
        fTestNet = fOldTestNet;
    }

    static int BaseHeight()
    {
        return std::max(FORK_HEIGHT_EPOCH_STATE_V3, FORK_HEIGHT_DAGKNIGHT) + 4;
    }

    // Mines and attaches one block on the current tip (or a base block).
    bool Extend()
    {
        const size_t i = vBlocks.size();
        CBlockIndex* pprev = i ? vBlocks[i - 1] : NULL;

        CBlock block;
        block.nVersion = 1;
        block.hashPrevBlock = pprev ? pprev->GetBlockHash() : uint256(0);
        block.nTime = (unsigned int)(1700000000 + i);
        block.nBits = bnProofOfWorkLimit.GetCompact();
        block.nNonce = (unsigned int)(i + 1);
        block.hashMerkleRoot = uint256((unsigned int)(i + 1));
        while (!CheckProofOfWork(block.GetHash(), block.nBits))
            ++block.nNonce;

        const uint256 hash = block.GetHash();
        CBlockIndex* pindex = new CBlockIndex(0, 0, block);
        pindex->nHeight = BaseHeight() + (int)i;
        pindex->pprev = pprev;
        std::pair<std::map<uint256, CBlockIndex*>::iterator, bool> ins =
            mapBlockIndex.insert(std::make_pair(hash, pindex));
        BOOST_REQUIRE(ins.second);
        pindex->phashBlock = &ins.first->first;
        vHashes.push_back(hash);
        vBlocks.push_back(pindex);

        std::vector<uint256> vParents;
        if (pprev)
            vParents.push_back(pprev->GetBlockHash());
        if (!g_dagManager.InitBlockDAGData(pindex, vParents))
            return false;
        if (!g_dagManager.ColorBlockDAGKnight(pindex))
            return false;
        pindex->nChainTrust = g_dagManager.ComputeDAGScore(pindex);
        return true;
    }

    // What PruneDAGData does to one block: the vertex goes, the index stays.
    void PruneVertex(size_t i)
    {
        g_dagManager.RemoveBlockDAGData(vHashes[i]);
        BOOST_REQUIRE(!g_dagManager.HasDAGData(vHashes[i]));
        BOOST_REQUIRE(mapBlockIndex.count(vHashes[i]) == 1);
    }

    CBlockDAGData Data(size_t i) const
    {
        CBlockDAGData data;
        BOOST_REQUIRE(g_dagManager.GetDAGData(vHashes[i], data));
        return data;
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(a_pruned_selected_parent_seeds_the_anchor_from_the_retained_frontier)
{
    Chain chain;
    for (int i = 0; i < 4; i++)
        BOOST_REQUIRE(chain.Extend());

    const CBlockDAGData before1 = chain.Data(1);
    const CBlockDAGData before3 = chain.Data(3);
    BOOST_REQUIRE(before1.nDAGScore != 0);
    BOOST_REQUIRE(before1.nInferredK >= DAGKNIGHT_K_FLOOR);

    // Prune the base: block 1 becomes the first retained vertex on the chain
    // while its selected parent keeps a block index at a post-fork height.
    chain.PruneVertex(0);
    g_dagManager.SetPrunedBelowHeight(chain.vBlocks[1]->nHeight);
    BOOST_REQUIRE(chain.vBlocks[0]->nHeight >= FORK_HEIGHT_DAG);

    // The dropped cache is rebuilt from block 1's own persisted score/k.
    BOOST_CHECK(g_dagManager.ColorBlockDAGKnight(chain.vBlocks[1]));
    BOOST_CHECK(chain.Data(1).nDAGScore == before1.nDAGScore);
    BOOST_CHECK_EQUAL(chain.Data(1).nInferredK, before1.nInferredK);

    // Descendants extend the seeded frontier to the same scores as before.
    BOOST_CHECK(g_dagManager.ColorBlockDAGKnight(chain.vBlocks[2]));
    BOOST_CHECK(g_dagManager.ColorBlockDAGKnight(chain.vBlocks[3]));
    BOOST_CHECK(chain.Data(3).nDAGScore == before3.nDAGScore);

    // A freshly mined block on the tip is accepted and scored past it.
    BOOST_CHECK(chain.Extend());
    BOOST_CHECK(chain.Data(4).nDAGScore ==
                before3.nDAGScore + chain.vBlocks[4]->GetBlockTrust());

    uint256 hashSelectedParent = 0;
    uint256 nScore = 0;
    int nInferredK = 0;
    std::vector<std::pair<uint256, bool> > vOrderColors;
    BOOST_CHECK(g_dagManager.GetDAGKnightAnchorMetrics(
        chain.vHashes[4], hashSelectedParent, nInferredK, nScore, vOrderColors));
    BOOST_CHECK(hashSelectedParent == chain.vHashes[3]);
}

BOOST_AUTO_TEST_CASE(a_vertex_missing_above_the_prune_boundary_is_still_corruption)
{
    Chain chain;
    for (int i = 0; i < 3; i++)
        BOOST_REQUIRE(chain.Extend());

    chain.PruneVertex(0);

    // No prune has run: the parent should have a vertex and does not.
    g_dagManager.SetPrunedBelowHeight(-1);
    BOOST_CHECK(!g_dagManager.ColorBlockDAGKnight(chain.vBlocks[1]));

    // A boundary at the parent's own height does not cover the parent either.
    g_dagManager.SetPrunedBelowHeight(chain.vBlocks[0]->nHeight);
    BOOST_CHECK(!g_dagManager.ColorBlockDAGKnight(chain.vBlocks[1]));

    // One above it does.
    g_dagManager.SetPrunedBelowHeight(chain.vBlocks[0]->nHeight + 1);
    BOOST_CHECK(g_dagManager.ColorBlockDAGKnight(chain.vBlocks[1]));
}

BOOST_AUTO_TEST_SUITE_END()
