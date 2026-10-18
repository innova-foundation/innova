// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Reachability index differential: index answers against an exact walk, and the
// manager's ancestor queries with the index on against the walk alone.

#include <boost/test/unit_test.hpp>

#include "../dag.h"
#include "../dagreach.h"
#include "../main.h"

#include <algorithm>
#include <map>
#include <set>
#include <vector>

extern bool fRegTest;
extern bool fTestNet;

BOOST_AUTO_TEST_SUITE(dag_reachability_tests)

namespace {

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

uint256 H(int i) { return uint256((uint64_t)(i + 1) * 0x9e3779b97f4a7c15ULL); }

// Random DAG: each node takes 1-4 parents from a recent window, first parent most recent-ish.
std::vector<std::vector<int> > RandomDag(Rng& rng, int n, int nWindow, int nMaxParents)
{
    std::vector<std::vector<int> > v(n);
    for (int i = 1; i < n; i++)
    {
        const int nLo = std::max(0, i - nWindow);
        const int nParents = 1 + (int)rng.Below(nMaxParents);
        for (int k = 0; k < nParents; k++)
        {
            const int p = nLo + (int)rng.Below(i - nLo);
            if (std::find(v[i].begin(), v[i].end(), p) == v[i].end())
                v[i].push_back(p);
        }
    }
    return v;
}

bool WalkReach(const std::map<uint256, std::vector<uint256> >& g, const uint256& a, const uint256& d)
{
    if (a == d)
        return true;
    std::vector<uint256> vStack(1, d);
    std::set<uint256> setSeen;
    while (!vStack.empty())
    {
        const uint256 h = vStack.back();
        vStack.pop_back();
        if (!setSeen.insert(h).second)
            continue;
        std::map<uint256, std::vector<uint256> >::const_iterator it = g.find(h);
        if (it == g.end())
            continue;
        for (size_t i = 0; i < it->second.size(); i++)
        {
            if (it->second[i] == a)
                return true;
            vStack.push_back(it->second[i]);
        }
    }
    return false;
}

void EnsureBuilt(CDAGReachability& idx, const std::map<uint256, std::vector<uint256> >& g)
{
    if (!idx.IsDirty())
        return;
    std::vector<std::pair<uint256, const std::vector<uint256>*> > v;
    for (std::map<uint256, std::vector<uint256> >::const_iterator it = g.begin(); it != g.end(); ++it)
        v.push_back(std::make_pair(it->first, &it->second));
    idx.Rebuild(v);
}

void CheckAllPairs(CDAGReachability& idx, const std::map<uint256, std::vector<uint256> >& gIndex,
                   const std::map<uint256, std::vector<uint256> >& gLive, const std::vector<uint256>& vAll)
{
    EnsureBuilt(idx, gIndex);
    BOOST_REQUIRE(idx.IsUsable());
    for (size_t i = 0; i < vAll.size(); i++)
        for (size_t j = 0; j < vAll.size(); j++)
        {
            const bool fIdx = idx.IsReachable(vAll[i], vAll[j]);
            BOOST_CHECK_EQUAL(fIdx, WalkReach(gIndex, vAll[i], vAll[j]));
            if (!fIdx)
                BOOST_CHECK(!WalkReach(gLive, vAll[i], vAll[j]));
        }
}

} // namespace

BOOST_AUTO_TEST_CASE(index_matches_walk_random_dags)
{
    for (int nSeed = 1; nSeed <= 24; nSeed++)
    {
        Rng rng(nSeed * 7919);
        const int n = 40 + (int)rng.Below(80);
        std::vector<std::vector<int> > dag = RandomDag(rng, n, 2 + (int)rng.Below(10), 1 + (int)rng.Below(4));

        CDAGReachability idx;
        std::map<uint256, std::vector<uint256> > g;
        std::vector<uint256> vAll;
        for (int i = 0; i < n; i++)
        {
            std::vector<uint256> vP;
            for (size_t k = 0; k < dag[i].size(); k++)
                vP.push_back(H(dag[i][k]));
            g[H(i)] = vP;
            vAll.push_back(H(i));
            idx.AddVertex(H(i), vP);
        }
        CheckAllPairs(idx, g, g, vAll);

        // Fresh rebuild answers the same.
        CDAGReachability idx2;
        idx2.MarkDirty();
        CheckAllPairs(idx2, g, g, vAll);
    }
}

BOOST_AUTO_TEST_CASE(index_out_of_order_and_removal)
{
    for (int nSeed = 1; nSeed <= 16; nSeed++)
    {
        Rng rng(nSeed * 104729);
        const int n = 60;
        std::vector<std::vector<int> > dag = RandomDag(rng, n, 6, 3);
        std::vector<int> vOrder;
        for (int i = 0; i < n; i++)
            vOrder.push_back(i);
        // Local shuffles so some children arrive before a parent.
        for (int i = 0; i + 1 < n; i++)
            if (rng.Below(4) == 0)
                std::swap(vOrder[i], vOrder[i + 1]);

        CDAGReachability idx;
        std::map<uint256, std::vector<uint256> > gLive, gIndex;
        std::vector<uint256> vAll;
        for (int i = 0; i < n; i++)
            vAll.push_back(H(i));
        for (size_t s = 0; s < vOrder.size(); s++)
        {
            const int i = vOrder[s];
            std::vector<uint256> vP;
            for (size_t k = 0; k < dag[i].size(); k++)
                vP.push_back(H(dag[i][k]));
            gLive[H(i)] = vP;
            gIndex[H(i)] = vP;
            const bool fWasDirty = idx.IsDirty();
            idx.AddVertex(H(i), vP);
            if (idx.IsDirty() && !fWasDirty)
                gIndex = gLive; // a rebuild reads the live graph
        }
        if (idx.IsDirty())
            gIndex = gLive;
        CheckAllPairs(idx, gIndex, gLive, vAll);

        // Removals keep the index edges; negatives stay exact on the live graph.
        for (int r = 0; r < 10; r++)
        {
            const uint256 h = H((int)rng.Below(n));
            if (gLive.erase(h))
                idx.NoteRemoved(h);
        }
        CheckAllPairs(idx, gIndex, gLive, vAll);

        // Re-adding with the same parents keeps the index; different parents force a rebuild.
        for (std::map<uint256, std::vector<uint256> >::const_iterator it = gIndex.begin(); it != gIndex.end(); ++it)
            if (!gLive.count(it->first))
            {
                gLive[it->first] = it->second;
                idx.AddVertex(it->first, it->second);
            }
        BOOST_CHECK(!idx.IsDirty());
        CheckAllPairs(idx, gIndex, gLive, vAll);

        const uint256 hChanged = H(n - 1);
        gLive[hChanged].push_back(H(0));
        idx.AddVertex(hChanged, gLive[hChanged]);
        // Not new: AddVertex refuses a known vertex with new links.
        BOOST_CHECK(idx.IsDirty());
        gIndex = gLive;
        CheckAllPairs(idx, gIndex, gLive, vAll);
    }
}

BOOST_AUTO_TEST_CASE(index_long_chain_exhausts_and_rebuilds)
{
    CDAGReachability idx;
    std::map<uint256, std::vector<uint256> > g;
    std::vector<uint256> vAll;
    int nRebuilds = 0;
    Rng rng(42);
    for (int i = 0; i < 3000; i++)
    {
        std::vector<uint256> vP;
        if (i > 0)
            vP.push_back(H(i - 1));
        if (i > 3 && rng.Below(5) == 0)
            vP.push_back(H(i - 2 - (int)rng.Below(2)));
        g[H(i)] = vP;
        vAll.push_back(H(i));
        idx.AddVertex(H(i), vP);
        if (idx.IsDirty())
        {
            EnsureBuilt(idx, g);
            ++nRebuilds;
        }
        BOOST_REQUIRE(idx.IsUsable());
    }
    BOOST_CHECK(nRebuilds > 0);
    for (int k = 0; k < 2000; k++)
    {
        const uint256 a = vAll[rng.Below(vAll.size())];
        const uint256 d = vAll[rng.Below(vAll.size())];
        BOOST_CHECK_EQUAL(idx.IsReachable(a, d), WalkReach(g, a, d));
    }
}

BOOST_AUTO_TEST_CASE(index_cycle_is_unusable)
{
    CDAGReachability idx;
    std::map<uint256, std::vector<uint256> > g;
    g[H(0)] = std::vector<uint256>(1, H(1));
    g[H(1)] = std::vector<uint256>(1, H(0));
    idx.MarkDirty();
    EnsureBuilt(idx, g);
    BOOST_CHECK(!idx.IsUsable());
}

namespace {

struct Harness
{
    std::vector<uint256> vHashes;
    std::vector<CBlockIndex*> vBlocks;
    bool fOldRegTest, fOldTestNet, fOldCheck;
    CBigNum bnOldLimit;

    Harness()
    {
        fOldRegTest = fRegTest;
        fOldTestNet = fTestNet;
        fOldCheck = fDAGReachabilityCheck;
        bnOldLimit = bnProofOfWorkLimit;
        fRegTest = true;
        fTestNet = false;
        fDAGReachabilityCheck = true;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
    }
    ~Harness()
    {
        for (size_t i = vHashes.size(); i-- > 0; )
        {
            g_dagManager.RemoveBlockDAGData(vHashes[i]);
            mapBlockIndex.erase(vHashes[i]);
            delete vBlocks[i];
        }
        bnProofOfWorkLimit = bnOldLimit;
        fRegTest = fOldRegTest;
        fTestNet = fOldTestNet;
        fDAGReachabilityCheck = fOldCheck;
    }
    void Mine(int nSeed, const std::vector<std::vector<int> >& dag)
    {
        for (size_t i = 0; i < dag.size(); i++)
        {
            CBlockIndex* pprev = dag[i].empty() ? NULL : vBlocks[dag[i][0]];
            CBlock block;
            block.nVersion = 1;
            block.hashPrevBlock = pprev ? pprev->GetBlockHash() : uint256(0);
            block.nTime = (unsigned int)(1700000000 + i);
            block.nBits = bnProofOfWorkLimit.GetCompact();
            block.nNonce = (unsigned int)(i + 1);
            block.hashMerkleRoot = uint256((uint64_t)nSeed * 100000 + i + 1);
            while (!CheckProofOfWork(block.GetHash(), block.nBits))
                ++block.nNonce;
            const uint256 hash = block.GetHash();
            CBlockIndex* pindex = new CBlockIndex(0, 0, block);
            int nHeight = 0;
            for (size_t k = 0; k < dag[i].size(); k++)
                nHeight = std::max(nHeight, vBlocks[dag[i][k]]->nHeight + 1);
            pindex->nHeight = nHeight;
            pindex->pprev = pprev;
            std::pair<std::map<uint256, CBlockIndex*>::iterator, bool> ins =
                mapBlockIndex.insert(std::make_pair(hash, pindex));
            BOOST_REQUIRE(ins.second);
            pindex->phashBlock = &ins.first->first;
            vHashes.push_back(hash);
            vBlocks.push_back(pindex);
        }
    }
    void Attach(const std::vector<std::vector<int> >& dag, int i)
    {
        std::vector<uint256> vP;
        for (size_t k = 0; k < dag[i].size(); k++)
            vP.push_back(vHashes[dag[i][k]]);
        BOOST_REQUIRE(g_dagManager.InitBlockDAGData(vBlocks[i], vP));
    }
};

void CompareManager(const Harness& h)
{
    const int nDepths[] = {2, 5, 1000};
    for (size_t i = 0; i < h.vHashes.size(); i++)
        for (size_t j = 0; j < h.vHashes.size(); j++)
        {
            for (size_t d = 0; d < sizeof(nDepths) / sizeof(nDepths[0]); d++)
                BOOST_CHECK_EQUAL(
                    g_dagManager.TestIsDAGAncestor(h.vHashes[i], h.vHashes[j], nDepths[d], true),
                    g_dagManager.TestIsDAGAncestor(h.vHashes[i], h.vHashes[j], nDepths[d], false));
            BOOST_CHECK_EQUAL(
                g_dagManager.TestIsDAGAncestorWithinMergeDepth(h.vHashes[i], h.vHashes[j], true),
                g_dagManager.TestIsDAGAncestorWithinMergeDepth(h.vHashes[i], h.vHashes[j], false));
        }
}

} // namespace

BOOST_AUTO_TEST_CASE(manager_index_matches_walk_with_reorg)
{
    const uint64_t nMismatchesBefore = nDAGReachabilityMismatches;
    for (int nSeed = 1; nSeed <= 6; nSeed++)
    {
        Rng rng(nSeed * 31337);
        std::vector<std::vector<int> > dag = RandomDag(rng, 48, 6, 3);
        Harness h;
        h.Mine(nSeed, dag);
        for (size_t i = 0; i < dag.size(); i++)
            h.Attach(dag, (int)i);
        CompareManager(h);

        // Disconnect a tail and a few interior vertices, compare, then reconnect.
        std::vector<int> vDetached;
        for (int i = (int)dag.size() - 1; i >= (int)dag.size() - 8; i--)
            vDetached.push_back(i);
        for (int r = 0; r < 4; r++)
            vDetached.push_back(1 + (int)rng.Below(dag.size() - 9));
        for (size_t k = 0; k < vDetached.size(); k++)
            g_dagManager.RemoveBlockDAGData(h.vHashes[vDetached[k]]);
        CompareManager(h);
        for (size_t k = vDetached.size(); k-- > 0; )
        {
            CBlockDAGData data;
            if (!g_dagManager.GetDAGData(h.vHashes[vDetached[k]], data))
                h.Attach(dag, vDetached[k]);
        }
        CompareManager(h);
    }
    BOOST_CHECK_EQUAL(nDAGReachabilityMismatches, nMismatchesBefore);
}

BOOST_AUTO_TEST_SUITE_END()
