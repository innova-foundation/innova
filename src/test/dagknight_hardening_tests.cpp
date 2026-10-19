// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// DAGKNIGHT hardening: worst-case cost, arrival-order and cache determinism, selected
// parent, parent-set limits, and k bounds/EMA.

#include <boost/test/unit_test.hpp>

#include "../dag.h"
#include "../main.h"
#include "../util.h"

#include <algorithm>
#include <sstream>
#include <string>
#include <vector>

extern bool fRegTest;
extern bool fTestNet;

BOOST_AUTO_TEST_SUITE(dagknight_hardening_tests)

namespace {

struct Node
{
    int nHeight;
    int nPrev;
    std::vector<int> vMerge;
};

struct Rng
{
    uint64_t n;
    explicit Rng(uint64_t s) : n(s ? s : 0x9e3779b97f4a7c15ULL) {}
    uint32_t Next() { n ^= n << 13; n ^= n >> 7; n ^= n << 17; return (uint32_t)(n >> 32); }
    uint32_t Below(uint32_t m) { return m ? Next() % m : 0; }
};

int BaseHeight()
{
    return std::max(FORK_HEIGHT_EPOCH_STATE_V3, FORK_HEIGHT_DAGKNIGHT) + 4;
}

// Shape description; blocks are mined up front and attached on demand.
struct Dag
{
    std::vector<Node>         vNodes;
    std::vector<uint256>      vHashes;
    std::vector<CBlockIndex*> vBlocks;
    std::vector<bool>         vAttached;
    CBlockIndex*              pOldBest;
    bool                      fOldRegTest, fOldTestNet;
    int                       nOldMergeset;
    CBigNum                   bnOldLimit;
    uint32_t                  nSalt;

    explicit Dag(uint32_t nSaltIn = 0) : nSalt(nSaltIn)
    {
        fOldRegTest = fRegTest;
        fOldTestNet = fTestNet;
        nOldMergeset = nRegtestMergesetHeight;
        bnOldLimit = bnProofOfWorkLimit;
        pOldBest = pindexBest;
        fRegTest = true;
        fTestNet = false;
        nRegtestMergesetHeight = PRIVACY_VNEXT_HEIGHT_UNSET;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        pindexBest = NULL;
    }

    ~Dag()
    {
        for (size_t i = vHashes.size(); i-- > 0; )
        {
            g_dagManager.RemoveBlockDAGData(vHashes[i]);
            mapBlockIndex.erase(vHashes[i]);
            delete vBlocks[i];
        }
        pindexBest = pOldBest;
        bnProofOfWorkLimit = bnOldLimit;
        nRegtestMergesetHeight = nOldMergeset;
        fRegTest = fOldRegTest;
        fTestNet = fOldTestNet;
    }

    int Add(int nPrev, const std::vector<int>& vMerge = std::vector<int>(), int nHeight = -1)
    {
        Node node;
        node.nPrev = nPrev;
        node.vMerge = vMerge;
        node.nHeight = nHeight >= 0 ? nHeight : (nPrev >= 0 ? vNodes[nPrev].nHeight + 1 : BaseHeight());
        const int i = (int)vNodes.size();
        vNodes.push_back(node);

        CBlockIndex* pprev = nPrev >= 0 ? vBlocks[nPrev] : NULL;
        CBlock block;
        block.nVersion = 1;
        block.hashPrevBlock = pprev ? pprev->GetBlockHash() : uint256(0);
        block.nTime = (unsigned int)(1700000000 + node.nHeight);
        block.nBits = bnProofOfWorkLimit.GetCompact();
        block.nNonce = (unsigned int)(i + 1);
        block.hashMerkleRoot = uint256((uint64_t)(i + 1) + ((uint64_t)nSalt << 32));
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
        vAttached.push_back(false);
        return i;
    }

    std::vector<uint256> Parents(int i) const
    {
        std::vector<uint256> v;
        if (vNodes[i].nPrev >= 0)
            v.push_back(vHashes[vNodes[i].nPrev]);
        for (size_t m = 0; m < vNodes[i].vMerge.size(); m++)
        {
            const uint256& h = vHashes[vNodes[i].vMerge[m]];
            if (std::find(v.begin(), v.end(), h) == v.end())
                v.push_back(h);
        }
        return v;
    }

    bool Attach(int i)
    {
        if (!g_dagManager.InitBlockDAGData(vBlocks[i], Parents(i)))
            return false;
        if (!g_dagManager.ColorBlockDAGKnight(vBlocks[i]))
            return false;
        vBlocks[i]->nChainTrust = g_dagManager.ComputeDAGScore(vBlocks[i]);
        vAttached[i] = true;
        return true;
    }

    void AttachAll(const std::vector<int>& vOrder)
    {
        for (size_t s = 0; s < vOrder.size(); s++)
            BOOST_REQUIRE_MESSAGE(Attach(vOrder[s]), "attach failed at step " << s);
    }

    std::vector<int> IndexOrder() const
    {
        std::vector<int> v;
        for (size_t i = 0; i < vNodes.size(); i++)
            v.push_back((int)i);
        return v;
    }

    // A random topological order: every parent precedes its child.
    std::vector<int> TopoOrder(uint32_t nSeed) const
    {
        Rng rng(0x2545f4914f6cdd1dULL * (nSeed + 1));
        const int n = (int)vNodes.size();
        std::vector<int> vPending(n, 0);
        std::vector<std::vector<int> > vChildren(n);
        for (int i = 0; i < n; i++)
        {
            std::vector<int> vP;
            if (vNodes[i].nPrev >= 0) vP.push_back(vNodes[i].nPrev);
            vP.insert(vP.end(), vNodes[i].vMerge.begin(), vNodes[i].vMerge.end());
            std::sort(vP.begin(), vP.end());
            vP.erase(std::unique(vP.begin(), vP.end()), vP.end());
            vPending[i] = (int)vP.size();
            for (size_t p = 0; p < vP.size(); p++)
                vChildren[vP[p]].push_back(i);
        }
        std::vector<int> vReady, vOut;
        for (int i = 0; i < n; i++)
            if (vPending[i] == 0) vReady.push_back(i);
        while (!vReady.empty())
        {
            const size_t k = rng.Below((uint32_t)vReady.size());
            const int i = vReady[k];
            vReady.erase(vReady.begin() + k);
            vOut.push_back(i);
            for (size_t c = 0; c < vChildren[i].size(); c++)
                if (--vPending[vChildren[i][c]] == 0)
                    vReady.push_back(vChildren[i][c]);
        }
        BOOST_REQUIRE((int)vOut.size() == n);
        return vOut;
    }
};

// Positional digest (shape index, not hash) so two DAG instances can be compared.
std::string Digest(const Dag& dag, bool fFullOrders)
{
    std::map<uint256, int> mapIdx;
    for (size_t i = 0; i < dag.vHashes.size(); i++)
        mapIdx[dag.vHashes[i]] = (int)i;
    std::ostringstream out;
    for (size_t i = 0; i < dag.vHashes.size(); i++)
    {
        CBlockDAGData data;
        if (!g_dagManager.GetDAGData(dag.vHashes[i], data))
        {
            out << i << " absent\n";
            continue;
        }
        out << i << " b=" << data.fBlue << " s=" << data.nDAGScore.GetHex()
            << " k=" << data.nInferredK;
        uint256 hashSP = 0, nScore = 0;
        int nK = 0;
        std::vector<std::pair<uint256, bool> > vOC;
        if (g_dagManager.GetDAGKnightAnchorMetrics(dag.vHashes[i], hashSP, nK, nScore, vOC))
        {
            out << " sp=" << (mapIdx.count(hashSP) ? mapIdx[hashSP] : -1) << " mk=" << nK
                << " ms=" << nScore.GetHex() << " oc=";
            for (size_t c = 0; c < vOC.size(); c++)
                out << (mapIdx.count(vOC[c].first) ? mapIdx[vOC[c].first] : -1) << ":"
                    << vOC[c].second << ",";
        }
        else
            out << " metrics=none";
        if (fFullOrders)
        {
            out << " o=";
            const std::vector<uint256> vO = g_dagManager.GetDAGLinearOrder(dag.vHashes[i], 0, true);
            for (size_t o = 0; o < vO.size(); o++)
                out << (mapIdx.count(vO[o]) ? mapIdx[vO[o]] : -1) << ".";
        }
        out << "\n";
    }
    CBlockIndex* pBest = g_dagManager.SelectBestDAGTip();
    out << "best=" << (pBest && mapIdx.count(pBest->GetBlockHash()) ? mapIdx[pBest->GetBlockHash()] : -1);
    return out.str();
}

// Braid: nWidth lanes, each block extends its lane and merges up to nMerge others at
// the previous height. Deterministic in nSeed.
void BuildBraid(Dag& dag, int nWidth, int nRows, int nMerge, uint32_t nSeed)
{
    Rng rng(nSeed * 7919 + 1);
    const int nBase = dag.Add(-1);
    std::vector<int> vPrevRow(nWidth, nBase);
    for (int r = 0; r < nRows; r++)
    {
        std::vector<int> vRow;
        for (int w = 0; w < nWidth; w++)
        {
            std::vector<int> vMerge;
            if (r > 0)
                for (int m = 0; m < nMerge; m++)
                {
                    const int lane = (int)rng.Below((uint32_t)nWidth);
                    if (lane != w && vPrevRow[lane] != vPrevRow[w])
                        vMerge.push_back(vPrevRow[lane]);
                }
            vRow.push_back(dag.Add(vPrevRow[w], vMerge));
        }
        vPrevRow = vRow;
    }
}

// Mirror of the EMA in BuildDAGKnightAnchorStateFrom.
int ExpectedK(const std::vector<int>& vSamples)
{
    int nEMA = vSamples[0] * 256;
    for (size_t i = 1; i < vSamples.size(); ++i)
        nEMA = ((256 - DAGKNIGHT_K_EMA_ALPHA) * nEMA + DAGKNIGHT_K_EMA_ALPHA * vSamples[i] * 256) / 256;
    return std::max(DAGKNIGHT_K_FLOOR, std::min(DAGKNIGHT_K_CEILING, (nEMA + 128) / 256));
}

int KOf(const Dag& dag, int i)
{
    uint256 sp = 0, s = 0;
    int k = 0;
    std::vector<std::pair<uint256, bool> > v;
    BOOST_REQUIRE(g_dagManager.GetDAGKnightAnchorMetrics(dag.vHashes[i], sp, k, s, v));
    return k;
}

struct FlagGuard
{
    bool fUnopt, fCheck;
    FlagGuard() : fUnopt(fDAGKnightUnoptimizedOrdering), fCheck(fDAGReachabilityCheck) {}
    ~FlagGuard() { fDAGKnightUnoptimizedOrdering = fUnopt; fDAGReachabilityCheck = fCheck; }
};

} // namespace

// (a) A max-parent anchor over 31 attacker chains, each as deep as the merge window.
BOOST_AUTO_TEST_CASE(worst_case_max_parent_wide_anticone_is_bounded)
{
    Dag dag;
    const int nBase = dag.Add(-1);
    const int nLen = DAG_MERGE_DEPTH - 4;
    int nMain = nBase;
    for (int h = 0; h < nLen; h++)
        nMain = dag.Add(nMain);
    std::vector<int> vTips;
    for (int c = 0; c < MAX_DAG_PARENTS - 1; c++)
    {
        int t = nBase;
        for (int h = 0; h < nLen; h++)
            t = dag.Add(t);
        vTips.push_back(t);
    }
    const int nAnchor = dag.Add(nMain, vTips);
    BOOST_REQUIRE_EQUAL(dag.Parents(nAnchor).size(), (size_t)MAX_DAG_PARENTS);

    std::vector<int> vOrder = dag.IndexOrder();
    vOrder.pop_back();
    dag.AttachAll(vOrder);

    std::string strError;
    BOOST_CHECK_MESSAGE(g_dagManager.CheckDAGKnightParentSet(dag.Parents(nAnchor),
                                                            dag.vNodes[nAnchor].nHeight, strError),
                        strError);

    const int64_t nStart = GetTimeMillis();
    BOOST_REQUIRE(dag.Attach(nAnchor));
    uint256 sp = 0, s = 0;
    int k = 0;
    std::vector<std::pair<uint256, bool> > vOC;
    BOOST_REQUIRE(g_dagManager.GetDAGKnightAnchorMetrics(dag.vHashes[nAnchor], sp, k, s, vOC, 1));
    const int64_t nElapsed = GetTimeMillis() - nStart;

    // Work: the anchor's own delta is every other chain plus the anchor.
    const size_t nCandidates = (size_t)(MAX_DAG_PARENTS - 1) * nLen;
    BOOST_CHECK_EQUAL(vOC.size() - 1, nCandidates);
    BOOST_CHECK(vOC.size() <= (size_t)DAGKNIGHT_MAX_ANCHOR_CANDIDATES + 1);
    // Block trust is hash entropy, so the equal-length chains differ in score; the
    // highest-scoring parent is selected.
    const std::vector<uint256> vAnchorParents = dag.Parents(nAnchor);
    uint256 hashBest = 0, nBest = 0;
    for (size_t p = 0; p < vAnchorParents.size(); p++)
    {
        CBlockDAGData d;
        BOOST_REQUIRE(g_dagManager.GetDAGData(vAnchorParents[p], d));
        if (hashBest == 0 || d.nDAGScore > nBest)
        {
            hashBest = vAnchorParents[p];
            nBest = d.nDAGScore;
        }
    }
    BOOST_CHECK(sp == hashBest);
    BOOST_CHECK(k >= DAGKNIGHT_K_FLOOR && k <= DAGKNIGHT_K_CEILING);
    // Blue count can never exceed the window + candidates and colouring must stay < 2s/anchor.
    BOOST_TEST_MESSAGE("worst-case anchor colour ms=" << nElapsed);
    BOOST_CHECK_MESSAGE(nElapsed < 2000, "worst-case colouring took " << nElapsed << " ms");
}

// (b) Same DAG, different topological arrival orders, on fresh states: identical results.
BOOST_AUTO_TEST_CASE(arrival_order_does_not_change_colouring)
{
    std::string strRef;
    for (uint32_t nOrder = 0; nOrder < 6; nOrder++)
    {
        Dag dag;
        BuildBraid(dag, 5, 30, 2, 11);
        dag.AttachAll(nOrder == 0 ? dag.IndexOrder() : dag.TopoOrder(nOrder));
        const std::string d = Digest(dag, true);
        if (nOrder == 0)
            strRef = d;
        else
            BOOST_CHECK_MESSAGE(d == strRef, "arrival order " << nOrder << " diverged");
        g_dagManager.RebuildDAGOrder();
        BOOST_CHECK_MESSAGE(Digest(dag, true) == strRef, "rebuild after order " << nOrder << " diverged");
    }
}

// (b) Warm vs cold caches, the unoptimized (drop-all) path, and -dagreachcheck all agree.
BOOST_AUTO_TEST_CASE(cache_state_does_not_change_colouring)
{
    FlagGuard guard;
    std::string strRef;
    for (int nMode = 0; nMode < 4; nMode++)
    {
        fDAGKnightUnoptimizedOrdering = (nMode == 1);
        fDAGReachabilityCheck = (nMode == 3);
        const uint64_t nMismatchBefore = nDAGReachabilityMismatches;
        Dag dag;
        BuildBraid(dag, 4, 40, 2, 23);
        std::vector<int> vOrder = dag.TopoOrder(5);
        for (size_t s = 0; s < vOrder.size(); s++)
        {
            BOOST_REQUIRE(dag.Attach(vOrder[s]));
            if (nMode == 2)
                (void)Digest(dag, false);  // pre-warm every anchor/past entry each step
        }
        const std::string d = Digest(dag, true);
        if (nMode == 0)
            strRef = d;
        else
            BOOST_CHECK_MESSAGE(d == strRef, "cache mode " << nMode << " diverged");
        if (nMode == 3)
            BOOST_CHECK_EQUAL(nDAGReachabilityMismatches, nMismatchBefore);
    }
}

// (b) Past cache eviction (512 entries) and uncached oversize past sets (>1024).
BOOST_AUTO_TEST_CASE(past_cache_eviction_does_not_change_colouring)
{
    FlagGuard guard;
    std::string strRef;
    const int nLen = 40;
    // The wide anchor's past is every lane: over the uncached past-set limit.
    BOOST_REQUIRE((size_t)MAX_DAG_PARENTS * nLen > DAGKNIGHT_PAST_SET_MAX);
    for (int nMode = 0; nMode < 2; nMode++)
    {
        fDAGKnightUnoptimizedOrdering = (nMode == 1);
        Dag dag(41);
        const int nBase = dag.Add(-1);
        std::vector<int> vTips;
        for (int c = 0; c < MAX_DAG_PARENTS; c++)
        {
            int t = nBase;
            for (int h = 0; h < nLen; h++)
                t = dag.Add(t);
            vTips.push_back(t);
        }
        const int nWide = dag.Add(vTips[0], std::vector<int>(vTips.begin() + 1, vTips.end()));
        // Children whose colouring queries the oversize past of nWide.
        const int nSide = dag.Add(vTips[1]);
        int nTop = dag.Add(nWide, std::vector<int>(1, nSide));
        const int nSide2 = dag.Add(vTips[2]);
        nTop = dag.Add(nTop, std::vector<int>(1, nSide2));
        BOOST_REQUIRE(dag.vNodes.size() > (size_t)DAGKNIGHT_PAST_CACHE_MAX);
        dag.AttachAll(dag.TopoOrder(9));
        const std::string d = Digest(dag, false);
        if (nMode == 0)
            strRef = d;
        else
            BOOST_CHECK_MESSAGE(d == strRef, "eviction path diverged from the uncached reference");
    }
}

// (c) Block trust is hash entropy, so sibling scores differ: both rules select the
// highest-scoring parent regardless of its position.
BOOST_AUTO_TEST_CASE(selected_parent_is_highest_score)
{
    Dag dag;
    const int nBase = dag.Add(-1);
    const int nOld = dag.Add(nBase);           // lower score, used as a weak primary
    const int a = dag.Add(nOld);
    const int b = dag.Add(nOld);
    const int c = dag.Add(nOld);
    const int nAB = dag.Add(a, std::vector<int>(1, b));
    const int nBA = dag.Add(b, std::vector<int>(1, a));
    std::vector<int> vWeak;
    vWeak.push_back(a);
    vWeak.push_back(b);
    vWeak.push_back(c);
    const int nWeak = dag.Add(nBase, vWeak, dag.vNodes[a].nHeight + 1);
    dag.AttachAll(dag.IndexOrder());

    CBlockDAGData da, db, dc;
    BOOST_REQUIRE(g_dagManager.GetDAGData(dag.vHashes[a], da));
    BOOST_REQUIRE(g_dagManager.GetDAGData(dag.vHashes[b], db));
    BOOST_REQUIRE(g_dagManager.GetDAGData(dag.vHashes[c], dc));
    BOOST_REQUIRE(da.nDAGScore != db.nDAGScore && db.nDAGScore != dc.nDAGScore &&
                  da.nDAGScore != dc.nDAGScore);

    const uint256 hBestAB = da.nDAGScore > db.nDAGScore ? dag.vHashes[a] : dag.vHashes[b];
    const uint256 nBestAB = std::max(da.nDAGScore, db.nDAGScore);
    const uint256 hBestABC = dc.nDAGScore > nBestAB ? dag.vHashes[c] : hBestAB;

    BOOST_CHECK(g_dagManager.GetSelectedParent(dag.vHashes[nAB]) == hBestAB);
    BOOST_CHECK(g_dagManager.GetSelectedParent(dag.vHashes[nBA]) == hBestAB);

    uint256 sp = 0, s = 0;
    int k = 0;
    std::vector<std::pair<uint256, bool> > v;
    BOOST_REQUIRE(g_dagManager.GetDAGKnightAnchorMetrics(dag.vHashes[nAB], sp, k, s, v));
    BOOST_CHECK(sp == hBestAB);
    BOOST_REQUIRE(g_dagManager.GetDAGKnightAnchorMetrics(dag.vHashes[nBA], sp, k, s, v));
    BOOST_CHECK(sp == hBestAB);
    // The weaker primary loses to the best merge parent.
    BOOST_REQUIRE(g_dagManager.GetDAGKnightAnchorMetrics(dag.vHashes[nWeak], sp, k, s, v));
    BOOST_CHECK(sp == hBestABC);
    // Mergeset rule rejects a set whose primary is not selected.
    std::string strError;
    BOOST_CHECK(!g_dagManager.CheckMergesetParentSet(dag.Parents(nWeak), dag.vNodes[nWeak].nHeight, strError));
    const int nGood = dag.vHashes[a] == hBestAB ? nAB : nBA;
    BOOST_CHECK(g_dagManager.CheckMergesetParentSet(dag.Parents(nGood), dag.vNodes[nGood].nHeight, strError));
}

// (d) CheckDAGKnightParentSet accept/reject.
BOOST_AUTO_TEST_CASE(parent_set_rules)
{
    Dag dag;
    const int nBase = dag.Add(-1);
    const int a = dag.Add(nBase);
    const int b = dag.Add(nBase);
    dag.AttachAll(dag.IndexOrder());
    const int nH = dag.vNodes[a].nHeight + 1;
    std::string strError;

    BOOST_CHECK(!g_dagManager.CheckDAGKnightParentSet(std::vector<uint256>(), nH, strError));
    BOOST_CHECK(strError.find("no primary parent") != std::string::npos);

    BOOST_CHECK(g_dagManager.CheckDAGKnightParentSet(std::vector<uint256>(1, dag.vHashes[a]), nH, strError));

    std::vector<uint256> vMerge;
    vMerge.push_back(dag.vHashes[a]);
    vMerge.push_back(dag.vHashes[b]);
    BOOST_CHECK(g_dagManager.CheckDAGKnightParentSet(vMerge, nH, strError));

    // A merge parent with no block index.
    std::vector<uint256> vUnknown = vMerge;
    vUnknown.push_back(uint256(12345));
    BOOST_CHECK(!g_dagManager.CheckDAGKnightParentSet(vUnknown, nH, strError));
    BOOST_CHECK(strError.find("unavailable merge history") != std::string::npos);

    // An unknown primary alone has no selectable parent... its score is zero but it is
    // still the only candidate; it must not crash and must return a definite answer.
    std::vector<uint256> vOnlyUnknown(1, uint256(54321));
    (void)g_dagManager.CheckDAGKnightParentSet(vOnlyUnknown, nH, strError);

    // A merge parent older than the merge window is ignored, not rejected.
    BOOST_CHECK(g_dagManager.CheckDAGKnightParentSet(vMerge, nH + DAG_MERGE_DEPTH + 5, strError));
}

BOOST_AUTO_TEST_CASE(parent_set_candidate_limit_rejects)
{
    Dag dag;
    // 31 two-chain lanes merged at their tips: over 2048 candidates outside the main past.
    const int nLen = 40;
    BOOST_REQUIRE((MAX_DAG_PARENTS - 1) * (2 * nLen + 1) > DAGKNIGHT_MAX_ANCHOR_CANDIDATES);
    const int nBase = dag.Add(-1);
    int nMain = nBase;
    for (int h = 0; h <= nLen; h++)
        nMain = dag.Add(nMain);
    std::vector<uint256> vParents(1, dag.vHashes[nMain]);
    for (int c = 0; c < MAX_DAG_PARENTS - 1; c++)
    {
        int x = nBase, y = nBase;
        for (int h = 0; h < nLen; h++)
        {
            x = dag.Add(x);
            y = dag.Add(y);
        }
        vParents.push_back(dag.vHashes[dag.Add(x, std::vector<int>(1, y))]);
    }
    dag.AttachAll(dag.IndexOrder());
    std::string strError;
    BOOST_CHECK(!g_dagManager.CheckDAGKnightParentSet(vParents, dag.vNodes[nMain].nHeight + 1, strError));
    BOOST_CHECK_MESSAGE(strError.find("exceeds") != std::string::npos, strError);
}

// (e) k: floor on a linear chain, exact EMA after an adversarial spike, ceiling never
// crossed under repeated spikes, decay back to the floor, fixed k under mergeset.
BOOST_AUTO_TEST_CASE(inferred_k_bounds_and_ema)
{
    Dag dag;
    const int nBase = dag.Add(-1);
    int nMain = nBase;
    std::vector<int> vSamples;
    for (int h = 0; h < 30; h++)
    {
        nMain = dag.Add(nMain);
    }
    // 31 attacker chains of depth 20 forked from the base.
    std::vector<int> vTips;
    for (int c = 0; c < MAX_DAG_PARENTS - 1; c++)
    {
        int t = nBase;
        for (int h = 0; h < 20; h++)
            t = dag.Add(t);
        vTips.push_back(t);
    }
    dag.AttachAll(dag.IndexOrder());
    int nLinearK = KOf(dag, nMain);
    BOOST_CHECK_EQUAL(nLinearK, DAGKNIGHT_K_FLOOR);

    // The base block has no DAG parents (sample = floor); every linear block samples floor.
    for (int i = 0; i < DAGKNIGHT_K_SAMPLE_DEPTH; i++)
        vSamples.push_back(DAGKNIGHT_K_FLOOR);

    const int nSpike = dag.Add(nMain, vTips);
    BOOST_REQUIRE(dag.Attach(nSpike));
    vSamples.push_back(DAGKNIGHT_K_CEILING);   // pressure >= 20 -> 2p+1 capped at 32
    vSamples.erase(vSamples.begin());
    BOOST_CHECK_EQUAL(KOf(dag, nSpike), ExpectedK(vSamples));
    BOOST_CHECK_EQUAL(KOf(dag, nSpike), 10);

    // Decay: each linear successor samples the floor; k is non-increasing and reaches it.
    int nPrevK = KOf(dag, nSpike), nTip = nSpike;
    for (int i = 0; i < DAGKNIGHT_K_SAMPLE_DEPTH; i++)
    {
        nTip = dag.Add(nTip);
        BOOST_REQUIRE(dag.Attach(nTip));
        vSamples.push_back(DAGKNIGHT_K_FLOOR);
        vSamples.erase(vSamples.begin());
        const int k = KOf(dag, nTip);
        BOOST_CHECK_EQUAL(k, ExpectedK(vSamples));
        BOOST_CHECK(k <= nPrevK);
        nPrevK = k;
    }
    BOOST_CHECK_EQUAL(nPrevK, DAGKNIGHT_K_FLOOR);

    // EMA of an all-ceiling window stays at the ceiling; the clamp holds for any samples.
    BOOST_CHECK_EQUAL(ExpectedK(std::vector<int>(DAGKNIGHT_K_SAMPLE_DEPTH, DAGKNIGHT_K_CEILING)),
                      DAGKNIGHT_K_CEILING);
    BOOST_CHECK_EQUAL(ExpectedK(std::vector<int>(1, 255)), DAGKNIGHT_K_CEILING);
    BOOST_CHECK_EQUAL(ExpectedK(std::vector<int>(1, 0)), DAGKNIGHT_K_FLOOR);
}

BOOST_AUTO_TEST_CASE(inferred_k_repeated_spikes_never_exceed_ceiling)
{
    Dag dag;
    const int nBase = dag.Add(-1);
    int nMain = nBase;
    for (int h = 0; h < 4; h++)
        nMain = dag.Add(nMain);
    dag.AttachAll(dag.IndexOrder());
    // Every anchor merges 31 fresh one-block siblings of its predecessor's parent row.
    for (int r = 0; r < 24; r++)
    {
        std::vector<int> vSide;
        const int nParentOfMain = dag.vNodes[nMain].nPrev;
        for (int c = 0; c < MAX_DAG_PARENTS - 1; c++)
        {
            const int s = dag.Add(nParentOfMain);
            BOOST_REQUIRE(dag.Attach(s));
            vSide.push_back(s);
        }
        nMain = dag.Add(nMain, vSide);
        BOOST_REQUIRE(dag.Attach(nMain));
        const int k = KOf(dag, nMain);
        BOOST_CHECK(k >= DAGKNIGHT_K_FLOOR && k <= DAGKNIGHT_K_CEILING);
    }
}

BOOST_AUTO_TEST_CASE(inferred_k_fixed_under_mergeset)
{
    Dag dag;
    nRegtestMergesetHeight = BaseHeight() + 1;
    const int nBase = dag.Add(-1);
    int nMain = nBase;
    for (int h = 0; h < 10; h++)
        nMain = dag.Add(nMain);
    std::vector<int> vTips;
    for (int c = 0; c < 8; c++)
    {
        int t = nBase;
        for (int h = 0; h < 6; h++)
            t = dag.Add(t);
        vTips.push_back(t);
    }
    const int nSpike = dag.Add(nMain, vTips);
    dag.AttachAll(dag.IndexOrder());
    BOOST_CHECK_EQUAL(KOf(dag, nMain), GHOSTDAG_K);
    BOOST_CHECK_EQUAL(KOf(dag, nSpike), GHOSTDAG_K);
}

BOOST_AUTO_TEST_SUITE_END()
