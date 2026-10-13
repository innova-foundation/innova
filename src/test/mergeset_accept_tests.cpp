// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Mergeset fork: the mergeset is the DAGKNIGHT order delta without its anchor, the
// selected parent must be the primary parent, and a mergeset holds at most 64 blocks.

#include <boost/test/unit_test.hpp>

#include "../bignum.h"
#include "../dag.h"
#include "../main.h"

#include <string>
#include <vector>

extern bool fRegTest;
extern bool fTestNet;

BOOST_AUTO_TEST_SUITE(mergeset_accept_tests)

namespace {

struct Dag
{
    std::vector<uint256>      vHashes;
    std::vector<CBlockIndex*> vBlocks;
    CBlockIndex*              pOldBest;
    bool                      fOldRegTest;
    bool                      fOldTestNet;
    CBigNum                   bnOldLimit;

    Dag()
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
        fRegTest = fOldRegTest;
        fTestNet = fOldTestNet;
    }

    static int BaseHeight()
    {
        return std::max(FORK_HEIGHT_EPOCH_STATE_V3, FORK_HEIGHT_DAGKNIGHT) + 4;
    }

    // A block on vParents[0] (or a base block) committing vParents, coloured as AddToBlockIndex does.
    CBlockIndex* Add(const std::vector<uint256>& vParents)
    {
        const size_t i = vBlocks.size();
        CBlockIndex* pprev = vParents.empty() ? NULL : mapBlockIndex[vParents[0]];

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
        pindex->nHeight = pprev ? pprev->nHeight + 1 : BaseHeight();
        pindex->pprev = pprev;
        std::pair<std::map<uint256, CBlockIndex*>::iterator, bool> ins =
            mapBlockIndex.insert(std::make_pair(hash, pindex));
        BOOST_REQUIRE(ins.second);
        pindex->phashBlock = &ins.first->first;
        vHashes.push_back(hash);
        vBlocks.push_back(pindex);

        BOOST_REQUIRE(g_dagManager.InitBlockDAGData(pindex, vParents));
        BOOST_REQUIRE(g_dagManager.ColorBlockDAGKnight(pindex));
        pindex->nChainTrust = g_dagManager.ComputeDAGScore(pindex);
        return pindex;
    }

    CBlockIndex* On(CBlockIndex* p) { return Add(std::vector<uint256>(1, p->GetBlockHash())); }

    CBlockIndex* Merge(CBlockIndex* p, CBlockIndex* m)
    {
        std::vector<uint256> v(1, p->GetBlockHash());
        v.push_back(m->GetBlockHash());
        return Add(v);
    }

    CBlockIndex* Chain(CBlockIndex* p, int n)
    {
        for (int i = 0; i < n; i++)
            p = On(p);
        return p;
    }
};

std::vector<uint256> Hashes(CBlockIndex* a, CBlockIndex* b)
{
    std::vector<uint256> v(1, a->GetBlockHash());
    v.push_back(b->GetBlockHash());
    return v;
}

} // namespace

BOOST_AUTO_TEST_CASE(mergeset_is_the_order_delta_without_its_anchor)
{
    Dag dag;
    CBlockIndex* c0 = dag.Add(std::vector<uint256>());
    CBlockIndex* c2 = dag.Chain(c0, 2);
    CBlockIndex* c5 = dag.Chain(c2, 3);
    CBlockIndex* s3 = dag.On(c2);
    CBlockIndex* s4 = dag.On(s3);
    CBlockIndex* b = dag.Merge(c5, s4);

    std::vector<std::pair<uint256, bool> > vSet;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(g_dagManager.GetDAGMergeSet(b->GetBlockHash(), vSet, strError), strError);
    BOOST_REQUIRE_EQUAL(vSet.size(), 2U);
    BOOST_CHECK(vSet[0].first == s3->GetBlockHash());
    BOOST_CHECK(vSet[1].first == s4->GetBlockHash());

    // A chain block merges nothing.
    BOOST_REQUIRE(g_dagManager.GetDAGMergeSet(c5->GetBlockHash(), vSet, strError));
    BOOST_CHECK(vSet.empty());
}

BOOST_AUTO_TEST_CASE(selected_parent_must_be_the_primary_parent)
{
    Dag dag;
    CBlockIndex* c0 = dag.Add(std::vector<uint256>());
    CBlockIndex* c2 = dag.Chain(c0, 2);
    CBlockIndex* c3 = dag.On(c2);
    CBlockIndex* s3 = dag.On(c2);
    CBlockIndex* c4 = dag.On(c3);
    CBlockIndex* m4 = dag.Merge(c3, s3);
    BOOST_REQUIRE(m4->nChainTrust > c4->nChainTrust);

    std::string strError;
    BOOST_CHECK(g_dagManager.CheckMergesetParentSet(Hashes(m4, c4), c4->nHeight + 1, strError));
    BOOST_CHECK(!g_dagManager.CheckMergesetParentSet(Hashes(c4, m4), c4->nHeight + 1, strError));
    BOOST_CHECK(strError.find("primary parent") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(mergeset_above_the_bound_is_refused)
{
    Dag dag;
    CBlockIndex* c0 = dag.Add(std::vector<uint256>());
    CBlockIndex* fork = dag.Chain(c0, 4);
    // The anchor sits at fork + 65, so the depth floor keeps every block above fork.
    CBlockIndex* tip = dag.Chain(fork, MERGESET_MAX_BLOCKS);
    CBlockIndex* branch = dag.Chain(fork, MERGESET_MAX_BLOCKS - 1);
    CBlockIndex* side = dag.On(fork);

    std::vector<uint256> vExact = Hashes(tip, branch);
    vExact.push_back(side->GetBlockHash());
    std::vector<uint256> vOver = vExact;
    vOver.push_back(dag.On(side)->GetBlockHash());

    std::string strError;
    BOOST_CHECK_MESSAGE(g_dagManager.CheckMergesetParentSet(vExact, tip->nHeight + 1, strError), strError);
    BOOST_CHECK(!g_dagManager.CheckMergesetParentSet(vOver, tip->nHeight + 1, strError));
    BOOST_CHECK(strError.find("limit") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(mergeset_retarget_smoothing)
{
    CBigNum bnLimit(~uint256(0) >> 20);
    CBigNum bnPrev(~uint256(0) >> 24);
    const unsigned int nBits = bnPrev.GetCompact();
    BOOST_CHECK_EQUAL(ComputeRetargetedBits(nBits, 300, 1, 300, true, bnLimit, 900), nBits);
    CBigNum bnFast, bnSlow;
    bnFast.SetCompact(ComputeRetargetedBits(nBits, 600, 1, 300, true, bnLimit));
    bnSlow.SetCompact(ComputeRetargetedBits(nBits, 600, 1, 300, true, bnLimit, 900));
    BOOST_CHECK(bnSlow > bnPrev && bnSlow < bnFast);
}

BOOST_AUTO_TEST_SUITE_END()
