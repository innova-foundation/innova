// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Merge-set bound: blocks a merge parent adds beyond past(primary parent) must number at
// most DAG_MERGE_SET_BOUND and descend from the primary chain within that depth.
// Synthetic indices only; linked last.

#include <boost/test/unit_test.hpp>

#include "../dag.h"
#include "../finality.h"
#include "../main.h"
#include "../mstimestamp.h"

#include <string>
#include <vector>

extern bool fRegTest;
extern bool fTestNet;

BOOST_AUTO_TEST_SUITE(dag_merge_set_bound_tests)

namespace {

// A trunk from the regtest genesis index to nTop, plus the side blocks a case attaches. Every
// index and every vertex registered here is removed again on exit, in reverse order, so the
// shared block index and DAG manager are left as they were found.
struct MergeSetChain
{
    std::vector<uint256>      vHashes;
    std::vector<CBlockIndex*> vIndex;
    std::vector<uint256>      vVertices;
    int          nTop;
    bool         fOldRegTest;
    bool         fOldTestNet;
    CBlockIndex* pOldBest;
    int64_t      nBaseTime;

    explicit MergeSetChain(int nTopIn) : nTop(nTopIn), nBaseTime(1760000000)
    {
        // Before any global moves: a throw here would skip the destructor that puts them back.
        BOOST_REQUIRE(pindexGenesisBlock != NULL);
        BOOST_REQUIRE(nTop >= 1);

        fOldRegTest = fRegTest;
        fOldTestNet = fTestNet;
        pOldBest = pindexBest;
        fRegTest = true;
        fTestNet = false;
        // AcceptBlock reads pindexBest only through the checkpoint helpers; a null tip puts
        // them on the genesis path, which every chain built here descends from.
        pindexBest = NULL;

        CBlockIndex* p = pindexGenesisBlock;
        for (int nHeight = 1; nHeight <= nTop; nHeight++)
            p = Add(nHeight, p);
    }

    ~MergeSetChain()
    {
        for (size_t i = vVertices.size(); i-- > 0; )
            g_dagManager.RemoveBlockDAGData(vVertices[i]);
        for (size_t i = vHashes.size(); i-- > 0; )
        {
            mapBlockIndex.erase(vHashes[i]);
            delete vIndex[i];
        }
        pindexBest = pOldBest;
        fRegTest = fOldRegTest;
        fTestNet = fOldTestNet;
    }

    // The trunk block at nHeight; the trunk occupies the first nTop entries, in height order.
    CBlockIndex* Trunk(int nHeight) const
    {
        BOOST_REQUIRE(nHeight >= 1 && nHeight <= nTop);
        CBlockIndex* p = vIndex[nHeight - 1];
        BOOST_REQUIRE_EQUAL(p->nHeight, nHeight);
        return p;
    }
    CBlockIndex* Tip() const { return Trunk(nTop); }

    // A side block on pprev, one above it.
    CBlockIndex* Side(CBlockIndex* pprev) { return Add(pprev->nHeight + 1, pprev); }

    // pprev extended by nCount side blocks, one height per step; the last one.
    CBlockIndex* Branch(CBlockIndex* pprev, int nCount)
    {
        CBlockIndex* p = pprev;
        for (int i = 0; i < nCount; i++)
            p = Side(p);
        return p;
    }

    // Registers pindex's committed parent set with the DAG manager, as AddToBlockIndex does
    // for an accepted block.
    void Commit(CBlockIndex* pindex, const std::vector<uint256>& vParents)
    {
        BOOST_REQUIRE(g_dagManager.InitBlockDAGData(pindex, vParents));
        vVertices.push_back(pindex->GetBlockHash());
    }

private:
    CBlockIndex* Add(int nHeight, CBlockIndex* pprev)
    {
        CBlock header;
        header.nVersion = CBlock::CURRENT_VERSION;
        header.hashPrevBlock = pprev->GetBlockHash();
        header.nTime = (unsigned int)(nBaseTime + nHeight);
        header.nBits = bnProofOfWorkLimit.GetCompact();
        header.nNonce = (unsigned int)(vHashes.size() + 1);
        header.hashMerkleRoot = uint256((unsigned int)(vHashes.size() + 1));

        const uint256 hash = header.GetHash();
        CBlockIndex* pindex = new CBlockIndex(0, 0, header);
        pindex->nHeight = nHeight;
        pindex->pprev = pprev;
        std::pair<std::map<uint256, CBlockIndex*>::iterator, bool> ins =
            mapBlockIndex.insert(std::make_pair(hash, pindex));
        BOOST_REQUIRE(ins.second);
        pindex->phashBlock = &ins.first->first;
        // The walk measures through GetAncestor, so the skip list it follows is built the
        // way the index writer builds it.
        pindex->BuildSkip();
        vHashes.push_back(hash);
        vIndex.push_back(pindex);
        return pindex;
    }
};

std::vector<uint256> Parents(const uint256& a)
{
    return std::vector<uint256>(1, a);
}

std::vector<uint256> Parents(const uint256& a, const uint256& b)
{
    std::vector<uint256> v(1, a);
    v.push_back(b);
    return v;
}

std::vector<uint256> Parents(const uint256& a, const uint256& b, const uint256& c)
{
    std::vector<uint256> v = Parents(a, b);
    v.push_back(c);
    return v;
}

std::vector<CBlockIndex*> One(CBlockIndex* p)
{
    return std::vector<CBlockIndex*>(1, p);
}

// The walk over vMerge against pPrev, in order; the count is reported either way.
bool Walk(const CBlockIndex* pPrev, const std::vector<CBlockIndex*>& vMerge,
          std::string& strError, int& nCount)
{
    CDAGMergeSetWalk walk(pPrev);
    strError.clear();
    bool fOK = true;
    for (size_t i = 0; fOK && i < vMerge.size(); i++)
        fOK = walk.AddMergeParent(vMerge[i]->GetBlockHash(), strError);
    nCount = walk.GetCount();
    return fOK;
}

// A proof-of-work block on pindexPrev committing vParents, valid up to the parent rules: the
// millisecond commitment AcceptBlock checks first is present and the target is the required
// one. It is never solved; AcceptBlock does not check the hash.
CBlock CandidateBlock(const CBlockIndex* pindexPrev, const std::vector<uint256>& vParents)
{
    const int nHeight = pindexPrev->nHeight + 1;

    CTransaction coinbase;
    coinbase.nTime = (unsigned int)(pindexPrev->GetBlockTime() + 1);
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << nHeight;
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = 0;
    coinbase.vout[0].scriptPubKey = BuildDAGParentScript(vParents);
    if (nHeight >= FORK_HEIGHT_MS_TIMESTAMP)
    {
        CTxOut msOut;
        msOut.nValue = 0;
        msOut.scriptPubKey = BuildMsTimestampScript(0);
        coinbase.vout.push_back(msOut);
    }

    CBlock block;
    block.nVersion = CBlock::CURRENT_VERSION;
    block.hashPrevBlock = pindexPrev->GetBlockHash();
    block.nTime = (unsigned int)(pindexPrev->GetBlockTime() + 1);
    block.nNonce = 12345;
    block.vtx.push_back(coinbase);
    block.nBits = GetNextTargetRequired(pindexPrev, false);
    block.hashMerkleRoot = block.BuildMerkleTree();
    block.nDoS = 0;
    return block;
}

} // namespace

// The bound is closed at DAG_MERGE_SET_BOUND. A merge parent whose pprev chain forks exactly
// that far below the primary parent passes, with every one of its blocks counted; one forking
// a single block deeper is refused however short it is, which only the root test can do.
BOOST_AUTO_TEST_CASE(a_fork_at_the_bound_passes_and_one_block_deeper_is_refused)
{
    LOCK(cs_main);
    MergeSetChain chain(FORK_HEIGHT_DAG + DAG_MERGE_SET_BOUND + 80);
    CBlockIndex* pPrev = chain.Tip();
    const int nRoot = pPrev->nHeight - DAG_MERGE_SET_BOUND;
    BOOST_REQUIRE(nRoot > 1);

    // Forks at the root and runs to the primary parent's height: exactly the bound in count.
    CBlockIndex* pAtBound = chain.Branch(chain.Trunk(nRoot), DAG_MERGE_SET_BOUND);
    BOOST_REQUIRE_EQUAL(pAtBound->nHeight, pPrev->nHeight);
    // Two blocks forking at the root, and two forking one below it.
    CBlockIndex* pShortAtBound = chain.Branch(chain.Trunk(nRoot), 2);
    CBlockIndex* pShortPastBound = chain.Branch(chain.Trunk(nRoot - 1), 2);

    std::string strError;
    int nCount = 0;
    BOOST_CHECK_MESSAGE(Walk(pPrev, One(pAtBound), strError, nCount), strError);
    BOOST_CHECK_EQUAL(nCount, DAG_MERGE_SET_BOUND);

    BOOST_CHECK_MESSAGE(Walk(pPrev, One(pShortAtBound), strError, nCount), strError);
    BOOST_CHECK_EQUAL(nCount, 2);

    BOOST_CHECK_MESSAGE(!Walk(pPrev, One(pShortPastBound), strError, nCount),
                        "a branch forking one block below the merge root was accepted");
}

// The primary parent is the chain the set is measured against, not the node's best tip: a
// joiner follows the primary chain, and that is the chain whose past it holds.
BOOST_AUTO_TEST_CASE(the_bound_is_measured_against_the_primary_parent_not_the_best_tip)
{
    LOCK(cs_main);
    MergeSetChain chain(FORK_HEIGHT_DAG + DAG_MERGE_SET_BOUND + 80);
    CBlockIndex* pTrunkTip = chain.Tip();
    const int nDeep = DAG_MERGE_SET_BOUND + 24;
    BOOST_REQUIRE(pTrunkTip->nHeight - nDeep > 1);

    // A branch as tall as the trunk, forking nDeep below its tip.
    CBlockIndex* pOtherTip = chain.Branch(chain.Trunk(pTrunkTip->nHeight - nDeep), nDeep);
    BOOST_REQUIRE_EQUAL(pOtherTip->nHeight, pTrunkTip->nHeight);
    // A leaf off the trunk, at the tip's height.
    CBlockIndex* pLeaf = chain.Side(chain.Trunk(pTrunkTip->nHeight - 1));

    std::string strError;
    int nCount = 0;

    // Primary parent on the trunk, best tip on the other branch: the leaf forks one deep.
    pindexBest = pOtherTip;
    BOOST_CHECK_MESSAGE(Walk(pTrunkTip, One(pLeaf), strError, nCount),
                        "measured against the best tip: " + strError);
    BOOST_CHECK_EQUAL(nCount, 1);

    // Primary parent on the other branch, best tip on the trunk: the leaf forks nDeep below.
    pindexBest = pTrunkTip;
    BOOST_CHECK_MESSAGE(!Walk(pOtherTip, One(pLeaf), strError, nCount),
                        "measured against the best tip, not the primary parent");
}

// The count spans the whole committed set, crossing merge edges and summing across
// merge parents.
BOOST_AUTO_TEST_CASE(the_count_crosses_merge_edges_and_accumulates_across_merge_parents)
{
    LOCK(cs_main);
    MergeSetChain chain(FORK_HEIGHT_DAG + DAG_MERGE_SET_BOUND + 80);
    CBlockIndex* pPrev = chain.Tip();
    const int nHalf = DAG_MERGE_SET_BOUND / 2 + 1;   // two of these exceed the bound
    const int nRest = DAG_MERGE_SET_BOUND - nHalf;   // one of these with one of those fits exactly
    BOOST_REQUIRE(2 * nHalf > DAG_MERGE_SET_BOUND);
    BOOST_REQUIRE(nHalf + nRest == DAG_MERGE_SET_BOUND);
    BOOST_REQUIRE(pPrev->nHeight - nHalf > 1);

    std::vector<int> vLengths;
    vLengths.push_back(nHalf);
    vLengths.push_back(nHalf);
    vLengths.push_back(nRest);
    std::vector<CBlockIndex*> vTips;
    for (size_t l = 0; l < vLengths.size(); l++)
    {
        CBlockIndex* pLast = NULL;
        for (int i = 0; i < vLengths[l]; i++)
        {
            CBlockIndex* pTrunk = chain.Trunk(pPrev->nHeight - vLengths[l] + i);
            CBlockIndex* pBlock = chain.Side(pTrunk);
            chain.Commit(pBlock, pLast ? Parents(pTrunk->GetBlockHash(), pLast->GetBlockHash())
                                       : Parents(pTrunk->GetBlockHash()));
            pLast = pBlock;
        }
        BOOST_REQUIRE_EQUAL(pLast->nHeight, pPrev->nHeight);
        vTips.push_back(pLast);
    }

    std::string strError;
    int nCount = 0;

    std::vector<CBlockIndex*> vFits;
    vFits.push_back(vTips[0]);
    vFits.push_back(vTips[2]);
    BOOST_CHECK_MESSAGE(Walk(pPrev, vFits, strError, nCount), strError);
    BOOST_CHECK_EQUAL(nCount, DAG_MERGE_SET_BOUND);

    std::vector<CBlockIndex*> vOver;
    vOver.push_back(vTips[0]);
    vOver.push_back(vTips[1]);
    BOOST_CHECK_MESSAGE(!Walk(pPrev, vOver, strError, nCount),
                        "two lineages summing past the bound were accepted");

    // Either half alone fits, so the refusal above came from the sum.
    BOOST_CHECK_MESSAGE(Walk(pPrev, One(vTips[1]), strError, nCount), strError);
    BOOST_CHECK_EQUAL(nCount, nHalf);
}

// Blocks already in past(primary parent) are cut before measuring, at any depth; the
// same tip named from a chain that never committed it is measured and refused.
BOOST_AUTO_TEST_CASE(blocks_the_primary_chain_committed_are_cut_before_they_are_measured)
{
    LOCK(cs_main);
    MergeSetChain chain(FORK_HEIGHT_DAG + 2 * DAG_MERGE_SET_BOUND + 200);
    CBlockIndex* pPrev = chain.Tip();
    const int nHeight = pPrev->nHeight;

    // Tops out at nHeight - 101, committed by the trunk block at nHeight - 100; forks below
    // the root.
    const int nDeepLen = DAG_MERGE_SET_BOUND + 1;
    BOOST_REQUIRE(nHeight - 101 - nDeepLen > 1);
    CBlockIndex* pDeep = chain.Branch(chain.Trunk(nHeight - 101 - nDeepLen), nDeepLen);
    BOOST_REQUIRE_EQUAL(pDeep->nHeight, nHeight - 101);
    BOOST_REQUIRE(nHeight - 101 - nDeepLen < nHeight - DAG_MERGE_SET_BOUND);
    chain.Commit(chain.Trunk(nHeight - 100),
                 Parents(chain.Trunk(nHeight - 101)->GetBlockHash(), pDeep->GetBlockHash()));

    // Tops out at nHeight - 12, committed by the trunk block at nHeight - 10; forks within
    // the bound.
    const int nNearLen = DAG_MERGE_SET_BOUND / 2 + 1;
    CBlockIndex* pNear = chain.Branch(chain.Trunk(nHeight - 12 - nNearLen), nNearLen);
    BOOST_REQUIRE_EQUAL(pNear->nHeight, nHeight - 12);
    chain.Commit(chain.Trunk(nHeight - 10),
                 Parents(chain.Trunk(nHeight - 11)->GetBlockHash(), pNear->GetBlockHash()));

    // A leaf off the trunk committing both branch tips.
    CBlockIndex* pLeaf = chain.Side(chain.Trunk(nHeight - 1));
    chain.Commit(pLeaf, Parents(chain.Trunk(nHeight - 1)->GetBlockHash(),
                                pDeep->GetBlockHash(), pNear->GetBlockHash()));

    std::string strError;
    int nCount = 0;
    BOOST_CHECK_MESSAGE(Walk(pPrev, One(pLeaf), strError, nCount), strError);
    BOOST_CHECK_EQUAL(nCount, 1);

    // A primary chain leaving the trunk below the block that committed pDeep.
    CBlockIndex* pOtherPrev = chain.Branch(chain.Trunk(nHeight - 102), 102);
    BOOST_REQUIRE_EQUAL(pOtherPrev->nHeight, nHeight);
    BOOST_CHECK_MESSAGE(!Walk(pOtherPrev, One(pDeep), strError, nCount),
                        "a deep branch was cut on a primary chain that never committed it");
}

// Committed history this node does not hold is a refusal, not a gap to step over: a walk that
// skipped it would under-count exactly the blocks a joiner has to fetch.
BOOST_AUTO_TEST_CASE(committed_history_that_is_not_indexed_fails_closed)
{
    LOCK(cs_main);
    MergeSetChain chain(FORK_HEIGHT_DAG + DAG_MERGE_SET_BOUND + 80);
    CBlockIndex* pPrev = chain.Tip();
    const uint256 hashAbsent(0xabce77ULL);
    BOOST_REQUIRE(!mapBlockIndex.count(hashAbsent));

    CBlockIndex* pLeaf = chain.Side(chain.Trunk(pPrev->nHeight - 1));
    chain.Commit(pLeaf, Parents(pLeaf->pprev->GetBlockHash(), hashAbsent));

    std::string strError;
    int nCount = 0;
    BOOST_CHECK_MESSAGE(!Walk(pPrev, One(pLeaf), strError, nCount),
                        "a committed parent that is not indexed was stepped over");

    CDAGMergeSetWalk direct(pPrev);
    BOOST_CHECK(!direct.AddMergeParent(hashAbsent, strError));
}

// AcceptBlock refuses a merge set past the bound at DoS 50, before writing or indexing.
BOOST_AUTO_TEST_CASE(accept_block_refuses_a_merge_set_past_the_bound_before_indexing)
{
    LOCK(cs_main);
    MergeSetChain chain(FORK_HEIGHT_DAG + DAG_MERGE_SET_BOUND + 80);
    CBlockIndex* pPrev = chain.Tip();
    const int nRoot = pPrev->nHeight - DAG_MERGE_SET_BOUND;
    BOOST_REQUIRE(nRoot > 1);

    // Forks one below the root, tops out one below the primary parent.
    CBlockIndex* pTip = chain.Branch(chain.Trunk(nRoot - 1), DAG_MERGE_SET_BOUND);
    BOOST_REQUIRE_EQUAL(pTip->nHeight, pPrev->nHeight - 1);
    BOOST_REQUIRE(pPrev->nHeight - pTip->nHeight <= DAG_MERGE_DEPTH);
    const uint256 hashAbsent(0xabce77ULL);
    BOOST_REQUIRE(!mapBlockIndex.count(hashAbsent));
    chain.Commit(pTip, Parents(pTip->pprev->GetBlockHash(), hashAbsent));

    std::vector<uint256> vParents;
    vParents.push_back(pPrev->GetBlockHash());
    vParents.push_back(pTip->GetBlockHash());
    std::string strError;
    BOOST_REQUIRE(IsBoundaryAActiveAtHeight(pPrev->nHeight + 1));
    BOOST_REQUIRE(!g_dagManager.CheckDAGKnightParentSet(vParents, pPrev->nHeight + 1, strError));
    int nCount = 0;
    BOOST_REQUIRE(!Walk(pPrev, One(pTip), strError, nCount));

    CBlock block = CandidateBlock(pPrev, vParents);
    const uint256 hash = block.GetHash();
    BOOST_CHECK(!block.AcceptBlock());
    BOOST_CHECK_MESSAGE(block.nDoS == 50,
                        "a merge set past the bound scored " << block.nDoS
                            << ", not the merge-set rule's 50");
    BOOST_CHECK(!mapBlockIndex.count(hash));
    BOOST_CHECK(!g_dagManager.HasDAGData(hash));
}

// A merge set within the bound passes on to the DAGKnight check, which refuses the
// block at 100 on an unheld parent the walk cut off.
BOOST_AUTO_TEST_CASE(accept_block_passes_a_merge_set_within_the_bound_on_to_the_dagknight_check)
{
    LOCK(cs_main);
    MergeSetChain chain(FORK_HEIGHT_DAG + DAG_MERGE_SET_BOUND + 80);
    CBlockIndex* pPrev = chain.Tip();
    const int nHeight = pPrev->nHeight;
    const int nRoot = nHeight - DAG_MERGE_SET_BOUND;
    BOOST_REQUIRE(nRoot > 1);

    // Forks at the root, tops out one below the primary parent: bound - 1 blocks.
    CBlockIndex* pTip = chain.Branch(chain.Trunk(nRoot), DAG_MERGE_SET_BOUND - 1);
    BOOST_REQUIRE_EQUAL(pTip->nHeight, nHeight - 1);
    BOOST_REQUIRE(nHeight - pTip->nHeight <= DAG_MERGE_DEPTH);

    const uint256 hashAbsent(0xabce77ULL);
    BOOST_REQUIRE(!mapBlockIndex.count(hashAbsent));
    CBlockIndex* pCommitted = chain.Side(chain.Trunk(nHeight - 4));
    chain.Commit(pCommitted, Parents(chain.Trunk(nHeight - 4)->GetBlockHash(), hashAbsent));
    chain.Commit(chain.Trunk(nHeight - 2),
                 Parents(chain.Trunk(nHeight - 3)->GetBlockHash(), pCommitted->GetBlockHash()));
    chain.Commit(pTip, Parents(pTip->pprev->GetBlockHash(), pCommitted->GetBlockHash()));

    std::vector<uint256> vParents;
    vParents.push_back(pPrev->GetBlockHash());
    vParents.push_back(pTip->GetBlockHash());
    std::string strError;
    BOOST_REQUIRE(IsBoundaryAActiveAtHeight(nHeight + 1));
    BOOST_REQUIRE(!g_dagManager.CheckDAGKnightParentSet(vParents, nHeight + 1, strError));
    int nCount = 0;
    BOOST_REQUIRE_MESSAGE(Walk(pPrev, One(pTip), strError, nCount), strError);
    BOOST_REQUIRE_EQUAL(nCount, DAG_MERGE_SET_BOUND - 1);

    CBlock block = CandidateBlock(pPrev, vParents);
    const uint256 hash = block.GetHash();
    BOOST_CHECK(!block.AcceptBlock());
    BOOST_CHECK_MESSAGE(block.nDoS == 100,
                        "a merge set within the bound scored " << block.nDoS
                            << ", not the DAGKnight check's 100");
    BOOST_CHECK(!mapBlockIndex.count(hash));
}

BOOST_AUTO_TEST_SUITE_END()
