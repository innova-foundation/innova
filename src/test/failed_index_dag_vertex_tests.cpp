// A retained failed index keeps its DAG vertex: later blocks read their sibling set
// from it. Mines past Boundary A; linked last in TEST_OBJS.

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include "../bignum.h"
#include "../dag.h"
#include "../init.h"
#include "../main.h"
#include "../miner.h"
#include "../txdb.h"
#include "../uint256.h"
#include "../wallet.h"

extern bool fRegTest;

BOOST_AUTO_TEST_SUITE(failed_index_dag_vertex_tests)

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

CBlockIndex* MineOne()
{
    unsigned int nExtraNonce = 0;
    CBlockIndex* pindexPrev = BestIndex();
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblock.get() != NULL);
    IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);
    BOOST_REQUIRE(SolveBlock(pblock.get()));
    const uint256 hash = pblock->GetHash();
    BOOST_REQUIRE(ProcessBlock(NULL, pblock.get()));
    LOCK(cs_main);
    BOOST_REQUIRE(mapBlockIndex.count(hash) != 0);
    return mapBlockIndex[hash];
}

void MineTo(int nTarget)
{
    while (BestIndex()->nHeight < nTarget)
        MineOne();
}

// A block CheckBlock accepts and ConnectBlock rejects: the coinbase overpays by
// one satoshi. It extends the tip, so AddToBlockIndex attempts SetBestChain and
// takes the permanent-invalid branch.
std::unique_ptr<CBlock> MakeOverpayingBlock(CBlockIndex* pindexPrev)
{
    unsigned int nExtraNonce = 0;
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblock.get() != NULL);
    IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);
    pblock->vtx[0].vout[0].nValue += 1;
    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
    BOOST_REQUIRE(SolveBlock(pblock.get()));
    return pblock;
}

} // namespace

BOOST_AUTO_TEST_CASE(a_flagged_index_keeps_its_vertex_and_the_loader_accepts_it)
{
    BOOST_REQUIRE(fRegTest);
    MineTo(FORK_HEIGHT_EPOCH_STATE_V3 + 2);
    CBlockIndex* pindexPrev = BestIndex();
    const uint256 hashPrev = pindexPrev->GetBlockHash();

    std::unique_ptr<CBlock> pblock = MakeOverpayingBlock(pindexPrev);
    const uint256 hash = pblock->GetHash();
    BOOST_CHECK(!ProcessBlock(NULL, pblock.get()));

    LOCK(cs_main);
    BOOST_CHECK(pindexBest == pindexPrev);
    BOOST_REQUIRE_MESSAGE(mapBlockIndex.count(hash) != 0,
                          "the flagged index was not retained");
    const CBlockIndex* pindex = mapBlockIndex[hash];
    BOOST_CHECK(pindex->IsFailed());

    // In memory and on disk, the vertex and the parent's child link survive the flag.
    BOOST_CHECK_MESSAGE(g_dagManager.HasDAGData(hash), "the flag stripped the vertex");
    CTxDB txdb("r");
    CBlockDAGData data;
    BOOST_REQUIRE_MESSAGE(txdb.ReadDAGLinks(hash, data),
                          "the vertex was not persisted with the flag");
    BOOST_REQUIRE(!data.vDAGParents.empty());
    BOOST_CHECK(data.vDAGParents[0] == hashPrev);
    CBlockDAGData parent;
    BOOST_REQUIRE(txdb.ReadDAGLinks(hashPrev, parent));
    BOOST_CHECK(std::find(parent.vDAGChildren.begin(), parent.vDAGChildren.end(),
                          hash) != parent.vDAGChildren.end());

    // What a restart sees: a flagged index with a vertex loads.
    CDAGManager scratch;
    BOOST_CHECK_MESSAGE(scratch.LoadDAGLinks(txdb),
                        "the loader refuses the persisted state");
}

// Reconsidering the rejected block re-attempts it: ConnectBlock rejects it again, the
// reselection flags it again with the vertex intact, and the recovery RPC succeeds.
BOOST_AUTO_TEST_CASE(reconsidering_a_rejected_block_flags_it_again_with_its_vertex)
{
    BOOST_REQUIRE(fRegTest);
    CBlockIndex* pindexPrev = BestIndex();
    std::unique_ptr<CBlock> pblock = MakeOverpayingBlock(pindexPrev);
    const uint256 hash = pblock->GetHash();
    BOOST_CHECK(!ProcessBlock(NULL, pblock.get()));

    LOCK(cs_main);
    BOOST_REQUIRE(mapBlockIndex.count(hash) != 0);
    CBlockIndex* pindex = mapBlockIndex[hash];
    BOOST_REQUIRE(pindex->IsFailed());

    CTxDB txdb;
    std::string strError;
    bool fFlagsCleared = false;
    BOOST_CHECK_MESSAGE(ReconsiderBlock(txdb, pindex, strError, &fFlagsCleared), strError);
    BOOST_CHECK(fFlagsCleared);
    BOOST_CHECK_MESSAGE(pindex->IsFailed(), "the rejected block was left unflagged after reconsider");
    BOOST_CHECK(pindexBest == pindexPrev);
    BOOST_CHECK(g_dagManager.HasDAGData(hash));
    CTxDB txdbRead("r");
    CBlockDAGData data;
    BOOST_CHECK(txdbRead.ReadDAGLinks(hash, data));
    CDAGManager scratch;
    BOOST_CHECK(scratch.LoadDAGLinks(txdbRead));
}

// Flagged with no vertex: reconsider must refuse before any write, and the loader
// tolerates the index as it is.
BOOST_AUTO_TEST_CASE(reconsider_refuses_a_flagged_block_without_a_vertex_and_changes_nothing)
{
    BOOST_REQUIRE(fRegTest);
    CBlockIndex* pindexPrev = BestIndex();
    std::unique_ptr<CBlock> pblock = MakeOverpayingBlock(pindexPrev);
    const uint256 hash = pblock->GetHash();
    BOOST_CHECK(!ProcessBlock(NULL, pblock.get()));

    LOCK(cs_main);
    BOOST_REQUIRE(mapBlockIndex.count(hash) != 0);
    CBlockIndex* pindex = mapBlockIndex[hash];
    BOOST_REQUIRE(pindex->IsFailed());
    BOOST_REQUIRE(g_dagManager.HasDAGData(hash));

    g_dagManager.RemoveBlockDAGData(hash);
    {
        CTxDB txdbDamage;
        BOOST_REQUIRE(txdbDamage.EraseDAGLinks(hash));
    }

    CTxDB txdb;
    std::string strError;
    bool fFlagsCleared = true;
    BOOST_CHECK(!ReconsiderBlock(txdb, pindex, strError, &fFlagsCleared));
    BOOST_CHECK_MESSAGE(strError.find("no DAG vertex") != std::string::npos, strError);
    BOOST_CHECK(!fFlagsCleared);
    BOOST_CHECK_MESSAGE(pindex->IsFailed(), "the refused reconsider cleared the flag");
    BOOST_CHECK(pindexBest == pindexPrev);

    CTxDB txdbRead("r");
    CDAGManager scratch;
    BOOST_CHECK_MESSAGE(scratch.LoadDAGLinks(txdbRead),
                        "the loader refuses a flagged, vertex-less index");
}

// A valid index with no vertex: the loader rebuilds and persists the vertex from the
// block on disk; a block not on disk stays fatal.
BOOST_AUTO_TEST_CASE(the_loader_rebuilds_a_missing_vertex_from_the_block_on_disk)
{
    BOOST_REQUIRE(fRegTest);
    CBlockIndex* pindexPrev = BestIndex();
    std::unique_ptr<CBlock> pblock = MakeOverpayingBlock(pindexPrev);
    const uint256 hash = pblock->GetHash();
    BOOST_CHECK(!ProcessBlock(NULL, pblock.get()));

    LOCK(cs_main);
    BOOST_REQUIRE(mapBlockIndex.count(hash) != 0);
    CBlockIndex* pindex = mapBlockIndex[hash];
    BOOST_REQUIRE(pindex->IsFailed());

    // The damage, then the flag cleared behind the guard's back.
    g_dagManager.RemoveBlockDAGData(hash);
    {
        CTxDB txdbDamage;
        BOOST_REQUIRE(txdbDamage.EraseDAGLinks(hash));
        pindex->ClearFailed();
        BOOST_REQUIRE(txdbDamage.WriteBlockIndex(CDiskBlockIndex(pindex)));
    }
    CTxDB txdbRead("r");
    CBlockDAGData gone;
    BOOST_REQUIRE(!txdbRead.ReadDAGLinks(hash, gone));

    CTxDB txdb;
    CDAGManager scratch;
    BOOST_REQUIRE_MESSAGE(scratch.LoadDAGLinks(txdb), "the loader refused a rebuildable index");
    CBlockDAGData rebuilt;
    BOOST_REQUIRE(scratch.GetDAGData(hash, rebuilt));
    std::vector<CScript> vScripts;
    for (size_t i = 0; i < pblock->vtx[0].vout.size(); i++)
        vScripts.push_back(pblock->vtx[0].vout[i].scriptPubKey);
    std::vector<uint256> vExpected;
    std::string strError;
    BOOST_REQUIRE(ReadDAGParentCommitmentAtHeight(vScripts, pindex->nHeight, vExpected, strError));
    BOOST_REQUIRE(!vExpected.empty());
    BOOST_CHECK(vExpected[0] == pindexPrev->GetBlockHash());
    BOOST_CHECK(rebuilt.vDAGParents == vExpected);
    BOOST_CHECK(scratch.GetMinRebuiltVertexHeight() >= FORK_HEIGHT_DAG);
    BOOST_CHECK(scratch.GetMinRebuiltVertexHeight() <= pindex->nHeight);
    CBlockDAGData persisted;
    BOOST_CHECK_MESSAGE(txdbRead.ReadDAGLinks(hash, persisted), "the rebuilt vertex was not persisted");
    BOOST_CHECK(persisted.vDAGParents == vExpected);

    // Leave the invalid block flagged for the suites that follow.
    pindex->SetFailedValid();
    BOOST_REQUIRE(txdb.WriteBlockIndex(CDiskBlockIndex(pindex)));

    // An index whose block is not on disk cannot be rebuilt.
    CBlock empty;
    CBlockIndex* pFake = new CBlockIndex(0, 0, empty);
    const uint256 hashFake(0xfa4e);
    pFake->pprev = pindexPrev;
    pFake->nHeight = pindexPrev->nHeight + 1;
    pFake->phashBlock = &mapBlockIndex.insert(std::make_pair(hashFake, pFake)).first->first;
    CDAGManager scratchFake;
    BOOST_CHECK_MESSAGE(!scratchFake.LoadDAGLinks(txdbRead), "an index with no block data loaded");
    mapBlockIndex.erase(hashFake);
    delete pFake;
}

BOOST_AUTO_TEST_SUITE_END()
