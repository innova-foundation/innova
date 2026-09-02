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

BOOST_AUTO_TEST_SUITE_END()
