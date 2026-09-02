// Verdicts that must not outlive this node's view.
//
// ConnectBlock's result is CONNECT_RESULT_INVALID unless a site says otherwise, and an
// INVALID result is serialized as BLOCK_FAILED_VALID. Every deterministic rejection in
// ConnectBlock is a DoS(...) return; a bare return comes from a clock or local read
// condition, so a verdict that did not raise nDoS is downgraded to TRANSIENT on exit.
// AcceptBlock refuses a child of a flagged parent, but the flag is this node's own,
// so the relayer is not scored.
//
// Mines on the shared regtest fixture; linked last in TEST_OBJS.

#include <boost/test/unit_test.hpp>

#include <memory>
#include <string>

#include "../bignum.h"
#include "../dag.h"
#include "../finality.h"
#include "../init.h"
#include "../main.h"
#include "../miner.h"
#include "../txdb.h"
#include "../uint256.h"
#include "../util.h"
#include "../wallet.h"

extern bool fRegTest;

BOOST_AUTO_TEST_SUITE(connect_verdict_locality_tests)

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

std::unique_ptr<CBlock> TemplateOnTip()
{
    unsigned int nExtraNonce = 0;
    CBlockIndex* pindexPrev = BestIndex();
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblock.get() != NULL);
    IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);
    return pblock;
}

CBlockIndex* MineOne()
{
    std::unique_ptr<CBlock> pblock = TemplateOnTip();
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

// ConnectBlock in check-only mode against an index that was never added: the result
// and the score are what the block would have been written down with.
CBlock::ConnectResult CheckOnly(CBlock& block, CBlockIndex* pindexPrev)
{
    const uint256 hash = block.GetHash();
    CBlockIndex index(0, 0, block);
    index.pprev = pindexPrev;
    index.nHeight = pindexPrev->nHeight + 1;
    index.phashBlock = &hash;
    block.nDoS = 0;
    CBlock::ConnectResult result = CBlock::CONNECT_RESULT_OK;
    LOCK(cs_main);
    CTxDB txdb("r");
    BOOST_CHECK(!block.ConnectBlock(txdb, &index, true, true, &result));
    return result;
}

} // namespace

BOOST_AUTO_TEST_CASE(an_unscored_refusal_is_transient_and_a_scored_one_persists)
{
    BOOST_REQUIRE(fRegTest);
    MineTo(FORK_HEIGHT_EPOCH_STATE_V3 + 2);
    CBlockIndex* pindexPrev = BestIndex();

    // Dated past the drift window: fails CheckBlock's clock check, which carries no score.
    std::unique_ptr<CBlock> pFuture = TemplateOnTip();
    pFuture->nTime = GetAdjustedTime() + 60 * 60;
    const CBlock::ConnectResult futureResult = CheckOnly(*pFuture, pindexPrev);
    BOOST_CHECK_EQUAL((int)futureResult, (int)CBlock::CONNECT_RESULT_TRANSIENT);
    BOOST_CHECK_EQUAL(pFuture->nDoS, 0);
    BOOST_CHECK(!ConnectResultMayPersistVerdict(futureResult));

    // Two coinbases: a structural refusal at the same site, scored.
    std::unique_ptr<CBlock> pTwo = TemplateOnTip();
    pTwo->vtx.push_back(pTwo->vtx[0]);
    pTwo->hashMerkleRoot = pTwo->BuildMerkleTree();
    const CBlock::ConnectResult twoResult = CheckOnly(*pTwo, pindexPrev);
    BOOST_CHECK_EQUAL((int)twoResult, (int)CBlock::CONNECT_RESULT_INVALID);
    BOOST_CHECK_GE(pTwo->nDoS, 100);
    BOOST_CHECK(ConnectResultMayPersistVerdict(twoResult));
}

BOOST_AUTO_TEST_CASE(a_child_of_a_flagged_parent_is_refused_without_a_score)
{
    BOOST_REQUIRE(fRegTest);
    CBlockIndex* pTip = BestIndex();
    BOOST_REQUIRE(pTip->pprev != NULL);
    std::unique_ptr<CBlock> pChild = TemplateOnTip();
    BOOST_REQUIRE(SolveBlock(pChild.get()));
    const uint256 hashChild = pChild->GetHash();

    {
        LOCK(cs_main);
        CTxDB txdb;
        std::string strError;
        BOOST_REQUIRE_MESSAGE(InvalidateBlock(txdb, pTip, strError), strError);
    }
    BOOST_REQUIRE(BestIndex() == pTip->pprev);
    BOOST_REQUIRE(pTip->IsInvalid());

    pChild->nDoS = 0;
    BOOST_CHECK(!ProcessBlock(NULL, pChild.get()));
    BOOST_CHECK_EQUAL(pChild->nDoS, 0);
    {
        LOCK(cs_main);
        BOOST_CHECK(mapBlockIndex.count(hashChild) == 0);
    }

    {
        LOCK(cs_main);
        CTxDB txdb;
        std::string strError;
        BOOST_REQUIRE_MESSAGE(ReconsiderBlock(txdb, pTip, strError), strError);
    }
    BOOST_CHECK(BestIndex() == pTip);
}

// A missing DAG vertex would shrink the sibling set, so the block is refused
// transiently rather than connected against a smaller set.
BOOST_AUTO_TEST_CASE(an_incomplete_sibling_set_is_a_transient_refusal)
{
    BOOST_REQUIRE(fRegTest);
    MineOne();
    CBlockIndex* pTip = BestIndex();
    CBlockIndex* pParent = pTip->pprev;
    BOOST_REQUIRE(pParent && pParent->nHeight >= FORK_HEIGHT_DAG);
    CBlock block;
    BOOST_REQUIRE(block.ReadFromDisk(pTip));

    bool fIncomplete = true;
    GetDAGSkippedTxsForBlock(block, pTip, &fIncomplete);
    BOOST_CHECK(!fIncomplete);

    CBlockDAGData parentData;
    BOOST_REQUIRE(g_dagManager.GetDAGData(pParent->GetBlockHash(), parentData));
    g_dagManager.RemoveBlockDAGData(pParent->GetBlockHash());
    fIncomplete = false;
    GetDAGSkippedTxsForBlock(block, pTip, &fIncomplete);
    BOOST_CHECK_MESSAGE(fIncomplete, "a missing parent vertex went unreported");

    block.nDoS = 0;
    CBlock::ConnectResult result = CBlock::CONNECT_RESULT_OK;
    {
        LOCK(cs_main);
        CTxDB txdb("r");
        BOOST_CHECK(!block.ConnectBlock(txdb, pTip, true, true, &result));
    }
    BOOST_CHECK_EQUAL((int)result, (int)CBlock::CONNECT_RESULT_TRANSIENT);
    BOOST_CHECK_EQUAL(block.nDoS, 0);

    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(pParent, parentData.vDAGParents));
    fIncomplete = true;
    GetDAGSkippedTxsForBlock(block, pTip, &fIncomplete);
    BOOST_CHECK(!fIncomplete);
}

BOOST_AUTO_TEST_SUITE_END()
