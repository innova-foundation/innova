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

// An epoch-state record that reads back damaged is this node's failure; an absent one is
// the chain's answer. The record is rewritten under its own key with the wrong epoch
// number -- what a corrupt decode looks like to the reader -- and restored afterwards.
BOOST_AUTO_TEST_CASE(a_damaged_epoch_record_is_a_local_failure_and_an_absent_one_is_not)
{
    BOOST_REQUIRE(fRegTest);
    // Finalized heights a few epochs back, so both the anchor record and the deeper
    // records between it and the tip are V3 records with a key of their own.
    const int nV3Epoch = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3);
    while (GetEpochForHeight(BestIndex()->nHeight) - 3 <= nV3Epoch)
        MineTo(BestIndex()->nHeight + 50);
    const int nTip = BestIndex()->nHeight;
    const int nAsOf = GetEpochForHeight(nTip) - 1;
    const int nFinEpoch = nAsOf - 2;
    const int nFinalized = GetEpochBoundaryHeight(nFinEpoch + 1, nTip) - 1;
    {
        std::map<int, CEpochState> states;
        std::map<int, CCurveTree> trees;
        for (int e = nFinEpoch; e <= nAsOf; e++)
        {
            CEpochState state;
            BOOST_REQUIRE(g_dagManager.GetEpochState(e, state));
            state.hashCurveRoot = 0;
            state.nFinalizedHeightAsOf = (e == nAsOf) ? nFinalized : 0;
            states[e] = state;
            trees[e] = CCurveTree();
        }
        BOOST_REQUIRE(g_dagManager.InstallEpochStateBatch(nFinEpoch, states, trees));
    }
    // The txdb readers under test read the records on disk, not the in-memory set.
    CTxDB txdb;
    for (int e = nFinEpoch; e <= nAsOf; e++)
        BOOST_REQUIRE(g_dagManager.WriteEpochState(txdb, e));
    CEpochState saved;
    BOOST_REQUIRE(txdb.ReadEpochState(nFinEpoch, saved));
    CEpochState state;

    // Intact: the finalized epoch's record is found.
    bool fLocal = true;
    BOOST_CHECK(g_dagManager.GetFinalizedEpochStateAsOf(txdb, nTip, 0, state, &fLocal));
    BOOST_CHECK(!fLocal);
    BOOST_CHECK_EQUAL(state.nEpoch, nFinEpoch);

    // Damaged: the same key holds a record that does not decode as this epoch.
    CEpochState wrong = saved;
    wrong.nEpoch = nFinEpoch + 100;
    BOOST_REQUIRE(txdb.WriteEpochState(nFinEpoch, wrong));
    fLocal = false;
    BOOST_CHECK(!g_dagManager.GetFinalizedEpochStateAsOf(txdb, nTip, 0, state, &fLocal));
    BOOST_CHECK_MESSAGE(fLocal, "a damaged epoch record was reported as the chain's answer");
    // The primary reader walks the deeper records between the anchor and the tip.
    CEpochState primary;
    bool fPrimaryLocal = false;
    BOOST_REQUIRE(txdb.WriteEpochState(nFinEpoch, saved));
    CEpochState savedDeeper;
    BOOST_REQUIRE(txdb.ReadEpochState(nAsOf - 1, savedDeeper));
    CEpochState wrongDeeper = savedDeeper;
    wrongDeeper.nEpoch = nAsOf + 100;
    BOOST_REQUIRE(txdb.WriteEpochState(nAsOf - 1, wrongDeeper));
    BOOST_CHECK(!g_dagManager.GetFinalizedEpochStateAsOf(txdb, nTip, primary, fPrimaryLocal));
    BOOST_CHECK_MESSAGE(fPrimaryLocal, "a damaged deeper record was skipped instead of reported");
    BOOST_REQUIRE(txdb.WriteEpochState(nAsOf - 1, savedDeeper));

    // Absent: an epoch far below the first record is the chain's answer.
    fLocal = true;
    BOOST_CHECK(!g_dagManager.GetFinalizedEpochStateAsOf(txdb, nTip, nFinEpoch + 1000, state, &fLocal));
    BOOST_CHECK(!fLocal);

    fLocal = true;
    BOOST_CHECK(g_dagManager.GetFinalizedEpochStateAsOf(txdb, nTip, 0, state, &fLocal));
    BOOST_CHECK(!fLocal);
}

BOOST_AUTO_TEST_SUITE_END()
