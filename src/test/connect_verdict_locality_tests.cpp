// Verdicts that must not outlive this node's view: a ConnectBlock rejection without nDoS
// is TRANSIENT, and a child of a locally flagged parent does not score the relayer.

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <map>
#include <vector>
#include <memory>
#include <string>

#include "../bignum.h"
#include "../dag.h"
#include "../finality.h"
#include "../init.h"
#include "../main.h"
#include "../miner.h"
#include "../nullsend_v2008.h"
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
    BOOST_REQUIRE_MESSAGE(pblock->hashPrevBlock == pindexPrev->GetBlockHash(),
                          "the template does not build on the tip");
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

CBlockIndex* AncestorAt(CBlockIndex* pindex, int nHeight)
{
    while (pindex && pindex->nHeight > nHeight)
        pindex = pindex->pprev;
    return pindex;
}

int HighestIndexedHeight()
{
    LOCK(cs_main);
    int nHighest = 0;
    for (std::map<uint256, CBlockIndex*>::const_iterator it = mapBlockIndex.begin();
         it != mapBlockIndex.end(); ++it)
        nHighest = std::max(nHighest, it->second->nHeight);
    return nHighest;
}

// The epoch records from nFrom up to the epoch after the tip's, in memory and on disk,
// put back when the holder goes out of scope. That range is every record an
// InstallEpochStateBatch(nFrom, ...) can replace or drop.
struct ScopedEpochRecords
{
    int nFrom;
    int nFirst; // the first epoch at or above nFrom with a record in memory
    int nLast;
    std::map<int, CEpochState> states;
    std::map<int, CEpochState> diskStates;
    std::map<int, CCurveTree> diskTrees;

    explicit ScopedEpochRecords(int nFromIn) : nFrom(nFromIn), nFirst(-1)
    {
        nLast = GetEpochForHeight(BestIndex()->nHeight) + 1;
        CTxDB txdb("r");
        for (int e = nFrom; e <= nLast; e++)
        {
            CEpochState state;
            if (g_dagManager.GetEpochState(e, state))
            {
                if (nFirst < 0)
                    nFirst = e;
                states[e] = state;
            }
            CEpochState onDisk;
            if (txdb.ReadEpochState(e, onDisk))
                diskStates[e] = onDisk;
            CCurveTree tree;
            if (txdb.ReadCurveTreeAtEpoch(e, tree))
                diskTrees[e] = tree;
        }
        BOOST_REQUIRE_MESSAGE(nFirst >= 0, "no epoch record at or above epoch " << nFrom);
    }

    ~ScopedEpochRecords()
    {
        // Memory: each saved state with the tree it was written with; a state whose tree
        // is not on disk goes back with an empty tree and root, as the siblings install.
        std::map<int, CEpochState> restored;
        std::map<int, CCurveTree> trees;
        for (std::map<int, CEpochState>::const_iterator it = states.begin(); it != states.end(); ++it)
        {
            CEpochState state = it->second;
            std::map<int, CCurveTree>::const_iterator itTree = diskTrees.find(it->first);
            if (itTree != diskTrees.end() && itTree->second.nLeafCount != 0)
                trees[it->first] = itTree->second;
            else
            {
                state.hashCurveRoot = 0;
                trees[it->first] = CCurveTree();
            }
            restored[it->first] = state;
        }
        BOOST_CHECK_MESSAGE(g_dagManager.InstallEpochStateBatch(nFirst, restored, trees),
                            "could not put the displaced epoch records back in memory");
        // Disk: exactly what was there, record by record.
        CTxDB txdb;
        bool fOK = true;
        for (int e = nFrom; e <= nLast; e++)
        {
            std::map<int, CEpochState>::const_iterator itState = diskStates.find(e);
            fOK = (itState != diskStates.end() ? txdb.WriteEpochState(e, itState->second)
                                               : txdb.EraseEpochState(e)) && fOK;
            std::map<int, CCurveTree>::const_iterator itTree = diskTrees.find(e);
            fOK = (itTree != diskTrees.end() ? txdb.WriteCurveTreeAtEpoch(e, itTree->second)
                                             : txdb.EraseCurveTreeAtEpoch(e)) && fOK;
        }
        BOOST_CHECK_MESSAGE(fOK, "could not put the displaced epoch records back on disk");
    }
};

// Every epoch record in memory is one the chain could have built, and the disk copy agrees.
// Catches a fixture that left a synthetic record behind.
void CheckEpochRecordsAreTheChains(const char* pszWhen)
{
    CBlockIndex* pTip = BestIndex();
    const int nLast = GetEpochForHeight(pTip->nHeight) + 1;
    CTxDB txdb("r");
    int nSeen = 0;
    for (int e = 0; e <= nLast; e++)
    {
        CEpochState state;
        if (!g_dagManager.GetEpochState(e, state))
        {
            BOOST_CHECK_MESSAGE(txdb.ProbeEpochState(e) == TXDB_READ_NOT_FOUND,
                                pszWhen << ": epoch " << e << " is on disk but not in memory");
            continue;
        }
        nSeen++;
        const int nFin = state.nFinalizedHeightAsOf;
        BOOST_CHECK_MESSAGE(nFin == 0 || (IsEpochBoundaryHeight(nFin) && nFin <= state.nHeightEnd),
                            pszWhen << ": epoch " << e << " names finalized height " << nFin
                            << ", which is not a boundary at or below its end " << state.nHeightEnd);
        if (nFin != 0)
        {
            const CBlockIndex* pAt = AncestorAt(pTip, nFin);
            BOOST_CHECK_MESSAGE(pAt && pAt->nHeight == nFin &&
                                pAt->GetBlockHash() == state.FinalizedAnchorHash(),
                                pszWhen << ": epoch " << e << " names a finalized block at "
                                << nFin << " that the tip's chain does not carry");
        }
        CEpochState onDisk;
        BOOST_CHECK_MESSAGE(txdb.ReadEpochState(e, onDisk) && onDisk.nEpoch == e &&
                            onDisk.nFinalizedHeightAsOf == nFin &&
                            onDisk.hashBoundaryBlock == state.hashBoundaryBlock,
                            pszWhen << ": epoch " << e << " differs between memory and disk");
    }
    BOOST_CHECK_MESSAGE(nSeen > 0, pszWhen << ": no epoch record in memory");
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

BOOST_AUTO_TEST_CASE(epoch_records_arrive_as_the_chain_built_them)
{
    BOOST_REQUIRE(fRegTest);
    CheckEpochRecordsAreTheChains("on entry");
}

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
    // Side branches earlier suites left indexed must not outweigh the chain once its tip
    // is refused: the tip's parent has to be the heaviest block that remains.
    MineTo(HighestIndexedHeight() + 3);
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
    BOOST_CHECK_MESSAGE(GetLastErrorString().find("marked failed/invalid") != std::string::npos ||
                        GetLastErrorString().find("AcceptBlock FAILED") != std::string::npos,
                        "refused for another reason: " << GetLastErrorString());
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
    BOOST_CHECK_MESSAGE(GetLastErrorString().find("incomplete on this node") != std::string::npos,
                        "refused for another reason: " << GetLastErrorString());

    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(pParent, parentData.vDAGParents));
    fIncomplete = true;
    GetDAGSkippedTxsForBlock(block, pTip, &fIncomplete);
    BOOST_CHECK(!fIncomplete);
}

// A damaged epoch-state record, or one absent between the floor and a present as-of
// record, is this node's failure; an absent as-of record is the chain's answer.
BOOST_AUTO_TEST_CASE(a_lost_or_damaged_epoch_record_is_local_and_an_absent_as_of_is_not)
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
    // Finalized at the boundary that closes nFinEpoch, which GetFinalizedEpochForHeight
    // resolves to nFinEpoch; the record names the tip's block there, as a built one would.
    const int nFinalized = GetEpochBoundaryHeight(nFinEpoch + 1, nTip);
    BOOST_REQUIRE_EQUAL(GetFinalizedEpochForHeight(nFinalized), nFinEpoch);
    CBlockIndex* pAttested = AncestorAt(BestIndex(), nFinalized);
    BOOST_REQUIRE(pAttested && pAttested->nHeight == nFinalized);
    ScopedEpochRecords records(nFinEpoch);
    {
        std::map<int, CEpochState> states;
        std::map<int, CCurveTree> trees;
        for (int e = nFinEpoch; e <= nAsOf; e++)
        {
            CEpochState state;
            BOOST_REQUIRE(g_dagManager.GetEpochState(e, state));
            state.hashCurveRoot = 0;
            state.nFinalizedHeightAsOf = (e == nAsOf) ? nFinalized : 0;
            state.hashVNextFinalizedAnchor = (e == nAsOf) ? pAttested->GetBlockHash() : uint256(0);
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

    // Absent above the floor with the as-of record present: records are dense there on
    // every node, so this one was lost here.
    BOOST_REQUIRE(txdb.EraseEpochState(nFinEpoch));
    fLocal = false;
    BOOST_CHECK(!g_dagManager.GetFinalizedEpochStateAsOf(txdb, nTip, 0, state, &fLocal));
    BOOST_CHECK_MESSAGE(fLocal, "a lost finalized record was reported as the chain's answer");
    BOOST_REQUIRE(txdb.WriteEpochState(nFinEpoch, saved));

    // Absent as-of record: the chain's answer.
    CEpochState savedAsOf;
    BOOST_REQUIRE(txdb.ReadEpochState(nAsOf, savedAsOf));
    BOOST_REQUIRE(txdb.EraseEpochState(nAsOf));
    fLocal = true;
    BOOST_CHECK(!g_dagManager.GetFinalizedEpochStateAsOf(txdb, nTip, 0, state, &fLocal));
    BOOST_CHECK_MESSAGE(!fLocal, "an absent as-of record was classed as a local failure");
    BOOST_REQUIRE(txdb.WriteEpochState(nAsOf, savedAsOf));

    fLocal = true;
    BOOST_CHECK(g_dagManager.GetFinalizedEpochStateAsOf(txdb, nTip, 0, state, &fLocal));
    BOOST_CHECK(!fLocal);
}

// The anchors ConnectBlock accepts at one height: the newest resolved anchor and five
// more from the same head, as one contiguous run.
std::vector<int> AcceptedAnchorEpochs(CTxDB& txdb, int nBlockHeight)
{
    std::vector<int> vEpochs;
    CEpochState state;
    bool fLocal = false;
    if (g_dagManager.GetFinalizedEpochStateAsOf(txdb, nBlockHeight, state, fLocal))
        vEpochs.push_back(state.nEpoch);
    for (int nBack = 1; nBack < EPOCHSTATE_VNEXT_MAX_ANCHOR_AGE_EPOCHS; ++nBack)
    {
        CEpochState older;
        bool fOlderLocal = false;
        if (g_dagManager.GetFinalizedEpochStateAsOf(txdb, nBlockHeight, nBack, older,
                                                    &fOlderLocal))
            vEpochs.push_back(older.nEpoch);
    }
    return vEpochs;
}

// Write every record the chain has at or below nAsOf with one finalized height, so the
// whole ladder resolves from a finality position this test chose.
void SetFinalizedAsOf(CTxDB& txdb, const ScopedEpochRecords& records, int nAsOf,
                      int nFinalizedHeight, const uint256& hashAttested)
{
    std::map<int, CEpochState> states;
    std::map<int, CCurveTree> trees;
    for (std::map<int, CEpochState>::const_iterator it = records.states.begin();
         it != records.states.end() && it->first <= nAsOf; ++it)
    {
        CEpochState state = it->second;
        state.hashCurveRoot = 0;
        state.nFinalizedHeightAsOf = nFinalizedHeight;
        state.hashVNextFinalizedAnchor = hashAttested;
        state.fFinalized = (state.nHeightEnd > 0 && nFinalizedHeight >= state.nHeightEnd);
        states[it->first] = state;
        trees[it->first] = CCurveTree();
    }
    BOOST_REQUIRE(g_dagManager.InstallEpochStateBatch(records.nFirst, states, trees));
    for (std::map<int, CEpochState>::const_iterator it = states.begin();
         it != states.end(); ++it)
        BOOST_REQUIRE(g_dagManager.WriteEpochState(txdb, it->first));
}

BOOST_AUTO_TEST_CASE(the_accepted_anchor_set_is_one_run_from_the_head_it_resolves)
{
    BOOST_REQUIRE(fRegTest);
    const int nTip = BestIndex()->nHeight;
    const int nAsOf = GetEpochForHeight(nTip) - 1;
    // The gap needs room for an unfinalized epoch deep enough to stand on its own above a
    // far-behind finalized one, which is a few epochs plus the depth rule's reach.
    BOOST_REQUIRE_MESSAGE(nAsOf >= 4, "chain too short to exercise the ladder: as-of epoch "
                          << nAsOf);
    BOOST_TEST_MESSAGE("anchor ladder: tip " << nTip << " as-of epoch " << nAsOf);
    ScopedEpochRecords records(0);
    CTxDB txdb;

    // Finality keeping up: the finalized epoch is the newest thing there is, the depth
    // rule finds nothing above it, and both halves count from the same place.
    {
        const int nFinEpoch = nAsOf - 1;
        const int nFinalized = GetEpochBoundaryHeight(nFinEpoch + 1, nTip);
        BOOST_REQUIRE_EQUAL(GetFinalizedEpochForHeight(nFinalized), nFinEpoch);
        CBlockIndex* pAttested = AncestorAt(BestIndex(), nFinalized);
        BOOST_REQUIRE(pAttested);
        SetFinalizedAsOf(txdb, records, nAsOf, nFinalized, pAttested->GetBlockHash());

        const std::vector<int> vSet = AcceptedAnchorEpochs(txdb, nTip);
        BOOST_REQUIRE(!vSet.empty());
        for (size_t i = 1; i < vSet.size(); i++)
            BOOST_CHECK_MESSAGE(vSet[i] == vSet[i - 1] - 1,
                                "with finality current the accepted anchors are not one "
                                "contiguous run: " << vSet[i - 1] << " then " << vSet[i]);
        BOOST_CHECK_MESSAGE(vSet.front() == nFinEpoch,
                            "the newest accepted anchor is not the finalized epoch");
    }

    // Finality far behind: the newest entry comes from the depth rule. The set must stay
    // one run from that head, including the finalized epoch.
    {
        const int nFinEpoch = 1;
        const int nFinalized = GetEpochBoundaryHeight(nFinEpoch + 1, nTip);
        BOOST_REQUIRE_EQUAL(GetFinalizedEpochForHeight(nFinalized), nFinEpoch);
        CBlockIndex* pAttested = AncestorAt(BestIndex(), nFinalized);
        BOOST_REQUIRE(pAttested);
        SetFinalizedAsOf(txdb, records, nAsOf, nFinalized, pAttested->GetBlockHash());

        const std::vector<int> vSet = AcceptedAnchorEpochs(txdb, nTip);
        BOOST_REQUIRE(!vSet.empty());
        const int nNewest = vSet.front();
        BOOST_REQUIRE_MESSAGE(nNewest > nFinEpoch,
                              "the depth rule did not reach past the finalized epoch, so this "
                              "case does not exercise the fallback at all");
        // One run from the head the height resolves, which is the depth pick here. Two
        // pieces with a gap is the shape this replaced: an anchor taken from the head then
        // expired at the next head change rather than five epochs later.
        for (size_t i = 1; i < vSet.size(); i++)
            BOOST_CHECK_MESSAGE(vSet[i] == vSet[i - 1] - 1,
                                "the accepted anchors came apart at " << vSet[i - 1]
                                << " then " << vSet[i] << "; the older entries are counting "
                                "from somewhere other than the head");
        BOOST_CHECK_MESSAGE(vSet.size() ==
                                (size_t)EPOCHSTATE_VNEXT_MAX_ANCHOR_AGE_EPOCHS ||
                            vSet.back() == 0,
                            "the run is shorter than the window and did not stop at epoch 0");
    }
}

// Anchor lifetime: acceptance is membership of the set the connecting height resolves,
// so an anchor lives until the head has moved past it by the window's width.
BOOST_AUTO_TEST_CASE(an_anchor_lasts_until_the_head_moves_a_window_past_it)
{
    BOOST_REQUIRE(fRegTest);
    const int nTip = BestIndex()->nHeight;
    const int nAsOf = GetEpochForHeight(nTip) - 1;
    BOOST_REQUIRE(nAsOf >= 4);
    ScopedEpochRecords records(0);
    CTxDB txdb;

    const int nFinEpoch = nAsOf - 1;
    const int nFinalized = GetEpochBoundaryHeight(nFinEpoch + 1, nTip);
    CBlockIndex* pAttested = AncestorAt(BestIndex(), nFinalized);
    BOOST_REQUIRE(pAttested);
    SetFinalizedAsOf(txdb, records, nAsOf, nFinalized, pAttested->GetBlockHash());

    // Walk the heights this chain can be asked about and record, for each, the head it
    // resolves and the oldest anchor it still accepts.
    int nFirstHead = -1;
    int nLastAccepting = -1;
    for (int h = GetEpochBoundaryHeight(2, nTip); h <= nTip; h += 50)
    {
        const std::vector<int> vSet = AcceptedAnchorEpochs(txdb, h);
        if (vSet.empty())
            continue;
        if (nFirstHead < 0)
            nFirstHead = vSet.front();
        if (std::find(vSet.begin(), vSet.end(), nFirstHead) != vSet.end())
            nLastAccepting = h;
        else
            BOOST_CHECK_MESSAGE(vSet.front() > nFirstHead + 
                                    EPOCHSTATE_VNEXT_MAX_ANCHOR_AGE_EPOCHS - 1,
                                "an anchor stopped being accepted while the head was still "
                                "within the window of it: head " << vSet.front()
                                << " anchor " << nFirstHead);
    }
    BOOST_REQUIRE(nFirstHead >= 0);
    BOOST_CHECK_MESSAGE(nLastAccepting >= GetEpochBoundaryHeight(2, nTip),
                        "the first head resolved was not accepted at any height");
}

// With nothing finalized, an epoch deep enough below the tip anchors on its own, so the
// IV5 pool is spendable before finality first advances.
BOOST_AUTO_TEST_CASE(with_nothing_finalized_a_deep_epoch_anchors_on_its_own)
{
    BOOST_REQUIRE(fRegTest);
    const int nTip = BestIndex()->nHeight;
    const int nAsOf = GetEpochForHeight(nTip) - 1;
    BOOST_REQUIRE(nAsOf >= 2);
    ScopedEpochRecords records(0);
    CTxDB txdb;

    // Nothing finalized in any record the chain has, written through.
    {
        std::map<int, CEpochState> states;
        std::map<int, CCurveTree> trees;
        for (std::map<int, CEpochState>::const_iterator it = records.states.begin();
             it != records.states.end() && it->first <= nAsOf; ++it)
        {
            CEpochState state = it->second;
            state.hashCurveRoot = 0;
            state.nFinalizedHeightAsOf = 0;
            state.fFinalized = false;
            states[it->first] = state;
            trees[it->first] = CCurveTree();
        }
        // Epoch 0 is the record floor on regtest: the truncated pre-DAG epoch the
        // migration base is built from, present on every node that holds epoch 1.
        BOOST_REQUIRE(states.count(0) != 0);
        BOOST_REQUIRE(states.count(1) != 0);
        BOOST_REQUIRE(g_dagManager.InstallEpochStateBatch(records.nFirst, states, trees));
        for (std::map<int, CEpochState>::const_iterator it = states.begin(); it != states.end(); ++it)
            BOOST_REQUIRE(g_dagManager.WriteEpochState(txdb, it->first));
    }

    CEpochState anchor;
    bool fLocal = true;
    BOOST_CHECK_MESSAGE(g_dagManager.GetFinalizedEpochStateAsOf(txdb, nTip, anchor, fLocal),
                        "with nothing finalized, no anchor at all: the pool is frozen until "
                        "the first finalization");
    BOOST_CHECK(!fLocal);
    BOOST_CHECK(anchor.nHeightEnd > 0);
    BOOST_CHECK(nTip - anchor.nHeightEnd >= EPOCHSTATE_VNEXT_MIN_UNFINALIZED_ANCHOR_DEPTH);
    BOOST_CHECK(!anchor.fFinalized);

    // A height whose as-of epoch has a record but nothing is deep enough: the floor,
    // which the validator's depth rule refuses as a spend anchor while shields, which
    // need only a context, keep working.
    const int nShallow = GetEpochBoundaryHeight(2, nTip) + 5;
    fLocal = true;
    CEpochState shallow;
    BOOST_CHECK(g_dagManager.GetFinalizedEpochStateAsOf(txdb, nShallow, shallow, fLocal));
    BOOST_CHECK(!fLocal);
    BOOST_CHECK_EQUAL(shallow.nEpoch, 0);
    BOOST_CHECK(!shallow.fFinalized);

    // The floor erased while the as-of record is present: a record this node lost, not
    // the chain's answer. Skipping it would pick epoch 1 here and epoch 0 on every node
    // that still holds it.
    txdb.EraseEpochState(0);
    txdb.EraseCurveTreeAtEpoch(0);
    fLocal = false;
    BOOST_CHECK(!g_dagManager.GetFinalizedEpochStateAsOf(txdb, nShallow, shallow, fLocal));
    BOOST_CHECK_MESSAGE(fLocal, "a lost floor record was skipped instead of reported");

    // A height whose as-of epoch has no record (epoch 0, erased): the as-of miss is the
    // chain's answer, as a context height past the connected chain is.
    fLocal = true;
    BOOST_CHECK(!g_dagManager.GetFinalizedEpochStateAsOf(
        txdb, GetEpochBoundaryHeight(1, nTip) + 5, shallow, fLocal));
    BOOST_CHECK(!fLocal);
}

// How long an anchor accepted now stays accepted, judged by the consensus check itself at
// every height, under three ways finality can move: every epoch finalized as soon as it can
// be, nothing finalized at all, and finality stalled far behind and then catching up at once.
// The head never passes two epochs behind the connecting height's epoch, so an anchor from
// epoch a lasts through the end of epoch a + 7 whatever finality does; a mix round's seat
// budgets against exactly that height. Epoch records are written in a transaction that is
// never committed, each with a root and tree size of its own so no pair repeats.
BOOST_AUTO_TEST_CASE(an_accepted_anchor_lasts_through_its_safe_height_however_finality_moves)
{
    BOOST_REQUIRE(fRegTest);
    const int nLastEpoch = 17;
    BOOST_REQUIRE_EQUAL(EPOCHSTATE_VNEXT_MAX_ANCHOR_AGE_EPOCHS, 6);
    BOOST_REQUIRE(EPOCHSTATE_VNEXT_MIN_UNFINALIZED_ANCHOR_DEPTH > FINALITY_EPOCH_INTERVAL_POST_DAG);

    PrivacyVNextDigest digest;
    digest.fill(0x5A);
    struct Anchor
    {
        PrivacyVNextDigest root;
        uint64_t nTreeSize;
    };
    std::vector<Anchor> vAnchors(nLastEpoch + 1);
    for (int e = 0; e <= nLastEpoch; ++e)
    {
        vAnchors[e].root.fill(0);
        vAnchors[e].root[0] = 0xA0;
        vAnchors[e].root[1] = (unsigned char)e;
        vAnchors[e].nTreeSize = 100 + e;
    }
    const int nStallUntil = 9;

    enum Regime { FINALIZED_EACH_EPOCH, NOTHING_FINALIZED, STALLED_THEN_CAUGHT_UP };
    const Regime vRegimes[3] = { FINALIZED_EACH_EPOCH, NOTHING_FINALIZED, STALLED_THEN_CAUGHT_UP };
    const char* vNames[3] = { "finalized each epoch", "nothing finalized",
                              "stalled then caught up" };
    for (int r = 0; r < 3; ++r)
    {
        CTxDB txdb("rw");
        BOOST_REQUIRE(txdb.TxnBegin());
        for (int e = 0; e <= nLastEpoch; ++e)
        {
            CEpochState state;
            state.nEpoch = e;
            state.nHeightStart = (int)GetEpochBoundaryHeight64(e);
            state.nHeightEnd = (int)GetEpochBoundaryHeight64(e + 1) - 1;
            state.hashBoundaryBlock = uint256(0xB0000000 + e);
            state.nSerVersion = EPOCHSTATE_SER_VERSION_V4;
            state.vchVNextRoot.assign(vAnchors[e].root.begin(), vAnchors[e].root.end());
            state.nVNextTreeSize = vAnchors[e].nTreeSize;
            state.vchVNextParameterDigest.assign(digest.begin(), digest.end());
            // Each record's finalized height is the one its as-of reader will see: the
            // epoch's own opening when every epoch completes a streak, a far-behind boundary
            // while stalled.
            int nFinalized = 0;
            if (vRegimes[r] == FINALIZED_EACH_EPOCH && e >= 1)
                nFinalized = state.nHeightStart;
            if (vRegimes[r] == STALLED_THEN_CAUGHT_UP && e >= 2)
                nFinalized = e < nStallUntil ? (int)GetEpochBoundaryHeight64(2) : state.nHeightStart;
            state.nFinalizedHeightAsOf = nFinalized;
            BOOST_REQUIRE(txdb.WriteEpochState(e, state));
        }

        const int nFirstHeight = (int)GetEpochBoundaryHeight64(2);
        const int nPastHeight = (int)GetEpochBoundaryHeight64(nLastEpoch + 1);
        // The head the resolver names never passes two epochs behind the height's epoch,
        // and never moves backward.
        int nPrevHead = -1;
        for (int h = nFirstHeight; h < nPastHeight; ++h)
        {
            CEpochState head;
            bool fLocal = false;
            if (!g_dagManager.GetFinalizedEpochStateAsOf(txdb, h, head, fLocal))
                continue;
            BOOST_CHECK_MESSAGE(head.nEpoch <= GetEpochForHeight(h) -
                                                   EPOCHSTATE_VNEXT_MIN_HEAD_LAG_EPOCHS,
                                vNames[r] << ": height " << h << " in epoch "
                                << GetEpochForHeight(h) << " resolves head " << head.nEpoch);
            BOOST_CHECK_MESSAGE(head.nEpoch >= nPrevHead,
                                vNames[r] << ": head moved back from " << nPrevHead << " to "
                                << head.nEpoch << " at height " << h);
            nPrevHead = head.nEpoch;
        }

        for (int a = 3; a <= 8; a += 5)
        {
            const int nSafeThrough = MixAnchorSafeThroughHeight(a);
            BOOST_REQUIRE_EQUAL(nSafeThrough, (int)GetEpochBoundaryHeight64(a + 8) - 1);
            BOOST_REQUIRE(nSafeThrough + 600 < nPastHeight);
            int nFirstAccepted = -1, nLastAccepted = -1;
            for (int h = nFirstHeight; h < nPastHeight; ++h)
            {
                int nEpoch = -1;
                bool fLocal = false;
                std::string strError;
                const bool fAccepted = CheckPrivacyVNextSpendAnchor(
                    txdb, h, vAnchors[a].root, vAnchors[a].nTreeSize, digest, nEpoch, fLocal,
                    strError);
                BOOST_CHECK_MESSAGE(!fLocal, vNames[r] << ": local failure at " << h << ": "
                                                       << strError);
                if (!fAccepted)
                {
                    BOOST_CHECK_MESSAGE(nFirstAccepted < 0 || h > nSafeThrough,
                                        vNames[r] << ": anchor " << a << " accepted from "
                                        << nFirstAccepted << " was refused at " << h
                                        << ", inside its safe height " << nSafeThrough
                                        << ": " << strError);
                    continue;
                }
                BOOST_CHECK_EQUAL(nEpoch, a);
                if (nFirstAccepted < 0)
                    nFirstAccepted = h;
                BOOST_CHECK_MESSAGE(nLastAccepted < 0 || nLastAccepted == h - 1,
                                    vNames[r] << ": anchor " << a << " refused at "
                                    << nLastAccepted + 1 << " then accepted again at " << h);
                nLastAccepted = h;
            }
            BOOST_REQUIRE_MESSAGE(nFirstAccepted >= 0,
                                  vNames[r] << ": anchor " << a << " is never accepted");
            // What a seat reads is the same check, one block past its tip.
            CMixRoundAnnouncement announce;
            announce.finalizedRoot = vAnchors[a].root;
            announce.nFinalizedTreeSize = vAnchors[a].nTreeSize;
            announce.parameterDigest = digest;
            CMixAnchorView view;
            BOOST_REQUIRE(ReadMixAnchorView(txdb, nFirstAccepted - 1, 0, announce, view));
            BOOST_CHECK_EQUAL(view.nAnchorEpoch, a);
            BOOST_CHECK_EQUAL(view.nSafeThroughHeight, nSafeThrough);
            BOOST_REQUIRE(ReadMixAnchorView(txdb, nFirstAccepted - 2, 0, announce, view));
            BOOST_CHECK_EQUAL(view.nAnchorEpoch, -1);
            BOOST_CHECK_MESSAGE(nLastAccepted >= nSafeThrough,
                                vNames[r] << ": anchor " << a << " last accepted at "
                                << nLastAccepted << ", before its safe height " << nSafeThrough);
            // Finalized as soon as it can be, the head is exactly two behind, so the bound is
            // tight. With nothing finalized the depth rule holds the anchor one epoch longer.
            if (vRegimes[r] == FINALIZED_EACH_EPOCH)
                BOOST_CHECK_EQUAL(nLastAccepted, nSafeThrough);
            if (vRegimes[r] == NOTHING_FINALIZED)
                BOOST_CHECK_EQUAL(nLastAccepted,
                                  (int)GetEpochBoundaryHeight64(a + 9) - 1 - 1);
        }
        txdb.TxnAbort();
    }
}

BOOST_AUTO_TEST_CASE(epoch_records_leave_as_the_chain_built_them)
{
    BOOST_REQUIRE(fRegTest);
    CheckEpochRecordsAreTheChains("on exit");
}

BOOST_AUTO_TEST_SUITE_END()
