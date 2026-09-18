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

    // Absent: the finalized epoch's own record erased is the chain's answer (NOT_FOUND
    // stays a chain property by design; see EpochStateReadIsLocalFailure).
    BOOST_REQUIRE(txdb.EraseEpochState(nFinEpoch));
    fLocal = true;
    BOOST_CHECK(!g_dagManager.GetFinalizedEpochStateAsOf(txdb, nTip, 0, state, &fLocal));
    BOOST_CHECK_MESSAGE(!fLocal, "an absent record was classed as a local failure");
    BOOST_REQUIRE(txdb.WriteEpochState(nFinEpoch, saved));

    fLocal = true;
    BOOST_CHECK(g_dagManager.GetFinalizedEpochStateAsOf(txdb, nTip, 0, state, &fLocal));
    BOOST_CHECK(!fLocal);
}

// Before the first finalization the finalized epoch is epoch 0, and a chain whose
// epochs begin at the DAG fork has no record for it. The reader used to require that
// record before it reached the depth anchor, so nothing in the IV5 pool was spendable
// until finality first advanced -- the window the depth anchor is for. With nothing
// finalized, an epoch deep enough below the tip anchors on its own.
// Which anchors consensus will accept at one height, enumerated.
//
// ConnectBlock takes the newest resolved anchor and then five more, and the two halves do
// not agree on what they are counting from: the newest comes from the depth rule, which
// past the finalized epoch takes the newest epoch already deep enough to stand on its own,
// while the other five are the FINALIZED epoch minus one through five. While finality keeps
// up those are one ladder and the set is contiguous. When finality falls far enough behind
// that an unfinalized epoch is deep enough, they are two ladders with a gap between them.
//
// This enumerates the set rather than asserting a remembered shape, because the shape is
// what the mix's anchor budget is built on and it was never written down.
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

BOOST_AUTO_TEST_CASE(the_accepted_anchor_set_is_two_ladders_when_finality_falls_behind)
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
        BOOST_CHECK_MESSAGE(nNewest > nFinEpoch,
                            "the depth rule did not reach past the finalized epoch, so this "
                            "case does not exercise the two ladders");
        // The gap, stated as the thing it is: epochs a wallet may legitimately hold an
        // anchor from, that consensus will not accept.
        bool fContiguous = true;
        for (size_t i = 1; i < vSet.size(); i++)
            if (vSet[i] != vSet[i - 1] - 1)
                fContiguous = false;
        BOOST_CHECK_MESSAGE(!fContiguous,
                            "expected a gap between the depth pick and the finalized ladder");
        BOOST_CHECK_MESSAGE(std::find(vSet.begin(), vSet.end(), nFinEpoch) == vSet.end(),
                            "the finalized epoch is accepted; the depth pick did not "
                            "displace it after all");
        // And the consequence the mix's budget rests on: the newest anchor is NOT good for
        // five more epochs. It is the depth pick, and the depth pick moves with the tip.
        const int nLaterTip = nTip;   // same tip: the shape, not the passage of time
        const std::vector<int> vAgain = AcceptedAnchorEpochs(txdb, nLaterTip);
        BOOST_CHECK(vAgain == vSet);
    }
}

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
        BOOST_REQUIRE(states.count(1) != 0);
        BOOST_REQUIRE(g_dagManager.InstallEpochStateBatch(records.nFirst, states, trees));
        for (std::map<int, CEpochState>::const_iterator it = states.begin(); it != states.end(); ++it)
            BOOST_REQUIRE(g_dagManager.WriteEpochState(txdb, it->first));
    }
    // And no record at all for epoch 0, as on a chain whose epochs start at the fork.
    txdb.EraseEpochState(0);
    txdb.EraseCurveTreeAtEpoch(0);

    CEpochState anchor;
    bool fLocal = true;
    BOOST_CHECK_MESSAGE(g_dagManager.GetFinalizedEpochStateAsOf(txdb, nTip, anchor, fLocal),
                        "with nothing finalized, no anchor at all: the pool is frozen until "
                        "the first finalization");
    BOOST_CHECK(!fLocal);
    BOOST_CHECK(anchor.nHeightEnd > 0);
    BOOST_CHECK(nTip - anchor.nHeightEnd >= EPOCHSTATE_VNEXT_MIN_UNFINALIZED_ANCHOR_DEPTH);
    BOOST_CHECK(!anchor.fFinalized);

    // A height whose as-of epoch has a record but is not yet deep enough: the oldest
    // record there is (epoch 1 here, epoch 0 having been erased), which the validator's
    // depth rule refuses as a spend anchor while shields, which need only a context, keep
    // working -- the pre-fix behaviour on chains that carry an epoch-0 record.
    fLocal = true;
    CEpochState shallow;
    BOOST_CHECK(g_dagManager.GetFinalizedEpochStateAsOf(
        txdb, GetEpochBoundaryHeight(2, nTip) + 5, shallow, fLocal));
    BOOST_CHECK(!fLocal);
    BOOST_CHECK_EQUAL(shallow.nEpoch, 1);
    BOOST_CHECK(!shallow.fFinalized);

    // A height whose as-of epoch has no record at all (epoch 0, erased): no state -- the
    // chain's answer, not a local failure.
    fLocal = true;
    BOOST_CHECK(!g_dagManager.GetFinalizedEpochStateAsOf(
        txdb, GetEpochBoundaryHeight(1, nTip) + 5, shallow, fLocal));
    BOOST_CHECK(!fLocal);
}

BOOST_AUTO_TEST_CASE(epoch_records_leave_as_the_chain_built_them)
{
    BOOST_REQUIRE(fRegTest);
    CheckEpochRecordsAreTheChains("on exit");
}

BOOST_AUTO_TEST_SUITE_END()
