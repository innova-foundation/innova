// The reorg finality guard admits a candidate iff the attested block is on its
// selected-parent chain, never persists its verdict, and reads the IV5 finalized anchor.
// Linked last in TEST_OBJS.

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include "../dag.h"
#include "../finality.h"
#include "../main.h"
#include "../privacy_vnext_ffi.h"
#include "../txdb.h"
#include "../uint256.h"
#include "synthetic_chain.h"

extern bool fRegTest;
extern bool fTestNet;

BOOST_AUTO_TEST_SUITE(reorg_finality_ancestry_tests)

namespace {

struct RegTestNetwork
{
    bool oldRegTest;
    bool oldTestNet;
    RegTestNetwork()
    {
        oldRegTest = fRegTest;
        oldTestNet = fTestNet;
        fRegTest = true;
        fTestNet = false;
    }
    ~RegTestNetwork()
    {
        fRegTest = oldRegTest;
        fTestNet = oldTestNet;
    }
};

int EpochStart(int nEpoch) { return GetEpochBoundaryHeight(nEpoch, 0); }
int EpochEnd(int nEpoch)   { return GetEpochBoundaryHeight(nEpoch + 1, 0) - 1; }

// Regtest layout: epoch k >= 1 opens at FORK_HEIGHT_DAG + (k-1)*300. The tip sits in
// epoch 5, so the guard reads epoch 4 for refusal and epoch 2 for the grade.
const int TIP = 1215;
const int AS_OF_EPOCH = 4;
const int LATCH_EPOCH = 2;
const int FINAL_CUR = 911;     // epoch 4's boundary, the block its votes name
const int FINAL_LATCH = 311;   // epoch 2's boundary

CBlockIndex* At(CBlockIndex* pTip, int nHeight)
{
    return pTip ? pTip->GetAncestor(nHeight) : NULL;
}

// One main chain and two branches off it, all indexed, none on disk.
//   M     0 .. 1300                              carries M[311], M[911]
//   S     forks at 900, tip 1215                 carries M[311], not M[911]
//   S2    forks at 300, tip 1215                 carries neither
struct Chains
{
    CSyntheticChain chain;
    CBlockIndex* pMain;
    CBlockIndex* pSide;
    CBlockIndex* pDeep;

    Chains() : chain(0xA5C10000U)
    {
        pMain = chain.Linear(1300);
        BOOST_REQUIRE(pMain != NULL);
        pSide = chain.Extend(At(pMain, FINAL_CUR - 11), TIP - (FINAL_CUR - 11));
        pDeep = chain.Extend(At(pMain, FINAL_LATCH - 11), TIP - (FINAL_LATCH - 11));
        BOOST_REQUIRE(pSide && pDeep);
        BOOST_REQUIRE_EQUAL(pSide->nHeight, TIP);
        BOOST_REQUIRE_EQUAL(pDeep->nHeight, TIP);
    }

    uint256 MainHash(int nHeight) const { return At(pMain, nHeight)->GetBlockHash(); }
};

// The pre-ancestry guard's input: the fork point of two tips along pprev.
int ForkHeight(const CBlockIndex* pa, const CBlockIndex* pb)
{
    while (pa && pb && pa != pb)
    {
        if (pa->nHeight > pb->nHeight)
            pa = pa->pprev;
        else if (pb->nHeight > pa->nHeight)
            pb = pb->pprev;
        else
        {
            pa = pa->pprev;
            pb = pb->pprev;
        }
    }
    return (pa && pa == pb) ? pa->nHeight : -1;
}

// What the height rule answered: refuse iff the fork point is below the finalized height.
bool HeightRuleRefuses(const CBlockIndex* pCandidate, const CBlockIndex* pTipInForce, int nFinalized)
{
    return nFinalized > 0 && ForkHeight(pCandidate, pTipInForce) < nFinalized;
}

// Epochs 1..4: epoch 2 names the lagged anchor, epoch 3 carries it, epoch 4 names the
// current one. Only the fields the guard reads are set; an empty curve tree pairs with a
// zero curve root, which is what ValidateEpochStateBatch requires.
void InstallAnchors(CDAGManager& dag, int nCur, const uint256& hashCur,
                    int nLatch, const uint256& hashLatch)
{
    std::map<int, CEpochState> states;
    std::map<int, CCurveTree> trees;
    for (int e = 1; e <= AS_OF_EPOCH; e++)
    {
        CEpochState state;
        state.nEpoch = e;
        state.nHeightStart = EpochStart(e);
        state.nHeightEnd = EpochEnd(e);
        state.hashCurveRoot = 0;
        if (e == AS_OF_EPOCH)
        {
            state.nFinalizedHeightAsOf = nCur;
            state.hashVNextFinalizedAnchor = hashCur;
        }
        else if (e >= LATCH_EPOCH)
        {
            state.nFinalizedHeightAsOf = nLatch;
            state.hashVNextFinalizedAnchor = hashLatch;
        }
        states[e] = state;
        trees[e] = CCurveTree();
    }
    BOOST_REQUIRE(dag.InstallEpochStateBatch(1, states, trees));
}

ReorgFinalityVerdict Verdict(const CDAGManager& dag, const CBlockIndex* pCandidate,
                             int* pnCur = NULL, int* pnLatch = NULL)
{
    int nCur = 0, nLatch = 0, nEpoch = 0;
    const ReorgFinalityVerdict v =
        CheckReorgAgainstFinality(dag, TIP, pCandidate, nCur, nLatch, nEpoch);
    BOOST_CHECK_EQUAL(nEpoch, AS_OF_EPOCH);
    if (pnCur) *pnCur = nCur;
    if (pnLatch) *pnLatch = nLatch;
    return v;
}

} // namespace

BOOST_AUTO_TEST_CASE(fixture_sits_where_the_layout_says)
{
    RegTestNetwork net;
    BOOST_CHECK_EQUAL(FORK_HEIGHT_FINALITY, 10);
    BOOST_CHECK_EQUAL(FORK_HEIGHT_DAG, 11);
    BOOST_CHECK_EQUAL(FORK_HEIGHT_EPOCH_STATE_V3, 311);
    BOOST_REQUIRE_EQUAL(GetEpochForHeight(TIP), AS_OF_EPOCH + 1);
    BOOST_REQUIRE_EQUAL(AS_OF_EPOCH - (REORG_LATCH_ANCHOR_LAG_EPOCHS - 1), LATCH_EPOCH);
    BOOST_REQUIRE_EQUAL(EpochStart(AS_OF_EPOCH), FINAL_CUR);
    BOOST_REQUIRE_EQUAL(EpochStart(LATCH_EPOCH), FINAL_LATCH);
    BOOST_REQUIRE(IsEpochBoundaryHeight(FINAL_CUR));
    BOOST_REQUIRE(IsEpochBoundaryHeight(FINAL_LATCH));
    BOOST_REQUIRE(TIP >= FORK_HEIGHT_EPOCH_STATE_V3);
}

// S holds finalized height 911 for M[911], which S does not carry. The chain carrying
// M[911] forks from S at 900 and must be admitted.
BOOST_AUTO_TEST_CASE(the_attested_block_decides_where_the_height_could_not)
{
    RegTestNetwork net;
    Chains c;
    CDAGManager dag;
    InstallAnchors(dag, FINAL_CUR, c.MainHash(FINAL_CUR), FINAL_LATCH, c.MainHash(FINAL_LATCH));

    // Same height, different block: the number alone cannot tell M[911] from S[911].
    const CBlockIndex* pAttested = At(c.pMain, FINAL_CUR);
    const CBlockIndex* pImpostor = At(c.pSide, FINAL_CUR);
    BOOST_REQUIRE_EQUAL(pAttested->nHeight, pImpostor->nHeight);
    BOOST_REQUIRE(pAttested->GetBlockHash() != pImpostor->GetBlockHash());

    int nCur = 0, nLatch = 0;
    const ReorgFinalityVerdict onMain = Verdict(dag, c.pMain, &nCur, &nLatch);
    BOOST_CHECK_EQUAL(nCur, FINAL_CUR);
    BOOST_CHECK_EQUAL(nLatch, FINAL_LATCH);
    BOOST_REQUIRE_MESSAGE(HeightRuleRefuses(c.pMain, c.pSide, nCur),
                          "the fixture does not reach the case the height rule got wrong");
    BOOST_CHECK_MESSAGE(onMain == REORG_FINALITY_ALLOW,
                        "the chain carrying the attested block was refused (verdict "
                        << (int)onMain << ")");

    // The branch that lacks it is still refused: it carries the lagged anchor's block
    // but not the current one, so the refusal is retryable.
    BOOST_CHECK_EQUAL((int)Verdict(dag, c.pSide), (int)REORG_FINALITY_REJECT_TRANSIENT);
    BOOST_CHECK(At(c.pSide, FINAL_LATCH) == At(c.pMain, FINAL_LATCH));

    // A branch carrying neither anchor's block is graded permanent.
    BOOST_CHECK_EQUAL((int)Verdict(dag, c.pDeep), (int)REORG_FINALITY_REJECT_PERMANENT);

    // A candidate too short to reach the attested height cannot carry the block.
    BOOST_CHECK_EQUAL((int)Verdict(dag, At(c.pMain, FINAL_CUR - 1)),
                      (int)REORG_FINALITY_REJECT_TRANSIENT);
    // A candidate that is the attested block, or its descendant by one, carries it.
    BOOST_CHECK_EQUAL((int)Verdict(dag, At(c.pMain, FINAL_CUR)), (int)REORG_FINALITY_ALLOW);
    BOOST_CHECK_EQUAL((int)Verdict(dag, At(c.pMain, FINAL_CUR + 1)), (int)REORG_FINALITY_ALLOW);
}

// Sibling records are refused at the source by both builders: finality_claim_tests,
// a_streak_completing_on_a_sibling_of_the_boundary_block_fails_the_build and
// the_v2_builder_refuses_a_streak_on_a_sibling_winner.

// Selected-parent ancestry, not DAG reachability: a merge edge to the attested block does
// not keep a candidate connected.
BOOST_AUTO_TEST_CASE(reachability_through_a_merge_parent_is_not_ancestry)
{
    RegTestNetwork net;
    Chains c;
    CDAGManager dag;
    InstallAnchors(dag, FINAL_CUR, c.MainHash(FINAL_CUR), FINAL_LATCH, c.MainHash(FINAL_LATCH));

    CBlockIndex* pAttested = At(c.pMain, FINAL_CUR);
    CBlockIndex* pMerge = c.chain.Add(c.pSide, TIP + 1);
    BOOST_REQUIRE(pMerge != NULL);

    std::vector<uint256> vAttestedParents(1, At(c.pMain, FINAL_CUR - 1)->GetBlockHash());
    std::vector<uint256> vSideParents(1, c.pSide->pprev->GetBlockHash());
    std::vector<uint256> vMergeParents;
    vMergeParents.push_back(c.pSide->GetBlockHash());
    vMergeParents.push_back(pAttested->GetBlockHash());
    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(pAttested, vAttestedParents));
    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(c.pSide, vSideParents));
    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(pMerge, vMergeParents));
    BOOST_REQUIRE(g_dagManager.HasDAGData(pMerge->GetBlockHash()));

    // Reachable through the merge edge, not an ancestor: refused.
    BOOST_CHECK(pMerge->GetAncestor(FINAL_CUR) != pAttested);
    BOOST_CHECK_EQUAL((int)Verdict(dag, pMerge), (int)REORG_FINALITY_REJECT_TRANSIENT);

    g_dagManager.RemoveBlockDAGData(pMerge->GetBlockHash());
    g_dagManager.RemoveBlockDAGData(c.pSide->GetBlockHash());
    g_dagManager.RemoveBlockDAGData(pAttested->GetBlockHash());
}

// No grade, including fail-closed, sets pfPermanentInvalid (which AddToBlockIndex
// would serialize as BLOCK_FAILED_VALID).
BOOST_AUTO_TEST_CASE(no_verdict_sets_the_permanent_invalid_flag)
{
    RegTestNetwork net;
    Chains c;
    CDAGManager dag;
    InstallAnchors(dag, FINAL_CUR, c.MainHash(FINAL_CUR), FINAL_LATCH, c.MainHash(FINAL_LATCH));

    int nCur = 0, nLatch = 0, nEpoch = 0;
    bool fPermanent = false;
    BOOST_CHECK_EQUAL((int)ApplyReorgFinalityGuard(dag, TIP, c.pDeep, &fPermanent,
                                                   nCur, nLatch, nEpoch),
                      (int)REORG_FINALITY_REJECT_PERMANENT);
    BOOST_CHECK_MESSAGE(!fPermanent, "a permanent grade was persisted");

    fPermanent = false;
    BOOST_CHECK_EQUAL((int)ApplyReorgFinalityGuard(dag, TIP, c.pSide, &fPermanent,
                                                   nCur, nLatch, nEpoch),
                      (int)REORG_FINALITY_REJECT_TRANSIENT);
    BOOST_CHECK(!fPermanent);

    fPermanent = false;
    BOOST_CHECK_EQUAL((int)ApplyReorgFinalityGuard(dag, TIP, c.pMain, &fPermanent,
                                                   nCur, nLatch, nEpoch),
                      (int)REORG_FINALITY_ALLOW);
    BOOST_CHECK(!fPermanent);

    CDAGManager empty;
    fPermanent = false;
    BOOST_CHECK_EQUAL((int)ApplyReorgFinalityGuard(empty, TIP, c.pDeep, &fPermanent,
                                                   nCur, nLatch, nEpoch),
                      (int)REORG_FINALITY_STATE_MISSING);
    BOOST_CHECK(!fPermanent);

    // A null flag pointer is the Reorganize-without-a-caller case; it must not crash.
    BOOST_CHECK_EQUAL((int)ApplyReorgFinalityGuard(dag, TIP, c.pDeep, NULL,
                                                   nCur, nLatch, nEpoch),
                      (int)REORG_FINALITY_REJECT_PERMANENT);
}

// A refusal follows the records, not the candidate: the same index is admitted once the
// records name the blocks its own chain carries.
BOOST_AUTO_TEST_CASE(a_refused_candidate_is_judged_again_under_new_records)
{
    RegTestNetwork net;
    Chains c;
    CDAGManager dag;
    InstallAnchors(dag, FINAL_CUR, c.MainHash(FINAL_CUR), FINAL_LATCH, c.MainHash(FINAL_LATCH));
    BOOST_REQUIRE_EQUAL((int)Verdict(dag, c.pDeep), (int)REORG_FINALITY_REJECT_PERMANENT);
    BOOST_REQUIRE_EQUAL((int)Verdict(dag, c.pMain), (int)REORG_FINALITY_ALLOW);

    InstallAnchors(dag, FINAL_CUR, At(c.pDeep, FINAL_CUR)->GetBlockHash(),
                   FINAL_LATCH, At(c.pDeep, FINAL_LATCH)->GetBlockHash());
    BOOST_CHECK_EQUAL((int)Verdict(dag, c.pDeep), (int)REORG_FINALITY_ALLOW);
    BOOST_CHECK_EQUAL((int)Verdict(dag, c.pMain), (int)REORG_FINALITY_REJECT_PERMANENT);
    BOOST_CHECK(!c.pDeep->IsInvalid());
    BOOST_CHECK(!c.pMain->IsInvalid());
}

// Fail closed: a record that names a height without a block was written by a build that
// compared heights, and the guard cannot judge ancestry from it. The anchors are still
// reported for the caller's message. The height rule admitted M here.
BOOST_AUTO_TEST_CASE(a_record_naming_a_height_without_a_block_fails_closed)
{
    RegTestNetwork net;
    Chains c;
    CDAGManager dag;
    InstallAnchors(dag, FINAL_CUR, 0, FINAL_LATCH, c.MainHash(FINAL_LATCH));

    int nCur = 0, nLatch = 0;
    BOOST_REQUIRE(!HeightRuleRefuses(c.pMain, c.pMain, FINAL_CUR));
    BOOST_CHECK_EQUAL((int)Verdict(dag, c.pMain, &nCur, &nLatch),
                      (int)REORG_FINALITY_STATE_MISSING);
    BOOST_CHECK_EQUAL(nCur, FINAL_CUR);
    BOOST_CHECK_EQUAL(nLatch, FINAL_LATCH);
    BOOST_CHECK_EQUAL((int)Verdict(dag, c.pSide), (int)REORG_FINALITY_STATE_MISSING);
}

// Fail closed: a block this node does not hold, or holds at another height, is not a
// block it can test ancestry against.
BOOST_AUTO_TEST_CASE(an_attested_block_this_node_cannot_resolve_fails_closed)
{
    RegTestNetwork net;
    Chains c;

    CDAGManager unknown;
    InstallAnchors(unknown, FINAL_CUR, uint256(0xA5C1DEAD), FINAL_LATCH, c.MainHash(FINAL_LATCH));
    BOOST_REQUIRE(mapBlockIndex.count(uint256(0xA5C1DEAD)) == 0);
    BOOST_CHECK_EQUAL((int)Verdict(unknown, c.pMain), (int)REORG_FINALITY_STATE_MISSING);

    CDAGManager misplaced;
    InstallAnchors(misplaced, FINAL_CUR, c.MainHash(FINAL_CUR - 1), FINAL_LATCH,
                   c.MainHash(FINAL_LATCH));
    BOOST_CHECK_EQUAL((int)Verdict(misplaced, c.pMain), (int)REORG_FINALITY_STATE_MISSING);
    BOOST_CHECK_EQUAL((int)Verdict(misplaced, c.pSide), (int)REORG_FINALITY_STATE_MISSING);
}

// Fail closed on a missing candidate, but only once there is something to protect: with
// nothing finalized there is no block to test against and every switch is allowed.
BOOST_AUTO_TEST_CASE(a_missing_candidate_fails_closed_only_when_something_is_finalized)
{
    RegTestNetwork net;
    Chains c;

    CDAGManager dag;
    InstallAnchors(dag, FINAL_CUR, c.MainHash(FINAL_CUR), FINAL_LATCH, c.MainHash(FINAL_LATCH));
    BOOST_CHECK_EQUAL((int)Verdict(dag, NULL), (int)REORG_FINALITY_STATE_MISSING);

    CDAGManager nothing;
    InstallAnchors(nothing, 0, 0, 0, 0);
    BOOST_CHECK_EQUAL((int)Verdict(nothing, NULL), (int)REORG_FINALITY_ALLOW);
    BOOST_CHECK_EQUAL((int)Verdict(nothing, c.pDeep), (int)REORG_FINALITY_ALLOW);
}

// The lagged anchor only grades. One that cannot be resolved softens the grade to
// retryable; it never fails the verdict closed, and never admits.
BOOST_AUTO_TEST_CASE(an_unresolvable_lagged_anchor_only_softens_the_grade)
{
    RegTestNetwork net;
    Chains c;

    CDAGManager noHash;
    InstallAnchors(noHash, FINAL_CUR, c.MainHash(FINAL_CUR), FINAL_LATCH, 0);
    BOOST_CHECK_EQUAL((int)Verdict(noHash, c.pDeep), (int)REORG_FINALITY_REJECT_TRANSIENT);
    BOOST_CHECK_EQUAL((int)Verdict(noHash, c.pMain), (int)REORG_FINALITY_ALLOW);

    CDAGManager wrongHeight;
    InstallAnchors(wrongHeight, FINAL_CUR, c.MainHash(FINAL_CUR), FINAL_LATCH,
                   c.MainHash(FINAL_LATCH + 1));
    BOOST_CHECK_EQUAL((int)Verdict(wrongHeight, c.pDeep), (int)REORG_FINALITY_REJECT_TRANSIENT);
}

// ---------------------------------------------------------------------------
// The guard reads hashVNextFinalizedAnchor; pre-Boundary-B records re-derive it at load.
// ---------------------------------------------------------------------------

namespace {

// A well-formed IV5 record at the bootstrap seed with one (boundary) block and nothing
// active, naming pFinalized as the finalized block.
CEpochState IV5Record(int nEpoch, const CBlockIndex* pBoundary, const CBlockIndex* pFinalized,
                      const PrivacyVNextEpochSeed& seed)
{
    CEpochState state;
    state.nEpoch = nEpoch;
    state.nHeightStart = EpochStart(nEpoch);
    state.nHeightEnd = EpochEnd(nEpoch);
    state.hashBoundaryBlock = pBoundary->GetBlockHash();
    state.vBlockHashes.push_back(state.hashBoundaryBlock);
    state.nBlockCount = 1;
    state.nTxCount = -1;
    state.nSerVersion = EPOCHSTATE_SER_VERSION;
    state.vchVNextTreeState = seed.vchTreeState;
    state.vchVNextRoot = seed.vchRoot;
    state.nVNextTreeSize = seed.nTreeSize;
    state.vchVNextNullifierState = seed.vchNullifierState;
    state.hashVNextNullifierRoot = uint256(seed.vchNullifierRoot);
    state.nVNextNullifierCount = seed.nNullifierCount;
    state.vchVNextParameterDigest = seed.vchParameterDigest;
    state.vVNextActiveBlockTxCounts.push_back(0);
    state.nFinalizedHeightAsOf = pFinalized->nHeight;
    state.nVNextFinalizedHeight = pFinalized->nHeight;
    state.hashVNextFinalizedAnchor = pFinalized->GetBlockHash();
    CHashWriter activeSetHasher(SER_GETHASH, 0);
    activeSetHasher << std::string("Innova/IV5/ActiveDAGTransactionSet/v1");
    activeSetHasher << state.hashBoundaryBlock << state.vBlockHashes;
    activeSetHasher << state.vVNextActiveBlockTxCounts;
    activeSetHasher << state.vVNextActiveTxIds;
    state.hashVNextActiveTxSet = activeSetHasher.GetHash();
    return state;
}

class SchemaTestDB : public CTxDB
{
public:
    SchemaTestDB() : CTxDB("r+") {}
    bool EraseEpochStateSchema() { return Erase(std::string("epochstateschema")); }
};

// The loader reads every record in the shared database; other suites' records are hidden
// for the case and restored when it ends.
struct HiddenEpochRecords
{
    CTxDB& txdb;
    std::map<int, CEpochState> states;
    std::map<int, CCurveTree> trees;

    explicit HiddenEpochRecords(CTxDB& db) : txdb(db)
    {
        BOOST_REQUIRE(txdb.IterateEpochStates(states));
        BOOST_REQUIRE(txdb.IterateCurveTreeEpochs(trees));
        BOOST_REQUIRE(txdb.TxnBegin());
        for (std::map<int, CEpochState>::const_iterator it = states.begin(); it != states.end(); ++it)
            BOOST_REQUIRE(txdb.EraseEpochState(it->first));
        for (std::map<int, CCurveTree>::const_iterator it = trees.begin(); it != trees.end(); ++it)
            BOOST_REQUIRE(txdb.EraseCurveTreeAtEpoch(it->first));
        BOOST_REQUIRE(txdb.TxnCommit());
    }

    ~HiddenEpochRecords()
    {
        std::map<int, CEpochState> left;
        std::map<int, CCurveTree> leftTrees;
        txdb.IterateEpochStates(left);
        txdb.IterateCurveTreeEpochs(leftTrees);
        bool fOK = txdb.TxnBegin();
        for (std::map<int, CEpochState>::const_iterator it = left.begin(); it != left.end(); ++it)
            fOK = txdb.EraseEpochState(it->first) && fOK;
        for (std::map<int, CCurveTree>::const_iterator it = leftTrees.begin(); it != leftTrees.end(); ++it)
            fOK = txdb.EraseCurveTreeAtEpoch(it->first) && fOK;
        for (std::map<int, CEpochState>::const_iterator it = states.begin(); it != states.end(); ++it)
            fOK = txdb.WriteEpochState(it->first, it->second) && fOK;
        for (std::map<int, CCurveTree>::const_iterator it = trees.begin(); it != trees.end(); ++it)
            fOK = txdb.WriteCurveTreeAtEpoch(it->first, it->second) && fOK;
        fOK = txdb.TxnCommit() && fOK;
        BOOST_CHECK_MESSAGE(fOK, "could not put the hidden epoch records back");
    }
};

} // namespace

// No record version was added for the anchor: the guard reads the IV5 finalized anchor
// every V4 record already carries, through one accessor that answers nothing when
// nothing is finalized, since an IV5 record then holds the genesis hash in the field.
BOOST_AUTO_TEST_CASE(the_guard_reads_the_iv5_finalized_anchor)
{
    RegTestNetwork net;
    BOOST_CHECK_EQUAL((int)EPOCHSTATE_SER_VERSION, (int)EPOCHSTATE_SER_VERSION_V6);

    CSyntheticChain chain(0xA5C20000U);
    CBlockIndex* pEnd = chain.Linear(EpochEnd(AS_OF_EPOCH));
    BOOST_REQUIRE(pEnd != NULL);
    const uint256 hashAttested = At(pEnd, FINAL_CUR)->GetBlockHash();
    const uint256 hashGenesis = At(pEnd, 0)->GetBlockHash();

    CEpochState named;
    named.nFinalizedHeightAsOf = FINAL_CUR;
    named.hashVNextFinalizedAnchor = hashAttested;
    BOOST_CHECK(named.FinalizedAnchorHash() == hashAttested);
    CEpochState nothing;
    nothing.hashVNextFinalizedAnchor = hashGenesis;
    BOOST_CHECK(nothing.FinalizedAnchorHash() == 0);

    // Both lookup paths answer through it. The epochs below AS_OF_EPOCH have nothing
    // finalized and hold the genesis hash, as a built IV5 record would.
    CDAGManager dag;
    std::map<int, CEpochState> states;
    std::map<int, CCurveTree> trees;
    for (int e = 1; e <= AS_OF_EPOCH; e++)
    {
        CEpochState state;
        state.nEpoch = e;
        state.nHeightStart = EpochStart(e);
        state.nHeightEnd = EpochEnd(e);
        state.hashCurveRoot = 0;
        state.nFinalizedHeightAsOf = (e == AS_OF_EPOCH) ? FINAL_CUR : 0;
        state.hashVNextFinalizedAnchor = (e == AS_OF_EPOCH) ? hashAttested : hashGenesis;
        states[e] = state;
        trees[e] = CCurveTree();
    }
    BOOST_REQUIRE(dag.InstallEpochStateBatch(1, states, trees));

    int nHeight = -1;
    uint256 hash = 1;
    BOOST_REQUIRE(dag.TryGetDeterministicFinalizedAnchor(AS_OF_EPOCH, nHeight, hash));
    BOOST_CHECK_EQUAL(nHeight, FINAL_CUR);
    BOOST_CHECK(hash == hashAttested);
    BOOST_REQUIRE(dag.TryGetDeterministicFinalizedAnchor(AS_OF_EPOCH - 1, nHeight, hash));
    BOOST_CHECK_EQUAL(nHeight, 0);
    BOOST_CHECK(hash == 0);
    dag.GetDeterministicFinalizedAnchor(AS_OF_EPOCH, nHeight, hash);
    BOOST_CHECK_EQUAL(nHeight, FINAL_CUR);
    BOOST_CHECK(hash == hashAttested);
    dag.GetDeterministicFinalizedAnchor(AS_OF_EPOCH - 1, nHeight, hash);
    BOOST_CHECK_EQUAL(nHeight, 0);
    BOOST_CHECK(hash == 0);

    // The verdict follows: the chain carrying the block is admitted and one forking
    // below it is refused, retryably, since the lagged record names no block.
    CBlockIndex* pTip = chain.Extend(pEnd, TIP - pEnd->nHeight);
    CBlockIndex* pOther = chain.Extend(At(pEnd, FINAL_CUR - 1), TIP - (FINAL_CUR - 1));
    BOOST_REQUIRE(pTip && pOther);
    BOOST_CHECK_EQUAL((int)Verdict(dag, pTip), (int)REORG_FINALITY_ALLOW);
    BOOST_CHECK_EQUAL((int)Verdict(dag, pOther), (int)REORG_FINALITY_REJECT_TRANSIENT);
}

// The field the guard reads is load-validated. An IV5 record whose anchor is not the
// block at its finalized height fails to load; the same record with that block loads
// and answers the anchor, so the refusal is this check and not another.
BOOST_AUTO_TEST_CASE(an_iv5_record_whose_anchor_is_not_at_its_finalized_height_fails_to_load)
{
    RegTestNetwork net;
    PrivacyVNextEpochSeed seed;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(LoadPrivacyVNextEpochSeed(seed, strError), strError);

    SchemaTestDB txdb;
    int nOldSchema = 0;
    const bool fHadOldSchema = txdb.ReadEpochStateSchema(nOldSchema);

    // Above every record other suites left in the shared database, which the loader
    // does not see for this case.
    std::map<int, CEpochState> existing;
    BOOST_REQUIRE(txdb.IterateEpochStates(existing));
    int E = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3) + 1;
    if (!existing.empty())
        E = std::max(E, existing.rbegin()->first + 1);
    HiddenEpochRecords hidden(txdb);
    const int hStart = EpochStart(E);
    const int hEnd = EpochEnd(E);
    const int nOldBoundaryB = nRegtestBoundaryBHeight;
    nRegtestBoundaryBHeight = hStart;
    BOOST_REQUIRE(IsBoundaryBActiveAtHeight(hEnd));

    CSyntheticChain chain(0xA5C30000U);
    CBlockIndex* pEnd = chain.Linear(hEnd);
    BOOST_REQUIRE(pEnd != NULL);
    const CEpochState good = IV5Record(E, pEnd, At(pEnd, hStart), seed);
    CEpochState wrongBlock = good;
    wrongBlock.hashVNextFinalizedAnchor = At(pEnd, hStart - 1)->GetBlockHash();

    struct Trial { const CEpochState* pRecord; bool fLoads; const char* pszWhat; };
    const Trial trials[] = {
        {&good, true, "an IV5 record naming the block at its finalized height"},
        {&wrongBlock, false, "an IV5 record naming a block at another height"},
    };
    for (size_t i = 0; i < sizeof(trials) / sizeof(trials[0]); i++)
    {
        BOOST_REQUIRE(txdb.TxnBegin());
        BOOST_REQUIRE(txdb.WriteEpochState(E, *trials[i].pRecord));
        BOOST_REQUIRE(txdb.WriteCurveTreeAtEpoch(E, CCurveTree()));
        BOOST_REQUIRE(txdb.WriteEpochStateSchema(EPOCHSTATE_SCHEMA_V5));
        BOOST_REQUIRE(txdb.TxnCommit());

        CDAGManager loader;
        std::vector<uint256> none;
        BOOST_REQUIRE(loader.InitBlockDAGData(pEnd, none));
        BOOST_CHECK_MESSAGE(loader.LoadEpochStates(txdb) == trials[i].fLoads,
                            trials[i].pszWhat
                            << (trials[i].fLoads ? " failed to load" : " loaded"));
        if (trials[i].fLoads)
        {
            int nHeight = 0;
            uint256 hash = 0;
            BOOST_REQUIRE(loader.TryGetDeterministicFinalizedAnchor(E, nHeight, hash));
            BOOST_CHECK_EQUAL(nHeight, hStart);
            BOOST_CHECK(hash == trials[i].pRecord->hashVNextFinalizedAnchor);
        }
    }

    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.EraseEpochState(E));
    BOOST_REQUIRE(txdb.EraseCurveTreeAtEpoch(E));
    if (fHadOldSchema)
        BOOST_REQUIRE(txdb.WriteEpochStateSchema(nOldSchema));
    else
        BOOST_REQUIRE(txdb.EraseEpochStateSchema());
    BOOST_REQUIRE(txdb.TxnCommit());
    nRegtestBoundaryBHeight = nOldBoundaryB;
}

// Below Boundary B the anchor is not on disk; the loader re-derives it by walking
// pprev from the boundary block. A chain that does not reach the height fails closed.
BOOST_AUTO_TEST_CASE(a_record_written_below_boundary_b_resolves_its_anchor_after_reload)
{
    RegTestNetwork net;
    SchemaTestDB txdb;
    int nOldSchema = 0;
    const bool fHadOldSchema = txdb.ReadEpochStateSchema(nOldSchema);

    std::map<int, CEpochState> existing;
    BOOST_REQUIRE(txdb.IterateEpochStates(existing));
    int E = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3) + 1;
    if (!existing.empty())
        E = std::max(E, existing.rbegin()->first + 1);
    HiddenEpochRecords hidden(txdb);
    const int hStart = EpochStart(E);
    const int hEnd = EpochEnd(E);
    const int nOldBoundaryB = nRegtestBoundaryBHeight;
    nRegtestBoundaryBHeight = PRIVACY_VNEXT_HEIGHT_UNSET;
    BOOST_REQUIRE(!IsBoundaryBActiveAtHeight(hEnd));

    CSyntheticChain chain(0xA5C40000U);
    CBlockIndex* pEnd = chain.Linear(hEnd);
    BOOST_REQUIRE(pEnd != NULL);
    const CBlockIndex* pAttested = At(pEnd, hStart);

    // What the builder holds for such an epoch: the finalized height and the anchor, at
    // a version that writes only the former.
    CEpochState record;
    record.nEpoch = E;
    record.nHeightStart = hStart;
    record.nHeightEnd = hEnd;
    record.hashBoundaryBlock = pEnd->GetBlockHash();
    record.vBlockHashes.push_back(record.hashBoundaryBlock);
    record.nBlockCount = 1;
    record.nTxCount = -1;
    record.nFinalizedHeightAsOf = hStart;
    record.hashVNextFinalizedAnchor = pAttested->GetBlockHash();
    BOOST_REQUIRE_EQUAL((int)record.nSerVersion, (int)EPOCHSTATE_SER_VERSION_V3);
    {
        CDataStream ss(SER_DISK, CLIENT_VERSION);
        ss << record;
        CEpochState back;
        ss >> back;
        BOOST_REQUIRE_MESSAGE(back.hashVNextFinalizedAnchor == 0,
                              "the fixture does not reach the case: a V3 record kept its anchor");
        BOOST_REQUIRE_EQUAL(back.nFinalizedHeightAsOf, hStart);
    }

    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.WriteEpochState(E, record));
    BOOST_REQUIRE(txdb.WriteCurveTreeAtEpoch(E, CCurveTree()));
    BOOST_REQUIRE(txdb.WriteEpochStateSchema(EPOCHSTATE_SCHEMA_V5));
    BOOST_REQUIRE(txdb.TxnCommit());

    CDAGManager loader;
    std::vector<uint256> none;
    BOOST_REQUIRE(loader.InitBlockDAGData(pEnd, none));
    BOOST_REQUIRE_MESSAGE(loader.LoadEpochStates(txdb),
                          "a record written below Boundary B failed to load");
    int nHeight = 0;
    uint256 hash = 0;
    BOOST_REQUIRE(loader.TryGetDeterministicFinalizedAnchor(E, nHeight, hash));
    BOOST_CHECK_EQUAL(nHeight, hStart);
    BOOST_CHECK_MESSAGE(hash == pAttested->GetBlockHash(),
                        "the reloaded record does not resolve the block at its finalized height");

    // A tip in the next epoch reads this record: the chain carrying the block is
    // admitted, a fork below it is refused, and nothing fails closed.
    const int nBest = EpochStart(E + 1) + 5;
    CBlockIndex* pTip = chain.Extend(pEnd, nBest - hEnd);
    CBlockIndex* pOther = chain.Extend(At(pEnd, hStart - 1), nBest - (hStart - 1));
    BOOST_REQUIRE(pTip && pOther);
    int nCur = 0, nLatch = 0, nEpoch = 0;
    BOOST_CHECK_EQUAL((int)CheckReorgAgainstFinality(loader, nBest, pTip, nCur, nLatch, nEpoch),
                      (int)REORG_FINALITY_ALLOW);
    BOOST_CHECK_EQUAL(nEpoch, E);
    BOOST_CHECK_EQUAL(nCur, hStart);
    const ReorgFinalityVerdict other =
        CheckReorgAgainstFinality(loader, nBest, pOther, nCur, nLatch, nEpoch);
    BOOST_CHECK(other != REORG_FINALITY_ALLOW);
    BOOST_CHECK(other != REORG_FINALITY_STATE_MISSING);

    // Fail closed: the boundary block's chain ends above the finalized height.
    CSyntheticChain stub(0xA5C41000U);
    CBlockIndex* pStubEnd = stub.Extend(stub.Add(NULL, hStart + 1), hEnd - hStart - 1);
    BOOST_REQUIRE(pStubEnd && pStubEnd->nHeight == hEnd);
    CEpochState unreachable = record;
    unreachable.hashBoundaryBlock = pStubEnd->GetBlockHash();
    unreachable.vBlockHashes.assign(1, unreachable.hashBoundaryBlock);
    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.WriteEpochState(E, unreachable));
    BOOST_REQUIRE(txdb.TxnCommit());
    CDAGManager refusing;
    BOOST_REQUIRE(refusing.InitBlockDAGData(pStubEnd, none));
    BOOST_CHECK_MESSAGE(!refusing.LoadEpochStates(txdb),
                        "a record whose boundary chain does not reach its finalized height loaded");

    BOOST_REQUIRE(txdb.TxnBegin());
    BOOST_REQUIRE(txdb.EraseEpochState(E));
    BOOST_REQUIRE(txdb.EraseCurveTreeAtEpoch(E));
    if (fHadOldSchema)
        BOOST_REQUIRE(txdb.WriteEpochStateSchema(nOldSchema));
    else
        BOOST_REQUIRE(txdb.EraseEpochStateSchema());
    BOOST_REQUIRE(txdb.TxnCommit());
    nRegtestBoundaryBHeight = nOldBoundaryB;
}

BOOST_AUTO_TEST_SUITE_END()
