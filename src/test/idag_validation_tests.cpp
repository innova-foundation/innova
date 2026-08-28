#include <boost/test/unit_test.hpp>

#include "../dag.h"
#include "../finality.h"
#include "../main.h"
#include "../txdb.h"
#include "../wallet.h"

#include <algorithm>

extern bool fRegTest;
extern bool fTestNet;

BOOST_AUTO_TEST_SUITE(idag_validation_tests)

namespace
{
class CDAGActiveSetTestDB : public CTxDB
{
public:
    CDAGActiveSetTestDB() : CTxDB("r+") {}

    template <typename T>
    bool WriteRawActiveSet(const uint256& hashBlock, const T& value)
    {
        return Write(std::make_pair(std::string("dagactiveset"), hashBlock),
                     value);
    }

    template <typename T>
    bool WriteRawTxIndex(const uint256& hashTx, const T& value)
    {
        return Write(std::make_pair(std::string("tx"), hashTx), value);
    }

    bool EraseActiveSet(const uint256& hashBlock)
    {
        return Erase(std::make_pair(std::string("dagactiveset"), hashBlock));
    }

    bool EraseTestTxIndex(const uint256& hashTx)
    {
        return Erase(std::make_pair(std::string("tx"), hashTx));
    }

    bool EraseActiveSetBuildMarker()
    {
        return Erase(std::string("dagactivesetbuild"));
    }
};

class CDAGActiveSetWithTrailingByte
{
public:
    int nSchema;
    uint32_t nBlockTxCount;
    uint256 hashMerkleRoot;
    std::vector<uint256> vSkipped;
    uint256 hashDigest;
    unsigned char trailing;

    CDAGActiveSetWithTrailingByte()
        : nSchema(DAG_ACTIVE_SET_SCHEMA), nBlockTxCount(0),
          trailing(0xa5) {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nSchema);
        READWRITE(nBlockTxCount);
        READWRITE(hashMerkleRoot);
        READWRITE(vSkipped);
        READWRITE(hashDigest);
        READWRITE(trailing);
    )
};

class CTxIndexWithTrailingByte
{
public:
    CTxIndex index;
    unsigned char trailing;

    CTxIndexWithTrailingByte() : trailing(0x5a) {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(index);
        READWRITE(trailing);
    )
};

uint256 TestDAGActiveSetDigest(const CBlock& block,
                              const std::vector<uint256>& vSkipped)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("Innova/IDAG/ActiveSet/v1");
    ss << block.GetHash() << block.hashMerkleRoot;
    ss << (uint32_t)block.vtx.size();
    ss << (uint64_t)vSkipped.size();
    for (std::vector<uint256>::const_iterator it = vSkipped.begin();
         it != vSkipped.end(); ++it)
        ss << *it;
    return ss.GetHash();
}
} // namespace

BOOST_AUTO_TEST_CASE(finality_stake_proof_spent_in_same_block_is_rejected)
{
    COutPoint proof(uint256(12345), 0);

    CTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();

    CTransaction spend;
    spend.vin.resize(1);
    spend.vin[0].prevout = proof;

    CFinalityVote vote;
    vote.vStakeProof.push_back(proof);

    CBlock block;
    block.vtx.push_back(coinbase);
    block.vtx.push_back(spend);

    std::vector<CFinalityVote> votes;
    votes.push_back(vote);

    BOOST_CHECK(!CheckFinalityStakeProofsNotSpentInBlock(block, votes));
}

BOOST_AUTO_TEST_CASE(post_dag_coinbase_reward_accounting_has_size_penalty)
{
    int64_t noPenalty = GetBlockSizePenalty(ADAPTIVE_BLOCK_FLOOR, ADAPTIVE_BLOCK_FLOOR);
    int64_t penalty = GetBlockSizePenalty(ADAPTIVE_BLOCK_FLOOR + (ADAPTIVE_BLOCK_FLOOR / 2),
                                          ADAPTIVE_BLOCK_FLOOR);

    BOOST_CHECK_EQUAL(noPenalty, 0);
    BOOST_CHECK(penalty > 0);
    BOOST_CHECK(penalty < COIN);
}

BOOST_AUTO_TEST_CASE(select_best_dag_tip_allows_non_best_chain_tip)
{
    CBlockIndex* oldBest = pindexBest;

    uint256 hParent(4242000);
    uint256 hSideTip(4242001);
    uint256 hMainTip(4242002);

    CBlockIndex parent;
    CBlockIndex sideTip;
    CBlockIndex mainTip;

    parent.nHeight = FORK_HEIGHT_DAG;
    sideTip.nHeight = FORK_HEIGHT_DAG + 1;
    mainTip.nHeight = FORK_HEIGHT_DAG + 1;
    sideTip.pprev = &parent;
    mainTip.pprev = &parent;
    parent.pnext = &mainTip;

    mapBlockIndex[hParent] = &parent;
    mapBlockIndex[hSideTip] = &sideTip;
    mapBlockIndex[hMainTip] = &mainTip;
    parent.phashBlock = &mapBlockIndex.find(hParent)->first;
    sideTip.phashBlock = &mapBlockIndex.find(hSideTip)->first;
    mainTip.phashBlock = &mapBlockIndex.find(hMainTip)->first;

    pindexBest = &mainTip;

    std::vector<uint256> noParents;
    std::vector<uint256> parentOnly;
    parentOnly.push_back(hParent);

    g_dagManager.InitBlockDAGData(&parent, noParents);
    g_dagManager.ColorBlock(&parent);
    g_dagManager.InitBlockDAGData(&mainTip, parentOnly);
    g_dagManager.ColorBlock(&mainTip);
    g_dagManager.InitBlockDAGData(&sideTip, parentOnly);
    g_dagManager.ColorBlock(&sideTip);

    CBlockIndex* selected = g_dagManager.SelectBestDAGTip();
    BOOST_CHECK(selected == &sideTip);

    g_dagManager.RemoveBlockDAGData(hSideTip);
    g_dagManager.RemoveBlockDAGData(hMainTip);
    g_dagManager.RemoveBlockDAGData(hParent);
    mapBlockIndex.erase(hSideTip);
    mapBlockIndex.erase(hMainTip);
    mapBlockIndex.erase(hParent);
    pindexBest = oldBest;
}

// Equal DAG scores at or above V3 break by height, then hash; otherwise tips of equal
// score at different heights order differently across nodes. Ties are built from
// GetBlockEntropy: complements 1, 2, 4 weigh 1, 2, 3 units, so 1 + 2 ties 3.
BOOST_AUTO_TEST_CASE(equal_dag_score_above_v3_breaks_by_height_before_hash)
{
    CBlockIndex* oldBest = pindexBest;

    const uint256 hParent(4243000);
    const uint256 hFirst = ~uint256(1);
    const uint256 hSecond = ~uint256(2);
    const uint256 hShort = ~uint256(4);

    // The taller tip has to be the one a hash comparison would reject, or the rule
    // and its negation would agree here and the case would prove nothing.
    BOOST_REQUIRE(hShort < hSecond);

    CBlockIndex parent, first, second, shortTip;
    CBlockIndex* vBlocks[] = { &parent, &first, &second, &shortTip };
    for (CBlockIndex* p : vBlocks)
        p->nBits = 0x1d00ffff;      // a zero target would make every trust zero

    parent.nHeight = FORK_HEIGHT_EPOCH_STATE_V3 + 1;
    first.nHeight = parent.nHeight + 1;
    second.nHeight = parent.nHeight + 2;    // the taller tip
    shortTip.nHeight = parent.nHeight + 1;

    first.pprev = &parent;
    second.pprev = &first;
    shortTip.pprev = &parent;

    mapBlockIndex[hParent] = &parent;
    mapBlockIndex[hFirst] = &first;
    mapBlockIndex[hSecond] = &second;
    mapBlockIndex[hShort] = &shortTip;
    parent.phashBlock = &mapBlockIndex.find(hParent)->first;
    first.phashBlock = &mapBlockIndex.find(hFirst)->first;
    second.phashBlock = &mapBlockIndex.find(hSecond)->first;
    shortTip.phashBlock = &mapBlockIndex.find(hShort)->first;

    std::vector<uint256> noParents;
    std::vector<uint256> onParent;
    onParent.push_back(hParent);
    std::vector<uint256> onFirst;
    onFirst.push_back(hFirst);

    g_dagManager.InitBlockDAGData(&parent, noParents);
    g_dagManager.ColorBlock(&parent);
    g_dagManager.InitBlockDAGData(&first, onParent);
    g_dagManager.ColorBlock(&first);
    g_dagManager.InitBlockDAGData(&second, onFirst);
    g_dagManager.ColorBlock(&second);
    g_dagManager.InitBlockDAGData(&shortTip, onParent);
    g_dagManager.ColorBlock(&shortTip);

    // The premise: the tips really are tied, so nothing but the tie-break decides.
    const uint256 nTallScore = g_dagManager.ComputeDAGScore(&second);
    const uint256 nShortScore = g_dagManager.ComputeDAGScore(&shortTip);
    BOOST_REQUIRE_MESSAGE(nTallScore == nShortScore,
                          "the tips are not tied: " + nTallScore.ToString() +
                              " against " + nShortScore.ToString());

    CBlockIndex* selected = g_dagManager.SelectBestDAGTip();
    BOOST_CHECK(selected == &second);

    g_dagManager.RemoveBlockDAGData(hShort);
    g_dagManager.RemoveBlockDAGData(hSecond);
    g_dagManager.RemoveBlockDAGData(hFirst);
    g_dagManager.RemoveBlockDAGData(hParent);
    mapBlockIndex.erase(hShort);
    mapBlockIndex.erase(hSecond);
    mapBlockIndex.erase(hFirst);
    mapBlockIndex.erase(hParent);
// At and above V3 an equal DAG score breaks on higher height first, then hash. Here the
// lower tip holds the lower hash, so the two rules disagree.
BOOST_AUTO_TEST_CASE(v3_equal_dag_score_breaks_by_height_before_hash)
    BOOST_REQUIRE(g_dagManager.GetDAGTips().empty());

    // A block whose compact target is zero contributes no trust, which is what
    // makes two tips at different heights hold the identical score.
    const uint256 hLow(0x0BA8001);
    const uint256 hRoot(0x0BA8002);
    const uint256 hHigh(0x0BA8003);
    BOOST_REQUIRE(hLow < hHigh);

    const int nV3 = FORK_HEIGHT_EPOCH_STATE_V3;
    CBlockIndex lowTip;
    CBlockIndex root;
    CBlockIndex highTip;
    lowTip.nHeight = nV3;
    root.nHeight = nV3;
    highTip.nHeight = nV3 + 1;
    highTip.pprev = &root;
    lowTip.nBits = 0;
    root.nBits = 0;
    highTip.nBits = 0;

    mapBlockIndex[hLow] = &lowTip;
    mapBlockIndex[hRoot] = &root;
    mapBlockIndex[hHigh] = &highTip;
    lowTip.phashBlock = &mapBlockIndex.find(hLow)->first;
    root.phashBlock = &mapBlockIndex.find(hRoot)->first;
    highTip.phashBlock = &mapBlockIndex.find(hHigh)->first;

    std::vector<uint256> rootOnly;
    rootOnly.push_back(hRoot);

    g_dagManager.InitBlockDAGData(&lowTip, noParents);
    g_dagManager.ColorBlock(&lowTip);
    g_dagManager.InitBlockDAGData(&root, noParents);
    g_dagManager.ColorBlock(&root);
    g_dagManager.InitBlockDAGData(&highTip, rootOnly);
    g_dagManager.ColorBlock(&highTip);

    BOOST_REQUIRE_EQUAL(g_dagManager.GetDAGTips().size(), 2u);
    BOOST_REQUIRE(g_dagManager.ComputeDAGScore(&lowTip) == g_dagManager.ComputeDAGScore(&highTip));

    BOOST_CHECK(selected == &highTip);

    g_dagManager.RemoveBlockDAGData(hHigh);
    g_dagManager.RemoveBlockDAGData(hRoot);
    g_dagManager.RemoveBlockDAGData(hLow);
    mapBlockIndex.erase(hHigh);
    mapBlockIndex.erase(hRoot);
    mapBlockIndex.erase(hLow);
    pindexBest = oldBest;
}

BOOST_AUTO_TEST_CASE(dag_sibling_conflict_detection_covers_nullifiers_and_prevouts)
{
    std::set<COutPoint> spentOutputs;
    std::set<uint256> spentNullifiers;

    COutPoint spentPrevout(uint256(10101), 0);
    uint256 spentNullifier(20202);
    spentOutputs.insert(spentPrevout);
    spentNullifiers.insert(spentNullifier);

    CTransaction transparentConflict;
    transparentConflict.vin.push_back(CTxIn(spentPrevout));
    BOOST_CHECK(TransactionConflictsWithDAGSiblingSpends(transparentConflict,
                                                        spentOutputs,
                                                        spentNullifiers));

    CTransaction shieldedConflict;
    shieldedConflict.nVersion = SHIELDED_TX_VERSION_FCMP;
    CShieldedSpendDescription spend;
    spend.nullifier = spentNullifier;
    shieldedConflict.vShieldedSpend.push_back(spend);
    BOOST_CHECK(TransactionConflictsWithDAGSiblingSpends(shieldedConflict,
                                                        spentOutputs,
                                                        spentNullifiers));

    CTransaction independent;
    independent.vin.push_back(CTxIn(COutPoint(uint256(30303), 1)));
    CShieldedSpendDescription independentSpend;
    independentSpend.nullifier = uint256(40404);
    independent.vShieldedSpend.push_back(independentSpend);
    BOOST_CHECK(!TransactionConflictsWithDAGSiblingSpends(independent,
                                                         spentOutputs,
                                                         spentNullifiers));

    // IsCoinBase() requires at least one output.
    CTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vout.resize(1);
    coinbase.vShieldedSpend.push_back(spend);
    BOOST_CHECK(coinbase.IsCoinBase());
    BOOST_CHECK(!TransactionConflictsWithDAGSiblingSpends(coinbase,
                                                         spentOutputs,
                                                         spentNullifiers));
}

BOOST_AUTO_TEST_CASE(dag_skipped_transactions_expand_to_in_block_descendants)
{
    std::set<COutPoint> spentOutputs;
    std::set<uint256> spentNullifiers;

    COutPoint siblingSpentPrevout(uint256(50505), 0);
    spentOutputs.insert(siblingSpentPrevout);

    CTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vout.resize(1);

    CTransaction directConflict;
    directConflict.vin.push_back(CTxIn(siblingSpentPrevout));
    uint256 directConflictHash = directConflict.GetHash();

    CTransaction descendant;
    descendant.vin.push_back(CTxIn(COutPoint(directConflictHash, 0)));

    CTransaction independent;
    independent.vin.push_back(CTxIn(COutPoint(uint256(60606), 1)));

    CBlock block;
    block.vtx.push_back(coinbase);
    block.vtx.push_back(directConflict);
    block.vtx.push_back(descendant);
    block.vtx.push_back(independent);

    std::set<uint256> skipped = GetDAGSkippedTxsFromSiblingSpends(block,
                                                                  spentOutputs,
                                                                  spentNullifiers);

    BOOST_CHECK(skipped.count(directConflictHash));
    BOOST_CHECK(skipped.count(descendant.GetHash()));
    BOOST_CHECK(!skipped.count(independent.GetHash()));

    CBlock activeBlock = GetDAGActiveBlock(block, skipped);
    BOOST_REQUIRE_EQUAL(activeBlock.vtx.size(), 2U);
    BOOST_CHECK_EQUAL(activeBlock.vtx[0].GetHash().ToString(), coinbase.GetHash().ToString());
    BOOST_CHECK_EQUAL(activeBlock.vtx[1].GetHash().ToString(), independent.GetHash().ToString());
}

BOOST_AUTO_TEST_CASE(dag_connect_time_active_set_survives_late_sibling_and_abort)
{
    CTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vout.push_back(CTxOut(1, CScript() << OP_TRUE));

    const COutPoint sharedPrevout(uint256(0xdac001), 0);
    CTransaction historicallyActive;
    historicallyActive.vin.push_back(CTxIn(sharedPrevout));
    historicallyActive.vout.push_back(CTxOut(1, CScript() << OP_TRUE));

    CBlock block;
    block.nVersion = CBlock::CURRENT_VERSION;
    block.nTime = 0xdac002;
    block.nNonce = 0xdac003;
    block.vtx.push_back(coinbase);
    block.vtx.push_back(historicallyActive);
    block.hashMerkleRoot = block.BuildMerkleTree();
    const uint256 hashBlock = block.GetHash();

    CDAGActiveSetTestDB db;
    db.EraseActiveSet(hashBlock);
    std::string error;
    std::set<uint256> persisted;
    BOOST_CHECK_EQUAL(db.ReadDAGSkippedTxsStatus(
                          block, persisted, error),
                      TXDB_READ_NOT_FOUND);

    // A connected before B existed, so A's transaction was active.
    BOOST_REQUIRE(db.TxnBegin());
    BOOST_REQUIRE(db.WriteDAGSkippedTxs(
        block, std::set<uint256>(), error));
    BOOST_REQUIRE_EQUAL(db.ReadDAGSkippedTxsStatus(
                            block, persisted, error),
                        TXDB_READ_FOUND);
    BOOST_CHECK(persisted.empty());
    BOOST_REQUIRE(db.TxnCommit());

    // Learning a conflicting sibling later changes a live recomputation, but
    // must not change the exact plan used for rollback.
    std::set<COutPoint> siblingSpentOutputs;
    siblingSpentOutputs.insert(sharedPrevout);
    const std::set<uint256> recomputed =
        GetDAGSkippedTxsFromSiblingSpends(
            block, siblingSpentOutputs, std::set<uint256>());
    BOOST_CHECK(recomputed.count(historicallyActive.GetHash()) == 1);
    BOOST_REQUIRE_EQUAL(db.ReadDAGSkippedTxsStatus(
                            block, persisted, error),
                        TXDB_READ_FOUND);
    BOOST_CHECK(persisted.empty());

    // A staged competing plan is visible inside its batch and disappears on
    // abort, matching the outer chain transaction's atomicity.
    BOOST_REQUIRE(db.TxnBegin());
    BOOST_REQUIRE(db.WriteDAGSkippedTxs(block, recomputed, error));
    BOOST_REQUIRE_EQUAL(db.ReadDAGSkippedTxsStatus(
                            block, persisted, error),
                        TXDB_READ_FOUND);
    BOOST_CHECK(persisted.count(historicallyActive.GetHash()) == 1);
    BOOST_REQUIRE(db.TxnAbort());
    BOOST_REQUIRE_EQUAL(db.ReadDAGSkippedTxsStatus(
                            block, persisted, error),
                        TXDB_READ_FOUND);
    BOOST_CHECK(persisted.empty());

    // Exact reads reject a valid prefix with trailing bytes.
    CDAGActiveSetWithTrailingByte trailing;
    trailing.nBlockTxCount = (uint32_t)block.vtx.size();
    trailing.hashMerkleRoot = block.hashMerkleRoot;
    trailing.vSkipped.assign(recomputed.begin(), recomputed.end());
    trailing.hashDigest = TestDAGActiveSetDigest(block,
                                                 trailing.vSkipped);
    BOOST_REQUIRE(db.WriteRawActiveSet(hashBlock, trailing));
    BOOST_CHECK_EQUAL(db.ReadDAGSkippedTxsStatus(
                          block, persisted, error),
                      TXDB_READ_ERROR);
    BOOST_CHECK(!error.empty());
    BOOST_REQUIRE(db.EraseActiveSet(hashBlock));
}

BOOST_AUTO_TEST_CASE(txindex_tri_state_read_is_exact_and_bounded)
{
    CDAGActiveSetTestDB db;
    const uint256 hashTx(0xdac100);
    db.EraseTestTxIndex(hashTx);

    CTxIndex index(CDiskTxPos(7, 11, 13), 2);
    BOOST_REQUIRE(db.UpdateTxIndex(hashTx, index));
    CTxIndex decoded;
    BOOST_REQUIRE_EQUAL(db.ReadTxIndexStatus(hashTx, decoded),
                        TXDB_READ_FOUND);
    BOOST_CHECK(decoded == index);

    CTxIndexWithTrailingByte trailing;
    trailing.index = index;
    BOOST_REQUIRE(db.WriteRawTxIndex(hashTx, trailing));
    BOOST_CHECK_EQUAL(db.ReadTxIndexStatus(hashTx, decoded),
                      TXDB_READ_ERROR);

    BOOST_REQUIRE(db.EraseTestTxIndex(hashTx));
    BOOST_CHECK_EQUAL(db.ReadTxIndexStatus(hashTx, decoded),
                      TXDB_READ_NOT_FOUND);
}

BOOST_AUTO_TEST_CASE(dag_active_set_recovery_progress_is_batch_atomic)
{
    CDAGActiveSetTestDB db;
    db.EraseActiveSetBuildMarker();

    CDAGActiveSetBuildRecord record;
    record.nMode = DAG_ACTIVE_SET_BUILD_REBUILD_SUFFIX;
    record.hashTargetBest = uint256(0xdac203);
    record.nTargetHeight = 203;
    record.hashTrustedBase = uint256(0xdac200);
    record.nTrustedBaseHeight = 200;
    record.hashNextBlock = record.hashTargetBest;
    record.nNextHeight = record.nTargetHeight;

    CDAGActiveSetBuildRecord decoded;
    BOOST_REQUIRE(db.TxnBegin());
    BOOST_REQUIRE(db.WriteDAGActiveSetBuild(record));
    BOOST_REQUIRE_EQUAL(db.ReadDAGActiveSetBuild(decoded),
                        TXDB_READ_FOUND);
    BOOST_CHECK_EQUAL(decoded.nNextHeight, 203);
    BOOST_REQUIRE(db.TxnAbort());
    BOOST_CHECK_EQUAL(db.ReadDAGActiveSetBuild(decoded),
                      TXDB_READ_NOT_FOUND);

    BOOST_REQUIRE(db.TxnBegin());
    BOOST_REQUIRE(db.WriteDAGActiveSetBuild(record));
    BOOST_REQUIRE(db.TxnCommit());
    BOOST_REQUIRE_EQUAL(db.ReadDAGActiveSetBuild(decoded),
                        TXDB_READ_FOUND);

    record.hashNextBlock = uint256(0xdac201);
    record.nNextHeight = 201;
    BOOST_REQUIRE(db.TxnBegin());
    BOOST_REQUIRE(db.WriteDAGActiveSetBuild(record));
    BOOST_REQUIRE_EQUAL(db.ReadDAGActiveSetBuild(decoded),
                        TXDB_READ_FOUND);
    BOOST_CHECK_EQUAL(decoded.nNextHeight, 201);
    BOOST_REQUIRE(db.TxnAbort());
    BOOST_REQUIRE_EQUAL(db.ReadDAGActiveSetBuild(decoded),
                        TXDB_READ_FOUND);
    BOOST_CHECK_EQUAL(decoded.nNextHeight, 203);

    BOOST_REQUIRE(db.EraseActiveSetBuildMarker());
}

BOOST_AUTO_TEST_CASE(v3_sibling_conflicts_ignore_unreachable_local_children)
{
    const int nV3Height = FORK_HEIGHT_EPOCH_STATE_V3;
    uint256 hGrandparent(710001);
    uint256 hParent(710002);
    uint256 hMergedSibling(710003);
    uint256 hLocalOnlySibling(710004);
    uint256 hBlock(710005);

    CBlockIndex grandparent;
    CBlockIndex parent;
    CBlockIndex mergedSibling;
    CBlockIndex localOnlySibling;
    CBlockIndex block;
    grandparent.nHeight = nV3Height - 2;
    parent.nHeight = nV3Height - 1;
    mergedSibling.nHeight = nV3Height;
    localOnlySibling.nHeight = nV3Height;
    block.nHeight = nV3Height + 1;
    parent.pprev = &grandparent;
    mergedSibling.pprev = &parent;
    localOnlySibling.pprev = &parent;
    block.pprev = &mergedSibling;

    mapBlockIndex[hGrandparent] = &grandparent;
    mapBlockIndex[hParent] = &parent;
    mapBlockIndex[hMergedSibling] = &mergedSibling;
    mapBlockIndex[hLocalOnlySibling] = &localOnlySibling;
    mapBlockIndex[hBlock] = &block;
    grandparent.phashBlock = &mapBlockIndex.find(hGrandparent)->first;
    parent.phashBlock = &mapBlockIndex.find(hParent)->first;
    mergedSibling.phashBlock = &mapBlockIndex.find(hMergedSibling)->first;
    localOnlySibling.phashBlock = &mapBlockIndex.find(hLocalOnlySibling)->first;
    block.phashBlock = &mapBlockIndex.find(hBlock)->first;

    std::vector<uint256> grandparentParents;
    std::vector<uint256> parentParents(1, hGrandparent);
    std::vector<uint256> siblingParents(1, hParent);
    std::vector<uint256> blockParents;
    blockParents.push_back(hMergedSibling);
    blockParents.push_back(hParent);

    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(&grandparent,
                                                 grandparentParents));
    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(&parent, parentParents));
    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(&mergedSibling,
                                                 siblingParents));
    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(&localOnlySibling,
                                                 siblingParents));
    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(&block, blockParents));

    const std::set<uint256> siblings =
        g_dagManager.GetDAGSiblingBlocks(hBlock);
    BOOST_CHECK(siblings.count(hMergedSibling));
    BOOST_CHECK(!siblings.count(hLocalOnlySibling));

    g_dagManager.RemoveBlockDAGData(hBlock);
    g_dagManager.RemoveBlockDAGData(hLocalOnlySibling);
    g_dagManager.RemoveBlockDAGData(hMergedSibling);
    g_dagManager.RemoveBlockDAGData(hParent);
    g_dagManager.RemoveBlockDAGData(hGrandparent);
    mapBlockIndex.erase(hBlock);
    mapBlockIndex.erase(hLocalOnlySibling);
    mapBlockIndex.erase(hMergedSibling);
    mapBlockIndex.erase(hParent);
    mapBlockIndex.erase(hGrandparent);
}

// The anchor-past restriction starts at FORK_HEIGHT_DAG, where every consumer of the sibling
// set lives; the old gate admitted unmerged locally-known children below V3.
BOOST_AUTO_TEST_CASE(dag_fork_sibling_conflicts_ignore_unreachable_local_children)
{
    const int nDAGHeight = FORK_HEIGHT_DAG;
    BOOST_REQUIRE(nDAGHeight + 1 < FORK_HEIGHT_EPOCH_STATE_V3);

    uint256 hGrandparent(720001);
    uint256 hParent(720002);
    uint256 hMergedSibling(720003);
    uint256 hLocalOnlySibling(720004);
    uint256 hBlock(720005);

    CBlockIndex grandparent;
    CBlockIndex parent;
    CBlockIndex mergedSibling;
    CBlockIndex localOnlySibling;
    CBlockIndex block;
    grandparent.nHeight = nDAGHeight;
    parent.nHeight = nDAGHeight;
    mergedSibling.nHeight = nDAGHeight + 1;
    localOnlySibling.nHeight = nDAGHeight + 1;
    block.nHeight = nDAGHeight + 2;
    parent.pprev = &grandparent;
    mergedSibling.pprev = &parent;
    localOnlySibling.pprev = &parent;
    block.pprev = &mergedSibling;

    mapBlockIndex[hGrandparent] = &grandparent;
    mapBlockIndex[hParent] = &parent;
    mapBlockIndex[hMergedSibling] = &mergedSibling;
    mapBlockIndex[hLocalOnlySibling] = &localOnlySibling;
    mapBlockIndex[hBlock] = &block;
    grandparent.phashBlock = &mapBlockIndex.find(hGrandparent)->first;
    parent.phashBlock = &mapBlockIndex.find(hParent)->first;
    mergedSibling.phashBlock = &mapBlockIndex.find(hMergedSibling)->first;
    localOnlySibling.phashBlock = &mapBlockIndex.find(hLocalOnlySibling)->first;
    block.phashBlock = &mapBlockIndex.find(hBlock)->first;

    std::vector<uint256> grandparentParents;
    std::vector<uint256> parentParents(1, hGrandparent);
    std::vector<uint256> siblingParents(1, hParent);
    std::vector<uint256> blockParents;
    blockParents.push_back(hMergedSibling);
    blockParents.push_back(hParent);

    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(&grandparent, grandparentParents));
    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(&parent, parentParents));
    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(&mergedSibling, siblingParents));
    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(&localOnlySibling, siblingParents));
    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(&block, blockParents));

    const std::set<uint256> siblings = g_dagManager.GetDAGSiblingBlocks(hBlock);
    BOOST_CHECK(siblings.count(hMergedSibling));
    BOOST_CHECK_MESSAGE(!siblings.count(hLocalOnlySibling),
                        "a sibling the block does not reach through its committed parents "
                        "made the active set depend on what this node happened to receive");

    g_dagManager.RemoveBlockDAGData(hBlock);
    g_dagManager.RemoveBlockDAGData(hLocalOnlySibling);
    g_dagManager.RemoveBlockDAGData(hMergedSibling);
    g_dagManager.RemoveBlockDAGData(hParent);
    g_dagManager.RemoveBlockDAGData(hGrandparent);
    mapBlockIndex.erase(hBlock);
    mapBlockIndex.erase(hLocalOnlySibling);
    mapBlockIndex.erase(hMergedSibling);
    mapBlockIndex.erase(hParent);
    mapBlockIndex.erase(hGrandparent);
}

// Sibling spend conflicts must resolve independently of nDAGOrder, which is -1 until a
// node-local rebuild runs. The merging block's hash sorts below its siblings while its
// height sorts above, so hash-only and order-based rules disagree.
BOOST_AUTO_TEST_CASE(dag_sibling_precedence_is_independent_of_dag_order_rebuilds)
{
    const int nDAGHeight = FORK_HEIGHT_DAG;
    BOOST_REQUIRE(nDAGHeight + 3 < FORK_HEIGHT_EPOCH_STATE_V3);

    CBlockIndex* pOldBest = pindexBest;

    // hMerge is the smallest of the five, so the pre-rebuild hash rule answers "no
    // sibling precedes me" while the height rule and any rebuilt order answer "both do".
    uint256 hMerge(0x9da0001);
    uint256 hSiblingA(0x9da0002);
    uint256 hSiblingB(0x9da0003);
    uint256 hParent(0x9da0004);
    uint256 hChild(0x9da0005);
    BOOST_REQUIRE(hMerge < hSiblingA && hMerge < hSiblingB);

    CBlockIndex parent;
    CBlockIndex siblingA;
    CBlockIndex siblingB;
    CBlockIndex child;
    CBlockIndex merge;
    parent.nHeight = nDAGHeight;
    siblingA.nHeight = nDAGHeight + 1;
    siblingB.nHeight = nDAGHeight + 1;
    child.nHeight = nDAGHeight + 2;
    merge.nHeight = nDAGHeight + 3;
    siblingA.pprev = &parent;
    siblingB.pprev = &parent;
    child.pprev = &siblingA;
    merge.pprev = &child;

    mapBlockIndex[hParent] = &parent;
    mapBlockIndex[hSiblingA] = &siblingA;
    mapBlockIndex[hSiblingB] = &siblingB;
    mapBlockIndex[hChild] = &child;
    mapBlockIndex[hMerge] = &merge;
    parent.phashBlock = &mapBlockIndex.find(hParent)->first;
    siblingA.phashBlock = &mapBlockIndex.find(hSiblingA)->first;
    siblingB.phashBlock = &mapBlockIndex.find(hSiblingB)->first;
    child.phashBlock = &mapBlockIndex.find(hChild)->first;
    merge.phashBlock = &mapBlockIndex.find(hMerge)->first;

    std::vector<uint256> noParents;
    std::vector<uint256> ofParent(1, hParent);
    std::vector<uint256> ofSiblingA(1, hSiblingA);
    // The merge commits the second height-(nDAGHeight+1) block and the shared parent, so
    // both of them are siblings of the merge and both are inside its reachable past.
    std::vector<uint256> ofChildAndParent;
    ofChildAndParent.push_back(hChild);
    ofChildAndParent.push_back(hSiblingB);
    ofChildAndParent.push_back(hParent);

    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(&parent, noParents));
    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(&siblingA, ofParent));
    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(&siblingB, ofParent));
    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(&child, ofSiblingA));
    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(&merge, ofChildAndParent));

    const std::set<uint256> siblings = g_dagManager.GetDAGSiblingBlocks(hMerge);
    BOOST_REQUIRE(siblings.count(hSiblingA));
    BOOST_REQUIRE(siblings.count(hSiblingB));

    // Node A: no rebuild has ever run here, so every order is still unassigned.
    CBlockDAGData dataFresh;
    BOOST_REQUIRE(g_dagManager.GetDAGData(hMerge, dataFresh));
    BOOST_REQUIRE_EQUAL(dataFresh.nDAGOrder, -1);
    const bool fFreshA = DAGSiblingPrecedesBlock(hMerge, hSiblingA);
    const bool fFreshB = DAGSiblingPrecedesBlock(hMerge, hSiblingB);

    // Node B: restarted once, or crossed the tip-flood threshold more than 60s after its
    // last rebuild. Same committed DAG, different local cache.
    pindexBest = &merge;
    g_dagManager.RebuildDAGOrder();
    CBlockDAGData dataRebuilt;
    CBlockDAGData dataSiblingA;
    BOOST_REQUIRE(g_dagManager.GetDAGData(hMerge, dataRebuilt));
    BOOST_REQUIRE(g_dagManager.GetDAGData(hSiblingA, dataSiblingA));
    BOOST_REQUIRE_MESSAGE(dataRebuilt.nDAGOrder >= 0 && dataSiblingA.nDAGOrder >= 0,
                          "the rebuild did not reach the shape, so the two node states are "
                          "not actually different and the test proves nothing");
    BOOST_REQUIRE_MESSAGE(dataSiblingA.nDAGOrder < dataRebuilt.nDAGOrder,
                          "DAG order and hash order must disagree here or the shape cannot "
                          "expose an order-dependent rule");
    const bool fRebuiltA = DAGSiblingPrecedesBlock(hMerge, hSiblingA);
    const bool fRebuiltB = DAGSiblingPrecedesBlock(hMerge, hSiblingB);

    BOOST_CHECK_MESSAGE(fFreshA == fRebuiltA && fFreshB == fRebuiltB,
                        "sibling precedence changed when only node-local DAG-order state "
                        "changed: the two nodes accept different blocks");

    // And the verdict both nodes reach is the committed one: a lower height always precedes.
    BOOST_CHECK(fRebuiltA);
    BOOST_CHECK(fRebuiltB);
    // A block never precedes itself, and equal heights fall back to the committed hash.
    BOOST_CHECK(!DAGSiblingPrecedesBlock(hSiblingA, hSiblingA));
    BOOST_CHECK(DAGSiblingPrecedesBlock(hSiblingB, hSiblingA));
    BOOST_CHECK(!DAGSiblingPrecedesBlock(hSiblingA, hSiblingB));

    g_dagManager.RemoveBlockDAGData(hMerge);
    g_dagManager.RemoveBlockDAGData(hChild);
    g_dagManager.RemoveBlockDAGData(hSiblingB);
    g_dagManager.RemoveBlockDAGData(hSiblingA);
    g_dagManager.RemoveBlockDAGData(hParent);
    mapBlockIndex.erase(hMerge);
    mapBlockIndex.erase(hChild);
    mapBlockIndex.erase(hSiblingB);
    mapBlockIndex.erase(hSiblingA);
    mapBlockIndex.erase(hParent);
    pindexBest = pOldBest;
}

// Schema-V3 epoch order ranks parents by nDAGScore, which below FORK_HEIGHT_DAGKNIGHT
// ColorBlock rewrites on node-local rebuilds (mainnet: DAG+300 .. DAG+50,000; other
// networks never hit this). The order must be stable across a rebuild.
BOOST_AUTO_TEST_CASE(schema_v3_order_is_stable_across_a_dag_rebuild_below_dagknight)
{
    const bool fOldRegTest = fRegTest;
    const bool fOldTestNet = fTestNet;
    fRegTest = false;
    fTestNet = false;   // mainnet fork heights

    // The window this test exists for. If the ladder ever moves DAGKNIGHT to or below V3 the
    // overlap is gone and this case is redundant rather than wrong -- but say so out loud.
    BOOST_REQUIRE_MESSAGE(FORK_HEIGHT_EPOCH_STATE_V3 < FORK_HEIGHT_DAGKNIGHT,
                          "mainnet no longer orders any ColorBlock-coloured block by the "
                          "schema-V3 rule; this test no longer covers anything");

    const int nBase = FORK_HEIGHT_EPOCH_STATE_V3 + 100;
    BOOST_REQUIRE(nBase + 3 < FORK_HEIGHT_DAGKNIGHT);

    CBlockIndex* pOldBest = pindexBest;

    uint256 hParent(0x9db0001);
    uint256 hSiblingA(0x9db0002);
    uint256 hSiblingB(0x9db0003);
    uint256 hChild(0x9db0004);
    uint256 hMerge(0x9db0005);

    CBlockIndex parent;
    CBlockIndex siblingA;
    CBlockIndex siblingB;
    CBlockIndex child;
    CBlockIndex merge;
    parent.nHeight = nBase;
    siblingA.nHeight = nBase + 1;
    siblingB.nHeight = nBase + 1;
    child.nHeight = nBase + 2;
    merge.nHeight = nBase + 3;
    parent.pprev = NULL;
    siblingA.pprev = &parent;
    siblingB.pprev = &parent;
    child.pprev = &siblingA;
    merge.pprev = &child;
    // GetBlockTrust returns 0 for a zero target, which would leave every nDAGScore at 0 and
    // make the parent ranking below meaningless. Give each block a real compact target.
    parent.nBits = 0x1d00ffff;
    siblingA.nBits = 0x1d00ffff;
    siblingB.nBits = 0x1d00ffff;
    child.nBits = 0x1d00ffff;
    merge.nBits = 0x1d00ffff;

    mapBlockIndex[hParent] = &parent;
    mapBlockIndex[hSiblingA] = &siblingA;
    mapBlockIndex[hSiblingB] = &siblingB;
    mapBlockIndex[hChild] = &child;
    mapBlockIndex[hMerge] = &merge;
    parent.phashBlock = &mapBlockIndex.find(hParent)->first;
    siblingA.phashBlock = &mapBlockIndex.find(hSiblingA)->first;
    siblingB.phashBlock = &mapBlockIndex.find(hSiblingB)->first;
    child.phashBlock = &mapBlockIndex.find(hChild)->first;
    merge.phashBlock = &mapBlockIndex.find(hMerge)->first;

    std::vector<uint256> noParents;
    std::vector<uint256> ofParent(1, hParent);
    std::vector<uint256> ofSiblingA(1, hSiblingA);
    // Two committed parents, so GetDAGKnightSelectedParent has a real choice to make and the
    // walk can move if the scores it ranks them by move.
    std::vector<uint256> ofChildAndSiblingB;
    ofChildAndSiblingB.push_back(hChild);
    ofChildAndSiblingB.push_back(hSiblingB);

    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(&parent, noParents));
    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(&siblingA, ofParent));
    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(&siblingB, ofParent));
    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(&child, ofSiblingA));
    BOOST_REQUIRE(g_dagManager.InitBlockDAGData(&merge, ofChildAndSiblingB));

    // Node A: coloured block by block as each arrived, the way AddToBlockIndex does it.
    g_dagManager.ColorBlock(&parent);
    g_dagManager.ColorBlock(&siblingA);
    g_dagManager.ColorBlock(&siblingB);
    g_dagManager.ColorBlock(&child);
    g_dagManager.ColorBlock(&merge);

    pindexBest = &merge;

    CBlockDAGData dataMergeFresh;
    BOOST_REQUIRE(g_dagManager.GetDAGData(hMerge, dataMergeFresh));
    const std::vector<uint256> vOrderFresh =
        g_dagManager.GetDAGLinearOrder(hMerge, 0, true);
    // Anti-vacuity: an empty or degenerate order, or a zero score, would let the comparison
    // below pass without the shape ever reaching the code under test.
    BOOST_REQUIRE_MESSAGE(!vOrderFresh.empty(),
                          "the schema-V3 order came back empty, so this test compares nothing");
    BOOST_REQUIRE_MESSAGE(vOrderFresh.size() >= 4,
                          "the schema-V3 order did not take in the merge shape, so a stable "
                          "answer below would prove nothing");
    BOOST_REQUIRE_MESSAGE(std::find(vOrderFresh.begin(), vOrderFresh.end(), hMerge) !=
                              vOrderFresh.end() &&
                          std::find(vOrderFresh.begin(), vOrderFresh.end(), hSiblingB) !=
                              vOrderFresh.end(),
                          "the order is missing the merge or its second parent, so the "
                          "selected-parent choice was never exercised");
    BOOST_REQUIRE_MESSAGE(dataMergeFresh.nDAGScore != 0,
                          "arrival colouring left nDAGScore at zero, so the ranking this test "
                          "is about never happened");

    // Node B: same committed DAG, but a rebuild has run since -- a restart, or the tip-flood
    // timer in InitBlockDAGData firing more than 60s after the last one.
    g_dagManager.RebuildDAGOrder();

    CBlockDAGData dataMergeRebuilt;
    CBlockDAGData dataSiblingBRebuilt;
    BOOST_REQUIRE(g_dagManager.GetDAGData(hMerge, dataMergeRebuilt));
    BOOST_REQUIRE(g_dagManager.GetDAGData(hSiblingB, dataSiblingBRebuilt));
    // The rebuild has to have actually reached these blocks. nDAGOrder is -1 until one
    // assigns it, so this separates "the order survived a rebuild" from "no rebuild ran".
    BOOST_REQUIRE_MESSAGE(dataMergeRebuilt.nDAGOrder >= 0 &&
                              dataSiblingBRebuilt.nDAGOrder >= 0,
                          "the rebuild never reached this shape, so the two node states are not "
                          "actually different and the comparison below proves nothing");
    const std::vector<uint256> vOrderRebuilt =
        g_dagManager.GetDAGLinearOrder(hMerge, 0, true);
    BOOST_REQUIRE(!vOrderRebuilt.empty());

    BOOST_CHECK_MESSAGE(vOrderFresh == vOrderRebuilt,
                        "the schema-V3 epoch order changed when only node-local colouring state "
                        "changed: two nodes with the same blocks build different epoch block "
                        "lists, so their epoch digests differ and each rejects the other's "
                        "votes and tally certificates");

    // The score the walk ranks parents by must not move either -- an order that happens to
    // survive a score change on this shape would still split on another.
    BOOST_CHECK_MESSAGE(dataMergeFresh.nDAGScore == dataMergeRebuilt.nDAGScore,
                        "ColorBlock produced a different nDAGScore on rebuild than on arrival, "
                        "so GetDAGKnightSelectedParent ranks the same committed parents "
                        "differently depending on local rebuild history");

    g_dagManager.RemoveBlockDAGData(hMerge);
    g_dagManager.RemoveBlockDAGData(hChild);
    g_dagManager.RemoveBlockDAGData(hSiblingB);
    g_dagManager.RemoveBlockDAGData(hSiblingA);
    g_dagManager.RemoveBlockDAGData(hParent);
    mapBlockIndex.erase(hMerge);
    mapBlockIndex.erase(hChild);
    mapBlockIndex.erase(hSiblingB);
    mapBlockIndex.erase(hSiblingA);
    mapBlockIndex.erase(hParent);
    pindexBest = pOldBest;

    fRegTest = fOldRegTest;
    fTestNet = fOldTestNet;
}

// BuildEpochStateV2Compat reads node-local fBlue, so it must never own an epoch with
// DAG-era blocks. The margin is one block (the first post-DAG epoch crosses at
// FORK_HEIGHT_EPOCH_STATE_V3). Drives the three production gate predicates.

// Epoch boundaries are a pure function of the epoch number (GetEpochBoundaryHeight ignores
// its height argument), so an epoch's last height is well defined without a chain.
static int EpochEndHeightForTest(int nEpoch)
{
    return GetEpochBoundaryHeight(nEpoch + 1, 0) - 1;
}

static void CheckV2CompatEpochIsPreDAG(const std::string& strArm, const char* strSite,
                                       int nHeight, int nEpoch)
{
    BOOST_CHECK_MESSAGE(
        nEpoch >= 0,
        strArm + ": " + strSite + " selected epoch " + std::to_string(nEpoch) +
            " at height " + std::to_string(nHeight));
    const int nEpochEnd = EpochEndHeightForTest(nEpoch);
    BOOST_CHECK_MESSAGE(
        nEpochEnd < FORK_HEIGHT_DAG,
        strArm + ": " + strSite + " at height " + std::to_string(nHeight) +
            " hands epoch " + std::to_string(nEpoch) + " (ending at height " +
            std::to_string(nEpochEnd) + ") to BuildEpochStateV2Compat, which orders it "
            "by node-local fBlue -- that epoch contains DAG-era blocks and its digest "
            "is consensus");
}

BOOST_AUTO_TEST_CASE(v2compat_epoch_build_never_owns_a_dag_era_epoch)
{
    const bool fOldRegTest = fRegTest;
    const bool fOldTestNet = fTestNet;

    struct CNetworkArm { const char* strName; bool fRegTestArm; bool fTestNetArm; };
    const CNetworkArm arms[] = { { "mainnet", false, false },
                                 { "regtest", true,  false },
                                 { "testnet", false, true  } };

    for (size_t i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
    {
        fRegTest = arms[i].fRegTestArm;
        fTestNet = arms[i].fTestNetArm;
        const std::string strArm(arms[i].strName);

        const int nDAG = FORK_HEIGHT_DAG;
        const int nV2 = FORK_HEIGHT_EPOCH_STATE_V2;

        // No post-DAG epoch may end before the V2 schema starts, or the pre-V2 builder
        // would own a DAG-era epoch through the AddToBlockIndex path.
        BOOST_CHECK_MESSAGE(nV2 == nDAG,
                            strArm + ": schema V2 must start exactly at the DAG fork");

        if (!IsEpochStateV3Configured())
        {
            // Release blocker: with V3 unset, every post-DAG epoch is owned by the
            // fBlue builder. Only public testnet may sit here.
            BOOST_CHECK_MESSAGE(arms[i].fTestNetArm,
                                strArm + ": only public testnet may carry the V3 sentinel");
            const int nFirstPostDAGCrossing =
                GetEpochBoundaryHeight(GetEpochForHeight(nDAG) + 1, 0);
            int nEpochSentinel = -1;
            BOOST_CHECK_MESSAGE(
                V2CompatEpochStagesAtBestChainCrossing(nFirstPostDAGCrossing, nEpochSentinel) &&
                    EpochEndHeightForTest(nEpochSentinel) >= nDAG,
                strArm + ": sentinel arm expected the fBlue builder to still own the first "
                         "post-DAG epoch; if this stopped being true the sentinel branch is "
                         "stale and must be removed");
            continue;
        }

        BOOST_CHECK_MESSAGE(FORK_HEIGHT_EPOCH_STATE_V3 ==
                                nDAG + FINALITY_EPOCH_INTERVAL_POST_DAG,
                            strArm + ": schema V3 must activate on the first post-DAG epoch "
                                     "crossing, otherwise the legacy fBlue epoch build "
                                     "becomes consensus for the epochs in between");

        const int nFrom = std::max(1, nDAG - 3 * FINALITY_EPOCH_INTERVAL_PRE_DAG);
        const int nTo = nDAG + 3 * FINALITY_EPOCH_INTERVAL_POST_DAG;

        // Sites 1 and 2: AddToBlockIndex and SetBestChainInner, driven block by block
        // across the whole fork window.
        for (int nHeight = nFrom; nHeight <= nTo; nHeight++)
        {
            int nEpoch = -1;
            if (V2CompatEpochBuildsAtIndexCrossing(nHeight, nEpoch))
                CheckV2CompatEpochIsPreDAG(strArm, "AddToBlockIndex", nHeight, nEpoch);
            if (V2CompatEpochStagesAtBestChainCrossing(nHeight, nEpoch))
                CheckV2CompatEpochIsPreDAG(strArm, "SetBestChainInner", nHeight, nEpoch);
        }

        // Site 3: Reorganize, gated on a staged-epoch range. Sweep each epoch boundary in the
        // window, the block either side, and the fork and activation heights.
        std::vector<int> vProbe;
        vProbe.push_back(nDAG - 1);
        vProbe.push_back(nDAG);
        vProbe.push_back(nDAG + 1);
        vProbe.push_back(FORK_HEIGHT_EPOCH_STATE_V3 - 1);
        vProbe.push_back(FORK_HEIGHT_EPOCH_STATE_V3);
        vProbe.push_back(FORK_HEIGHT_EPOCH_STATE_V3 + 1);
        for (int nEpoch = GetEpochForHeight(nFrom); nEpoch <= GetEpochForHeight(nTo); nEpoch++)
        {
            const int nBoundary = GetEpochBoundaryHeight(nEpoch, 0);
            vProbe.push_back(nBoundary - 1);
            vProbe.push_back(nBoundary);
            vProbe.push_back(nBoundary + 1);
        }
        for (size_t a = 0; a < vProbe.size(); a++)
            for (size_t b = 0; b < vProbe.size(); b++)
                for (size_t c = 0; c < vProbe.size(); c++)
                {
                    const int nOldTip = vProbe[a];
                    const int nNewTip = vProbe[b];
                    const int nForkHeight = vProbe[c];
                    if (nOldTip < 1 || nNewTip < 1 || nForkHeight < 1)
                        continue;
                    // A reorg's common ancestor is at or below both tips.
                    if (nForkHeight > nOldTip || nForkHeight > nNewTip)
                        continue;

                    int nFirstEpoch = -1;
                    int nLastEpoch = -1;
                    if (!V2CompatReorgStagesEpochRange(nOldTip, nNewTip, nForkHeight,
                                                       nFirstEpoch, nLastEpoch))
                        continue;

                    // Every epoch the connect loop may stage must be pre-DAG. An empty
                    // range (first > last) stages nothing and is vacuously safe.
                    for (int nEpoch = nFirstEpoch; nEpoch <= nLastEpoch; nEpoch++)
                        CheckV2CompatEpochIsPreDAG(strArm, "Reorganize (staged range)",
                                                   nNewTip, nEpoch);

                    // And the per-block crossing predicate must not reach outside it.
                    for (size_t d = 0; d < vProbe.size(); d++)
                    {
                        const int nConnectHeight = vProbe[d];
                        if (nConnectHeight <= nForkHeight || nConnectHeight > nNewTip)
                            continue;
                        int nEpochAtCrossing = -1;
                        if (V2CompatEpochStagesAtReorgCrossing(nConnectHeight, nFirstEpoch,
                                                               nLastEpoch, nEpochAtCrossing))
                            CheckV2CompatEpochIsPreDAG(strArm, "Reorganize (connect loop)",
                                                       nConnectHeight, nEpochAtCrossing);
                    }
                }
    }

    fRegTest = fOldRegTest;
    fTestNet = fOldTestNet;
}

BOOST_AUTO_TEST_CASE(wallet_shielded_positions_use_active_block_prefix)
{
    CTransaction first;
    first.nVersion = SHIELDED_TX_VERSION;
    first.nLockTime = 801;
    first.vShieldedOutput.resize(2);

    CTransaction skipped;
    skipped.nVersion = SHIELDED_TX_VERSION;
    skipped.nLockTime = 802;
    skipped.vShieldedOutput.resize(7);

    CTransaction second;
    second.nVersion = SHIELDED_TX_VERSION;
    second.nLockTime = 803;
    second.vShieldedOutput.resize(3);

    CTransaction spendOnly;
    spendOnly.nVersion = SHIELDED_TX_VERSION;
    spendOnly.nLockTime = 804;

    CBlock block;
    block.vtx.push_back(first);
    block.vtx.push_back(skipped);
    block.vtx.push_back(second);
    block.vtx.push_back(spendOnly);

    std::set<uint256> skippedTransactions;
    skippedTransactions.insert(skipped.GetHash());
    std::vector<CWalletShieldedTxPosition> positions;
    std::string error;
    BOOST_REQUIRE(ComputeWalletShieldedTxPositions(
        block, skippedTransactions, 100, true, 200, positions, error));
    BOOST_REQUIRE_EQUAL(positions.size(), 3U);
    BOOST_CHECK_EQUAL(positions[0].hashTx.ToString(), first.GetHash().ToString());
    BOOST_CHECK_EQUAL(positions[0].nMerklePosition, 100U);
    BOOST_CHECK_EQUAL(positions[0].nCurveLeafPosition, 200U);
    BOOST_CHECK(positions[0].fHasCurveLeafPosition);
    BOOST_CHECK_EQUAL(positions[1].hashTx.ToString(), second.GetHash().ToString());
    BOOST_CHECK_EQUAL(positions[1].nMerklePosition, 102U);
    BOOST_CHECK_EQUAL(positions[1].nCurveLeafPosition, 202U);
    BOOST_CHECK_EQUAL(positions[2].hashTx.ToString(), spendOnly.GetHash().ToString());
    BOOST_CHECK_EQUAL(positions[2].nMerklePosition, 105U);
    BOOST_CHECK_EQUAL(positions[2].nCurveLeafPosition, 205U);
}

BOOST_AUTO_TEST_CASE(wallet_shielded_positions_reject_persisted_range_overflow)
{
    CTransaction tx;
    tx.nVersion = SHIELDED_TX_VERSION;
    tx.nLockTime = 901;
    tx.vShieldedOutput.resize(2);
    CBlock block;
    block.vtx.push_back(tx);

    std::vector<CWalletShieldedTxPosition> positions;
    std::string error;
    BOOST_CHECK(!ComputeWalletShieldedTxPositions(
        block, std::set<uint256>(),
        (uint64_t)std::numeric_limits<uint32_t>::max(),
        false, 0, positions, error));
    BOOST_CHECK(positions.empty());
    BOOST_CHECK(error.find("uint32") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(wallet_multiblock_disconnect_is_independent_of_final_tree)
{
    CTransaction firstTx;
    firstTx.nVersion = SHIELDED_TX_VERSION;
    firstTx.nLockTime = 1001;
    firstTx.vShieldedOutput.resize(1);
    CBlock firstBlock;
    firstBlock.nNonce = 1001;
    firstBlock.vtx.push_back(firstTx);

    CTransaction secondTx;
    secondTx.nVersion = SHIELDED_TX_VERSION;
    secondTx.nLockTime = 1002;
    secondTx.vShieldedOutput.resize(1);
    CBlock secondBlock;
    secondBlock.nNonce = 1002;
    secondBlock.vtx.push_back(secondTx);

    const uint256 firstBlockHash = firstBlock.GetHash();
    const uint256 secondBlockHash = secondBlock.GetHash();
    CBlockIndex firstIndex;
    CBlockIndex secondIndex;
    firstIndex.nHeight = FORK_HEIGHT_SHIELDED;
    secondIndex.nHeight = FORK_HEIGHT_SHIELDED + 1;
    firstIndex.phashBlock = &firstBlockHash;
    secondIndex.phashBlock = &secondBlockHash;

    CWallet wallet;
    CWallet::CShieldedWalletNote firstNote;
    firstNote.txhash = firstTx.GetHash();
    firstNote.nPosition = 1234;
    firstNote.nHeight = firstIndex.nHeight;
    CWallet::CShieldedWalletNote secondNote;
    secondNote.txhash = secondTx.GetHash();
    secondNote.nPosition = 987654;
    secondNote.nHeight = secondIndex.nHeight;
    CWallet::CShieldedWalletNote unrelatedNote;
    unrelatedNote.txhash = uint256(1003);
    unrelatedNote.nPosition = 42;
    CWallet::CShieldedWalletNote olderDuplicateTxNote;
    olderDuplicateTxNote.txhash = secondTx.GetHash();
    olderDuplicateTxNote.nPosition = 41;
    olderDuplicateTxNote.nHeight = firstIndex.nHeight - 1;
    wallet.vShieldedNotes.push_back(firstNote);
    wallet.vShieldedNotes.push_back(secondNote);
    wallet.vShieldedNotes.push_back(unrelatedNote);
    wallet.vShieldedNotes.push_back(olderDuplicateTxNote);

    // No shielded tree or per-block snapshot is installed.  This models replay
    // after a multi-block reorg has already left the new branch's final tree in
    // global storage; disconnect cleanup must use note identities only.
    const std::set<uint256> kNoDAGSkippedTxs;
    std::string error;
    BOOST_REQUIRE(wallet.DisconnectShieldedBlockRecoveryChecked(
        secondBlock, kNoDAGSkippedTxs, &secondIndex, error));
    BOOST_REQUIRE_EQUAL(wallet.vShieldedNotes.size(), 3U);
    BOOST_CHECK_EQUAL(wallet.vShieldedNotes[0].txhash.ToString(),
                      firstTx.GetHash().ToString());
    BOOST_CHECK_EQUAL(wallet.vShieldedNotes[1].txhash.ToString(),
                      unrelatedNote.txhash.ToString());
    BOOST_CHECK_EQUAL(wallet.vShieldedNotes[2].nHeight,
                      olderDuplicateTxNote.nHeight);

    // A crash after the Berkeley DB commit but before outbox acknowledgement
    // replays this exact block.  The second disconnect must be a no-op.
    BOOST_REQUIRE(wallet.DisconnectShieldedBlockRecoveryChecked(
        secondBlock, kNoDAGSkippedTxs, &secondIndex, error));
    BOOST_REQUIRE_EQUAL(wallet.vShieldedNotes.size(), 3U);

    BOOST_REQUIRE(wallet.DisconnectShieldedBlockRecoveryChecked(
        firstBlock, kNoDAGSkippedTxs, &firstIndex, error));
    BOOST_REQUIRE_EQUAL(wallet.vShieldedNotes.size(), 2U);
    BOOST_CHECK_EQUAL(wallet.vShieldedNotes[0].txhash.ToString(),
                      unrelatedNote.txhash.ToString());
    BOOST_CHECK_EQUAL(wallet.vShieldedNotes[1].nHeight,
                      olderDuplicateTxNote.nHeight);
}

BOOST_AUTO_TEST_CASE(anonymous_preimage_is_wallet_independent_and_bounded)
{
    CTransaction tx;
    tx.nVersion = ANON_TXN_VERSION;
    tx.nTime = 123456;
    tx.nLockTime = 99;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = uint256(77);
    tx.vin[0].prevout.n = ((uint32_t)MIN_RING_SIZE << 16) | 3;
    tx.vin[0].scriptSig.resize(
        2 + (size_t)MIN_RING_SIZE * ec_compressed_size, 0x42);
    tx.vout.push_back(CTxOut(10, CScript() << OP_TRUE));

    uint256 pureHash;
    BOOST_REQUIRE_EQUAL(GetAnonTxnPreImage(tx, pureHash), 0);

    CWallet wallet;
    uint256 compatibilityHash;
    BOOST_REQUIRE_EQUAL(wallet.GetTxnPreImage(tx, compatibilityHash), 0);
    BOOST_CHECK_EQUAL(pureHash.ToString(), compatibilityHash.ToString());

    tx.vin[0].scriptSig.resize(
        2 + (size_t)MIN_RING_SIZE * ec_compressed_size - 1);
    BOOST_CHECK_NE(GetAnonTxnPreImage(tx, pureHash), 0);
}


// R-EPV2-003. A V2-range epoch is staged inside the best-chain write batch, not
// built when the block index is inserted. The difference is which arrivals can
// move the canonical epoch cache: AddToBlockIndex runs for every block that
// arrives, side branches included, while the best-chain path runs only for the
// block that becomes the tip.
//
// On the ladder as configured the property holds for a stronger reason than the
// staging branch: there is no V2-range epoch to stage. Schema V2 starts at the
// DAG fork and schema V3 one post-DAG epoch above it, so the first epoch whose
// range reaches V2 is [DAG, DAG+300) and its crossing block lands on V3 itself,
// where both V2 predicates are already off. Every crossing below V3 therefore
// completes an epoch that ends below V2, and the index path only ever owns those.
// So this is what can honestly be executed: the index path never owns a V2-range
// epoch, the two predicates never claim the same crossing, and the staging branch
// they guard is unreached at the shipping gate values. The last of those is a
// tripwire -- move V3 off the first post-DAG epoch crossing and the staging path
// becomes live, at which point it needs a behavioural test rather than this one.
BOOST_AUTO_TEST_CASE(no_epoch_crossing_hands_a_v2_range_epoch_to_the_index_path)
{
    const bool fOldRegTest = fRegTest;
    const bool fOldTestNet = fTestNet;

    struct CNetworkArm { const char* strName; bool fRegTestArm; bool fTestNetArm; };
    const CNetworkArm arms[] = { { "mainnet", false, false },
                                 { "regtest", true,  false },
                                 { "testnet", false, true  } };

    int nIndexOwnedSeen = 0;
    int nStagedSeen = 0;
    int nNetworksSwept = 0;

    for (size_t i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
    {
        fRegTest = arms[i].fRegTestArm;
        fTestNet = arms[i].fTestNetArm;
        const std::string strArm(arms[i].strName);

        if (!IsEpochStateV3Configured())
            continue;               // covered by the sentinel arm of the case above

        const int nV2 = FORK_HEIGHT_EPOCH_STATE_V2;
        const int nV3 = FORK_HEIGHT_EPOCH_STATE_V3;
        BOOST_REQUIRE_MESSAGE(nV3 > nV2, strArm + ": the V2 range is empty");
        nNetworksSwept++;

        const int nFrom = std::max(1, nV2 - 3 * FINALITY_EPOCH_INTERVAL_PRE_DAG);
        for (int nHeight = nFrom; nHeight < nV3; nHeight++)
        {
            int nIndexEpoch = -1;
            int nStagedEpoch = -1;
            const bool fIndex = V2CompatEpochBuildsAtIndexCrossing(nHeight, nIndexEpoch);
            const bool fStaged =
                V2CompatEpochStagesAtBestChainCrossing(nHeight, nStagedEpoch);

            // No crossing may be owned twice: two owners is two writes of the same
            // epoch record, one of them reachable from a side branch.
            BOOST_REQUIRE_MESSAGE(!(fIndex && fStaged),
                                  strArm + ": height " + std::to_string(nHeight) +
                                      " is owned by both the index and the best-chain "
                                      "path");
            if (fStaged)
                nStagedSeen++;
            if (!fIndex)
                continue;

            nIndexOwnedSeen++;
            const int nEpochEnd = EpochEndHeightForTest(nIndexEpoch);
            BOOST_CHECK_MESSAGE(nEpochEnd < nV2,
                                strArm + ": the epoch ending at height " +
                                    std::to_string(nEpochEnd) +
                                    " reaches the V2 range but is built during "
                                    "block-index insertion, where a side-branch "
                                    "arrival reaches it");
        }
    }

    fRegTest = fOldRegTest;
    fTestNet = fOldTestNet;

    BOOST_REQUIRE_MESSAGE(nNetworksSwept > 0, "no network had schema V3 configured");
    BOOST_CHECK_MESSAGE(nIndexOwnedSeen > 0,
                        "no epoch crossing was reached on any network, so the loop "
                        "asserted nothing");
    BOOST_CHECK_MESSAGE(nStagedSeen == 0,
                        "the V2 best-chain staging branch is now reachable ("
                            << nStagedSeen << " crossing(s)); it needs a behavioural "
                            "test of its own, because this case only says it is not "
                            "reached");
namespace
uint256 TestDAGParentHash(unsigned int i)
    return uint256(1000 + i);
}

// Same payload layout and push encoding BuildDAGParentScript emits, with the
// count free so a value the builder refuses can still be handed to a decoder.
CScript MakeIDAGCommitmentScript(unsigned int nCount)
    std::vector<unsigned char> vchData;
    vchData.insert(vchData.end(), DAG_PARENT_TAG, DAG_PARENT_TAG + 4);
    vchData.push_back((unsigned char)nCount);
    for (unsigned int i = 0; i < nCount; i++)
        const uint256 hash = TestDAGParentHash(i);
        const unsigned char* p = hash.begin();
        vchData.insert(vchData.end(), p, p + 32);
    CScript script;
    script << OP_RETURN << vchData;
    return script;
} // namespace

// The parent cap belongs to the decoder, not to AcceptBlock: AcceptBlock only
// ever sees the set a decoder returned, so the count check is what has to hold.
BOOST_AUTO_TEST_CASE(dag_parent_commitment_cap_is_enforced_by_the_canonical_decoder)
    const unsigned int nCap = (unsigned int)MAX_DAG_PARENTS;

    // At the cap the canonical decoder accepts and returns the whole set.
        const CScript script = MakeIDAGCommitmentScript(nCap);
        std::vector<uint256> vParents;
        std::string strError;
        BOOST_CHECK_EQUAL((int)DecodeCanonicalDAGParentScript(script, vParents, strError),
                          (int)DAG_PARENT_VALID);
        BOOST_CHECK_EQUAL(vParents.size(), nCap);

    // Past the cap, up to the widest count the one-byte field can name.
    const unsigned int vOversized[] = { nCap + 1, nCap + 2, nCap + 3, 64, 65, 255 };
    for (unsigned int nCount : vOversized)
        const CScript script = MakeIDAGCommitmentScript(nCount);
                          (int)DAG_PARENT_MALFORMED);
        BOOST_CHECK(vParents.empty());
        // Assert the count as the rejection reason: the re-encode comparison also fails on an
        // oversized commitment and would mask the cap.
        BOOST_CHECK(strError.find("parent count") != std::string::npos);

        // The whole-coinbase extractor AcceptBlock calls refuses it too.
        std::vector<CScript> vScripts;
        vScripts.push_back(CScript() << OP_TRUE);
        vScripts.push_back(script);
        std::vector<uint256> vExtracted;
        std::string strExtractError;
        BOOST_CHECK(!ExtractCanonicalDAGParentCommitment(vScripts, vExtracted, strExtractError));
        BOOST_CHECK(vExtracted.empty());

    // The builder refuses to emit an oversized commitment, so a producer taking
    // the ordinary path cannot create one either.
        std::vector<uint256> vTooMany;
        for (unsigned int i = 0; i <= nCap; i++)
            vTooMany.push_back(TestDAGParentHash(i));
        BOOST_CHECK(BuildDAGParentScript(vTooMany).empty());

// From the POEM height a block contributes its entropy weight to chain trust,
// not the inverse-target work value. The two are different numbers for the same
// block, so a node still on the old form ranks branches differently.
BOOST_AUTO_TEST_CASE(chain_trust_is_the_poem_entropy_weight_from_the_gate)
    const bool fSavedRegTest = fRegTest;
    const bool fSavedTestNet = fTestNet;
    struct Restore
        bool fRegTestSaved, fTestNetSaved;
        ~Restore() { fRegTest = fRegTestSaved; fTestNet = fTestNetSaved; }
    } restore = { fSavedRegTest, fSavedTestNet };
    fRegTest = false;
    fTestNet = false;

    const unsigned int nBits = 0x1d00ffff;
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);
    const uint256 nWorkValue = ((CBigNum(1) << 256) / (bnTarget + 1)).getuint256();

    const uint256 hashBlock("0x00000000000000009051f1e2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6");
    CBlockIndex index;
    index.nHeight = FORK_HEIGHT_POEM;
    index.nBits = nBits;
    index.nFlags = 0;                 // proof of work
    index.phashBlock = &hashBlock;
    BOOST_REQUIRE(!index.IsProofOfStake());

    const uint256 nEntropy = GetBlockEntropy(hashBlock);
    // The two forms have to disagree for this block, or the assertion below
    // would hold whichever branch ran.
    BOOST_REQUIRE(nEntropy != nWorkValue);

    BOOST_CHECK(index.GetBlockTrust() == nEntropy);

    // One block below the gate the old inverse-target value is still what the
    // already-connected history was ranked by.
    index.nHeight = FORK_HEIGHT_POEM - 1;
    BOOST_REQUIRE(index.nHeight < FORK_HEIGHT_DAG);
    BOOST_CHECK(index.GetBlockTrust() == nWorkValue);

// The pre-Boundary-A decoder reads its payload through CScript::GetOp, which
// refuses any push above MAX_SCRIPT_ELEMENT_SIZE. Below Boundary A the parent
// count is therefore ceilinged by the script element size well before
// MAX_DAG_PARENTS is reached, and a commitment naming more simply decodes to
// nothing. Pinned because the two eras do not share a ceiling.
BOOST_AUTO_TEST_CASE(pre_boundary_a_parent_count_is_ceilinged_by_the_script_element_size)
    const unsigned int nElementCeiling = (MAX_SCRIPT_ELEMENT_SIZE - 5) / 32;
    BOOST_REQUIRE(nElementCeiling < (unsigned int)MAX_DAG_PARENTS);

    BOOST_CHECK_EQUAL(ExtractDAGParents(MakeIDAGCommitmentScript(nElementCeiling)).size(),
                      nElementCeiling);
    BOOST_CHECK(ExtractDAGParents(MakeIDAGCommitmentScript(nElementCeiling + 1)).empty());

    // Whatever the count byte names, the legacy path never yields more than the
    // consensus maximum.
    for (unsigned int nCount = 1; nCount <= 255; nCount++)
        BOOST_CHECK(ExtractDAGParents(MakeIDAGCommitmentScript(nCount)).size()
                        <= (size_t)MAX_DAG_PARENTS);
}

BOOST_AUTO_TEST_SUITE_END()
