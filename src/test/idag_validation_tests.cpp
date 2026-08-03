#include <boost/test/unit_test.hpp>

#include "../dag.h"
#include "../finality.h"
#include "../main.h"
#include "../txdb.h"
#include "../wallet.h"

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
    std::string error;
    BOOST_REQUIRE(wallet.DisconnectShieldedBlockRecoveryChecked(
        secondBlock, &secondIndex, error));
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
        secondBlock, &secondIndex, error));
    BOOST_REQUIRE_EQUAL(wallet.vShieldedNotes.size(), 3U);

    BOOST_REQUIRE(wallet.DisconnectShieldedBlockRecoveryChecked(
        firstBlock, &firstIndex, error));
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

BOOST_AUTO_TEST_SUITE_END()
