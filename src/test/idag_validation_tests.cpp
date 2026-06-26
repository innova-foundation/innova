#include <boost/test/unit_test.hpp>

#include "../dag.h"
#include "../finality.h"
#include "../main.h"

BOOST_AUTO_TEST_SUITE(idag_validation_tests)

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

BOOST_AUTO_TEST_SUITE_END()
