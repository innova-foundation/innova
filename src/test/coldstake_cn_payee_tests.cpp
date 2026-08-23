// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Behavioural cover for the cold-stake collateralnode payee check in ConnectBlock.
//
// The expected payee is read from the gossiped winner schedule and the gossiped
// collateralnode list. Neither is derivable from the chain: the schedule is
// relayed and pruned, and the list is empty until peers answer a list request. So
// the same block gets different answers on different nodes, and the rejection may
// never be written into the block index -- BLOCK_FAILED_VALID is serialized and
// cleared only by reconsiderblock.
//
// Unlike the two payment-rule sites (unreachable on every test network, see
// cn_payment_verdict_tests), this one activates at height 1 on regtest, so the
// path is driven end to end here: a real chain, a real P2CS delegation, a real
// cold-stake coinstake carrying a payment to a payee this node has not heard of,
// and a real ConnectBlock. The three arms connect the same block bytes every
// time; only the node-local state around it changes.

#include <boost/test/unit_test.hpp>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "../collateralnode.h"
#include "../key.h"
#include "../main.h"
#include "../miner.h"
#include "../script.h"
#include "../txdb.h"
#include "../util.h"
#include "../wallet.h"

extern CWallet* pwalletMain;

BOOST_AUTO_TEST_SUITE(coldstake_cn_payee_tests)

namespace {

// Restores the gossiped collateralnode list on scope exit. Every arm below edits
// it, and the rest of the binary must not see the edits.
struct CollateralnodeViewGuard
{
    std::vector<CCollateralNode> vSaved;
    CollateralnodeViewGuard()
    {
        LOCK(cs_collateralnodes);
        vSaved = vecCollateralnodes;
        vecCollateralnodes.clear();
    }
    ~CollateralnodeViewGuard()
    {
        LOCK(cs_collateralnodes);
        vecCollateralnodes = vSaved;
    }
};

// Restores the mocked clock on scope exit.
struct MockClockGuard
{
    ~MockClockGuard() { SetMockTime(0); }
};

// The suite mines real blocks. A registered wallet would record their coinbases
// and the funding transaction, moving the ordering counters other suites pin.
struct DetachedWalletGuard
{
    DetachedWalletGuard() { UnregisterWallet(pwalletMain); }
    ~DetachedWalletGuard() { RegisterWallet(pwalletMain); }
};

CScript PayToKey(const CKey& key)
{
    CScript script;
    script.SetDestination(key.GetPubKey().GetID());
    return script;
}

// A collateralnode this node has heard of, paying to key.
void AnnounceCollateralnode(const CKey& key, bool fEnabled)
{
    CService addr;
    CTxIn vin;
    std::vector<unsigned char> sig;
    CCollateralNode mn(addr, vin, key.GetPubKey(), sig, GetTime(),
                       key.GetPubKey(), PROTOCOL_VERSION);
    mn.enabled = fEnabled ? 1 : 0;
    LOCK(cs_collateralnodes);
    vecCollateralnodes.push_back(mn);
}

void ClearCollateralnodeView()
{
    LOCK(cs_collateralnodes);
    vecCollateralnodes.clear();
}

// Seal a template that the caller has already filled, and put it on the chain.
// IncrementExtraNonce rebuilds the merkle tree, so it runs after the extra
// transactions are appended.
bool SealAndProcess(CBlock* pblock, CBlockIndex* pindexParent)
{
    unsigned int nExtraNonce = 0;
    IncrementExtraNonce(pblock, pindexParent, nExtraNonce);

    CBigNum target;
    target.SetCompact(pblock->nBits);
    const uint256 hashTarget = target.getuint256();
    unsigned int nHashes = 0;
    while (pblock->GetPoWHash() > hashTarget)
    {
        ++pblock->nNonce;
        if (pblock->nNonce == 0)
            ++pblock->nTime;
        if (++nHashes > 2000000U)
            return false;
    }
    return ProcessBlock(NULL, pblock);
}

CBlockIndex* ParentOf(const CBlock& block)
{
    LOCK(cs_main);
    std::map<uint256, CBlockIndex*>::const_iterator mi =
        mapBlockIndex.find(block.hashPrevBlock);
    return mi == mapBlockIndex.end() ? NULL : mi->second;
}

// One empty proof-of-work block on the tip, returned so the caller can spend its
// coinbase later.
bool MineOneBlock(CBlock& blockOut)
{
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    if (pblock.get() == NULL)
        return false;
    CBlockIndex* pindexParent = ParentOf(*pblock);
    if (pindexParent == NULL)
        return false;
    if (!SealAndProcess(pblock.get(), pindexParent))
        return false;
    blockOut = *pblock;
    return true;
}

// A block carrying one transaction the caller builds against the template's own
// header time. The mempool is not used: CTxMemPool::accept dereferences the name
// hooks, which the unit-test harness never installs.
bool MineBlockWithFunding(const CTransaction& txCoinbasePrev, const CScript& p2csScript,
                          const CScript& plainScript, int64_t nLegValue,
                          CTransaction& txFundOut)
{
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    if (pblock.get() == NULL)
        return false;
    CBlockIndex* pindexParent = ParentOf(*pblock);
    if (pindexParent == NULL)
        return false;

    const int64_t nIn = txCoinbasePrev.vout[0].nValue;
    if (nIn < 3 * nLegValue)
        return false;

    CTransaction txFund;
    txFund.nTime = pblock->nTime;
    txFund.vin.push_back(CTxIn(txCoinbasePrev.GetHash(), 0));
    txFund.vout.push_back(CTxOut(nLegValue, p2csScript));
    txFund.vout.push_back(CTxOut(nLegValue, plainScript));
    txFund.vout.push_back(CTxOut(nIn - 2 * nLegValue - CENT, plainScript));
    if (!SignSignature(*pwalletMain, txCoinbasePrev, txFund, 0, SIGHASH_ALL))
        return false;

    pblock->vtx.push_back(txFund);
    if (!SealAndProcess(pblock.get(), pindexParent))
        return false;
    txFundOut = txFund;
    return true;
}

// Cold-stake coinstake spending one P2CS and one plain output; the last, non-P2CS
// output pays payeeScript (the collateralnode payment). The plain input funds the
// whole reward, so the coinstake mints nothing and needs no coin age.
struct ColdStakeBlock
{
    CBlock block;
    uint256 hash;
    int nHeight;
    CBlockIndex index;

    CBlockIndex* Index() { return &index; }
};

bool BuildColdStakeBlock(const CTransaction& txFund, unsigned int nP2CSOut,
                         unsigned int nPlainOut, const CScript& p2csScript,
                         const CScript& payeeScript, ColdStakeBlock& out)
{
    CBlockIndex* pindexPrev = pindexBest;
    if (pindexPrev == NULL)
        return false;
    const int64_t nBlockTime = pindexPrev->GetBlockTime() + 1;

    const int64_t nP2CSIn = txFund.vout[nP2CSOut].nValue;
    const int64_t nPlainIn = txFund.vout[nPlainOut].nValue;
    const int64_t nCNPayment = nPlainIn / 10;
    if (nCNPayment <= 0)
        return false;

    CTransaction txStake;
    txStake.nTime = (unsigned int)nBlockTime;
    txStake.vin.push_back(CTxIn(txFund.GetHash(), nP2CSOut));
    txStake.vin.push_back(CTxIn(txFund.GetHash(), nPlainOut));
    txStake.vout.push_back(CTxOut());
    txStake.vout[0].SetEmpty();
    txStake.vout.push_back(CTxOut(nP2CSIn + nPlainIn - nCNPayment, p2csScript));
    txStake.vout.push_back(CTxOut(nCNPayment, payeeScript));

    if (!SignSignature(*pwalletMain, txFund, txStake, 0, SIGHASH_ALL))
        return false;
    if (!SignSignature(*pwalletMain, txFund, txStake, 1, SIGHASH_ALL))
        return false;
    if (!txStake.IsCoinStake())
        return false;

    out.nHeight = pindexPrev->nHeight + 1;

    CTransaction txCoinBase;
    txCoinBase.nTime = (unsigned int)nBlockTime;
    txCoinBase.vin.resize(1);
    txCoinBase.vin[0].prevout.SetNull();
    txCoinBase.vin[0].scriptSig = CScript() << out.nHeight << CBigNum(1);
    txCoinBase.vout.resize(1);
    txCoinBase.vout[0].SetEmpty();

    out.block.SetNull();
    out.block.nVersion = CBlock::CURRENT_VERSION;
    out.block.hashPrevBlock = pindexPrev->GetBlockHash();
    out.block.nTime = (unsigned int)nBlockTime;
    out.block.nBits = GetNextTargetRequired(pindexPrev, true);
    out.block.nNonce = 0;
    out.block.vtx.push_back(txCoinBase);
    out.block.vtx.push_back(txStake);
    out.block.hashMerkleRoot = out.block.BuildMerkleTree();

    out.hash = out.block.GetHash();
    out.index = CBlockIndex(0, 0, out.block);
    out.index.pprev = pindexPrev;
    out.index.nHeight = out.nHeight;
    out.index.phashBlock = &out.hash;
    return out.block.IsProofOfStake();
}

// Connect and hand back the verdict, discarding every write. The accepted arms
// would otherwise spend the funding outputs for the rest of the binary.
CBlock::ConnectResult ConnectAndRollBack(ColdStakeBlock& cs)
{
    LOCK(cs_main);
    CTxDB txdb;
    CBlock::ConnectResult result = CBlock::CONNECT_RESULT_INVALID;
    // Without an open batch the writes would land, so this is not optional.
    BOOST_REQUIRE(txdb.TxnBegin());
    const bool fConnected = cs.block.ConnectBlock(txdb, cs.Index(), false, false, &result);
    BOOST_REQUIRE(txdb.TxnAbort());
    BOOST_CHECK_EQUAL(fConnected, result == CBlock::CONNECT_RESULT_OK);
    return result;
}

} // namespace

// The gate. It is the payment rule's window applied to the payee check, so a block
// old enough that no node can still resolve its payee is not judged on the payee
// at all -- which is what stops a refusal from being retried forever.
BOOST_AUTO_TEST_CASE(the_payee_check_runs_only_inside_the_node_local_window)
{
    const int nSaved = nCoinbaseMaturity;
    nCoinbaseMaturity = 65;
    const int64_t nWindow = CollateralnodePaymentWindowSeconds();
    const int64_t nBlockTime = 1750000000;
    const int nHeight = FORK_HEIGHT_CN_PAYMENT_VALIDATION + 10;

    BOOST_CHECK(ColdStakeCNPayeeRuleApplies(false, nHeight, 1, nBlockTime, nBlockTime));

    // No payment output, nothing to judge.
    BOOST_CHECK(!ColdStakeCNPayeeRuleApplies(false, nHeight, 0, nBlockTime, nBlockTime));

    // Before the fork height the rule does not exist.
    BOOST_CHECK(!ColdStakeCNPayeeRuleApplies(false, FORK_HEIGHT_CN_PAYMENT_VALIDATION - 1,
                                             1, nBlockTime, nBlockTime));

    // A re-check that is not connecting the block never judges the payee.
    BOOST_CHECK(!ColdStakeCNPayeeRuleApplies(true, nHeight, 1, nBlockTime, nBlockTime));

    // The last clock reading that still judges it, and the first that does not.
    BOOST_CHECK(ColdStakeCNPayeeRuleApplies(false, nHeight, 1, nBlockTime,
                                            nBlockTime + nWindow - 1));
    BOOST_CHECK(!ColdStakeCNPayeeRuleApplies(false, nHeight, 1, nBlockTime,
                                             nBlockTime + nWindow));

    // Past some clock reading the rule stops applying, so a transient refusal
    // cannot become an unbounded re-download loop on nodes that never learn the payee.
    BOOST_CHECK(!ColdStakeCNPayeeRuleApplies(false, nHeight, 1, nBlockTime,
                                             nBlockTime + nWindow + 86400));

    nCoinbaseMaturity = nSaved;
}

// The verdict is read out of state the chain does not carry. Same height, same
// script, two answers -- which is what makes persisting it a permanent split.
BOOST_AUTO_TEST_CASE(the_payee_verdict_is_read_from_gossiped_state)
{
    CollateralnodeViewGuard guard;

    CKey payeeKey;
    payeeKey.MakeNewKey(true);
    const CScript payeeScript = PayToKey(payeeKey);
    const int nHeight = FORK_HEIGHT_CN_PAYMENT_VALIDATION + 10;

    BOOST_CHECK_MESSAGE(!ColdStakeCNPayeeIsRegistered(nHeight, payeeScript),
                        "a node that has not yet received a collateralnode list "
                        "recognises no payee -- the state of every node for the "
                        "first minutes after start-up");

    // A disabled entry is not a registration.
    AnnounceCollateralnode(payeeKey, false);
    BOOST_CHECK(!ColdStakeCNPayeeIsRegistered(nHeight, payeeScript));

    ClearCollateralnodeView();
    AnnounceCollateralnode(payeeKey, true);
    BOOST_CHECK_MESSAGE(ColdStakeCNPayeeIsRegistered(nHeight, payeeScript),
                        "the same height and the same script now resolve -- "
                        "nothing about the block changed, only what this node "
                        "has heard");

    // Another node's payee is still not this one's.
    CKey otherKey;
    otherKey.MakeNewKey(true);
    BOOST_CHECK(!ColdStakeCNPayeeIsRegistered(nHeight, PayToKey(otherKey)));
}

// Connect the same cold-stake block three times, changing only node-local state:
// unknown payee in window -> transient refusal; payee announced -> connects;
// clock past window -> connects.
BOOST_AUTO_TEST_CASE(a_gossip_derived_refusal_is_never_persistable)
{
    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(pindexBest != NULL);
    BOOST_REQUIRE(FORK_HEIGHT_CN_PAYMENT_VALIDATION <= 1);
    BOOST_REQUIRE_MESSAGE(pindexBest->nHeight + 6 < FORK_HEIGHT_DAG,
                          "the cold-stake payee check sits on the proof-of-stake "
                          "path, which ends at the DAG fork; this suite must run "
                          "before anything mines past it");

    CollateralnodeViewGuard guard;
    MockClockGuard clockGuard;
    DetachedWalletGuard walletGuard;

    // The staker signs the coinstake, the owner holds the coins, and the payee is
    // whoever the block claims is a collateralnode.
    CKey stakerKey, ownerKey, payeeKey;
    stakerKey.MakeNewKey(true);
    ownerKey.MakeNewKey(true);
    payeeKey.MakeNewKey(true);
    BOOST_REQUIRE(pwalletMain->AddKey(stakerKey));
    BOOST_REQUIRE(pwalletMain->AddKey(ownerKey));

    const CScript p2csScript = GetScriptForColdStaking(stakerKey.GetPubKey().GetID(),
                                                       ownerKey.GetPubKey().GetID());
    BOOST_REQUIRE(IsPayToColdStaking(p2csScript));
    const CScript ownerScript = PayToKey(ownerKey);
    const CScript payeeScript = PayToKey(payeeKey);

    // Enough blocks for one coinbase to mature, with room left under the DAG fork.
    CBlock blockFirst;
    BOOST_REQUIRE_MESSAGE(MineOneBlock(blockFirst), "failed to mine regtest block 0");
    for (int i = 1; i < 4; i++)
    {
        CBlock block;
        BOOST_REQUIRE_MESSAGE(MineOneBlock(block), "failed to mine regtest block " << i);
    }

    // One transaction funding both legs: the delegation, and the plain output that
    // pays for the collateralnode payment.
    CTransaction txFund;
    BOOST_REQUIRE_MESSAGE(MineBlockWithFunding(blockFirst.vtx[0], p2csScript,
                                               ownerScript, 2 * COIN, txFund),
                          "could not fund the cold-stake delegation");

    ColdStakeBlock cs;
    BOOST_REQUIRE_MESSAGE(BuildColdStakeBlock(txFund, 0, 1, p2csScript, payeeScript, cs),
                          "could not build the cold-stake block");
    BOOST_REQUIRE(cs.nHeight < FORK_HEIGHT_DAG);

    // Pin the clock inside the window, so the rule is live for the first two arms.
    SetMockTime(cs.block.GetBlockTime());
    BOOST_REQUIRE(ColdStakeCNPayeeRuleApplies(false, cs.nHeight, 1,
                                              cs.block.GetBlockTime(), GetTime()));

    // Arm 1: payee unknown to this node. Must be transient, not DoS(100), which
    // would persist BLOCK_FAILED_VALID.
    BOOST_REQUIRE(!ColdStakeCNPayeeIsRegistered(cs.nHeight, payeeScript));
    const CBlock::ConnectResult refused = ConnectAndRollBack(cs);
    BOOST_CHECK_MESSAGE(refused == CBlock::CONNECT_RESULT_TRANSIENT,
                        "a payee this node has not heard of must produce a "
                        "transient refusal, got result " << (int)refused);
    BOOST_CHECK_MESSAGE(!ConnectResultMayPersistVerdict(refused),
                        "the refusal reached SetFailedValid(); one unsynced "
                        "collateralnode list would then permanently condemn a "
                        "block the rest of the network accepted");

    // Arm 2: nothing about the block changes; this node simply hears about the
    // payee. The same bytes now connect -- the split stated as an experiment.
    AnnounceCollateralnode(payeeKey, true);
    BOOST_REQUIRE(ColdStakeCNPayeeIsRegistered(cs.nHeight, payeeScript));
    const CBlock::ConnectResult announced = ConnectAndRollBack(cs);
    BOOST_CHECK_MESSAGE(announced == CBlock::CONNECT_RESULT_OK,
                        "the same block must connect once the payee is known, "
                        "got result " << (int)announced);

    // Arm 3: the payee is unknown again and the clock has moved past the window.
    // A node that never resolves the payee stops refusing the block instead of
    // re-downloading it forever.
    ClearCollateralnodeView();
    BOOST_REQUIRE(!ColdStakeCNPayeeIsRegistered(cs.nHeight, payeeScript));
    SetMockTime(cs.block.GetBlockTime() + CollateralnodePaymentWindowSeconds() + 60);
    BOOST_REQUIRE(!ColdStakeCNPayeeRuleApplies(false, cs.nHeight, 1,
                                               cs.block.GetBlockTime(), GetTime()));
    const CBlock::ConnectResult aged = ConnectAndRollBack(cs);
    BOOST_CHECK_MESSAGE(aged == CBlock::CONNECT_RESULT_OK,
                        "a block past the window must not be judged on a payee no "
                        "node can still resolve, got result " << (int)aged);
}

BOOST_AUTO_TEST_SUITE_END()
