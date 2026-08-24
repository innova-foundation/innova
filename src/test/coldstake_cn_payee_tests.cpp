// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Behavioural cover for the cold-stake branch of ConnectBlock: the gate, the
// repayment floor, the collateralnode payment cap, and the payee check.
//
// The payee half. The expected payee is read from the gossiped winner schedule
// and the gossiped collateralnode list. Neither is derivable from the chain: the
// schedule is relayed and pruned, and the list is empty until peers answer a list
// request. So the same block gets different answers on different nodes, and the
// rejection may never be written into the block index -- BLOCK_FAILED_VALID is
// serialized and cleared only by reconsiderblock.
//
// Unlike the two payment-rule sites (unreachable on every test network, see
// cn_payment_verdict_tests), this one activates at height 1 on regtest, so the
// path is driven end to end here: a real chain, a real P2CS delegation, a real
// cold-stake coinstake carrying a payment to a payee this node has not heard of,
// and a real ConnectBlock. The three arms connect the same block bytes every
// time; only the node-local state around it changes.
//
// The value half. OP_CHECKCOLDSTAKEVERIFY enforces its own copy of the output
// structure and its own collateralnode-payment cap, and the interpreter runs
// first, so a case has to prove which of the two refused the block. Every arm
// below therefore calls VerifySignature on the same coinstake it hands to
// ConnectBlock and asserts the interpreter's answer: where the interpreter
// accepts, the ConnectBlock clause is the sole enforcer and the arm covers it;
// where the interpreter refuses, the arm says so and claims nothing.
//
// The window this branch governs is [FORK_HEIGHT_COLD_STAKING, FORK_HEIGHT_DAG),
// because no coinstake of any shape connects at or above the DAG fork. On
// mainnet that is 8,070,000 to 8,220,000, plus every later replay of it. On
// regtest the DAG fork is height 11, which is the whole block budget this suite
// has to build in -- hence one shared funding transaction rather than one per
// case.

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

// Restores the cold-staking rehearsal height on scope exit. Moving it moves the
// gate for the whole binary, including GetCurrentCollateralNode's score width.
struct ColdStakingGateGuard
{
    int nSaved;
    ColdStakingGateGuard() : nSaved(nRegtestColdStakingHeight) {}
    ~ColdStakingGateGuard() { nRegtestColdStakingHeight = nSaved; }
};

// The network flags are read by the gate helper itself, so the mainnet and
// testnet answers are observed rather than restated.
struct NetworkGuard
{
    bool fRegSaved, fTestSaved;
    NetworkGuard() : fRegSaved(fRegTest), fTestSaved(fTestNet) {}
    ~NetworkGuard() { fRegTest = fRegSaved; fTestNet = fTestSaved; }
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

// The legs of the shared funding transaction. Named rather than numbered so a
// case reads as the delegation it spends instead of as an index.
enum FundingLeg
{
    LEG_P2CS_SMALL = 0,   //  2 INN delegated, for the payee arms
    LEG_PLAIN_SMALL = 1,  //  2 INN, funds the payee arms' reward
    LEG_P2CS_LARGE = 2,   // 10 INN delegated, for the value arms
    LEG_PLAIN_ONE = 3,    //  1 INN, funds the value arms' reward
    LEG_PLAIN_SPARE = 4,  //  2 INN, spent by the gate arm's plain-input coinstake
    LEG_CHANGE = 5
};

const int64_t nLegValues[LEG_CHANGE] = { 2 * COIN, 2 * COIN, 10 * COIN,
                                         1 * COIN, 2 * COIN };

// A block carrying one transaction the caller builds against the template's own
// header time. The mempool is not used: CTxMemPool::accept dereferences the name
// hooks, which the unit-test harness never installs.
bool MineBlockWithFunding(const CTransaction& txCoinbasePrev, const CScript& p2csScript,
                          const CScript& plainScript, CTransaction& txFundOut)
{
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    if (pblock.get() == NULL)
        return false;
    CBlockIndex* pindexParent = ParentOf(*pblock);
    if (pindexParent == NULL)
        return false;

    int64_t nLegTotal = 0;
    for (int i = 0; i < (int)LEG_CHANGE; i++)
        nLegTotal += nLegValues[i];

    const int64_t nIn = txCoinbasePrev.vout[0].nValue;
    if (nIn < nLegTotal + CENT)
        return false;

    CTransaction txFund;
    txFund.nTime = pblock->nTime;
    txFund.vin.push_back(CTxIn(txCoinbasePrev.GetHash(), 0));
    txFund.vout.push_back(CTxOut(nLegValues[LEG_P2CS_SMALL], p2csScript));
    txFund.vout.push_back(CTxOut(nLegValues[LEG_PLAIN_SMALL], plainScript));
    txFund.vout.push_back(CTxOut(nLegValues[LEG_P2CS_LARGE], p2csScript));
    txFund.vout.push_back(CTxOut(nLegValues[LEG_PLAIN_ONE], plainScript));
    txFund.vout.push_back(CTxOut(nLegValues[LEG_PLAIN_SPARE], plainScript));
    txFund.vout.push_back(CTxOut(nIn - nLegTotal - CENT, plainScript));
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

// Coinstake spending the funding legs to the given outputs, in a PoS block on the
// tip. Signed last, so a tampered output set still carries valid scriptSigs.
bool BuildStakeBlock(const CTransaction& txFund,
                     const std::vector<unsigned int>& vLegs,
                     const std::vector<CTxOut>& vOutputs,
                     ColdStakeBlock& out)
{
    CBlockIndex* pindexPrev = pindexBest;
    if (pindexPrev == NULL || vLegs.empty() || vOutputs.empty())
        return false;
    const int64_t nBlockTime = pindexPrev->GetBlockTime() + 1;

    CTransaction txStake;
    txStake.nTime = (unsigned int)nBlockTime;
    for (size_t i = 0; i < vLegs.size(); i++)
        txStake.vin.push_back(CTxIn(txFund.GetHash(), vLegs[i]));
    txStake.vout.push_back(CTxOut());
    txStake.vout[0].SetEmpty();
    for (size_t i = 0; i < vOutputs.size(); i++)
        txStake.vout.push_back(vOutputs[i]);

    for (unsigned int i = 0; i < txStake.vin.size(); i++)
        if (!SignSignature(*pwalletMain, txFund, txStake, i, SIGHASH_ALL))
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

// Whether the script interpreter -- which runs before the cold-stake branch, on
// the same coinstake -- accepts the delegation input. The flags are the ones
// ConnectBlock computes at or above FORK_HEIGHT_TIGHTER_DRIFT, which on regtest
// is every height. A value arm is only cover for ConnectBlock's clause if this
// answers true.
bool InterpreterAcceptsLeg(const CTransaction& txFund, const ColdStakeBlock& cs,
                           unsigned int nIn)
{
    const unsigned int flags = MANDATORY_SCRIPT_VERIFY_FLAGS |
                               SCRIPT_VERIFY_STRICTENC |
                               SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    return VerifySignature(txFund, cs.block.vtx[1], nIn, flags, 0);
}

// One funding transaction for the suite: a fixture per case would run the chain past
// the regtest DAG fork (11), where no coinstake connects.
struct ColdStakeFixture
{
    bool fBuilt;
    CKey stakerKey, ownerKey;
    CScript p2csScript, ownerScript;
    CTransaction txFund;
    ColdStakeFixture() : fBuilt(false) {}
};

ColdStakeFixture g_fixture;

// Build it on first use. The caller holds DetachedWalletGuard: these blocks reach
// the chain, and a registered wallet would record their coinbases and move the
// ordering counters other suites pin.
bool EnsureFixture()
{
    if (g_fixture.fBuilt)
        return true;

    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(pindexBest != NULL);
    BOOST_REQUIRE_MESSAGE(pindexBest->nHeight + 6 < FORK_HEIGHT_DAG,
                          "the cold-stake branch sits on the proof-of-stake path, "
                          "which ends at the DAG fork; this suite must run before "
                          "anything mines past it (tip " << pindexBest->nHeight
                          << ", fork " << FORK_HEIGHT_DAG << ")");

    g_fixture.stakerKey.MakeNewKey(true);
    g_fixture.ownerKey.MakeNewKey(true);
    BOOST_REQUIRE(pwalletMain->AddKey(g_fixture.stakerKey));
    BOOST_REQUIRE(pwalletMain->AddKey(g_fixture.ownerKey));

    g_fixture.p2csScript =
        GetScriptForColdStaking(g_fixture.stakerKey.GetPubKey().GetID(),
                                g_fixture.ownerKey.GetPubKey().GetID());
    BOOST_REQUIRE(IsPayToColdStaking(g_fixture.p2csScript));
    g_fixture.ownerScript = PayToKey(g_fixture.ownerKey);

    // Four blocks for maturity and margin, then the funding block; later suites
    // depend on this height.
    CBlock blockFirst;
    BOOST_REQUIRE_MESSAGE(MineOneBlock(blockFirst), "failed to mine regtest block 0");
    for (int i = 1; i < 4; i++)
    {
        CBlock block;
        BOOST_REQUIRE_MESSAGE(MineOneBlock(block), "failed to mine regtest block " << i);
    }

    BOOST_REQUIRE_MESSAGE(MineBlockWithFunding(blockFirst.vtx[0], g_fixture.p2csScript,
                                               g_fixture.ownerScript, g_fixture.txFund),
                          "could not fund the cold-stake delegation");
    g_fixture.fBuilt = true;
    return true;
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

    CollateralnodeViewGuard guard;
    MockClockGuard clockGuard;
    DetachedWalletGuard walletGuard;
    ColdStakingGateGuard gateGuard;

    BOOST_REQUIRE(EnsureFixture());
    const CScript& p2csScript = g_fixture.p2csScript;
    const CTransaction& txFund = g_fixture.txFund;

    // The payee is whoever the block claims is a collateralnode.
    CKey payeeKey;
    payeeKey.MakeNewKey(true);
    const CScript payeeScript = PayToKey(payeeKey);

    // The plain leg funds the whole cold-stake reward, so the coinstake mints
    // nothing and the reward cap holds at any height on any chain.
    const int64_t nP2CSIn = nLegValues[LEG_P2CS_SMALL];
    const int64_t nPlainIn = nLegValues[LEG_PLAIN_SMALL];
    const int64_t nCNPayment = nPlainIn / 10;

    std::vector<unsigned int> vLegs;
    vLegs.push_back(LEG_P2CS_SMALL);
    vLegs.push_back(LEG_PLAIN_SMALL);
    std::vector<CTxOut> vOutputs;
    vOutputs.push_back(CTxOut(nP2CSIn + nPlainIn - nCNPayment, p2csScript));
    vOutputs.push_back(CTxOut(nCNPayment, payeeScript));

    ColdStakeBlock cs;
    BOOST_REQUIRE_MESSAGE(BuildStakeBlock(txFund, vLegs, vOutputs, cs),
                          "could not build the cold-stake block");
    BOOST_REQUIRE(cs.nHeight < FORK_HEIGHT_DAG);
    BOOST_REQUIRE_MESSAGE(cs.nHeight >= FORK_HEIGHT_COLD_STAKING,
                          "the block sits below the cold-staking gate, so the "
                          "payee check is not the branch it would take");
    BOOST_REQUIRE_MESSAGE(InterpreterAcceptsLeg(txFund, cs, 0),
                          "the interpreter refused the delegation input, so every "
                          "arm below would be judging a script failure");

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

// The rehearsal knob's own arithmetic, and its fail-closed default. Without a
// height named, regtest answers exactly as it did before the knob existed.
BOOST_AUTO_TEST_CASE(the_cold_staking_rehearsal_knob_is_regtest_only)
{
    ColdStakingGateGuard gateGuard;
    NetworkGuard netGuard;

    BOOST_REQUIRE(fRegTest && !fTestNet);
    nRegtestColdStakingHeight = 0;
    BOOST_CHECK_EQUAL(FORK_HEIGHT_COLD_STAKING, 1);

    nRegtestColdStakingHeight = 40;
    BOOST_CHECK_EQUAL(FORK_HEIGHT_COLD_STAKING, 40);

    // The knob moves nothing off regtest.
    fRegTest = false;
    fTestNet = true;
    BOOST_CHECK_EQUAL(FORK_HEIGHT_COLD_STAKING, 1);

    fTestNet = false;
    BOOST_CHECK_MESSAGE(FORK_HEIGHT_COLD_STAKING > 1000000,
                        "the regtest height reached mainnet: got "
                        << FORK_HEIGHT_COLD_STAKING);
    BOOST_CHECK_EQUAL(FORK_HEIGHT_COLD_STAKING, ShiftMainnetV5Activation(7800000));
}

// R-CS-001. A coinstake carrying a P2CS output is invalid below the gate. The
// coinstake spends a plain input, so only the gate (moved via -regtestcoldstaking)
// differs between arms.
BOOST_AUTO_TEST_CASE(a_cold_staking_output_below_the_gate_is_refused)
{
    ColdStakingGateGuard gateGuard;
    CollateralnodeViewGuard cnGuard;
    MockClockGuard clockGuard;
    DetachedWalletGuard walletGuard;

    BOOST_REQUIRE(EnsureFixture());
    nRegtestColdStakingHeight = 0;

    std::vector<unsigned int> vLegs;
    vLegs.push_back(LEG_PLAIN_SPARE);
    std::vector<CTxOut> vOutputs;
    vOutputs.push_back(CTxOut(nLegValues[LEG_PLAIN_SPARE], g_fixture.p2csScript));

    ColdStakeBlock cs;
    BOOST_REQUIRE_MESSAGE(BuildStakeBlock(g_fixture.txFund, vLegs, vOutputs, cs),
                          "could not build the plain-input coinstake");
    BOOST_REQUIRE(cs.nHeight < FORK_HEIGHT_DAG);
    BOOST_REQUIRE_MESSAGE(IsPayToColdStaking(cs.block.vtx[1].vout[1].scriptPubKey),
                          "the coinstake carries no cold-staking output; the arm "
                          "is not adversarial");
    BOOST_REQUIRE_MESSAGE(InterpreterAcceptsLeg(g_fixture.txFund, cs, 0),
                          "the interpreter refused the plain input, so a refusal "
                          "below would not be the gate's");

    // Arm 1, the positive control: the gate is at or below this height, the
    // coinstake spends no delegation, and the same bytes connect.
    BOOST_REQUIRE(cs.nHeight >= FORK_HEIGHT_COLD_STAKING);
    const CBlock::ConnectResult allowed = ConnectAndRollBack(cs);
    BOOST_CHECK_MESSAGE(allowed == CBlock::CONNECT_RESULT_OK,
                        "a cold-staking output at or above the gate must connect, "
                        "got result " << (int)allowed);

    // Arm 2: nothing about the block changes; the gate moves one height above it.
    nRegtestColdStakingHeight = cs.nHeight + 1;
    BOOST_REQUIRE(cs.nHeight < FORK_HEIGHT_COLD_STAKING);
    BOOST_REQUIRE_MESSAGE(InterpreterAcceptsLeg(g_fixture.txFund, cs, 0),
                          "the gate must not change what the interpreter says");
    const CBlock::ConnectResult refused = ConnectAndRollBack(cs);
    BOOST_CHECK_MESSAGE(refused == CBlock::CONNECT_RESULT_INVALID,
                        "a cold-staking output below the gate must be refused "
                        "deterministically, got result " << (int)refused);
    BOOST_CHECK_MESSAGE(ConnectResultMayPersistVerdict(refused),
                        "the gate is a height comparison every node reproduces, so "
                        "the refusal must be persistable");
}

// R-CS-002. The P2CS output value may not fall below the P2CS input value.
// The interpreter cannot see input value, so this floor is ConnectBlock's alone.
BOOST_AUTO_TEST_CASE(a_cold_stake_may_not_return_less_than_it_delegated)
{
    ColdStakingGateGuard gateGuard;
    CollateralnodeViewGuard cnGuard;
    MockClockGuard clockGuard;
    DetachedWalletGuard walletGuard;

    BOOST_REQUIRE(EnsureFixture());
    nRegtestColdStakingHeight = 0;

    CKey payeeKey;
    payeeKey.MakeNewKey(true);
    const CScript payeeScript = PayToKey(payeeKey);
    AnnounceCollateralnode(payeeKey, true);

    const int64_t nP2CSIn = nLegValues[LEG_P2CS_LARGE];
    const int64_t nPlainIn = nLegValues[LEG_PLAIN_ONE];
    const int64_t nTotalIn = nP2CSIn + nPlainIn;

    std::vector<unsigned int> vLegs;
    vLegs.push_back(LEG_P2CS_LARGE);
    vLegs.push_back(LEG_PLAIN_ONE);

    // Arm 1, the positive control. The delegation is repaid in full and the
    // collateralnode leg is well under the cap, so nothing but the arms below can
    // account for a refusal.
    {
        const int64_t nCNPayment = 5 * CENT;
        std::vector<CTxOut> vOutputs;
        vOutputs.push_back(CTxOut(nTotalIn - nCNPayment, g_fixture.p2csScript));
        vOutputs.push_back(CTxOut(nCNPayment, payeeScript));

        ColdStakeBlock cs;
        BOOST_REQUIRE(BuildStakeBlock(g_fixture.txFund, vLegs, vOutputs, cs));
        BOOST_REQUIRE(cs.nHeight >= FORK_HEIGHT_COLD_STAKING &&
                      cs.nHeight < FORK_HEIGHT_DAG);
        BOOST_REQUIRE(ColdStakeCNPayeeIsRegistered(cs.nHeight, payeeScript));
        BOOST_REQUIRE_MESSAGE(nTotalIn - nCNPayment >= nP2CSIn,
                              "the control does not repay the delegation");
        BOOST_REQUIRE(InterpreterAcceptsLeg(g_fixture.txFund, cs, 0));
        const CBlock::ConnectResult ok = ConnectAndRollBack(cs);
        BOOST_CHECK_MESSAGE(ok == CBlock::CONNECT_RESULT_OK,
                            "a cold stake that repays its delegation must connect, "
                            "got result " << (int)ok);
    }

    // Arm 2, the rule. One INN of the delegation is diverted into the
    // collateralnode output: the cold-staking outputs no longer cover the
    // delegation, and the owner is one INN short.
    {
        const int64_t nCNPayment = 1 * COIN;
        const int64_t nP2CSOut = nP2CSIn - nCNPayment;
        std::vector<CTxOut> vOutputs;
        vOutputs.push_back(CTxOut(nP2CSOut, g_fixture.p2csScript));
        vOutputs.push_back(CTxOut(nCNPayment, payeeScript));

        ColdStakeBlock cs;
        BOOST_REQUIRE(BuildStakeBlock(g_fixture.txFund, vLegs, vOutputs, cs));
        BOOST_REQUIRE(cs.nHeight >= FORK_HEIGHT_COLD_STAKING &&
                      cs.nHeight < FORK_HEIGHT_DAG);
        BOOST_REQUIRE(ColdStakeCNPayeeIsRegistered(cs.nHeight, payeeScript));
        BOOST_REQUIRE_MESSAGE(nP2CSOut < nP2CSIn,
                              "the arm repays the delegation in full; it is not "
                              "adversarial");
        // The two earlier value checks must not be what fires: the total output
        // still covers the delegation exactly, so the reward is zero and the cap
        // is not evaluated at all.
        BOOST_REQUIRE_EQUAL(nP2CSOut + nCNPayment, nP2CSIn);
        BOOST_REQUIRE_MESSAGE(InterpreterAcceptsLeg(g_fixture.txFund, cs, 0),
                              "OP_CHECKCOLDSTAKEVERIFY refused this coinstake, so "
                              "the refusal below would not be ConnectBlock's floor");

        const CBlock::ConnectResult refused = ConnectAndRollBack(cs);
        BOOST_CHECK_MESSAGE(refused == CBlock::CONNECT_RESULT_INVALID,
                            "a cold stake repaying less than it delegated must be "
                            "refused deterministically, got result " << (int)refused);
        BOOST_CHECK(ConnectResultMayPersistVerdict(refused));
    }

    // Arm 3: a non-delegation, non-last output. The interpreter's identical
    // structural check makes such a coinstake unsignable; assert that.
    {
        std::vector<CTxOut> vOutputs;
        vOutputs.push_back(CTxOut(9 * COIN, g_fixture.p2csScript));
        vOutputs.push_back(CTxOut(1 * COIN, g_fixture.ownerScript));
        vOutputs.push_back(CTxOut(1 * COIN, payeeScript));

        ColdStakeBlock cs;
        BOOST_CHECK_MESSAGE(!BuildStakeBlock(g_fixture.txFund, vLegs, vOutputs, cs),
                            "an output that is neither the delegation script nor "
                            "the exempt last output was signed; the interpreter no "
                            "longer refuses that structure, so ConnectBlock's copy "
                            "of the clause is the only enforcer and needs its own "
                            "arm");
    }
}

// R-CS-003. The collateralnode leg is capped at ~30% of the stake reward.
// The interpreter caps at 30% of total output, so every arm sits in the band only
// ConnectBlock refuses.
BOOST_AUTO_TEST_CASE(a_cold_stake_collateralnode_payment_is_capped_at_a_share_of_the_reward)
{
    ColdStakingGateGuard gateGuard;
    CollateralnodeViewGuard cnGuard;
    MockClockGuard clockGuard;
    DetachedWalletGuard walletGuard;

    BOOST_REQUIRE(EnsureFixture());
    nRegtestColdStakingHeight = 0;

    CKey payeeKey;
    payeeKey.MakeNewKey(true);
    const CScript payeeScript = PayToKey(payeeKey);
    AnnounceCollateralnode(payeeKey, true);

    const int64_t nP2CSIn = nLegValues[LEG_P2CS_LARGE];
    const int64_t nPlainIn = nLegValues[LEG_PLAIN_ONE];
    const int64_t nTotalIn = nP2CSIn + nPlainIn;
    // Every arm keeps the total output at the total input, so the reward is the
    // plain leg whatever the split, and only the collateralnode share varies.
    const int64_t nReward = nTotalIn - nP2CSIn;
    BOOST_REQUIRE_EQUAL(nReward, nPlainIn);

    std::vector<unsigned int> vLegs;
    vLegs.push_back(LEG_P2CS_LARGE);
    vLegs.push_back(LEG_PLAIN_ONE);

    // The last value the cap admits and the first it refuses, read off the rule:
    // refused when nCNPayment / 3 > nReward / 10 + 1.
    const int64_t nFirstRefused = 3 * (nReward / 10 + 2);
    const int64_t nLastAdmitted = nFirstRefused - 1;
    BOOST_REQUIRE_MESSAGE(nLastAdmitted / 3 <= nReward / 10 + 1,
                          "the admitted boundary is on the wrong side of the cap");
    BOOST_REQUIRE_MESSAGE(nFirstRefused / 3 > nReward / 10 + 1,
                          "the refused boundary is on the wrong side of the cap");

    struct Arm { int64_t nCNPayment; bool fAccept; const char* pszWhat; };
    const Arm vArms[] = {
        { nReward / 10,  true,  "a tenth of the reward" },
        { nLastAdmitted, true,  "the last value the cap admits" },
        { nFirstRefused, false, "the first value the cap refuses" },
    };

    for (size_t i = 0; i < sizeof(vArms) / sizeof(vArms[0]); i++)
    {
        const int64_t nCNPayment = vArms[i].nCNPayment;
        const int64_t nP2CSOut = nTotalIn - nCNPayment;
        BOOST_REQUIRE_MESSAGE(nP2CSOut >= nP2CSIn,
                              vArms[i].pszWhat << ": the arm underpays the "
                              "delegation, so the floor would fire instead");

        std::vector<CTxOut> vOutputs;
        vOutputs.push_back(CTxOut(nP2CSOut, g_fixture.p2csScript));
        vOutputs.push_back(CTxOut(nCNPayment, payeeScript));

        ColdStakeBlock cs;
        BOOST_REQUIRE(BuildStakeBlock(g_fixture.txFund, vLegs, vOutputs, cs));
        BOOST_REQUIRE(cs.nHeight >= FORK_HEIGHT_COLD_STAKING &&
                      cs.nHeight < FORK_HEIGHT_DAG);
        BOOST_REQUIRE(ColdStakeCNPayeeIsRegistered(cs.nHeight, payeeScript));
        BOOST_REQUIRE_MESSAGE(InterpreterAcceptsLeg(g_fixture.txFund, cs, 0),
                              vArms[i].pszWhat << ": OP_CHECKCOLDSTAKEVERIFY "
                              "refused this coinstake, so the verdict below is "
                              "the interpreter's looser cap, not ConnectBlock's");

        const CBlock::ConnectResult result = ConnectAndRollBack(cs);
        if (vArms[i].fAccept)
            BOOST_CHECK_MESSAGE(result == CBlock::CONNECT_RESULT_OK,
                                vArms[i].pszWhat << " (" << nCNPayment
                                << " of reward " << nReward << ") was refused, "
                                "result " << (int)result);
        else
        {
            BOOST_CHECK_MESSAGE(result == CBlock::CONNECT_RESULT_INVALID,
                                vArms[i].pszWhat << " (" << nCNPayment
                                << " of reward " << nReward << ") was accepted, "
                                "result " << (int)result);
            BOOST_CHECK(ConnectResultMayPersistVerdict(result));
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
