// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Proof-of-work collateralnode payment rules in ConnectBlock. -regtestcnpayments opens
// the era on regtest; each rejection arm edits one coinbase field.

#include <boost/test/unit_test.hpp>

#include <boost/preprocessor/stringize.hpp>

#include <fstream>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "../base58.h"
#include "../collateralnode.h"
#include "../finality.h"
#include "../key.h"
#include "../main.h"
#include "../miner.h"
#include "../script.h"
#include "../subsidy.h"
#include "../txdb.h"
#include "../util.h"
#include "../wallet.h"

extern CWallet* pwalletMain;

BOOST_AUTO_TEST_SUITE(cn_pow_payment_tests)

namespace {

// The mainnet era height, written down once so the cases that pin it read as
// one assertion rather than as arithmetic repeated four times.
const int MAINNET_CN_PAYMENT_ERA_HEIGHT = 2085001;

struct CNPaymentEraGuard
{
    int nSaved;
    CNPaymentEraGuard() : nSaved(nRegtestCNPaymentsHeight) {}
    ~CNPaymentEraGuard() { nRegtestCNPaymentsHeight = nSaved; }
};

// The network flags are read by the gate helpers themselves, so the mainnet and
// testnet answers are observed rather than restated.
struct NetworkGuard
{
    bool fRegSaved, fTestSaved;
    NetworkGuard() : fRegSaved(fRegTest), fTestSaved(fTestNet) {}
    ~NetworkGuard() { fRegTest = fRegSaved; fTestNet = fTestSaved; }
};

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

struct MockClockGuard
{
    ~MockClockGuard() { SetMockTime(0); }
};

// The suite mines. A registered wallet would record the coinbases and move the
// ordering counters other suites pin.
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

// The payee the producer falls back to when it knows of no collateralnode, and
// the one the validator accepts without consulting its list.
CScript BurnPayee()
{
    CBitcoinAddress burnDestination;
    burnDestination.SetString(fTestNet ? "8TestXXXXXXXXXXXXXXXXXXXXXXXXbCvpq"
                                       : "INNXXXXXXXXXXXXXXXXXXXXXXXXXZeeDTw");
    return GetScriptForDestination(burnDestination.Get());
}

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

CBlockIndex* ParentOf(const CBlock& block)
{
    LOCK(cs_main);
    std::map<uint256, CBlockIndex*>::const_iterator mi =
        mapBlockIndex.find(block.hashPrevBlock);
    return mi == mapBlockIndex.end() ? NULL : mi->second;
}

// ConnectBlock re-runs CheckBlock with the proof-of-work check on, so an edited
// block has to carry real work even when it never reaches the chain.
bool GrindHeader(CBlock* pblock)
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
        if (++nHashes > 2000000U)
            return false;
    }
    return true;
}

// A template on the tip plus the index ConnectBlock gets. Build, optionally edit the
// coinbase, then Seal to recompute the merkle root and work.
struct CandidateBlock
{
    CBlock block;
    uint256 hash;
    CBlockIndex index;
    CBlockIndex* pparent;

    CandidateBlock() : pparent(NULL) {}
    CBlockIndex* Index() { return &index; }
    int Height() const { return pparent->nHeight + 1; }
    CTransaction& Coinbase() { return block.vtx[0]; }
};

bool BuildCandidate(CandidateBlock& out)
{
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    if (pblock.get() == NULL)
        return false;
    CBlockIndex* pindexParent = ParentOf(*pblock);
    if (pindexParent == NULL)
        return false;
    unsigned int nExtraNonce = 0;
    IncrementExtraNonce(pblock.get(), pindexParent, nExtraNonce);
    out.block = *pblock;
    out.pparent = pindexParent;
    return true;
}

bool Seal(CandidateBlock& out)
{
    out.block.hashMerkleRoot = out.block.BuildMerkleTree();
    if (!GrindHeader(&out.block))
        return false;
    out.hash = out.block.GetHash();
    out.index = CBlockIndex(0, 0, out.block);
    out.index.pprev = out.pparent;
    out.index.nHeight = out.pparent->nHeight + 1;
    out.index.phashBlock = &out.hash;
    return true;
}

// Connect and hand back the verdict, discarding every write. Without an open
// batch the accepted arms would spend this chain's outputs for the rest of the
// binary.
CBlock::ConnectResult ConnectAndRollBack(CandidateBlock& cb)
{
    LOCK(cs_main);
    CTxDB txdb;
    CBlock::ConnectResult result = CBlock::CONNECT_RESULT_INVALID;
    BOOST_REQUIRE(txdb.TxnBegin());
    const bool fConnected = cb.block.ConnectBlock(txdb, cb.Index(), false, false, &result);
    BOOST_REQUIRE(txdb.TxnAbort());
    BOOST_CHECK_EQUAL(fConnected, result == CBlock::CONNECT_RESULT_OK);
    return result;
}

// Asserts every entry condition of the payment branch. The regtest window is 20s, so
// the clock is pinned to keep entry deterministic.
void RequirePaymentBranchEntered(CandidateBlock& cb)
{
    SetMockTime(cb.block.GetBlockTime());
    BOOST_TEST_MESSAGE("collateralnode payment branch at height "
                       << cb.Height() << " (DAG fork " << FORK_HEIGHT_DAG
                       << ", era " << GetCollateralnodePaymentEraHeight()
                       << ", enforcement " << CollateralnodeEnforcementHeight() << ")");
    BOOST_REQUIRE_MESSAGE(CollateralnodePaymentsEnabledAtHeight(cb.Height()),
                          "the payment era is not enabled at height " << cb.Height());
    BOOST_REQUIRE_MESSAGE(
        CollateralnodePaymentRuleApplies(false, cb.block.GetBlockTime(), GetTime(), true),
        "the block is outside the node-local payment window");
    BOOST_REQUIRE_MESSAGE(pindexBest != NULL &&
                              pindexBest->GetBlockHash() == cb.block.hashPrevBlock,
                          "the candidate does not extend this node's own tip");
    BOOST_REQUIRE_MESSAGE(!IsInitialBlockDownload(),
                          "initial download suppresses the payment check");
    BOOST_REQUIRE_MESSAGE(cb.block.IsProofOfWork(),
                          "the branch under test is the proof-of-work one");
    BOOST_REQUIRE_MESSAGE(cb.Height() >= CollateralnodeEnforcementHeight(),
                          "below the enforcement height an unrecognised payee is "
                          "forgiven, so the payee arm would prove nothing");
}

// The payment the validator recomputes from the coinbase it is handed. Stated
// here the way ConnectBlock states it, so an arm asserting a mismatch is
// asserting against the rule rather than against a second copy of the rate.
int64_t ExpectedPayment(const CTransaction& coinbase)
{
    return CBlockSubsidySplit::CollateralnodeShareOfBase(
        FinalityCollateralnodePaymentBase(coinbase.GetValueOut(), 0));
}

std::string ReadSourceFile(const std::string& strName)
{
    const std::string strPath =
        std::string(BOOST_PP_STRINGIZE(TEST_DATA_DIR)) + "/../../" + strName;
    std::ifstream in(strPath.c_str());
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

} // namespace

// The knob's own arithmetic, and the fail-closed default: with no height named,
// regtest answers exactly as it did before the knob existed -- the era never
// opens, and the rules stay unreachable.
BOOST_AUTO_TEST_CASE(the_payment_era_defaults_to_unreachable_on_regtest)
{
    CNPaymentEraGuard eraGuard;
    BOOST_REQUIRE(fRegTest && !fTestNet);

    nRegtestCNPaymentsHeight = 0;
    BOOST_CHECK_EQUAL(GetCollateralnodePaymentEraHeight(), 0);
    BOOST_CHECK(!CollateralnodePaymentsEnabledAtHeight(0));
    BOOST_CHECK(!CollateralnodePaymentsEnabledAtHeight(1));
    BOOST_CHECK_MESSAGE(!CollateralnodePaymentsEnabledAtHeight(
                            std::numeric_limits<int>::max()),
                        "zero must mean disabled at every height, not activation "
                        "at height zero");
    BOOST_CHECK_EQUAL(CollateralnodeEnforcementHeight(), MN_ENFORCEMENT_ACTIVE_HEIGHT);

    nRegtestCNPaymentsHeight = 40;
    BOOST_CHECK_EQUAL(GetCollateralnodePaymentEraHeight(), 40);
    BOOST_CHECK(!CollateralnodePaymentsEnabledAtHeight(39));
    BOOST_CHECK(CollateralnodePaymentsEnabledAtHeight(40));
    BOOST_CHECK(CollateralnodePaymentsEnabledAtHeight(41));

    // Payments and enforcement open together; otherwise every regtest block would forgive
    // an unrecognised payee and the payee rule would never reject.
    BOOST_CHECK_EQUAL(CollateralnodeEnforcementHeight(), 40);
}

// The knob is regtest-only, and the two shipped networks answer exactly what
// they answered before it existed.
BOOST_AUTO_TEST_CASE(the_knob_does_not_reach_mainnet_or_testnet)
{
    CNPaymentEraGuard eraGuard;
    NetworkGuard netGuard;

    nRegtestCNPaymentsHeight = 7; // a height a regtest chain actually reaches

    fRegTest = false;
    fTestNet = false;
    BOOST_CHECK_EQUAL(GetCollateralnodePaymentEraHeight(),
                      MAINNET_CN_PAYMENT_ERA_HEIGHT);
    BOOST_CHECK_MESSAGE(!CollateralnodePaymentsEnabledAtHeight(7),
                        "the regtest height reached a network it must not touch");
    BOOST_CHECK(!CollateralnodePaymentsEnabledAtHeight(MAINNET_CN_PAYMENT_ERA_HEIGHT - 1));
    BOOST_CHECK(CollateralnodePaymentsEnabledAtHeight(MAINNET_CN_PAYMENT_ERA_HEIGHT));
    BOOST_CHECK_EQUAL(CollateralnodeEnforcementHeight(), MN_ENFORCEMENT_ACTIVE_HEIGHT);
    // The composite the regtest knob reproduces.
    BOOST_CHECK_MESSAGE(GetCollateralnodePaymentEraHeight() > CollateralnodeEnforcementHeight(),
                        "on mainnet a paying block is always an enforced one");

    fRegTest = false;
    fTestNet = true;
    BOOST_CHECK_EQUAL(GetCollateralnodePaymentEraHeight(),
                      BLOCK_START_COLLATERALNODE_PAYMENTS_TESTNET + 1);
    BOOST_CHECK(!CollateralnodePaymentsEnabledAtHeight(7));
    BOOST_CHECK_EQUAL(CollateralnodeEnforcementHeight(),
                      MN_ENFORCEMENT_ACTIVE_HEIGHT_TESTNET);
}

// The era condition has one definition. A producer copy that disagrees with the
// validator builds blocks the validator rejects, which on regtest is a silent stall.
BOOST_AUTO_TEST_CASE(the_era_condition_has_a_single_definition)
{
    static const char* const kConsumers[] = { "main.cpp", "miner.cpp",
                                              "rpcmining.cpp", "wallet.cpp" };
    for (size_t i = 0; i < sizeof(kConsumers) / sizeof(kConsumers[0]); i++)
    {
        const std::string strFile = ReadSourceFile(kConsumers[i]);
        BOOST_REQUIRE_MESSAGE(!strFile.empty(),
                              "could not read src/" << kConsumers[i]);
        BOOST_CHECK_MESSAGE(strFile.find("2085000") == std::string::npos,
                            "src/" << kConsumers[i] << " restates the payment-era "
                            "height; it must read CollateralnodePaymentsEnabledAtHeight");
        BOOST_CHECK_MESSAGE(
            strFile.find("CollateralnodePaymentsEnabledAtHeight") != std::string::npos,
            "src/" << kConsumers[i] << " no longer reads the shared era condition");
    }

    // The enforcement height reaches consensus through one function too.
    const std::string strMain = ReadSourceFile("main.cpp");
    BOOST_CHECK_MESSAGE(
        strMain.find("CollateralnodeEnforcementHeight()") != std::string::npos,
        "ConnectBlock no longer reads the shared enforcement height");
}

// The producer's half, and the positive control for every arm below: with the
// era open, CreateNewBlock adds a payment output the validator recomputes to the
// same satoshi, and the block goes on the chain.
BOOST_AUTO_TEST_CASE(a_block_the_producer_built_carries_the_payment_and_connects)
{
    CNPaymentEraGuard eraGuard;
    CollateralnodeViewGuard cnGuard;
    MockClockGuard clockGuard;
    DetachedWalletGuard walletGuard;

    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(pindexBest != NULL);

    // With no height named the producer adds nothing, which is the shipped
    // behaviour this knob must leave alone.
    nRegtestCNPaymentsHeight = 0;
    CandidateBlock plain;
    BOOST_REQUIRE(BuildCandidate(plain));
    const size_t nPlainOuts = plain.Coinbase().vout.size();

    nRegtestCNPaymentsHeight = pindexBest->nHeight + 1;
    CandidateBlock cb;
    BOOST_REQUIRE(BuildCandidate(cb));
    BOOST_REQUIRE_EQUAL(cb.Height(), nRegtestCNPaymentsHeight);
    BOOST_REQUIRE(Seal(cb));

    BOOST_CHECK_MESSAGE(cb.Coinbase().vout.size() == nPlainOuts + 1,
                        "opening the era must add exactly one coinbase output; "
                        "got " << cb.Coinbase().vout.size() << " against "
                        << nPlainOuts << " with the era closed");

    const CTxOut& cnOut = cb.Coinbase().vout.back();
    const int64_t nExpected = ExpectedPayment(cb.Coinbase());
    BOOST_REQUIRE_MESSAGE(nExpected > 0,
                          "the collateralnode share is zero at height "
                          << cb.Height() << "; every arm below would be vacuous");
    BOOST_CHECK_MESSAGE(cnOut.nValue == nExpected,
                        "the producer paid " << cnOut.nValue << " where the "
                        "validator recomputes " << nExpected);
    BOOST_CHECK_MESSAGE(cnOut.scriptPubKey == BurnPayee(),
                        "a producer that knows of no collateralnode must burn the "
                        "share, not keep it");

    RequirePaymentBranchEntered(cb);
    const CBlock::ConnectResult accepted = ConnectAndRollBack(cb);
    BOOST_CHECK_MESSAGE(accepted == CBlock::CONNECT_RESULT_OK,
                        "the producer's own block was refused, result "
                        << (int)accepted);

    // On the chain, through the shipped path, so the arms below build on a tip
    // whose predecessor really carried a payment.
    BOOST_REQUIRE_MESSAGE(ProcessBlock(NULL, &cb.block),
                          "a paying block was not accepted by the full path");
    BOOST_CHECK_EQUAL(pindexBest->nHeight, cb.Height());
}

// The amount. One satoshi moves from the producer's output into the payment
// output, so the coinbase value out -- and with it the payment the validator
// recomputes -- is unchanged: only the split is wrong.
BOOST_AUTO_TEST_CASE(a_coinbase_paying_the_wrong_collateralnode_amount_is_refused)
{
    CNPaymentEraGuard eraGuard;
    CollateralnodeViewGuard cnGuard;
    MockClockGuard clockGuard;
    DetachedWalletGuard walletGuard;

    BOOST_REQUIRE(pindexBest != NULL);
    nRegtestCNPaymentsHeight = pindexBest->nHeight + 1;

    CandidateBlock cb;
    BOOST_REQUIRE(BuildCandidate(cb));
    BOOST_REQUIRE(cb.Coinbase().vout.size() >= 2);

    const int64_t nValueOutBefore = cb.Coinbase().GetValueOut();
    const int64_t nExpected = ExpectedPayment(cb.Coinbase());
    BOOST_REQUIRE(nExpected > 0);
    BOOST_REQUIRE(cb.Coinbase().vout[0].nValue > 0);

    cb.Coinbase().vout[0].nValue -= 1;
    cb.Coinbase().vout.back().nValue += 1;
    BOOST_REQUIRE_EQUAL(cb.Coinbase().GetValueOut(), nValueOutBefore);
    for (unsigned int i = 0; i < cb.Coinbase().vout.size(); i++)
        BOOST_REQUIRE_MESSAGE(cb.Coinbase().vout[i].nValue != nExpected,
                              "coinbase output " << i << " still carries the "
                              "expected payment; the arm is not adversarial");
    BOOST_REQUIRE(Seal(cb));

    RequirePaymentBranchEntered(cb);
    const CBlock::ConnectResult refused = ConnectAndRollBack(cb);
    BOOST_CHECK_MESSAGE(refused == CBlock::CONNECT_RESULT_TRANSIENT,
                        "a coinbase carrying no output equal to the collateralnode "
                        "share must be refused, got result " << (int)refused);
    BOOST_CHECK_MESSAGE(!ConnectResultMayPersistVerdict(refused),
                        "the refusal is read off this node's gossiped list and its "
                        "own clock, so it may never be written into the index");

    // The tip is where it was: a refused attempt changes nothing.
    BOOST_CHECK_EQUAL(pindexBest->nHeight + 1, cb.Height());
}

// The payee. Same value, same coinbase, a script this node has not heard of.
// Above the enforcement height that is a refusal; announce the payee and the
// identical bytes connect, which is what makes the verdict node-local.
BOOST_AUTO_TEST_CASE(a_payee_this_node_does_not_recognise_is_refused)
{
    CNPaymentEraGuard eraGuard;
    CollateralnodeViewGuard cnGuard;
    MockClockGuard clockGuard;
    DetachedWalletGuard walletGuard;

    BOOST_REQUIRE(pindexBest != NULL);
    nRegtestCNPaymentsHeight = pindexBest->nHeight + 1;

    CKey payeeKey;
    payeeKey.MakeNewKey(true);
    const CScript payeeScript = PayToKey(payeeKey);

    CandidateBlock cb;
    BOOST_REQUIRE(BuildCandidate(cb));
    BOOST_REQUIRE(cb.Coinbase().vout.size() >= 2);
    const int64_t nExpected = ExpectedPayment(cb.Coinbase());
    BOOST_REQUIRE(nExpected > 0);
    BOOST_REQUIRE_EQUAL(cb.Coinbase().vout.back().nValue, nExpected);

    cb.Coinbase().vout.back().scriptPubKey = payeeScript;
    BOOST_REQUIRE(payeeScript != BurnPayee());
    BOOST_REQUIRE(Seal(cb));

    RequirePaymentBranchEntered(cb);
    BOOST_REQUIRE_MESSAGE(!ColdStakeCNPayeeIsRegistered(cb.Height(), payeeScript),
                          "this node already recognises the payee; the arm is not "
                          "adversarial");
    const CBlock::ConnectResult refused = ConnectAndRollBack(cb);
    BOOST_CHECK_MESSAGE(refused == CBlock::CONNECT_RESULT_TRANSIENT,
                        "a payment to a script this node has never heard of must "
                        "be refused above the enforcement height, got result "
                        << (int)refused);
    BOOST_CHECK(!ConnectResultMayPersistVerdict(refused));

    // Nothing about the block changes; this node simply hears about the payee.
    AnnounceCollateralnode(payeeKey, true);
    BOOST_REQUIRE(ColdStakeCNPayeeIsRegistered(cb.Height(), payeeScript));
    RequirePaymentBranchEntered(cb);
    const CBlock::ConnectResult announced = ConnectAndRollBack(cb);
    BOOST_CHECK_MESSAGE(announced == CBlock::CONNECT_RESULT_OK,
                        "the same bytes must connect once the payee is known, got "
                        "result " << (int)announced);
}

// With the era closed the branch is never entered: no payment output is added or required.
BOOST_AUTO_TEST_CASE(with_the_era_closed_the_payment_branch_never_runs)
{
    CNPaymentEraGuard eraGuard;
    CollateralnodeViewGuard cnGuard;
    MockClockGuard clockGuard;
    DetachedWalletGuard walletGuard;

    BOOST_REQUIRE(pindexBest != NULL);
    nRegtestCNPaymentsHeight = 0;

    CandidateBlock cb;
    BOOST_REQUIRE(BuildCandidate(cb));
    BOOST_REQUIRE(Seal(cb));
    BOOST_CHECK(!CollateralnodePaymentsEnabledAtHeight(cb.Height()));

    SetMockTime(cb.block.GetBlockTime());
    const int64_t nExpected = ExpectedPayment(cb.Coinbase());
    for (unsigned int i = 0; i < cb.Coinbase().vout.size(); i++)
        BOOST_CHECK_MESSAGE(cb.Coinbase().vout[i].nValue != nExpected,
                            "the producer added a collateralnode payment with the "
                            "era closed");

    const CBlock::ConnectResult accepted = ConnectAndRollBack(cb);
    BOOST_CHECK_MESSAGE(accepted == CBlock::CONNECT_RESULT_OK,
                        "a block with no collateralnode payment must connect while "
                        "the era is closed, got result " << (int)accepted);
}

BOOST_AUTO_TEST_SUITE_END()
