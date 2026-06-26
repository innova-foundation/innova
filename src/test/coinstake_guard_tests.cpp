// Regression tests for the coinstake-position handling (CR-1, re-audit
// 2026-06-12): a coinstake-shaped transaction outside vtx[1] of a
// proof-of-stake block must never reach the coinstake validation exemptions
// (shielded value balance, nullifier binding, value conservation), and a
// coinstake may never unshield (positive nValueBalance). Also covers the
// pinned V2/V3 kernel metadata helper and the mainnet fork-ladder alignment
// that keeps the shielded pool born-safe.

#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../curvetree.h"

#include <vector>

// Defined in util.cpp; extern at global scope so the linker resolves the real
// symbols (see nullsend_binding_tests.cpp for the same pattern).
extern bool fRegTest;
extern bool fTestNet;

namespace {

// Regtest fork heights + a tip past all of them, restored on scope exit.
struct RegTestChainGuard
{
    bool fRegTestSaved;
    bool fTestNetSaved;
    int nBestHeightSaved;
    RegTestChainGuard()
    {
        fRegTestSaved = fRegTest;
        fTestNetSaved = fTestNet;
        nBestHeightSaved = nBestHeight;
        fRegTest = true;
        fTestNet = false;
        nBestHeight = 100;
    }
    ~RegTestChainGuard()
    {
        fRegTest = fRegTestSaved;
        fTestNet = fTestNetSaved;
        nBestHeight = nBestHeightSaved;
    }
};

CTransaction MakeCoinbase(unsigned int nTime)
{
    CTransaction tx;
    tx.nTime = nTime;
    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vin[0].scriptSig = CScript() << 42 << 42;
    tx.vout.resize(1);
    tx.vout[0].nValue = 0;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return tx;
}

CTransaction MakeNormalTx(unsigned int nTime, unsigned int nSeed)
{
    CTransaction tx;
    tx.nTime = nTime;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(uint256(1000 + nSeed), 0);
    tx.vin[0].scriptSig = CScript() << 1;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1 * COIN;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return tx;
}

// NullStake-version coinstake SHAPE: shielded spend present, empty vout[0].
// This is what CR-1 placed into vtx[2] of a proof-of-work block.
CTransaction MakeNullStakeShapedTx(unsigned int nTime)
{
    CTransaction tx;
    tx.nVersion = SHIELDED_TX_VERSION_NULLSTAKE_V2;
    tx.nTime = nTime;
    tx.vShieldedSpend.resize(1);
    tx.vShieldedSpend[0].nullifier = uint256(0xBEEF);
    tx.vout.resize(1);
    tx.vout[0].SetEmpty();
    tx.nValueBalance = -1; // shape of a genuine coinstake (reward into pool)
    return tx;
}

CBlock MakePoWBlock(const std::vector<CTransaction>& vTxs)
{
    CBlock block;
    unsigned int nTime = 0;
    for (const CTransaction& tx : vTxs)
    {
        block.vtx.push_back(tx);
        if (tx.nTime > nTime)
            nTime = tx.nTime;
    }
    block.nTime = nTime;
    return block;
}

} // namespace

BOOST_AUTO_TEST_SUITE(coinstake_guard_tests)

BOOST_AUTO_TEST_CASE(checkblock_rejects_nullstake_coinstake_outside_vtx1)
{
    RegTestChainGuard guard;
    unsigned int nTime = GetAdjustedTime();

    std::vector<CTransaction> vTxs;
    vTxs.push_back(MakeCoinbase(nTime));
    vTxs.push_back(MakeNormalTx(nTime, 1));
    vTxs.push_back(MakeNullStakeShapedTx(nTime));

    CBlock block = MakePoWBlock(vTxs);
    BOOST_REQUIRE(block.IsProofOfWork()); // vtx[1] is not a coinstake
    BOOST_REQUIRE(block.vtx[2].IsCoinStake());

    // Must be rejected even though the block is proof-of-work: the coinstake
    // exemptions in ConnectInputs would otherwise be claimable from vtx[2].
    BOOST_CHECK(!block.CheckBlock(false, false, false));
}

BOOST_AUTO_TEST_CASE(checkblock_accepts_same_block_without_extra_coinstake)
{
    RegTestChainGuard guard;
    unsigned int nTime = GetAdjustedTime();

    std::vector<CTransaction> vTxs;
    vTxs.push_back(MakeCoinbase(nTime));
    vTxs.push_back(MakeNormalTx(nTime, 1));
    vTxs.push_back(MakeNormalTx(nTime, 2));

    CBlock block = MakePoWBlock(vTxs);
    BOOST_CHECK(block.CheckBlock(false, false, false));
}

BOOST_AUTO_TEST_CASE(checkblock_rejects_second_coinstake_in_pos_block)
{
    RegTestChainGuard guard;
    unsigned int nTime = GetAdjustedTime();

    // vtx[1] coinstake makes the block proof-of-stake; the second
    // NullStake-shaped coinstake at vtx[2] must still be rejected.
    std::vector<CTransaction> vTxs;
    vTxs.push_back(MakeCoinbase(nTime));
    vTxs[0].vout[0].SetEmpty(); // PoS coinbase must be empty
    vTxs.push_back(MakeNullStakeShapedTx(nTime));
    vTxs.push_back(MakeNullStakeShapedTx(nTime + 1));

    CBlock block = MakePoWBlock(vTxs);
    BOOST_REQUIRE(block.IsProofOfStake());
    BOOST_CHECK(!block.CheckBlock(false, false, false));
}

BOOST_AUTO_TEST_CASE(checktransaction_rejects_coinstake_with_positive_balance)
{
    RegTestChainGuard guard;
    unsigned int nTime = GetAdjustedTime();

    // A coinstake only ever ADDS its reward to the shielded pool
    // (nValueBalance <= 0). Positive balance = unshield placed under the
    // coinstake exemptions.
    CTransaction txBad = MakeNullStakeShapedTx(nTime);
    txBad.nValueBalance = 1;
    BOOST_REQUIRE(txBad.IsCoinStake());
    BOOST_CHECK(!txBad.CheckTransaction());

    CTransaction txGood = MakeNullStakeShapedTx(nTime);
    txGood.nValueBalance = -1;
    BOOST_REQUIRE(txGood.IsCoinStake());
    BOOST_CHECK(txGood.CheckTransaction());
}

BOOST_AUTO_TEST_CASE(kernel_pinning_helper_pins_all_metadata)
{
    const unsigned int nTimeTx = 2000000000u;
    const unsigned int nGoodBTF = (unsigned int)((int64_t)nTimeTx - NULLSTAKE_PINNED_AGE);

    // Pinned shape passes.
    BOOST_CHECK(CheckNullStakeKernelPinning(nGoodBTF, 0, nGoodBTF, 0, nTimeTx));

    // Every unpinned field is a grinding dimension and must fail.
    BOOST_CHECK(!CheckNullStakeKernelPinning(nGoodBTF - 1, 0, nGoodBTF - 1, 0, nTimeTx)); // forged age
    BOOST_CHECK(!CheckNullStakeKernelPinning(nGoodBTF, 0, nGoodBTF + 7, 0, nTimeTx));     // free nTxTimePrev
    BOOST_CHECK(!CheckNullStakeKernelPinning(nGoodBTF, 3, nGoodBTF, 0, nTimeTx));         // free nTxPrevOffset
    BOOST_CHECK(!CheckNullStakeKernelPinning(nGoodBTF, 0, nGoodBTF, 9, nTimeTx));         // free nVoutN
    BOOST_CHECK(!CheckNullStakeKernelPinning(0, 0, 0, 0, (unsigned int)NULLSTAKE_PINNED_AGE)); // degenerate time
}

BOOST_AUTO_TEST_CASE(mainnet_fork_ladder_keeps_shielded_pool_born_safe)
{
    bool fRegTestSaved = fRegTest;
    bool fTestNetSaved = fTestNet;
    fRegTest = false;
    fTestNet = false;

    // The original supply-inflation P0 bug is live at any height where a shielded
    // spend can exist without nullifier binding: binding must activate with
    // the shielded pool itself, and kernel pinning with NullStake V2.
    BOOST_CHECK_EQUAL(GetForkHeightNullifierBinding(), GetForkHeightShielded());
    BOOST_CHECK_EQUAL(GetForkHeightKernelPinning(), GetForkHeightNullStakeV2());
    BOOST_CHECK(GetForkHeightShielded() <= GetForkHeightFCMP());
    BOOST_CHECK(GetForkHeightNullStakeV2() <= GetForkHeightNullStakeV3());
    BOOST_CHECK(GetForkHeightNullStakeV3() <= GetForkHeightDAG());

    fRegTest = fRegTestSaved;
    fTestNet = fTestNetSaved;
}

BOOST_AUTO_TEST_SUITE_END()
