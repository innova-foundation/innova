// Regression tests for the coinstake-position handling: a coinstake-shaped transaction outside vtx[1] of a
// proof-of-stake block must never reach the coinstake validation exemptions
// (shielded value balance, nullifier binding, value conservation), and a
// coinstake may never unshield (positive nValueBalance). Also covers the
// pinned V2/V3 kernel metadata helper and the mainnet fork-ladder alignment
// that keeps the shielded pool born-safe.

#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../curvetree.h"
#include "../wallet.h"

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

struct NetworkFlagsGuard
{
    bool fRegTestSaved;
    bool fTestNetSaved;
    StakingMode eStakingModeSaved;
    CBlockIndex* pindexBestSaved;

    NetworkFlagsGuard()
        : fRegTestSaved(fRegTest), fTestNetSaved(fTestNet),
          pindexBestSaved(pindexBest)
    {
        LOCK(cs_stakingMode);
        eStakingModeSaved = nStakingMode;
    }

    ~NetworkFlagsGuard()
    {
        fRegTest = fRegTestSaved;
        fTestNet = fTestNetSaved;
        pindexBest = pindexBestSaved;
        LOCK(cs_stakingMode);
        nStakingMode = eStakingModeSaved;
    }
};

void SetTestStakingMode(StakingMode eMode)
{
    LOCK(cs_stakingMode);
    nStakingMode = eMode;
}

std::vector<unsigned char> SerializeTransaction(const CTransaction& tx)
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << tx;
    return std::vector<unsigned char>(stream.begin(), stream.end());
}

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

    // The ladder moves only as one unit, in 60-block steps so the DAG gate stays an
    // epoch boundary. These golden vectors catch an accidental partial shift.
    BOOST_CHECK_GE(MAINNET_V5_ACTIVATION_SHIFT, 0);
    BOOST_CHECK_EQUAL(MAINNET_V5_ACTIVATION_SHIFT % 60, 0);
    BOOST_CHECK_EQUAL(GetForkHeightTighterDrift(),
                      7800000 + MAINNET_V5_ACTIVATION_SHIFT);
    BOOST_CHECK_EQUAL(GetForkHeightShielded(),
                      7800060 + MAINNET_V5_ACTIVATION_SHIFT);
    BOOST_CHECK_EQUAL(GetForkHeightFCMP(),
                      7800120 + MAINNET_V5_ACTIVATION_SHIFT);
    BOOST_CHECK_EQUAL(GetForkHeightDAG(),
                      7801200 + MAINNET_V5_ACTIVATION_SHIFT);
    BOOST_CHECK_EQUAL(GetForkHeightDAGKnight(),
                      7851200 + MAINNET_V5_ACTIVATION_SHIFT);
    // DAGKNIGHT is the top rung; the M-of-N staking gates are not on the public ladder.
    BOOST_CHECK_EQUAL(GetForkHeightNullStakeDelegSet(), PRIVACY_VNEXT_HEIGHT_UNSET);

    fRegTest = fRegTestSaved;
    fTestNet = fTestNetSaved;
}

BOOST_AUTO_TEST_CASE(public_wallet_policy_disables_legacy_private_staking_creation)
{
    NetworkFlagsGuard guard;

    // Public mainnet/testnet policy disables both legacy private staking modes
    // immediately, without affecting either transparent staking mode.
    fRegTest = false;
    fTestNet = false;
    BOOST_CHECK(!IsLegacyPrivateStakeCreationAllowed(STAKE_NULLSTAKE, 0));
    BOOST_CHECK(!IsLegacyPrivateStakeCreationAllowed(STAKE_NULLSTAKE_COLD, 0));
    BOOST_CHECK(IsLegacyPrivateStakeCreationAllowed(STAKE_TRANSPARENT, 0));
    BOOST_CHECK(IsLegacyPrivateStakeCreationAllowed(STAKE_COLD, 0));

    fTestNet = true;
    BOOST_CHECK(!IsLegacyPrivateStakeCreationAllowed(STAKE_NULLSTAKE, 0));
    BOOST_CHECK(!IsLegacyPrivateStakeCreationAllowed(STAKE_NULLSTAKE_COLD, 0));

    // Historical construction remains available only on isolated regtest and
    // only before a configured Boundary A.
    fRegTest = true;
    fTestNet = false;
    BOOST_CHECK(IsLegacyPrivateStakeCreationAllowed(STAKE_NULLSTAKE, 0));
    BOOST_CHECK(IsLegacyPrivateStakeCreationAllowed(STAKE_NULLSTAKE_COLD, 0));
    BOOST_CHECK(!IsLegacyPrivateStakeCreationAllowed(
        STAKE_NULLSTAKE, FORK_HEIGHT_BOUNDARY_A));
    BOOST_CHECK(!IsLegacyPrivateStakeCreationAllowed(
        STAKE_NULLSTAKE_COLD, FORK_HEIGHT_BOUNDARY_A));
    BOOST_CHECK(IsLegacyPrivateStakeCreationAllowed(
        STAKE_TRANSPARENT, FORK_HEIGHT_BOUNDARY_A));
    BOOST_CHECK(IsLegacyPrivateStakeCreationAllowed(
        STAKE_COLD, FORK_HEIGHT_BOUNDARY_A));
}

BOOST_AUTO_TEST_CASE(privacy_vnext_product_contract_keeps_all_required_modes)
{
    BOOST_CHECK_EQUAL((int)PRIVACY_MODE_TRANSPARENT, 0);
    BOOST_CHECK_EQUAL((int)PRIVACY_MODE_FULL, 7);
    BOOST_CHECK_EQUAL((int)PRIVACY_MODE_MASK, 7);
    BOOST_CHECK_EQUAL((int)SHIELDED_VNEXT_PRIVACY_MODE_COUNT, 8);
    BOOST_CHECK_EQUAL((int)SHIELDED_VNEXT_NULLSTAKE_GENERATION_COUNT, 3);
    BOOST_CHECK_EQUAL((int)SHIELDED_VNEXT_TREE_LAYERS, 8);
    BOOST_CHECK_EQUAL((int)SHIELDED_VNEXT_NULLSTAKE_V1, 1);
    BOOST_CHECK_EQUAL((int)SHIELDED_VNEXT_NULLSTAKE_V2, 2);
    BOOST_CHECK_EQUAL((int)SHIELDED_VNEXT_NULLSTAKE_V3, 3);
    BOOST_CHECK_EQUAL((int)SHIELDED_VNEXT_OPERATION_SHIELD, 0);
    BOOST_CHECK_EQUAL((int)SHIELDED_VNEXT_OPERATION_UNSHIELD, 1);
    BOOST_CHECK_EQUAL((int)SHIELDED_VNEXT_OPERATION_TRANSFER, 2);
    BOOST_CHECK_EQUAL((int)SHIELDED_VNEXT_OPERATION_NULLSEND, 3);
    BOOST_CHECK_EQUAL((int)SHIELDED_VNEXT_OPERATION_CONDITIONAL_MIGRATION, 7);
    BOOST_CHECK(iv5::EnvelopeAllows(2000, iv5::NOTE_TRANSFER,
                                    iv5::FINALITY_NONE, iv5::AUTH_OWNER,
                                    iv5::FINALITY_OBJECT_NONE, 7));
    BOOST_CHECK(!iv5::EnvelopeAllows(2000, iv5::NOTE_TRANSFER,
                                     iv5::FINALITY_NONE, iv5::AUTH_OWNER,
                                     iv5::FINALITY_OBJECT_NONE, 6));
    BOOST_CHECK(iv5::EnvelopeAllows(2003, iv5::NOTE_OPERATION_NONE,
                                    iv5::FINALITY_NULLSTAKE_V1,
                                    iv5::AUTH_OWNER,
                                    iv5::FINALITY_OBJECT_VOTE, 7));
    BOOST_CHECK(iv5::EnvelopeAllows(2008,
                                    iv5::NOTE_CONDITIONAL_MIGRATION,
                                    iv5::FINALITY_NONE, iv5::AUTH_OWNER,
                                    iv5::FINALITY_OBJECT_NONE, 0));
    // The mirror must know the operation the Rust decoder assigns to a collateral
    // attestation, or the raw-transaction view reports nothing about one.
    BOOST_CHECK_EQUAL((int)iv5::NOTE_COLLATERAL_REGISTER, 8);
    BOOST_CHECK(iv5::IsKnownNoteOperation(iv5::NOTE_COLLATERAL_REGISTER));
    BOOST_CHECK(iv5::EnvelopeAllows(2008, iv5::NOTE_COLLATERAL_REGISTER,
                                    iv5::FINALITY_NONE, iv5::AUTH_OWNER,
                                    iv5::FINALITY_OBJECT_NONE, 7));
    // Still refused on every earlier wire version.
    BOOST_CHECK(!iv5::EnvelopeAllows(2001, iv5::NOTE_COLLATERAL_REGISTER,
                                     iv5::FINALITY_NONE, iv5::AUTH_OWNER,
                                     iv5::FINALITY_OBJECT_NONE, 7));
}

BOOST_AUTO_TEST_CASE(public_private_staking_guard_precedes_wallet_mutation)
{
    NetworkFlagsGuard guard;
    fRegTest = false;
    fTestNet = false;
    pindexBest = NULL;

    CWallet wallet;
    CKey key;
    const StakingMode vPrivateModes[] = {
        STAKE_NULLSTAKE,
        STAKE_NULLSTAKE_COLD
    };

    for (size_t i = 0; i < sizeof(vPrivateModes) / sizeof(vPrivateModes[0]); ++i)
    {
        SetTestStakingMode(vPrivateModes[i]);

        CTransaction tx;
        tx.nTime = 123456;
        tx.vin.push_back(CTxIn(COutPoint(uint256(1234 + i), 1)));
        tx.vout.push_back(CTxOut(7, CScript() << OP_TRUE));
        const std::vector<unsigned char> vBefore = SerializeTransaction(tx);

        BOOST_CHECK(!wallet.CreateCoinStake(wallet, 0x1d00ffff, 1, 0,
                                             tx, key));
        BOOST_CHECK(vBefore == SerializeTransaction(tx));
    }
}

BOOST_AUTO_TEST_SUITE_END()
