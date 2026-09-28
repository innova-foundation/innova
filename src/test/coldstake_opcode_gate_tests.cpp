// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// OP_CHECKCOLDSTAKEVERIFY is undefined (fails the script) before the cold-staking fork,
// as in v4.3.9.5. Pins the interpreter flag and each validator's activation height.

#include <boost/test/unit_test.hpp>

#include <limits>

#include "../key.h"
#include "../keystore.h"
#include "../main.h"
#include "../script.h"
#include "../txdb.h"

BOOST_AUTO_TEST_SUITE(coldstake_opcode_gate_tests)

namespace {

struct NetworkGuard
{
    bool fRegSaved, fTestSaved;
    NetworkGuard() : fRegSaved(fRegTest), fTestSaved(fTestNet) {}
    ~NetworkGuard() { fRegTest = fRegSaved; fTestNet = fTestSaved; }
};

struct ReplayVerifyGuard
{
    bool fSaved;
    ReplayVerifyGuard() : fSaved(fFullReplayVerify) { fFullReplayVerify = true; }
    ~ReplayVerifyGuard() { fFullReplayVerify = fSaved; }
};

// The flag sets ConnectBlock uses below and at/after FORK_HEIGHT_TIGHTER_DRIFT.
const unsigned int nBlockFlagsLoose = SCRIPT_VERIFY_NONE;
const unsigned int nBlockFlagsStrict = MANDATORY_SCRIPT_VERIFY_FLAGS |
                                       SCRIPT_VERIFY_STRICTENC |
                                       SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;

struct Delegation
{
    CKey stakerKey, ownerKey;
    CScript p2cs;
    Delegation()
    {
        stakerKey.MakeNewKey(true);
        ownerKey.MakeNewKey(true);
        p2cs = GetScriptForColdStaking(stakerKey.GetPubKey().GetID(),
                                       ownerKey.GetPubKey().GetID());
    }
};

CTransaction FundingTx(const CScript& scriptOut, int64_t nValue)
{
    CTransaction tx;
    tx.nTime = 1000;
    tx.vin.push_back(CTxIn(uint256(1), 0));
    tx.vout.push_back(CTxOut(nValue, scriptOut));
    return tx;
}

// Coinstake-shaped spend of txFrom:0 that pays scriptOut back.
CTransaction CoinstakeSpend(const CTransaction& txFrom, const CScript& scriptOut, int64_t nValue)
{
    CTransaction tx;
    tx.nTime = txFrom.nTime + 1;
    tx.vin.push_back(CTxIn(txFrom.GetHash(), 0));
    tx.vout.push_back(CTxOut());
    tx.vout[0].SetEmpty();
    tx.vout.push_back(CTxOut(nValue, scriptOut));
    return tx;
}

// Staker-path signature (the keystore holds only the staker key).
bool SignStaker(const Delegation& d, const CTransaction& txFrom, CTransaction& txTo)
{
    CBasicKeyStore keystore;
    keystore.AddKey(d.stakerKey);
    return SignSignature(keystore, txFrom, txTo, 0, SIGHASH_ALL);
}

// ConnectInputs on a synthetic input set, at a validated height.
bool ConnectAt(const CTransaction& txFrom, const CTransaction& tx, int nPrevHeight,
               bool fBlock, bool fMiner, int nCandidateHeight, unsigned int flags)
{
    LOCK(cs_main);
    CTxDB txdb("r");
    MapPrevTx inputs;
    inputs[txFrom.GetHash()] = std::make_pair(CTxIndex(CDiskTxPos(1, 1, 1), txFrom.vout.size()), txFrom);
    std::map<uint256, CTxIndex> mapTestPool;
    CBlockIndex index;
    index.nHeight = nPrevHeight;
    CTransaction txCopy = tx;
    return txCopy.ConnectInputs(txdb, inputs, mapTestPool, CDiskTxPos(1, 1, 1), &index,
                                fBlock, fMiner, flags, true, false, false,
                                nCandidateHeight, 0);
}

} // namespace

BOOST_AUTO_TEST_CASE(the_script_flag_follows_the_cold_staking_gate_on_every_network)
{
    NetworkGuard netGuard;

    fRegTest = false;
    fTestNet = false;
    const int nMain = FORK_HEIGHT_COLD_STAKING;
    BOOST_REQUIRE(nMain > 1000000);
    BOOST_CHECK_EQUAL(GetColdStakeScriptFlags(nMain - 1), 0U);
    BOOST_CHECK_EQUAL(GetColdStakeScriptFlags(nMain), (unsigned int)SCRIPT_VERIFY_COLDSTAKE);
    BOOST_CHECK_EQUAL(GetColdStakeScriptFlags(0), 0U);

    fTestNet = true;
    const int nTest = FORK_HEIGHT_COLD_STAKING;
    BOOST_CHECK_EQUAL(GetColdStakeScriptFlags(nTest - 1), 0U);
    BOOST_CHECK_EQUAL(GetColdStakeScriptFlags(nTest), (unsigned int)SCRIPT_VERIFY_COLDSTAKE);

    // The bit is not part of any standard set, so the non-mandatory retry keeps it.
    BOOST_CHECK_EQUAL(STANDARD_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_COLDSTAKE, 0U);
    BOOST_CHECK_EQUAL(STANDARD_NOT_MANDATORY_VERIFY_FLAGS & SCRIPT_VERIFY_COLDSTAKE, 0U);
}

BOOST_AUTO_TEST_CASE(a_staker_path_spend_fails_the_interpreter_below_the_gate)
{
    NetworkGuard netGuard;
    fRegTest = false;
    fTestNet = false;
    const int nGate = FORK_HEIGHT_COLD_STAKING;

    Delegation d;
    const CTransaction txFrom = FundingTx(d.p2cs, 10 * COIN);
    CTransaction txStake = CoinstakeSpend(txFrom, d.p2cs, 10 * COIN);
    BOOST_REQUIRE(txStake.IsCoinStake());
    BOOST_REQUIRE_MESSAGE(SignStaker(d, txFrom, txStake), "the signer refused a valid staker-path spend");

    BOOST_CHECK(!VerifySignature(txFrom, txStake, 0, nBlockFlagsLoose, 0));
    BOOST_CHECK(!VerifySignature(txFrom, txStake, 0, nBlockFlagsStrict, 0));
    BOOST_CHECK(!VerifySignature(txFrom, txStake, 0, nBlockFlagsStrict | GetColdStakeScriptFlags(nGate - 1), 0));
    BOOST_CHECK(VerifySignature(txFrom, txStake, 0, nBlockFlagsLoose | GetColdStakeScriptFlags(nGate), 0));
    BOOST_CHECK(VerifySignature(txFrom, txStake, 0, nBlockFlagsStrict | GetColdStakeScriptFlags(nGate), 0));

    // Any executed 0xd1 is gated, not only the P2CS template.
    CScript scriptBare;
    scriptBare << OP_CHECKCOLDSTAKEVERIFY << OP_TRUE;
    const CTransaction txBare = FundingTx(scriptBare, 10 * COIN);
    const CTransaction txBareStake = CoinstakeSpend(txBare, scriptBare, 10 * COIN);
    BOOST_CHECK(!VerifySignature(txBare, txBareStake, 0, nBlockFlagsLoose, 0));
    BOOST_CHECK(VerifySignature(txBare, txBareStake, 0, SCRIPT_VERIFY_COLDSTAKE, 0));

    // In an unexecuted branch 0xd1 stays inert, as in v4.
    CScript scriptSkipped;
    scriptSkipped << OP_0 << OP_IF << OP_CHECKCOLDSTAKEVERIFY << OP_ENDIF << OP_TRUE;
    const CTransaction txSkipped = FundingTx(scriptSkipped, 10 * COIN);
    const CTransaction txSkippedStake = CoinstakeSpend(txSkipped, scriptSkipped, 10 * COIN);
    BOOST_CHECK(VerifySignature(txSkipped, txSkippedStake, 0, nBlockFlagsLoose, 0));
}

BOOST_AUTO_TEST_CASE(an_owner_path_spend_passes_below_the_gate)
{
    Delegation d;
    const CTransaction txFrom = FundingTx(d.p2cs, 10 * COIN);

    CTransaction txSpend;
    txSpend.nTime = txFrom.nTime + 1;
    txSpend.vin.push_back(CTxIn(txFrom.GetHash(), 0));
    CScript scriptOwner;
    scriptOwner.SetDestination(d.ownerKey.GetPubKey().GetID());
    txSpend.vout.push_back(CTxOut(9 * COIN, scriptOwner));

    CBasicKeyStore keystore;
    keystore.AddKey(d.ownerKey);
    BOOST_REQUIRE(SignSignature(keystore, txFrom, txSpend, 0, SIGHASH_ALL));

    BOOST_CHECK(VerifySignature(txFrom, txSpend, 0, nBlockFlagsLoose, 0));
    BOOST_CHECK(VerifySignature(txFrom, txSpend, 0, nBlockFlagsStrict, 0));
    BOOST_CHECK(VerifySignature(txFrom, txSpend, 0, nBlockFlagsStrict | SCRIPT_VERIFY_COLDSTAKE, 0));
}

// Block (ConnectBlock), mempool (AcceptToMemoryPool) and miner (CreateNewBlock) call
// shapes, at gate-1 and gate on mainnet. The caller-passed bit is overridden.
BOOST_AUTO_TEST_CASE(connect_inputs_sets_the_flag_by_the_carrying_block_height)
{
    NetworkGuard netGuard;
    ReplayVerifyGuard replayGuard;
    fRegTest = false;
    fTestNet = false;
    const int nGate = FORK_HEIGHT_COLD_STAKING;

    Delegation d;
    const CTransaction txFrom = FundingTx(d.p2cs, 10 * COIN);
    CTransaction txStake = CoinstakeSpend(txFrom, d.p2cs, 9 * COIN);
    BOOST_REQUIRE(SignStaker(d, txFrom, txStake));

    const unsigned int vFlags[4] = {
        nBlockFlagsLoose, nBlockFlagsStrict,
        nBlockFlagsStrict | SCRIPT_VERIFY_COLDSTAKE, STANDARD_SCRIPT_VERIFY_FLAGS
    };
    for (int f = 0; f < 4; f++)
    {
        const unsigned int flags = vFlags[f];
        // ConnectBlock: pindex is the carrying block, candidate height is its height.
        BOOST_CHECK_MESSAGE(!ConnectAt(txFrom, txStake, nGate - 1, true, false, nGate - 1, flags),
                            "block below the gate accepted a staker-path spend, flags " << flags);
        BOOST_CHECK_MESSAGE(ConnectAt(txFrom, txStake, nGate, true, false, nGate, flags),
                            "block at the gate refused a staker-path spend, flags " << flags);

        // Mempool: pindexBest is the parent, candidate height is the next block.
        BOOST_CHECK_MESSAGE(!ConnectAt(txFrom, txStake, nGate - 2, false, false, nGate - 1, flags),
                            "mempool below the gate accepted a staker-path spend, flags " << flags);
        BOOST_CHECK_MESSAGE(ConnectAt(txFrom, txStake, nGate - 1, false, false, nGate, flags),
                            "mempool for the gate block refused a staker-path spend, flags " << flags);

        // Miner: no candidate height, derived from the parent.
        BOOST_CHECK_MESSAGE(!ConnectAt(txFrom, txStake, nGate - 2, false, true, -1, flags),
                            "miner below the gate accepted a staker-path spend, flags " << flags);
        BOOST_CHECK_MESSAGE(ConnectAt(txFrom, txStake, nGate - 1, false, true, -1, flags),
                            "miner for the gate block refused a staker-path spend, flags " << flags);
    }
}

BOOST_AUTO_TEST_SUITE_END()
