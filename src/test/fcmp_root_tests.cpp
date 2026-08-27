#include <boost/test/unit_test.hpp>

#include "../ipa.h"
#include "../main.h"
#include "../shielded.h"
#include "../txdb.h"

// Defined in util.cpp.  Keep this declaration at global scope so it resolves
// the process-wide network selector rather than a namespace-local symbol.
extern bool fRegTest;

namespace
{

// Selects the public-network policy (legacy privacy relay rejected) for one test and
// restores the global afterwards.
struct PublicRelayPolicyGuard
{
    bool fRegTestSaved;

    PublicRelayPolicyGuard() : fRegTestSaved(fRegTest)
    {
        fRegTest = false;
    }

    ~PublicRelayPolicyGuard()
    {
        fRegTest = fRegTestSaved;
    }
};

CTransaction BuildFCMPSpendTx(const uint256& hashSpendRoot,
                              const uint256& nullifier = uint256(101))
{
    CTransaction tx;
    tx.nVersion = SHIELDED_TX_VERSION_FCMP;
    tx.nPrivacyMode = PRIVACY_MODE_FULL;

    CShieldedSpendDescription spend;
    spend.nullifier = nullifier;
    spend.curveTreeRoot = hashSpendRoot;
    tx.vShieldedSpend.push_back(spend);
    return tx;
}

CTransaction BuildBindingHashCoverageTx(int nVersion)
{
    CTransaction tx;
    tx.nVersion = nVersion;
    tx.nTime = 123456;
    tx.nLockTime = 0;
    tx.nPrivacyMode = PRIVACY_MODE_FULL;
    tx.nValueBalance = 0;

    CShieldedSpendDescription spend;
    spend.anchor = uint256(11);
    spend.nullifier = uint256(12);
    spend.rangeProof.vchProof.push_back(0x21);
    spend.vchLelantusProof.push_back(0x22);
    spend.lelantusSerial = uint256(13);
    spend.nPlaintextValue = 77;
    spend.vchPlaintextBlind.assign(32, 0x23);
    if (nVersion >= SHIELDED_TX_VERSION_FCMP)
    {
        spend.fcmpProof.vchProof.push_back(0x24);
        spend.fcmpProof.vchProof.push_back(0x25);
        spend.curveTreeRoot = uint256(14);
    }
    tx.vShieldedSpend.push_back(spend);

    CShieldedOutputDescription output;
    output.cmu = uint256(15);
    output.vchEphemeralKey.push_back(0x31);
    output.vchEncCiphertext.push_back(0x32);
    output.vchOutCiphertext.push_back(0x33);
    output.rangeProof.vchProof.push_back(0x34);
    output.nPlaintextValue = 55;
    output.vchPlaintextBlind.assign(32, 0x35);
    output.vchRecipientScript.push_back(0x36);
    tx.vShieldedOutput.push_back(output);

    return tx;
}

// B2-e Phase 3c: a SHIELDED_TX_VERSION_MOFN_MINT tx with one M-of-N mint output (marker 1: cv3 leaf
// + fresh value commitment Vv + 97-byte Okamoto link, hidden-amount) and one ordinary change output
// (marker 0, carries no M-of-N fields).
CTransaction BuildMofNMintTx()
{
    CTransaction tx;
    tx.nVersion = SHIELDED_TX_VERSION_MOFN_MINT;
    tx.nTime = 123456;
    tx.nLockTime = 0;
    tx.nPrivacyMode = PRIVACY_MODE_FULL;
    tx.nValueBalance = 0;

    CShieldedOutputDescription mofn;
    mofn.cv.vchCommitment.assign(33, 0x02);
    mofn.cmu = uint256(15);
    mofn.vchEphemeralKey.push_back(0x31);
    mofn.vchEncCiphertext.push_back(0x32);
    mofn.vchOutCiphertext.push_back(0x33);
    mofn.rangeProof.vchProof.push_back(0x34);
    mofn.nPlaintextValue = -1;
    mofn.nMofNType = 1;
    mofn.valueCommitmentVv.vchCommitment.assign(33, 0x03);
    mofn.vchMofNLink.assign(97, 0x44);
    tx.vShieldedOutput.push_back(mofn);

    CShieldedOutputDescription change;
    change.cv.vchCommitment.assign(33, 0x05);
    change.cmu = uint256(16);
    change.nPlaintextValue = -1;
    change.nMofNType = 0;
    tx.vShieldedOutput.push_back(change);

    return tx;
}

// B2-e Phase 3c.4: a SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM tx with an owner reclaim-auth struct.
CTransaction BuildReclaimTx()
{
    CTransaction tx;
    tx.nVersion = SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM;
    tx.nTime = 123456;
    tx.nLockTime = 0;
    tx.nPrivacyMode = PRIVACY_MODE_FULL;
    tx.nValueBalance = 0;

    CShieldedSpendDescription spend;
    spend.cv.vchCommitment.assign(33, 0x02);
    spend.nullifier = uint256(77);
    spend.vchRk.assign(33, 0x09);
    tx.vShieldedSpend.push_back(spend);

    tx.reclaimAuth.delegationHash = uint256(4242);
    tx.reclaimAuth.nThresholdM = 2;
    tx.reclaimAuth.vStakerSet.push_back(std::vector<unsigned char>(33, 0x11));
    tx.reclaimAuth.vStakerSet.push_back(std::vector<unsigned char>(33, 0x22));
    tx.reclaimAuth.vchPkOwner.assign(33, 0x09);

    return tx;
}

} // namespace

BOOST_AUTO_TEST_SUITE(fcmp_root_tests)

BOOST_AUTO_TEST_CASE(v5_unbound_membership_is_stopped_at_public_relay_policy)
{
    BOOST_REQUIRE(CZKContext::Initialize());

    // Proof-level membership statement only: zero nullifier, no value balance or output, so
    // it cannot create value if submitted.
    std::vector<unsigned char> blind(IPA_SCALAR_SIZE, 0);
    blind[IPA_SCALAR_SIZE - 1] = 7;
    CPedersenCommitment suppliedLeaf;
    BOOST_REQUIRE(CreatePedersenCommitment(17, blind, suppliedLeaf));

    // A recorded v5 envelope for this leaf, kept as a byte fixture now that the
    // prover that produced it is gone. Its siblings were prover-selected, so it
    // never established membership in any tree.
    CFCMPProof proof;
    proof.vchProof = ParseHex(
        "0500000001000000010000002102a96c22c9d4211cea9f84e168f7b842d9ee17cdf8ae21b2031456bffdd6171b5b"
        "21033c934127b15d08b6817197cac5c7deddf738fc0b3a0e7fd8444b0d24ab483dda208b5ced9121856fae79922a"
        "852542b51c101246d82a31fd172f22f21bf1143c6e20e346209e742c091cb11238053ee0bcb49c0878b38c02c98d"
        "fda90699f1cc2fe900000000203a09914253006315682ee12ae1db3007e98478ef395d8776e390495b53124f11208b"
        "70435b71c38b1c6baed52c03567e57ee3b73a8ee32a8c9df45557f93859b8f000000002102a7c0f07b05aeb35976"
        "e5b4d20f77a0994ae326d1422dbf9bbd821a5e21c7b313");
    BOOST_REQUIRE(!proof.IsNull());

    std::vector<unsigned char> unrelatedBlind(IPA_SCALAR_SIZE, 0);
    unrelatedBlind[IPA_SCALAR_SIZE - 1] = 9;
    CPedersenCommitment unrelatedLeaf;
    BOOST_REQUIRE(CreatePedersenCommitment(23, unrelatedBlind,
                                           unrelatedLeaf));
    CCurveTree unrelatedTree;
    BOOST_REQUIRE(unrelatedTree.InsertLeaf(unrelatedLeaf));
    BOOST_REQUIRE(unrelatedTree.FindLeafIndex(suppliedLeaf) < 0);

    CTransaction tx;
    tx.nVersion = SHIELDED_TX_VERSION_FCMP;
    tx.nPrivacyMode = PRIVACY_MODE_FULL;
    CShieldedSpendDescription spend;
    spend.cv = suppliedLeaf;
    spend.fcmpProof = proof;
    spend.curveTreeRoot = unrelatedTree.GetRoot();
    // Keep the context-free transaction intentionally invalid.  A zero
    // nullifier makes CheckTransaction increment nDoS if relay ever reaches
    // structural validation, which lets the assertion below prove ordering.
    spend.nullifier = uint256(0);
    tx.vShieldedSpend.push_back(spend);

    // Matching the root field in the transaction is only envelope equality; no
    // membership statement survives in this envelope. What refuses it, and in
    // what order, is what the rest of this case measures.

    // Confirm that nDoS is a reliable sentinel for the next validation stage:
    // an isolated context-free check sees the intentionally zero nullifier.
    CTransaction contextFreeProbe(tx);
    BOOST_CHECK(!contextFreeProbe.CheckTransaction());
    BOOST_CHECK_GT(contextFreeProbe.nDoS, 0);

    // The first rejection is the relay gate ("legacy shielded/privacy relay is
    // disabled"), before CheckTransaction (nDoS stays 0) and before input lookups.
    CTxDB txdb("r");
    CTxMemPool isolatedPool;
    bool fMissingInputs = false;
    bool fAccepted = true;
    {
        PublicRelayPolicyGuard policyGuard;
        BOOST_REQUIRE(IsLegacyPrivacyPolicyDisabled());
        LOCK(cs_main);
        fAccepted = isolatedPool.accept(txdb, tx, false,
                                        &fMissingInputs, true);
    }
    BOOST_CHECK(!fAccepted);
    BOOST_CHECK(!fMissingInputs);
    BOOST_CHECK_EQUAL(tx.nDoS, 0);
    BOOST_CHECK_EQUAL(isolatedPool.size(), 0U);
}

BOOST_AUTO_TEST_CASE(duplicate_shielded_nullifiers_are_rejected)
{
    CTransaction duplicate = BuildFCMPSpendTx(uint256(111111), uint256(9090));
    CShieldedSpendDescription duplicateSpend = duplicate.vShieldedSpend[0];
    duplicate.vShieldedSpend.push_back(duplicateSpend);
    BOOST_CHECK(!duplicate.CheckTransaction());
}

BOOST_AUTO_TEST_CASE(binding_sighash_covers_fcmp_proof_and_root_for_all_fcmp_versions)
{
    const int versions[] = {
        SHIELDED_TX_VERSION_FCMP,
        SHIELDED_TX_VERSION_NULLSTAKE,
        SHIELDED_TX_VERSION_NULLSTAKE_V2,
        SHIELDED_TX_VERSION_NULLSTAKE_COLD
    };

    for (int nVersion : versions)
    {
        CTransaction tx = BuildBindingHashCoverageTx(nVersion);
        uint256 hashBase = tx.GetBindingSigHash();

        CTransaction mutatedProof = tx;
        mutatedProof.vShieldedSpend[0].fcmpProof.vchProof[0] ^= 0x01;
        BOOST_CHECK(hashBase != mutatedProof.GetBindingSigHash());

        CTransaction mutatedRoot = tx;
        mutatedRoot.vShieldedSpend[0].curveTreeRoot = uint256(999000 + nVersion);
        BOOST_CHECK(hashBase != mutatedRoot.GetBindingSigHash());
    }
}

BOOST_AUTO_TEST_CASE(binding_sighash_covers_dsp_fields_for_versions_2001_to_2005)
{
    const int versions[] = {
        SHIELDED_TX_VERSION_DSP_PROTOTYPE,
        SHIELDED_TX_VERSION_FCMP,
        SHIELDED_TX_VERSION_NULLSTAKE,
        SHIELDED_TX_VERSION_NULLSTAKE_V2,
        SHIELDED_TX_VERSION_NULLSTAKE_COLD
    };

    for (int nVersion : versions)
    {
        CTransaction tx = BuildBindingHashCoverageTx(nVersion);
        uint256 hashBase = tx.GetBindingSigHash();

        CTransaction mutatedSpendValue = tx;
        mutatedSpendValue.vShieldedSpend[0].nPlaintextValue++;
        BOOST_CHECK(hashBase != mutatedSpendValue.GetBindingSigHash());

        CTransaction mutatedSpendBlind = tx;
        mutatedSpendBlind.vShieldedSpend[0].vchPlaintextBlind[0] ^= 0x01;
        BOOST_CHECK(hashBase != mutatedSpendBlind.GetBindingSigHash());

        CTransaction mutatedOutputValue = tx;
        mutatedOutputValue.vShieldedOutput[0].nPlaintextValue++;
        BOOST_CHECK(hashBase != mutatedOutputValue.GetBindingSigHash());

        CTransaction mutatedOutputBlind = tx;
        mutatedOutputBlind.vShieldedOutput[0].vchPlaintextBlind[0] ^= 0x01;
        BOOST_CHECK(hashBase != mutatedOutputBlind.GetBindingSigHash());

        CTransaction mutatedRecipient = tx;
        mutatedRecipient.vShieldedOutput[0].vchRecipientScript[0] ^= 0x01;
        BOOST_CHECK(hashBase != mutatedRecipient.GetBindingSigHash());

        CTransaction mutatedMode = tx;
        mutatedMode.nPrivacyMode ^= PRIVACY_HIDE_RECEIVER;
        BOOST_CHECK(hashBase != mutatedMode.GetBindingSigHash());
    }
}

// B2-e Phase 3c: the version-gated M-of-N mint output fields must round-trip through serialization,
// and a marker-0 output in the same tx must carry none of them.
BOOST_AUTO_TEST_CASE(mofn_mint_output_serialization_roundtrip)
{
    CTransaction tx = BuildMofNMintTx();

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << tx;
    CTransaction tx2;
    ss >> tx2;

    BOOST_REQUIRE_EQUAL(tx2.nVersion, SHIELDED_TX_VERSION_MOFN_MINT);
    BOOST_REQUIRE_EQUAL(tx2.vShieldedOutput.size(), 2u);

    // marked M-of-N output: fields round-trip exactly.
    BOOST_CHECK_EQUAL((int)tx2.vShieldedOutput[0].nMofNType, 1);
    BOOST_CHECK(tx2.vShieldedOutput[0].valueCommitmentVv.vchCommitment
                == tx.vShieldedOutput[0].valueCommitmentVv.vchCommitment);
    BOOST_CHECK(tx2.vShieldedOutput[0].vchMofNLink == tx.vShieldedOutput[0].vchMofNLink);
    BOOST_CHECK_EQUAL(tx2.vShieldedOutput[0].vchMofNLink.size(), 97u);

    // unmarked output: no M-of-N fields on the wire (marker round-trips 0; Vv stays at its 33-zero
    // construction default since it is not serialized; the link vector stays empty).
    BOOST_CHECK_EQUAL((int)tx2.vShieldedOutput[1].nMofNType, 0);
    BOOST_CHECK(tx2.vShieldedOutput[1].valueCommitmentVv.vchCommitment
                == tx.vShieldedOutput[1].valueCommitmentVv.vchCommitment);
    BOOST_CHECK(tx2.vShieldedOutput[1].vchMofNLink.empty());

    // whole-tx hash is stable across the round-trip.
    BOOST_CHECK(tx.GetHash() == tx2.GetHash());
}

// INV-4: the binding-sig hash MUST commit the M-of-N marker, Vv, and the link, or an in-flight
// adversary could re-randomize them and permanently brick the minted note.
BOOST_AUTO_TEST_CASE(binding_sighash_covers_mofn_mint_fields)
{
    CTransaction tx = BuildMofNMintTx();
    uint256 hashBase = tx.GetBindingSigHash();

    CTransaction mMarker = tx;
    mMarker.vShieldedOutput[0].nMofNType = 0;
    BOOST_CHECK(hashBase != mMarker.GetBindingSigHash());

    CTransaction mVv = tx;
    mVv.vShieldedOutput[0].valueCommitmentVv.vchCommitment[0] ^= 0x01;
    BOOST_CHECK(hashBase != mVv.GetBindingSigHash());

    CTransaction mLink = tx;
    mLink.vShieldedOutput[0].vchMofNLink[0] ^= 0x01;
    BOOST_CHECK(hashBase != mLink.GetBindingSigHash());
}

// B2-e Phase 3c.4: the version-gated reclaim-auth fields must round-trip through serialization.
BOOST_AUTO_TEST_CASE(reclaim_auth_serialization_roundtrip)
{
    CTransaction tx = BuildReclaimTx();

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << tx;
    CTransaction tx2;
    ss >> tx2;

    BOOST_REQUIRE_EQUAL(tx2.nVersion, SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM);
    BOOST_CHECK(tx2.reclaimAuth.delegationHash == tx.reclaimAuth.delegationHash);
    BOOST_CHECK_EQUAL(tx2.reclaimAuth.nThresholdM, 2u);
    BOOST_REQUIRE_EQUAL(tx2.reclaimAuth.vStakerSet.size(), 2u);
    BOOST_CHECK(tx2.reclaimAuth.vStakerSet[0] == tx.reclaimAuth.vStakerSet[0]);
    BOOST_CHECK(tx2.reclaimAuth.vchPkOwner == tx.reclaimAuth.vchPkOwner);
    BOOST_CHECK(tx.GetHash() == tx2.GetHash());
}

// The owner spend-auth sig binds the reclaim only if the reclaim-auth is in the binding-sig hash.
BOOST_AUTO_TEST_CASE(binding_sighash_covers_reclaim_auth)
{
    CTransaction tx = BuildReclaimTx();
    uint256 hashBase = tx.GetBindingSigHash();

    CTransaction mD = tx;
    mD.reclaimAuth.delegationHash = uint256(9999);
    BOOST_CHECK(hashBase != mD.GetBindingSigHash());

    CTransaction mOwner = tx;
    mOwner.reclaimAuth.vchPkOwner[0] ^= 0x01;
    BOOST_CHECK(hashBase != mOwner.GetBindingSigHash());

    CTransaction mSet = tx;
    mSet.reclaimAuth.vStakerSet[0][0] ^= 0x01;
    BOOST_CHECK(hashBase != mSet.GetBindingSigHash());
}

BOOST_AUTO_TEST_SUITE_END()
