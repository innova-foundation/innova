#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../shielded.h"

namespace
{

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

BOOST_AUTO_TEST_CASE(finalized_epoch_root_policy_rejects_wrong_stale_missing_roots)
{
    const uint256 hashFinalizedRoot(111111);
    const uint256 hashWrongRoot(222222);
    const uint256 hashStaleRoot(333333);
    std::string strError;

    CTransaction valid = BuildFCMPSpendTx(hashFinalizedRoot);
    BOOST_CHECK(CheckFCMPSpendRoots(valid,
                                    FORK_HEIGHT_EPOCH_ROOT_FCMP,
                                    hashFinalizedRoot,
                                    strError));

    CTransaction wrong = BuildFCMPSpendTx(hashWrongRoot);
    strError.clear();
    BOOST_CHECK(!CheckFCMPSpendRoots(wrong,
                                     FORK_HEIGHT_EPOCH_ROOT_FCMP,
                                     hashFinalizedRoot,
                                     strError));
    BOOST_CHECK(strError.find("does not match finalized epoch root") != std::string::npos);

    CTransaction stale = BuildFCMPSpendTx(hashStaleRoot);
    strError.clear();
    BOOST_CHECK(!CheckFCMPSpendRoots(stale,
                                     FORK_HEIGHT_EPOCH_ROOT_FCMP + 1,
                                     hashFinalizedRoot,
                                     strError));

    CTransaction missing = BuildFCMPSpendTx(uint256(0));
    strError.clear();
    BOOST_CHECK(!CheckFCMPSpendRoots(missing,
                                     FORK_HEIGHT_EPOCH_ROOT_FCMP,
                                     hashFinalizedRoot,
                                     strError));

    CTransaction preForkMutable = BuildFCMPSpendTx(hashWrongRoot);
    strError.clear();
    BOOST_CHECK(CheckFCMPSpendRoots(preForkMutable,
                                    FORK_HEIGHT_EPOCH_ROOT_FCMP - 1,
                                    hashFinalizedRoot,
                                    strError));

    CTransaction noSpend;
    noSpend.nVersion = SHIELDED_TX_VERSION_FCMP;
    strError.clear();
    BOOST_CHECK(CheckFCMPSpendRoots(noSpend,
                                    FORK_HEIGHT_EPOCH_ROOT_FCMP,
                                    hashFinalizedRoot,
                                    strError));
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
        SHIELDED_TX_VERSION_DSP,
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
