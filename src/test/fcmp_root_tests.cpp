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

BOOST_AUTO_TEST_SUITE_END()
