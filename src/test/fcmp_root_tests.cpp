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

BOOST_AUTO_TEST_SUITE_END()
