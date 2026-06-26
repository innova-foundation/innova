// B2-e: half-aggregated Schnorr M-of-N staking authorization — unit tests.
//
// Exercises the public-signer half-aggregation primitives: each signer produces a
// detached (R_j, s_j) share over a stake spend digest; the s-scalars are summed
// (AggregatePartialSigs) while the R-points are kept; verification checks
//   Sum_j R_j == s_agg*G + Sum_j e_j*pk_j.

#include <boost/test/unit_test.hpp>

#include "../uint256.h"
#include "../zkproof.h"

#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(halfagg_stake_tests)

namespace
{
typedef std::vector<unsigned char> valtype;

// Build an M-of-N half-aggregated signature over sighash from M signer scalars.
bool BuildHalfAggSig(const std::vector<uint256>& vSk,
                     const uint256& sighash,
                     std::vector<valtype>& vPk,
                     std::vector<valtype>& vR,
                     valtype& sAgg)
{
    vPk.clear();
    vR.clear();
    std::vector<valtype> vS;
    for (size_t i = 0; i < vSk.size(); i++)
    {
        valtype pk, R, s;
        if (!HalfAggStakeDerivePubKey(vSk[i], pk)) return false;
        if (!SignHalfAggStakeShare(vSk[i], sighash, R, s)) return false;
        vPk.push_back(pk);
        vR.push_back(R);
        vS.push_back(s);
    }
    return AggregatePartialSigs(vS, sAgg);
}
} // namespace

BOOST_AUTO_TEST_CASE(halfagg_stake_roundtrip_3of3)
{
    BOOST_REQUIRE(CZKContext::Initialize());

    uint256 sighash(987654321ULL);
    std::vector<uint256> vSk;
    vSk.push_back(uint256(111111ULL));
    vSk.push_back(uint256(222222ULL));
    vSk.push_back(uint256(333333ULL));

    std::vector<valtype> vPk, vR;
    valtype sAgg;
    BOOST_REQUIRE(BuildHalfAggSig(vSk, sighash, vPk, vR, sAgg));
    BOOST_CHECK_EQUAL(vPk.size(), 3u);
    BOOST_CHECK_EQUAL(sAgg.size(), 32u);

    std::string err;
    BOOST_CHECK_MESSAGE(VerifyHalfAggStakeSignature(vPk, vR, sAgg, sighash, err),
                        "valid 3-of-3 half-agg signature should verify: " + err);
}

BOOST_AUTO_TEST_CASE(halfagg_stake_single_signer)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    uint256 sighash(42ULL);
    std::vector<uint256> vSk(1, uint256(7654321ULL));
    std::vector<valtype> vPk, vR;
    valtype sAgg;
    BOOST_REQUIRE(BuildHalfAggSig(vSk, sighash, vPk, vR, sAgg));
    std::string err;
    BOOST_CHECK_MESSAGE(VerifyHalfAggStakeSignature(vPk, vR, sAgg, sighash, err),
                        "valid 1-of-1 should verify: " + err);
}

BOOST_AUTO_TEST_CASE(halfagg_stake_tampered_sscalar_fails)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    uint256 sighash(987654321ULL);
    std::vector<uint256> vSk;
    vSk.push_back(uint256(111111ULL));
    vSk.push_back(uint256(222222ULL));
    std::vector<valtype> vPk, vR;
    valtype sAgg;
    BOOST_REQUIRE(BuildHalfAggSig(vSk, sighash, vPk, vR, sAgg));

    sAgg[16] ^= 0x01; // flip a bit in the aggregated s-scalar
    std::string err;
    BOOST_CHECK_MESSAGE(!VerifyHalfAggStakeSignature(vPk, vR, sAgg, sighash, err),
                        "tampered s-scalar must NOT verify");
}

BOOST_AUTO_TEST_CASE(halfagg_stake_tampered_rpoint_fails)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    uint256 sighash(987654321ULL);
    std::vector<uint256> vSk;
    vSk.push_back(uint256(111111ULL));
    vSk.push_back(uint256(222222ULL));
    std::vector<valtype> vPk, vR;
    valtype sAgg;
    BOOST_REQUIRE(BuildHalfAggSig(vSk, sighash, vPk, vR, sAgg));

    vR[1][20] ^= 0x01; // perturb an R-point body (keep the 0x02/0x03 prefix)
    std::string err;
    BOOST_CHECK_MESSAGE(!VerifyHalfAggStakeSignature(vPk, vR, sAgg, sighash, err),
                        "tampered R-point must NOT verify");
}

BOOST_AUTO_TEST_CASE(halfagg_stake_wrong_sighash_fails)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    uint256 sighash(987654321ULL);
    std::vector<uint256> vSk;
    vSk.push_back(uint256(111111ULL));
    vSk.push_back(uint256(222222ULL));
    std::vector<valtype> vPk, vR;
    valtype sAgg;
    BOOST_REQUIRE(BuildHalfAggSig(vSk, sighash, vPk, vR, sAgg));

    std::string err;
    BOOST_CHECK_MESSAGE(!VerifyHalfAggStakeSignature(vPk, vR, sAgg, uint256(987654322ULL), err),
                        "signature must NOT verify under a different sighash");
}

BOOST_AUTO_TEST_CASE(halfagg_stake_duplicate_signer_fails)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    uint256 sighash(987654321ULL);
    std::vector<uint256> vSk;
    vSk.push_back(uint256(111111ULL));
    vSk.push_back(uint256(111111ULL)); // same key twice -> not M distinct signers
    vSk.push_back(uint256(333333ULL));
    std::vector<valtype> vPk, vR;
    valtype sAgg;
    BOOST_REQUIRE(BuildHalfAggSig(vSk, sighash, vPk, vR, sAgg));

    std::string err;
    BOOST_CHECK_MESSAGE(!VerifyHalfAggStakeSignature(vPk, vR, sAgg, sighash, err),
                        "duplicate signer pubkey must be rejected");
}

BOOST_AUTO_TEST_CASE(halfagg_stake_dropped_signer_fails)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    // Aggregate over 3 signers, but present only 2 of the pk/R pairs: the relation
    // can no longer close, so a sub-threshold subset must not verify.
    uint256 sighash(987654321ULL);
    std::vector<uint256> vSk;
    vSk.push_back(uint256(111111ULL));
    vSk.push_back(uint256(222222ULL));
    vSk.push_back(uint256(333333ULL));
    std::vector<valtype> vPk, vR;
    valtype sAgg;
    BOOST_REQUIRE(BuildHalfAggSig(vSk, sighash, vPk, vR, sAgg));

    std::vector<valtype> vPk2(vPk.begin(), vPk.begin() + 2);
    std::vector<valtype> vR2(vR.begin(), vR.begin() + 2);
    std::string err;
    BOOST_CHECK_MESSAGE(!VerifyHalfAggStakeSignature(vPk2, vR2, sAgg, sighash, err),
                        "aggregate over 3 must not verify against 2 signers");
}

BOOST_AUTO_TEST_CASE(halfagg_stake_count_mismatch_fails)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    uint256 sighash(987654321ULL);
    std::vector<uint256> vSk;
    vSk.push_back(uint256(111111ULL));
    vSk.push_back(uint256(222222ULL));
    std::vector<valtype> vPk, vR;
    valtype sAgg;
    BOOST_REQUIRE(BuildHalfAggSig(vSk, sighash, vPk, vR, sAgg));

    vR.pop_back(); // R-point count no longer matches signer count
    std::string err;
    BOOST_CHECK_MESSAGE(!VerifyHalfAggStakeSignature(vPk, vR, sAgg, sighash, err),
                        "mismatched R-point/signer counts must be rejected");
}

BOOST_AUTO_TEST_SUITE_END()
