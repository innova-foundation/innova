// B2-e: half-aggregated Schnorr M-of-N staking authorization — unit tests.
//
// Exercises the public-signer half-aggregation primitives: each signer produces a
// detached (R_j, s_j) share over a stake spend digest; the s-scalars are summed
// (AggregatePartialSigs) while the R-points are kept; verification checks
//   Sum_j R_j == s_agg*G + Sum_j e_j*pk_j.

#include <boost/test/unit_test.hpp>

#include "../uint256.h"
#include "../zkproof.h"
#include "../nullstake.h"
#include "../bulletproof_ac.h"
#include "../serialize.h"
#include "../version.h"

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

// Build an M-of-N authorization: derive the staker set + delegationHash from vSetSk, and a
// half-aggregated signature over stakeDigest from the signing keys vSignSk (which need not
// equal the set, so tests can exercise non-member signers).
bool BuildMofNAuth(const std::vector<uint256>& vSetSk, unsigned int M, const valtype& owner,
                   const std::vector<uint256>& vSignSk, const uint256& stakeDigest,
                   std::vector<valtype>& vSet, uint256& delegHash,
                   std::vector<valtype>& vSignerPk, std::vector<valtype>& vSignerR, valtype& sAgg)
{
    vSet.clear(); vSignerPk.clear(); vSignerR.clear();
    for (size_t i = 0; i < vSetSk.size(); i++)
    {
        valtype pk;
        if (!HalfAggStakeDerivePubKey(vSetSk[i], pk)) return false;
        vSet.push_back(pk);
    }
    if (!ComputeNullStakeV3DelegationSetHash(vSet, M, owner, delegHash)) return false;
    std::vector<valtype> vS;
    for (size_t i = 0; i < vSignSk.size(); i++)
    {
        valtype pk, R, s;
        if (!HalfAggStakeDerivePubKey(vSignSk[i], pk)) return false;
        if (!SignHalfAggStakeShare(vSignSk[i], stakeDigest, R, s)) return false;
        vSignerPk.push_back(pk); vSignerR.push_back(R); vS.push_back(s);
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

// --- Phase 2: delegation-set commitment ---
BOOST_AUTO_TEST_CASE(halfagg_stake_delegation_set_hash)
{
    BOOST_REQUIRE(CZKContext::Initialize());

    std::vector<valtype> set;
    for (int i = 1; i <= 3; i++)
    {
        valtype pk;
        BOOST_REQUIRE(HalfAggStakeDerivePubKey(uint256((uint64_t)(1000 + i)), pk));
        set.push_back(pk);
    }
    valtype owner;
    BOOST_REQUIRE(HalfAggStakeDerivePubKey(uint256(9999ULL), owner));

    uint256 h1, h2, hM, hbad;
    BOOST_REQUIRE(ComputeNullStakeV3DelegationSetHash(set, 2, owner, h1));
    BOOST_CHECK(h1 != uint256(0));

    // Order-independent: reversed member order yields the same commitment.
    std::vector<valtype> rev(set.rbegin(), set.rend());
    BOOST_REQUIRE(ComputeNullStakeV3DelegationSetHash(rev, 2, owner, h2));
    BOOST_CHECK_MESSAGE(h1 == h2, "delegation set hash must be order-independent");

    // Threshold M is bound into the commitment.
    BOOST_REQUIRE(ComputeNullStakeV3DelegationSetHash(set, 3, owner, hM));
    BOOST_CHECK_MESSAGE(h1 != hM, "changing M must change the delegation hash");

    // Rejections: duplicate member, M > N, M = 0.
    std::vector<valtype> dup = set; dup[1] = dup[0];
    BOOST_CHECK_MESSAGE(!ComputeNullStakeV3DelegationSetHash(dup, 2, owner, hbad),
                        "duplicate member must be rejected");
    BOOST_CHECK_MESSAGE(!ComputeNullStakeV3DelegationSetHash(set, 4, owner, hbad),
                        "M > N must be rejected");
    BOOST_CHECK_MESSAGE(!ComputeNullStakeV3DelegationSetHash(set, 0, owner, hbad),
                        "M = 0 must be rejected");
}

// --- Phase 2: V3 proof M-of-N fields serialize/deserialize round-trip ---
BOOST_AUTO_TEST_CASE(halfagg_stake_proof_serialization_roundtrip)
{
    BOOST_REQUIRE(CZKContext::Initialize());

    CNullStakeKernelProofV3 proof;
    proof.nThresholdM = 2;
    proof.nStakeModifier = 12345;
    proof.delegationHash = uint256(777ULL);
    for (int i = 1; i <= 2; i++)
    {
        valtype pk, R, s;
        BOOST_REQUIRE(HalfAggStakeDerivePubKey(uint256((uint64_t)(2000 + i)), pk));
        BOOST_REQUIRE(SignHalfAggStakeShare(uint256((uint64_t)(2000 + i)), uint256(55ULL), R, s));
        proof.vSignerPubKeys.push_back(pk);
        proof.vSignerRPoints.push_back(R);
    }
    proof.vchAggregatedSScalar = valtype(32, 0x07);

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << proof;
    CNullStakeKernelProofV3 proof2;
    ss >> proof2;

    BOOST_CHECK_EQUAL(proof2.nThresholdM, 2u);
    BOOST_CHECK(proof2.nStakeModifier == 12345ULL);
    BOOST_CHECK(proof2.delegationHash == uint256(777ULL));
    BOOST_CHECK_EQUAL(proof2.vSignerPubKeys.size(), 2u);
    BOOST_CHECK(proof2.vSignerPubKeys == proof.vSignerPubKeys);
    BOOST_CHECK(proof2.vSignerRPoints == proof.vSignerRPoints);
    BOOST_CHECK(proof2.vchAggregatedSScalar == proof.vchAggregatedSScalar);
}

// --- Phase 3: M-of-N authorization verifier (adversarial) ---
BOOST_AUTO_TEST_CASE(halfagg_stake_authorization_valid)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    valtype owner; BOOST_REQUIRE(HalfAggStakeDerivePubKey(uint256(8888ULL), owner));
    uint256 digest(424242ULL);
    std::vector<uint256> setSk;
    setSk.push_back(uint256(10001ULL)); setSk.push_back(uint256(10002ULL)); setSk.push_back(uint256(10003ULL));
    std::vector<uint256> signSk;
    signSk.push_back(uint256(10001ULL)); signSk.push_back(uint256(10002ULL)); // 2 of 3
    std::vector<valtype> vSet, vPk, vR; uint256 dh; valtype sAgg;
    BOOST_REQUIRE(BuildMofNAuth(setSk, 2, owner, signSk, digest, vSet, dh, vPk, vR, sAgg));
    std::string err;
    BOOST_CHECK_MESSAGE(VerifyNullStakeMofNAuthorization(vSet, 2, owner, dh, vPk, vR, sAgg, digest, err),
                        "valid 2-of-3 authorization should verify: " + err);
}

BOOST_AUTO_TEST_CASE(halfagg_stake_authorization_subthreshold_fails)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    valtype owner; BOOST_REQUIRE(HalfAggStakeDerivePubKey(uint256(8888ULL), owner));
    uint256 digest(424242ULL);
    std::vector<uint256> setSk;
    setSk.push_back(uint256(10001ULL)); setSk.push_back(uint256(10002ULL)); setSk.push_back(uint256(10003ULL));
    std::vector<uint256> signSk; signSk.push_back(uint256(10001ULL)); // only 1, M=2
    std::vector<valtype> vSet, vPk, vR; uint256 dh; valtype sAgg;
    BOOST_REQUIRE(BuildMofNAuth(setSk, 2, owner, signSk, digest, vSet, dh, vPk, vR, sAgg));
    std::string err;
    BOOST_CHECK_MESSAGE(!VerifyNullStakeMofNAuthorization(vSet, 2, owner, dh, vPk, vR, sAgg, digest, err),
                        "sub-threshold (1 of 2) must be rejected");
}

BOOST_AUTO_TEST_CASE(halfagg_stake_authorization_forged_set_fails)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    valtype owner; BOOST_REQUIRE(HalfAggStakeDerivePubKey(uint256(8888ULL), owner));
    uint256 digest(424242ULL);
    // Legit committed delegation hash for the real set.
    std::vector<uint256> setSk;
    setSk.push_back(uint256(10001ULL)); setSk.push_back(uint256(10002ULL)); setSk.push_back(uint256(10003ULL));
    std::vector<uint256> signSk; signSk.push_back(uint256(10001ULL)); signSk.push_back(uint256(10002ULL));
    std::vector<valtype> vSet, vPk, vR; uint256 dh; valtype sAgg;
    BOOST_REQUIRE(BuildMofNAuth(setSk, 2, owner, signSk, digest, vSet, dh, vPk, vR, sAgg));
    // Attacker substitutes their OWN set + a valid sig over it, but must verify against the
    // REAL committed delegationHash dh -> the recompute diverges and is rejected.
    std::vector<uint256> aSetSk;
    aSetSk.push_back(uint256(20001ULL)); aSetSk.push_back(uint256(20002ULL)); aSetSk.push_back(uint256(20003ULL));
    std::vector<uint256> aSignSk; aSignSk.push_back(uint256(20001ULL)); aSignSk.push_back(uint256(20002ULL));
    std::vector<valtype> aSet, aPk, aR; uint256 aDh; valtype aSAgg;
    BOOST_REQUIRE(BuildMofNAuth(aSetSk, 2, owner, aSignSk, digest, aSet, aDh, aPk, aR, aSAgg));
    std::string err;
    BOOST_CHECK_MESSAGE(!VerifyNullStakeMofNAuthorization(aSet, 2, owner, dh, aPk, aR, aSAgg, digest, err),
                        "a substituted staker set must not match the committed delegation hash");
}

BOOST_AUTO_TEST_CASE(halfagg_stake_authorization_nonmember_signer_fails)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    valtype owner; BOOST_REQUIRE(HalfAggStakeDerivePubKey(uint256(8888ULL), owner));
    uint256 digest(424242ULL);
    std::vector<uint256> setSk;
    setSk.push_back(uint256(10001ULL)); setSk.push_back(uint256(10002ULL)); setSk.push_back(uint256(10003ULL));
    // One signer (10001) is a member; the other (99999) is NOT in the set.
    std::vector<uint256> signSk; signSk.push_back(uint256(10001ULL)); signSk.push_back(uint256(99999ULL));
    std::vector<valtype> vSet, vPk, vR; uint256 dh; valtype sAgg;
    BOOST_REQUIRE(BuildMofNAuth(setSk, 2, owner, signSk, digest, vSet, dh, vPk, vR, sAgg));
    std::string err;
    BOOST_CHECK_MESSAGE(!VerifyNullStakeMofNAuthorization(vSet, 2, owner, dh, vPk, vR, sAgg, digest, err),
                        "a non-member signer must be rejected");
}

BOOST_AUTO_TEST_CASE(halfagg_stake_authorization_wrong_digest_fails)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    valtype owner; BOOST_REQUIRE(HalfAggStakeDerivePubKey(uint256(8888ULL), owner));
    uint256 digest(424242ULL);
    std::vector<uint256> setSk;
    setSk.push_back(uint256(10001ULL)); setSk.push_back(uint256(10002ULL)); setSk.push_back(uint256(10003ULL));
    std::vector<uint256> signSk; signSk.push_back(uint256(10001ULL)); signSk.push_back(uint256(10002ULL));
    std::vector<valtype> vSet, vPk, vR; uint256 dh; valtype sAgg;
    BOOST_REQUIRE(BuildMofNAuth(setSk, 2, owner, signSk, digest, vSet, dh, vPk, vR, sAgg));
    std::string err;
    // A different stake digest must not verify (the sig binds the specific stake -> no replay).
    BOOST_CHECK_MESSAGE(!VerifyNullStakeMofNAuthorization(vSet, 2, owner, dh, vPk, vR, sAgg, uint256(424243ULL), err),
                        "authorization must not verify under a different stake digest");
}

BOOST_AUTO_TEST_SUITE_END()
