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
#include <utility>
#include <algorithm>

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
// equal the set, so tests can exercise non-member signers). The set and the signer subset are
// produced in canonical strictly-ascending order (the wire form the verifier now requires);
// the half-agg signature is order-independent so reordering the (pk,R,s) triples by pk is safe.
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
    std::sort(vSet.begin(), vSet.end());  // canonical ascending set
    if (!ComputeNullStakeV3DelegationSetHash(vSet, M, owner, delegHash)) return false;

    // Build (pk -> (R, s)) signer triples, then sort ascending by pk (R/s stay paired).
    std::vector<std::pair<valtype, std::pair<valtype, valtype> > > trips;
    for (size_t i = 0; i < vSignSk.size(); i++)
    {
        valtype pk, R, s;
        if (!HalfAggStakeDerivePubKey(vSignSk[i], pk)) return false;
        if (!SignHalfAggStakeShare(vSignSk[i], stakeDigest, R, s)) return false;
        trips.push_back(std::make_pair(pk, std::make_pair(R, s)));
    }
    std::sort(trips.begin(), trips.end());  // distinct pks -> deterministic ascending order
    std::vector<valtype> vS;
    for (size_t i = 0; i < trips.size(); i++)
    {
        vSignerPk.push_back(trips[i].first);
        vSignerR.push_back(trips[i].second.first);
        vS.push_back(trips[i].second.second);
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
    for (int i = 1; i <= 3; i++)   // 3-member set, 2 signers
    {
        valtype pk;
        BOOST_REQUIRE(HalfAggStakeDerivePubKey(uint256((uint64_t)(2000 + i)), pk));
        proof.vStakerSet.push_back(pk);
    }
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
    BOOST_CHECK_EQUAL(proof2.vStakerSet.size(), 3u);
    BOOST_CHECK(proof2.vStakerSet == proof.vStakerSet);
    BOOST_CHECK_EQUAL(proof2.vSignerPubKeys.size(), 2u);
    BOOST_CHECK(proof2.vSignerPubKeys == proof.vSignerPubKeys);
    BOOST_CHECK(proof2.vSignerRPoints == proof.vSignerRPoints);
    BOOST_CHECK(proof2.vchAggregatedSScalar == proof.vchAggregatedSScalar);

    // Legacy (nThresholdM == 0) proof must serialize compactly: the M-of-N fields are absent
    // on the wire, so a populated-then-zeroed proof round-trips with empty M-of-N vectors and
    // is byte-identical to one that never set them.
    CNullStakeKernelProofV3 legacy;
    legacy.nThresholdM = 0;
    legacy.delegationHash = uint256(888ULL);
    legacy.vStakerSet = proof.vStakerSet;        // set but must NOT be serialized for M==0
    legacy.vSignerPubKeys = proof.vSignerPubKeys; // ditto
    CDataStream ssL(SER_DISK, CLIENT_VERSION);
    ssL << legacy;
    size_t legacySize = ssL.size();   // measure BEFORE the read below consumes the stream
    CNullStakeKernelProofV3 legacy2;
    ssL >> legacy2;
    BOOST_CHECK_EQUAL(legacy2.nThresholdM, 0u);
    BOOST_CHECK_MESSAGE(legacy2.vStakerSet.empty(), "legacy proof must not carry the staker set on the wire");
    BOOST_CHECK_MESSAGE(legacy2.vSignerPubKeys.empty(), "legacy proof must not carry signer pubkeys on the wire");
    CNullStakeKernelProofV3 legacyClean;
    legacyClean.nThresholdM = 0;
    legacyClean.delegationHash = uint256(888ULL);
    CDataStream ssC(SER_DISK, CLIENT_VERSION);
    ssC << legacyClean;
    BOOST_CHECK_MESSAGE(legacySize == ssC.size(),
                        "legacy serialization must be independent of unused M-of-N members");
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

// --- Phase 3b step 1: stake-authorization digest ---
BOOST_AUTO_TEST_CASE(halfagg_stake_digest_deterministic_and_bound)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    uint256 dh(111ULL);
    valtype cv(33, 0x02);
    uint256 d1 = ComputeNullStakeMofNStakeDigest(dh, 5, 6, 7, 8, 9, 10, cv);
    uint256 d2 = ComputeNullStakeMofNStakeDigest(dh, 5, 6, 7, 8, 9, 10, cv);
    BOOST_CHECK_MESSAGE(d1 == d2, "stake digest must be deterministic");
    BOOST_CHECK(d1 != uint256(0));
    // Every bound field must change the digest.
    BOOST_CHECK(ComputeNullStakeMofNStakeDigest(uint256(112ULL), 5, 6, 7, 8, 9, 10, cv) != d1);
    BOOST_CHECK(ComputeNullStakeMofNStakeDigest(dh, 6, 6, 7, 8, 9, 10, cv) != d1);
    BOOST_CHECK(ComputeNullStakeMofNStakeDigest(dh, 5, 6, 7, 8, 9, 11, cv) != d1);
    valtype cv2(33, 0x03);
    BOOST_CHECK(ComputeNullStakeMofNStakeDigest(dh, 5, 6, 7, 8, 9, 10, cv2) != d1);
}

BOOST_AUTO_TEST_CASE(halfagg_stake_digest_endtoend_authorization)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    valtype owner; BOOST_REQUIRE(HalfAggStakeDerivePubKey(uint256(8888ULL), owner));
    std::vector<uint256> setSk;
    setSk.push_back(uint256(10001ULL)); setSk.push_back(uint256(10002ULL)); setSk.push_back(uint256(10003ULL));
    std::vector<valtype> vSet;
    for (size_t i = 0; i < setSk.size(); i++)
    {
        valtype pk; BOOST_REQUIRE(HalfAggStakeDerivePubKey(setSk[i], pk)); vSet.push_back(pk);
    }
    std::sort(vSet.begin(), vSet.end());  // canonical order required by the verifier (R4)
    uint256 dh; BOOST_REQUIRE(ComputeNullStakeV3DelegationSetHash(vSet, 2, owner, dh));

    valtype cv(33, 0x02);
    uint256 digest = ComputeNullStakeMofNStakeDigest(dh, 1234, 11, 22, 33, 1, 44, cv);
    std::vector<uint256> signSk; signSk.push_back(uint256(10001ULL)); signSk.push_back(uint256(10002ULL));
    std::vector<valtype> vSet2, vPk, vR; uint256 dh2; valtype sAgg;
    BOOST_REQUIRE(BuildMofNAuth(setSk, 2, owner, signSk, digest, vSet2, dh2, vPk, vR, sAgg));

    std::string err;
    BOOST_CHECK_MESSAGE(VerifyNullStakeMofNAuthorization(vSet, 2, owner, dh, vPk, vR, sAgg, digest, err),
                        "end-to-end digest + authorization should verify: " + err);
    // The same signature must NOT authorize a stake with a different kernel parameter.
    uint256 digestReplay = ComputeNullStakeMofNStakeDigest(dh, 9999, 11, 22, 33, 1, 44, cv);
    BOOST_CHECK_MESSAGE(!VerifyNullStakeMofNAuthorization(vSet, 2, owner, dh, vPk, vR, sAgg, digestReplay, err),
                        "signature must not authorize a different stake (replay protection)");
}

// --- Phase 3b step 2: delegationHash-binding commitment ---
BOOST_AUTO_TEST_CASE(halfagg_stake_delegation_commitment)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    valtype blind(32, 0x11); blind[31] = 0x07; // nonzero 32-byte blinding
    int64_t value = 5000000;
    uint256 dh(123456ULL);

    CPedersenCommitment c;
    BOOST_REQUIRE(CreateNullStakeMofNCommitment(value, blind, dh, c));
    BOOST_CHECK(!c.IsNull());

    // Opens to exactly (value, blind, delegationHash).
    BOOST_CHECK(VerifyNullStakeMofNCommitment(c, value, blind, dh));

    // Binding: any change in value / blind / delegationHash fails to open.
    BOOST_CHECK(!VerifyNullStakeMofNCommitment(c, value + 1, blind, dh));
    valtype blind2 = blind; blind2[0] ^= 0x01;
    BOOST_CHECK(!VerifyNullStakeMofNCommitment(c, value, blind2, dh));
    BOOST_CHECK(!VerifyNullStakeMofNCommitment(c, value, blind, uint256(123457ULL)));

    // Deterministic.
    CPedersenCommitment c2;
    BOOST_REQUIRE(CreateNullStakeMofNCommitment(value, blind, dh, c2));
    BOOST_CHECK(c.vchCommitment == c2.vchCommitment);

    // delegationHash == 0 reduces to the plain value commitment.
    CPedersenCommitment cZero, cPlain;
    BOOST_REQUIRE(CreateNullStakeMofNCommitment(value, blind, uint256(0), cZero));
    BOOST_REQUIRE(CreatePedersenCommitment(value, blind, cPlain));
    BOOST_CHECK_MESSAGE(cZero.vchCommitment == cPlain.vchCommitment,
                        "delegationHash==0 must reduce to the plain Pedersen commitment");

    // A different delegation yields a different commitment point.
    CPedersenCommitment cOther;
    BOOST_REQUIRE(CreateNullStakeMofNCommitment(value, blind, uint256(999ULL), cOther));
    BOOST_CHECK(cOther.vchCommitment != c.vchCommitment);
}

// --- Phase 3b step 3 (core): cv_plain derivation from the 3-generator leaf ---
BOOST_AUTO_TEST_CASE(halfagg_stake_cvplain_derivation)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    valtype blind(32, 0x11); blind[31] = 0x07;
    int64_t value = 5000000;
    uint256 dh(123456ULL);

    // Leaf cv3 = value*H + blind*G + dh*J ; the plain commitment = value*H + blind*G.
    CPedersenCommitment cv3, cvExpected, cvPlain;
    BOOST_REQUIRE(CreateNullStakeMofNCommitment(value, blind, dh, cv3));
    BOOST_REQUIRE(CreatePedersenCommitment(value, blind, cvExpected));

    // The correct delegationHash recovers exactly the plain value commitment.
    BOOST_REQUIRE(NullStakeMofNDeriveValueCommitment(cv3, dh, cvPlain));
    BOOST_CHECK_MESSAGE(cvPlain.vchCommitment == cvExpected.vchCommitment,
                        "cv_plain must equal the plain value commitment for the correct delegationHash");
    // ...and it opens as a normal 2-generator value commitment (range/nullifier would accept).
    BOOST_CHECK(VerifyPedersenCommitment(cvPlain, value, blind));

    // A WRONG delegationHash leaves a residual J term: cv_plain != the plain commitment and
    // does NOT open to (value, blind), so the 2-generator range proof would reject it.
    CPedersenCommitment cvWrong;
    BOOST_REQUIRE(NullStakeMofNDeriveValueCommitment(cv3, uint256(123457ULL), cvWrong));
    BOOST_CHECK(cvWrong.vchCommitment != cvExpected.vchCommitment);
    BOOST_CHECK_MESSAGE(!VerifyPedersenCommitment(cvWrong, value, blind),
                        "a wrong delegationHash must not yield a valid value commitment");
}

// --- Audit R4/R8: canonical wire order is enforced + s-scalar range ---
namespace
{
void Build2of3(std::vector<valtype>& vSet, uint256& dh, valtype& owner,
               std::vector<valtype>& vPk, std::vector<valtype>& vR, valtype& sAgg,
               const uint256& digest)
{
    BOOST_REQUIRE(HalfAggStakeDerivePubKey(uint256(8888ULL), owner));
    std::vector<uint256> setSk;
    setSk.push_back(uint256(10001ULL)); setSk.push_back(uint256(10002ULL)); setSk.push_back(uint256(10003ULL));
    std::vector<uint256> signSk; signSk.push_back(uint256(10001ULL)); signSk.push_back(uint256(10002ULL));
    BOOST_REQUIRE(BuildMofNAuth(setSk, 2, owner, signSk, digest, vSet, dh, vPk, vR, sAgg));
}
} // namespace

BOOST_AUTO_TEST_CASE(halfagg_stake_noncanonical_set_rejected)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    uint256 digest(424242ULL);
    std::vector<valtype> vSet, vPk, vR; uint256 dh; valtype owner, sAgg;
    Build2of3(vSet, dh, owner, vPk, vR, sAgg, digest);
    std::string err;
    BOOST_REQUIRE_MESSAGE(VerifyNullStakeMofNAuthorization(vSet, 2, owner, dh, vPk, vR, sAgg, digest, err),
                          "canonical form should verify: " + err);
    // Descending (non-canonical) staker set must be rejected even though it hashes the same.
    std::vector<valtype> vSetRev(vSet.rbegin(), vSet.rend());
    BOOST_CHECK_MESSAGE(!VerifyNullStakeMofNAuthorization(vSetRev, 2, owner, dh, vPk, vR, sAgg, digest, err),
                        "a non-canonical (descending) staker set must be rejected");
}

BOOST_AUTO_TEST_CASE(halfagg_stake_noncanonical_signers_rejected)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    uint256 digest(424242ULL);
    std::vector<valtype> vSet, vPk, vR; uint256 dh; valtype owner, sAgg;
    Build2of3(vSet, dh, owner, vPk, vR, sAgg, digest);
    std::string err;
    // Reverse the signer pubkeys and R-points in lockstep (pairing preserved, order descending).
    std::vector<valtype> vPkRev(vPk.rbegin(), vPk.rend());
    std::vector<valtype> vRRev(vR.rbegin(), vR.rend());
    BOOST_CHECK_MESSAGE(!VerifyNullStakeMofNAuthorization(vSet, 2, owner, dh, vPkRev, vRRev, sAgg, digest, err),
                        "a non-canonical (descending) signer set must be rejected");
}

BOOST_AUTO_TEST_CASE(halfagg_stake_sagg_out_of_range_rejected)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    uint256 digest(424242ULL);
    std::vector<valtype> vSet, vPk, vR; uint256 dh; valtype owner, sAgg;
    Build2of3(vSet, dh, owner, vPk, vR, sAgg, digest);
    // s_agg = 2^256-1 is >= n and must be rejected by the half-agg range check.
    valtype sBad(32, 0xFF);
    std::string err;
    BOOST_CHECK_MESSAGE(!VerifyHalfAggStakeSignature(vPk, vR, sBad, digest, err),
                        "an out-of-range aggregated s-scalar (>= n) must be rejected");
}

// --- B2-c hidden-signer research prototype: BPAC gate + threshold-ring xM fallback ---
namespace
{
bool BuildHiddenFixture(unsigned int N, unsigned int M,
                        std::vector<uint256>& setSk,
                        std::vector<valtype>& set,
                        valtype& owner,
                        uint256& delegationHash,
                        CPedersenCommitment& cv3,
                        uint256& stakeDigest)
{
    setSk.clear();
    set.clear();
    for (unsigned int i = 0; i < N; i++)
    {
        uint256 sk((uint64_t)(90000 + i + 37 * N));
        valtype pk;
        if (!HalfAggStakeDerivePubKey(sk, pk)) return false;
        setSk.push_back(sk);
        set.push_back(pk);
    }
    std::sort(set.begin(), set.end());
    if (!HalfAggStakeDerivePubKey(uint256((uint64_t)(99000 + N)), owner)) return false;
    if (!ComputeNullStakeV3DelegationSetHash(set, M, owner, delegationHash)) return false;

    valtype blind(32, 0x42);
    blind[0] = (unsigned char)N;
    blind[31] = (unsigned char)M;
    if (!CreateNullStakeMofNCommitment(5000000 + N, blind, delegationHash, cv3)) return false;
    stakeDigest = ComputeNullStakeMofNStakeDigest(delegationHash,
                                                  0x1122334455667788ULL + N,
                                                  100000 + N, 7, 100010 + N,
                                                  3, 110000 + N,
                                                  cv3.vchCommitment);
    return true;
}

std::vector<uint256> FirstSigners(const std::vector<uint256>& setSk, unsigned int M)
{
    std::vector<uint256> out;
    for (unsigned int i = 0; i < M; i++)
        out.push_back(setSk[i]);
    return out;
}
} // namespace

BOOST_AUTO_TEST_CASE(hidden_auth_bpac_gate_falls_back)
{
    CNullStakeB2CBPACBudget selectorOnly, fullEC;
    BOOST_REQUIRE(EstimateNullStakeB2CHiddenAuthBPACBudget(32, 16, false, selectorOnly));
    BOOST_CHECK(!selectorOnly.fBPACFeasible);
    BOOST_CHECK_EQUAL(selectorOnly.nECAuthConstraints, 0u);

    BOOST_REQUIRE(EstimateNullStakeB2CHiddenAuthBPACBudget(32, 16, true, fullEC));
    BOOST_CHECK(!fullEC.fBPACFeasible);
    BOOST_CHECK_GT(fullEC.nECAuthConstraints, 0u);
    BOOST_CHECK_GT(fullEC.nTotalConstraints, NULLSTAKE_B2C_BPAC_AUTH_CONSTRAINT_CAP);
}

BOOST_AUTO_TEST_CASE(hidden_auth_roundtrip_target_sizes)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    const unsigned int targets[][4] = {
        {3, 1, 2, 3},
        {8, 1, 4, 8},
        {16, 1, 8, 16},
        {32, 1, 16, 32}
    };
    for (size_t row = 0; row < sizeof(targets) / sizeof(targets[0]); row++)
    {
        unsigned int N = targets[row][0];
        for (size_t col = 1; col < 4; col++)
        {
            unsigned int M = targets[row][col];
            std::vector<uint256> setSk;
            std::vector<valtype> set;
            valtype owner;
            uint256 dh, digest;
            CPedersenCommitment cv3;
            BOOST_REQUIRE(BuildHiddenFixture(N, M, setSk, set, owner, dh, cv3, digest));

            CNullStakeMofNHiddenAuthProof proof;
            std::string err;
            BOOST_REQUIRE_MESSAGE(CreateNullStakeMofNHiddenAuthProof(set, M, owner, dh, digest, cv3,
                                                                     FirstSigners(setSk, M),
                                                                     proof, err),
                                  "hidden auth create failed for target");
            BOOST_CHECK_EQUAL(proof.nAuthType, NULLSTAKE_B2C_AUTH_TYPE_RINGXM_DLEQ);
            BOOST_CHECK_EQUAL(proof.vRingSlotProofs.size(), M);
            BOOST_CHECK_MESSAGE(VerifyNullStakeMofNHiddenAuthProof(set, M, owner, dh, digest, cv3,
                                                                   proof, err),
                                "hidden auth verify failed: " + err);
        }
    }
}

BOOST_AUTO_TEST_CASE(hidden_auth_adversarial_rejections)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    std::vector<uint256> setSk;
    std::vector<valtype> set;
    valtype owner;
    uint256 dh, digest;
    CPedersenCommitment cv3;
    BOOST_REQUIRE(BuildHiddenFixture(3, 2, setSk, set, owner, dh, cv3, digest));

    std::string err;
    CNullStakeMofNHiddenAuthProof proof;
    BOOST_REQUIRE(CreateNullStakeMofNHiddenAuthProof(set, 2, owner, dh, digest, cv3,
                                                     FirstSigners(setSk, 2), proof, err));

    std::vector<uint256> oneSigner;
    oneSigner.push_back(setSk[0]);
    CNullStakeMofNHiddenAuthProof badProof;
    BOOST_CHECK_MESSAGE(!CreateNullStakeMofNHiddenAuthProof(set, 2, owner, dh, digest, cv3,
                                                            oneSigner, badProof, err),
                        "subthreshold hidden signer set must be rejected");

    std::vector<uint256> dup;
    dup.push_back(setSk[0]);
    dup.push_back(setSk[0]);
    BOOST_CHECK_MESSAGE(!CreateNullStakeMofNHiddenAuthProof(set, 2, owner, dh, digest, cv3,
                                                            dup, badProof, err),
                        "duplicate hidden signer must be rejected");

    std::vector<uint256> nonMember;
    nonMember.push_back(setSk[0]);
    nonMember.push_back(uint256(123456789ULL));
    BOOST_CHECK_MESSAGE(!CreateNullStakeMofNHiddenAuthProof(set, 2, owner, dh, digest, cv3,
                                                            nonMember, badProof, err),
                        "non-member secret must be rejected");

    std::vector<valtype> forgedSet = set;
    valtype attackerPk;
    BOOST_REQUIRE(HalfAggStakeDerivePubKey(uint256(22222222ULL), attackerPk));
    forgedSet[0] = attackerPk;
    std::sort(forgedSet.begin(), forgedSet.end());
    BOOST_CHECK_MESSAGE(!VerifyNullStakeMofNHiddenAuthProof(forgedSet, 2, owner, dh, digest, cv3,
                                                            proof, err),
                        "forged set/delegationHash must be rejected");

    uint256 replayDigest = ComputeNullStakeMofNStakeDigest(dh, 0x9999ULL, 100000, 7,
                                                           100010, 3, 110000,
                                                           cv3.vchCommitment);
    BOOST_CHECK_MESSAGE(!VerifyNullStakeMofNHiddenAuthProof(set, 2, owner, dh, replayDigest, cv3,
                                                            proof, err),
                        "replay across different kernel params must be rejected");

    CNullStakeMofNHiddenAuthProof duplicateTag = proof;
    duplicateTag.vRingSlotProofs[1].vchTag = duplicateTag.vRingSlotProofs[0].vchTag;
    BOOST_CHECK_MESSAGE(!VerifyNullStakeMofNHiddenAuthProof(set, 2, owner, dh, digest, cv3,
                                                            duplicateTag, err),
                        "duplicate hidden tag must be rejected");
}

BOOST_AUTO_TEST_CASE(hidden_auth_serialization_and_privacy_shape)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    std::vector<uint256> setSk;
    std::vector<valtype> set;
    valtype owner;
    uint256 dh, digest;
    CPedersenCommitment cv3;
    BOOST_REQUIRE(BuildHiddenFixture(8, 4, setSk, set, owner, dh, cv3, digest));

    std::string err;
    CNullStakeMofNHiddenAuthProof p1, p2, pOther;
    BOOST_REQUIRE(CreateNullStakeMofNHiddenAuthProof(set, 4, owner, dh, digest, cv3,
                                                     FirstSigners(setSk, 4), p1, err));
    BOOST_REQUIRE(CreateNullStakeMofNHiddenAuthProof(set, 4, owner, dh, digest, cv3,
                                                     FirstSigners(setSk, 4), p2, err));

    BOOST_CHECK_MESSAGE(p1.vchTagBaseNonce != p2.vchTagBaseNonce,
                        "same subset proofs must use different tag-base nonces");
    BOOST_CHECK_MESSAGE(p1.vRingSlotProofs[0].vchTag != p2.vRingSlotProofs[0].vchTag,
                        "same subset proofs must not expose a stable signer tag");

    std::vector<uint256> otherSigners;
    otherSigners.push_back(setSk[1]);
    otherSigners.push_back(setSk[2]);
    otherSigners.push_back(setSk[3]);
    otherSigners.push_back(setSk[4]);
    BOOST_REQUIRE(CreateNullStakeMofNHiddenAuthProof(set, 4, owner, dh, digest, cv3,
                                                     otherSigners, pOther, err));
    BOOST_CHECK_EQUAL(p1.GetProofSize(), pOther.GetProofSize());
    BOOST_CHECK(p1.vchResearchProof.empty());

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << p1;
    std::vector<unsigned char> bytes(ss.begin(), ss.end());
    CNullStakeMofNHiddenAuthProof decoded;
    ss >> decoded;
    CDataStream ss2(SER_DISK, CLIENT_VERSION);
    ss2 << decoded;
    std::vector<unsigned char> bytes2(ss2.begin(), ss2.end());
    BOOST_CHECK(bytes == bytes2);
    BOOST_CHECK_MESSAGE(VerifyNullStakeMofNHiddenAuthProof(set, 4, owner, dh, digest, cv3,
                                                           decoded, err),
                        "decoded hidden auth proof must verify: " + err);
}

BOOST_AUTO_TEST_SUITE_END()
