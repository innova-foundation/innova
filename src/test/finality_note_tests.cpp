// Tests for F2 note-weighted finality votes (finality_note.h/.cpp): the ed25519
// scalar field the note commitments live in, the Pedersen-VSS shares that let a
// committee sum a note's weight without seeing it, the complaint that attributes
// an unusable share, the tier range proofs, the validator-side aggregates, and
// the binding/sigma that make a vote undetachable from its own fields.
// One case covers the existing transparent tracker, which must stay unaffected
// by note/private votes.

#include <boost/test/unit_test.hpp>

#include "../finality.h"
#include "../finality_note.h"
#include "../hash.h"
#include "../key.h"
#include "../main.h"
#include "../privacy_vnext/iv5_protocol.h"
#include "../privacy_vnext_ffi.h"
#include "../serialize.h"
#include "../util.h"
#include "../zkproof.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include <string>
#include <string.h>
#include <vector>

namespace
{

struct ScopedTallyArgs
{
    std::map<std::string, std::string> mapArgsSaved;
    std::map<std::string, std::vector<std::string> > mapMultiArgsSaved;

    ScopedTallyArgs()
        : mapArgsSaved(mapArgs),
          mapMultiArgsSaved(mapMultiArgs)
    {
    }

    ~ScopedTallyArgs()
    {
        mapArgs = mapArgsSaved;
        mapMultiArgs = mapMultiArgsSaved;
    }
};

// The committee travels through the real -finalitytally* parser, so the tests bind
// to the configuration consensus actually sees rather than a hand-filled struct.
CFinalityTallyConfig MakeNoteCommittee(std::vector<CKey>& vKeys, int nThreshold)
{
    std::vector<std::string> vPubKeyHex;
    for (size_t i = 0; i < vKeys.size(); i++)
    {
        vKeys[i].MakeNewKey(true);
        const CPubKey pubkey = vKeys[i].GetPubKey();
        vPubKeyHex.push_back(HexStr(pubkey.begin(), pubkey.end()));
    }

    mapArgs["-finalitytallymode"] = "committee";
    mapArgs["-finalitytallythreshold"] =
        strprintf("%d-of-%d", nThreshold, (int)vKeys.size());
    mapMultiArgs["-finalitytallypubkey"] = vPubKeyHex;

    CFinalityTallyConfig config = GetFinalityTallyConfig();
    BOOST_REQUIRE(config.fCommitteeValid);
    BOOST_REQUIRE_EQUAL(config.nThresholdM, nThreshold);
    BOOST_REQUIRE_EQUAL(config.vCommitteePubKeys.size(), vKeys.size());
    for (size_t i = 0; i < vKeys.size(); i++)
        BOOST_REQUIRE(config.vCommitteePubKeys[i] == vKeys[i].GetPubKey());
    return config;
}

uint256 RandomScalar()
{
    return Ed25519ScalarReduce(GetRandHash());
}

PrivacyVNextDigest ZeroDigest()
{
    PrivacyVNextDigest out;
    out.fill(0);
    return out;
}

// value*H + blind*G, reached only through the FFI's own combination. Every point a
// test hands to a checker is built here, never taken from the object under test.
PrivacyVNextDigest CommitPoint(const uint256& value, const uint256& blind)
{
    std::vector<PrivacyVNextCombineTerm> vTerms(2);
    vTerms[0].nSource = PRIVACY_VNEXT_TERM_MONERO_H;
    vTerms[0].scalar = Ed25519ScalarToDigest(value);
    vTerms[1].nSource = PRIVACY_VNEXT_TERM_ED25519_G;
    vTerms[1].scalar = Ed25519ScalarToDigest(blind);
    PrivacyVNextDigest out = ZeroDigest();
    std::string error;
    BOOST_REQUIRE_MESSAGE(CombinePrivacyVNextPoints(vTerms, out, error), error);
    return out;
}

PrivacyVNextDigest SumPoints(const std::vector<PrivacyVNextDigest>& vPoints)
{
    const uint256 one = Ed25519ScalarFromUint64(1);
    std::vector<PrivacyVNextCombineTerm> vTerms;
    for (size_t i = 0; i < vPoints.size(); i++)
    {
        PrivacyVNextCombineTerm term;
        term.nSource = PRIVACY_VNEXT_TERM_SUPPLIED;
        term.scalar = Ed25519ScalarToDigest(one);
        term.point = vPoints[i];
        vTerms.push_back(term);
    }
    PrivacyVNextDigest out = ZeroDigest();
    std::string error;
    BOOST_REQUIRE_MESSAGE(CombinePrivacyVNextPoints(vTerms, out, error), error);
    return out;
}

PrivacyVNextDigest IdentityPoint()
{
    return SumPoints(std::vector<PrivacyVNextDigest>());
}

// x*G. The sigma witness is (x, y) with O~ = x*G + y*T; T is not an exposed combine
// source, so the tests below take y = 0 and reach O~ through G alone.
PrivacyVNextDigest BasePointMultiple(const uint256& x)
{
    return CommitPoint(uint256(0), x);
}

CNoteVoteShare MakeShare(const CFinalityTallyConfig& config,
                         int nEpoch,
                         int64_t nAmount,
                         const uint256& maskTilde,
                         int64_t nReward,
                         const uint256& rewardBlind)
{
    CNoteVoteShare share;
    share.nEpoch = nEpoch;
    share.committeeSetHash = config.committeeSetHash;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(BuildNoteVoteShare(share, nAmount, maskTilde, nReward,
                                             rewardBlind, config, &strError),
                          strError);
    BOOST_REQUIRE(share.IsValidBasic(&strError));
    return share;
}

// The pinned one-input membership verify request. The O~/C~ accessors are pure
// offsets into this layout, so a test that wants a chosen C~ has to write one.
std::vector<unsigned char> MakeMembershipRequest(const uint256& hashCurveRoot,
                                                 const PrivacyVNextDigest& oTilde,
                                                 const PrivacyVNextDigest& cTilde)
{
    std::vector<unsigned char> vch;
    vch.push_back((unsigned char)iv5::PROTOCOL_SCHEMA);
    vch.push_back(0);
    vch.push_back((unsigned char)iv5::TREE_LAYERS);
    vch.push_back(2);
    vch.push_back(1);
    vch.push_back(0);
    vch.push_back(0);
    vch.push_back(0);
    vch.insert(vch.end(), hashCurveRoot.begin(), hashCurveRoot.end());
    vch.insert(vch.end(), oTilde.begin(), oTilde.end());
    vch.insert(vch.end(), 64, 0);   // I~ and R, which consensus reads from neither offset
    vch.insert(vch.end(), cTilde.begin(), cTilde.end());
    const uint32_t nProofLen = 8;
    for (int i = 0; i < 4; i++)
        vch.push_back((unsigned char)((nProofLen >> (8 * i)) & 0xff));
    vch.insert(vch.end(), nProofLen, 0x5a);
    BOOST_REQUIRE(vch.size() >= FINALITY_NOTE_MEMBERSHIP_MIN);
    return vch;
}

CNoteFinalityVote MakeVote(const CNoteVoteShare& share,
                           const uint256& hashBlock,
                           const PrivacyVNextDigest& cTilde,
                           unsigned char nTagSeed,
                           const PrivacyVNextDigest* pOTilde = NULL)
{
    CNoteFinalityVote vote;
    vote.nEpoch = share.nEpoch;
    vote.hashBlock = hashBlock;
    vote.nHeight = 7000 + share.nEpoch;
    vote.nTime = 1700000000;
    vote.hashCurveRoot = uint256(0x4321);
    vote.hashNullifierRoot = uint256(0x8765);
    vote.committeeSetHash = share.committeeSetHash;
    vote.vchMembership = MakeMembershipRequest(vote.hashCurveRoot,
                                               pOTilde ? *pOTilde : ZeroDigest(), cTilde);
    vote.vchTag.assign(FINALITY_NOTE_POINT_SIZE, nTagSeed);
    vote.vchSigma.assign(FINALITY_NOTE_SIGMA_SIZE, 0x11);
    vote.share = share;
    return vote;
}

// --- Adversary-side reimplementation of the envelope sealing -----------------
//
// A voter that seals evaluations off its own committed polynomial is exactly what
// the VSS coefficients exist to catch, and nothing exported can build one. These
// three helpers reproduce the module's ECDH, AAD and envelope encoding so a test
// can forge that envelope; the round-trip case below proves the reproduction is
// faithful before the forgery case relies on it.

const char* TEST_SHARE_ECDH_DOMAIN = "Innova/IV5/NoteVote/ShareECDH/v1";
const char* TEST_SHARE_AAD_DOMAIN = "Innova/IV5/NoteVote/ShareAAD/v1";

bool TestSharedPoint(const CKey& keyPrivate, const CPubKey& pubPeer,
                     unsigned char sharedBytesOut[33])
{
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BN_CTX* ctx = group ? BN_CTX_new() : NULL;
    BIGNUM* bnPriv = ctx ? BN_bin2bn(keyPrivate.begin(), 32, NULL) : NULL;
    EC_POINT* peerPoint = group ? EC_POINT_new(group) : NULL;
    EC_POINT* sharedPoint = group ? EC_POINT_new(group) : NULL;
    const bool fOk =
        group && ctx && bnPriv && peerPoint && sharedPoint &&
        EC_POINT_oct2point(group, peerPoint, pubPeer.begin(), pubPeer.size(), ctx) == 1 &&
        EC_POINT_mul(group, sharedPoint, NULL, peerPoint, bnPriv, ctx) == 1 &&
        EC_POINT_point2oct(group, sharedPoint, POINT_CONVERSION_COMPRESSED,
                           sharedBytesOut, 33, ctx) == 33;
    if (sharedPoint) EC_POINT_free(sharedPoint);
    if (peerPoint) EC_POINT_free(peerPoint);
    if (bnPriv) BN_clear_free(bnPriv);
    if (ctx) BN_CTX_free(ctx);
    if (group) EC_GROUP_free(group);
    return fOk;
}

std::vector<unsigned char> TestEnvelopeKey(const unsigned char sharedBytes[33],
                                           const CPubKey& pubRecipient,
                                           const CPubKey& pubEphemeral,
                                           int nRecipientIndex,
                                           const uint256& committeeSetHash)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string(TEST_SHARE_ECDH_DOMAIN);
    for (size_t i = 0; i < 33; i++)
        ss << sharedBytes[i];
    ss << std::vector<unsigned char>(pubEphemeral.begin(), pubEphemeral.end());
    ss << std::vector<unsigned char>(pubRecipient.begin(), pubRecipient.end());
    ss << committeeSetHash;
    ss << nRecipientIndex;
    const uint256 hashKey = ss.GetHash();
    return std::vector<unsigned char>(hashKey.begin(), hashKey.begin() + 32);
}

std::vector<unsigned char> TestShareAAD(const CNoteVoteShare& share,
                                        int nRecipientIndex,
                                        const CPubKey& pubEphemeral)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << std::string(TEST_SHARE_AAD_DOMAIN);
    ss << share.nVersion;
    ss << share.nEpoch;
    ss << share.committeeSetHash;
    ss << share.vVssCoefficients;
    ss << nRecipientIndex;
    ss << std::vector<unsigned char>(pubEphemeral.begin(), pubEphemeral.end());
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

bool TestParseEnvelope(const std::vector<unsigned char>& vchEnvelope,
                       int& nRecipientIndexOut,
                       CPubKey& pubEphemeralOut,
                       std::vector<unsigned char>& vchCiphertextOut)
{
    try
    {
        CDataStream ss(vchEnvelope, SER_NETWORK, PROTOCOL_VERSION);
        uint32_t nEnvelopeVersion = 0;
        std::vector<unsigned char> vchEphemeral;
        ss >> nEnvelopeVersion;
        ss >> nRecipientIndexOut;
        ss >> vchEphemeral;
        ss >> vchCiphertextOut;
        if (nEnvelopeVersion != FINALITY_NOTE_SHARE_VERSION || vchEphemeral.size() != 33)
            return false;
        pubEphemeralOut = CPubKey(vchEphemeral);
        return pubEphemeralOut.IsValid() && pubEphemeralOut.IsCompressed();
    }
    catch (const std::exception&)
    {
        return false;
    }
}

// Replace one recipient's envelope with a freshly sealed one carrying `plain`,
// keeping the ephemeral key so the recipient's own decryption still reaches it.
void TestResealEnvelope(CNoteVoteShare& share,
                        const CKey& keyRecipient,
                        int nRecipientIndex,
                        const CNoteTallyPlainShare& plain)
{
    int nEnvelopeRecipient = -1;
    CPubKey pubEphemeral;
    std::vector<unsigned char> vchCiphertext;
    BOOST_REQUIRE(TestParseEnvelope(share.vEncryptedRecipientShares[nRecipientIndex],
                                    nEnvelopeRecipient, pubEphemeral, vchCiphertext));
    BOOST_REQUIRE_EQUAL(nEnvelopeRecipient, nRecipientIndex);

    unsigned char sharedBytes[33];
    BOOST_REQUIRE(TestSharedPoint(keyRecipient, pubEphemeral, sharedBytes));
    const std::vector<unsigned char> vchKey =
        TestEnvelopeKey(sharedBytes, keyRecipient.GetPubKey(), pubEphemeral,
                        nRecipientIndex, share.committeeSetHash);

    CDataStream ssPlain(SER_NETWORK, PROTOCOL_VERSION);
    ssPlain << (uint32_t)FINALITY_NOTE_SHARE_VERSION;
    ssPlain << plain.nRecipientIndex;
    ssPlain << plain.nX;
    ssPlain << plain.evalWeight;
    ssPlain << plain.evalWeightBlind;
    ssPlain << plain.evalReward;
    ssPlain << plain.evalRewardBlind;

    std::vector<unsigned char> vchSealed;
    BOOST_REQUIRE(ChaCha20Poly1305Encrypt(
        vchKey, std::vector<unsigned char>(ssPlain.begin(), ssPlain.end()),
        TestShareAAD(share, nRecipientIndex, pubEphemeral), vchSealed));

    CDataStream ssOut(SER_NETWORK, PROTOCOL_VERSION);
    ssOut << (uint32_t)FINALITY_NOTE_SHARE_VERSION;
    ssOut << nRecipientIndex;
    ssOut << std::vector<unsigned char>(pubEphemeral.begin(), pubEphemeral.end());
    ssOut << vchSealed;
    share.vEncryptedRecipientShares[nRecipientIndex].assign(ssOut.begin(), ssOut.end());
}

CFinalityVote MakeTransparentVote(int nEpoch, const uint256& hashBlock, int nHeight,
                                  int64_t nWeight, const CKey& key, int nSeed)
{
    CFinalityVote vote;
    vote.nProofMode = FINALITY_PROOF_TRANSPARENT;
    vote.nEpoch = nEpoch;
    vote.hashBlock = hashBlock;
    vote.nHeight = nHeight;
    vote.nTime = 1700000000 + nSeed;
    vote.nVoteWeight = nWeight;
    vote.nReward = 0;
    vote.nullifier = uint256(1000 + nSeed);
    const CPubKey pubkey = key.GetPubKey();
    vote.vchPubKey.assign(pubkey.begin(), pubkey.end());
    return vote;
}

CFinalityVote MakePrivateVote(int nEpoch, const uint256& hashBlock, int nHeight,
                              int64_t nDeclaredWeight, int nSeed)
{
    CFinalityVote vote;
    vote.nProofMode = FINALITY_PROOF_NULLSTAKE_V3_COLD;
    vote.nEpoch = nEpoch;
    vote.hashBlock = hashBlock;
    vote.nHeight = nHeight;
    vote.nTime = 1700000000 + nSeed;
    vote.nVoteWeight = nDeclaredWeight;
    vote.nReward = 0;
    vote.nullifier = uint256(2000 + nSeed);
    return vote;
}

} // namespace

BOOST_AUTO_TEST_SUITE(finality_note_tests)

BOOST_AUTO_TEST_CASE(ed25519_scalar_field_reduces_inverts_and_bounds_money)
{
    // ell = 2^252 + 27742317777372353535851937790883648493, little-endian.
    uint256 ell = 0;
    static const unsigned char ELL_LE[16] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14
    };
    memcpy(ell.begin(), ELL_LE, sizeof(ELL_LE));
    ell.begin()[31] = 0x10;

    const uint256 zero = 0;
    const uint256 one = Ed25519ScalarFromUint64(1);
    BOOST_CHECK(Ed25519ScalarReduce(ell) == zero);
    BOOST_CHECK(!Ed25519ScalarIsCanonical(ell));
    BOOST_CHECK(Ed25519ScalarReduce(Ed25519ScalarAdd(ell, one)) == one);
    BOOST_CHECK(Ed25519ScalarIsCanonical(one));

    const uint256 a = RandomScalar();
    const uint256 b = RandomScalar();
    BOOST_CHECK(Ed25519ScalarSub(Ed25519ScalarAdd(a, b), b) == a);
    BOOST_CHECK(Ed25519ScalarMul(a, one) == a);
    BOOST_CHECK(Ed25519ScalarAdd(a, Ed25519ScalarNeg(a)) == zero);
    BOOST_CHECK(Ed25519ScalarMul(a, Ed25519ScalarInv(a)) == one);
    BOOST_CHECK(Ed25519ScalarInv(zero) == zero);

    BOOST_CHECK(Ed25519ScalarFromInt64(-1) == Ed25519ScalarNeg(one));
    BOOST_CHECK(Ed25519ScalarFromInt64(7) == Ed25519ScalarFromUint64(7));
    BOOST_CHECK(Ed25519ScalarAdd(Ed25519ScalarFromInt64(-9),
                                 Ed25519ScalarFromInt64(9)) == zero);
    // The most negative int64 has no positive counterpart, so the negation path
    // must not reach it through a cast.
    BOOST_CHECK(Ed25519ScalarAdd(Ed25519ScalarFromInt64(-9223372036854775807LL - 1),
                                 Ed25519ScalarFromUint64(9223372036854775808ULL)) == zero);

    int64_t nMoney = -1;
    BOOST_CHECK(Ed25519ScalarToMoney(Ed25519ScalarFromUint64((uint64_t)MAX_MONEY), nMoney));
    BOOST_CHECK_EQUAL(nMoney, MAX_MONEY);
    BOOST_CHECK(Ed25519ScalarToMoney(zero, nMoney));
    BOOST_CHECK_EQUAL(nMoney, 0);
    BOOST_CHECK(!Ed25519ScalarToMoney(
        Ed25519ScalarFromUint64((uint64_t)MAX_MONEY + 1), nMoney));

    uint256 highByte = Ed25519ScalarFromUint64(5);
    highByte.begin()[8] = 1;
    BOOST_CHECK(!Ed25519ScalarToMoney(highByte, nMoney));
    BOOST_CHECK(!Ed25519ScalarToMoney(Ed25519ScalarNeg(one), nMoney));

    BOOST_CHECK(Ed25519ScalarFromDigest(Ed25519ScalarToDigest(a)) == a);
}

BOOST_AUTO_TEST_CASE(shamir_shares_recover_one_voter_and_sum_two_voters)
{
    ScopedTallyArgs scopedArgs;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeNoteCommittee(vKeys, 2);

    const int64_t nAmountA = 1234567;
    const int64_t nRewardA = 4242;
    const uint256 maskA = RandomScalar();
    const uint256 rewardBlindA = RandomScalar();
    const CNoteVoteShare shareA =
        MakeShare(config, 900, nAmountA, maskA, nRewardA, rewardBlindA);

    std::vector<CNoteTallyPlainShare> vPlainA(vKeys.size());
    for (size_t i = 0; i < vKeys.size(); i++)
    {
        BOOST_REQUIRE(DecryptNoteVoteShareForRecipient(shareA, config, vKeys[i],
                                                       (int)i, vPlainA[i]));
        BOOST_CHECK_EQUAL(vPlainA[i].nRecipientIndex, (int)i);
        BOOST_CHECK_EQUAL(vPlainA[i].nX, (int)i + 1);
    }

    // One voter: aggregating a single evaluation still has to interpolate back to
    // the note's own opening, or the two-voter sum below means nothing.
    std::vector<CNoteTallyPlainShare> vSingleVoter;
    std::vector<CNoteTallyPlainShare> vAggregatedA(vKeys.size());
    for (size_t i = 0; i < vKeys.size(); i++)
    {
        vSingleVoter.assign(1, vPlainA[i]);
        BOOST_REQUIRE(AggregateNoteTallyPlainShares(vSingleVoter, vAggregatedA[i]));
    }

    uint256 weight, weightBlind, reward, rewardBlind;
    std::vector<CNoteTallyPlainShare> vTwo;
    vTwo.push_back(vAggregatedA[0]);
    vTwo.push_back(vAggregatedA[2]);
    BOOST_REQUIRE(RecoverNoteTallySecrets(vTwo, config.nThresholdM, weight, weightBlind,
                                          reward, rewardBlind));
    BOOST_CHECK(weight == Ed25519ScalarFromInt64(nAmountA));
    BOOST_CHECK(weightBlind == maskA);
    BOOST_CHECK(reward == Ed25519ScalarFromInt64(nRewardA));
    BOOST_CHECK(rewardBlind == rewardBlindA);

    int64_t nRecovered = 0;
    BOOST_REQUIRE(Ed25519ScalarToMoney(weight, nRecovered));
    BOOST_CHECK_EQUAL(nRecovered, nAmountA);

    // Below the threshold nothing is recoverable, which is the only reason a
    // single committee member holding a share reveals no weight.
    std::vector<CNoteTallyPlainShare> vOne(1, vAggregatedA[0]);
    BOOST_CHECK(!RecoverNoteTallySecrets(vOne, config.nThresholdM, weight, weightBlind,
                                         reward, rewardBlind));

    const int64_t nAmountB = 987654;
    const int64_t nRewardB = 11;
    const uint256 maskB = RandomScalar();
    const uint256 rewardBlindB = RandomScalar();
    const CNoteVoteShare shareB =
        MakeShare(config, 900, nAmountB, maskB, nRewardB, rewardBlindB);

    std::vector<CNoteTallyPlainShare> vPlainB(vKeys.size());
    for (size_t i = 0; i < vKeys.size(); i++)
        BOOST_REQUIRE(DecryptNoteVoteShareForRecipient(shareB, config, vKeys[i],
                                                       (int)i, vPlainB[i]));

    // Shamir is linear, so summing per recipient index and interpolating once
    // yields the epoch total without ever reconstructing either voter's opening.
    std::vector<CNoteTallyPlainShare> vSum(vKeys.size());
    for (size_t i = 0; i < vKeys.size(); i++)
    {
        std::vector<CNoteTallyPlainShare> vBoth;
        vBoth.push_back(vPlainA[i]);
        vBoth.push_back(vPlainB[i]);
        BOOST_REQUIRE(AggregateNoteTallyPlainShares(vBoth, vSum[i]));
        BOOST_CHECK_EQUAL(vSum[i].nX, (int)i + 1);
    }

    // A mismatched recipient index would silently sum evaluations at different x.
    std::vector<CNoteTallyPlainShare> vCrossed;
    vCrossed.push_back(vPlainA[0]);
    vCrossed.push_back(vPlainB[1]);
    CNoteTallyPlainShare crossedOut;
    BOOST_CHECK(!AggregateNoteTallyPlainShares(vCrossed, crossedOut));

    std::vector<CNoteTallyPlainShare> vSumTwo;
    vSumTwo.push_back(vSum[1]);
    vSumTwo.push_back(vSum[2]);
    BOOST_REQUIRE(RecoverNoteTallySecrets(vSumTwo, config.nThresholdM, weight,
                                          weightBlind, reward, rewardBlind));
    BOOST_CHECK(weight == Ed25519ScalarFromInt64(nAmountA + nAmountB));
    BOOST_CHECK(weightBlind == Ed25519ScalarAdd(maskA, maskB));
    BOOST_CHECK(reward == Ed25519ScalarFromInt64(nRewardA + nRewardB));
    BOOST_CHECK(rewardBlind == Ed25519ScalarAdd(rewardBlindA, rewardBlindB));

    BOOST_REQUIRE(Ed25519ScalarToMoney(weight, nRecovered));
    BOOST_CHECK_EQUAL(nRecovered, nAmountA + nAmountB);

    // The summed opening still opens the sum of the two commitments, which is what
    // the validator recomputes from the votes.
    std::vector<PrivacyVNextDigest> vCommitments;
    PrivacyVNextDigest commitmentA = ZeroDigest();
    PrivacyVNextDigest commitmentB = ZeroDigest();
    BOOST_REQUIRE(shareA.GetCommitment(commitmentA));
    BOOST_REQUIRE(shareB.GetCommitment(commitmentB));
    vCommitments.push_back(commitmentA);
    vCommitments.push_back(commitmentB);
    BOOST_CHECK(SumPoints(vCommitments) == CommitPoint(weight, weightBlind));
}

BOOST_AUTO_TEST_CASE(vss_coefficients_bind_the_share_to_the_vote_commitment)
{
    ScopedTallyArgs scopedArgs;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeNoteCommittee(vKeys, 2);

    const int64_t nAmount = 555000;
    const uint256 mask = RandomScalar();
    const CNoteVoteShare share = MakeShare(config, 901, nAmount, mask, 33, RandomScalar());

    // K_0 must be the note's own commitment, reached here from the opening alone.
    PrivacyVNextDigest commitment = ZeroDigest();
    BOOST_REQUIRE(share.GetCommitment(commitment));
    BOOST_CHECK(commitment == CommitPoint(Ed25519ScalarFromInt64(nAmount), mask));
    BOOST_CHECK(commitment != CommitPoint(Ed25519ScalarFromInt64(nAmount + 1), mask));
    BOOST_REQUIRE_EQUAL(share.vVssCoefficients.size(), (size_t)config.nThresholdM);

    std::string strError;
    for (size_t i = 0; i < vKeys.size(); i++)
    {
        CNoteTallyPlainShare plain;
        BOOST_REQUIRE(DecryptNoteVoteShareForRecipient(share, config, vKeys[i],
                                                       (int)i, plain));
        BOOST_CHECK(CheckNoteVoteVssEvaluation(share, plain, &strError));

        CNoteTallyPlainShare perturbed = plain;
        perturbed.evalWeight = Ed25519ScalarAdd(perturbed.evalWeight,
                                                Ed25519ScalarFromUint64(1));
        BOOST_CHECK(!CheckNoteVoteVssEvaluation(share, perturbed, &strError));

        perturbed = plain;
        perturbed.evalWeightBlind = Ed25519ScalarAdd(perturbed.evalWeightBlind,
                                                     Ed25519ScalarFromUint64(1));
        BOOST_CHECK(!CheckNoteVoteVssEvaluation(share, perturbed, &strError));

        // An evaluation is only meaningful at its own x.
        perturbed = plain;
        perturbed.nX = plain.nX + 1;
        BOOST_CHECK(!CheckNoteVoteVssEvaluation(share, perturbed, &strError));
    }
}

BOOST_AUTO_TEST_CASE(poisoned_share_is_detected_and_attributable)
{
    ScopedTallyArgs scopedArgs;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeNoteCommittee(vKeys, 2);

    const int64_t nAmountA = 400000;
    const uint256 maskA = RandomScalar();
    const CNoteVoteShare shareA = MakeShare(config, 902, nAmountA, maskA, 5, RandomScalar());

    const int64_t nAmountB = 700000;
    const uint256 maskB = RandomScalar();
    const CNoteVoteShare shareB = MakeShare(config, 902, nAmountB, maskB, 6, RandomScalar());

    std::vector<CNoteTallyPlainShare> vPlainA(vKeys.size());
    std::vector<CNoteTallyPlainShare> vPlainB(vKeys.size());
    for (size_t i = 0; i < vKeys.size(); i++)
    {
        BOOST_REQUIRE(DecryptNoteVoteShareForRecipient(shareA, config, vKeys[i],
                                                       (int)i, vPlainA[i]));
        BOOST_REQUIRE(DecryptNoteVoteShareForRecipient(shareB, config, vKeys[i],
                                                       (int)i, vPlainB[i]));
    }

    // A corrupted envelope is unusable for exactly one recipient, and that
    // recipient can tell it apart from a local failure.
    CNoteVoteShare corrupted = shareB;
    const size_t nTarget = 1;
    std::vector<unsigned char>& vchEnvelope = corrupted.vEncryptedRecipientShares[nTarget];
    vchEnvelope[vchEnvelope.size() - 1] ^= 0x01;
    for (size_t i = 0; i < vKeys.size(); i++)
    {
        CNoteTallyPlainShare plain;
        bool fComplainable = false;
        const bool fDecrypted = DecryptNoteVoteShareForRecipient(
            corrupted, config, vKeys[i], (int)i, plain, &fComplainable);
        if (i == nTarget)
        {
            BOOST_CHECK(!fDecrypted);
            BOOST_CHECK(fComplainable);
        }
        else
        {
            BOOST_CHECK(fDecrypted);
            BOOST_CHECK(!fComplainable);
            BOOST_CHECK(plain.evalWeight == vPlainB[i].evalWeight);
        }
    }

    // Splicing another share's coefficients onto these envelopes poisons every
    // recipient at once. The envelope AAD covers vVssCoefficients, so this one is
    // caught by the envelope tag before the coefficient check is ever reached.
    CNoteVoteShare spliced = shareB;
    spliced.vVssCoefficients = shareA.vVssCoefficients;
    for (size_t i = 0; i < vKeys.size(); i++)
    {
        CNoteTallyPlainShare plain;
        bool fComplainable = false;
        BOOST_CHECK(!DecryptNoteVoteShareForRecipient(spliced, config, vKeys[i], (int)i,
                                                      plain, &fComplainable));
        BOOST_CHECK(fComplainable);

        // The unspliced share is the positive case: only the splice rejects it.
        BOOST_CHECK(DecryptNoteVoteShareForRecipient(shareB, config, vKeys[i], (int)i,
                                                     plain, &fComplainable));
        BOOST_CHECK(!fComplainable);
    }

    // Re-sealing an envelope with its own evaluations must change nothing. This
    // pins the forgery below to the plaintext and nothing else.
    CNoteVoteShare resealed = shareB;
    TestResealEnvelope(resealed, vKeys[0], 0, vPlainB[0]);
    BOOST_CHECK(resealed.vEncryptedRecipientShares[0] !=
                shareB.vEncryptedRecipientShares[0]);
    CNoteTallyPlainShare plainResealed;
    bool fComplainable = false;
    BOOST_CHECK(DecryptNoteVoteShareForRecipient(resealed, config, vKeys[0], 0,
                                                 plainResealed, &fComplainable));
    BOOST_CHECK(!fComplainable);
    BOOST_CHECK(plainResealed.evalWeight == vPlainB[0].evalWeight);

    // Now a voter that seals an evaluation off its own committed polynomial: the
    // envelope authenticates and the plaintext parses, so the coefficient check is
    // the only thing left that can reject it. A build whose
    // CheckNoteVoteVssEvaluation always returns true accepts this share, and the
    // epoch's recovered sum then fails to open the validator-recomputed total with
    // nothing to say whose share caused it.
    CNoteVoteShare forged = shareB;
    CNoteTallyPlainShare offCurve = vPlainA[0];
    BOOST_REQUIRE_EQUAL(offCurve.nRecipientIndex, 0);
    BOOST_REQUIRE_EQUAL(offCurve.nX, 1);
    TestResealEnvelope(forged, vKeys[0], 0, offCurve);
    CNoteTallyPlainShare plainForged;
    fComplainable = false;
    BOOST_CHECK(!DecryptNoteVoteShareForRecipient(forged, config, vKeys[0], 0,
                                                  plainForged, &fComplainable));
    BOOST_CHECK(fComplainable);
    BOOST_CHECK(!CheckNoteVoteVssEvaluation(forged, offCurve));
    // Positive case for the same evaluation against the share it does open.
    BOOST_CHECK(CheckNoteVoteVssEvaluation(shareA, offCurve));

    // The other recipients' envelopes were untouched, so the poison is attributable
    // to one index rather than to the share as a whole.
    for (size_t i = 1; i < vKeys.size(); i++)
    {
        CNoteTallyPlainShare plain;
        BOOST_CHECK(DecryptNoteVoteShareForRecipient(forged, config, vKeys[i], (int)i,
                                                     plain));
    }
}

BOOST_AUTO_TEST_CASE(complaint_is_publicly_verifiable_and_cannot_accuse_an_honest_share)
{
    ScopedTallyArgs scopedArgs;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeNoteCommittee(vKeys, 2);

    const int64_t nAmount = 250000;
    const uint256 mask = RandomScalar();
    const CNoteVoteShare honest = MakeShare(config, 903, nAmount, mask, 9, RandomScalar());
    const PrivacyVNextDigest cTilde = CommitPoint(Ed25519ScalarFromInt64(nAmount), mask);

    CNoteTallyPlainShare plain0;
    BOOST_REQUIRE(DecryptNoteVoteShareForRecipient(honest, config, vKeys[0], 0, plain0));

    const CNoteVoteShare other =
        MakeShare(config, 903, 111000, RandomScalar(), 4, RandomScalar());
    CNoteTallyPlainShare plainOther;
    BOOST_REQUIRE(DecryptNoteVoteShareForRecipient(other, config, vKeys[0], 0, plainOther));

    // A share whose evaluation does not open its coefficients: the accused envelope
    // decrypts, so only the VSS branch of the complaint check can uphold it.
    CNoteVoteShare poisoned = honest;
    TestResealEnvelope(poisoned, vKeys[0], 0, plainOther);
    CNoteFinalityVote poisonedVote = MakeVote(poisoned, uint256(0x1111), cTilde, 0x21);

    std::string strError;
    CNoteVoteComplaint complaint;
    BOOST_REQUIRE_MESSAGE(BuildNoteVoteComplaint(complaint, poisonedVote, config,
                                                 vKeys[0], 0, &strError), strError);
    BOOST_CHECK(complaint.IsValidBasic(&strError));
    BOOST_CHECK(CheckNoteVoteComplaint(complaint, poisonedVote, config, &strError));

    // "Verifiable on every node" means the committee's public keys are the whole
    // input: no committee member's private key takes part in the check.
    CFinalityTallyConfig publicConfig;
    publicConfig.fCommitteeValid = true;
    publicConfig.nThresholdM = config.nThresholdM;
    publicConfig.nThresholdN = config.nThresholdN;
    publicConfig.vCommitteePubKeys = config.vCommitteePubKeys;
    publicConfig.committeeSetHash = config.committeeSetHash;
    BOOST_CHECK(CheckNoteVoteComplaint(complaint, poisonedVote, publicConfig, &strError));

    // A corrupted envelope is complainable on the decryption branch instead.
    CNoteVoteShare corrupted = honest;
    std::vector<unsigned char>& vchAccused = corrupted.vEncryptedRecipientShares[1];
    vchAccused[vchAccused.size() - 1] ^= 0x80;
    CNoteFinalityVote corruptedVote = MakeVote(corrupted, uint256(0x1111), cTilde, 0x22);
    CNoteVoteComplaint corruptedComplaint;
    BOOST_REQUIRE(BuildNoteVoteComplaint(corruptedComplaint, corruptedVote, config,
                                         vKeys[1], 1, &strError));
    BOOST_CHECK(CheckNoteVoteComplaint(corruptedComplaint, corruptedVote, publicConfig,
                                       &strError));

    // A complaint against an honest share must fail, or one hostile member could
    // jam any epoch by accusing every share it does not like.
    CNoteFinalityVote honestVote = MakeVote(honest, uint256(0x1111), cTilde, 0x23);
    CNoteVoteComplaint falseComplaint;
    BOOST_REQUIRE(BuildNoteVoteComplaint(falseComplaint, honestVote, config, vKeys[0], 0,
                                         &strError));
    BOOST_CHECK(!CheckNoteVoteComplaint(falseComplaint, honestVote, config, &strError));

    // The DLEQ is what stops a member revealing a point that is not the shared
    // secret in order to make an honest envelope look undecryptable.
    CKey keyForeign;
    keyForeign.MakeNewKey(true);
    const CPubKey pubForeign = keyForeign.GetPubKey();
    CNoteVoteComplaint wrongPoint = complaint;
    wrongPoint.vchSharedPoint.assign(pubForeign.begin(), pubForeign.end());
    BOOST_REQUIRE_EQUAL(wrongPoint.vchSharedPoint.size(), (size_t)33);
    BOOST_CHECK(wrongPoint.IsValidBasic(&strError));
    BOOST_CHECK(!CheckNoteVoteComplaint(wrongPoint, poisonedVote, config, &strError));

    CNoteVoteComplaint wrongIndex = complaint;
    wrongIndex.nRecipientIndex = 1;
    BOOST_CHECK(!CheckNoteVoteComplaint(wrongIndex, poisonedVote, config, &strError));

    CNoteVoteComplaint wrongTag = complaint;
    wrongTag.voteTag = uint256(0x9999);
    BOOST_CHECK(!CheckNoteVoteComplaint(wrongTag, poisonedVote, config, &strError));

    CNoteVoteComplaint wrongShare = complaint;
    wrongShare.hashShare = other.GetHash();
    BOOST_CHECK(!CheckNoteVoteComplaint(wrongShare, poisonedVote, config, &strError));

    CNoteVoteComplaint wrongEpoch = complaint;
    wrongEpoch.nEpoch = poisonedVote.nEpoch + 1;
    BOOST_CHECK(!CheckNoteVoteComplaint(wrongEpoch, poisonedVote, config, &strError));

    // The complaint names one share, so it cannot be replayed against another.
    CNoteFinalityVote otherVote = MakeVote(other, uint256(0x1111), cTilde, 0x21);
    BOOST_CHECK(!CheckNoteVoteComplaint(complaint, otherVote, config, &strError));

    // Only the accused recipient can open its own envelope.
    CNoteVoteComplaint foreignComplaint;
    BOOST_CHECK(!BuildNoteVoteComplaint(foreignComplaint, poisonedVote, config,
                                        vKeys[1], 0, &strError));
}

BOOST_AUTO_TEST_CASE(tier_proofs_verify_only_against_the_derived_points_and_their_own_tier)
{
    PrivacyVNextDigest entropy;
    entropy.fill(0x3c);

    const int vTiers[3] = { FINALITY_HARD, FINALITY_SOFT, FINALITY_TENTATIVE };
    const int64_t nPrivateActive = 3000;
    const int64_t vExactWinning[3] = { 2000, 1500, 1000 };

    for (int t = 0; t < 3; t++)
    {
        const int nTier = vTiers[t];
        int64_t nWinningCoeff = 0;
        int64_t nActiveCoeff = 0;
        BOOST_REQUIRE(GetNoteTallyTierCoefficients(nTier, nWinningCoeff, nActiveCoeff));
        const int64_t nPrivateWinning = vExactWinning[t];
        // The chosen opening clears the tier with no slack at all.
        BOOST_REQUIRE_EQUAL(nWinningCoeff * nPrivateWinning, nActiveCoeff * nPrivateActive);

        const uint256 activeBlind = RandomScalar();
        const uint256 winningBlind = RandomScalar();
        const PrivacyVNextDigest activePoint =
            CommitPoint(Ed25519ScalarFromInt64(nPrivateActive), activeBlind);
        const PrivacyVNextDigest winningPoint =
            CommitPoint(Ed25519ScalarFromInt64(nPrivateWinning), winningBlind);

        std::string strError;
        CNoteTallyTierProofs proofs;
        BOOST_REQUIRE_MESSAGE(BuildNoteTallyTierProofs(nTier, nPrivateActive, activeBlind,
                                                       nPrivateWinning, winningBlind,
                                                       0, 0, entropy, proofs, &strError),
                              strError);
        BOOST_CHECK(!proofs.IsNull());
        BOOST_CHECK(CheckNoteTallyTierProofs(nTier, activePoint, winningPoint, 0, 0,
                                             proofs, &strError));

        // One atomic unit short of the tier is not provable at all.
        CNoteTallyTierProofs shortProofs;
        BOOST_CHECK(!BuildNoteTallyTierProofs(nTier, nPrivateActive, activeBlind,
                                              nPrivateWinning - 1, winningBlind, 0, 0,
                                              entropy, shortProofs, &strError));
        BOOST_CHECK(shortProofs.IsNull());

        // A winning sum above the active sum is not an opening the caps allow.
        CNoteTallyTierProofs overProofs;
        BOOST_CHECK(!BuildNoteTallyTierProofs(nTier, nPrivateActive, activeBlind,
                                              nPrivateActive + 1, winningBlind, 0, 0,
                                              entropy, overProofs, &strError));

        // Points are consensus inputs the validator derives; a substituted one must
        // not verify, or the tier claim would rest on numbers the prover chose.
        const PrivacyVNextDigest perturbedActive =
            CommitPoint(Ed25519ScalarFromInt64(nPrivateActive - 1), activeBlind);
        BOOST_CHECK(perturbedActive != activePoint);
        BOOST_CHECK(!CheckNoteTallyTierProofs(nTier, perturbedActive, winningPoint, 0, 0,
                                              proofs, &strError));
        const PrivacyVNextDigest perturbedWinning =
            CommitPoint(Ed25519ScalarFromInt64(nPrivateWinning + 1), winningBlind);
        BOOST_CHECK(perturbedWinning != winningPoint);
        BOOST_CHECK(!CheckNoteTallyTierProofs(nTier, activePoint, perturbedWinning, 0, 0,
                                              proofs, &strError));

        // The transparent weights enter the statement points, so a validator using
        // different ones rejects rather than silently mixing tallies.
        BOOST_CHECK(!CheckNoteTallyTierProofs(nTier, activePoint, winningPoint, 10, 0,
                                              proofs, &strError));
        BOOST_CHECK(!CheckNoteTallyTierProofs(nTier, activePoint, winningPoint, 10, 10,
                                              proofs, &strError));

        CNoteTallyTierProofs emptyProofs;
        BOOST_CHECK(!CheckNoteTallyTierProofs(nTier, activePoint, winningPoint, 0, 0,
                                              emptyProofs, &strError));
    }

    // Tier coefficients differ, so proofs for a weaker tier are not proofs for a
    // stronger one.
    {
        const uint256 activeBlind = RandomScalar();
        const uint256 winningBlind = RandomScalar();
        const PrivacyVNextDigest activePoint =
            CommitPoint(Ed25519ScalarFromInt64(3000), activeBlind);
        const PrivacyVNextDigest winningPoint =
            CommitPoint(Ed25519ScalarFromInt64(1000), winningBlind);

        std::string strError;
        CNoteTallyTierProofs tentative;
        BOOST_REQUIRE(BuildNoteTallyTierProofs(FINALITY_TENTATIVE, 3000, activeBlind,
                                               1000, winningBlind, 0, 0, entropy,
                                               tentative, &strError));
        BOOST_CHECK(CheckNoteTallyTierProofs(FINALITY_TENTATIVE, activePoint, winningPoint,
                                             0, 0, tentative, &strError));
        BOOST_CHECK(!CheckNoteTallyTierProofs(FINALITY_SOFT, activePoint, winningPoint,
                                              0, 0, tentative, &strError));
        BOOST_CHECK(!CheckNoteTallyTierProofs(FINALITY_HARD, activePoint, winningPoint,
                                              0, 0, tentative, &strError));
        BOOST_CHECK(!CheckNoteTallyTierProofs(FINALITY_NONE, activePoint, winningPoint,
                                              0, 0, tentative, &strError));

        int64_t nUnusedWinning = 0;
        int64_t nUnusedActive = 0;
        BOOST_CHECK(!GetNoteTallyTierCoefficients(FINALITY_NONE, nUnusedWinning,
                                                  nUnusedActive));
    }

    // No note vote reached the winning block: the winning aggregate is the identity
    // and the tier rests on the transparent weights alone.
    {
        const uint256 activeBlind = RandomScalar();
        const PrivacyVNextDigest activePoint =
            CommitPoint(Ed25519ScalarFromInt64(2000), activeBlind);
        const PrivacyVNextDigest winningPoint = IdentityPoint();
        BOOST_CHECK(winningPoint == CommitPoint(uint256(0), uint256(0)));

        std::string strError;
        CNoteTallyTierProofs proofs;
        BOOST_REQUIRE_MESSAGE(BuildNoteTallyTierProofs(FINALITY_HARD, 2000, activeBlind,
                                                       0, uint256(0), 4000, 4000,
                                                       entropy, proofs, &strError),
                              strError);
        BOOST_CHECK(CheckNoteTallyTierProofs(FINALITY_HARD, activePoint, winningPoint,
                                             4000, 4000, proofs, &strError));
        BOOST_CHECK(!CheckNoteTallyTierProofs(FINALITY_HARD, activePoint, activePoint,
                                              4000, 4000, proofs, &strError));
        BOOST_CHECK(!CheckNoteTallyTierProofs(FINALITY_HARD, activePoint, winningPoint,
                                              4000, 3999, proofs, &strError));
    }
}

BOOST_AUTO_TEST_CASE(note_tally_aggregates_are_recomputed_from_the_covered_votes)
{
    const uint256 hashA = uint256(0xa1a1);
    const uint256 hashB = uint256(0xb2b2);

    const int64_t vAmounts[3] = { 1000, 2500, 700 };
    uint256 vBlinds[3];
    std::vector<PrivacyVNextDigest> vCommitments;
    for (int i = 0; i < 3; i++)
    {
        vBlinds[i] = RandomScalar();
        vCommitments.push_back(CommitPoint(Ed25519ScalarFromInt64(vAmounts[i]), vBlinds[i]));
    }

    CNoteVoteShare share;
    share.nEpoch = 904;
    share.committeeSetHash = uint256(0x5151);

    CNoteFinalityVote voteA0 = MakeVote(share, hashA, vCommitments[0], 0x31);
    CNoteFinalityVote voteA1 = MakeVote(share, hashA, vCommitments[1], 0x32);
    CNoteFinalityVote voteB0 = MakeVote(share, hashB, vCommitments[2], 0x33);

    PrivacyVNextDigest readBack = ZeroDigest();
    BOOST_REQUIRE(voteA1.GetCTilde(readBack));
    BOOST_CHECK(readBack == vCommitments[1]);

    std::vector<const CNoteFinalityVote*> vVotes;
    vVotes.push_back(&voteA0);
    vVotes.push_back(&voteA1);
    vVotes.push_back(&voteB0);

    std::string strError;
    PrivacyVNextDigest active = ZeroDigest();
    PrivacyVNextDigest winning = ZeroDigest();
    BOOST_REQUIRE_MESSAGE(DeriveNoteTallyAggregates(vVotes, hashA, active, winning,
                                                    &strError), strError);

    BOOST_CHECK(active == SumPoints(vCommitments));
    BOOST_CHECK(active == CommitPoint(
        Ed25519ScalarFromInt64(vAmounts[0] + vAmounts[1] + vAmounts[2]),
        Ed25519ScalarAdd(Ed25519ScalarAdd(vBlinds[0], vBlinds[1]), vBlinds[2])));

    std::vector<PrivacyVNextDigest> vWinnerCommitments;
    vWinnerCommitments.push_back(vCommitments[0]);
    vWinnerCommitments.push_back(vCommitments[1]);
    BOOST_CHECK(winning == SumPoints(vWinnerCommitments));
    BOOST_CHECK(winning == CommitPoint(
        Ed25519ScalarFromInt64(vAmounts[0] + vAmounts[1]),
        Ed25519ScalarAdd(vBlinds[0], vBlinds[1])));
    BOOST_CHECK(active != winning);

    // Both aggregates are a pure function of the covered set, never a running
    // total: drop one vote and both change.
    std::vector<const CNoteFinalityVote*> vFewer;
    vFewer.push_back(&voteA0);
    vFewer.push_back(&voteB0);
    PrivacyVNextDigest activeFewer = ZeroDigest();
    PrivacyVNextDigest winningFewer = ZeroDigest();
    BOOST_REQUIRE(DeriveNoteTallyAggregates(vFewer, hashA, activeFewer, winningFewer,
                                            &strError));
    BOOST_CHECK(activeFewer != active);
    BOOST_CHECK(winningFewer != winning);
    BOOST_CHECK(winningFewer == vCommitments[0]);

    // A winner no vote names leaves the winning aggregate at the identity while
    // the active aggregate is unchanged.
    PrivacyVNextDigest activeNoWinner = ZeroDigest();
    PrivacyVNextDigest winningNoWinner = ZeroDigest();
    BOOST_REQUIRE(DeriveNoteTallyAggregates(vVotes, uint256(0xc3c3), activeNoWinner,
                                            winningNoWinner, &strError));
    BOOST_CHECK(activeNoWinner == active);
    BOOST_CHECK(winningNoWinner == IdentityPoint());

    // A vote whose membership instance is too short carries no commitment to sum.
    CNoteFinalityVote truncated = voteB0;
    truncated.vchMembership.resize(FINALITY_NOTE_MEMBERSHIP_MIN - 1);
    std::vector<const CNoteFinalityVote*> vTruncated;
    vTruncated.push_back(&truncated);
    BOOST_CHECK(!DeriveNoteTallyAggregates(vTruncated, hashB, activeNoWinner,
                                           winningNoWinner, &strError));

    std::vector<const CNoteFinalityVote*> vNull(1, (const CNoteFinalityVote*)NULL);
    BOOST_CHECK(!DeriveNoteTallyAggregates(vNull, hashA, activeNoWinner, winningNoWinner,
                                           &strError));
}

BOOST_AUTO_TEST_CASE(note_votes_are_inert_in_the_transparent_fallback_tally)
{
    // Liveness floor: a dead or absent tally committee must still let the chain
    // advance finality on transparent votes alone. Private (and F2 note) votes
    // reveal no clear weight, so they must contribute exactly zero to both the
    // numerator and the denominator of the fallback ratio rather than being
    // counted at whatever weight they happen to declare.
    const int nEpoch = 4242;
    const uint256 hashA = uint256(0x0a0a);
    const uint256 hashB = uint256(0x0b0b);
    const int nHeightA = 90000;
    const int nHeightB = 90001;

    std::vector<CKey> vVoterKeys(3);
    for (size_t i = 0; i < vVoterKeys.size(); i++)
        vVoterKeys[i].MakeNewKey(true);

    const CFinalityTallyCertificate noCert;

    // A private vote declaring a weight larger than the whole transparent tally,
    // cast for the losing block. If either fallback path counted it, the tier and
    // the winner below would both change.
    const int64_t nDeclared = 1000000;

    struct Split
    {
        int64_t nFirstA;
        int64_t nSecondA;
        int64_t nB;
        int nExpectedTier;
    };
    const Split vSplits[2] = {
        { 2000, 2000, 2000, FINALITY_HARD },   // 4000/6000 == 2/3 exactly
        { 1900, 1900, 2200, FINALITY_SOFT }    // 3800/6000 is over 1/2, under 2/3
    };

    for (int s = 0; s < 2; s++)
    {
        const Split& split = vSplits[s];
        const int64_t nTransparentTotal = split.nFirstA + split.nSecondA + split.nB;

        CFinalityTracker tracker;
        BOOST_REQUIRE(tracker.AddVote(
            MakeTransparentVote(nEpoch, hashA, nHeightA, split.nFirstA, vVoterKeys[0], 1),
            false, true));
        BOOST_REQUIRE(tracker.AddVote(
            MakeTransparentVote(nEpoch, hashA, nHeightA, split.nSecondA, vVoterKeys[1], 2),
            false, true));
        BOOST_REQUIRE(tracker.AddVote(
            MakeTransparentVote(nEpoch, hashB, nHeightB, split.nB, vVoterKeys[2], 3),
            false, true));
        BOOST_REQUIRE(tracker.AddVote(
            MakePrivateVote(nEpoch, hashB, nHeightB, 0, 4), false, true));
        BOOST_REQUIRE(tracker.AddVote(
            MakePrivateVote(nEpoch, hashB, nHeightB, nDeclared, 5), false, true));

        // The private votes are genuinely in the tracker, so nothing below passes
        // by their simply having been dropped.
        BOOST_CHECK_EQUAL(tracker.GetEpochVoteCount(nEpoch), 5);
        int nTransparentVotes = 0;
        int nPrivateVotes = 0;
        tracker.GetEpochVoteModeCounts(nEpoch, nTransparentVotes, nPrivateVotes);
        BOOST_CHECK_EQUAL(nTransparentVotes, 3);
        BOOST_CHECK_EQUAL(nPrivateVotes, 2);

        // Denominator: exactly the transparent weights, and no unique-voter credit
        // for a vote that names no transparent key.
        BOOST_CHECK_EQUAL(tracker.GetEpochVoteWeight(nEpoch), nTransparentTotal);
        BOOST_CHECK_EQUAL(tracker.GetEpochVoterCount(nEpoch), 3);

        // Numerator: the winner and its tier are what the transparent votes alone
        // justify. Counting either private vote would move the winner to hashB.
        int nTier = FINALITY_NONE;
        uint256 hashWinner = 0;
        int nWinnerHeight = 0;
        int nVoterCount = 0;
        BOOST_REQUIRE(tracker.ComputeDeterministicEpochTier(nEpoch, false, noCert, nTier,
                                                            hashWinner, nWinnerHeight,
                                                            nVoterCount));
        BOOST_CHECK_EQUAL(nTier, split.nExpectedTier);
        BOOST_CHECK(hashWinner == hashA);
        BOOST_CHECK_EQUAL(nWinnerHeight, nHeightA);
        BOOST_CHECK_EQUAL(nVoterCount, 3);
    }

    // With no transparent vote at all the fallback has no denominator, so private
    // votes on their own can never finalize an epoch.
    {
        CFinalityTracker tracker;
        BOOST_REQUIRE(tracker.AddVote(
            MakePrivateVote(nEpoch, hashA, nHeightA, nDeclared, 6), false, true));
        BOOST_REQUIRE(tracker.AddVote(
            MakePrivateVote(nEpoch, hashA, nHeightA, nDeclared, 7), false, true));
        BOOST_CHECK_EQUAL(tracker.GetEpochVoteWeight(nEpoch), 0);
        BOOST_CHECK_EQUAL(tracker.GetEpochVoterCount(nEpoch), 0);

        int nTier = FINALITY_NONE;
        uint256 hashWinner = 0;
        int nWinnerHeight = 0;
        int nVoterCount = 0;
        BOOST_CHECK(!tracker.ComputeDeterministicEpochTier(nEpoch, false, noCert, nTier,
                                                           hashWinner, nWinnerHeight,
                                                           nVoterCount));
        BOOST_CHECK_EQUAL(nTier, FINALITY_NONE);
    }
}

BOOST_AUTO_TEST_CASE(note_vote_binding_covers_every_replayable_field)
{
    ScopedTallyArgs scopedArgs;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeNoteCommittee(vKeys, 2);

    const uint256 mask = RandomScalar();
    const CNoteVoteShare share = MakeShare(config, 905, 640000, mask, 12, RandomScalar());
    PrivacyVNextDigest cTilde = ZeroDigest();
    BOOST_REQUIRE(share.GetCommitment(cTilde));

    const CNoteFinalityVote base = MakeVote(share, uint256(0x2222), cTilde, 0x41);
    const uint256 binding = ComputeNoteVoteBinding(base);
    BOOST_CHECK(binding != 0);
    BOOST_CHECK(ComputeNoteVoteBinding(base) == binding);

    // The membership proof binds no message, so anything a whole valid vote could be
    // replayed under has to move this digest or the sigma travels with it.
    CNoteFinalityVote mutated = base;
    mutated.nVersion = base.nVersion + 1;
    BOOST_CHECK(ComputeNoteVoteBinding(mutated) != binding);

    mutated = base;
    mutated.nEpoch = base.nEpoch + 1;
    BOOST_CHECK(ComputeNoteVoteBinding(mutated) != binding);

    mutated = base;
    mutated.hashCurveRoot = uint256(0x4322);
    BOOST_CHECK(ComputeNoteVoteBinding(mutated) != binding);

    mutated = base;
    mutated.hashNullifierRoot = uint256(0x8766);
    BOOST_CHECK(ComputeNoteVoteBinding(mutated) != binding);

    mutated = base;
    mutated.hashBlock = uint256(0x2223);
    BOOST_CHECK(ComputeNoteVoteBinding(mutated) != binding);

    mutated = base;
    mutated.nHeight = base.nHeight + 1;
    BOOST_CHECK(ComputeNoteVoteBinding(mutated) != binding);

    mutated = base;
    mutated.nTime = base.nTime + 1;
    BOOST_CHECK(ComputeNoteVoteBinding(mutated) != binding);

    mutated = base;
    mutated.committeeSetHash = uint256(0x5152);
    BOOST_CHECK(ComputeNoteVoteBinding(mutated) != binding);

    mutated = base;
    mutated.vchMembership[mutated.vchMembership.size() - 1] ^= 0x01;
    BOOST_CHECK(ComputeNoteVoteBinding(mutated) != binding);

    // The share reaches the binding through its own hash, which is what makes one share
    // structurally this vote's own: mutating or swapping it strands the sigma.
    mutated = base;
    mutated.share.vVssCoefficients[1][0] ^= 0x01;
    BOOST_CHECK(ComputeNoteVoteBinding(mutated) != binding);

    mutated = base;
    mutated.share.vEncryptedRecipientShares[2][0] ^= 0x01;
    BOOST_CHECK(ComputeNoteVoteBinding(mutated) != binding);

    const CNoteVoteShare foreign =
        MakeShare(config, 905, 640000, mask, 12, RandomScalar());
    BOOST_CHECK(foreign.GetHash() != share.GetHash());
    mutated = base;
    mutated.share = foreign;
    BOOST_CHECK(ComputeNoteVoteBinding(mutated) != binding);

    // The tag and the sigma are bound by the sigma's own challenge, not by this digest.
    mutated = base;
    mutated.vchTag.assign(FINALITY_NOTE_POINT_SIZE, 0x42);
    mutated.vchSigma.assign(FINALITY_NOTE_SIGMA_SIZE, 0x99);
    BOOST_CHECK(ComputeNoteVoteBinding(mutated) == binding);
}

BOOST_AUTO_TEST_CASE(note_vote_structural_rules_reject_before_the_sigma)
{
    ScopedTallyArgs scopedArgs;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeNoteCommittee(vKeys, 2);

    const int64_t nAmount = 512000;
    const uint256 mask = RandomScalar();
    const CNoteVoteShare share = MakeShare(config, 906, nAmount, mask, 3, RandomScalar());
    PrivacyVNextDigest cTilde = ZeroDigest();
    BOOST_REQUIRE(share.GetCommitment(cTilde));
    BOOST_REQUIRE(cTilde == CommitPoint(Ed25519ScalarFromInt64(nAmount), mask));

    // The sigma is deliberately unprovable here; every rule below rejects ahead of it,
    // so the sigma error is the marker for "this vote got past the structural rules".
    const CNoteFinalityVote base = MakeVote(share, uint256(0x3333), cTilde, 0x51);
    const std::string strSigmaError = "note vote sigma does not verify";

    std::string strError;
    BOOST_CHECK(!CheckNoteVote(base, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError, strSigmaError);

    CNoteFinalityVote vote = base;
    vote.nVersion = FINALITY_NOTE_VOTE_VERSION + 1;
    BOOST_CHECK(!CheckNoteVote(vote, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError, "note vote version is not the F2 version");

    // The O~/C~ accessors are fixed offsets, so the shape they assume is consensus.
    vote = base;
    vote.vchMembership[2] = (unsigned char)(iv5::TREE_LAYERS + 1);
    BOOST_CHECK(!CheckNoteVote(vote, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError,
                      "note vote membership instance is not the pinned one-input shape");

    vote = base;
    vote.vchMembership[3] = 1;   // a root curve the offsets were not written for
    BOOST_CHECK(!CheckNoteVote(vote, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError,
                      "note vote membership instance is not the pinned one-input shape");

    vote = base;
    vote.vchMembership[4] = 2;   // two inputs behind a one-input layout
    BOOST_CHECK(!CheckNoteVote(vote, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError,
                      "note vote membership instance is not the pinned one-input shape");

    vote = base;
    vote.vchMembership[FINALITY_NOTE_MEMBERSHIP_HEADER] ^= 0x01;
    BOOST_CHECK(!CheckNoteVote(vote, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError,
                      "note vote membership root differs from the declared anchor");

    vote = base;
    vote.vchTag.assign(FINALITY_NOTE_POINT_SIZE - 1, 0x51);
    BOOST_CHECK(!CheckNoteVote(vote, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError, "note vote tag is not a point");

    vote = base;
    vote.vchSigma.assign(FINALITY_NOTE_SIGMA_SIZE - 1, 0x11);
    BOOST_CHECK(!CheckNoteVote(vote, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError, "note vote sigma has the wrong length");

    vote = base;
    vote.share.nEpoch = base.nEpoch + 1;
    BOOST_CHECK(!CheckNoteVote(vote, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError,
                      "note vote share does not name the vote's epoch and committee");

    vote = base;
    vote.share.committeeSetHash = uint256(0x5152);
    BOOST_CHECK(!CheckNoteVote(vote, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError,
                      "note vote share does not name the vote's epoch and committee");

    vote = base;
    vote.hashBlock = 0;
    BOOST_CHECK(!CheckNoteVote(vote, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError, "note vote leaves a bound field empty");

    // K_0 == C~ is what ties an accepted share set to this vote's own weight. The same
    // vote with K_0 left alone reaches the sigma, so the rule is what fired here.
    vote = base;
    const PrivacyVNextDigest wrongCommitment =
        CommitPoint(Ed25519ScalarFromInt64(nAmount + 1), mask);
    BOOST_REQUIRE(wrongCommitment != cTilde);
    vote.share.vVssCoefficients[0].assign(wrongCommitment.begin(), wrongCommitment.end());
    BOOST_CHECK(!CheckNoteVote(vote, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError,
                      "note vote share coefficient K_0 is not the vote's commitment");

    vote.share.vVssCoefficients[0] = base.share.vVssCoefficients[0];
    BOOST_CHECK(!CheckNoteVote(vote, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError, strSigmaError);
}

BOOST_AUTO_TEST_CASE(note_vote_sigma_binds_the_vote_and_gates_the_membership_proof)
{
    ScopedTallyArgs scopedArgs;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeNoteCommittee(vKeys, 2);

    const uint256 mask = RandomScalar();
    const CNoteVoteShare share = MakeShare(config, 907, 777000, mask, 21, RandomScalar());
    PrivacyVNextDigest cTilde = ZeroDigest();
    BOOST_REQUIRE(share.GetCommitment(cTilde));

    const uint256 x = RandomScalar();
    const PrivacyVNextDigest oTilde = BasePointMultiple(x);
    CNoteFinalityVote vote = MakeVote(share, uint256(0x4444), cTilde, 0x61, &oTilde);

    const uint256 binding = ComputeNoteVoteBinding(vote);
    PrivacyVNextDigest bindingDigest = ZeroDigest();
    memcpy(bindingDigest.data(), binding.begin(), 32);
    PrivacyVNextDigest entropy;
    entropy.fill(0x7e);

    PrivacyVNextDigest tag = ZeroDigest();
    std::vector<unsigned char> vchSigma;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        ProvePrivacyVNextVoteSigma((uint64_t)vote.nEpoch, oTilde, cTilde, bindingDigest,
                                   Ed25519ScalarToDigest(x),
                                   Ed25519ScalarToDigest(uint256(0)), entropy, tag,
                                   vchSigma, error),
        error);
    vote.vchTag.assign(tag.begin(), tag.end());
    vote.vchSigma = vchSigma;
    BOOST_REQUIRE(VerifyPrivacyVNextVoteSigma((uint64_t)vote.nEpoch, oTilde, cTilde,
                                              bindingDigest, tag, vchSigma, error));

    // The sigma passes, so the only thing left to reject this vote is the membership
    // proof, which is deliberately not a real one here.
    const std::string strMembershipError = "note vote membership proof does not verify";
    const std::string strSigmaError = "note vote sigma does not verify";
    std::string strError;
    BOOST_CHECK(!CheckNoteVote(vote, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError, strMembershipError);

    // Every field the binding covers now has to strand this sigma. Fields that another
    // rule also pins are moved consistently, so the sigma is what rejects them.
    CNoteFinalityVote mutated = vote;
    mutated.nEpoch = vote.nEpoch + 1;
    mutated.share.nEpoch = mutated.nEpoch;
    BOOST_CHECK(!CheckNoteVote(mutated, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError, strSigmaError);

    mutated = vote;
    mutated.hashBlock = uint256(0x4445);
    BOOST_CHECK(!CheckNoteVote(mutated, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError, strSigmaError);

    mutated = vote;
    mutated.nHeight = vote.nHeight + 1;
    BOOST_CHECK(!CheckNoteVote(mutated, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError, strSigmaError);

    mutated = vote;
    mutated.nTime = vote.nTime + 1;
    BOOST_CHECK(!CheckNoteVote(mutated, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError, strSigmaError);

    mutated = vote;
    mutated.hashNullifierRoot = uint256(0x8766);
    BOOST_CHECK(!CheckNoteVote(mutated, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError, strSigmaError);

    mutated = vote;
    mutated.hashCurveRoot = uint256(0x4322);
    memcpy(&mutated.vchMembership[FINALITY_NOTE_MEMBERSHIP_HEADER],
           mutated.hashCurveRoot.begin(), 32);
    BOOST_CHECK(!CheckNoteVote(mutated, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError, strSigmaError);

    mutated = vote;
    mutated.committeeSetHash = uint256(0x5152);
    mutated.share.committeeSetHash = mutated.committeeSetHash;
    BOOST_CHECK(!CheckNoteVote(mutated, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError, strSigmaError);

    mutated = vote;
    mutated.vchMembership[mutated.vchMembership.size() - 1] ^= 0x01;
    BOOST_CHECK(!CheckNoteVote(mutated, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError, strSigmaError);

    mutated = vote;
    mutated.share.vVssCoefficients[1][0] ^= 0x01;
    BOOST_CHECK(!CheckNoteVote(mutated, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError, strSigmaError);

    mutated = vote;
    mutated.share.vEncryptedRecipientShares[2][0] ^= 0x01;
    BOOST_CHECK(!CheckNoteVote(mutated, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError, strSigmaError);

    // A sigma proved for one epoch does not verify under another, so a whole vote cannot
    // be lifted into the next epoch's tally.
    BOOST_CHECK(!VerifyPrivacyVNextVoteSigma((uint64_t)vote.nEpoch + 1, oTilde, cTilde,
                                             bindingDigest, tag, vchSigma, error));
    BOOST_CHECK(!VerifyPrivacyVNextVoteSigma((uint64_t)vote.nEpoch, oTilde,
                                             CommitPoint(Ed25519ScalarFromInt64(1), mask),
                                             bindingDigest, tag, vchSigma, error));
    BOOST_CHECK(!VerifyPrivacyVNextVoteSigma((uint64_t)vote.nEpoch,
                                             BasePointMultiple(RandomScalar()), cTilde,
                                             bindingDigest, tag, vchSigma, error));

    // The tag is the once-per-epoch dedup key, so it cannot be swapped for another.
    PrivacyVNextDigest foreignTag = ZeroDigest();
    memcpy(foreignTag.data(), BasePointMultiple(RandomScalar()).data(), 32);
    BOOST_CHECK(!VerifyPrivacyVNextVoteSigma((uint64_t)vote.nEpoch, oTilde, cTilde,
                                             bindingDigest, foreignTag, vchSigma, error));
    mutated = vote;
    mutated.vchTag.assign(foreignTag.begin(), foreignTag.end());
    BOOST_CHECK(!CheckNoteVote(mutated, config.nThresholdM, config.nThresholdN, &strError));
    BOOST_CHECK_EQUAL(strError, strSigmaError);
    BOOST_CHECK(mutated.GetVoteTag() != vote.GetVoteTag());
}

BOOST_AUTO_TEST_SUITE_END()
