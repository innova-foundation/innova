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
#include "../privacy_vnext_store.h"
#include "../serialize.h"
#include "../txdb.h"
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
    vote.hashCurveRoot = uint256(0x4321);
    vote.hashNullifierRoot = uint256(0x8765);
    vote.committeeSetHash = share.committeeSetHash;
    vote.vchMembership = MakeMembershipRequest(vote.hashCurveRoot,
                                               pOTilde ? *pOTilde : ZeroDigest(), cTilde);
    vote.vchTag.assign(FINALITY_NOTE_POINT_SIZE, nTagSeed);
    vote.vchSigma.assign(FINALITY_NOTE_SIGMA_SIZE, 0x11);
    // Filler of a legal length: every case below rejects at or before the sigma, which
    // runs ahead of the weight-floor verification.
    vote.vchWeightFloorProof.assign(672, 0x33);
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

// --- F2 certificate helpers ---------------------------------------------------

struct ScopedNoteVoteFork
{
    int nSaved;
    explicit ScopedNoteVoteFork(int nHeight) : nSaved(nRegtestIV5NoteVoteHeight)
    {
        nRegtestIV5NoteVoteHeight = nHeight;
    }
    ~ScopedNoteVoteFork() { nRegtestIV5NoteVoteHeight = nSaved; }
};

// A structurally-complete v4 certificate. The tier proofs are filler of a legal
// length: IsValidBasic and the digests only read their bytes, and the cases that
// need a proof to actually verify build a real one.
CFinalityTallyCertificate MakeNoteCert(int nEpoch, int nHeight,
                                       const uint256& committeeSetHash)
{
    CFinalityTallyCertificate cert;
    cert.nVersion = FINALITY_NOTE_CERT_VERSION;
    cert.nEpoch = nEpoch;
    cert.nHeight = nHeight;
    cert.hashBlock = uint256(0xbeef01);
    cert.nTier = FINALITY_HARD;
    cert.nConsecutiveHardCount = 0;
    cert.committeeSetHash = committeeSetHash;
    cert.nTransparentActiveWeight = 0;
    cert.nTransparentWinningWeight = 0;
    cert.nTransparentRewardBudget = 0;
    cert.vVoteNullifiers.push_back(uint256(0x7001));
    cert.vNoteVoteTags.push_back(uint256(0x3001));
    cert.vNoteVoteTags.push_back(uint256(0x3002));
    cert.noteTierProofs.vchTierSlack.assign(64, 0x71);
    cert.noteTierProofs.vchWinningCap.assign(64, 0x72);
    cert.noteTierProofs.vchActiveCap.assign(64, 0x73);
    return cert;
}

CNoteVoteComplaint MakeStubComplaint(int nEpoch, const uint256& voteTag,
                                     unsigned char nSeed)
{
    CNoteVoteComplaint complaint;
    complaint.nEpoch = nEpoch;
    complaint.voteTag = voteTag;
    complaint.hashShare = uint256(0x4000 + nSeed);
    complaint.nRecipientIndex = 0;
    complaint.vchSharedPoint.assign(33, nSeed);
    complaint.vchDleqProof.assign(FINALITY_NOTE_DLEQ_SIZE, nSeed);
    return complaint;
}

void SignCertByCommittee(CFinalityTallyCertificate& cert, std::vector<CKey>& vKeys,
                         int nCount)
{
    cert.vSignerIndexes.clear();
    cert.vSignerSigs.clear();
    const uint256 digest = cert.GetSignatureDigest();
    for (int i = 0; i < nCount; i++)
    {
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(vKeys[i].Sign(digest, sig));
        cert.vSignerIndexes.push_back((uint16_t)i);
        cert.vSignerSigs.push_back(sig);
    }
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
    mutated.vchWeightFloorProof[0] ^= 0x01;
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

    // At the floor, so this vote can carry a real weight-floor proof and the membership
    // proof stays the only thing left to reject it.
    const int64_t nAmount = FINALITY_MIN_VOTE_WEIGHT;
    const uint256 mask = RandomScalar();
    const CNoteVoteShare share = MakeShare(config, 907, nAmount, mask, 21, RandomScalar());
    PrivacyVNextDigest cTilde = ZeroDigest();
    BOOST_REQUIRE(share.GetCommitment(cTilde));

    const uint256 x = RandomScalar();
    const PrivacyVNextDigest oTilde = BasePointMultiple(x);
    CNoteFinalityVote vote = MakeVote(share, uint256(0x4444), cTilde, 0x61, &oTilde);
    {
        PrivacyVNextDigest entropySeed;
        entropySeed.fill(0x6f);
        std::string strFloorError;
        BOOST_REQUIRE_MESSAGE(
            BuildNoteVoteWeightFloorProof(nAmount, mask, entropySeed,
                                          vote.vchWeightFloorProof, &strFloorError),
            strFloorError);
    }

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
    mutated.vchWeightFloorProof[0] ^= 0x01;
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

// --- The producer -----------------------------------------------------------
//
// Every case above builds its vote around a membership request that is deliberately not a
// real proof. These run the producer instead, over a note actually placed in the IV5 tree,
// so the membership proof is real and CheckNoteVote is reached in full.

namespace
{

// One note in the IV5 tree and the material a vote over it is built from.
struct VotableNote
{
    PrivacyVNextSpendInput input;
    PrivacyVNextDigest mask;
    uint256 hashAnchorRoot;
    uint64_t nAmount;
    uint64_t nTreeSize;

    VotableNote() : hashAnchorRoot(0), nAmount(0), nTreeSize(0) {}
};

// Reset the tree store to one leaf we own, then cut that leaf's witness from it. The
// anchor root and the witness come from the same frontier, which is the only pairing
// that folds onto a root a validator accepts.
void FundVotableNote(CTxDB& txdb, VotableNote& funded, unsigned char nSeed,
                     uint64_t nAmount)
{
    std::string error;
    PrivacyVNextDigest genesis;
    PrivacyVNextLocalGenesis(genesis.data());
    const uint8_t nNetwork = PrivacyVNextLocalNetworkId();

    PrivacyVNextDigest seed;
    seed.fill(nSeed);
    PrivacyVNextDerivedKeys keys;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextKeys(seed, genesis, 0, nNetwork, 0, keys, error), error);

    // Canonical field elements: a repeated byte overflows the group order.
    PrivacyVNextDigest noteEphemeral, tweakEphemeral, outY, outMask;
    noteEphemeral.fill(0);
    tweakEphemeral.fill(0);
    outY.fill(0);
    outMask.fill(0);
    noteEphemeral[0] = (unsigned char)(nSeed ^ 0x11);
    tweakEphemeral[0] = (unsigned char)(nSeed ^ 0x22);
    outY[0] = (unsigned char)(nSeed ^ 0x33);
    outMask[0] = (unsigned char)(nSeed ^ 0x44);
    PrivacyVNextEncryptedOutput funding;
    BOOST_REQUIRE_MESSAGE(
        EncryptPrivacyVNextNote(nNetwork, 0, 0, genesis, keys.spendPublic,
                                keys.viewPublic, keys.outgoingViewSecret,
                                noteEphemeral, tweakEphemeral, nAmount, outY,
                                outMask, funding, error),
        error);

    PrivacyVNextEpochSeed epochSeed;
    BOOST_REQUIRE_MESSAGE(LoadPrivacyVNextEpochSeed(epochSeed, error), error);
    std::vector<unsigned char> treeState = epochSeed.vchTreeState;
    BOOST_REQUIRE_MESSAGE(TrimPrivacyVNextTreeStore(txdb, 0, treeState, error), error);
    std::vector<PrivacyVNextOutputLeaf> vLeaves(1, funding.leaf);
    BOOST_REQUIRE_MESSAGE(
        GrowPrivacyVNextTreeStore(txdb, vLeaves, treeState, error), error);

    std::vector<unsigned char> vchRoot;
    BOOST_REQUIRE_MESSAGE(
        DecodePrivacyVNextTreeState(treeState, vchRoot, funded.nTreeSize, error), error);
    BOOST_REQUIRE_EQUAL(vchRoot.size(), 32U);

    std::vector<uint64_t> vTargets(1, 0);
    std::vector<unsigned char> vchPaths;
    BOOST_REQUIRE_MESSAGE(
        ReadPrivacyVNextTreePaths(txdb, funded.nTreeSize, treeState, vTargets,
                                  vchPaths, error),
        error);
    std::vector<PrivacyVNextMembershipWitness> vWitnesses;
    PrivacyVNextDigest treeRoot;
    BOOST_REQUIRE_MESSAGE(
        BuildPrivacyVNextWitnessesFromPaths(treeState, vTargets, vchPaths,
                                            vWitnesses, treeRoot, error),
        error);
    BOOST_REQUIRE_EQUAL(vWitnesses.size(), 1U);
    BOOST_REQUIRE(std::equal(treeRoot.begin(), treeRoot.end(), vchRoot.begin()));

    PrivacyVNextEncryptedNote onChain;
    onChain.nOutputIndex = 0;
    onChain.genesis = genesis;
    onChain.leafO = funding.leaf.owner;
    onChain.leafC = funding.leaf.commitment;
    onChain.noteEphemeral = funding.noteEphemeral;
    onChain.tweakEphemeral = funding.tweakEphemeral;
    onChain.vchCiphertext = funding.vchRecipientCiphertext;
    PrivacyVNextScannedNote scanned;
    BOOST_REQUIRE_MESSAGE(
        ScanPrivacyVNextNote(PRIVACY_VNEXT_SCAN_FULL, nNetwork, 0, onChain,
                             keys.viewSecret, keys.spendSecret, scanned, error),
        error);
    BOOST_REQUIRE_EQUAL(scanned.nAmount, nAmount);

    funded.input.spendScalar = scanned.spendSecret;
    funded.input.commitmentScalar = scanned.y;
    funded.input.leaf = funding.leaf;
    funded.input.vchWitnessRecord = vWitnesses[0].vchRecord;
    funded.mask = scanned.mask;
    funded.nAmount = scanned.nAmount;
    funded.hashAnchorRoot = 0;
    memcpy(funded.hashAnchorRoot.begin(), &vchRoot[0], 32);
}

// Chain context a note vote is checked against, restored on the way out. The note-vote
// fork height, the block the vote targets and the finalized epoch state are all global.
struct ScopedNoteVoteContext
{
    int nNoteVoteHeightSaved;
    uint256 hashBlock;
    CBlockIndex index;
    CBlockIndex* pOldIndex;
    bool fHadOldIndex;
    CTxDB& txdb;
    int nEpochStateKey;
    CEpochState original;
    bool fHadOriginal;

    ScopedNoteVoteContext(CTxDB& txdbIn, const uint256& hashBlockIn, int nBlockHeight,
                          int nEpochStateKeyIn)
        : nNoteVoteHeightSaved(nRegtestIV5NoteVoteHeight), hashBlock(hashBlockIn),
          pOldIndex(NULL), fHadOldIndex(false), txdb(txdbIn),
          nEpochStateKey(nEpochStateKeyIn), fHadOriginal(false)
    {
        nRegtestIV5NoteVoteHeight = 0;

        std::map<uint256, CBlockIndex*>::iterator itOld = mapBlockIndex.find(hashBlock);
        if (itOld != mapBlockIndex.end())
        {
            fHadOldIndex = true;
            pOldIndex = itOld->second;
        }
        index.nHeight = nBlockHeight;
        index.nFlags = 0;   // proof of work, which a note vote must target
        mapBlockIndex[hashBlock] = &index;
        index.phashBlock = &mapBlockIndex.find(hashBlock)->first;

        fHadOriginal = txdb.ReadEpochState(nEpochStateKey, original);
        txdb.EraseEpochState(nEpochStateKey);
    }

    ~ScopedNoteVoteContext()
    {
        if (fHadOriginal)
            txdb.WriteEpochState(nEpochStateKey, original);
        else
            txdb.EraseEpochState(nEpochStateKey);
        if (fHadOldIndex)
            mapBlockIndex[hashBlock] = pOldIndex;
        else
            mapBlockIndex.erase(hashBlock);
        nRegtestIV5NoteVoteHeight = nNoteVoteHeightSaved;
    }
};

CNoteVoteBuildContext VoteContext(const VotableNote& funded, int nEpoch)
{
    CNoteVoteBuildContext ctx;
    ctx.nEpoch = nEpoch;
    ctx.nHeight = GetEpochBoundaryHeight(nEpoch, 0);
    ctx.hashBlock = uint256(0x9001);
    ctx.hashAnchorRoot = funded.hashAnchorRoot;
    ctx.hashNullifierRoot = uint256(0x9002);
    ctx.nAmount = (int64_t)funded.nAmount;
    ctx.nReward = 11;
    return ctx;
}

} // namespace

// The whole contract, end to end: a vote built over a note that is really in the tree has
// to pass the checker consensus runs, with the real membership proof rather than the
// stand-in every case above uses.
BOOST_AUTO_TEST_CASE(a_produced_note_vote_passes_the_checker)
{
    ScopedTallyArgs scopedArgs;
    CTxDB txdb("r+");
    std::vector<CKey> vKeys(4);
    const CFinalityTallyConfig config = MakeNoteCommittee(vKeys, 3);

    VotableNote funded;
    FundVotableNote(txdb, funded, 0x71, (uint64_t)FINALITY_MIN_VOTE_WEIGHT + 4200);
    const CNoteVoteBuildContext ctx = VoteContext(funded, 907);

    CNoteFinalityVote vote;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(
        BuildNoteFinalityVote(ctx, funded.input, funded.mask, config, vote, &strError),
        strError);

    BOOST_CHECK(CheckNoteVote(vote, config.nThresholdM, config.nThresholdN, &strError));

    // The vote names the epoch it was asked for and the anchor it proved against, and the
    // proof's own root field is that anchor rather than one declared beside it.
    BOOST_CHECK_EQUAL(vote.nEpoch, ctx.nEpoch);
    BOOST_CHECK(vote.hashCurveRoot == funded.hashAnchorRoot);
    BOOST_CHECK(memcmp(&vote.vchMembership[FINALITY_NOTE_MEMBERSHIP_HEADER],
                       funded.hashAnchorRoot.begin(), 32) == 0);
    BOOST_CHECK(vote.committeeSetHash == config.committeeSetHash);

    // Share shape is the committee's, not the voter's, and K_0 is the commitment the
    // membership proof re-randomized rather than the note's own leaf commitment.
    BOOST_CHECK_EQUAL((int)vote.share.vVssCoefficients.size(), config.nThresholdM);
    BOOST_CHECK_EQUAL((int)vote.share.vEncryptedRecipientShares.size(),
                      config.nThresholdN);
    PrivacyVNextDigest cTilde = ZeroDigest();
    PrivacyVNextDigest commitment = ZeroDigest();
    BOOST_REQUIRE(vote.GetCTilde(cTilde));
    BOOST_REQUIRE(vote.share.GetCommitment(commitment));
    BOOST_CHECK(commitment == cTilde);
    BOOST_CHECK(cTilde != funded.input.leaf.commitment);

    // Every committee member can open its own evaluation, which is what makes the vote
    // tallyable rather than merely well-formed.
    for (size_t i = 0; i < vKeys.size(); i++)
    {
        CNoteTallyPlainShare plain;
        bool fComplainable = false;
        BOOST_CHECK(DecryptNoteVoteShareForRecipient(vote.share, config, vKeys[i],
                                                     (int)i, plain, &fComplainable));
        BOOST_CHECK(CheckNoteVoteVssEvaluation(vote.share, plain, &strError));
    }
}

// Nothing half-built ever leaves the producer: an input it cannot satisfy yields no vote
// at all, because a partial vote relayed is a peer's rejection and a producer's wasted
// block space.
BOOST_AUTO_TEST_CASE(note_vote_production_fails_closed)
{
    ScopedTallyArgs scopedArgs;
    CTxDB txdb("r+");
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeNoteCommittee(vKeys, 2);

    VotableNote funded;
    FundVotableNote(txdb, funded, 0x72, (uint64_t)FINALITY_MIN_VOTE_WEIGHT);
    const CNoteVoteBuildContext base = VoteContext(funded, 908);

    CNoteFinalityVote vote;
    std::string strError;

    // No finalized anchor: nothing to prove against, so nothing is produced.
    CNoteVoteBuildContext ctx = base;
    ctx.hashAnchorRoot = 0;
    BOOST_CHECK(!BuildNoteFinalityVote(ctx, funded.input, funded.mask, config, vote,
                                       &strError));
    BOOST_CHECK_EQUAL(strError, "note vote has no finalized anchor to build against");
    BOOST_CHECK(vote.vchMembership.empty() && vote.vchSigma.empty());

    // Under the floor there is no weight-floor proof to make, so the vote is refused here
    // rather than at the first peer that checks it.
    ctx = base;
    ctx.nAmount = FINALITY_MIN_VOTE_WEIGHT - 1;
    BOOST_CHECK(!BuildNoteFinalityVote(ctx, funded.input, funded.mask, config, vote,
                                       &strError));
    BOOST_CHECK_EQUAL(strError,
                      "note vote weight or reward is outside the range a vote may carry");
    BOOST_CHECK(vote.vchMembership.empty());

    // A committee of one opens this voter's exact weight, which is the one thing the
    // share split exists to prevent.
    std::vector<CKey> vSolo(1);
    const CFinalityTallyConfig soloConfig = MakeNoteCommittee(vSolo, 1);
    BOOST_CHECK(!BuildNoteFinalityVote(base, funded.input, funded.mask, soloConfig, vote,
                                       &strError));
    BOOST_CHECK_EQUAL(strError,
                      "note vote needs a valid M-of-N committee with M above one");

    // No witness, no membership proof. A note may be ours and still have no position
    // under the anchor the vote has to name.
    PrivacyVNextSpendInput witnessless;
    witnessless.spendScalar = funded.input.spendScalar;
    witnessless.commitmentScalar = funded.input.commitmentScalar;
    witnessless.leaf = funded.input.leaf;
    BOOST_CHECK(!BuildNoteFinalityVote(base, witnessless, funded.mask, config, vote,
                                       &strError));
    BOOST_CHECK_EQUAL(strError,
                      "note vote has no membership witness for the anchor tree");

    // A mask that does not open the note's own commitment reaches a C~ the membership
    // proof never produced, so K_0 cannot be the vote's commitment.
    PrivacyVNextDigest wrongMask = funded.mask;
    wrongMask[0] ^= 0x01;
    BOOST_CHECK(!BuildNoteFinalityVote(base, funded.input, wrongMask, config, vote,
                                       &strError));
    BOOST_CHECK_EQUAL(strError,
                      "note vote share does not open the membership proof's commitment");
    BOOST_CHECK(vote.vchMembership.empty() && vote.vchTag.empty());
}

// The tag is one note's single identity for one epoch. Two runs over the same note reach
// it again -- which is why the producer may only run once per note per epoch -- and a
// different epoch reaches a different one.
BOOST_AUTO_TEST_CASE(one_note_reaches_one_tag_per_epoch)
{
    ScopedTallyArgs scopedArgs;
    CTxDB txdb("r+");
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeNoteCommittee(vKeys, 2);

    VotableNote funded;
    FundVotableNote(txdb, funded, 0x73, (uint64_t)FINALITY_MIN_VOTE_WEIGHT + 9);
    const CNoteVoteBuildContext ctx = VoteContext(funded, 909);

    CNoteFinalityVote first, second;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(
        BuildNoteFinalityVote(ctx, funded.input, funded.mask, config, first, &strError),
        strError);
    BOOST_REQUIRE_MESSAGE(
        BuildNoteFinalityVote(ctx, funded.input, funded.mask, config, second, &strError),
        strError);

    // Same tag, different bytes: running the producer twice inside one epoch mints a
    // second identity under one tag, and a tag with two identities counts for neither.
    BOOST_CHECK(first.GetVoteTag() == second.GetVoteTag());
    BOOST_CHECK(first.GetVoteTag() != 0);
    BOOST_CHECK(first.GetHash() != second.GetHash());
    std::vector<const CNoteFinalityVote*> vCarried;
    vCarried.push_back(&first);
    vCarried.push_back(&second);
    std::map<uint256, const CNoteFinalityVote*> mapCounted;
    std::set<uint256> setEquivocated;
    ResolveNoteVoteCounting(vCarried, mapCounted, setEquivocated);
    BOOST_CHECK(mapCounted.empty());
    BOOST_CHECK_EQUAL(setEquivocated.size(), 1U);

    CNoteVoteBuildContext nextEpoch = ctx;
    nextEpoch.nEpoch = ctx.nEpoch + 1;
    CNoteFinalityVote later;
    BOOST_REQUIRE_MESSAGE(
        BuildNoteFinalityVote(nextEpoch, funded.input, funded.mask, config, later,
                              &strError),
        strError);
    BOOST_CHECK(later.GetVoteTag() != first.GetVoteTag());
    BOOST_CHECK(CheckNoteVote(later, config.nThresholdM, config.nThresholdN, &strError));
}

// With a real membership proof the sigma is the only thing left to reject a mutated vote,
// which is where the binding is actually load-bearing: nothing the producer put in the
// vote can be restated by a relaying peer.
BOOST_AUTO_TEST_CASE(a_produced_note_vote_is_bound_to_the_fields_it_declares)
{
    ScopedTallyArgs scopedArgs;
    CTxDB txdb("r+");
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeNoteCommittee(vKeys, 2);

    VotableNote funded;
    FundVotableNote(txdb, funded, 0x74, (uint64_t)FINALITY_MIN_VOTE_WEIGHT + 77);
    const CNoteVoteBuildContext ctx = VoteContext(funded, 910);

    CNoteFinalityVote vote;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(
        BuildNoteFinalityVote(ctx, funded.input, funded.mask, config, vote, &strError),
        strError);

    const std::string strSigmaError = "note vote sigma does not verify";
    CNoteFinalityVote mutated = vote;
    mutated.nEpoch = vote.nEpoch + 1;
    mutated.share.nEpoch = mutated.nEpoch;
    BOOST_CHECK(!CheckNoteVote(mutated, config.nThresholdM, config.nThresholdN,
                               &strError));
    BOOST_CHECK_EQUAL(strError, strSigmaError);

    mutated = vote;
    mutated.hashBlock = uint256(0x9999);
    BOOST_CHECK(!CheckNoteVote(mutated, config.nThresholdM, config.nThresholdN,
                               &strError));
    BOOST_CHECK_EQUAL(strError, strSigmaError);

    mutated = vote;
    mutated.nHeight = vote.nHeight + 1;
    BOOST_CHECK(!CheckNoteVote(mutated, config.nThresholdM, config.nThresholdN,
                               &strError));
    BOOST_CHECK_EQUAL(strError, strSigmaError);

    mutated = vote;
    mutated.hashNullifierRoot = uint256(0x9003);
    BOOST_CHECK(!CheckNoteVote(mutated, config.nThresholdM, config.nThresholdN,
                               &strError));
    BOOST_CHECK_EQUAL(strError, strSigmaError);

    // The weight-floor proof re-randomizes over the same point, so leaving it unbound
    // would let a peer mint a byte-distinct twin under this vote's own tag.
    mutated = vote;
    mutated.vchWeightFloorProof[0] ^= 0x01;
    BOOST_CHECK(!CheckNoteVote(mutated, config.nThresholdM, config.nThresholdN,
                               &strError));
    BOOST_CHECK_EQUAL(strError, strSigmaError);

    // Swapping the anchor for another real root strands the vote at the structural check,
    // before either the sigma or the membership verification runs.
    VotableNote other;
    FundVotableNote(txdb, other, 0x75, (uint64_t)FINALITY_MIN_VOTE_WEIGHT + 5);
    BOOST_REQUIRE(other.hashAnchorRoot != funded.hashAnchorRoot);
    mutated = vote;
    mutated.hashCurveRoot = other.hashAnchorRoot;
    BOOST_CHECK(!CheckNoteVote(mutated, config.nThresholdM, config.nThresholdN,
                               &strError));
    BOOST_CHECK_EQUAL(strError,
                      "note vote membership root differs from the declared anchor");
}

// The anchor a note vote declares is the finalized epoch's IV5 note-tree root, because
// that is the root its membership proof is over and the one IsValidBasic pins the proof's
// own root field to. CEpochState::hashCurveRoot is the retired ring-signature curve tree
// and is a different value entirely -- zero on a chain that never carried one -- so a
// context check reading it rejects every note vote that could ever exist.
BOOST_AUTO_TEST_CASE(note_vote_context_anchors_to_the_iv5_tree_root)
{
    ScopedTallyArgs scopedArgs;
    CTxDB txdb("r+");
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeNoteCommittee(vKeys, 2);

    CFinalityTracker tracker;
    tracker.SetInitialFinalityCommittee(config.vCommitteePubKeys, config.nThresholdM);

    // An epoch whose boundary is past the DAG fork, so the anchor resolves from the
    // persisted epoch state the way a connecting block resolves it.
    const int nVoteEpoch = 3;
    const int nVoteHeight = GetEpochBoundaryHeight(nVoteEpoch, 0);
    BOOST_REQUIRE_EQUAL(GetEpochForHeight(nVoteHeight), nVoteEpoch);
    BOOST_REQUIRE(nVoteHeight >= FORK_HEIGHT_EPOCH_STATE_V2);
    const int nAnchorEpoch = nVoteEpoch - 1;
    const int nFinalizedHeight = GetEpochBoundaryHeight(nAnchorEpoch, 0) + 1;
    BOOST_REQUIRE_EQUAL(GetEpochForHeight(nFinalizedHeight), nAnchorEpoch);

    const uint256 hashEpochBlock(0x9101);
    ScopedNoteVoteContext context(txdb, hashEpochBlock, nVoteHeight, nAnchorEpoch);

    const uint256 hashIV5Root(0x9102);
    const uint256 hashNullifierRoot(0x9103);
    CEpochState anchor;
    anchor.nEpoch = nAnchorEpoch;
    anchor.nFinalizedHeightAsOf = nFinalizedHeight;
    anchor.nSerVersion = EPOCHSTATE_SER_VERSION_V4;
    // The retired curve tree's root, deliberately not the IV5 one. A validator that
    // compares the vote against this field can never accept a real membership proof.
    anchor.hashCurveRoot = uint256(0x9104);
    anchor.hashNullifierRoot = hashNullifierRoot;
    anchor.vchVNextRoot.assign(hashIV5Root.begin(), hashIV5Root.end());
    anchor.nVNextTreeSize = 1;
    BOOST_REQUIRE(txdb.WriteEpochState(nAnchorEpoch, anchor));

    const int64_t nAmount = FINALITY_MIN_VOTE_WEIGHT;
    const uint256 mask = RandomScalar();
    const CNoteVoteShare share =
        MakeShare(config, nVoteEpoch, nAmount, mask, 13, RandomScalar());
    PrivacyVNextDigest cTilde = ZeroDigest();
    BOOST_REQUIRE(share.GetCommitment(cTilde));

    CNoteFinalityVote vote = MakeVote(share, hashEpochBlock, cTilde, 0x62);
    vote.nHeight = nVoteHeight;
    vote.hashCurveRoot = hashIV5Root;
    vote.hashNullifierRoot = hashNullifierRoot;
    vote.vchMembership = MakeMembershipRequest(vote.hashCurveRoot, ZeroDigest(), cTilde);
    BOOST_REQUIRE(vote.IsValidBasic());

    // The anchor check has to pass this vote through to the proof checks. Reaching the
    // sigma is what says the anchor was accepted: the sigma here is filler, and nothing
    // between the two can reject anything.
    std::string strError;
    FinalityResult result = FINALITY_RESULT_OK;
    BOOST_CHECK(!tracker.CheckNoteVoteForContext(vote, txdb, &strError, nVoteHeight,
                                                 &result));
    BOOST_CHECK_EQUAL(strError, "note vote sigma does not verify");
    BOOST_CHECK_EQUAL((int)result, (int)FINALITY_RESULT_INVALID);

    // A vote naming any other root is still rejected as unanchored, so the fix widens
    // nothing: it only points the comparison at the tree the proof is actually over.
    CNoteFinalityVote strayAnchor = vote;
    strayAnchor.hashCurveRoot = anchor.hashCurveRoot;
    strayAnchor.vchMembership =
        MakeMembershipRequest(strayAnchor.hashCurveRoot, ZeroDigest(), cTilde);
    BOOST_CHECK(!tracker.CheckNoteVoteForContext(strayAnchor, txdb, &strError,
                                                 nVoteHeight, &result));
    BOOST_CHECK_EQUAL(strError, "note vote not anchored to last finalized epoch root");

    // An anchor epoch that carries no IV5 root at all is this node's missing state, not
    // the vote's fault, so it must not be attributed to the producer.
    CEpochState rootless = anchor;
    rootless.vchVNextRoot.clear();
    BOOST_REQUIRE(txdb.WriteEpochState(nAnchorEpoch, rootless));
    BOOST_CHECK(!tracker.CheckNoteVoteForContext(vote, txdb, &strError, nVoteHeight,
                                                 &result));
    BOOST_CHECK_EQUAL(strError, "note vote anchor epoch carries no IV5 tree root");
    BOOST_CHECK_EQUAL((int)result, (int)FINALITY_RESULT_LOCAL_STATE);
}

// --- F2 certificate schema (increment A) --------------------------------------

BOOST_AUTO_TEST_CASE(note_cert_identity_and_signature_digest_cover_the_note_fields)
{
    ScopedNoteVoteFork fork(0);
    ScopedTallyArgs scopedArgs;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeNoteCommittee(vKeys, 2);

    CFinalityTallyCertificate cert = MakeNoteCert(11, GetEpochBoundaryHeight(11, 0),
                                                  config.committeeSetHash);
    cert.vNoteComplaints.push_back(MakeStubComplaint(11, uint256(0x3101), 0x41));

    const uint256 baseHash = cert.GetHash();
    const uint256 baseDigest = cert.GetSignatureDigest();

    // The complaint set decides which connected votes the certificate may leave out,
    // so it changes the covered set and therefore the tier the certificate can prove.
    // If it were outside the identity a relay could swap it without changing the hash;
    // if it were outside the digest the committee would never have signed the coverage.
    CFinalityTallyCertificate swapped = cert;
    swapped.vNoteComplaints[0] = MakeStubComplaint(11, uint256(0x3102), 0x42);
    BOOST_CHECK(swapped.GetHash() != baseHash);
    BOOST_CHECK(swapped.GetSignatureDigest() != baseDigest);

    CFinalityTallyCertificate stripped = cert;
    stripped.vNoteComplaints.clear();
    BOOST_CHECK(stripped.GetHash() != baseHash);
    BOOST_CHECK(stripped.GetSignatureDigest() != baseDigest);

    CFinalityTallyCertificate retagged = cert;
    retagged.vNoteVoteTags[1] = uint256(0x3999);
    BOOST_CHECK(retagged.GetHash() != baseHash);
    BOOST_CHECK(retagged.GetSignatureDigest() != baseDigest);

    CFinalityTallyCertificate reproved = cert;
    reproved.noteTierProofs.vchWinningCap.assign(64, 0x7f);
    BOOST_CHECK(reproved.GetHash() != baseHash);
    BOOST_CHECK(reproved.GetSignatureDigest() != baseDigest);

    // A v3 certificate's bytes must not move: the note fields enter both hashes only
    // from v4, so every certificate that already exists keeps its identity.
    CFinalityTallyCertificate v3 = cert;
    v3.nVersion = 3;
    v3.vNoteVoteTags.clear();
    v3.vNoteComplaints.clear();
    v3.noteTierProofs = CNoteTallyTierProofs();
    CFinalityTallyCertificate v3WithNoteBytes = v3;
    v3WithNoteBytes.vNoteVoteTags.push_back(uint256(0x3001));
    BOOST_CHECK(v3WithNoteBytes.GetHash() == v3.GetHash());
    BOOST_CHECK(v3WithNoteBytes.GetSignatureDigest() == v3.GetSignatureDigest());

    // The signatures are what authorize a note tally, so the binding has to survive
    // all the way through them: a swapped complaint set must invalidate the signatures
    // the committee produced over the original coverage.
    SignCertByCommittee(cert, vKeys, 2);
    std::string strError;
    BOOST_CHECK(CheckTallyCertificateCommitteeSignatures(
        cert, config.vCommitteePubKeys, config.nThresholdM, config.committeeSetHash,
        &strError));

    CFinalityTallyCertificate forged = cert;
    forged.vNoteComplaints[0] = MakeStubComplaint(11, uint256(0x3102), 0x42);
    BOOST_CHECK(!CheckTallyCertificateCommitteeSignatures(
        forged, config.vCommitteePubKeys, config.nThresholdM, config.committeeSetHash,
        &strError));

    CFinalityTallyCertificate droppedComplaint = cert;
    droppedComplaint.vNoteComplaints.clear();
    BOOST_CHECK(!CheckTallyCertificateCommitteeSignatures(
        droppedComplaint, config.vCommitteePubKeys, config.nThresholdM,
        config.committeeSetHash, &strError));
}

BOOST_AUTO_TEST_CASE(note_cert_version_is_gated_on_the_note_vote_fork)
{
    ScopedTallyArgs scopedArgs;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeNoteCommittee(vKeys, 2);

    const int nEpoch = 12;
    const int nBoundary = GetEpochBoundaryHeight(nEpoch, 0);
    std::string strError;

    {
        // Unconfigured fork: v4 does not exist at any height. This is the state of
        // every public network, so the whole schema stays inert there.
        ScopedNoteVoteFork fork(PRIVACY_VNEXT_HEIGHT_UNSET);
        CFinalityTallyCertificate cert = MakeNoteCert(nEpoch, nBoundary,
                                                      config.committeeSetHash);
        BOOST_CHECK(!cert.IsValidBasic(&strError));
        BOOST_CHECK_EQUAL(strError,
                          "note tally certificate version before note-vote activation");
    }

    {
        // Configured above this certificate's boundary: still rejected.
        ScopedNoteVoteFork fork(nBoundary + 1);
        CFinalityTallyCertificate cert = MakeNoteCert(nEpoch, nBoundary,
                                                      config.committeeSetHash);
        BOOST_CHECK(!cert.IsValidBasic(&strError));
        BOOST_CHECK_EQUAL(strError,
                          "note tally certificate version before note-vote activation");
    }

    {
        ScopedNoteVoteFork fork(nBoundary);
        CFinalityTallyCertificate cert = MakeNoteCert(nEpoch, nBoundary,
                                                      config.committeeSetHash);
        BOOST_CHECK_MESSAGE(cert.IsValidBasic(&strError), strError);

        // Below the fork the note fields must be absent entirely, at every version
        // that could carry them on the wire.
        for (int nVersion = 1; nVersion <= 3; nVersion++)
        {
            CFinalityTallyCertificate older = cert;
            older.nVersion = nVersion;
            older.vSignerIndexes.clear();
            older.vSignerSigs.clear();
            BOOST_CHECK(!older.IsValidBasic(&strError));
            BOOST_CHECK_EQUAL(strError,
                              "pre-v4 tally certificate must not carry note fields");
        }

        // Half a note side is not a note side: a certificate that names tags but
        // proves no tier, or proves a tier over nothing, has a claim nothing backs.
        // These two rules are also what make HasNoteWeight() -- which the gates key
        // on -- true exactly when a note tally is present.
        CFinalityTallyCertificate tagsOnly = cert;
        tagsOnly.noteTierProofs = CNoteTallyTierProofs();
        BOOST_CHECK(!tagsOnly.IsValidBasic(&strError));
        BOOST_CHECK_EQUAL(strError,
                          "tally certificate note tier proof has an unusable length");

        CFinalityTallyCertificate proofsOnly = cert;
        proofsOnly.vNoteVoteTags.clear();
        BOOST_CHECK(!proofsOnly.IsValidBasic(&strError));
        BOOST_CHECK_EQUAL(strError,
                          "tally certificate proves a note tier over no votes");

        // A certificate that only complains still has to prove its tier, so it can
        // never reach the gates with a note side HasNoteWeight() cannot see.
        CFinalityTallyCertificate complaintsOnly = cert;
        complaintsOnly.vNoteVoteTags.clear();
        complaintsOnly.noteTierProofs = CNoteTallyTierProofs();
        complaintsOnly.vNoteComplaints.push_back(
            MakeStubComplaint(nEpoch, uint256(0x3201), 0x52));
        BOOST_CHECK(!complaintsOnly.HasNoteWeight());
        BOOST_CHECK(!complaintsOnly.IsValidBasic(&strError));
        BOOST_CHECK_EQUAL(strError,
                          "tally certificate note tier proof has an unusable length");

        CFinalityTallyCertificate dupTag = cert;
        dupTag.vNoteVoteTags[1] = dupTag.vNoteVoteTags[0];
        BOOST_CHECK(!dupTag.IsValidBasic(&strError));
        BOOST_CHECK_EQUAL(strError,
                          "duplicate or zero tally certificate note vote tag");

        CFinalityTallyCertificate coverAndComplain = cert;
        coverAndComplain.vNoteComplaints.push_back(
            MakeStubComplaint(nEpoch, coverAndComplain.vNoteVoteTags[0], 0x51));
        BOOST_CHECK(!coverAndComplain.IsValidBasic(&strError));
        BOOST_CHECK_EQUAL(strError,
                          "tally certificate both covers and complains of a vote");

        CFinalityTallyCertificate oversizedProof = cert;
        oversizedProof.noteTierProofs.vchActiveCap.assign(
            FINALITY_NOTE_MAX_RANGE_PROOF_BYTES + 1, 0x74);
        BOOST_CHECK(!oversizedProof.IsValidBasic(&strError));
        BOOST_CHECK_EQUAL(strError,
                          "tally certificate note tier proof has an unusable length");

        // The retired secp tally and the note tally are different tallies. One
        // certificate claiming both would have two thresholds and one tier.
        CFinalityTallyCertificate both = cert;
        both.vTallyShareHashes.push_back(uint256(0x8001));
        BOOST_CHECK(!both.IsValidBasic(&strError));
        BOOST_CHECK_EQUAL(
            strError, "tally certificate carries both legacy private and note weight");

        BOOST_CHECK(cert.nVersion == FINALITY_NOTE_CERT_VERSION);
        CFinalityTallyCertificate tooNew = cert;
        tooNew.nVersion = FINALITY_NOTE_CERT_VERSION + 1;
        BOOST_CHECK(!tooNew.IsValidBasic(&strError));
        BOOST_CHECK_EQUAL(strError, "unsupported tally certificate version");
    }
}

BOOST_AUTO_TEST_CASE(note_cert_coverage_carve_out_requires_a_valid_complaint)
{
    ScopedTallyArgs scopedArgs;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeNoteCommittee(vKeys, 2);

    const int nEpoch = 913;
    const int64_t nAmount = 250000;
    const uint256 mask = RandomScalar();
    const CNoteVoteShare honest =
        MakeShare(config, nEpoch, nAmount, mask, 9, RandomScalar());
    const PrivacyVNextDigest cTilde = CommitPoint(Ed25519ScalarFromInt64(nAmount), mask);

    const CNoteVoteShare second =
        MakeShare(config, nEpoch, 111000, RandomScalar(), 4, RandomScalar());

    CNoteTallyPlainShare plainOther;
    BOOST_REQUIRE(DecryptNoteVoteShareForRecipient(second, config, vKeys[0], 0,
                                                   plainOther));
    CNoteVoteShare poisoned = honest;
    TestResealEnvelope(poisoned, vKeys[0], 0, plainOther);

    CNoteFinalityVote voteGood = MakeVote(honest, uint256(0x1111), cTilde, 0x61);
    CNoteFinalityVote voteAlso = MakeVote(second, uint256(0x1111), cTilde, 0x62);
    CNoteFinalityVote votePoisoned = MakeVote(poisoned, uint256(0x1111), cTilde, 0x63);

    std::vector<const CNoteFinalityVote*> vConnected;
    vConnected.push_back(&voteGood);
    vConnected.push_back(&voteAlso);
    vConnected.push_back(&votePoisoned);

    std::string strError;
    std::vector<uint256> vAllTags;
    for (size_t i = 0; i < vConnected.size(); i++)
        vAllTags.push_back(vConnected[i]->GetVoteTag());

    // Covering everything connected needs no complaint at all.
    std::vector<const CNoteFinalityVote*> vCovered;
    BOOST_CHECK_MESSAGE(
        ResolveNoteTallyCoverage(vConnected, vAllTags,
                                 std::vector<CNoteVoteComplaint>(), config, vCovered,
                                 &strError), strError);
    BOOST_CHECK_EQUAL(vCovered.size(), (size_t)3);

    // Dropping a vote with no complaint deflates the denominator, which is the
    // censorship this rule exists to price.
    std::vector<uint256> vShortTags;
    vShortTags.push_back(voteGood.GetVoteTag());
    vShortTags.push_back(voteAlso.GetVoteTag());
    BOOST_CHECK(!ResolveNoteTallyCoverage(vConnected, vShortTags,
                                          std::vector<CNoteVoteComplaint>(), config,
                                          vCovered, &strError));
    BOOST_CHECK_EQUAL(strError,
                      "note tally certificate omits a vote with no valid complaint");

    // With the evidence, the same omission is the intended carve-out.
    CNoteVoteComplaint complaint;
    BOOST_REQUIRE_MESSAGE(BuildNoteVoteComplaint(complaint, votePoisoned, config,
                                                 vKeys[0], 0, &strError), strError);
    std::vector<CNoteVoteComplaint> vComplaints(1, complaint);
    BOOST_CHECK_MESSAGE(ResolveNoteTallyCoverage(vConnected, vShortTags, vComplaints,
                                                 config, vCovered, &strError),
                        strError);
    BOOST_CHECK_EQUAL(vCovered.size(), (size_t)2);

    // A complaint against an honest share must not buy an omission, or one hostile
    // member could drop any voter it disliked.
    CNoteVoteComplaint falseComplaint;
    BOOST_REQUIRE(BuildNoteVoteComplaint(falseComplaint, voteAlso, config, vKeys[0], 0,
                                         &strError));
    std::vector<uint256> vDropHonest;
    vDropHonest.push_back(voteGood.GetVoteTag());
    vDropHonest.push_back(votePoisoned.GetVoteTag());
    std::vector<CNoteVoteComplaint> vFalse(1, falseComplaint);
    BOOST_CHECK(!ResolveNoteTallyCoverage(vConnected, vDropHonest, vFalse, config,
                                          vCovered, &strError));

    // THE TRAP the connect path must avoid. Coverage hard-fails on a repeated tag,
    // and an equivocated tag IS a repeated tag among the raw carried votes -- so
    // feeding the raw set would let one anonymous equivocator make an epoch
    // permanently uncertifiable. CheckTallyCertificate therefore feeds
    // GetCountedEpochNoteVotes, whose view holds one identity per tag by
    // construction and drops equivocated tags entirely.
    CNoteFinalityVote equivocation = votePoisoned;
    equivocation.hashBlock = uint256(0x2222);
    BOOST_CHECK(equivocation.GetVoteTag() == votePoisoned.GetVoteTag());
    std::vector<const CNoteFinalityVote*> vRaw = vConnected;
    vRaw.push_back(&equivocation);
    BOOST_CHECK(!ResolveNoteTallyCoverage(vRaw, vAllTags,
                                          std::vector<CNoteVoteComplaint>(), config,
                                          vCovered, &strError));
    BOOST_CHECK_EQUAL(strError, "note tally coverage saw a repeated vote tag");

    // The counted view GetCountedEpochNoteVotes is built from resolves that same raw
    // set into one identity per tag and drops the equivocated tag entirely, so the
    // set the validator actually receives can never trip the repeated-tag failure.
    std::map<uint256, const CNoteFinalityVote*> mapCounted;
    std::set<uint256> setEquivocated;
    ResolveNoteVoteCounting(vRaw, mapCounted, setEquivocated);
    BOOST_CHECK_EQUAL(setEquivocated.size(), (size_t)1);
    BOOST_CHECK(setEquivocated.count(votePoisoned.GetVoteTag()));
    BOOST_CHECK(!mapCounted.count(votePoisoned.GetVoteTag()));
    BOOST_CHECK_EQUAL(mapCounted.size(), (size_t)2);

    std::vector<const CNoteFinalityVote*> vCountedPtrs;
    std::vector<uint256> vCountedTags;
    for (std::map<uint256, const CNoteFinalityVote*>::const_iterator it =
             mapCounted.begin(); it != mapCounted.end(); ++it)
    {
        vCountedPtrs.push_back(it->second);
        vCountedTags.push_back(it->first);
    }
    BOOST_CHECK_MESSAGE(
        ResolveNoteTallyCoverage(vCountedPtrs, vCountedTags,
                                 std::vector<CNoteVoteComplaint>(), config, vCovered,
                                 &strError), strError);
    BOOST_CHECK_EQUAL(vCovered.size(), (size_t)2);
}

BOOST_AUTO_TEST_CASE(note_weight_is_not_legacy_private_weight)
{
    ScopedNoteVoteFork fork(0);
    ScopedTallyArgs scopedArgs;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeNoteCommittee(vKeys, 2);

    const int nEpoch = 14;
    CFinalityTallyCertificate cert = MakeNoteCert(nEpoch, GetEpochBoundaryHeight(nEpoch, 0),
                                                  config.committeeSetHash);
    cert.vNoteComplaints.push_back(MakeStubComplaint(nEpoch, uint256(0x3101), 0x43));
    SignCertByCommittee(cert, vKeys, 2);

    std::string strError;
    BOOST_CHECK_MESSAGE(cert.IsValidBasic(&strError), strError);

    // The whole point of the separate predicate: HasPrivateWeight() drives the
    // retired-secp disable gates and the Boundary-A miner skip, which must keep
    // rejecting the legacy path while admitting v4.
    BOOST_CHECK(cert.HasNoteWeight());
    BOOST_CHECK(!cert.HasPrivateWeight());

    CFinalityTallyCertificate legacy = cert;
    legacy.vNoteVoteTags.clear();
    legacy.vNoteComplaints.clear();
    legacy.noteTierProofs = CNoteTallyTierProofs();
    legacy.vTallyShareHashes.push_back(uint256(0x8001));
    BOOST_CHECK(!legacy.HasNoteWeight());
    BOOST_CHECK(legacy.HasPrivateWeight());

    // Canonical envelope: schema 2 is the only one that transports a note tally, and
    // it has to carry the signer set too -- a v4 certificate's authorization IS its
    // signatures, since its range proofs cannot be rebuilt byte-for-byte. The
    // canonical carrier has its own signing domain, so the committee signs after the
    // certificate is marked, exactly as a producer would.
    cert.MarkCanonicalEnvelope();
    SignCertByCommittee(cert, vKeys, 2);
    CCanonicalFinalityTallyCertificateEnvelope envelope;
    BOOST_REQUIRE(envelope.FromLogical(cert));
    BOOST_CHECK_EQUAL(envelope.nLogicalVersion,
                      FINALITY_CANONICAL_TALLY_CERT_VERSION_NOTE);
    BOOST_CHECK_EQUAL(envelope.nCertificateVersion, FINALITY_NOTE_CERT_VERSION);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << envelope;
    CCanonicalFinalityTallyCertificateEnvelope decodedEnvelope;
    ss >> decodedEnvelope;
    BOOST_CHECK(ss.empty());

    CFinalityTallyCertificate decoded;
    BOOST_REQUIRE(decodedEnvelope.ToLogical(decoded));
    BOOST_CHECK(decoded.IsCanonicalEnvelope());
    BOOST_CHECK(decoded.HasNoteWeight());
    BOOST_CHECK(decoded.vNoteVoteTags == cert.vNoteVoteTags);
    BOOST_CHECK(decoded.vNoteComplaints.size() == cert.vNoteComplaints.size());
    BOOST_CHECK(decoded.vNoteComplaints[0].GetHash() ==
                cert.vNoteComplaints[0].GetHash());
    BOOST_CHECK(decoded.noteTierProofs.vchTierSlack ==
                cert.noteTierProofs.vchTierSlack);
    BOOST_CHECK(decoded.vSignerIndexes == cert.vSignerIndexes);
    BOOST_CHECK(decoded.vSignerSigs == cert.vSignerSigs);
    // The round trip has to preserve the signed content exactly, or the committee's
    // signatures would not survive being carried in a block.
    BOOST_CHECK(decoded.GetSignatureDigest() == cert.GetSignatureDigest());
    BOOST_CHECK(decoded.GetHash() == cert.GetHash());
    BOOST_CHECK(CheckTallyCertificateCommitteeSignatures(
        decoded, config.vCommitteePubKeys, config.nThresholdM,
        config.committeeSetHash, &strError));

    // Schema 2 is unreadable before the fork, so a pre-fork block cannot carry a
    // well-formed note certificate at all.
    {
        ScopedNoteVoteFork closed(PRIVACY_VNEXT_HEIGHT_UNSET);
        CFinalityTallyCertificate rejected;
        BOOST_CHECK(!decodedEnvelope.ToLogical(rejected));
    }

    // Schema 1 keeps its exact meaning: it refuses a note certificate outright, and
    // refuses to hand one back even if an in-memory envelope claims one.
    CFinalityTallyCertificate transparent = cert;
    transparent.nVersion = 2;
    transparent.vNoteVoteTags.clear();
    transparent.vNoteComplaints.clear();
    transparent.noteTierProofs = CNoteTallyTierProofs();
    transparent.vSignerIndexes.clear();
    transparent.vSignerSigs.clear();
    transparent.MarkCanonicalEnvelope();
    CCanonicalFinalityTallyCertificateEnvelope legacyEnvelope;
    BOOST_REQUIRE(legacyEnvelope.FromLogical(transparent));
    BOOST_CHECK_EQUAL(legacyEnvelope.nLogicalVersion,
                      FINALITY_CANONICAL_TALLY_CERT_VERSION);

    CCanonicalFinalityTallyCertificateEnvelope smuggled = legacyEnvelope;
    smuggled.vNoteVoteTags.push_back(uint256(0x3001));
    CFinalityTallyCertificate smuggledOut;
    BOOST_CHECK(!smuggled.ToLogical(smuggledOut));

    // A schema-2 envelope naming a non-v4 certificate is not a second spelling of a
    // transparent certificate.
    CCanonicalFinalityTallyCertificateEnvelope crossed = decodedEnvelope;
    crossed.nCertificateVersion = 2;
    CFinalityTallyCertificate crossedOut;
    BOOST_CHECK(!crossed.ToLogical(crossedOut));
}

namespace
{

// One voter's whole object: the share the committee sums and the vote that carries it,
// with a C~ that really opens to the amount below.
struct TalliedVote
{
    int64_t nAmount;
    uint256 mask;
    PrivacyVNextDigest cTilde;
    CNoteVoteShare share;
    CNoteFinalityVote vote;
};

TalliedVote MakeTalliedVote(const CFinalityTallyConfig& config, int nEpoch,
                            const uint256& hashBlock, int64_t nAmount, int64_t nReward,
                            unsigned char nTagSeed)
{
    TalliedVote out;
    out.nAmount = nAmount;
    out.mask = RandomScalar();
    out.cTilde = CommitPoint(Ed25519ScalarFromInt64(nAmount), out.mask);
    out.share = MakeShare(config, nEpoch, nAmount, out.mask, nReward, RandomScalar());
    out.vote = MakeVote(out.share, hashBlock, out.cTilde, nTagSeed);
    return out;
}

CNoteTallyAggregatePartial MakePartial(const CNoteTallyCommitteePass& pass,
                                       const CFinalityTallyConfig& config,
                                       const CKey& keyMember, int nMemberIndex,
                                       int nEpoch, const uint256& hashWinner)
{
    CNoteTallyAggregatePartial partial;
    partial.nEpoch = nEpoch;
    partial.committeeSetHash = config.committeeSetHash;
    partial.hashWinner = hashWinner;
    partial.nSourceIndex = nMemberIndex;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(BuildEncryptedNoteTallyAggregatePartial(partial, pass, config,
                                                                  keyMember, &strError),
                          strError);
    return partial;
}

// The producer's own selection step, reproduced here so the tests exercise what the
// automation does rather than a restatement of it: take only the partials that agree on
// the covered set, open both aggregates against the points recomputed from the votes.
bool OpenCoveredAggregates(const std::vector<CNoteTallyAggregatePartial>& vPartials,
                           const std::vector<const CNoteFinalityVote*>& vCovered,
                           const std::vector<uint256>& vCoveredTags,
                           const uint256& hashWinner,
                           const CFinalityTallyConfig& config,
                           const CKey& keyLocal, int nLocalIndex,
                           int64_t& nActiveOut, uint256& activeBlindOut,
                           int64_t& nWinningOut, uint256& winningBlindOut,
                           bool& fHaveRewardOut, std::string& strError)
{
    bool fWinnerHasVotes = false;
    for (size_t i = 0; i < vCovered.size(); i++)
        if (vCovered[i]->hashBlock == hashWinner)
            fWinnerHasVotes = true;

    std::vector<CNoteTallyPlainShare> vActive;
    std::vector<CNoteTallyPlainShare> vWinning;
    std::set<int> setX;
    for (size_t i = 0; i < vPartials.size(); i++)
    {
        if (vPartials[i].vAcceptedTags != vCoveredTags)
            continue;
        CNoteTallyPlainShare active, winning;
        bool fHaveActive = false, fHaveWinning = false;
        if (!DecryptNoteTallyAggregatePartialForRecipient(vPartials[i], config, keyLocal,
                                                          nLocalIndex, active, fHaveActive,
                                                          winning, fHaveWinning))
            continue;
        if (!fHaveActive || fHaveWinning != fWinnerHasVotes)
            continue;
        if (active.nX <= 0 || !setX.insert(active.nX).second)
            continue;
        vActive.push_back(active);
        if (fHaveWinning)
            vWinning.push_back(winning);
    }
    if ((int)vActive.size() < config.nThresholdM)
    {
        strError = "not enough agreeing partials";
        return false;
    }

    PrivacyVNextDigest activePoint = ZeroDigest();
    PrivacyVNextDigest winningPoint = ZeroDigest();
    if (!DeriveNoteTallyAggregates(vCovered, hashWinner, activePoint, winningPoint,
                                   &strError))
        return false;

    int64_t nReward = 0;
    uint256 rewardBlind;
    if (!OpenNoteTallyAggregate(vActive, config.nThresholdM, activePoint, nActiveOut,
                                activeBlindOut, nReward, rewardBlind, &fHaveRewardOut,
                                &strError))
        return false;

    nWinningOut = 0;
    winningBlindOut = uint256(0);
    if (fWinnerHasVotes)
    {
        int64_t nWinReward = 0;
        uint256 winRewardBlind;
        bool fHaveWinReward = false;
        if (!OpenNoteTallyAggregate(vWinning, config.nThresholdM, winningPoint, nWinningOut,
                                    winningBlindOut, nWinReward, winRewardBlind,
                                    &fHaveWinReward, &strError))
            return false;
    }
    return true;
}

std::vector<uint256> SortedTags(const std::vector<uint256>& vTags)
{
    std::vector<uint256> vOut = vTags;
    std::sort(vOut.begin(), vOut.end());
    return vOut;
}

} // namespace

// Increment B's core loop: every member sums its own evaluation of the same covered set,
// seals it to the others, and M of those partials interpolate to an opening of the point
// the validator recomputes from the votes' own commitments.
BOOST_AUTO_TEST_CASE(note_tally_partials_open_the_recomputed_aggregate)
{
    ScopedTallyArgs scopedArgs;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeNoteCommittee(vKeys, 2);

    const int nEpoch = 921;
    const uint256 hashWinner(0x7711);
    const uint256 hashOther(0x7722);

    TalliedVote a = MakeTalliedVote(config, nEpoch, hashWinner, 400000, 7, 0x71);
    TalliedVote b = MakeTalliedVote(config, nEpoch, hashWinner, 250000, 3, 0x72);
    TalliedVote c = MakeTalliedVote(config, nEpoch, hashOther, 150000, 5, 0x73);

    std::vector<const CNoteFinalityVote*> vCovered;
    vCovered.push_back(&a.vote);
    vCovered.push_back(&b.vote);
    vCovered.push_back(&c.vote);
    std::vector<uint256> vCoveredTags;
    for (size_t i = 0; i < vCovered.size(); i++)
        vCoveredTags.push_back(vCovered[i]->GetVoteTag());
    vCoveredTags = SortedTags(vCoveredTags);

    std::vector<CNoteTallyAggregatePartial> vPartials;
    for (size_t i = 0; i < vKeys.size(); i++)
    {
        CNoteTallyCommitteePass pass;
        std::string strError;
        BOOST_REQUIRE_MESSAGE(RunNoteTallyCommitteePass(vCovered, hashWinner, config,
                                                        vKeys[i], (int)i, pass, &strError),
                              strError);
        BOOST_CHECK(pass.vComplaints.empty());
        BOOST_CHECK(pass.fHaveActive);
        BOOST_CHECK(pass.fHaveWinning);
        BOOST_CHECK(SortedTags(pass.vAcceptedTags) == vCoveredTags);
        vPartials.push_back(MakePartial(pass, config, vKeys[i], (int)i, nEpoch, hashWinner));
        BOOST_CHECK(vPartials.back().vAcceptedTags == vCoveredTags);
        std::string strSig;
        BOOST_CHECK_MESSAGE(
            CheckNoteTallyAggregatePartialSignature(vPartials.back(), config, &strSig),
            strSig);
    }

    int64_t nActive = 0, nWinning = 0;
    uint256 activeBlind, winningBlind;
    bool fHaveReward = false;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(OpenCoveredAggregates(vPartials, vCovered, vCoveredTags,
                                                hashWinner, config, vKeys[0], 0, nActive,
                                                activeBlind, nWinning, winningBlind,
                                                fHaveReward, strError), strError);
    BOOST_CHECK_EQUAL(nActive, a.nAmount + b.nAmount + c.nAmount);
    BOOST_CHECK_EQUAL(nWinning, a.nAmount + b.nAmount);
    BOOST_CHECK(fHaveReward);
    BOOST_CHECK(activeBlind ==
                Ed25519ScalarAdd(Ed25519ScalarAdd(a.mask, b.mask), c.mask));

    // The tier is the COMBINED comparison: transparent weights plus these openings.
    // Nothing else is what makes a note vote carry finality weight at all.
    CNoteTallyTierProofs proofs;
    PrivacyVNextDigest entropy;
    entropy.fill(0x5b);
    const int64_t nTransparentActive = 100000;
    const int64_t nTransparentWinning = 100000;
    BOOST_REQUIRE_MESSAGE(
        BuildNoteTallyTierProofs(FINALITY_HARD, nActive, activeBlind, nWinning,
                                 winningBlind, nTransparentActive, nTransparentWinning,
                                 entropy, proofs, &strError), strError);
    PrivacyVNextDigest activePoint = ZeroDigest();
    PrivacyVNextDigest winningPoint = ZeroDigest();
    BOOST_REQUIRE(DeriveNoteTallyAggregates(vCovered, hashWinner, activePoint,
                                            winningPoint, &strError));
    BOOST_CHECK(CheckNoteTallyTierProofs(FINALITY_HARD, activePoint, winningPoint,
                                         nTransparentActive, nTransparentWinning, proofs,
                                         &strError));
    // Without the note weight the same transparent pair is not HARD, so the proof above
    // is exactly the note contribution.
    BOOST_CHECK((nTransparentWinning + nWinning) * 3 >=
                (nTransparentActive + nActive) * 2);
    BOOST_CHECK(!(nTransparentWinning * 3 >= (nTransparentActive + nActive) * 2));

    // MUTATION: an interpolation that does not open the recomputed point must fail, or a
    // poisoned partial would set the epoch's private weight to whatever it liked. Sealing
    // a tampered evaluation is the only way to reach that state, since the VSS check
    // already caught a tampered per-vote share.
    {
        CNoteTallyCommitteePass tampered;
        std::string strPassError;
        BOOST_REQUIRE(RunNoteTallyCommitteePass(vCovered, hashWinner, config, vKeys[1], 1,
                                                tampered, &strPassError));
        tampered.aggregateActive.evalWeight =
            Ed25519ScalarAdd(tampered.aggregateActive.evalWeight,
                             Ed25519ScalarFromUint64(1));
        std::vector<CNoteTallyAggregatePartial> vBad;
        vBad.push_back(vPartials[0]);
        vBad.push_back(MakePartial(tampered, config, vKeys[1], 1, nEpoch, hashWinner));
        int64_t nBadActive = 0, nBadWinning = 0;
        uint256 badActiveBlind, badWinningBlind;
        bool fBadReward = false;
        std::string strBadError;
        BOOST_CHECK(!OpenCoveredAggregates(vBad, vCovered, vCoveredTags, hashWinner,
                                           config, vKeys[0], 0, nBadActive, badActiveBlind,
                                           nBadWinning, badWinningBlind, fBadReward,
                                           strBadError));
        BOOST_CHECK_EQUAL(strBadError,
                          "note tally aggregate does not open the recomputed commitment");
    }

    // MUTATION: the covered set is part of what a partial says. Opening partials that
    // summed three votes against the point of a two-vote set must fail rather than
    // silently under- or over-counting the epoch's private weight.
    {
        std::vector<const CNoteFinalityVote*> vFewer;
        vFewer.push_back(&a.vote);
        vFewer.push_back(&b.vote);
        std::vector<uint256> vFewerTags;
        vFewerTags.push_back(a.vote.GetVoteTag());
        vFewerTags.push_back(b.vote.GetVoteTag());
        vFewerTags = SortedTags(vFewerTags);

        PrivacyVNextDigest fewerActive = ZeroDigest();
        PrivacyVNextDigest fewerWinning = ZeroDigest();
        BOOST_REQUIRE(DeriveNoteTallyAggregates(vFewer, hashWinner, fewerActive,
                                                fewerWinning, &strError));
        std::vector<CNoteTallyPlainShare> vThreeVoteShares;
        for (size_t i = 0; i < 2; i++)
        {
            CNoteTallyPlainShare active, winning;
            bool fA = false, fW = false;
            BOOST_REQUIRE(DecryptNoteTallyAggregatePartialForRecipient(
                vPartials[i], config, vKeys[0], 0, active, fA, winning, fW));
            vThreeVoteShares.push_back(active);
        }
        int64_t nOut = 0, nRewardOut = 0;
        uint256 blindOut, rewardBlindOut;
        bool fHave = false;
        BOOST_CHECK(!OpenNoteTallyAggregate(vThreeVoteShares, config.nThresholdM,
                                            fewerActive, nOut, blindOut, nRewardOut,
                                            rewardBlindOut, &fHave, &strError));
    }
}

// The required deviation from the dead code. Reward shares carry no VSS coefficients, so
// any voter can share a reward that passes every check and interpolates out of range. If
// that failed the opening, one voter could jam the whole epoch's private weight with
// nothing that names it. The weight pair must stay strict.
BOOST_AUTO_TEST_CASE(an_unopenable_reward_does_not_jam_the_note_weight)
{
    ScopedTallyArgs scopedArgs;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeNoteCommittee(vKeys, 2);

    const int nEpoch = 922;
    const uint256 hashWinner(0x7811);

    TalliedVote honest = MakeTalliedVote(config, nEpoch, hashWinner, 300000, 9, 0x81);
    TalliedVote jammer = MakeTalliedVote(config, nEpoch, hashWinner, 500000, 4, 0x82);

    // The jammer keeps the weight opening the coefficients commit to and replaces only
    // the reward evaluation, which nothing checks.
    for (size_t i = 0; i < vKeys.size(); i++)
    {
        CNoteTallyPlainShare plain;
        BOOST_REQUIRE(DecryptNoteVoteShareForRecipient(jammer.share, config, vKeys[i],
                                                       (int)i, plain));
        // One constant at every x is the constant polynomial, so the jammer's reward
        // interpolates to MAX_MONEY and the epoch total lands just outside the range.
        plain.evalReward = Ed25519ScalarFromUint64((uint64_t)MAX_MONEY);
        TestResealEnvelope(jammer.share, vKeys[i], (int)i, plain);
    }
    jammer.vote.share = jammer.share;

    std::string strError;
    // The forged reward is invisible to the per-share check, which is exactly why it
    // cannot be attributed to anyone.
    for (size_t i = 0; i < vKeys.size(); i++)
    {
        CNoteTallyPlainShare plain;
        bool fComplainable = true;
        BOOST_CHECK(DecryptNoteVoteShareForRecipient(jammer.vote.share, config, vKeys[i],
                                                     (int)i, plain, &fComplainable));
        BOOST_CHECK(CheckNoteVoteVssEvaluation(jammer.vote.share, plain, &strError));
    }

    std::vector<const CNoteFinalityVote*> vCovered;
    vCovered.push_back(&honest.vote);
    vCovered.push_back(&jammer.vote);
    std::vector<uint256> vCoveredTags;
    vCoveredTags.push_back(honest.vote.GetVoteTag());
    vCoveredTags.push_back(jammer.vote.GetVoteTag());
    vCoveredTags = SortedTags(vCoveredTags);

    std::vector<CNoteTallyAggregatePartial> vPartials;
    for (size_t i = 0; i < vKeys.size(); i++)
    {
        CNoteTallyCommitteePass pass;
        BOOST_REQUIRE_MESSAGE(RunNoteTallyCommitteePass(vCovered, hashWinner, config,
                                                        vKeys[i], (int)i, pass, &strError),
                              strError);
        BOOST_CHECK(pass.vComplaints.empty());
        vPartials.push_back(MakePartial(pass, config, vKeys[i], (int)i, nEpoch, hashWinner));
    }

    // MUTATION: make the reward opening strict again (drop the fHaveReward carve-out in
    // OpenNoteTallyAggregate) and this returns false -- the jammer has silently killed
    // the epoch's private weight.
    int64_t nActive = 0, nWinning = 0;
    uint256 activeBlind, winningBlind;
    bool fHaveReward = true;
    BOOST_REQUIRE_MESSAGE(OpenCoveredAggregates(vPartials, vCovered, vCoveredTags,
                                                hashWinner, config, vKeys[0], 0, nActive,
                                                activeBlind, nWinning, winningBlind,
                                                fHaveReward, strError), strError);
    BOOST_CHECK(!fHaveReward);
    BOOST_CHECK_EQUAL(nActive, honest.nAmount + jammer.nAmount);
    BOOST_CHECK_EQUAL(nWinning, honest.nAmount + jammer.nAmount);
    BOOST_CHECK(activeBlind == Ed25519ScalarAdd(honest.mask, jammer.mask));

    // And the tier the certificate would claim is still provable, so the jam really is
    // absent rather than merely reported.
    CNoteTallyTierProofs proofs;
    PrivacyVNextDigest entropy;
    entropy.fill(0x2d);
    BOOST_CHECK_MESSAGE(BuildNoteTallyTierProofs(FINALITY_HARD, nActive, activeBlind,
                                                 nWinning, winningBlind, 0, 0, entropy,
                                                 proofs, &strError), strError);

    // The weight pair is NOT tolerated: an aggregate whose weight does not open the
    // recomputed point still fails. MUTATION: relax the expectedPoint check and this
    // passes, which would let a poisoned partial name any private weight it liked.
    {
        std::vector<CNoteTallyPlainShare> vShares;
        for (size_t i = 0; i < 2; i++)
        {
            CNoteTallyPlainShare active, winning;
            bool fA = false, fW = false;
            BOOST_REQUIRE(DecryptNoteTallyAggregatePartialForRecipient(
                vPartials[i], config, vKeys[0], 0, active, fA, winning, fW));
            vShares.push_back(active);
        }
        const PrivacyVNextDigest wrongPoint =
            CommitPoint(Ed25519ScalarFromInt64(nActive + 1), activeBlind);
        int64_t nOut = 0, nRewardOut = 0;
        uint256 blindOut, rewardBlindOut;
        bool fHave = false;
        BOOST_CHECK(!OpenNoteTallyAggregate(vShares, config.nThresholdM, wrongPoint, nOut,
                                            blindOut, nRewardOut, rewardBlindOut, &fHave,
                                            &strError));
        BOOST_CHECK_EQUAL(strError,
                          "note tally aggregate does not open the recomputed commitment");
    }
}

// Convergence. A member that summed over a vote another member can prove unusable re-runs
// against the smaller set; only partials naming the same covered set can be opened
// together, and the equivocation slot must not suppress the re-run.
BOOST_AUTO_TEST_CASE(note_tally_partials_converge_on_a_changed_complaint_set)
{
    ScopedTallyArgs scopedArgs;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeNoteCommittee(vKeys, 2);

    const int nEpoch = 923;
    const uint256 hashWinner(0x7911);

    TalliedVote a = MakeTalliedVote(config, nEpoch, hashWinner, 300000, 6, 0x91);
    TalliedVote b = MakeTalliedVote(config, nEpoch, hashWinner, 200000, 6, 0x92);
    TalliedVote bad = MakeTalliedVote(config, nEpoch, hashWinner, 900000, 6, 0x93);

    // Member 1's envelope alone is poisoned, so member 0's first pass covers all three
    // and member 1's covers two plus the evidence.
    {
        CNoteTallyPlainShare other;
        BOOST_REQUIRE(DecryptNoteVoteShareForRecipient(a.share, config, vKeys[1], 1, other));
        TestResealEnvelope(bad.share, vKeys[1], 1, other);
        bad.vote.share = bad.share;
    }

    std::vector<const CNoteFinalityVote*> vAll;
    vAll.push_back(&a.vote);
    vAll.push_back(&b.vote);
    vAll.push_back(&bad.vote);
    std::vector<uint256> vAllTags;
    for (size_t i = 0; i < vAll.size(); i++)
        vAllTags.push_back(vAll[i]->GetVoteTag());
    vAllTags = SortedTags(vAllTags);

    std::string strError;
    CNoteTallyCommitteePass pass0;
    BOOST_REQUIRE_MESSAGE(RunNoteTallyCommitteePass(vAll, hashWinner, config, vKeys[0], 0,
                                                    pass0, &strError), strError);
    BOOST_CHECK(pass0.vComplaints.empty());
    BOOST_CHECK(SortedTags(pass0.vAcceptedTags) == vAllTags);

    CNoteTallyCommitteePass pass1;
    BOOST_REQUIRE_MESSAGE(RunNoteTallyCommitteePass(vAll, hashWinner, config, vKeys[1], 1,
                                                    pass1, &strError), strError);
    BOOST_CHECK_EQUAL(pass1.vComplaints.size(), (size_t)1);
    BOOST_CHECK(pass1.vComplaints[0].voteTag == bad.vote.GetVoteTag());
    BOOST_CHECK_EQUAL(pass1.vAcceptedTags.size(), (size_t)2);

    const CNoteTallyAggregatePartial partial0Wide =
        MakePartial(pass0, config, vKeys[0], 0, nEpoch, hashWinner);
    const CNoteTallyAggregatePartial partial1 =
        MakePartial(pass1, config, vKeys[1], 1, nEpoch, hashWinner);
    BOOST_CHECK(partial0Wide.vAcceptedTags == vAllTags);
    BOOST_CHECK_EQUAL(partial1.vComplaints.size(), (size_t)1);

    // The complaint rides inside the partial, which is the only reason member 0 ever
    // learns the covered set has to shrink.
    BOOST_CHECK(CheckNoteVoteComplaint(partial1.vComplaints[0], bad.vote, config,
                                       &strError));

    std::vector<const CNoteFinalityVote*> vCovered;
    vCovered.push_back(&a.vote);
    vCovered.push_back(&b.vote);
    std::vector<uint256> vCoveredTags;
    vCoveredTags.push_back(a.vote.GetVoteTag());
    vCoveredTags.push_back(b.vote.GetVoteTag());
    vCoveredTags = SortedTags(vCoveredTags);

    CNoteTallyCommitteePass pass0Narrow;
    BOOST_REQUIRE_MESSAGE(RunNoteTallyCommitteePass(vCovered, hashWinner, config, vKeys[0],
                                                    0, pass0Narrow, &strError), strError);
    BOOST_CHECK(SortedTags(pass0Narrow.vAcceptedTags) == vCoveredTags);
    const CNoteTallyAggregatePartial partial0Narrow =
        MakePartial(pass0Narrow, config, vKeys[0], 0, nEpoch, hashWinner);

    // The re-run is a NEW slot, so a per-source equivocation index that ignored the
    // covered set would suppress it and convergence would never complete. MUTATION: drop
    // vAcceptedTags from GetSourceSlot() and these two collide.
    BOOST_CHECK(partial0Wide.GetSourceSlot() != partial0Narrow.GetSourceSlot());
    // Two different contents for ONE slot is the equivocation the index does catch.
    const CNoteTallyAggregatePartial partial0Again =
        MakePartial(pass0Narrow, config, vKeys[0], 0, nEpoch, hashWinner);
    BOOST_CHECK(partial0Again.GetSourceSlot() == partial0Narrow.GetSourceSlot());
    BOOST_CHECK(partial0Again.GetContentDigest() != partial0Narrow.GetContentDigest());

    std::vector<CNoteTallyAggregatePartial> vPartials;
    vPartials.push_back(partial0Wide);
    vPartials.push_back(partial0Narrow);
    vPartials.push_back(partial1);

    int64_t nActive = 0, nWinning = 0;
    uint256 activeBlind, winningBlind;
    bool fHaveReward = false;
    BOOST_REQUIRE_MESSAGE(OpenCoveredAggregates(vPartials, vCovered, vCoveredTags,
                                                hashWinner, config, vKeys[0], 0, nActive,
                                                activeBlind, nWinning, winningBlind,
                                                fHaveReward, strError), strError);
    BOOST_CHECK_EQUAL(nActive, a.nAmount + b.nAmount);
    BOOST_CHECK(activeBlind == Ed25519ScalarAdd(a.mask, b.mask));

    // MUTATION: select partials without requiring vAcceptedTags equality (mix member 0's
    // wide partial with member 1's narrow one) and the aggregate no longer opens.
    {
        std::vector<CNoteTallyPlainShare> vMixed;
        CNoteTallyPlainShare active, winning;
        bool fA = false, fW = false;
        BOOST_REQUIRE(DecryptNoteTallyAggregatePartialForRecipient(
            partial0Wide, config, vKeys[0], 0, active, fA, winning, fW));
        vMixed.push_back(active);
        BOOST_REQUIRE(DecryptNoteTallyAggregatePartialForRecipient(
            partial1, config, vKeys[0], 0, active, fA, winning, fW));
        vMixed.push_back(active);

        PrivacyVNextDigest coveredPoint = ZeroDigest();
        PrivacyVNextDigest coveredWinning = ZeroDigest();
        BOOST_REQUIRE(DeriveNoteTallyAggregates(vCovered, hashWinner, coveredPoint,
                                                coveredWinning, &strError));
        int64_t nOut = 0, nRewardOut = 0;
        uint256 blindOut, rewardBlindOut;
        bool fHave = false;
        BOOST_CHECK(!OpenNoteTallyAggregate(vMixed, config.nThresholdM, coveredPoint, nOut,
                                            blindOut, nRewardOut, rewardBlindOut, &fHave,
                                            &strError));
    }

    // A partial is signed content: tampering with the covered set it names breaks the
    // source signature, and the sealed evaluations stop opening at all.
    {
        CNoteTallyAggregatePartial forged = partial1;
        forged.vAcceptedTags = vAllTags;
        BOOST_CHECK(!CheckNoteTallyAggregatePartialSignature(forged, config, &strError));
        CNoteTallyPlainShare active, winning;
        bool fA = false, fW = false;
        BOOST_CHECK(!DecryptNoteTallyAggregatePartialForRecipient(forged, config, vKeys[0],
                                                                  0, active, fA, winning,
                                                                  fW));
    }

    // Wire round-trip: what a peer decodes is what the source signed.
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << partial1;
        CNoteTallyAggregatePartial decoded;
        ss >> decoded;
        BOOST_CHECK(ss.empty());
        BOOST_CHECK(decoded.GetHash() == partial1.GetHash());
        BOOST_CHECK(decoded.GetContentDigest() == partial1.GetContentDigest());
        BOOST_CHECK(decoded.GetSourceSlot() == partial1.GetSourceSlot());
        BOOST_CHECK_MESSAGE(decoded.IsValidBasic(&strError), strError);
        BOOST_CHECK(CheckNoteTallyAggregatePartialSignature(decoded, config, &strError));
    }
}

// The trap the whole increment is built around: an equivocated tag is a repeated tag
// among the raw carried votes, and every routine that resolves coverage hard-fails on
// one. Feeding the committee pass the raw set instead of the counted view would let a
// single anonymous equivocator make every epoch permanently uncertifiable.
BOOST_AUTO_TEST_CASE(an_equivocated_note_tag_does_not_jam_the_committee_pass)
{
    ScopedTallyArgs scopedArgs;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeNoteCommittee(vKeys, 2);

    const int nEpoch = 924;
    const uint256 hashWinner(0x7a11);

    TalliedVote a = MakeTalliedVote(config, nEpoch, hashWinner, 300000, 6, 0xa1);
    TalliedVote b = MakeTalliedVote(config, nEpoch, hashWinner, 200000, 6, 0xa2);
    TalliedVote e = MakeTalliedVote(config, nEpoch, hashWinner, 900000, 6, 0xa3);
    CNoteFinalityVote equivocation = e.vote;
    equivocation.hashBlock = uint256(0x7a22);
    BOOST_REQUIRE(equivocation.GetVoteTag() == e.vote.GetVoteTag());

    std::vector<const CNoteFinalityVote*> vRaw;
    vRaw.push_back(&a.vote);
    vRaw.push_back(&b.vote);
    vRaw.push_back(&e.vote);
    vRaw.push_back(&equivocation);

    // MUTATION: feed the producer the raw carried votes and the pass dies here, so no
    // member ever publishes a partial and the epoch can never be certified.
    std::string strError;
    CNoteTallyCommitteePass jammed;
    BOOST_CHECK(!RunNoteTallyCommitteePass(vRaw, hashWinner, config, vKeys[0], 0, jammed,
                                           &strError));
    BOOST_CHECK_EQUAL(strError, "note tally pass saw a repeated vote tag");

    // The counted view drops the equivocated tag entirely and keeps one identity per tag,
    // so the same epoch tallies normally.
    std::map<uint256, const CNoteFinalityVote*> mapCounted;
    std::set<uint256> setEquivocated;
    ResolveNoteVoteCounting(vRaw, mapCounted, setEquivocated);
    BOOST_CHECK_EQUAL(setEquivocated.size(), (size_t)1);
    BOOST_CHECK(setEquivocated.count(e.vote.GetVoteTag()));
    BOOST_CHECK_EQUAL(mapCounted.size(), (size_t)2);

    std::vector<const CNoteFinalityVote*> vCounted;
    std::vector<uint256> vCountedTags;
    for (std::map<uint256, const CNoteFinalityVote*>::const_iterator it = mapCounted.begin();
         it != mapCounted.end(); ++it)
    {
        vCounted.push_back(it->second);
        vCountedTags.push_back(it->first);
    }
    vCountedTags = SortedTags(vCountedTags);

    std::vector<CNoteTallyAggregatePartial> vPartials;
    for (size_t i = 0; i < vKeys.size(); i++)
    {
        CNoteTallyCommitteePass pass;
        BOOST_REQUIRE_MESSAGE(RunNoteTallyCommitteePass(vCounted, hashWinner, config,
                                                        vKeys[i], (int)i, pass, &strError),
                              strError);
        BOOST_CHECK(SortedTags(pass.vAcceptedTags) == vCountedTags);
        vPartials.push_back(MakePartial(pass, config, vKeys[i], (int)i, nEpoch, hashWinner));
    }

    int64_t nActive = 0, nWinning = 0;
    uint256 activeBlind, winningBlind;
    bool fHaveReward = false;
    BOOST_REQUIRE_MESSAGE(OpenCoveredAggregates(vPartials, vCounted, vCountedTags,
                                                hashWinner, config, vKeys[0], 0, nActive,
                                                activeBlind, nWinning, winningBlind,
                                                fHaveReward, strError), strError);
    BOOST_CHECK_EQUAL(nActive, a.nAmount + b.nAmount);

    // The equivocator's weight is excluded rather than counted, so it buys nothing.
    BOOST_CHECK(nActive < a.nAmount + b.nAmount + e.nAmount);

    // And the certificate over the counted set validates end to end, which is what
    // "an equivocated tag must not jam certification" actually means.
    CNoteTallyTierProofs proofs;
    PrivacyVNextDigest entropy;
    entropy.fill(0x66);
    BOOST_REQUIRE_MESSAGE(BuildNoteTallyTierProofs(FINALITY_HARD, nActive, activeBlind,
                                                   nWinning, winningBlind, 0, 0, entropy,
                                                   proofs, &strError), strError);
    BOOST_CHECK_MESSAGE(
        CheckNoteTallyCertificate(FINALITY_HARD, hashWinner, vCounted, vCountedTags,
                                  std::vector<CNoteVoteComplaint>(), config, 0, 0, proofs,
                                  &strError), strError);
}

// A note certificate's whole authorization is its M-of-N signature set: the range proofs
// are entropy-bearing, so no validator can rebuild one byte-for-byte and no two members
// ever produce the same candidate. The collection has to assemble the version the
// committee actually signed.
BOOST_AUTO_TEST_CASE(assembling_a_note_certificate_keeps_the_version_it_was_signed_at)
{
    ScopedNoteVoteFork fork(0);
    ScopedTallyArgs scopedArgs;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeNoteCommittee(vKeys, 2);

    const int nEpoch = 926;
    CFinalityTallyCertificate cert =
        MakeNoteCert(nEpoch, GetEpochBoundaryHeight(nEpoch, 0), config.committeeSetHash);
    // A canonical-envelope certificate carries at least FINALITY_MIN_VOTERS nullifiers.
    cert.vVoteNullifiers.push_back(uint256(0x7002));
    cert.MarkCanonicalEnvelope();
    cert.vSignerIndexes.clear();
    cert.vSignerSigs.clear();
    BOOST_REQUIRE_EQUAL(cert.nVersion, FINALITY_NOTE_CERT_VERSION);

    // Every member signs the candidate as it stands, which is v4.
    const uint256 signedDigest = cert.GetSignatureDigest();
    std::map<uint16_t, std::vector<unsigned char> > collected;
    for (int i = 0; i < 2; i++)
    {
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(vKeys[i].Sign(signedDigest, sig));
        collected[(uint16_t)i] = sig;
    }

    // MUTATION: set cert.nVersion = 3 unconditionally in
    // AssembleCertificateFromSignatures and this fails -- the assembler recomputes a v3
    // digest, every signature is filtered out as invalid, and no note certificate can
    // ever be assembled on any network.
    CFinalityTallyCertificate assembled = cert;
    BOOST_REQUIRE(AssembleCertificateFromSignatures(assembled, collected,
                                                    config.vCommitteePubKeys, 2,
                                                    config.committeeSetHash));
    BOOST_CHECK_EQUAL(assembled.nVersion, FINALITY_NOTE_CERT_VERSION);
    BOOST_CHECK_EQUAL(assembled.vSignerIndexes.size(), (size_t)2);
    BOOST_CHECK(assembled.GetSignatureDigest() == signedDigest);
    BOOST_CHECK(assembled.HasNoteWeight());
    BOOST_CHECK(assembled.IsCanonicalEnvelope());

    std::string strError;
    BOOST_CHECK_MESSAGE(assembled.IsValidBasic(&strError), strError);
    BOOST_CHECK(CheckTallyCertificateCommitteeSignatures(assembled,
                                                          config.vCommitteePubKeys, 2,
                                                          config.committeeSetHash,
                                                          &strError));

    // The v3 floor still applies to everything that predates the signer-set.
    CFinalityTallyCertificate legacy = cert;
    legacy.nVersion = 2;
    legacy.vNoteVoteTags.clear();
    legacy.vNoteComplaints.clear();
    legacy.noteTierProofs = CNoteTallyTierProofs();
    legacy.vSignerIndexes.clear();
    legacy.vSignerSigs.clear();
    CFinalityTallyCertificate promoted = legacy;
    promoted.nVersion = 3;
    const uint256 v3Digest = promoted.GetSignatureDigest();
    std::map<uint16_t, std::vector<unsigned char> > legacySigs;
    for (int i = 0; i < 2; i++)
    {
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(vKeys[i].Sign(v3Digest, sig));
        legacySigs[(uint16_t)i] = sig;
    }
    BOOST_CHECK(AssembleCertificateFromSignatures(legacy, legacySigs,
                                                  config.vCommitteePubKeys, 2,
                                                  config.committeeSetHash));
    BOOST_CHECK_EQUAL(legacy.nVersion, 3);
}

// Determinism. A certificate is checked against the connected chain plus its own bytes,
// never against the producer's relay state, so a producer working from a stale view
// builds an object that is rejected on every node rather than one that splits them.
BOOST_AUTO_TEST_CASE(a_stale_view_note_certificate_is_rejected_not_split)
{
    ScopedTallyArgs scopedArgs;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeNoteCommittee(vKeys, 2);

    const int nEpoch = 925;
    const uint256 hashWinner(0x7b11);

    TalliedVote a = MakeTalliedVote(config, nEpoch, hashWinner, 300000, 6, 0xb1);
    TalliedVote b = MakeTalliedVote(config, nEpoch, hashWinner, 200000, 6, 0xb2);
    TalliedVote late = MakeTalliedVote(config, nEpoch, hashWinner, 400000, 6, 0xb3);

    std::vector<const CNoteFinalityVote*> vStale;
    vStale.push_back(&a.vote);
    vStale.push_back(&b.vote);
    std::vector<uint256> vStaleTags;
    vStaleTags.push_back(a.vote.GetVoteTag());
    vStaleTags.push_back(b.vote.GetVoteTag());
    vStaleTags = SortedTags(vStaleTags);

    std::vector<const CNoteFinalityVote*> vFresh = vStale;
    vFresh.push_back(&late.vote);
    std::vector<uint256> vFreshTags = vStaleTags;
    vFreshTags.push_back(late.vote.GetVoteTag());
    vFreshTags = SortedTags(vFreshTags);

    std::string strError;
    const auto tallyOver = [&](const std::vector<const CNoteFinalityVote*>& vCovered,
                               const std::vector<uint256>& vTags,
                               CNoteTallyTierProofs& proofsOut) {
        std::vector<CNoteTallyAggregatePartial> vPartials;
        for (size_t i = 0; i < vKeys.size(); i++)
        {
            CNoteTallyCommitteePass pass;
            std::string strPassError;
            BOOST_REQUIRE_MESSAGE(RunNoteTallyCommitteePass(vCovered, hashWinner, config,
                                                            vKeys[i], (int)i, pass,
                                                            &strPassError),
                                  strPassError);
            vPartials.push_back(MakePartial(pass, config, vKeys[i], (int)i, nEpoch,
                                            hashWinner));
        }
        int64_t nActive = 0, nWinning = 0;
        uint256 activeBlind, winningBlind;
        bool fHaveReward = false;
        std::string strOpenError;
        BOOST_REQUIRE_MESSAGE(OpenCoveredAggregates(vPartials, vCovered, vTags, hashWinner,
                                                    config, vKeys[0], 0, nActive,
                                                    activeBlind, nWinning, winningBlind,
                                                    fHaveReward, strOpenError),
                              strOpenError);
        PrivacyVNextDigest entropy;
        entropy.fill(0x77);
        std::string strProofError;
        BOOST_REQUIRE_MESSAGE(BuildNoteTallyTierProofs(FINALITY_HARD, nActive, activeBlind,
                                                       nWinning, winningBlind, 0, 0,
                                                       entropy, proofsOut, &strProofError),
                              strProofError);
    };

    CNoteTallyTierProofs staleProofs;
    tallyOver(vStale, vStaleTags, staleProofs);
    CNoteTallyTierProofs freshProofs;
    tallyOver(vFresh, vFreshTags, freshProofs);

    // Against the stale producer's own view the certificate is fine, which is why the
    // producer built it at all.
    BOOST_CHECK_MESSAGE(
        CheckNoteTallyCertificate(FINALITY_HARD, hashWinner, vStale, vStaleTags,
                                  std::vector<CNoteVoteComplaint>(), config, 0, 0,
                                  staleProofs, &strError), strError);

    // Against the connected set the block actually commits to it is rejected, with the
    // same reason on every node: the input is the connected chain, not local state.
    BOOST_CHECK(!CheckNoteTallyCertificate(FINALITY_HARD, hashWinner, vFresh, vStaleTags,
                                           std::vector<CNoteVoteComplaint>(), config, 0, 0,
                                           staleProofs, &strError));
    BOOST_CHECK_EQUAL(strError,
                      "note tally certificate omits a vote with no valid complaint");

    // MUTATION: let the producer omit a connected vote it merely has no partial for (drop
    // the coverage-equality rule) and the stale certificate above becomes valid, which is
    // denominator deflation.
    BOOST_CHECK_MESSAGE(
        CheckNoteTallyCertificate(FINALITY_HARD, hashWinner, vFresh, vFreshTags,
                                  std::vector<CNoteVoteComplaint>(), config, 0, 0,
                                  freshProofs, &strError), strError);

    // Rejection is a pure function of (connected votes, certificate bytes, committee,
    // transparent weights). Repeating both checks gives the same answers, and the tier
    // proofs of one covered set never verify against the other's recomputed points.
    BOOST_CHECK(!CheckNoteTallyCertificate(FINALITY_HARD, hashWinner, vFresh, vStaleTags,
                                           std::vector<CNoteVoteComplaint>(), config, 0, 0,
                                           staleProofs, &strError));
    BOOST_CHECK(!CheckNoteTallyCertificate(FINALITY_HARD, hashWinner, vFresh, vFreshTags,
                                           std::vector<CNoteVoteComplaint>(), config, 0, 0,
                                           staleProofs, &strError));
    // The transparent weights enter the statement points, so a node recomputing a
    // different transparent pair rejects rather than accepting a mixed tally.
    BOOST_CHECK(!CheckNoteTallyCertificate(FINALITY_HARD, hashWinner, vFresh, vFreshTags,
                                           std::vector<CNoteVoteComplaint>(), config, 10, 0,
                                           freshProofs, &strError));
}

// The shape an honest epoch actually takes: every covered note vote names the winner, so
// the active and winning aggregates are the SAME point and the winning cap's statement has
// value 0 and blind 0 -- the identity, which nothing can range-prove. The public G shift
// every statement carries is what makes that case provable at all.
BOOST_AUTO_TEST_CASE(tier_proofs_survive_an_all_on_the_winner_note_tally)
{
    PrivacyVNextDigest entropy;
    entropy.fill(0x11);
    const uint256 blind = RandomScalar();
    const int64_t nWeight = 500000;

    // MUTATION: drop TierStatementShift from either side of DeriveTierStatementPoints or
    // from the prover's blinds and this build fails with "note tally statement could not
    // be range-proved", which is every honest note tally on a single-winner epoch.
    std::string strError;
    CNoteTallyTierProofs proofs;
    BOOST_REQUIRE_MESSAGE(BuildNoteTallyTierProofs(FINALITY_HARD, nWeight, blind, nWeight,
                                                   blind, 0, 0, entropy, proofs,
                                                   &strError), strError);

    const PrivacyVNextDigest point =
        CommitPoint(Ed25519ScalarFromInt64(nWeight), blind);
    BOOST_CHECK(CheckNoteTallyTierProofs(FINALITY_HARD, point, point, 0, 0, proofs,
                                         &strError));

    // The shift is a function of the points, so a substituted point moves the statement
    // and its shift together and still fails to verify.
    const PrivacyVNextDigest other =
        CommitPoint(Ed25519ScalarFromInt64(nWeight + 1), blind);
    BOOST_CHECK(!CheckNoteTallyTierProofs(FINALITY_HARD, other, point, 0, 0, proofs,
                                          &strError));
    BOOST_CHECK(!CheckNoteTallyTierProofs(FINALITY_HARD, point, other, 0, 0, proofs,
                                          &strError));
    BOOST_CHECK(!CheckNoteTallyTierProofs(FINALITY_SOFT, point, point, 0, 0, proofs,
                                          &strError));
    BOOST_CHECK(!CheckNoteTallyTierProofs(FINALITY_HARD, point, point, 1, 0, proofs,
                                          &strError));

    // The shift changes no value: an overclaimed tier is still unprovable.
    CNoteTallyTierProofs overclaimed;
    BOOST_CHECK(!BuildNoteTallyTierProofs(FINALITY_HARD, nWeight, blind, nWeight + 1,
                                          blind, 0, 0, entropy, overclaimed, &strError));
}

BOOST_AUTO_TEST_SUITE_END()
