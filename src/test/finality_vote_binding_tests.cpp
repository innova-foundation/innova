// Tests for private finality vote nullifier binding (HIGH-2 fix): one stake
// note maps to exactly one vote tag per epoch, so hidden finality weight can
// no longer be inflated by re-voting a note under fresh nullifiers. The
// binding proof commits to the (epoch, epoch-block) context, so it cannot be
// replayed at another boundary or grafted onto another stake. Consensus
// enforcement lives in CFinalityTracker::CheckVote / AddVote (finality.cpp).

#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../base58.h"
#include "../finality.h"
#include "../util.h"
#include "../zkproof.h"

#include <algorithm>
#include <map>
#include <limits>
#include <string>
#include <vector>

namespace {

struct Stake
{
    int64_t value;
    std::vector<unsigned char> blind;
    CPedersenCommitment cv;
    std::vector<unsigned char> nfPoint;
};

Stake MakeStake(int64_t value)
{
    Stake s;
    s.value = value;
    BOOST_REQUIRE(GenerateBlindingFactor(s.blind));
    BOOST_REQUIRE(CreatePedersenCommitment(value, s.blind, s.cv));
    BOOST_REQUIRE(ComputeNullifierPoint(s.blind, s.nfPoint));
    BOOST_REQUIRE_EQUAL(s.nfPoint.size(), (size_t)NULLIFIER_POINT_SIZE);
    return s;
}

// Models AddVote's registry: every counted vote is keyed by its nullifier
// tag (mapVoteHashByNullifier), so a second vote carrying the same tag never
// counts twice regardless of its other contents.
struct VoteTagRegistry
{
    std::map<uint256, uint256> mapVoteHashByNullifier;
    bool AcceptVote(const uint256& tag, const uint256& hashVote)
    {
        if (mapVoteHashByNullifier.count(tag))
            return false;
        mapVoteHashByNullifier[tag] = hashVote;
        return true;
    }
};

template <typename T>
std::vector<unsigned char> SerializeEnvelope(const T& value, int nType,
                                             int nVersion)
{
    CDataStream ss(nType, nVersion);
    ss << value;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

CScript TaggedFinalityScript(const unsigned char* pchTag,
                             const std::vector<unsigned char>& vPayload)
{
    std::vector<unsigned char> vData(pchTag, pchTag + 4);
    vData.insert(vData.end(), vPayload.begin(), vPayload.end());
    CScript script;
    script << OP_RETURN << vData;
    return script;
}

CScript NonMinimalTaggedFinalityScript(
    const unsigned char* pchTag,
    const std::vector<unsigned char>& vPayload)
{
    std::vector<unsigned char> vData(pchTag, pchTag + 4);
    vData.insert(vData.end(), vPayload.begin(), vPayload.end());
    CScript script;
    script.push_back(OP_RETURN);
    script.push_back(OP_PUSHDATA4);
    const uint32_t nSize = (uint32_t)vData.size();
    script.push_back((unsigned char)(nSize & 0xff));
    script.push_back((unsigned char)((nSize >> 8) & 0xff));
    script.push_back((unsigned char)((nSize >> 16) & 0xff));
    script.push_back((unsigned char)((nSize >> 24) & 0xff));
    script.insert(script.end(), vData.begin(), vData.end());
    return script;
}

CFinalityVote CanonicalVoteFixture()
{
    CFinalityVote vote;
    vote.nEpoch = 7;
    vote.hashBlock = uint256(0x11);
    vote.nHeight = 120;
    vote.nTime = 123456789;
    vote.nVoteWeight = 5000;
    vote.nReward = 50;
    vote.nullifier = uint256(0x22);
    vote.vStakeProof.push_back(COutPoint(uint256(0x33), 2));
    vote.vchPubKey = std::vector<unsigned char>{0x02, 0xaa, 0xbb};
    vote.vchSig = std::vector<unsigned char>{0x30, 0x01};
    vote.MarkCanonicalEnvelope();
    return vote;
}

CFinalityTallyCertificate CanonicalCertificateFixture()
{
    CFinalityTallyCertificate cert;
    cert.nVersion = 2;
    cert.nEpoch = 9;
    cert.hashBlock = uint256(0x44);
    cert.nHeight = 180;
    cert.nTier = FINALITY_HARD;
    cert.nConsecutiveHardCount = 2;
    cert.hashCurveRoot = uint256(0x55);
    cert.hashNullifierRoot = uint256(0x66);
    cert.committeeSetHash = uint256(0x77);
    cert.nTransparentActiveWeight = 9000;
    cert.nTransparentWinningWeight = 6000;
    cert.nTransparentRewardBudget = 25;
    cert.vVoteNullifiers.push_back(uint256(0x88));
    cert.vVoteNullifiers.push_back(uint256(0x99));
    cert.MarkCanonicalEnvelope();
    return cert;
}

struct ScopedRegtestBoundary
{
    bool fSavedRegTest;
    bool fSavedTestNet;

    ScopedRegtestBoundary()
        : fSavedRegTest(fRegTest), fSavedTestNet(fTestNet)
    {
        fRegTest = true;
        fTestNet = false;
    }

    ~ScopedRegtestBoundary()
    {
        fRegTest = fSavedRegTest;
        fTestNet = fSavedTestNet;
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(finality_vote_binding_tests)

BOOST_AUTO_TEST_CASE(transparent_cold_stake_finality_uses_staker_authority)
{
    CKey stakerKey;
    CKey ownerKey;
    stakerKey.MakeNewKey(true);
    ownerKey.MakeNewKey(true);
    const CKeyID stakerKeyID = stakerKey.GetPubKey().GetID();
    const CKeyID ownerKeyID = ownerKey.GetPubKey().GetID();
    BOOST_REQUIRE(stakerKeyID != ownerKeyID);

    const CScript coldStakeScript =
        GetScriptForColdStaking(stakerKeyID, ownerKeyID);

    // General destination extraction exposes the owner/spend branch.  The
    // finality-specific resolver must instead select only delegated staking
    // authority, otherwise the owner could vote and the staker could not.
    CTxDestination walletDestination;
    BOOST_REQUIRE(ExtractDestination(coldStakeScript, walletDestination));
    CKeyID walletKeyID;
    BOOST_REQUIRE(CBitcoinAddress(walletDestination).GetKeyID(walletKeyID));
    BOOST_CHECK(walletKeyID == ownerKeyID);

    CKeyID finalityKeyID;
    BOOST_REQUIRE(ExtractFinalityStakeKeyID(coldStakeScript,
                                            finalityKeyID));
    BOOST_CHECK(finalityKeyID == stakerKeyID);
    BOOST_CHECK(finalityKeyID != ownerKeyID);

    // Preserve the historical transparent stake-proof behavior for ordinary
    // P2PKH and P2PK scripts.
    BOOST_REQUIRE(ExtractFinalityStakeKeyID(
        GetScriptForDestination(stakerKeyID), finalityKeyID));
    BOOST_CHECK(finalityKeyID == stakerKeyID);

    const CScript payToPubKey =
        CScript() << stakerKey.GetPubKey() << OP_CHECKSIG;
    BOOST_REQUIRE(ExtractFinalityStakeKeyID(payToPubKey, finalityKeyID));
    BOOST_CHECK(finalityKeyID == stakerKeyID);
}

BOOST_AUTO_TEST_CASE(finality_vote_modes_select_the_intended_private_note_kind)
{
    // Explicit NullStake is the non-M-of-N V2 path only.
    BOOST_CHECK(FinalityVoteModeAllowsPrivateNote("nullstake", false));
    BOOST_CHECK(!FinalityVoteModeAllowsPrivateNote("nullstake", true));

    // Explicit NullStake cold is the M-of-N V3 path only.
    BOOST_CHECK(!FinalityVoteModeAllowsPrivateNote("nullstakecold", false));
    BOOST_CHECK(FinalityVoteModeAllowsPrivateNote("nullstakecold", true));

    // Auto may select either available private note kind. Transparent and
    // unknown modes must never enter private proof generation.
    BOOST_CHECK(FinalityVoteModeAllowsPrivateNote("auto", false));
    BOOST_CHECK(FinalityVoteModeAllowsPrivateNote("auto", true));
    BOOST_CHECK(!FinalityVoteModeAllowsPrivateNote("transparent", false));
    BOOST_CHECK(!FinalityVoteModeAllowsPrivateNote("transparent", true));
    BOOST_CHECK(!FinalityVoteModeAllowsPrivateNote("unknown", false));
    BOOST_CHECK(!FinalityVoteModeAllowsPrivateNote("unknown", true));
}

// Tag is deterministic per (note, epoch), distinct across epochs and notes.
BOOST_AUTO_TEST_CASE(vote_tag_is_epoch_scoped_and_note_bound)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    Stake a = MakeStake(2500000000LL);

    BOOST_CHECK(FinalityNullifierTag(a.nfPoint, 4) == FinalityNullifierTag(a.nfPoint, 4));
    BOOST_CHECK(FinalityNullifierTag(a.nfPoint, 4) != FinalityNullifierTag(a.nfPoint, 5));

    Stake b = MakeStake(2500000000LL); // same value, different note
    BOOST_CHECK(FinalityNullifierTag(a.nfPoint, 4) != FinalityNullifierTag(b.nfPoint, 4));
}

// HIGH-2 regression: N vote attempts by one stake note within one epoch
// collapse to exactly one accepted vote. Pre-fix, each attempt could carry a
// fresh attacker-chosen nullifier and claim a fresh vote slot.
BOOST_AUTO_TEST_CASE(one_stake_votes_at_most_once_per_epoch)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    Stake stake = MakeStake(5000000000LL);

    VoteTagRegistry registry;
    int nEpoch = 7;
    int nAccepted = 0;
    for (uint32_t i = 0; i < 8; i++)
    {
        // Distinct vote messages (different hash), identical bound tag.
        uint256 tag = FinalityNullifierTag(stake.nfPoint, nEpoch);
        if (registry.AcceptVote(tag, uint256(0x1000 + i)))
            nAccepted++;
    }
    BOOST_CHECK_MESSAGE(nAccepted == 1,
        "a single stake voted multiple times in one epoch (accepted=" +
        std::to_string(nAccepted) + ", expected 1) -> binding regression");

    // The same stake may vote again in the NEXT epoch.
    uint256 tagNext = FinalityNullifierTag(stake.nfPoint, nEpoch + 1);
    BOOST_CHECK(registry.AcceptVote(tagNext, uint256(0x2000)));
}

// The binding proof commits to the (epoch, epoch-block) context: a proof made
// for one epoch boundary does not verify at any other.
BOOST_AUTO_TEST_CASE(vote_binding_proof_rejects_cross_epoch_replay)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    Stake stake = MakeStake(1230000000LL);

    uint256 hashBlock4 = uint256(0xAAAA);
    uint256 hashBlock5 = uint256(0xBBBB);
    uint256 ctx4 = FinalityNullifierBindContext(4, hashBlock4);

    std::vector<unsigned char> proof;
    BOOST_REQUIRE(CreateNullifierBindingProof(stake.value, stake.blind, stake.cv,
                                              stake.nfPoint, ctx4, proof));
    BOOST_CHECK(VerifyNullifierBindingProof(stake.cv, stake.nfPoint, ctx4, proof, 0 /* below every gate */));

    BOOST_CHECK(!VerifyNullifierBindingProof(stake.cv, stake.nfPoint,
                                             FinalityNullifierBindContext(5, hashBlock5), proof, 0 /* below every gate */));
    BOOST_CHECK(!VerifyNullifierBindingProof(stake.cv, stake.nfPoint,
                                             FinalityNullifierBindContext(5, hashBlock4), proof, 0 /* below every gate */));
    BOOST_CHECK(!VerifyNullifierBindingProof(stake.cv, stake.nfPoint,
                                             FinalityNullifierBindContext(4, hashBlock5), proof, 0 /* below every gate */));
}

// A vote-binding proof for stake A cannot be grafted onto stake B's
// commitment or nullifier point (CheckVote verifies against the vote's own
// stakeWeightCommitment and declared point).
BOOST_AUTO_TEST_CASE(vote_binding_proof_rejects_foreign_stake)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    Stake a = MakeStake(900000000LL);
    Stake b = MakeStake(800000000LL);

    uint256 ctx = FinalityNullifierBindContext(3, uint256(0xCCCC));
    std::vector<unsigned char> proofA;
    BOOST_REQUIRE(CreateNullifierBindingProof(a.value, a.blind, a.cv,
                                              a.nfPoint, ctx, proofA));
    BOOST_REQUIRE(VerifyNullifierBindingProof(a.cv, a.nfPoint, ctx, proofA, 0 /* below every gate */));

    BOOST_CHECK(!VerifyNullifierBindingProof(b.cv, a.nfPoint, ctx, proofA, 0 /* below every gate */));
    BOOST_CHECK(!VerifyNullifierBindingProof(a.cv, b.nfPoint, ctx, proofA, 0 /* below every gate */));
    BOOST_CHECK(!VerifyNullifierBindingProof(b.cv, b.nfPoint, ctx, proofA, 0 /* below every gate */));
}

BOOST_AUTO_TEST_CASE(canonical_vote_envelope_has_golden_context_independent_bytes)
{
    CFinalityVote vote = CanonicalVoteFixture();
    CCanonicalFinalityVoteEnvelope envelope;
    BOOST_REQUIRE(envelope.FromLogical(vote));

    const std::vector<unsigned char> network =
        SerializeEnvelope(envelope, SER_NETWORK, PROTOCOL_VERSION);
    const std::vector<unsigned char> disk =
        SerializeEnvelope(envelope, SER_DISK, 1);
    const std::vector<unsigned char> hashing =
        SerializeEnvelope(envelope, SER_GETHASH, 0);
    BOOST_CHECK(network == disk);
    BOOST_CHECK(network == hashing);

    const std::string golden =
        "0100000007000000"
        "1100000000000000000000000000000000000000000000000000000000000000"
        "78000000"
        "15cd5b0700000000"
        "8813000000000000"
        "3200000000000000"
        "2200000000000000000000000000000000000000000000000000000000000000"
        "01"
        "3300000000000000000000000000000000000000000000000000000000000000"
        "02000000"
        "0302aabb"
        "023001";
    BOOST_CHECK_EQUAL(HexStr(network.begin(), network.end()), golden);

    CFinalityVote decoded;
    BOOST_REQUIRE(envelope.ToLogical(decoded));
    BOOST_CHECK(decoded.IsCanonicalEnvelope());
    BOOST_CHECK_EQUAL(decoded.nProofMode, FINALITY_PROOF_TRANSPARENT);
    BOOST_CHECK_EQUAL(decoded.nEpoch, vote.nEpoch);
    BOOST_CHECK(decoded.hashBlock == vote.hashBlock);
    BOOST_CHECK(decoded.vStakeProof == vote.vStakeProof);

    CFinalityVote legacyView = vote;
    legacyView.fCanonicalEnvelope = false;
    BOOST_CHECK(vote.GetHash() != legacyView.GetHash());
    BOOST_CHECK(vote.GetSignatureHash() != legacyView.GetSignatureHash());
}

BOOST_AUTO_TEST_CASE(canonical_certificate_envelope_is_transparent_and_golden)
{
    CFinalityTallyCertificate cert = CanonicalCertificateFixture();
    CCanonicalFinalityTallyCertificateEnvelope envelope;
    BOOST_REQUIRE(envelope.FromLogical(cert));

    const std::vector<unsigned char> network =
        SerializeEnvelope(envelope, SER_NETWORK, PROTOCOL_VERSION);
    BOOST_CHECK(network == SerializeEnvelope(envelope, SER_DISK, 1));
    BOOST_CHECK(network == SerializeEnvelope(envelope, SER_GETHASH, 0));

    const std::string golden =
        "010000000200000009000000"
        "4400000000000000000000000000000000000000000000000000000000000000"
        "b40000000300000002000000"
        "5500000000000000000000000000000000000000000000000000000000000000"
        "6600000000000000000000000000000000000000000000000000000000000000"
        "7700000000000000000000000000000000000000000000000000000000000000"
        "2823000000000000"
        "7017000000000000"
        "1900000000000000"
        "02"
        "8800000000000000000000000000000000000000000000000000000000000000"
        "9900000000000000000000000000000000000000000000000000000000000000";
    BOOST_CHECK_EQUAL(HexStr(network.begin(), network.end()), golden);

    CFinalityTallyCertificate decoded;
    BOOST_REQUIRE(envelope.ToLogical(decoded));
    BOOST_CHECK(decoded.IsCanonicalEnvelope());
    BOOST_CHECK(!decoded.HasPrivateWeight());
    BOOST_CHECK(decoded.vchAggregateThresholdProof.empty());
    BOOST_CHECK(decoded.vchRewardBudgetProof.empty());
    BOOST_CHECK(decoded.vVoteNullifiers == cert.vVoteNullifiers);

    CFinalityTallyCertificate legacyView = cert;
    legacyView.fCanonicalEnvelope = false;
    BOOST_CHECK(cert.GetHash() != legacyView.GetHash());
    BOOST_CHECK(cert.GetSignatureDigest() != legacyView.GetSignatureDigest());

    CFinalityTallyCertificate privateWeight = cert;
    privateWeight.vTallyShareHashes.push_back(uint256(0xa1));
    BOOST_CHECK(!envelope.FromLogical(privateWeight));
    CFinalityTallyCertificate privateProofBlob = cert;
    privateProofBlob.vchAggregateThresholdProof.push_back(0x01);
    BOOST_CHECK(!envelope.FromLogical(privateProofBlob));
    CFinalityTallyCertificate dependentSignerContent = cert;
    dependentSignerContent.nVersion = 3;
    dependentSignerContent.vSignerIndexes.push_back(0);
    dependentSignerContent.vSignerSigs.push_back(
        std::vector<unsigned char>(70, 0x02));
    BOOST_CHECK(!envelope.FromLogical(dependentSignerContent));
}

BOOST_AUTO_TEST_CASE(canonical_finality_scripts_are_exact_and_height_selected)
{
    ScopedRegtestBoundary networkFlags;
    BOOST_REQUIRE(IsBoundaryAConfigured());
    const int nBoundaryA = FORK_HEIGHT_BOUNDARY_A;
    BOOST_REQUIRE(nBoundaryA > 0);

    CFinalityVote canonicalVote = CanonicalVoteFixture();
    CFinalityVote legacyVote = canonicalVote;
    legacyVote.fCanonicalEnvelope = false;

    CScript legacyVoteScript = BuildFinalityVoteScript(legacyVote);
    CScript selectedLegacyVote;
    BOOST_REQUIRE(BuildFinalityVoteScriptForHeight(
        legacyVote, nBoundaryA - 1, selectedLegacyVote));
    BOOST_CHECK(selectedLegacyVote == legacyVoteScript);

    CScript canonicalVoteScript;
    BOOST_REQUIRE(BuildFinalityVoteScriptForHeight(
        canonicalVote, nBoundaryA, canonicalVoteScript));
    BOOST_CHECK(canonicalVoteScript != legacyVoteScript);
    BOOST_CHECK_EQUAL(std::string(GetFinalityVoteCommandForHeight(nBoundaryA - 1)),
                      "fvote");
    BOOST_CHECK_EQUAL(std::string(GetFinalityVoteCommandForHeight(nBoundaryA)),
                      FINALITY_CANONICAL_VOTE_COMMAND);

    CFinalityVote decodedVote;
    BOOST_CHECK_EQUAL(ExtractFinalityVoteForHeight(
                          legacyVoteScript, nBoundaryA, decodedVote),
                      FINALITY_ENVELOPE_LEGACY_AFTER_BOUNDARY);
    BOOST_CHECK_EQUAL(ExtractFinalityVoteForHeight(
                          TaggedFinalityScript(FINALITY_VOTE_TAG,
                                               std::vector<unsigned char>()),
                          nBoundaryA, decodedVote),
                      FINALITY_ENVELOPE_LEGACY_AFTER_BOUNDARY);
    BOOST_CHECK_EQUAL(ExtractFinalityVoteForHeight(
                          canonicalVoteScript, nBoundaryA - 1, decodedVote),
                      FINALITY_ENVELOPE_NO_MATCH);
    BOOST_CHECK_EQUAL(ExtractFinalityVoteForHeight(
                          canonicalVoteScript, nBoundaryA, decodedVote),
                      FINALITY_ENVELOPE_VALID);
    BOOST_CHECK(decodedVote.IsCanonicalEnvelope());

    CBlock canonicalBlock;
    canonicalBlock.vtx.push_back(CTransaction());
    canonicalBlock.vtx[0].vout.push_back(CTxOut(0, canonicalVoteScript));
    std::vector<CFinalityVote> blockVotes;
    FinalityEnvelopeDecodeResult blockFailure = FINALITY_ENVELOPE_INVALID;
    BOOST_REQUIRE(ExtractFinalityVotesFromBlockForHeight(
        canonicalBlock, nBoundaryA, blockVotes, &blockFailure));
    BOOST_REQUIRE_EQUAL(blockVotes.size(), 1U);
    BOOST_CHECK(blockVotes[0].IsCanonicalEnvelope());

    CBlock legacyBlock;
    legacyBlock.vtx.push_back(CTransaction());
    legacyBlock.vtx[0].vout.push_back(CTxOut(0, legacyVoteScript));
    BOOST_CHECK(!ExtractFinalityVotesFromBlockForHeight(
        legacyBlock, nBoundaryA, blockVotes, &blockFailure));
    BOOST_CHECK_EQUAL(blockFailure,
                      FINALITY_ENVELOPE_LEGACY_AFTER_BOUNDARY);
    BOOST_CHECK(blockVotes.empty());

    // Golden historical behavior: IFCV was unknown data, and an IFVT tag with
    // an undecodable payload was ignored rather than invalidating the block.
    CBlock historicalIgnoredVoteBlock;
    historicalIgnoredVoteBlock.vtx.push_back(CTransaction());
    historicalIgnoredVoteBlock.vtx[0].vout.push_back(
        CTxOut(0, canonicalVoteScript));
    historicalIgnoredVoteBlock.vtx[0].vout.push_back(CTxOut(
        0, TaggedFinalityScript(FINALITY_VOTE_TAG,
                                std::vector<unsigned char>())));
    BOOST_REQUIRE(ExtractFinalityVotesFromBlockForHeight(
        historicalIgnoredVoteBlock, nBoundaryA - 1, blockVotes,
        &blockFailure));
    BOOST_CHECK(blockVotes.empty());

    CCanonicalFinalityVoteEnvelope voteEnvelope;
    BOOST_REQUIRE(voteEnvelope.FromLogical(canonicalVote));
    std::vector<unsigned char> voteBytes =
        SerializeEnvelope(voteEnvelope, SER_NETWORK, PROTOCOL_VERSION);
    std::vector<unsigned char> trailingVoteBytes = voteBytes;
    trailingVoteBytes.push_back(0xa5);
    BOOST_CHECK(!ExtractCanonicalFinalityVote(
        TaggedFinalityScript(FINALITY_CANONICAL_VOTE_TAG, trailingVoteBytes),
        decodedVote));
    std::vector<unsigned char> tamperedVoteBytes = voteBytes;
    tamperedVoteBytes[0] = 2;
    BOOST_CHECK(!ExtractCanonicalFinalityVote(
        TaggedFinalityScript(FINALITY_CANONICAL_VOTE_TAG, tamperedVoteBytes),
        decodedVote));
    BOOST_CHECK(!ExtractCanonicalFinalityVote(
        TaggedFinalityScript(FINALITY_TALLY_CERT_TAG, voteBytes), decodedVote));
    CScript nonMinimalVote = NonMinimalTaggedFinalityScript(
        FINALITY_CANONICAL_VOTE_TAG, voteBytes);
    BOOST_CHECK(!ExtractCanonicalFinalityVote(nonMinimalVote, decodedVote));
    BOOST_CHECK_EQUAL(ExtractFinalityVoteForHeight(
                          nonMinimalVote, nBoundaryA, decodedVote),
                      FINALITY_ENVELOPE_INVALID);

    // Historical decoder behavior remains unchanged, including its accepted
    // trailing bytes; only the height-aware post-A API rejects the legacy tag.
    CDataStream legacyVoteBytes(SER_NETWORK, PROTOCOL_VERSION);
    legacyVoteBytes << legacyVote;
    std::vector<unsigned char> legacyTrailing(legacyVoteBytes.begin(),
                                               legacyVoteBytes.end());
    legacyTrailing.push_back(0xa5);
    CFinalityVote historicalVote;
    historicalVote.MarkCanonicalEnvelope();
    BOOST_CHECK(ExtractFinalityVote(
        TaggedFinalityScript(FINALITY_VOTE_TAG, legacyTrailing), historicalVote));
    BOOST_CHECK(!historicalVote.IsCanonicalEnvelope());

    CFinalityTallyCertificate canonicalCert = CanonicalCertificateFixture();
    CFinalityTallyCertificate legacyCert = canonicalCert;
    legacyCert.fCanonicalEnvelope = false;
    CScript legacyCertScript = BuildFinalityTallyCertificateScript(legacyCert);
    CScript selectedLegacyCert;
    BOOST_REQUIRE(BuildFinalityTallyCertificateScriptForHeight(
        legacyCert, nBoundaryA - 1, selectedLegacyCert));
    BOOST_CHECK(selectedLegacyCert == legacyCertScript);
    CScript canonicalCertScript;
    BOOST_REQUIRE(BuildFinalityTallyCertificateScriptForHeight(
        canonicalCert, nBoundaryA, canonicalCertScript));
    BOOST_CHECK_EQUAL(std::string(
                          GetFinalityTallyCertificateCommandForHeight(nBoundaryA)),
                      FINALITY_CANONICAL_TALLY_CERT_COMMAND);
    CFinalityTallyCertificate decodedCert;
    BOOST_CHECK_EQUAL(ExtractFinalityTallyCertificateForHeight(
                          legacyCertScript, nBoundaryA, decodedCert),
                      FINALITY_ENVELOPE_LEGACY_AFTER_BOUNDARY);
    BOOST_CHECK_EQUAL(ExtractFinalityTallyCertificateForHeight(
                          canonicalCertScript, nBoundaryA, decodedCert),
                      FINALITY_ENVELOPE_VALID);
    BOOST_CHECK(decodedCert.IsCanonicalEnvelope());

    CBlock canonicalCertBlock;
    canonicalCertBlock.vtx.push_back(CTransaction());
    canonicalCertBlock.vtx[0].vout.push_back(
        CTxOut(0, canonicalCertScript));
    std::vector<CFinalityTallyCertificate> blockCerts;
    BOOST_REQUIRE(ExtractFinalityTallyCertificatesFromBlockForHeight(
        canonicalCertBlock, nBoundaryA, blockCerts, &blockFailure));
    BOOST_REQUIRE_EQUAL(blockCerts.size(), 1U);
    BOOST_CHECK(blockCerts[0].IsCanonicalEnvelope());

    CBlock legacyCertBlock;
    legacyCertBlock.vtx.push_back(CTransaction());
    legacyCertBlock.vtx[0].vout.push_back(CTxOut(0, legacyCertScript));
    BOOST_CHECK(!ExtractFinalityTallyCertificatesFromBlockForHeight(
        legacyCertBlock, nBoundaryA, blockCerts, &blockFailure));
    BOOST_CHECK_EQUAL(blockFailure,
                      FINALITY_ENVELOPE_LEGACY_AFTER_BOUNDARY);
    BOOST_CHECK(blockCerts.empty());

    CBlock historicalIgnoredCertBlock;
    historicalIgnoredCertBlock.vtx.push_back(CTransaction());
    historicalIgnoredCertBlock.vtx[0].vout.push_back(
        CTxOut(0, canonicalCertScript));
    historicalIgnoredCertBlock.vtx[0].vout.push_back(CTxOut(
        0, TaggedFinalityScript(FINALITY_TALLY_CERT_TAG,
                                std::vector<unsigned char>())));
    BOOST_REQUIRE(ExtractFinalityTallyCertificatesFromBlockForHeight(
        historicalIgnoredCertBlock, nBoundaryA - 1, blockCerts,
        &blockFailure));
    BOOST_CHECK(blockCerts.empty());

    CCanonicalFinalityTallyCertificateEnvelope certEnvelope;
    BOOST_REQUIRE(certEnvelope.FromLogical(canonicalCert));
    std::vector<unsigned char> certBytes =
        SerializeEnvelope(certEnvelope, SER_NETWORK, PROTOCOL_VERSION);
    std::vector<unsigned char> trailingCertBytes = certBytes;
    trailingCertBytes.push_back(0xa5);
    BOOST_CHECK(!ExtractCanonicalFinalityTallyCertificate(
        TaggedFinalityScript(FINALITY_CANONICAL_TALLY_CERT_TAG,
                             trailingCertBytes),
        decodedCert));
    std::vector<unsigned char> tamperedCertBytes = certBytes;
    tamperedCertBytes[0] = 2;
    BOOST_CHECK(!ExtractCanonicalFinalityTallyCertificate(
        TaggedFinalityScript(FINALITY_CANONICAL_TALLY_CERT_TAG,
                             tamperedCertBytes),
        decodedCert));
    BOOST_CHECK(!ExtractCanonicalFinalityTallyCertificate(
        TaggedFinalityScript(FINALITY_VOTE_TAG, certBytes), decodedCert));
    BOOST_CHECK(!ExtractCanonicalFinalityTallyCertificate(
        NonMinimalTaggedFinalityScript(FINALITY_CANONICAL_TALLY_CERT_TAG,
                                       certBytes),
        decodedCert));

    CFinalityTallyCertificate privateCert = canonicalCert;
    privateCert.vTallyShareHashes.push_back(uint256(0xb1));
    CScript rejected;
    BOOST_CHECK(!BuildFinalityTallyCertificateScriptForHeight(
        privateCert, nBoundaryA, rejected));

    CFinalityVote privateVote = canonicalVote;
    privateVote.nProofMode = FINALITY_PROOF_NULLSTAKE_V2;
    BOOST_CHECK(!BuildFinalityVoteScriptForHeight(
        privateVote, nBoundaryA, rejected));
}

BOOST_AUTO_TEST_CASE(canonical_finality_envelope_bounds_are_exact)
{
    CCanonicalFinalityVoteEnvelope vote;
    vote.vStakeProof.assign(FINALITY_MAX_STAKE_PROOFS, COutPoint());
    CDataStream voteAtMax(SER_NETWORK, PROTOCOL_VERSION);
    voteAtMax << vote;
    CCanonicalFinalityVoteEnvelope decodedVote;
    BOOST_CHECK_NO_THROW(voteAtMax >> decodedVote);
    BOOST_CHECK(voteAtMax.empty());

    vote.vStakeProof.push_back(COutPoint());
    CDataStream voteTooLarge(SER_NETWORK, PROTOCOL_VERSION);
    voteTooLarge << vote;
    BOOST_CHECK_THROW(voteTooLarge >> decodedVote, std::ios_base::failure);

    CCanonicalFinalityTallyCertificateEnvelope cert;
    cert.vVoteNullifiers.assign(FINALITY_CANONICAL_CERT_MAX_NULLIFIERS,
                                uint256(1));
    CDataStream certAtMax(SER_NETWORK, PROTOCOL_VERSION);
    certAtMax << cert;
    CCanonicalFinalityTallyCertificateEnvelope decodedCert;
    BOOST_CHECK_NO_THROW(certAtMax >> decodedCert);
    BOOST_CHECK(certAtMax.empty());

    CCanonicalFinalityTallyCertificateEnvelope tooManyNullifiers = cert;
    tooManyNullifiers.vVoteNullifiers.push_back(uint256(2));
    CDataStream certTooManyNullifiers(SER_NETWORK, PROTOCOL_VERSION);
    certTooManyNullifiers << tooManyNullifiers;
    BOOST_CHECK_THROW(certTooManyNullifiers >> decodedCert,
                      std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(legacy_pre_boundary_complete_oversize_is_recognized_invalid)
{
    ScopedRegtestBoundary boundary;
    const int nHistoricalHeight = FORK_HEIGHT_BOUNDARY_A - 1;
    BOOST_REQUIRE(nHistoricalHeight >= 0);

    CFinalityVote oversizedVote;
    oversizedVote.vStakeProof.assign(FINALITY_MAX_STAKE_PROOFS + 1,
                                      COutPoint(uint256(0xA101), 0));
    const std::vector<unsigned char> voteBytes = SerializeEnvelope(
        oversizedVote, SER_NETWORK, PROTOCOL_VERSION);
    const CScript voteScript = TaggedFinalityScript(
        FINALITY_VOTE_TAG, voteBytes);
    CFinalityVote decodedVote;
    BOOST_CHECK_EQUAL(ExtractFinalityVoteForHeight(
                          voteScript, nHistoricalHeight, decodedVote),
                      FINALITY_ENVELOPE_VALID);
    BOOST_CHECK_EQUAL(decodedVote.vStakeProof.size(),
                      (size_t)FINALITY_MAX_STAKE_PROOFS + 1);
    BOOST_CHECK(!decodedVote.IsValid());
    BOOST_CHECK_EQUAL(ExtractFinalityVoteForHeight(
                          voteScript, FORK_HEIGHT_BOUNDARY_A, decodedVote),
                      FINALITY_ENVELOPE_LEGACY_AFTER_BOUNDARY);

    std::vector<unsigned char> truncatedVoteBytes = voteBytes;
    BOOST_REQUIRE(!truncatedVoteBytes.empty());
    truncatedVoteBytes.pop_back();
    BOOST_CHECK_EQUAL(ExtractFinalityVoteForHeight(
                          TaggedFinalityScript(FINALITY_VOTE_TAG,
                                               truncatedVoteBytes),
                          nHistoricalHeight, decodedVote),
                      FINALITY_ENVELOPE_NO_MATCH);

    CFinalityTallyCertificate oversizedCert;
    oversizedCert.nVersion = 3;
    oversizedCert.nEpoch = 1;
    oversizedCert.hashBlock = uint256(0xA102);
    oversizedCert.nHeight = 60;
    oversizedCert.nTier = FINALITY_HARD;
    oversizedCert.nTransparentActiveWeight = 2 * COIN;
    oversizedCert.nTransparentWinningWeight = 2 * COIN;
    oversizedCert.vVoteNullifiers.push_back(uint256(0xA103));
    oversizedCert.vVoteNullifiers.push_back(uint256(0xA104));
    oversizedCert.vSignerIndexes.resize(FINALITY_MAX_TALLY_COMMITTEE + 1);
    oversizedCert.vSignerSigs.assign(
        FINALITY_MAX_TALLY_COMMITTEE + 1,
        std::vector<unsigned char>(1, 0x30));
    const std::vector<unsigned char> certBytes = SerializeEnvelope(
        oversizedCert, SER_NETWORK, PROTOCOL_VERSION);
    const CScript certScript = TaggedFinalityScript(
        FINALITY_TALLY_CERT_TAG, certBytes);
    CFinalityTallyCertificate decodedCert;
    BOOST_CHECK_EQUAL(ExtractFinalityTallyCertificateForHeight(
                          certScript, nHistoricalHeight, decodedCert),
                      FINALITY_ENVELOPE_VALID);
    BOOST_CHECK_EQUAL(decodedCert.vSignerIndexes.size(),
                      (size_t)FINALITY_MAX_TALLY_COMMITTEE + 1);
    BOOST_CHECK(!decodedCert.IsValidBasic());

    std::vector<unsigned char> truncatedCertBytes = certBytes;
    BOOST_REQUIRE(!truncatedCertBytes.empty());
    truncatedCertBytes.pop_back();
    BOOST_CHECK_EQUAL(ExtractFinalityTallyCertificateForHeight(
                          TaggedFinalityScript(FINALITY_TALLY_CERT_TAG,
                                               truncatedCertBytes),
                          nHistoricalHeight, decodedCert),
                      FINALITY_ENVELOPE_NO_MATCH);
}

BOOST_AUTO_TEST_CASE(canonical_vote_signature_cannot_be_legacy_transcoded)
{
    CKey key;
    key.MakeNewKey(true);

    CFinalityVote canonical = CanonicalVoteFixture();
    canonical.vchPubKey.clear();
    canonical.vchSig.clear();
    BOOST_REQUIRE(canonical.Sign(key));
    BOOST_REQUIRE(canonical.CheckSignature());
    const uint256 canonicalHash = canonical.GetHash();

    CScript script;
    BOOST_REQUIRE(BuildCanonicalFinalityVoteScript(canonical, script));
    CFinalityVote decoded;
    BOOST_REQUIRE(ExtractCanonicalFinalityVote(script, decoded));
    BOOST_CHECK(decoded.IsCanonicalEnvelope());
    BOOST_CHECK(decoded.CheckSignature());
    BOOST_CHECK(decoded.GetHash() == canonicalHash);

    CFinalityVote legacyInterpretation = decoded;
    legacyInterpretation.fCanonicalEnvelope = false;
    BOOST_CHECK(!legacyInterpretation.CheckSignature());
    BOOST_CHECK(legacyInterpretation.GetHash() != canonicalHash);

    CFinalityVote legacy = CanonicalVoteFixture();
    legacy.fCanonicalEnvelope = false;
    legacy.vchPubKey.clear();
    legacy.vchSig.clear();
    BOOST_REQUIRE(legacy.Sign(key));
    BOOST_REQUIRE(legacy.CheckSignature());
    const uint256 legacyHash = legacy.GetHash();
    legacy.MarkCanonicalEnvelope();
    BOOST_CHECK(!legacy.CheckSignature());
    BOOST_CHECK(legacy.GetHash() != legacyHash);
}

BOOST_AUTO_TEST_CASE(canonical_p2p_commands_switch_at_boundary_a_minus_one)
{
    ScopedRegtestBoundary boundary;
    const int nBoundaryA = FORK_HEIGHT_BOUNDARY_A;
    BOOST_REQUIRE(nBoundaryA > 0);

    BOOST_CHECK(!UseCanonicalFinalityTrafficForTip(nBoundaryA - 2));
    BOOST_CHECK(UseCanonicalFinalityTrafficForTip(nBoundaryA - 1));
    BOOST_CHECK(UseCanonicalFinalityTrafficForTip(nBoundaryA));
    BOOST_CHECK(UseCanonicalFinalityTrafficForTip(
        std::numeric_limits<int>::max()));

    const int nEpoch = GetEpochForHeight(nBoundaryA);
    const int nEpochBoundary = GetEpochBoundaryHeight(nEpoch, nBoundaryA);
    BOOST_CHECK(!IsFinalityVoteWindowClosedForTip(
        nEpoch, nEpochBoundary + FINALITY_VOTE_INCLUSION_WINDOW - 2));
    BOOST_CHECK(IsFinalityVoteWindowClosedForTip(
        nEpoch, nEpochBoundary + FINALITY_VOTE_INCLUSION_WINDOW - 1));
}

BOOST_AUTO_TEST_CASE(canonical_transparent_certificate_production_is_deterministic)
{
    BOOST_REQUIRE(FINALITY_MIN_VOTERS >= 1);
    std::vector<CFinalityVote> votes;
    int64_t nExpectedReward = 0;
    const size_t nWinningVotes =
        ((size_t)FINALITY_MIN_VOTERS * 2 + 2) / 3;
    for (int i = 0; i < FINALITY_MIN_VOTERS; ++i)
    {
        CFinalityVote vote;
        vote.nEpoch = 12;
        vote.nHeight = 3600;
        vote.hashBlock = (size_t)i < nWinningVotes
            ? uint256(0x1201) : uint256(0x1202);
        vote.nVoteWeight = COIN;
        vote.nReward = i + 1;
        vote.nullifier = uint256(0x1300 + FINALITY_MIN_VOTERS - i);
        votes.push_back(vote);
        nExpectedReward += vote.nReward;
    }

    CFinalityTallyCertificate cert;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(BuildCanonicalTransparentFinalityCertificate(
                              votes, cert, &strError), strError);
    BOOST_CHECK(cert.IsCanonicalEnvelope());
    BOOST_CHECK_EQUAL(cert.nVersion, 2);
    BOOST_CHECK_EQUAL(cert.nEpoch, 12);
    BOOST_CHECK(cert.hashBlock == uint256(0x1201));
    BOOST_CHECK_EQUAL(cert.nHeight, 3600);
    BOOST_CHECK_EQUAL(cert.nTier, FINALITY_HARD);
    BOOST_CHECK_EQUAL(cert.nTransparentActiveWeight,
                      (int64_t)FINALITY_MIN_VOTERS * COIN);
    BOOST_CHECK_EQUAL(cert.nTransparentWinningWeight,
                      (int64_t)nWinningVotes * COIN);
    BOOST_CHECK_EQUAL(cert.nTransparentRewardBudget, nExpectedReward);
    BOOST_REQUIRE_EQUAL(cert.vVoteNullifiers.size(), votes.size());
    BOOST_CHECK(std::is_sorted(cert.vVoteNullifiers.begin(),
                               cert.vVoteNullifiers.end()));

    std::reverse(votes.begin(), votes.end());
    CFinalityTallyCertificate reversed;
    BOOST_REQUIRE_MESSAGE(BuildCanonicalTransparentFinalityCertificate(
                              votes, reversed, &strError), strError);
    BOOST_CHECK(reversed.GetHash() == cert.GetHash());
    BOOST_CHECK(reversed.GetSignatureDigest() == cert.GetSignatureDigest());

    std::vector<CFinalityVote> tooFew(
        votes.begin(), votes.begin() + FINALITY_MIN_VOTERS - 1);
    BOOST_CHECK(!BuildCanonicalTransparentFinalityCertificate(
        tooFew, reversed, &strError));

    votes[0].nProofMode = FINALITY_PROOF_NULLSTAKE_V2;
    BOOST_CHECK(!BuildCanonicalTransparentFinalityCertificate(
        votes, reversed, &strError));

    std::vector<CFinalityVote> atCapacity;
    atCapacity.reserve(FINALITY_CANONICAL_CERT_MAX_NULLIFIERS + 1);
    for (unsigned int i = 0;
         i < FINALITY_CANONICAL_CERT_MAX_NULLIFIERS + 1; ++i)
    {
        CFinalityVote vote;
        vote.nEpoch = 13;
        vote.nHeight = 3900;
        vote.hashBlock = uint256(0x1401);
        vote.nVoteWeight = COIN;
        vote.nReward = 1;
        vote.nullifier = uint256(0x1500 + i);
        atCapacity.push_back(vote);
    }
    std::vector<CFinalityVote> oneTooMany = atCapacity;
    atCapacity.resize(FINALITY_CANONICAL_CERT_MAX_NULLIFIERS);
    BOOST_REQUIRE_MESSAGE(BuildCanonicalTransparentFinalityCertificate(
                              atCapacity, reversed, &strError), strError);
    BOOST_CHECK_EQUAL(reversed.vVoteNullifiers.size(),
                      FINALITY_CANONICAL_CERT_MAX_NULLIFIERS);
    BOOST_CHECK(!BuildCanonicalTransparentFinalityCertificate(
        oneTooMany, reversed, &strError));
}

BOOST_AUTO_TEST_CASE(canonical_epoch_vote_capacity_is_exact_across_blocks)
{
    ScopedRegtestBoundary boundary;
    const int nHeight = FORK_HEIGHT_BOUNDARY_A;
    const int nEpoch = GetEpochForHeight(nHeight);
    CFinalityTracker tracker;
    std::vector<CFinalityVote> connected;
    for (unsigned int i = 0;
         i < FINALITY_CANONICAL_CERT_MAX_NULLIFIERS; ++i)
    {
        CFinalityVote vote;
        vote.nProofMode = FINALITY_PROOF_NULLSTAKE_V2;
        vote.nEpoch = nEpoch;
        vote.nHeight = nHeight;
        vote.hashBlock = uint256(0x1601);
        vote.nullifier = uint256(0x1700 + i);
        BOOST_REQUIRE(tracker.AddVote(vote, false, true));
        connected.push_back(vote);
    }

    std::string strError;
    BOOST_CHECK(tracker.CheckCanonicalVoteSetCapacity(
        std::vector<CFinalityVote>(), nHeight, &strError));
    // Re-carrying an already-connected nullifier on a DAG sibling does not
    // consume another slot.
    BOOST_CHECK(tracker.CheckCanonicalVoteSetCapacity(
        std::vector<CFinalityVote>(1, connected[0]), nHeight, &strError));
    CFinalityVote overflow = connected[0];
    overflow.nullifier = uint256(0x1801);
    BOOST_CHECK(!tracker.CheckCanonicalVoteSetCapacity(
        std::vector<CFinalityVote>(1, overflow), nHeight, &strError));
    BOOST_CHECK(!strError.empty());
}

BOOST_AUTO_TEST_SUITE_END()
