// The certificate's note leg as a commitment rather than an enumeration.
//
// A v4 certificate names the epoch's counted note votes by Merkle root and count instead
// of listing every tag at 32 bytes. That is what lets the per-epoch note-vote cap move to
// FINALITY_MAX_EPOCH_NOTE_VOTES without the canonical carrier growing, and it leaves the
// transparent nullifier enumeration -- which is hashed into every certificate identity
// ever produced and is live under Boundary A -- exactly as it was.
//
// Everything here is behind FORK_HEIGHT_IV5_NOTE_VOTE, which is unset on mainnet and
// testnet, so the cases drive it through the regtest knob and restore it at teardown.

#include <boost/test/unit_test.hpp>

#include "../finality.h"
#include "../finality_note.h"
#include "../hash.h"
#include "../main.h"
#include "../script.h"
#include "../serialize.h"
#include "../uint256.h"

#include <algorithm>
#include <string>
#include <vector>

namespace
{

struct ScopedNoteVoteFork
{
    int nSaved;
    explicit ScopedNoteVoteFork(int nHeight) : nSaved(nRegtestIV5NoteVoteHeight)
    {
        nRegtestIV5NoteVoteHeight = nHeight;
    }
    ~ScopedNoteVoteFork() { nRegtestIV5NoteVoteHeight = nSaved; }
};

// An epoch-boundary height at or above the note-vote fork, so cert.nHeight satisfies both
// the boundary rule IsValidBasic's callers apply and the fork gate IsValidBasic applies.
int NoteBoundaryHeight()
{
    const int nEpoch = GetEpochForHeight(FORK_HEIGHT_DAG) + 4;
    return GetEpochBoundaryHeight(nEpoch, FORK_HEIGHT_DAG);
}

std::vector<uint256> MakeTags(size_t n, unsigned int nSeed)
{
    std::vector<uint256> vTags;
    vTags.reserve(n);
    for (size_t i = 0; i < n; i++)
        vTags.push_back(Hash(BEGIN(nSeed), END(nSeed)) + uint256((uint64_t)(i + 1)));
    std::sort(vTags.begin(), vTags.end());
    return vTags;
}

// A structurally complete canonical v4 certificate with a note leg and no transparent
// private weight. Callers set the two note fields themselves.
CFinalityTallyCertificate MakeCanonicalNoteCert(int nHeight, size_t nNullifiers)
{
    CFinalityTallyCertificate cert;
    cert.nVersion = FINALITY_NOTE_CERT_VERSION;
    cert.nEpoch = GetEpochForHeight(nHeight);
    cert.nHeight = nHeight;
    cert.hashBlock = uint256(0xb0a11);
    cert.nTier = FINALITY_HARD;
    cert.nConsecutiveHardCount = 0;
    cert.committeeSetHash = uint256(0xc0ffee);
    cert.nTransparentActiveWeight = 0;
    cert.nTransparentWinningWeight = 0;
    cert.nTransparentRewardBudget = 0;
    const std::vector<uint256> vNullifiers = MakeTags(nNullifiers, 0x4e554c4c);
    cert.vVoteNullifiers = vNullifiers;
    cert.MarkCanonicalEnvelope();
    return cert;
}

// A counted note vote is only its tag and the block it names, as far as the note leg is
// concerned; nothing else on the vote reaches coverage or the tier.
CNoteFinalityVote MakeCountedVote(unsigned char nTagSeed, const uint256& hashNamed)
{
    CNoteFinalityVote vote;
    vote.vchTag.assign(FINALITY_NOTE_POINT_SIZE, nTagSeed);
    vote.hashBlock = hashNamed;
    return vote;
}

} // namespace

BOOST_AUTO_TEST_SUITE(finality_note_cert_root_tests)

// The root is a function of the exact ordered leaf set, and the odd tail is promoted
// rather than duplicated. Duplicating it would give {a,b,c} and {a,b,c,c} one root, so a
// certificate could commit to two different counted sets at once.
BOOST_AUTO_TEST_CASE(note_vote_set_root_binds_the_exact_leaf_set)
{
    const std::vector<uint256> vEmpty;
    BOOST_CHECK(ComputeNoteVoteSetRoot(vEmpty) == uint256(0));

    const std::vector<uint256> vThree = MakeTags(3, 0x11);
    const std::vector<uint256> vTwo(vThree.begin(), vThree.begin() + 2);
    const uint256 rootThree = ComputeNoteVoteSetRoot(vThree);
    const uint256 rootTwo = ComputeNoteVoteSetRoot(vTwo);
    BOOST_CHECK(rootThree != uint256(0));
    BOOST_CHECK(rootTwo != rootThree);

    // MUTATION: promote the odd tail by duplicating it instead
    // (vNext.push_back(vLevel.back()) twice) and this equality holds.
    std::vector<uint256> vThreePlusDup = vThree;
    vThreePlusDup.push_back(vThree.back());
    BOOST_CHECK(ComputeNoteVoteSetRoot(vThreePlusDup) != rootThree);

    // Order is part of the commitment, which is why the counted set is sorted before it
    // is taken. MUTATION: sort inside ComputeNoteVoteSetRoot and this fails.
    std::vector<uint256> vReversed = vThree;
    std::reverse(vReversed.begin(), vReversed.end());
    BOOST_CHECK(ComputeNoteVoteSetRoot(vReversed) != rootThree);

    // One leaf is the leaf hash, not the tag and not a node hash, so no tag can be read
    // as a subtree root. MUTATION: drop the leaf domain string and the first check fails.
    const std::vector<uint256> vOne(vThree.begin(), vThree.begin() + 1);
    const uint256 rootOne = ComputeNoteVoteSetRoot(vOne);
    BOOST_CHECK(rootOne != vThree[0]);
    CHashWriter nodeAsLeaf(SER_GETHASH, 0);
    nodeAsLeaf << std::string("Innova/Finality/NoteVoteNode/v1");
    nodeAsLeaf << vThree[0];
    BOOST_CHECK(rootOne != nodeAsLeaf.GetHash());

    // A tag that changes changes the root, at every position.
    for (size_t i = 0; i < vThree.size(); i++)
    {
        std::vector<uint256> vMutated = vThree;
        vMutated[i] = vMutated[i] + uint256(0x1000);
        BOOST_CHECK(ComputeNoteVoteSetRoot(vMutated) != rootThree);
    }
}

// The counted view is one tag per vote. A repeated or zero tag is a caller bug, not a set
// to take a root over, so the helper refuses it rather than committing to nonsense.
BOOST_AUTO_TEST_CASE(counted_note_vote_tags_are_sorted_unique_and_nonzero)
{
    CNoteFinalityVote a;
    a.vchTag.assign(FINALITY_NOTE_POINT_SIZE, 0x22);
    CNoteFinalityVote b;
    b.vchTag.assign(FINALITY_NOTE_POINT_SIZE, 0x11);

    std::vector<CNoteFinalityVote> vVotes;
    vVotes.push_back(a);
    vVotes.push_back(b);
    std::vector<uint256> vTags;
    BOOST_REQUIRE(GetNoteVoteSetTags(vVotes, vTags));
    BOOST_REQUIRE_EQUAL(vTags.size(), (size_t)2);
    // MUTATION: drop the std::sort and this fails.
    BOOST_CHECK(vTags[0] < vTags[1]);
    BOOST_CHECK(vTags[0] == b.GetVoteTag());

    // MUTATION: drop the setSeen insert check and this passes with a duplicated tag.
    vVotes.push_back(a);
    BOOST_CHECK(!GetNoteVoteSetTags(vVotes, vTags));
    BOOST_CHECK(vTags.empty());

    // A vote with no tag reaches uint256(0), which is the empty-set root's own value.
    CNoteFinalityVote untagged;
    std::vector<CNoteFinalityVote> vUntagged;
    vUntagged.push_back(untagged);
    BOOST_CHECK(!GetNoteVoteSetTags(vUntagged, vTags));
}

// The note leg is wholly present or wholly absent, and it is a v4 field.
BOOST_AUTO_TEST_CASE(note_cert_root_and_count_must_agree)
{
    ScopedNoteVoteFork fork(1);
    const int nHeight = NoteBoundaryHeight();
    BOOST_REQUIRE(IsIV5NoteVoteActiveAtHeight(nHeight));

    CFinalityTallyCertificate cert = MakeCanonicalNoteCert(nHeight, 2);
    std::string strError;

    // Both set: a note leg.
    cert.nNoteVoteCount = 3;
    cert.hashNoteVoteRoot = ComputeNoteVoteSetRoot(MakeTags(3, 0x33));
    BOOST_CHECK_MESSAGE(cert.IsValidBasic(&strError), strError);
    BOOST_CHECK(cert.HasNoteWeight());

    // Neither set: no note leg, still a valid v4 certificate on its transparent leg. The
    // tier falls to the transparent rule, which has no weight here, so it is NONE.
    CFinalityTallyCertificate bare = cert;
    bare.nNoteVoteCount = 0;
    bare.hashNoteVoteRoot = 0;
    bare.nTier = FINALITY_NONE;
    BOOST_CHECK_MESSAGE(bare.IsValidBasic(&strError), strError);
    BOOST_CHECK(!bare.HasNoteWeight());

    // MUTATION: relax the (count == 0) != (root == 0) rule and both of these pass.
    CFinalityTallyCertificate rootOnly = cert;
    rootOnly.nNoteVoteCount = 0;
    BOOST_CHECK(!rootOnly.IsValidBasic(&strError));
    BOOST_CHECK_EQUAL(strError, "tally certificate note root and count disagree");

    CFinalityTallyCertificate countOnly = cert;
    countOnly.hashNoteVoteRoot = 0;
    BOOST_CHECK(!countOnly.IsValidBasic(&strError));
    BOOST_CHECK_EQUAL(strError, "tally certificate note root and count disagree");

    // Over the note-lane cap.
    CFinalityTallyCertificate tooMany = cert;
    tooMany.nNoteVoteCount = FINALITY_MAX_EPOCH_NOTE_VOTES + 1;
    BOOST_CHECK(!tooMany.IsValidBasic(&strError));
    BOOST_CHECK_EQUAL(strError, "tally certificate note set size out of range");
    tooMany.nNoteVoteCount = FINALITY_MAX_EPOCH_NOTE_VOTES;
    BOOST_CHECK_MESSAGE(tooMany.IsValidBasic(&strError), strError);

    // A pre-v4 certificate must not carry either field.
    CFinalityTallyCertificate legacy = cert;
    legacy.nVersion = 2;
    legacy.nTier = FINALITY_NONE;
    legacy.nNoteVoteCount = 0;
    legacy.hashNoteVoteRoot = uint256(0x99);
    BOOST_CHECK(!legacy.IsValidBasic(&strError));
    BOOST_CHECK_EQUAL(strError, "pre-v4 tally certificate must not carry note fields");
    legacy.hashNoteVoteRoot = 0;
    legacy.nNoteVoteCount = 1;
    BOOST_CHECK(!legacy.IsValidBasic(&strError));
    BOOST_CHECK_EQUAL(strError, "pre-v4 tally certificate must not carry note fields");
}

// The certificate's identity and the digest the committee signs both cover the note leg,
// so a certificate cannot be restated over a different counted set under one signature.
BOOST_AUTO_TEST_CASE(note_cert_digests_cover_the_root_and_the_count)
{
    ScopedNoteVoteFork fork(1);
    const int nHeight = NoteBoundaryHeight();

    CFinalityTallyCertificate cert = MakeCanonicalNoteCert(nHeight, 2);
    cert.nNoteVoteCount = 4;
    cert.hashNoteVoteRoot = ComputeNoteVoteSetRoot(MakeTags(4, 0x44));

    // MUTATION: drop `ss << hashNoteVoteRoot` from FinalityAppendNoteCertFields and the
    // first pair of checks fails; drop `ss << nNoteVoteCount` and the second pair fails.
    CFinalityTallyCertificate otherRoot = cert;
    otherRoot.hashNoteVoteRoot = ComputeNoteVoteSetRoot(MakeTags(4, 0x45));
    BOOST_REQUIRE(otherRoot.hashNoteVoteRoot != cert.hashNoteVoteRoot);
    BOOST_CHECK(otherRoot.GetHash() != cert.GetHash());
    BOOST_CHECK(otherRoot.GetSignatureDigest() != cert.GetSignatureDigest());

    CFinalityTallyCertificate otherCount = cert;
    otherCount.nNoteVoteCount = 5;
    BOOST_CHECK(otherCount.GetHash() != cert.GetHash());
    BOOST_CHECK(otherCount.GetSignatureDigest() != cert.GetSignatureDigest());

    // A v3 certificate reaches the same digest with or without the note fields set,
    // because the version gate is what decides whether they are hashed at all.
    CFinalityTallyCertificate v3 = cert;
    v3.nVersion = 3;
    v3.nNoteVoteCount = 0;
    v3.hashNoteVoteRoot = 0;
    CFinalityTallyCertificate v3WithFields = v3;
    v3WithFields.nNoteVoteCount = 9;
    v3WithFields.hashNoteVoteRoot = uint256(0x77);
    BOOST_CHECK(v3.GetHash() == v3WithFields.GetHash());
}

// Schema 2 carries the note leg as 36 bytes and round-trips it exactly.
BOOST_AUTO_TEST_CASE(note_cert_note_leg_round_trips_through_schema_two)
{
    ScopedNoteVoteFork fork(1);
    const int nHeight = NoteBoundaryHeight();
    BOOST_REQUIRE(IsIV5NoteVoteActiveAtHeight(nHeight));

    CFinalityTallyCertificate cert = MakeCanonicalNoteCert(nHeight, 3);
    cert.nNoteVoteCount = 7;
    cert.hashNoteVoteRoot = ComputeNoteVoteSetRoot(MakeTags(7, 0x66));
    std::string strError;
    BOOST_REQUIRE_MESSAGE(cert.IsValidBasic(&strError), strError);

    CCanonicalFinalityTallyCertificateEnvelope envelope;
    BOOST_REQUIRE(envelope.FromLogical(cert));
    BOOST_CHECK_EQUAL(envelope.nLogicalVersion,
                      FINALITY_CANONICAL_TALLY_CERT_VERSION_NOTE);
    BOOST_CHECK(envelope.hashNoteVoteRoot == cert.hashNoteVoteRoot);
    BOOST_CHECK_EQUAL(envelope.nNoteVoteCount, cert.nNoteVoteCount);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << envelope;
    CCanonicalFinalityTallyCertificateEnvelope decoded;
    ss >> decoded;
    BOOST_CHECK(ss.empty());

    CFinalityTallyCertificate back;
    BOOST_REQUIRE(decoded.ToLogical(back));
    BOOST_CHECK(back.hashNoteVoteRoot == cert.hashNoteVoteRoot);
    BOOST_CHECK_EQUAL(back.nNoteVoteCount, cert.nNoteVoteCount);
    BOOST_CHECK(back.GetHash() == cert.GetHash());
    BOOST_CHECK(back.GetSignatureDigest() == cert.GetSignatureDigest());

    // Schema 1 has no note leg at all, so a note-bearing certificate cannot smuggle one
    // through it and a schema-1 envelope carrying one is refused.
    CCanonicalFinalityTallyCertificateEnvelope smuggled = envelope;
    smuggled.nLogicalVersion = FINALITY_CANONICAL_TALLY_CERT_VERSION;
    smuggled.nCertificateVersion = 2;
    CFinalityTallyCertificate refused;
    BOOST_CHECK(!smuggled.ToLogical(refused));

    // Schema 2 stays unreadable while the note-vote fork is unconfigured, which is what
    // makes every rule in this file inert on a value network.
    {
        ScopedNoteVoteFork unset(PRIVACY_VNEXT_HEIGHT_UNSET);
        BOOST_REQUIRE(!IsIV5NoteVoteActiveAtHeight(nHeight));
        CFinalityTallyCertificate inert;
        BOOST_CHECK(!decoded.ToLogical(inert));
        BOOST_CHECK(!cert.IsValidBasic(&strError));
    }
}

// The whole point of the root: a certificate at the note-lane cap still fits the carrier,
// worst case, with a full transparent leg and a full committee signer set beside it.
BOOST_AUTO_TEST_CASE(note_cert_at_the_epoch_cap_fits_max_script_size)
{
    ScopedNoteVoteFork fork(1);
    const int nHeight = NoteBoundaryHeight();

    CFinalityTallyCertificate cert =
        MakeCanonicalNoteCert(nHeight, FINALITY_CANONICAL_CERT_MAX_NULLIFIERS);
    cert.nNoteVoteCount = FINALITY_MAX_EPOCH_NOTE_VOTES;
    cert.hashNoteVoteRoot =
        ComputeNoteVoteSetRoot(MakeTags(FINALITY_MAX_EPOCH_NOTE_VOTES, 0x88));
    // The signer set at its own bound, with maximum-length signatures.
    for (uint16_t i = 0; i < FINALITY_MAX_TALLY_COMMITTEE; i++)
    {
        cert.vSignerIndexes.push_back(i);
        cert.vSignerSigs.push_back(std::vector<unsigned char>(80, 0x30));
    }
    std::string strError;
    BOOST_REQUIRE_MESSAGE(cert.IsValidBasic(&strError), strError);

    CScript script;
    // MUTATION: restore the tag enumeration (256 * 32 bytes) and this build fails.
    BOOST_REQUIRE(BuildCanonicalFinalityTallyCertificateScript(cert, script));
    BOOST_CHECK_LE(script.size(), (size_t)MAX_SCRIPT_SIZE);

    CFinalityTallyCertificate decoded;
    BOOST_REQUIRE(ExtractCanonicalFinalityTallyCertificate(script, decoded));
    BOOST_CHECK(decoded.hashNoteVoteRoot == cert.hashNoteVoteRoot);
    BOOST_CHECK_EQUAL(decoded.nNoteVoteCount, cert.nNoteVoteCount);

    // The note leg costs 36 bytes whatever the cap is, so doubling the cap again would
    // not move the carrier. MUTATION: make the leg size-dependent and this fails.
    CFinalityTallyCertificate smallLeg = cert;
    smallLeg.nNoteVoteCount = 1;
    smallLeg.hashNoteVoteRoot = ComputeNoteVoteSetRoot(MakeTags(1, 0x89));
    CScript smallScript;
    BOOST_REQUIRE(BuildCanonicalFinalityTallyCertificateScript(smallLeg, smallScript));
    BOOST_CHECK_EQUAL(script.size(), smallScript.size());
}

// The transparent enumeration is untouched: its bound is still 128 and the canonical
// envelope still refuses a 129th nullifier. Raising the note cap must not raise it.
BOOST_AUTO_TEST_CASE(the_transparent_nullifier_bound_did_not_move)
{
    ScopedNoteVoteFork fork(1);
    const int nHeight = NoteBoundaryHeight();

    BOOST_CHECK_EQUAL(FINALITY_CANONICAL_CERT_MAX_NULLIFIERS, 128u);
    BOOST_CHECK_EQUAL(FINALITY_MAX_EPOCH_NOTE_VOTES, 256u);

    CFinalityTallyCertificate atBound =
        MakeCanonicalNoteCert(nHeight, FINALITY_CANONICAL_CERT_MAX_NULLIFIERS);
    atBound.nNoteVoteCount = 1;
    atBound.hashNoteVoteRoot = ComputeNoteVoteSetRoot(MakeTags(1, 0x90));
    CCanonicalFinalityTallyCertificateEnvelope envelope;
    BOOST_CHECK(envelope.FromLogical(atBound));

    // MUTATION: point FromLogical's nullifier bound at FINALITY_MAX_EPOCH_NOTE_VOTES and
    // this passes.
    CFinalityTallyCertificate overBound =
        MakeCanonicalNoteCert(nHeight, FINALITY_CANONICAL_CERT_MAX_NULLIFIERS + 1);
    overBound.nNoteVoteCount = 1;
    overBound.hashNoteVoteRoot = atBound.hashNoteVoteRoot;
    CCanonicalFinalityTallyCertificateEnvelope refused;
    BOOST_CHECK(!refused.FromLogical(overBound));
}

// The connect-time coverage rule: a certificate is accepted only against the counted set
// it actually commits to, and a set this node cannot form is local state rather than a
// verdict on the peer's certificate.
BOOST_AUTO_TEST_CASE(note_leg_coverage_refuses_a_wrong_counted_set)
{
    const uint256 hashWinner(0xc0de01);
    std::vector<CNoteFinalityVote> vCounted;
    vCounted.push_back(MakeCountedVote(0x11, hashWinner));
    vCounted.push_back(MakeCountedVote(0x22, hashWinner));
    vCounted.push_back(MakeCountedVote(0x33, uint256(0xc0de02)));

    std::vector<uint256> vTags;
    BOOST_REQUIRE(GetNoteVoteSetTags(vCounted, vTags));
    const uint256 hashRoot = ComputeNoteVoteSetRoot(vTags);
    const uint32_t nCount = (uint32_t)vTags.size();

    // The control.
    BOOST_CHECK_EQUAL(CheckNoteVoteSetCommitment(vCounted, hashRoot, nCount),
                      NOTE_VOTE_SET_OK);

    // Denominator deflation: a certificate that leaves a connected vote out. MUTATION:
    // drop the count comparison and this returns OK.
    BOOST_CHECK_EQUAL(CheckNoteVoteSetCommitment(vCounted, hashRoot, nCount - 1),
                      NOTE_VOTE_SET_COUNT);
    BOOST_CHECK_EQUAL(CheckNoteVoteSetCommitment(vCounted, hashRoot, nCount + 1),
                      NOTE_VOTE_SET_COUNT);

    // Same size, different set: the count alone would admit it. MUTATION: drop the root
    // comparison and this returns OK.
    std::vector<CNoteFinalityVote> vSwapped = vCounted;
    vSwapped[2] = MakeCountedVote(0x44, uint256(0xc0de02));
    std::vector<uint256> vSwappedTags;
    BOOST_REQUIRE(GetNoteVoteSetTags(vSwapped, vSwappedTags));
    const uint256 hashSwappedRoot = ComputeNoteVoteSetRoot(vSwappedTags);
    BOOST_REQUIRE(hashSwappedRoot != hashRoot);
    BOOST_CHECK_EQUAL(CheckNoteVoteSetCommitment(vCounted, hashSwappedRoot, nCount),
                      NOTE_VOTE_SET_ROOT);

    // A counted view this node cannot form is local state, so a certificate is never
    // marked invalid over it. MUTATION: fold UNUSABLE into ROOT and a node with a broken
    // counted view starts handing out verdicts on other nodes' certificates.
    std::vector<CNoteFinalityVote> vDuplicated = vCounted;
    vDuplicated.push_back(MakeCountedVote(0x11, hashWinner));
    BOOST_CHECK_EQUAL(CheckNoteVoteSetCommitment(vDuplicated, hashRoot, nCount),
                      NOTE_VOTE_SET_UNUSABLE);

    // The empty counted set carries no leg, and a certificate claiming one over it is a
    // count mismatch rather than an accidental root match on 0.
    const std::vector<CNoteFinalityVote> vNone;
    BOOST_CHECK_EQUAL(CheckNoteVoteSetCommitment(vNone, uint256(0), 0),
                      NOTE_VOTE_SET_OK);
    BOOST_CHECK_EQUAL(CheckNoteVoteSetCommitment(vNone, hashRoot, nCount),
                      NOTE_VOTE_SET_COUNT);
}

// The note leg's contribution to the tier is a plaintext count: every counted vote is a
// voter, and the winning subset is the votes naming the certificate's block.
BOOST_AUTO_TEST_CASE(note_leg_voter_counts_are_counted_votes_and_their_winners)
{
    const uint256 hashWinner(0xc0de01);
    const uint256 hashOther(0xc0de02);
    std::vector<CNoteFinalityVote> vCounted;
    vCounted.push_back(MakeCountedVote(0x11, hashWinner));
    vCounted.push_back(MakeCountedVote(0x22, hashWinner));
    vCounted.push_back(MakeCountedVote(0x33, hashOther));

    int nVoters = 0;
    int nWinners = 0;
    GetNoteVoteCounts(vCounted, hashWinner, nVoters, nWinners);
    BOOST_CHECK_EQUAL(nVoters, 3);
    // MUTATION: count every vote as a winner and this fails.
    BOOST_CHECK_EQUAL(nWinners, 2);

    GetNoteVoteCounts(vCounted, hashOther, nVoters, nWinners);
    BOOST_CHECK_EQUAL(nVoters, 3);
    BOOST_CHECK_EQUAL(nWinners, 1);

    GetNoteVoteCounts(vCounted, uint256(0xc0de03), nVoters, nWinners);
    BOOST_CHECK_EQUAL(nVoters, 3);
    BOOST_CHECK_EQUAL(nWinners, 0);

    // The predicate CheckTallyCertificate now applies to these counts. It is the same
    // one the transparent leg applies to weights, which is exactly why the note leg's
    // counts and the transparent leg's weights are never summed into one pair.
    BOOST_CHECK(VerifyFinalityThresholdTier(FINALITY_HARD, 3, 2));
    BOOST_CHECK(!VerifyFinalityThresholdTier(FINALITY_HARD, 3, 1));
    BOOST_CHECK(VerifyFinalityThresholdTier(FINALITY_HARD, 2, 2));
    BOOST_CHECK(VerifyFinalityThresholdTier(FINALITY_SOFT, 4, 3));
    // SOFT is a strict majority, so an even split names no winner.
    BOOST_CHECK(!VerifyFinalityThresholdTier(FINALITY_SOFT, 4, 2));
    BOOST_CHECK(VerifyFinalityThresholdTier(FINALITY_NONE, 0, 0));
}

// The per-block carrier cap and the per-epoch cap have to leave the epoch cap binding:
// 32 votes a block over a 24-block inclusion window is 768 slots against 256, so no block
// is ever forced to carry a whole epoch's votes to reach the cap.
BOOST_AUTO_TEST_CASE(note_vote_block_and_epoch_caps_are_consistent)
{
    const unsigned int nWindowSlots =
        (unsigned int)FINALITY_MAX_BLOCK_NOTE_VOTES * FINALITY_VOTE_INCLUSION_WINDOW;
    BOOST_CHECK_GT(nWindowSlots, FINALITY_MAX_EPOCH_NOTE_VOTES);
    // And one block alone cannot reach the epoch cap, so the epoch bound is a real
    // constraint on the window rather than a restatement of the block bound.
    BOOST_CHECK_LT((unsigned int)FINALITY_MAX_BLOCK_NOTE_VOTES,
                   FINALITY_MAX_EPOCH_NOTE_VOTES);
}

BOOST_AUTO_TEST_SUITE_END()
