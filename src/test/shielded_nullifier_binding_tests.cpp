// Tests for shielded nullifier binding: a note must map to one unforgeable
// spend tag so it cannot be re-spent under a different nullifier, and the
// binding proof primitive (zkproof.cpp) must reject forged/foreign/tampered
// inputs. See docs/security/shielded_nullifier_binding_fix.md.

#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../shielded.h"
#include "../zkproof.h"

#include <set>
#include <vector>

namespace {

// Models the FIXED consensus double-spend key: the spent-set is keyed on the
// note-bound nullifier tag (src/main.cpp ConnectInputs requires
// spend.nullifier == NullifierTagFromPoint(NF), and NF is forced to the note's
// canonical r*G_nf by VerifyNullifierBindingProof). The tag is therefore a
// pure function of the note, NOT an attacker-chosen field.
uint256 SpendDoubleSpendTag(const CShieldedSpendDescription& spend)
{
    return NullifierTagFromPoint(spend.vchNullifierPoint);
}

// A node's persisted spent-tag set + the accept/reject decision, mirroring the
// ConnectInputs nullifier check.
struct SpentTagSet
{
    std::set<uint256> seen;
    bool AcceptSpend(const CShieldedSpendDescription& spend)
    {
        uint256 tag = SpendDoubleSpendTag(spend);
        if (seen.count(tag))
            return false; // double-spend rejected
        seen.insert(tag);
        return true;
    }
};

// Build a shielded spend of a note from its value+blind, deriving the canonical
// nullifier point/tag the way fixed consensus requires. An attacker cannot vary
// the tag for a given note: it is r*G_nf bound by the proof (see the proof-level
// soundness tests below). The legacy `nullifier`-as-free-field channel is dead.
CShieldedSpendDescription MakeSpendOfNote(int64_t value,
                                          const std::vector<unsigned char>& blind)
{
    CShieldedSpendDescription spend;
    BOOST_REQUIRE(CreatePedersenCommitment(value, blind, spend.cv));
    BOOST_REQUIRE(CreateBulletproofRangeProof(value, blind, spend.cv, spend.rangeProof));
    BOOST_REQUIRE(ComputeNullifierPoint(blind, spend.vchNullifierPoint));
    spend.nullifier = NullifierTagFromPoint(spend.vchNullifierPoint);
    return spend;
}

} // namespace

BOOST_AUTO_TEST_SUITE(shielded_nullifier_binding_tests)

// The note-bound nullifier point/tag is deterministic for a given note and
// distinct across notes — the property that makes the spent-set guard sound.
BOOST_AUTO_TEST_CASE(note_bound_tag_is_deterministic_and_unique)
{
    BOOST_REQUIRE(CZKContext::Initialize());

    std::vector<unsigned char> blind;
    BOOST_REQUIRE(GenerateBlindingFactor(blind));

    CShieldedSpendDescription a = MakeSpendOfNote(1234500000, blind);
    CShieldedSpendDescription b = MakeSpendOfNote(1234500000, blind); // same note
    BOOST_CHECK(a.cv.vchCommitment == b.cv.vchCommitment);
    BOOST_CHECK(SpendDoubleSpendTag(a) == SpendDoubleSpendTag(b)); // same note -> same tag

    std::vector<unsigned char> blind2;
    BOOST_REQUIRE(GenerateBlindingFactor(blind2));
    CShieldedSpendDescription c = MakeSpendOfNote(1234500000, blind2); // different note
    BOOST_CHECK(SpendDoubleSpendTag(a) != SpendDoubleSpendTag(c));
}

// SECURE INVARIANT (now enforced): a node that accepted a spend of a note must
// reject any further spend of that SAME note. Because the tag is the note-bound
// NF tag, a re-spend collapses to the same tag and is rejected.
BOOST_AUTO_TEST_CASE(second_spend_of_same_note_is_rejected)
{
    BOOST_REQUIRE(CZKContext::Initialize());

    std::vector<unsigned char> blind;
    BOOST_REQUIRE(GenerateBlindingFactor(blind));

    SpentTagSet node;
    CShieldedSpendDescription firstSpend = MakeSpendOfNote(5000000000, blind);
    BOOST_REQUIRE(node.AcceptSpend(firstSpend));

    // Re-spend the SAME note. Even constructing a fresh spend object, the tag is
    // forced to the note's canonical NF tag, so it is rejected as a double-spend.
    CShieldedSpendDescription replaySpend = MakeSpendOfNote(5000000000, blind);
    BOOST_CHECK_MESSAGE(!node.AcceptSpend(replaySpend),
        "second spend of the same note was accepted -> binding regression");
}

// N attempts to spend one note collapse to exactly ONE accepted spend.
BOOST_AUTO_TEST_CASE(one_note_yields_at_most_one_spend)
{
    BOOST_REQUIRE(CZKContext::Initialize());

    std::vector<unsigned char> blind;
    BOOST_REQUIRE(GenerateBlindingFactor(blind));

    SpentTagSet node;
    int nAccepted = 0;
    for (uint32_t i = 0; i < 8; i++)
    {
        CShieldedSpendDescription spend = MakeSpendOfNote(100000000, blind);
        if (node.AcceptSpend(spend))
            nAccepted++;
    }

    BOOST_CHECK_MESSAGE(nAccepted == 1,
        "a single note was spent multiple times (accepted=" +
        std::to_string(nAccepted) + ", expected 1) -> binding regression");
}

BOOST_AUTO_TEST_SUITE_END()

// ===========================================================================
// Tests for the FIX primitive: CreateNullifierBindingProof /
// VerifyNullifierBindingProof / ComputeNullifierPoint (zkproof.cpp).
// These exercise the real cryptography and must all pass green.
// ===========================================================================

namespace {

struct Note
{
    int64_t value;
    std::vector<unsigned char> blind;
    CPedersenCommitment cv;
    std::vector<unsigned char> nfPoint;
};

Note MakeNote(int64_t value)
{
    Note n;
    n.value = value;
    BOOST_REQUIRE(GenerateBlindingFactor(n.blind));
    BOOST_REQUIRE(CreatePedersenCommitment(value, n.blind, n.cv));
    BOOST_REQUIRE(ComputeNullifierPoint(n.blind, n.nfPoint));
    BOOST_REQUIRE_EQUAL(n.nfPoint.size(), (size_t)NULLIFIER_POINT_SIZE);
    return n;
}

} // namespace

BOOST_AUTO_TEST_SUITE(shielded_nullifier_binding_proof_tests)

BOOST_AUTO_TEST_CASE(binding_proof_round_trip)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    Note note = MakeNote(4200000000);
    uint256 sighash = uint256(0x1234);

    std::vector<unsigned char> proof;
    BOOST_REQUIRE(CreateNullifierBindingProof(note.value, note.blind, note.cv,
                                              note.nfPoint, sighash, proof));
    BOOST_REQUIRE_EQUAL(proof.size(), (size_t)NULLIFIER_BINDING_PROOF_SIZE);
    BOOST_CHECK(VerifyNullifierBindingProof(note.cv, note.nfPoint, sighash, proof));
}

// Determinism + uniqueness: the same note always yields the same nullifier
// point/tag (=> a second spend is caught), and distinct notes yield distinct
// nullifiers.
BOOST_AUTO_TEST_CASE(nullifier_point_is_deterministic_and_unique)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    Note a = MakeNote(1000000000);

    std::vector<unsigned char> nfAgain;
    BOOST_REQUIRE(ComputeNullifierPoint(a.blind, nfAgain));
    BOOST_CHECK(nfAgain == a.nfPoint); // same note -> same NF
    BOOST_CHECK(NullifierTagFromPoint(nfAgain) == NullifierTagFromPoint(a.nfPoint));

    Note b = MakeNote(1000000000); // same value, different blind
    BOOST_CHECK(b.nfPoint != a.nfPoint);
    BOOST_CHECK(NullifierTagFromPoint(b.nfPoint) != NullifierTagFromPoint(a.nfPoint));
}

// SOUNDNESS: a prover cannot bind a note's commitment to any nullifier point
// other than its canonical one. The mint/drain exploit required exactly this.
BOOST_AUTO_TEST_CASE(binding_proof_rejects_forged_nullifier_point)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    Note note = MakeNote(777777777);
    uint256 sighash = uint256(0xBEEF);

    // Forge a different nullifier point from an unrelated blind.
    std::vector<unsigned char> forgedBlind;
    BOOST_REQUIRE(GenerateBlindingFactor(forgedBlind));
    std::vector<unsigned char> forgedNf;
    BOOST_REQUIRE(ComputeNullifierPoint(forgedBlind, forgedNf));
    BOOST_REQUIRE(forgedNf != note.nfPoint);

    // Even though the prover knows the real opening of cv, no proof binds cv to
    // the forged NF: verification against the forged NF must fail.
    std::vector<unsigned char> proof;
    BOOST_REQUIRE(CreateNullifierBindingProof(note.value, note.blind, note.cv,
                                              forgedNf, sighash, proof));
    BOOST_CHECK(!VerifyNullifierBindingProof(note.cv, forgedNf, sighash, proof));

    // And a proof made for the canonical NF does not transfer to the forged NF.
    std::vector<unsigned char> realProof;
    BOOST_REQUIRE(CreateNullifierBindingProof(note.value, note.blind, note.cv,
                                              note.nfPoint, sighash, realProof));
    BOOST_CHECK(VerifyNullifierBindingProof(note.cv, note.nfPoint, sighash, realProof));
    BOOST_CHECK(!VerifyNullifierBindingProof(note.cv, forgedNf, sighash, realProof));
}

// A proof for note A must not verify against a different note B's commitment.
BOOST_AUTO_TEST_CASE(binding_proof_rejects_foreign_commitment)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    Note a = MakeNote(500000000);
    Note b = MakeNote(900000000);
    uint256 sighash = uint256(0xCAFE);

    std::vector<unsigned char> proofA;
    BOOST_REQUIRE(CreateNullifierBindingProof(a.value, a.blind, a.cv,
                                              a.nfPoint, sighash, proofA));
    BOOST_CHECK(VerifyNullifierBindingProof(a.cv, a.nfPoint, sighash, proofA));
    BOOST_CHECK(!VerifyNullifierBindingProof(b.cv, a.nfPoint, sighash, proofA));
    BOOST_CHECK(!VerifyNullifierBindingProof(a.cv, b.nfPoint, sighash, proofA));
}

// The proof is bound to the transaction sighash (no cross-tx replay).
BOOST_AUTO_TEST_CASE(binding_proof_is_bound_to_sighash)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    Note note = MakeNote(123456789);

    std::vector<unsigned char> proof;
    BOOST_REQUIRE(CreateNullifierBindingProof(note.value, note.blind, note.cv,
                                              note.nfPoint, uint256(0x1111), proof));
    BOOST_CHECK(VerifyNullifierBindingProof(note.cv, note.nfPoint, uint256(0x1111), proof));
    BOOST_CHECK(!VerifyNullifierBindingProof(note.cv, note.nfPoint, uint256(0x2222), proof));
}

// Any tamper of the proof bytes is rejected.
BOOST_AUTO_TEST_CASE(binding_proof_rejects_tampering)
{
    BOOST_REQUIRE(CZKContext::Initialize());
    Note note = MakeNote(333333333);
    uint256 sighash = uint256(0x9999);

    std::vector<unsigned char> proof;
    BOOST_REQUIRE(CreateNullifierBindingProof(note.value, note.blind, note.cv,
                                              note.nfPoint, sighash, proof));
    BOOST_REQUIRE(VerifyNullifierBindingProof(note.cv, note.nfPoint, sighash, proof));

    for (size_t pos : {size_t(0), size_t(40), size_t(70), size_t(100), size_t(129)})
    {
        std::vector<unsigned char> bad = proof;
        bad[pos] ^= 0x01;
        BOOST_CHECK_MESSAGE(!VerifyNullifierBindingProof(note.cv, note.nfPoint, sighash, bad),
                            "tampered proof accepted at byte " + std::to_string(pos));
    }

    // Wrong length rejected.
    std::vector<unsigned char> shortProof(proof.begin(), proof.end() - 1);
    BOOST_CHECK(!VerifyNullifierBindingProof(note.cv, note.nfPoint, sighash, shortProof));
}

BOOST_AUTO_TEST_SUITE_END()
