// Tests for private finality vote nullifier binding (HIGH-2 fix): one stake
// note maps to exactly one vote tag per epoch, so hidden finality weight can
// no longer be inflated by re-voting a note under fresh nullifiers. The
// binding proof commits to the (epoch, epoch-block) context, so it cannot be
// replayed at another boundary or grafted onto another stake. Consensus
// enforcement lives in CFinalityTracker::CheckVote / AddVote (finality.cpp).

#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../finality.h"
#include "../zkproof.h"

#include <map>
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

} // namespace

BOOST_AUTO_TEST_SUITE(finality_vote_binding_tests)

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
    BOOST_CHECK(VerifyNullifierBindingProof(stake.cv, stake.nfPoint, ctx4, proof));

    BOOST_CHECK(!VerifyNullifierBindingProof(stake.cv, stake.nfPoint,
                                             FinalityNullifierBindContext(5, hashBlock5), proof));
    BOOST_CHECK(!VerifyNullifierBindingProof(stake.cv, stake.nfPoint,
                                             FinalityNullifierBindContext(5, hashBlock4), proof));
    BOOST_CHECK(!VerifyNullifierBindingProof(stake.cv, stake.nfPoint,
                                             FinalityNullifierBindContext(4, hashBlock5), proof));
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
    BOOST_REQUIRE(VerifyNullifierBindingProof(a.cv, a.nfPoint, ctx, proofA));

    BOOST_CHECK(!VerifyNullifierBindingProof(b.cv, a.nfPoint, ctx, proofA));
    BOOST_CHECK(!VerifyNullifierBindingProof(a.cv, b.nfPoint, ctx, proofA));
    BOOST_CHECK(!VerifyNullifierBindingProof(b.cv, b.nfPoint, ctx, proofA));
}

BOOST_AUTO_TEST_SUITE_END()
