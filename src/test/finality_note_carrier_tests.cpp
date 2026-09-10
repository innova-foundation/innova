// Tests for the note-vote tally rules: the shape a payload-derived record must have, the
// equivocation rule that drops a conflicting tag instead of the block carrying it, the
// re-carry rule, and the per-block and per-epoch caps.

#include <boost/test/unit_test.hpp>

#include "../finality.h"
#include "../finality_note.h"
#include "../hash.h"
#include "../key.h"
#include "../main.h"
#include "../privacy_vnext/iv5_protocol.h"
#include "../privacy_vnext_ffi.h"
#include "../script.h"
#include "../serialize.h"
#include "../txdb.h"
#include "../util.h"

#include <string>
#include <string.h>
#include <vector>

namespace
{

// A payload-derived record. It carries no proof and no anchor: the operation-10 payload
// carries those and was verified when it connected, so everything here is what the tally
// actually reads -- the epoch, the boundary it names, and the tag that dedups it.
CNoteFinalityVote MakeVote(int nEpoch, const uint256& hashBlock, unsigned char nTagSeed)
{
    CNoteFinalityVote vote;
    vote.nEpoch = nEpoch;
    vote.hashBlock = hashBlock;
    vote.nHeight = 6000 + nEpoch;
    vote.vchTag.assign(FINALITY_NOTE_POINT_SIZE, nTagSeed);
    std::string strError;
    BOOST_REQUIRE_MESSAGE(vote.IsValidBasic(&strError), strError);
    return vote;
}

} // namespace

BOOST_AUTO_TEST_SUITE(finality_note_carrier_tests)

// Record shape is fail-closed both ways: startup rejects the load on any invalid
// record, so a record the tally rejects must be refused before it is written.
BOOST_AUTO_TEST_CASE(a_record_carrying_a_proof_or_an_anchor_is_refused)
{
    const CNoteFinalityVote good = MakeVote(21, uint256(0x1234), 0x55);
    BOOST_REQUIRE(good.IsValidBasic());
    BOOST_CHECK_EQUAL(good.nVersion, FINALITY_NOTE_VOTE_VERSION);

    // Version 1 carried its proofs in a coinbase script. It is refused, not armed: a v1
    // record left on disk must fail the load rather than be counted as a phantom vote.
    CNoteFinalityVote v1 = good;
    v1.nVersion = 1;
    BOOST_CHECK(!v1.IsValidBasic());

    // Every proof field the payload owns.
    CNoteFinalityVote withMembership = good;
    withMembership.vchMembership.assign(8, 0);
    BOOST_CHECK(!withMembership.IsValidBasic());
    CNoteFinalityVote withSigma = good;
    withSigma.vchSigma.assign(1, 0);
    BOOST_CHECK(!withSigma.IsValidBasic());
    CNoteFinalityVote withFloorProof = good;
    withFloorProof.vchWeightFloorProof.assign(1, 0);
    BOOST_CHECK(!withFloorProof.IsValidBasic());

    // Every anchor field the payload owns.
    CNoteFinalityVote withCurveRoot = good;
    withCurveRoot.hashCurveRoot = uint256(1);
    BOOST_CHECK(!withCurveRoot.IsValidBasic());
    CNoteFinalityVote withNullifierRoot = good;
    withNullifierRoot.hashNullifierRoot = uint256(1);
    BOOST_CHECK(!withNullifierRoot.IsValidBasic());
    CNoteFinalityVote withCommittee = good;
    withCommittee.committeeSetHash = uint256(1);
    BOOST_CHECK(!withCommittee.IsValidBasic());

    // The two fields the tally cannot do without.
    CNoteFinalityVote noBoundary = good;
    noBoundary.hashBlock = 0;
    BOOST_CHECK(!noBoundary.IsValidBasic());
    CNoteFinalityVote zeroTag = good;
    zeroTag.vchTag.assign(FINALITY_NOTE_POINT_SIZE, 0);
    BOOST_CHECK(!zeroTag.IsValidBasic());
    CNoteFinalityVote shortTag = good;
    shortTag.vchTag.assign(FINALITY_NOTE_POINT_SIZE - 1, 0x55);
    BOOST_CHECK(!shortTag.IsValidBasic());

    // What the startup load actually does with an accepted record.
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << good;
    CNoteFinalityVote reloaded;
    ss >> reloaded;
    BOOST_CHECK(reloaded.IsValidBasic());
    BOOST_CHECK(reloaded.GetHash() == good.GetHash());
    BOOST_CHECK(reloaded.GetVoteTag() == good.GetVoteTag());
}

// A conflicting tag is resolved by dropping the tag, never the carrier. The outcome is
// a pure function of the carried set, so connect order cannot change it.
BOOST_AUTO_TEST_CASE(note_vote_equivocation_counts_for_neither)
{
    const CNoteFinalityVote voteA = MakeVote(11, uint256(0xaaaa), 0x31);
    CNoteFinalityVote voteB = MakeVote(11, uint256(0xbbbb), 0x31);
    voteB.vchTag = voteA.vchTag;
    const CNoteFinalityVote voteOther = MakeVote(11, uint256(0xaaaa), 0x32);
    BOOST_REQUIRE(voteA.GetVoteTag() == voteB.GetVoteTag());
    BOOST_REQUIRE(GetNoteVoteSemanticIdentity(voteA) != GetNoteVoteSemanticIdentity(voteB));

    std::vector<const CNoteFinalityVote*> vCarried;
    vCarried.push_back(&voteA);
    vCarried.push_back(&voteB);
    vCarried.push_back(&voteOther);
    std::map<uint256, const CNoteFinalityVote*> mapCounted;
    std::set<uint256> setEquivocated;
    ResolveNoteVoteCounting(vCarried, mapCounted, setEquivocated);
    BOOST_CHECK_EQUAL(mapCounted.size(), (size_t)1);
    BOOST_CHECK(mapCounted.count(voteOther.GetVoteTag()) == 1);
    BOOST_CHECK(setEquivocated.count(voteA.GetVoteTag()) == 1);

    // Reversed arrival order lands on the same answer, which is what makes the rule
    // safe to apply at connect time on nodes that saw the siblings in either order.
    std::vector<const CNoteFinalityVote*> vReversed(vCarried.rbegin(), vCarried.rend());
    std::map<uint256, const CNoteFinalityVote*> mapReversed;
    std::set<uint256> setReversed;
    ResolveNoteVoteCounting(vReversed, mapReversed, setReversed);
    BOOST_CHECK_EQUAL(mapReversed.size(), mapCounted.size());
    BOOST_CHECK(mapReversed.count(voteOther.GetVoteTag()) == 1);
    BOOST_CHECK(setReversed == setEquivocated);

    // A re-carry of the identical vote is one vote, not a conflict.
    std::vector<const CNoteFinalityVote*> vRecarried;
    vRecarried.push_back(&voteA);
    vRecarried.push_back(&voteA);
    std::map<uint256, const CNoteFinalityVote*> mapRecarried;
    std::set<uint256> setRecarriedEquivocated;
    ResolveNoteVoteCounting(vRecarried, mapRecarried, setRecarriedEquivocated);
    BOOST_CHECK_EQUAL(mapRecarried.size(), (size_t)1);
    BOOST_CHECK(setRecarriedEquivocated.empty());
}

// The same rule, driven through the tracker: two sibling carriers, both valid.
BOOST_AUTO_TEST_CASE(note_vote_equivocation_leaves_both_carriers_valid)
{
    const int nEpoch = 4011;
    const CNoteFinalityVote voteA = MakeVote(nEpoch, uint256(0xaaaa), 0x41);
    CNoteFinalityVote voteB = MakeVote(nEpoch, uint256(0xbbbb), 0x41);
    voteB.vchTag = voteA.vchTag;
    const uint256 tag = voteA.GetVoteTag();
    const uint256 hashSiblingA(0x51510001);
    const uint256 hashSiblingB(0x51510002);

    CTxDB txdb("r+");
    FinalityResult result = FINALITY_RESULT_INVALID;
    BOOST_REQUIRE(g_finalityTracker.ConnectBlockNoteVotes(
        txdb, hashSiblingA, std::vector<CNoteFinalityVote>(1, voteA), CFinalityVoteContext::ChainHeight(6100), &result,
        false));
    BOOST_CHECK_EQUAL(result, FINALITY_RESULT_OK);
    BOOST_CHECK_EQUAL(g_finalityTracker.GetNoteVoteCountingState(nEpoch, tag),
                      NOTE_VOTE_COUNTED);

    // The sibling carrying the conflicting vote stays valid: an anonymous voter must
    // not be able to destroy another producer's block for the price of one note.
    result = FINALITY_RESULT_INVALID;
    BOOST_CHECK(g_finalityTracker.ConnectBlockNoteVotes(
        txdb, hashSiblingB, std::vector<CNoteFinalityVote>(1, voteB), CFinalityVoteContext::ChainHeight(6100), &result,
        false));
    BOOST_CHECK_EQUAL(result, FINALITY_RESULT_OK);
    BOOST_CHECK_EQUAL(g_finalityTracker.GetNoteVoteCountingState(nEpoch, tag),
                      NOTE_VOTE_EQUIVOCATED);
    BOOST_CHECK_EQUAL(g_finalityTracker.GetEpochNoteVoteCount(nEpoch), 0);
    BOOST_CHECK_EQUAL(g_finalityTracker.GetEpochEquivocatedNoteVoteCount(nEpoch), 1);

    // Disconnecting the conflicting carrier restores the surviving vote, so the drop is
    // reorg-symmetric rather than a permanent mark.
    BOOST_REQUIRE(g_finalityTracker.DisconnectBlockNoteVotes(
        txdb, hashSiblingB, std::vector<CNoteFinalityVote>(1, voteB)));
    BOOST_CHECK_EQUAL(g_finalityTracker.GetNoteVoteCountingState(nEpoch, tag),
                      NOTE_VOTE_COUNTED);
    BOOST_CHECK_EQUAL(g_finalityTracker.GetEpochNoteVoteCount(nEpoch), 1);

    BOOST_REQUIRE(g_finalityTracker.DisconnectBlockNoteVotes(
        txdb, hashSiblingA, std::vector<CNoteFinalityVote>(1, voteA)));
    BOOST_CHECK_EQUAL(g_finalityTracker.GetNoteVoteCountingState(nEpoch, tag),
                      NOTE_VOTE_UNSEEN);
}

// One vote carried by two connected siblings counts once, and survives losing one of them.
BOOST_AUTO_TEST_CASE(note_vote_recarry_counts_once_and_survives_one_carrier)
{
    const int nEpoch = 4012;
    const CNoteFinalityVote vote = MakeVote(nEpoch, uint256(0xcccc), 0x61);
    const uint256 tag = vote.GetVoteTag();
    const uint256 hashFirst(0x52520001);
    const uint256 hashSecond(0x52520002);
    const std::vector<CNoteFinalityVote> vVotes(1, vote);

    CTxDB txdb("r+");
    BOOST_REQUIRE(g_finalityTracker.ConnectBlockNoteVotes(
        txdb, hashFirst, vVotes, CFinalityVoteContext::ChainHeight(6100), NULL, false));
    BOOST_REQUIRE(g_finalityTracker.ConnectBlockNoteVotes(
        txdb, hashSecond, vVotes, CFinalityVoteContext::ChainHeight(6100), NULL, false));
    BOOST_CHECK_EQUAL(g_finalityTracker.GetEpochNoteVoteCount(nEpoch), 1);
    BOOST_CHECK_EQUAL(g_finalityTracker.GetCountedEpochNoteVotes(nEpoch).size(),
                      (size_t)1);

    BOOST_REQUIRE(g_finalityTracker.DisconnectBlockNoteVotes(txdb, hashFirst, vVotes));
    BOOST_CHECK_EQUAL(g_finalityTracker.GetNoteVoteCountingState(nEpoch, tag),
                      NOTE_VOTE_COUNTED);

    BOOST_REQUIRE(g_finalityTracker.DisconnectBlockNoteVotes(txdb, hashSecond, vVotes));
    BOOST_CHECK_EQUAL(g_finalityTracker.GetNoteVoteCountingState(nEpoch, tag),
                      NOTE_VOTE_UNSEEN);
}

// The per-block carrier cap is re-asserted for note envelopes.
BOOST_AUTO_TEST_CASE(note_vote_block_cap_is_enforced)
{
    const int nEpoch = 4013;
    std::vector<CNoteFinalityVote> vVotes;
    for (int i = 0; i <= FINALITY_MAX_BLOCK_NOTE_VOTES; i++)
        vVotes.push_back(MakeVote(nEpoch, uint256(0xdddd), (unsigned char)(0x80 + i)));
    BOOST_REQUIRE_EQUAL(vVotes.size(), (size_t)FINALITY_MAX_BLOCK_NOTE_VOTES + 1);

    CTxDB txdb("r+");
    const uint256 hashBlock(0x53530001);
    BOOST_CHECK(!g_finalityTracker.ConnectBlockNoteVotes(
        txdb, hashBlock, vVotes, CFinalityVoteContext::ChainHeight(6100), NULL, false));

    // The same block one vote lighter is accepted, so the cap is what rejected it.
    vVotes.pop_back();
    BOOST_REQUIRE(g_finalityTracker.ConnectBlockNoteVotes(
        txdb, hashBlock, vVotes, CFinalityVoteContext::ChainHeight(6100), NULL, false));
    BOOST_CHECK_EQUAL(g_finalityTracker.GetEpochNoteVoteCount(nEpoch),
                      FINALITY_MAX_BLOCK_NOTE_VOTES);
    BOOST_REQUIRE(g_finalityTracker.DisconnectBlockNoteVotes(txdb, hashBlock, vVotes));

    // A tag repeated inside one block is the producer's own doing and does invalidate it.
    std::vector<CNoteFinalityVote> vDuplicate;
    vDuplicate.push_back(vVotes[0]);
    vDuplicate.push_back(vVotes[0]);
    BOOST_CHECK(!g_finalityTracker.ConnectBlockNoteVotes(
        txdb, hashBlock, vDuplicate, CFinalityVoteContext::ChainHeight(6100), NULL, false));
}

// The epoch's canonical vote set is capped, and an equivocator must not be able to buy
// extra slots by conflicting itself: capacity counts every tag the epoch has seen.
BOOST_AUTO_TEST_CASE(note_vote_epoch_capacity_counts_dropped_tags)
{
    const int nEpoch = 4014;
    CTxDB txdb("r+");
    unsigned int nTagSeed = 0;
    auto makeTagged = [&](unsigned int nSeed) {
        CNoteFinalityVote vote = MakeVote(nEpoch, uint256(0xf00d), 0x01);
        vote.vchTag.assign(FINALITY_NOTE_POINT_SIZE, 0);
        vote.vchTag[0] = (unsigned char)(nSeed & 0xff);
        vote.vchTag[1] = (unsigned char)((nSeed >> 8) & 0xff);
        vote.vchTag[2] = 0xa5;   // an all-zero tag is not a tag
        return vote;
    };

    std::vector<std::pair<uint256, std::vector<CNoteFinalityVote> > > vCarriers;
    while (nTagSeed < FINALITY_MAX_EPOCH_NOTE_VOTES)
    {
        std::vector<CNoteFinalityVote> vBlockVotes;
        for (int i = 0; i < FINALITY_MAX_BLOCK_NOTE_VOTES &&
                        nTagSeed < FINALITY_MAX_EPOCH_NOTE_VOTES;
             i++, nTagSeed++)
            vBlockVotes.push_back(makeTagged(nTagSeed));
        const uint256 hashBlock(0x54540000 + (int)vCarriers.size());
        vCarriers.push_back(std::make_pair(hashBlock, vBlockVotes));
        BOOST_REQUIRE(g_finalityTracker.ConnectBlockNoteVotes(
            txdb, hashBlock, vBlockVotes, CFinalityVoteContext::ChainHeight(6100), NULL, false));
    }
    BOOST_CHECK_EQUAL(g_finalityTracker.GetEpochNoteVoteCount(nEpoch),
                      (int)FINALITY_MAX_EPOCH_NOTE_VOTES);

    const CNoteFinalityVote overflow = makeTagged(nTagSeed);
    BOOST_CHECK(!g_finalityTracker.ConnectBlockNoteVotes(
        txdb, uint256(0x54549999), std::vector<CNoteFinalityVote>(1, overflow), CFinalityVoteContext::ChainHeight(6100),
        NULL, false));

    for (size_t i = 0; i < vCarriers.size(); i++)
        BOOST_REQUIRE(g_finalityTracker.DisconnectBlockNoteVotes(
            txdb, vCarriers[i].first, vCarriers[i].second));
    BOOST_CHECK_EQUAL(g_finalityTracker.GetEpochNoteVoteCount(nEpoch), 0);
}
BOOST_AUTO_TEST_SUITE_END()
