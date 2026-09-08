// Tests for the note-vote block carrier and the consensus rules it ships with: the
// one-push coinbase envelope and its generational decode, the equivocation rule that
// drops a conflicting tag instead of the block carrying it, the per-block and per-epoch
// caps, and the minimum vote weight.

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

struct ScopedCarrierArgs
{
    std::map<std::string, std::string> mapArgsSaved;
    std::map<std::string, std::vector<std::string> > mapMultiArgsSaved;
    int nNoteVoteHeightSaved;

    ScopedCarrierArgs()
        : mapArgsSaved(mapArgs),
          mapMultiArgsSaved(mapMultiArgs),
          nNoteVoteHeightSaved(nRegtestIV5NoteVoteHeight)
    {
    }

    ~ScopedCarrierArgs()
    {
        mapArgs = mapArgsSaved;
        mapMultiArgs = mapMultiArgsSaved;
        nRegtestIV5NoteVoteHeight = nNoteVoteHeightSaved;
    }
};

PrivacyVNextDigest ZeroDigest()
{
    PrivacyVNextDigest out;
    out.fill(0);
    return out;
}

// The prover rejects an all-zero seed, so every proving call here supplies one.
PrivacyVNextDigest ProofEntropy(unsigned char nSeed)
{
    PrivacyVNextDigest out;
    out.fill(nSeed);
    return out;
}

uint256 RandomScalar()
{
    return Ed25519ScalarReduce(GetRandHash());
}

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

CFinalityTallyConfig MakeCarrierCommittee(std::vector<CKey>& vKeys, int nThreshold)
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
    return config;
}

std::vector<unsigned char> MakeMembershipRequest(const uint256& hashCurveRoot,
                                                 const PrivacyVNextDigest& cTilde,
                                                 size_t nProofBytes)
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
    const PrivacyVNextDigest oTilde = ZeroDigest();
    vch.insert(vch.end(), oTilde.begin(), oTilde.end());
    vch.insert(vch.end(), 64, 0);
    vch.insert(vch.end(), cTilde.begin(), cTilde.end());
    const uint32_t nProofLen = (uint32_t)nProofBytes;
    for (int i = 0; i < 4; i++)
        vch.push_back((unsigned char)((nProofLen >> (8 * i)) & 0xff));
    vch.insert(vch.end(), nProofBytes, 0x5a);
    return vch;
}

// A structurally complete vote. The sigma and membership bytes are filler because no
// test here reaches the proof verifiers; every rule under test is a carrier or
// bookkeeping rule that runs before them.
CNoteFinalityVote MakeCarrierVote(const CFinalityTallyConfig& config,
                                  int nEpoch,
                                  const uint256& hashBlock,
                                  unsigned char nTagSeed,
                                  size_t nMembershipProofBytes = 6656,
                                  int64_t nAmount = 500 * COIN)
{
    const uint256 maskTilde = RandomScalar();
    std::string strError;

    CNoteFinalityVote vote;
    vote.nEpoch = nEpoch;
    vote.hashBlock = hashBlock;
    vote.nHeight = 6000 + nEpoch;
    vote.hashCurveRoot = uint256(0x4321);
    vote.hashNullifierRoot = uint256(0x8765);
    vote.committeeSetHash = config.committeeSetHash;
    vote.vchMembership = MakeMembershipRequest(
        vote.hashCurveRoot, CommitPoint(Ed25519ScalarFromInt64(nAmount), maskTilde),
        nMembershipProofBytes);
    vote.vchTag.assign(FINALITY_NOTE_POINT_SIZE, nTagSeed);
    vote.vchSigma.assign(FINALITY_NOTE_SIGMA_SIZE, 0x11);
    BOOST_REQUIRE_MESSAGE(
        BuildNoteVoteWeightFloorProof(nAmount, vote.nHeight, maskTilde,
                                      ProofEntropy(0x91),
                                      vote.vchWeightFloorProof, &strError),
        strError);
    BOOST_REQUIRE_MESSAGE(vote.IsValidBasic(&strError), strError);
    return vote;
}

// True when the script is OP_RETURN followed by exactly one PUSHDATA2 push that runs to
// the end. CScript::GetOp cannot be used here: it refuses any push over
// MAX_SCRIPT_ELEMENT_SIZE, which is why the finality extractors read the push themselves.
bool IsSingleOpReturnPushData2(const CScript& script, size_t& nPushedOut)
{
    nPushedOut = 0;
    if (script.size() < 4 || script[0] != OP_RETURN || script[1] != OP_PUSHDATA2)
        return false;
    const size_t nSize = (size_t)script[2] | ((size_t)script[3] << 8);
    if (script.size() != 4 + nSize)
        return false;
    nPushedOut = nSize;
    return true;
}

} // namespace

BOOST_AUTO_TEST_SUITE(finality_note_carrier_tests)

// A working-size note vote is one push in one output. The 520-byte element cap binds
// executed scripts only, so nothing forces the envelope to be split.
BOOST_AUTO_TEST_CASE(note_vote_is_one_push_in_one_output)
{
    ScopedCarrierArgs scoped;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeCarrierCommittee(vKeys, 2);

    const CNoteFinalityVote vote = MakeCarrierVote(config, 11, uint256(0xa1), 0x21);
    const size_t nEnvelope =
        ::GetSerializeSize(vote, SER_NETWORK, PROTOCOL_VERSION);
    // Membership proof plus tag, sigma and the floor proof; the Shamir share and the
    // reward commitment the F2 vote used to carry are gone.
    BOOST_CHECK_GT(nEnvelope, (size_t)7000);
    BOOST_CHECK_LT(nEnvelope, (size_t)MAX_SCRIPT_SIZE - 4);

    CScript script;
    BOOST_REQUIRE(BuildNoteFinalityVoteScript(vote, script));
    BOOST_CHECK_LE(script.size(), (size_t)MAX_SCRIPT_SIZE);
    size_t nPushed = 0;
    BOOST_CHECK(IsSingleOpReturnPushData2(script, nPushed));
    BOOST_CHECK_EQUAL(nPushed, nEnvelope + 4);
    BOOST_CHECK_GT(nPushed, (size_t)MAX_SCRIPT_ELEMENT_SIZE);

    CNoteFinalityVote decoded;
    BOOST_REQUIRE(ExtractNoteFinalityVote(script, decoded));
    BOOST_CHECK(decoded.GetHash() == vote.GetHash());
}

// One byte past the script budget has to fail at build time rather than produce a
// carrier no node will accept.
BOOST_AUTO_TEST_CASE(note_vote_over_the_script_budget_fails_to_build)
{
    ScopedCarrierArgs scoped;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeCarrierCommittee(vKeys, 2);

    // Grow the membership blob until the envelope lands exactly on the budget, then add
    // one byte. The length prefixes move with the blob, so the size is converged on
    // rather than computed.
    const size_t nBudget = (size_t)MAX_SCRIPT_SIZE - 8;
    size_t nProofBytes = 8000;
    CNoteFinalityVote atBudget = MakeCarrierVote(config, 11, uint256(0xa1), 0x21, 64);
    for (int i = 0; i < 8; i++)
    {
        atBudget = MakeCarrierVote(config, 11, uint256(0xa1), 0x21, nProofBytes);
        const size_t nSize = ::GetSerializeSize(atBudget, SER_NETWORK, PROTOCOL_VERSION);
        if (nSize == nBudget)
            break;
        BOOST_REQUIRE_GT(nProofBytes + nBudget, nSize);
        nProofBytes = nProofBytes + nBudget - nSize;
    }
    BOOST_REQUIRE_EQUAL(::GetSerializeSize(atBudget, SER_NETWORK, PROTOCOL_VERSION),
                        nBudget);
    CScript script;
    BOOST_CHECK(BuildNoteFinalityVoteScript(atBudget, script));
    BOOST_CHECK_EQUAL(script.size(), (size_t)MAX_SCRIPT_SIZE);

    CNoteFinalityVote overBudget =
        MakeCarrierVote(config, 11, uint256(0xa1), 0x21, nProofBytes + 1);
    BOOST_REQUIRE_EQUAL(::GetSerializeSize(overBudget, SER_NETWORK, PROTOCOL_VERSION),
                        nBudget + 1);
    CScript overScript;
    BOOST_CHECK(!BuildNoteFinalityVoteScript(overBudget, overScript));
    BOOST_CHECK(overScript.empty());
}

// The tag is unknown data before the fork and must decode or invalidate after it.
BOOST_AUTO_TEST_CASE(note_vote_decode_is_generational)
{
    ScopedCarrierArgs scoped;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeCarrierCommittee(vKeys, 2);
    const CNoteFinalityVote vote = MakeCarrierVote(config, 11, uint256(0xa1), 0x21);

    CScript script;
    BOOST_REQUIRE(BuildNoteFinalityVoteScript(vote, script));

    nRegtestIV5NoteVoteHeight = 500;
    CNoteFinalityVote decoded;
    BOOST_CHECK_EQUAL(ExtractNoteFinalityVoteForHeight(script, 499, decoded),
                      FINALITY_ENVELOPE_NO_MATCH);
    BOOST_CHECK_EQUAL(ExtractNoteFinalityVoteForHeight(script, 500, decoded),
                      FINALITY_ENVELOPE_VALID);

    // A tagged script that does not decode is a block-invalidating carrier after the
    // fork: treating it as absent would let two nodes disagree on what the block carried.
    CScript truncated(script.begin(), script.begin() + script.size() - 32);
    CNoteFinalityVote ignored;
    BOOST_CHECK_EQUAL(ExtractNoteFinalityVoteForHeight(truncated, 500, ignored),
                      FINALITY_ENVELOPE_NO_MATCH);   // length prefix no longer matches

    // Correct tag, payload that does not deserialize: a carrier every node has to
    // agree is broken, so it invalidates rather than being read as absent.
    std::vector<unsigned char> vPayload(script.begin() + 4, script.end());
    std::vector<unsigned char> vShort(vPayload.begin(), vPayload.begin() + 200);
    CScript shortPayload;
    shortPayload << OP_RETURN << vShort;
    BOOST_CHECK_EQUAL(ExtractNoteFinalityVoteForHeight(shortPayload, 500, ignored),
                      FINALITY_ENVELOPE_INVALID);

    // Same payload, wrong tag, and the same payload split across two pushes.
    std::vector<unsigned char> vWrongTag;
    vWrongTag.insert(vWrongTag.end(), FINALITY_CANONICAL_VOTE_TAG,
                     FINALITY_CANONICAL_VOTE_TAG + 4);
    vWrongTag.insert(vWrongTag.end(), vPayload.begin() + 4, vPayload.end());
    CScript wrongTag;
    wrongTag << OP_RETURN << vWrongTag;
    BOOST_CHECK_EQUAL(ExtractNoteFinalityVoteForHeight(wrongTag, 500, ignored),
                      FINALITY_ENVELOPE_NO_MATCH);

    std::vector<unsigned char> vHead;
    vHead.insert(vHead.end(), FINALITY_NOTE_VOTE_TAG, FINALITY_NOTE_VOTE_TAG + 4);
    vHead.insert(vHead.end(), vPayload.begin(), vPayload.begin() + 100);
    CScript multiPush;
    multiPush << OP_RETURN << vHead
              << std::vector<unsigned char>(vPayload.begin() + 100, vPayload.end());
    BOOST_CHECK_EQUAL(ExtractNoteFinalityVoteForHeight(multiPush, 500, ignored),
                      FINALITY_ENVELOPE_NO_MATCH);
}

// A conflicting tag is resolved by dropping the tag, never the carrier. The outcome is
// a pure function of the carried set, so connect order cannot change it.
BOOST_AUTO_TEST_CASE(note_vote_equivocation_counts_for_neither)
{
    ScopedCarrierArgs scoped;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeCarrierCommittee(vKeys, 2);

    const CNoteFinalityVote voteA = MakeCarrierVote(config, 11, uint256(0xaaaa), 0x31);
    CNoteFinalityVote voteB = MakeCarrierVote(config, 11, uint256(0xbbbb), 0x31);
    voteB.vchTag = voteA.vchTag;
    const CNoteFinalityVote voteOther = MakeCarrierVote(config, 11, uint256(0xaaaa), 0x32);
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

    // Proof bytes are outside the semantic identity, so a peer that re-randomizes a
    // relayed vote cannot manufacture an equivocation out of it.
    CNoteFinalityVote reencoded = voteA;
    reencoded.vchSigma.assign(FINALITY_NOTE_SIGMA_SIZE, 0x22);
    BOOST_CHECK(reencoded.GetHash() != voteA.GetHash());
    BOOST_CHECK(GetNoteVoteSemanticIdentity(reencoded) ==
                GetNoteVoteSemanticIdentity(voteA));
}

// The same rule, driven through the tracker: two sibling carriers, both valid.
BOOST_AUTO_TEST_CASE(note_vote_equivocation_leaves_both_carriers_valid)
{
    ScopedCarrierArgs scoped;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeCarrierCommittee(vKeys, 2);

    const int nEpoch = 4011;
    const CNoteFinalityVote voteA = MakeCarrierVote(config, nEpoch, uint256(0xaaaa), 0x41);
    CNoteFinalityVote voteB = MakeCarrierVote(config, nEpoch, uint256(0xbbbb), 0x41);
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
    ScopedCarrierArgs scoped;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeCarrierCommittee(vKeys, 2);

    const int nEpoch = 4012;
    const CNoteFinalityVote vote = MakeCarrierVote(config, nEpoch, uint256(0xcccc), 0x61);
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
    ScopedCarrierArgs scoped;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeCarrierCommittee(vKeys, 2);

    const int nEpoch = 4013;
    std::vector<CNoteFinalityVote> vVotes;
    for (int i = 0; i <= FINALITY_MAX_BLOCK_NOTE_VOTES; i++)
        vVotes.push_back(MakeCarrierVote(config, nEpoch, uint256(0xdddd),
                                         (unsigned char)(0x80 + i), 64));
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
    ScopedCarrierArgs scoped;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeCarrierCommittee(vKeys, 2);

    const int nEpoch = 4014;
    CTxDB txdb("r+");
    unsigned int nTagSeed = 0;
    auto makeTagged = [&](unsigned int nSeed) {
        CNoteFinalityVote vote = MakeCarrierVote(config, nEpoch, uint256(0xf00d), 0x01, 64);
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

// The floor proof is over C~ - W_min*H, recomputed by the verifier from the vote's own
// commitment at the vote's own height. A weight under that height's floor has no in-range
// opening of the point.
BOOST_AUTO_TEST_CASE(note_vote_weight_floor_is_unconstructible_below_the_floor)
{
    const int nHeight = 6000;
    const int64_t nFloor = GetFinalityMinVoteWeight(nHeight);
    const uint256 mask = RandomScalar();
    std::vector<unsigned char> vchProof;
    std::string strError;

    BOOST_CHECK(BuildNoteVoteWeightFloorProof(nFloor, nHeight, mask,
                                              ProofEntropy(0x92), vchProof, &strError));
    BOOST_CHECK(!vchProof.empty());

    vchProof.clear();
    BOOST_CHECK(!BuildNoteVoteWeightFloorProof(nFloor - 1, nHeight, mask,
                                               ProofEntropy(0x92), vchProof, &strError));
    BOOST_CHECK(vchProof.empty());
    BOOST_CHECK(!BuildNoteVoteWeightFloorProof(0, nHeight, mask, ProofEntropy(0x92),
                                               vchProof, &strError));
    BOOST_CHECK(!BuildNoteVoteWeightFloorProof(-1, nHeight, mask, ProofEntropy(0x92),
                                               vchProof, &strError));
}

// The verifier never accepts a supplied commitment point: a proof over C~ itself, which
// any honest note could produce, must not satisfy the floor.
BOOST_AUTO_TEST_CASE(note_vote_weight_floor_rejects_a_supplied_commitment_point)
{
    ScopedCarrierArgs scoped;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeCarrierCommittee(vKeys, 2);

    const int64_t nDust = 1;
    const uint256 maskTilde = RandomScalar();
    const PrivacyVNextDigest cTilde =
        CommitPoint(Ed25519ScalarFromInt64(nDust), maskTilde);

    // A dust note range-proving its own commitment: valid over C~, useless over the
    // shifted point the verifier derives.
    PrivacyVNextDigest provedOver = ZeroDigest();
    std::vector<unsigned char> vchDustProof;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        ProvePrivacyVNextRange((uint64_t)nDust, Ed25519ScalarToDigest(maskTilde),
                               ProofEntropy(0x93), provedOver, vchDustProof, error),
        error);
    BOOST_CHECK(provedOver == cTilde);
    BOOST_CHECK(VerifyPrivacyVNextRange(cTilde, ZeroDigest(), vchDustProof, error));

    PrivacyVNextDigest floorPoint = ZeroDigest();
    BOOST_REQUIRE(DeriveNoteVoteWeightFloorPoint(cTilde, 6012, floorPoint));
    BOOST_CHECK(floorPoint != cTilde);
    BOOST_CHECK(!VerifyPrivacyVNextRange(floorPoint, ZeroDigest(), vchDustProof, error));

    std::string strError;

    CNoteFinalityVote vote;
    vote.nEpoch = 12;
    vote.hashBlock = uint256(0xeeee);
    vote.nHeight = 6012;
    vote.hashCurveRoot = uint256(0x4321);
    vote.hashNullifierRoot = uint256(0x8765);
    vote.committeeSetHash = config.committeeSetHash;
    vote.vchMembership = MakeMembershipRequest(vote.hashCurveRoot, cTilde, 64);
    vote.vchTag.assign(FINALITY_NOTE_POINT_SIZE, 0x71);
    vote.vchSigma.assign(FINALITY_NOTE_SIGMA_SIZE, 0x11);
    vote.vchWeightFloorProof = vchDustProof;
    BOOST_REQUIRE(vote.IsValidBasic(&strError));
    BOOST_CHECK(!CheckNoteVoteWeightFloorProof(vote, &strError));
    BOOST_CHECK_EQUAL(strError, "note vote does not reach the minimum vote weight");

    // The same vote with a real floor proof passes, so the floor check is what failed.
    const int64_t nAtFloor = GetFinalityMinVoteWeight(vote.nHeight);
    const uint256 maskAtFloor = RandomScalar();
    CNoteFinalityVote funded = vote;
    funded.vchMembership = MakeMembershipRequest(
        funded.hashCurveRoot,
        CommitPoint(Ed25519ScalarFromInt64(nAtFloor), maskAtFloor), 64);
    BOOST_REQUIRE(BuildNoteVoteWeightFloorProof(nAtFloor, funded.nHeight, maskAtFloor,
                                                ProofEntropy(0x94),
                                                funded.vchWeightFloorProof, &strError));
    BOOST_CHECK(CheckNoteVoteWeightFloorProof(funded, &strError));
}

// The floor proof is inside the vote's sigma binding, so it cannot be swapped for
// another proof over the same point to mint a second object under one tag.
BOOST_AUTO_TEST_CASE(note_vote_binding_covers_the_weight_floor_proof)
{
    ScopedCarrierArgs scoped;
    std::vector<CKey> vKeys(3);
    const CFinalityTallyConfig config = MakeCarrierCommittee(vKeys, 2);

    const CNoteFinalityVote vote = MakeCarrierVote(config, 13, uint256(0xffff), 0x81, 64);
    CNoteFinalityVote reproved = vote;
    reproved.vchWeightFloorProof[0] ^= 0x01;
    BOOST_CHECK(ComputeNoteVoteBinding(reproved) != ComputeNoteVoteBinding(vote));
}

// Carrying a full block of note votes is economically indifferent for the producer at
// the working envelope size, and the miner's own byte accounting is what bounds the
// oversized case rather than a surprise penalty.
BOOST_AUTO_TEST_CASE(note_vote_carriage_is_penalty_free_at_the_generation_target)
{
    // Upper bound on the working size of a note-vote carrier script. The envelope this
    // suite builds is smaller since the share came out, so this stays conservative;
    // raise it with the prover, never to make a failing case pass.
    const unsigned int nCarrier = 8400;
    const unsigned int nOrdinaryTraffic = 30000;
    const unsigned int nMedian = ADAPTIVE_BLOCK_FLOOR;

    const unsigned int nFullVoteBlock =
        (unsigned int)FINALITY_MAX_BLOCK_NOTE_VOTES * nCarrier + nOrdinaryTraffic;
    BOOST_CHECK_LE(nFullVoteBlock, nMedian);
    BOOST_CHECK_EQUAL(GetBlockSizePenalty(nFullVoteBlock, nMedian), 0);

    // A producer that raises its own target past the median self-prices; the same
    // penalty the validator recomputes is the one the miner applied.
    BOOST_CHECK_GT(GetBlockSizePenalty(nMedian + nMedian / 10, nMedian), 0);
    BOOST_CHECK_GT(GetBlockSizePenalty(
                       (unsigned int)FINALITY_MAX_BLOCK_NOTE_VOTES * MAX_SCRIPT_SIZE,
                       nMedian),
                   0);
}

BOOST_AUTO_TEST_SUITE_END()
