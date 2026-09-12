// The v2008 mix round's rules: who may say what, when, and under which identity.

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

#include "../key.h"
#include "../nullsend.h"
#include "../nullsend_v2008.h"
#include "../privacy_vnext/iv5_protocol.h"
#include "../privacy_vnext_ffi.h"

extern bool fRegTest;

namespace {

// One RSA key for the suite: generating a 2048-bit key per case buys nothing and
// costs seconds.
CNullSendSession& Coordinator()
{
    static CNullSendSession session;
    static bool fKeyed = false;
    if (!fKeyed)
    {
        session.nSessionID = 11;
        BOOST_REQUIRE(session.GenerateSessionRSAKey());
        fKeyed = true;
    }
    return session;
}

// A token a participant would hold after the blind-signature exchange. The value
// varies so two tokens are never the same credential.
struct Token
{
    std::vector<unsigned char> vchCredential;
    std::vector<unsigned char> vchSignature;
};

Token MintToken(int64_t nValue)
{
    CNullSendSession& server = Coordinator();
    CNullSendClient client;
    client.vMyOutputsDeferred.push_back(CShieldedOutputDescription());
    client.nMyOutputValue = nValue;
    BOOST_REQUIRE(client.BlindOutputCredential(server.vchRSA_N, server.vchRSA_E));
    std::vector<unsigned char> vchBlindSig;
    BOOST_REQUIRE(server.BlindSign(client.vchBlindedCredential, vchBlindSig));
    BOOST_REQUIRE(client.UnblindSignature(vchBlindSig));
    Token token;
    token.vchCredential = client.vchCredentialHash;
    token.vchSignature = client.vchUnblindedSig;
    return token;
}

struct Seat
{
    CKey key;
    CPubKey pubkey;
    uint256 keyImage;
};

Seat MakeSeat(unsigned int nImage)
{
    Seat seat;
    seat.key.MakeNewKey(true);
    seat.pubkey = seat.key.GetPubKey();
    seat.keyImage = uint256(nImage);
    return seat;
}

// A round opened with isolation, filled to nSeats, with the input set frozen.
bool OpenAndFill(CMixRound& round, std::vector<Seat>& vSeats, int nSeats, int64_t nNow)
{
    CNullSendSession& server = Coordinator();
    std::string strError;
    if (!round.Open(uint256(0xBEEF), nSeats, server.vchRSA_N, server.vchRSA_E,
                    true, false, nNow, &strError))
    {
        BOOST_ERROR("round did not open: " << strError);
        return false;
    }
    for (int i = 0; i < nSeats; i++)
    {
        // Descending key images, so a sorted final set is not just arrival order.
        vSeats.push_back(MakeSeat((unsigned int)(100 - i)));
        if (!round.Join(vSeats.back().pubkey, vSeats.back().keyImage, &strError))
        {
            BOOST_ERROR("join refused: " << strError);
            return false;
        }
    }
    return true;
}

// -- A mix instance whose shares really open, for the joint signature ----------
// Each share states pseudo_out - output - fee_share*H == mask*G, so zero output masks
// make share mask == pseudo-output mask.

PrivacyVNextDigest ScalarOf(uint64_t n)
{
    PrivacyVNextDigest d;
    d.fill(0);
    for (int i = 0; i < 8; i++)
        d[i] = (unsigned char)((n >> (8 * i)) & 0xFF);
    return d;
}

PrivacyVNextDigest MaskOf(unsigned char ch)
{
    PrivacyVNextDigest d;
    d.fill(0);
    d[0] = ch;
    d[1] = 0x11;
    return d;
}

// amount*H + mask*G.
PrivacyVNextDigest Commit(uint64_t nAmount, const PrivacyVNextDigest& mask)
{
    std::vector<PrivacyVNextCombineTerm> vTerms(2);
    vTerms[0].nSource = PRIVACY_VNEXT_TERM_MONERO_H;
    vTerms[0].scalar = ScalarOf(nAmount);
    vTerms[1].nSource = PRIVACY_VNEXT_TERM_ED25519_G;
    vTerms[1].scalar = mask;
    PrivacyVNextDigest point;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(CombinePrivacyVNextPoints(vTerms, point, strError), strError);
    return point;
}

// A two-seat mix: each spends nInput and creates nInput - nFeeShare, so the fee is the
// sum of the shares and the transparent value balance is zero.
struct MixInstance
{
    PrivacyVNextMixBalanceFacts facts;
    std::vector<PrivacyVNextMixBalanceShare> vShares;
};

MixInstance BuildInstance(unsigned char chEntropy, uint64_t nFeeShare = 7)
{
    const uint64_t nInput = 1000;
    MixInstance mix;
    mix.facts.nInputCount = 2;
    mix.facts.nOutputCount = 2;
    mix.facts.nTransparentValueBalance = 0;
    mix.facts.nFee = 2 * nFeeShare;
    mix.facts.signableHash.fill(0x5c);
    for (int i = 0; i < 2; i++)
    {
        const PrivacyVNextDigest mask = MaskOf((unsigned char)(0x21 + i));
        mix.facts.vPseudoOuts.push_back(Commit(nInput, mask));
        // Output mask zero, so the share mask is the pseudo-output's.
        PrivacyVNextDigest zero;
        zero.fill(0);
        mix.facts.vOutputs.push_back(Commit(nInput - nFeeShare, zero));

        PrivacyVNextMixBalanceShare share;
        share.nInputIndex = (uint8_t)i;
        share.nOutputIndex = (uint8_t)i;
        share.nFeeShare = nFeeShare;
        share.mask = mask;
        // Fresh per signing attempt: derived entropy would repeat a nonce across a
        // restart, and the guard that refuses a second aggregate is process state a
        // restart clears.
        share.entropy.fill(chEntropy);
        share.entropy[31] = (unsigned char)i;
        mix.vShares.push_back(share);
    }
    return mix;
}

} // namespace

BOOST_AUTO_TEST_SUITE(nullsend_round_tests)

BOOST_AUTO_TEST_CASE(a_round_runs_from_join_to_publish)
{
    const int64_t nNow = 1000000;
    CMixRound round;
    std::vector<Seat> vSeats;
    BOOST_REQUIRE(OpenAndFill(round, vSeats, 3, nNow));
    BOOST_CHECK_EQUAL((int)round.Phase(), (int)MIX_PHASE_JOIN);

    std::string strError;
    BOOST_REQUIRE_MESSAGE(round.CloseJoin(nNow, &strError), strError);
    BOOST_CHECK_EQUAL((int)round.Phase(), (int)MIX_PHASE_KEYED);
    for (size_t i = 0; i < vSeats.size(); i++)
        BOOST_REQUIRE_MESSAGE(round.IssueToken(vSeats[i].pubkey, &strError), strError);
    BOOST_REQUIRE_MESSAGE(round.OpenOutputWindow(nNow, &strError), strError);
    BOOST_CHECK_EQUAL((int)round.Phase(), (int)MIX_PHASE_OUTPUT);

    for (int i = 0; i < 3; i++)
    {
        const Token token = MintToken(1000 + i);
        BOOST_REQUIRE_MESSAGE(round.RegisterOutput(token.vchCredential, token.vchSignature,
                                                   uint256(500 + i), nNow + 1, &strError),
                              strError);
    }
    BOOST_CHECK_EQUAL(round.Outputs(), 3u);
    BOOST_CHECK(round.CanPublish(nNow + MIX_OUTPUT_WINDOW + 1));
}

// The one that carries the unlinkability. An output is presented with a token and
// nothing else: RegisterOutput cannot see a session key, so there is no call the
// coordinator could make that names which seat an output came from.
BOOST_AUTO_TEST_CASE(an_output_is_registered_against_a_token_not_a_seat)
{
    const int64_t nNow = 2000000;
    CMixRound round;
    std::vector<Seat> vSeats;
    BOOST_REQUIRE(OpenAndFill(round, vSeats, 2, nNow));
    std::string strError;
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    BOOST_REQUIRE(round.IssueToken(vSeats[0].pubkey, &strError));
    BOOST_REQUIRE(round.IssueToken(vSeats[1].pubkey, &strError));
    BOOST_REQUIRE(round.OpenOutputWindow(nNow, &strError));

    // Any valid token registers any output. That is the property, not a gap: if the
    // round could tell which seat a token came from, the blind signature would be
    // doing nothing.
    const Token first = MintToken(2001);
    BOOST_REQUIRE(round.RegisterOutput(first.vchCredential, first.vchSignature,
                                       uint256(900), nNow, &strError));

    // One token, once. Nothing else limits an unlinkable caller.
    BOOST_CHECK_MESSAGE(!round.RegisterOutput(first.vchCredential, first.vchSignature,
                                              uint256(901), nNow, &strError),
                        "a token registered a second output");
    BOOST_CHECK(strError.find("already registered") != std::string::npos);

    // A token the round's key did not sign is refused.
    CNullSendSession stranger;
    stranger.nSessionID = 99;
    BOOST_REQUIRE(stranger.GenerateSessionRSAKey());
    CNullSendClient outsider;
    outsider.vMyOutputsDeferred.push_back(CShieldedOutputDescription());
    outsider.nMyOutputValue = 2002;
    BOOST_REQUIRE(outsider.BlindOutputCredential(stranger.vchRSA_N, stranger.vchRSA_E));
    std::vector<unsigned char> vchForeignBlindSig;
    BOOST_REQUIRE(stranger.BlindSign(outsider.vchBlindedCredential, vchForeignBlindSig));
    BOOST_REQUIRE(outsider.UnblindSignature(vchForeignBlindSig));
    BOOST_CHECK_MESSAGE(!round.RegisterOutput(outsider.vchCredentialHash,
                                              outsider.vchUnblindedSig,
                                              uint256(902), nNow, &strError),
                        "a token from another round's key was accepted");

    // And no more outputs than seats, whatever the tokens say.
    const Token second = MintToken(2003);
    BOOST_REQUIRE(round.RegisterOutput(second.vchCredential, second.vchSignature,
                                       uint256(903), nNow, &strError));
    const Token third = MintToken(2004);
    BOOST_CHECK_MESSAGE(!round.RegisterOutput(third.vchCredential, third.vchSignature,
                                              uint256(904), nNow, &strError),
                        "a third output landed in a two-seat round");
}

// The self-pay index binds the sorted key image set, so a seat lost after the set is
// frozen re-points every participant's output. The round ends rather than building a
// payload whose outputs sit at an index nobody derived.
BOOST_AUTO_TEST_CASE(a_seat_lost_after_the_set_is_frozen_aborts_the_round)
{
    const int64_t nNow = 3000000;
    std::string strError;

    // Before the freeze it is an ordinary withdrawal.
    CMixRound joining;
    std::vector<Seat> vJoining;
    BOOST_REQUIRE(OpenAndFill(joining, vJoining, 3, nNow));
    joining.Drop(vJoining[1].pubkey);
    BOOST_CHECK_EQUAL((int)joining.Phase(), (int)MIX_PHASE_JOIN);
    BOOST_CHECK_EQUAL(joining.Seats(), 2u);
    // And the round will not close short: the index binds the seats it announced.
    BOOST_CHECK(!joining.CloseJoin(nNow, &strError));

    CMixRound frozen;
    std::vector<Seat> vFrozen;
    BOOST_REQUIRE(OpenAndFill(frozen, vFrozen, 3, nNow));
    BOOST_REQUIRE(frozen.CloseJoin(nNow, &strError));
    frozen.Drop(vFrozen[1].pubkey);
    BOOST_CHECK_MESSAGE(frozen.Phase() == MIX_PHASE_ABORTED,
                        "a seat vanished after the freeze and the round carried on, so "
                        "every output would sit at an index nobody derived");
    BOOST_CHECK(frozen.AbortReason().find("frozen") != std::string::npos);
}

// Two coordinators reading the same seats must reach the same index, so the frozen
// set is sorted rather than left in arrival order, and nothing joins after.
BOOST_AUTO_TEST_CASE(the_input_set_is_frozen_and_sorted)
{
    const int64_t nNow = 4000000;
    CMixRound round;
    std::vector<Seat> vSeats;
    BOOST_REQUIRE(OpenAndFill(round, vSeats, 3, nNow));
    BOOST_CHECK(round.FinalKeyImages().empty());

    std::string strError;
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    const std::vector<uint256>& vFinal = round.FinalKeyImages();
    BOOST_REQUIRE_EQUAL(vFinal.size(), 3u);
    for (size_t i = 1; i < vFinal.size(); i++)
        BOOST_CHECK_MESSAGE(vFinal[i - 1] < vFinal[i],
                            "the frozen set is in arrival order, so two coordinators "
                            "reading the same seats derive different indexes");

    const Seat late = MakeSeat(7);
    BOOST_CHECK(!round.Join(late.pubkey, late.keyImage, &strError));
}

// Without stream isolation the coordinator sees the participant's real address at
// every phase. A feature that silently degrades is worse than an absent one.
BOOST_AUTO_TEST_CASE(a_round_without_stream_isolation_does_not_open)
{
    CNullSendSession& server = Coordinator();
    std::string strError;

    CMixRound refused;
    BOOST_CHECK_MESSAGE(!refused.Open(uint256(1), 3, server.vchRSA_N, server.vchRSA_E,
                                      false, false, 5000000, &strError),
                        "a round opened with no stream isolation and no override");
    BOOST_CHECK(strError.find("isolation") != std::string::npos);
    BOOST_CHECK_EQUAL((int)refused.Phase(), (int)MIX_PHASE_ABORTED);

    // The operator may say so, and then it opens.
    CMixRound overridden;
    BOOST_CHECK(overridden.Open(uint256(1), 3, server.vchRSA_N, server.vchRSA_E,
                                false, true, 5000000, &strError));
    BOOST_CHECK_EQUAL((int)overridden.Phase(), (int)MIX_PHASE_JOIN);
}

BOOST_AUTO_TEST_CASE(a_seat_is_one_session_key_and_one_note)
{
    const int64_t nNow = 6000000;
    CNullSendSession& server = Coordinator();
    CMixRound round;
    std::string strError;
    BOOST_REQUIRE(round.Open(uint256(2), 3, server.vchRSA_N, server.vchRSA_E,
                             true, false, nNow, &strError));

    const Seat a = MakeSeat(10);
    const Seat b = MakeSeat(11);
    BOOST_REQUIRE(round.Join(a.pubkey, a.keyImage, &strError));

    BOOST_CHECK_MESSAGE(!round.Join(a.pubkey, b.keyImage, &strError),
                        "one session key took two seats, so one participant claims two outputs");
    BOOST_CHECK_MESSAGE(!round.Join(b.pubkey, a.keyImage, &strError),
                        "one note took two seats");

    BOOST_REQUIRE(round.Join(b.pubkey, b.keyImage, &strError));
    const Seat c = MakeSeat(12);
    BOOST_REQUIRE(round.Join(c.pubkey, c.keyImage, &strError));
    const Seat d = MakeSeat(13);
    BOOST_CHECK(!round.Join(d.pubkey, d.keyImage, &strError));

    // One token per seat: two tokens is two outputs.
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    BOOST_REQUIRE(round.IssueToken(a.pubkey, &strError));
    BOOST_CHECK_MESSAGE(!round.IssueToken(a.pubkey, &strError),
                        "a seat took a second token");
    BOOST_CHECK(!round.IssueToken(d.pubkey, &strError));

    // And the window does not open while a seat holds no token, which would leave it
    // unable to register the output the round is waiting for.
    BOOST_CHECK(!round.OpenOutputWindow(nNow, &strError));
    BOOST_REQUIRE(round.IssueToken(b.pubkey, &strError));
    BOOST_REQUIRE(round.IssueToken(c.pubkey, &strError));
    BOOST_CHECK(round.OpenOutputWindow(nNow, &strError));
}

// The window is what decorrelates arrival order from registration order. Publishing
// when the last output lands throws that away, so it waits even when the round is
// otherwise finished.
BOOST_AUTO_TEST_CASE(nothing_publishes_before_the_window_closes)
{
    const int64_t nNow = 7000000;
    CMixRound round;
    std::vector<Seat> vSeats;
    BOOST_REQUIRE(OpenAndFill(round, vSeats, 2, nNow));
    std::string strError;
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    BOOST_REQUIRE(round.IssueToken(vSeats[0].pubkey, &strError));
    BOOST_REQUIRE(round.IssueToken(vSeats[1].pubkey, &strError));
    BOOST_REQUIRE(round.OpenOutputWindow(nNow, &strError));

    const Token first = MintToken(7001);
    BOOST_REQUIRE(round.RegisterOutput(first.vchCredential, first.vchSignature,
                                       uint256(800), nNow, &strError));
    BOOST_CHECK(!round.CanPublish(nNow + 1));
    const Token second = MintToken(7002);
    BOOST_REQUIRE(round.RegisterOutput(second.vchCredential, second.vchSignature,
                                       uint256(801), nNow + 1, &strError));

    BOOST_CHECK_MESSAGE(!round.CanPublish(nNow + 2),
                        "the round published as soon as the last output arrived, so the "
                        "two lists are in the same order");
    BOOST_CHECK(!round.CanPublish(nNow + MIX_OUTPUT_WINDOW));
    BOOST_CHECK(round.CanPublish(nNow + MIX_OUTPUT_WINDOW + 1));

    // A late output is refused rather than reopening the window.
    const Token late = MintToken(7003);
    BOOST_CHECK(!round.RegisterOutput(late.vchCredential, late.vchSignature,
                                      uint256(802), nNow + MIX_OUTPUT_WINDOW + 1, &strError));
}

// A phase is reached by passing through the one before it.
BOOST_AUTO_TEST_CASE(the_phases_run_in_order)
{
    const int64_t nNow = 8000000;
    CMixRound round;
    std::vector<Seat> vSeats;
    BOOST_REQUIRE(OpenAndFill(round, vSeats, 2, nNow));
    std::string strError;

    const Token early = MintToken(8001);
    BOOST_CHECK(!round.RegisterOutput(early.vchCredential, early.vchSignature,
                                      uint256(1), nNow, &strError));
    BOOST_CHECK(!round.OpenOutputWindow(nNow, &strError));
    BOOST_CHECK(!round.IssueToken(vSeats[0].pubkey, &strError));

    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    BOOST_CHECK(!round.CloseJoin(nNow, &strError));
    BOOST_CHECK(!round.RegisterOutput(early.vchCredential, early.vchSignature,
                                      uint256(1), nNow, &strError));

    // An aborted round accepts nothing further.
    round.Abort("operator stopped it");
    BOOST_CHECK(!round.IssueToken(vSeats[0].pubkey, &strError));
    BOOST_CHECK(!round.OpenOutputWindow(nNow, &strError));
    BOOST_CHECK(!round.CanPublish(nNow + MIX_OUTPUT_WINDOW + 1));
}

// -- The joint balance signature ----------------------------------------------

// A round signs ONCE. Signing one payload under two nonce sets lets the coordinator solve
// for a participant's mask, which also breaks the membership proof.
BOOST_AUTO_TEST_CASE(a_round_signs_once)
{
    const int64_t nNow = 9000000;
    CMixRound round;
    std::vector<Seat> vSeats;
    BOOST_REQUIRE(OpenAndFill(round, vSeats, 2, nNow));
    std::string strError;
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    BOOST_REQUIRE(round.IssueToken(vSeats[0].pubkey, &strError));
    BOOST_REQUIRE(round.IssueToken(vSeats[1].pubkey, &strError));
    BOOST_REQUIRE(round.OpenOutputWindow(nNow, &strError));
    const Token a = MintToken(9001);
    BOOST_REQUIRE(round.RegisterOutput(a.vchCredential, a.vchSignature, uint256(1), nNow, &strError));
    const Token b = MintToken(9002);
    BOOST_REQUIRE(round.RegisterOutput(b.vchCredential, b.vchSignature, uint256(2), nNow, &strError));

    const int64_t nClosed = nNow + MIX_OUTPUT_WINDOW + 1;
    BOOST_REQUIRE_MESSAGE(round.OpenSigning(nClosed, &strError), strError);
    BOOST_CHECK_EQUAL((int)round.Phase(), (int)MIX_PHASE_SIGN);

    const std::vector<unsigned char> vchNonce(32, 0x41);
    BOOST_REQUIRE(round.SubmitNonce(vSeats[0].pubkey, vchNonce, &strError));
    BOOST_REQUIRE(round.SubmitNonce(vSeats[1].pubkey, std::vector<unsigned char>(32, 0x42), &strError));
    BOOST_REQUIRE(round.FreezeNonces(&strError));

    BOOST_CHECK_MESSAGE(!round.OpenSigning(nClosed, &strError),
                        "signing reopened, so a second aggregate can be put to the same seats");
    BOOST_CHECK_MESSAGE(round.Phase() == MIX_PHASE_ABORTED,
                        "a second signing attempt did not end the round");
    BOOST_CHECK(round.AbortReason().find("twice") != std::string::npos);
}

// The aggregate is what the challenge is taken over, so it is fixed before anyone
// responds and cannot move afterwards.
BOOST_AUTO_TEST_CASE(the_aggregate_is_fixed_before_any_response)
{
    const int64_t nNow = 10000000;
    CMixRound round;
    std::vector<Seat> vSeats;
    BOOST_REQUIRE(OpenAndFill(round, vSeats, 2, nNow));
    std::string strError;
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    BOOST_REQUIRE(round.IssueToken(vSeats[0].pubkey, &strError));
    BOOST_REQUIRE(round.IssueToken(vSeats[1].pubkey, &strError));
    BOOST_REQUIRE(round.OpenOutputWindow(nNow, &strError));
    const Token a = MintToken(10001);
    BOOST_REQUIRE(round.RegisterOutput(a.vchCredential, a.vchSignature, uint256(3), nNow, &strError));
    const Token b = MintToken(10002);
    BOOST_REQUIRE(round.RegisterOutput(b.vchCredential, b.vchSignature, uint256(4), nNow, &strError));

    // Not before the output set is final: the signable hash covers the outputs.
    BOOST_CHECK(!round.OpenSigning(nNow + 1, &strError));
    const int64_t nClosed = nNow + MIX_OUTPUT_WINDOW + 1;
    BOOST_REQUIRE(round.OpenSigning(nClosed, &strError));

    const std::vector<unsigned char> vchNonce(32, 0x51);
    BOOST_CHECK_MESSAGE(!round.SubmitResponse(vSeats[0].pubkey, vchNonce, &strError),
                        "a seat responded before the aggregate was fixed, so it responded "
                        "under a challenge that can still move");
    BOOST_CHECK(!round.FreezeNonces(&strError));   // a seat has no nonce yet

    BOOST_REQUIRE(round.SubmitNonce(vSeats[0].pubkey, vchNonce, &strError));
    BOOST_CHECK_MESSAGE(!round.SubmitNonce(vSeats[0].pubkey, vchNonce, &strError),
                        "a seat published two nonces");
    BOOST_CHECK(!round.SubmitNonce(vSeats[0].pubkey, std::vector<unsigned char>(31, 0x51), &strError));
    BOOST_REQUIRE(round.SubmitNonce(vSeats[1].pubkey, std::vector<unsigned char>(32, 0x52), &strError));
    BOOST_REQUIRE(round.FreezeNonces(&strError));

    BOOST_CHECK_MESSAGE(!round.SubmitNonce(vSeats[0].pubkey, vchNonce, &strError),
                        "a nonce moved after the aggregate was fixed");
    BOOST_CHECK(!round.SigningComplete());
    BOOST_REQUIRE(round.SubmitResponse(vSeats[0].pubkey, std::vector<unsigned char>(32, 0x61), &strError));
    BOOST_CHECK(!round.SubmitResponse(vSeats[0].pubkey, std::vector<unsigned char>(32, 0x62), &strError));
    BOOST_CHECK(!round.SigningComplete());
    BOOST_REQUIRE(round.SubmitResponse(vSeats[1].pubkey, std::vector<unsigned char>(32, 0x63), &strError));
    BOOST_CHECK(round.SigningComplete());
}

// The combine reads the nonce points in input order, which is a seat's position in the
// frozen key image set -- not the order the seats happened to submit in.
BOOST_AUTO_TEST_CASE(the_nonce_order_is_the_frozen_input_order)
{
    const int64_t nNow = 11000000;
    CMixRound round;
    std::vector<Seat> vSeats;
    // OpenAndFill joins in descending key image, so arrival order is the reverse of
    // the frozen order and the two cannot be confused for one another.
    BOOST_REQUIRE(OpenAndFill(round, vSeats, 3, nNow));
    std::string strError;
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    for (size_t i = 0; i < vSeats.size(); i++)
        BOOST_REQUIRE(round.IssueToken(vSeats[i].pubkey, &strError));
    BOOST_REQUIRE(round.OpenOutputWindow(nNow, &strError));
    for (int i = 0; i < 3; i++)
    {
        const Token t = MintToken(11001 + i);
        BOOST_REQUIRE(round.RegisterOutput(t.vchCredential, t.vchSignature,
                                           uint256(20 + i), nNow, &strError));
    }
    BOOST_REQUIRE(round.OpenSigning(nNow + MIX_OUTPUT_WINDOW + 1, &strError));

    BOOST_CHECK(round.NoncesInInputOrder().empty());
    for (size_t i = 0; i < vSeats.size(); i++)
    {
        std::vector<unsigned char> vchNonce(32, (unsigned char)(0x70 + i));
        BOOST_REQUIRE(round.SubmitNonce(vSeats[i].pubkey, vchNonce, &strError));
    }
    const std::vector<std::vector<unsigned char> > vOrdered = round.NoncesInInputOrder();
    BOOST_REQUIRE_EQUAL(vOrdered.size(), 3u);
    // Seat i joined with key image 100 - i, so the frozen set reverses arrival order.
    for (size_t i = 0; i < vSeats.size(); i++)
        BOOST_CHECK_MESSAGE(vOrdered[2 - i][0] == (unsigned char)(0x70 + i),
                            "the nonce points are in arrival order, not in the order the "
                            "combine reads them");
}

// End to end through the FFI: a mix instance whose shares really open produces a proof,
// and the combine verifies it before returning, so a wrong share yields no proof rather
// than a bad one.
BOOST_AUTO_TEST_CASE(a_two_party_joint_balance_proof_verifies)
{
    MixInstance mix = BuildInstance(0x31);
    std::string strError;

    std::vector<PrivacyVNextDigest> vNonces;
    for (size_t i = 0; i < mix.vShares.size(); i++)
    {
        PrivacyVNextDigest nonce;
        BOOST_REQUIRE_MESSAGE(
            PrivacyVNextMixBalanceNonce(mix.facts, mix.vShares[i], nonce, strError), strError);
        vNonces.push_back(nonce);
    }

    std::vector<PrivacyVNextDigest> vResponses;
    for (size_t i = 0; i < mix.vShares.size(); i++)
    {
        PrivacyVNextDigest response;
        BOOST_REQUIRE_MESSAGE(
            PrivacyVNextMixBalanceSign(mix.facts, mix.vShares[i], vNonces, response, strError),
            strError);
        vResponses.push_back(response);
    }

    std::vector<unsigned char> vchProof;
    BOOST_REQUIRE_MESSAGE(
        PrivacyVNextMixBalanceCombine(mix.facts, vNonces, vResponses, vchProof, strError),
        strError);
    BOOST_CHECK_EQUAL(vchProof.size(), 64u);

    std::vector<PrivacyVNextDigest> vBad = vResponses;
    vBad[1][0] ^= 0x01;
    std::vector<unsigned char> vchNoProof;
    BOOST_CHECK_MESSAGE(
        !PrivacyVNextMixBalanceCombine(mix.facts, vNonces, vBad, vchNoProof, strError),
        "a wrong share produced a proof, so the combine did not verify what it returned");
    BOOST_CHECK(vchNoProof.empty());

    // A mask that does not open the share's own pair is refused at round one, before
    // any nonce exists.
    PrivacyVNextMixBalanceShare wrong = mix.vShares[0];
    wrong.mask = MaskOf(0x7f);
    PrivacyVNextDigest unused;
    BOOST_CHECK(!PrivacyVNextMixBalanceNonce(mix.facts, wrong, unused, strError));
}

// The guard the doc calls a protocol requirement, checked here rather than trusted: one
// nonce signs under one aggregate, and a second aggregate is an error rather than the
// second response that solves for the mask.
BOOST_AUTO_TEST_CASE(one_nonce_signs_under_one_aggregate)
{
    MixInstance mix = BuildInstance(0x44);
    std::string strError;

    std::vector<PrivacyVNextDigest> vNonces;
    for (size_t i = 0; i < mix.vShares.size(); i++)
    {
        PrivacyVNextDigest nonce;
        BOOST_REQUIRE(PrivacyVNextMixBalanceNonce(mix.facts, mix.vShares[i], nonce, strError));
        vNonces.push_back(nonce);
    }

    PrivacyVNextDigest first;
    BOOST_REQUIRE_MESSAGE(
        PrivacyVNextMixBalanceSign(mix.facts, mix.vShares[0], vNonces, first, strError), strError);

    // Same share, same nonce, a sybil nonce point in the other slot: a different
    // aggregate, therefore a different challenge.
    std::vector<PrivacyVNextDigest> vSybil = vNonces;
    vSybil[1] = vNonces[0];
    PrivacyVNextDigest second;
    BOOST_CHECK_MESSAGE(
        !PrivacyVNextMixBalanceSign(mix.facts, mix.vShares[0], vSybil, second, strError),
        "one nonce signed under two aggregates; the two responses solve for the share mask, "
        "and a leaked mix mask undoes the membership proof, not merely the amount");

    // Signing again under the SAME aggregate is not the attack and is allowed, so a
    // dropped connection does not strand a participant.
    PrivacyVNextDigest again;
    BOOST_CHECK_MESSAGE(
        PrivacyVNextMixBalanceSign(mix.facts, mix.vShares[0], vNonces, again, strError),
        strError);
    BOOST_CHECK(again == first);
}

BOOST_AUTO_TEST_SUITE_END()
