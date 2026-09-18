// The v2008 mix round's rules: who may say what, when, and under which identity.

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

#include "../key.h"
#include "../nullsend.h"
#include "../nullsend_v2008.h"
#include "../netbase.h"
#include "../privacy_vnext/iv5_protocol.h"
#include "../ed25519_zk.h"
#include "../main.h"
#include "../privacy_vnext_ffi.h"
#include "../privacy_vnext_store.h"
#include "../txdb.h"

#ifndef WIN32
#include <sys/socket.h>
#include <unistd.h>
#endif

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

// Every output in a round carries the same amount; the round needs it to check an
// opening against the commitment it is handed.
const uint64_t MIX_DENOM = 1000;

// The frame's own little-endian u16, so a hand-built body can be malformed on purpose.
void PutU16Test(std::vector<unsigned char>& vch, unsigned int n)
{
    vch.push_back((unsigned char)(n & 0xff));
    vch.push_back((unsigned char)((n >> 8) & 0xff));
}

// The round every OpenAndFill round opens under. The token binds it, so a token
// minted for another round does not register here.
const uint256 ROUND_HASH = uint256(0xBEEF);

// A token a participant would hold after the blind-signature exchange. It names the
// round and the output key it authorises, so two tokens are never the same credential
// and a token cannot be re-pointed at another key.
struct Token
{
    std::vector<unsigned char> vchCredential;
    std::vector<unsigned char> vchSignature;
};

// The complete record a participant registers: its key and opening, with ephemerals and
// ciphertexts of the exact sizes a payload carries, distinct per key.
CMixOutputRecord Rec(const uint256& outputKey, const PrivacyVNextDigest& commitment,
                     const PrivacyVNextDigest& mask)
{
    CMixOutputRecord record;
    memcpy(record.owner.data(), outputKey.begin(), 32);
    record.commitment = commitment;
    record.mask = mask;
    record.noteEphemeral.fill(0x5e);
    record.noteEphemeral[0] = outputKey.begin()[0];
    record.tweakEphemeral.fill(0x7e);
    record.tweakEphemeral[0] = outputKey.begin()[0];
    record.vchRecipientCiphertext.assign(INNOVA_PRIVACY_VNEXT_RECIPIENT_CIPHERTEXT_SIZE, 0xa1);
    record.vchOutgoingCiphertext.assign(INNOVA_PRIVACY_VNEXT_OUTGOING_CIPHERTEXT_SIZE, 0xb2);
    return record;
}

// A seat registers one variant per position. Where a test does not care which position
// its output lands at, the same record stands at every one, so what the round keeps is
// the record the test named.
std::vector<CMixOutputRecord> Bundle(const CMixOutputRecord& record, const CMixRound& round)
{
    return std::vector<CMixOutputRecord>(round.Seats(), record);
}

Token MintToken(const std::vector<CMixOutputRecord>& vBundle)
{
    CNullSendSession& server = Coordinator();
    CNullSendClient client;
    BOOST_REQUIRE(client.BlindCredentialMessage(server.vchRSA_N, server.vchRSA_E,
                                                MixOutputBundleCredentialHash(vBundle)));
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
    if (!round.Open(ROUND_HASH, nSeats, server.vchRSA_N, server.vchRSA_E,
                    true, false, MIX_DENOM, nNow, &strError))
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


// One output's opening: the mask and the commitment it opens at MIX_DENOM. Distinct per
// tag, because a round refuses a commitment it has already registered.
struct MixOpening
{
    PrivacyVNextDigest commitment;
    PrivacyVNextDigest mask;
};

MixOpening Opening(unsigned char chTag)
{
    MixOpening o;
    o.mask = MaskOf(chTag);
    o.commitment = Commit(MIX_DENOM, o.mask);
    return o;
}

CMixOutputRecord Rec(const uint256& outputKey, unsigned char chOpening)
{
    const MixOpening o = Opening(chOpening);
    return Rec(outputKey, o.commitment, o.mask);
}

// A two-seat mix: each spends nInput and creates nInput - nFeeShare, so the fee is the
// sum of the shares and the transparent value balance is zero.
struct MixInstance
{
    PrivacyVNextMixBalanceFacts facts;
    std::vector<PrivacyVNextMixBalanceShare> vShares;
    // Output openings in output order. Public in a mix -- amounts are disclosed -- and
    // folded in by the combiner, because a seat that signed its own output's mask would
    // be naming its output to whoever collected the response.
    std::vector<PrivacyVNextDigest> vOutputMasks;
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
        const PrivacyVNextDigest outputMask = MaskOf((unsigned char)(0x31 + i));
        mix.facts.vPseudoOuts.push_back(Commit(nInput, mask));
        mix.facts.vOutputs.push_back(Commit(nInput - nFeeShare, outputMask));
        mix.vOutputMasks.push_back(outputMask);

        PrivacyVNextMixBalanceShare share;
        share.nInputIndex = (uint8_t)i;
        share.nOutputIndex = (uint8_t)i;
        share.nFeeShare = nFeeShare;
        share.mask = mask;
        share.outputMask = outputMask;
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
    BOOST_REQUIRE_MESSAGE(round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError), strError);
    BOOST_CHECK_EQUAL((int)round.Phase(), (int)MIX_PHASE_OUTPUT);

    for (int i = 0; i < 3; i++)
    {
        const Token token = MintToken(Bundle(Rec(uint256(500 + i), (unsigned char)(0x94 + i)), round));
        BOOST_REQUIRE_MESSAGE(round.RegisterOutput(token.vchCredential, token.vchSignature, Bundle(Rec(uint256(500 + i), (unsigned char)(0x94 + i)), round), nNow + 1, &strError),
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
    BOOST_REQUIRE(round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError));

    // Any valid token registers any output. That is the property, not a gap: if the
    // round could tell which seat a token came from, the blind signature would be
    // doing nothing.
    const Token first = MintToken(Bundle(Rec(uint256(900), 0x39), round));
    BOOST_REQUIRE(round.RegisterOutput(first.vchCredential, first.vchSignature, Bundle(Rec(uint256(900), 0x39), round), nNow, &strError));

    // A repeat of the SAME token is a retransmission: accepted, registers nothing further,
    // and never places a second output.
    BOOST_REQUIRE_EQUAL(round.Outputs(), 1u);
    BOOST_CHECK_MESSAGE(round.RegisterOutput(first.vchCredential, first.vchSignature, Bundle(Rec(uint256(900), 0x39), round), nNow, &strError),
                        "a retransmitted registration was refused, stranding the seat that retried");
    BOOST_CHECK_MESSAGE(round.Outputs() == 1u, "a retransmission placed a second output");

    // The signature is checked before the replay is recognised: a credential this round
    // did sign, carried with a signature it did not, is not a retransmission.
    std::vector<unsigned char> vchMangled = first.vchSignature;
    vchMangled[vchMangled.size() / 2] ^= 0x01;
    BOOST_CHECK_MESSAGE(!round.RegisterOutput(first.vchCredential, vchMangled, Bundle(Rec(uint256(900), 0x39), round), nNow, &strError),
                        "a replay carrying a mangled signature was taken as a retransmission");
    BOOST_CHECK(strError.find("does not verify") != std::string::npos);

    // And it registers that key and no other: rewriting the key in flight, which the
    // OUTPUT frame is unauthenticated enough to allow, makes the token stop opening.
    BOOST_CHECK_MESSAGE(!round.RegisterOutput(first.vchCredential, first.vchSignature, Bundle(Rec(uint256(901), 0x37), round), nNow, &strError),
                        "a token authorised an output key it was not minted for");
    BOOST_CHECK(strError.find("does not authorise") != std::string::npos);

    // A token minted under ANOTHER round's key is refused, which is where round
    // separation comes from: the message names only the key, so nothing but the modulus
    // tells the two rounds apart. A fresh key per round is therefore a driver obligation.
    CNullSendSession other;
    other.nSessionID = 98;
    BOOST_REQUIRE(other.GenerateSessionRSAKey());
    CNullSendClient elsewhere;
    BOOST_REQUIRE(elsewhere.BlindCredentialMessage(other.vchRSA_N, other.vchRSA_E,
                                                   MixOutputBundleCredentialHash(Bundle(Rec(uint256(905), 0xb6), round))));
    std::vector<unsigned char> vchOtherBlindSig;
    BOOST_REQUIRE(other.BlindSign(elsewhere.vchBlindedCredential, vchOtherBlindSig));
    BOOST_REQUIRE(elsewhere.UnblindSignature(vchOtherBlindSig));
    BOOST_CHECK_MESSAGE(!round.RegisterOutput(elsewhere.vchCredentialHash,
                                              elsewhere.vchUnblindedSig, Bundle(Rec(uint256(905), 0xb6), round), nNow, &strError),
                        "a token from another round's key registered an output");

    // And the credential must carry NO round id: if it did, a coordinator handing each
    // seat its own round id would read the seat straight off an unauthenticated OUTPUT by
    // trying every id it minted against the key it was handed.
    BOOST_CHECK(MixOutputBundleCredentialHash(Bundle(Rec(uint256(900), 0x39), round)) !=
                MixOutputBundleCredentialHash(Bundle(Rec(uint256(901), 0x39), round)));
    {
        CMixRound otherRound;
        std::vector<Seat> vOtherSeats;
        BOOST_REQUIRE(OpenAndFill(otherRound, vOtherSeats, 2, nNow));
        BOOST_CHECK_MESSAGE(otherRound.RoundId() == round.RoundId(),
                            "the fixture must open both rounds under one id for the next "
                            "assertion to mean anything");
    }

    // A token the round's key did not sign is refused.
    CNullSendSession stranger;
    stranger.nSessionID = 99;
    BOOST_REQUIRE(stranger.GenerateSessionRSAKey());
    CNullSendClient outsider;
    BOOST_REQUIRE(outsider.BlindCredentialMessage(stranger.vchRSA_N, stranger.vchRSA_E,
                                                  MixOutputBundleCredentialHash(Bundle(Rec(uint256(902), 0xab), round))));
    std::vector<unsigned char> vchForeignBlindSig;
    BOOST_REQUIRE(stranger.BlindSign(outsider.vchBlindedCredential, vchForeignBlindSig));
    BOOST_REQUIRE(outsider.UnblindSignature(vchForeignBlindSig));
    BOOST_CHECK_MESSAGE(!round.RegisterOutput(outsider.vchCredentialHash,
                                              outsider.vchUnblindedSig, Bundle(Rec(uint256(902), 0xab), round), nNow, &strError),
                        "a token from another round's key was accepted");

    // And no more outputs than seats, whatever the tokens say.
    const Token second = MintToken(Bundle(Rec(uint256(903), 0xd2), round));
    BOOST_REQUIRE(round.RegisterOutput(second.vchCredential, second.vchSignature, Bundle(Rec(uint256(903), 0xd2), round), nNow, &strError));
    const Token third = MintToken(Bundle(Rec(uint256(904), 0xdb), round));
    BOOST_CHECK_MESSAGE(!round.RegisterOutput(third.vchCredential, third.vchSignature, Bundle(Rec(uint256(904), 0xdb), round), nNow, &strError),
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

// A drop past the freeze ends the round, so it must be a seat that asks for one. Anyone
// can produce a key and sign a frame with it, and without a membership check that is a
// one-frame abort of a round the sender never joined.
BOOST_AUTO_TEST_CASE(a_key_that_holds_no_seat_cannot_drop_a_round)
{
    const int64_t nNow = 3100000;
    std::string strError;
    CMixRound round;
    std::vector<Seat> vSeats;
    BOOST_REQUIRE(OpenAndFill(round, vSeats, 3, nNow));
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));

    const Seat outsider = MakeSeat(0x5150);
    round.Drop(outsider.pubkey);
    BOOST_CHECK_MESSAGE(round.Phase() != MIX_PHASE_ABORTED,
                        "a key that never joined aborted the round");
    BOOST_CHECK_EQUAL(round.Seats(), 3u);

    // Before the freeze the same key is a no-op rather than an erase.
    CMixRound joining;
    std::vector<Seat> vJoining;
    BOOST_REQUIRE(OpenAndFill(joining, vJoining, 3, nNow));
    joining.Drop(outsider.pubkey);
    BOOST_CHECK_EQUAL(joining.Seats(), 3u);
    BOOST_CHECK_EQUAL((int)joining.Phase(), (int)MIX_PHASE_JOIN);

    // And a real seat still ends it, so the guard is about membership and not the phase.
    round.Drop(vSeats[0].pubkey);
    BOOST_CHECK_EQUAL((int)round.Phase(), (int)MIX_PHASE_ABORTED);
}

// Every seat signs ONE view digest over the announcement and the whole roster, and refuses
// to spend a token until it has seen all n signatures over its own digest.
BOOST_AUTO_TEST_CASE(every_seat_signs_one_view_and_the_round_can_tell)
{
    const int64_t nNow = 3400000;
    std::string strError;
    CMixRound round;
    std::vector<Seat> vSeats;
    BOOST_REQUIRE(OpenAndFill(round, vSeats, 3, nNow));

    const uint256 hashAnnounce = uint256(0xA22EE);

    // Nothing to sign before the freeze: the roster is what is being agreed.
    BOOST_CHECK(round.ViewDigest(hashAnnounce) == 0);
    BOOST_CHECK(!round.SubmitViewSignature(vSeats[0].pubkey, hashAnnounce,
                                           std::vector<unsigned char>(), &strError));

    BOOST_REQUIRE_MESSAGE(round.CloseJoin(nNow, &strError), strError);
    const uint256 hashView = round.ViewDigest(hashAnnounce);
    BOOST_REQUIRE(hashView != 0);
    BOOST_CHECK_EQUAL(round.Roster().size(), 3u);

    // The roster is the frozen set seen as pairs, in the same byte order.
    for (size_t i = 1; i < round.Roster().size(); i++)
        BOOST_CHECK(std::lexicographical_compare(
            round.Roster()[i - 1].keyImage.begin(), round.Roster()[i - 1].keyImage.end(),
            round.Roster()[i].keyImage.begin(), round.Roster()[i].keyImage.end()));

    BOOST_CHECK(!round.ViewAgreed(hashAnnounce));

    // A key that holds no seat cannot sign into the certificate.
    const Seat outsider = MakeSeat(0x5151);
    std::vector<unsigned char> vchOutsider;
    BOOST_REQUIRE(outsider.key.Sign(hashView, vchOutsider));
    BOOST_CHECK(!round.SubmitViewSignature(outsider.pubkey, hashAnnounce, vchOutsider,
                                           &strError));
    BOOST_CHECK(strError.find("no seat") != std::string::npos);

    for (size_t i = 0; i < vSeats.size(); i++)
    {
        std::vector<unsigned char> vchSig;
        BOOST_REQUIRE(vSeats[i].key.Sign(hashView, vchSig));
        BOOST_REQUIRE_MESSAGE(
            round.SubmitViewSignature(vSeats[i].pubkey, hashAnnounce, vchSig, &strError),
            strError);
        // Not agreed until the LAST one lands.
        BOOST_CHECK_EQUAL(round.ViewAgreed(hashAnnounce), i + 1 == vSeats.size());
    }

    // One view per seat per attempt: a seat shown a second announcement cannot sign it
    // too, which is what stops a coordinator collecting a full certificate from seats it
    // showed different views to.
    const uint256 hashOther = uint256(0xB33FF);
    const uint256 hashOtherView = round.ViewDigest(hashOther);
    BOOST_REQUIRE(hashOtherView != hashView);
    std::vector<unsigned char> vchSecond;
    BOOST_REQUIRE(vSeats[0].key.Sign(hashOtherView, vchSecond));
    BOOST_CHECK_MESSAGE(!round.SubmitViewSignature(vSeats[0].pubkey, hashOther, vchSecond,
                                                   &strError),
                        "a seat signed a second view, so a coordinator showing two seats "
                        "two announcements could still complete a certificate");
    BOOST_CHECK(strError.find("already signed") != std::string::npos);

    // And the certificate is over ONE announcement: the same signatures do not agree a
    // different one.
    BOOST_CHECK(!round.ViewAgreed(hashOther));
}

// The digest covers the SESSION KEYS, not the key images alone. A digest over the inputs
// only would let a coordinator present one input set with a different set of signers --
// the roster of alleged signers has to be inside the thing they sign.
BOOST_AUTO_TEST_CASE(the_view_digest_covers_who_signs_it)
{
    std::vector<CMixRosterEntry> vA(2), vB(2);
    const Seat a = MakeSeat(0x11), b = MakeSeat(0x12), c = MakeSeat(0x13);
    vA[0].keyImage = uint256(10); vA[0].pubkeySession = a.pubkey;
    vA[1].keyImage = uint256(20); vA[1].pubkeySession = b.pubkey;
    vB[0].keyImage = uint256(10); vB[0].pubkeySession = a.pubkey;
    vB[1].keyImage = uint256(20); vB[1].pubkeySession = c.pubkey;   // same inputs, other signer

    const uint256 hashAnnounce = uint256(0x777);
    BOOST_CHECK(MixViewDigest(hashAnnounce, vA) != 0);
    BOOST_CHECK_MESSAGE(MixViewDigest(hashAnnounce, vA) != MixViewDigest(hashAnnounce, vB),
                        "the digest ignored the session keys, so one input set can be "
                        "presented with any set of signers");

    // Order does not matter; the roster is sorted before it is hashed.
    std::vector<CMixRosterEntry> vSwapped;
    vSwapped.push_back(vA[1]);
    vSwapped.push_back(vA[0]);
    BOOST_CHECK(MixViewDigest(hashAnnounce, vSwapped) == MixViewDigest(hashAnnounce, vA));

    // A repeated key image or a repeated session key is not a roster of n seats.
    std::vector<CMixRosterEntry> vDupImage = vA; vDupImage[1].keyImage = vDupImage[0].keyImage;
    std::vector<CMixRosterEntry> vDupKey = vA;   vDupKey[1].pubkeySession = vDupKey[0].pubkeySession;
    BOOST_CHECK(MixViewDigest(hashAnnounce, vDupImage) == 0);
    BOOST_CHECK(MixViewDigest(hashAnnounce, vDupKey) == 0);

    // The announcement is in it too, which is the whole point.
    BOOST_CHECK(MixViewDigest(uint256(0x778), vA) != MixViewDigest(hashAnnounce, vA));
}

// A coordinator that fabricates a roster around one honest seat still gets a complete,
// valid certificate. The certificate does not prove the seats are independent.
BOOST_AUTO_TEST_CASE(a_complete_certificate_does_not_prove_the_seats_are_independent)
{
    const int64_t nNow = 3500000;
    std::string strError;
    CNullSendSession& server = Coordinator();
    CMixRound round;
    BOOST_REQUIRE(round.Open(ROUND_HASH, 3, server.vchRSA_N, server.vchRSA_E,
                             true, false, MIX_DENOM, nNow, &strError));

    // One honest seat, two the coordinator made up and holds the keys for.
    const Seat honest = MakeSeat(0x600);
    const Seat sybilA = MakeSeat(0x601), sybilB = MakeSeat(0x602);
    BOOST_REQUIRE(round.Join(honest.pubkey, honest.keyImage, &strError));
    BOOST_REQUIRE(round.Join(sybilA.pubkey, sybilA.keyImage, &strError));
    BOOST_REQUIRE(round.Join(sybilB.pubkey, sybilB.keyImage, &strError));
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));

    const uint256 hashAnnounce = uint256(0xC0FFEE);
    const uint256 hashView = round.ViewDigest(hashAnnounce);
    const Seat vAll[3] = { honest, sybilA, sybilB };
    for (int i = 0; i < 3; i++)
    {
        std::vector<unsigned char> vchSig;
        BOOST_REQUIRE(vAll[i].key.Sign(hashView, vchSig));
        BOOST_REQUIRE(round.SubmitViewSignature(vAll[i].pubkey, hashAnnounce, vchSig,
                                                &strError));
    }

    BOOST_CHECK_MESSAGE(round.ViewAgreed(hashAnnounce),
                        "the fixture is wrong if a fabricated roster fails to certify -- "
                        "the point is that it succeeds");
    // Every local check an honest seat can run still passes.
    BOOST_CHECK_EQUAL(round.Roster().size(), 3u);
    bool fSelfPresent = false;
    for (size_t i = 0; i < round.Roster().size(); i++)
        if (round.Roster()[i].keyImage == honest.keyImage &&
            round.Roster()[i].pubkeySession == honest.pubkey)
            fSelfPresent = true;
    BOOST_CHECK(fSelfPresent);
}

// Through the dispatcher: a token is not issued until every seat has signed the same view.
BOOST_AUTO_TEST_CASE(a_token_is_not_issued_until_every_seat_signed_one_view)
{
    const int64_t nNow = 3600000;
    std::string strError;
    CNullSendSession& server = Coordinator();
    const uint256 hashRound = uint256(0xD00D);
    CMixRound round;
    BOOST_REQUIRE(round.Open(hashRound, 2, server.vchRSA_N, server.vchRSA_E,
                             true, false, MIX_DENOM, nNow, &strError));
    const Seat a = MakeSeat(0x700), b = MakeSeat(0x701);
    BOOST_REQUIRE(round.Join(a.pubkey, a.keyImage, &strError));
    BOOST_REQUIRE(round.Join(b.pubkey, b.keyImage, &strError));
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));

    const uint256 hashAnnounce = uint256(0xA55E);
    const uint256 hashView = round.ViewDigest(hashAnnounce);
    BOOST_REQUIRE(hashView != 0);

    // A blinded request before the view is agreed is refused, and no token is spent.
    std::vector<unsigned char> vchBlinded(64, 0x5a), vchBody, vchFrame;
    BOOST_REQUIRE(BuildMixBlindRequestBody(a.pubkey, hashAnnounce, vchBlinded, vchBody));
    BOOST_REQUIRE(BuildAuthedMixFrame(a.key, hashRound, MIX_FRAME_BLIND_REQUEST, vchBody,
                                      vchFrame));
    BOOST_CHECK_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_BLIND_REQUEST, vchFrame, nNow,
                                            strError), (int)MIX_DISPATCH_REFUSED);
    BOOST_CHECK(strError.find("signed this view") != std::string::npos);

    // Both seats sign, through the frame.
    const Seat vSeats[2] = { a, b };
    for (int i = 0; i < 2; i++)
    {
        std::vector<unsigned char> vchSig, vchVBody, vchVFrame;
        BOOST_REQUIRE(vSeats[i].key.Sign(hashView, vchSig));
        BOOST_REQUIRE(BuildMixViewSigBody(vSeats[i].pubkey, hashAnnounce, vchSig, vchVBody));
        BOOST_REQUIRE(BuildAuthedMixFrame(vSeats[i].key, hashRound, MIX_FRAME_VIEW_SIG,
                                          vchVBody, vchVFrame));
        BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_VIEW_SIG, vchVFrame, nNow,
                                                  strError), (int)MIX_DISPATCH_OK);
    }
    BOOST_REQUIRE(round.ViewAgreed(hashAnnounce));

    // Agreement alone is not enough: the prefix needs every seat's input construction, so
    // a token waits for those too.
    BOOST_CHECK_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_BLIND_REQUEST, vchFrame, nNow,
                                            strError), (int)MIX_DISPATCH_REFUSED);
    BOOST_CHECK(strError.find("input constructions") != std::string::npos);
    for (int i = 0; i < 2; i++)
    {
        std::vector<unsigned char> vchCBody, vchCFrame;
        BOOST_REQUIRE(BuildMixInputConstructionBody(vSeats[i].pubkey, hashAnnounce,
                                                    vSeats[i].keyImage,
                                                    MaskOf((unsigned char)(0x61 + i)),
                                                    vchCBody));
        BOOST_REQUIRE(BuildAuthedMixFrame(vSeats[i].key, hashRound,
                                          MIX_FRAME_INPUT_CONSTRUCTION, vchCBody, vchCFrame));
        BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_INPUT_CONSTRUCTION,
                                                  vchCFrame, nNow, strError),
                            (int)MIX_DISPATCH_OK);
    }
    BOOST_REQUIRE(round.InputConstructionsComplete());

    // Now the token issues, and only once per seat. The round holds no private exponent, so
    // the blinded message has to come back out or nothing can ever sign it.
    CMixDispatchEffect effect;
    BOOST_CHECK_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_BLIND_REQUEST, vchFrame, nNow,
                                            strError, &effect), (int)MIX_DISPATCH_OK);
    BOOST_CHECK_EQUAL((int)effect.nFrame, (int)MIX_FRAME_BLIND_REQUEST);
    BOOST_CHECK_MESSAGE(effect.vchBlinded == vchBlinded,
                        "the driver was not handed the message it has to blind-sign");
    BOOST_CHECK(effect.pubkeySession == a.pubkey);
    BOOST_CHECK_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_BLIND_REQUEST, vchFrame, nNow,
                                            strError), (int)MIX_DISPATCH_REFUSED);

    // And a request naming a DIFFERENT announcement is refused even after agreement:
    // the gate is the view these seats actually signed, not any view.
    std::vector<unsigned char> vchOtherBody, vchOtherFrame;
    effect.Clear();
    BOOST_REQUIRE(BuildMixBlindRequestBody(b.pubkey, uint256(0xBEEF), vchBlinded,
                                           vchOtherBody));
    BOOST_REQUIRE(BuildAuthedMixFrame(b.key, hashRound, MIX_FRAME_BLIND_REQUEST,
                                      vchOtherBody, vchOtherFrame));
    BOOST_CHECK_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_BLIND_REQUEST, vchOtherFrame,
                                            nNow, strError, &effect),
                      (int)MIX_DISPATCH_REFUSED);
    BOOST_CHECK_MESSAGE(effect.vchBlinded.empty(),
                        "a refused request still handed the driver something to sign");

    // An unauthenticated blind request is not a frame the dispatcher acts on. If it ever
    // became one, any connection takes tokens without holding a seat.
    BOOST_CHECK_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_BLIND_REQUEST, vchBody, nNow,
                                            strError), (int)MIX_DISPATCH_REFUSED);
}

// A seat's input construction is its pseudo-output for the key image it joined with. It is
// taken only once the view is agreed, once per seat, for that seat's own key image, and
// never twice for one pseudo-output; the prefix reads them back in input order.
BOOST_AUTO_TEST_CASE(an_input_construction_belongs_to_its_seat_and_its_key_image)
{
    const int64_t nNow = 3650000;
    std::string strError;
    CMixRound round;
    std::vector<Seat> vSeats;
    BOOST_REQUIRE(OpenAndFill(round, vSeats, 2, nNow));
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    const uint256 hashAnnounce = uint256(0xC0DE);
    const uint256 hashView = round.ViewDigest(hashAnnounce);
    BOOST_REQUIRE(hashView != 0);
    const PrivacyVNextDigest pseudo0 = MaskOf(0x71), pseudo1 = MaskOf(0x72);

    // Before agreement nothing is taken.
    BOOST_CHECK(!round.SubmitInputConstruction(vSeats[0].pubkey, hashAnnounce,
                                               vSeats[0].keyImage, pseudo0, &strError));
    for (size_t i = 0; i < vSeats.size(); i++)
    {
        std::vector<unsigned char> vchSig;
        BOOST_REQUIRE(vSeats[i].key.Sign(hashView, vchSig));
        BOOST_REQUIRE(round.SubmitViewSignature(vSeats[i].pubkey, hashAnnounce, vchSig,
                                                &strError));
    }

    // Another seat's key image, a zero pseudo-output and a stranger are all refused.
    BOOST_CHECK(!round.SubmitInputConstruction(vSeats[0].pubkey, hashAnnounce,
                                               vSeats[1].keyImage, pseudo0, &strError));
    BOOST_CHECK(strError.find("did not join with") != std::string::npos);
    PrivacyVNextDigest zero;
    zero.fill(0);
    BOOST_CHECK(!round.SubmitInputConstruction(vSeats[0].pubkey, hashAnnounce,
                                               vSeats[0].keyImage, zero, &strError));
    const Seat stranger = MakeSeat(0x999);
    BOOST_CHECK(!round.SubmitInputConstruction(stranger.pubkey, hashAnnounce,
                                               stranger.keyImage, pseudo0, &strError));
    BOOST_CHECK(round.PseudoOutsInInputOrder().empty());

    BOOST_REQUIRE_MESSAGE(round.SubmitInputConstruction(vSeats[0].pubkey, hashAnnounce,
                                                        vSeats[0].keyImage, pseudo0,
                                                        &strError), strError);
    // Once per seat, and one pseudo-output cannot serve two inputs.
    BOOST_CHECK(!round.SubmitInputConstruction(vSeats[0].pubkey, hashAnnounce,
                                               vSeats[0].keyImage, pseudo1, &strError));
    BOOST_CHECK(!round.SubmitInputConstruction(vSeats[1].pubkey, hashAnnounce,
                                               vSeats[1].keyImage, pseudo0, &strError));
    BOOST_CHECK(!round.InputConstructionsComplete());
    BOOST_REQUIRE(round.SubmitInputConstruction(vSeats[1].pubkey, hashAnnounce,
                                                vSeats[1].keyImage, pseudo1, &strError));
    BOOST_REQUIRE(round.InputConstructionsComplete());

    // Input order is the sorted key-image order CloseJoin fixed, not submission order.
    const std::vector<PrivacyVNextDigest> vOrdered = round.PseudoOutsInInputOrder();
    const std::vector<CMixParticipant>& vParticipants = round.Participants();
    BOOST_REQUIRE_EQUAL(vOrdered.size(), 2u);
    for (size_t i = 0; i < vParticipants.size(); i++)
        BOOST_CHECK(vOrdered[vParticipants[i].nInputIndex] == vParticipants[i].pseudoOut);
}

// The prefix a seat approves is written through the payload builder's own assembler, from the
// frozen inputs in input order and the registered records at the round's denomination -- and
// only for a NullSend operation at the NullSend mask, with every piece in.
BOOST_AUTO_TEST_CASE(a_mix_prefix_is_the_builder_layout_over_the_round_state)
{
    const int64_t nNow = 3660000;
    std::string strError;
    CMixRound round;
    std::vector<Seat> vSeats;
    BOOST_REQUIRE(OpenAndFill(round, vSeats, 2, nNow));
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    const uint256 hashAnnounce = uint256(0xFEED);
    const uint256 hashView = round.ViewDigest(hashAnnounce);
    for (size_t i = 0; i < vSeats.size(); i++)
    {
        std::vector<unsigned char> vchSig;
        BOOST_REQUIRE(vSeats[i].key.Sign(hashView, vchSig));
        BOOST_REQUIRE(round.SubmitViewSignature(vSeats[i].pubkey, hashAnnounce, vchSig,
                                                &strError));
    }
    for (size_t i = 0; i < vSeats.size(); i++)
    {
        BOOST_REQUIRE(round.SubmitInputConstruction(vSeats[i].pubkey, hashAnnounce,
                                                    vSeats[i].keyImage,
                                                    MaskOf((unsigned char)(0x81 + i)),
                                                    &strError));
        BOOST_REQUIRE(round.IssueToken(vSeats[i].pubkey, &strError));
    }
    BOOST_REQUIRE(round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError));

    PrivacyVNextPrefixHeader header;
    header.nOperation = iv5::NOTE_NULLSEND;
    header.nDisclosureMask = iv5::NULLSEND_DISCLOSURE_MASK;
    header.nNetwork = 1;
    header.genesis.fill(0x11);
    header.parameterDigest.fill(0x22);
    header.finalizedRoot.fill(0x33);
    header.nFinalizedTreeSize = 77;
    header.nFee = 1000;
    header.transparentBinding.fill(0x44);
    std::vector<unsigned char> vchPrefix;

    // Not until every output is in.
    const CMixOutputRecord first = Rec(uint256(0x7A0), 0x91);
    const Token firstToken = MintToken(Bundle(first, round));
    BOOST_REQUIRE(round.RegisterOutput(firstToken.vchCredential, firstToken.vchSignature, Bundle(first, round),
                                       nNow, &strError));
    BOOST_CHECK(!round.AssemblePrefix(header, vchPrefix, &strError));
    const CMixOutputRecord second = Rec(uint256(0x7A1), 0x92);
    const Token secondToken = MintToken(Bundle(second, round));
    BOOST_REQUIRE(round.RegisterOutput(secondToken.vchCredential, secondToken.vchSignature, Bundle(second, round), nNow, &strError));

    // Only the mix shape.
    PrivacyVNextPrefixHeader wrong = header;
    wrong.nOperation = iv5::NOTE_TRANSFER;
    BOOST_CHECK(!round.AssemblePrefix(wrong, vchPrefix, &strError));
    wrong = header;
    wrong.nDisclosureMask = iv5::DISCLOSURE_MASK;
    BOOST_CHECK(!round.AssemblePrefix(wrong, vchPrefix, &strError));
    wrong = header;
    wrong.nTransparentValueBalance = 1;
    BOOST_CHECK(!round.AssemblePrefix(wrong, vchPrefix, &strError));

    BOOST_REQUIRE_MESSAGE(round.AssemblePrefix(header, vchPrefix, &strError), strError);

    // The same bytes the builder's assembler writes from the same pieces.
    const std::vector<PrivacyVNextDigest> vPseudo = round.PseudoOutsInInputOrder();
    const std::vector<uint256>& vKeyImages = round.FinalKeyImages();
    std::vector<PrivacyVNextPrefixInput> vInputs(2);
    for (size_t i = 0; i < 2; i++)
    {
        vInputs[i].pseudoOut = vPseudo[i];
        memcpy(vInputs[i].keyImage.data(), vKeyImages[i].begin(), 32);
        vInputs[i].senderAuthority.fill(0);
    }
    std::vector<PrivacyVNextPrefixOutput> vOutputs(2);
    const CMixOutputRecord vRecords[2] = { first, second };
    for (size_t i = 0; i < 2; i++)
    {
        vOutputs[i].owner = vRecords[i].owner;
        vOutputs[i].commitment = vRecords[i].commitment;
        vOutputs[i].noteEphemeral = vRecords[i].noteEphemeral;
        vOutputs[i].tweakEphemeral = vRecords[i].tweakEphemeral;
        vOutputs[i].vchRecipientCiphertext = vRecords[i].vchRecipientCiphertext;
        vOutputs[i].vchOutgoingCiphertext = vRecords[i].vchOutgoingCiphertext;
        vOutputs[i].recipientSpend.fill(0);
        vOutputs[i].recipientView.fill(0);
        vOutputs[i].nAmount = MIX_DENOM;
        vOutputs[i].mask = vRecords[i].mask;
    }
    std::vector<unsigned char> vchExpected;
    BOOST_REQUIRE(AssemblePrivacyVNextPayloadPrefix(header, vInputs, vOutputs, vchExpected,
                                                    strError));
    BOOST_CHECK(vchPrefix == vchExpected);

    // And the layout itself: nine header bytes, three digests, three 64-bit fields, the
    // binding, then the input count and the first input's pseudo-output and key image.
    const size_t nInputs = 9 + 3 * 32 + 3 * 8 + 32;
    BOOST_REQUIRE(vchPrefix.size() > nInputs + 1 + 64);
    BOOST_CHECK_EQUAL(vchPrefix[2], iv5::NOTE_NULLSEND);
    BOOST_CHECK_EQUAL(vchPrefix[5], iv5::NULLSEND_DISCLOSURE_MASK);
    BOOST_CHECK_EQUAL(vchPrefix[nInputs], 2);
    BOOST_CHECK(std::equal(vPseudo[0].begin(), vPseudo[0].end(), vchPrefix.begin() + nInputs + 1));
    BOOST_CHECK(std::equal(vKeyImages[0].begin(), vKeyImages[0].end(),
                           vchPrefix.begin() + nInputs + 1 + 32));
    // The disclosed amounts close the prefix: each output's amount and mask, then an empty
    // finality body.
    const size_t nTail = 2 * (8 + 32) + 1;
    uint64_t nAmount = 0;
    for (size_t i = 0; i < 8; i++)
        nAmount |= (uint64_t)vchPrefix[vchPrefix.size() - nTail + i] << (8 * i);
    BOOST_CHECK_EQUAL(nAmount, MIX_DENOM);
}

namespace {

const uint256 PREFIX_ANNOUNCE = uint256(0xFACE);

PrivacyVNextPrefixHeader MixHeader()
{
    PrivacyVNextPrefixHeader header;
    header.nOperation = iv5::NOTE_NULLSEND;
    header.nDisclosureMask = iv5::NULLSEND_DISCLOSURE_MASK;
    header.nNetwork = 1;
    header.genesis.fill(0x11);
    header.parameterDigest.fill(0x22);
    header.finalizedRoot.fill(0x33);
    header.nFinalizedTreeSize = 77;
    header.nFee = 1000;
    header.transparentBinding = MixTransparentBinding();
    return header;
}

// A two-seat round with the view signed, every construction in and every output
// registered; the output window is still open.
void RoundWithOutputs(CMixRound& round, std::vector<Seat>& vSeats, int64_t nNow)
{
    std::string strError;
    BOOST_REQUIRE(OpenAndFill(round, vSeats, 2, nNow));
    BOOST_REQUIRE_MESSAGE(round.CloseJoin(nNow, &strError), strError);
    const uint256 hashView = round.ViewDigest(PREFIX_ANNOUNCE);
    for (size_t i = 0; i < vSeats.size(); i++)
    {
        std::vector<unsigned char> vchSig;
        BOOST_REQUIRE(vSeats[i].key.Sign(hashView, vchSig));
        BOOST_REQUIRE_MESSAGE(round.SubmitViewSignature(vSeats[i].pubkey, PREFIX_ANNOUNCE,
                                                        vchSig, &strError), strError);
    }
    for (size_t i = 0; i < vSeats.size(); i++)
    {
        BOOST_REQUIRE_MESSAGE(round.SubmitInputConstruction(vSeats[i].pubkey, PREFIX_ANNOUNCE,
                                                            vSeats[i].keyImage,
                                                            MaskOf((unsigned char)(0x81 + i)),
                                                            &strError), strError);
        BOOST_REQUIRE_MESSAGE(round.IssueToken(vSeats[i].pubkey, &strError), strError);
    }
    BOOST_REQUIRE_MESSAGE(round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError), strError);
    for (int i = 0; i < 2; i++)
    {
        const CMixOutputRecord record = Rec(uint256(0x7B0 + i), (unsigned char)(0x95 + i));
        const Token token = MintToken(Bundle(record, round));
        BOOST_REQUIRE_MESSAGE(round.RegisterOutput(token.vchCredential, token.vchSignature, Bundle(record, round), nNow, &strError), strError);
    }
}

std::vector<unsigned char> MixPrefixOver(
    const PrivacyVNextPrefixHeader& header,
    const std::vector<std::pair<uint256, PrivacyVNextDigest> >& vInputs,
    const std::vector<CMixOutputRecord>& vRecords, const std::vector<uint64_t>& vAmounts)
{
    std::vector<PrivacyVNextPrefixInput> vIn(vInputs.size());
    for (size_t i = 0; i < vIn.size(); i++)
    {
        memcpy(vIn[i].keyImage.data(), vInputs[i].first.begin(), 32);
        vIn[i].pseudoOut = vInputs[i].second;
        vIn[i].senderAuthority.fill(0);
    }
    std::vector<PrivacyVNextPrefixOutput> vOut(vRecords.size());
    for (size_t i = 0; i < vOut.size(); i++)
    {
        vOut[i].owner = vRecords[i].owner;
        vOut[i].commitment = vRecords[i].commitment;
        vOut[i].noteEphemeral = vRecords[i].noteEphemeral;
        vOut[i].tweakEphemeral = vRecords[i].tweakEphemeral;
        vOut[i].vchRecipientCiphertext = vRecords[i].vchRecipientCiphertext;
        vOut[i].vchOutgoingCiphertext = vRecords[i].vchOutgoingCiphertext;
        vOut[i].recipientSpend.fill(0);
        vOut[i].recipientView.fill(0);
        vOut[i].nAmount = vAmounts[i];
        vOut[i].mask = vRecords[i].mask;
    }
    std::vector<unsigned char> vchPrefix;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(AssemblePrivacyVNextPayloadPrefix(header, vIn, vOut, vchPrefix, strError),
                          strError);
    return vchPrefix;
}

} // namespace

// The coordinator fixes one prefix under the agreed view, and it cannot move once seats
// start approving it: a certificate collected over two prefixes would let a coordinator
// show each seat the statement that seat would accept.
BOOST_AUTO_TEST_CASE(a_prefix_is_frozen_once_and_every_seat_approves_the_same_one)
{
    const int64_t nNow = 3665000;
    std::string strError;
    CMixRound round;
    std::vector<Seat> vSeats;
    RoundWithOutputs(round, vSeats, nNow);
    const PrivacyVNextPrefixHeader header = MixHeader();

    BOOST_CHECK_MESSAGE(!round.FreezePrefix(header, PREFIX_ANNOUNCE, &strError),
                        "a prefix froze while outputs could still register");
    const int64_t nClosed = nNow + MIX_OUTPUT_WINDOW + 1;
    BOOST_REQUIRE_MESSAGE(round.OpenSigning(nClosed, &strError), strError);
    BOOST_CHECK(round.PrefixDigest() == 0);
    BOOST_CHECK(!round.PrefixAgreed());

    BOOST_CHECK_MESSAGE(!round.FreezePrefix(header, uint256(0xBAD), &strError),
                        "a prefix froze under a view the seats did not sign");
    PrivacyVNextPrefixHeader wrong = header;
    wrong.transparentBinding.fill(0x44);
    BOOST_CHECK_MESSAGE(!round.FreezePrefix(wrong, PREFIX_ANNOUNCE, &strError),
                        "a prefix froze with a transparent binding no mix carries");
    wrong = header;
    wrong.nTransparentValueBalance = 1;
    BOOST_CHECK(!round.FreezePrefix(wrong, PREFIX_ANNOUNCE, &strError));

    BOOST_REQUIRE_MESSAGE(round.FreezePrefix(header, PREFIX_ANNOUNCE, &strError), strError);
    std::vector<unsigned char> vchAssembled;
    BOOST_REQUIRE(round.AssemblePrefix(header, vchAssembled, &strError));
    BOOST_CHECK(round.FrozenPrefix() == vchAssembled);
    PrivacyVNextDigest signingHash;
    BOOST_REQUIRE(HashPrivacyVNextPayloadPrefix(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                                vchAssembled, signingHash, strError));
    const uint256 hashPrefix = round.PrefixDigest();
    BOOST_CHECK(hashPrefix == MixPrefixDigest(round.ViewDigest(PREFIX_ANNOUNCE), signingHash));

    PrivacyVNextPrefixHeader other = header;
    other.nFee = header.nFee + 1;
    BOOST_CHECK_MESSAGE(!round.FreezePrefix(other, PREFIX_ANNOUNCE, &strError),
                        "a frozen prefix was replaced under the approvals collecting for it");
    BOOST_CHECK(round.FrozenPrefix() == vchAssembled);
    BOOST_CHECK(round.PrefixDigest() == hashPrefix);

    // An approval is a seated key's signature over the frozen digest, once per seat.
    std::vector<unsigned char> vchWrong;
    BOOST_REQUIRE(vSeats[0].key.Sign(MixPrefixDigest(round.ViewDigest(PREFIX_ANNOUNCE),
                                                     MaskOf(0x01)), vchWrong));
    BOOST_CHECK_MESSAGE(!round.SubmitPrefixSignature(vSeats[0].pubkey, vchWrong, &strError),
                        "an approval of another prefix counted for this one");
    const Seat stranger = MakeSeat(7);
    std::vector<unsigned char> vchStranger;
    BOOST_REQUIRE(stranger.key.Sign(hashPrefix, vchStranger));
    BOOST_CHECK(!round.SubmitPrefixSignature(stranger.pubkey, vchStranger, &strError));
    std::vector<unsigned char> vchSig0, vchSig1;
    BOOST_REQUIRE(vSeats[0].key.Sign(hashPrefix, vchSig0));
    BOOST_REQUIRE_MESSAGE(round.SubmitPrefixSignature(vSeats[0].pubkey, vchSig0, &strError),
                          strError);
    BOOST_CHECK(!round.SubmitPrefixSignature(vSeats[0].pubkey, vchSig0, &strError));
    BOOST_CHECK_MESSAGE(!round.PrefixAgreed(), "one approval of two agreed the prefix");
    BOOST_REQUIRE(vSeats[1].key.Sign(hashPrefix, vchSig1));
    BOOST_REQUIRE_MESSAGE(round.SubmitPrefixSignature(vSeats[1].pubkey, vchSig1, &strError),
                          strError);
    BOOST_CHECK(round.PrefixAgreed());
}

// A nonce is a seat's share of the challenge; a prefix fixed after one is in would put
// that share under a statement the seat never saw.
BOOST_AUTO_TEST_CASE(a_prefix_cannot_be_frozen_under_a_nonce)
{
    const int64_t nNow = 3667000;
    std::string strError;
    CMixRound round;
    std::vector<Seat> vSeats;
    RoundWithOutputs(round, vSeats, nNow);
    BOOST_REQUIRE_MESSAGE(round.OpenSigning(nNow + MIX_OUTPUT_WINDOW + 1, &strError), strError);
    BOOST_REQUIRE_MESSAGE(round.SubmitNonce(vSeats[0].pubkey,
                                            std::vector<unsigned char>(32, 0xA5), &strError),
                          strError);
    BOOST_CHECK_MESSAGE(!round.FreezePrefix(MixHeader(), PREFIX_ANNOUNCE, &strError),
                        "a prefix froze after a seat's nonce was already in");
}

// A live round is not reusable, and a reopened one carries no output record, frozen
// prefix, token or authenticated frame from the last.
BOOST_AUTO_TEST_CASE(a_reopened_round_carries_no_records_or_prefix)
{
    const int64_t nNow = 3668000;
    std::string strError;
    CMixRound round;
    std::vector<Seat> vSeats;
    RoundWithOutputs(round, vSeats, nNow);
    BOOST_REQUIRE_MESSAGE(round.OpenSigning(nNow + MIX_OUTPUT_WINDOW + 1, &strError), strError);
    BOOST_REQUIRE_MESSAGE(round.FreezePrefix(MixHeader(), PREFIX_ANNOUNCE, &strError), strError);
    BOOST_REQUIRE_EQUAL(round.OutputRecords().size(), 2u);

    CNullSendSession& server = Coordinator();
    BOOST_CHECK_MESSAGE(!round.Open(ROUND_HASH, 2, server.vchRSA_N, server.vchRSA_E,
                                    true, false, MIX_DENOM, nNow + 1000, &strError),
                        "a live round was reopened, carrying its spent credentials with it");
    round.Abort("test");
    BOOST_REQUIRE(round.Open(ROUND_HASH, 2, server.vchRSA_N, server.vchRSA_E,
                             true, false, MIX_DENOM, nNow + 1000, &strError));
    BOOST_CHECK(round.OutputRecords().empty());
    BOOST_CHECK(round.FrozenPrefix().empty());
    BOOST_CHECK(round.PrefixDigest() == 0);
}

// The seat does not trust the coordinator's statement. It holds every field it can know
// on its own, and refuses a prefix that differs in any of them, including the parts that
// are not its own entries.
BOOST_AUTO_TEST_CASE(a_seat_checks_the_whole_prefix_before_approving_it)
{
    std::string strError;
    const PrivacyVNextPrefixHeader header = MixHeader();
    std::vector<uint256> vRoster;
    vRoster.push_back(uint256(0x0200));
    vRoster.push_back(uint256(0x0100));
    std::vector<uint256> vSorted = vRoster;
    std::sort(vSorted.begin(), vSorted.end(), [](const uint256& a, const uint256& b) {
        return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
    });
    BOOST_REQUIRE(vSorted != vRoster);

    std::vector<std::pair<uint256, PrivacyVNextDigest> > vInputs;
    vInputs.push_back(std::make_pair(vSorted[0], MaskOf(0xE1)));
    vInputs.push_back(std::make_pair(vSorted[1], MaskOf(0xE2)));
    const CMixOutputRecord mine = Rec(uint256(0x7C0), 0xE5);
    const CMixOutputRecord theirs = Rec(uint256(0x7C1), 0xE6);
    std::vector<CMixOutputRecord> vRecords;
    vRecords.push_back(theirs);
    vRecords.push_back(mine);
    const std::vector<uint64_t> vAmounts(2, MIX_DENOM);
    const std::vector<unsigned char> vchPrefix = MixPrefixOver(header, vInputs, vRecords, vAmounts);

    CMixSeatExpectation expect;
    expect.nNetwork = header.nNetwork;
    expect.genesis = header.genesis;
    expect.parameterDigest = header.parameterDigest;
    expect.finalizedRoot = header.finalizedRoot;
    expect.nFinalizedTreeSize = header.nFinalizedTreeSize;
    expect.nFee = header.nFee;
    expect.nDenomination = MIX_DENOM;
    expect.transparentBinding = MixTransparentBinding();
    expect.vRosterKeyImages = vRoster;
    expect.myKeyImage = vSorted[1];
    expect.myPseudoOut = MaskOf(0xE2);
    expect.vMyOutputs.push_back(std::make_pair(-1, mine));
    BOOST_REQUIRE_MESSAGE(CheckMixPrefixForSeat(vchPrefix, expect, strError), strError);

    CMixPrefixView view;
    BOOST_REQUIRE_MESSAGE(ParseMixPrefix(vchPrefix, view, strError), strError);
    BOOST_CHECK_EQUAL((int)view.nOperation, (int)iv5::NOTE_NULLSEND);
    BOOST_CHECK_EQUAL((int)view.nNetwork, (int)header.nNetwork);
    BOOST_CHECK(view.finalizedRoot == header.finalizedRoot);
    BOOST_CHECK_EQUAL(view.nFinalizedTreeSize, header.nFinalizedTreeSize);
    BOOST_CHECK_EQUAL(view.nFee, header.nFee);
    BOOST_CHECK(view.transparentBinding == MixTransparentBinding());
    BOOST_CHECK(view.vKeyImages == vSorted);
    BOOST_REQUIRE_EQUAL(view.vOutputs.size(), 2u);
    std::vector<unsigned char> vchParsed, vchMine;
    BOOST_REQUIRE(EncodeMixOutputRecord(view.vOutputs[1], vchParsed));
    BOOST_REQUIRE(EncodeMixOutputRecord(mine, vchMine));
    BOOST_CHECK(vchParsed == vchMine);

    const auto refused = [](const std::vector<unsigned char>& vch, const CMixSeatExpectation& e,
                            const char* pszWhat) {
        std::string strWhy;
        BOOST_CHECK_MESSAGE(!CheckMixPrefixForSeat(vch, e, strWhy), pszWhat);
    };

    // What the seat knows on its own.
    CMixSeatExpectation e = expect;
    e.nFee = expect.nFee + 1;
    refused(vchPrefix, e, "a prefix at another fee was approved");
    e = expect;
    e.finalizedRoot.fill(0x34);
    refused(vchPrefix, e, "a prefix over another tree root was approved");
    e = expect;
    e.nFinalizedTreeSize = expect.nFinalizedTreeSize + 1;
    refused(vchPrefix, e, "a prefix over another tree size was approved");
    e = expect;
    e.nNetwork = 2;
    refused(vchPrefix, e, "a prefix for another network was approved");
    e = expect;
    e.genesis.fill(0x12);
    refused(vchPrefix, e, "a prefix under another genesis was approved");
    e = expect;
    e.parameterDigest.fill(0x23);
    refused(vchPrefix, e, "a prefix under another parameter digest was approved");
    e = expect;
    e.nDenomination = MIX_DENOM + 1;
    refused(vchPrefix, e, "a prefix at another denomination was approved");
    e = expect;
    e.transparentBinding.fill(0x44);
    refused(vchPrefix, e, "a prefix with another transparent binding was approved");
    e = expect;
    e.vRosterKeyImages.push_back(uint256(0x0300));
    refused(vchPrefix, e, "a prefix missing a rostered input was approved");
    e = expect;
    e.myPseudoOut = MaskOf(0xE3);
    refused(vchPrefix, e, "a prefix carrying another construction for this seat was approved");
    e = expect;
    e.vMyOutputs[0].second = Rec(uint256(0x7C3), 0xE7);
    refused(vchPrefix, e, "a prefix without this seat's output was approved");
    e = expect;
    e.vMyOutputs[0].first = 0;
    refused(vchPrefix, e, "this seat's output was approved at a position it is not valid at");
    e.vMyOutputs[0].first = 1;
    BOOST_CHECK_MESSAGE(CheckMixPrefixForSeat(vchPrefix, e, strError), strError);

    // What the coordinator could change in the prefix.
    PrivacyVNextPrefixHeader h = header;
    h.nFee = header.nFee + 1;
    refused(MixPrefixOver(h, vInputs, vRecords, vAmounts), expect, "a raised fee was approved");
    h = header;
    h.nTransparentValueBalance = 1;
    refused(MixPrefixOver(h, vInputs, vRecords, vAmounts), expect,
            "a prefix moving transparent value was approved");
    h = header;
    h.nDisclosureMask = iv5::DISCLOSURE_MASK;
    refused(MixPrefixOver(h, vInputs, vRecords, vAmounts), expect,
            "a prefix at another disclosure mask was approved");

    std::vector<std::pair<uint256, PrivacyVNextDigest> > vIn = vInputs;
    std::swap(vIn[0], vIn[1]);
    refused(MixPrefixOver(header, vIn, vRecords, vAmounts), expect,
            "inputs out of the agreed order were approved");
    vIn = vInputs;
    vIn[0].second = vIn[1].second;
    refused(MixPrefixOver(header, vIn, vRecords, vAmounts), expect,
            "a repeated pseudo-output was approved");

    std::vector<CMixOutputRecord> vRec = vRecords;
    vRec.push_back(Rec(uint256(0x7C2), 0xE8));
    refused(MixPrefixOver(header, vInputs, vRec, std::vector<uint64_t>(3, MIX_DENOM)), expect,
            "an added output was approved");
    vRec = vRecords;
    vRec.erase(vRec.begin());
    refused(MixPrefixOver(header, vInputs, vRec, std::vector<uint64_t>(1, MIX_DENOM)), expect,
            "a dropped output was approved");
    vRec = vRecords;
    vRec[0] = mine;
    refused(MixPrefixOver(header, vInputs, vRec, vAmounts), expect,
            "this seat's output twice was approved");
    vRec = vRecords;
    vRec[0] = Rec(uint256(0x7C1), mine.commitment, mine.mask);
    refused(MixPrefixOver(header, vInputs, vRec, vAmounts), expect,
            "a repeated commitment was approved");
    vRec = vRecords;
    vRec[0] = Rec(uint256(0x7C1), Commit(MIX_DENOM + 1, MaskOf(0xE9)), MaskOf(0xE9));
    std::vector<uint64_t> vAmt = vAmounts;
    vAmt[0] = MIX_DENOM + 1;
    refused(MixPrefixOver(header, vInputs, vRec, vAmt), expect,
            "an output above the denomination was approved");
    vRec = vRecords;
    vRec[0] = Rec(uint256(0x7C1), theirs.commitment, MaskOf(0xEA));
    refused(MixPrefixOver(header, vInputs, vRec, vAmounts), expect,
            "a disclosed opening that does not open its commitment was approved");

    std::vector<unsigned char> vchLong = vchPrefix;
    vchLong.push_back(0);
    refused(vchLong, expect, "a prefix with a trailing byte was approved");
    const std::vector<unsigned char> vchShort(vchPrefix.begin(), vchPrefix.end() - 1);
    refused(vchShort, expect, "a truncated prefix was approved");
}

// The opening is checked BEFORE the token is spent: the token authorises only the output
// key, and the combiner sees only the sum of openings, so a bad one cannot be attributed later.
BOOST_AUTO_TEST_CASE(an_output_opening_is_checked_before_its_token_is_spent)
{
    const int64_t nNow = 3700000;
    std::string strError;
    CMixRound round;
    std::vector<Seat> vSeats;
    BOOST_REQUIRE(OpenAndFill(round, vSeats, 2, nNow));
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    BOOST_REQUIRE(round.IssueToken(vSeats[0].pubkey, &strError));
    BOOST_REQUIRE(round.IssueToken(vSeats[1].pubkey, &strError));
    BOOST_REQUIRE(round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError));

    const uint256 outputKey = uint256(0x4A0);
    const MixOpening good = Opening(0xC1);
    const MixOpening other = Opening(0xC2);

    // The token binds the whole record, so a participant can still hold a token over a
    // record whose mask does not open its commitment: the coordinator blind-signs without
    // seeing it. That registration is refused, and the token for the GOOD record survives.
    const CMixOutputRecord badMask = Rec(outputKey, good.commitment, other.mask);
    const Token badMaskToken = MintToken(Bundle(badMask, round));
    BOOST_CHECK_MESSAGE(!round.RegisterOutput(badMaskToken.vchCredential,
                                              badMaskToken.vchSignature, Bundle(badMask, round),
                                              nNow, &strError),
                        "an opening that does not open its commitment was accepted");
    BOOST_CHECK(strError.find("does not open") != std::string::npos);
    BOOST_CHECK_EQUAL(round.Outputs(), 0u);

    // A commitment at the wrong amount is refused too: the denomination is what makes the
    // disclosed amounts stop discriminating between outputs.
    const CMixOutputRecord wrongAmount =
        Rec(outputKey, Commit(MIX_DENOM + 1, good.mask), good.mask);
    const Token wrongAmountToken = MintToken(Bundle(wrongAmount, round));
    BOOST_CHECK(!round.RegisterOutput(wrongAmountToken.vchCredential,
                                      wrongAmountToken.vchSignature, Bundle(wrongAmount, round),
                                      nNow, &strError));

    // A token over the good record does not authorise it with the mask swapped in flight.
    const CMixOutputRecord goodRecord = Rec(outputKey, good.commitment, good.mask);
    const Token token = MintToken(Bundle(goodRecord, round));
    BOOST_CHECK(!round.RegisterOutput(token.vchCredential, token.vchSignature, Bundle(badMask, round),
                                      nNow, &strError));
    BOOST_CHECK(strError.find("does not authorise") != std::string::npos);

    // The matching record is taken, and the opening is kept for the combiner in
    // registration order.
    BOOST_REQUIRE_MESSAGE(round.RegisterOutput(token.vchCredential, token.vchSignature, Bundle(goodRecord, round), nNow, &strError), strError);
    BOOST_REQUIRE_EQUAL(round.OutputMasks().size(), 1u);
    BOOST_CHECK(round.OutputMasks()[0] == good.mask);
    BOOST_CHECK(round.OutputCommitments()[0] == good.commitment);
    BOOST_REQUIRE_EQUAL(round.OutputRecords().size(), 1u);
    BOOST_CHECK(round.OutputRecords()[0].OwnerKey() == outputKey);

    // One commitment, once -- two outputs at one commitment is one output paid twice.
    const CMixOutputRecord sameCommitment = Rec(uint256(0x4A1), good.commitment, good.mask);
    const Token second = MintToken(Bundle(sameCommitment, round));
    BOOST_CHECK(!round.RegisterOutput(second.vchCredential, second.vchSignature, Bundle(sameCommitment, round), nNow, &strError));
    BOOST_CHECK(strError.find("already registered") != std::string::npos);
}

// A token covers the canonical bundle: every field of every variant, the variant count and
// order all change the credential, and a wrongly shaped bundle has no credential.
BOOST_AUTO_TEST_CASE(a_token_authorises_every_field_of_every_variant_in_its_bundle)
{
    std::vector<CMixOutputRecord> vBase;
    vBase.push_back(Rec(uint256(0x6A0), 0xE1));
    vBase.push_back(Rec(uint256(0x6A1), 0xE2));
    const uint256 hashBase = MixOutputBundleCredentialHash(vBase);
    BOOST_REQUIRE(hashBase != 0);

    std::vector<unsigned char> vchEncoded;
    BOOST_REQUIRE(EncodeMixOutputBundle(vBase, vchEncoded));
    BOOST_CHECK_EQUAL(vchEncoded.size(), 1 + 2 * MIX_OUTPUT_RECORD_BYTES);
    std::vector<CMixOutputRecord> vDecoded;
    BOOST_REQUIRE(DecodeMixOutputBundle(vchEncoded, vDecoded));
    BOOST_CHECK(MixOutputBundleCredentialHash(vDecoded) == hashBase);

    // Every field of the variant a round would keep, and of the one it would not.
    for (size_t nVariant = 0; nVariant < 2; nVariant++)
    {
        std::vector<std::vector<CMixOutputRecord> > vChanged(7, vBase);
        vChanged[0][nVariant].owner[5] ^= 1;
        vChanged[1][nVariant].commitment[5] ^= 1;
        vChanged[2][nVariant].noteEphemeral[5] ^= 1;
        vChanged[3][nVariant].tweakEphemeral[5] ^= 1;
        vChanged[4][nVariant].vchRecipientCiphertext[100] ^= 1;
        vChanged[5][nVariant].vchOutgoingCiphertext[200] ^= 1;
        vChanged[6][nVariant].mask[5] ^= 1;
        for (size_t i = 0; i < vChanged.size(); i++)
            BOOST_CHECK_MESSAGE(MixOutputBundleCredentialHash(vChanged[i]) != hashBase,
                                "field " << i << " of variant " << nVariant
                                         << " is not bound by its token");
    }

    // The bundle's length and the order of its variants are bound too.
    std::vector<CMixOutputRecord> vSwapped;
    vSwapped.push_back(vBase[1]);
    vSwapped.push_back(vBase[0]);
    BOOST_CHECK_MESSAGE(MixOutputBundleCredentialHash(vSwapped) != hashBase,
                        "a bundle reordered under one token authorises another position");
    std::vector<CMixOutputRecord> vShorter(1, vBase[0]);
    BOOST_CHECK(MixOutputBundleCredentialHash(vShorter) != hashBase);
    std::vector<CMixOutputRecord> vLonger = vBase;
    vLonger.push_back(vBase[0]);
    BOOST_CHECK(MixOutputBundleCredentialHash(vLonger) != hashBase);

    std::vector<CMixOutputRecord> vShortCiphertext = vBase;
    vShortCiphertext[1].vchRecipientCiphertext.pop_back();
    BOOST_CHECK(MixOutputBundleCredentialHash(vShortCiphertext) == 0);
    BOOST_CHECK(!EncodeMixOutputBundle(vShortCiphertext, vchEncoded));
    BOOST_CHECK(MixOutputBundleCredentialHash(std::vector<CMixOutputRecord>()) == 0);
    std::vector<unsigned char> vchTruncated(1 + 2 * MIX_OUTPUT_RECORD_BYTES - 1, 0);
    vchTruncated[0] = 2;
    BOOST_CHECK(!DecodeMixOutputBundle(vchTruncated, vDecoded));
    std::vector<unsigned char> vchZeroCount(1, 0);
    BOOST_CHECK(!DecodeMixOutputBundle(vchZeroCount, vDecoded));
}

// The round hands out positions; a registrant cannot choose one. What it keeps is the
// variant for the position it assigns next, and a bundle is one variant per seat.
BOOST_AUTO_TEST_CASE(a_bundle_gives_the_round_the_variant_for_the_position_it_assigns)
{
    const int64_t nNow = 3900000;
    std::string strError;
    CMixRound round;
    std::vector<Seat> vSeats;
    BOOST_REQUIRE(OpenAndFill(round, vSeats, 2, nNow));
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    for (size_t i = 0; i < vSeats.size(); i++)
        BOOST_REQUIRE(round.IssueToken(vSeats[i].pubkey, &strError));
    BOOST_REQUIRE(round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError));

    std::vector<CMixOutputRecord> vFirst, vSecond;
    vFirst.push_back(Rec(uint256(0x8A0), 0xC1));
    vFirst.push_back(Rec(uint256(0x8A1), 0xC2));
    vSecond.push_back(Rec(uint256(0x8B0), 0xC3));
    vSecond.push_back(Rec(uint256(0x8B1), 0xC4));

    const std::vector<CMixOutputRecord> vShort(1, vFirst[0]);
    const Token shortToken = MintToken(vShort);
    BOOST_CHECK_MESSAGE(!round.RegisterOutput(shortToken.vchCredential, shortToken.vchSignature,
                                              vShort, nNow, &strError),
                        "a bundle short of a variant per seat registered an output");
    std::vector<CMixOutputRecord> vLong = vFirst;
    vLong.push_back(vFirst[0]);
    const Token longToken = MintToken(vLong);
    BOOST_CHECK(!round.RegisterOutput(longToken.vchCredential, longToken.vchSignature, vLong,
                                      nNow, &strError));

    const Token first = MintToken(vFirst);
    BOOST_REQUIRE_MESSAGE(round.RegisterOutput(first.vchCredential, first.vchSignature, vFirst,
                                               nNow, &strError), strError);
    const Token second = MintToken(vSecond);
    BOOST_REQUIRE_MESSAGE(round.RegisterOutput(second.vchCredential, second.vchSignature, vSecond,
                                               nNow, &strError), strError);
    BOOST_REQUIRE_EQUAL(round.OutputRecords().size(), 2u);
    std::vector<unsigned char> vchKept, vchWanted;
    BOOST_REQUIRE(EncodeMixOutputRecord(round.OutputRecords()[0], vchKept));
    BOOST_REQUIRE(EncodeMixOutputRecord(vFirst[0], vchWanted));
    BOOST_CHECK_MESSAGE(vchKept == vchWanted,
                        "the first registration did not keep its variant for position 0");
    BOOST_REQUIRE(EncodeMixOutputRecord(round.OutputRecords()[1], vchKept));
    BOOST_REQUIRE(EncodeMixOutputRecord(vSecond[1], vchWanted));
    BOOST_CHECK_MESSAGE(vchKept == vchWanted,
                        "the second registration did not keep its variant for position 1");
}

// A bundle of the wrong shape has no credential at all. The coordinator blind-signs
// whatever message it is handed, so a caller can hold a valid signature over the empty
// hash -- and without the shape check that token would open a malformed bundle.
BOOST_AUTO_TEST_CASE(a_malformed_bundle_has_no_credential_for_a_token_to_open)
{
    const int64_t nNow = 3950000;
    std::string strError;
    CMixRound round;
    std::vector<Seat> vSeats;
    BOOST_REQUIRE(OpenAndFill(round, vSeats, 2, nNow));
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    for (size_t i = 0; i < vSeats.size(); i++)
        BOOST_REQUIRE(round.IssueToken(vSeats[i].pubkey, &strError));
    BOOST_REQUIRE(round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError));

    CNullSendSession& server = Coordinator();
    CNullSendClient client;
    BOOST_REQUIRE(client.BlindCredentialMessage(server.vchRSA_N, server.vchRSA_E, uint256(0)));
    std::vector<unsigned char> vchBlindSig;
    BOOST_REQUIRE(server.BlindSign(client.vchBlindedCredential, vchBlindSig));
    BOOST_REQUIRE(client.UnblindSignature(vchBlindSig));

    std::vector<CMixOutputRecord> vMalformed(2, Rec(uint256(0x8C0), 0xD1));
    vMalformed[0].vchRecipientCiphertext.pop_back();
    BOOST_REQUIRE(MixOutputBundleCredentialHash(vMalformed) == 0);
    BOOST_CHECK_MESSAGE(!round.RegisterOutput(client.vchCredentialHash, client.vchUnblindedSig,
                                              vMalformed, nNow, &strError),
                        "a bundle with no credential registered under a token over the empty hash");
    BOOST_CHECK_EQUAL(round.Outputs(), 0u);
}

// A round opened without a denomination cannot check an opening, so it registers nothing
// rather than accepting one it cannot judge.
BOOST_AUTO_TEST_CASE(a_round_with_no_denomination_registers_no_output)
{
    const int64_t nNow = 3800000;
    std::string strError;
    CNullSendSession& server = Coordinator();
    CMixRound round;
    BOOST_REQUIRE(round.Open(ROUND_HASH, 2, server.vchRSA_N, server.vchRSA_E,
                             true, false, 0, nNow, &strError));
    const Seat a = MakeSeat(0x810), b = MakeSeat(0x811);
    BOOST_REQUIRE(round.Join(a.pubkey, a.keyImage, &strError));
    BOOST_REQUIRE(round.Join(b.pubkey, b.keyImage, &strError));
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    BOOST_REQUIRE(round.IssueToken(a.pubkey, &strError));
    BOOST_REQUIRE(round.IssueToken(b.pubkey, &strError));
    BOOST_REQUIRE(round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError));

    const CMixOutputRecord record = Rec(uint256(0x4B0), 0xD1);
    const Token token = MintToken(Bundle(record, round));
    BOOST_CHECK(!round.RegisterOutput(token.vchCredential, token.vchSignature, Bundle(record, round),
                                      nNow, &strError));
    BOOST_CHECK(strError.find("denomination") != std::string::npos);
    BOOST_CHECK_EQUAL(round.Outputs(), 0u);
}

// The credential names the OUTPUT RECORD and nothing else: a round identifier in it would
// let a coordinator that gives each seat its own round id identify the seat from OUTPUT.
// Pinned as: ONE credential opens in ANY round issued under the same key.
BOOST_AUTO_TEST_CASE(a_token_does_not_name_the_round_it_is_spent_in)
{
    const int64_t nNow = 3300000;
    CNullSendSession& server = Coordinator();
    std::string strError;

    const uint256 outputKey = uint256(0x515);
    const CMixOutputRecord record = Rec(outputKey, 0x66);
    const std::vector<CMixOutputRecord> vBundle(2, record);
    const Token token = MintToken(vBundle);
    BOOST_REQUIRE_EQUAL(token.vchCredential.size(), 32u);

    // The credential is exactly H(tag || bundle): no round, no seat, nothing else.
    std::vector<unsigned char> vchBundle;
    BOOST_REQUIRE(EncodeMixOutputBundle(vBundle, vchBundle));
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("innova/iv5/mix/token/v4");
    ss << vchBundle;
    const uint256 hashExpected = ss.GetHash();
    BOOST_CHECK(hashExpected == MixOutputBundleCredentialHash(vBundle));
    BOOST_CHECK(std::equal(hashExpected.begin(), hashExpected.end(),
                           token.vchCredential.begin()));

    // Two rounds with DIFFERENT identifiers, one key. The same token opens in both, which
    // is what proves the credential carries no round. If it named the round, the second
    // registration would fail -- and that failure is exactly the tag.
    const uint256 vRounds[2] = { uint256(0xA11CE), uint256(0xB0B) };
    BOOST_REQUIRE(vRounds[0] != vRounds[1]);
    for (int i = 0; i < 2; i++)
    {
        CMixRound round;
        BOOST_REQUIRE(round.Open(vRounds[i], 2, server.vchRSA_N, server.vchRSA_E,
                                 true, false, MIX_DENOM, nNow, &strError));
        const Seat a = MakeSeat((unsigned int)(0x900 + i * 2));
        const Seat b = MakeSeat((unsigned int)(0x901 + i * 2));
        BOOST_REQUIRE(round.Join(a.pubkey, a.keyImage, &strError));
        BOOST_REQUIRE(round.Join(b.pubkey, b.keyImage, &strError));
        BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
        BOOST_REQUIRE(round.IssueToken(a.pubkey, &strError));
        BOOST_REQUIRE(round.IssueToken(b.pubkey, &strError));
        BOOST_REQUIRE(round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError));
        BOOST_CHECK_MESSAGE(
            round.RegisterOutput(token.vchCredential, token.vchSignature, vBundle, nNow,
                                 &strError),
            "round " << i << " refused a token minted without naming it: " << strError);
    }

    // Round separation therefore comes from the KEY, which a driver must draw fresh per
    // round. That obligation is stated in the header and cannot be enforced here.
}

// The key-set frame carries one order and refuses any other. A reordered set derives a
// different self-pay input_context, and the seat silently never finds its own output.
BOOST_AUTO_TEST_CASE(the_key_set_frame_carries_one_order_and_refuses_the_other)
{
    // The pair uint256 and byte order disagree on.
    uint256 hi, lo;
    hi = 0; lo = 0;
    hi.begin()[0] = 0x01;    // 0x01 00 .. 00
    lo.begin()[31] = 0x02;   // 0x00 .. 00 02
    BOOST_REQUIRE_MESSAGE(hi < lo, "the fixture needs a pair the two orders disagree on");

    std::vector<uint256> vByteOrder;
    vByteOrder.push_back(lo);   // byte 0 is 0x00, so it sorts first as bytes
    vByteOrder.push_back(hi);

    std::vector<unsigned char> vchBody;
    BOOST_REQUIRE(BuildMixKeySetBody(vByteOrder, vchBody));

    std::vector<uint256> vRead;
    BOOST_REQUIRE(ReadMixKeySetBody(vchBody, vRead));
    BOOST_REQUIRE_EQUAL(vRead.size(), 2u);
    BOOST_CHECK(vRead[0] == lo);
    BOOST_CHECK(vRead[1] == hi);

    // It is the order PrivacyVNextChangeIndexFor derives the index from: the same set as
    // 32-byte arrays. This is the cross-derivation check, not a restatement of the sort.
    std::vector<PrivacyVNextDigest> vAsDigests(2);
    std::memcpy(vAsDigests[0].data(), hi.begin(), 32);
    std::memcpy(vAsDigests[1].data(), lo.begin(), 32);
    std::sort(vAsDigests.begin(), vAsDigests.end());
    for (size_t i = 0; i < 2; i++)
        BOOST_CHECK_MESSAGE(std::memcmp(vRead[i].begin(), vAsDigests[i].data(), 32) == 0,
                            "the frame order and the index derivation disagree at " << i);

    // The uint256 order is refused on the way out AND on the way in -- neither side
    // silently sorts, because sorting is what hides the disagreement.
    std::vector<uint256> vIntOrder;
    vIntOrder.push_back(hi);
    vIntOrder.push_back(lo);
    std::vector<unsigned char> vchRefused;
    BOOST_CHECK_MESSAGE(!BuildMixKeySetBody(vIntOrder, vchRefused),
                        "the builder accepted a set in the integer order");

    std::vector<unsigned char> vchHand;
    PutU16Test(vchHand, 2);
    vchHand.insert(vchHand.end(), hi.begin(), hi.end());
    vchHand.insert(vchHand.end(), lo.begin(), lo.end());
    std::vector<uint256> vOut;
    BOOST_CHECK_MESSAGE(!ReadMixKeySetBody(vchHand, vOut),
                        "the reader accepted a set it would have had to reorder");

    // A repeat is not a set of n seats.
    std::vector<uint256> vDup;
    vDup.push_back(lo);
    vDup.push_back(lo);
    BOOST_CHECK(!BuildMixKeySetBody(vDup, vchRefused));

    // And the frozen set a round produces goes through the frame unchanged.
    const int64_t nNow = 3900000;
    std::string strError;
    CMixRound round;
    std::vector<Seat> vSeats;
    BOOST_REQUIRE(OpenAndFill(round, vSeats, 3, nNow));
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    std::vector<unsigned char> vchFrozen;
    BOOST_REQUIRE(BuildMixKeySetBody(round.FinalKeyImages(), vchFrozen));
    std::vector<uint256> vRoundTrip;
    BOOST_REQUIRE(ReadMixKeySetBody(vchFrozen, vRoundTrip));
    BOOST_CHECK(vRoundTrip == round.FinalKeyImages());
}

// The frozen set is sorted as BYTES, as PrivacyVNextChangeIndexFor derives it (uint256
// compares little-endian). The other order derives an input_context the scanner never rebuilds.
BOOST_AUTO_TEST_CASE(the_frozen_set_is_ordered_the_way_the_index_derives_it)
{
    // The pair the two orders disagree on: as bytes B < A, as an integer A < B.
    uint256 hiFirst, loFirst;
    hiFirst = 0; loFirst = 0;
    hiFirst.begin()[0] = 0x01;    // 0x01 00 .. 00
    loFirst.begin()[31] = 0x02;   // 0x00 .. 00 02
    BOOST_REQUIRE_MESSAGE(hiFirst < loFirst,
                          "the fixture must pick a pair uint256 orders the other way, or "
                          "this case proves nothing");

    const int64_t nNow = 3200000;
    CNullSendSession& server = Coordinator();
    CMixRound round;
    std::string strError;
    BOOST_REQUIRE(round.Open(ROUND_HASH, 2, server.vchRSA_N, server.vchRSA_E,
                             true, false, MIX_DENOM, nNow, &strError));
    Seat a = MakeSeat(1); a.keyImage = hiFirst;
    Seat b = MakeSeat(2); b.keyImage = loFirst;
    BOOST_REQUIRE(round.Join(a.pubkey, a.keyImage, &strError));
    BOOST_REQUIRE(round.Join(b.pubkey, b.keyImage, &strError));
    BOOST_REQUIRE_MESSAGE(round.CloseJoin(nNow, &strError), strError);

    const std::vector<uint256>& vFrozen = round.FinalKeyImages();
    BOOST_REQUIRE_EQUAL(vFrozen.size(), 2u);

    // What the index derivation would do with the same set, held as it holds it.
    std::vector<PrivacyVNextDigest> vAsDigests(2);
    std::memcpy(vAsDigests[0].data(), hiFirst.begin(), 32);
    std::memcpy(vAsDigests[1].data(), loFirst.begin(), 32);
    std::sort(vAsDigests.begin(), vAsDigests.end());

    for (size_t i = 0; i < 2; i++)
        BOOST_CHECK_MESSAGE(
            std::memcmp(vFrozen[i].begin(), vAsDigests[i].data(), 32) == 0,
            "the frozen set and the index derivation disagree at position " << i);
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
                                      false, false, MIX_DENOM, 5000000, &strError),
                        "a round opened with no stream isolation and no override");
    BOOST_CHECK(strError.find("isolation") != std::string::npos);
    BOOST_CHECK_EQUAL((int)refused.Phase(), (int)MIX_PHASE_ABORTED);

    // The operator may say so, and then it opens.
    CMixRound overridden;
    BOOST_CHECK(overridden.Open(uint256(1), 3, server.vchRSA_N, server.vchRSA_E,
                                false, true, MIX_DENOM, 5000000, &strError));
    BOOST_CHECK_EQUAL((int)overridden.Phase(), (int)MIX_PHASE_JOIN);
}

BOOST_AUTO_TEST_CASE(a_seat_is_one_session_key_and_one_note)
{
    const int64_t nNow = 6000000;
    CNullSendSession& server = Coordinator();
    CMixRound round;
    std::string strError;
    BOOST_REQUIRE(round.Open(uint256(2), 3, server.vchRSA_N, server.vchRSA_E,
                             true, false, MIX_DENOM, nNow, &strError));

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
    BOOST_CHECK(!round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError));
    BOOST_REQUIRE(round.IssueToken(b.pubkey, &strError));
    BOOST_REQUIRE(round.IssueToken(c.pubkey, &strError));
    BOOST_CHECK(round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError));
}

// The window decorrelates arrival from publication order for an outside observer only
// (the coordinator sees every arrival). Publication waits for the window even when the
// round is otherwise finished.
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
    BOOST_REQUIRE(round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError));

    const Token first = MintToken(Bundle(Rec(uint256(800), 0x93), round));
    BOOST_REQUIRE(round.RegisterOutput(first.vchCredential, first.vchSignature, Bundle(Rec(uint256(800), 0x93), round), nNow, &strError));
    BOOST_CHECK(!round.CanPublish(nNow + 1));
    const Token second = MintToken(Bundle(Rec(uint256(801), 0x3b), round));
    BOOST_REQUIRE(round.RegisterOutput(second.vchCredential, second.vchSignature, Bundle(Rec(uint256(801), 0x3b), round), nNow + 1, &strError));

    BOOST_CHECK_MESSAGE(!round.CanPublish(nNow + 2),
                        "the round published as soon as the last output arrived, so the "
                        "two lists are in the same order");
    BOOST_CHECK(!round.CanPublish(nNow + MIX_OUTPUT_WINDOW));
    BOOST_CHECK(round.CanPublish(nNow + MIX_OUTPUT_WINDOW + 1));

    // A late output is refused rather than reopening the window.
    const Token late = MintToken(Bundle(Rec(uint256(802), 0xb5), round));
    BOOST_CHECK(!round.RegisterOutput(late.vchCredential, late.vchSignature, Bundle(Rec(uint256(802), 0xb5), round), nNow + MIX_OUTPUT_WINDOW + 1, &strError));
}

// A phase is reached by passing through the one before it.
BOOST_AUTO_TEST_CASE(the_phases_run_in_order)
{
    const int64_t nNow = 8000000;
    CMixRound round;
    std::vector<Seat> vSeats;
    BOOST_REQUIRE(OpenAndFill(round, vSeats, 2, nNow));
    std::string strError;

    const Token early = MintToken(Bundle(Rec(uint256(1), 0xd0), round));
    BOOST_CHECK(!round.RegisterOutput(early.vchCredential, early.vchSignature, Bundle(Rec(uint256(1), 0xd0), round), nNow, &strError));
    BOOST_CHECK(!round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError));
    BOOST_CHECK(!round.IssueToken(vSeats[0].pubkey, &strError));

    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    BOOST_CHECK(!round.CloseJoin(nNow, &strError));
    BOOST_CHECK(!round.RegisterOutput(early.vchCredential, early.vchSignature, Bundle(Rec(uint256(1), 0xd0), round), nNow, &strError));

    // An aborted round accepts nothing further.
    round.Abort("operator stopped it");
    BOOST_CHECK(!round.IssueToken(vSeats[0].pubkey, &strError));
    BOOST_CHECK(!round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError));
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
    BOOST_REQUIRE(round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError));
    const Token a = MintToken(Bundle(Rec(uint256(1), 0xd0), round));
    BOOST_REQUIRE(round.RegisterOutput(a.vchCredential, a.vchSignature, Bundle(Rec(uint256(1), 0xd0), round), nNow, &strError));
    const Token b = MintToken(Bundle(Rec(uint256(2), 0x26), round));
    BOOST_REQUIRE(round.RegisterOutput(b.vchCredential, b.vchSignature, Bundle(Rec(uint256(2), 0x26), round), nNow, &strError));

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
    BOOST_REQUIRE(round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError));
    const Token a = MintToken(Bundle(Rec(uint256(3), 0xe3), round));
    BOOST_REQUIRE(round.RegisterOutput(a.vchCredential, a.vchSignature, Bundle(Rec(uint256(3), 0xe3), round), nNow, &strError));
    const Token b = MintToken(Bundle(Rec(uint256(4), 0x7f), round));
    BOOST_REQUIRE(round.RegisterOutput(b.vchCredential, b.vchSignature, Bundle(Rec(uint256(4), 0x7f), round), nNow, &strError));

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
    BOOST_REQUIRE(round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError));
    for (int i = 0; i < 3; i++)
    {
        const Token t = MintToken(Bundle(Rec(uint256(20 + i), (unsigned char)(0x6f + i)), round));
        BOOST_REQUIRE(round.RegisterOutput(t.vchCredential, t.vchSignature, Bundle(Rec(uint256(20 + i), (unsigned char)(0x6f + i)), round), nNow, &strError));
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
        PrivacyVNextMixBalanceCombine(mix.facts, vNonces, vResponses, mix.vOutputMasks,
                                      vchProof, strError),
        strError);
    BOOST_CHECK_EQUAL(vchProof.size(), 64u);

    std::vector<PrivacyVNextDigest> vBad = vResponses;
    vBad[1][0] ^= 0x01;
    std::vector<unsigned char> vchNoProof;
    BOOST_CHECK_MESSAGE(
        !PrivacyVNextMixBalanceCombine(mix.facts, vNonces, vBad, mix.vOutputMasks, vchNoProof,
                                       strError),
        "a wrong share produced a proof, so the combine did not verify what it returned");
    BOOST_CHECK(vchNoProof.empty());

    // Nor can the combiner fold in openings it does not hold.
    std::vector<PrivacyVNextDigest> vWrongMasks = mix.vOutputMasks;
    vWrongMasks[0] = MaskOf(0x6e);
    std::vector<unsigned char> vchWrongMaskProof;
    BOOST_CHECK(!PrivacyVNextMixBalanceCombine(mix.facts, vNonces, vResponses, vWrongMasks,
                                               vchWrongMaskProof, strError));

    // A mask that does not open the share's own pair is refused at round one, before
    // any nonce exists.
    PrivacyVNextMixBalanceShare wrong = mix.vShares[0];
    wrong.mask = MaskOf(0x7f);
    PrivacyVNextDigest unused;
    BOOST_CHECK(!PrivacyVNextMixBalanceNonce(mix.facts, wrong, unused, strError));

    // And an output opening that is not this seat's is refused there too: the pair check
    // survived the change, only the scalar the response carries did not.
    PrivacyVNextMixBalanceShare wrongOutput = mix.vShares[0];
    wrongOutput.outputMask = MaskOf(0x7e);
    BOOST_CHECK(!PrivacyVNextMixBalanceNonce(mix.facts, wrongOutput, unused, strError));
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

// -- Dispatch, over the wire format -------------------------------------------

namespace {

// One authenticated frame payload, as a participant would put it on the wire.
std::vector<unsigned char> AuthedFrame(const Seat& seat, const uint256& hashRound,
                                       MixFrameType nType,
                                       const std::vector<unsigned char>& vchBody)
{
    std::vector<unsigned char> vchPayload;
    BOOST_REQUIRE(BuildAuthedMixFrame(seat.key, hashRound, nType, vchBody, vchPayload));
    return vchPayload;
}

std::vector<unsigned char> JoinFrame(const Seat& seat, const uint256& hashRound)
{
    std::vector<unsigned char> vchBody;
    BOOST_REQUIRE(BuildMixJoinBody(seat.pubkey, seat.keyImage, vchBody));
    return AuthedFrame(seat, hashRound, MIX_FRAME_JOIN, vchBody);
}

std::vector<unsigned char> ScalarFrame(const Seat& seat, const uint256& hashRound,
                                       MixFrameType nType, unsigned char ch)
{
    std::vector<unsigned char> vchBody;
    BOOST_REQUIRE(BuildMixScalarBody(seat.pubkey, std::vector<unsigned char>(32, ch), vchBody));
    return AuthedFrame(seat, hashRound, nType, vchBody);
}

std::vector<unsigned char> OutputFrame(const Token& token,
                                       const std::vector<CMixOutputRecord>& vBundle)
{
    std::vector<unsigned char> vchBody;
    BOOST_REQUIRE(BuildMixOutputBundleBody(token.vchCredential, token.vchSignature, vBundle,
                                           vchBody));
    return vchBody;
}

// Each seat's input carries its output's denomination plus its share of the fee.
const uint64_t MIX_FEE_SHARE = 500;

// A real two-seat mix built once: two notes in one tree, two outputs under the mix's input
// context, and every proof for the one prefix. Valid for any seats with these key images.
struct MixProofSet
{
    PrivacyVNextPrefixHeader header;
    std::vector<uint256> vKeyImages;                     // funding order
    std::vector<PrivacyVNextDigest> vPseudoOuts;
    std::vector<std::vector<CMixOutputRecord> > vBundles; // seat i's variants, position order
    std::vector<CMixOutputRecord> vRecords;              // the variant kept at position i
    std::vector<std::vector<unsigned char> > vProofs;    // funding order, under the prefix
    std::vector<unsigned char> vchOtherHashProof;        // input 0 under another signing hash
    std::vector<PrivacyVNextDigest> vSeatMasks;          // note mask plus the proving delta
    std::vector<PrivacyVNextScanKey> vRecipients;        // who each record pays
    std::vector<PrivacyVNextSpendInput> vSpends;         // the notes themselves, for a client
    std::vector<PrivacyVNextDigest> vNoteMasks;
};

PrivacyVNextDigest LowScalar(unsigned char ch)
{
    PrivacyVNextDigest d;
    d.fill(0);
    d[0] = ch;
    return d;
}

const MixProofSet& MixProofs()
{
    static MixProofSet set;
    static bool fBuilt = false;
    if (fBuilt)
        return set;
    std::string error;
    CTxDB txdb("r+");
    PrivacyVNextDigest genesis;
    PrivacyVNextLocalGenesis(genesis.data());
    const uint8_t nNetwork = PrivacyVNextLocalNetworkId();
    PrivacyVNextDigest context;
    BOOST_REQUIRE_MESSAGE(DerivePrivacyVNextInputContext(iv5::NOTE_SHIELD, MixTransparentBinding(),
                                                         std::vector<PrivacyVNextDigest>(),
                                                         context, error), error);

    const size_t nInputs = 2;
    std::vector<PrivacyVNextDerivedKeys> vKeys(nInputs);
    std::vector<PrivacyVNextEncryptedOutput> vEncrypted(nInputs);
    std::vector<PrivacyVNextOutputLeaf> vLeaves;
    for (size_t i = 0; i < nInputs; i++)
    {
        PrivacyVNextDigest seed;
        seed.fill((unsigned char)(0x61 + i));
        BOOST_REQUIRE_MESSAGE(DerivePrivacyVNextKeys(seed, genesis, 0, nNetwork, 0, vKeys[i], error),
                              error);
        const unsigned char chBase = (unsigned char)(0x11 + 4 * i);
        BOOST_REQUIRE_MESSAGE(
            EncryptPrivacyVNextNote(nNetwork, 0, 0, genesis, vKeys[i].spendPublic,
                                    vKeys[i].viewPublic, vKeys[i].outgoingViewSecret,
                                    LowScalar(chBase), LowScalar(chBase + 1),
                                    MIX_DENOM + MIX_FEE_SHARE,
                                    LowScalar(chBase + 2), LowScalar(chBase + 3), context,
                                    vEncrypted[i], error),
            error);
        vLeaves.push_back(vEncrypted[i].leaf);
    }

    PrivacyVNextEpochSeed epochSeed;
    BOOST_REQUIRE_MESSAGE(LoadPrivacyVNextEpochSeed(epochSeed, error), error);
    std::vector<unsigned char> treeState = epochSeed.vchTreeState;
    BOOST_REQUIRE_MESSAGE(TrimPrivacyVNextTreeStore(txdb, 0, treeState, error), error);
    BOOST_REQUIRE_MESSAGE(GrowPrivacyVNextTreeStore(txdb, vLeaves, treeState, error), error);
    std::vector<unsigned char> vchRoot;
    uint64_t nTreeSize = 0;
    BOOST_REQUIRE_MESSAGE(DecodePrivacyVNextTreeState(treeState, vchRoot, nTreeSize, error), error);
    BOOST_REQUIRE_EQUAL(vchRoot.size(), 32u);
    PrivacyVNextDigest root;
    memcpy(root.data(), &vchRoot[0], 32);
    std::vector<uint64_t> vTargets;
    for (size_t i = 0; i < nInputs; i++)
        vTargets.push_back(i);
    std::vector<unsigned char> vchPaths;
    BOOST_REQUIRE_MESSAGE(ReadPrivacyVNextTreePaths(txdb, nTreeSize, treeState, vTargets, vchPaths,
                                                    error), error);
    std::vector<PrivacyVNextMembershipWitness> vWitnesses;
    PrivacyVNextDigest treeRoot;
    BOOST_REQUIRE_MESSAGE(BuildPrivacyVNextWitnessesFromPaths(treeState, vTargets, vchPaths,
                                                              vWitnesses, treeRoot, error), error);
    BOOST_REQUIRE_EQUAL(vWitnesses.size(), nInputs);

    std::vector<PrivacyVNextSpendInput> vSpends(nInputs);
    std::vector<PrivacyVNextDigest> vNoteMasks(nInputs);
    for (size_t i = 0; i < nInputs; i++)
    {
        PrivacyVNextEncryptedNote onChain;
        onChain.nOutputIndex = 0;
        onChain.genesis = genesis;
        onChain.leafO = vEncrypted[i].leaf.owner;
        onChain.leafC = vEncrypted[i].leaf.commitment;
        onChain.noteEphemeral = vEncrypted[i].noteEphemeral;
        onChain.tweakEphemeral = vEncrypted[i].tweakEphemeral;
        onChain.vchCiphertext = vEncrypted[i].vchRecipientCiphertext;
        onChain.inputContext = context;
        PrivacyVNextScannedNote scanned;
        BOOST_REQUIRE_MESSAGE(ScanPrivacyVNextNote(PRIVACY_VNEXT_SCAN_FULL, nNetwork, 0, onChain,
                                                   vKeys[i].viewSecret, vKeys[i].spendSecret,
                                                   scanned, error), error);
        vSpends[i].spendScalar = scanned.spendSecret;
        vSpends[i].commitmentScalar = scanned.y;
        vSpends[i].leaf = vEncrypted[i].leaf;
        vSpends[i].vchWitnessRecord = vWitnesses[i].vchRecord;
        vNoteMasks[i] = scanned.mask;
    }

    // Pass one fixes each input's pseudo-output and key image; the signing hash does not
    // enter them.
    PrivacyVNextDigest provisional;
    provisional.fill(0);
    provisional[0] = 1;
    for (size_t i = 0; i < nInputs; i++)
    {
        const std::vector<PrivacyVNextSpendInput> one(1, vSpends[i]);
        std::vector<PrivacyVNextSpendConstruction> vDraft;
        std::vector<unsigned char> vchDraft;
        BOOST_REQUIRE_MESSAGE(ProvePrivacyVNextMembership(root, provisional,
                                                          LowScalar((unsigned char)(0x71 + i)),
                                                          one, vDraft, vchDraft, error), error);
        BOOST_REQUIRE_EQUAL(vDraft.size(), 1u);
        uint256 keyImage;
        memcpy(keyImage.begin(), vDraft[0].keyImage.data(), 32);
        set.vKeyImages.push_back(keyImage);
        set.vPseudoOuts.push_back(vDraft[0].pseudoOut);
        if (i == 0)
            set.vchOtherHashProof = vchDraft;
    }

    set.vSpends = vSpends;
    set.vNoteMasks = vNoteMasks;
    set.header = MixHeader();
    set.header.nNetwork = nNetwork;
    set.header.genesis = genesis;
    BOOST_REQUIRE_EQUAL(epochSeed.vchParameterDigest.size(), 32u);
    memcpy(set.header.parameterDigest.data(), &epochSeed.vchParameterDigest[0], 32);
    set.header.finalizedRoot = root;
    set.header.nFinalizedTreeSize = nTreeSize;
    set.header.nFee = nInputs * MIX_FEE_SHARE;
    std::vector<std::pair<uint256, PrivacyVNextDigest> > vSorted;
    for (size_t i = 0; i < nInputs; i++)
        vSorted.push_back(std::make_pair(set.vKeyImages[i], set.vPseudoOuts[i]));
    std::sort(vSorted.begin(), vSorted.end(),
              [](const std::pair<uint256, PrivacyVNextDigest>& a,
                 const std::pair<uint256, PrivacyVNextDigest>& b) {
                  return std::lexicographical_compare(a.first.begin(), a.first.end(),
                                                      b.first.begin(), b.first.end());
              });

    // Outputs derive under the mix's input context: its operation, its binding, and the key
    // images in input order.
    std::vector<PrivacyVNextDigest> vInputImages;
    for (size_t i = 0; i < vSorted.size(); i++)
    {
        PrivacyVNextDigest d;
        memcpy(d.data(), vSorted[i].first.begin(), 32);
        vInputImages.push_back(d);
    }
    PrivacyVNextDigest mixContext;
    BOOST_REQUIRE_MESSAGE(DerivePrivacyVNextInputContext(iv5::NOTE_NULLSEND, MixTransparentBinding(),
                                                         vInputImages, mixContext, error), error);
    // One bundle per seat: a variant for every position it might be given, with the same
    // amount, opening and commitment and its own ephemerals per position.
    for (size_t i = 0; i < nInputs; i++)
    {
        PrivacyVNextDigest seed;
        seed.fill((unsigned char)(0x91 + i));
        PrivacyVNextDerivedKeys recipient;
        BOOST_REQUIRE_MESSAGE(DerivePrivacyVNextKeys(seed, genesis, 0, nNetwork, 0, recipient, error),
                              error);
        const unsigned char chBase = (unsigned char)(0x41 + 8 * i);
        const PrivacyVNextDigest outputMask = LowScalar(chBase + 7);
        std::vector<std::pair<PrivacyVNextDigest, PrivacyVNextDigest> > vEphemerals;
        for (size_t j = 0; j < nInputs; j++)
            vEphemerals.push_back(std::make_pair(LowScalar((unsigned char)(chBase + 2 * j)),
                                                 LowScalar((unsigned char)(chBase + 2 * j + 1))));
        std::vector<CMixOutputRecord> vBundle;
        BOOST_REQUIRE_MESSAGE(
            BuildMixOutputBundle(nNetwork, genesis, recipient.spendPublic, recipient.viewPublic,
                                 vKeys[i].outgoingViewSecret, mixContext, MIX_DENOM,
                                 LowScalar(chBase + 6), outputMask, vEphemerals, vBundle, error),
            error);
        BOOST_REQUIRE_EQUAL(vBundle.size(), nInputs);
        set.vBundles.push_back(vBundle);
        set.vRecords.push_back(vBundle[i]);
        PrivacyVNextScanKey scanKey;
        scanKey.scanSecret = recipient.viewSecret;
        scanKey.spendMaterial = recipient.spendSecret;
        set.vRecipients.push_back(scanKey);
    }

    const std::vector<unsigned char> vchPrefix =
        MixPrefixOver(set.header, vSorted, set.vRecords,
                      std::vector<uint64_t>(nInputs, MIX_DENOM));
    PrivacyVNextDigest signingHash;
    BOOST_REQUIRE_MESSAGE(HashPrivacyVNextPayloadPrefix(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                                        vchPrefix, signingHash, error), error);

    for (size_t i = 0; i < nInputs; i++)
    {
        const std::vector<PrivacyVNextSpendInput> one(1, vSpends[i]);
        std::vector<PrivacyVNextSpendConstruction> vFinal;
        std::vector<unsigned char> vchProof;
        BOOST_REQUIRE_MESSAGE(ProvePrivacyVNextMembership(root, signingHash,
                                                          LowScalar((unsigned char)(0x71 + i)),
                                                          one, vFinal, vchProof, error), error);
        BOOST_REQUIRE(vFinal.size() == 1 && vFinal[0].pseudoOut == set.vPseudoOuts[i]);
        set.vProofs.push_back(vchProof);
        std::vector<unsigned char> vchSeatMask;
        BOOST_REQUIRE(Ed25519ScalarAdd(std::vector<unsigned char>(vNoteMasks[i].begin(),
                                                                  vNoteMasks[i].end()),
                                       std::vector<unsigned char>(vFinal[0].pseudoOutMaskDelta.begin(),
                                                                  vFinal[0].pseudoOutMaskDelta.end()),
                                       vchSeatMask));
        BOOST_REQUIRE_EQUAL(vchSeatMask.size(), 32u);
        PrivacyVNextDigest seatMask;
        memcpy(seatMask.data(), &vchSeatMask[0], 32);
        set.vSeatMasks.push_back(seatMask);
    }
    fBuilt = true;
    return set;
}

size_t ProvenIndex(const uint256& keyImage)
{
    const MixProofSet& proofs = MixProofs();
    for (size_t i = 0; i < proofs.vKeyImages.size(); i++)
        if (proofs.vKeyImages[i] == keyImage)
            return i;
    BOOST_FAIL("no proven input for that key image");
    return 0;
}

Seat ProvenSeat(size_t nIndex)
{
    Seat seat = MakeSeat(1);
    seat.keyImage = MixProofs().vKeyImages[nIndex];
    return seat;
}

// Every seat signs the view and submits its construction, over the wire.
void AgreeViewOverWire(CMixRound& round, const std::vector<Seat>& vSeats,
                       const uint256& hashRound, int64_t nNow)
{
    std::string strError;
    const uint256 hashView = round.ViewDigest(PREFIX_ANNOUNCE);
    for (size_t i = 0; i < vSeats.size(); i++)
    {
        std::vector<unsigned char> vchSig, vchBody;
        BOOST_REQUIRE(vSeats[i].key.Sign(hashView, vchSig));
        BOOST_REQUIRE(BuildMixViewSigBody(vSeats[i].pubkey, PREFIX_ANNOUNCE, vchSig, vchBody));
        BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_VIEW_SIG,
                                                  AuthedFrame(vSeats[i], hashRound,
                                                              MIX_FRAME_VIEW_SIG, vchBody),
                                                  nNow, strError),
                            (int)MIX_DISPATCH_OK);
    }
    for (size_t i = 0; i < vSeats.size(); i++)
    {
        std::vector<unsigned char> vchBody;
        BOOST_REQUIRE(BuildMixInputConstructionBody(vSeats[i].pubkey, PREFIX_ANNOUNCE,
                                                    vSeats[i].keyImage,
                                                    MixProofs().vPseudoOuts[ProvenIndex(vSeats[i].keyImage)],
                                                    vchBody));
        BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_INPUT_CONSTRUCTION,
                                                  AuthedFrame(vSeats[i], hashRound,
                                                              MIX_FRAME_INPUT_CONSTRUCTION,
                                                              vchBody),
                                                  nNow, strError),
                            (int)MIX_DISPATCH_OK);
    }
}

std::vector<unsigned char> PrefixSigFrame(const Seat& seat, const uint256& hashRound,
                                          const uint256& hashPrefix)
{
    std::vector<unsigned char> vchSig, vchBody;
    BOOST_REQUIRE(seat.key.Sign(hashPrefix, vchSig));
    BOOST_REQUIRE(BuildMixPrefixSigBody(seat.pubkey, PREFIX_ANNOUNCE, vchSig, vchBody));
    return AuthedFrame(seat, hashRound, MIX_FRAME_PREFIX_SIG, vchBody);
}

// The coordinator freezes the prefix and every seat approves it, over the wire.
void AgreePrefixOverWire(CMixRound& round, const std::vector<Seat>& vSeats,
                         const uint256& hashRound, int64_t nNow)
{
    std::string strError;
    BOOST_REQUIRE_MESSAGE(round.FreezePrefix(MixProofs().header, PREFIX_ANNOUNCE, &strError),
                          strError);
    for (size_t i = 0; i < vSeats.size(); i++)
        BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_PREFIX_SIG,
                                                  PrefixSigFrame(vSeats[i], hashRound,
                                                                 round.PrefixDigest()),
                                                  nNow, strError),
                            (int)MIX_DISPATCH_OK);
    BOOST_REQUIRE(round.PrefixAgreed());
}

std::vector<unsigned char> MembershipFrame(const Seat& seat, const uint256& hashRound,
                                           const std::vector<unsigned char>& vchProof)
{
    std::vector<unsigned char> vchBody;
    BOOST_REQUIRE(BuildMixMembershipProofBody(seat.pubkey, PREFIX_ANNOUNCE, vchProof, vchBody));
    return AuthedFrame(seat, hashRound, MIX_FRAME_MEMBERSHIP_PROOF, vchBody);
}

std::vector<unsigned char> ShareFrame(const Seat& seat, const uint256& hashRound,
                                      MixFrameType nType, const PrivacyVNextDigest& share)
{
    std::vector<unsigned char> vchBody;
    BOOST_REQUIRE(BuildMixScalarBody(seat.pubkey, std::vector<unsigned char>(share.begin(), share.end()),
                                     vchBody));
    return AuthedFrame(seat, hashRound, nType, vchBody);
}

// Every seat sends its membership proof, over the wire.
void ProveOverWire(CMixRound& round, const std::vector<Seat>& vSeats, const uint256& hashRound,
                   int64_t nNow)
{
    std::string strError;
    for (size_t i = 0; i < vSeats.size(); i++)
        BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_MEMBERSHIP_PROOF,
                                                  MembershipFrame(vSeats[i], hashRound,
                                                                  MixProofs().vProofs[ProvenIndex(
                                                                      vSeats[i].keyImage)]),
                                                  nNow, strError),
                            (int)MIX_DISPATCH_OK);
    BOOST_REQUIRE(round.MembershipProofsComplete());
}

} // namespace

// A whole two-seat round driven through the wire format and a pair of connected
// sockets: nothing here calls the round directly except the coordinator's own phase
// transitions, which no participant sends a frame for.
BOOST_AUTO_TEST_CASE(a_round_runs_over_the_wire)
{
    const uint256 hashRound = uint256(0xBEEF);
    const int64_t nNow = 12000000;
    CNullSendSession& server = Coordinator();
    CMixRound round;
    std::string strError;
    BOOST_REQUIRE(round.Open(hashRound, 2, server.vchRSA_N, server.vchRSA_E,
                             true, false, MIX_DENOM, nNow, &strError));

    std::vector<Seat> vSeats;
    vSeats.push_back(ProvenSeat(0));
    vSeats.push_back(ProvenSeat(1));

    // Each phase on its own connection, which is the point of the transport.
    for (size_t i = 0; i < vSeats.size(); i++)
    {
        int hPair[2];
        BOOST_REQUIRE_EQUAL(socketpair(AF_UNIX, SOCK_STREAM, 0, hPair), 0);
        CMixStream participant, coordinator;
        participant.Adopt(hPair[0]);
        coordinator.Adopt(hPair[1]);
        BOOST_REQUIRE(participant.Send(MIX_FRAME_JOIN, JoinFrame(vSeats[i], hashRound), &strError));
        MixFrameType nType;
        std::vector<unsigned char> vchPayload;
        BOOST_REQUIRE_MESSAGE(coordinator.Receive(nType, vchPayload, 2000, &strError), strError);
        BOOST_REQUIRE_EQUAL(
            (int)DispatchMixFrame(round, nType, vchPayload, nNow, strError),
            (int)MIX_DISPATCH_OK);
    }
    BOOST_REQUIRE_EQUAL(round.Seats(), 2u);

    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    AgreeViewOverWire(round, vSeats, hashRound, nNow);
    BOOST_REQUIRE(round.IssueToken(vSeats[0].pubkey, &strError));
    BOOST_REQUIRE(round.IssueToken(vSeats[1].pubkey, &strError));
    BOOST_REQUIRE(round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError));

    for (int i = 0; i < 2; i++)
    {
        const std::vector<CMixOutputRecord>& vBundle = MixProofs().vBundles[i];
        const Token token = MintToken(vBundle);
        int hPair[2];
        BOOST_REQUIRE_EQUAL(socketpair(AF_UNIX, SOCK_STREAM, 0, hPair), 0);
        CMixStream participant, coordinator;
        participant.Adopt(hPair[0]);
        coordinator.Adopt(hPair[1]);
        BOOST_REQUIRE(participant.Send(MIX_FRAME_OUTPUT, OutputFrame(token, vBundle), &strError));
        MixFrameType nType;
        std::vector<unsigned char> vchPayload;
        BOOST_REQUIRE(coordinator.Receive(nType, vchPayload, 2000, &strError));
        BOOST_REQUIRE_EQUAL(
            (int)DispatchMixFrame(round, nType, vchPayload, nNow, strError),
            (int)MIX_DISPATCH_OK);
    }

    const int64_t nClosed = nNow + MIX_OUTPUT_WINDOW + 1;
    BOOST_REQUIRE(round.OpenSigning(nClosed, &strError));
    BOOST_CHECK_MESSAGE(
        DispatchMixFrame(round, MIX_FRAME_NONCE,
                         ScalarFrame(vSeats[0], hashRound, MIX_FRAME_NONCE, 0x80), nClosed,
                         strError) == MIX_DISPATCH_REFUSED,
        "a nonce was taken before every seat approved the prefix");
    AgreePrefixOverWire(round, vSeats, hashRound, nClosed);
    ProveOverWire(round, vSeats, hashRound, nClosed);
    for (size_t i = 0; i < vSeats.size(); i++)
        BOOST_REQUIRE_EQUAL(
            (int)DispatchMixFrame(round, MIX_FRAME_NONCE,
                                  ScalarFrame(vSeats[i], hashRound, MIX_FRAME_NONCE,
                                              (unsigned char)(0x80 + i)),
                                  nClosed, strError),
            (int)MIX_DISPATCH_OK);
    BOOST_REQUIRE(round.FreezeNonces(&strError));
    for (size_t i = 0; i < vSeats.size(); i++)
        BOOST_REQUIRE_EQUAL(
            (int)DispatchMixFrame(round, MIX_FRAME_RESPONSE,
                                  ScalarFrame(vSeats[i], hashRound, MIX_FRAME_RESPONSE,
                                              (unsigned char)(0x90 + i)),
                                  nClosed, strError),
            (int)MIX_DISPATCH_OK);
    BOOST_CHECK(round.SigningComplete());
}

// The dispatcher's shape is the design. An output frame has nowhere to put a session
// key and no branch that reads one, so there is no way for the coordinator to learn
// which seat registered which output.
BOOST_AUTO_TEST_CASE(an_output_frame_cannot_name_a_seat)
{
    const uint256 hashRound = uint256(0xC0DE);
    const int64_t nNow = 13000000;
    CNullSendSession& server = Coordinator();
    CMixRound round;
    std::string strError;
    BOOST_REQUIRE(round.Open(hashRound, 2, server.vchRSA_N, server.vchRSA_E,
                             true, false, MIX_DENOM, nNow, &strError));
    const Seat a = MakeSeat(50), b = MakeSeat(51);
    BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_JOIN,
                                              JoinFrame(a, hashRound), nNow, strError),
                        (int)MIX_DISPATCH_OK);
    BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_JOIN,
                                              JoinFrame(b, hashRound), nNow, strError),
                        (int)MIX_DISPATCH_OK);
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    BOOST_REQUIRE(round.IssueToken(a.pubkey, &strError));
    BOOST_REQUIRE(round.IssueToken(b.pubkey, &strError));
    BOOST_REQUIRE(round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError));

    const Token token = MintToken(Bundle(Rec(uint256(60), 0x60), round));
    const std::vector<unsigned char> vchBody =
        OutputFrame(token, Bundle(Rec(uint256(60), 0x60), round));

    // An output with a session signature appended is not a longer output frame; it is
    // a malformed one, because the body ends where the key would have to start.
    std::vector<unsigned char> vchNamed;
    BOOST_REQUIRE(BuildAuthedMixFrame(a.key, hashRound, MIX_FRAME_OUTPUT, vchBody, vchNamed));
    BOOST_CHECK_MESSAGE(
        DispatchMixFrame(round, MIX_FRAME_OUTPUT, vchNamed, nNow, strError)
            == MIX_DISPATCH_REFUSED,
        "an output frame carrying a session key was accepted, so the coordinator learns "
        "which seat registered which output");

    // The unnamed one is the one that works.
    BOOST_CHECK_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_OUTPUT, vchBody,
                                            nNow, strError),
                      (int)MIX_DISPATCH_OK);
}

// Everything a participant can put on the wire that should not move the round.
BOOST_AUTO_TEST_CASE(the_dispatcher_refuses_what_it_should)
{
    const uint256 hashRound = uint256(0xFEED);
    const int64_t nNow = 14000000;
    CNullSendSession& server = Coordinator();
    CMixRound round;
    std::string strError;
    BOOST_REQUIRE(round.Open(hashRound, 2, server.vchRSA_N, server.vchRSA_E,
                             true, false, MIX_DENOM, nNow, &strError));
    const Seat a = MakeSeat(40);

    // A join signed for another round.
    BOOST_CHECK_MESSAGE(
        DispatchMixFrame(round, MIX_FRAME_JOIN, JoinFrame(a, uint256(0xFEEE)),
                         nNow, strError) == MIX_DISPATCH_REFUSED,
        "a join signed for another round was accepted");
    BOOST_CHECK_EQUAL(round.Seats(), 0u);

    // A nonce body presented as a response: the type is inside the signed hash.
    const std::vector<unsigned char> vchNonce =
        ScalarFrame(a, hashRound, MIX_FRAME_NONCE, 0xA1);
    BOOST_CHECK(DispatchMixFrame(round, MIX_FRAME_RESPONSE, vchNonce, nNow, strError)
                == MIX_DISPATCH_REFUSED);

    // Frames only a coordinator sends.
    BOOST_CHECK(DispatchMixFrame(round, MIX_FRAME_KEY, vchNonce, nNow, strError)
                == MIX_DISPATCH_REFUSED);
    BOOST_CHECK(DispatchMixFrame(round, MIX_FRAME_TRANSACTION, vchNonce, nNow, strError)
                == MIX_DISPATCH_REFUSED);

    // Truncations, at each place a length is read.
    std::vector<unsigned char> vchJoin = JoinFrame(a, hashRound);
    for (size_t n = 0; n < vchJoin.size(); n++)
    {
        const std::vector<unsigned char> vchShort(vchJoin.begin(), vchJoin.begin() + n);
        BOOST_CHECK_MESSAGE(
            DispatchMixFrame(round, MIX_FRAME_JOIN, vchShort, nNow, strError)
                == MIX_DISPATCH_REFUSED,
            "a join truncated to " << n << " bytes was acted on");
    }
    std::vector<unsigned char> vchOutput;
    BOOST_REQUIRE(BuildMixOutputBundleBody(
        std::vector<unsigned char>(8, 1), std::vector<unsigned char>(8, 2),
        std::vector<CMixOutputRecord>(2, Rec(uint256(9), 0x09)), vchOutput));
    for (size_t n = 0; n < vchOutput.size(); n++)
    {
        const std::vector<unsigned char> vchShort(vchOutput.begin(), vchOutput.begin() + n);
        BOOST_CHECK_MESSAGE(
            DispatchMixFrame(round, MIX_FRAME_OUTPUT, vchShort, nNow, strError)
                == MIX_DISPATCH_REFUSED,
            "an output truncated to " << n << " bytes was acted on");
    }

    // Trailing bytes are a different frame, not a longer one.
    std::vector<unsigned char> vchLong = vchJoin;
    vchLong.insert(vchLong.begin() + 65, 0x00);
    BOOST_CHECK(DispatchMixFrame(round, MIX_FRAME_JOIN, vchLong, nNow, strError)
                == MIX_DISPATCH_REFUSED);

    BOOST_CHECK_EQUAL(round.Seats(), 0u);
    BOOST_CHECK_EQUAL((int)round.Phase(), (int)MIX_PHASE_JOIN);
}

// A signature made for one frame type must not reach another type's handler; an
// unrecognised type must not fall through to the response branch.
BOOST_AUTO_TEST_CASE(a_frame_signed_as_another_type_is_not_a_response)
{
    const uint256 hashRound = uint256(0xDEAD);
    const int64_t nNow = 15000000;
    CNullSendSession& server = Coordinator();
    CMixRound round;
    std::string strError;
    BOOST_REQUIRE(round.Open(hashRound, 2, server.vchRSA_N, server.vchRSA_E,
                             true, false, MIX_DENOM, nNow, &strError));
    const Seat a = ProvenSeat(0), b = ProvenSeat(1);
    BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_JOIN,
                                              JoinFrame(a, hashRound), nNow, strError),
                        (int)MIX_DISPATCH_OK);
    BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_JOIN,
                                              JoinFrame(b, hashRound), nNow, strError),
                        (int)MIX_DISPATCH_OK);
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    std::vector<Seat> vSeats;
    vSeats.push_back(a);
    vSeats.push_back(b);
    AgreeViewOverWire(round, vSeats, hashRound, nNow);
    BOOST_REQUIRE(round.IssueToken(a.pubkey, &strError));
    BOOST_REQUIRE(round.IssueToken(b.pubkey, &strError));
    BOOST_REQUIRE(round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError));
    for (int i = 0; i < 2; i++)
    {
        const std::vector<CMixOutputRecord>& vBundle = MixProofs().vBundles[i];
        const Token t = MintToken(vBundle);
        BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_OUTPUT,
                                                  OutputFrame(t, vBundle), nNow, strError),
                            (int)MIX_DISPATCH_OK);
    }
    const int64_t nClosed = nNow + MIX_OUTPUT_WINDOW + 1;
    BOOST_REQUIRE(round.OpenSigning(nClosed, &strError));
    AgreePrefixOverWire(round, vSeats, hashRound, nClosed);
    ProveOverWire(round, vSeats, hashRound, nClosed);
    BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_NONCE,
                                              ScalarFrame(a, hashRound, MIX_FRAME_NONCE, 0xB1),
                                              nClosed, strError),
                        (int)MIX_DISPATCH_OK);
    BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_NONCE,
                                              ScalarFrame(b, hashRound, MIX_FRAME_NONCE, 0xB2),
                                              nClosed, strError),
                        (int)MIX_DISPATCH_OK);
    BOOST_REQUIRE(round.FreezeNonces(&strError));

    // Signed as a key announcement, which no participant sends. Everything about it is
    // valid except which frame it is, and at this point a response would be accepted.
    const std::vector<unsigned char> vchAsKey = ScalarFrame(a, hashRound, MIX_FRAME_KEY, 0xC1);
    BOOST_CHECK_MESSAGE(
        DispatchMixFrame(round, MIX_FRAME_KEY, vchAsKey, nClosed, strError)
            == MIX_DISPATCH_REFUSED,
        "a frame signed as a key announcement was spent as this seat's response");
    BOOST_CHECK_MESSAGE(!round.SigningComplete(),
                        "a seat responded without ever sending a response");

    // The real response still works, so the refusal above is about the type and not
    // about the seat.
    BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_RESPONSE,
                                              ScalarFrame(a, hashRound, MIX_FRAME_RESPONSE, 0xC2),
                                              nClosed, strError),
                        (int)MIX_DISPATCH_OK);
}

// One signed body has one reading. A body signed with bytes after the scalar must not
// be read as the shorter frame and acted on, or the same signature covers two meanings.
BOOST_AUTO_TEST_CASE(a_signed_body_with_trailing_bytes_is_refused)
{
    const uint256 hashRound = uint256(0xBADD);
    const int64_t nNow = 16000000;
    CNullSendSession& server = Coordinator();
    CMixRound round;
    std::string strError;
    BOOST_REQUIRE(round.Open(hashRound, 2, server.vchRSA_N, server.vchRSA_E,
                             true, false, MIX_DENOM, nNow, &strError));
    const Seat a = MakeSeat(20);

    std::vector<unsigned char> vchBody;
    BOOST_REQUIRE(BuildMixJoinBody(a.pubkey, a.keyImage, vchBody));
    vchBody.push_back(0x00);   // signed as part of the body, not appended to the frame
    const std::vector<unsigned char> vchPayload =
        AuthedFrame(a, hashRound, MIX_FRAME_JOIN, vchBody);

    BOOST_CHECK_MESSAGE(
        DispatchMixFrame(round, MIX_FRAME_JOIN, vchPayload, nNow, strError)
            == MIX_DISPATCH_REFUSED,
        "a signed body with a trailing byte was read as the shorter frame, so one "
        "signature covers more than one message");
    BOOST_CHECK_EQUAL(round.Seats(), 0u);

    // Without the trailing byte the same seat joins, so the refusal is about the length.
    BOOST_CHECK_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_JOIN,
                                            JoinFrame(a, hashRound), nNow, strError),
                      (int)MIX_DISPATCH_OK);
}

// The late-output check must fire on the window, not the seat count, so the round here
// still has a free slot.
BOOST_AUTO_TEST_CASE(a_late_output_is_refused_while_a_slot_is_still_free)
{
    const int64_t nNow = 17000000;
    CMixRound round;
    std::vector<Seat> vSeats;
    BOOST_REQUIRE(OpenAndFill(round, vSeats, 3, nNow));
    std::string strError;
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    for (size_t i = 0; i < vSeats.size(); i++)
        BOOST_REQUIRE(round.IssueToken(vSeats[i].pubkey, &strError));
    BOOST_REQUIRE(round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError));

    // One of three slots used, so the seat count cannot be what refuses anything below.
    const Token first = MintToken(Bundle(Rec(uint256(310), 0xdd), round));
    BOOST_REQUIRE(round.RegisterOutput(first.vchCredential, first.vchSignature, Bundle(Rec(uint256(310), 0xdd), round), nNow, &strError));
    BOOST_REQUIRE_EQUAL(round.Outputs(), 1u);

    const Token late = MintToken(Bundle(Rec(uint256(311), 0x2e), round));
    BOOST_CHECK_MESSAGE(!round.RegisterOutput(late.vchCredential, late.vchSignature, Bundle(Rec(uint256(311), 0x2e), round),
                                              nNow + MIX_OUTPUT_WINDOW + 1, &strError),
                        "an output arriving after the window closed was accepted into a "
                        "round with slots to spare, so the window decorrelates nothing");
    BOOST_CHECK(strError.find("window") != std::string::npos);
    BOOST_CHECK_EQUAL(round.Outputs(), 1u);

    // The same token inside the window is taken, so the refusal was about the deadline.
    BOOST_CHECK(round.RegisterOutput(late.vchCredential, late.vchSignature, Bundle(Rec(uint256(311), 0x2e), round), nNow + MIX_OUTPUT_WINDOW, &strError));
}

// Two seats naming one output key would make one seat's value payable to another's key.
BOOST_AUTO_TEST_CASE(two_outputs_may_not_name_the_same_key)
{
    const int64_t nNow = 18000000;
    CMixRound round;
    std::vector<Seat> vSeats;
    BOOST_REQUIRE(OpenAndFill(round, vSeats, 3, nNow));
    std::string strError;
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    for (size_t i = 0; i < vSeats.size(); i++)
        BOOST_REQUIRE(round.IssueToken(vSeats[i].pubkey, &strError));
    BOOST_REQUIRE(round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError));

    const CMixOutputRecord taken = Rec(uint256(320), 0xb8);
    const std::vector<CMixOutputRecord> vFirst(round.Seats(), taken);
    const Token first = MintToken(vFirst);
    BOOST_REQUIRE(round.RegisterOutput(first.vchCredential, first.vchSignature, vFirst, nNow,
                                       &strError));

    // A DIFFERENT bundle -- so a different credential, and not a retransmission -- whose
    // variant for the next free position names the key already registered. A slot is still
    // free, so the seat count is not what refuses it.
    std::vector<CMixOutputRecord> vSecond(round.Seats(), Rec(uint256(321), 0xaf));
    vSecond[1] = taken;
    const Token second = MintToken(vSecond);
    BOOST_CHECK(second.vchCredential != first.vchCredential);
    BOOST_CHECK_MESSAGE(!round.RegisterOutput(second.vchCredential, second.vchSignature, vSecond,
                                              nNow, &strError),
                        "two outputs named one key, so one seat's value is payable to "
                        "another seat's key");
    BOOST_CHECK(strError.find("already registered") != std::string::npos);
    BOOST_CHECK_EQUAL(round.Outputs(), 1u);

    // The same token under another bundle is refused too, now for the binding rather than
    // the spend: one token names one bundle.
    BOOST_CHECK(!round.RegisterOutput(second.vchCredential, second.vchSignature, Bundle(Rec(uint256(322), 0xaf), round), nNow, &strError));
    BOOST_CHECK(strError.find("does not authorise") != std::string::npos);

    // A token minted for that key is taken, so the refusals were about the key and not
    // the slot.
    const Token other = MintToken(Bundle(Rec(uint256(321), 0xaf), round));
    BOOST_CHECK(round.RegisterOutput(other.vchCredential, other.vchSignature, Bundle(Rec(uint256(321), 0xaf), round), nNow, &strError));
    BOOST_CHECK_EQUAL(round.Outputs(), 2u);
}

// The prefix travels coordinator to seat, never the other way, and its frame carries the
// prefix and nothing else. An approval reaches the round only once the prefix is frozen.
BOOST_AUTO_TEST_CASE(a_prefix_frame_carries_exactly_the_prefix)
{
    const std::vector<unsigned char> vchPrefix(300, 0x5a);
    std::vector<unsigned char> vchBody, vchRead;
    BOOST_REQUIRE(BuildMixPrefixBody(vchPrefix, vchBody));
    BOOST_REQUIRE(ReadMixPrefixBody(vchBody, vchRead));
    BOOST_CHECK(vchRead == vchPrefix);
    std::vector<unsigned char> vchLong = vchBody;
    vchLong.push_back(0);
    BOOST_CHECK(!ReadMixPrefixBody(vchLong, vchRead));
    const std::vector<unsigned char> vchShort(vchBody.begin(), vchBody.end() - 1);
    BOOST_CHECK(!ReadMixPrefixBody(vchShort, vchRead));
    BOOST_CHECK(!BuildMixPrefixBody(std::vector<unsigned char>(), vchBody));

    const uint256 hashRound = uint256(0xF00D);
    const int64_t nNow = 16000000;
    CNullSendSession& server = Coordinator();
    CMixRound round;
    std::string strError;
    BOOST_REQUIRE(round.Open(hashRound, 2, server.vchRSA_N, server.vchRSA_E,
                             true, false, MIX_DENOM, nNow, &strError));
    std::vector<Seat> vSeats;
    vSeats.push_back(ProvenSeat(0));
    vSeats.push_back(ProvenSeat(1));
    for (size_t i = 0; i < vSeats.size(); i++)
        BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_JOIN,
                                                  JoinFrame(vSeats[i], hashRound), nNow, strError),
                            (int)MIX_DISPATCH_OK);
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    AgreeViewOverWire(round, vSeats, hashRound, nNow);

    std::vector<unsigned char> vchAsPrefix;
    BOOST_REQUIRE(BuildMixPrefixBody(vchPrefix, vchAsPrefix));
    BOOST_CHECK_MESSAGE(
        DispatchMixFrame(round, MIX_FRAME_TRANSACTION_PREFIX,
                         AuthedFrame(vSeats[0], hashRound, MIX_FRAME_TRANSACTION_PREFIX,
                                     vchAsPrefix),
                         nNow, strError) == MIX_DISPATCH_REFUSED,
        "a participant sent the coordinator a prefix");
    BOOST_CHECK_MESSAGE(
        DispatchMixFrame(round, MIX_FRAME_PREFIX_SIG,
                         PrefixSigFrame(vSeats[0], hashRound, uint256(0x1234)), nNow,
                         strError) == MIX_DISPATCH_REFUSED,
        "an approval was taken with no prefix frozen");
}

// A seat's membership proof is checked on arrival against its own input and the approved
// prefix, exactly as the payload's membership section checks it, so a proof that fails
// names its seat. Nonces wait until every proof is in.
BOOST_AUTO_TEST_CASE(a_membership_proof_is_checked_against_its_seat_and_the_approved_prefix)
{
    const MixProofSet& proofs = MixProofs();
    const uint256 hashRound = uint256(0xFEE1);
    const int64_t nNow = 17000000;
    CNullSendSession& server = Coordinator();
    CMixRound round;
    std::string strError;
    BOOST_REQUIRE(round.Open(hashRound, 2, server.vchRSA_N, server.vchRSA_E,
                             true, false, MIX_DENOM, nNow, &strError));
    // Joined in descending key-image order, so input order is not join order.
    const bool fFirstIsLower = std::lexicographical_compare(
        proofs.vKeyImages[0].begin(), proofs.vKeyImages[0].end(),
        proofs.vKeyImages[1].begin(), proofs.vKeyImages[1].end());
    std::vector<Seat> vSeats;
    vSeats.push_back(ProvenSeat(fFirstIsLower ? 1 : 0));
    vSeats.push_back(ProvenSeat(fFirstIsLower ? 0 : 1));
    for (size_t i = 0; i < 2; i++)
        BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_JOIN,
                                                  JoinFrame(vSeats[i], hashRound), nNow, strError),
                            (int)MIX_DISPATCH_OK);
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    AgreeViewOverWire(round, vSeats, hashRound, nNow);
    for (size_t i = 0; i < 2; i++)
        BOOST_REQUIRE(round.IssueToken(vSeats[i].pubkey, &strError));
    BOOST_REQUIRE(round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError));
    for (size_t i = 0; i < 2; i++)
    {
        const Token token = MintToken(proofs.vBundles[i]);
        BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_OUTPUT,
                                                  OutputFrame(token, proofs.vBundles[i]), nNow,
                                                  strError),
                            (int)MIX_DISPATCH_OK);
    }
    const int64_t nClosed = nNow + MIX_OUTPUT_WINDOW + 1;
    BOOST_REQUIRE(round.OpenSigning(nClosed, &strError));

    const std::vector<unsigned char>& vchMine = proofs.vProofs[ProvenIndex(vSeats[0].keyImage)];
    const std::vector<unsigned char>& vchTheirs = proofs.vProofs[ProvenIndex(vSeats[1].keyImage)];
    BOOST_CHECK(!round.SubmitMembershipProof(vSeats[0].pubkey, vchMine, &strError));
    // Frozen and approved by one seat of two: the proof would verify, and is still refused.
    BOOST_REQUIRE_MESSAGE(round.FreezePrefix(proofs.header, PREFIX_ANNOUNCE, &strError), strError);
    BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_PREFIX_SIG,
                                              PrefixSigFrame(vSeats[0], hashRound, round.PrefixDigest()),
                                              nClosed, strError),
                        (int)MIX_DISPATCH_OK);
    BOOST_CHECK_MESSAGE(!round.SubmitMembershipProof(vSeats[0].pubkey, vchMine, &strError),
                        "a proof was taken before every seat approved the prefix");
    BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_PREFIX_SIG,
                                              PrefixSigFrame(vSeats[1], hashRound, round.PrefixDigest()),
                                              nClosed, strError),
                        (int)MIX_DISPATCH_OK);
    BOOST_REQUIRE(round.PrefixAgreed());

    BOOST_CHECK_MESSAGE(!round.SubmitMembershipProof(vSeats[0].pubkey, vchTheirs, &strError),
                        "one seat's proof stood for another seat's input");
    if (ProvenIndex(vSeats[0].keyImage) == 0)
        BOOST_CHECK_MESSAGE(!round.SubmitMembershipProof(vSeats[0].pubkey, proofs.vchOtherHashProof,
                                                         &strError),
                            "a proof under another statement was taken for the approved prefix");
    else
        BOOST_CHECK_MESSAGE(!round.SubmitMembershipProof(vSeats[1].pubkey, proofs.vchOtherHashProof,
                                                         &strError),
                            "a proof under another statement was taken for the approved prefix");
    const std::vector<unsigned char> vchShort(vchMine.begin(), vchMine.end() - 1);
    BOOST_CHECK(!round.SubmitMembershipProof(vSeats[0].pubkey, vchShort, &strError));
    std::vector<unsigned char> vchFlipped = vchMine;
    vchFlipped[vchFlipped.size() / 2] ^= 0x01;
    BOOST_CHECK_MESSAGE(!round.SubmitMembershipProof(vSeats[0].pubkey, vchFlipped, &strError),
                        "a proof with a flipped byte verified");
    const Seat stranger = MakeSeat(8);
    BOOST_CHECK(!round.SubmitMembershipProof(stranger.pubkey, vchMine, &strError));

    BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_MEMBERSHIP_PROOF,
                                              MembershipFrame(vSeats[0], hashRound, vchMine),
                                              nClosed, strError),
                        (int)MIX_DISPATCH_OK);
    BOOST_CHECK_MESSAGE(!round.SubmitMembershipProof(vSeats[0].pubkey, vchMine, &strError),
                        "a seat proved its input twice");
    BOOST_CHECK(!round.MembershipProofsComplete());
    BOOST_CHECK(round.MembershipSection().empty());
    BOOST_CHECK_MESSAGE(
        DispatchMixFrame(round, MIX_FRAME_NONCE,
                         ScalarFrame(vSeats[0], hashRound, MIX_FRAME_NONCE, 0xE0), nClosed,
                         strError) == MIX_DISPATCH_REFUSED,
        "a nonce was taken before every seat proved its input");

    BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_MEMBERSHIP_PROOF,
                                              MembershipFrame(vSeats[1], hashRound, vchTheirs),
                                              nClosed, strError),
                        (int)MIX_DISPATCH_OK);
    BOOST_CHECK(round.MembershipProofsComplete());

    // The section a payload carries: each proof at its input's position, key-image order.
    std::vector<unsigned char> vchExpected;
    const std::vector<uint256>& vOrder = round.FinalKeyImages();
    BOOST_REQUIRE_EQUAL(vOrder.size(), 2u);
    BOOST_REQUIRE(vOrder[0] == vSeats[1].keyImage);
    for (size_t k = 0; k < vOrder.size(); k++)
    {
        const std::vector<unsigned char>& vchProof = proofs.vProofs[ProvenIndex(vOrder[k])];
        vchExpected.insert(vchExpected.end(), vchProof.begin(), vchProof.end());
    }
    BOOST_CHECK(round.MembershipSection() == vchExpected);
    size_t nOneInput = 0;
    BOOST_REQUIRE(GetPrivacyVNextProofSize(1, nOneInput, strError));
    BOOST_CHECK_EQUAL(round.MembershipSection().size(), 2 * nOneInput);

    BOOST_CHECK_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_NONCE,
                                            ScalarFrame(vSeats[0], hashRound, MIX_FRAME_NONCE, 0xE0),
                                            nClosed, strError),
                      (int)MIX_DISPATCH_OK);
}

namespace {

// A proven round driven over the wire to the point every membership proof is in.
void ProvenRoundThroughProofs(CMixRound& round, std::vector<Seat>& vSeats,
                              const uint256& hashRound, int64_t nNow)
{
    const MixProofSet& proofs = MixProofs();
    CNullSendSession& server = Coordinator();
    std::string strError;
    BOOST_REQUIRE(round.Open(hashRound, 2, server.vchRSA_N, server.vchRSA_E,
                             true, false, MIX_DENOM, nNow, &strError));
    for (size_t i = 0; i < 2; i++)
    {
        vSeats.push_back(ProvenSeat(i));
        BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_JOIN,
                                                  JoinFrame(vSeats[i], hashRound), nNow, strError),
                            (int)MIX_DISPATCH_OK);
    }
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    AgreeViewOverWire(round, vSeats, hashRound, nNow);
    for (size_t i = 0; i < 2; i++)
        BOOST_REQUIRE(round.IssueToken(vSeats[i].pubkey, &strError));
    BOOST_REQUIRE(round.OpenOutputWindow(nNow, nNow + MIX_OUTPUT_WINDOW, &strError));
    for (size_t i = 0; i < 2; i++)
    {
        const Token token = MintToken(proofs.vBundles[i]);
        BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_OUTPUT,
                                                  OutputFrame(token, proofs.vBundles[i]), nNow,
                                                  strError),
                            (int)MIX_DISPATCH_OK);
    }
    const int64_t nClosed = nNow + MIX_OUTPUT_WINDOW + 1;
    BOOST_REQUIRE(round.OpenSigning(nClosed, &strError));
    AgreePrefixOverWire(round, vSeats, hashRound, nClosed);
    ProveOverWire(round, vSeats, hashRound, nClosed);
}

// What every seat signs over: read from the frozen prefix, as a seat would from the bytes
// it approved.
PrivacyVNextMixBalanceFacts FactsFromPrefix(const std::vector<unsigned char>& vchPrefix)
{
    CMixPrefixView view;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(ParseMixPrefix(vchPrefix, view, strError), strError);
    PrivacyVNextMixBalanceFacts facts;
    facts.nInputCount = (uint8_t)view.vPseudoOuts.size();
    facts.nOutputCount = (uint8_t)view.vOutputs.size();
    facts.nTransparentValueBalance = view.nTransparentValueBalance;
    facts.nFee = view.nFee;
    BOOST_REQUIRE_MESSAGE(HashPrivacyVNextPayloadPrefix(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                                        vchPrefix, facts.signableHash, strError),
                          strError);
    facts.vPseudoOuts = view.vPseudoOuts;
    for (size_t i = 0; i < view.vOutputs.size(); i++)
        facts.vOutputs.push_back(view.vOutputs[i].commitment);
    return facts;
}

// Seat i's share: its input at the position the round sorted it to, its own output, its
// fee share and the mask it proves with.
PrivacyVNextMixBalanceShare SeatShare(const CMixRound& round, const Seat& seat, unsigned char chEntropy)
{
    const MixProofSet& proofs = MixProofs();
    const size_t nFunded = ProvenIndex(seat.keyImage);
    PrivacyVNextMixBalanceShare share;
    const std::vector<uint256>& vOrder = round.FinalKeyImages();
    share.nInputIndex = 0xff;
    for (size_t k = 0; k < vOrder.size(); k++)
        if (vOrder[k] == seat.keyImage)
            share.nInputIndex = (uint8_t)k;
    BOOST_REQUIRE(share.nInputIndex != 0xff);
    share.nOutputIndex = (uint8_t)nFunded;
    share.nFeeShare = MIX_FEE_SHARE;
    share.mask = proofs.vSeatMasks[nFunded];
    share.outputMask = proofs.vRecords[nFunded].mask;
    share.entropy.fill(chEntropy);
    share.entropy[31] = (unsigned char)nFunded;
    return share;
}

// Every seat publishes its nonce, the aggregate is fixed, and every seat responds; with
// fCopyResponse seat 0 sends seat 1's response in place of its own.
void SignOverWire(CMixRound& round, const std::vector<Seat>& vSeats, const uint256& hashRound,
                  int64_t nNow, bool fCopyResponse)
{
    std::string strError;
    const PrivacyVNextMixBalanceFacts facts = FactsFromPrefix(round.FrozenPrefix());
    std::vector<PrivacyVNextMixBalanceShare> vShares;
    for (size_t i = 0; i < vSeats.size(); i++)
    {
        vShares.push_back(SeatShare(round, vSeats[i], 0x3c));
        PrivacyVNextDigest nonce;
        BOOST_REQUIRE_MESSAGE(PrivacyVNextMixBalanceNonce(facts, vShares[i], nonce, strError),
                              strError);
        BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_NONCE,
                                                  ShareFrame(vSeats[i], hashRound, MIX_FRAME_NONCE,
                                                             nonce),
                                                  nNow, strError),
                            (int)MIX_DISPATCH_OK);
    }
    BOOST_REQUIRE_MESSAGE(round.FreezeNonces(&strError), strError);
    const std::vector<std::vector<unsigned char> > vNonceBytes = round.NoncesInInputOrder();
    std::vector<PrivacyVNextDigest> vNonces(vNonceBytes.size());
    for (size_t i = 0; i < vNonceBytes.size(); i++)
        memcpy(vNonces[i].data(), &vNonceBytes[i][0], 32);
    std::vector<PrivacyVNextDigest> vResponses(vSeats.size());
    for (size_t i = 0; i < vSeats.size(); i++)
        BOOST_REQUIRE_MESSAGE(PrivacyVNextMixBalanceSign(facts, vShares[i], vNonces, vResponses[i],
                                                         strError),
                              strError);
    if (fCopyResponse)
        vResponses[0] = vResponses[1];
    for (size_t i = 0; i < vSeats.size(); i++)
        BOOST_REQUIRE_EQUAL((int)DispatchMixFrame(round, MIX_FRAME_RESPONSE,
                                                  ShareFrame(vSeats[i], hashRound, MIX_FRAME_RESPONSE,
                                                             vResponses[i]),
                                                  nNow, strError),
                            (int)MIX_DISPATCH_OK);
    BOOST_REQUIRE(round.SigningComplete());
}

} // namespace

// The assembled payload passes the same validation a node runs, every proof verified,
// on a transaction with no transparent side.
BOOST_AUTO_TEST_CASE(a_mix_round_assembles_a_payload_that_validates)
{
    const MixProofSet& proofs = MixProofs();
    const uint256 hashRound = uint256(0xFEE2);
    const int64_t nNow = 18000000;
    const int64_t nClosed = nNow + MIX_OUTPUT_WINDOW + 1;
    CMixRound round;
    std::vector<Seat> vSeats;
    ProvenRoundThroughProofs(round, vSeats, hashRound, nNow);
    std::string strError;
    std::vector<unsigned char> vchPayload;
    BOOST_CHECK_MESSAGE(!round.AssemblePayload(vchPayload, &strError),
                        "a payload was assembled before any seat signed");
    BOOST_CHECK(vchPayload.empty());

    SignOverWire(round, vSeats, hashRound, nClosed, false);
    BOOST_REQUIRE_MESSAGE(round.AssemblePayload(vchPayload, &strError), strError);

    // The prefix it carries is the one the seats approved, and it validates as a node does.
    BOOST_REQUIRE(vchPayload.size() > round.FrozenPrefix().size());
    BOOST_CHECK(std::equal(round.FrozenPrefix().begin(), round.FrozenPrefix().end(),
                           vchPayload.begin()));
    PrivacyVNextStateEffects effects;
    const PrivacyVNextPayloadValidation validation = ExtractPrivacyVNextPayloadEffects(
        INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, vchPayload, effects);
    BOOST_REQUIRE_MESSAGE(validation.nResult == INNOVA_PRIVACY_VNEXT_VALID, validation.strError);
    BOOST_CHECK_EQUAL(effects.nFee, 2 * MIX_FEE_SHARE);
    BOOST_CHECK_EQUAL(effects.nTransparentValueBalance, 0);
    BOOST_REQUIRE_EQUAL(effects.keyImages.size(), 2u);
    BOOST_REQUIRE_EQUAL(effects.outputLeaves.size(), 2u);
    for (size_t k = 0; k < 2; k++)
    {
        BOOST_CHECK(memcmp(effects.keyImages[k].data(), round.FinalKeyImages()[k].begin(), 32) == 0);
        BOOST_CHECK(effects.outputLeaves[k].owner == proofs.vRecords[k].owner);
        BOOST_CHECK(effects.outputLeaves[k].commitment == proofs.vRecords[k].commitment);
    }

    // Each recipient finds its own output, at its own position and at the denomination, and
    // nothing else.
    for (size_t k = 0; k < 2; k++)
    {
        std::vector<PrivacyVNextScanKey> vKeys(1, proofs.vRecipients[k]);
        std::vector<PrivacyVNextScanMatch> vMatches;
        std::vector<PrivacyVNextDigest> vScannedImages;
        uint8_t nOutputCount = 0;
        BOOST_REQUIRE_MESSAGE(ScanPrivacyVNextPayload(PRIVACY_VNEXT_SCAN_FULL, proofs.header.nNetwork,
                                                      0, INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                                      vchPayload, vKeys, vMatches, vScannedImages,
                                                      nOutputCount, strError),
                              strError);
        BOOST_CHECK_EQUAL((int)nOutputCount, 2);
        BOOST_REQUIRE_EQUAL(vMatches.size(), 1u);
        BOOST_CHECK_EQUAL(vMatches[0].nOutputIndex, (uint32_t)k);
        BOOST_CHECK_EQUAL(vMatches[0].nAmount, MIX_DENOM);
    }

    // A round that has published is finished, and a finished round is the only kind a
    // driver may reuse the object for.
    BOOST_REQUIRE_MESSAGE(round.MarkComplete(&strError), strError);
    BOOST_CHECK_EQUAL((int)round.Phase(), (int)MIX_PHASE_COMPLETE);
    BOOST_CHECK(round.MarkComplete(&strError));

    CTransaction tx;
    BOOST_REQUIRE_MESSAGE(BuildMixTransaction(vchPayload, 1500000000U, tx, strError), strError);
    BOOST_CHECK(tx.vin.empty());
    BOOST_CHECK(tx.vout.empty());
    BOOST_CHECK_EQUAL(tx.nLockTime, 0U);
    BOOST_CHECK(tx.privacyVNext.vchPayload == vchPayload);
    const uint256 binding = GetPrivacyVNextTransparentBinding(tx);
    const PrivacyVNextDigest mixBinding = MixTransparentBinding();
    BOOST_CHECK(memcmp(binding.begin(), mixBinding.data(), 32) == 0);

    // A payload that does not validate has no carrier.
    std::vector<unsigned char> vchBroken = vchPayload;
    vchBroken[vchBroken.size() - 10] ^= 0x01;
    CTransaction txBroken;
    BOOST_CHECK(!BuildMixTransaction(vchBroken, 1500000000U, txBroken, strError));
    BOOST_CHECK(txBroken.privacyVNext.vchPayload.empty());
}

// A seat that sends another seat's valid response: the share is well formed and made under
// the fixed aggregate, but the joint proof does not verify, so no payload comes out. Only
// the sum of the responses enters the proof, which is why the failure names no seat.
BOOST_AUTO_TEST_CASE(a_round_with_a_copied_response_assembles_nothing)
{
    const uint256 hashRound = uint256(0xFEE3);
    const int64_t nNow = 19000000;
    CMixRound round;
    std::vector<Seat> vSeats;
    ProvenRoundThroughProofs(round, vSeats, hashRound, nNow);
    std::string strError;
    BOOST_CHECK_MESSAGE(!round.MarkComplete(&strError),
                        "a round with no finished signature was marked complete");
    SignOverWire(round, vSeats, hashRound, nNow + MIX_OUTPUT_WINDOW + 1, true);
    std::vector<unsigned char> vchPayload;
    BOOST_CHECK_MESSAGE(!round.AssemblePayload(vchPayload, &strError),
                        "a payload was assembled over a copied response");
    BOOST_CHECK(vchPayload.empty());
}

// Why a bundle is needed at all: the parts a position enters differ variant by variant,
// while the value the round has to agree on does not.
BOOST_AUTO_TEST_CASE(a_bundles_variants_differ_only_where_the_position_enters)
{
    const MixProofSet& proofs = MixProofs();
    BOOST_REQUIRE_EQUAL(proofs.vBundles.size(), 2u);
    for (size_t i = 0; i < proofs.vBundles.size(); i++)
    {
        const std::vector<CMixOutputRecord>& vBundle = proofs.vBundles[i];
        BOOST_REQUIRE_EQUAL(vBundle.size(), 2u);
        // One amount, one opening, one commitment across the bundle, so the joint balance
        // closes whichever variant the round keeps.
        BOOST_CHECK(vBundle[0].commitment == vBundle[1].commitment);
        BOOST_CHECK(vBundle[0].mask == vBundle[1].mask);
        // The owner key and the ciphertexts are position-bound, which is the whole reason a
        // seat cannot generate one record before it knows its slot.
        BOOST_CHECK_MESSAGE(!(vBundle[0].owner == vBundle[1].owner),
                            "the owner key does not depend on the output position");
        BOOST_CHECK(vBundle[0].vchRecipientCiphertext != vBundle[1].vchRecipientCiphertext);
        BOOST_CHECK(!(vBundle[0].noteEphemeral == vBundle[1].noteEphemeral));
    }
}

// Coordinator transport: one request and one reply per connection, "nobody called" is not
// an error. Binds loopback only; the endpoint is reached through its onion service.
BOOST_AUTO_TEST_CASE(the_coordinator_listens_and_answers_one_connection_at_a_time)
{
    std::string strError;
    CMixListener listener;
    BOOST_REQUIRE_MESSAGE(listener.Listen(0, &strError), strError);
    BOOST_REQUIRE(listener.IsOpen());
    BOOST_REQUIRE(listener.Port() > 0);

    // Nobody is calling: an expiry is not a failure, and says nothing.
    CMixStream idle;
    BOOST_CHECK(!listener.Accept(idle, 50, &strError));
    BOOST_CHECK_MESSAGE(strError.empty(), "an empty wait reported an error: " << strError);
    BOOST_CHECK(!idle.IsOpen());

    // Dialled by hand rather than through ConnectSocket, which would consult whatever
    // proxy the node is configured with; this test is about the listener, not the dialer.
    const SOCKET hClient = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BOOST_REQUIRE(hClient != INVALID_SOCKET);
    struct sockaddr_in addrLocal;
    memset(&addrLocal, 0, sizeof(addrLocal));
    addrLocal.sin_family = AF_INET;
    addrLocal.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addrLocal.sin_port = htons((unsigned short)listener.Port());
    BOOST_REQUIRE_MESSAGE(connect(hClient, (struct sockaddr*)&addrLocal, sizeof(addrLocal)) == 0,
                          "could not dial the listener");
    CMixStream client;
    client.Adopt(hClient);

    CMixStream served;
    BOOST_REQUIRE_MESSAGE(listener.Accept(served, 2000, &strError), strError);
    BOOST_REQUIRE(served.IsOpen());

    const std::vector<unsigned char> vchRequest(16, 0x5a);
    BOOST_REQUIRE(client.Send(MIX_FRAME_JOIN, vchRequest, &strError));
    MixFrameType nType = MIX_FRAME_NONE;
    std::vector<unsigned char> vchPayload;
    BOOST_REQUIRE_MESSAGE(served.Receive(nType, vchPayload, 2000, &strError), strError);
    BOOST_CHECK_EQUAL((int)nType, (int)MIX_FRAME_JOIN);
    BOOST_CHECK(vchPayload == vchRequest);

    const std::vector<unsigned char> vchReply(4, 0xA1);
    BOOST_REQUIRE(served.Send(MIX_FRAME_ABORT, vchReply, &strError));
    BOOST_REQUIRE_MESSAGE(client.Receive(nType, vchPayload, 2000, &strError), strError);
    BOOST_CHECK_EQUAL((int)nType, (int)MIX_FRAME_ABORT);
    BOOST_CHECK(vchPayload == vchReply);

    // The connection is dropped after its one exchange, and the listener survives it.
    client.Close();
    served.Close();
    CMixStream after;
    BOOST_CHECK(!listener.Accept(after, 50, &strError));
    BOOST_CHECK(strError.empty());
    listener.Close();
    BOOST_CHECK(!listener.IsOpen());
}

// The roster frame carries the session-key pairs in the round's frozen order and refuses
// any other; a seat needs them to compute the view it signs.
BOOST_AUTO_TEST_CASE(the_roster_frame_carries_the_pairs_in_the_order_the_round_froze)
{
    const int64_t nNow = 3970000;
    std::string strError;
    CMixRound round;
    std::vector<Seat> vSeats;
    BOOST_REQUIRE(OpenAndFill(round, vSeats, 3, nNow));
    BOOST_REQUIRE(round.CloseJoin(nNow, &strError));
    const std::vector<CMixRosterEntry>& vRoster = round.Roster();
    BOOST_REQUIRE_EQUAL(vRoster.size(), 3u);

    std::vector<unsigned char> vchBody;
    BOOST_REQUIRE(BuildMixRosterBody(vRoster, vchBody));
    std::vector<CMixRosterEntry> vRead;
    BOOST_REQUIRE(ReadMixRosterBody(vchBody, vRead));
    BOOST_REQUIRE_EQUAL(vRead.size(), vRoster.size());
    for (size_t i = 0; i < vRead.size(); i++)
    {
        BOOST_CHECK(vRead[i].keyImage == vRoster[i].keyImage);
        BOOST_CHECK(vRead[i].pubkeySession == vRoster[i].pubkeySession);
    }
    // What the seat does with it: the same view digest the round computes.
    BOOST_CHECK(MixViewDigest(uint256(0xFACE), vRead) == round.ViewDigest(uint256(0xFACE)));

    // Neither side sorts.
    std::vector<CMixRosterEntry> vSwapped = vRoster;
    std::swap(vSwapped[0], vSwapped[1]);
    BOOST_CHECK_MESSAGE(!BuildMixRosterBody(vSwapped, vchBody),
                        "the writer accepted an order it would have had to fix");
    BOOST_REQUIRE(BuildMixRosterBody(vRoster, vchBody));
    std::vector<unsigned char> vchReordered = vchBody;
    std::swap_ranges(vchReordered.begin() + 2, vchReordered.begin() + 2 + 32,
                     vchReordered.begin() + 2 + 65);
    BOOST_CHECK_MESSAGE(!ReadMixRosterBody(vchReordered, vRead),
                        "the reader accepted an order it would have had to fix");

    // Shape: nothing truncated, nothing trailing, no invalid key.
    for (size_t n = 0; n + 1 < vchBody.size(); n++)
    {
        const std::vector<unsigned char> vchShort(vchBody.begin(), vchBody.begin() + n);
        BOOST_CHECK(!ReadMixRosterBody(vchShort, vRead));
    }
    std::vector<unsigned char> vchLong = vchBody;
    vchLong.push_back(0);
    BOOST_CHECK(!ReadMixRosterBody(vchLong, vRead));
    std::vector<unsigned char> vchBadKey = vchBody;
    vchBadKey[2 + 32] = 0x09;   // not a valid compressed point prefix
    BOOST_CHECK(!ReadMixRosterBody(vchBadKey, vRead));
}

// The public snapshot carries only the phase; the seat snapshot carries the frozen
// transcript. An aborted round's prefix holds disclosed openings and must stay seat-only.
BOOST_AUTO_TEST_CASE(a_snapshot_tells_the_public_the_phase_and_a_seat_the_transcript)
{
    const uint256 hashRound = uint256(0xFEE5);
    const int64_t nNow = 20000000;
    CMixRound round;
    std::vector<Seat> vSeats;
    ProvenRoundThroughProofs(round, vSeats, hashRound, nNow);
    std::string strError;

    CMixSnapshot open;
    BOOST_REQUIRE(BuildMixSnapshot(round, MIX_SNAPSHOT_PUBLIC, open));
    BOOST_CHECK_EQUAL((int)open.nPhase, (int)round.Phase());
    BOOST_CHECK_EQUAL((int)open.nSeats, (int)round.Seats());
    BOOST_CHECK(open.hashRound == hashRound);
    BOOST_CHECK_MESSAGE(open.vchPrefix.empty() && open.vRoster.empty() &&
                        open.vchRsaN.empty() && open.vNonces.empty(),
                        "the public snapshot carried the round's frozen transcript");

    CMixSnapshot seat;
    BOOST_REQUIRE(BuildMixSnapshot(round, MIX_SNAPSHOT_SEAT, seat));
    BOOST_CHECK(seat.vRoster.size() == round.Seats());
    BOOST_CHECK(seat.vchRsaN == round.RsaModulus());
    BOOST_CHECK(seat.vchPrefix == round.FrozenPrefix());
    BOOST_CHECK(seat.vNonces.empty());   // nothing has published a nonce yet

    // Both forms round-trip, and the reader refuses a public snapshot carrying more.
    std::vector<unsigned char> vchOpen, vchSeat;
    BOOST_REQUIRE(BuildMixSnapshotBody(open, vchOpen));
    BOOST_REQUIRE(BuildMixSnapshotBody(seat, vchSeat));
    BOOST_CHECK_MESSAGE(vchOpen.size() == 36u, "the public snapshot is four bytes and a hash");
    CMixSnapshot readOpen, readSeat;
    BOOST_REQUIRE(ReadMixSnapshotBody(vchOpen, readOpen));
    BOOST_REQUIRE(ReadMixSnapshotBody(vchSeat, readSeat));
    BOOST_CHECK_EQUAL((int)readOpen.nAudience, (int)MIX_SNAPSHOT_PUBLIC);
    BOOST_CHECK(readSeat.vchPrefix == seat.vchPrefix);
    BOOST_REQUIRE_EQUAL(readSeat.vRoster.size(), seat.vRoster.size());
    for (size_t i = 0; i < readSeat.vRoster.size(); i++)
    {
        BOOST_CHECK(readSeat.vRoster[i].keyImage == seat.vRoster[i].keyImage);
        BOOST_CHECK(readSeat.vRoster[i].pubkeySession == seat.vRoster[i].pubkeySession);
    }

    CMixSnapshot leaky = open;
    leaky.vchPrefix = round.FrozenPrefix();
    std::vector<unsigned char> vchLeaky;
    BOOST_CHECK_MESSAGE(!BuildMixSnapshotBody(leaky, vchLeaky),
                        "a public snapshot was allowed to carry the frozen prefix");

    std::vector<unsigned char> vchLong = vchSeat;
    vchLong.push_back(0);
    BOOST_CHECK(!ReadMixSnapshotBody(vchLong, readSeat));
    for (size_t n = 0; n + 1 < vchOpen.size(); n++)
        BOOST_CHECK(!ReadMixSnapshotBody(std::vector<unsigned char>(vchOpen.begin(),
                                                                    vchOpen.begin() + n),
                                         readOpen));

    // The aggregate appears once it is fixed, in input order, and not before.
    SignOverWire(round, vSeats, hashRound, nNow + MIX_OUTPUT_WINDOW + 1, false);
    BOOST_REQUIRE(BuildMixSnapshot(round, MIX_SNAPSHOT_SEAT, seat));
    BOOST_REQUIRE_EQUAL(seat.vNonces.size(), round.Seats());
    const std::vector<std::vector<unsigned char> > vNonces = round.NoncesInInputOrder();
    for (size_t i = 0; i < seat.vNonces.size(); i++)
        BOOST_CHECK(std::equal(seat.vNonces[i].begin(), seat.vNonces[i].end(),
                               vNonces[i].begin()));

    // The reply to anything that changes the round says only whether it was taken.
    std::vector<unsigned char> vchAck;
    bool fAccepted = false;
    BOOST_REQUIRE(BuildMixAckBody(true, vchAck));
    BOOST_CHECK_EQUAL(vchAck.size(), 1u);
    BOOST_REQUIRE(ReadMixAckBody(vchAck, fAccepted));
    BOOST_CHECK(fAccepted);
    BOOST_REQUIRE(BuildMixAckBody(false, vchAck));
    BOOST_REQUIRE(ReadMixAckBody(vchAck, fAccepted));
    BOOST_CHECK(!fAccepted);
    BOOST_CHECK(!ReadMixAckBody(std::vector<unsigned char>(1, 2), fAccepted));
    BOOST_CHECK(!ReadMixAckBody(std::vector<unsigned char>(2, 1), fAccepted));
}

namespace {

// A signed announcement over the proven round's own transcript, so the prefix the
// coordinator freezes is the one the cached proofs were made for.
CMixRoundAnnouncement ProvenAnnouncement(CKey& keyOut, const CNullSendSession& roundKey,
                                         int64_t nStart)
{
    const MixProofSet& proofs = MixProofs();
    keyOut.MakeNewKey(true);
    CMixRoundAnnouncement announce;
    announce.hashRoundKey = MixRoundKeyCommitment(roundKey.vchRSA_N, roundKey.vchRSA_E);
    announce.strEndpoint = "wq3wlxjlpvxhuxpe5x6dtnrhrxvgkfxkvxmmwpnrfexbbxbxbxbxbxbd.onion";
    announce.nPort = 8443;
    announce.nParticipants = 2;
    announce.nTime = nStart;
    announce.nNetwork = proofs.header.nNetwork;
    announce.genesis = proofs.header.genesis;
    announce.parameterDigest = proofs.header.parameterDigest;
    announce.finalizedRoot = proofs.header.finalizedRoot;
    announce.nFinalizedTreeSize = proofs.header.nFinalizedTreeSize;
    announce.nDenomination = MIX_DENOM;
    announce.nFee = proofs.header.nFee;
    announce.nJoinSecs = 60;
    announce.nViewSecs = 60;
    announce.nTokenSecs = 60;
    announce.nOutputSecs = 120;
    announce.nApproveSecs = 60;
    announce.nNonceSecs = 60;
    announce.nResponseSecs = 60;
    announce.nTerminalSecs = 300;
    BOOST_REQUIRE(announce.Sign(keyOut));
    return announce;
}

// A fresh blind-signature key per round, which is what the ledger in the coordinator
// enforces: a modulus that ran twice verifies the earlier round's tokens in the later one.
CNullSendSession FreshRoundKey(int nId)
{
    CNullSendSession session;
    session.nSessionID = nId;
    BOOST_REQUIRE(session.GenerateSessionRSAKey());
    return session;
}

// The authenticated frames, built against the announcement the coordinator is running
// rather than the fixture's own constant.
std::vector<unsigned char> ViewSigFrame(const Seat& seat, const uint256& hashRound,
                                        const uint256& hashAnnounce, const uint256& hashView)
{
    std::vector<unsigned char> vchSig, vchBody;
    BOOST_REQUIRE(seat.key.Sign(hashView, vchSig));
    BOOST_REQUIRE(BuildMixViewSigBody(seat.pubkey, hashAnnounce, vchSig, vchBody));
    return AuthedFrame(seat, hashRound, MIX_FRAME_VIEW_SIG, vchBody);
}

std::vector<unsigned char> ConstructionFrame(const Seat& seat, const uint256& hashRound,
                                             const uint256& hashAnnounce,
                                             const PrivacyVNextDigest& pseudoOut)
{
    std::vector<unsigned char> vchBody;
    BOOST_REQUIRE(BuildMixInputConstructionBody(seat.pubkey, hashAnnounce, seat.keyImage,
                                                pseudoOut, vchBody));
    return AuthedFrame(seat, hashRound, MIX_FRAME_INPUT_CONSTRUCTION, vchBody);
}

std::vector<unsigned char> PrefixSigFrameFor(const Seat& seat, const uint256& hashRound,
                                             const uint256& hashAnnounce,
                                             const uint256& hashPrefix)
{
    std::vector<unsigned char> vchSig, vchBody;
    BOOST_REQUIRE(seat.key.Sign(hashPrefix, vchSig));
    BOOST_REQUIRE(BuildMixPrefixSigBody(seat.pubkey, hashAnnounce, vchSig, vchBody));
    return AuthedFrame(seat, hashRound, MIX_FRAME_PREFIX_SIG, vchBody);
}

std::vector<unsigned char> MembershipFrameFor(const Seat& seat, const uint256& hashRound,
                                              const uint256& hashAnnounce,
                                              const std::vector<unsigned char>& vchProof)
{
    std::vector<unsigned char> vchBody;
    BOOST_REQUIRE(BuildMixMembershipProofBody(seat.pubkey, hashAnnounce, vchProof, vchBody));
    return AuthedFrame(seat, hashRound, MIX_FRAME_MEMBERSHIP_PROOF, vchBody);
}

// One request through the service, returning the frame it answers with.
MixFrameType Ask(CMixCoordinator& coord, MixFrameType nType,
                 const std::vector<unsigned char>& vchPayload, int64_t nNow,
                 std::vector<unsigned char>& vchReply)
{
    MixFrameType nReply = MIX_FRAME_NONE;
    vchReply.clear();
    if (!coord.Serve(nType, vchPayload, nNow, nReply, vchReply))
        return MIX_FRAME_NONE;
    return nReply;
}

bool Accepted(CMixCoordinator& coord, MixFrameType nType,
              const std::vector<unsigned char>& vchPayload, int64_t nNow)
{
    std::vector<unsigned char> vchReply;
    if (Ask(coord, nType, vchPayload, nNow, vchReply) != MIX_FRAME_ACK)
        return false;
    bool fAccepted = false;
    return ReadMixAckBody(vchReply, fAccepted) && fAccepted;
}

} // namespace

// The service end to end on its announced schedule, from join to a validating transaction.
// Every phase transition is the clock reaching an instant fixed by the announcement.
BOOST_AUTO_TEST_CASE(the_coordinator_runs_a_round_on_its_announced_schedule)
{
    const MixProofSet& proofs = MixProofs();
    const int64_t T0 = 21000300;
    CKey keyCoordinator;
    const CNullSendSession roundKey = FreshRoundKey(4001);
    const CMixRoundAnnouncement announce = ProvenAnnouncement(keyCoordinator, roundKey, T0);
    const uint256 hashRound = announce.hashRound;

    CMixCoordinator coord;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(coord.Open(announce, roundKey, T0, &strError), strError);
    BOOST_CHECK_EQUAL((int)coord.Stage(T0), (int)MIX_STAGE_JOIN);

    // Anyone may read how far it has got; nobody unauthenticated gets the transcript.
    std::vector<unsigned char> vchReply;
    BOOST_REQUIRE_EQUAL((int)Ask(coord, MIX_FRAME_STATE, std::vector<unsigned char>(), T0,
                                 vchReply),
                        (int)MIX_FRAME_SNAPSHOT);
    CMixSnapshot snapshot;
    BOOST_REQUIRE(ReadMixSnapshotBody(vchReply, snapshot));
    BOOST_CHECK_EQUAL((int)snapshot.nAudience, (int)MIX_SNAPSHOT_PUBLIC);
    BOOST_CHECK_EQUAL((int)snapshot.nSeats, 0);

    std::vector<Seat> vSeats;
    vSeats.push_back(ProvenSeat(0));
    vSeats.push_back(ProvenSeat(1));
    for (size_t i = 0; i < vSeats.size(); i++)
        BOOST_REQUIRE_MESSAGE(Accepted(coord, MIX_FRAME_JOIN, JoinFrame(vSeats[i], hashRound), T0),
                              "the coordinator refused a join inside its join window");

    // Out of its window, a frame is refused however well formed it is: the schedule is
    // what decides, not whether the round could use it.
    BOOST_CHECK_MESSAGE(!Accepted(coord, MIX_FRAME_VIEW_SIG,
                                  ViewSigFrame(vSeats[0], hashRound, announce.hashRound,
                                               coord.Round().ViewDigest(announce.hashRound)),
                                  T0),
                        "a view signature was taken before its window opened");

    // View window: the join set freezes on the clock, and a seat reads the roster it must
    // sign over rather than being told the digest.
    const int64_t T1 = announce.JoinCloses();
    BOOST_CHECK_EQUAL((int)coord.Stage(T1), (int)MIX_STAGE_VIEW);
    coord.Tick(T1);
    std::vector<unsigned char> vchAuthBody, vchAuthFrame;
    BOOST_REQUIRE(BuildMixStateAuthBody(vSeats[0].pubkey, announce.hashRound, vchAuthBody));
    BOOST_REQUIRE(BuildAuthedMixFrame(vSeats[0].key, hashRound, MIX_FRAME_STATE_AUTH,
                                      vchAuthBody, vchAuthFrame));
    BOOST_REQUIRE_EQUAL((int)Ask(coord, MIX_FRAME_STATE_AUTH, vchAuthFrame, T1, vchReply),
                        (int)MIX_FRAME_SNAPSHOT);
    BOOST_REQUIRE(ReadMixSnapshotBody(vchReply, snapshot));
    BOOST_CHECK_EQUAL((int)snapshot.nAudience, (int)MIX_SNAPSHOT_SEAT);
    BOOST_REQUIRE_EQUAL(snapshot.vRoster.size(), 2u);
    BOOST_CHECK(snapshot.vchRsaN == roundKey.vchRSA_N);
    const uint256 hashView = MixViewDigest(announce.hashRound, snapshot.vRoster);
    BOOST_CHECK_MESSAGE(hashView == coord.Round().ViewDigest(announce.hashRound),
                        "a seat could not derive the view it is asked to sign");
    for (size_t i = 0; i < vSeats.size(); i++)
        BOOST_REQUIRE(Accepted(coord, MIX_FRAME_VIEW_SIG,
                               ViewSigFrame(vSeats[i], hashRound, announce.hashRound, hashView),
                               T1));
    for (size_t i = 0; i < vSeats.size(); i++)
        BOOST_REQUIRE(Accepted(coord, MIX_FRAME_INPUT_CONSTRUCTION,
                               ConstructionFrame(vSeats[i], hashRound, announce.hashRound,
                                                 proofs.vPseudoOuts[ProvenIndex(vSeats[i].keyImage)]),
                               T1));

    // A stranger cannot read it: the seat form carries every output's disclosed opening once the
    // prefix freezes, and an abandoned round never publishes those any other way.
    const Seat stranger = MakeSeat(9);
    BOOST_REQUIRE(BuildMixStateAuthBody(stranger.pubkey, announce.hashRound, vchAuthBody));
    BOOST_REQUIRE(BuildAuthedMixFrame(stranger.key, hashRound, MIX_FRAME_STATE_AUTH,
                                      vchAuthBody, vchAuthFrame));
    BOOST_CHECK_EQUAL((int)Ask(coord, MIX_FRAME_STATE_AUTH, vchAuthFrame, T1, vchReply),
                        (int)MIX_FRAME_NONE);

    // Token window: the coordinator signs what it is handed and re-serves a lost reply.
    const int64_t T2 = announce.ViewCloses();
    BOOST_CHECK_EQUAL((int)coord.Stage(T2), (int)MIX_STAGE_TOKEN);
    std::vector<Token> vTokens;
    for (size_t i = 0; i < vSeats.size(); i++)
    {
        const std::vector<CMixOutputRecord>& vBundle =
            proofs.vBundles[ProvenIndex(vSeats[i].keyImage)];
        CNullSendClient client;
        BOOST_REQUIRE(client.BlindCredentialMessage(roundKey.vchRSA_N, roundKey.vchRSA_E,
                                                    MixOutputBundleCredentialHash(vBundle)));
        std::vector<unsigned char> vchBody, vchFrame;
        BOOST_REQUIRE(BuildMixBlindRequestBody(vSeats[i].pubkey, announce.hashRound,
                                               client.vchBlindedCredential, vchBody));
        BOOST_REQUIRE(BuildAuthedMixFrame(vSeats[i].key, hashRound, MIX_FRAME_BLIND_REQUEST,
                                          vchBody, vchFrame));
        BOOST_REQUIRE_EQUAL((int)Ask(coord, MIX_FRAME_BLIND_REQUEST, vchFrame, T2, vchReply),
                            (int)MIX_FRAME_BLIND_SIGNATURE);
        const std::vector<unsigned char> vchFirst = vchReply;
        // The same request again: a reply lost on its own circuit is routine, and a retry
        // that came back empty-handed would strand the seat with no token and no way to
        // ask for one.
        BOOST_REQUIRE_EQUAL((int)Ask(coord, MIX_FRAME_BLIND_REQUEST, vchFrame, T2, vchReply),
                            (int)MIX_FRAME_BLIND_SIGNATURE);
        BOOST_CHECK_MESSAGE(vchReply == vchFirst,
                            "a retried token request got a different signature");
        // A different blinded message under the same seat is not a retry: it would hand
        // back a signature over the FIRST message, which this seat cannot unblind, and it
        // has no second token to ask for.
        std::vector<unsigned char> vchOtherBody, vchOtherFrame;
        BOOST_REQUIRE(BuildMixBlindRequestBody(vSeats[i].pubkey, announce.hashRound,
                                               std::vector<unsigned char>(
                                                   client.vchBlindedCredential.size(), 0x5a),
                                               vchOtherBody));
        BOOST_REQUIRE(BuildAuthedMixFrame(vSeats[i].key, hashRound, MIX_FRAME_BLIND_REQUEST,
                                          vchOtherBody, vchOtherFrame));
        BOOST_CHECK_MESSAGE(
            Ask(coord, MIX_FRAME_BLIND_REQUEST, vchOtherFrame, T2, vchReply) != MIX_FRAME_BLIND_SIGNATURE,
            "a second blinded message under one seat was answered with the first signature");
        BOOST_REQUIRE(client.UnblindSignature(vchFirst));
        Token token;
        token.vchCredential = client.vchCredentialHash;
        token.vchSignature = client.vchUnblindedSig;
        vTokens.push_back(token);
    }

    // Output window: anonymous, and the registration is idempotent for the same reason.
    const int64_t T3 = announce.TokenCloses();
    BOOST_CHECK_EQUAL((int)coord.Stage(T3), (int)MIX_STAGE_OUTPUT);
    for (size_t i = 0; i < vSeats.size(); i++)
    {
        const std::vector<CMixOutputRecord>& vBundle =
            proofs.vBundles[ProvenIndex(vSeats[i].keyImage)];
        const std::vector<unsigned char> vchFrame = OutputFrame(vTokens[i], vBundle);
        BOOST_REQUIRE(Accepted(coord, MIX_FRAME_OUTPUT, vchFrame, T3));
        BOOST_CHECK_MESSAGE(Accepted(coord, MIX_FRAME_OUTPUT, vchFrame, T3),
                            "a retransmitted registration was refused");
    }
    BOOST_CHECK_EQUAL(coord.Round().Outputs(), 2u);

    // Approval window: the prefix is frozen by the clock, not by the last output arriving.
    // The output window ends strictly after its close, which is the comparison the round
    // itself makes, so a registration at exactly that instant is still in time.
    const int64_t T4 = announce.OutputCloses();
    BOOST_CHECK_EQUAL((int)coord.Stage(T4), (int)MIX_STAGE_OUTPUT);
    BOOST_CHECK_EQUAL((int)coord.Stage(T4 + 1), (int)MIX_STAGE_APPROVE);
    coord.Tick(T4 + 1);
    BOOST_REQUIRE_MESSAGE(!coord.Round().FrozenPrefix().empty(),
                          "the coordinator did not freeze a prefix at its scheduled instant");
    for (size_t i = 0; i < vSeats.size(); i++)
        BOOST_REQUIRE(Accepted(coord, MIX_FRAME_PREFIX_SIG,
                               PrefixSigFrameFor(vSeats[i], hashRound, announce.hashRound,
                                                 coord.Round().PrefixDigest()),
                               T4 + 1));

    // A seat proves only once every seat has approved, learned from the certificate in its
    // snapshot, which appears only when complete.
    BOOST_REQUIRE(BuildMixStateAuthBody(vSeats[1].pubkey, announce.hashRound, vchAuthBody));
    BOOST_REQUIRE(BuildAuthedMixFrame(vSeats[1].key, hashRound, MIX_FRAME_STATE_AUTH,
                                      vchAuthBody, vchAuthFrame));
    BOOST_REQUIRE_EQUAL((int)Ask(coord, MIX_FRAME_STATE_AUTH, vchAuthFrame, T4 + 1, vchReply),
                        (int)MIX_FRAME_SNAPSHOT);
    BOOST_REQUIRE(ReadMixSnapshotBody(vchReply, snapshot));
    BOOST_CHECK_EQUAL(snapshot.vPrefixSigs.size(), 2u);
    BOOST_CHECK_EQUAL(snapshot.vViewSigs.size(), 2u);
    for (size_t i = 0; i < vSeats.size(); i++)
        BOOST_REQUIRE(Accepted(coord, MIX_FRAME_MEMBERSHIP_PROOF,
                               MembershipFrameFor(vSeats[i], hashRound, announce.hashRound,
                                                  proofs.vProofs[ProvenIndex(vSeats[i].keyImage)]),
                               T4 + 1));

    // Everything the round needs is in, and the nonce window has still not opened: the
    // round itself would take a nonce now, and the schedule is what refuses it. A phase
    // that opened as soon as its predecessor filled would be a phase the coordinator times.
    {
        const PrivacyVNextMixBalanceFacts early = FactsFromPrefix(coord.Round().FrozenPrefix());
        const PrivacyVNextMixBalanceShare share = SeatShare(coord.Round(), vSeats[0], 0x4c);
        PrivacyVNextDigest nonce;
        BOOST_REQUIRE_MESSAGE(PrivacyVNextMixBalanceNonce(early, share, nonce, strError),
                              strError);
        BOOST_CHECK_MESSAGE(!Accepted(coord, MIX_FRAME_NONCE,
                                      ShareFrame(vSeats[0], hashRound, MIX_FRAME_NONCE, nonce),
                                      T4 + 1),
                            "a nonce was taken before its window opened");
    }

    // Nonce and response windows.
    const int64_t T5 = announce.ApproveCloses();
    BOOST_CHECK_EQUAL((int)coord.Stage(T5), (int)MIX_STAGE_NONCE);
    coord.Tick(T5);
    const PrivacyVNextMixBalanceFacts facts = FactsFromPrefix(coord.Round().FrozenPrefix());
    std::vector<PrivacyVNextMixBalanceShare> vShares;
    for (size_t i = 0; i < vSeats.size(); i++)
    {
        vShares.push_back(SeatShare(coord.Round(), vSeats[i], 0x4d));
        PrivacyVNextDigest nonce;
        BOOST_REQUIRE_MESSAGE(PrivacyVNextMixBalanceNonce(facts, vShares[i], nonce, strError),
                              strError);
        BOOST_REQUIRE(Accepted(coord, MIX_FRAME_NONCE,
                               ShareFrame(vSeats[i], hashRound, MIX_FRAME_NONCE, nonce), T5));
    }

    const int64_t T6 = announce.NonceCloses();
    BOOST_CHECK_EQUAL((int)coord.Stage(T6), (int)MIX_STAGE_RESPONSE);
    coord.Tick(T6);
    const std::vector<std::vector<unsigned char> > vNonceBytes =
        coord.Round().NoncesInInputOrder();
    std::vector<PrivacyVNextDigest> vNonces(vNonceBytes.size());
    for (size_t i = 0; i < vNonceBytes.size(); i++)
        memcpy(vNonces[i].data(), &vNonceBytes[i][0], 32);
    for (size_t i = 0; i < vSeats.size(); i++)
    {
        PrivacyVNextDigest response;
        BOOST_REQUIRE_MESSAGE(PrivacyVNextMixBalanceSign(facts, vShares[i], vNonces, response,
                                                         strError), strError);
        BOOST_REQUIRE(Accepted(coord, MIX_FRAME_RESPONSE,
                               ShareFrame(vSeats[i], hashRound, MIX_FRAME_RESPONSE, response),
                               T6));
    }

    // The schedule ends and the round publishes.
    const int64_t T7 = announce.ResponseCloses();
    coord.Tick(T7);
    BOOST_REQUIRE_MESSAGE(coord.HasTransaction(),
                          "the coordinator did not assemble a transaction: "
                          << coord.Round().AbortReason());
    BOOST_CHECK_EQUAL((int)coord.Round().Phase(), (int)MIX_PHASE_COMPLETE);

    // And anyone may collect it, without holding a seat.
    BOOST_REQUIRE_EQUAL((int)Ask(coord, MIX_FRAME_RESULT, std::vector<unsigned char>(), T7,
                                 vchReply),
                        (int)MIX_FRAME_TRANSACTION);
    CDataStream ssTx(vchReply, SER_NETWORK, PROTOCOL_VERSION);
    CTransaction txRead;
    ssTx >> txRead;
    BOOST_CHECK(txRead.GetHash() == coord.Transaction().GetHash());
    PrivacyVNextStateEffects effects;
    const PrivacyVNextPayloadValidation validation = ExtractPrivacyVNextPayloadEffects(
        INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, txRead.privacyVNext.vchPayload, effects);
    BOOST_CHECK_MESSAGE(validation.nResult == INNOVA_PRIVACY_VNEXT_VALID, validation.strError);
}

// A round that does not fill dies at its own deadline, and says nothing about who was
// missing. Nothing the coordinator publishes names a roster position.
BOOST_AUTO_TEST_CASE(a_round_that_does_not_fill_ends_at_its_join_deadline)
{
    const int64_t T0 = 22000000;
    CKey keyCoordinator;
    const CNullSendSession roundKey = FreshRoundKey(4002);
    const CMixRoundAnnouncement announce = ProvenAnnouncement(keyCoordinator, roundKey, T0);
    CMixCoordinator coord;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(coord.Open(announce, roundKey, T0, &strError), strError);

    const Seat only = ProvenSeat(0);
    BOOST_REQUIRE(Accepted(coord, MIX_FRAME_JOIN, JoinFrame(only, announce.hashRound), T0));
    coord.Tick(announce.JoinCloses());
    BOOST_CHECK_EQUAL((int)coord.Round().Phase(), (int)MIX_PHASE_ABORTED);

    std::vector<unsigned char> vchReply;
    BOOST_CHECK_EQUAL((int)Ask(coord, MIX_FRAME_RESULT, std::vector<unsigned char>(),
                               announce.JoinCloses(), vchReply),
                      (int)MIX_FRAME_ABORT);
    BOOST_CHECK_MESSAGE(vchReply.empty(),
                        "the abort reply carried something about who did not arrive");
}

// The round key is single use, and the record of use survives a restart.
BOOST_AUTO_TEST_CASE(a_round_key_runs_one_round)
{
    const int64_t T0 = 23000100;
    CKey keyCoordinator;
    const CNullSendSession roundKey = FreshRoundKey(4003);
    const CMixRoundAnnouncement first = ProvenAnnouncement(keyCoordinator, roundKey, T0);
    CMixCoordinator coordFirst;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(coordFirst.Open(first, roundKey, T0, &strError), strError);

    CKey keySecond;
    const CMixRoundAnnouncement second = ProvenAnnouncement(keySecond, roundKey, T0 + MIX_RENDEZVOUS_SLOT_SECONDS);
    CMixCoordinator coordSecond;
    BOOST_CHECK_MESSAGE(!coordSecond.Open(second, roundKey, T0 + MIX_RENDEZVOUS_SLOT_SECONDS, &strError),
                        "a blind-signature key ran a second round");
    BOOST_CHECK(strError.find("already run") != std::string::npos);
    BOOST_CHECK(MixRoundKeyWasUsed(roundKey.vchRSA_N));

    // And a key the announcement did not commit to is refused whether or not it is fresh:
    // a per-seat key is how a coordinator reads the seat off an anonymous registration, and
    // the commitment is what a seat checks before it blinds anything.
    const CNullSendSession otherKey = FreshRoundKey(4005);
    CKey keyOther;
    const CMixRoundAnnouncement mismatched = ProvenAnnouncement(keyOther, roundKey, T0 + 3000);
    CMixCoordinator coordMismatch;
    BOOST_CHECK_MESSAGE(!coordMismatch.Open(mismatched, otherKey, T0 + 3000, &strError),
                        "a round opened under a key its announcement does not commit to");
    BOOST_CHECK(strError.find("commits to") != std::string::npos);

    // A fresh key opens fine, which is what makes the refusal above about reuse.
    const CNullSendSession freshKey = FreshRoundKey(4004);
    CKey keyThird;
    const CMixRoundAnnouncement third = ProvenAnnouncement(keyThird, freshKey, T0 + 2000);
    CMixCoordinator coordThird;
    BOOST_CHECK_MESSAGE(coordThird.Open(third, freshKey, T0 + 2000, &strError), strError);
}

namespace {

// What a seat brings to an attempt, drawn for this attempt only.
CMixSeatMaterial SeatMaterial(size_t nIndex, size_t nSeats, unsigned char chSeed)
{
    const MixProofSet& proofs = MixProofs();
    PrivacyVNextDigest seed;
    seed.fill(chSeed);
    PrivacyVNextDerivedKeys recipient;
    std::string strError;
    PrivacyVNextDigest genesis;
    PrivacyVNextLocalGenesis(genesis.data());
    BOOST_REQUIRE_MESSAGE(DerivePrivacyVNextKeys(seed, genesis, 0, PrivacyVNextLocalNetworkId(),
                                                 0, recipient, strError), strError);
    CMixSeatMaterial material;
    material.input.spendScalar = proofs.vSpends[nIndex].spendScalar;
    material.input.commitmentScalar = proofs.vSpends[nIndex].commitmentScalar;
    material.input.leaf = proofs.vSpends[nIndex].leaf;
    material.input.vchWitnessRecord = proofs.vSpends[nIndex].vchWitnessRecord;
    material.recipientSpend = recipient.spendPublic;
    material.recipientView = recipient.viewPublic;
    material.outgoingSecret = recipient.outgoingViewSecret;
    material.noteMask = proofs.vNoteMasks[nIndex];
    material.outputY = LowScalar((unsigned char)(chSeed + 1));
    material.outputMask = LowScalar((unsigned char)(chSeed + 2));
    for (size_t j = 0; j < nSeats; j++)
        material.vEphemerals.push_back(std::make_pair(LowScalar((unsigned char)(chSeed + 3 + 2 * j)),
                                                      LowScalar((unsigned char)(chSeed + 4 + 2 * j))));
    material.membershipEntropy = LowScalar((unsigned char)(chSeed + 0x20));
    material.balanceEntropy = LowScalar((unsigned char)(chSeed + 0x30));
    return material;
}

// Whether a frame was taken, rather than merely answered.
bool AcceptedFrame(CMixCoordinator& coord, MixFrameType nType,
                   const std::vector<unsigned char>& vchFrame, int64_t nNow)
{
    MixFrameType nReply = MIX_FRAME_NONE;
    std::vector<unsigned char> vchReply;
    if (!coord.Serve(nType, vchFrame, nNow, nReply, vchReply) || nReply != MIX_FRAME_ACK)
        return false;
    bool fAccepted = false;
    return ReadMixAckBody(vchReply, fAccepted) && fAccepted;
}

// The fixture's own ladder: the shipped one is 1 and 10 INN, which a test chain has no
// notes at. What matters is that a seat checks the announcement against a policy of its
// own rather than taking the coordinator's word for the amount and the share.
CMixPolicy TestPolicy()
{
    CMixPolicy policy;
    policy.vDenominations.push_back(MIX_DENOM);
    policy.nFeeSharePerSeat = MIX_FEE_SHARE;
    return policy;
}

// What the chain says about this round, for a seat that read it.
CMixRendezvous TestRendezvous(const CMixRoundAnnouncement& announce)
{
    CMixRendezvous rendezvous;
    rendezvous.pubkeyCoordinator = announce.pubkeyCoordinator;
    rendezvous.nSlot = MixRendezvousSlot(announce.nTime);
    rendezvous.hashCommitment = MixRendezvousCommitment(announce.pubkeyCoordinator,
                                                        rendezvous.nSlot, announce.hashRound);
    return rendezvous;
}

// The reply a seat gets, unpacked.
bool AskSeat(CMixCoordinator& coord, MixFrameType nType,
             const std::vector<unsigned char>& vchFrame, int64_t nNow,
             MixFrameType& nReplyOut, std::vector<unsigned char>& vchReplyOut)
{
    nReplyOut = MIX_FRAME_NONE;
    return coord.Serve(nType, vchFrame, nNow, nReplyOut, vchReplyOut);
}

// A seat's own read of the round.
bool ReadSnapshot(CMixCoordinator& coord, const Seat& seat, const uint256& hashRound,
                  const uint256& hashAnnounce, int64_t nNow, CMixSnapshot& snapshotOut)
{
    std::vector<unsigned char> vchBody, vchFrame, vchReply;
    if (!BuildMixStateAuthBody(seat.pubkey, hashAnnounce, vchBody) ||
        !BuildAuthedMixFrame(seat.key, hashRound, MIX_FRAME_STATE_AUTH, vchBody, vchFrame))
        return false;
    MixFrameType nReply = MIX_FRAME_NONE;
    if (!coord.Serve(MIX_FRAME_STATE_AUTH, vchFrame, nNow, nReply, vchReply) ||
        nReply != MIX_FRAME_SNAPSHOT)
        return false;
    return ReadMixSnapshotBody(vchReply, snapshotOut);
}

} // namespace

// Two real clients against the real service, every step a frame: the coordinator publishes
// a validating transaction and each recipient finds its note in it.
BOOST_AUTO_TEST_CASE(two_seats_and_a_coordinator_run_a_round_over_frames_alone)
{
    const int64_t T0 = 24000300;
    CKey keyCoordinator;
    const CNullSendSession roundKey = FreshRoundKey(4101);
    const CMixRoundAnnouncement announce = ProvenAnnouncement(keyCoordinator, roundKey, T0);
    const uint256 hashRound = announce.hashRound;
    CMixCoordinator coord;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(coord.Open(announce, roundKey, T0, &strError), strError);

    // Each seat starts its attempt, which is where it proves its input once to fix what it
    // will publish about it.
    CMixSeat seatA, seatB;
    Seat idA = MakeSeat(1), idB = MakeSeat(2);
    BOOST_REQUIRE_MESSAGE(seatA.Begin(announce, idA.key, SeatMaterial(0, 2, 0x31), TestPolicy(),
                                        TestRendezvous(announce), &strError),
                          strError);
    BOOST_REQUIRE_MESSAGE(seatB.Begin(announce, idB.key, SeatMaterial(1, 2, 0x51), TestPolicy(),
                                        TestRendezvous(announce), &strError),
                          strError);
    idA.keyImage = seatA.KeyImage();
    idB.keyImage = seatB.KeyImage();
    BOOST_CHECK(idA.keyImage != idB.keyImage);

    CMixSeat* vSeatsPtr[2] = { &seatA, &seatB };
    Seat vIds[2] = { idA, idB };

    std::vector<unsigned char> vchFrame, vchReply;
    MixFrameType nReply = MIX_FRAME_NONE;
    for (size_t i = 0; i < 2; i++)
    {
        BOOST_REQUIRE(vSeatsPtr[i]->BuildJoin(vchFrame, &strError));
        BOOST_REQUIRE(AskSeat(coord, MIX_FRAME_JOIN, vchFrame, T0, nReply, vchReply));
        BOOST_CHECK_EQUAL((int)nReply, (int)MIX_FRAME_ACK);
    }

    // The view: each seat reads the roster and signs what it implies, rather than being
    // handed a digest.
    const int64_t T1 = announce.JoinCloses();
    coord.Tick(T1);
    CMixSnapshot snapshot;
    // A roster this seat is not in is not a view it signs: certifying one would certify a
    // round it holds no place in.
    BOOST_REQUIRE(ReadSnapshot(coord, vIds[1], hashRound, announce.hashRound, T1, snapshot));
    {
        CMixSnapshot without = snapshot;
        for (size_t i = 0; i < without.vRoster.size(); i++)
            if (without.vRoster[i].keyImage == seatB.KeyImage())
                without.vRoster[i].keyImage = uint256(0xDEAD);
        std::vector<unsigned char> vchIgnored;
        BOOST_CHECK_MESSAGE(!seatB.AcceptRoster(without, vchIgnored, &strError),
                            "a seat signed a view over a roster it is not in");
    }
    for (size_t i = 0; i < 2; i++)
    {
        BOOST_REQUIRE(ReadSnapshot(coord, vIds[i], hashRound, announce.hashRound, T1, snapshot));
        BOOST_REQUIRE_MESSAGE(vSeatsPtr[i]->AcceptRoster(snapshot, vchFrame, &strError), strError);
        BOOST_REQUIRE_MESSAGE(AcceptedFrame(coord, MIX_FRAME_VIEW_SIG, vchFrame, T1),
                              "the coordinator refused a seat's view signature");
    }
    // A construction only counts once every seat has signed the same view, so the round
    // cannot be handed an input set under a roster the seats have not all accepted.
    for (size_t i = 0; i < 2; i++)
    {
        BOOST_REQUIRE(vSeatsPtr[i]->BuildConstruction(vchFrame, &strError));
        BOOST_REQUIRE_MESSAGE(AcceptedFrame(coord, MIX_FRAME_INPUT_CONSTRUCTION, vchFrame, T1),
                              "the coordinator refused a seat's input construction");
    }
    // A second view, however well formed, is refused by the seat itself: signing two is how
    // one input ends up in two rounds.
    BOOST_CHECK_MESSAGE(!seatA.AcceptRoster(snapshot, vchFrame, &strError),
                        "a seat signed a second view in one attempt");

    // The token, checked against the announcement's commitment before anything is blinded,
    // and verified before it is ever presented anonymously.
    const int64_t T2 = announce.ViewCloses();
    const CNullSendSession otherKey = FreshRoundKey(4102);
    {
        // A key the announcement did not commit to is a per-seat key, and a token minted
        // under one is read straight off the anonymous registration.
        BOOST_REQUIRE(ReadSnapshot(coord, vIds[0], hashRound, announce.hashRound, T2, snapshot));
        CMixSnapshot forged = snapshot;
        forged.vchRsaN = otherKey.vchRSA_N;
        forged.vchRsaE = otherKey.vchRSA_E;
        std::vector<unsigned char> vchIgnored;
        BOOST_CHECK_MESSAGE(!seatA.BuildTokenRequest(forged, vchIgnored, &strError),
                            "a seat blinded its credential to a key the announcement never named");
    }
    for (size_t i = 0; i < 2; i++)
    {
        BOOST_REQUIRE(ReadSnapshot(coord, vIds[i], hashRound, announce.hashRound, T2, snapshot));
        BOOST_REQUIRE_MESSAGE(vSeatsPtr[i]->BuildTokenRequest(snapshot, vchFrame, &strError),
                              strError);
        BOOST_REQUIRE(AskSeat(coord, MIX_FRAME_BLIND_REQUEST, vchFrame, T2, nReply, vchReply));
        BOOST_REQUIRE_EQUAL((int)nReply, (int)MIX_FRAME_BLIND_SIGNATURE);
        BOOST_REQUIRE_MESSAGE(vSeatsPtr[i]->AcceptToken(vchReply, &strError), strError);
    }

    // The registration, which names no seat.
    const int64_t T3 = announce.TokenCloses();
    for (size_t i = 0; i < 2; i++)
    {
        std::vector<unsigned char> vchBody;
        BOOST_REQUIRE(vSeatsPtr[i]->BuildRegistration(vchBody, &strError));
        BOOST_REQUIRE(AskSeat(coord, MIX_FRAME_OUTPUT, vchBody, T3, nReply, vchReply));
        bool fAccepted = false;
        BOOST_REQUIRE(ReadMixAckBody(vchReply, fAccepted));
        BOOST_CHECK(fAccepted);
    }

    // The prefix: each seat checks the whole thing itself before approving it.
    const int64_t T4 = announce.OutputCloses() + 1;
    coord.Tick(T4);
    BOOST_REQUIRE(ReadSnapshot(coord, vIds[1], hashRound, announce.hashRound, T4, snapshot));
    {
        // A prefix carrying a fee the announcement never named is refused by the seat
        // before it approves anything, not by the round afterwards.
        CMixPrefixView view;
        BOOST_REQUIRE(ParseMixPrefix(snapshot.vchPrefix, view, strError));
        std::vector<std::pair<uint256, PrivacyVNextDigest> > vInputs;
        for (size_t i = 0; i < view.vKeyImages.size(); i++)
            vInputs.push_back(std::make_pair(view.vKeyImages[i], view.vPseudoOuts[i]));
        PrivacyVNextPrefixHeader header;
        header.nOperation = iv5::NOTE_NULLSEND;
        header.nDisclosureMask = iv5::NULLSEND_DISCLOSURE_MASK;
        header.nNetwork = announce.nNetwork;
        header.genesis = announce.genesis;
        header.parameterDigest = announce.parameterDigest;
        header.finalizedRoot = announce.finalizedRoot;
        header.nFinalizedTreeSize = announce.nFinalizedTreeSize;
        header.nFee = announce.nFee + announce.nParticipants;
        header.transparentBinding = MixTransparentBinding();
        CMixSnapshot raised = snapshot;
        raised.vchPrefix = MixPrefixOver(header, vInputs, view.vOutputs,
                                         std::vector<uint64_t>(view.vOutputs.size(), MIX_DENOM));
        std::vector<unsigned char> vchIgnored;
        BOOST_CHECK_MESSAGE(!seatB.AcceptPrefix(raised, vchIgnored, &strError),
                            "a seat approved a prefix carrying a fee its announcement never named");
    }
    for (size_t i = 0; i < 2; i++)
    {
        BOOST_REQUIRE(ReadSnapshot(coord, vIds[i], hashRound, announce.hashRound, T4, snapshot));
        BOOST_REQUIRE_MESSAGE(vSeatsPtr[i]->AcceptPrefix(snapshot, vchFrame, &strError), strError);
        BOOST_REQUIRE(AskSeat(coord, MIX_FRAME_PREFIX_SIG, vchFrame, T4, nReply, vchReply));
    }
    BOOST_CHECK_MESSAGE(!seatA.AcceptPrefix(snapshot, vchFrame, &strError),
                        "a seat approved a second prefix in one attempt");

    // The proofs, under the prefix each seat approved and nothing else.
    for (size_t i = 0; i < 2; i++)
    {
        BOOST_REQUIRE_MESSAGE(vSeatsPtr[i]->BuildMembershipProof(vchFrame, &strError), strError);
        BOOST_REQUIRE(AskSeat(coord, MIX_FRAME_MEMBERSHIP_PROOF, vchFrame, T4, nReply, vchReply));
        bool fAccepted = false;
        BOOST_REQUIRE(ReadMixAckBody(vchReply, fAccepted));
        BOOST_CHECK_MESSAGE(fAccepted, "the coordinator refused a seat's own proof");
    }

    // The joint signature: a nonce each, then a response computed against the aggregate
    // each seat reads back rather than one it is told.
    const int64_t T5 = announce.ApproveCloses();
    coord.Tick(T5);
    for (size_t i = 0; i < 2; i++)
    {
        BOOST_REQUIRE_MESSAGE(vSeatsPtr[i]->BuildNonce(vchFrame, &strError), strError);
        BOOST_REQUIRE(AskSeat(coord, MIX_FRAME_NONCE, vchFrame, T5, nReply, vchReply));
        bool fAccepted = false;
        BOOST_REQUIRE(ReadMixAckBody(vchReply, fAccepted));
        BOOST_CHECK(fAccepted);
    }
    const int64_t T6 = announce.NonceCloses();
    coord.Tick(T6);
    for (size_t i = 0; i < 2; i++)
    {
        BOOST_REQUIRE(ReadSnapshot(coord, vIds[i], hashRound, announce.hashRound, T6, snapshot));
        BOOST_REQUIRE_EQUAL(snapshot.vNonces.size(), 2u);
        BOOST_REQUIRE_MESSAGE(vSeatsPtr[i]->BuildResponse(snapshot, vchFrame, &strError), strError);
        BOOST_REQUIRE(AskSeat(coord, MIX_FRAME_RESPONSE, vchFrame, T6, nReply, vchReply));
        bool fAccepted = false;
        BOOST_REQUIRE(ReadMixAckBody(vchReply, fAccepted));
        BOOST_CHECK(fAccepted);
    }

    coord.Tick(announce.ResponseCloses());
    BOOST_REQUIRE_MESSAGE(coord.HasTransaction(),
                          "the round did not publish: " << coord.Round().AbortReason());
    PrivacyVNextStateEffects effects;
    const PrivacyVNextPayloadValidation validation = ExtractPrivacyVNextPayloadEffects(
        INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
        coord.Transaction().privacyVNext.vchPayload, effects);
    BOOST_REQUIRE_MESSAGE(validation.nResult == INNOVA_PRIVACY_VNEXT_VALID, validation.strError);
    BOOST_CHECK_EQUAL(effects.keyImages.size(), 2u);
    BOOST_CHECK_EQUAL(effects.outputLeaves.size(), 2u);
}

// A seated key has a budget, since every join proof is verified on arrival; public reads
// have a round-wide ceiling, since they carry no caller identity.
BOOST_AUTO_TEST_CASE(a_seat_and_the_public_surface_each_have_a_ceiling)
{
    const int64_t T0 = 25000000;
    CKey keyCoordinator;
    const CNullSendSession roundKey = FreshRoundKey(4201);
    const CMixRoundAnnouncement announce = ProvenAnnouncement(keyCoordinator, roundKey, T0);
    const uint256 hashRound = announce.hashRound;
    CMixCoordinator coord;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(coord.Open(announce, roundKey, T0, &strError), strError);

    std::vector<Seat> vSeats;
    vSeats.push_back(ProvenSeat(0));
    vSeats.push_back(ProvenSeat(1));
    for (size_t i = 0; i < vSeats.size(); i++)
        BOOST_REQUIRE(Accepted(coord, MIX_FRAME_JOIN, JoinFrame(vSeats[i], hashRound), T0));

    // One seat, one frame type, repeated. The budget is per type, so a seat that spends
    // its allowance on one kind still has its others.
    const int64_t T1 = announce.JoinCloses();
    coord.Tick(T1);
    const uint256 hashView = coord.Round().ViewDigest(announce.hashRound);
    std::vector<unsigned char> vchReply;
    // Reads are stopped by the budget alone. Proofs share the allowance, but the round
    // refuses a second proof on its own.
    std::vector<unsigned char> vchReadBody, vchReadFrame;
    BOOST_REQUIRE(BuildMixStateAuthBody(vSeats[0].pubkey, announce.hashRound, vchReadBody));
    BOOST_REQUIRE(BuildAuthedMixFrame(vSeats[0].key, hashRound, MIX_FRAME_STATE_AUTH,
                                      vchReadBody, vchReadFrame));
    int nAnsweredReads = 0;
    for (int i = 0; i < MIX_SEAT_REQUEST_BUDGET + 4; i++)
        if (Ask(coord, MIX_FRAME_STATE_AUTH, vchReadFrame, T1, vchReply) == MIX_FRAME_SNAPSHOT)
            nAnsweredReads++;
    BOOST_CHECK_EQUAL(nAnsweredReads, MIX_SEAT_REQUEST_BUDGET);
    BOOST_CHECK_MESSAGE(Ask(coord, MIX_FRAME_STATE_AUTH, vchReadFrame, T1, vchReply) ==
                        MIX_FRAME_ACK,
                        "a seat past its budget got something other than a refusal");

    // Its view signature is still its own to spend.
    BOOST_CHECK_MESSAGE(Accepted(coord, MIX_FRAME_VIEW_SIG,
                                 ViewSigFrame(vSeats[0], hashRound, announce.hashRound, hashView),
                                 T1),
                        "one exhausted allowance took the seat's others with it");
    // The public surface, which nothing identifies: the round stops answering once its
    // second's allowance is gone, and answers again in the next one.
    int nAnswered = 0;
    for (int i = 0; i < MIX_PUBLIC_READS_PER_SECOND + 8; i++)
        if (Ask(coord, MIX_FRAME_STATE, std::vector<unsigned char>(), T1, vchReply) ==
            MIX_FRAME_SNAPSHOT)
            nAnswered++;
    BOOST_CHECK_EQUAL(nAnswered, MIX_PUBLIC_READS_PER_SECOND);
    BOOST_CHECK_MESSAGE(Ask(coord, MIX_FRAME_STATE, std::vector<unsigned char>(), T1 + 1,
                            vchReply) == MIX_FRAME_SNAPSHOT,
                        "the public surface stayed shut after its second was over");

    // A forged frame cannot spend a seat's allowance: the signature is checked first.
    const Seat stranger = MakeSeat(11);
    std::vector<unsigned char> vchBody, vchForged;
    BOOST_REQUIRE(BuildMixViewSigBody(vSeats[1].pubkey, announce.hashRound,
                                      std::vector<unsigned char>(64, 0x5a), vchBody));
    BOOST_REQUIRE(BuildAuthedMixFrame(stranger.key, hashRound, MIX_FRAME_VIEW_SIG, vchBody,
                                      vchForged));
    for (int i = 0; i < MIX_SEAT_REQUEST_BUDGET + 2; i++)
        BOOST_CHECK(Ask(coord, MIX_FRAME_VIEW_SIG, vchForged, T1 + 1, vchReply) ==
                    MIX_FRAME_NONE);
    BOOST_CHECK_MESSAGE(Accepted(coord, MIX_FRAME_VIEW_SIG,
                                 ViewSigFrame(vSeats[1], hashRound, announce.hashRound, hashView),
                                 T1 + 1),
                        "forged frames spent the allowance of the seat they named");

    // And a key that holds no seat is turned away in front of the work, not by the round
    // behind it: a properly signed frame from a stranger gets no reply at all, where one
    // the round refused would come back as a refusal.
    std::vector<unsigned char> vchOwnBody, vchOwnFrame;
    BOOST_REQUIRE(BuildMixStateAuthBody(stranger.pubkey, announce.hashRound, vchOwnBody));
    BOOST_REQUIRE(BuildAuthedMixFrame(stranger.key, hashRound, MIX_FRAME_STATE_AUTH,
                                      vchOwnBody, vchOwnFrame));
    BOOST_CHECK_MESSAGE(Ask(coord, MIX_FRAME_STATE_AUTH, vchOwnFrame, T1 + 1, vchReply) ==
                        MIX_FRAME_NONE,
                        "a key holding no seat was carried into the round's own refusals");
    std::vector<unsigned char> vchNonceBody, vchNonceFrame;
    BOOST_REQUIRE(BuildMixScalarBody(stranger.pubkey, std::vector<unsigned char>(32, 0x11),
                                     vchNonceBody));
    BOOST_REQUIRE(BuildAuthedMixFrame(stranger.key, hashRound, MIX_FRAME_NONCE, vchNonceBody,
                                      vchNonceFrame));
    BOOST_CHECK(Ask(coord, MIX_FRAME_NONCE, vchNonceFrame, T1 + 1, vchReply) == MIX_FRAME_NONE);
}

// The denomination and the share are the wallet's choice. A round announcing an amount
// nobody else mixes at has no anonymity to offer whatever its seat count says, and a share
// the coordinator picked for itself could make one seat pay a distinctive amount.
BOOST_AUTO_TEST_CASE(a_seat_mixes_at_its_own_denominations_and_its_own_share)
{
    const CMixPolicy standard = CMixPolicy::Standard();
    std::string strError;

    // The shipped ladder: two decimal tiers, one shielded transaction fee per seat.
    BOOST_CHECK(standard.Allows(100000000ULL));
    BOOST_CHECK(standard.Allows(1000000000ULL));
    BOOST_CHECK_MESSAGE(!standard.Allows(500000000ULL),
                        "a tier nobody else mixes at was accepted");
    BOOST_CHECK_EQUAL(standard.nFeeSharePerSeat, (uint64_t)MIN_TX_FEE_SHIELDED);
    // The share is 0.1% of the base tier: a tier small enough for the fee to matter is one
    // nobody should be mixing at.
    BOOST_CHECK_EQUAL(standard.vDenominations[0] / standard.nFeeSharePerSeat, 1000u);

    // The fee a round announces is the share times its seats, whatever its size, so a
    // wallet prepares one amount per tier without knowing how big its round will be.
    for (int nSeats = NULLSEND_MIN_PARTICIPANTS; nSeats <= (int)iv5::MAX_NULLSEND_INPUTS; nSeats++)
        BOOST_CHECK_MESSAGE(standard.AllowsRound(100000000ULL,
                                                 (uint64_t)nSeats * MIN_TX_FEE_SHIELDED,
                                                 nSeats, &strError), strError);

    BOOST_CHECK_MESSAGE(!standard.AllowsRound(100000000ULL, 2 * MIN_TX_FEE_SHIELDED + 1, 2,
                                              &strError),
                        "a fee that is not the share per seat was accepted");
    BOOST_CHECK_MESSAGE(!standard.AllowsRound(100000000ULL, 4 * MIN_TX_FEE_SHIELDED, 2,
                                              &strError),
                        "a doubled share was accepted because it still divided evenly");
    BOOST_CHECK(!standard.AllowsRound(12345, 2 * MIN_TX_FEE_SHIELDED, 2, &strError));
    BOOST_CHECK(!standard.AllowsRound(100000000ULL, MIN_TX_FEE_SHIELDED, 1, &strError));

    // And the seat refuses the round before it proves anything: the announcement is
    // checked against the wallet's own policy, not taken on the coordinator's word.
    const int64_t T0 = 26000100;
    CKey keyCoordinator;
    const CNullSendSession roundKey = FreshRoundKey(4301);
    const CMixRoundAnnouncement announce = ProvenAnnouncement(keyCoordinator, roundKey, T0);
    CMixSeat seat;
    const Seat id = MakeSeat(12);
    BOOST_CHECK_MESSAGE(!seat.Begin(announce, id.key, SeatMaterial(0, 2, 0xB1), standard,
                                    TestRendezvous(announce), &strError),
                        "a seat joined a round at a denomination it does not mix at");
    BOOST_CHECK(strError.find("denomination") != std::string::npos);
}

// A seat checks the announcement against the record the chain holds for this coordinator
// and slot before it reveals a key image.
BOOST_AUTO_TEST_CASE(a_seat_joins_only_the_round_its_slot_published)
{
    const int64_t T0 = 27000300;
    CKey keyCoordinator;
    const CNullSendSession roundKey = FreshRoundKey(4401);
    const CMixRoundAnnouncement announce = ProvenAnnouncement(keyCoordinator, roundKey, T0);
    const CMixRendezvous rendezvous = TestRendezvous(announce);
    std::string strError;

    BOOST_CHECK_MESSAGE(MixAnnouncementMatchesRendezvous(announce, rendezvous, &strError),
                        strError);

    // A slot that published nothing is a slot to skip. Taking whatever a server offers is
    // precisely the case the commitment exists to refuse.
    BOOST_CHECK(!MixAnnouncementMatchesRendezvous(announce, CMixRendezvous(), &strError));

    // And an empty announcement agrees with an empty slot on every later check: the two
    // invalid keys compare equal, both slots are zero, and the commitment over an invalid key
    // is the zero an empty record holds. Only refusing emptiness outright catches it.
    const CMixRoundAnnouncement nothing;
    BOOST_CHECK_MESSAGE(!MixAnnouncementMatchesRendezvous(nothing, CMixRendezvous(), &strError),
                        "an empty announcement matched an empty slot");

    // A second announcement from the same coordinator for the same slot: well formed, signed,
    // and not the one the slot authorises.
    CMixRoundAnnouncement other = announce;
    other.nPort = 8444;
    other.hashRound = other.DerivedRoundId();
    BOOST_REQUIRE(other.hashRound != announce.hashRound);
    BOOST_CHECK_MESSAGE(!MixAnnouncementMatchesRendezvous(other, rendezvous, &strError),
                        "a seat took a second announcement for one slot");

    // Another coordinator's round, however valid, is not this slot's.
    CKey keyOther;
    const CMixRoundAnnouncement elsewhere = ProvenAnnouncement(keyOther, FreshRoundKey(4403), T0);
    BOOST_CHECK(!MixAnnouncementMatchesRendezvous(elsewhere, rendezvous, &strError));

    // The slot is taken from the announcement's start time. The commitment matches the
    // rendezvous slot, so only the slot check can refuse this.
    CMixRendezvous elsewhen = rendezvous;
    elsewhen.nSlot = rendezvous.nSlot + 1;
    elsewhen.hashCommitment = MixRendezvousCommitment(announce.pubkeyCoordinator,
                                                      elsewhen.nSlot, announce.hashRound);
    BOOST_CHECK_MESSAGE(!MixAnnouncementMatchesRendezvous(announce, elsewhen, &strError),
                        "a record published for one slot authorised a round in another");
    BOOST_CHECK(strError.find("slot") != std::string::npos);

    // And the seat itself refuses, before it proves an input or reveals a key image.
    CMixSeat seat;
    const Seat id = MakeSeat(13);
    BOOST_CHECK_MESSAGE(!seat.Begin(announce, id.key, SeatMaterial(0, 2, 0xC1), TestPolicy(),
                                    CMixRendezvous(), &strError),
                        "a seat joined a round no slot published");
    BOOST_CHECK(seat.KeyImage() == 0);
}

// The record the chain carries, and the rule that picks one of them.
BOOST_AUTO_TEST_CASE(one_record_per_identity_and_slot_is_the_one_that_counts)
{
    CKey keyCoordinator;
    keyCoordinator.MakeNewKey(true);
    const CPubKey pubkey = keyCoordinator.GetPubKey();
    CKey keyOther;
    keyOther.MakeNewKey(true);
    const int64_t nSlot = 45001;
    const uint256 idSlot = MixRendezvousIdentitySlot(pubkey, nSlot);
    BOOST_REQUIRE(idSlot != 0);
    BOOST_CHECK(MixRendezvousIdentitySlot(pubkey, nSlot + 1) != idSlot);
    BOOST_CHECK(MixRendezvousIdentitySlot(keyOther.GetPubKey(), nSlot) != idSlot);

    uint256 hashFirst, hashSecond;
    hashFirst.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    hashSecond.SetHex("2222222222222222222222222222222222222222222222222222222222222222");

    // Compressed only: one key with two encodings would be two identity-and-slot keys, and
    // the first-wins rule would never see a coordinator's two publications together.
    CKey keyWide;
    keyWide.MakeNewKey(false);
    BOOST_REQUIRE(!keyWide.GetPubKey().IsCompressed());
    BOOST_CHECK(MixRendezvousIdentitySlot(keyWide.GetPubKey(), nSlot) == 0);
    BOOST_CHECK(MixRendezvousCommitment(keyWide.GetPubKey(), nSlot, hashFirst) == 0);

    CMixRendezvousRecord recFirst, recSecond;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(SignMixRendezvous(keyCoordinator, nSlot, hashFirst, recFirst,
                                            &strError), strError);
    BOOST_REQUIRE(SignMixRendezvous(keyCoordinator, nSlot, hashSecond, recSecond, &strError));
    BOOST_CHECK(recFirst.idSlot == idSlot);
    BOOST_CHECK(recFirst.hashCommitment == MixRendezvousCommitment(pubkey, nSlot, hashFirst));
    BOOST_CHECK(CheckMixRendezvousRecord(recFirst, pubkey, nSlot));
    BOOST_CHECK(!CheckMixRendezvousRecord(recFirst, pubkey, nSlot + 1));
    BOOST_CHECK(!CheckMixRendezvousRecord(recFirst, keyOther.GetPubKey(), nSlot));

    const CScript script = BuildMixRendezvousScript(recFirst);
    BOOST_CHECK_EQUAL(script.size(), 3u + MIX_RENDEZVOUS_PAYLOAD_SIZE);
    CMixRendezvousRecord read;
    BOOST_REQUIRE(DecodeMixRendezvousScript(script, read));
    BOOST_CHECK(read.idSlot == recFirst.idSlot);
    BOOST_CHECK(read.hashCommitment == recFirst.hashCommitment);
    BOOST_CHECK(read.vchSig == recFirst.vchSig);

    // The signature is what makes the record the coordinator's. Without it anyone who knew
    // the key and the slot could publish a commitment to nothing first and, under first-wins,
    // end that coordinator's slot for good.
    CMixRendezvousRecord squatter;
    squatter.idSlot = idSlot;
    squatter.hashCommitment = hashSecond;
    CKey keyAttacker;
    keyAttacker.MakeNewKey(true);
    BOOST_REQUIRE(keyAttacker.SignCompact(MixRendezvousAuthHash(squatter.idSlot,
                                                                squatter.hashCommitment),
                                          squatter.vchSig));
    BOOST_CHECK_MESSAGE(!CheckMixRendezvousRecord(squatter, pubkey, nSlot),
                        "anyone could publish a record for this coordinator's slot");

    // Every byte of a record is under the signature or is the signature. Altering any of
    // them leaves a record that is not this coordinator's, so there is no variant of an
    // authorised record that authorises anything else.
    for (size_t i = 0; i < recFirst.vchSig.size(); i += 7)
    {
        CMixRendezvousRecord tweaked = recFirst;
        tweaked.vchSig[i] = (unsigned char)(tweaked.vchSig[i] ^ 0x01);
        BOOST_CHECK_MESSAGE(!CheckMixRendezvousRecord(tweaked, pubkey, nSlot),
                            "a record with an altered signature still passed as authorised");
    }
    CMixRendezvousRecord swapped = recFirst;
    swapped.hashCommitment = recSecond.hashCommitment;
    BOOST_CHECK_MESSAGE(!CheckMixRendezvousRecord(swapped, pubkey, nSlot),
                        "a commitment was moved under another record's signature");

    // Another feature's OP_RETURN is not a malformed record, it is not a record.
    CScript untagged;
    std::vector<unsigned char> vchOther(MIX_RENDEZVOUS_PAYLOAD_SIZE, 0x7a);
    untagged << OP_RETURN << vchOther;
    BOOST_CHECK(!DecodeMixRendezvousScript(untagged, read));

    // One length, one encoding, nothing after it: a payload this size has exactly one minimal
    // push, and a second encoding of one record would let a coordinator publish a commitment
    // a stricter reader sees and a looser one does not.
    CScript wide;
    wide.push_back(OP_RETURN);
    wide.push_back(OP_PUSHDATA2);
    wide.push_back((unsigned char)MIX_RENDEZVOUS_PAYLOAD_SIZE);
    wide.push_back(0x00);
    wide.insert(wide.end(), script.begin() + 3, script.end());
    BOOST_CHECK_MESSAGE(!DecodeMixRendezvousScript(wide, read),
                        "a non-minimal push decoded as a rendezvous record");
    CScript trailing = script;
    trailing << OP_TRUE;
    BOOST_CHECK_MESSAGE(!DecodeMixRendezvousScript(trailing, read),
                        "a record with script after it decoded");
    CScript truncated(script.begin(), script.end() - 1);
    truncated[2] = (unsigned char)(MIX_RENDEZVOUS_PAYLOAD_SIZE - 1);
    BOOST_CHECK_MESSAGE(!DecodeMixRendezvousScript(truncated, read),
                        "a record one byte short decoded");

    // First AUTHORISED record in chain order wins. A squatter takes no part, a coordinator
    // that published twice has not offered a choice, and a later record does not cancel a
    // round participants have already prepared for.
    std::vector<CMixRendezvousRecord> vRecords;
    vRecords.push_back(squatter);
    vRecords.push_back(recFirst);
    vRecords.push_back(recSecond);
    CMixRendezvous rendezvous;
    BOOST_REQUIRE(SelectMixRendezvous(vRecords, pubkey, nSlot, rendezvous));
    BOOST_CHECK(rendezvous.hashCommitment == recFirst.hashCommitment);
    BOOST_CHECK_EQUAL(rendezvous.nSlot, nSlot);
    BOOST_CHECK(!SelectMixRendezvous(vRecords, pubkey, nSlot + 1, rendezvous));
    BOOST_CHECK(rendezvous.IsNull());
    // A slot holding nothing but a squatter's record is a slot with no round, not a slot
    // whose round is the squatter's.
    std::vector<CMixRendezvousRecord> vSquatOnly(1, squatter);
    BOOST_CHECK(!SelectMixRendezvous(vSquatOnly, pubkey, nSlot, rendezvous));

    // The window is in median time past, which only moves forward: a block carrying an early
    // timestamp cannot be published late into a settled window.
    const int64_t nSlotOpens = nSlot * MIX_RENDEZVOUS_SLOT_SECONDS;
    BOOST_CHECK(MixRendezvousInWindow(nSlotOpens - 1, nSlot));
    BOOST_CHECK(!MixRendezvousInWindow(nSlotOpens, nSlot));
    BOOST_CHECK(!MixRendezvousInWindow(nSlotOpens + 60, nSlot));
    // And a record older than the earliest publishable point is not for this slot at all,
    // so a bounded scan cannot miss one that came first.
    BOOST_CHECK(MixRendezvousInWindow(nSlotOpens - (int64_t)MIX_RENDEZVOUS_PUBLISH_SLOTS *
                                                   MIX_RENDEZVOUS_SLOT_SECONDS, nSlot));
    BOOST_CHECK(!MixRendezvousInWindow(nSlotOpens - (int64_t)MIX_RENDEZVOUS_PUBLISH_SLOTS *
                                                    MIX_RENDEZVOUS_SLOT_SECONDS - 1, nSlot));
}

// A round must start far enough into its slot that a seat can have settled it first. Median
// time past and finality both lag, so a round starting at the opening is one honest seats
// reach late -- the short-join-window outcome by another route.
BOOST_AUTO_TEST_CASE(a_round_starts_far_enough_into_its_slot_to_be_settled_first)
{
    CKey key;
    const CNullSendSession roundKey = FreshRoundKey(4501);
    const int64_t T0 = 28000200;                       // 200s into its slot
    BOOST_REQUIRE(T0 % MIX_RENDEZVOUS_SLOT_SECONDS < MIX_RENDEZVOUS_MIN_START_SLACK);
    const CMixRoundAnnouncement early = ProvenAnnouncement(key, roundKey, T0);
    std::string strError;
    BOOST_CHECK_MESSAGE(!early.IsValidBasic(&strError),
                        "a round starting before its slot could be settled was accepted");
    BOOST_CHECK(strError.find("slot") != std::string::npos);

    CKey keyLater;
    const CMixRoundAnnouncement onTime =
        ProvenAnnouncement(keyLater, FreshRoundKey(4502),
                           T0 - T0 % MIX_RENDEZVOUS_SLOT_SECONDS +
                           MIX_RENDEZVOUS_MIN_START_SLACK);
    BOOST_CHECK_MESSAGE(onTime.IsValidBasic(&strError), strError);

    // What a whole announcement costs, which decides whether putting one on chain instead of
    // a commitment is a simplification or a cost.
    BOOST_TEST_MESSAGE("announcement serialized bytes: "
                       << ::GetSerializeSize(onTime, SER_NETWORK, PROTOCOL_VERSION));
}

// What a block yields, in output order, with everything else in it invisible.
BOOST_AUTO_TEST_CASE(a_block_yields_its_rendezvous_records_in_output_order)
{
    CKey keyCoordinator;
    keyCoordinator.MakeNewKey(true);
    const int64_t nSlot = 45002;
    uint256 hashA, hashB;
    hashA.SetHex("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a");
    hashB.SetHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    CMixRendezvousRecord recA, recB;
    std::string strError;
    BOOST_REQUIRE(SignMixRendezvous(keyCoordinator, nSlot, hashA, recA, &strError));
    BOOST_REQUIRE(SignMixRendezvous(keyCoordinator, nSlot, hashB, recB, &strError));

    CBlock block;
    CTransaction txFirst;
    txFirst.vout.resize(3);
    txFirst.vout[0].scriptPubKey = CScript() << OP_TRUE;          // an ordinary payment
    txFirst.vout[1].scriptPubKey = BuildMixRendezvousScript(recA);
    std::vector<unsigned char> vchElse(8, 0x11);
    txFirst.vout[2].scriptPubKey = CScript() << OP_RETURN << vchElse;  // another feature's
    CTransaction txSecond;
    txSecond.vout.resize(1);
    txSecond.vout[0].scriptPubKey = BuildMixRendezvousScript(recB);
    block.vtx.push_back(txFirst);
    block.vtx.push_back(txSecond);

    std::vector<CMixRendezvousRecord> vRecords;
    CollectMixRendezvousRecords(block, vRecords);
    BOOST_REQUIRE_EQUAL(vRecords.size(), 2u);
    BOOST_CHECK(vRecords[0].hashCommitment == recA.hashCommitment);
    BOOST_CHECK(vRecords[1].hashCommitment == recB.hashCommitment);

    // And within one block the earlier output is the one that counts.
    CMixRendezvous rendezvous;
    BOOST_REQUIRE(SelectMixRendezvous(vRecords, keyCoordinator.GetPubKey(), nSlot, rendezvous));
    BOOST_CHECK(rendezvous.hashCommitment == recA.hashCommitment);
}

// Which blocks a slot may be read from. The rule is the whole agreement: two seats that
// disagree about the window disagree about which record came first.
BOOST_AUTO_TEST_CASE(a_slot_is_read_only_once_the_finalized_chain_has_passed_it)
{
    // A chain of one-minute blocks, so median time past moves in steps a test can name.
    const int64_t nSlot = 45010;
    const int64_t nOpens = nSlot * MIX_RENDEZVOUS_SLOT_SECONDS;
    const int nBlocks = 260;
    const int64_t nStep = 60;
    std::vector<CBlockIndex> vChain((size_t)nBlocks);
    for (int i = 0; i < nBlocks; i++)
    {
        vChain[i].nHeight = i;
        // The chain has to run well past the slot's opening, or nothing is settled yet.
        vChain[i].nTime = (unsigned int)(nOpens - (int64_t)(nBlocks - 1 - i) * nStep +
                                         30 * nStep);
        vChain[i].pprev = (i == 0) ? NULL : &vChain[i - 1];
    }
    const CBlockIndex* pindexTip = &vChain[nBlocks - 1];
    std::string strError;
    std::vector<const CBlockIndex*> vScan;

    // Finalized short of the slot's opening: a block that still belongs in the window can be
    // finalized later, so there is no answer yet -- and a refusal is the answer.
    int nBehind = -1;
    for (int i = 0; i < nBlocks; i++)
        if (vChain[i].GetMedianTimePast() < nOpens)
            nBehind = i;
    BOOST_REQUIRE(nBehind > 0);
    BOOST_CHECK_MESSAGE(!SelectMixRendezvousBlocks(pindexTip, nBehind, nSlot, vScan, &strError),
                        "a slot was read before the finalized chain passed its opening");
    BOOST_CHECK(strError.find("settled") != std::string::npos);

    // Finalized past it: the window is fixed, and holds exactly the blocks inside it.
    BOOST_REQUIRE_MESSAGE(SelectMixRendezvousBlocks(pindexTip, nBehind + 1, nSlot, vScan,
                                                    &strError), strError);
    BOOST_REQUIRE(!vScan.empty());
    for (size_t i = 0; i < vScan.size(); i++)
        BOOST_CHECK(MixRendezvousInWindow(vScan[i]->GetMedianTimePast(), nSlot));
    size_t nExpected = 0;
    for (int i = 0; i <= nBehind + 1; i++)
        if (MixRendezvousInWindow(vChain[i].GetMedianTimePast(), nSlot))
            nExpected++;
    BOOST_CHECK_EQUAL(vScan.size(), nExpected);
    // Newest first, so the read can reverse it into the order first-wins is defined over.
    for (size_t i = 1; i < vScan.size(); i++)
        BOOST_CHECK(vScan[i]->nHeight < vScan[i - 1]->nHeight);

    // A chain that does not reach back to the window's start is still a complete view of it.
    std::vector<CBlockIndex> vShort(vChain.begin() + nBehind - 20, vChain.begin() + nBehind + 2);
    for (size_t i = 0; i < vShort.size(); i++)
        vShort[i].pprev = (i == 0) ? NULL : &vShort[i - 1];
    BOOST_CHECK_MESSAGE(SelectMixRendezvousBlocks(&vShort[vShort.size() - 1],
                                                  vShort[vShort.size() - 1].nHeight, nSlot,
                                                  vScan, &strError),
                        strError);

    // And a finalized height this chain does not reach is not a view at all.
    BOOST_CHECK(!SelectMixRendezvousBlocks(pindexTip, nBlocks + 5, nSlot, vScan, &strError));

    // More blocks inside one window than a seat will scan. Shortening the window silently
    // would let whoever filled it decide which publication a seat sees first, so the answer
    // is that there is no answer.
    const int nPacked = MIX_RENDEZVOUS_MAX_BLOCKS + 32;
    const int nAfter = 16;
    std::vector<CBlockIndex> vDense((size_t)(nPacked + nAfter));
    for (int i = 0; i < nPacked + nAfter; i++)
    {
        vDense[i].nHeight = i;
        vDense[i].nTime = (unsigned int)(i < nPacked ? nOpens - 10 : nOpens + 10);
        vDense[i].pprev = (i == 0) ? NULL : &vDense[i - 1];
    }
    const CBlockIndex* pindexDense = &vDense[nPacked + nAfter - 1];
    BOOST_REQUIRE(pindexDense->GetMedianTimePast() >= nOpens);
    BOOST_CHECK_MESSAGE(!SelectMixRendezvousBlocks(pindexDense, pindexDense->nHeight, nSlot,
                                                   vScan, &strError),
                        "a window longer than the scan cap was answered anyway");
    BOOST_CHECK(strError.find("incomplete") != std::string::npos);
    BOOST_CHECK(vScan.empty());
}

// A record nothing will relay is not a carrier. The ordinary data-push bound here is 48
// bytes, well under a record, so the record is admitted by its exact shape instead -- and
// nothing else gains room.
BOOST_AUTO_TEST_CASE(a_rendezvous_record_relays_and_nothing_else_grows)
{
    LOCK(cs_main);
    CKey keyCoordinator;
    keyCoordinator.MakeNewKey(true);
    uint256 hashRound;
    hashRound.SetHex("3333333333333333333333333333333333333333333333333333333333333333");
    CMixRendezvousRecord record;
    std::string strError;
    BOOST_REQUIRE(SignMixRendezvous(keyCoordinator, 45003, hashRound, record, &strError));
    const CScript scriptRecord = BuildMixRendezvousScript(record);
    BOOST_REQUIRE(scriptRecord.size() > 2 + MAX_OP_RETURN_RELAY);
    BOOST_CHECK_MESSAGE(scriptRecord.HasCanonicalPushes(),
                        "the record's own push is not the minimal encoding");

    CScript scriptP2PKH;
    scriptP2PKH << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 1)
                << OP_EQUALVERIFY << OP_CHECKSIG;

    CTransaction txPublish;
    txPublish.nTime = GetAdjustedTime();
    txPublish.vin.push_back(CTxIn());
    txPublish.vout.push_back(CTxOut(CENT, scriptP2PKH));
    txPublish.vout.push_back(CTxOut(0, scriptRecord));
    std::string reason;
    BOOST_CHECK_MESSAGE(IsStandardTx(txPublish, reason),
                        "a coordinator cannot publish a rendezvous record: " << reason);

    // A data push of the same size that is not a record stays non-standard: the exemption is
    // the shape, not the length.
    std::vector<unsigned char> vchSameSize(MIX_RENDEZVOUS_PAYLOAD_SIZE, 0x5a);
    CScript scriptBig;
    scriptBig << OP_RETURN << vchSameSize;
    CTransaction txBig;
    txBig.nTime = GetAdjustedTime();
    txBig.vin.push_back(CTxIn());
    txBig.vout.push_back(CTxOut(CENT, scriptP2PKH));
    txBig.vout.push_back(CTxOut(0, scriptBig));
    reason.clear();
    BOOST_CHECK_MESSAGE(!IsStandardTx(txBig, reason),
                        "an ordinary data push of a record's size became standard");

    // The exemption covers the record's own output and nothing else about the transaction:
    // a record does not launder a change output that policy would refuse on its own.
    CScript scriptOdd;
    scriptOdd << OP_RETURN << OP_RETURN << OP_RETURN;
    CTransaction txOddChange;
    txOddChange.nTime = GetAdjustedTime();
    txOddChange.vin.push_back(CTxIn());
    txOddChange.vout.push_back(CTxOut(CENT, scriptOdd));
    txOddChange.vout.push_back(CTxOut(0, scriptRecord));
    reason.clear();
    BOOST_CHECK_MESSAGE(!IsStandardTx(txOddChange, reason),
                        "a rendezvous record made a nonstandard output standard");

    // And one byte off the record is not the record.
    CScript scriptOff = scriptRecord;
    scriptOff[3] = (unsigned char)(scriptOff[3] ^ 0xff);   // break the tag
    CTransaction txOff;
    txOff.nTime = GetAdjustedTime();
    txOff.vin.push_back(CTxIn());
    txOff.vout.push_back(CTxOut(CENT, scriptP2PKH));
    txOff.vout.push_back(CTxOut(0, scriptOff));
    reason.clear();
    BOOST_CHECK(!IsStandardTx(txOff, reason));
}

BOOST_AUTO_TEST_SUITE_END()
