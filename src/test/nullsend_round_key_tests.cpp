// The round key must be committed before use: a coordinator handing each participant a
// different blinding key could link outputs by which key verifies. The gossiped
// announcement names one key, so participants refuse any other.

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

#include "../key.h"
#include "../nullsend.h"
#include "../nullsend_v2008.h"
#include "../privacy_vnext/iv5_protocol.h"

extern bool fRegTest;

namespace {

std::vector<unsigned char> Modulus(unsigned char chSeed)
{
    std::vector<unsigned char> vch(NULLSEND_RSA_BITS / 8, chSeed);
    vch[0] = 0xC0 | (chSeed & 0x0F);  // a modulus has its top bits set
    return vch;
}

const std::vector<unsigned char>& Exponent()
{
    static std::vector<unsigned char> vch;
    if (vch.empty())
    {
        vch.push_back(0x01);
        vch.push_back(0x00);
        vch.push_back(0x01);          // 65537
    }
    return vch;
}

// The transcript every seat has to agree on, and the schedule it derives its deadlines
// from. A round announcing neither is refused, so every fixture carries one.
void FillTranscript(CMixRoundAnnouncement& announce)
{
    announce.nNetwork = 1;
    announce.genesis.fill(0x11);
    announce.parameterDigest.fill(0x22);
    announce.finalizedRoot.fill(0x33);
    announce.nFinalizedTreeSize = 4096;
    announce.nDenomination = 1000;
    announce.nFee = 4 * 25;
    announce.nJoinSecs = 120;
    announce.nViewSecs = 60;
    announce.nTokenSecs = 60;
    announce.nOutputSecs = 120;
    announce.nApproveSecs = 120;
    announce.nNonceSecs = 60;
    announce.nResponseSecs = 60;
    announce.nTerminalSecs = 300;
}

CMixRoundAnnouncement Announce(CKey& keyOut, const std::vector<unsigned char>& vchN)
{
    keyOut.MakeNewKey(true);
    CMixRoundAnnouncement announce;
    // hashRound is not set here: Sign derives it from the contents.
    announce.hashRoundKey = MixRoundKeyCommitment(vchN, Exponent());
    announce.strEndpoint = "wq3wlxjlpvxhuxpe5x6dtnrhrxvgkfxkvxmmwpnrfexbbxbxbxbxbxbd.onion";
    announce.nPort = 8443;
    announce.nParticipants = 4;
    announce.nTime = GetTime();
    FillTranscript(announce);
    BOOST_REQUIRE(announce.Sign(keyOut));
    return announce;
}

} // namespace

BOOST_AUTO_TEST_SUITE(nullsend_round_key_tests)

// The whole point: a key that is not the announced one is refused before the
// participant blinds anything under it.
BOOST_AUTO_TEST_CASE(a_key_that_is_not_the_announced_one_is_refused)
{
    const std::vector<unsigned char> vchAnnounced = Modulus(0x11);
    CKey key;
    const CMixRoundAnnouncement announce = Announce(key, vchAnnounced);

    BOOST_CHECK(announce.KeyOpensCommitment(vchAnnounced, Exponent()));

    // A per-participant key: same shape, different modulus. This is the whole
    // attack, and it does not get past the commitment.
    BOOST_CHECK_MESSAGE(!announce.KeyOpensCommitment(Modulus(0x12), Exponent()),
                        "a second modulus opened the commitment, so the coordinator "
                        "can still hand every participant its own key");

    // The exponent is committed too. A coordinator that varies only e still
    // separates participants, because which key verifies is what it reads.
    std::vector<unsigned char> vchOtherE;
    vchOtherE.push_back(0x03);
    BOOST_CHECK(!announce.KeyOpensCommitment(vchAnnounced, vchOtherE));

    // Nothing opens a commitment that was never made.
    CMixRoundAnnouncement blank;
    BOOST_CHECK(!blank.KeyOpensCommitment(vchAnnounced, Exponent()));
    BOOST_CHECK(!announce.KeyOpensCommitment(std::vector<unsigned char>(), Exponent()));
    BOOST_CHECK(!announce.KeyOpensCommitment(vchAnnounced, std::vector<unsigned char>()));
}

// Both halves are length-prefixed, so no two different keys can be re-cut into one
// byte string and open the same commitment.
BOOST_AUTO_TEST_CASE(the_commitment_does_not_confuse_a_split)
{
    std::vector<unsigned char> vchA, vchB, vchC, vchD;
    vchA.push_back(0x01); vchA.push_back(0x02);
    vchB.push_back(0x03);
    vchC.push_back(0x01);
    vchD.push_back(0x02); vchD.push_back(0x03);
    BOOST_CHECK(MixRoundKeyCommitment(vchA, vchB) != MixRoundKeyCommitment(vchC, vchD));
}

// The commitment is inside the signed hash. If it were not, a coordinator could
// gossip one announcement and edit the commitment per participant in flight, which
// is the same attack wearing the signature as cover.
BOOST_AUTO_TEST_CASE(the_signature_covers_the_commitment)
{
    CKey key;
    CMixRoundAnnouncement announce = Announce(key, Modulus(0x21));
    std::string strError;
    BOOST_REQUIRE_MESSAGE(announce.IsValidBasic(&strError), strError);

    CMixRoundAnnouncement edited = announce;
    edited.hashRoundKey = MixRoundKeyCommitment(Modulus(0x22), Exponent());
    BOOST_CHECK_MESSAGE(!edited.CheckSignature(),
                        "the commitment moved and the signature still verified");
    BOOST_CHECK(!edited.IsValidBasic(&strError));

    // Every other field is covered too, so a round cannot be re-pointed either.
    CMixRoundAnnouncement moved = announce;
    moved.strEndpoint = "other.onion";
    BOOST_CHECK(!moved.CheckSignature());
    CMixRoundAnnouncement renumbered = announce;
    renumbered.hashRound = uint256(78);
    BOOST_CHECK(!renumbered.CheckSignature());
    CMixRoundAnnouncement resized = announce;
    resized.nParticipants = 3;
    BOOST_CHECK(!resized.CheckSignature());

    // The transcript fields too: an edited copy would build a prefix the co-seats refuse.
    CMixRoundAnnouncement reanchored = announce;
    reanchored.finalizedRoot.fill(0x44);
    BOOST_CHECK_MESSAGE(!reanchored.CheckSignature(),
                        "the anchor moved and the signature still verified");
    BOOST_CHECK(reanchored.DerivedRoundId() != announce.hashRound);
    CMixRoundAnnouncement redenominated = announce;
    redenominated.nDenomination = announce.nDenomination + 1;
    BOOST_CHECK(!redenominated.CheckSignature());
    BOOST_CHECK(redenominated.DerivedRoundId() != announce.hashRound);
    CMixRoundAnnouncement refeed = announce;
    refeed.nFee = announce.nFee + announce.nParticipants;
    BOOST_CHECK(!refeed.CheckSignature());
    CMixRoundAnnouncement rescheduled = announce;
    rescheduled.nApproveSecs = announce.nApproveSecs + 1;
    BOOST_CHECK_MESSAGE(!rescheduled.CheckSignature(),
                        "a window moved and the signature still verified");
    BOOST_CHECK(rescheduled.DerivedRoundId() != announce.hashRound);

    // What a round may not announce.
    CMixRoundAnnouncement uneven = announce;
    uneven.nFee = announce.nFee + 1;
    BOOST_REQUIRE(uneven.Sign(key));
    BOOST_CHECK_MESSAGE(!uneven.IsValidBasic(&strError),
                        "a fee that does not divide into equal shares was accepted");
    CMixRoundAnnouncement hurried = announce;
    hurried.nApproveSecs = MIX_PROOF_WINDOW_MIN_SECS - 1;
    BOOST_REQUIRE(hurried.Sign(key));
    BOOST_CHECK_MESSAGE(!hurried.IsValidBasic(&strError),
                        "an approval window shorter than a proof takes was accepted");
    CMixRoundAnnouncement endless = announce;
    endless.nJoinSecs = MIX_WINDOW_MAX_SECS + 1;
    BOOST_REQUIRE(endless.Sign(key));
    BOOST_CHECK(!endless.IsValidBasic(&strError));
    CMixRoundAnnouncement unanchored = announce;
    unanchored.finalizedRoot.fill(0);
    BOOST_REQUIRE(unanchored.Sign(key));
    BOOST_CHECK(!unanchored.IsValidBasic(&strError));
    CMixRoundAnnouncement free = announce;
    free.nDenomination = 0;
    BOOST_REQUIRE(free.Sign(key));
    BOOST_CHECK(!free.IsValidBasic(&strError));
}

// A round the participant cannot judge is not one it joins.
BOOST_AUTO_TEST_CASE(an_announcement_without_a_commitment_is_refused)
{
    CKey key;
    key.MakeNewKey(true);
    CMixRoundAnnouncement announce;
    announce.hashRound = uint256(79);
    announce.hashRoundKey = 0;
    announce.strEndpoint = "coordinator.onion";
    announce.nPort = 8443;
    announce.nParticipants = 4;
    announce.nTime = GetTime();
    FillTranscript(announce);
    BOOST_REQUIRE(announce.Sign(key));

    std::string strError;
    BOOST_CHECK_MESSAGE(!announce.IsValidBasic(&strError),
                        "a signed announcement with no key commitment was accepted, "
                        "so any key the coordinator sends would be taken");
    BOOST_CHECK(strError.find("commitment") != std::string::npos);
}

// Shape bounds, including the one that matters for the payload: a v2008 mix carries
// at most MAX_NULLSEND_INPUTS inputs, so a round cannot announce more seats than the
// transaction can hold.
BOOST_AUTO_TEST_CASE(the_announcement_shape_is_bounded)
{
    CKey key;
    const CMixRoundAnnouncement good = Announce(key, Modulus(0x31));
    std::string strError;
    BOOST_REQUIRE(good.IsValidBasic(&strError));

    struct { const char* pszName; int nParticipants; bool fValid; } vCases[] = {
        { "below the minimum",   NULLSEND_MIN_PARTICIPANTS - 1,            false },
        { "at the minimum",      NULLSEND_MIN_PARTICIPANTS,                true  },
        { "at the payload cap",  (int)iv5::MAX_NULLSEND_INPUTS,            true  },
        { "past the payload cap",(int)iv5::MAX_NULLSEND_INPUTS + 1,        false },
    };
    for (size_t i = 0; i < sizeof(vCases) / sizeof(vCases[0]); i++)
    {
        CMixRoundAnnouncement a = good;
        a.nParticipants = vCases[i].nParticipants;
        // One share per seat, exactly: the fee follows the seat count or the announcement
        // is refused for a reason this case is not about.
        a.nFee = (uint64_t)(a.nParticipants > 0 ? a.nParticipants : 1) * 25;
        BOOST_REQUIRE(a.Sign(key));
        BOOST_CHECK_MESSAGE(a.IsValidBasic(&strError) == vCases[i].fValid,
                            vCases[i].pszName << ": " << a.nParticipants
                            << " seats judged " << (vCases[i].fValid ? "invalid" : "valid"));
    }

    CMixRoundAnnouncement noEndpoint = good;
    noEndpoint.strEndpoint.clear();
    BOOST_REQUIRE(noEndpoint.Sign(key));
    BOOST_CHECK(!noEndpoint.IsValidBasic(&strError));

    CMixRoundAnnouncement longEndpoint = good;
    longEndpoint.strEndpoint = std::string(MIX_ROUND_ENDPOINT_MAX + 1, 'a');
    BOOST_REQUIRE(longEndpoint.Sign(key));
    BOOST_CHECK(!longEndpoint.IsValidBasic(&strError));

    CMixRoundAnnouncement badPort = good;
    badPort.nPort = 0;
    BOOST_REQUIRE(badPort.Sign(key));
    BOOST_CHECK(!badPort.IsValidBasic(&strError));

    // An announcement stops being joinable rather than staying open forever.
    BOOST_CHECK(!good.IsExpired(good.Ends()));
    BOOST_CHECK(good.IsExpired(good.Ends() + 1));
    // Joinable only inside its own join window, which every seat computes for itself.
    BOOST_CHECK(good.IsJoinable(good.nTime));
    BOOST_CHECK(!good.IsJoinable(good.nTime - 1));
    BOOST_CHECK(!good.IsJoinable(good.JoinCloses()));
}

// Round trip, so a participant judges the bytes it received rather than a local
// object that never crossed the wire.
BOOST_AUTO_TEST_CASE(an_announcement_survives_the_wire)
{
    CKey key;
    const std::vector<unsigned char> vchN = Modulus(0x41);
    const CMixRoundAnnouncement sent = Announce(key, vchN);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << sent;
    CMixRoundAnnouncement received;
    ss >> received;

    std::string strError;
    BOOST_REQUIRE_MESSAGE(received.IsValidBasic(&strError), strError);
    BOOST_CHECK(received.hashRoundKey == sent.hashRoundKey);
    BOOST_CHECK(received.KeyOpensCommitment(vchN, Exponent()));
    BOOST_CHECK(!received.KeyOpensCommitment(Modulus(0x42), Exponent()));
}

// The round identifier is derived from the announcement, so one coordinator cannot
// issue per-participant announcements with different key commitments.
BOOST_AUTO_TEST_CASE(one_round_identifier_names_one_key_commitment)
{
    CKey key;
    const CMixRoundAnnouncement first = Announce(key, Modulus(0x51));
    std::string strError;
    BOOST_REQUIRE_MESSAGE(first.IsValidBasic(&strError), strError);
    BOOST_CHECK(first.hashRound == first.DerivedRoundId());

    // The equivocation, built as carefully as a coordinator could: same round, same
    // everything, another key commitment, freshly and validly signed.
    CMixRoundAnnouncement second = first;
    second.hashRoundKey = MixRoundKeyCommitment(Modulus(0x52), Exponent());
    second.hashRound = first.hashRound;
    BOOST_REQUIRE(key.Sign(second.GetSignatureHash(), second.vchSig));
    BOOST_CHECK_MESSAGE(second.CheckSignature(),
                        "the setup is wrong if the equivocating announcement does not "
                        "even carry a valid signature");
    BOOST_CHECK_MESSAGE(!second.IsValidBasic(&strError),
                        "two announcements named one round with two different key "
                        "commitments, so the coordinator can key each participant apart");
    BOOST_CHECK(strError.find("identifier") != std::string::npos);

    // Signing it properly is allowed and is the point: it is then a DIFFERENT round,
    // whose seats and tokens do not interoperate with the first.
    BOOST_REQUIRE(second.Sign(key));
    BOOST_REQUIRE(second.IsValidBasic(&strError));
    BOOST_CHECK(second.hashRound != first.hashRound);

    // Every field the identifier covers moves it.
    const char* pszWhat[] = { "endpoint", "port", "seats", "time" };
    for (int i = 0; i < 4; i++)
    {
        CMixRoundAnnouncement edited = first;
        if (i == 0)
            edited.strEndpoint = "2bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion";
        else if (i == 1)
            edited.nPort = first.nPort + 1;
        else if (i == 2)
            edited.nParticipants = first.nParticipants + 1;
        else
            edited.nTime = first.nTime + 1;
        BOOST_CHECK_MESSAGE(edited.DerivedRoundId() != first.hashRound,
                            pszWhat[i] << " moved and the round identifier did not");
    }
}

// The OUTPUT frame is a bearer token on a stream with no MAC of its own. A clearnet
// endpoint reached through Tor puts the exit on that path, so an announcement that
// names one is not a round a participant should join.
BOOST_AUTO_TEST_CASE(an_announcement_must_name_an_onion)
{
    CKey key;
    const CMixRoundAnnouncement good = Announce(key, Modulus(0x53));
    std::string strError;
    BOOST_REQUIRE(good.IsValidBasic(&strError));
    BOOST_CHECK(IsMixOnionEndpoint(good.strEndpoint));

    const char* pszBad[] = {
        "coordinator.onion",                                                // too short
        "mix.example.com",                                                  // clearnet
        "203.0.113.9",                                                      // a literal
        "WQ3WLXJLPVXHUXPE5X6DTNRHRXVGKFXKVXMMWPNRFEXBBXBXBXBXBXBD.onion",   // not base32
        "wq3wlxjlpvxhuxpe5x6dtnrhrxvgkfxkvxmmwpnrfexbbxbxbxbxbxb1.onion",   // 1 is not base32
        "wq3wlxjlpvxhuxpe5x6dtnrhrxvgkfxkvxmmwpnrfexbbxbxbxbxbxbd.onions",  // suffix
    };
    for (size_t i = 0; i < sizeof(pszBad) / sizeof(pszBad[0]); i++)
    {
        BOOST_CHECK_MESSAGE(!IsMixOnionEndpoint(pszBad[i]),
                            pszBad[i] << " was taken for an onion");
        CMixRoundAnnouncement a = good;
        a.strEndpoint = pszBad[i];
        BOOST_REQUIRE(a.Sign(key));
        BOOST_CHECK_MESSAGE(!a.IsValidBasic(&strError),
                            pszBad[i] << " was announced as a round endpoint");
    }
}

BOOST_AUTO_TEST_SUITE_END()
