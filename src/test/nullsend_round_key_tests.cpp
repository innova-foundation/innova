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

CMixRoundAnnouncement Announce(CKey& keyOut, const std::vector<unsigned char>& vchN)
{
    keyOut.MakeNewKey(true);
    CMixRoundAnnouncement announce;
    announce.hashRound = uint256(77);
    announce.hashRoundKey = MixRoundKeyCommitment(vchN, Exponent());
    announce.strEndpoint = "wq3wlxjlpvxhuxpe5x6dtnrhrxvgkfxkvxmmwpnrfexbbxbxbxbxbxbd.onion";
    announce.nPort = 8443;
    announce.nParticipants = 4;
    announce.nTime = GetTime();
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
    BOOST_CHECK(!good.IsExpired(good.nTime + MIX_ROUND_ANNOUNCE_TIMEOUT));
    BOOST_CHECK(good.IsExpired(good.nTime + MIX_ROUND_ANNOUNCE_TIMEOUT + 1));
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

BOOST_AUTO_TEST_SUITE_END()
