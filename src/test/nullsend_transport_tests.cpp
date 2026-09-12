// Transport for a v2008 mix round: a SOCKS stream per phase, each on its own Tor circuit
// keyed on the SOCKS username/password pair, never the node's P2P connection.

#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

#include <string>
#include <vector>

#include "../netbase.h"
#include "../nullsend_v2008.h"
#include "../util.h"

#ifndef WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

// The suite macro opens a namespace, so a declaration inside it would name a new
// symbol rather than the global the rest of the tree links against.
extern bool fRegTest;

namespace {

// A SOCKS5 proxy that answers from a script, so a dial can be judged on the bytes
// it sends rather than on whether some live proxy happened to be reachable.
class ScriptedProxy
{
public:
    // fAuthAnyway separates what the proxy ANSWERS from what it then DOES. A proxy
    // that names no-auth, or that rejects the pair, and forwards the stream anyway
    // is the adversary here: it carries the phase without isolating it. Only the
    // client's own refusal can stop that, so the stub must never close first --
    // otherwise the dial fails on a dead socket and the check under test is never
    // the reason.
    ScriptedProxy(unsigned char chMethodReply, unsigned char chAuthStatus,
                  bool fAuthAnywayIn = false)
        : hListen(-1), nPort(0), chMethod(chMethodReply), chAuth(chAuthStatus),
          fAuthAnyway(fAuthAnywayIn),
          fGreetingSeen(false), fAuthSeen(false), fConnectSeen(false) {}

    bool Start()
    {
        hListen = socket(AF_INET, SOCK_STREAM, 0);
        if (hListen < 0)
            return false;
        int nReuse = 1;
        setsockopt(hListen, SOL_SOCKET, SO_REUSEADDR, &nReuse, sizeof(nReuse));
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(hListen, (struct sockaddr*)&addr, sizeof(addr)) != 0)
            return false;
        if (::listen(hListen, 1) != 0)
            return false;
        socklen_t len = sizeof(addr);
        if (getsockname(hListen, (struct sockaddr*)&addr, &len) != 0)
            return false;
        nPort = ntohs(addr.sin_port);
        thread = boost::thread(boost::bind(&ScriptedProxy::Serve, this));
        return nPort != 0;
    }

    ~ScriptedProxy()
    {
        if (hListen >= 0)
            close(hListen);
        thread.join();
    }

    int Port() const { return nPort; }
    bool GreetingSeen() const { return fGreetingSeen; }
    bool AuthSeen() const { return fAuthSeen; }
    bool ConnectSeen() const { return fConnectSeen; }
    const std::vector<unsigned char>& Greeting() const { return vchGreeting; }
    const std::vector<unsigned char>& Auth() const { return vchAuth; }

private:
    bool ReadExactly(int hSocket, std::vector<unsigned char>& vchOut, size_t n)
    {
        vchOut.resize(n);
        size_t nHave = 0;
        while (nHave < n)
        {
            ssize_t got = recv(hSocket, (char*)&vchOut[nHave], n - nHave, 0);
            if (got <= 0)
                return false;
            nHave += (size_t)got;
        }
        return true;
    }

    void Serve()
    {
        const int hSocket = accept(hListen, NULL, NULL);
        if (hSocket < 0)
            return;
        do
        {
            // Greeting: version, count, then that many method bytes.
            std::vector<unsigned char> vchHead;
            if (!ReadExactly(hSocket, vchHead, 2) || vchHead[0] != 0x05)
                break;
            std::vector<unsigned char> vchMethods;
            if (!ReadExactly(hSocket, vchMethods, vchHead[1]))
                break;
            vchGreeting = vchHead;
            vchGreeting.insert(vchGreeting.end(), vchMethods.begin(), vchMethods.end());
            fGreetingSeen = true;

            unsigned char pchReply[2] = { 0x05, chMethod };
            if (send(hSocket, (const char*)pchReply, 2, 0) != 2)
                break;
            if (chMethod == 0x02 || fAuthAnyway)
            {
                // Sub-negotiation: its own version byte, then two length-prefixed
                // fields.
                std::vector<unsigned char> vchVer, vchUser, vchPass, vchLen;
                if (!ReadExactly(hSocket, vchVer, 2) || vchVer[0] != 0x01)
                    break;
                if (!ReadExactly(hSocket, vchUser, vchVer[1]))
                    break;
                if (!ReadExactly(hSocket, vchLen, 1))
                    break;
                if (!ReadExactly(hSocket, vchPass, vchLen[0]))
                    break;
                vchAuth = vchVer;
                vchAuth.insert(vchAuth.end(), vchUser.begin(), vchUser.end());
                vchAuth.insert(vchAuth.end(), vchLen.begin(), vchLen.end());
                vchAuth.insert(vchAuth.end(), vchPass.begin(), vchPass.end());
                fAuthSeen = true;
                unsigned char pchAuthReply[2] = { 0x01, chAuth };
                if (send(hSocket, (const char*)pchAuthReply, 2, 0) != 2)
                    break;
            }

            // CONNECT: version, command, reserved, address type, then the address.
            std::vector<unsigned char> vchReq;
            if (!ReadExactly(hSocket, vchReq, 4) || vchReq[0] != 0x05 || vchReq[3] != 0x03)
                break;
            std::vector<unsigned char> vchNameLen, vchName, vchPort;
            if (!ReadExactly(hSocket, vchNameLen, 1))
                break;
            if (!ReadExactly(hSocket, vchName, vchNameLen[0]))
                break;
            if (!ReadExactly(hSocket, vchPort, 2))
                break;
            fConnectSeen = true;

            const unsigned char pchOk[10] = { 0x05, 0x00, 0x00, 0x01,
                                              0x7f, 0x00, 0x00, 0x01, 0x00, 0x00 };
            send(hSocket, (const char*)pchOk, 10, 0);
        } while (false);
        close(hSocket);
    }

    int hListen;
    int nPort;
    unsigned char chMethod;
    unsigned char chAuth;
    bool fAuthAnyway;
    bool fGreetingSeen;
    bool fAuthSeen;
    bool fConnectSeen;
    std::vector<unsigned char> vchGreeting;
    std::vector<unsigned char> vchAuth;
    boost::thread thread;
};

std::string BytesToString(const std::vector<unsigned char>& vch, size_t nOffset, size_t nLen)
{
    return std::string(vch.begin() + nOffset, vch.begin() + nOffset + nLen);
}

} // namespace

BOOST_AUTO_TEST_SUITE(nullsend_transport_tests)

// The sub-negotiation carries its own version byte, 0x01, not SOCKS5's 0x05, and
// two length-prefixed fields. Getting the version wrong is the mistake that reads
// as an authentication failure against a real proxy.
BOOST_AUTO_TEST_CASE(the_auth_request_is_the_rfc_1929_shape)
{
    ProxyCredentials auth;
    auth.strUser = "circuit-a";
    auth.strPassword = "phase-one";

    std::vector<unsigned char> vch;
    BOOST_REQUIRE(BuildSocks5AuthRequest(auth, vch));
    BOOST_REQUIRE_EQUAL(vch.size(), 1 + 1 + auth.strUser.size() + 1 + auth.strPassword.size());
    BOOST_CHECK_EQUAL((int)vch[0], 1);
    BOOST_CHECK_EQUAL((size_t)vch[1], auth.strUser.size());
    BOOST_CHECK_EQUAL(BytesToString(vch, 2, auth.strUser.size()), auth.strUser);
    const size_t nPlen = 2 + auth.strUser.size();
    BOOST_CHECK_EQUAL((size_t)vch[nPlen], auth.strPassword.size());
    BOOST_CHECK_EQUAL(BytesToString(vch, nPlen + 1, auth.strPassword.size()), auth.strPassword);

    // Refused rather than truncated: a field that does not fit one length byte has
    // no encoding, and an empty one is not a credential.
    std::vector<unsigned char> vchRefused;
    ProxyCredentials bad;
    BOOST_CHECK(!BuildSocks5AuthRequest(bad, vchRefused));
    bad.strUser = "u";
    BOOST_CHECK(!BuildSocks5AuthRequest(bad, vchRefused));
    bad.strPassword = std::string(256, 'p');
    BOOST_CHECK(!BuildSocks5AuthRequest(bad, vchRefused));
    bad.strUser = std::string(256, 'u');
    bad.strPassword = "p";
    BOOST_CHECK(!BuildSocks5AuthRequest(bad, vchRefused));
}

// Isolation is only worth anything if two phases get different pairs.
BOOST_AUTO_TEST_CASE(fresh_credentials_differ_between_calls)
{
    const ProxyCredentials a = RandomProxyCredentials();
    const ProxyCredentials b = RandomProxyCredentials();
    BOOST_CHECK_EQUAL(a.strUser.size(), 32u);
    BOOST_CHECK_EQUAL(a.strPassword.size(), 32u);
    BOOST_CHECK(a.strUser != a.strPassword);
    BOOST_CHECK_MESSAGE(a.strUser != b.strUser,
                        "two dials drew the same username, so Tor would put them on one circuit");
    BOOST_CHECK(a.strPassword != b.strPassword);

    std::vector<unsigned char> vch;
    BOOST_CHECK(BuildSocks5AuthRequest(a, vch));
}

// Without credentials the dial offers one method, no auth.
BOOST_AUTO_TEST_CASE(a_dial_without_credentials_offers_no_auth)
{
    ScriptedProxy proxy(0x00, 0x00);
    BOOST_REQUIRE(proxy.Start());
    CService addrProxy("127.0.0.1", (unsigned short)proxy.Port());

    SOCKET hSocket = INVALID_SOCKET;
    BOOST_REQUIRE(ConnectSocks5ByName(addrProxy, "example.onion", 8443, hSocket, 5000));
    CloseSocket(hSocket);

    BOOST_REQUIRE(proxy.GreetingSeen());
    BOOST_REQUIRE_EQUAL(proxy.Greeting().size(), 3u);
    BOOST_CHECK_EQUAL((int)proxy.Greeting()[1], 1);
    BOOST_CHECK_EQUAL((int)proxy.Greeting()[2], 0x00);
    BOOST_CHECK(!proxy.AuthSeen());
    BOOST_CHECK(proxy.ConnectSeen());
}

// With credentials the dial offers username/password and sends the pair.
BOOST_AUTO_TEST_CASE(a_dial_with_credentials_authenticates)
{
    ScriptedProxy proxy(0x02, 0x00);
    BOOST_REQUIRE(proxy.Start());
    CService addrProxy("127.0.0.1", (unsigned short)proxy.Port());

    ProxyCredentials auth;
    auth.strUser = "phase-register";
    auth.strPassword = "round-7";

    SOCKET hSocket = INVALID_SOCKET;
    BOOST_REQUIRE(ConnectSocks5ByName(addrProxy, "example.onion", 8443, hSocket, 5000, &auth));
    CloseSocket(hSocket);

    BOOST_REQUIRE(proxy.GreetingSeen());
    BOOST_REQUIRE_EQUAL(proxy.Greeting().size(), 3u);
    BOOST_CHECK_EQUAL((int)proxy.Greeting()[2], 0x02);
    BOOST_REQUIRE(proxy.AuthSeen());
    std::vector<unsigned char> vchExpected;
    BOOST_REQUIRE(BuildSocks5AuthRequest(auth, vchExpected));
    BOOST_CHECK(proxy.Auth() == vchExpected);
    BOOST_CHECK(proxy.ConnectSeen());
}

// A proxy that answers no-auth to an offer of username/password cannot isolate the
// stream, so the dial must fail rather than silently reuse the last circuit.
BOOST_AUTO_TEST_CASE(a_proxy_that_will_not_isolate_fails_the_dial)
{
    // It answers no-auth and would carry the stream regardless, so nothing but the
    // client's own method check can refuse it.
    ScriptedProxy proxy(0x00, 0x00, true);
    BOOST_REQUIRE(proxy.Start());
    CService addrProxy("127.0.0.1", (unsigned short)proxy.Port());

    ProxyCredentials auth = RandomProxyCredentials();
    SOCKET hSocket = INVALID_SOCKET;
    BOOST_CHECK_MESSAGE(!ConnectSocks5ByName(addrProxy, "example.onion", 8443, hSocket, 5000, &auth),
                        "the dial accepted a no-auth proxy, so the phase shares a circuit");
    BOOST_CHECK(proxy.GreetingSeen());
    BOOST_CHECK_EQUAL((int)proxy.Greeting()[2], 0x02);
    BOOST_CHECK(!proxy.AuthSeen());
    BOOST_CHECK(!proxy.ConnectSeen());
}

// A rejected pair is a failed dial, not a dial that proceeds unisolated.
BOOST_AUTO_TEST_CASE(a_rejected_pair_fails_the_dial)
{
    // It rejects the pair and then serves the CONNECT anyway: a stream it never
    // isolated. Only the client's status check stops the phase going out on it.
    ScriptedProxy proxy(0x02, 0x01);
    BOOST_REQUIRE(proxy.Start());
    CService addrProxy("127.0.0.1", (unsigned short)proxy.Port());

    ProxyCredentials auth = RandomProxyCredentials();
    SOCKET hSocket = INVALID_SOCKET;
    BOOST_CHECK_MESSAGE(!ConnectSocks5ByName(addrProxy, "example.onion", 8443, hSocket, 5000, &auth),
                        "the dial proceeded past a rejected pair onto an unisolated stream");
    BOOST_CHECK(proxy.AuthSeen());
    BOOST_CHECK(!proxy.ConnectSeen());
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

// The stream carries a type, a bounded length and a payload. It carries no
// version, no address and no clock, which is the reason it is not the node's own
// protocol.
BOOST_AUTO_TEST_CASE(a_frame_round_trips_and_carries_no_identity)
{
    std::vector<unsigned char> vchPayload;
    for (int i = 0; i < 40; i++)
        vchPayload.push_back((unsigned char)i);

    std::vector<unsigned char> vchFrame;
    BOOST_REQUIRE(BuildMixFrame(MIX_FRAME_JOIN, vchPayload, vchFrame));
    BOOST_REQUIRE_EQUAL(vchFrame.size(), MIX_FRAME_HEADER_BYTES + vchPayload.size());
    BOOST_CHECK_EQUAL((int)vchFrame[4], (int)MIX_FRAME_JOIN);

    MixFrameType nType = MIX_FRAME_NONE;
    std::vector<unsigned char> vchBack;
    size_t nConsumed = 0;
    BOOST_REQUIRE_EQUAL(ReadMixFrame(vchFrame, nType, vchBack, nConsumed), MIX_DECODE_OK);
    BOOST_CHECK_EQUAL((int)nType, (int)MIX_FRAME_JOIN);
    BOOST_CHECK(vchBack == vchPayload);
    BOOST_CHECK_EQUAL(nConsumed, vchFrame.size());

    // An empty payload is a frame, not a decode failure: a phase that only needs
    // its type has nothing to say.
    std::vector<unsigned char> vchEmptyFrame;
    BOOST_REQUIRE(BuildMixFrame(MIX_FRAME_ABORT, std::vector<unsigned char>(), vchEmptyFrame));
    BOOST_REQUIRE_EQUAL(ReadMixFrame(vchEmptyFrame, nType, vchBack, nConsumed), MIX_DECODE_OK);
    BOOST_CHECK_EQUAL((int)nType, (int)MIX_FRAME_ABORT);
    BOOST_CHECK(vchBack.empty());
}

// A short read is not a bad frame. Telling the two apart is what lets a reader
// keep going instead of dropping a round on a partial packet.
BOOST_AUTO_TEST_CASE(a_partial_frame_is_incomplete_not_invalid)
{
    std::vector<unsigned char> vchPayload(64, 0x7e);
    std::vector<unsigned char> vchFrame;
    BOOST_REQUIRE(BuildMixFrame(MIX_FRAME_OUTPUT, vchPayload, vchFrame));

    MixFrameType nType;
    std::vector<unsigned char> vchBack;
    size_t nConsumed = 0;
    for (size_t n = 0; n < vchFrame.size(); n++)
    {
        const std::vector<unsigned char> vchShort(vchFrame.begin(), vchFrame.begin() + n);
        BOOST_CHECK_MESSAGE(ReadMixFrame(vchShort, nType, vchBack, nConsumed) == MIX_DECODE_INCOMPLETE,
                            "a prefix of " << n << " bytes was not judged incomplete");
    }
    BOOST_CHECK_EQUAL(ReadMixFrame(vchFrame, nType, vchBack, nConsumed), MIX_DECODE_OK);

    // Two frames back to back: the reader takes the first and says where it ended.
    std::vector<unsigned char> vchSecond;
    BOOST_REQUIRE(BuildMixFrame(MIX_FRAME_ABORT, std::vector<unsigned char>(), vchSecond));
    std::vector<unsigned char> vchBoth(vchFrame);
    vchBoth.insert(vchBoth.end(), vchSecond.begin(), vchSecond.end());
    BOOST_REQUIRE_EQUAL(ReadMixFrame(vchBoth, nType, vchBack, nConsumed), MIX_DECODE_OK);
    BOOST_CHECK_EQUAL((int)nType, (int)MIX_FRAME_OUTPUT);
    BOOST_CHECK_EQUAL(nConsumed, vchFrame.size());
}

// A declared length past the bound is refused on the header alone. Waiting for
// bytes a peer will never send is a free way to hold a reader open.
BOOST_AUTO_TEST_CASE(an_oversized_length_is_refused_on_the_header)
{
    std::vector<unsigned char> vchFrame;
    BOOST_REQUIRE(BuildMixFrame(MIX_FRAME_KEY, std::vector<unsigned char>(4, 0x01), vchFrame));
    const uint32_t nHuge = MIX_FRAME_MAX_PAYLOAD + 1;
    vchFrame[5] = (unsigned char)(nHuge & 0xFF);
    vchFrame[6] = (unsigned char)((nHuge >> 8) & 0xFF);
    vchFrame[7] = (unsigned char)((nHuge >> 16) & 0xFF);
    vchFrame[8] = (unsigned char)((nHuge >> 24) & 0xFF);

    MixFrameType nType;
    std::vector<unsigned char> vchBack;
    size_t nConsumed = 0;
    BOOST_CHECK_MESSAGE(ReadMixFrame(vchFrame, nType, vchBack, nConsumed) == MIX_DECODE_INVALID,
                        "an over-long declared length was treated as a short read, so a "
                        "peer can hold the reader open on bytes it never sends");

    // 0xFFFFFFFF is the same finding at the end of the range, where a length that
    // is added to a header size would wrap.
    for (int i = 5; i <= 8; i++)
        vchFrame[i] = 0xFF;
    BOOST_CHECK_EQUAL(ReadMixFrame(vchFrame, nType, vchBack, nConsumed), MIX_DECODE_INVALID);

    // A builder will not produce one either.
    std::vector<unsigned char> vchRefused;
    BOOST_CHECK(!BuildMixFrame(MIX_FRAME_KEY, std::vector<unsigned char>(MIX_FRAME_MAX_PAYLOAD + 1, 0), vchRefused));
}

// A stream pointed at the wrong service, or a type with no handler, is refused
// rather than dispatched.
BOOST_AUTO_TEST_CASE(a_foreign_stream_or_unknown_type_is_refused)
{
    std::vector<unsigned char> vchFrame;
    BOOST_REQUIRE(BuildMixFrame(MIX_FRAME_JOIN, std::vector<unsigned char>(2, 0x09), vchFrame));

    MixFrameType nType;
    std::vector<unsigned char> vchBack;
    size_t nConsumed = 0;

    std::vector<unsigned char> vchForeign(vchFrame);
    vchForeign[0] ^= 0xFF;
    BOOST_CHECK_EQUAL(ReadMixFrame(vchForeign, nType, vchBack, nConsumed), MIX_DECODE_INVALID);

    std::vector<unsigned char> vchUnknown(vchFrame);
    vchUnknown[4] = (unsigned char)(MIX_FRAME_TYPE_MAX + 1);
    BOOST_CHECK_EQUAL(ReadMixFrame(vchUnknown, nType, vchBack, nConsumed), MIX_DECODE_INVALID);

    std::vector<unsigned char> vchZeroType(vchFrame);
    vchZeroType[4] = 0;
    BOOST_CHECK_EQUAL(ReadMixFrame(vchZeroType, nType, vchBack, nConsumed), MIX_DECODE_INVALID);

    BOOST_CHECK(!BuildMixFrame(MIX_FRAME_NONE, std::vector<unsigned char>(), vchFrame));
    BOOST_CHECK(!BuildMixFrame((MixFrameType)(MIX_FRAME_TYPE_MAX + 1), std::vector<unsigned char>(), vchFrame));
}

// ---------------------------------------------------------------------------
// Per-participant authentication
// ---------------------------------------------------------------------------

// The point of the session key: a participant is recognised by key, so a phase can
// arrive on a fresh connection -- which is what lets each phase have its own
// circuit. Identifying by socket is what forces them all onto one.
BOOST_AUTO_TEST_CASE(a_session_key_authenticates_across_connections)
{
    CKey key;
    key.MakeNewKey(true);
    const CPubKey pubkey = key.GetPubKey();
    const uint256 hashRound = uint256(4242);
    std::vector<unsigned char> vchPayload(32, 0x5a);

    std::vector<unsigned char> vchSig;
    BOOST_REQUIRE(SignMixSessionFrame(key, hashRound, MIX_FRAME_OUTPUT, vchPayload, vchSig));
    BOOST_CHECK(CheckMixSessionFrame(pubkey, hashRound, MIX_FRAME_OUTPUT, vchPayload, vchSig));

    CKey other;
    other.MakeNewKey(true);
    BOOST_CHECK(!CheckMixSessionFrame(other.GetPubKey(), hashRound, MIX_FRAME_OUTPUT, vchPayload, vchSig));

    std::vector<unsigned char> vchEdited(vchPayload);
    vchEdited[0] ^= 0x01;
    BOOST_CHECK(!CheckMixSessionFrame(pubkey, hashRound, MIX_FRAME_OUTPUT, vchEdited, vchSig));
    BOOST_CHECK(!CheckMixSessionFrame(pubkey, hashRound, MIX_FRAME_OUTPUT, vchPayload,
                                      std::vector<unsigned char>()));
}

// The round and the frame type are inside the signed hash, so a message cannot be
// lifted into another round or re-presented as another phase.
BOOST_AUTO_TEST_CASE(a_signed_frame_does_not_move_between_rounds_or_phases)
{
    CKey key;
    key.MakeNewKey(true);
    const CPubKey pubkey = key.GetPubKey();
    const uint256 hashRound = uint256(7);
    std::vector<unsigned char> vchPayload(16, 0x33);

    std::vector<unsigned char> vchSig;
    BOOST_REQUIRE(SignMixSessionFrame(key, hashRound, MIX_FRAME_JOIN, vchPayload, vchSig));

    BOOST_CHECK_MESSAGE(!CheckMixSessionFrame(pubkey, uint256(8), MIX_FRAME_JOIN, vchPayload, vchSig),
                        "a join from one round verified in another");
    BOOST_CHECK_MESSAGE(!CheckMixSessionFrame(pubkey, hashRound, MIX_FRAME_OUTPUT, vchPayload, vchSig),
                        "a join verified as an output registration");

    BOOST_CHECK(MixSessionSigHash(hashRound, MIX_FRAME_JOIN, vchPayload) !=
                MixSessionSigHash(hashRound, MIX_FRAME_OUTPUT, vchPayload));
    BOOST_CHECK(MixSessionSigHash(hashRound, MIX_FRAME_JOIN, vchPayload) !=
                MixSessionSigHash(uint256(8), MIX_FRAME_JOIN, vchPayload));
}

BOOST_AUTO_TEST_SUITE_END()
