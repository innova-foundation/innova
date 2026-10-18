#include <boost/test/unit_test.hpp>

#include "addrman.h"
#include "main.h"
#include "net.h"
#include "netbase.h"
#include "protocol.h"
#include "serialize.h"
#include "util.h"
#include "version.h"

BOOST_AUTO_TEST_SUITE(addrv2_tests)

static const char* V3 = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";

BOOST_AUTO_TEST_CASE(sha3_256_vectors)
{
    unsigned char h[32];
    SHA3_256(NULL, 0, h);
    BOOST_CHECK_EQUAL(HexStr(h, h + 32), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    const unsigned char abc[] = {'a', 'b', 'c'};
    SHA3_256(abc, 3, h);
    BOOST_CHECK_EQUAL(HexStr(h, h + 32), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    std::vector<unsigned char> big(200, 0xa3);
    SHA3_256(&big[0], big.size(), h);
    BOOST_CHECK_EQUAL(HexStr(h, h + 32), "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787");
}

BOOST_AUTO_TEST_CASE(torv3_parse_print)
{
    CNetAddr a;
    BOOST_CHECK(a.SetSpecial(V3));
    BOOST_CHECK(a.IsTorV3());
    BOOST_CHECK(a.IsTor());
    BOOST_CHECK(a.IsValid());
    BOOST_CHECK(a.IsRoutable());
    BOOST_CHECK(a.GetNetwork() == NET_TOR);
    BOOST_CHECK(!a.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(a.ToStringIP(), V3);

    unsigned char id; std::vector<unsigned char> v;
    a.GetBIP155(id, v);
    BOOST_CHECK_EQUAL(id, BIP155_TORV3);
    BOOST_CHECK_EQUAL(HexStr(v), "79bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f");

    // upper case accepted, printed lower case
    std::string up(V3);
    for (size_t i = 0; i < up.size(); i++) up[i] = toupper(up[i]);
    CNetAddr b;
    BOOST_CHECK(b.SetSpecial(up));
    BOOST_CHECK(a == b);

    // string constructor goes through the same parser
    CService s(std::string(V3) + ":15539", false);
    BOOST_CHECK(s.IsTorV3());
    BOOST_CHECK_EQUAL(s.ToStringIPPort(), std::string(V3) + ":15539");
}

BOOST_AUTO_TEST_CASE(torv3_rejects_bad_checksum_and_version)
{
    std::string bad(V3);
    bad[0] = (bad[0] == 'a') ? 'b' : 'a';
    CNetAddr a;
    BOOST_CHECK(!a.SetSpecial(bad));

    // version byte != 3: last base32 char carries the version bits
    std::string ver(V3);
    ver[55] = (ver[55] == 'd') ? 'e' : 'd';
    BOOST_CHECK(!a.SetSpecial(ver));
}

BOOST_AUTO_TEST_CASE(torv3_distinct_from_shared_prefix)
{
    CNetAddr a, b;
    BOOST_CHECK(a.SetSpecial(V3));
    std::vector<unsigned char> v;
    unsigned char id;
    a.GetBIP155(id, v);
    v[31] ^= 1;
    BOOST_CHECK(b.SetBIP155(BIP155_TORV3, v));
    BOOST_CHECK(a != b);
    BOOST_CHECK((a < b) != (b < a));
    BOOST_CHECK(CService(a, 1).GetKey() != CService(b, 1).GetKey());
}

BOOST_AUTO_TEST_CASE(addrv2_roundtrip)
{
    std::vector<CAddress> vIn;
    CNetAddr onion;
    onion.SetSpecial(V3);
    vIn.push_back(CAddress(CService(onion, 15539)));
    vIn.push_back(CAddress(CService("8.8.8.8", 15540)));
    vIn.push_back(CAddress(CService("2001:4860:4860::8888", 15539)));
    for (size_t i = 0; i < vIn.size(); i++) {
        vIn[i].nTime = 1700000000 + i;
        vIn[i].nServices = NODE_NETWORK;
    }

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << CAddrV2Vector(vIn);
    BOOST_CHECK_EQUAL(ss.size(), ::GetSerializeSize(CAddrV2Vector(vIn), SER_NETWORK, PROTOCOL_VERSION));
    std::vector<CAddress> vOut;
    CAddrV2Vector w(vOut);
    ss >> w;
    BOOST_CHECK(ss.empty());
    BOOST_REQUIRE_EQUAL(vOut.size(), vIn.size());
    for (size_t i = 0; i < vIn.size(); i++) {
        BOOST_CHECK((CService)vOut[i] == (CService)vIn[i]);
        BOOST_CHECK_EQUAL(vOut[i].nTime, vIn[i].nTime);
        BOOST_CHECK_EQUAL(vOut[i].nServices, vIn[i].nServices);
    }
    BOOST_CHECK(vOut[0].IsTorV3());

    // v1 encoding of IPv4 stays byte-identical to the legacy form
    CDataStream s1(SER_NETWORK, PROTOCOL_VERSION);
    s1 << CNetAddr("8.8.8.8");
    BOOST_CHECK_EQUAL(s1.size(), 16U);
}

BOOST_AUTO_TEST_CASE(addrv2_wire_format)
{
    // BIP155 example: IPv4 1.2.3.4 -> 01 04 01020304
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION | ADDRV2_FORMAT);
    ss << CNetAddr("1.2.3.4");
    BOOST_CHECK_EQUAL(HexStr(ss.begin(), ss.end()), "010401020304");

    // unknown network id: skipped as an invalid address, not an error
    CDataStream su(ParseHex("ff0401020304"), SER_NETWORK, PROTOCOL_VERSION | ADDRV2_FORMAT);
    CNetAddr u;
    su >> u;
    BOOST_CHECK(!u.IsValid());

    // known id with wrong length is rejected
    CDataStream sb(ParseHex("0105010203040506"), SER_NETWORK, PROTOCOL_VERSION | ADDRV2_FORMAT);
    CNetAddr b;
    BOOST_CHECK_THROW(sb >> b, std::ios_base::failure);

    // IPv4-mapped IPv6 under id 2 is refused
    CDataStream sm(ParseHex("021000000000000000000000ffff01020304"), SER_NETWORK, PROTOCOL_VERSION | ADDRV2_FORMAT);
    CNetAddr m;
    sm >> m;
    BOOST_CHECK(!m.IsValid());
}

BOOST_AUTO_TEST_CASE(addrman_stores_torv3)
{
    CAddrMan am;
    CNetAddr onion;
    onion.SetSpecial(V3);
    CAddress a(CService(onion, 15539));
    BOOST_CHECK(am.Add(a, CNetAddr("8.8.4.4")));
    BOOST_CHECK_EQUAL(am.size(), 1);

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << am;
    CAddrMan am2;
    ss >> am2;
    BOOST_CHECK_EQUAL(am2.size(), 1);
    CAddress sel = am2.Select();
    BOOST_CHECK(sel.IsTorV3());
    BOOST_CHECK((CService)sel == (CService)a);
}

namespace {
struct TestPeer
{
    CNode node;
    explicit TestPeer(int nPort)
        : node(INVALID_SOCKET, CAddress(CService("127.0.0.1", nPort)), "", false)
    {
        node.nVersion = PROTOCOL_VERSION;
        node.nPingNonceSent = 1;
        node.fStartSync = false;
        node.nLastBlockRecv = GetTime();
    }
};

void Deliver(TestPeer& from, TestPeer& to)
{
    CSerializeData data;
    {
        LOCK(from.node.cs_vSend);
        BOOST_REQUIRE(!from.node.vSendMsg.empty());
        data = from.node.vSendMsg.back();
        from.node.vSendMsg.clear();
    }
    BOOST_REQUIRE(to.node.ReceiveMsgBytes(&data[0], (unsigned int)data.size()));
    LOCK(to.node.cs_vRecvMsg);
    BOOST_REQUIRE(ProcessMessages(&to.node));
}
}

BOOST_AUTO_TEST_CASE(sendaddrv2_negotiation)
{
    TestPeer a(29411), b(29412);
    BOOST_CHECK(!b.node.fWantsAddrV2);
    a.node.PushMessage("sendaddrv2");
    Deliver(a, b);
    BOOST_CHECK(b.node.fWantsAddrV2);

    // an addrv2 message carrying a Tor v3 entry is accepted without penalty
    std::vector<CAddress> v;
    CNetAddr onion;
    onion.SetSpecial(V3);
    v.push_back(CAddress(CService(onion, 15539)));
    v[0].nTime = GetAdjustedTime();
    a.node.PushMessage("addrv2", CAddrV2Vector(v));
    Deliver(a, b);
    BOOST_CHECK_EQUAL(b.node.nMisbehavior, 0);
    BOOST_CHECK(b.node.setAddrKnown.count(v[0]));

    CAddress ip4(CService("8.8.8.8", 15539));
    BOOST_CHECK(!v[0].IsAddrV1Compatible());
    BOOST_CHECK(ip4.IsAddrV1Compatible());
}

BOOST_AUTO_TEST_SUITE_END()
