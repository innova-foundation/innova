#include <boost/test/unit_test.hpp>

#include "addrman.h"
#include "net.h"
#include "serialize.h"

BOOST_AUTO_TEST_SUITE(addrman_port_tests)

BOOST_AUTO_TEST_CASE(two_ports_one_ip_stored_separately)
{
    CAddrMan am;
    CNetAddr src("8.8.4.4");
    CAddress a(CService("8.8.8.8", 15539));
    CAddress b(CService("8.8.8.8", 15540));
    BOOST_CHECK(am.Add(a, src));
    BOOST_CHECK(am.Add(b, src));
    BOOST_CHECK_EQUAL(am.size(), 2);
    BOOST_CHECK(!am.Add(b, src));
    BOOST_CHECK_EQUAL(am.size(), 2);
}

BOOST_AUTO_TEST_CASE(peers_dat_roundtrip_keeps_ports)
{
    CAddrMan am;
    CNetAddr src("8.8.4.4");
    am.Add(CAddress(CService("8.8.8.8", 15539)), src);
    am.Add(CAddress(CService("8.8.8.8", 15540)), src);
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << am;
    BOOST_CHECK_EQUAL((int)(unsigned char)ss[0], 2);
    CAddrMan am2;
    ss >> am2;
    BOOST_CHECK_EQUAL(am2.size(), 2);
}

BOOST_AUTO_TEST_CASE(outbound_port_policy)
{
    BOOST_CHECK(IsBadPort(22));
    BOOST_CHECK(IsBadPort(25));
    BOOST_CHECK(!IsBadPort(15539));
    BOOST_CHECK(!IsBadPort(15540));
}

BOOST_AUTO_TEST_SUITE_END()
