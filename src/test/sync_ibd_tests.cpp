// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include "main.h"
#include "net.h"
#include "util.h"

#include <map>
#include <set>
#include <vector>

BOOST_AUTO_TEST_SUITE(sync_ibd_tests)

namespace {
struct Peer
{
    CNode node;
    Peer() : node(INVALID_SOCKET, CAddress(CService("203.0.113.9", 14530)), "", false) {}
};
}

BOOST_AUTO_TEST_CASE(peer_scan_does_not_expire_in_flight_entries)
{
    const int64_t nNow = GetTime();
    Peer peer;
    peer.node.nBestKnownHeight = 1000;
    peer.node.nLastHeightUpdate = nNow;
    const uint256 hash((uint64_t)0x1bd0001ull);
    peer.node.setBlocksInFlight.insert(hash);
    peer.node.mapBlockInFlightSince[hash] = nNow - 700;

    std::vector<CNode*> vPeers(1, &peer.node);
    int nFresh = -1;
    int64_t nLastRecv = 0;
    BOOST_CHECK(!ScanPeersForCatchup(vPeers, nNow, 10, nFresh, nLastRecv));
    BOOST_CHECK_EQUAL(nFresh, 1000);
    BOOST_CHECK_EQUAL(peer.node.setBlocksInFlight.count(hash), 1U);
    BOOST_CHECK_EQUAL(peer.node.mapBlockInFlightSince.count(hash), 1U);
}

BOOST_AUTO_TEST_CASE(a_live_request_to_a_peer_ahead_is_catchup)
{
    const int64_t nNow = GetTime();
    Peer peer;
    peer.node.nBestKnownHeight = 1000;
    const uint256 hash((uint64_t)0x1bd0002ull);
    peer.node.setBlocksInFlight.insert(hash);
    peer.node.mapBlockInFlightSince[hash] = nNow;

    std::vector<CNode*> vPeers(1, &peer.node);
    int nFresh = -1;
    int64_t nLastRecv = 0;
    BOOST_CHECK(ScanPeersForCatchup(vPeers, nNow, 10, nFresh, nLastRecv));
    BOOST_CHECK(!ScanPeersForCatchup(vPeers, nNow, 999, nFresh, nLastRecv));
}

BOOST_AUTO_TEST_CASE(repeated_calls_give_the_same_answer)
{
    const bool f1 = IsInitialBlockDownload();
    const bool f2 = IsInitialBlockDownload();
    BOOST_CHECK_EQUAL(f1, f2);
}

BOOST_AUTO_TEST_SUITE_END()
