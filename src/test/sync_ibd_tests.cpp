// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include "main.h"
#include "net.h"
#include "txdb.h"
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

BOOST_AUTO_TEST_CASE(a_send_drain_below_the_limit_wakes_the_handler)
{
    BOOST_CHECK(SendDrainUnblocksGetData(10000, 9999, 10000));
    BOOST_CHECK(!SendDrainUnblocksGetData(9000, 100, 10000));
    BOOST_CHECK(!SendDrainUnblocksGetData(20000, 10000, 10000));
}

BOOST_AUTO_TEST_CASE(ibd_commits_sync_per_batch_or_time_slice)
{
    BOOST_CHECK(IBDBatchShouldSync(false, 0, 0, 500, 10000));
    BOOST_CHECK(IBDBatchShouldSync(true, 0, 0, 0, 10000));
    BOOST_CHECK(!IBDBatchShouldSync(true, 0, 0, 500, 10000));
    BOOST_CHECK(!IBDBatchShouldSync(true, 498, 9999, 500, 10000));
    BOOST_CHECK(IBDBatchShouldSync(true, 499, 0, 500, 10000));
    BOOST_CHECK(IBDBatchShouldSync(true, 3, 10000, 500, 10000));
}

BOOST_AUTO_TEST_CASE(header_prechecks_run_without_the_index)
{
    BOOST_REQUIRE(pindexGenesisBlock != NULL);
    const CBlock genesis = pindexGenesisBlock->GetBlockHeader();
    std::vector<CBlock> vHeaders(2000, genesis);
    vHeaders[1].nBits = 0x01010000;
    std::vector<uint256> vHash;
    std::vector<char> vPowOk;

    const int64_t nStart = GetTimeMicros();
    PrecheckHeaders(vHeaders, vHash, vPowOk);
    const int64_t nElapsed = GetTimeMicros() - nStart;
    BOOST_TEST_MESSAGE("PrecheckHeaders: 2000 headers in " << nElapsed << " us");

    BOOST_REQUIRE_EQUAL(vHash.size(), 2000U);
    BOOST_REQUIRE_EQUAL(vPowOk.size(), 2000U);
    BOOST_CHECK(vHash[0] == genesis.GetHash());
    BOOST_CHECK(vHash[1] == vHeaders[1].GetHash());
    BOOST_CHECK_EQUAL(vPowOk[0] != 0, CheckProofOfWork(vHash[0], genesis.nBits));
    BOOST_CHECK(!vPowOk[1]);
}

BOOST_AUTO_TEST_SUITE_END()
