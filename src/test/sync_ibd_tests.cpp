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

namespace {
struct ToyChain
{
    std::vector<uint256> vHash;
    std::vector<CBlockIndex> vIndex;
    ToyChain() : vHash(10), vIndex(10)
    {
        // 0..5 main (5 is linked onward to 9 so it counts as main), 6..8 a side branch off 2, 9 the tip pad
        for (int i = 0; i < 10; i++)
        {
            vHash[i] = uint256((uint64_t)(0x5100 + i));
            vIndex[i].phashBlock = &vHash[i];
        }
        for (int i = 1; i <= 5; i++)
        {
            vIndex[i].pprev = &vIndex[i - 1];
            vIndex[i - 1].pnext = &vIndex[i];
            vIndex[i].nHeight = i;
        }
        vIndex[5].pnext = &vIndex[9];
        vIndex[9].pprev = &vIndex[5];
        vIndex[9].nHeight = 6;
        vIndex[6].pprev = &vIndex[2]; vIndex[6].nHeight = 3;
        vIndex[7].pprev = &vIndex[6]; vIndex[7].nHeight = 4;
        vIndex[8].pprev = &vIndex[7]; vIndex[8].nHeight = 5;
    }
    CBlockIndex* operator[](int i) { return &vIndex[i]; }
};
}

BOOST_AUTO_TEST_CASE(getheaders_serves_a_side_branch_from_the_fork)
{
    ToyChain c;
    std::vector<CBlockIndex*> vOut;
    std::set<uint256> setHave;

    setHave.insert(c.vHash[2]);
    BOOST_CHECK(CollectSideBranchHeaders(setHave, c[2], c[8], 2000, vOut));
    BOOST_REQUIRE_EQUAL(vOut.size(), 3U);
    BOOST_CHECK(vOut[0] == c[6] && vOut[1] == c[7] && vOut[2] == c[8]);

    setHave.clear();
    setHave.insert(c.vHash[0]);
    BOOST_CHECK(CollectSideBranchHeaders(setHave, c[0], c[8], 2000, vOut));
    BOOST_REQUIRE_EQUAL(vOut.size(), 5U);
    BOOST_CHECK(vOut[0] == c[1] && vOut[1] == c[2] && vOut[2] == c[6] && vOut[4] == c[8]);

    BOOST_CHECK(CollectSideBranchHeaders(setHave, c[0], c[8], 3, vOut));
    BOOST_REQUIRE_EQUAL(vOut.size(), 3U);
    BOOST_CHECK(vOut[2] == c[6]);

    setHave.clear();
    setHave.insert(c.vHash[6]);
    BOOST_CHECK(CollectSideBranchHeaders(setHave, c[2], c[8], 2000, vOut));
    BOOST_REQUIRE_EQUAL(vOut.size(), 2U);
    BOOST_CHECK(vOut[0] == c[7]);
}

BOOST_AUTO_TEST_CASE(getheaders_side_branch_stops_at_an_invalid_block)
{
    ToyChain c;
    std::vector<CBlockIndex*> vOut;
    std::set<uint256> setHave;
    setHave.insert(c.vHash[2]);
    c[7]->SetFailedValid();
    BOOST_CHECK(CollectSideBranchHeaders(setHave, c[2], c[8], 2000, vOut));
    BOOST_REQUIRE_EQUAL(vOut.size(), 1U);
    BOOST_CHECK(vOut[0] == c[6]);
}

BOOST_AUTO_TEST_CASE(getheaders_main_chain_stop_uses_the_main_chain_path)
{
    ToyChain c;
    std::vector<CBlockIndex*> vOut;
    std::set<uint256> setHave;
    setHave.insert(c.vHash[0]);
    BOOST_CHECK(!CollectSideBranchHeaders(setHave, c[0], c[4], 2000, vOut));
    BOOST_CHECK(vOut.empty());
}

BOOST_AUTO_TEST_CASE(orphans_parked_long_ago_stop_counting_toward_the_cap)
{
    LOCK(cs_main);
    const std::map<uint256, COrphanBlock> savedBlocks = mapOrphanBlocks;
    const std::map<uint256, NodeId> savedByNode = mapOrphanBlocksByNode;
    mapOrphanBlocks.clear();
    mapOrphanBlocksByNode.clear();
    const int64_t nNow = 1000000;
    // Peer 7 holds 760 orphans, 700 of them parked two minutes ago; peer 8 holds one fresh one.
    for (int i = 0; i < 761; i++)
    {
        const uint256 hash((uint64_t)(0x0c0000 + i));
        mapOrphanBlocks[hash] = COrphanBlock(NULL, 100, uint256(0), i < 700 ? nNow - 120 : nNow - 5);
        mapOrphanBlocksByNode[hash] = (i == 760) ? (NodeId)8 : (NodeId)7;
    }
    BOOST_CHECK_EQUAL(OrphanCountTowardCap(7, 10, nNow), 10);
    BOOST_CHECK_EQUAL(OrphanCountTowardCap(7, 760, nNow), 60);
    BOOST_CHECK_EQUAL(OrphanCountTowardCap(7, 760, nNow - 100), 760);
    BOOST_CHECK_EQUAL(OrphanCountTowardCap(8, 750, nNow), 750);
    mapOrphanBlocks = savedBlocks;
    mapOrphanBlocksByNode = savedByNode;
}

BOOST_AUTO_TEST_SUITE_END()
