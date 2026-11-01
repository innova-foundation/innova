// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include "checkpoints.h"
#include "init.h"
#include "main.h"
#include "net.h"
#include "txdb.h"
#include "util.h"
#include "version.h"
#include "wallet.h"
#include "walletdb.h"

#include <leveldb/cache.h>

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

BOOST_AUTO_TEST_CASE(a_bdb_write_fsyncs_the_pending_ibd_batch_first)
{
    mapArgs["-ibdbatchalways"] = "1";
    InitIBDBatching();
    BOOST_CHECK(!IBDBlockCommitSync());
    BOOST_CHECK(!IBDBatchPending());
    NoteUnsyncedIBDCommit();
    BOOST_CHECK(IBDBatchPending());
    {
        CWalletDB walletdb(pwalletMain->strWalletFile);
        BOOST_CHECK(walletdb.WriteName("ibd-batch-test", "x"));
    }
    BOOST_CHECK(!IBDBatchPending());
    NoteUnsyncedIBDCommit();
    FlushIBDBatch();
    BOOST_CHECK(!IBDBatchPending());
    mapArgs.erase("-ibdbatchalways");
    InitIBDBatching();
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
    // The decay stops at the hard ceiling, so one peer cannot climb to the pool limit.
    BOOST_CHECK_EQUAL(OrphanPeerHardCeiling(DEFAULT_MAX_ORPHAN_BLOCKS), 1000);
    BOOST_CHECK_EQUAL(OrphanPeerHardCeiling(100), 750);
    BOOST_CHECK_EQUAL(OrphanCountTowardCap(7, 999, nNow), 299);
    BOOST_CHECK_EQUAL(OrphanCountTowardCap(7, 1000, nNow), 1000);
    mapOrphanBlocks = savedBlocks;
    mapOrphanBlocksByNode = savedByNode;
}

BOOST_AUTO_TEST_CASE(headers_forking_below_the_last_checkpoint_are_refused)
{
    BOOST_CHECK(HeaderForksBelowCheckpoint(1000, 5000, 4000));
    BOOST_CHECK(HeaderForksBelowCheckpoint(4000, 4000, 4000));
    BOOST_CHECK(!HeaderForksBelowCheckpoint(4001, 5000, 4000));
    BOOST_CHECK(!HeaderForksBelowCheckpoint(1000, 3999, 4000));
    BOOST_CHECK(!HeaderForksBelowCheckpoint(1, 5000, 0));
}

namespace {
// True when the handshake was accepted. A socketless peer raises fDisconnect on any send.
bool DeliverVersion(CNode& receiver, int nVersion)
{
    CNode scratch(INVALID_SOCKET, CAddress(CService("203.0.113.10", 14531)), "", false);
    scratch.PushMessage("version", nVersion, (uint64_t)NODE_NETWORK, GetTime(),
                        CAddress(CService("203.0.113.11", 14532)), CAddress(CService("203.0.113.10", 14531)),
                        (uint64_t)1, std::string("/test/"), 1);
    CSerializeData data;
    {
        LOCK(scratch.cs_vSend);
        BOOST_REQUIRE(!scratch.vSendMsg.empty());
        data = scratch.vSendMsg.back();
    }
    BOOST_REQUIRE(receiver.ReceiveMsgBytes(&data[0], (unsigned int)data.size()));
    LOCK(receiver.cs_vRecvMsg);
    ProcessMessages(&receiver);
    return receiver.fSuccessfullyConnected;
}
}

BOOST_AUTO_TEST_CASE(peers_below_52002_are_disconnected_at_any_height)
{
    BOOST_CHECK_EQUAL(MIN_PEER_PROTO_VERSION, 52002);
    {
        CNode node(INVALID_SOCKET, CAddress(CService("203.0.113.12", 14533)), "", false);
        node.nPingNonceSent = 1;
        BOOST_CHECK(!DeliverVersion(node, 52001));
        BOOST_CHECK(node.fDisconnect);
    }
    {
        CNode node(INVALID_SOCKET, CAddress(CService("203.0.113.13", 14534)), "", false);
        node.nPingNonceSent = 1;
        BOOST_CHECK(!DeliverVersion(node, 43950));
        BOOST_CHECK(node.fDisconnect);
    }
    {
        CNode node(INVALID_SOCKET, CAddress(CService("203.0.113.14", 14535)), "", false);
        node.nPingNonceSent = 1;
        BOOST_CHECK(DeliverVersion(node, 52002));
        BOOST_CHECK_EQUAL(node.nVersion, 52002);
    }
}

BOOST_AUTO_TEST_CASE(signature_skip_needs_the_checkpointed_chain)
{
    ToyChain c;
    for (int i = 0; i < 10; i++)
        c[i]->BuildSkip();
    Checkpoints::MapCheckpoints cps;
    cps[0] = c.vHash[0];
    cps[2] = c.vHash[2];
    cps[4] = c.vHash[4];
    std::map<uint256, CBlockIndex*> mapIndex;
    for (int i = 0; i < 4; i++)
        mapIndex[c.vHash[i]] = c[i];

    // Last checkpoint not indexed yet: every checkpoint passed so far must match.
    BOOST_CHECK(Checkpoints::IsCheckpointedAncestor(cps, mapIndex, c[3]));
    BOOST_CHECK(Checkpoints::IsCheckpointedAncestor(cps, mapIndex, c[6]));
    Checkpoints::MapCheckpoints cpsBad = cps;
    cpsBad[2] = uint256((uint64_t)0xbad);
    BOOST_CHECK(!Checkpoints::IsCheckpointedAncestor(cpsBad, mapIndex, c[3]));

    // Indexed: ancestry of the last checkpoint only.
    mapIndex[c.vHash[4]] = c[4];
    BOOST_CHECK(Checkpoints::IsCheckpointedAncestor(cps, mapIndex, c[3]));
    BOOST_CHECK(Checkpoints::IsCheckpointedAncestor(cps, mapIndex, c[4]));
    BOOST_CHECK(!Checkpoints::IsCheckpointedAncestor(cps, mapIndex, c[6]));
    BOOST_CHECK(!Checkpoints::IsCheckpointedAncestor(cps, mapIndex, c[7]));

    // Never above the last checkpoint.
    BOOST_CHECK(!Checkpoints::IsCheckpointedAncestor(cps, mapIndex, c[5]));
    BOOST_CHECK(!Checkpoints::IsCheckpointedAncestor(cps, mapIndex, NULL));
}

BOOST_AUTO_TEST_CASE(memory_defaults_follow_the_synced_marker)
{
    const int64_t nNow = 2000000000;
    BOOST_CHECK(!OpensSynced(0, nNow));
    BOOST_CHECK(OpensSynced(nNow - 3600, nNow));
    BOOST_CHECK(!OpensSynced(nNow - 2 * 24 * 3600, nNow));
    BOOST_CHECK_EQUAL(DefaultDbCacheMB(false), 300);
    BOOST_CHECK_EQUAL(DefaultDbCacheMB(true), 64);
}

namespace {
void DeleteNothing(const leveldb::Slice&, void*) {}
}

BOOST_AUTO_TEST_CASE(leveldb_cache_shrinks_in_place)
{
    leveldb::Cache* cache = leveldb::NewLRUCache(16 * 1000);
    static int nValue = 0;
    for (int i = 0; i < 1000; i++)
    {
        const std::string key = strprintf("k%d", i);
        cache->Release(cache->Insert(key, &nValue, 10, DeleteNothing));
    }
    int nBefore = 0;
    for (int i = 0; i < 1000; i++)
    {
        leveldb::Cache::Handle* h = cache->Lookup(strprintf("k%d", i));
        if (h) { nBefore++; cache->Release(h); }
    }
    cache->SetCapacity(16 * 10);
    int nAfter = 0;
    for (int i = 0; i < 1000; i++)
    {
        leveldb::Cache::Handle* h = cache->Lookup(strprintf("k%d", i));
        if (h) { nAfter++; cache->Release(h); }
    }
    BOOST_CHECK_EQUAL(nBefore, 1000);
    BOOST_CHECK(nAfter <= 16 * 1 + 16);
    delete cache;
}

BOOST_AUTO_TEST_SUITE_END()
