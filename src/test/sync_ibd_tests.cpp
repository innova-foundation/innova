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

static std::string strIBDFlushFailure;
static void RecordIBDFlushFailure(const std::string& s) { strIBDFlushFailure = s; }

BOOST_AUTO_TEST_CASE(failed_ibd_flush_refuses_the_wallet_write)
{
    mapArgs["-ibdbatchalways"] = "1";
    InitIBDBatching();
    void (*pPrev)(const std::string&) = pIBDFlushFailed;
    pIBDFlushFailed = RecordIBDFlushFailure;
    strIBDFlushFailure.clear();
    NoteUnsyncedIBDCommit();
    fIBDFlushFailForTest = true;
    {
        CWalletDB walletdb(pwalletMain->strWalletFile);
        BOOST_CHECK(!walletdb.WriteName("ibd-flush-fail", "x"));
    }
    BOOST_CHECK(strIBDFlushFailure.find("sync failed") != std::string::npos);
    BOOST_CHECK(IBDBatchPending());
    BOOST_CHECK(!FlushIBDBatch());
    fIBDFlushFailForTest = false;
    BOOST_CHECK(FlushIBDBatch());
    BOOST_CHECK(!IBDBatchPending());
    pIBDFlushFailed = pPrev;
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
        mapOrphanBlocks[hash] = COrphanBlock(NULL, 100, uint256((uint64_t)0), i < 700 ? nNow - 120 : nNow - 5);
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

    // Last checkpoint not indexed yet: only up to the highest indexed one, on its ancestry.
    BOOST_CHECK(Checkpoints::IsCheckpointedAncestor(cps, mapIndex, c[1]));
    BOOST_CHECK(Checkpoints::IsCheckpointedAncestor(cps, mapIndex, c[2]));
    BOOST_CHECK(!Checkpoints::IsCheckpointedAncestor(cps, mapIndex, c[3]));
    BOOST_CHECK(!Checkpoints::IsCheckpointedAncestor(cps, mapIndex, c[6]));
    CBlockIndex fork1;
    fork1.nHeight = 1;
    fork1.pprev = c[0];
    BOOST_CHECK(!Checkpoints::IsCheckpointedAncestor(cps, mapIndex, &fork1));
    Checkpoints::MapCheckpoints cpsBad = cps;
    cpsBad[2] = uint256((uint64_t)0xbad);
    BOOST_CHECK(Checkpoints::IsCheckpointedAncestor(cpsBad, mapIndex, c[0]));
    BOOST_CHECK(!Checkpoints::IsCheckpointedAncestor(cpsBad, mapIndex, c[1]));
    BOOST_CHECK(!Checkpoints::IsCheckpointedAncestor(Checkpoints::MapCheckpoints(), mapIndex, c[0]));

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

static std::vector<uint256> FetchRun(uint64_t nFirst, size_t n)
{
    std::vector<uint256> v;
    for (size_t i = 0; i < n; i++)
        v.push_back(uint256(nFirst + i));
    return v;
}

BOOST_AUTO_TEST_CASE(header_fetch_run_appends_at_the_tail_and_replaces_from_the_index)
{
    std::vector<uint256> vQueue;
    size_t nNext = 0;
    int nTail = -1;
    const std::vector<uint256> vFirst = FetchRun(0x5f0001ull, 2000);
    BOOST_CHECK(MergeHeaderFetchRun(vQueue, nNext, nTail, uint256((uint64_t)7), true, vFirst, 2100));
    BOOST_CHECK_EQUAL(vQueue.size(), 2000u);
    BOOST_CHECK_EQUAL(nTail, 2100);

    // Linked at the tail: appended, the cursor kept.
    nNext = 10;
    const std::vector<uint256> vNext = FetchRun(0x6f0001ull, 500);
    BOOST_CHECK(MergeHeaderFetchRun(vQueue, nNext, nTail, vFirst.back(), false, vNext, 2600));
    BOOST_CHECK_EQUAL(vQueue.size(), 2500u);
    BOOST_CHECK_EQUAL(nNext, 10u);
    BOOST_CHECK(vQueue.back() == vNext.back());
    BOOST_CHECK_EQUAL(nTail, 2600);

    // Neither linked nor rooted in the index while entries remain: refused, queue unchanged.
    const std::vector<uint256> vLoose = FetchRun(0x7f0001ull, 5);
    BOOST_CHECK(!MergeHeaderFetchRun(vQueue, nNext, nTail, uint256((uint64_t)9), false, vLoose, 3000));
    BOOST_CHECK_EQUAL(vQueue.size(), 2500u);
    BOOST_CHECK_EQUAL(nTail, 2600);

    // Rooted in the index: the peer's current chain replaces the queue.
    BOOST_CHECK(MergeHeaderFetchRun(vQueue, nNext, nTail, uint256((uint64_t)9), true, vLoose, 3000));
    BOOST_CHECK_EQUAL(vQueue.size(), 5u);
    BOOST_CHECK_EQUAL(nNext, 0u);
    BOOST_CHECK_EQUAL(nTail, 3000);

    // A shorter run from the index, such as a side branch, leaves the queue in place.
    const std::vector<uint256> vSide = FetchRun(0x8f0001ull, 3);
    BOOST_CHECK(!MergeHeaderFetchRun(vQueue, nNext, nTail, uint256((uint64_t)13), true, vSide, 2990));
    BOOST_CHECK_EQUAL(vQueue.size(), 5u);
    BOOST_CHECK_EQUAL(nTail, 3000);

    // A drained queue takes any run.
    nNext = vQueue.size();
    BOOST_CHECK(MergeHeaderFetchRun(vQueue, nNext, nTail, uint256((uint64_t)11), false, vFirst, 5000));
    BOOST_CHECK_EQUAL(vQueue.size(), 2000u);
    BOOST_CHECK_EQUAL(nNext, 0u);
}

BOOST_AUTO_TEST_CASE(header_fetch_queue_is_bounded_and_compacted)
{
    std::vector<uint256> vQueue = FetchRun(0x100001ull, 2000);
    size_t nNext = 0;
    int nTail = 2000;
    // A run that would put more than the cap ahead of the cursor is refused.
    const std::vector<uint256> vMore = FetchRun(0x200001ull, 2000);
    BOOST_CHECK(MergeHeaderFetchRun(vQueue, nNext, nTail, vQueue.back(), false, vMore, 4000));
    const std::vector<uint256> vOver = FetchRun(0x300001ull, 2000);
    BOOST_CHECK(!MergeHeaderFetchRun(vQueue, nNext, nTail, vQueue.back(), false, vOver, 6000));
    BOOST_CHECK_EQUAL(vQueue.size(), 4000u);

    // Held entries before the cursor are dropped once past the compaction mark.
    nNext = 3000;
    const uint256 hashAtCursor = vQueue[nNext];
    BOOST_CHECK(MergeHeaderFetchRun(vQueue, nNext, nTail, vQueue.back(), false, vOver, 6000));
    BOOST_CHECK_EQUAL(nNext, 0u);
    BOOST_CHECK(vQueue.front() == hashAtCursor);
    BOOST_CHECK_EQUAL(vQueue.size(), 3000u);
    BOOST_CHECK_EQUAL(nTail, 6000);
}

BOOST_AUTO_TEST_CASE(header_fetch_extends_below_the_refill_mark_while_the_peer_is_ahead)
{
    const int64_t nNow = 1000000;
    BOOST_CHECK(ShouldExtendHeaderFetch(2000, 1500, 2000, 9000, false, nNow - 5, nNow));
    BOOST_CHECK(!ShouldExtendHeaderFetch(2000, 100, 2000, 9000, false, nNow - 5, nNow));
    BOOST_CHECK(!ShouldExtendHeaderFetch(2000, 1500, 2000, 2000, false, nNow - 5, nNow));
    BOOST_CHECK(!ShouldExtendHeaderFetch(2000, 1500, 2000, 9000, true, nNow - 5, nNow));
    BOOST_CHECK(!ShouldExtendHeaderFetch(0, 0, -1, 9000, false, nNow - 5, nNow));
    // At most once a second, drained or not.
    BOOST_CHECK(!ShouldExtendHeaderFetch(2000, 2000, 2000, 9000, false, nNow, nNow));
    BOOST_CHECK(ShouldExtendHeaderFetch(2000, 2000, 2000, 9000, false, nNow - 1, nNow));
}

BOOST_AUTO_TEST_CASE(getblocks_is_the_fallback_only_after_an_unanswered_getheaders)
{
    const int64_t nNow = 1000000;
    BOOST_CHECK(!HeadersRequestUnanswered(false, nNow - 100, nNow));
    BOOST_CHECK(!HeadersRequestUnanswered(true, nNow - HEADERS_REPLY_WAIT, nNow));
    BOOST_CHECK(HeadersRequestUnanswered(true, nNow - HEADERS_REPLY_WAIT - 1, nNow));
    BOOST_CHECK(HeadersRequestOpen(true, nNow - HEADERS_REPLY_WAIT, nNow));
    BOOST_CHECK(!HeadersRequestOpen(true, nNow - HEADERS_REPLY_WAIT - 1, nNow));
    BOOST_CHECK(!HeadersRequestOpen(false, nNow, nNow));
}

BOOST_AUTO_TEST_CASE(expired_requests_release_only_this_peers_ask_record)
{
    const int64_t nNow = GetTime();
    Peer peer;
    const uint256 hashOwn((uint64_t)0x5e0001ull);
    const uint256 hashRetaken((uint64_t)0x5e0002ull);
    const uint256 hashFresh((uint64_t)0x5e0003ull);
    const uint256 hashOther((uint64_t)0x5e0004ull);
    const int64_t nOld = nNow - 100;
    peer.node.setBlocksInFlight.insert(hashOwn);
    peer.node.mapBlockInFlightSince[hashOwn] = nOld;
    peer.node.setBlocksInFlight.insert(hashRetaken);
    peer.node.mapBlockInFlightSince[hashRetaken] = nOld;
    peer.node.setBlocksInFlight.insert(hashFresh);
    peer.node.mapBlockInFlightSince[hashFresh] = nNow;
    {
        LOCK(cs_mapAlreadyAskedFor);
        mapAlreadyAskedFor[CInv(MSG_BLOCK, hashOwn)] = nOld * 1000000;
        // Asked again by another peer after this one.
        mapAlreadyAskedFor[CInv(MSG_BLOCK, hashRetaken)] = (nNow - 2) * 1000000;
        mapAlreadyAskedFor[CInv(MSG_BLOCK, hashFresh)] = nNow * 1000000;
        mapAlreadyAskedFor[CInv(MSG_BLOCK, hashOther)] = nOld * 1000000;
    }
    peer.node.ExpireBlockInFlight(nNow, 15);
    BOOST_CHECK_EQUAL(peer.node.vExpiredBlockRequests.size(), 2u);
    BOOST_CHECK(peer.node.setBlocksInFlight.count(hashFresh));
    ReleaseExpiredBlockRequests(&peer.node);
    BOOST_CHECK(peer.node.vExpiredBlockRequests.empty());
    {
        LOCK(cs_mapAlreadyAskedFor);
        BOOST_CHECK(!mapAlreadyAskedFor.count(CInv(MSG_BLOCK, hashOwn)));
        BOOST_CHECK(mapAlreadyAskedFor.count(CInv(MSG_BLOCK, hashRetaken)));
        BOOST_CHECK(mapAlreadyAskedFor.count(CInv(MSG_BLOCK, hashFresh)));
        // Another peer's stale record is not this peer's to clear.
        BOOST_CHECK(mapAlreadyAskedFor.count(CInv(MSG_BLOCK, hashOther)));
        mapAlreadyAskedFor.erase(CInv(MSG_BLOCK, hashRetaken));
        mapAlreadyAskedFor.erase(CInv(MSG_BLOCK, hashFresh));
        mapAlreadyAskedFor.erase(CInv(MSG_BLOCK, hashOther));
    }
}

BOOST_AUTO_TEST_CASE(stale_block_ask_records_are_pruned_and_fresh_ones_kept)
{
    const int64_t nNowUs = GetTime() * 1000000;
    const int64_t nTimeoutUs = CNode::BlockInFlightTimeout() * 1000000;
    const CInv invOld(MSG_BLOCK, uint256((uint64_t)0x5d0001ull));
    const CInv invFresh(MSG_BLOCK, uint256((uint64_t)0x5d0002ull));
    const CInv invLater(MSG_BLOCK, uint256((uint64_t)0x5d0003ull));
    const CInv invTx(MSG_TX, uint256((uint64_t)0x5d0004ull));
    const CInv invFar(MSG_BLOCK, uint256((uint64_t)0x5d0005ull));
    {
        LOCK(cs_mapAlreadyAskedFor);
        mapAlreadyAskedFor[invOld] = nNowUs - nTimeoutUs - 1000000;
        mapAlreadyAskedFor[invFresh] = nNowUs - 1000000;
        mapAlreadyAskedFor[invLater] = nNowUs + 5 * 1000000;
        mapAlreadyAskedFor[invFar] = nNowUs + nTimeoutUs + 1000000;
        mapAlreadyAskedFor[invTx] = nNowUs - nTimeoutUs - 1000000;
    }
    PruneStaleBlockAskRecords(nNowUs);
    LOCK(cs_mapAlreadyAskedFor);
    BOOST_CHECK(!mapAlreadyAskedFor.count(invOld));
    BOOST_CHECK(mapAlreadyAskedFor.count(invFresh));
    BOOST_CHECK(mapAlreadyAskedFor.count(invLater));
    BOOST_CHECK(!mapAlreadyAskedFor.count(invFar));
    BOOST_CHECK(mapAlreadyAskedFor.count(invTx));
    mapAlreadyAskedFor.erase(invFresh);
    mapAlreadyAskedFor.erase(invLater);
    mapAlreadyAskedFor.erase(invTx);
}

BOOST_AUTO_TEST_CASE(peer_stats_do_not_expire_in_flight_requests)
{
    Peer peer;
    const uint256 hash((uint64_t)0x5d0011ull);
    peer.node.setBlocksInFlight.insert(hash);
    peer.node.mapBlockInFlightSince[hash] = GetTime() - 1000;
    CNodeStats stats;
    peer.node.copyStats(stats);
    BOOST_CHECK_EQUAL(stats.nBlocksInFlight, 1);
    BOOST_CHECK(peer.node.vExpiredBlockRequests.empty());
    BOOST_CHECK(peer.node.setBlocksInFlight.count(hash));
}

BOOST_AUTO_TEST_SUITE_END()
