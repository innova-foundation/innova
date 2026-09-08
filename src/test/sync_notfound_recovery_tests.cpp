// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Sync recovery: a notfound frees the in-flight slot, records the decline and re-queues
// the hash on other announcers.

#include <boost/test/unit_test.hpp>

#include "main.h"
#include "net.h"
#include "protocol.h"
#include "util.h"

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

// Defined in main.cpp. Declared here rather than in main.h: the record is
// private to the two request paths that read it, and these are its test hooks.
void MarkBlockDeclinedByPeer(NodeId id, const uint256& hash, int64_t nNow);
bool IsBlockDeclinedByPeer(NodeId id, const uint256& hash, int64_t nNow);
size_t GetBlocksDeclinedByPeerCount(NodeId id);
size_t GetBlockDeclinePeerCount();
void ClearBlockDeclineRecords();

BOOST_AUTO_TEST_SUITE(sync_notfound_recovery_tests)

namespace {

// Past every -blockinflighttimeout clamp, so a decline is lapsed at this offset
// whatever the argument says.
const int64_t nPastAnyTimeout = 601;

// A peer with a send buffer but no socket: framed bytes stay readable in vSendMsg and
// the failed write raises fDisconnect. Routable address so Misbehaving scores apply;
// ports are unique because the stall throttle is keyed on addrName.
struct TestPeer
{
    CNode node;

    explicit TestPeer(int nPort)
        : node(INVALID_SOCKET, CAddress(CService("203.0.113.7", nPort)), "", false)
    {
        node.nVersion = PROTOCOL_VERSION;
        node.nPingNonceSent = 1;          // no ping on a dead socket
        node.fStartSync = false;          // no getblocks of our own
        node.nLastBlockRecv = GetTime();  // no stall recovery unless asked for
        node.fPreferHeaders = true;
    }
};

// No block from this peer for longer than the recovery gate's 15 s.
void Stall(TestPeer& peer)
{
    peer.node.nLastBlockRecv = GetTime() - 20;
}

// SendMessages on a socketless peer frames its getdata and then fails the send,
// which raises fDisconnect, and ProcessMessages skips a peer with the flag up.
// The flag is the fixture's, not the path under test, so it is cleared here.
bool Flush(TestPeer& peer)
{
    const bool fOk = SendMessages(&peer.node, false);
    peer.node.fDisconnect = false;
    return fOk;
}

// main.h defines a MESSAGE_START_SIZE macro that shadows the enum member of
// that name, so reach the command offset through the members it leaves alone.
const size_t nCommandOffset =
    (size_t)CMessageHeader::MESSAGE_SIZE_OFFSET - (size_t)CMessageHeader::COMMAND_SIZE;

std::string CommandOf(const CSerializeData& data)
{
    if (data.size() < (size_t)CMessageHeader::HEADER_SIZE)
        return std::string();
    const char* pszCommand = &data[nCommandOffset];
    size_t nLen = 0;
    while (nLen < (size_t)CMessageHeader::COMMAND_SIZE && pszCommand[nLen] != '\0')
        nLen++;
    return std::string(pszCommand, nLen);
}

unsigned int CountCommand(CNode& node, const std::string& strWant)
{
    unsigned int n = 0;
    LOCK(node.cs_vSend);
    for (const CSerializeData& data : node.vSendMsg)
        if (CommandOf(data) == strWant)
            n++;
    return n;
}

std::set<uint256> QueuedBlockHashes(const CNode& node)
{
    std::set<uint256> setQueued;
    for (std::multimap<int64_t, CInv>::const_iterator it = node.mapAskFor.begin();
         it != node.mapAskFor.end(); ++it)
        if (it->second.type == MSG_BLOCK || it->second.type == MSG_FILTERED_BLOCK)
            setQueued.insert(it->second.hash);
    return setQueued;
}

// Frame a message through a scratch sender and dispatch it to `receiver` as
// coming from that peer, the way the socket thread would.
template <typename T>
void Deliver(TestPeer& receiver, const char* pszCommand, const T& payload)
{
    TestPeer scratch(1);
    scratch.node.PushMessage(pszCommand, payload);
    CSerializeData data;
    {
        LOCK(scratch.node.cs_vSend);
        BOOST_REQUIRE(!scratch.node.vSendMsg.empty());
        data = scratch.node.vSendMsg.back();
    }
    BOOST_REQUIRE(receiver.node.ReceiveMsgBytes(&data[0], (unsigned int)data.size()));
    LOCK(receiver.node.cs_vRecvMsg);
    BOOST_REQUIRE(ProcessMessages(&receiver.node));
}

void DeliverNotFound(TestPeer& receiver, const std::vector<CInv>& vInv)
{
    Deliver(receiver, "notfound", vInv);
}

// The notfound handler walks vNodes for the re-ask, so a peer that should be
// re-asked has to be listed there for the duration of a case.
struct ScopedVNodes
{
    std::vector<CNode*> vJoined;

    void Join(CNode& node)
    {
        LOCK(cs_vNodes);
        vNodes.push_back(&node);
        vJoined.push_back(&node);
    }

    ~ScopedVNodes()
    {
        LOCK(cs_vNodes);
        for (size_t i = 0; i < vJoined.size(); i++)
            vNodes.erase(std::remove(vNodes.begin(), vNodes.end(), vJoined[i]), vNodes.end());
    }
};

// Saves, clears and restores every table these cases touch, and pins GetTime() at or
// past AskFor's process-wide floor (read through a probe ask), which earlier suites may
// have advanced.
class CScopedSyncState
{
    std::map<uint256, COrphanBlock> savedBlocks;
    std::multimap<uint256, CBlock*> savedByPrev;
    std::map<uint256, NodeId> savedByNode;
    std::map<NodeId, int> savedCount;
    std::map<CInv, int64_t> savedAsked;

public:
    CScopedSyncState()
    {
        {
            LOCK(cs_main);
            savedBlocks = mapOrphanBlocks;
            savedByPrev = mapOrphanBlocksByPrev;
            savedByNode = mapOrphanBlocksByNode;
            savedCount = mapOrphanCountByNode;
            mapOrphanBlocks.clear();
            mapOrphanBlocksByPrev.clear();
            mapOrphanBlocksByNode.clear();
            mapOrphanCountByNode.clear();
            ClearOrphanRefusalRecords();
            ClearOrphanDepartedOwners();
            ClearOrphanBlockRequestSuppression();
            RecomputeOrphanBlocksFootprint();
            RecomputeOrphanGaps();
        }
        {
            LOCK(cs_mapAlreadyAskedFor);
            savedAsked = mapAlreadyAskedFor;
            mapAlreadyAskedFor.clear();
        }
        ClearBlockDeclineRecords();
        {
            CNode probe(INVALID_SOCKET, CAddress(), "", false);
            const CInv invProbe(MSG_BLOCK, uint256((uint64_t)0x6e000001ull));
            probe.AskFor(invProbe);
            BOOST_REQUIRE_EQUAL(probe.mapAskFor.size(), 1U);
            const int64_t nFloor = probe.mapAskFor.begin()->first / 1000000 + 1;
            {
                LOCK(cs_mapAlreadyAskedFor);
                mapAlreadyAskedFor.erase(invProbe);
            }
            SetMockTime(std::max(GetTime(), nFloor));
        }
    }
    ~CScopedSyncState()
    {
        SetMockTime(0);
        {
            LOCK(cs_main);
            for (std::map<uint256, COrphanBlock>::iterator it = mapOrphanBlocks.begin();
                 it != mapOrphanBlocks.end(); ++it)
                delete it->second.pblock;
            mapOrphanBlocks = savedBlocks;
            mapOrphanBlocksByPrev = savedByPrev;
            mapOrphanBlocksByNode = savedByNode;
            mapOrphanCountByNode = savedCount;
            ClearOrphanRefusalRecords();
            ClearOrphanDepartedOwners();
            ClearOrphanBlockRequestSuppression();
            RecomputeOrphanBlocksFootprint();
            RecomputeOrphanGaps();
        }
        {
            LOCK(cs_mapAlreadyAskedFor);
            mapAlreadyAskedFor = savedAsked;
        }
        ClearBlockDeclineRecords();
    }
};

CBlock* SyntheticOrphan(unsigned int nSeed, const uint256& hashPrev)
{
    CBlock* pblock = new CBlock();
    pblock->nVersion = CBlock::CURRENT_VERSION;
    pblock->hashPrevBlock = hashPrev;
    pblock->hashMerkleRoot = uint256((uint64_t)nSeed + 1);
    pblock->nTime = 1000 + nSeed;
    pblock->nBits = 0x1d00ffff;
    pblock->nNonce = nSeed;
    return pblock;
}

// Park nCount synthetic orphans for owner, chained above hashGap, and publish
// the gap so the owner is gated on hashGap.
void ParkChain(unsigned int nSeedBase, const uint256& hashGap, unsigned int nCount, NodeId owner)
{
    LOCK(cs_main);
    uint256 hashPrev = hashGap;
    for (unsigned int i = 0; i < nCount; i++)
    {
        CBlock* pblock = SyntheticOrphan(nSeedBase + i, hashPrev);
        const uint256 hash = pblock->GetHash();
        BOOST_REQUIRE(AddOrphanBlock(hash, pblock, hashPrev, owner, OrphanBlockFootprint(*pblock)));
        hashPrev = hash;
    }
    RecomputeOrphanGaps();
}

CBlockIndex* AttachIndex(CBlockIndex* pprev, int nHeight, const uint256& hash)
{
    CBlockIndex* pindex = new CBlockIndex();
    pindex->pprev = pprev;
    pindex->nHeight = nHeight;
    std::pair<std::map<uint256, CBlockIndex*>::iterator, bool> ins =
        mapBlockIndex.insert(std::make_pair(hash, pindex));
    BOOST_REQUIRE(ins.second);
    pindex->phashBlock = &ins.first->first;
    return pindex;
}

// A block this node holds off its main chain: no pnext, not pindexBest.
struct ScopedSideIndex
{
    uint256 hash;
    CBlockIndex* pindex;

    ScopedSideIndex(CBlockIndex* pprev, int nHeight, uint64_t nSeed, bool fFailed = false)
        : hash(nSeed)
    {
        LOCK(cs_main);
        pindex = AttachIndex(pprev, nHeight, hash);
        if (fFailed)
            pindex->SetFailedValid();
    }

    ~ScopedSideIndex()
    {
        LOCK(cs_main);
        mapBlockIndex.erase(hash);
        delete pindex;
    }
};

// Two synthetic blocks on top of the real tip, so there is a main-chain block
// below the tip to place a behind peer on whatever height the shared database
// has reached. Everything the recovery path reads is restored on exit.
struct ScopedChainExtension
{
    CBlockIndex* pRealBest;
    int nRealHeight;
    uint256 hashF1, hashF2;
    CBlockIndex* pF1;
    CBlockIndex* pF2;

    explicit ScopedChainExtension(uint64_t nSeed)
        : hashF1(nSeed), hashF2(nSeed + 1)
    {
        LOCK(cs_main);
        BOOST_REQUIRE(pindexBest != NULL);
        pRealBest = pindexBest;
        nRealHeight = nBestHeight;
        pF1 = AttachIndex(pRealBest, pRealBest->nHeight + 1, hashF1);
        pF2 = AttachIndex(pF1, pF1->nHeight + 1, hashF2);
        pRealBest->pnext = pF1;
        pF1->pnext = pF2;
        pindexBest = pF2;
        nBestHeight = pF2->nHeight;
    }

    ~ScopedChainExtension()
    {
        LOCK(cs_main);
        pindexBest = pRealBest;
        nBestHeight = nRealHeight;
        pRealBest->pnext = NULL;
        mapBlockIndex.erase(hashF1);
        mapBlockIndex.erase(hashF2);
        delete pF1;
        delete pF2;
    }

    int Height() const { return pF2->nHeight; }
};

// The peer reports nHeight and its best-known block is hash.
void SetPeerView(TestPeer& peer, int nHeight, const uint256& hash)
{
    peer.node.nChainHeight = nHeight;
    peer.node.UpdateBestKnownBlock(nHeight, hash);
}

} // namespace

// ---------------------------------------------------------------------------
// notfound

// The slot is freed on the answer, not at the timeout, and the answer is not
// scored: a peer that lacks a block is not misbehaving.
BOOST_AUTO_TEST_CASE(notfound_frees_the_in_flight_slot_at_once)
{
    CScopedSyncState state;
    TestPeer peer(21101);
    const CInv inv(MSG_BLOCK, uint256((uint64_t)0x6e010001ull));

    peer.node.AskFor(inv);
    BOOST_REQUIRE(Flush(peer));
    BOOST_REQUIRE(peer.node.setBlocksInFlight.count(inv.hash) == 1);
    BOOST_REQUIRE_EQUAL(CountCommand(peer.node, "getdata"), 1U);

    DeliverNotFound(peer, std::vector<CInv>(1, inv));

    BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.count(inv.hash) == 0,
                        "the declined hash is still in flight");
    BOOST_CHECK_EQUAL(peer.node.mapBlockInFlightSince.count(inv.hash), 0U);
    BOOST_CHECK_EQUAL(peer.node.nMisbehavior, 0);
    BOOST_CHECK(!peer.node.fDisconnect);
    BOOST_CHECK(IsBlockDeclinedByPeer(peer.node.GetId(), inv.hash, GetTime()));
}

// Another announcer is re-asked immediately (its fallback ask is a second out and the
// clock is pinned); the declining peer is not.
BOOST_AUTO_TEST_CASE(a_freed_hash_is_re_requested_from_a_peer_that_announced_it)
{
    CScopedSyncState state;
    ScopedVNodes nodes;
    TestPeer decliner(21102), announcer(21103);
    nodes.Join(decliner.node);
    nodes.Join(announcer.node);
    const CInv inv(MSG_BLOCK, uint256((uint64_t)0x6e020001ull));
    decliner.node.AddInventoryKnown(inv);
    announcer.node.AddInventoryKnown(inv);

    decliner.node.AskFor(inv);
    BOOST_REQUIRE(Flush(decliner));
    BOOST_REQUIRE(decliner.node.setBlocksInFlight.count(inv.hash) == 1);
    // The announcer's own ask, queued a second behind the request just sent.
    announcer.node.AskFor(inv);
    BOOST_REQUIRE_EQUAL(announcer.node.mapAskFor.size(), 1U);

    DeliverNotFound(decliner, std::vector<CInv>(1, inv));

    BOOST_REQUIRE(Flush(announcer));
    BOOST_CHECK_MESSAGE(announcer.node.setBlocksInFlight.count(inv.hash) == 1,
                        "the freed hash was not requested from the announcing peer");
    BOOST_CHECK_EQUAL(CountCommand(announcer.node, "getdata"), 1U);

    BOOST_CHECK_EQUAL(QueuedBlockHashes(decliner.node).count(inv.hash), 0U);
    BOOST_REQUIRE(Flush(decliner));
    BOOST_CHECK_MESSAGE(decliner.node.setBlocksInFlight.count(inv.hash) == 0,
                        "the declining peer was asked again");
    BOOST_CHECK_EQUAL(CountCommand(decliner.node, "getdata"), 1U);
}

// A declined hash is not re-asked of that peer for the timeout, so two peers lacking it
// cannot pass it back and forth.
BOOST_AUTO_TEST_CASE(a_peer_that_declined_a_hash_is_not_asked_for_it_again)
{
    CScopedSyncState state;
    ScopedVNodes nodes;
    TestPeer first(21104), second(21105);
    nodes.Join(first.node);
    nodes.Join(second.node);
    const CInv inv(MSG_BLOCK, uint256((uint64_t)0x6e030001ull));
    first.node.AddInventoryKnown(inv);
    second.node.AddInventoryKnown(inv);

    first.node.AskFor(inv);
    BOOST_REQUIRE(Flush(first));
    BOOST_REQUIRE(first.node.setBlocksInFlight.count(inv.hash) == 1);
    DeliverNotFound(first, std::vector<CInv>(1, inv));
    BOOST_REQUIRE(Flush(second));
    BOOST_REQUIRE(second.node.setBlocksInFlight.count(inv.hash) == 1);

    DeliverNotFound(second, std::vector<CInv>(1, inv));

    BOOST_CHECK_EQUAL(second.node.setBlocksInFlight.count(inv.hash), 0U);
    BOOST_CHECK_MESSAGE(QueuedBlockHashes(first.node).count(inv.hash) == 0,
                        "the first decliner was re-asked on the second decline");
    BOOST_REQUIRE(Flush(first));
    BOOST_CHECK_EQUAL(first.node.setBlocksInFlight.count(inv.hash), 0U);
    BOOST_CHECK_EQUAL(CountCommand(first.node, "getdata"), 1U);
    BOOST_CHECK_EQUAL(GetBlocksDeclinedByPeerCount(first.node.GetId()), 1U);
    BOOST_CHECK_EQUAL(GetBlocksDeclinedByPeerCount(second.node.GetId()), 1U);
}

// The gap path re-asks every pass; the decline holds the peer off for the timeout,
// after which the ask returns on its own.
BOOST_AUTO_TEST_CASE(a_declined_gap_root_waits_out_the_timeout_on_that_peer)
{
    CScopedSyncState state;
    TestPeer peer(21106);
    const NodeId owner = peer.node.GetId();
    const uint256 hashGap((uint64_t)0x6e040001ull);
    ParkChain(64100, hashGap, 3, owner);
    BOOST_REQUIRE(IsOrphanGapGatedPeer(owner));
    BOOST_REQUIRE(IsOrphanGapHashForPeer(owner, hashGap));

    BOOST_REQUIRE(Flush(peer));
    BOOST_REQUIRE(peer.node.setBlocksInFlight.count(hashGap) == 1);
    BOOST_REQUIRE_EQUAL(CountCommand(peer.node, "getdata"), 1U);

    DeliverNotFound(peer, std::vector<CInv>(1, CInv(MSG_BLOCK, hashGap)));
    BOOST_REQUIRE_EQUAL(peer.node.setBlocksInFlight.count(hashGap), 0U);

    BOOST_REQUIRE(Flush(peer));
    BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.count(hashGap) == 0,
                        "the gap path re-asked the declining peer on the next pass");
    BOOST_CHECK_EQUAL(CountCommand(peer.node, "getdata"), 1U);

    // Lapsed: the record is dropped on the read and the next pass asks again.
    BOOST_CHECK(IsBlockDeclinedByPeer(owner, hashGap, GetTime()));
    BOOST_CHECK(!IsBlockDeclinedByPeer(owner, hashGap, GetTime() + nPastAnyTimeout));
    BOOST_REQUIRE(Flush(peer));
    BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.count(hashGap) == 1,
                        "the gap root was not asked again once the decline lapsed");
    BOOST_CHECK_EQUAL(CountCommand(peer.node, "getdata"), 2U);
}

// A hash the peer was never asked for frees nothing, records nothing and
// re-queues nothing: a peer cannot use notfound to make this node request
// arbitrary hashes from everyone that announced them.
BOOST_AUTO_TEST_CASE(a_notfound_for_a_hash_not_in_flight_changes_nothing)
{
    CScopedSyncState state;
    ScopedVNodes nodes;
    TestPeer peer(21107), announcer(21108);
    nodes.Join(announcer.node);
    const CInv inv(MSG_BLOCK, uint256((uint64_t)0x6e050001ull));
    announcer.node.AddInventoryKnown(inv);

    DeliverNotFound(peer, std::vector<CInv>(1, inv));

    BOOST_CHECK_EQUAL(announcer.node.mapAskFor.size(), 0U);
    BOOST_CHECK_EQUAL(GetBlocksDeclinedByPeerCount(peer.node.GetId()), 0U);
    BOOST_CHECK(!IsBlockDeclinedByPeer(peer.node.GetId(), inv.hash, GetTime()));
    BOOST_CHECK_EQUAL(peer.node.nMisbehavior, 0);
}

// The inv and getdata cap applies, so the work a notfound can demand is bounded
// by the message cap before the in-flight filter bounds it by the window. Over
// the cap the message is dropped whole and, unlike inv, not scored.
BOOST_AUTO_TEST_CASE(an_oversized_notfound_is_dropped_whole)
{
    CScopedSyncState state;
    TestPeer peer(21109);
    const CInv inv(MSG_BLOCK, uint256((uint64_t)0x6e060001ull));
    peer.node.MarkBlockInFlight(inv.hash);

    std::vector<CInv> vInv;
    vInv.reserve(MAX_INV_SZ + 1);
    vInv.push_back(inv);
    for (unsigned int i = 1; i <= MAX_INV_SZ; i++)
        vInv.push_back(CInv(MSG_BLOCK, uint256((uint64_t)0x6e060000ull + 0x1000ull + i)));
    BOOST_REQUIRE_EQUAL(vInv.size(), (size_t)MAX_INV_SZ + 1);

    DeliverNotFound(peer, vInv);
    BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.count(inv.hash) == 1,
                        "an oversized notfound was acted on");
    BOOST_CHECK_EQUAL(peer.node.nMisbehavior, 0);
    BOOST_CHECK(!peer.node.fDisconnect);

    // At the cap the message is ordinary.
    vInv.resize(MAX_INV_SZ);
    DeliverNotFound(peer, vInv);
    BOOST_CHECK_EQUAL(peer.node.setBlocksInFlight.count(inv.hash), 0U);
}

// The decline record is a memory bound of two windows per peer: past it the
// oldest entry goes, so a peer that declines everything it is asked cannot grow
// the record with the hashes it declines.
BOOST_AUTO_TEST_CASE(the_decline_record_is_bounded_per_peer)
{
    CScopedSyncState state;
    TestPeer peer(21110);
    const NodeId id = peer.node.GetId();

    for (unsigned int round = 0; round < 3; round++)
    {
        std::vector<CInv> vInv;
        for (unsigned int i = 0; i < MAX_BLOCKS_IN_FLIGHT_PER_PEER; i++)
        {
            const CInv inv(MSG_BLOCK, uint256((uint64_t)0x6e070000ull + round * 0x1000ull + i));
            peer.node.MarkBlockInFlight(inv.hash);
            vInv.push_back(inv);
        }
        DeliverNotFound(peer, vInv);
        BOOST_REQUIRE(peer.node.setBlocksInFlight.empty());
    }

    BOOST_CHECK_EQUAL(GetBlocksDeclinedByPeerCount(id), 2 * MAX_BLOCKS_IN_FLIGHT_PER_PEER);
}

// A peer whose declines have all lapsed is dropped from the record on the next
// write, so a departed peer holds no entry past one timeout.
BOOST_AUTO_TEST_CASE(lapsed_decline_records_are_swept)
{
    CScopedSyncState state;
    const NodeId idGone = 900001, idLive = 900002;
    const uint256 hashA((uint64_t)0x6e080001ull), hashB((uint64_t)0x6e080002ull);
    const int64_t nBase = GetTime();

    MarkBlockDeclinedByPeer(idGone, hashA, nBase);
    BOOST_REQUIRE_EQUAL(GetBlockDeclinePeerCount(), 1U);

    MarkBlockDeclinedByPeer(idLive, hashB, nBase + nPastAnyTimeout);

    BOOST_CHECK_EQUAL(GetBlockDeclinePeerCount(), 1U);
    BOOST_CHECK(IsBlockDeclinedByPeer(idLive, hashB, nBase + nPastAnyTimeout));
    BOOST_CHECK(!IsBlockDeclinedByPeer(idGone, hashA, nBase + nPastAnyTimeout));
}

// ---------------------------------------------------------------------------
// headers round

// Equal height, best-known block held off our main chain: a headers round goes
// out. Nothing else does -- no getblocks and no ask-record reset, which are for
// a height gap.
BOOST_AUTO_TEST_CASE(an_equal_height_peer_off_our_chain_gets_a_headers_round)
{
    CScopedSyncState state;
    ScopedChainExtension chain(0x6e090001ull);
    ScopedSideIndex side(chain.pF1, chain.Height(), 0x6e090011ull);
    TestPeer peer(21111);
    SetPeerView(peer, chain.Height(), side.hash);
    Stall(peer);
    const CInv invSeed(MSG_BLOCK, uint256((uint64_t)0x6e090021ull));
    {
        LOCK(cs_mapAlreadyAskedFor);
        mapAlreadyAskedFor[invSeed] = 1;
    }

    BOOST_REQUIRE(SendMessages(&peer.node, false));

    BOOST_CHECK_MESSAGE(CountCommand(peer.node, "getheaders") == 1U,
                        "an equal-height peer on another chain got no headers round");
    BOOST_CHECK_EQUAL(CountCommand(peer.node, "getblocks"), 0U);
    LOCK(cs_mapAlreadyAskedFor);
    BOOST_CHECK_MESSAGE(mapAlreadyAskedFor.count(invSeed) == 1,
                        "the equal-height round reset the block ask records");
}

// Behind us, best-known block on our main chain: the existing announcement,
// and no headers round.
BOOST_AUTO_TEST_CASE(a_peer_behind_us_on_our_chain_gets_no_headers_round)
{
    CScopedSyncState state;
    ScopedChainExtension chain(0x6e0a0001ull);
    TestPeer peer(21112);
    SetPeerView(peer, chain.pF1->nHeight, chain.hashF1);
    Stall(peer);

    BOOST_REQUIRE(SendMessages(&peer.node, false));

    BOOST_CHECK_EQUAL(CountCommand(peer.node, "headers"), 1U);
    BOOST_CHECK_MESSAGE(CountCommand(peer.node, "getheaders") == 0U,
                        "a peer behind us on our own chain was sent a headers round");
}

// Behind us, best-known block on a branch we hold but do not follow: the
// announcement as before, and now the headers round too. This is the joiner
// parked on a longer side branch than the peer's tip.
BOOST_AUTO_TEST_CASE(a_peer_behind_us_on_a_side_branch_gets_a_headers_round)
{
    CScopedSyncState state;
    ScopedChainExtension chain(0x6e0b0001ull);
    ScopedSideIndex side(chain.pRealBest, chain.pF1->nHeight, 0x6e0b0011ull);
    TestPeer peer(21113);
    SetPeerView(peer, chain.pF1->nHeight, side.hash);
    Stall(peer);

    BOOST_REQUIRE(SendMessages(&peer.node, false));

    BOOST_CHECK_EQUAL(CountCommand(peer.node, "headers"), 1U);
    BOOST_CHECK_MESSAGE(CountCommand(peer.node, "getheaders") == 1U,
                        "a peer behind us on a side branch got no headers round");
}

// A branch this node has marked invalid is not one to fetch headers for.
BOOST_AUTO_TEST_CASE(a_peer_on_an_invalid_branch_gets_no_headers_round)
{
    CScopedSyncState state;
    ScopedChainExtension chain(0x6e0c0001ull);
    ScopedSideIndex side(chain.pF1, chain.Height(), 0x6e0c0011ull, true);
    TestPeer peer(21114);
    SetPeerView(peer, chain.Height(), side.hash);
    Stall(peer);

    BOOST_REQUIRE(SendMessages(&peer.node, false));

    BOOST_CHECK_EQUAL(CountCommand(peer.node, "getheaders"), 0U);
}

// A best-known hash this node does not hold is not counted as off-chain: the
// headers path that recorded it has asked for the block already, and a new tip
// announcement would otherwise fire a round on every peer at once.
BOOST_AUTO_TEST_CASE(an_unknown_best_known_hash_does_not_trigger_a_round)
{
    CScopedSyncState state;
    BOOST_REQUIRE(pindexBest != NULL);
    TestPeer peer(21115);
    SetPeerView(peer, nBestHeight, uint256((uint64_t)0x6e0d0001ull));
    Stall(peer);

    BOOST_REQUIRE(SendMessages(&peer.node, false));

    BOOST_CHECK_EQUAL(CountCommand(peer.node, "getheaders"), 0U);
}

// The in-flight gate is kept: nothing outstanding to the peer, or no round.
// Deferred, not dropped -- the round goes out once the window drains.
BOOST_AUTO_TEST_CASE(the_off_chain_round_waits_for_the_in_flight_window)
{
    CScopedSyncState state;
    ScopedChainExtension chain(0x6e0e0001ull);
    ScopedSideIndex side(chain.pF1, chain.Height(), 0x6e0e0011ull);
    TestPeer peer(21116);
    SetPeerView(peer, chain.Height(), side.hash);
    Stall(peer);
    const uint256 hashOutstanding((uint64_t)0x6e0e0021ull);
    peer.node.MarkBlockInFlight(hashOutstanding);

    BOOST_REQUIRE(SendMessages(&peer.node, false));
    BOOST_CHECK_MESSAGE(CountCommand(peer.node, "getheaders") == 0U,
                        "a headers round went out with a block still in flight");

    peer.node.ClearBlockInFlight(hashOutstanding);
    BOOST_REQUIRE(SendMessages(&peer.node, false));
    BOOST_CHECK_EQUAL(CountCommand(peer.node, "getheaders"), 1U);
}

// The 15 s throttle is kept: one round per peer per window.
BOOST_AUTO_TEST_CASE(the_off_chain_round_is_throttled)
{
    CScopedSyncState state;
    ScopedChainExtension chain(0x6e0f0001ull);
    ScopedSideIndex side(chain.pF1, chain.Height(), 0x6e0f0011ull);
    TestPeer peer(21117);
    SetPeerView(peer, chain.Height(), side.hash);
    Stall(peer);

    BOOST_REQUIRE(SendMessages(&peer.node, false));
    BOOST_REQUIRE_EQUAL(CountCommand(peer.node, "getheaders"), 1U);
    BOOST_REQUIRE(SendMessages(&peer.node, false));
    BOOST_REQUIRE(SendMessages(&peer.node, false));

    BOOST_CHECK_MESSAGE(CountCommand(peer.node, "getheaders") == 1U,
                        "the off-chain headers round is not throttled");
}

// The peer-ahead round is as it was: getblocks and getheaders together.
BOOST_AUTO_TEST_CASE(a_peer_ahead_still_gets_the_existing_round)
{
    CScopedSyncState state;
    BOOST_REQUIRE(pindexBest != NULL);
    TestPeer peer(21118);
    SetPeerView(peer, nBestHeight + 10, uint256(0));
    Stall(peer);

    BOOST_REQUIRE(SendMessages(&peer.node, false));

    BOOST_CHECK_EQUAL(CountCommand(peer.node, "getblocks"), 1U);
    BOOST_CHECK_EQUAL(CountCommand(peer.node, "getheaders"), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
