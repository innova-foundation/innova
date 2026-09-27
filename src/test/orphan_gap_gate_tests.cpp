// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// While fetching an orphan's unheld ancestors from a peer, this node asks that peer for
// nothing past the gap. Linked last in TEST_OBJS; shares the regtest fixture.

#include <boost/test/unit_test.hpp>

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "../bignum.h"
#include "../init.h"
#include "../main.h"
#include "../miner.h"
#include "../wallet.h"
#include "../net.h"
#include "../util.h"

extern bool fRegTest;

BOOST_AUTO_TEST_SUITE(orphan_gap_gate_tests)

namespace
{

// A peer with a send buffer but no socket, quiet enough to reach the getdata flush. A local
// address is never scored, so scoring cases use a routable one.
struct TestPeer
{
    CNode node;

    explicit TestPeer(int nPort, const char* pszAddr = "127.0.0.1")
        : node(INVALID_SOCKET, CAddress(CService(pszAddr, nPort)), "", false)
    {
        node.nVersion = PROTOCOL_VERSION;
        node.nPingNonceSent = 1;
        node.fStartSync = false;
        node.nLastBlockRecv = GetTime();
    }
};

// Save, clear and restore every table these cases touch.
class CScopedGapState
{
    std::map<uint256, COrphanBlock> savedBlocks;
    std::multimap<uint256, CBlock*> savedByPrev;
    std::map<uint256, NodeId> savedByNode;
    std::map<NodeId, int> savedCount;
    std::map<CInv, int64_t> savedAsked;

public:
    CScopedGapState()
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
        LOCK(cs_mapAlreadyAskedFor);
        savedAsked = mapAlreadyAskedFor;
        mapAlreadyAskedFor.clear();
    }
    ~CScopedGapState()
    {
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
        LOCK(cs_mapAlreadyAskedFor);
        mapAlreadyAskedFor = savedAsked;
    }
};

// Override one -arg for the duration of a case.
class CScopedArg
{
    std::string strName;
    std::string strSaved;
    bool fHad;

public:
    CScopedArg(const std::string& strNameIn, const std::string& strValue)
        : strName(strNameIn)
    {
        fHad = mapArgs.count(strName) != 0;
        if (fHad)
            strSaved = mapArgs[strName];
        mapArgs[strName] = strValue;
    }
    ~CScopedArg()
    {
        if (fHad)
            mapArgs[strName] = strSaved;
        else
            mapArgs.erase(strName);
    }
};

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

// A record with no wire form, parked through the real writer.
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

uint256 ParkSynthetic(unsigned int nSeed, const uint256& hashPrev, NodeId owner)
{
    LOCK(cs_main);
    CBlock* pblock = SyntheticOrphan(nSeed, hashPrev);
    const uint256 hash = pblock->GetHash();
    BOOST_REQUIRE(AddOrphanBlock(hash, pblock, hashPrev, owner, OrphanBlockFootprint(*pblock)));
    return hash;
}

// A chain of nCount parked records rooted at hashGap, oldest first. Every record
// waits on the one below it, so all of them resolve to hashGap.
std::vector<uint256> ParkChain(unsigned int nSeedBase, const uint256& hashGap,
                               unsigned int nCount, NodeId owner)
{
    std::vector<uint256> vHashes;
    uint256 hashPrev = hashGap;
    for (unsigned int i = 0; i < nCount; i++)
    {
        hashPrev = ParkSynthetic(nSeedBase + i, hashPrev, owner);
        vHashes.push_back(hashPrev);
    }
    LOCK(cs_main);
    RecomputeOrphanGaps();
    return vHashes;
}

// A peer's queued block hashes. Asserted directly: AskFor's process-wide static
// request-time floor can defer the flush independently of the enqueue guard.
std::set<uint256> QueuedBlockHashes(const CNode& node)
{
    std::set<uint256> setQueued;
    for (std::multimap<int64_t, CInv>::const_iterator it = node.mapAskFor.begin();
         it != node.mapAskFor.end(); ++it)
        if (it->second.type == MSG_BLOCK || it->second.type == MSG_FILTERED_BLOCK)
            setQueued.insert(it->second.hash);
    return setQueued;
}

void QueueBlockRequest(CNode& node, int64_t nRequestTime, const uint256& hash)
{
    node.mapAskFor.insert(std::make_pair(nRequestTime, CInv(MSG_BLOCK, hash)));
}

// The snapshot recomputed from scratch, for comparison with the published one. Keyed by
// owner: a root belongs to the peer that delivered the waiting record.
std::map<NodeId, std::set<uint256> > ExpectedGaps()
{
    AssertLockHeld(cs_main);
    std::map<NodeId, std::set<uint256> > mapOut;
    for (std::map<uint256, COrphanBlock>::const_iterator it = mapOrphanBlocks.begin();
         it != mapOrphanBlocks.end(); ++it)
    {
        std::map<uint256, NodeId>::const_iterator itOwner = mapOrphanBlocksByNode.find(it->first);
        if (itOwner == mapOrphanBlocksByNode.end() || itOwner->second < 0)
            continue;
        uint256 hashCur = it->first;
        size_t nSteps = 0;
        bool fTerminated = false;
        while (nSteps++ <= mapOrphanBlocks.size() + 1)
        {
            std::map<uint256, COrphanBlock>::const_iterator itCur = mapOrphanBlocks.find(hashCur);
            if (itCur == mapOrphanBlocks.end())
            {
                fTerminated = true;
                break;
            }
            hashCur = itCur->second.hashWaitedFor;
        }
        if (!fTerminated || mapBlockIndex.count(hashCur))
            continue;
        mapOut[itOwner->second].insert(hashCur);
    }
    return mapOut;
}

// T7's checker: the published snapshot is exactly that independent computation,
// owner by owner.
void CheckSnapshotMatches(const char* pszWhere)
{
    LOCK(cs_main);
    const std::map<NodeId, std::set<uint256> > mapComputed = ExpectedGaps();
    const std::map<NodeId, std::set<uint256> > mapPublished = GetOrphanGapSnapshot();

    BOOST_CHECK_MESSAGE(mapPublished == mapComputed,
                        "the published per-peer gap sets are not a from-scratch computation at "
                            << pszWhere << " (" << mapPublished.size() << " owners published "
                            << "against " << mapComputed.size() << " computed)");
    BOOST_CHECK_MESSAGE(GetOrphanGapGatedPeerCount() == mapComputed.size(),
                        "the published gated-owner count is " << GetOrphanGapGatedPeerCount()
                            << " against " << mapComputed.size() << " computed at " << pszWhere);
    std::set<uint256> setAll;
    for (std::map<NodeId, std::set<uint256> >::const_iterator it = mapComputed.begin();
         it != mapComputed.end(); ++it)
    {
        BOOST_CHECK_MESSAGE(IsOrphanGapGatedPeer(it->first),
                            "owner " << it->first << " holds a gap-rooted record but is not gated at "
                                     << pszWhere);
        for (std::set<uint256>::const_iterator ith = it->second.begin();
             ith != it->second.end(); ++ith)
        {
            setAll.insert(*ith);
            BOOST_CHECK_MESSAGE(IsOrphanGapHashForPeer(it->first, *ith),
                                "owner " << it->first << " is not gated on its own root at "
                                         << pszWhere);
        }
    }
    BOOST_CHECK_MESSAGE(GetOrphanGapHashCount() == setAll.size(),
                        "the published distinct-hash count is " << GetOrphanGapHashCount()
                            << " against " << setAll.size() << " computed at " << pszWhere);
}

std::vector<CBlock> MakeHeaderChain(const uint256& hashParent, unsigned int nCount,
                                    unsigned int nSeed)
{
    std::vector<CBlock> vHeaders;
    vHeaders.reserve(nCount);
    uint256 hashPrev = hashParent;
    const int64_t nBase = GetAdjustedTime() - (int64_t)nCount - 10;
    for (unsigned int i = 0; i < nCount; i++)
    {
        CBlock header;
        header.nVersion = CBlock::CURRENT_VERSION;
        header.hashPrevBlock = hashPrev;
        header.hashMerkleRoot = uint256((uint64_t)(nSeed * 100003u + i + 1));
        header.nTime = (unsigned int)(nBase + i);
        header.nBits = bnProofOfWorkLimit.GetCompact();
        header.nNonce = 1;
        while (!CheckProofOfWork(header.GetHash(), header.nBits))
            header.nNonce++;
        hashPrev = header.GetHash();
        vHeaders.push_back(header);
    }
    return vHeaders;
}

void DeliverHeaders(TestPeer& sender, TestPeer& receiver, const std::vector<CBlock>& vHeaders)
{
    sender.node.PushMessage("headers", vHeaders);
    CSerializeData data;
    {
        LOCK(sender.node.cs_vSend);
        BOOST_REQUIRE(!sender.node.vSendMsg.empty());
        data = sender.node.vSendMsg.back();
        sender.node.vSendMsg.clear();
    }
    BOOST_REQUIRE(receiver.node.ReceiveMsgBytes(&data[0], (unsigned int)data.size()));
    {
        LOCK(receiver.node.cs_vRecvMsg);
        BOOST_REQUIRE(ProcessMessages(&receiver.node));
    }
}

bool SolveBlock(CBlock* pblock)
{
    CBigNum target;
    target.SetCompact(pblock->nBits);
    const uint256 hashTarget = target.getuint256();
    unsigned int nHashes = 0;
    while (pblock->GetPoWHash() > hashTarget)
    {
        ++pblock->nNonce;
        if (pblock->nNonce == 0)
            ++pblock->nTime;
        if (++nHashes > 4000000U)
            return false;
    }
    return true;
}

CTransaction PadTx(unsigned int nTime, unsigned int nSeed, size_t nBytes)
{
    CTransaction tx;
    tx.nTime = nTime;
    tx.vin.push_back(CTxIn(COutPoint(uint256((uint64_t)nSeed), 0)));
    CTxOut out;
    out.nValue = 1;
    out.scriptPubKey = CScript() << OP_RETURN
                                 << std::vector<unsigned char>(nBytes, (unsigned char)(nSeed & 0xff));
    tx.vout.push_back(out);
    return tx;
}

// A signed template on the current chain, then re-parented onto hashPrev, so
// ProcessBlock reaches the classic park site with a block CheckBlock admits.
CBlock DetachedBlockOn(const uint256& hashPrev, unsigned int nSeed)
{
    unsigned int nExtraNonce = 0;
    std::unique_ptr<CBlock> ptmpl(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(ptmpl.get() != NULL);
    CBlockIndex* pindexPrev = NULL;
    {
        LOCK(cs_main);
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(ptmpl->hashPrevBlock);
        BOOST_REQUIRE(mi != mapBlockIndex.end());
        pindexPrev = mi->second;
    }
    IncrementExtraNonce(ptmpl.get(), pindexPrev, nExtraNonce);

    CBlock block = *ptmpl;
    block.hashPrevBlock = hashPrev;
    block.vtx.push_back(PadTx(block.nTime, nSeed * 100003u + 1, 512));
    block.nNonce = nSeed;
    block.vMerkleTree.clear();
    block.hashMerkleRoot = block.BuildMerkleTree();
    BOOST_REQUIRE(SolveBlock(&block));
    BOOST_REQUIRE_MESSAGE(block.CheckBlock(), "the detached block is not admissible");
    return block;
}

CBlock DetachedBlock(unsigned int nSeed)
{
    return DetachedBlockOn(uint256((uint64_t)0xd0d00000u + nSeed), nSeed);
}

// One padded record, parked through the real writer, so a byte bound can be
// crossed without a pool full of blocks.
uint256 ParkPadded(unsigned int nSeed, const uint256& hashPrev, NodeId owner, size_t nBytes)
{
    LOCK(cs_main);
    CBlock* pblock = SyntheticOrphan(nSeed, hashPrev);
    pblock->vtx.push_back(PadTx(pblock->nTime, nSeed, nBytes));
    const uint256 hash = pblock->GetHash();
    BOOST_REQUIRE(AddOrphanBlock(hash, pblock, hashPrev, owner, OrphanBlockFootprint(*pblock)));
    return hash;
}

// Mock clock for the duration of a case.
class CScopedMockClock
{
public:
    explicit CScopedMockClock(int64_t nTime) { SetMockTime(nTime); }
    void Set(int64_t nTime) { SetMockTime(nTime); }
    ~CScopedMockClock() { SetMockTime(0); }
};

int OrphanCountFor(NodeId id)
{
    std::map<NodeId, int>::const_iterator it = mapOrphanCountByNode.find(id);
    return it == mapOrphanCountByNode.end() ? 0 : it->second;
}

} // namespace

// T1. A peer holding a gap-rooted orphan is sent only the gap hash; forward requests stay
// queued in order and go out once the gap closes.
BOOST_AUTO_TEST_CASE(a_gated_peer_is_sent_the_gap_and_nothing_past_it)
{
    CScopedGapState state;
    TestPeer peer(19401);
    const NodeId owner = peer.node.GetId();

    const uint256 hashGap((uint64_t)0x9a900001ull);
    ParkChain(74100, hashGap, 4, owner);
    BOOST_REQUIRE(IsOrphanGapGatedPeer(owner));
    BOOST_REQUIRE(IsOrphanGapHashForPeer(owner, hashGap));

    const int64_t nBaseKey = (GetTime() - 30) * 1000000;
    std::vector<uint256> vForward;
    for (unsigned int i = 0; i < 300; i++)
    {
        const uint256 hashForward((uint64_t)(0x9a910000ull + i));
        vForward.push_back(hashForward);
        QueueBlockRequest(peer.node, nBaseKey + (int64_t)i, hashForward);
    }
    QueueBlockRequest(peer.node, nBaseKey + 300, hashGap);
    BOOST_REQUIRE_EQUAL(peer.node.mapAskFor.size(), 301U);

    BOOST_CHECK(SendMessages(&peer.node, false));

    BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.count(hashGap) == 1,
                        "the gap hash was not requested from the gated peer");
    BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.size() == 1U,
                        "a gated peer was asked for " << peer.node.setBlocksInFlight.size()
                            << " blocks, not the one gap hash");
    // Nothing was consumed: the gap hash went out from the peer's own snapshot,
    // not from the queue, and the forward requests are all still queued.
    BOOST_CHECK_MESSAGE(peer.node.mapAskFor.size() == 301U,
                        "the deferred requests were not left queued ("
                            << peer.node.mapAskFor.size() << " of 301 remain)");

    // Deferred, not re-timed: the queue is still in its original order.
    std::multimap<int64_t, CInv>::const_iterator it = peer.node.mapAskFor.begin();
    for (unsigned int i = 0; i < 300; i++, ++it)
    {
        BOOST_REQUIRE(it != peer.node.mapAskFor.end());
        BOOST_CHECK_MESSAGE(it->second.hash == vForward[i],
                            "the deferred queue lost its order at entry " << i);
        BOOST_CHECK_MESSAGE(it->first == nBaseKey + (int64_t)i,
                            "the deferred entry at " << i << " was re-timed");
    }

    // Close the gap: the records drain, the snapshot is republished, and the
    // same queue flushes with nothing re-announced.
    {
        LOCK(cs_main);
        std::vector<uint256> vHeld;
        for (std::map<uint256, COrphanBlock>::const_iterator itHeld = mapOrphanBlocks.begin();
             itHeld != mapOrphanBlocks.end(); ++itHeld)
            vHeld.push_back(itHeld->first);
        for (unsigned int i = 0; i < vHeld.size(); i++)
            EraseOrphanBlock(vHeld[i], true);
        RecomputeOrphanGaps();
    }
    BOOST_REQUIRE(!IsOrphanGapGatedPeer(owner));

    BOOST_CHECK(SendMessages(&peer.node, false));

    BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.size() == MAX_BLOCKS_IN_FLIGHT_PER_PEER,
                        "the deferred window did not go out once the gap closed ("
                            << peer.node.setBlocksInFlight.size() << " in flight)");
    for (unsigned int i = 0; i + 1 < MAX_BLOCKS_IN_FLIGHT_PER_PEER; i++)
        BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.count(vForward[i]) == 1,
                            "deferred request " << i << " was dropped rather than deferred");
}

// T2. Enqueue skip: a header whose parent is a held orphan parks and is not requested; one
// on an indexed parent still is.
BOOST_AUTO_TEST_CASE(headers_above_a_held_orphan_are_not_requested)
{
    CScopedGapState state;
    BOOST_REQUIRE(pindexBest != NULL);
    TestPeer sender(19403), receiver(19404);

    std::vector<CBlock> vHeaders = MakeHeaderChain(pindexBest->GetBlockHash(), 40, 21);
    const size_t nHeld = 5;
    {
        LOCK(cs_main);
        CBlock* pheld = new CBlock(vHeaders[nHeld]);
        BOOST_REQUIRE(AddOrphanBlock(pheld->GetHash(), pheld, pheld->hashPrevBlock,
                                     (NodeId)-1, OrphanBlockFootprint(*pheld)));
        RecomputeOrphanGaps();
    }

    DeliverHeaders(sender, receiver, vHeaders);

    const std::set<uint256> setQueued = QueuedBlockHashes(receiver.node);

    // Below the held orphan: parents resolve through the announced chain and
    // nothing is held under them, so every one of them is requested.
    for (size_t i = 0; i < nHeld; i++)
        BOOST_CHECK_MESSAGE(setQueued.count(vHeaders[i].GetHash()) == 1,
                            "header " << i << " on an indexed or announced parent was not requested");
    BOOST_CHECK_MESSAGE(setQueued.count(vHeaders[nHeld].GetHash()) == 0,
                        "a block already held as an orphan was requested again");
    // Above it: the direct child, whose parent is held, and every header after
    // it, whose parent was skipped here.
    for (size_t i = nHeld + 1; i < vHeaders.size(); i++)
        BOOST_CHECK_MESSAGE(setQueued.count(vHeaders[i].GetHash()) == 0,
                            "header " << i << " above a held orphan was requested");
    BOOST_CHECK_MESSAGE(setQueued.size() == nHeld,
                        "the headers site enqueued " << setQueued.size()
                            << " block requests, not the " << nHeld << " below the gap");
}

// T3. With one in-flight forward window there is room for 622 ancestors: the measured 619
// fits and the 623rd is refused.
BOOST_AUTO_TEST_CASE(one_forward_window_leaves_room_for_the_measured_branch)
{
    BOOST_REQUIRE(fRegTest);
    CScopedGapState state;
    CScopedArg entries("-maxorphanblocks", "2500");
    CScopedArg mem("-maxorphanmem", "256");

    TestPeer peer(19405);
    const NodeId owner = peer.node.GetId();

    const uint256 hashGap((uint64_t)0x9a920001ull);
    // The branch below the merging block, 619 as measured, then the merging
    // block and one in-flight window of blocks above it.
    std::vector<uint256> vBranch = ParkChain(75000, hashGap, 619, owner);
    std::vector<uint256> vForward = ParkChain(76000, vBranch.back(),
                                              MAX_BLOCKS_IN_FLIGHT_PER_PEER, owner);
    {
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(OrphanCountFor(owner) == 619 + (int)MAX_BLOCKS_IN_FLIGHT_PER_PEER,
                            "the peer holds " << OrphanCountFor(owner)
                                << " records, not 619 + one window");
        BOOST_CHECK_MESSAGE(OrphanCountFor(owner) == 747,
                            "the measured geometry is 747 held, not " << OrphanCountFor(owner));
        BOOST_CHECK_MESSAGE(OrphanCountFor(owner) < 750,
                            "619 branch blocks under one forward window do not fit the cap");
    }
    BOOST_CHECK_MESSAGE(IsOrphanGapHashForPeer(owner, hashGap),
                        "the root of the whole chain is not the gap hash");
    BOOST_CHECK_MESSAGE(GetOrphanGapHashCount() == 1U,
                        "one chain published " << GetOrphanGapHashCount() << " gap hashes");
    CheckSnapshotMatches("747 held");

    // The 748th ancestor still parks: 619 + 128 leaves three of the budget.
    {
        CBlock fits = DetachedBlock(7401);
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(ProcessBlock(&peer.node, &fits),
                            "a 748th record was refused although the budget has room");
        BOOST_CHECK_MESSAGE(OrphanCountFor(owner) == 748,
                            "the peer holds " << OrphanCountFor(owner) << " records, not 748");
    }

    // Two more take the peer to the cap, and the next delivery is refused. That
    // is the pre-existing bound, unmoved: it is reachable only past L = 622.
    ParkChain(77000, uint256((uint64_t)0x9a930001ull), 2, owner);
    {
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(OrphanCountFor(owner) == 750,
                            "the peer holds " << OrphanCountFor(owner) << " records, not 750");
    }
    {
        CBlock over = DetachedBlock(7402);
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(!ProcessBlock(&peer.node, &over),
                            "a peer at the per-peer cap was still allowed to park");
        BOOST_CHECK_MESSAGE(OrphanCountFor(owner) == 750,
                            "the refused delivery changed the peer's charge to "
                                << OrphanCountFor(owner));
    }
}

// T4. Per peer: a peer with no gap-rooted record keeps fetching forward while another's gap
// fills, and is gated only at its own first park above the gap.
BOOST_AUTO_TEST_CASE(the_gate_is_per_peer)
{
    CScopedGapState state;
    TestPeer peerA(19407), peerB(19408);
    const NodeId ownerA = peerA.node.GetId();
    const NodeId ownerB = peerB.node.GetId();

    const uint256 hashGap((uint64_t)0x9a940001ull);
    std::vector<uint256> vChainA = ParkChain(78000, hashGap, 3, ownerA);
    BOOST_REQUIRE(IsOrphanGapGatedPeer(ownerA));
    BOOST_CHECK_MESSAGE(!IsOrphanGapGatedPeer(ownerB),
                        "a peer holding nothing was gated by another peer's gap");

    const int64_t nBaseKey = (GetTime() - 30) * 1000000;
    const uint256 hashForwardA((uint64_t)0x9a950001ull);
    const uint256 hashForwardB((uint64_t)0x9a950002ull);
    QueueBlockRequest(peerA.node, nBaseKey, hashForwardA);
    QueueBlockRequest(peerB.node, nBaseKey, hashForwardB);

    BOOST_CHECK(SendMessages(&peerA.node, false));
    BOOST_CHECK(SendMessages(&peerB.node, false));

    BOOST_CHECK_MESSAGE(peerA.node.setBlocksInFlight.count(hashForwardA) == 0,
                        "the gated peer was asked for a block past its gap");
    BOOST_CHECK_MESSAGE(peerB.node.setBlocksInFlight.count(hashForwardB) == 1,
                        "an ungated peer was stopped by another peer's gap");

    // B parks one block above the same gap: it now owns a gap-rooted record and
    // is gated on its own account.
    ParkSynthetic(78900, vChainA.back(), ownerB);
    {
        LOCK(cs_main);
        RecomputeOrphanGaps();
    }
    BOOST_CHECK_MESSAGE(IsOrphanGapGatedPeer(ownerB),
                        "a peer that parked above the gap was not gated");
    CheckSnapshotMatches("B parked above the gap");

    const uint256 hashForwardB2((uint64_t)0x9a950003ull);
    QueueBlockRequest(peerB.node, nBaseKey + 1, hashForwardB2);
    BOOST_CHECK(SendMessages(&peerB.node, false));
    BOOST_CHECK_MESSAGE(peerB.node.setBlocksInFlight.count(hashForwardB2) == 0,
                        "a newly gated peer was still asked for a block past the gap");
}

// T5. A peer that never serves the ancestor is ungated when the sweep expires its records;
// a second peer is untouched. The sweep republishes the snapshot.
BOOST_AUTO_TEST_CASE(a_peer_that_never_serves_the_gap_is_ungated_by_the_expiry)
{
    CScopedGapState state;
    TestPeer peerP(19409), peerQ(19410);
    const NodeId ownerP = peerP.node.GetId();
    const NodeId ownerQ = peerQ.node.GetId();

    const uint256 hashGap((uint64_t)0x9a960001ull);
    ParkChain(79000, hashGap, 5, ownerP);
    BOOST_REQUIRE(IsOrphanGapGatedPeer(ownerP));
    BOOST_CHECK_MESSAGE(!IsOrphanGapGatedPeer(ownerQ),
                        "a peer holding nothing was gated before the sweep");

    const int64_t nBaseKey = (GetTime() - 30) * 1000000;
    const uint256 hashQ1((uint64_t)0x9a970001ull);
    QueueBlockRequest(peerQ.node, nBaseKey, hashQ1);
    BOOST_CHECK(SendMessages(&peerQ.node, false));
    BOOST_CHECK_MESSAGE(peerQ.node.setBlocksInFlight.count(hashQ1) == 1,
                        "the second peer was throttled while the first held a gap");

    size_t nDropped = 0;
    {
        LOCK(cs_main);
        nDropped = SweepOrphanPool(GetTime() + ORPHAN_BLOCK_EXPIRY_SECONDS + 1);
    }
    BOOST_CHECK_MESSAGE(nDropped == 5U, "the sweep dropped " << nDropped << " records, not 5");
    BOOST_CHECK_MESSAGE(!IsOrphanGapGatedPeer(ownerP),
                        "the peer stayed gated after the sweep released its records");
    BOOST_CHECK_MESSAGE(GetOrphanGapHashCount() == 0U,
                        "the sweep left " << GetOrphanGapHashCount() << " gap hashes published");
    CheckSnapshotMatches("after the expiry sweep");

    const uint256 hashP1((uint64_t)0x9a970002ull);
    QueueBlockRequest(peerP.node, nBaseKey + 1, hashP1);
    BOOST_CHECK(SendMessages(&peerP.node, false));
    BOOST_CHECK_MESSAGE(peerP.node.setBlocksInFlight.count(hashP1) == 1,
                        "the ungated peer was still refused a forward request");

    const uint256 hashQ2((uint64_t)0x9a970003ull);
    QueueBlockRequest(peerQ.node, nBaseKey + 2, hashQ2);
    BOOST_CHECK(SendMessages(&peerQ.node, false));
    BOOST_CHECK_MESSAGE(peerQ.node.setBlocksInFlight.count(hashQ2) == 1,
                        "the second peer was affected by the first peer's expiry");
}

// T6. Expiry does not re-request a dropped window, so stall recovery asks for headers
// when the peer is ahead with nothing in flight.
BOOST_AUTO_TEST_CASE(the_stall_recovery_asks_for_headers_when_nothing_is_in_flight)
{
    CScopedGapState state;
    BOOST_REQUIRE(pindexBest != NULL);
    TestPeer peer(19411);

    peer.node.nLastBlockRecv = GetTime() - 600;
    peer.node.nChainHeight = nBestHeight + 50;
    peer.node.UpdateBestKnownBlock(nBestHeight + 50, uint256((uint64_t)0x9a980001ull));
    BOOST_REQUIRE(peer.node.setBlocksInFlight.empty());

    BOOST_CHECK(SendMessages(&peer.node, false));

    BOOST_CHECK_MESSAGE(CountCommand(peer.node, "getheaders") >= 1U,
                        "the stall recovery sent no getheaders with the peer ahead and "
                        "nothing in flight");
}

// T6b. The same recovery re-asks the gap for a gated peer with nothing in
// flight. The gap request goes out once; if it is lost nothing else reissues it
// and the gate would hold on a peer with an empty in-flight set.
BOOST_AUTO_TEST_CASE(the_stall_recovery_re_asks_a_gated_peers_gap)
{
    CScopedGapState state;
    BOOST_REQUIRE(pindexBest != NULL);
    TestPeer peer(19412);
    const NodeId owner = peer.node.GetId();

    const uint256 hashGap((uint64_t)0x9a990001ull);
    ParkChain(80000, hashGap, 2, owner);
    BOOST_REQUIRE(IsOrphanGapGatedPeer(owner));

    peer.node.nLastBlockRecv = GetTime() - 600;
    peer.node.nChainHeight = nBestHeight + 50;
    peer.node.UpdateBestKnownBlock(nBestHeight + 50, uint256((uint64_t)0x9a990002ull));
    BOOST_REQUIRE(peer.node.mapAskFor.empty());
    BOOST_REQUIRE(peer.node.setBlocksInFlight.empty());

    BOOST_CHECK(SendMessages(&peer.node, false));

    const bool fAsked = peer.node.setBlocksInFlight.count(hashGap) ||
                        QueuedBlockHashes(peer.node).count(hashGap);
    BOOST_CHECK_MESSAGE(fAsked,
                        "the stall recovery did not re-ask the gap of a gated peer with "
                        "nothing in flight");
}

// T7. The snapshot is derived, never maintained: after every mutation of the
// pool the published sets equal a from-scratch walk of the tables. Checked over
// a park, a re-park onto a different wait hash, a drain and a release.
BOOST_AUTO_TEST_CASE(the_snapshot_equals_a_from_scratch_computation)
{
    CScopedGapState state;
    TestPeer peerA(19413), peerB(19414);
    const NodeId ownerA = peerA.node.GetId();
    const NodeId ownerB = peerB.node.GetId();

    CheckSnapshotMatches("empty pool");

    const uint256 hashGapA((uint64_t)0x9aa00001ull);
    const uint256 hashGapB((uint64_t)0x9aa00002ull);
    std::vector<uint256> vA = ParkChain(81000, hashGapA, 6, ownerA);
    CheckSnapshotMatches("one chain parked");
    std::vector<uint256> vB = ParkChain(82000, hashGapB, 4, ownerB);
    CheckSnapshotMatches("two chains parked");
    BOOST_CHECK_MESSAGE(GetOrphanGapHashCount() == 2U,
                        "two independent chains published " << GetOrphanGapHashCount()
                            << " gap hashes");

    // A record that moves to a different wait hash, as the drain's re-park does.
    {
        LOCK(cs_main);
        std::map<uint256, COrphanBlock>::iterator it = mapOrphanBlocks.find(vB.back());
        BOOST_REQUIRE(it != mapOrphanBlocks.end());
        mapOrphanBlocksByPrev.erase(it->second.hashWaitedFor);
        it->second.hashWaitedFor = vA.back();
        mapOrphanBlocksByPrev.insert(std::make_pair(vA.back(), it->second.pblock));
        RecomputeOrphanGaps();
    }
    CheckSnapshotMatches("a record re-parked onto another chain");

    // A drain: the whole of A's chain leaves, so B's re-parked record is left
    // waiting on a hash the pool no longer holds and becomes its own gap.
    {
        LOCK(cs_main);
        for (unsigned int i = 0; i < vA.size(); i++)
            EraseOrphanBlock(vA[i], true);
        RecomputeOrphanGaps();
    }
    CheckSnapshotMatches("after a drain");

    // A departed owner's release, through the sweep.
    OrphanBlocksNodeDisconnected(ownerB);
    {
        LOCK(cs_main);
        SweepOrphanPool(GetTime());
    }
    CheckSnapshotMatches("after a departed owner's release");
    BOOST_CHECK_MESSAGE(!IsOrphanGapGatedPeer(ownerB),
                        "a departed peer stayed gated after its records were released");
}

// T8. The park boundary. The snapshot is published from ProcessBlock itself, so
// a delivery that parks gates its own peer with no other call in between: the
// live path never recomputes by hand.
BOOST_AUTO_TEST_CASE(a_park_through_process_block_gates_its_own_peer)
{
    BOOST_REQUIRE(fRegTest);
    CScopedGapState state;
    CScopedArg entries("-maxorphanblocks", "2500");
    CScopedArg mem("-maxorphanmem", "256");

    TestPeer peer(19415);
    const NodeId owner = peer.node.GetId();
    BOOST_REQUIRE(!IsOrphanGapGatedPeer(owner));

    CBlock parked = DetachedBlock(7501);
    const uint256 hashWanted = parked.hashPrevBlock;
    {
        LOCK(cs_main);
        BOOST_REQUIRE(ProcessBlock(&peer.node, &parked));
    }

    BOOST_CHECK_MESSAGE(IsOrphanGapGatedPeer(owner),
                        "a peer that parked a block through ProcessBlock was not gated");
    BOOST_CHECK_MESSAGE(IsOrphanGapHashForPeer(owner, hashWanted),
                        "the parent the park waits on was not published as a gap hash");

    const int64_t nBaseKey = (GetTime() - 30) * 1000000;
    const uint256 hashForward((uint64_t)0x9ab00001ull);
    QueueBlockRequest(peer.node, nBaseKey, hashForward);
    QueueBlockRequest(peer.node, nBaseKey + 1, hashWanted);
    BOOST_CHECK(SendMessages(&peer.node, false));

    BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.count(hashWanted) == 1,
                        "the parent the park waits on was not requested");
    BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.count(hashForward) == 0,
                        "a block past the gap was requested from the peer that parked it");
}

// T9. The deferred queue does not grow with what a peer re-announces. Nothing
// drains while the gate holds, so a hash offered again would stack a second
// entry behind the first; the earliest entry is kept and the later ones go.
BOOST_AUTO_TEST_CASE(a_gated_peer_cannot_grow_the_queue_by_re_announcing)
{
    CScopedGapState state;
    TestPeer peer(19417);
    const NodeId owner = peer.node.GetId();

    const uint256 hashGap((uint64_t)0x9ac00001ull);
    ParkChain(83000, hashGap, 2, owner);
    BOOST_REQUIRE(IsOrphanGapGatedPeer(owner));

    const int64_t nBaseKey = (GetTime() - 30) * 1000000;
    const uint256 hashForward((uint64_t)0x9ac10001ull);
    const uint256 hashOther((uint64_t)0x9ac10002ull);
    for (unsigned int i = 0; i < 8; i++)
        QueueBlockRequest(peer.node, nBaseKey + (int64_t)i, hashForward);
    QueueBlockRequest(peer.node, nBaseKey + 8, hashOther);
    BOOST_REQUIRE_EQUAL(peer.node.mapAskFor.size(), 9U);

    BOOST_CHECK(SendMessages(&peer.node, false));

    BOOST_CHECK_MESSAGE(peer.node.mapAskFor.size() == 2U,
                        "the gated queue kept " << peer.node.mapAskFor.size()
                            << " entries for two distinct hashes");
    BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.count(hashForward) == 0 &&
                            peer.node.setBlocksInFlight.count(hashOther) == 0,
                        "a gated peer was asked for a block past the gap");
    BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.size() == 1U,
                        "a gated peer was asked for " << peer.node.setBlocksInFlight.size()
                            << " blocks, not the one gap hash");
    std::multimap<int64_t, CInv>::const_iterator it = peer.node.mapAskFor.begin();
    BOOST_CHECK_MESSAGE(it->second.hash == hashForward && it->first == nBaseKey,
                        "the surviving duplicate is not the earliest entry");
    ++it;
    BOOST_CHECK_MESSAGE(it->second.hash == hashOther,
                        "the second distinct hash was dropped with the duplicates");

    // Still deferred, not discarded: it goes out once the gap closes.
    {
        LOCK(cs_main);
        std::vector<uint256> vHeld;
        for (std::map<uint256, COrphanBlock>::const_iterator itHeld = mapOrphanBlocks.begin();
             itHeld != mapOrphanBlocks.end(); ++itHeld)
            vHeld.push_back(itHeld->first);
        for (unsigned int i = 0; i < vHeld.size(); i++)
            EraseOrphanBlock(vHeld[i], true);
        RecomputeOrphanGaps();
    }
    BOOST_CHECK(SendMessages(&peer.node, false));
    BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.count(hashForward) == 1,
                        "the deferred request was lost with its duplicates");
    BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.count(hashOther) == 1,
                        "the second deferred request was lost");
}

// T10a. The flush consults only the peer's own gap set, so another peer's root
// offered via inv stays deferred.
BOOST_AUTO_TEST_CASE(a_gated_peers_flush_never_admits_another_peers_gap)
{
    CScopedGapState state;
    TestPeer peerH(19419), peerA(19420);
    const NodeId ownerH = peerH.node.GetId();
    const NodeId ownerA = peerA.node.GetId();

    // H's root is a hash nothing else refers to; A's is the one A is waiting on.
    const uint256 hashGapH((uint64_t)0x9ad00001ull);
    const uint256 hashGapA((uint64_t)0x9ad00002ull);
    ParkChain(84000, hashGapH, 3, ownerH);
    ParkChain(85000, hashGapA, 3, ownerA);
    BOOST_REQUIRE(IsOrphanGapGatedPeer(ownerH));
    BOOST_REQUIRE(IsOrphanGapGatedPeer(ownerA));
    CheckSnapshotMatches("two peers gated on roots of their own");

    // The snapshot itself carries no union.
    BOOST_CHECK(IsOrphanGapHashForPeer(ownerA, hashGapA));
    BOOST_CHECK(IsOrphanGapHashForPeer(ownerH, hashGapH));
    BOOST_CHECK_MESSAGE(!IsOrphanGapHashForPeer(ownerA, hashGapH),
                        "one peer's entry carries a root it delivered no child of");
    BOOST_CHECK_MESSAGE(!IsOrphanGapHashForPeer(ownerH, hashGapA),
                        "one peer's entry carries a root it delivered no child of");

    const int64_t nBaseKey = (GetTime() - 30) * 1000000;
    const uint256 hashForwardA((uint64_t)0x9ad10001ull);
    QueueBlockRequest(peerA.node, nBaseKey, hashGapH);
    QueueBlockRequest(peerA.node, nBaseKey + 1, hashForwardA);

    BOOST_CHECK(SendMessages(&peerA.node, false));

    BOOST_CHECK_MESSAGE(peerA.node.setBlocksInFlight.count(hashGapA) == 1,
                        "the gated peer was not asked for the root under its own records");
    BOOST_CHECK_MESSAGE(peerA.node.setBlocksInFlight.count(hashGapH) == 0,
                        "another peer's gap hash was requested from this peer");
    BOOST_CHECK_MESSAGE(peerA.node.setBlocksInFlight.count(hashForwardA) == 0,
                        "a gated peer was asked for a block past its gap");
    BOOST_CHECK_MESSAGE(peerA.node.setBlocksInFlight.size() == 1U,
                        "the gated peer's window holds " << peerA.node.setBlocksInFlight.size()
                            << " requests, not the one root of its own");
    BOOST_CHECK_MESSAGE(QueuedBlockHashes(peerA.node).count(hashGapH) == 1,
                        "the offered hash was consumed rather than deferred");

    // The owner of the other root is asked for it, and for nothing of A's.
    BOOST_CHECK(SendMessages(&peerH.node, false));

    BOOST_CHECK_MESSAGE(peerH.node.setBlocksInFlight.count(hashGapH) == 1,
                        "the peer that delivered the records was not asked for their root");
    BOOST_CHECK_MESSAGE(peerH.node.setBlocksInFlight.count(hashGapA) == 0,
                        "another peer's gap hash was requested from this peer");
    BOOST_CHECK_MESSAGE(peerH.node.setBlocksInFlight.size() == 1U,
                        "the gated peer's window holds " << peerH.node.setBlocksInFlight.size()
                            << " requests, not the one root of its own");
}

// T10b. Same rule on the stall re-ask: it only draws from the peer's own gap set.
BOOST_AUTO_TEST_CASE(a_gated_peers_stall_re_ask_never_draws_another_peers_gap)
{
    CScopedGapState state;
    BOOST_REQUIRE(pindexBest != NULL);
    TestPeer peerH(19422), peerA(19423);
    const NodeId ownerH = peerH.node.GetId();
    const NodeId ownerA = peerA.node.GetId();

    const uint256 hashGapH((uint64_t)0x9ad20001ull);
    const uint256 hashGapA((uint64_t)0x9ad20002ull);
    ParkChain(84500, hashGapH, 3, ownerH);
    ParkChain(85500, hashGapA, 3, ownerA);
    BOOST_REQUIRE(IsOrphanGapGatedPeer(ownerA));
    BOOST_REQUIRE(IsOrphanGapGatedPeer(ownerH));

    peerA.node.nLastBlockRecv = GetTime() - 600;
    peerA.node.nChainHeight = nBestHeight + 50;
    peerA.node.UpdateBestKnownBlock(nBestHeight + 50, uint256((uint64_t)0x9ad30001ull));
    BOOST_REQUIRE(peerA.node.mapAskFor.empty());
    BOOST_REQUIRE(peerA.node.setBlocksInFlight.empty());

    BOOST_CHECK(SendMessages(&peerA.node, false));

    BOOST_CHECK_MESSAGE(peerA.node.setBlocksInFlight.count(hashGapA) == 1,
                        "the stall pass did not ask the gated peer for its own root");
    BOOST_CHECK_MESSAGE(peerA.node.setBlocksInFlight.count(hashGapH) == 0,
                        "the stall re-ask put another peer's gap in this peer's window");
    const std::set<uint256> setLeft = QueuedBlockHashes(peerA.node);
    BOOST_CHECK_MESSAGE(setLeft.count(hashGapH) == 0,
                        "the stall re-ask queued another peer's gap on this peer");
    // Every hash left queued is this peer's own root (not an empty-queue check:
    // AskFor's static request-time floor may defer entries).
    for (std::set<uint256>::const_iterator it = setLeft.begin(); it != setLeft.end(); ++it)
        BOOST_CHECK_MESSAGE(IsOrphanGapHashForPeer(ownerA, *it),
                            "the stall re-ask queued a hash that is not a root of this "
                            "peer's own records");
}

// T11. A gated pass steps over at most MAX_GAP_DEFERRALS_PER_PASS entries and the
// next pass resumes there. The awaited hash is asked from the snapshot, not the queue.
BOOST_AUTO_TEST_CASE(a_gated_pass_stops_at_its_deferral_cap)
{
    CScopedGapState state;
    TestPeer peer(19421);
    const NodeId owner = peer.node.GetId();

    const uint256 hashGap((uint64_t)0x9ae00001ull);
    ParkChain(86000, hashGap, 2, owner);
    BOOST_REQUIRE(IsOrphanGapGatedPeer(owner));

    int64_t nKey = (GetTime() - 30) * 1000000;
    // One full cap of distinct forward hashes.
    for (size_t i = 0; i < MAX_GAP_DEFERRALS_PER_PASS; i++)
        QueueBlockRequest(peer.node, nKey++, uint256((uint64_t)(0x9ae10000ull + i)));
    // Then hashes offered twice, past where the cap stops. A pass that reaches
    // them drops the later copy of each; a capped pass does not reach them.
    const size_t nDup = 5;
    for (size_t i = 0; i < nDup; i++)
    {
        const uint256 hashDup((uint64_t)(0x9ae20000ull + i));
        QueueBlockRequest(peer.node, nKey++, hashDup);
        QueueBlockRequest(peer.node, nKey++, hashDup);
    }
    // The gap hash last of all, behind everything the cap will stop at.
    QueueBlockRequest(peer.node, nKey++, hashGap);
    const size_t nQueued = peer.node.mapAskFor.size();
    BOOST_REQUIRE_EQUAL(nQueued, MAX_GAP_DEFERRALS_PER_PASS + 2 * nDup + 1);

    BOOST_CHECK(SendMessages(&peer.node, false));

    BOOST_CHECK_MESSAGE(peer.node.mapAskFor.size() == nQueued,
                        "the pass walked past its cap: " << peer.node.mapAskFor.size()
                            << " of " << nQueued << " entries remain, so the duplicates "
                            << "behind the cap were reached");
    // Behind the cap and requested all the same.
    BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.count(hashGap) == 1,
                        "the gap hash queued behind the cap was not requested");
    BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.size() == 1U,
                        "a gated peer was asked for " << peer.node.setBlocksInFlight.size()
                            << " blocks, not the one gap hash");

    // The next pass resumes where this one stopped and takes the rest: the
    // duplicates go, and so does the queued copy of the hash already in flight.
    BOOST_CHECK(SendMessages(&peer.node, false));

    BOOST_CHECK_MESSAGE(peer.node.mapAskFor.size() == nQueued - nDup - 1,
                        "the resumed pass left " << peer.node.mapAskFor.size()
                            << " entries, not " << (nQueued - nDup - 1));
    BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.size() == 1U,
                        "the resumed pass sent a request past the gap");
}

// T13. A gap root the pool refused is deferred for its backoff, then asked again.
BOOST_AUTO_TEST_CASE(a_refused_gap_root_waits_out_its_backoff_and_is_then_asked_again)
{
    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(pindexBest != NULL);
    CScopedGapState state;
    CScopedArg entries("-maxorphanblocks", "2500");
    CScopedArg mem("-maxorphanmem", "32");    // the floor, so the share is 9.6 MB

    TestPeer peer(19423, "198.51.100.23");
    const NodeId owner = peer.node.GetId();

    // Built first, so the record that waits on it can name it, and admissible,
    // so the delivery below reaches the park site rather than the DoS check.
    CBlock blockGap = DetachedBlockOn(uint256((uint64_t)0xd0d09001ull), 9101);
    const uint256 hashGap = blockGap.GetHash();
    ParkSynthetic(9102, hashGap, owner);

    // The peer over its own byte share, on a record rooted in the index so it
    // publishes no gap of its own.
    ParkPadded(9103, pindexBest->GetBlockHash(), owner, 10 * 1024 * 1024);
    {
        LOCK(cs_main);
        RecomputeOrphanGaps();
    }
    BOOST_REQUIRE(GetOrphanBlocksFootprintForNode(owner) > GetMaxOrphanBlocksFootprintPerPeer());
    BOOST_REQUIRE(IsOrphanGapHashForPeer(owner, hashGap));
    BOOST_REQUIRE_EQUAL(GetOrphanGapHashesForPeer(owner).size(), 1U);

    // The gate asks for it, as it should.
    BOOST_CHECK(SendMessages(&peer.node, false));
    BOOST_REQUIRE_MESSAGE(peer.node.setBlocksInFlight.count(hashGap) == 1,
                          "the gap root was not asked for in the first place");

    // The peer serves it and the pool has no room: refused, unscored, deferred.
    // The flush's own send fails on a peer with no socket, which raises the
    // disconnect flag the park site refuses on before it reaches the pool.
    peer.node.fDisconnect = false;
    peer.node.ClearBlockInFlight(hashGap);
    {
        LOCK(cs_main);
        BOOST_REQUIRE_MESSAGE(!ProcessBlock(&peer.node, &blockGap),
                              "the pool parked a block the peer has no share left for");
    }
    BOOST_CHECK_MESSAGE(peer.node.nMisbehavior == 0,
                        "the peer was scored " << peer.node.nMisbehavior
                            << " for a gap block the pool refused");
    BOOST_REQUIRE_MESSAGE(IsOrphanRequestDeferred(hashGap, GetTime()),
                          "the refusal recorded no deferral for the gap root");
    BOOST_REQUIRE(IsOrphanGapHashForPeer(owner, hashGap));

    // The next pass does not ask again. This is the hot loop: without the read,
    // the root goes straight back out here and on every pass after it.
    BOOST_CHECK(SendMessages(&peer.node, false));
    BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.count(hashGap) == 0,
                        "a gap root the pool refused was re-asked on the next pass, "
                            "so it is re-requested for as long as the pool stays full");
    BOOST_CHECK_MESSAGE(peer.node.nMisbehavior == 0,
                        "the re-ask scored the peer " << peer.node.nMisbehavior);

    // Deferred, not withdrawn: the backoff lapses and the ask returns, which is
    // what stops a temporary refusal from wedging the node for good.
    const int64_t nBackoff = GetOrphanRefusalBackoff(hashGap);
    BOOST_REQUIRE(nBackoff >= ORPHAN_REFUSAL_BACKOFF_SECONDS);
    {
        CScopedMockClock clock(GetTime() + nBackoff + 1);
        BOOST_REQUIRE(!IsOrphanRequestDeferred(hashGap, GetTime()));
        BOOST_CHECK(SendMessages(&peer.node, false));
        BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.count(hashGap) == 1,
                            "the gap root was not asked again once its deferral lapsed, "
                                "so a refusal that should be temporary is permanent");
    }
}

// T14. A gap block refused at the per-peer entry cap is deferred, not scored; a block
// outside the gap set is scored as usual.
BOOST_AUTO_TEST_CASE(a_gap_block_refused_at_the_entry_cap_is_deferred_not_scored)
{
    BOOST_REQUIRE(fRegTest);
    CScopedGapState state;
    CScopedArg entries("-maxorphanblocks", "2500");
    CScopedArg mem("-maxorphanmem", "256");
    BOOST_REQUIRE_MESSAGE(!IsInitialBlockDownload(),
                          "the scored branch is skipped during initial block download");

    TestPeer peer(19425, "198.51.100.25");
    const NodeId owner = peer.node.GetId();

    CBlock blockGap = DetachedBlockOn(uint256((uint64_t)0xd0d09201ull), 9201);
    const uint256 hashGap = blockGap.GetHash();
    ParkSynthetic(9202, hashGap, owner);
    {
        LOCK(cs_main);
        RecomputeOrphanGaps();
        // Past MAX_ORPHAN_BLOCKS_PER_PEER, which the park site reads directly.
        mapOrphanCountByNode[owner] = 100000;
    }
    BOOST_REQUIRE(IsOrphanGapHashForPeer(owner, hashGap));

    {
        LOCK(cs_main);
        BOOST_REQUIRE_MESSAGE(!ProcessBlock(&peer.node, &blockGap),
                              "the pool parked a block past the peer's entry cap");
    }
    BOOST_CHECK_MESSAGE(peer.node.nMisbehavior == 0,
                        "the peer was scored " << peer.node.nMisbehavior
                            << " for serving a gap block this node asked it for");
    BOOST_CHECK_MESSAGE(IsOrphanRequestDeferred(hashGap, GetTime()),
                        "the gap block refused at the entry cap was not deferred, so the "
                            "direct ask puts it straight back out");

    // The control. Same peer, same cap, a hash the node is not gating it on: the
    // cap still scores and no gap deferral is taken.
    CBlock blockOther = DetachedBlockOn(uint256((uint64_t)0xd0d09401ull), 9401);
    {
        LOCK(cs_main);
        BOOST_REQUIRE(!IsOrphanGapHashForPeer(owner, blockOther.GetHash()));
        BOOST_REQUIRE(!ProcessBlock(&peer.node, &blockOther));
    }
    BOOST_CHECK_MESSAGE(peer.node.nMisbehavior > 0,
                        "a block outside the peer's gap set was not scored at the entry cap");
    BOOST_CHECK_MESSAGE(!IsOrphanRequestDeferred(blockOther.GetHash(), GetTime()),
                        "a block outside the peer's gap set took the gap deferral");
}

// T15. A gap root the pool can never hold is not asked for until the request paths
// lift the suppression.
BOOST_AUTO_TEST_CASE(a_gap_root_the_pool_can_never_hold_is_not_asked_for)
{
    BOOST_REQUIRE(fRegTest);
    CScopedGapState state;
    CScopedArg entries("-maxorphanblocks", "2500");
    CScopedArg mem("-maxorphanmem", "256");

    TestPeer peer(19427, "198.51.100.27");
    const NodeId owner = peer.node.GetId();

    CBlock blockGap = DetachedBlockOn(uint256((uint64_t)0xd0d09601ull), 9601);
    const uint256 hashGap = blockGap.GetHash();
    ParkSynthetic(9602, hashGap, owner);
    {
        LOCK(cs_main);
        RecomputeOrphanGaps();
    }
    BOOST_REQUIRE(IsOrphanGapHashForPeer(owner, hashGap));

    BOOST_CHECK(SendMessages(&peer.node, false));
    BOOST_REQUIRE_MESSAGE(peer.node.setBlocksInFlight.count(hashGap) == 1,
                          "the gap root was not asked for in the first place");

    // Delivered into a pool that can hold nothing, so the refusal suppresses the
    // hash rather than deferring it.
    peer.node.fDisconnect = false;
    peer.node.ClearBlockInFlight(hashGap);
    {
        CScopedArg none("-maxorphanblocks", "0");
        LOCK(cs_main);
        BOOST_REQUIRE(!ProcessBlock(&peer.node, &blockGap));
    }
    BOOST_REQUIRE_MESSAGE(IsOrphanBlockRequestSuppressed(hashGap),
                          "a block the pool could never hold was not suppressed");
    BOOST_CHECK_MESSAGE(peer.node.nMisbehavior == 0,
                        "the peer was scored " << peer.node.nMisbehavior
                            << " for a gap block the pool could never hold");
    BOOST_REQUIRE(IsOrphanGapHashForPeer(owner, hashGap));

    BOOST_CHECK(SendMessages(&peer.node, false));
    BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.count(hashGap) == 0,
                        "a gap root the pool can never hold was asked for again, so it is "
                            "re-downloaded on every pass for as long as the gate holds");

    // Lifted, and the gate asks again: the suppression is a state of the pool,
    // not a verdict on the hash.
    LiftOrphanBlockRequestSuppression(hashGap);
    BOOST_CHECK(SendMessages(&peer.node, false));
    BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.count(hashGap) == 1,
                        "the gap root was not asked again once the suppression was lifted");
}

// The hashStop of every getheaders the peer was sent, in order.
static std::vector<uint256> GetHeadersStops(CNode& node)
{
    std::vector<uint256> vStops;
    LOCK(node.cs_vSend);
    for (const CSerializeData& data : node.vSendMsg)
    {
        if (CommandOf(data) != "getheaders")
            continue;
        CDataStream ss(&data[0] + CMessageHeader::HEADER_SIZE, &data[0] + data.size(),
                       SER_NETWORK, PROTOCOL_VERSION);
        CBlockLocator locator;
        uint256 hashStop;
        ss >> locator >> hashStop;
        vStops.push_back(hashStop);
    }
    return vStops;
}

// T16. Deep missing ancestry is asked once as a headers range and fetched forward one
// in-flight window per pass, not one block per round trip.
BOOST_AUTO_TEST_CASE(a_deep_missing_ancestry_is_asked_as_one_range)
{
    BOOST_REQUIRE(fRegTest);
    BOOST_REQUIRE(pindexBest != NULL);
    CScopedGapState state;
    CScopedArg entries("-maxorphanblocks", "2500");
    CScopedArg mem("-maxorphanmem", "256");

    TestPeer peer(19431), server(19432);
    const NodeId owner = peer.node.GetId();

    const unsigned int nDepth = 300;
    const std::vector<CBlock> vHeaders = MakeHeaderChain(pindexBest->GetBlockHash(), nDepth, 31);
    const uint256 hashGap = vHeaders.back().GetHash();

    CBlock parked = DetachedBlockOn(hashGap, 7531);
    {
        LOCK(cs_main);
        BOOST_REQUIRE(ProcessBlock(&peer.node, &parked));
    }
    BOOST_REQUIRE(IsOrphanGapHashForPeer(owner, hashGap));
    BOOST_CHECK(SendMessages(&peer.node, false));
    // The socketless peer's optimistic write of the request marks it
    // disconnected; the message itself stays queued for inspection.
    peer.node.fDisconnect = false;

    std::vector<uint256> vStops = GetHeadersStops(peer.node);
    BOOST_CHECK_MESSAGE(vStops.size() == 1U,
                        "the park sent " << vStops.size() << " headers requests, not one range");
    BOOST_CHECK_MESSAGE(!vStops.empty() && vStops[0] == hashGap,
                        "the range request does not stop at the gap");

    // A second park on the same gap inside the interval adds no request.
    CBlock parked2 = DetachedBlockOn(hashGap, 7532);
    {
        LOCK(cs_main);
        BOOST_REQUIRE(ProcessBlock(&peer.node, &parked2));
    }
    BOOST_CHECK(SendMessages(&peer.node, false));
    BOOST_CHECK_MESSAGE(GetHeadersStops(peer.node).size() == 1U,
                        "a second park inside the interval sent another headers request");

    DeliverHeaders(server, peer, vHeaders);
    BOOST_CHECK(SendMessages(&peer.node, false));

    // The gap hash from the snapshot, then the run from the fork forward, to
    // exactly one window.
    BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.size() == MAX_BLOCKS_IN_FLIGHT_PER_PEER,
                        "a gated peer with a " << nDepth << "-deep gap was asked for "
                            << peer.node.setBlocksInFlight.size() << " blocks, not one window");
    BOOST_CHECK(peer.node.setBlocksInFlight.count(hashGap) == 1);
    for (unsigned int i = 0; i + 1 < MAX_BLOCKS_IN_FLIGHT_PER_PEER; i++)
        BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.count(vHeaders[i].GetHash()) == 1,
                            "ancestor " << i << " above the fork was not in the first window");
    BOOST_CHECK(peer.node.setBlocksInFlight.count(parked.GetHash()) == 0);
    BOOST_CHECK(peer.node.setBlocksInFlight.count(parked2.GetHash()) == 0);

    // The window frees; the next pass continues in order and repeats nothing.
    for (unsigned int i = 0; i + 1 < MAX_BLOCKS_IN_FLIGHT_PER_PEER; i++)
        peer.node.ClearBlockInFlight(vHeaders[i].GetHash());
    BOOST_CHECK(SendMessages(&peer.node, false));
    const unsigned int nFirst = MAX_BLOCKS_IN_FLIGHT_PER_PEER - 1;
    for (unsigned int i = nFirst; i < 2 * nFirst; i++)
        BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.count(vHeaders[i].GetHash()) == 1,
                            "ancestor " << i << " was not in the second window");
    for (unsigned int i = 0; i < nFirst; i++)
        BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.count(vHeaders[i].GetHash()) == 0,
                            "ancestor " << i << " was asked for twice");
    BOOST_CHECK(peer.node.setBlocksInFlight.size() <= MAX_BLOCKS_IN_FLIGHT_PER_PEER);
    BOOST_CHECK_MESSAGE(GetHeadersStops(peer.node).size() == 1U,
                        "the forward fetch sent another headers request");
}

// T17. The run ends below the first held orphan. A block above a held orphan
// parks on delivery, so it is not part of what the run fetches.
BOOST_AUTO_TEST_CASE(the_ancestry_run_ends_below_a_held_orphan)
{
    BOOST_REQUIRE(pindexBest != NULL);
    CScopedGapState state;
    TestPeer peer(19433), server(19434);
    const NodeId owner = peer.node.GetId();

    const std::vector<CBlock> vHeaders = MakeHeaderChain(pindexBest->GetBlockHash(), 40, 33);
    const size_t nHeld = 10;
    {
        LOCK(cs_main);
        CBlock* pheld = new CBlock(vHeaders[nHeld]);
        BOOST_REQUIRE(AddOrphanBlock(pheld->GetHash(), pheld, pheld->hashPrevBlock,
                                     owner, OrphanBlockFootprint(*pheld)));
        RecomputeOrphanGaps();
    }
    BOOST_REQUIRE(IsOrphanGapHashForPeer(owner, vHeaders[nHeld - 1].GetHash()));

    DeliverHeaders(server, peer, vHeaders);
    BOOST_CHECK_MESSAGE(peer.node.vAncestryFill.size() == nHeld,
                        "the run holds " << peer.node.vAncestryFill.size() << " hashes, not the "
                            << nHeld << " below the held orphan");
    BOOST_CHECK(SendMessages(&peer.node, false));

    for (size_t i = 0; i < nHeld; i++)
        BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.count(vHeaders[i].GetHash()) == 1,
                            "ancestor " << i << " below the held orphan was not requested");
    for (size_t i = nHeld; i < vHeaders.size(); i++)
        BOOST_CHECK_MESSAGE(peer.node.setBlocksInFlight.count(vHeaders[i].GetHash()) == 0,
                            "header " << i << " at or above the held orphan was requested");
}

// T18. A peer holding nothing is not gated and keeps the ordinary headers path:
// no run is recorded for it.
BOOST_AUTO_TEST_CASE(an_ungated_peer_records_no_ancestry_run)
{
    BOOST_REQUIRE(pindexBest != NULL);
    CScopedGapState state;
    TestPeer peer(19435), server(19436);
    BOOST_REQUIRE(!IsOrphanGapGatedPeer(peer.node.GetId()));

    DeliverHeaders(server, peer, MakeHeaderChain(pindexBest->GetBlockHash(), 20, 35));
    BOOST_CHECK_MESSAGE(peer.node.vAncestryFill.empty(),
                        "an ungated peer recorded an ancestry run of "
                            << peer.node.vAncestryFill.size());
}

// T19. A run whose last block is indexed while the peer is still gated asks
// for the next range from that block, once, and is dropped. A branch deeper
// than one headers reply is fetched range by range.
BOOST_AUTO_TEST_CASE(a_drained_run_asks_for_the_next_range_from_its_last_block)
{
    BOOST_REQUIRE(pindexBest != NULL);
    CScopedGapState state;
    TestPeer peer(19437);
    const NodeId owner = peer.node.GetId();

    ParkChain(76100, uint256((uint64_t)0x9ad00001ull), 2, owner);
    BOOST_REQUIRE(IsOrphanGapGatedPeer(owner));

    peer.node.vAncestryFill.push_back(pindexBest->GetBlockHash());
    peer.node.nAncestryFillNext = 1;
    BOOST_CHECK(SendMessages(&peer.node, false));

    BOOST_CHECK_MESSAGE(GetHeadersStops(peer.node).size() == 1U,
                        "a drained run sent " << GetHeadersStops(peer.node).size()
                            << " headers requests, not one");
    BOOST_CHECK_MESSAGE(peer.node.vAncestryFill.empty(), "the drained run was kept");

    BOOST_CHECK(SendMessages(&peer.node, false));
    BOOST_CHECK_MESSAGE(GetHeadersStops(peer.node).size() == 1U,
                        "the continuation was sent again on the next pass");
}

BOOST_AUTO_TEST_SUITE_END()
