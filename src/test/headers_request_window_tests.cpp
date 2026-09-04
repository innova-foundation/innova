// A peer's headers message must not pin the block-request window: header-derived
// requests go through AskFor, only within the window of the tip, never for a held
// orphan, and a full batch does not trigger a repeat getheaders from the same locator.

#include <boost/test/unit_test.hpp>

#include "main.h"
#include "net.h"

#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(headers_request_window_tests)

namespace {

// A peer with a real send buffer but no socket: PushMessage lands framed bytes in
// vSendMsg and the optimistic write fails, so they stay readable (same shape as
// block_inv_response_tests).
struct TestPeer
{
    CNode node;

    explicit TestPeer(int nPort)
        : node(INVALID_SOCKET, CAddress(CService("127.0.0.1", nPort)), "", false)
    {
        node.nVersion = PROTOCOL_VERSION;
        node.nPingNonceSent = 1;          // no ping on a dead socket
        node.fStartSync = false;          // no getblocks of our own
        node.nLastBlockRecv = GetTime();  // no stall-recovery announcement
        node.fPreferHeaders = true;
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

// Save, clear and restore the orphan tables so a test that parks a block as an
// orphan leaves no trace for the suites that follow.
class CScopedOrphanTables
{
    std::map<uint256, COrphanBlock> savedBlocks;
    std::multimap<uint256, CBlock*> savedByPrev;
    std::map<uint256, NodeId> savedByNode;
public:
    CScopedOrphanTables()
    {
        savedBlocks = mapOrphanBlocks;
        savedByPrev = mapOrphanBlocksByPrev;
        savedByNode = mapOrphanBlocksByNode;
        mapOrphanBlocks.clear();
        mapOrphanBlocksByPrev.clear();
        mapOrphanBlocksByNode.clear();
        RecomputeOrphanBlocksFootprint();
    }
    ~CScopedOrphanTables()
    {
        for (std::map<uint256, COrphanBlock>::iterator it = mapOrphanBlocks.begin();
             it != mapOrphanBlocks.end(); ++it)
            delete it->second.pblock;
        mapOrphanBlocks = savedBlocks;
        mapOrphanBlocksByPrev = savedByPrev;
        mapOrphanBlocksByNode = savedByNode;
        RecomputeOrphanBlocksFootprint();
    }
};

// A chain of header-only blocks off a given parent. Heights past the regtest DAG fork
// are PoW-checked by the handler, so grind the nonce against the regtest limit, which
// admits half of all hashes.
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

// Frame a headers message through a sender's PushMessage and feed the bytes to the
// receiver exactly as the socket thread would, then dispatch it.
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

struct Fixture
{
    Fixture()
    {
        LOCK(cs_mapAlreadyAskedFor);
        mapAlreadyAskedFor.clear();
    }
    ~Fixture()
    {
        LOCK(cs_mapAlreadyAskedFor);
        mapAlreadyAskedFor.clear();
    }
};

} // namespace

// A 2000-header batch requests at most one window of blocks, all within the window of
// the tip, and every request goes through the flush: nothing is marked in flight until
// SendMessages sends it.
BOOST_FIXTURE_TEST_CASE(batch_requests_at_most_one_window, Fixture)
{
    CScopedOrphanTables tables;
    BOOST_REQUIRE(pindexBest != NULL);
    TestPeer sender(19001), receiver(19002);

    std::vector<CBlock> vHeaders = MakeHeaderChain(pindexBest->GetBlockHash(), 2000, 1);
    DeliverHeaders(sender, receiver, vHeaders);

    // The handler queued asks but sent nothing itself.
    BOOST_CHECK_EQUAL(receiver.node.setBlocksInFlight.size(), 0U);
    BOOST_CHECK_EQUAL(CountCommand(receiver.node, "getdata"), 0U);
    BOOST_CHECK(receiver.node.mapAskFor.size() <= MAX_BLOCKS_IN_FLIGHT_PER_PEER);

    SendMessages(&receiver.node, false);

    BOOST_CHECK_EQUAL(receiver.node.setBlocksInFlight.size(), MAX_BLOCKS_IN_FLIGHT_PER_PEER);
    BOOST_CHECK(CountCommand(receiver.node, "getdata") >= 1U);
    // Exactly the first window of the chain is in flight; the header just past it is not.
    for (size_t i = 0; i < MAX_BLOCKS_IN_FLIGHT_PER_PEER; i++)
        BOOST_CHECK(receiver.node.setBlocksInFlight.count(vHeaders[i].GetHash()));
    BOOST_CHECK(!receiver.node.setBlocksInFlight.count(vHeaders[MAX_BLOCKS_IN_FLIGHT_PER_PEER].GetHash()));
}

// A held orphan and anything announced above it are not requested (see
// orphan_gap_gate_tests).
BOOST_FIXTURE_TEST_CASE(held_orphan_is_not_requested, Fixture)
{
    CScopedOrphanTables tables;
    BOOST_REQUIRE(pindexBest != NULL);
    TestPeer sender(19003), receiver(19004);

    std::vector<CBlock> vHeaders = MakeHeaderChain(pindexBest->GetBlockHash(), 40, 2);
    const size_t nHeld = 5;
    CBlock* pheld = new CBlock(vHeaders[nHeld]);
    {
        LOCK(cs_main);
        AddOrphanBlock(pheld->GetHash(), pheld, pheld->hashPrevBlock, (NodeId)-1,
                       OrphanBlockFootprint(*pheld));
    }

    DeliverHeaders(sender, receiver, vHeaders);
    SendMessages(&receiver.node, false);

    BOOST_CHECK(!receiver.node.setBlocksInFlight.count(vHeaders[nHeld].GetHash()));
    BOOST_CHECK(receiver.node.setBlocksInFlight.count(vHeaders[nHeld - 1].GetHash()));
    BOOST_CHECK(!receiver.node.setBlocksInFlight.count(vHeaders[nHeld + 1].GetHash()));
    BOOST_CHECK_EQUAL(receiver.node.setBlocksInFlight.size(), nHeld);
}

// A full node does not answer a full batch with another getheaders from the same locator.
BOOST_FIXTURE_TEST_CASE(full_node_does_not_continue_header_sync, Fixture)
{
    CScopedOrphanTables tables;
    BOOST_REQUIRE(pindexBest != NULL);
    BOOST_REQUIRE(!fSPVMode);
    TestPeer sender(19005), receiver(19006);

    DeliverHeaders(sender, receiver, MakeHeaderChain(pindexBest->GetBlockHash(), 2000, 3));
    SendMessages(&receiver.node, false);

    BOOST_CHECK_EQUAL(CountCommand(receiver.node, "getheaders"), 0U);
}

// A batch whose first parent is unknown requests nothing.
BOOST_FIXTURE_TEST_CASE(unknown_parent_requests_nothing, Fixture)
{
    CScopedOrphanTables tables;
    TestPeer sender(19007), receiver(19008);

    DeliverHeaders(sender, receiver, MakeHeaderChain(uint256((uint64_t)0xdeadbeef), 50, 4));
    SendMessages(&receiver.node, false);

    BOOST_CHECK_EQUAL(receiver.node.setBlocksInFlight.size(), 0U);
    BOOST_CHECK_EQUAL(receiver.node.mapAskFor.size(), 0U);
    BOOST_CHECK_EQUAL(CountCommand(receiver.node, "getdata"), 0U);
}

// Re-sending the same batch, or fresh batches off the tip, cannot grow the in-flight
// set past the window or the ask queue without bound.
BOOST_FIXTURE_TEST_CASE(repeated_batches_stay_bounded, Fixture)
{
    CScopedOrphanTables tables;
    BOOST_REQUIRE(pindexBest != NULL);
    TestPeer sender(19009), receiver(19010);

    std::vector<CBlock> vSame = MakeHeaderChain(pindexBest->GetBlockHash(), 2000, 5);
    for (int round = 0; round < 5; round++)
    {
        DeliverHeaders(sender, receiver, vSame);
        SendMessages(&receiver.node, false);
        BOOST_CHECK(receiver.node.setBlocksInFlight.size() <= MAX_BLOCKS_IN_FLIGHT_PER_PEER);
        BOOST_CHECK(receiver.node.mapAskFor.size() <= MAX_BLOCKS_IN_FLIGHT_PER_PEER);
    }
    for (int round = 0; round < 5; round++)
    {
        DeliverHeaders(sender, receiver, MakeHeaderChain(pindexBest->GetBlockHash(), 2000, 100 + round));
        SendMessages(&receiver.node, false);
        BOOST_CHECK(receiver.node.setBlocksInFlight.size() <= MAX_BLOCKS_IN_FLIGHT_PER_PEER);
        BOOST_CHECK(receiver.node.mapAskFor.size() <= 2 * MAX_BLOCKS_IN_FLIGHT_PER_PEER);
    }
}

// The DoS scorer resolves a peer by id (Misbehaving in main.cpp scans vNodes for a
// matching GetId()), and the per-peer orphan budget is a map keyed on it, so two live
// peers sharing an id score and charge each other.
BOOST_AUTO_TEST_CASE(each_peer_is_given_its_own_id)
{
    std::vector<TestPeer*> vPeers;
    for (int i = 0; i < 8; i++)
        vPeers.push_back(new TestPeer(20000 + i));

    std::set<NodeId> setIds;
    NodeId idPrev = 0;
    for (size_t i = 0; i < vPeers.size(); i++)
    {
        const NodeId id = vPeers[i]->node.GetId();
        BOOST_CHECK_MESSAGE(setIds.insert(id).second,
            strprintf("peer %d reused id %d", (int)i, (int)id));
        if (i > 0)
            BOOST_CHECK_MESSAGE(id > idPrev,
                strprintf("peer %d took id %d, not above %d", (int)i, (int)id, (int)idPrev));
        idPrev = id;
    }

    for (size_t i = 0; i < vPeers.size(); i++)
        delete vPeers[i];
}

BOOST_AUTO_TEST_SUITE_END()
