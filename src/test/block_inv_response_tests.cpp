// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include "main.h"
#include "net.h"
#include "protocol.h"
#include "util.h"

#include <algorithm>
#include <string>
#include <vector>

// Answers to explicit requests in vInventoryToSend must go out as inv: an
// unconnectable header is dropped and setInventoryKnown swallows the resend.
// Own-tip announcements to a sendheaders peer stay headers (BIP130).

BOOST_AUTO_TEST_SUITE(block_inv_response_tests)

namespace {

// A peer with a real send buffer but no socket: PushMessage lands the framed
// bytes in vSendMsg and the optimistic write fails, so they stay readable.
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

std::vector<std::string> SentCommands(CNode& node)
{
    std::vector<std::string> vCommands;
    LOCK(node.cs_vSend);
    for (const CSerializeData& data : node.vSendMsg)
    {
        const std::string strCommand = CommandOf(data);
        if (!strCommand.empty())
            vCommands.push_back(strCommand);
    }
    return vCommands;
}

bool SentAny(CNode& node, const std::string& strCommand)
{
    const std::vector<std::string> vCommands = SentCommands(node);
    return std::find(vCommands.begin(), vCommands.end(), strCommand) != vCommands.end();
}

std::string SentJoined(CNode& node)
{
    const std::vector<std::string> vCommands = SentCommands(node);
    std::string strOut;
    for (size_t i = 0; i < vCommands.size(); i++)
        strOut += (i ? "," : "") + vCommands[i];
    return strOut.empty() ? std::string("<nothing>") : strOut;
}

// True when some inv message on the wire announces this block.
bool InvAnnounces(CNode& node, const uint256& hash)
{
    LOCK(node.cs_vSend);
    for (const CSerializeData& data : node.vSendMsg)
    {
        if (CommandOf(data) != "inv")
            continue;
        const char* pBegin = &data[0] + CMessageHeader::HEADER_SIZE;
        const char* pEnd = &data[0] + data.size();
        CDataStream ss(pBegin, pEnd, SER_NETWORK, PROTOCOL_VERSION);
        std::vector<CInv> vInv;
        try
        {
            ss >> vInv;
        }
        catch (const std::exception&)
        {
            continue;
        }
        for (const CInv& inv : vInv)
            if (inv.type == MSG_BLOCK && inv.hash == hash)
                return true;
    }
    return false;
}

// A header we hold, standing in for one a getblocks walk reaches via pnext.
CBlock MakeHeader(unsigned int nSeed)
{
    CBlock header;
    header.nVersion = 8;
    header.hashPrevBlock = uint256(nSeed + 1);
    header.hashMerkleRoot = uint256(nSeed + 2);
    header.nTime = 1700000000 + nSeed;
    header.nBits = 0x1d00ffff;
    header.nNonce = nSeed;
    return header;
}

// The drain looks the queued hash up in mapBlockIndex, so a request answer only
// reproduces if the block is one we actually have.
struct ScopedBlockIndex
{
    uint256 hash;
    CBlockIndex* pindex;

    explicit ScopedBlockIndex(unsigned int nSeed)
    {
        CBlock header = MakeHeader(nSeed);
        hash = header.GetHash();
        pindex = new CBlockIndex(0, 0, header);
        pindex->nHeight = 1512;
        std::pair<std::map<uint256, CBlockIndex*>::iterator, bool> ins =
            mapBlockIndex.insert(std::make_pair(hash, pindex));
        BOOST_REQUIRE(ins.second);
        pindex->phashBlock = &ins.first->first;
    }

    ~ScopedBlockIndex()
    {
        mapBlockIndex.erase(hash);
        delete pindex;
    }
};

void QueueRequestAnswer(CNode& node, const uint256& hash)
{
    LOCK(node.cs_inventory);
    node.vInventoryToSend.push_back(CInv(MSG_BLOCK, hash));
}

} // namespace

// The defect: a getblocks answer queued for a sendheaders peer went out as a
// bare header, which the requester cannot connect and never re-requests.
BOOST_AUTO_TEST_CASE(getblocks_answer_goes_out_as_inv_to_a_sendheaders_peer)
{
    ScopedBlockIndex block(0x51a11edu);
    TestPeer peer(18450);
    BOOST_REQUIRE(peer.node.fPreferHeaders);

    QueueRequestAnswer(peer.node, block.hash);
    SendMessages(&peer.node, false);

    BOOST_CHECK_MESSAGE(InvAnnounces(peer.node, block.hash),
        "a block queued on vInventoryToSend did not reach a sendheaders peer as an inv "
        "(sent: " << SentJoined(peer.node) << "). A getblocks answer rewritten into a "
        "header is unconnectable at the requester, which then issues no getdata and "
        "stalls, and setInventoryKnown swallows every retry.");
    BOOST_CHECK_MESSAGE(!SentAny(peer.node, "headers"),
        "the request-answer queue emitted a headers message (sent: "
        << SentJoined(peer.node) << "); headers belong to the tip-announcement path only");
}

// Same queue, peer that never sent sendheaders: inv both before and after.
BOOST_AUTO_TEST_CASE(getblocks_answer_goes_out_as_inv_to_a_plain_peer)
{
    ScopedBlockIndex block(0x51a11eeu);
    TestPeer peer(18451);
    peer.node.fPreferHeaders = false;

    QueueRequestAnswer(peer.node, block.hash);
    SendMessages(&peer.node, false);

    BOOST_CHECK_MESSAGE(InvAnnounces(peer.node, block.hash),
        "a block queued on vInventoryToSend did not reach a plain peer as an inv (sent: "
        << SentJoined(peer.node) << ")");
}

// The path that must keep its headers: announcing our own new tip (BIP130).
BOOST_AUTO_TEST_CASE(tip_announcement_to_a_sendheaders_peer_stays_headers)
{
    TestPeer peer(18452);
    BOOST_REQUIRE(peer.node.fPreferHeaders);

    const CBlock header = MakeHeader(0xb1300001u);
    PushBlockAnnouncement(&peer.node, header, true);

    BOOST_CHECK_MESSAGE(SentAny(peer.node, "headers"),
        "a spontaneous tip announcement to a sendheaders peer must be a headers message (sent: "
        << SentJoined(peer.node) << ")");
    BOOST_CHECK_MESSAGE(!SentAny(peer.node, "inv"),
        "a sendheaders peer was announced a new tip by inv (sent: "
        << SentJoined(peer.node) << ")");
}

// The same announcement to a peer that never sent sendheaders queues an inv,
// and the drain must carry it out as one.
BOOST_AUTO_TEST_CASE(tip_announcement_to_a_plain_peer_stays_inv)
{
    TestPeer peer(18453);
    peer.node.fPreferHeaders = false;

    const CBlock header = MakeHeader(0xb1300002u);
    PushBlockAnnouncement(&peer.node, header, true);
    SendMessages(&peer.node, false);

    BOOST_CHECK_MESSAGE(InvAnnounces(peer.node, header.GetHash()),
        "a tip announcement to a plain peer did not go out as an inv (sent: "
        << SentJoined(peer.node) << ")");
    BOOST_CHECK_MESSAGE(!SentAny(peer.node, "headers"),
        "a peer that never sent sendheaders received a headers message (sent: "
        << SentJoined(peer.node) << ")");
}

BOOST_AUTO_TEST_SUITE_END()
