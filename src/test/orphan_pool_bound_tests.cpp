// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The orphan block pool is bounded in bytes as well as entries; the byte bound refuses
// and never evicts, and a per-peer share limits each peer. Linked last in TEST_OBJS.

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdio>
#include <deque>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "../bignum.h"
#include "../dag.h"
#include "../init.h"
#include "../main.h"
#include "../miner.h"
#include "../net.h"
#include "../shielded.h"
#include "../uint256.h"
#include "../wallet.h"

extern bool fRegTest;

BOOST_AUTO_TEST_SUITE(orphan_pool_bound_tests)

namespace
{

// A peer with a real send buffer but no socket: the park sites push getblocks and
// AskFor entries onto it and nothing is written.
struct TestPeer
{
    CNode node;

    explicit TestPeer(int nPort)
        : node(INVALID_SOCKET, CAddress(CService("127.0.0.1", nPort)), "", false)
    {
        node.nVersion = PROTOCOL_VERSION;
        node.nPingNonceSent = 1;
        node.fStartSync = false;
        node.nLastBlockRecv = GetTime();
    }
};

// Save, clear and restore the orphan tables, so a case leaves nothing behind.
class CScopedOrphanTables
{
    std::map<uint256, COrphanBlock> savedBlocks;
    std::multimap<uint256, CBlock*> savedByPrev;
    std::map<uint256, NodeId> savedByNode;
    std::map<NodeId, int> savedCount;
    std::set<std::pair<COutPoint, unsigned int> > savedStakeSeen;

public:
    CScopedOrphanTables()
    {
        LOCK(cs_main);
        savedBlocks = mapOrphanBlocks;
        savedByPrev = mapOrphanBlocksByPrev;
        savedByNode = mapOrphanBlocksByNode;
        savedCount = mapOrphanCountByNode;
        savedStakeSeen = setStakeSeenOrphan;
        mapOrphanBlocks.clear();
        mapOrphanBlocksByPrev.clear();
        mapOrphanBlocksByNode.clear();
        mapOrphanCountByNode.clear();
        setStakeSeenOrphan.clear();
        ClearOrphanRefusalRecords();
        ClearOrphanDepartedOwners();
        ClearOrphanBlockRequestSuppression();
        RecomputeOrphanBlocksFootprint();
    }
    ~CScopedOrphanTables()
    {
        LOCK(cs_main);
        for (std::map<uint256, COrphanBlock>::iterator it = mapOrphanBlocks.begin();
             it != mapOrphanBlocks.end(); ++it)
            delete it->second.pblock;
        mapOrphanBlocks = savedBlocks;
        mapOrphanBlocksByPrev = savedByPrev;
        mapOrphanBlocksByNode = savedByNode;
        mapOrphanCountByNode = savedCount;
        setStakeSeenOrphan = savedStakeSeen;
        ClearOrphanRefusalRecords();
        ClearOrphanDepartedOwners();
        ClearOrphanBlockRequestSuppression();
        RecomputeOrphanBlocksFootprint();
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

// Remove one -arg for the duration of a case, so a default can be read.
class CScopedArgUnset
{
    std::string strName;
    std::string strSaved;
    bool fHad;

public:
    explicit CScopedArgUnset(const std::string& strNameIn)
        : strName(strNameIn)
    {
        fHad = mapArgs.count(strName) != 0;
        if (fHad)
            strSaved = mapArgs[strName];
        mapArgs.erase(strName);
    }
    ~CScopedArgUnset()
    {
        if (fHad)
            mapArgs[strName] = strSaved;
        else
            mapArgs.erase(strName);
    }
};

// Reads a peer's count without creating an entry: operator[] would insert a zero
// and the invariant below forbids one.
int OrphanCountFor(NodeId id)
{
    std::map<NodeId, int>::const_iterator it = mapOrphanCountByNode.find(id);
    return it == mapOrphanCountByNode.end() ? 0 : it->second;
}

// total == sum(record.nFootprint); the by-prev index carries one entry per held
// block; every owned block has a positive count; no count is zero or negative.
void CheckPoolInvariants(const char* pszWhere)
{
    LOCK(cs_main);

    size_t nSum = 0;
    for (std::map<uint256, COrphanBlock>::const_iterator it = mapOrphanBlocks.begin();
         it != mapOrphanBlocks.end(); ++it)
    {
        nSum += it->second.nFootprint;
        BOOST_CHECK_MESSAGE(it->second.pblock != NULL,
                            "a record holds no block at " << pszWhere);
    }
    BOOST_CHECK_MESSAGE(nSum == GetOrphanBlocksFootprint(),
                        "the orphan pool total is not the sum of its records at "
                            << pszWhere << " (total " << GetOrphanBlocksFootprint()
                            << ", sum " << nSum << ")");

    BOOST_CHECK_MESSAGE(mapOrphanBlocks.size() == mapOrphanBlocksByPrev.size(),
                        "the by-prev index and the record set disagree at "
                            << pszWhere << " (" << mapOrphanBlocks.size() << " vs "
                            << mapOrphanBlocksByPrev.size() << ")");

    for (std::map<NodeId, int>::const_iterator it = mapOrphanCountByNode.begin();
         it != mapOrphanCountByNode.end(); ++it)
        BOOST_CHECK_MESSAGE(it->second > 0,
                            "peer " << it->first << " holds a non-positive orphan count "
                                    << it->second << " at " << pszWhere);

    size_t nCounted = 0;
    for (std::map<NodeId, int>::const_iterator it = mapOrphanCountByNode.begin();
         it != mapOrphanCountByNode.end(); ++it)
        nCounted += (size_t)it->second;
    BOOST_CHECK_MESSAGE(nCounted == mapOrphanBlocksByNode.size(),
                        "per-peer counts do not add up to the owned blocks at "
                            << pszWhere << " (" << nCounted << " vs "
                            << mapOrphanBlocksByNode.size() << ")");

    // The per-owner split is what byte pressure aims with, so it has to be the
    // same bytes the bound is measured in, owner by owner and with no bucket
    // left behind for an owner that holds nothing.
    std::map<NodeId, size_t> mapBytes;
    size_t nUnowned = 0;
    for (std::map<uint256, COrphanBlock>::const_iterator it = mapOrphanBlocks.begin();
         it != mapOrphanBlocks.end(); ++it)
    {
        std::map<uint256, NodeId>::const_iterator itOwner = mapOrphanBlocksByNode.find(it->first);
        if (itOwner == mapOrphanBlocksByNode.end())
            nUnowned += it->second.nFootprint;
        else
            mapBytes[itOwner->second] += it->second.nFootprint;
    }
    for (std::map<NodeId, size_t>::const_iterator it = mapBytes.begin(); it != mapBytes.end(); ++it)
        BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprintForNode(it->first) == it->second,
                            "peer " << it->first << " is charged "
                                    << GetOrphanBlocksFootprintForNode(it->first)
                                    << " bytes but holds " << it->second << " at " << pszWhere);
    BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprintForNode(-1) == nUnowned,
                        "the unowned bytes are " << GetOrphanBlocksFootprintForNode(-1)
                            << " but the unowned records hold " << nUnowned << " at " << pszWhere);
    BOOST_CHECK_MESSAGE(GetOrphanOwnerBucketCount() == mapBytes.size(),
                        "the per-owner byte split carries " << GetOrphanOwnerBucketCount()
                            << " owners against " << mapBytes.size() << " holding blocks at "
                            << pszWhere);
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

CBlockIndex* BestIndex()
{
    LOCK(cs_main);
    return pindexBest;
}

// A signed, well-formed proof-of-work template on the current chain, with the
// coinbase already carrying its extra nonce.
CBlock BaseTemplate()
{
    unsigned int nExtraNonce = 0;
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblock.get() != NULL);
    CBlockIndex* pindexPrev = NULL;
    {
        LOCK(cs_main);
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(pblock->hashPrevBlock);
        BOOST_REQUIRE(mi != mapBlockIndex.end());
        pindexPrev = mi->second;
    }
    IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);
    return *pblock;
}

// One padding transaction of roughly nBytes wire bytes.
CTransaction PadTx(unsigned int nTime, unsigned int nSeed, size_t nBytes)
{
    CTransaction tx;
    tx.nTime = nTime;
    tx.vin.push_back(CTxIn(COutPoint(uint256((uint64_t)nSeed), 0)));
    CTxOut out;
    out.nValue = 1;
    if (nBytes == 0)
        out.scriptPubKey = CScript() << OP_1;
    else
        out.scriptPubKey = CScript() << OP_RETURN
                                     << std::vector<unsigned char>(nBytes, (unsigned char)(nSeed & 0xff));
    tx.vout.push_back(out);
    return tx;
}

// A block whose parent this node does not have, so ProcessBlock reaches the
// classic park site. nPadTx padding transactions of nPadBytes each set its size.
CBlock DetachedBlock(const CBlock& tmpl, unsigned int nSeed, unsigned int nPadTx, size_t nPadBytes)
{
    CBlock block = tmpl;
    block.hashPrevBlock = uint256((uint64_t)0xd00d0000u + nSeed);
    block.vtx.reserve(block.vtx.size() + nPadTx);
    for (unsigned int i = 0; i < nPadTx; i++)
        block.vtx.push_back(PadTx(block.nTime, nSeed * 100003u + i + 1, nPadBytes));
    block.nNonce = nSeed;
    block.vMerkleTree.clear();
    block.hashMerkleRoot = block.BuildMerkleTree();
    BOOST_REQUIRE(SolveBlock(&block));
    BOOST_REQUIRE_MESSAGE(block.CheckBlock(), "the detached block is not admissible");
    return block;
}

std::vector<uint256> CoinbaseDAGParents(const CBlock& block, int nHeight)
{
    std::vector<uint256> vParents;
    if (block.vtx.empty())
        return vParents;
    std::vector<CScript> vScripts;
    for (std::vector<CTxOut>::const_iterator it = block.vtx[0].vout.begin();
         it != block.vtx[0].vout.end(); ++it)
        vScripts.push_back(it->scriptPubKey);
    std::string strError;
    if (!ReadDAGParentCommitmentAtHeight(vScripts, nHeight, vParents, strError))
        vParents.clear();
    return vParents;
}

// A block on a known parent whose coinbase commits to one merge parent this node
// does not have, so ProcessBlock reaches the DAG park site. Returns the missing
// hash in hashMissingOut.
CBlock DAGOrphanBlock(const CBlock& tmpl, unsigned int nSeed, unsigned int nPadTx,
                      size_t nPadBytes, uint256& hashMissingOut)
{
    CBlock block = tmpl;

    int nHeight = 0;
    {
        LOCK(cs_main);
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
        BOOST_REQUIRE(mi != mapBlockIndex.end());
        nHeight = mi->second->nHeight + 1;
    }
    BOOST_REQUIRE_GE(nHeight, FORK_HEIGHT_DAG);

    std::vector<uint256> vParents = CoinbaseDAGParents(block, nHeight);
    BOOST_REQUIRE_MESSAGE(!vParents.empty(), "the template committed no DAG parents");

    hashMissingOut = uint256((uint64_t)0xa05e2700u + nSeed);
    vParents.push_back(hashMissingOut);

    // Replace the commitment output the reader actually reads.
    bool fReplaced = false;
    for (unsigned int i = 0; i < block.vtx[0].vout.size(); i++)
    {
        std::vector<uint256> vOne;
        std::string strWhy;
        const bool fCarries =
            DecodeCanonicalDAGParentScript(block.vtx[0].vout[i].scriptPubKey, vOne, strWhy)
                == DAG_PARENT_VALID ||
            !ExtractDAGParents(block.vtx[0].vout[i].scriptPubKey).empty();
        if (!fCarries)
            continue;
        block.vtx[0].vout[i].scriptPubKey = BuildDAGParentScript(vParents);
        fReplaced = true;
        break;
    }
    BOOST_REQUIRE_MESSAGE(fReplaced, "no canonical DAG parent commitment in the template coinbase");

    for (unsigned int i = 0; i < nPadTx; i++)
        block.vtx.push_back(PadTx(block.nTime, 0x5eed0000u + nSeed * 977u + i, nPadBytes));

    block.nNonce = 0x1000u + nSeed;
    block.vMerkleTree.clear();
    block.hashMerkleRoot = block.BuildMerkleTree();
    BOOST_REQUIRE(SolveBlock(&block));
    BOOST_REQUIRE_MESSAGE(block.CheckBlock(), "the DAG orphan block is not admissible");

    std::vector<uint256> vReadBack = CoinbaseDAGParents(block, nHeight);
    BOOST_REQUIRE_MESSAGE(!vReadBack.empty() && vReadBack.back() == hashMissingOut,
                          "the rewritten commitment does not read back");
    return block;
}

bool Deliver(TestPeer& peer, CBlock& block)
{
    LOCK(cs_main);
    return ProcessBlock(&peer.node, &block);
}

// A record with no wire form, for setting up a pool state cheaply. Parked through
// the real writer, with its real footprint.
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

void ParkSynthetic(CBlock* pblock, NodeId owner)
{
    LOCK(cs_main);
    AddOrphanBlock(pblock->GetHash(), pblock, pblock->hashPrevBlock, owner,
                   OrphanBlockFootprint(*pblock));
}

// A padded record with no wire form: the cheapest way to put byte-heavy records
// in the pool, since nothing validates a block parked through the writer.
CBlock* SyntheticOrphanPadded(unsigned int nSeed, const uint256& hashPrev, unsigned int nPadTx)
{
    CBlock* pblock = SyntheticOrphan(nSeed, hashPrev);
    for (unsigned int i = 0; i < nPadTx; i++)
        pblock->vtx.push_back(PadTx(pblock->nTime, nSeed * 100003u + i + 1, 0));
    return pblock;
}

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

// Every inventory item this peer has actually been sent a getdata for. Read off
// the framed bytes in its send buffer, so what is under test is the message that
// left the node and not a queue it might never drain.
std::vector<CInv> GetDataSentTo(CNode& node)
{
    std::vector<CInv> vSent;
    LOCK(node.cs_vSend);
    for (std::deque<CSerializeData>::const_iterator it = node.vSendMsg.begin();
         it != node.vSendMsg.end(); ++it)
    {
        if (CommandOf(*it) != "getdata")
            continue;
        CDataStream ss(std::vector<char>(it->begin() + (size_t)CMessageHeader::HEADER_SIZE, it->end()),
                       SER_NETWORK, PROTOCOL_VERSION);
        std::vector<CInv> vInv;
        try { ss >> vInv; } catch (const std::exception&) { continue; }
        vSent.insert(vSent.end(), vInv.begin(), vInv.end());
    }
    return vSent;
}

bool AskedFor(CNode& node, const uint256& hash)
{
    for (std::multimap<int64_t, CInv>::const_iterator it = node.mapAskFor.begin();
         it != node.mapAskFor.end(); ++it)
        if (it->second.type == MSG_BLOCK && it->second.hash == hash)
            return true;
    return false;
}

// The time a queued request for this hash is scheduled for, in microseconds, or
// -1 if nothing is queued. The deferral a refusal applies is only visible here
// and in mapAlreadyAskedFor.
int64_t AskForTimeFor(CNode& node, const uint256& hash)
{
    for (std::multimap<int64_t, CInv>::const_iterator it = node.mapAskFor.begin();
         it != node.mapAskFor.end(); ++it)
        if (it->second.type == MSG_BLOCK && it->second.hash == hash)
            return it->first;
    return -1;
}

// The furthest-out queued request for a hash, in microseconds, or -1. The cap is
// on how far a refusal may push the next request, so the last one queued is what
// it has to hold for.
int64_t MaxAskForTimeFor(CNode& node, const uint256& hash)
{
    int64_t nMax = -1;
    for (std::multimap<int64_t, CInv>::const_iterator it = node.mapAskFor.begin();
         it != node.mapAskFor.end(); ++it)
        if (it->second.type == MSG_BLOCK && it->second.hash == hash && it->first > nMax)
            nMax = it->first;
    return nMax;
}

int64_t AlreadyAskedForTime(const uint256& hash)
{
    LOCK(cs_mapAlreadyAskedFor);
    std::map<CInv, int64_t>::const_iterator it = mapAlreadyAskedFor.find(CInv(MSG_BLOCK, hash));
    return it == mapAlreadyAskedFor.end() ? -1 : it->second;
}

void ForgetAskedFor(const uint256& hash)
{
    LOCK(cs_mapAlreadyAskedFor);
    mapAlreadyAskedFor.erase(CInv(MSG_BLOCK, hash));
}

// Turn a peer's queues into framed messages. The peer has no socket, so the send
// attempt itself fails and flags the peer for disconnect; the cases are about
// what was framed, so the flag is cleared again.
bool FlushToWire(CNode& node)
{
    const bool fOk = SendMessages(&node, true);
    node.fDisconnect = false;
    return fOk;
}

// Framed messages of one command in a peer's send buffer.
unsigned int MessagesSentTo(CNode& node, const std::string& strCommand)
{
    unsigned int nCount = 0;
    LOCK(node.cs_vSend);
    for (std::deque<CSerializeData>::const_iterator it = node.vSendMsg.begin();
         it != node.vSendMsg.end(); ++it)
        if (CommandOf(*it) == strCommand)
            nCount++;
    return nCount;
}

// Drives GetTime for a case. Every clock the pool reads -- the park stamp, the
// expiry, the refusal deferral -- goes through it, so a case can age a pool
// without waiting.
class CScopedMockTime
{
public:
    explicit CScopedMockTime(int64_t nTime) { SetMockTime(nTime); }
    void Set(int64_t nTime) { SetMockTime(nTime); }
    ~CScopedMockTime() { SetMockTime(0); }
};

// A detached block whose held footprint exceeds nMinFootprint. Padding is added
// in bulk from the measured per-transaction cost, because measuring the whole
// block on every added transaction is quadratic in its size.
CBlock DetachedBlockOverFootprint(const CBlock& tmpl, unsigned int nSeed, size_t nMinFootprint)
{
    CBlock block = tmpl;
    block.hashPrevBlock = uint256((uint64_t)0xd00d0000u + nSeed);

    const CTransaction txPad = PadTx(block.nTime, nSeed, 0);
    const size_t nPerTx = ::GetSerializeSize(txPad, SER_NETWORK, PROTOCOL_VERSION)
                        + sizeof(CTransaction) + txPad.vin.size() * sizeof(CTxIn)
                        + txPad.vout.size() * sizeof(CTxOut) + 2 * sizeof(uint256);
    BOOST_REQUIRE(nPerTx > 0);

    const size_t nBase = OrphanBlockFootprint(block);
    unsigned int nNext = 1;
    if (nMinFootprint > nBase)
    {
        const unsigned int nBulk = (unsigned int)((nMinFootprint - nBase) / nPerTx);
        for (unsigned int i = 0; i < nBulk; i++)
            block.vtx.push_back(PadTx(block.nTime, nSeed * 100003u + nNext++, 0));
    }
    while (OrphanBlockFootprint(block) <= nMinFootprint)
    {
        for (unsigned int i = 0; i < 64; i++)
            block.vtx.push_back(PadTx(block.nTime, nSeed * 100003u + nNext++, 0));
        BOOST_REQUIRE(nNext < 200000u);
    }

    block.nNonce = nSeed;
    block.vMerkleTree.clear();
    block.hashMerkleRoot = block.BuildMerkleTree();
    BOOST_REQUIRE(SolveBlock(&block));
    BOOST_REQUIRE_MESSAGE(block.CheckBlock(), "the oversize detached block is not admissible");
    return block;
}

const size_t nMiB = 1024 * 1024;

// Many minimal transactions maximise held footprint per wire byte: about one MiB
// of footprint at the measured expansion.
const unsigned int nTxFill = 500;

// Park records owned by other peers until one more block of nIncoming bytes no longer
// fits, filling the pool exactly to its ceiling. Returns the hashes parked.
std::vector<uint256> FillPoolAgainst(size_t nIncoming, const NodeId* pOwners, size_t nOwners,
                                     unsigned int nSeed, uint64_t nPrevBase)
{
    const size_t nCeiling = GetMaxOrphanBlocksFootprint();
    // Bytes one padding transaction costs, from the measured expansion.
    const size_t nPerTx = 2100;
    std::vector<uint256> vHeld;
    const unsigned int nSeedFirst = nSeed;
    while (GetOrphanBlocksFootprint() + nIncoming <= nCeiling)
    {
        const size_t nGap = nCeiling - GetOrphanBlocksFootprint();
        const unsigned int nPad = (unsigned int)std::min((size_t)nTxFill, nGap / nPerTx);
        if (nPad == 0)
            break;
        CBlock* pblock = SyntheticOrphanPadded(nSeed, uint256(nPrevBase + nSeed), nPad);
        if (OrphanBlockFootprint(*pblock) > nGap)
        {
            delete pblock;
            break;
        }
        vHeld.push_back(pblock->GetHash());
        ParkSynthetic(pblock, pOwners[nSeed % nOwners]);
        nSeed++;
        BOOST_REQUIRE(nSeed < nSeedFirst + 400);
    }
    return vHeld;
}

// Park padded records owned by one peer, through the real room test, until it is
// refused. Returns the number parked.
unsigned int FillOwnerToItsShare(NodeId owner, unsigned int nSeedBase, unsigned int nMax)
{
    unsigned int nParked = 0;
    for (unsigned int i = 0; i < nMax; i++)
    {
        CBlock* pblock = SyntheticOrphanPadded(nSeedBase + i,
                                               uint256((uint64_t)0xb0110000u + nSeedBase + i),
                                               nTxFill);
        const size_t nFootprint = OrphanBlockFootprint(*pblock);
        LOCK(cs_main);
        if (!PruneOrphanBlocks(nFootprint, owner))
        {
            delete pblock;
            break;
        }
        AddOrphanBlock(pblock->GetHash(), pblock, pblock->hashPrevBlock, owner, nFootprint);
        nParked++;
    }
    return nParked;
}

// A header-only block on a given parent, ground against the regtest limit so the
// headers handler's own proof-of-work check admits it.
CBlock MakeHeaderOn(const uint256& hashParent, unsigned int nSeed)
{
    CBlock header;
    header.nVersion = CBlock::CURRENT_VERSION;
    header.hashPrevBlock = hashParent;
    header.hashMerkleRoot = uint256((uint64_t)(nSeed * 100003u + 1));
    header.nTime = (unsigned int)(GetAdjustedTime() - 10);
    header.nBits = bnProofOfWorkLimit.GetCompact();
    header.nNonce = 1;
    while (!CheckProofOfWork(header.GetHash(), header.nBits))
        header.nNonce++;
    return header;
}

// The header form of a block: the same hash, no transactions on the wire.
CBlock HeaderOf(const CBlock& block)
{
    CBlock header = block;
    header.vtx.clear();
    header.vMerkleTree.clear();
    return header;
}

// Frame a headers message through a sender's PushMessage and feed the bytes to a
// receiver exactly as the socket thread would, then dispatch it. What is under
// test is the real handler and not a copy of its request rule.
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
    LOCK(receiver.node.cs_vRecvMsg);
    BOOST_REQUIRE(ProcessMessages(&receiver.node));
}

CBlockIndex* MineOne()
{
    unsigned int nExtraNonce = 0;
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblock.get() != NULL);
    CBlockIndex* pindexPrev = NULL;
    {
        LOCK(cs_main);
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(pblock->hashPrevBlock);
        BOOST_REQUIRE(mi != mapBlockIndex.end());
        pindexPrev = mi->second;
    }
    IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);
    BOOST_REQUIRE(SolveBlock(pblock.get()));
    const uint256 hash = pblock->GetHash();
    {
        LOCK(cs_main);
        BOOST_REQUIRE(ProcessBlock(NULL, pblock.get()));
        BOOST_REQUIRE(mapBlockIndex.count(hash) != 0);
        return mapBlockIndex[hash];
    }
}

// A solved block on the current tip that is not processed, so its hash can be
// named as a merge parent before it is in the index.
CBlock SolvedBlockOnTip(unsigned int nExtraNonce)
{
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    BOOST_REQUIRE(pblock.get() != NULL);
    CBlockIndex* pindexPrev = NULL;
    {
        LOCK(cs_main);
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(pblock->hashPrevBlock);
        BOOST_REQUIRE(mi != mapBlockIndex.end());
        pindexPrev = mi->second;
    }
    IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);
    BOOST_REQUIRE(SolveBlock(pblock.get()));
    return *pblock;
}

// A block on a known parent whose coinbase commits to hashMissing as a merge
// parent and whose held footprint exceeds nMinFootprint: a DAG orphan the pool
// can never hold.
CBlock DAGOrphanBlockOverFootprint(const CBlock& tmpl, unsigned int nSeed,
                                   const std::vector<uint256>& vMissing, size_t nMinFootprint)
{
    CBlock block = tmpl;

    int nHeight = 0;
    {
        LOCK(cs_main);
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
        BOOST_REQUIRE(mi != mapBlockIndex.end());
        nHeight = mi->second->nHeight + 1;
    }
    BOOST_REQUIRE_GE(nHeight, FORK_HEIGHT_DAG);

    std::vector<uint256> vParents = CoinbaseDAGParents(block, nHeight);
    BOOST_REQUIRE_MESSAGE(!vParents.empty(), "the template committed no DAG parents");
    BOOST_REQUIRE(!vMissing.empty());
    for (unsigned int i = 0; i < vMissing.size(); i++)
        vParents.push_back(vMissing[i]);

    bool fReplaced = false;
    for (unsigned int i = 0; i < block.vtx[0].vout.size(); i++)
    {
        std::vector<uint256> vOne;
        std::string strWhy;
        const bool fCarries =
            DecodeCanonicalDAGParentScript(block.vtx[0].vout[i].scriptPubKey, vOne, strWhy)
                == DAG_PARENT_VALID ||
            !ExtractDAGParents(block.vtx[0].vout[i].scriptPubKey).empty();
        if (!fCarries)
            continue;
        block.vtx[0].vout[i].scriptPubKey = BuildDAGParentScript(vParents);
        fReplaced = true;
        break;
    }
    BOOST_REQUIRE_MESSAGE(fReplaced, "no canonical DAG parent commitment in the template coinbase");

    const CTransaction txPad = PadTx(block.nTime, nSeed, 0);
    const size_t nPerTx = ::GetSerializeSize(txPad, SER_NETWORK, PROTOCOL_VERSION)
                        + sizeof(CTransaction) + txPad.vin.size() * sizeof(CTxIn)
                        + txPad.vout.size() * sizeof(CTxOut) + 2 * sizeof(uint256);
    const size_t nBase = OrphanBlockFootprint(block);
    unsigned int nNext = 1;
    if (nMinFootprint > nBase)
    {
        const unsigned int nBulk = (unsigned int)((nMinFootprint - nBase) / nPerTx);
        for (unsigned int i = 0; i < nBulk; i++)
            block.vtx.push_back(PadTx(block.nTime, nSeed * 100003u + nNext++, 0));
    }
    while (OrphanBlockFootprint(block) <= nMinFootprint)
    {
        for (unsigned int i = 0; i < 64; i++)
            block.vtx.push_back(PadTx(block.nTime, nSeed * 100003u + nNext++, 0));
        BOOST_REQUIRE(nNext < 200000u);
    }

    block.nNonce = 0x2000u + nSeed;
    block.vMerkleTree.clear();
    block.hashMerkleRoot = block.BuildMerkleTree();
    BOOST_REQUIRE(SolveBlock(&block));
    BOOST_REQUIRE_MESSAGE(block.CheckBlock(), "the oversize DAG orphan is not admissible");

    std::vector<uint256> vReadBack = CoinbaseDAGParents(block, nHeight);
    BOOST_REQUIRE_MESSAGE(vReadBack.size() >= vMissing.size(),
                          "the rewritten commitment does not read back");
    for (unsigned int i = 0; i < vMissing.size(); i++)
        BOOST_REQUIRE_MESSAGE(vReadBack[vReadBack.size() - vMissing.size() + i] == vMissing[i],
                              "the rewritten commitment does not read back");
    return block;
}

CBlock DAGOrphanBlockOverFootprint(const CBlock& tmpl, unsigned int nSeed,
                                   const uint256& hashMissing, size_t nMinFootprint)
{
    return DAGOrphanBlockOverFootprint(tmpl, nSeed, std::vector<uint256>(1, hashMissing),
                                       nMinFootprint);
}

// Frame an inv message the same way DeliverHeaders frames headers.
void DeliverInv(TestPeer& sender, TestPeer& receiver, const std::vector<CInv>& vInv)
{
    sender.node.PushMessage("inv", vInv);
    CSerializeData data;
    {
        LOCK(sender.node.cs_vSend);
        BOOST_REQUIRE(!sender.node.vSendMsg.empty());
        data = sender.node.vSendMsg.back();
        sender.node.vSendMsg.clear();
    }
    BOOST_REQUIRE(receiver.node.ReceiveMsgBytes(&data[0], (unsigned int)data.size()));
    LOCK(receiver.node.cs_vRecvMsg);
    BOOST_REQUIRE(ProcessMessages(&receiver.node));
}

// The DAG park site only exists past the fork, so a case that needs it mines to
// it rather than depending on what earlier suites left behind.
void EnsureDAGHeight()
{
    for (int i = 0; i < 40 && BestIndex()->nHeight + 1 < FORK_HEIGHT_DAG + 2; i++)
        MineOne();
    BOOST_REQUIRE_GE(BestIndex()->nHeight + 1, FORK_HEIGHT_DAG + 2);
}

} // namespace

// U7. The footprint is the wire size, the per-object overhead of the vectors the
// block deserialises into, and the merkle tree the parked copy carries; nothing
// else.
BOOST_AUTO_TEST_CASE(the_footprint_is_the_wire_size_plus_object_overhead)
{
    const unsigned int nTx = 6;
    CBlock block;
    block.nVersion = CBlock::CURRENT_VERSION;
    block.nTime = 1000;
    block.nBits = 0x1d00ffff;
    CTransaction coinbase;
    coinbase.nTime = block.nTime;
    coinbase.vin.push_back(CTxIn(COutPoint(), CScript() << OP_1 << OP_1));
    CTxOut cbout;
    cbout.nValue = 1;
    cbout.scriptPubKey = CScript() << OP_1;
    coinbase.vout.push_back(cbout);
    block.vtx.push_back(coinbase);
    for (unsigned int i = 0; i < nTx - 1; i++)
        block.vtx.push_back(PadTx(block.nTime, i + 1, 8));

    // CheckBlock leaves the merkle tree on the block and the parked copy carries
    // it, so a block is measured the way it is held.
    block.hashMerkleRoot = block.BuildMerkleTree();
    BOOST_REQUIRE(!block.vMerkleTree.empty());

    const size_t nWire = ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION);
    const size_t nExpected = nWire
        + nTx * sizeof(CTransaction)
        + nTx * sizeof(CTxIn)
        + nTx * sizeof(CTxOut)
        + block.vMerkleTree.size() * sizeof(uint256);

    BOOST_CHECK_EQUAL(OrphanBlockFootprint(block), nExpected);
    BOOST_CHECK_MESSAGE(OrphanBlockFootprint(block) > nWire,
                        "the footprint carries no object overhead at all");

    printf("orphan footprint: sizeof(CTransaction)=%u sizeof(CTxIn)=%u sizeof(CTxOut)=%u "
           "sizeof(CShieldedSpendDescription)=%u sizeof(CShieldedOutputDescription)=%u\n",
           (unsigned)sizeof(CTransaction), (unsigned)sizeof(CTxIn), (unsigned)sizeof(CTxOut),
           (unsigned)sizeof(CShieldedSpendDescription), (unsigned)sizeof(CShieldedOutputDescription));
    printf("orphan footprint: %u-tx block wire=%u footprint=%u ratio=%.2f\n",
           nTx, (unsigned)nWire, (unsigned)OrphanBlockFootprint(block),
           (double)OrphanBlockFootprint(block) / (double)nWire);
}

namespace
{

// A transaction as it is held: its wire bytes plus the objects it deserialises
// into plus its share of the merkle tree CheckBlock leaves on the block.
size_t HeldCostOfTx(const CTransaction& tx)
{
    return sizeof(CTransaction)
         + tx.vin.size() * sizeof(CTxIn)
         + tx.vout.size() * sizeof(CTxOut)
         + 2 * sizeof(uint256);   // 2n-1 merkle nodes for n transactions
}

// What a block of nWire wire bytes made of this transaction costs held.
size_t ModelledBlockFootprint(size_t nWire, const CTransaction& tx)
{
    const size_t nTxWire = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
    return nWire + (nWire / nTxWire) * HeldCostOfTx(tx);
}

// The cheapest transaction CheckTransaction admits: one input, one output of
// value 1. Its wire form is the smallest and its held cost the same as any
// other one-in-one-out transaction, so it is the worst expansion available.
CTransaction MinimalTx()
{
    CTransaction tx;
    tx.nTime = 1000;
    tx.vin.push_back(CTxIn(COutPoint(uint256(1), 0)));
    CTxOut out;
    out.nValue = 1;
    out.scriptPubKey = CScript() << OP_1;
    tx.vout.push_back(out);
    return tx;
}

// An ordinary transparent payment: one signed input, two pay-to-pubkey-hash
// outputs. This is what a post-fork block is actually full of.
CTransaction OrdinaryTransparentTx(unsigned int nSeed)
{
    CTransaction tx;
    tx.nTime = 1000;
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>(72, (unsigned char)(nSeed & 0xff));   // signature
    scriptSig << std::vector<unsigned char>(33, 0x02);                            // pubkey
    tx.vin.push_back(CTxIn(COutPoint(uint256((uint64_t)nSeed), 0), scriptSig));
    for (int i = 0; i < 2; i++)
    {
        CTxOut out;
        out.nValue = 1000000 + i;
        out.scriptPubKey = CScript() << OP_DUP << OP_HASH160
                                     << std::vector<unsigned char>(20, (unsigned char)(nSeed + i))
                                     << OP_EQUALVERIFY << OP_CHECKSIG;
        tx.vout.push_back(out);
    }
    return tx;
}

} // namespace

// The default ceiling holds the worst block CheckBlock admits at the expansion of
// ordinary transparent transactions, and the honest headroom matches the constant's
// comment.
BOOST_AUTO_TEST_CASE(the_ceiling_holds_the_worst_admitted_block_at_the_measured_expansion)
{
    const CTransaction txMin = MinimalTx();
    const CTransaction txOrdinary = OrdinaryTransparentTx(7);
    const size_t nMinWire = ::GetSerializeSize(txMin, SER_NETWORK, PROTOCOL_VERSION);
    const size_t nOrdWire = ::GetSerializeSize(txOrdinary, SER_NETWORK, PROTOCOL_VERSION);

    const double dMinRatio = (double)(nMinWire + HeldCostOfTx(txMin)) / (double)nMinWire;
    const double dOrdRatio = (double)(nOrdWire + HeldCostOfTx(txOrdinary)) / (double)nOrdWire;

    // The model is the same arithmetic the numbers below are quoted from, so it
    // is checked against a block the real accounting measures.
    {
        CBlock sample;
        sample.nVersion = CBlock::CURRENT_VERSION;
        sample.nTime = 1000;
        sample.nBits = 0x1d00ffff;
        for (unsigned int i = 0; i < 512; i++)
            sample.vtx.push_back(OrdinaryTransparentTx(i + 1));
        sample.hashMerkleRoot = sample.BuildMerkleTree();
        const size_t nWire = ::GetSerializeSize(sample, SER_NETWORK, PROTOCOL_VERSION);
        const size_t nReal = OrphanBlockFootprint(sample);
        const size_t nModelled = ModelledBlockFootprint(nWire, txOrdinary);
        const double dError = (double)(nReal > nModelled ? nReal - nModelled : nModelled - nReal)
                            / (double)nReal;
        printf("orphan headroom: 512-tx transparent block wire=%u real=%u modelled=%u error=%.3f%%\n",
               (unsigned)nWire, (unsigned)nReal, (unsigned)nModelled, dError * 100.0);
        BOOST_CHECK_MESSAGE(dError < 0.02,
                            "the headroom model is " << dError * 100.0
                            << "% off the measured footprint, so the numbers below are not the pool's");
    }

    const size_t nDefault = (size_t)DEFAULT_MAX_ORPHAN_BLOCKS_MEM * nMiB;
    const size_t nLowMem = (size_t)LOWMEM_MAX_ORPHAN_BLOCKS_MEM * nMiB;
    const size_t nWorstBlock = ModelledBlockFootprint(ADAPTIVE_BLOCK_CEILING, txMin);
    const size_t nCeilingBlock = ModelledBlockFootprint(ADAPTIVE_BLOCK_CEILING, txOrdinary);
    const size_t nFloorBlock = ModelledBlockFootprint(ADAPTIVE_BLOCK_FLOOR, txOrdinary);

    printf("orphan headroom: wire min=%u ordinary=%u; expansion min=%.2fx ordinary=%.2fx\n",
           (unsigned)nMinWire, (unsigned)nOrdWire, dMinRatio, dOrdRatio);
    printf("orphan headroom: worst admitted block=%u ceiling-size ordinary=%u floor-size ordinary=%u\n",
           (unsigned)nWorstBlock, (unsigned)nCeilingBlock, (unsigned)nFloorBlock);
    printf("orphan headroom: at the default (%u bytes) that is %u floor-size, %u ceiling-size; "
           "at the low-memory set (%u bytes) %u floor-size\n",
           (unsigned)nDefault, (unsigned)(nDefault / nFloorBlock), (unsigned)(nDefault / nCeilingBlock),
           (unsigned)nLowMem, (unsigned)(nLowMem / nFloorBlock));
    printf("orphan headroom: one peer's in-flight window of floor-size blocks = %u bytes\n",
           (unsigned)(MAX_BLOCKS_IN_FLIGHT_PER_PEER * nFloorBlock));

    // The expansion the argument is made on is the transparent one. A private
    // transaction expands by about 1.02x; anything near that here means the
    // wrong transaction shape was measured.
    BOOST_CHECK_MESSAGE(dOrdRatio > 6.0,
                        "an ordinary transparent transaction expands only " << dOrdRatio
                        << "x, so the headroom below is not being computed on transparent traffic");

    // The default has to hold the worst block CheckBlock admits, or an empty
    // pool refuses it. If this goes red the fix is to raise
    // DEFAULT_MAX_ORPHAN_BLOCKS_MEM, not to relax the check.
    BOOST_CHECK_MESSAGE(nWorstBlock < nDefault,
                        "the worst admitted block costs " << nWorstBlock
                        << " bytes held against a default ceiling of " << nDefault);
    BOOST_CHECK_MESSAGE(nCeilingBlock < nDefault,
                        "a ceiling-size block of ordinary transactions costs " << nCeilingBlock
                        << " bytes held against a default ceiling of " << nDefault);

    // One peer's share has to hold the largest block honest transparent traffic
    // produces, or the share refuses a ceiling-size block from every peer. The
    // pathological all-minimal-transaction block is outside it by design.
    const size_t nShareAtDefault = nDefault / 100 * MAX_ORPHAN_MEM_SHARE_PER_PEER_PERCENT;
    printf("orphan headroom: one peer's share of the default = %u bytes, %u floor-size blocks\n",
           (unsigned)nShareAtDefault, (unsigned)(nShareAtDefault / nFloorBlock));
    BOOST_CHECK_MESSAGE(nCeilingBlock < nShareAtDefault,
                        "a ceiling-size block of ordinary transactions costs " << nCeilingBlock
                        << " bytes against a per-peer share of " << nShareAtDefault);

    // Half the default would not hold the worst admitted block, so the ceiling is the
    // smallest step that does.
    BOOST_CHECK_MESSAGE(nDefault / 2 < nWorstBlock,
                        "half the default ceiling (" << nDefault / 2
                        << " bytes) would still hold the worst admitted block ("
                        << nWorstBlock << " bytes), so the default is larger than the "
                        "never-refuse property forces");

    // And the headroom the ceiling comment states.
    BOOST_CHECK_MESSAGE(nDefault / nFloorBlock >= 90,
                        "the default holds only " << nDefault / nFloorBlock
                        << " floor-size blocks of ordinary transactions, not the ~100 stated");
    BOOST_CHECK_MESSAGE(nDefault / nCeilingBlock >= 3,
                        "the default holds only " << nDefault / nCeilingBlock
                        << " ceiling-size blocks of ordinary transactions, not the ~3 stated");

    // The low-memory profile is a real pool, not a token one: it still holds a
    // sync's worth of floor-size blocks. It does not hold a ceiling-size block,
    // which is the trade that profile is making.
    BOOST_CHECK_MESSAGE(nLowMem / nFloorBlock >= 20,
                        "the low-memory ceiling holds only " << nLowMem / nFloorBlock
                        << " floor-size blocks of ordinary transactions");
}

// The floor on the ceiling knob is a sanity clamp, not a second default: set at
// the low-memory profile's own value it would hand those devices the full
// default pool, which is the branch's whole reason for existing.
BOOST_AUTO_TEST_CASE(the_floor_leaves_the_low_memory_profile_a_smaller_pool)
{
    BOOST_CHECK_MESSAGE(MIN_MAX_ORPHAN_BLOCKS_MEM < LOWMEM_MAX_ORPHAN_BLOCKS_MEM,
                        "the ceiling floor (" << MIN_MAX_ORPHAN_BLOCKS_MEM
                        << " MiB) is not below the low-memory soft-set ("
                        << LOWMEM_MAX_ORPHAN_BLOCKS_MEM << " MiB)");
    BOOST_CHECK_MESSAGE(LOWMEM_MAX_ORPHAN_BLOCKS_MEM < DEFAULT_MAX_ORPHAN_BLOCKS_MEM,
                        "the low-memory soft-set is not a reduction against the default");

    {
        CScopedArg lowmem("-maxorphanmem", strprintf("%u", LOWMEM_MAX_ORPHAN_BLOCKS_MEM));
        BOOST_CHECK_MESSAGE(GetMaxOrphanBlocksFootprint() == (size_t)LOWMEM_MAX_ORPHAN_BLOCKS_MEM * nMiB,
                            "the low-memory soft-set resolves to " << GetMaxOrphanBlocksFootprint()
                            << " bytes, not the " << (size_t)LOWMEM_MAX_ORPHAN_BLOCKS_MEM * nMiB
                            << " it asks for: the floor clamped it back up");
    }

    {
        CScopedArgUnset unset("-maxorphanmem");
        BOOST_CHECK_MESSAGE(GetMaxOrphanBlocksFootprint() == (size_t)DEFAULT_MAX_ORPHAN_BLOCKS_MEM * nMiB,
                            "an unset -maxorphanmem resolves to " << GetMaxOrphanBlocksFootprint()
                            << " bytes, not the default "
                            << (size_t)DEFAULT_MAX_ORPHAN_BLOCKS_MEM * nMiB);
    }

    {
        // The megabyte-to-byte multiply is done in size_t: an absurd argument
        // must not wrap to a ceiling below the floor.
        CScopedArg absurd("-maxorphanmem", "9223372036854775807");
        BOOST_CHECK_MESSAGE(GetMaxOrphanBlocksFootprint() >= (size_t)MIN_MAX_ORPHAN_BLOCKS_MEM * nMiB,
                            "an absurd -maxorphanmem wrapped to " << GetMaxOrphanBlocksFootprint()
                            << " bytes, below the floor");
    }
}

// U1 and U4a: the byte bound holds with few entries, the classic site tests the
// incoming size, and a delivery that does not fit is refused without eviction.
BOOST_AUTO_TEST_CASE(the_byte_bound_refuses_rather_than_evicting)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    CScopedArg mem("-maxorphanmem", "1");   // clamped up to the floor
    CScopedArg entries("-maxorphanblocks", "2500");

    const size_t nCeiling = GetMaxOrphanBlocksFootprint();
    BOOST_REQUIRE_EQUAL(nCeiling, (size_t)MIN_MAX_ORPHAN_BLOCKS_MEM * nMiB);

    TestPeer peer(19301);
    const CBlock tmpl = BaseTemplate();

    // The block that will not fit, measured before the pool is filled for it.
    CBlock arriving = DetachedBlock(tmpl, 1200, nTxFill, 0);
    const size_t nIncoming = OrphanBlockFootprint(arriving);
    BOOST_REQUIRE_MESSAGE(nIncoming * 8 < nCeiling, "the padded block is too large for this ceiling");

    // Fill to within one arriving block of the ceiling, spread over owners that
    // are not the delivering peer and each well under its share.
    const NodeId vFiller[4] = { 700001, 700002, 700003, 700004 };
    std::vector<uint256> vHeld = FillPoolAgainst(nIncoming, vFiller, 4, 5000, 0xb10c0000ULL);
    BOOST_REQUIRE_MESSAGE(vHeld.size() >= 8, "the fill parked too few records to prove anything");
    CheckPoolInvariants("byte fill");

    size_t nSizeBefore = 0, nBytesBefore = 0;
    {
        LOCK(cs_main);
        nSizeBefore = mapOrphanBlocks.size();
        nBytesBefore = GetOrphanBlocksFootprint();
        BOOST_REQUIRE_MESSAGE(nBytesBefore + nIncoming > nCeiling,
                              "the arriving block still fits, so this case tests nothing");
        BOOST_REQUIRE_MESSAGE(nSizeBefore * 4 < (size_t)GetArg("-maxorphanblocks", 2500),
                              "the entry count is near its own bound, so the byte bound "
                              "may not be what refuses");
    }

    BOOST_CHECK_MESSAGE(!Deliver(peer, arriving),
                        "a block the pool has no room for was parked anyway");
    CheckPoolInvariants("after the refusal");

    LOCK(cs_main);
    BOOST_CHECK_MESSAGE(mapOrphanBlocks.size() == nSizeBefore,
                        "the byte bound evicted for a block it could not fit ("
                            << nSizeBefore << " -> " << mapOrphanBlocks.size() << ")");
    BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprint() == nBytesBefore,
                        "the refused delivery cost the pool held bytes");
    size_t nLost = 0;
    for (unsigned int i = 0; i < vHeld.size(); i++)
        nLost += 1 - mapOrphanBlocks.count(vHeld[i]);
    BOOST_CHECK_MESSAGE(nLost == 0, "the refused delivery discarded " << nLost << " held records");
    BOOST_CHECK_MESSAGE(mapOrphanBlocks.count(arriving.GetHash()) == 0,
                        "the refused block was parked anyway");
    BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprint() <= nCeiling,
                        "the orphan pool exceeded its byte ceiling");
    BOOST_CHECK_MESSAGE(peer.node.nMisbehavior == 0,
                        "a refusal for want of pool room scored the peer");

    printf("orphan pool: ceiling=%u held=%u entries %u bytes, refused an %u-byte block, evicted 0\n",
           (unsigned)nCeiling, (unsigned)mapOrphanBlocks.size(),
           (unsigned)GetOrphanBlocksFootprint(), (unsigned)nIncoming);
}

// U4b. The DAG park site passes the incoming size too. Passing zero instead
// would leave the pool over its ceiling after a park that should not have
// happened.
BOOST_AUTO_TEST_CASE(the_dag_park_site_prunes_against_the_incoming_size)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    CScopedArg mem("-maxorphanmem", "1");   // clamped up to the floor
    CScopedArg entries("-maxorphanblocks", "2500");

    EnsureDAGHeight();
    const size_t nCeiling = GetMaxOrphanBlocksFootprint();
    TestPeer peer(19302);
    const CBlock tmpl = BaseTemplate();

    uint256 hashMissing;
    CBlock dagOrphan = DAGOrphanBlock(tmpl, 3, nTxFill, 0, hashMissing);
    const size_t nIncoming = OrphanBlockFootprint(dagOrphan);

    // Fill to a point where the pool is under its ceiling but the DAG orphan is
    // not: only a bound that reads the incoming size can tell the two apart.
    const NodeId vFiller[4] = { 710001, 710002, 710003, 710004 };
    FillPoolAgainst(nIncoming, vFiller, 4, 6000, 0x0da60000ULL);
    const size_t nBefore = GetOrphanBlocksFootprint();
    const size_t nSizeBefore = mapOrphanBlocks.size();
    BOOST_REQUIRE_MESSAGE(nBefore <= nCeiling, "the fill already crossed the ceiling");
    BOOST_REQUIRE_MESSAGE(nBefore + nIncoming > nCeiling,
                          "the DAG block still fits, so the case proves nothing");

    BOOST_CHECK_MESSAGE(!Deliver(peer, dagOrphan),
                        "the DAG park site parked a block the pool has no room for");
    CheckPoolInvariants("dag park refusal");

    LOCK(cs_main);
    BOOST_CHECK_MESSAGE(mapOrphanBlocks.count(dagOrphan.GetHash()) == 0,
                        "the refused DAG orphan was parked anyway");
    BOOST_CHECK_MESSAGE(mapOrphanBlocksByPrev.count(hashMissing) == 0,
                        "the refused DAG orphan left a by-prev entry behind");
    BOOST_CHECK_MESSAGE(mapOrphanBlocks.size() == nSizeBefore,
                        "the DAG site evicted for a block it then refused");
    BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprint() == nBefore,
                        "the DAG site's refusal cost the pool held bytes");
    BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprint() <= nCeiling,
                        "the DAG park site left the pool over its byte ceiling ("
                            << GetOrphanBlocksFootprint() << " > " << nCeiling << ")");
    BOOST_CHECK_MESSAGE(peer.node.nMisbehavior == 0,
                        "a refusal for want of pool room scored the peer");

    printf("orphan pool: dag site held=%u incoming=%u ceiling=%u refused\n",
           (unsigned)nBefore, (unsigned)nIncoming, (unsigned)nCeiling);
}

// U2. The entry bound still holds, with the byte total far under the ceiling.
BOOST_AUTO_TEST_CASE(the_entry_bound_still_holds_with_bytes_to_spare)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    CScopedArg entries("-maxorphanblocks", "10");
    CScopedArg mem("-maxorphanmem", "256");

    TestPeer peer(19303);
    const CBlock tmpl = BaseTemplate();

    for (unsigned int i = 0; i < 30; i++)
    {
        CBlock small = DetachedBlock(tmpl, 1000 + i, 0, 0);
        BOOST_REQUIRE(Deliver(peer, small));
        CheckPoolInvariants("entry fill");

        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(mapOrphanBlocks.size() <= 10,
                            "the orphan pool holds " << mapOrphanBlocks.size()
                                                     << " entries against a bound of 10");
    }

    LOCK(cs_main);
    BOOST_CHECK_EQUAL(mapOrphanBlocks.size(), 10U);
    BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprint() * 100 < GetMaxOrphanBlocksFootprint(),
                        "the byte bound is what engaged, not the entry bound");
}

// U3 and U6. A parent that connects drains its waiters: records, index entries,
// ownership and the byte total all fall together, and the peer's count entry is
// erased rather than left at zero.
BOOST_AUTO_TEST_CASE(a_connecting_parent_drains_the_pool_and_its_counters)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    CScopedArg entries("-maxorphanblocks", "2500");
    CScopedArg mem("-maxorphanmem", "256");

    TestPeer peer(19304);

    // A solved block on the tip, held back, and a child parked on it.
    CBlock parent = BaseTemplate();
    parent.nNonce = 0;
    BOOST_REQUIRE(SolveBlock(&parent));
    BOOST_REQUIRE(parent.CheckBlock());
    const uint256 hashParent = parent.GetHash();

    CBlock child = BaseTemplate();
    child.hashPrevBlock = hashParent;
    child.vtx.push_back(PadTx(child.nTime, 4242, 32));
    child.nNonce = 7;
    child.vMerkleTree.clear();
    child.hashMerkleRoot = child.BuildMerkleTree();
    BOOST_REQUIRE(SolveBlock(&child));
    BOOST_REQUIRE(child.CheckBlock());
    const uint256 hashChild = child.GetHash();

    BOOST_REQUIRE(Deliver(peer, child));
    CheckPoolInvariants("after park");

    const size_t nAfterPark = GetOrphanBlocksFootprint();
    {
        LOCK(cs_main);
        BOOST_REQUIRE_EQUAL(mapOrphanBlocks.count(hashChild), 1U);
        BOOST_REQUIRE_EQUAL(mapOrphanBlocksByPrev.count(hashParent), 1U);
        BOOST_REQUIRE_EQUAL(mapOrphanBlocksByNode.count(hashChild), 1U);
        BOOST_REQUIRE_EQUAL(OrphanCountFor(peer.node.GetId()), 1);
        BOOST_REQUIRE(nAfterPark > 0);
    }

    // The parent connects; the child drains whether or not it is itself accepted.
    BOOST_REQUIRE(Deliver(peer, parent));
    CheckPoolInvariants("after drain");

    LOCK(cs_main);
    BOOST_CHECK_MESSAGE(mapOrphanBlocks.count(hashChild) == 0,
                        "the drained child is still held");
    BOOST_CHECK_MESSAGE(mapOrphanBlocksByPrev.count(hashParent) == 0,
                        "the by-prev entry survived the drain");
    BOOST_CHECK_MESSAGE(mapOrphanBlocksByNode.count(hashChild) == 0,
                        "the ownership entry survived the drain");
    BOOST_CHECK_MESSAGE(mapOrphanCountByNode.count(peer.node.GetId()) == 0,
                        "the peer's orphan count was left behind at "
                            << OrphanCountFor(peer.node.GetId())
                            << " instead of being erased");
    BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprint() == 0,
                        "the drain did not give back the child's footprint ("
                            << GetOrphanBlocksFootprint() << " bytes left)");
}

// U6, the drift half. The periodic reset during initial download clears the counts
// but not the ownership map, so a later removal must not push a count below zero.
BOOST_AUTO_TEST_CASE(a_removal_after_a_count_reset_never_goes_negative)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    CScopedArg entries("-maxorphanblocks", "2500");

    const NodeId owner = 42;
    std::vector<uint256> vHeld;
    for (unsigned int i = 0; i < 3; i++)
    {
        CBlock* pblock = SyntheticOrphan(6100 + i, uint256((uint64_t)(0xbeef0000u + i)));
        vHeld.push_back(pblock->GetHash());
        ParkSynthetic(pblock, owner);
    }
    CheckPoolInvariants("synthetic park");

    {
        LOCK(cs_main);
        BOOST_REQUIRE_EQUAL(OrphanCountFor(owner), 3);
        mapOrphanCountByNode.clear();   // what the initial-download reset does
    }

    for (unsigned int i = 0; i < vHeld.size(); i++)
    {
        LOCK(cs_main);
        BOOST_CHECK(EraseOrphanBlock(vHeld[i], true));
        std::map<NodeId, int>::const_iterator it = mapOrphanCountByNode.find(owner);
        BOOST_CHECK_MESSAGE(it == mapOrphanCountByNode.end() || it->second > 0,
                            "peer " << owner << " holds a non-positive orphan count "
                                    << (it == mapOrphanCountByNode.end() ? 0 : it->second)
                                    << " after a removal following a count reset");
    }

    LOCK(cs_main);
    BOOST_CHECK_EQUAL(mapOrphanCountByNode.count(owner), 0U);
    BOOST_CHECK_EQUAL(GetOrphanBlocksFootprint(), 0U);
}

// The room test is the byte bound's other half. The bound refuses instead of
// evicting, so every park that does not fit is a refusal; maxEntries == 0 refuses
// too; and a peer may not take more than its share even of an empty pool.
BOOST_AUTO_TEST_CASE(the_room_test_refuses_what_will_not_fit)
{
    CScopedOrphanTables tables;
    CScopedArg mem("-maxorphanmem", "1");   // clamped up to the floor

    LOCK(cs_main);
    BOOST_REQUIRE(mapOrphanBlocks.empty());

    const size_t nCeiling = GetMaxOrphanBlocksFootprint();
    const size_t nShare = GetMaxOrphanBlocksFootprintPerPeer();
    BOOST_REQUIRE_MESSAGE(nShare > 0 && nShare < nCeiling,
                          "the per-peer share is not a share of the ceiling");
    {
        CScopedArg entries("-maxorphanblocks", "2500");
        BOOST_CHECK_MESSAGE(!PruneOrphanBlocks(nCeiling + 1, (NodeId)-1),
                            "the pool reported room for a block larger than its "
                            "whole byte ceiling");
        BOOST_CHECK_MESSAGE(PruneOrphanBlocks(nCeiling, (NodeId)-1),
                            "the pool refused a block of its own submission that "
                            "exactly fills its ceiling");
        // The same block from a peer is over that peer's share.
        BOOST_CHECK_MESSAGE(!PruneOrphanBlocks(nCeiling, (NodeId)7),
                            "one peer was allowed the whole ceiling");
        BOOST_CHECK_MESSAGE(PruneOrphanBlocks(nShare, (NodeId)7),
                            "a peer was refused a block that exactly fills its share");
        BOOST_CHECK_MESSAGE(!PruneOrphanBlocks(nShare + 1, (NodeId)7),
                            "a peer was allowed a block larger than its share");
    }
    {
        CScopedArg entries("-maxorphanblocks", "0");
        BOOST_CHECK_MESSAGE(!PruneOrphanBlocks(0, (NodeId)-1),
                            "the pool reported room with an entry bound of zero");
    }

    // And a refusal costs the held orphans nothing: emptying the pool for a park
    // that is refused anyway is the failure the room test exists to prevent.
    CScopedArg entries("-maxorphanblocks", "2500");
    for (unsigned int i = 0; i < 4; i++)
    {
        CBlock* pblock = SyntheticOrphan(9100 + i, uint256((uint64_t)(0xd0e50000u + i)));
        AddOrphanBlock(pblock->GetHash(), pblock, pblock->hashPrevBlock, (NodeId)-1,
                       OrphanBlockFootprint(*pblock));
    }
    const size_t nSizeBefore = mapOrphanBlocks.size();
    const size_t nBytesBefore = GetOrphanBlocksFootprint();
    BOOST_REQUIRE_EQUAL(nSizeBefore, 4U);
    BOOST_CHECK_MESSAGE(!PruneOrphanBlocks(nCeiling + 1, (NodeId)-1),
                        "the pool reported room for a block larger than its whole ceiling");
    BOOST_CHECK_MESSAGE(mapOrphanBlocks.size() == nSizeBefore,
                        "a refused park emptied the pool (" << nSizeBefore << " -> "
                        << mapOrphanBlocks.size() << ")");
    BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprint() == nBytesBefore,
                        "a refused park cost the pool held bytes");
}

// A refused delivery adds no per-peer count entry, so the map does not grow with
// connection churn.
BOOST_AUTO_TEST_CASE(a_refused_delivery_leaves_no_per_peer_count_entry)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    CScopedArg entries("-maxorphanblocks", "0");

    TestPeer peer(19307);
    const CBlock tmpl = BaseTemplate();
    CBlock refused = DetachedBlock(tmpl, 6001, 0, 0);

    BOOST_CHECK_MESSAGE(!Deliver(peer, refused),
                        "a pool with an entry bound of zero still parked a block");

    LOCK(cs_main);
    BOOST_CHECK_MESSAGE(mapOrphanBlocks.count(refused.GetHash()) == 0,
                        "the refused block was parked anyway");
    BOOST_CHECK_MESSAGE(mapOrphanCountByNode.count(peer.node.GetId()) == 0,
                        "a refused delivery left a count entry for a peer that "
                        "holds no orphan");
    BOOST_CHECK_MESSAGE(peer.node.nMisbehavior == 0,
                        "a refusal for want of pool room scored the peer");
    BOOST_CHECK_MESSAGE(!AskedFor(peer.node, refused.GetHash()),
                        "a pool switched off still asked for the block it will refuse again");
    CheckPoolInvariants("after a refused delivery");
}

// The same at the DAG park site.
BOOST_AUTO_TEST_CASE(a_refused_dag_delivery_leaves_no_per_peer_count_entry)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    EnsureDAGHeight();
    CScopedArg entries("-maxorphanblocks", "0");

    TestPeer peer(19308);
    const CBlock tmpl = BaseTemplate();
    uint256 hashMissing;
    CBlock refused = DAGOrphanBlock(tmpl, 11, 0, 0, hashMissing);

    BOOST_CHECK_MESSAGE(!Deliver(peer, refused),
                        "a pool with an entry bound of zero still parked a DAG orphan");

    LOCK(cs_main);
    BOOST_CHECK_MESSAGE(mapOrphanBlocks.count(refused.GetHash()) == 0,
                        "the refused DAG orphan was parked anyway");
    BOOST_CHECK_MESSAGE(mapOrphanCountByNode.count(peer.node.GetId()) == 0,
                        "a refused DAG delivery left a count entry for a peer that "
                        "holds no orphan");
    BOOST_CHECK_MESSAGE(peer.node.nMisbehavior == 0,
                        "a refusal for want of pool room scored the peer");
    CheckPoolInvariants("after a refused dag delivery");
}

// U5, classic site. A peer already at its per-peer cap is refused, and the refusal
// costs no held orphan: eviction runs after the cap check, not before it.
BOOST_AUTO_TEST_CASE(a_refused_peer_evicts_nothing_at_the_classic_site)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    CScopedArg entries("-maxorphanblocks", "750");
    CScopedArg mem("-maxorphanmem", "256");

    TestPeer peer(19305);
    const NodeId owner = peer.node.GetId();
    for (unsigned int i = 0; i < 750; i++)
        ParkSynthetic(SyntheticOrphan(7100 + i, uint256((uint64_t)(0xcafe0000u + i))), owner);
    CheckPoolInvariants("cap fill");

    size_t nSizeBefore = 0, nFootprintBefore = 0;
    {
        LOCK(cs_main);
        BOOST_REQUIRE_EQUAL(OrphanCountFor(owner), 750);
        nSizeBefore = mapOrphanBlocks.size();
        nFootprintBefore = GetOrphanBlocksFootprint();
    }

    const CBlock tmpl = BaseTemplate();
    CBlock over = DetachedBlock(tmpl, 7999, 1, 4096);
    BOOST_CHECK_MESSAGE(!Deliver(peer, over),
                        "a peer over its orphan cap was still allowed to park");

    LOCK(cs_main);
    BOOST_CHECK_MESSAGE(mapOrphanBlocks.size() == nSizeBefore,
                        "the refused block evicted a held orphan (" << nSizeBefore
                            << " -> " << mapOrphanBlocks.size() << ")");
    BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprint() == nFootprintBefore,
                        "the refused block cost held bytes");
    BOOST_CHECK_MESSAGE(mapOrphanBlocks.count(over.GetHash()) == 0,
                        "the refused block was parked anyway");
}

// U5, DAG site. Same ordering requirement on the other park site.
BOOST_AUTO_TEST_CASE(a_refused_peer_evicts_nothing_at_the_dag_site)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    CScopedArg entries("-maxorphanblocks", "750");
    CScopedArg mem("-maxorphanmem", "256");

    EnsureDAGHeight();
    TestPeer peer(19306);
    const NodeId owner = peer.node.GetId();
    for (unsigned int i = 0; i < 750; i++)
        ParkSynthetic(SyntheticOrphan(8100 + i, uint256((uint64_t)(0xf00d0000u + i))), owner);
    CheckPoolInvariants("cap fill");

    size_t nSizeBefore = 0, nFootprintBefore = 0;
    {
        LOCK(cs_main);
        BOOST_REQUIRE_EQUAL(OrphanCountFor(owner), 750);
        nSizeBefore = mapOrphanBlocks.size();
        nFootprintBefore = GetOrphanBlocksFootprint();
    }

    const CBlock tmpl = BaseTemplate();
    uint256 hashMissing;
    CBlock over = DAGOrphanBlock(tmpl, 9, 1, 4096, hashMissing);
    BOOST_CHECK_MESSAGE(!Deliver(peer, over),
                        "a peer over its orphan cap was still allowed to park a DAG orphan");

    LOCK(cs_main);
    BOOST_CHECK_MESSAGE(mapOrphanBlocks.size() == nSizeBefore,
                        "the refused DAG orphan evicted a held orphan (" << nSizeBefore
                            << " -> " << mapOrphanBlocks.size() << ")");
    BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprint() == nFootprintBefore,
                        "the refused DAG orphan cost held bytes");
    BOOST_CHECK_MESSAGE(mapOrphanBlocks.count(over.GetHash()) == 0,
                        "the refused DAG orphan was parked anyway");
}

namespace
{

// Missing both its parent and a committed merge parent: parks under the parent, then
// is re-parked under the merge parent when the parent connects.
CBlock ChildOnWithheldParent(const CBlock& tmpl, const uint256& hashParent, int nChildHeight,
                             uint256& hashMissingOut)
{
    CBlock block = tmpl;
    block.hashPrevBlock = hashParent;

    hashMissingOut = uint256((uint64_t)0xdadb10c0u);
    std::vector<uint256> vParents;
    vParents.push_back(hashParent);
    vParents.push_back(hashMissingOut);

    bool fReplaced = false;
    for (unsigned int i = 0; i < block.vtx[0].vout.size(); i++)
    {
        std::vector<uint256> vOne;
        std::string strWhy;
        const bool fCarries =
            DecodeCanonicalDAGParentScript(block.vtx[0].vout[i].scriptPubKey, vOne, strWhy)
                == DAG_PARENT_VALID ||
            !ExtractDAGParents(block.vtx[0].vout[i].scriptPubKey).empty();
        if (!fCarries)
            continue;
        block.vtx[0].vout[i].scriptPubKey = BuildDAGParentScript(vParents);
        fReplaced = true;
        break;
    }
    BOOST_REQUIRE_MESSAGE(fReplaced, "no canonical DAG parent commitment in the template coinbase");

    block.nNonce = 0x7000;
    block.vMerkleTree.clear();
    block.hashMerkleRoot = block.BuildMerkleTree();
    BOOST_REQUIRE(SolveBlock(&block));
    BOOST_REQUIRE_MESSAGE(block.CheckBlock(), "the withheld-parent child is not admissible");

    std::vector<uint256> vReadBack = CoinbaseDAGParents(block, nChildHeight);
    BOOST_REQUIRE_MESSAGE(vReadBack.size() == 2 && vReadBack[1] == hashMissingOut,
                          "the rewritten commitment does not read back at the child's height");
    return block;
}

} // namespace

// A peer cannot make this node discard another peer's orphans. Four peers fill the
// pool just under the ceiling; a fifth, holding nothing, delivers a block that does
// not fit, and every held record must survive byte for byte.
BOOST_AUTO_TEST_CASE(a_peer_cannot_displace_another_peers_orphans_with_what_it_sends)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    CScopedArg mem("-maxorphanmem", "1");   // clamped up to the floor
    CScopedArg entries("-maxorphanblocks", "2500");

    const size_t nCeiling = GetMaxOrphanBlocksFootprint();
    TestPeer joiner(19310);
    const NodeId idJoiner = joiner.node.GetId();
    const CBlock tmpl = BaseTemplate();

    CBlock arriving = DetachedBlock(tmpl, 2200, nTxFill, 0);
    const size_t nIncoming = OrphanBlockFootprint(arriving);

    // Four holders, none of them the joiner, each under its own share. The
    // records vary in size so that a largest-first pick has something to aim at.
    const NodeId vHolder[4] = { 720001, 720002, 720003, 720004 };
    std::vector<uint256> vHeld = FillPoolAgainst(nIncoming, vHolder, 4, 7000, 0xd15b0000ULL);
    BOOST_REQUIRE_MESSAGE(vHeld.size() >= 8, "the fill parked too few records to prove anything");
    CheckPoolInvariants("holder fill");

    // The record an eviction would take: the largest of whichever holder is
    // charged the most bytes.
    uint256 hashTarget = 0;
    size_t nHeaviestBytes = 0;
    NodeId idHeaviest = -1;
    for (unsigned int i = 0; i < 4; i++)
    {
        const size_t nBytes = GetOrphanBlocksFootprintForNode(vHolder[i]);
        if (nBytes > nHeaviestBytes)
        {
            nHeaviestBytes = nBytes;
            idHeaviest = vHolder[i];
        }
    }
    size_t nSizeBefore = 0, nBytesBefore = 0;
    {
        LOCK(cs_main);
        BOOST_REQUIRE_MESSAGE(idHeaviest >= 0, "no holder was charged any bytes");
        size_t nLargest = 0;
        for (std::map<uint256, COrphanBlock>::const_iterator it = mapOrphanBlocks.begin();
             it != mapOrphanBlocks.end(); ++it)
        {
            std::map<uint256, NodeId>::const_iterator itOwner = mapOrphanBlocksByNode.find(it->first);
            if (itOwner == mapOrphanBlocksByNode.end() || itOwner->second != idHeaviest)
                continue;
            if (it->second.nFootprint > nLargest)
            {
                nLargest = it->second.nFootprint;
                hashTarget = it->first;
            }
        }
        BOOST_REQUIRE(hashTarget != 0);
        nSizeBefore = mapOrphanBlocks.size();
        nBytesBefore = GetOrphanBlocksFootprint();
        BOOST_REQUIRE_MESSAGE(nBytesBefore + nIncoming > nCeiling,
                              "the arriving block still fits, so nothing would be displaced");
        BOOST_REQUIRE_MESSAGE(GetOrphanBlocksFootprintForNode(idJoiner) == 0,
                              "the joiner already holds bytes, so it is not the empty-handed "
                              "peer this case is about");
    }

    BOOST_CHECK_MESSAGE(!Deliver(joiner, arriving),
                        "a peer holding nothing parked a block the pool has no room for");
    CheckPoolInvariants("after the empty-handed delivery");

    LOCK(cs_main);
    BOOST_CHECK_MESSAGE(mapOrphanBlocks.count(hashTarget) == 1,
                        "a peer holding nothing displaced peer " << idHeaviest
                            << "'s largest orphan with one delivery");
    size_t nLost = 0;
    for (unsigned int i = 0; i < vHeld.size(); i++)
        nLost += 1 - mapOrphanBlocks.count(vHeld[i]);
    BOOST_CHECK_MESSAGE(nLost == 0,
                        "one delivery from a peer holding nothing discarded " << nLost
                            << " of another peer's orphans");
    BOOST_CHECK_MESSAGE(mapOrphanBlocks.size() == nSizeBefore,
                        "the pool lost records to a refused delivery (" << nSizeBefore
                            << " -> " << mapOrphanBlocks.size() << ")");
    BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprint() == nBytesBefore,
                        "the pool lost bytes to a refused delivery");
    BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprintForNode(idHeaviest) == nHeaviestBytes,
                        "the heaviest holder was charged fewer bytes after another peer's "
                        "delivery");
    BOOST_CHECK_MESSAGE(joiner.node.nMisbehavior == 0,
                        "a refusal for want of pool room scored the peer");

    printf("orphan pool: %u records over 4 holders (%u bytes of %u), empty-handed peer "
           "refused an %u-byte block, displaced 0\n",
           (unsigned)mapOrphanBlocks.size(), (unsigned)GetOrphanBlocksFootprint(),
           (unsigned)nCeiling, (unsigned)nIncoming);
}

// A refused block goes back into the peer's mapAskFor and leaves as a getdata with
// no new announcement, then parks once there is room.
BOOST_AUTO_TEST_CASE(a_refused_orphan_is_asked_for_again_and_parks_when_room_returns)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    CScopedArg mem("-maxorphanmem", "1");   // clamped up to the floor
    CScopedArg entries("-maxorphanblocks", "2500");

    const size_t nCeiling = GetMaxOrphanBlocksFootprint();
    TestPeer peer(19312);
    const CBlock tmpl = BaseTemplate();

    // The refusal defers the retry, so the case has to drive the clock past the
    // deferral to see the getdata leave.
    const int64_t nStart = GetTime();
    CScopedMockTime clock(nStart);

    CBlock arriving = DetachedBlock(tmpl, 2400, nTxFill, 0);
    const uint256 hashArriving = arriving.GetHash();
    const size_t nIncoming = OrphanBlockFootprint(arriving);

    const NodeId vHolder[4] = { 730001, 730002, 730003, 730004 };
    std::vector<uint256> vHeld = FillPoolAgainst(nIncoming, vHolder, 4, 8000, 0xa5ea0000ULL);
    BOOST_REQUIRE_MESSAGE(vHeld.size() >= 8, "the fill parked too few records to prove anything");
    BOOST_REQUIRE_MESSAGE(GetOrphanBlocksFootprint() + nIncoming > GetMaxOrphanBlocksFootprint(),
                          "the arriving block still fits, so it would not be refused");

    // Nothing has been asked of this peer yet, and it has announced nothing.
    {
        LOCK(cs_mapAlreadyAskedFor);
        mapAlreadyAskedFor.erase(CInv(MSG_BLOCK, hashArriving));
    }
    BOOST_REQUIRE(!AskedFor(peer.node, hashArriving));
    BOOST_REQUIRE(GetDataSentTo(peer.node).empty());

    BOOST_CHECK_MESSAGE(!Deliver(peer, arriving),
                        "the pool parked a block it has no room for");

    // Queued for this peer, and deferred rather than cleared: clearing the ask
    // record is what put the retry on the next pass and kept it there.
    BOOST_CHECK_MESSAGE(AskedFor(peer.node, hashArriving),
                        "a refused block was not put back in the peer's request queue");
    BOOST_CHECK_MESSAGE(AskForTimeFor(peer.node, hashArriving)
                            >= (nStart + ORPHAN_REFUSAL_BACKOFF_SECONDS) * 1000000,
                        "the refused block's retry is not deferred");

    // Nothing goes out yet.
    BOOST_REQUIRE(FlushToWire(peer.node));
    {
        std::vector<CInv> vEarly = GetDataSentTo(peer.node);
        for (unsigned int i = 0; i < vEarly.size(); i++)
            BOOST_CHECK_MESSAGE(!(vEarly[i].type == MSG_BLOCK && vEarly[i].hash == hashArriving),
                                "the refused block was re-requested inside its deferral");
    }

    // And once the deferral has passed it actually leaves as a getdata, with no
    // inv from the peer.
    clock.Set(nStart + ORPHAN_REFUSAL_BACKOFF_SECONDS + 2);
    BOOST_REQUIRE(FlushToWire(peer.node));
    std::vector<CInv> vSent = GetDataSentTo(peer.node);
    bool fRequested = false;
    for (unsigned int i = 0; i < vSent.size(); i++)
        if (vSent[i].type == MSG_BLOCK && vSent[i].hash == hashArriving)
            fRequested = true;
    BOOST_CHECK_MESSAGE(fRequested,
                        "no getdata for the refused block reached the peer that offered it");
    BOOST_CHECK_MESSAGE(peer.node.IsBlockInFlight(hashArriving),
                        "the refused block was not marked in flight after the getdata");

    // Room returns the way it does in service: a parent connects and the drain
    // erases what was waiting on it.
    {
        LOCK(cs_main);
        for (unsigned int i = 0; i < vHeld.size() && GetOrphanBlocksFootprint() + nIncoming > nCeiling; i++)
            EraseOrphanBlock(vHeld[i], true);
        BOOST_REQUIRE_MESSAGE(GetOrphanBlocksFootprint() + nIncoming <= nCeiling,
                              "the drain did not free enough room for the retry");
    }
    CheckPoolInvariants("after the drain");

    // The peer answers the getdata with the same block.
    BOOST_CHECK_MESSAGE(Deliver(peer, arriving),
                        "the re-delivered block was refused a second time");
    CheckPoolInvariants("after the re-delivery");

    LOCK(cs_main);
    BOOST_CHECK_MESSAGE(mapOrphanBlocks.count(hashArriving) == 1,
                        "the re-delivered block was not parked");
    BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprintForNode(peer.node.GetId()) == nIncoming,
                        "the re-delivered block was not charged to the peer that sent it");
    BOOST_CHECK_MESSAGE(peer.node.nMisbehavior == 0,
                        "the refusal and retry scored the peer");

    printf("orphan pool: refused an %u-byte block, re-asked it over getdata, parked it on "
           "re-delivery (%u bytes held)\n",
           (unsigned)nIncoming, (unsigned)GetOrphanBlocksFootprint());
}

// The per-peer share keeps one peer's never-draining orphans from pinning the whole
// byte ceiling.
BOOST_AUTO_TEST_CASE(no_single_peer_can_pin_the_byte_ceiling)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    CScopedArg mem("-maxorphanmem", "1");   // clamped up to the floor
    CScopedArg entries("-maxorphanblocks", "2500");

    const size_t nCeiling = GetMaxOrphanBlocksFootprint();
    const size_t nShare = GetMaxOrphanBlocksFootprintPerPeer();
    TestPeer first(19313);
    TestPeer second(19314);
    const CBlock tmpl = BaseTemplate();

    unsigned int nParked = 0;
    unsigned int nSeed = 9000;
    bool fRefused = false;
    while (nSeed < 9060)
    {
        CBlock block = DetachedBlock(tmpl, nSeed++, nTxFill, 0);
        if (!Deliver(first, block))
        {
            fRefused = true;
            break;
        }
        nParked++;
    }
    BOOST_REQUIRE_MESSAGE(fRefused, "the first peer was never refused, so no bound engaged");
    BOOST_REQUIRE_MESSAGE(nParked >= 2, "the first peer parked too little to prove anything");
    CheckPoolInvariants("share fill");

    const size_t nHeld = GetOrphanBlocksFootprintForNode(first.node.GetId());
    BOOST_CHECK_MESSAGE(nHeld <= nShare,
                        "one peer holds " << nHeld << " bytes against a share of " << nShare);
    BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprint() * 2 < nCeiling,
                        "the pool is near its ceiling, so the ceiling and not the share is "
                        "what refused (" << GetOrphanBlocksFootprint() << " of " << nCeiling << ")");

    // The pool is nowhere near full, so another peer parks normally.
    CBlock other = DetachedBlock(tmpl, 9500, nTxFill, 0);
    BOOST_CHECK_MESSAGE(Deliver(second, other),
                        "a second peer was refused while the first peer's fill held the pool");
    CheckPoolInvariants("second peer");

    LOCK(cs_main);
    BOOST_CHECK_MESSAGE(mapOrphanBlocks.count(other.GetHash()) == 1,
                        "the second peer's block was not parked");

    printf("orphan pool: ceiling=%u share=%u first peer held %u bytes in %u records, "
           "second peer parked\n",
           (unsigned)nCeiling, (unsigned)nShare, (unsigned)nHeld, nParked);
}

// A drain that re-parks an incomplete DAG orphan under its new merge parent must
// update the record's key, or a later eviction leaves a dangling by-prev entry.
BOOST_AUTO_TEST_CASE(a_re_parked_dag_orphan_carries_its_key_to_its_eviction)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    CScopedArg entries("-maxorphanblocks", "2500");
    CScopedArg mem("-maxorphanmem", "256");

    EnsureDAGHeight();
    TestPeer peer(19311);

    // A solved block on the tip, held back, and its child, which also commits to
    // a merge parent this node does not have.
    CBlock parent = BaseTemplate();
    parent.nNonce = 0;
    BOOST_REQUIRE(SolveBlock(&parent));
    BOOST_REQUIRE(parent.CheckBlock());
    const uint256 hashParent = parent.GetHash();

    uint256 hashMissing;
    CBlock child = ChildOnWithheldParent(BaseTemplate(), hashParent,
                                         BestIndex()->nHeight + 2, hashMissing);
    const uint256 hashChild = child.GetHash();

    // The prev is unknown, so it parks at the classic site, under the parent.
    BOOST_REQUIRE(Deliver(peer, child));
    CheckPoolInvariants("after the classic park");
    {
        LOCK(cs_main);
        BOOST_REQUIRE_EQUAL(mapOrphanBlocks.count(hashChild), 1U);
        BOOST_REQUIRE_EQUAL(mapOrphanBlocksByPrev.count(hashParent), 1U);
        BOOST_REQUIRE_MESSAGE(mapOrphanBlocks[hashChild].hashWaitedFor == hashParent,
                              "the parked record does not wait on the parent it is keyed under");
    }

    // The parent connects. The merge parent is still missing, so the drain
    // re-parks the child rather than accepting it.
    BOOST_REQUIRE(Deliver(peer, parent));
    CheckPoolInvariants("after the re-park");
    {
        LOCK(cs_main);
        BOOST_REQUIRE_MESSAGE(mapOrphanBlocks.count(hashChild) == 1,
                              "the drain did not hold the still-incomplete orphan");
        BOOST_CHECK_MESSAGE(mapOrphanBlocksByPrev.count(hashParent) == 0,
                            "the old by-prev entry survived the drain");
        BOOST_CHECK_MESSAGE(mapOrphanBlocksByPrev.count(hashMissing) == 1,
                            "the orphan was not re-parked under its missing merge parent");
        BOOST_CHECK_MESSAGE(mapOrphanBlocks[hashChild].hashWaitedFor == hashMissing,
                            "the re-parked record still waits on the hash it was parked under "
                            "before the drain, so its removal will erase the wrong by-prev key");
        BOOST_REQUIRE_EQUAL(mapOrphanBlocks.size(), 1U);
    }

    // Now evict it. Its by-prev entry has to go with it: what is left behind
    // otherwise is a pointer to a block this erase frees.
    {
        CScopedArg one("-maxorphanblocks", "1");
        CBlock filler = DetachedBlock(BaseTemplate(), 4321, 0, 0);
        BOOST_REQUIRE(Deliver(peer, filler));

        LOCK(cs_main);
        BOOST_REQUIRE_MESSAGE(mapOrphanBlocks.count(hashChild) == 0,
                              "the entry bound did not evict the re-parked orphan");
        BOOST_CHECK_MESSAGE(mapOrphanBlocksByPrev.count(hashMissing) == 0,
                            "the re-parked orphan's by-prev entry outlived the block it points at");
    }
    CheckPoolInvariants("after evicting the re-parked orphan");
}

// Orphans expire: a record past the expiry is dropped with its bytes and entry
// charge, and one inside it is kept.
BOOST_AUTO_TEST_CASE(an_orphan_older_than_the_expiry_is_dropped_and_a_younger_one_is_not)
{
    CScopedOrphanTables tables;
    CScopedArg mem("-maxorphanmem", "256");
    CScopedArg entries("-maxorphanblocks", "2500");

    const int64_t nStart = GetTime();
    CScopedMockTime clock(nStart);

    const NodeId owner = 770001;
    uint256 hashOld, hashYoung;
    {
        CBlock* pOld = SyntheticOrphanPadded(31001, uint256((uint64_t)0x0a9e0001u), 32);
        hashOld = pOld->GetHash();
        ParkSynthetic(pOld, owner);
    }

    // Parked one second before the expiry would catch the first one.
    clock.Set(nStart + ORPHAN_BLOCK_EXPIRY_SECONDS);
    {
        CBlock* pYoung = SyntheticOrphanPadded(31002, uint256((uint64_t)0x0a9e0002u), 32);
        hashYoung = pYoung->GetHash();
        ParkSynthetic(pYoung, owner);
    }

    size_t nBytesOld = 0;
    {
        LOCK(cs_main);
        BOOST_REQUIRE_EQUAL(mapOrphanBlocks.size(), 2U);
        BOOST_REQUIRE_EQUAL(OrphanCountFor(owner), 2);
        nBytesOld = mapOrphanBlocks[hashOld].nFootprint;
        BOOST_REQUIRE(nBytesOld > 0);
        BOOST_REQUIRE_EQUAL(mapOrphanBlocks[hashOld].nTimeParked, nStart);
    }
    const size_t nBytesBefore = GetOrphanBlocksFootprint();

    // At exactly the expiry nothing has aged out: the boundary belongs to the
    // orphan, so a fetch that takes the whole budget still lands.
    {
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(ExpireOrphanBlocks(nStart + ORPHAN_BLOCK_EXPIRY_SECONDS) == 0,
                            "an orphan exactly at the expiry was dropped");
        BOOST_CHECK_EQUAL(mapOrphanBlocks.size(), 2U);
    }

    // One second past it the older record goes and the younger one stays.
    clock.Set(nStart + ORPHAN_BLOCK_EXPIRY_SECONDS + 1);
    {
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(ExpireOrphanBlocks(GetTime()) == 1,
                            "the expiry did not drop the aged orphan");
        BOOST_CHECK_MESSAGE(mapOrphanBlocks.count(hashOld) == 0,
                            "the aged orphan is still held");
        BOOST_CHECK_MESSAGE(mapOrphanBlocks.count(hashYoung) == 1,
                            "an orphan inside the expiry was dropped, which turns an "
                            "ancestor fetch in progress into a sync failure");
        BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprint() == nBytesBefore - nBytesOld,
                            "the expiry did not release the aged orphan's bytes ("
                                << GetOrphanBlocksFootprint() << " held against "
                                << nBytesBefore - nBytesOld << " expected)");
        BOOST_CHECK_MESSAGE(OrphanCountFor(owner) == 1,
                            "the expiry did not release the aged orphan's entry charge");
    }
    CheckPoolInvariants("after the expiry");

    // And the younger one goes when its own budget runs out, so the expiry is a
    // lifetime and not a one-off.
    clock.Set(nStart + 2 * ORPHAN_BLOCK_EXPIRY_SECONDS + 2);
    {
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(ExpireOrphanBlocks(GetTime()) == 1,
                            "the second orphan never aged out");
        BOOST_CHECK_MESSAGE(mapOrphanBlocks.empty(), "the pool did not empty");
        BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprint() == 0,
                            "the pool total did not fall to zero with the records");
        BOOST_CHECK_MESSAGE(OrphanCountFor(owner) == 0,
                            "the peer still carries an entry charge with nothing held");
        BOOST_CHECK_MESSAGE(GetOrphanOwnerBucketCount() == 0,
                            "a byte bucket outlived the records behind it");
    }
    CheckPoolInvariants("after the pool aged out");
}

// Expiry takes one record, never a subtree: a child of an expired orphan stays
// indexed and ages out on its own budget.
BOOST_AUTO_TEST_CASE(expiring_a_parent_leaves_its_waiting_child_indexed)
{
    CScopedOrphanTables tables;
    CScopedArg mem("-maxorphanmem", "256");
    CScopedArg entries("-maxorphanblocks", "2500");

    const int64_t nStart = GetTime();
    CScopedMockTime clock(nStart);

    CBlock* pParent = SyntheticOrphanPadded(35001, uint256((uint64_t)0x0c0f0001u), 16);
    const uint256 hashParent = pParent->GetHash();
    ParkSynthetic(pParent, (NodeId)778001);

    clock.Set(nStart + 10);
    CBlock* pChild = SyntheticOrphanPadded(35002, hashParent, 16);
    const uint256 hashChild = pChild->GetHash();
    ParkSynthetic(pChild, (NodeId)778002);
    CheckPoolInvariants("parent and child parked");

    clock.Set(nStart + ORPHAN_BLOCK_EXPIRY_SECONDS + 1);
    {
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(ExpireOrphanBlocks(GetTime()) == 1,
                            "the expiry took more than the one record that had aged out");
        BOOST_CHECK_MESSAGE(mapOrphanBlocks.count(hashParent) == 0,
                            "the aged parent is still held");
        BOOST_CHECK_MESSAGE(mapOrphanBlocks.count(hashChild) == 1,
                            "expiring a parent took the child that was waiting on it");
        BOOST_CHECK_MESSAGE(mapOrphanBlocksByPrev.count(hashParent) == 1,
                            "the child lost the index entry it is found by, so a later "
                            "delivery of the parent would not drain it");
    }
    CheckPoolInvariants("after expiring the parent");

    clock.Set(nStart + 10 + ORPHAN_BLOCK_EXPIRY_SECONDS + 1);
    {
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(ExpireOrphanBlocks(GetTime()) == 1,
                            "the child never aged out on its own budget");
        BOOST_CHECK_MESSAGE(mapOrphanBlocks.empty(), "the pool did not empty");
    }
    CheckPoolInvariants("after the child aged out");
}

// The expiry covers an honest ancestor fetch: ceiling/expansion wire bytes over the
// expiry must be well under the rate needed to follow the chain.
BOOST_AUTO_TEST_CASE(the_expiry_covers_an_honest_ancestor_fetch)
{
    const CTransaction txOrdinary = OrdinaryTransparentTx(11);
    const size_t nOrdWire = ::GetSerializeSize(txOrdinary, SER_NETWORK, PROTOCOL_VERSION);
    const double dExpansion = (double)(nOrdWire + HeldCostOfTx(txOrdinary)) / (double)nOrdWire;

    const size_t nDefault = (size_t)DEFAULT_MAX_ORPHAN_BLOCKS_MEM * nMiB;
    const size_t nLowMem = (size_t)LOWMEM_MAX_ORPHAN_BLOCKS_MEM * nMiB;
    const double dPoolWire = (double)nDefault / dExpansion;
    const double dLowMemWire = (double)nLowMem / dExpansion;
    const double dRate = dPoolWire / (double)ORPHAN_BLOCK_EXPIRY_SECONDS;
    const double dLowMemRate = dLowMemWire / (double)ORPHAN_BLOCK_EXPIRY_SECONDS;

    // What following the chain costs at all: one penalty-free block per block
    // interval. A node below this is not syncing whatever the pool does.
    const double dTipRate = (double)ADAPTIVE_BLOCK_FLOOR / (double)POST_DAG_TARGET_SPACING;

    printf("orphan expiry: expansion %.2fx, pool holds %.1f MB of wire, drained inside %" PRId64
           "s that is %.1f KB/s (low-memory %.1f KB/s); following the tip costs %.1f KB/s\n",
           dExpansion, dPoolWire / 1e6, (int64_t)ORPHAN_BLOCK_EXPIRY_SECONDS,
           dRate / 1024.0, dLowMemRate / 1024.0, dTipRate / 1024.0);

    BOOST_CHECK_MESSAGE(dRate * 4.0 < dTipRate,
                        "draining a full pool inside the expiry needs " << dRate / 1024.0
                            << " KB/s against the " << dTipRate / 1024.0
                            << " KB/s a node must already sustain to follow the chain, so the "
                               "expiry is not comfortably inside an honest fetch");
    BOOST_CHECK_MESSAGE(dLowMemRate < dRate,
                        "the low-memory profile asks more of a peer than the default one");

    // The stall bound. The deepest chain of orphans the entry bound can hold,
    // drained through one peer's in-flight window at the -blockinflighttimeout
    // edge, has to fit inside the expiry with margin.
    const int64_t nInFlightTimeout = 30;    // the -blockinflighttimeout default
    const int64_t nWindows = ((int64_t)DEFAULT_MAX_ORPHAN_BLOCKS + (int64_t)MAX_BLOCKS_IN_FLIGHT_PER_PEER - 1)
                           / (int64_t)MAX_BLOCKS_IN_FLIGHT_PER_PEER;
    const int64_t nWorstDrain = nWindows * nInFlightTimeout;
    printf("orphan expiry: %d entries / %u in flight = %" PRId64 " windows x %" PRId64
           "s = %" PRId64 "s worst drain, against a %" PRId64 "s expiry\n",
           (int)DEFAULT_MAX_ORPHAN_BLOCKS, (unsigned)MAX_BLOCKS_IN_FLIGHT_PER_PEER,
           nWindows, nInFlightTimeout, nWorstDrain, (int64_t)ORPHAN_BLOCK_EXPIRY_SECONDS);
    BOOST_CHECK_MESSAGE(nWorstDrain * 2 <= ORPHAN_BLOCK_EXPIRY_SECONDS,
                        "the worst honest drain is " << nWorstDrain
                            << "s against an expiry of " << ORPHAN_BLOCK_EXPIRY_SECONDS
                            << "s, which leaves no margin");

    // Upper anchor: a peer silent for TIMEOUT_INTERVAL is disconnected and its records
    // released, so the expiry matches it.
    BOOST_CHECK_MESSAGE(ORPHAN_BLOCK_EXPIRY_SECONDS == TIMEOUT_INTERVAL,
                        "the expiry (" << ORPHAN_BLOCK_EXPIRY_SECONDS
                            << "s) no longer meets the peer liveness timeout ("
                            << TIMEOUT_INTERVAL << "s)");
}

// A departed peer's bytes and entry charge in mapOrphanBlocksByNode and
// mapOrphanCountByNode are released.
BOOST_AUTO_TEST_CASE(a_departed_peer_releases_its_bytes_and_its_entry_charge)
{
    CScopedOrphanTables tables;
    CScopedArg mem("-maxorphanmem", "256");
    CScopedArg entries("-maxorphanblocks", "2500");

    const NodeId departing = 771001;
    const NodeId staying = 771002;

    for (unsigned int i = 0; i < 6; i++)
        ParkSynthetic(SyntheticOrphanPadded(32100 + i, uint256((uint64_t)0x0de40000u + i), 24),
                      i % 2 == 0 ? departing : staying);
    CheckPoolInvariants("both peers holding");

    size_t nStayingBytes = 0;
    {
        LOCK(cs_main);
        BOOST_REQUIRE_EQUAL(OrphanCountFor(departing), 3);
        BOOST_REQUIRE_EQUAL(OrphanCountFor(staying), 3);
        BOOST_REQUIRE(GetOrphanBlocksFootprintForNode(departing) > 0);
        nStayingBytes = GetOrphanBlocksFootprintForNode(staying);
    }

    OrphanBlocksNodeDisconnected(departing);
    {
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(ReleaseDepartedOrphanOwners() == 3,
                            "the departed peer's records were not released");
        BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprintForNode(departing) == 0,
                            "the departed peer is still charged "
                                << GetOrphanBlocksFootprintForNode(departing) << " bytes");
        BOOST_CHECK_MESSAGE(OrphanCountFor(departing) == 0,
                            "the departed peer still carries an entry charge of "
                                << OrphanCountFor(departing));
        BOOST_CHECK_MESSAGE(mapOrphanCountByNode.count(departing) == 0,
                            "a count bucket outlived the peer it belongs to");

        // And it took nothing from the peer that stayed.
        BOOST_CHECK_MESSAGE(OrphanCountFor(staying) == 3,
                            "releasing one peer's records cost another peer its orphans");
        BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprintForNode(staying) == nStayingBytes,
                            "releasing one peer's records changed another peer's charge");
        BOOST_CHECK_MESSAGE(mapOrphanBlocks.size() == 3U,
                            "the pool holds " << mapOrphanBlocks.size()
                                << " records after releasing one of two peers");
    }
    CheckPoolInvariants("after the release");

    // A charge with no records behind it is released too. The periodic count
    // reset during initial download leaves exactly that, and nothing else would
    // ever clear it for a peer that has gone.
    {
        LOCK(cs_main);
        mapOrphanCountByNode[departing] = 5;
    }
    OrphanBlocksNodeDisconnected(departing);
    {
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(ReleaseDepartedOrphanOwners() == 0,
                            "the release reported dropping records the peer did not hold");
        BOOST_CHECK_MESSAGE(mapOrphanCountByNode.count(departing) == 0,
                            "an entry charge left by the initial-download count reset "
                            "survived the peer's disconnect");
    }
    CheckPoolInvariants("after releasing a stale charge");
}

// NodeIds are never reused, so a reconnecting host is a new owner. Each cycle fills
// one connection to its share, drops it and sweeps; the charge must not accumulate.
BOOST_AUTO_TEST_CASE(a_reconnecting_host_cannot_pin_the_pool)
{
    CScopedOrphanTables tables;
    CScopedArg mem("-maxorphanmem", "1");   // clamped up to the floor
    CScopedArg entries("-maxorphanblocks", "2500");

    const size_t nCeiling = GetMaxOrphanBlocksFootprint();
    const size_t nShare = GetMaxOrphanBlocksFootprintPerPeer();
    BOOST_REQUIRE(nShare > 0 && nShare < nCeiling);

    size_t nPeak = 0;
    unsigned int nFirstCycleParked = 0;
    for (unsigned int nCycle = 0; nCycle < 6; nCycle++)
    {
        const NodeId owner = (NodeId)(772000 + nCycle);      // a fresh connection
        const unsigned int nParked = FillOwnerToItsShare(owner, 33000 + nCycle * 100, 60);
        if (nCycle == 0)
            nFirstCycleParked = nParked;

        BOOST_REQUIRE_MESSAGE(nParked >= 2,
                              "cycle " << nCycle << " parked only " << nParked
                                  << " records: the pool is already pinned by the "
                                     "connections that came before it");
        BOOST_CHECK_MESSAGE(nParked >= nFirstCycleParked,
                            "cycle " << nCycle << " parked " << nParked
                                << " records against the first cycle's " << nFirstCycleParked
                                << ", so earlier connections are still occupying the pool");

        if (GetOrphanBlocksFootprint() > nPeak)
            nPeak = GetOrphanBlocksFootprint();

        // Nothing swept between the cycles but the room test itself, so what is
        // held here is this connection's records and nothing earlier: every
        // previous cycle's bytes and entry charges are gone.
        {
            LOCK(cs_main);
            BOOST_CHECK_MESSAGE(GetOrphanOwnerBucketCount() == 1,
                                "cycle " << nCycle << " runs with "
                                    << GetOrphanOwnerBucketCount()
                                    << " owners charged: the connections that came before it "
                                       "are still holding bytes");
            BOOST_CHECK_MESSAGE(mapOrphanBlocks.size() == nParked,
                                "cycle " << nCycle << " sees " << mapOrphanBlocks.size()
                                    << " records against the " << nParked << " it parked");
            BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprintForNode(owner) == GetOrphanBlocksFootprint(),
                                "cycle " << nCycle << " holds bytes charged to an earlier "
                                    "connection");
        }
        CheckPoolInvariants("cycle fill");

        OrphanBlocksNodeDisconnected(owner);
    }

    {
        LOCK(cs_main);
        SweepOrphanPool(GetTime());
        BOOST_CHECK_MESSAGE(mapOrphanBlocks.empty(),
                            "the last connection's records outlived it");
        BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprint() == 0,
                            "bytes survived every connection that could own them");
        BOOST_CHECK_MESSAGE(GetOrphanOwnerBucketCount() == 0,
                            "an owner bucket survived every connection");
        BOOST_CHECK_MESSAGE(mapOrphanCountByNode.empty(),
                            "an entry charge survived every connection");
    }
    CheckPoolInvariants("after the last release");

    BOOST_CHECK_MESSAGE(nPeak <= nShare,
                        "six connection cycles peaked at " << nPeak
                            << " bytes held against a per-peer share of " << nShare);

    printf("orphan pool: six reconnect cycles at a %u-byte share peaked at %u bytes held, "
           "%u records parked per cycle\n",
           (unsigned)nShare, (unsigned)nPeak, nFirstCycleParked);
}

// With zero peers the sweep must still run and release a departed peer's charge.
// The clock passes the sweep interval but stays inside the expiry.
BOOST_AUTO_TEST_CASE(a_node_with_no_peers_still_releases_a_departed_peer)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    CScopedArg mem("-maxorphanmem", "256");
    CScopedArg entries("-maxorphanblocks", "2500");

    const NodeId departing = 776001;
    for (unsigned int i = 0; i < 4; i++)
        ParkSynthetic(SyntheticOrphanPadded(34100 + i, uint256((uint64_t)0x0f1e0000u + i), 24),
                      departing);
    CheckPoolInvariants("quiescent fill");
    {
        LOCK(cs_main);
        BOOST_REQUIRE_EQUAL(mapOrphanBlocks.size(), 4U);
    }

    OrphanBlocksNodeDisconnected(departing);

    const int64_t nStart = GetTime();
    BOOST_REQUIRE(ORPHAN_POOL_SWEEP_INTERVAL_SECONDS < 600
                  && 600 < ORPHAN_BLOCK_EXPIRY_SECONDS);
    CScopedMockTime clock(nStart + 600);
    BOOST_REQUIRE_MESSAGE(vNodes.empty(),
                          "the case is only about a node with no peers, and this one has "
                              << vNodes.size());
    PeriodicOrphanPoolSweep();

    {
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(mapOrphanBlocks.empty(),
                            "a node with no peers held " << mapOrphanBlocks.size()
                                << " records for a peer that had gone");
        BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprint() == 0,
                            "the departed peer's bytes survived on a node with no peers");
        BOOST_CHECK_MESSAGE(mapOrphanCountByNode.count(departing) == 0,
                            "the departed peer's entry charge survived on a node with no peers");
    }
    CheckPoolInvariants("after the periodic sweep");
}

// Repeated refusals of the same hash defer the next request further each time; the
// deferral must survive SendMessages resetting mapAlreadyAskedFor on each getdata.
BOOST_AUTO_TEST_CASE(a_refused_block_is_re_asked_with_a_growing_backoff)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    CScopedArg mem("-maxorphanmem", "1");   // clamped up to the floor
    CScopedArg entries("-maxorphanblocks", "2500");

    TestPeer peer(19321);
    const CBlock tmpl = BaseTemplate();
    CBlock arriving = DetachedBlock(tmpl, 2600, nTxFill, 0);
    const uint256 hashArriving = arriving.GetHash();
    const size_t nIncoming = OrphanBlockFootprint(arriving);

    const NodeId vHolder[2] = { 773001, 773002 };
    std::vector<uint256> vHeld = FillPoolAgainst(nIncoming, vHolder, 2, 8600, 0xa6ea0000ULL);
    BOOST_REQUIRE(vHeld.size() >= 4);
    BOOST_REQUIRE(GetOrphanBlocksFootprint() + nIncoming > GetMaxOrphanBlocksFootprint());

    ForgetAskedFor(hashArriving);
    const int64_t nStart = GetTime();
    CScopedMockTime clock(nStart);

    int64_t nPrevDeferral = 0;
    for (unsigned int nRound = 0; nRound < 3; nRound++)
    {
        const int64_t nNow = GetTime();
        BOOST_REQUIRE_MESSAGE(!Deliver(peer, arriving),
                              "round " << nRound << ": the pool parked a block it has no room for");

        const int64_t nQueued = AskForTimeFor(peer.node, hashArriving);
        BOOST_REQUIRE_MESSAGE(nQueued >= 0,
                              "round " << nRound << ": the refused block was not re-asked");
        const int64_t nDeferral = (nQueued - nNow * 1000000) / 1000000;
        printf("orphan backoff: refusal %u deferred the next request %" PRId64 "s\n",
               nRound + 1, nDeferral);

        BOOST_CHECK_MESSAGE(nDeferral >= ORPHAN_REFUSAL_BACKOFF_SECONDS,
                            "round " << nRound << ": the retry is deferred only " << nDeferral
                                << "s, under the " << ORPHAN_REFUSAL_BACKOFF_SECONDS
                                << "s base, so a full pool has the peer re-serving the "
                                   "block on every pass");
        if (nRound > 0)
            BOOST_CHECK_MESSAGE(nDeferral > nPrevDeferral,
                                "round " << nRound << ": the deferral did not grow ("
                                    << nPrevDeferral << "s then " << nDeferral
                                    << "s), so the retry rate is fixed rather than backing off");
        nPrevDeferral = nDeferral;

        // The request goes out, which is what resets mapAlreadyAskedFor and what
        // a backoff carried in that map alone would not survive.
        clock.Set(nNow + nDeferral + 1);
        BOOST_REQUIRE(FlushToWire(peer.node));
        peer.node.ClearBlockInFlight(hashArriving);
    }

    // A successful park spends the history, so the next refusal starts over.
    {
        LOCK(cs_main);
        for (unsigned int i = 0; i < vHeld.size(); i++)
            EraseOrphanBlock(vHeld[i], true);
        BOOST_REQUIRE(GetOrphanBlocksFootprint() + nIncoming <= GetMaxOrphanBlocksFootprint());
    }
    BOOST_REQUIRE_MESSAGE(Deliver(peer, arriving), "the re-delivered block was refused");
    {
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(GetOrphanRefusalBackoff(hashArriving) == ORPHAN_REFUSAL_BACKOFF_SECONDS,
                            "a parked block kept its refusal history, so an unrelated later "
                            "refusal starts at " << GetOrphanRefusalBackoff(hashArriving) << "s");
    }
    CheckPoolInvariants("after the park");

    BOOST_CHECK_MESSAGE(peer.node.nMisbehavior == 0, "the refusals scored the peer");
}

// A block larger than the whole per-peer share is not re-asked; it still progresses
// via the ancestor requests and is accepted on delivery once its parent connects.
BOOST_AUTO_TEST_CASE(a_block_that_can_never_fit_is_refused_without_a_re_ask)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    CScopedArg mem("-maxorphanmem", "1");   // clamped up to the floor
    CScopedArg entries("-maxorphanblocks", "2500");

    const size_t nCeiling = GetMaxOrphanBlocksFootprint();
    const size_t nShare = GetMaxOrphanBlocksFootprintPerPeer();

    // The predicate itself, on both bounds it answers for.
    BOOST_CHECK_MESSAGE(OrphanPoolCouldEverHold(nShare, (NodeId)5),
                        "a block that exactly fills a peer's share is called impossible");
    BOOST_CHECK_MESSAGE(!OrphanPoolCouldEverHold(nShare + 1, (NodeId)5),
                        "a block larger than a peer's share is called possible");
    BOOST_CHECK_MESSAGE(OrphanPoolCouldEverHold(nCeiling, (NodeId)-1),
                        "a block of this node's own that exactly fills the ceiling is "
                        "called impossible");
    BOOST_CHECK_MESSAGE(!OrphanPoolCouldEverHold(nCeiling + 1, (NodeId)-1),
                        "a block larger than the whole ceiling is called possible");

    // And the wiring, on an empty pool: nothing here is a matter of room.
    TestPeer peer(19322);
    const CBlock tmpl = BaseTemplate();
    CBlock huge = DetachedBlockOverFootprint(tmpl, 2700, nShare);
    const uint256 hashHuge = huge.GetHash();
    const size_t nFootprint = OrphanBlockFootprint(huge);
    BOOST_REQUIRE_MESSAGE(nFootprint > nShare && nFootprint <= nCeiling,
                          "the oversize block (" << nFootprint << " bytes) is not between the "
                          "share (" << nShare << ") and the ceiling (" << nCeiling << ")");
    printf("orphan pool: never-fits block is %u wire bytes, %u held, against a %u-byte share\n",
           (unsigned)::GetSerializeSize(huge, SER_NETWORK, PROTOCOL_VERSION),
           (unsigned)nFootprint, (unsigned)nShare);

    ForgetAskedFor(hashHuge);
    {
        LOCK(cs_main);
        BOOST_REQUIRE(mapOrphanBlocks.empty());
    }

    BOOST_CHECK_MESSAGE(!Deliver(peer, huge), "a block larger than the share was parked");
    BOOST_CHECK_MESSAGE(!AskedFor(peer.node, hashHuge),
                        "a block the pool can never hold was asked for again, which "
                        "re-downloads it for the life of the connection");
    BOOST_CHECK_MESSAGE(AlreadyAskedForTime(hashHuge) < 0,
                        "a block the pool can never hold left an ask record behind");

    // The ancestor request still goes out, which is how that block makes
    // progress at all.
    BOOST_CHECK_MESSAGE(AskedFor(peer.node, huge.hashPrevBlock),
                        "a block the pool can never hold did not ask for its parent, so "
                        "nothing about it can ever change");
    BOOST_CHECK_MESSAGE(peer.node.nMisbehavior == 0, "the refusal scored the peer");
    CheckPoolInvariants("after refusing a block that can never fit");
}

// The refusal path requests the missing parent (classic park site).
BOOST_AUTO_TEST_CASE(a_refused_orphan_still_asks_for_its_parent)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    CScopedArg mem("-maxorphanmem", "1");   // clamped up to the floor
    CScopedArg entries("-maxorphanblocks", "2500");

    TestPeer peer(19323);
    const CBlock tmpl = BaseTemplate();
    CBlock arriving = DetachedBlock(tmpl, 2800, nTxFill, 0);
    const uint256 hashPrev = arriving.hashPrevBlock;
    const size_t nIncoming = OrphanBlockFootprint(arriving);

    const NodeId vHolder[2] = { 774001, 774002 };
    std::vector<uint256> vHeld = FillPoolAgainst(nIncoming, vHolder, 2, 8800, 0xa7ea0000ULL);
    BOOST_REQUIRE(vHeld.size() >= 4);
    BOOST_REQUIRE(GetOrphanBlocksFootprint() + nIncoming > GetMaxOrphanBlocksFootprint());

    ForgetAskedFor(hashPrev);
    peer.node.getBlocksIndex.clear();
    peer.node.getBlocksHash.clear();
    const unsigned int nGetBlocksFramedBefore = MessagesSentTo(peer.node, "getblocks");

    BOOST_REQUIRE_MESSAGE(!Deliver(peer, arriving),
                          "the pool parked a block it has no room for");

    BOOST_CHECK_MESSAGE(AskedFor(peer.node, hashPrev),
                        "a refused orphan did not ask for the parent it is waiting on, so "
                        "it can never connect");
    BOOST_CHECK_MESSAGE(!peer.node.getBlocksHash.empty(),
                        "a refused orphan queued no getblocks, so the ancestor chain was "
                        "never requested");

    // And that queue is what SendMessages turns into the message on the wire.
    BOOST_REQUIRE(FlushToWire(peer.node));
    BOOST_CHECK_MESSAGE(MessagesSentTo(peer.node, "getblocks") > nGetBlocksFramedBefore,
                        "the queued getblocks never reached the peer");
    BOOST_CHECK_MESSAGE(peer.node.nMisbehavior == 0, "the refusal scored the peer");
    CheckPoolInvariants("after a refused classic park");
}

// The same on the DAG park site: the merge parents it is waiting on.
BOOST_AUTO_TEST_CASE(a_refused_dag_orphan_still_asks_for_its_merge_parents)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    EnsureDAGHeight();
    CScopedArg mem("-maxorphanmem", "1");   // clamped up to the floor
    CScopedArg entries("-maxorphanblocks", "2500");

    TestPeer peer(19324);
    const CBlock tmpl = BaseTemplate();
    uint256 hashMissing;
    CBlock arriving = DAGOrphanBlock(tmpl, 41, nTxFill, 0, hashMissing);
    const size_t nIncoming = OrphanBlockFootprint(arriving);

    const NodeId vHolder[2] = { 775001, 775002 };
    std::vector<uint256> vHeld = FillPoolAgainst(nIncoming, vHolder, 2, 9200, 0xa8ea0000ULL);
    BOOST_REQUIRE(vHeld.size() >= 4);
    BOOST_REQUIRE(GetOrphanBlocksFootprint() + nIncoming > GetMaxOrphanBlocksFootprint());

    ForgetAskedFor(hashMissing);

    BOOST_REQUIRE_MESSAGE(!Deliver(peer, arriving),
                          "the pool parked a DAG orphan it has no room for");

    BOOST_CHECK_MESSAGE(AskedFor(peer.node, hashMissing),
                        "a refused DAG orphan did not ask for the merge parent it is "
                        "waiting on, so it can never connect");
    BOOST_CHECK_MESSAGE(peer.node.nMisbehavior == 0, "the refusal scored the peer");
    CheckPoolInvariants("after a refused dag park");
}

// A block from a peer flagged for disconnect is not parked, whether its id was
// already recorded and swept or the removal is still to come.
BOOST_AUTO_TEST_CASE(a_disconnecting_peer_is_not_charged_for_a_park)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    CScopedArg mem("-maxorphanmem", "256");
    CScopedArg entries("-maxorphanblocks", "2500");

    const CBlock tmpl = BaseTemplate();

    {
        TestPeer peer(19325);
        CBlock arriving = DetachedBlock(tmpl, 2950, 4, 0);
        const uint256 hash = arriving.GetHash();
        const uint256 hashPrev = arriving.hashPrevBlock;
        ForgetAskedFor(hash);
        ForgetAskedFor(hashPrev);

        peer.node.fDisconnect = true;
        OrphanBlocksNodeDisconnected(peer.node.GetId());

        BOOST_CHECK_MESSAGE(!Deliver(peer, arriving),
                            "a block from a peer being removed was accepted as a park");
        {
            LOCK(cs_main);
            SweepOrphanPool(GetTime());
            BOOST_CHECK_MESSAGE(mapOrphanBlocks.count(hash) == 0,
                                "a park charged to a peer whose departed record the park's own "
                                "sweep consumed survives every later sweep");
            BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprint() == 0,
                                "bytes stayed charged to a peer that is gone");
            BOOST_CHECK_MESSAGE(GetOrphanOwnerBucketCount() == 0 && OrphanCountFor(peer.node.GetId()) == 0,
                                "an owner bucket was left for a peer that is gone");
        }
        BOOST_CHECK_MESSAGE(!AskedFor(peer.node, hash) && !AskedFor(peer.node, hashPrev),
                            "a request was queued to a peer that is gone");
        BOOST_CHECK_MESSAGE(peer.node.nMisbehavior == 0, "the refusal scored the peer");
    }

    {
        TestPeer peer(19326);
        CBlock arriving = DetachedBlock(tmpl, 2951, 4, 0);
        const uint256 hash = arriving.GetHash();
        ForgetAskedFor(hash);

        peer.node.fDisconnect = true;
        BOOST_CHECK_MESSAGE(!Deliver(peer, arriving),
                            "a block from a peer flagged for disconnect was parked");
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(mapOrphanBlocks.count(hash) == 0 && GetOrphanBlocksFootprint() == 0,
                            "a park was charged to a peer flagged for disconnect");
    }
    CheckPoolInvariants("after the disconnecting deliveries");
}

// A park cannot outlive its owner's release in either order: departure recording and
// the sweep/park are not mutually ordered, so the departure marker outlives the sweep.
// fDisconnect is left clear so the marker is what is tested.
BOOST_AUTO_TEST_CASE(a_park_cannot_outlive_its_owners_release_in_either_order)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    CScopedArg mem("-maxorphanmem", "256");
    CScopedArg entries("-maxorphanblocks", "2500");

    const CBlock tmpl = BaseTemplate();

    // Order one: departure recorded, consumed by the park's own sweep, park last.
    {
        TestPeer peer(19331);
        const NodeId owner = peer.node.GetId();
        CBlock arriving = DetachedBlock(tmpl, 2960, 4, 0);
        const uint256 hash = arriving.GetHash();
        ForgetAskedFor(hash);

        // Recorded before the delivery, so the sweep at the top of
        // PruneOrphanBlocks is the one that consumes it.
        OrphanBlocksNodeDisconnected(owner);
        BOOST_REQUIRE_MESSAGE(!peer.node.fDisconnect,
                              "the case is about the departure marker, not the disconnect flag");

        BOOST_CHECK_MESSAGE(!Deliver(peer, arriving),
                            "a block was parked for a peer whose departed record the park's "
                            "own sweep had already consumed");
        {
            LOCK(cs_main);
            BOOST_CHECK_MESSAGE(mapOrphanBlocks.count(hash) == 0,
                                "a park charged to a peer whose departed record the park's own "
                                "sweep consumed is held by the pool");
            BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprintForNode(owner) == 0,
                                "peer " << owner << " is charged "
                                    << GetOrphanBlocksFootprintForNode(owner)
                                    << " bytes after its release");
            BOOST_CHECK_MESSAGE(OrphanCountFor(owner) == 0,
                                "peer " << owner << " carries an entry charge of "
                                    << OrphanCountFor(owner) << " after its release");

            // And no later sweep will revisit it, which is what makes the leak
            // permanent rather than late.
            SweepOrphanPool(GetTime());
            BOOST_CHECK_MESSAGE(mapOrphanBlocks.count(hash) == 0,
                                "a park charged to a peer whose departed record the park's own "
                                "sweep consumed survived every later sweep");
            BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprint() == 0,
                                "bytes survived every sweep after the owner had gone ("
                                    << GetOrphanBlocksFootprint() << " held)");
            BOOST_CHECK_MESSAGE(GetOrphanOwnerBucketCount() == 0,
                                "an owner bucket survived every sweep after the owner had gone");

            // The writer refuses on its own: the cut at the park site runs
            // before the room test, and a departure recorded between that cut
            // and the insert has only this guard.
            CBlock* pLate = SyntheticOrphan(29601, uint256((uint64_t)0xdead2960ULL));
            const uint256 hashLate = pLate->GetHash();
            BOOST_CHECK_MESSAGE(!AddOrphanBlock(hashLate, pLate, pLate->hashPrevBlock, owner,
                                                OrphanBlockFootprint(*pLate)),
                                "the writer parked a block for an owner whose departure marker "
                                "is set, so a departure recorded after the park site's cut is "
                                "charged to an id no sweep revisits");
            BOOST_CHECK_MESSAGE(mapOrphanBlocks.count(hashLate) == 0 &&
                                GetOrphanBlocksFootprintForNode(owner) == 0,
                                "the writer charged a departed owner");
        }
        CheckPoolInvariants("after a park behind its owner's release");
    }

    // Order two: the park lands first and the departure is recorded after it.
    // Nothing refuses this one; the next sweep is what has to release it.
    {
        TestPeer peer(19332);
        const NodeId owner = peer.node.GetId();
        CBlock arriving = DetachedBlock(tmpl, 2961, 4, 0);
        const uint256 hash = arriving.GetHash();
        ForgetAskedFor(hash);

        BOOST_REQUIRE_MESSAGE(Deliver(peer, arriving),
                              "the pool refused a block from a peer that is still connected");
        {
            LOCK(cs_main);
            BOOST_REQUIRE_MESSAGE(mapOrphanBlocks.count(hash) == 1,
                                  "the park did not reach the pool");
            BOOST_REQUIRE(GetOrphanBlocksFootprintForNode(owner) > 0);
        }

        OrphanBlocksNodeDisconnected(owner);
        {
            LOCK(cs_main);
            SweepOrphanPool(GetTime());
            BOOST_CHECK_MESSAGE(mapOrphanBlocks.count(hash) == 0,
                                "a record parked before its owner departed outlived the release");
            BOOST_CHECK_MESSAGE(GetOrphanBlocksFootprintForNode(owner) == 0,
                                "bytes stayed charged to a peer that departed after the park");
        }
        CheckPoolInvariants("after a release behind its own park");
    }

    // The marker is bounded: it is retired when the peer's CNode is destroyed,
    // which is the point no thread can name the id to park with it again.
    {
        NodeId owner = -1;
        {
            TestPeer peer(19333);
            owner = peer.node.GetId();
            OrphanBlocksNodeDisconnected(owner);
            {
                LOCK(cs_main);
                SweepOrphanPool(GetTime());
            }
            BOOST_CHECK_MESSAGE(OrphanOwnerHasDeparted(owner),
                                "the departure marker was retired while the peer's CNode was "
                                "still alive, so a park still in flight for it would be charged");
        }
        BOOST_CHECK_MESSAGE(!OrphanOwnerHasDeparted(owner),
                            "the departure marker outlived the peer's CNode, so the set grows "
                            "with every connection this node ever loses");
        BOOST_CHECK_MESSAGE(GetOrphanDepartedOwnerCount() == 0,
                            "the departure markers held are "
                                << GetOrphanDepartedOwnerCount() << " with no peer left to hold one");
    }
}

// A never-fits block is not re-fetched by the headers path either: the suppression
// is keyed by hash and consulted by AskFor. It is bounded: it lapses, and is lifted
// once the parent is indexed. Both bounds are checked.
BOOST_AUTO_TEST_CASE(a_never_fits_block_is_not_re_asked_by_the_headers_path)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    CScopedArg mem("-maxorphanmem", "1");   // clamped up to the floor
    CScopedArg entries("-maxorphanblocks", "2500");

    const size_t nShare = GetMaxOrphanBlocksFootprintPerPeer();
    BOOST_REQUIRE(pindexBest != NULL);

    TestPeer sender(19341), receiver(19342);
    const CBlock tmpl = BaseTemplate();

    // The never-fits block, re-parented onto a header the peer announces, so the
    // headers handler resolves its height and asks for it the way it asks for any
    // other announced block.
    const CBlock headerParent = MakeHeaderOn(pindexBest->GetBlockHash(), 61);
    CBlock huge = DetachedBlockOverFootprint(tmpl, 2760, nShare);
    huge.hashPrevBlock = headerParent.GetHash();
    BOOST_REQUIRE(SolveBlock(&huge));
    BOOST_REQUIRE_MESSAGE(huge.CheckBlock(), "the re-parented oversize block is not admissible");
    const uint256 hashHuge = huge.GetHash();
    const size_t nFootprint = OrphanBlockFootprint(huge);
    BOOST_REQUIRE_MESSAGE(nFootprint > nShare,
                          "the block (" << nFootprint << " bytes held) fits the "
                              << nShare << "-byte share, so it is not a never-fits case");

    std::vector<CBlock> vHeaders;
    vHeaders.push_back(headerParent);
    vHeaders.push_back(HeaderOf(huge));

    // The headers path does ask for it, which is the repetition under test.
    ForgetAskedFor(hashHuge);
    receiver.node.mapAskFor.clear();
    DeliverHeaders(sender, receiver, vHeaders);
    BOOST_REQUIRE_MESSAGE(AskedFor(receiver.node, hashHuge),
                          "the headers path did not ask for the announced block at all, so "
                          "this case would pass without testing anything");

    // The refusal.
    ForgetAskedFor(hashHuge);
    receiver.node.mapAskFor.clear();
    BOOST_REQUIRE_MESSAGE(!Deliver(receiver, huge),
                          "a block larger than the peer's share was parked");
    BOOST_REQUIRE_MESSAGE(GetOrphanBlockRequestSuppressionCount() == 1,
                          "the refusal recorded " << GetOrphanBlockRequestSuppressionCount()
                              << " suppressions rather than one");

    // The same headers round again: no requester may ask for it now.
    receiver.node.mapAskFor.clear();
    ForgetAskedFor(hashHuge);
    DeliverHeaders(sender, receiver, vHeaders);
    BOOST_CHECK_MESSAGE(!AskedFor(receiver.node, hashHuge),
                        "the headers path asked for a block the pool can never hold again, so "
                        "it is re-downloaded on every headers round");
    BOOST_CHECK_MESSAGE(AlreadyAskedForTime(hashHuge) < 0,
                        "a suppressed block left an ask record behind");

    // The header announced beside it is still asked for: the suppression is on
    // the one hash and not on the round.
    BOOST_CHECK_MESSAGE(AskedFor(receiver.node, headerParent.GetHash()),
                        "suppressing one hash stopped the rest of the headers round being "
                        "requested");

    // Bounded, not permanent: the window lapses and the hash is asked for again.
    {
        const int64_t nStart = GetTime();
        CScopedMockTime clock(nStart + ORPHAN_NEVER_FITS_SUPPRESS_SECONDS + 1);
        receiver.node.mapAskFor.clear();
        ForgetAskedFor(hashHuge);
        DeliverHeaders(sender, receiver, vHeaders);
        BOOST_CHECK_MESSAGE(AskedFor(receiver.node, hashHuge),
                            "the suppression outlived its "
                                << ORPHAN_NEVER_FITS_SUPPRESS_SECONDS
                                << "s window, so the block is never fetched again at all");
    }

    // And lifted outright once the parent is in the index, where the block would
    // be accepted on delivery and the pool is not involved.
    {
        CBlock onTip = huge;
        onTip.hashPrevBlock = pindexBest->GetBlockHash();
        BOOST_REQUIRE(SolveBlock(&onTip));
        const uint256 hashOnTip = onTip.GetHash();

        SuppressOrphanBlockRequest(hashOnTip, GetTime(),
                                   std::vector<uint256>(1, onTip.hashPrevBlock));
        BOOST_REQUIRE(IsOrphanBlockRequestSuppressed(hashOnTip));

        std::vector<CBlock> vOnTip;
        vOnTip.push_back(HeaderOf(onTip));
        receiver.node.mapAskFor.clear();
        ForgetAskedFor(hashOnTip);
        DeliverHeaders(sender, receiver, vOnTip);

        BOOST_CHECK_MESSAGE(!IsOrphanBlockRequestSuppressed(hashOnTip),
                            "the suppression stands for a block whose parent is in the index, "
                            "so a sync that reaches its parent stalls on it");
        BOOST_CHECK_MESSAGE(AskedFor(receiver.node, hashOnTip),
                            "a block whose parent is in the index was not requested");
    }

    BOOST_CHECK_MESSAGE(receiver.node.nMisbehavior == 0, "the refusal scored the peer");
    CheckPoolInvariants("after the suppressed headers rounds");
}

// The per-hash re-ask deferral in mapAlreadyAskedFor is capped against now, so
// accumulated refusals cannot push a needed block arbitrarily far out.
BOOST_AUTO_TEST_CASE(the_re_ask_deferral_is_capped_however_many_refusals_land)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    CScopedArg mem("-maxorphanmem", "1");   // clamped up to the floor
    CScopedArg entries("-maxorphanblocks", "2500");

    TestPeer peer(19351);
    const CBlock tmpl = BaseTemplate();
    CBlock arriving = DetachedBlock(tmpl, 2620, nTxFill, 0);
    const uint256 hashArriving = arriving.GetHash();
    const size_t nIncoming = OrphanBlockFootprint(arriving);

    // Earlier cases advance AskFor's monotonic counter; start past it so the measured
    // value is the refusal's deferral.
    const uint256 hashProbe((uint64_t)0xf10091aULL);
    peer.node.AskFor(CInv(MSG_BLOCK, hashProbe));
    const int64_t nFloor = AlreadyAskedForTime(hashProbe) / 1000000;
    ForgetAskedFor(hashProbe);
    peer.node.mapAskFor.clear();

    // The clock is set before the pool is filled, so the records are stamped at
    // it and the expiry does not empty the pool the refusals depend on.
    const int64_t nStart = std::max(GetTime(), nFloor + 2);
    CScopedMockTime clock(nStart);

    const NodeId vHolder[2] = { 778001, 778002 };
    std::vector<uint256> vHeld = FillPoolAgainst(nIncoming, vHolder, 2, 9600, 0xa9ea0000ULL);
    BOOST_REQUIRE(vHeld.size() >= 4);
    BOOST_REQUIRE(GetOrphanBlocksFootprint() + nIncoming > GetMaxOrphanBlocksFootprint());

    ForgetAskedFor(hashArriving);
    peer.node.mapAskFor.clear();

    // The clock does not move and nothing is flushed, so every refusal lands on
    // the record the one before it left: the accumulation the cap has to hold
    // against.
    const unsigned int nRefusals = 20;
    for (unsigned int i = 0; i < nRefusals; i++)
        BOOST_REQUIRE_MESSAGE(!Deliver(peer, arriving),
                              "refusal " << i << ": the pool parked a block it has no room for");

    const int64_t nRecorded = AlreadyAskedForTime(hashArriving);
    BOOST_REQUIRE_MESSAGE(nRecorded >= 0, "the refused block was not re-asked at all");
    const int64_t nDeferral = (nRecorded - nStart * 1000000) / 1000000;
    printf("orphan backoff: %u refusals of one hash deferred its next request %" PRId64 "s "
           "against a %" PRId64 "s cap\n",
           nRefusals, nDeferral, (int64_t)ORPHAN_REASK_MAX_DEFERRAL_SECONDS);

    // AskFor adds its own second on top of what the refusal writes, so the cap is
    // held to within that one step.
    BOOST_CHECK_MESSAGE(nDeferral <= ORPHAN_REASK_MAX_DEFERRAL_SECONDS + 1,
                        nRefusals << " refusals pushed the next request for one hash "
                            << nDeferral << "s out against a cap of "
                            << ORPHAN_REASK_MAX_DEFERRAL_SECONDS
                            << "s, so a peer over its byte share can defer a block this node "
                               "needs without limit");

    const int64_t nQueued = MaxAskForTimeFor(peer.node, hashArriving);
    BOOST_REQUIRE(nQueued >= 0);
    const int64_t nQueuedDeferral = (nQueued - nStart * 1000000) / 1000000;
    BOOST_CHECK_MESSAGE(nQueuedDeferral <= ORPHAN_REASK_MAX_DEFERRAL_SECONDS + 1,
                        "the furthest queued request for the hash is " << nQueuedDeferral
                            << "s out against a cap of " << ORPHAN_REASK_MAX_DEFERRAL_SECONDS
                            << "s");

    // Still a real backoff under the cap: the first refusal is not already at it.
    BOOST_CHECK_MESSAGE(nDeferral >= ORPHAN_REFUSAL_BACKOFF_SECONDS,
                        "the capped deferral is only " << nDeferral
                            << "s, under the " << ORPHAN_REFUSAL_BACKOFF_SECONDS << "s base");
    BOOST_CHECK_MESSAGE(peer.node.nMisbehavior == 0, "the refusals scored the peer");
    CheckPoolInvariants("after the capped refusals");
}

// A never-fits DAG orphan is not re-asked until the merge parent it waits on is
// indexed; the suppression records the full wait set.
BOOST_AUTO_TEST_CASE(a_never_fits_dag_orphan_is_not_re_asked_until_its_merge_parent_connects)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    EnsureDAGHeight();
    CScopedArg mem("-maxorphanmem", "1");   // clamped up to the floor
    CScopedArg entries("-maxorphanblocks", "2500");

    const size_t nShare = GetMaxOrphanBlocksFootprintPerPeer();
    TestPeer sender(19361), receiver(19362);

    // The merge parent: solved on the tip, not yet processed, so the orphan can
    // name it while the index does not hold it.
    const CBlock mergeParent = SolvedBlockOnTip(5);
    const uint256 hashMergeParent = mergeParent.GetHash();
    {
        LOCK(cs_main);
        BOOST_REQUIRE(mapBlockIndex.count(hashMergeParent) == 0);
    }

    const CBlock tmpl = BaseTemplate();
    CBlock huge = DAGOrphanBlockOverFootprint(tmpl, 2770, hashMergeParent, nShare);
    const uint256 hashHuge = huge.GetHash();
    BOOST_REQUIRE_MESSAGE(OrphanBlockFootprint(huge) > nShare, "not a never-fits case");

    std::vector<CBlock> vHeaders(1, HeaderOf(huge));
    std::vector<CInv> vInv(1, CInv(MSG_BLOCK, hashHuge));

    // Its parent is the tip, so the headers path asks for it.
    ForgetAskedFor(hashHuge);
    receiver.node.mapAskFor.clear();
    DeliverHeaders(sender, receiver, vHeaders);
    BOOST_REQUIRE_MESSAGE(AskedFor(receiver.node, hashHuge),
                          "the headers path did not ask for the announced block at all");

    // The refusal, at the DAG park site.
    ForgetAskedFor(hashHuge);
    ForgetAskedFor(hashMergeParent);
    receiver.node.mapAskFor.clear();
    BOOST_REQUIRE_MESSAGE(!Deliver(receiver, huge), "a block larger than the peer's share was parked");
    {
        LOCK(cs_main);
        BOOST_REQUIRE(mapOrphanBlocks.count(hashHuge) == 0);
    }
    BOOST_REQUIRE_MESSAGE(GetOrphanBlockRequestSuppressionCount() == 1,
                          "the refusal recorded " << GetOrphanBlockRequestSuppressionCount()
                              << " suppressions rather than one");
    BOOST_CHECK_MESSAGE(AskedFor(receiver.node, hashMergeParent),
                        "the refused DAG orphan did not ask for its merge parent");

    // The parent is in the index and the merge parent is not: neither request
    // path may lift.
    receiver.node.mapAskFor.clear();
    ForgetAskedFor(hashHuge);
    DeliverHeaders(sender, receiver, vHeaders);
    BOOST_CHECK_MESSAGE(!AskedFor(receiver.node, hashHuge),
                        "the headers path lifted the suppression on a DAG orphan whose merge "
                        "parent is still missing, so a block the pool can never hold is "
                        "re-downloaded on every headers round");
    receiver.node.mapAskFor.clear();
    ForgetAskedFor(hashHuge);
    DeliverInv(sender, receiver, vInv);
    BOOST_CHECK_MESSAGE(!AskedFor(receiver.node, hashHuge),
                        "the inv path lifted the suppression on a DAG orphan whose merge "
                        "parent is still missing");
    BOOST_CHECK_MESSAGE(IsOrphanBlockRequestSuppressed(hashHuge),
                        "the suppression was dropped with the wait set still short");

    // One headers message with a DAG orphan (merge parent missing) and a block whose
    // wait set is indexed: the round asks for the second only.
    {
        const CBlock accepted = SolvedBlockOnTip(6);
        const uint256 hashAccepted = accepted.GetHash();
        BOOST_REQUIRE(hashAccepted != hashHuge);
        {
            LOCK(cs_main);
            std::map<uint256, CBlockIndex*>::iterator miPrev =
                mapBlockIndex.find(accepted.hashPrevBlock);
            BOOST_REQUIRE(miPrev != mapBlockIndex.end());
            // Would really be accepted on delivery: parent indexed and every
            // merge parent its coinbase commits to indexed too, which is the
            // test the DAG park site applies.
            const std::vector<uint256> vCommitted =
                CoinbaseDAGParents(accepted, miPrev->second->nHeight + 1);
            BOOST_REQUIRE_MESSAGE(!vCommitted.empty(),
                                  "the acceptable block committed no DAG parents");
            for (unsigned int i = 1; i < vCommitted.size(); i++)
                BOOST_REQUIRE_MESSAGE(mapBlockIndex.count(vCommitted[i]) != 0,
                                      "the acceptable block names a merge parent that is "
                                      "not in the index, so it would park too");
        }
        SuppressOrphanBlockRequest(hashAccepted, GetTime(),
                                   std::vector<uint256>(1, accepted.hashPrevBlock));
        BOOST_REQUIRE(IsOrphanBlockRequestSuppressed(hashAccepted));

        std::vector<CBlock> vBoth;
        vBoth.push_back(HeaderOf(huge));
        vBoth.push_back(HeaderOf(accepted));
        receiver.node.mapAskFor.clear();
        ForgetAskedFor(hashHuge);
        ForgetAskedFor(hashAccepted);
        DeliverHeaders(sender, receiver, vBoth);

        BOOST_CHECK_MESSAGE(!AskedFor(receiver.node, hashHuge),
                            "the headers round re-asked a never-fits DAG orphan whose merge "
                            "parent is still missing, so it is re-downloaded and refused "
                            "again on every round");
        BOOST_CHECK_MESSAGE(AlreadyAskedForTime(hashHuge) < 0,
                            "the suppressed DAG orphan left an ask record behind");
        BOOST_CHECK_MESSAGE(AskedFor(receiver.node, hashAccepted),
                            "the same round did not ask for a block whose wait set is fully "
                            "indexed, so the suppression stalls a block this node would "
                            "accept on delivery");
        BOOST_CHECK_MESSAGE(IsOrphanBlockRequestSuppressed(hashHuge),
                            "the round dropped the suppression on the still-blocked orphan");
        BOOST_CHECK_MESSAGE(!IsOrphanBlockRequestSuppressed(hashAccepted),
                            "the round left the suppression on the connectable block standing");
    }

    // A header carries no coinbase, so a classic-site record names only the parent and
    // may be downloaded once more; the refusal then re-records the merge parents.
    {
        SuppressOrphanBlockRequest(hashHuge, GetTime(),
                                   std::vector<uint256>(1, huge.hashPrevBlock));
        receiver.node.mapAskFor.clear();
        ForgetAskedFor(hashHuge);
        DeliverHeaders(sender, receiver, vHeaders);
        BOOST_CHECK_MESSAGE(AskedFor(receiver.node, hashHuge),
                            "a record naming only the parent did not lift once the parent was "
                            "in the index, so the classic site's own case regressed");

        // The re-download, refused again at the DAG park site.
        ForgetAskedFor(hashHuge);
        receiver.node.mapAskFor.clear();
        CBlock again = huge;
        BOOST_REQUIRE_MESSAGE(!Deliver(receiver, again), "the re-delivered block was parked");
        BOOST_REQUIRE_MESSAGE(GetOrphanBlockRequestSuppressionCount() == 1,
                              "the second refusal recorded "
                                  << GetOrphanBlockRequestSuppressionCount()
                                  << " suppressions rather than one");

        // Re-recorded against the merge parent, so the next round is quiet.
        receiver.node.mapAskFor.clear();
        ForgetAskedFor(hashHuge);
        DeliverHeaders(sender, receiver, vHeaders);
        BOOST_CHECK_MESSAGE(!AskedFor(receiver.node, hashHuge),
                            "the refusal did not replace a parent-only wait set with the merge "
                            "parents the block is really waiting on, so every headers round "
                            "lifts and re-downloads it again");
        BOOST_CHECK_MESSAGE(IsOrphanBlockRequestSuppressed(hashHuge),
                            "the re-refusal left no suppression standing");
    }

    // The merge parent connects. Now the block is accepted on delivery, and the
    // next round of either path asks for it.
    {
        LOCK(cs_main);
        CBlock connecting = mergeParent;
        BOOST_REQUIRE_MESSAGE(ProcessBlock(NULL, &connecting), "the merge parent did not connect");
        BOOST_REQUIRE(mapBlockIndex.count(hashMergeParent) != 0);
    }
    receiver.node.mapAskFor.clear();
    ForgetAskedFor(hashHuge);
    DeliverInv(sender, receiver, vInv);
    BOOST_CHECK_MESSAGE(AskedFor(receiver.node, hashHuge),
                        "the inv path left the suppression standing after every hash the "
                        "refusal waited on connected, so a node that learns of the block by "
                        "inv waits out the window on a block it would accept");
    BOOST_CHECK_MESSAGE(!IsOrphanBlockRequestSuppressed(hashHuge),
                        "the suppression stands with the wait set fully indexed");

    SuppressOrphanBlockRequest(hashHuge, GetTime(), std::vector<uint256>(1, hashMergeParent));
    receiver.node.mapAskFor.clear();
    ForgetAskedFor(hashHuge);
    DeliverHeaders(sender, receiver, vHeaders);
    BOOST_CHECK_MESSAGE(AskedFor(receiver.node, hashHuge),
                        "the headers path left the suppression standing after every hash the "
                        "refusal waited on connected, so the sync stalls on a block it would "
                        "accept");

    BOOST_CHECK_MESSAGE(receiver.node.nMisbehavior == 0, "the refusal scored the peer");
    CheckPoolInvariants("after the DAG suppression rounds");
}

// A DAG orphan waiting on two merge parents is not re-asked until the second one
// connects.
BOOST_AUTO_TEST_CASE(a_dag_orphan_waiting_on_two_merge_parents_waits_for_the_second)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    EnsureDAGHeight();
    CScopedArg mem("-maxorphanmem", "1");   // clamped up to the floor
    CScopedArg entries("-maxorphanblocks", "2500");

    const size_t nShare = GetMaxOrphanBlocksFootprintPerPeer();
    TestPeer sender(19363), receiver(19364);

    // Two merge parents, solved on the tip and not processed, so the orphan can
    // name both while the index holds neither.
    const CBlock mpFirst = SolvedBlockOnTip(11);
    const CBlock mpSecond = SolvedBlockOnTip(12);
    const uint256 hashFirst = mpFirst.GetHash();
    const uint256 hashSecond = mpSecond.GetHash();
    BOOST_REQUIRE(hashFirst != hashSecond);
    {
        LOCK(cs_main);
        BOOST_REQUIRE(mapBlockIndex.count(hashFirst) == 0);
        BOOST_REQUIRE(mapBlockIndex.count(hashSecond) == 0);
    }

    std::vector<uint256> vMissing;
    vMissing.push_back(hashFirst);
    vMissing.push_back(hashSecond);

    const CBlock tmpl = BaseTemplate();
    CBlock huge = DAGOrphanBlockOverFootprint(tmpl, 2790, vMissing, nShare);
    const uint256 hashHuge = huge.GetHash();
    BOOST_REQUIRE_MESSAGE(OrphanBlockFootprint(huge) > nShare, "not a never-fits case");

    std::vector<CBlock> vHeaders(1, HeaderOf(huge));

    // The refusal, at the DAG park site: both merge parents are recorded.
    ForgetAskedFor(hashHuge);
    ForgetAskedFor(hashFirst);
    ForgetAskedFor(hashSecond);
    receiver.node.mapAskFor.clear();
    BOOST_REQUIRE_MESSAGE(!Deliver(receiver, huge), "a block larger than the peer's share was parked");
    BOOST_REQUIRE_MESSAGE(GetOrphanBlockRequestSuppressionCount() == 1,
                          "the refusal recorded " << GetOrphanBlockRequestSuppressionCount()
                              << " suppressions rather than one");
    BOOST_CHECK_MESSAGE(AskedFor(receiver.node, hashFirst),
                        "the refused DAG orphan did not ask for its first merge parent");
    BOOST_CHECK_MESSAGE(AskedFor(receiver.node, hashSecond),
                        "the refused DAG orphan did not ask for its second merge parent");

    // The first connects. The block would still park, so no path may lift.
    {
        LOCK(cs_main);
        CBlock connecting = mpFirst;
        BOOST_REQUIRE_MESSAGE(ProcessBlock(NULL, &connecting), "the first merge parent did not connect");
        BOOST_REQUIRE(mapBlockIndex.count(hashFirst) != 0);
        BOOST_REQUIRE(mapBlockIndex.count(hashSecond) == 0);
    }
    receiver.node.mapAskFor.clear();
    ForgetAskedFor(hashHuge);
    DeliverHeaders(sender, receiver, vHeaders);
    BOOST_CHECK_MESSAGE(!AskedFor(receiver.node, hashHuge),
                        "the headers path lifted with one of the two merge parents still "
                        "missing, so the block is re-downloaded and refused on every round");
    BOOST_CHECK_MESSAGE(IsOrphanBlockRequestSuppressed(hashHuge),
                        "the suppression was dropped with one merge parent still missing");

    // The second connects: every hash the refusal waited on is in the index and
    // the block is accepted on delivery.
    {
        LOCK(cs_main);
        CBlock connecting = mpSecond;
        BOOST_REQUIRE_MESSAGE(ProcessBlock(NULL, &connecting), "the second merge parent did not connect");
        BOOST_REQUIRE(mapBlockIndex.count(hashSecond) != 0);
    }
    receiver.node.mapAskFor.clear();
    ForgetAskedFor(hashHuge);
    DeliverHeaders(sender, receiver, vHeaders);
    BOOST_CHECK_MESSAGE(AskedFor(receiver.node, hashHuge),
                        "the headers path left the suppression standing after both merge "
                        "parents connected, so the sync stalls on a block it would accept");
    BOOST_CHECK_MESSAGE(!IsOrphanBlockRequestSuppressed(hashHuge),
                        "the suppression stands with the wait set fully indexed");

    BOOST_CHECK_MESSAGE(receiver.node.nMisbehavior == 0, "the refusal scored the peer");
    CheckPoolInvariants("after the two-merge-parent suppression rounds");
}

// A delivery from a departed or departing peer evicts nothing; the disconnect cut
// runs before the room test at both sites.
BOOST_AUTO_TEST_CASE(a_departed_peers_delivery_evicts_nothing)
{
    BOOST_REQUIRE(fRegTest);
    CScopedOrphanTables tables;
    EnsureDAGHeight();
    CScopedArg mem("-maxorphanmem", "256");
    CScopedArg entries("-maxorphanblocks", "8");

    const NodeId holder = 776001;
    for (unsigned int i = 0; i < 8; i++)
        ParkSynthetic(SyntheticOrphan(8300 + i, uint256((uint64_t)(0xf11d0000u + i))), holder);
    size_t nHeld = 0;
    {
        LOCK(cs_main);
        nHeld = mapOrphanBlocks.size();
        BOOST_REQUIRE_EQUAL(nHeld, (size_t)8);
    }

    const CBlock tmpl = BaseTemplate();

    // Departure recorded, flag clear: the classic site.
    {
        TestPeer peer(19371);
        OrphanBlocksNodeDisconnected(peer.node.GetId());
        CBlock arriving = DetachedBlock(tmpl, 2980, 4, 0);
        ForgetAskedFor(arriving.GetHash());
        BOOST_CHECK(!Deliver(peer, arriving));
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(mapOrphanBlocks.size() == nHeld,
                            "a delivery from a departed peer evicted a held orphan at the "
                            "entry bound (" << nHeld << " -> " << mapOrphanBlocks.size() << ")");
    }

    // Flag set, no departure yet: the classic site.
    {
        TestPeer peer(19372);
        peer.node.fDisconnect = true;
        CBlock arriving = DetachedBlock(tmpl, 2981, 4, 0);
        ForgetAskedFor(arriving.GetHash());
        BOOST_CHECK(!Deliver(peer, arriving));
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(mapOrphanBlocks.size() == nHeld,
                            "a delivery from a peer flagged for disconnect evicted a held "
                            "orphan at the entry bound");
    }

    // Departure recorded: the DAG site.
    {
        TestPeer peer(19373);
        OrphanBlocksNodeDisconnected(peer.node.GetId());
        uint256 hashMissing;
        CBlock arriving = DAGOrphanBlock(tmpl, 12, 1, 4096, hashMissing);
        ForgetAskedFor(arriving.GetHash());
        ForgetAskedFor(hashMissing);
        BOOST_CHECK(!Deliver(peer, arriving));
        LOCK(cs_main);
        BOOST_CHECK_MESSAGE(mapOrphanBlocks.size() == nHeld,
                            "a DAG delivery from a departed peer evicted a held orphan at the "
                            "entry bound");
        BOOST_CHECK_MESSAGE(!AskedFor(peer.node, hashMissing),
                            "a request was queued to a peer that is gone");
    }

    CheckPoolInvariants("after the departed deliveries");
}

BOOST_AUTO_TEST_SUITE_END()
