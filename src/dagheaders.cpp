// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "dagheaders.h"

#include "dag.h"
#include "main.h"
#include "net.h"
#include "protocol.h"
#include "state.h"
#include "util.h"

#include <algorithm>

// Wire commands are truncated past COMMAND_SIZE.
static_assert(sizeof(DAGHEADERS_GETCMD) - 1 <= CMessageHeader::COMMAND_SIZE, "command too long");
static_assert(sizeof(DAGHEADERS_CMD) - 1 <= CMessageHeader::COMMAND_SIZE, "command too long");

bool fDAGHeadersSync = false;
bool fDAGHeadersServe = true;

namespace {

CDAGHeaderSkeleton g_skeleton(DEFAULT_DAGHEADERS_WINDOW);

struct CAssumeValidAnchor
{
    uint256 hashAssumeValid;
    uint256 hashRoot;
    int nRootHeight;
    std::vector<uint256> vChain;  // heights nRootHeight+1 .. nRootHeight+vChain.size()

    CAssumeValidAnchor() : nRootHeight(-1) {}
} g_anchor;

// One sync peer at a time; all of this is guarded by cs_main.
NodeId nSyncPeer = -1;
int64_t nSyncActivityMs = 0;
uint256 hashSyncLast = 0;
int nSyncLastHeight = -1;

class CDAGLocator : public CBlockLocator
{
public:
    CDAGLocator() {}
    CDAGLocator(const CBlockIndex* pindex, const uint256& hashFirst) : CBlockLocator(pindex)
    {
        if (hashFirst != 0)
            vHave.insert(vHave.begin(), hashFirst);
    }
    size_t Size() const { return vHave.size(); }
};

void ReleaseSyncPeer()
{
    nSyncPeer = -1;
}

} // namespace

bool CheckDAGHeaderEntry(const CDAGHeaderEntry& entry, int nHeight,
                         std::vector<uint256>& vParentsOut, std::string& strError)
{
    vParentsOut.clear();
    strError.clear();

    if (!entry.txCoinbase.IsCoinBase())
    {
        strError = "first transaction is not a coinbase";
        return false;
    }
    if (entry.vMerkleBranch.size() > MAX_DAGHEADERS_BRANCH)
    {
        strError = "coinbase merkle branch too long";
        return false;
    }
    // A 64-byte leaf could pose as an inner merkle node.
    const unsigned int nTxSize =
        ::GetSerializeSize(entry.txCoinbase, SER_NETWORK, PROTOCOL_VERSION);
    if (nTxSize == 64 || nTxSize > GetMaxBlockSize(nHeight))
    {
        strError = "coinbase size out of range";
        return false;
    }
    if (CBlock::CheckMerkleBranch(entry.txCoinbase.GetHash(), entry.vMerkleBranch, 0) !=
        entry.header.hashMerkleRoot)
    {
        strError = "coinbase merkle branch does not reach the header merkle root";
        return false;
    }

    if (nHeight < FORK_HEIGHT_DAG)
        return true;

    std::vector<CScript> vScripts;
    for (std::vector<CTxOut>::const_iterator it = entry.txCoinbase.vout.begin();
         it != entry.txCoinbase.vout.end(); ++it)
        vScripts.push_back(it->scriptPubKey);
    std::vector<uint256> vParents;
    if (!ReadDAGParentCommitmentAtHeight(vScripts, nHeight, vParents, strError))
        return false;
    if (vParents.empty() || vParents.size() > (size_t)MAX_DAG_PARENTS)
    {
        strError = "DAG parent count out of range";
        return false;
    }
    if (vParents[0] != entry.header.hashPrevBlock)
    {
        strError = "DAG primary parent does not match hashPrevBlock";
        return false;
    }
    const uint256 hash = entry.header.GetHash();
    for (size_t i = 1; i < vParents.size(); i++)
    {
        if (vParents[i] == hash)
        {
            strError = "DAG parent is a self-reference";
            return false;
        }
    }
    vParentsOut.swap(vParents);
    return true;
}

const CDAGSkeletonNode* CDAGHeaderSkeleton::Find(const uint256& hash) const
{
    std::map<uint256, CDAGSkeletonNode>::const_iterator it = mapNodes.find(hash);
    return it == mapNodes.end() ? NULL : &it->second;
}

bool CDAGHeaderSkeleton::Add(const uint256& hash, const CDAGSkeletonNode& node)
{
    if (mapNodes.count(hash))
        return true;
    if (mapNodes.size() >= nMaxEntries)
        return false;
    mapNodes.insert(std::make_pair(hash, node));
    mapByHeight.insert(std::make_pair(node.nHeight, hash));
    return true;
}

void CDAGHeaderSkeleton::PruneAtOrBelow(int nHeight)
{
    while (!mapByHeight.empty() && mapByHeight.begin()->first <= nHeight)
    {
        mapNodes.erase(mapByHeight.begin()->second);
        mapByHeight.erase(mapByHeight.begin());
    }
}

void CDAGHeaderSkeleton::Clear()
{
    mapNodes.clear();
    mapByHeight.clear();
}

bool CDAGHeaderSkeleton::CollectChain(const uint256& hashTip, uint256& hashRootOut,
                                      int& nRootHeightOut, std::vector<uint256>& vChainOut) const
{
    vChainOut.clear();
    const CDAGSkeletonNode* pnode = Find(hashTip);
    if (pnode == NULL)
        return false;
    uint256 hash = hashTip;
    while (pnode != NULL)
    {
        vChainOut.push_back(hash);
        nRootHeightOut = pnode->nHeight - 1;
        hash = pnode->hashPrev;
        const CDAGSkeletonNode* pprev = Find(hash);
        if (pprev != NULL && pprev->nHeight != pnode->nHeight - 1)
            return false;
        pnode = pprev;
    }
    hashRootOut = hash;
    std::reverse(vChainOut.begin(), vChainOut.end());
    return true;
}

CDAGHeaderSkeleton& DAGHeaderSkeleton()
{
    return g_skeleton;
}

void DAGHeadersSetAssumeValidAnchor(const uint256& hashAssumeValid, const uint256& hashRoot,
                                    int nRootHeight, const std::vector<uint256>& vChain)
{
    g_anchor.hashAssumeValid = hashAssumeValid;
    g_anchor.hashRoot = hashRoot;
    g_anchor.nRootHeight = nRootHeight;
    g_anchor.vChain = vChain;
}

void DAGHeadersClearAssumeValidAnchor()
{
    g_anchor = CAssumeValidAnchor();
}

bool DAGHeadersHaveAssumeValidAnchor(const uint256& hashAssumeValid)
{
    return hashAssumeValid != 0 && g_anchor.hashAssumeValid == hashAssumeValid &&
           !g_anchor.vChain.empty();
}

bool DAGHeadersIsAssumeValidAncestor(const uint256& hashAssumeValid, const CBlockIndex* pindex)
{
    if (pindex == NULL || !DAGHeadersHaveAssumeValidAnchor(hashAssumeValid))
        return false;
    if (pindex->nHeight > g_anchor.nRootHeight)
    {
        const size_t i = (size_t)(pindex->nHeight - g_anchor.nRootHeight - 1);
        return i < g_anchor.vChain.size() && g_anchor.vChain[i] == pindex->GetBlockHash();
    }
    std::map<uint256, CBlockIndex*>::const_iterator mi = mapBlockIndex.find(g_anchor.hashRoot);
    if (mi == mapBlockIndex.end() || mi->second == NULL ||
        mi->second->nHeight != g_anchor.nRootHeight)
        return false;
    return mi->second->GetAncestor(pindex->nHeight) == pindex;
}

void InitDAGHeaders(size_t nWindow)
{
    LOCK(cs_main);
    g_skeleton.Clear();
    g_skeleton.SetMaxEntries(nWindow);
    DAGHeadersClearAssumeValidAnchor();
    nSyncPeer = -1;
    hashSyncLast = 0;
    nSyncLastHeight = -1;
}

// Drops headers whose bodies have caught up, and the anchor once its block is indexed.
static void PruneDAGHeaders()
{
    g_skeleton.PruneAtOrBelow(nBestHeight);
    if (g_anchor.hashAssumeValid != 0 && mapBlockIndex.count(g_anchor.hashAssumeValid))
        DAGHeadersClearAssumeValidAnchor();
}

static void ServeDAGHeaders(CNode* pfrom, CDataStream& vRecv)
{
    CDAGLocator locator;
    uint256 hashStop;
    vRecv >> locator >> hashStop;

    if (!fDAGHeadersServe || fSPVMode)
        return;

    const int64_t nNowMs = GetTimeMillis();
    if (pfrom->nDAGHeadersServeTimeMs == 0)
        pfrom->nDAGHeadersServeTokens = DAGHEADERS_SERVE_BURST * 1000;
    else
        pfrom->nDAGHeadersServeTokens = std::min<int64_t>(
            DAGHEADERS_SERVE_BURST * 1000,
            pfrom->nDAGHeadersServeTokens +
                std::max<int64_t>(0, nNowMs - pfrom->nDAGHeadersServeTimeMs) * DAGHEADERS_SERVE_PER_SEC);
    pfrom->nDAGHeadersServeTimeMs = nNowMs;
    if (pfrom->nDAGHeadersServeTokens < 1000)
    {
        pfrom->Misbehaving(10, "getdaghdrs rate");
        return;
    }
    pfrom->nDAGHeadersServeTokens -= 1000;

    if (locator.Size() > 101)
    {
        pfrom->Misbehaving(20, "getdaghdrs locator too large");
        return;
    }

    std::vector<CDAGHeaderEntry> vEntries;
    {
        LOCK(cs_main);
        CBlockIndex* pindex = locator.GetBlockIndex();
        if (pindex)
            pindex = pindex->pnext;
        size_t nBytes = 0;
        for (; pindex && vEntries.size() < MAX_DAGHEADERS_PER_MSG; pindex = pindex->pnext)
        {
            CBlock block;
            if (!block.ReadFromDisk(pindex->nFile, pindex->nBlockPos, true, false) ||
                block.vtx.empty() || block.BuildMerkleTree() != pindex->hashMerkleRoot)
                break;
            CDAGHeaderEntry entry;
            entry.header = pindex->GetBlockHeader();
            entry.txCoinbase = block.vtx[0];
            entry.vMerkleBranch = block.GetMerkleBranch(0);
            nBytes += ::GetSerializeSize(entry, SER_NETWORK, PROTOCOL_VERSION);
            vEntries.push_back(entry);
            if (nBytes >= MAX_DAGHEADERS_REPLY_BYTES || pindex->GetBlockHash() == hashStop)
                break;
        }
    }
    if (fDebugNet)
        printf("dagheaders: serving %u to peer=%d\n", (unsigned int)vEntries.size(), (int)pfrom->GetId());
    pfrom->PushMessage(DAGHEADERS_CMD, vEntries);
}

static void ReceiveDAGHeaders(CNode* pfrom, CDataStream& vRecv)
{
    if (pfrom->nDAGHeadersRequestMs == 0)
    {
        pfrom->Misbehaving(10, "unsolicited daghdrs");
        return;
    }
    pfrom->nDAGHeadersRequestMs = 0;

    std::vector<CDAGHeaderEntry> vEntries;
    vRecv >> vEntries;

    LOCK(cs_main);
    nSyncActivityMs = GetTimeMillis();
    if (vEntries.size() > MAX_DAGHEADERS_PER_MSG)
    {
        pfrom->fDAGHeadersExhausted = true;
        if (nSyncPeer == pfrom->GetId())
            ReleaseSyncPeer();
        pfrom->Misbehaving(20, "daghdrs message too large");
        return;
    }

    const uint256 hashAssumeValid = GetPrivacyVNextAssumeValidHash();
    unsigned int nAdded = 0;
    bool fStop = false;
    for (size_t i = 0; i < vEntries.size() && !fStop; i++)
    {
        const CDAGHeaderEntry& entry = vEntries[i];
        const uint256 hash = entry.header.GetHash();
        if (mapBlockIndex.count(hash) || g_skeleton.Have(hash))
            continue;

        int nHeight = -1;
        std::map<uint256, CBlockIndex*>::const_iterator mi = mapBlockIndex.find(entry.header.hashPrevBlock);
        if (mi != mapBlockIndex.end())
            nHeight = mi->second->nHeight + 1;
        else if (const CDAGSkeletonNode* pprev = g_skeleton.Find(entry.header.hashPrevBlock))
            nHeight = pprev->nHeight + 1;
        else
            break;

        // Same PoW rule the headers handler applies: legacy PoS headers carry no work.
        if ((nHeight >= FORK_HEIGHT_DAG || entry.header.nNonce != 0) &&
            !CheckProofOfWork(hash, entry.header.nBits))
        {
            pfrom->fDAGHeadersExhausted = true;
            ReleaseSyncPeer();
            pfrom->Misbehaving(100, "daghdrs invalid proof of work");
            return;
        }
        if (entry.header.GetBlockTime() > FutureDrift(GetAdjustedTime()))
            break;

        CDAGSkeletonNode node;
        std::string strError;
        if (!CheckDAGHeaderEntry(entry, nHeight, node.vParents, strError))
        {
            if (fDebug)
                printf("dagheaders: %s at height %d from peer=%d\n", strError.c_str(), nHeight,
                       (int)pfrom->GetId());
            pfrom->fDAGHeadersExhausted = true;
            ReleaseSyncPeer();
            pfrom->Misbehaving(100, "daghdrs invalid coinbase proof");
            return;
        }
        node.hashPrev = entry.header.hashPrevBlock;
        node.nHeight = nHeight;
        node.nTime = entry.header.nTime;
        node.nBits = entry.header.nBits;
        if (!g_skeleton.Add(hash, node))
        {
            fStop = true;
            break;
        }
        nAdded++;
        hashSyncLast = hash;
        nSyncLastHeight = nHeight;

        if (hash == hashAssumeValid)
        {
            uint256 hashRoot;
            int nRootHeight = -1;
            std::vector<uint256> vChain;
            std::map<uint256, CBlockIndex*>::const_iterator miRoot;
            if (g_skeleton.CollectChain(hash, hashRoot, nRootHeight, vChain) &&
                (miRoot = mapBlockIndex.find(hashRoot)) != mapBlockIndex.end() &&
                miRoot->second->nHeight == nRootHeight)
            {
                DAGHeadersSetAssumeValidAnchor(hash, hashRoot, nRootHeight, vChain);
                printf("dagheaders: assume-valid block %s known from headers at height %d\n",
                       hash.ToString().substr(0, 16).c_str(), nHeight);
            }
        }
    }

    if (fDebug)
        printf("dagheaders: %u of %u indexed ahead of bodies (skeleton %u, top %d) peer=%d\n",
               nAdded, (unsigned int)vEntries.size(), (unsigned int)g_skeleton.Size(),
               g_skeleton.TopHeight(), (int)pfrom->GetId());

    // An empty or stale reply means the peer has nothing further for us.
    if (nAdded == 0 && !fStop)
    {
        pfrom->fDAGHeadersExhausted = true;
        if (nSyncPeer == pfrom->GetId())
            ReleaseSyncPeer();
    }
}

bool ProcessDAGHeadersMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv)
{
    if (strCommand == DAGHEADERS_GETCMD)
    {
        ServeDAGHeaders(pfrom, vRecv);
        return true;
    }
    if (strCommand == DAGHEADERS_CMD)
    {
        ReceiveDAGHeaders(pfrom, vRecv);
        return true;
    }
    return false;
}

void SendDAGHeadersRequest(CNode* pto)
{
    if (!fDAGHeadersSync || fSPVMode)
        return;

    TRY_LOCK(cs_main, lockMain);
    if (!lockMain)
        return;
    PruneDAGHeaders();
    if (!(pto->nServices & NODE_DAGHEADERS) || pto->fDAGHeadersExhausted ||
        !pto->fSuccessfullyConnected || pto->fDisconnect)
        return;

    const int64_t nNowMs = GetTimeMillis();
    const NodeId id = pto->GetId();
    if (pto->nDAGHeadersRequestMs != 0)
    {
        if (nNowMs - pto->nDAGHeadersRequestMs > DAGHEADERS_REQUEST_TIMEOUT * 1000)
        {
            pto->nDAGHeadersRequestMs = 0;
            pto->fDAGHeadersExhausted = true;
            if (nSyncPeer == id)
                ReleaseSyncPeer();
        }
        return;
    }
    // A sync peer that went quiet (gone, or waiting on room) gives the slot back.
    if (nSyncPeer != -1 && nNowMs - nSyncActivityMs > 2 * DAGHEADERS_REQUEST_TIMEOUT * 1000)
        ReleaseSyncPeer();
    if (nSyncPeer != -1 && nSyncPeer != id)
        return;
    if (nSyncPeer == id && nNowMs - nSyncActivityMs < DAGHEADERS_REQUEST_INTERVAL_MS)
        return;

    uint256 hashFrom = 0;
    int nFrom = nBestHeight;
    if (hashSyncLast != 0 && g_skeleton.Have(hashSyncLast) && nSyncLastHeight > nBestHeight)
    {
        hashFrom = hashSyncLast;
        nFrom = nSyncLastHeight;
    }
    const int nPeerHeight = pto->nBestKnownHeight >= 0 ? pto->nBestKnownHeight : pto->nChainHeight;
    if (nSyncPeer == -1 && nPeerHeight < nFrom + DAGHEADERS_MIN_GAP)
        return;
    if (g_skeleton.Room() < MAX_DAGHEADERS_PER_MSG)
        return;

    pto->PushMessage(DAGHEADERS_GETCMD, CDAGLocator(pindexBest, hashFrom), uint256(0));
    pto->nDAGHeadersRequestMs = nNowMs;
    nSyncPeer = id;
    nSyncActivityMs = nNowMs;
    if (fDebugNet)
        printf("dagheaders: requesting from height %d peer=%d\n", nFrom, (int)id);
}
