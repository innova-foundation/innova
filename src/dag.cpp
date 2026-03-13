// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "dag.h"
#include "main.h"
#include "txdb.h"
#include "util.h"
#include "finality.h"
#include "hash.h"

#include <algorithm>
#include <queue>

CDAGManager g_dagManager;


// ---------------------------------------------------------------------------
// DAG Parent Commitment: coinbase OP_RETURN encoding
// ---------------------------------------------------------------------------

uint256 ComputeDAGParentsHash(const std::vector<uint256>& vParents)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("Innova/DAG/Parents/v1");
    for (const uint256& h : vParents)
        ss << h;
    return ss.GetHash();
}

std::vector<uint256> ExtractDAGParents(const CScript& scriptCoinbase)
{
    std::vector<uint256> vResult;

    // Walk coinbase outputs looking for OP_RETURN with IDAG tag
    // The script format: OP_RETURN <push: tag(4) || count(1) || hashes(32*count)>
    CScript::const_iterator pc = scriptCoinbase.begin();
    if (pc >= scriptCoinbase.end())
        return vResult;

    opcodetype opcode;
    std::vector<unsigned char> vchData;
    if (!scriptCoinbase.GetOp(pc, opcode, vchData))
        return vResult;

    if (opcode != OP_RETURN)
        return vResult;

    if (!scriptCoinbase.GetOp(pc, opcode, vchData))
        return vResult;

    // Verify IDAG tag prefix
    if (vchData.size() < 5) // 4 tag + 1 count minimum
        return vResult;

    if (memcmp(vchData.data(), DAG_PARENT_TAG, 4) != 0)
        return vResult;

    unsigned int nCount = vchData[4];
    if (nCount == 0 || nCount > MAX_DAG_PARENTS)
        return vResult;

    unsigned int nExpectedSize = 5 + nCount * 32;
    if (vchData.size() < nExpectedSize)
        return vResult;

    for (unsigned int i = 0; i < nCount; i++)
    {
        uint256 hash;
        memcpy(hash.begin(), &vchData[5 + i * 32], 32);
        vResult.push_back(hash);
    }

    return vResult;
}

CScript BuildDAGParentScript(const std::vector<uint256>& vParents)
{
    if (vParents.empty() || vParents.size() > MAX_DAG_PARENTS)
        return CScript();

    std::vector<unsigned char> vchData;
    vchData.reserve(5 + vParents.size() * 32);

    // IDAG tag
    vchData.insert(vchData.end(), DAG_PARENT_TAG, DAG_PARENT_TAG + 4);

    // Count
    vchData.push_back((unsigned char)vParents.size());

    // Parent hashes
    for (const uint256& hash : vParents)
    {
        const unsigned char* p = hash.begin();
        vchData.insert(vchData.end(), p, p + 32);
    }

    CScript script;
    script << OP_RETURN << vchData;
    return script;
}


// ---------------------------------------------------------------------------
// CDAGManager: Initialization
// ---------------------------------------------------------------------------

bool CDAGManager::InitBlockDAGData(CBlockIndex* pindex, const std::vector<uint256>& vParents)
{
    LOCK(cs_dag);

    if (!pindex || !pindex->phashBlock)
        return false;

    uint256 hash = pindex->GetBlockHash();

    CBlockDAGData& data = mapDAGData[hash];
    data.vDAGParents = vParents;
    data.fBlue = true; // default, will be colored by ColorBlock()
    data.nDAGScore = 0;
    data.nDAGOrder = -1;

    // Register as child of each parent
    for (const uint256& hashParent : vParents)
    {
        if (mapDAGData.count(hashParent))
            mapDAGData[hashParent].vDAGChildren.push_back(hash);
    }

    // Update DAG tips: this block is a new tip, parents are no longer tips
    setDAGTips.insert(hash);
    for (const uint256& hashParent : vParents)
        setDAGTips.erase(hashParent);

    return true;
}


// ---------------------------------------------------------------------------
// CDAGManager: Tips and Best Tip Selection
// ---------------------------------------------------------------------------

std::vector<uint256> CDAGManager::GetDAGTips() const
{
    LOCK(cs_dag);
    return std::vector<uint256>(setDAGTips.begin(), setDAGTips.end());
}

CBlockIndex* CDAGManager::SelectBestDAGTip() const
{
    LOCK(cs_dag);

    CBlockIndex* pBest = NULL;
    uint256 nBestScore = 0;

    for (const uint256& hashTip : setDAGTips)
    {
        auto it = mapDAGData.find(hashTip);
        if (it == mapDAGData.end())
            continue;

        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashTip);
        if (mi == mapBlockIndex.end())
            continue;

        CBlockIndex* pindex = mi->second;
        if (it->second.nDAGScore > nBestScore ||
            (it->second.nDAGScore == nBestScore && (!pBest || hashTip < pBest->GetBlockHash())))
        {
            nBestScore = it->second.nDAGScore;
            pBest = pindex;
        }
    }

    return pBest;
}


// ---------------------------------------------------------------------------
// CDAGManager: GHOSTDAG Blue-Set Coloring
// ---------------------------------------------------------------------------

void CDAGManager::ColorBlock(CBlockIndex* pindex)
{
    LOCK(cs_dag);

    if (!pindex || !pindex->phashBlock)
        return;

    uint256 hash = pindex->GetBlockHash();
    auto it = mapDAGData.find(hash);
    if (it == mapDAGData.end())
        return;

    CBlockDAGData& data = it->second;
    const std::vector<uint256>& vParents = data.vDAGParents;

    if (vParents.empty())
    {
        // Genesis or pre-DAG block: always blue
        data.fBlue = true;
        data.nDAGScore = pindex->GetBlockTrust();
        return;
    }

    // Find selected parent = parent with highest DAG score
    uint256 hashSelectedParent;
    uint256 nBestParentScore = 0;

    for (const uint256& hashParent : vParents)
    {
        auto pit = mapDAGData.find(hashParent);
        if (pit == mapDAGData.end())
            continue;

        if (pit->second.nDAGScore > nBestParentScore ||
            (pit->second.nDAGScore == nBestParentScore && (hashSelectedParent == 0 || hashParent < hashSelectedParent)))
        {
            nBestParentScore = pit->second.nDAGScore;
            hashSelectedParent = hashParent;
        }
    }

    if (hashSelectedParent == 0)
    {
        data.fBlue = true;
        data.nDAGScore = pindex->GetBlockTrust();
        return;
    }

    // Inherit blue set from selected parent
    std::set<uint256> blueSet = GetBlueSet(hashSelectedParent);

    // For each merge parent, try to add its blue blocks
    for (const uint256& hashParent : vParents)
    {
        if (hashParent == hashSelectedParent)
            continue;

        auto pit = mapDAGData.find(hashParent);
        if (pit == mapDAGData.end())
            continue;

        // Get blue blocks reachable from this merge parent
        std::set<uint256> mergeBlue = GetBlueSet(hashParent);

        for (const uint256& hashCandidate : mergeBlue)
        {
            if (blueSet.count(hashCandidate))
                continue; // already in blue set

            // Check anticone size: |anticone(X) ∩ blue_set| <= GHOSTDAG_K
            int nAnticone = AnticoneSize(hashCandidate, blueSet);
            if (nAnticone <= GHOSTDAG_K)
            {
                blueSet.insert(hashCandidate);
                // Mark block as blue
                auto cit = mapDAGData.find(hashCandidate);
                if (cit != mapDAGData.end())
                    cit->second.fBlue = true;
            }
            else
            {
                // Mark as red
                auto cit = mapDAGData.find(hashCandidate);
                if (cit != mapDAGData.end())
                    cit->second.fBlue = false;
            }
        }
    }

    // This block itself is always blue
    data.fBlue = true;
    blueSet.insert(hash);

    // Compute DAG score: sum of GetBlockTrust() for all blue blocks reachable
    uint256 nScore = 0;
    for (const uint256& hashBlue : blueSet)
    {
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlue);
        if (mi != mapBlockIndex.end())
        {
            uint256 trust = mi->second->GetBlockTrust();
            nScore = nScore + trust;
        }
    }
    data.nDAGScore = nScore;
}


// ---------------------------------------------------------------------------
// CDAGManager: GHOSTDAG Linear Ordering
// ---------------------------------------------------------------------------

std::vector<uint256> CDAGManager::GetDAGLinearOrder(const uint256& hashTip) const
{
    LOCK(cs_dag);

    std::vector<uint256> vOrder;
    std::set<uint256> visited;

    // Follow selected-parent chain from tip to genesis
    std::vector<uint256> selectedChain;
    uint256 hashCurrent = hashTip;

    while (hashCurrent != 0)
    {
        selectedChain.push_back(hashCurrent);
        hashCurrent = GetSelectedParent(hashCurrent);
    }

    // Reverse to go genesis->tip
    std::reverse(selectedChain.begin(), selectedChain.end());

    // At each step on the selected chain, insert newly-visible blocks
    for (const uint256& hashChainBlock : selectedChain)
    {
        if (!visited.insert(hashChainBlock).second)
            continue;

        auto it = mapDAGData.find(hashChainBlock);
        if (it == mapDAGData.end())
        {
            vOrder.push_back(hashChainBlock);
            continue;
        }

        // Collect merge parents' blocks not yet visited
        // Insert blue blocks first (topological), then red blocks
        std::vector<uint256> vBlueInsert;
        std::vector<uint256> vRedInsert;

        std::queue<uint256> queue;
        for (const uint256& hashParent : it->second.vDAGParents)
        {
            if (hashParent != GetSelectedParent(hashChainBlock))
                queue.push(hashParent);
        }

        std::set<uint256> queueVisited;
        while (!queue.empty())
        {
            uint256 h = queue.front();
            queue.pop();

            if (!queueVisited.insert(h).second)
                continue;
            if (visited.count(h))
                continue;

            visited.insert(h);

            auto dit = mapDAGData.find(h);
            if (dit != mapDAGData.end())
            {
                if (dit->second.fBlue)
                    vBlueInsert.push_back(h);
                else
                    vRedInsert.push_back(h);

                // Continue BFS through parents
                for (const uint256& hp : dit->second.vDAGParents)
                {
                    if (!visited.count(hp) && !queueVisited.count(hp))
                        queue.push(hp);
                }
            }
            else
            {
                vBlueInsert.push_back(h); // pre-DAG blocks treated as blue
            }
        }

        // Sort by hash for determinism within each color group
        std::sort(vBlueInsert.begin(), vBlueInsert.end());
        std::sort(vRedInsert.begin(), vRedInsert.end());

        // Insert: blue first, then red, then this chain block
        for (const uint256& h : vBlueInsert)
            vOrder.push_back(h);
        for (const uint256& h : vRedInsert)
            vOrder.push_back(h);
        vOrder.push_back(hashChainBlock);
    }

    return vOrder;
}


// ---------------------------------------------------------------------------
// CDAGManager: DAG Score Computation
// ---------------------------------------------------------------------------

uint256 CDAGManager::ComputeDAGScore(CBlockIndex* pindex)
{
    LOCK(cs_dag);

    if (!pindex || !pindex->phashBlock)
        return 0;

    uint256 hash = pindex->GetBlockHash();
    auto it = mapDAGData.find(hash);
    if (it != mapDAGData.end())
        return it->second.nDAGScore;

    // Pre-DAG block: use nChainTrust
    return pindex->nChainTrust;
}


// ---------------------------------------------------------------------------
// CDAGManager: Selected Parent
// ---------------------------------------------------------------------------

uint256 CDAGManager::GetSelectedParent(const uint256& hashBlock) const
{
    // No lock needed — caller should hold cs_dag
    auto it = mapDAGData.find(hashBlock);
    if (it == mapDAGData.end() || it->second.vDAGParents.empty())
        return 0;

    // Selected parent = parent with highest DAG score
    uint256 hashBest;
    uint256 nBestScore = 0;

    for (const uint256& hashParent : it->second.vDAGParents)
    {
        auto pit = mapDAGData.find(hashParent);
        if (pit == mapDAGData.end())
            continue;

        if (pit->second.nDAGScore > nBestScore ||
            (pit->second.nDAGScore == nBestScore && (hashBest == 0 || hashParent < hashBest)))
        {
            nBestScore = pit->second.nDAGScore;
            hashBest = hashParent;
        }
    }

    return hashBest;
}


// ---------------------------------------------------------------------------
// CDAGManager: Blue Set and Anticone helpers
// ---------------------------------------------------------------------------

std::set<uint256> CDAGManager::GetBlueSet(const uint256& hashBlock) const
{
    // No lock needed — caller should hold cs_dag
    std::set<uint256> blueSet;
    std::set<uint256> visited;
    std::queue<uint256> queue;
    queue.push(hashBlock);

    while (!queue.empty())
    {
        uint256 h = queue.front();
        queue.pop();

        if (!visited.insert(h).second)
            continue;

        auto it = mapDAGData.find(h);
        if (it == mapDAGData.end())
        {
            blueSet.insert(h); // pre-DAG blocks are blue
            continue;
        }

        if (it->second.fBlue)
            blueSet.insert(h);

        // BFS through parents (bounded by depth for performance)
        if ((int)visited.size() > DAG_PRUNE_DEPTH)
            break;

        for (const uint256& hp : it->second.vDAGParents)
        {
            if (!visited.count(hp))
                queue.push(hp);
        }
    }

    return blueSet;
}

int CDAGManager::AnticoneSize(const uint256& hashBlock, const std::set<uint256>& blueSet) const
{
    // Anticone of X w.r.t. blue set: blocks in blueSet that are neither
    // ancestors nor descendants of X.
    // Simplified approximation: count blue-set blocks at same height not in X's past
    // For correctness with small K this works well.

    auto itX = mapDAGData.find(hashBlock);
    if (itX == mapDAGData.end())
        return 0;

    // Get X's past set (ancestors)
    std::set<uint256> pastX = GetPastSet(hashBlock, DAG_MERGE_DEPTH * 2);

    int nAnticone = 0;
    for (const uint256& hashBlue : blueSet)
    {
        if (hashBlue == hashBlock)
            continue;
        if (pastX.count(hashBlue))
            continue; // ancestor of X, not in anticone

        // Check if X is an ancestor of hashBlue
        std::set<uint256> pastBlue = GetPastSet(hashBlue, DAG_MERGE_DEPTH * 2);
        if (pastBlue.count(hashBlock))
            continue; // X is ancestor of this blue block, not in anticone

        nAnticone++;
    }

    return nAnticone;
}

std::set<uint256> CDAGManager::GetPastSet(const uint256& hashBlock, int nMaxDepth) const
{
    // No lock needed — caller should hold cs_dag
    std::set<uint256> past;
    std::queue<uint256> queue;

    auto it = mapDAGData.find(hashBlock);
    if (it == mapDAGData.end())
        return past;

    for (const uint256& hp : it->second.vDAGParents)
        queue.push(hp);

    int nDepth = 0;
    while (!queue.empty() && nDepth < nMaxDepth)
    {
        uint256 h = queue.front();
        queue.pop();

        if (!past.insert(h).second)
            continue;

        auto pit = mapDAGData.find(h);
        if (pit != mapDAGData.end())
        {
            for (const uint256& hp : pit->second.vDAGParents)
            {
                if (!past.count(hp))
                    queue.push(hp);
            }
        }
        nDepth++;
    }

    return past;
}


// ---------------------------------------------------------------------------
// CDAGManager: Sibling Blocks (for conflict resolution in ConnectBlock)
// ---------------------------------------------------------------------------

std::set<uint256> CDAGManager::GetDAGSiblingBlocks(const uint256& hashBlock) const
{
    LOCK(cs_dag);

    std::set<uint256> siblings;
    auto it = mapDAGData.find(hashBlock);
    if (it == mapDAGData.end())
        return siblings;

    // Siblings = other children of our parents
    for (const uint256& hashParent : it->second.vDAGParents)
    {
        auto pit = mapDAGData.find(hashParent);
        if (pit == mapDAGData.end())
            continue;

        for (const uint256& hashChild : pit->second.vDAGChildren)
        {
            if (hashChild != hashBlock)
                siblings.insert(hashChild);
        }
    }

    return siblings;
}

bool CDAGManager::HasDAGData(const uint256& hash) const
{
    LOCK(cs_dag);
    return mapDAGData.count(hash) > 0;
}

const CBlockDAGData* CDAGManager::GetDAGData(const uint256& hash) const
{
    LOCK(cs_dag);
    auto it = mapDAGData.find(hash);
    if (it == mapDAGData.end())
        return NULL;
    return &it->second;
}


// ---------------------------------------------------------------------------
// CDAGManager: LevelDB Persistence
// ---------------------------------------------------------------------------

bool CDAGManager::WriteDAGLinks(CTxDB& txdb, const uint256& hash)
{
    LOCK(cs_dag);

    auto it = mapDAGData.find(hash);
    if (it == mapDAGData.end())
        return false;

    return txdb.WriteDAGLinks(hash, it->second);
}

bool CDAGManager::LoadDAGLinks(CTxDB& txdb)
{
    LOCK(cs_dag);

    mapDAGData.clear();
    setDAGTips.clear();

    // Load DAG links for all blocks that have them
    // Iterate through mapBlockIndex and try to read DAG data for each
    for (const auto& item : mapBlockIndex)
    {
        CBlockDAGData data;
        if (txdb.ReadDAGLinks(item.first, data))
            mapDAGData[item.first] = data;
    }

    // Rebuild tips: any block in mapDAGData with no children is a tip
    for (const auto& pair : mapDAGData)
    {
        if (pair.second.vDAGChildren.empty())
            setDAGTips.insert(pair.first);
    }

    if (!mapDAGData.empty())
        printf("LoadDAGLinks: loaded %d DAG entries, %d tips\n",
               (int)mapDAGData.size(), (int)setDAGTips.size());

    return true;
}


// ---------------------------------------------------------------------------
// CDAGManager: Rebuild Ordering
// ---------------------------------------------------------------------------

void CDAGManager::RebuildDAGOrder()
{
    LOCK(cs_dag);

    // Re-color all blocks and recompute scores
    // Process blocks in height order
    std::vector<std::pair<int, uint256>> vByHeight;

    for (const auto& pair : mapDAGData)
    {
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(pair.first);
        if (mi != mapBlockIndex.end())
            vByHeight.push_back(std::make_pair(mi->second->nHeight, pair.first));
    }

    std::sort(vByHeight.begin(), vByHeight.end());

    for (const auto& pair : vByHeight)
    {
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(pair.second);
        if (mi != mapBlockIndex.end())
            ColorBlock(mi->second);
    }

    // Assign linear ordering from best tip
    CBlockIndex* pBestTip = SelectBestDAGTip();
    if (pBestTip && pBestTip->phashBlock)
    {
        std::vector<uint256> vOrder = GetDAGLinearOrder(pBestTip->GetBlockHash());
        for (int i = 0; i < (int)vOrder.size(); i++)
        {
            auto it = mapDAGData.find(vOrder[i]);
            if (it != mapDAGData.end())
                it->second.nDAGOrder = i;
        }
    }

    printf("RebuildDAGOrder: recolored and ordered %d DAG blocks\n", (int)vByHeight.size());
}
