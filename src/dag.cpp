// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "dag.h"
#include "main.h"
#include "txdb.h"
#include "finality.h"
#include "util.h"

#include <algorithm>
#include <queue>

CDAGManager g_dagManager;


// ---------------------------------------------------------------------------
// DAG Parent Commitment: coinbase OP_RETURN encoding
// ---------------------------------------------------------------------------

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

    vchData.insert(vchData.end(), DAG_PARENT_TAG, DAG_PARENT_TAG + 4);
    vchData.push_back((unsigned char)vParents.size());
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
    data.fBlue = true; // default, recolored by ColorBlock/ColorBlockDAGKnight
    data.nDAGScore = 0;
    data.nDAGOrder = -1;
    data.nInferredK = -1;

    // Invalidate blue set cache (new block changes ancestry relationships)
    mapBlueSetCache.clear();

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
// CDAGManager: GHOSTDAG Blue-Set Coloring (pre-DAGKNIGHT)
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
    // Pre-DAG parents use their nChainTrust as effective DAG score
    uint256 hashSelectedParent;
    uint256 nBestParentScore = 0;

    for (const uint256& hashParent : vParents)
    {
        uint256 nParentScore = 0;
        auto pit = mapDAGData.find(hashParent);
        if (pit != mapDAGData.end())
        {
            nParentScore = pit->second.nDAGScore;
        }
        else
        {
            // Pre-DAG parent: use accumulated chain trust as base score
            std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashParent);
            if (mi != mapBlockIndex.end())
                nParentScore = mi->second->nChainTrust;
        }

        if (nParentScore > nBestParentScore ||
            (nParentScore == nBestParentScore && (hashSelectedParent == 0 || hashParent < hashSelectedParent)))
        {
            nBestParentScore = nParentScore;
            hashSelectedParent = hashParent;
        }
    }

    if (hashSelectedParent == 0)
    {
        // Fallback: use parent's chain trust + this block's trust
        if (pindex->pprev)
            data.nDAGScore = pindex->pprev->nChainTrust + pindex->GetBlockTrust();
        else
            data.nDAGScore = pindex->GetBlockTrust();
        data.fBlue = true;
        return;
    }

    // Inherit blue set from selected parent
    std::set<uint256> blueSet = GetBlueSetCached(hashSelectedParent);
    // Cache selected parent's blue set before merge modifications (avoid redundant BFS)
    std::set<uint256> selectedParentBlue = blueSet;

    // For each merge parent, try to add its blue blocks
    for (const uint256& hashParent : vParents)
    {
        if (hashParent == hashSelectedParent)
            continue;

        auto pit = mapDAGData.find(hashParent);
        if (pit == mapDAGData.end())
            continue;

        // Get blue blocks reachable from this merge parent
        std::set<uint256> mergeBlue = GetBlueSetCached(hashParent);

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

    // Compute DAG score incrementally:
    // score = selected_parent_score + this_block_trust
    //       + trust of newly-blue merge blocks (not already in selected parent's blue set)
    uint256 nScore = nBestParentScore + pindex->GetBlockTrust();

    // Add trust from newly-blue merge parent blocks (using cached selectedParentBlue)
    for (const uint256& hashBlue : blueSet)
    {
        if (hashBlue == hash)
            continue; // already counted above
        if (selectedParentBlue.count(hashBlue))
            continue; // already in selected parent's score

        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlue);
        if (mi != mapBlockIndex.end())
        {
            nScore = nScore + mi->second->GetBlockTrust();
        }
    }
    data.nDAGScore = nScore;
}


// ---------------------------------------------------------------------------
// CDAGManager: DAG Linear Ordering
// ---------------------------------------------------------------------------

std::vector<uint256> CDAGManager::GetDAGLinearOrder(const uint256& hashTip, int nMaxBlocks) const
{
    LOCK(cs_dag);

    std::vector<uint256> vOrder;
    std::set<uint256> visited;

    // Follow selected-parent chain from tip to genesis
    // Bounded by mapDAGData size + cycle detection for safety
    std::vector<uint256> selectedChain;
    std::set<uint256> chainVisited;
    uint256 hashCurrent = hashTip;
    int nMaxChainLen = (int)mapDAGData.size() + 1;

    // If caller requests limited output, limit chain walk depth too
    if (nMaxBlocks > 0 && nMaxBlocks < nMaxChainLen)
        nMaxChainLen = nMaxBlocks;

    while (hashCurrent != 0 && nMaxChainLen > 0)
    {
        if (!chainVisited.insert(hashCurrent).second)
            break; // cycle detected — stop
        selectedChain.push_back(hashCurrent);
        hashCurrent = GetSelectedParent(hashCurrent);
        nMaxChainLen--;
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
    // Pre-DAG parents use nChainTrust as effective score
    uint256 hashBest;
    uint256 nBestScore = 0;

    for (const uint256& hashParent : it->second.vDAGParents)
    {
        uint256 nParentScore = 0;
        auto pit = mapDAGData.find(hashParent);
        if (pit != mapDAGData.end())
        {
            nParentScore = pit->second.nDAGScore;
        }
        else
        {
            // Pre-DAG parent: use chain trust
            std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashParent);
            if (mi != mapBlockIndex.end())
                nParentScore = mi->second->nChainTrust;
        }

        if (nParentScore > nBestScore ||
            (nParentScore == nBestScore && (hashBest == 0 || hashParent < hashBest)))
        {
            nBestScore = nParentScore;
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
    // Bounded by DAG_MERGE_DEPTH * 4 to prevent DoS from deep BFS traversals
    static const int BLUESET_MAX_VISITED = DAG_MERGE_DEPTH * 4; // 256

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
            // Deterministic boundary: any missing block at/above FORK_HEIGHT_DAG is a
            // pruned DAG block (stop BFS). Below FORK_HEIGHT_DAG is a genuine pre-DAG
            // block (add to blue set). This is deterministic regardless of local pruning state.
            std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(h);
            if (mi != mapBlockIndex.end() && mi->second->nHeight >= FORK_HEIGHT_DAG)
                continue; // pruned DAG-era block — BFS boundary
            blueSet.insert(h); // genuine pre-DAG block
            continue;
        }

        if (it->second.fBlue)
            blueSet.insert(h);

        // Bounded BFS to prevent DoS
        if ((int)visited.size() >= BLUESET_MAX_VISITED)
            break;

        for (const uint256& hp : it->second.vDAGParents)
        {
            if (!visited.count(hp))
                queue.push(hp);
        }
    }

    return blueSet;
}

std::set<uint256> CDAGManager::GetBlueSetCached(const uint256& hashBlock) const
{
    // Check cache first
    auto cit = mapBlueSetCache.find(hashBlock);
    if (cit != mapBlueSetCache.end())
        return cit->second;

    // Compute and cache
    std::set<uint256> blueSet = GetBlueSet(hashBlock);

    // Evict oldest if cache full (simple eviction: clear half)
    if ((int)mapBlueSetCache.size() >= BLUESET_CACHE_MAX)
    {
        auto it = mapBlueSetCache.begin();
        int nToRemove = BLUESET_CACHE_MAX / 2;
        while (it != mapBlueSetCache.end() && nToRemove > 0)
        {
            it = mapBlueSetCache.erase(it);
            nToRemove--;
        }
    }

    mapBlueSetCache[hashBlock] = blueSet;
    return blueSet;
}

int CDAGManager::AnticoneSize(const uint256& hashBlock, const std::set<uint256>& blueSet) const
{
    // Anticone of X w.r.t. blue set: blocks in blueSet that are neither
    // ancestors nor descendants of X.

    auto itX = mapDAGData.find(hashBlock);
    if (itX == mapDAGData.end())
        return 0;

    // Get X's past set (ancestors) — computed once
    std::set<uint256> pastX = GetPastSet(hashBlock, DAG_MERGE_DEPTH * 2);

    // Get X's future set by checking which blueSet blocks have X in their past
    // Build a combined future set for efficiency: collect all blocks that have X as ancestor
    std::set<uint256> futureX;
    for (const uint256& hashBlue : blueSet)
    {
        if (hashBlue == hashBlock || pastX.count(hashBlue))
            continue;

        // Check if hashBlue has hashBlock in its past (i.e., X is ancestor of hashBlue)
        // Use bounded BFS from hashBlue back through parents
        std::set<uint256> visited;
        std::queue<uint256> q;
        auto bit = mapDAGData.find(hashBlue);
        if (bit == mapDAGData.end())
            continue;

        bool fFound = false;
        for (const uint256& hp : bit->second.vDAGParents)
            q.push(hp);

        int nSteps = 0;
        while (!q.empty() && nSteps < DAG_MERGE_DEPTH * 2)
        {
            uint256 h = q.front();
            q.pop();
            if (!visited.insert(h).second)
                continue;
            if (h == hashBlock)
            {
                fFound = true;
                break;
            }
            auto pit = mapDAGData.find(h);
            if (pit != mapDAGData.end())
            {
                for (const uint256& hp : pit->second.vDAGParents)
                {
                    if (!visited.count(hp))
                        q.push(hp);
                }
            }
            nSteps++;
        }

        if (fFound)
            futureX.insert(hashBlue);
    }

    // Anticone = blueSet - {X} - past(X) - future(X)
    int nAnticone = 0;
    for (const uint256& hashBlue : blueSet)
    {
        if (hashBlue == hashBlock)
            continue;
        if (pastX.count(hashBlue))
            continue;
        if (futureX.count(hashBlue))
            continue;
        nAnticone++;
    }

    return nAnticone;
}

std::set<uint256> CDAGManager::GetPastSet(const uint256& hashBlock, int nMaxDepth) const
{
    // No lock needed — caller should hold cs_dag
    // Uses height-based depth (not BFS step count) for deterministic traversal
    std::set<uint256> past;
    std::queue<uint256> queue;

    auto it = mapDAGData.find(hashBlock);
    if (it == mapDAGData.end())
        return past;

    // Get starting block height for depth comparison
    int nStartHeight = -1;
    std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi != mapBlockIndex.end())
        nStartHeight = mi->second->nHeight;

    for (const uint256& hp : it->second.vDAGParents)
        queue.push(hp);

    while (!queue.empty())
    {
        uint256 h = queue.front();
        queue.pop();

        if (!past.insert(h).second)
            continue;

        // Height-based depth check: stop when block is too far below start
        if (nStartHeight >= 0)
        {
            std::map<uint256, CBlockIndex*>::iterator mh = mapBlockIndex.find(h);
            if (mh != mapBlockIndex.end() && nStartHeight - mh->second->nHeight > nMaxDepth)
                continue; // don't expand parents beyond depth limit
        }

        auto pit = mapDAGData.find(h);
        if (pit != mapDAGData.end())
        {
            for (const uint256& hp : pit->second.vDAGParents)
            {
                if (!past.count(hp))
                    queue.push(hp);
            }
        }
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

bool CDAGManager::GetDAGData(const uint256& hash, CBlockDAGData& dataOut) const
{
    LOCK(cs_dag);
    auto it = mapDAGData.find(hash);
    if (it == mapDAGData.end())
        return false;
    dataOut = it->second;
    return true;
}


void CDAGManager::RemoveBlockDAGData(const uint256& hashBlock)
{
    LOCK(cs_dag);

    auto it = mapDAGData.find(hashBlock);
    if (it == mapDAGData.end())
        return;

    // Remove this block from its parents' child lists
    for (const uint256& hashParent : it->second.vDAGParents)
    {
        auto pit = mapDAGData.find(hashParent);
        if (pit != mapDAGData.end())
        {
            auto& children = pit->second.vDAGChildren;
            children.erase(std::remove(children.begin(), children.end(), hashBlock), children.end());
            // Parent may become a tip again if it has no other children
            if (children.empty())
                setDAGTips.insert(hashParent);
        }
    }

    // Remove from tips and data
    setDAGTips.erase(hashBlock);
    mapDAGData.erase(it);
    mapBlueSetCache.clear();
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

    // Load DAG links using efficient LevelDB prefix iteration
    txdb.IterateDAGLinks(mapDAGData);

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

    // Clear blue set cache to avoid stale entries during rebuild
    mapBlueSetCache.clear();

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
        {
            // Phase 4: Fork-gate between GHOSTDAG and DAGKNIGHT coloring
            if (mi->second->nHeight >= FORK_HEIGHT_DAGKNIGHT)
                ColorBlockDAGKnight(mi->second);
            else
                ColorBlock(mi->second);
        }
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


// ---------------------------------------------------------------------------
// CDAGManager: Incremental Rebuild (only recolors blocks above nCleanHeight)
// ---------------------------------------------------------------------------

void CDAGManager::RebuildDAGOrderIncremental(int nCleanHeight)
{
    LOCK(cs_dag);

    // Clear blue set cache to avoid stale entries during rebuild
    mapBlueSetCache.clear();

    std::vector<std::pair<int, uint256>> vByHeight;

    for (const auto& pair : mapDAGData)
    {
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(pair.first);
        if (mi != mapBlockIndex.end() && mi->second->nHeight > nCleanHeight)
            vByHeight.push_back(std::make_pair(mi->second->nHeight, pair.first));
    }

    std::sort(vByHeight.begin(), vByHeight.end());

    for (const auto& pair : vByHeight)
    {
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(pair.second);
        if (mi != mapBlockIndex.end())
        {
            // Phase 4: Fork-gate between GHOSTDAG and DAGKNIGHT coloring
            if (mi->second->nHeight >= FORK_HEIGHT_DAGKNIGHT)
                ColorBlockDAGKnight(mi->second);
            else
                ColorBlock(mi->second);
        }
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

    printf("RebuildDAGOrderIncremental: recolored %d blocks above height %d\n",
           (int)vByHeight.size(), nCleanHeight);
}


// ---------------------------------------------------------------------------
// CDAGManager: DAG Pruning
// ---------------------------------------------------------------------------

bool CDAGManager::PruneDAGData(CTxDB& txdb, int nHeight)
{
    LOCK(cs_dag);

    int nPruneBelow = nHeight - DAG_PRUNE_DEPTH;
    if (nPruneBelow <= 0)
        return true; // nothing to prune

    int nPruned = 0;
    std::vector<uint256> vToErase;

    for (const auto& pair : mapDAGData)
    {
        // Don't prune epoch boundary blocks
        if (setEpochBoundaryBlocks.count(pair.first))
            continue;

        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(pair.first);
        if (mi == mapBlockIndex.end())
            continue;

        if (mi->second->nHeight < nPruneBelow)
            vToErase.push_back(pair.first);
    }

    if (vToErase.empty())
        return true;

    // Phase 1: Write erasures + prune height to LevelDB atomically
    if (!txdb.TxnBegin())
        return false;

    for (const uint256& hash : vToErase)
        txdb.EraseDAGLinks(hash);

    // Persist prune height so GetBlueSet boundary check survives restart
    txdb.WriteDAGCleanHeight(nPruneBelow);

    if (!txdb.TxnCommit())
        return false;

    // Phase 2: Erase from memory only after LevelDB commit succeeds
    for (const uint256& hash : vToErase)
    {
        mapDAGData.erase(hash);
        setDAGTips.erase(hash);
        nPruned++;
    }

    nPrunedBelowHeight = nPruneBelow;

    if (nPruned > 0)
        printf("PruneDAGData: pruned %d entries below height %d (%d remaining)\n",
               nPruned, nPruneBelow, (int)mapDAGData.size());

    return true;
}


// ---------------------------------------------------------------------------
// CDAGManager: Epoch State Computation
// ---------------------------------------------------------------------------

bool CDAGManager::ComputeEpochState(int nEpoch, int nEpochInterval)
{
    LOCK(cs_dag);

    CEpochState state;
    state.nEpoch = nEpoch;
    // Use GetEpochBoundaryHeight for correct post-DAG height computation
    state.nHeightStart = GetEpochBoundaryHeight(nEpoch, nEpoch * nEpochInterval);
    state.nHeightEnd = state.nHeightStart + nEpochInterval - 1;
    state.nBlockCount = 0;
    state.nTxCount = 0;
    state.nTotalTrust = 0;
    state.fFinalized = false;

    // Find the boundary block (last block of this epoch)
    CBlockIndex* pBoundary = FindBlockByHeight(state.nHeightEnd);
    if (pBoundary && pBoundary->phashBlock)
    {
        state.hashBoundaryBlock = pBoundary->GetBlockHash();
        setEpochBoundaryBlocks.insert(state.hashBoundaryBlock);
    }

    // Collect blocks in this epoch range that have DAG data
    std::vector<std::pair<int, uint256>> vEpochBlocks;
    for (const auto& pair : mapDAGData)
    {
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(pair.first);
        if (mi == mapBlockIndex.end())
            continue;

        int nBlockHeight = mi->second->nHeight;
        if (nBlockHeight >= state.nHeightStart && nBlockHeight <= state.nHeightEnd)
        {
            vEpochBlocks.push_back(std::make_pair(nBlockHeight, pair.first));
            state.nBlockCount++;

            if (pair.second.fBlue)
                state.nTotalTrust = state.nTotalTrust + mi->second->GetBlockTrust();
        }
    }

    // Order blocks by height within epoch (hash tiebreaker for determinism)
    std::sort(vEpochBlocks.begin(), vEpochBlocks.end());
    for (const auto& pair : vEpochBlocks)
        state.vBlockHashes.push_back(pair.second);

    // Transaction counting deferred to RPC layer (getepochinfo) to avoid
    // blocking block processing with disk I/O at every epoch boundary.
    // nTxCount = -1 signals "not yet counted"; RPC can populate on demand.
    state.nTxCount = -1;

    // Check finality
    state.fFinalized = g_finalityTracker.IsFinalized(state.nHeightEnd);

    mapEpochState[nEpoch] = state;

    printf("ComputeEpochState: epoch %d (%d-%d), %d blocks, %d txs, finalized=%d\n",
           nEpoch, state.nHeightStart, state.nHeightEnd,
           state.nBlockCount, state.nTxCount, state.fFinalized);

    return true;
}

bool CDAGManager::WriteEpochState(CTxDB& txdb, int nEpoch)
{
    LOCK(cs_dag);

    auto it = mapEpochState.find(nEpoch);
    if (it == mapEpochState.end())
        return false;

    return txdb.WriteEpochState(nEpoch, it->second);
}

bool CDAGManager::GetEpochState(int nEpoch, CEpochState& stateOut) const
{
    LOCK(cs_dag);

    auto it = mapEpochState.find(nEpoch);
    if (it == mapEpochState.end())
        return false;

    stateOut = it->second;
    return true;
}

int CDAGManager::GetDAGEntryCount() const
{
    LOCK(cs_dag);
    return (int)mapDAGData.size();
}

int CDAGManager::GetPrunedBelowHeight() const
{
    LOCK(cs_dag);
    return nPrunedBelowHeight;
}

void CDAGManager::SetPrunedBelowHeight(int nHeight)
{
    LOCK(cs_dag);
    nPrunedBelowHeight = nHeight;
}


// ---------------------------------------------------------------------------
// CDAGManager: DAGKNIGHT Adaptive Ordering (Phase 4)
// ---------------------------------------------------------------------------

int CDAGManager::InferLocalK(const uint256& hashBlock) const
{
    // No lock — caller holds cs_dag
    // Determinism: use each ancestor's already-stored nInferredK (computed at
    // their own coloring time) rather than recomputing against a stale blue set.
    // For the current block, compute its own anticone against its selected parent.
    auto it = mapDAGData.find(hashBlock);
    if (it == mapDAGData.end())
        return 0;

    uint256 hashSelectedParent = GetSelectedParent(hashBlock);
    if (hashSelectedParent == 0)
        return 0;

    // Compute this block's anticone against its own selected parent's blue set
    std::set<uint256> blueSet = GetBlueSetCached(hashSelectedParent);
    int nAnticone = AnticoneSize(hashBlock, blueSet);

    // Clamp seed to ceiling to prevent single outlier from dominating EMA
    int nSeedAnticone = std::min(nAnticone, DAGKNIGHT_K_CEILING);

    // Sample stored nInferredK from ancestors (deterministic — values were
    // computed at coloring time before any pruning occurred)
    // Use EMA smoothing for stable k estimation
    int nEMAk = nSeedAnticone * 256; // fixed-point (*256), clamped seed
    uint256 hashWalk = hashSelectedParent;
    int nSamples = 0;

    while (nSamples < DAGKNIGHT_K_SAMPLE_DEPTH && hashWalk != 0)
    {
        auto wit = mapDAGData.find(hashWalk);
        if (wit == mapDAGData.end())
            break;

        if (wit->second.nInferredK >= 0)
        {
            // EMA: k_new = alpha * sample + (1 - alpha) * k_old
            nEMAk = (DAGKNIGHT_K_EMA_ALPHA * wit->second.nInferredK * 256
                     + (256 - DAGKNIGHT_K_EMA_ALPHA) * nEMAk) / 256;

        }

        hashWalk = GetSelectedParent(hashWalk);
        nSamples++;
    }

    // Use EMA estimate only (not max — max is dominated by outliers, allowing k inflation)
    int nResult = (nEMAk + 128) / 256; // round from fixed-point

    // Apply floor and ceiling
    if (nResult < DAGKNIGHT_K_FLOOR)
        nResult = DAGKNIGHT_K_FLOOR;
    if (nResult > DAGKNIGHT_K_CEILING)
        nResult = DAGKNIGHT_K_CEILING;

    return nResult;
}

int CDAGManager::SupportingMass(const uint256& hashA, const uint256& hashB) const
{
    // supporting_mass(A>B) = |{C : A in past(C) AND B not in past(C)}|
    // Bounded by both step count and visited set size to prevent DoS
    static const int SM_MAX_VISITED = 2048;
    int nBound = DAGKNIGHT_MAX_ANTICONE_WINDOW * 2;

    std::set<uint256> futureA;
    std::set<uint256> futureB;

    // BFS forward from A through children
    std::queue<uint256> qA;
    qA.push(hashA);
    int nSteps = 0;
    while (!qA.empty() && nSteps < nBound && (int)futureA.size() < SM_MAX_VISITED)
    {
        uint256 h = qA.front();
        qA.pop();
        if (!futureA.insert(h).second)
            continue;
        auto it = mapDAGData.find(h);
        if (it != mapDAGData.end())
        {
            for (const uint256& hc : it->second.vDAGChildren)
            {
                if (!futureA.count(hc) && (int)qA.size() < SM_MAX_VISITED)
                    qA.push(hc);
            }
        }
        nSteps++;
    }

    // BFS forward from B through children
    std::queue<uint256> qB;
    qB.push(hashB);
    nSteps = 0;
    while (!qB.empty() && nSteps < nBound && (int)futureB.size() < SM_MAX_VISITED)
    {
        uint256 h = qB.front();
        qB.pop();
        if (!futureB.insert(h).second)
            continue;
        auto it = mapDAGData.find(h);
        if (it != mapDAGData.end())
        {
            for (const uint256& hc : it->second.vDAGChildren)
            {
                if (!futureB.count(hc) && (int)qB.size() < SM_MAX_VISITED)
                    qB.push(hc);
            }
        }
        nSteps++;
    }

    // Count blocks in future(A) not in future(B)
    int nSupport = 0;
    for (const uint256& h : futureA)
    {
        if (h != hashA && !futureB.count(h))
            nSupport++;
    }

    return nSupport;
}

int CDAGManager::CompareBlockOrder(const uint256& hashA, const uint256& hashB,
                                    int& nConfidence) const
{
    LOCK(cs_dag);

    if (hashA == hashB)
    {
        nConfidence = 0;
        return 0;
    }

    // Check topological ordering: is A ancestor of B or vice versa?
    std::set<uint256> pastB = GetPastSet(hashB, DAGKNIGHT_MAX_ANTICONE_WINDOW);
    if (pastB.count(hashA))
    {
        nConfidence = (int)pastB.size();
        return -1; // A precedes B
    }

    std::set<uint256> pastA = GetPastSet(hashA, DAGKNIGHT_MAX_ANTICONE_WINDOW);
    if (pastA.count(hashB))
    {
        nConfidence = (int)pastA.size();
        return 1; // B precedes A
    }

    // Blocks in each other's anticone — use supporting mass
    int nSupportAB = SupportingMass(hashA, hashB);
    int nSupportBA = SupportingMass(hashB, hashA);

    nConfidence = abs(nSupportAB - nSupportBA);

    if (nSupportAB > nSupportBA + DAGKNIGHT_MIN_CONFIDENCE)
        return -1; // A precedes B
    if (nSupportBA > nSupportAB + DAGKNIGHT_MIN_CONFIDENCE)
        return 1;  // B precedes A

    // Tie: deterministic hash comparison
    nConfidence = 0;
    return (hashA < hashB) ? -1 : 1;
}

void CDAGManager::ColorBlockDAGKnight(CBlockIndex* pindex)
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
        data.fBlue = true;
        data.nDAGScore = pindex->GetBlockTrust();
        data.nInferredK = 0;
        return;
    }

    // Find selected parent (highest DAG score)
    uint256 hashSelectedParent;
    uint256 nBestParentScore = 0;

    for (const uint256& hashParent : vParents)
    {
        uint256 nParentScore = 0;
        auto pit = mapDAGData.find(hashParent);
        if (pit != mapDAGData.end())
            nParentScore = pit->second.nDAGScore;
        else
        {
            std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashParent);
            if (mi != mapBlockIndex.end())
                nParentScore = mi->second->nChainTrust;
        }

        if (nParentScore > nBestParentScore ||
            (nParentScore == nBestParentScore && (hashSelectedParent == 0 || hashParent < hashSelectedParent)))
        {
            nBestParentScore = nParentScore;
            hashSelectedParent = hashParent;
        }
    }

    if (hashSelectedParent == 0)
    {
        if (pindex->pprev)
            data.nDAGScore = pindex->pprev->nChainTrust + pindex->GetBlockTrust();
        else
            data.nDAGScore = pindex->GetBlockTrust();
        data.fBlue = true;
        data.nInferredK = 0;
        return;
    }

    // DAGKNIGHT: Infer local k from DAG structure
    int nLocalK = InferLocalK(hash);
    data.nInferredK = nLocalK;

    // Inherit blue set from selected parent
    std::set<uint256> blueSet = GetBlueSet(hashSelectedParent);
    std::set<uint256> selectedParentBlue = blueSet;

    // Merge parents' blue blocks using adaptive k
    for (const uint256& hashParent : vParents)
    {
        if (hashParent == hashSelectedParent)
            continue;

        auto pit = mapDAGData.find(hashParent);
        if (pit == mapDAGData.end())
            continue;

        std::set<uint256> mergeBlue = GetBlueSet(hashParent);

        for (const uint256& hashCandidate : mergeBlue)
        {
            if (blueSet.count(hashCandidate))
                continue;

            // DAGKNIGHT: Use inferred k instead of fixed GHOSTDAG_K
            int nAnticone = AnticoneSize(hashCandidate, blueSet);
            if (nAnticone <= nLocalK)
            {
                blueSet.insert(hashCandidate);
                auto cit = mapDAGData.find(hashCandidate);
                if (cit != mapDAGData.end())
                    cit->second.fBlue = true;
            }
            else
            {
                auto cit = mapDAGData.find(hashCandidate);
                if (cit != mapDAGData.end())
                    cit->second.fBlue = false;
            }
        }
    }

    // This block is always blue
    data.fBlue = true;
    blueSet.insert(hash);

    // Compute score: selected parent score + this block trust + newly-blue merge blocks
    uint256 nScore = nBestParentScore + pindex->GetBlockTrust();
    for (const uint256& hashBlue : blueSet)
    {
        if (hashBlue == hash)
            continue;
        if (selectedParentBlue.count(hashBlue))
            continue;
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlue);
        if (mi != mapBlockIndex.end())
            nScore = nScore + mi->second->GetBlockTrust();
    }
    data.nDAGScore = nScore;
}

int CDAGManager::GetOrderConfidence(const uint256& hashBlock) const
{
    LOCK(cs_dag);

    auto it = mapDAGData.find(hashBlock);
    if (it == mapDAGData.end())
        return 0;

    // Count blue descendants as confidence measure
    int nConfidence = 0;
    std::set<uint256> visited;
    std::queue<uint256> queue;
    queue.push(hashBlock);
    int nDepth = 0;

    while (!queue.empty() && nDepth < DAGKNIGHT_MAX_ANTICONE_WINDOW)
    {
        uint256 h = queue.front();
        queue.pop();
        if (!visited.insert(h).second)
            continue;

        auto dit = mapDAGData.find(h);
        if (dit == mapDAGData.end())
            continue;

        if (dit->second.fBlue && h != hashBlock)
            nConfidence++;

        for (const uint256& hc : dit->second.vDAGChildren)
        {
            if (!visited.count(hc))
                queue.push(hc);
        }
        nDepth++;
    }

    return nConfidence;
}
