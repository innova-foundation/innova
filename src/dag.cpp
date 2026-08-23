// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "dag.h"
#include "main.h"
#include "txdb.h"
#include "finality.h"
#include "privacy_vnext_ffi.h"
#include "util.h"
#include "blockprofile.h"

#include <algorithm>
#include <queue>

CDAGManager g_dagManager;

bool fDAGKnightUnoptimizedOrdering = false;

uint256 CEpochState::GetDigest() const
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << (nSerVersion >= EPOCHSTATE_SER_VERSION_V4
               ? std::string("Innova/IDAG/EpochState/v4")
               : std::string("Innova/IDAG/EpochState/v3"));
    ss << nEpoch << hashBoundaryBlock << nHeightStart << nHeightEnd << vBlockHashes;
    ss << hashCurveRoot << hashNullifierRoot << hashVoteSetRoot << hashFinalityCertificate;
    ss << nTotalTrust << nBlockCount << nTxCount << nFinalityTier;
    ss << nConsecutiveHardCount << fFinalized << nFinalizedHeightAsOf;
    if (nSerVersion >= EPOCHSTATE_SER_VERSION_V4)
    {
        ss << vchVNextRoot << nVNextTreeSize << vchVNextNullifierState;
        ss << hashVNextNullifierRoot << nVNextNullifierCount;
        ss << vVNextEpochNullifiers;
        ss << vchVNextParameterDigest << hashVNextFinalizedAnchor;
        ss << nVNextFinalizedHeight << vVNextActiveBlockTxCounts;
        ss << vVNextActiveTxIds << hashVNextActiveTxSet;
        if (nSerVersion >= EPOCHSTATE_SER_VERSION_V5)
            ss << nVNextPoolBalance;
        // Covered from V6 so two nodes that drew different committees disagree here,
        // at the epoch record, instead of silently accepting each other's blocks and
        // splitting later on a certificate. V5 records hash exactly as before.
        if (nSerVersion >= EPOCHSTATE_SER_VERSION_V6)
            ss << vFinalityCommittee << nFinalityCommitteeM;
    }
    return ss.GetHash();
}


// ---------------------------------------------------------------------------
// DAG Parent Commitment: coinbase OP_RETURN encoding
// ---------------------------------------------------------------------------

// A commitment payload is bounded by the count byte: at most 255 hashes.
static const uint64_t DAG_PARENT_MAX_PAYLOAD = 5 + (uint64_t)255 * 32;

// Read the one data push after OP_RETURN without GetOp's 520-byte element cap, which a
// 32-parent commitment (1,029 bytes) exceeds. Otherwise acceptance matches GetOp.
static bool ReadBoundedDataPush(const CScript& script,
                                CScript::const_iterator& pc,
                                std::vector<unsigned char>& vchData)
{
    vchData.clear();
    if (pc >= script.end())
        return false;

    const unsigned int opcode = *pc++;
    if (opcode > OP_PUSHDATA4)
        return false;

    uint64_t nSize = 0;
    if (opcode < OP_PUSHDATA1)
    {
        nSize = opcode;
    }
    else if (opcode == OP_PUSHDATA1)
    {
        if (script.end() - pc < 1)
            return false;
        nSize = *pc++;
    }
    else if (opcode == OP_PUSHDATA2)
    {
        if (script.end() - pc < 2)
            return false;
        unsigned int nRead = 0;
        memcpy(&nRead, &pc[0], 2);
        nSize = nRead;
        pc += 2;
    }
    else
    {
        if (script.end() - pc < 4)
            return false;
        unsigned int nRead = 0;
        memcpy(&nRead, &pc[0], 4);
        nSize = nRead;
        pc += 4;
    }

    if (nSize > DAG_PARENT_MAX_PAYLOAD)
        return false;
    if ((uint64_t)(script.end() - pc) < nSize)
        return false;

    vchData.assign(pc, pc + (size_t)nSize);
    pc += (size_t)nSize;
    return true;
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

    if (!ReadBoundedDataPush(scriptCoinbase, pc, vchData))
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

DAGParentDecodeStatus DecodeCanonicalDAGParentScript(
    const CScript& script, std::vector<uint256>& vParents,
    std::string& strError)
{
    vParents.clear();
    strError.clear();

    if (script.size() < 2 || script[0] != OP_RETURN)
        return DAG_PARENT_NOT_FOUND;

    // 32 hashes (1,029 payload bytes) exceed the 520-byte element policy, so parse the push
    // directly while keeping the canonical-encoding checks below.
    size_t nOffset = 1;
    const unsigned char opcode = script[nOffset++];
    uint64_t nDataSize = 0;
    if (opcode <= 75)
        nDataSize = opcode;
    else if (opcode == OP_PUSHDATA1)
    {
        if (nOffset + 1 > script.size())
            return DAG_PARENT_NOT_FOUND;
        nDataSize = script[nOffset++];
    }
    else if (opcode == OP_PUSHDATA2)
    {
        if (nOffset + 2 > script.size())
            return DAG_PARENT_NOT_FOUND;
        nDataSize = (uint64_t)script[nOffset] |
                    ((uint64_t)script[nOffset + 1] << 8);
        nOffset += 2;
    }
    else
        return DAG_PARENT_NOT_FOUND;
    // The count byte bounds malformed candidates to at most 255 hashes. Read
    // that bounded shape so max-plus-one is classified as malformed rather
    // than silently treated as an unrelated OP_RETURN.
    if (nDataSize > DAG_PARENT_MAX_PAYLOAD ||
        nOffset + nDataSize > script.size())
        return DAG_PARENT_NOT_FOUND;

    std::vector<unsigned char> vchData(
        script.begin() + nOffset,
        script.begin() + nOffset + (size_t)nDataSize);
    nOffset += (size_t)nDataSize;
    if (vchData.size() < 4 ||
        memcmp(vchData.data(), DAG_PARENT_TAG, 4) != 0)
        return DAG_PARENT_NOT_FOUND;

    if (nOffset != script.size())
    {
        strError = "IDAG commitment has trailing script operations";
        return DAG_PARENT_MALFORMED;
    }
    if (vchData.size() < 5)
    {
        strError = "IDAG commitment is missing its parent count";
        return DAG_PARENT_MALFORMED;
    }

    const unsigned int nCount = vchData[4];
    if (nCount == 0 || nCount > MAX_DAG_PARENTS)
    {
        strError = strprintf("IDAG parent count %u is outside 1..%d",
                             nCount, MAX_DAG_PARENTS);
        return DAG_PARENT_MALFORMED;
    }
    const size_t nExpected = 5 + (size_t)nCount * 32;
    if (vchData.size() != nExpected)
    {
        strError = strprintf("IDAG payload length %u does not match count %u",
                             (unsigned int)vchData.size(), nCount);
        return DAG_PARENT_MALFORMED;
    }

    std::set<uint256> setParents;
    for (unsigned int i = 0; i < nCount; ++i)
    {
        uint256 hash;
        memcpy(hash.begin(), &vchData[5 + i * 32], 32);
        if (hash == 0)
        {
            strError = strprintf("IDAG parent[%u] is zero", i);
            vParents.clear();
            return DAG_PARENT_MALFORMED;
        }
        if (!setParents.insert(hash).second)
        {
            strError = strprintf("IDAG parent[%u] is duplicated", i);
            vParents.clear();
            return DAG_PARENT_MALFORMED;
        }
        vParents.push_back(hash);
    }

    if (BuildDAGParentScript(vParents) != script)
    {
        strError = "IDAG commitment uses a non-canonical push encoding";
        vParents.clear();
        return DAG_PARENT_MALFORMED;
    }
    return DAG_PARENT_VALID;
}

bool ExtractCanonicalDAGParentCommitment(
    const std::vector<CScript>& vScripts,
    std::vector<uint256>& vParents,
    std::string& strError)
{
    vParents.clear();
    strError.clear();
    bool fFound = false;
    for (std::vector<CScript>::const_iterator it = vScripts.begin();
         it != vScripts.end(); ++it)
    {
        std::vector<uint256> vDecoded;
        std::string strDecodeError;
        const DAGParentDecodeStatus status =
            DecodeCanonicalDAGParentScript(*it, vDecoded, strDecodeError);
        if (status == DAG_PARENT_MALFORMED)
        {
            strError = strDecodeError;
            return false;
        }
        if (status != DAG_PARENT_VALID)
            continue;
        if (fFound)
        {
            strError = "multiple canonical IDAG commitments";
            vParents.clear();
            return false;
        }
        fFound = true;
        vParents = vDecoded;
    }
    if (!fFound)
    {
        strError = "missing canonical IDAG commitment";
        return false;
    }
    return true;
}

bool ReadDAGParentCommitmentAtHeight(
    const std::vector<CScript>& vScripts,
    int nHeight,
    std::vector<uint256>& vParents,
    std::string& strError)
{
    vParents.clear();
    strError.clear();

    if (IsBoundaryAActiveAtHeight(nHeight))
        return ExtractCanonicalDAGParentCommitment(vScripts, vParents, strError);

    // Historical pre-A decoder intentionally retains its permissive shape for
    // byte-identical replay.
    for (std::vector<CScript>::const_iterator it = vScripts.begin();
         it != vScripts.end(); ++it)
    {
        vParents = ExtractDAGParents(*it);
        if (!vParents.empty())
            return true;
    }

    strError = "post-DAG-fork block missing DAG parent commitment";
    return false;
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

void CDAGManager::AddChildNoDuplicate(std::vector<uint256>& vChildren, const uint256& hashChild) const
{
    if (std::find(vChildren.begin(), vChildren.end(), hashChild) == vChildren.end())
        vChildren.push_back(hashChild);
}

// Blue sets depend on neighbour colours and must be dropped here; DAGKNIGHT anchor state
// does not (see InvalidateDAGKnightAnchorDescendants). Keep the two invalidations separate.
void CDAGManager::InvalidateBlueSetCacheForBlock(const uint256& hashBlock) const
{
    mapBlueSetCache.erase(hashBlock);
}

// Anchor state depends only on the anchor's past, so a change at hashRoot affects only descendants.
// Past the walk bound the whole cache is dropped.
void CDAGManager::InvalidateDAGKnightAnchorDescendants(const uint256& hashRoot) const
{
    if (fDAGKnightUnoptimizedOrdering)
    {
        mapDAGKnightAnchorCache.clear();
        mapDAGKnightPastCache.clear();
        return;
    }
    if (mapDAGKnightAnchorCache.empty() && mapDAGKnightPastCache.empty())
        return;

    std::vector<uint256> vStack(1, hashRoot);
    std::set<uint256> setSeen;
    while (!vStack.empty())
    {
        const uint256 hash = vStack.back();
        vStack.pop_back();
        if (!setSeen.insert(hash).second)
            continue;
        if (setSeen.size() > (size_t)DAGKNIGHT_ANCHOR_CACHE_MAX)
        {
            mapDAGKnightAnchorCache.clear();
            mapDAGKnightPastCache.clear();
            return;
        }
        mapDAGKnightAnchorCache.erase(hash);
        mapDAGKnightPastCache.erase(hash);
        std::map<uint256, CBlockDAGData>::const_iterator dit = mapDAGData.find(hash);
        if (dit == mapDAGData.end())
            continue;
        for (std::vector<uint256>::const_iterator it = dit->second.vDAGChildren.begin();
             it != dit->second.vDAGChildren.end(); ++it)
            vStack.push_back(*it);
    }
}

void CDAGManager::RebuildPendingChildIndex()
{
    mapPendingChildrenByParent.clear();
    for (auto& pair : mapDAGData)
        pair.second.vDAGChildren.clear();

    for (auto& pair : mapDAGData)
    {
        for (const uint256& hashParent : pair.second.vDAGParents)
        {
            auto pit = mapDAGData.find(hashParent);
            if (pit != mapDAGData.end())
                AddChildNoDuplicate(pit->second.vDAGChildren, pair.first);
            else
                mapPendingChildrenByParent[hashParent].insert(pair.first);
        }
    }

    setDAGTips.clear();
    for (const auto& pair : mapDAGData)
    {
        if (pair.second.vDAGChildren.empty())
            setDAGTips.insert(pair.first);
    }
}

bool CDAGManager::InitBlockDAGData(CBlockIndex* pindex, const std::vector<uint256>& vParents)
{
    LOCK(cs_dag);

    if (!pindex || !pindex->phashBlock)
        return false;
    if (pindex->nHeight >= FORK_HEIGHT_DAG && pindex->IsProofOfStake())
        return false;

    uint256 hash = pindex->GetBlockHash();

    CBlockDAGData& data = mapDAGData[hash];
    data.vDAGParents = vParents;
    data.fBlue = true; // default, recolored by ColorBlock/ColorBlockDAGKnight
    data.nDAGScore = 0;
    data.nDAGOrder = -1;
    data.nInferredK = -1;

    InvalidateBlueSetCacheForBlock(hash);

    // Register as child of each parent
    for (const uint256& hashParent : vParents)
    {
        auto pit = mapDAGData.find(hashParent);
        if (pit != mapDAGData.end())
        {
            AddChildNoDuplicate(pit->second.vDAGChildren, hash);
            InvalidateBlueSetCacheForBlock(hashParent);
        }
        else
        {
            mapPendingChildrenByParent[hashParent].insert(hash);
        }
    }

    // Attach children that arrived while this parent was missing; their anchor view is stale.
    auto pendingIt = mapPendingChildrenByParent.find(hash);
    if (pendingIt != mapPendingChildrenByParent.end())
    {
        for (const uint256& hashChild : pendingIt->second)
        {
            AddChildNoDuplicate(data.vDAGChildren, hashChild);
            InvalidateBlueSetCacheForBlock(hashChild);
        }
        mapPendingChildrenByParent.erase(pendingIt);
        BlockProfileCount("dagk_late_parent", 1);
    }

    // This block's own state (a re-added block may have one) and anything downstream of it.
    InvalidateDAGKnightAnchorDescendants(hash);

    // Update DAG tips: this block is a tip only if no earlier child referenced it.
    if (data.vDAGChildren.empty())
        setDAGTips.insert(hash);
    else
        setDAGTips.erase(hash);
    for (const uint256& hashParent : vParents)
        setDAGTips.erase(hashParent);

    static int64_t nLastRebuildTime = 0;
    if ((int)setDAGTips.size() > 64)
    {
        int64_t nNow = GetTimeMillis();
        if (nNow - nLastRebuildTime > 60000)
        {
            nLastRebuildTime = nNow;
            printf("InitBlockDAGData: tip flood detected (%d tips), triggering incremental rebuild\n",
                   (int)setDAGTips.size());
            RebuildDAGOrderIncremental(nPrunedBelowHeight);
        }
    }

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
        // An invalidated tip stays in the set; skip it or the miner keeps building on it.
        if (pindex->IsInvalid())
            continue;
        if (pindex->nHeight >= FORK_HEIGHT_DAG && pindex->IsProofOfStake())
            continue;

        bool fBetter = false;
        if (!pBest)
            fBetter = true;
        else if (it->second.nDAGScore > nBestScore)
            fBetter = true;
        else if (it->second.nDAGScore == nBestScore)
        {
            if (pindex->nHeight >= FORK_HEIGHT_EPOCH_STATE_V3 &&
                pBest->nHeight >= FORK_HEIGHT_EPOCH_STATE_V3)
            {
                if (pindex->nHeight != pBest->nHeight)
                    fBetter = pindex->nHeight > pBest->nHeight;
                else
                    fBetter = hashTip < pBest->GetBlockHash();
            }
            else if (pindex->nChainTrust != pBest->nChainTrust)
                fBetter = pindex->nChainTrust > pBest->nChainTrust;
            else if (pindex->nHeight != pBest->nHeight)
                fBetter = pindex->nHeight > pBest->nHeight;
            else
                fBetter = hashTip < pBest->GetBlockHash();
        }

        if (fBetter)
        {
            nBestScore = it->second.nDAGScore;
            pBest = pindex;
        }
    }

    if (!pBest && pindexBest)
    {
        pBest = pindexBest;
        while (pBest && pBest->nHeight >= FORK_HEIGHT_DAG && pBest->IsProofOfStake())
            pBest = pBest->pprev;
        if (!pBest)
            pBest = pindexBest;
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
    if (pindex->nHeight >= FORK_HEIGHT_DAG && pindex->IsProofOfStake())
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
            if (mi != mapBlockIndex.end() &&
                !(mi->second->nHeight >= FORK_HEIGHT_DAG && mi->second->IsProofOfStake()))
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
            if (mi->second->nHeight >= FORK_HEIGHT_DAG && mi->second->IsProofOfStake())
                continue;
            nScore = nScore + mi->second->GetBlockTrust();
        }
    }
    data.nDAGScore = nScore;
}


// ---------------------------------------------------------------------------
// CDAGManager: DAG Linear Ordering
// ---------------------------------------------------------------------------

std::vector<uint256> CDAGManager::GetDAGLinearOrder(const uint256& hashTip, int nMaxBlocks,
                                                    bool fForceSchemaV3Order) const
{
    LOCK(cs_dag);

    std::vector<uint256> vOrder;
    std::set<uint256> visited;

    bool fSchemaV3Order = fForceSchemaV3Order;
    std::map<uint256, CBlockIndex*>::const_iterator miTip = mapBlockIndex.find(hashTip);
    if (miTip != mapBlockIndex.end() && miTip->second &&
        miTip->second->nHeight >= FORK_HEIGHT_EPOCH_STATE_V3)
        fSchemaV3Order = true;

    if (fSchemaV3Order)
    {
        std::vector<uint256> vSelectedChain;
        std::set<uint256> setChain;
        uint256 hashCurrent = hashTip;
        int nRemaining = (int)mapDAGData.size() + 1;
        if (nMaxBlocks > 0 && nMaxBlocks < nRemaining)
            nRemaining = nMaxBlocks;

        while (hashCurrent != 0 && nRemaining-- > 0 &&
               setChain.insert(hashCurrent).second)
        {
            vSelectedChain.push_back(hashCurrent);
            std::map<uint256, CBlockDAGData>::const_iterator dit =
                mapDAGData.find(hashCurrent);
            if (dit == mapDAGData.end())
                break;
            hashCurrent = GetDAGKnightSelectedParent(dit->second.vDAGParents);
        }
        std::reverse(vSelectedChain.begin(), vSelectedChain.end());

        for (std::vector<uint256>::const_iterator cit = vSelectedChain.begin();
             cit != vSelectedChain.end(); ++cit)
        {
            if (mapDAGData.count(*cit) == 0)
            {
                if (visited.insert(*cit).second)
                    vOrder.push_back(*cit);
                continue;
            }
            if (!EnsureDAGKnightAnchorState(*cit))
                return std::vector<uint256>();
            std::map<uint256, CDAGKnightAnchorState>::const_iterator sit =
                mapDAGKnightAnchorCache.find(*cit);
            if (sit == mapDAGKnightAnchorCache.end())
                return std::vector<uint256>();
            for (std::vector<std::pair<uint256, bool> >::const_iterator oit =
                     sit->second.vOrderDelta.begin();
                 oit != sit->second.vOrderDelta.end(); ++oit)
            {
                if (visited.insert(oit->first).second)
                    vOrder.push_back(oit->first);
            }
        }
        return vOrder;
    }

    // V3 epoch ordering follows the committed primary-parent chain and treats
    // every other parent as a merge. This removes mutable live blue-score state
    // from the anchor-derived order; pre-V3 callers retain historical behavior.
    auto getOrderParent = [&](const uint256& hashBlock) -> uint256 {
        std::map<uint256, CBlockDAGData>::const_iterator it = mapDAGData.find(hashBlock);
        if (fSchemaV3Order && it != mapDAGData.end() && !it->second.vDAGParents.empty())
            return it->second.vDAGParents[0];
        return GetSelectedParent(hashBlock);
    };

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
        hashCurrent = getOrderParent(hashCurrent);
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
        const uint256 hashOrderParent = getOrderParent(hashChainBlock);
        for (const uint256& hashParent : it->second.vDAGParents)
        {
            if (hashParent != hashOrderParent)
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

        if (fSchemaV3Order)
        {
            // Parent heights are below child heights, so (height, hash) is a deterministic topological order.
            vBlueInsert.insert(vBlueInsert.end(), vRedInsert.begin(), vRedInsert.end());
            vRedInsert.clear();
            std::sort(vBlueInsert.begin(), vBlueInsert.end(),
                      [](const uint256& a, const uint256& b) {
                          std::map<uint256, CBlockIndex*>::const_iterator ia = mapBlockIndex.find(a);
                          std::map<uint256, CBlockIndex*>::const_iterator ib = mapBlockIndex.find(b);
                          const int ha = (ia != mapBlockIndex.end() && ia->second)
                                           ? ia->second->nHeight : -1;
                          const int hb = (ib != mapBlockIndex.end() && ib->second)
                                           ? ib->second->nHeight : -1;
                          return ha != hb ? ha < hb : a < b;
                      });
        }
        else
        {
            // Legacy order: blue first, then red, hash tie-break within color.
            std::sort(vBlueInsert.begin(), vBlueInsert.end());
            std::sort(vRedInsert.begin(), vRedInsert.end());
        }

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
    if (pindex->nHeight >= FORK_HEIGHT_DAG && pindex->IsProofOfStake())
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
            if (mi != mapBlockIndex.end() &&
                !(mi->second->nHeight >= FORK_HEIGHT_DAG && mi->second->IsProofOfStake()))
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

    // A known child of a parent counts only if this block reaches it through its committed parents,
    // otherwise activation depends on arrival order. Applies from FORK_HEIGHT_DAG.
    bool fRequireReachableSibling = false;
    std::set<uint256> setReachablePast;
    std::map<uint256, CBlockIndex*>::const_iterator miBlock =
        mapBlockIndex.find(hashBlock);
    if (miBlock != mapBlockIndex.end() && miBlock->second &&
        miBlock->second->nHeight >= FORK_HEIGHT_DAG)
    {
        fRequireReachableSibling = true;
        setReachablePast = GetPastSet(hashBlock, DAG_MERGE_DEPTH);
    }

    // Siblings = other children of our parents
    for (const uint256& hashParent : it->second.vDAGParents)
    {
        auto pit = mapDAGData.find(hashParent);
        if (pit == mapDAGData.end())
            continue;

        for (const uint256& hashChild : pit->second.vDAGChildren)
        {
            if (hashChild != hashBlock &&
                (!fRequireReachableSibling || setReachablePast.count(hashChild)))
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

    // Collect before the links are torn down: the descendants are found through them.
    BlockProfileCount("dagk_remove_block", 1);
    InvalidateDAGKnightAnchorDescendants(hashBlock);

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
        else
        {
            auto pendingIt = mapPendingChildrenByParent.find(hashParent);
            if (pendingIt != mapPendingChildrenByParent.end())
            {
                pendingIt->second.erase(hashBlock);
                if (pendingIt->second.empty())
                    mapPendingChildrenByParent.erase(pendingIt);
            }
        }
    }

    for (const uint256& hashChild : it->second.vDAGChildren)
    {
        mapPendingChildrenByParent[hashBlock].insert(hashChild);
        InvalidateBlueSetCacheForBlock(hashChild);
    }

    // Remove from tips and data
    setDAGTips.erase(hashBlock);
    mapDAGData.erase(it);
    InvalidateBlueSetCacheForBlock(hashBlock);
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
    mapPendingChildrenByParent.clear();

    // Load DAG links using efficient LevelDB prefix iteration
    std::map<uint256, CBlockDAGData> mapLoaded;
    if (!txdb.IterateDAGLinks(mapLoaded))
        return false;

    // V3 must never start with a partial DAG: cross-check each retained V3 index against its vertex
    // and each vertex against the block-index parent chain. Records below the prune boundary are absent.
    int nCleanHeight = 0;
    if (!txdb.ReadDAGCleanHeight(nCleanHeight) || nCleanHeight < 0)
        nCleanHeight = 0;

    for (std::map<uint256, CBlockDAGData>::const_iterator it = mapLoaded.begin();
         it != mapLoaded.end(); ++it)
    {
        std::map<uint256, CBlockIndex*>::const_iterator mi =
            mapBlockIndex.find(it->first);
        if (mi == mapBlockIndex.end() || !mi->second || !mi->second->phashBlock)
        {
            printf("LoadDAGLinks: FATAL persisted DAG vertex %s has no block index; "
                   "-reindex/resync required\n",
                   it->first.ToString().substr(0,20).c_str());
            return false;
        }

        const CBlockIndex* pindex = mi->second;
        if (pindex->nHeight < FORK_HEIGHT_DAG || pindex->IsProofOfStake())
        {
            printf("LoadDAGLinks: FATAL DAG vertex %s has invalid height/type; "
                   "-reindex/resync required\n",
                   it->first.ToString().substr(0,20).c_str());
            return false;
        }

        if (pindex->nHeight >= FORK_HEIGHT_EPOCH_STATE_V3)
        {
            const std::vector<uint256>& vParents = it->second.vDAGParents;
            if (vParents.empty() || vParents.size() > MAX_DAG_PARENTS ||
                !pindex->pprev || !pindex->pprev->phashBlock ||
                vParents[0] != pindex->pprev->GetBlockHash())
            {
                printf("LoadDAGLinks: FATAL V3 DAG vertex %s has an invalid primary-parent "
                       "binding; -reindex/resync required\n",
                       it->first.ToString().substr(0,20).c_str());
                return false;
            }
            for (size_t i = 0; i < vParents.size(); ++i)
            {
                std::map<uint256, CBlockIndex*>::const_iterator pi =
                    mapBlockIndex.find(vParents[i]);
                if (pi == mapBlockIndex.end() || !pi->second ||
                    pi->second->nHeight >= pindex->nHeight ||
                    (pi->second->nHeight >= FORK_HEIGHT_DAG &&
                     pi->second->IsProofOfStake()) ||
                    (i > 0 && pindex->pprev->nHeight - pi->second->nHeight >
                                  DAG_MERGE_DEPTH))
                {
                    printf("LoadDAGLinks: FATAL V3 DAG vertex %s references invalid/missing "
                           "parent %s; -reindex/resync required\n",
                           it->first.ToString().substr(0,20).c_str(),
                           vParents[i].ToString().substr(0,20).c_str());
                    return false;
                }
            }
        }
    }

    for (std::map<uint256, CBlockIndex*>::const_iterator it = mapBlockIndex.begin();
         it != mapBlockIndex.end(); ++it)
    {
        const CBlockIndex* pindex = it->second;
        if (!pindex || pindex->nHeight < FORK_HEIGHT_EPOCH_STATE_V3 ||
            pindex->nHeight < nCleanHeight || pindex->IsProofOfStake() ||
            pindex->IsInvalid())
            continue;
        if (!mapLoaded.count(it->first))
        {
            printf("LoadDAGLinks: FATAL retained V3 block index %s at height %d has no "
                   "DAG vertex; -reindex/resync required\n",
                   it->first.ToString().substr(0,20).c_str(), pindex->nHeight);
            return false;
        }
    }
    mapDAGData.swap(mapLoaded);

    RebuildPendingChildIndex();

    if (!mapDAGData.empty())
        printf("LoadDAGLinks: loaded %d DAG entries, %d tips, %d pending parent links\n",
               (int)mapDAGData.size(), (int)setDAGTips.size(), (int)mapPendingChildrenByParent.size());

    return true;
}

bool CDAGManager::LoadEpochStates(CTxDB& txdb)
{
    LOCK(cs_dag);

    std::map<int, CEpochState> mapStates;
    if (!txdb.IterateEpochStates(mapStates))
        return false;

    std::map<int, CCurveTree> mapTrees;
    if (!txdb.IterateCurveTreeEpochs(mapTrees))
        return false;

    int nSchema = 0;
    if (!txdb.ReadEpochStateSchema(nSchema) && txdb.HasEpochStateSchema())
    {
        printf("LoadEpochStates: FATAL epoch-state schema marker is corrupt; "
               "-reindex/resync required\n");
        return false;
    }

    // Older V2 prefix records stay byte-identical, so V3-only invariants apply from the migration
    // boundary; the generation-independent checks below apply to all records.
    const int nFirstStrictV3Epoch =
        GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3) - 1;

    // Every state is a consensus anchor and must have exactly one same-epoch curve snapshot.
    // Validate temporary maps completely before replacing the live cache.
    if (mapStates.size() != mapTrees.size())
    {
        printf("LoadEpochStates: FATAL state/tree count mismatch (%d states, %d snapshots); "
               "-reindex/resync required\n", (int)mapStates.size(), (int)mapTrees.size());
        return false;
    }
    if (nSchema >= EPOCHSTATE_SCHEMA_V4)
    {
        // The linked decoder must answer with a well-formed bootstrap seed, or this
        // node cannot judge a payload below the chain's first IV5 epoch. Nothing here
        // inspects persisted state: that is the chain's, and is judged as its own.
        PrivacyVNextEpochSeed expectedVNextSeed;
        std::string seedError;
        if (!LoadPrivacyVNextEpochSeed(expectedVNextSeed, seedError))
        {
            printf("LoadEpochStates: FATAL IV5 epoch seed unavailable: %s\n",
                   seedError.c_str());
            return false;
        }
        if (expectedVNextSeed.vchParameterDigest.size() !=
            EPOCHSTATE_VNEXT_DIGEST_SIZE)
        {
            printf("LoadEpochStates: FATAL IV5 epoch seed parameter digest is "
                   "malformed\n");
            return false;
        }
    }
    for (std::map<int, CEpochState>::const_iterator it = mapStates.begin();
         it != mapStates.end(); ++it)
    {
        const int nEpoch = it->first;
        const CEpochState& state = it->second;
        const bool fStrictV3Record =
            nSchema >= EPOCHSTATE_SCHEMA_V3 &&
            nEpoch >= nFirstStrictV3Epoch;
        std::map<int, CCurveTree>::const_iterator itTree = mapTrees.find(nEpoch);
        if (itTree == mapTrees.end())
        {
            printf("LoadEpochStates: FATAL missing curve snapshot for epoch %d; "
                   "-reindex/resync required\n", nEpoch);
            return false;
        }
        if (state.nEpoch != nEpoch || state.hashBoundaryBlock == 0)
        {
            printf("LoadEpochStates: FATAL invalid epoch/key or null boundary at epoch %d; "
                   "-reindex/resync required\n", nEpoch);
            return false;
        }
        const int nExpectedStart = GetEpochBoundaryHeight(nEpoch, state.nHeightEnd);
        const int nExpectedEnd = GetEpochBoundaryHeight(nEpoch + 1, state.nHeightEnd) - 1;
        if (state.nHeightStart != nExpectedStart || state.nHeightEnd != nExpectedEnd ||
            state.nHeightEnd < state.nHeightStart)
        {
            printf("LoadEpochStates: FATAL invalid height range %d-%d for epoch %d "
                   "(expected %d-%d); -reindex/resync required\n", state.nHeightStart,
                   state.nHeightEnd, nEpoch, nExpectedStart, nExpectedEnd);
            return false;
        }
        if (nSchema >= EPOCHSTATE_SCHEMA_V2 && state.nSerVersion == 0)
        {
            printf("LoadEpochStates: FATAL legacy record at epoch %d under schema %d; "
                   "-reindex/resync required\n", nEpoch, nSchema);
            return false;
        }
        if (fStrictV3Record &&
            (state.nBlockCount < 0 || (size_t)state.nBlockCount != state.vBlockHashes.size()))
        {
            printf("LoadEpochStates: FATAL V3 block-count mismatch at epoch %d; "
                   "-reindex/resync required\n", nEpoch);
            return false;
        }
        if (fStrictV3Record &&
            state.nHeightEnd >= FORK_HEIGHT_DAG &&
            !mapDAGData.count(state.hashBoundaryBlock))
        {
            printf("LoadEpochStates: FATAL V3 boundary DAG vertex is missing at epoch %d; "
                   "-reindex/resync required\n", nEpoch);
            return false;
        }

        CCurveTree checkedTree = itTree->second;
        if (checkedTree.nLeafCount == 0)
        {
            if (state.hashCurveRoot != 0)
            {
                printf("LoadEpochStates: FATAL empty snapshot/root mismatch at epoch %d; "
                       "-reindex/resync required\n", nEpoch);
                return false;
            }
        }
        else
        {
            if (checkedTree.vLevels.empty() ||
                checkedTree.vLevels[0].size() != checkedTree.nLeafCount ||
                !checkedTree.RebuildParentNodes() || checkedTree.GetRoot() != state.hashCurveRoot)
            {
                printf("LoadEpochStates: FATAL corrupt snapshot or curve-root mismatch at epoch %d; "
                       "-reindex/resync required\n", nEpoch);
                return false;
            }
        }

        const bool fExpectedVNext =
            IsBoundaryBActiveAtHeight(state.nHeightEnd);
        const bool fHaveVNext =
            state.nSerVersion >= EPOCHSTATE_SER_VERSION_V4;
        if (fExpectedVNext != fHaveVNext ||
            (fHaveVNext && nSchema < EPOCHSTATE_SCHEMA_V4))
        {
            printf("LoadEpochStates: FATAL IV5 generation mismatch at epoch %d "
                   "(expected=%d record=%d schema=%d); -reindex/resync required\n",
                   nEpoch, fExpectedVNext, fHaveVNext, nSchema);
            return false;
        }
        if (fHaveVNext)
        {
            std::vector<unsigned char> checkedVNextRoot;
            uint64_t checkedVNextSize = 0;
            std::string treeError;
            if (state.vchVNextTreeState.size() !=
                    EPOCHSTATE_VNEXT_TREE_STATE_SIZE ||
                state.vchVNextNullifierState.size() !=
                    EPOCHSTATE_VNEXT_NULLIFIER_STATE_SIZE ||
                state.vchVNextRoot.size() !=
                    EPOCHSTATE_VNEXT_DIGEST_SIZE ||
                // Width only. A persisted digest is what this chain chose; a build
                // that called an unlisted one corruption would demand a resync of every
                // node holding IV5 state the moment the contract text was edited.
                state.vchVNextParameterDigest.size() !=
                    EPOCHSTATE_VNEXT_DIGEST_SIZE ||
                !DecodePrivacyVNextTreeState(state.vchVNextTreeState,
                                             checkedVNextRoot,
                                             checkedVNextSize,
                                             treeError) ||
                checkedVNextRoot != state.vchVNextRoot ||
                checkedVNextSize != state.nVNextTreeSize ||
                state.hashVNextNullifierRoot == 0)
            {
                printf("LoadEpochStates: FATAL corrupt IV5 root/frontier at epoch %d "
                       "(%s); -reindex/resync required\n",
                       nEpoch, treeError.c_str());
                return false;
            }

            std::vector<unsigned char> checkedNullifierRoot;
            uint64_t checkedNullifierCount = 0;
            if (!DecodePrivacyVNextNullifierState(
                    state.vchVNextNullifierState, checkedNullifierRoot,
                    checkedNullifierCount, treeError) ||
                checkedNullifierRoot.size() != EPOCHSTATE_VNEXT_DIGEST_SIZE ||
                uint256(checkedNullifierRoot) != state.hashVNextNullifierRoot ||
                checkedNullifierCount != state.nVNextNullifierCount ||
                state.vVNextEpochNullifiers.size() > checkedNullifierCount)
            {
                printf("LoadEpochStates: FATAL corrupt IV5 nullifier accumulator "
                       "at epoch %d (%s); -reindex/resync required\n",
                       nEpoch, treeError.c_str());
                return false;
            }

            if (state.vVNextActiveBlockTxCounts.size() !=
                state.vBlockHashes.size())
            {
                printf("LoadEpochStates: FATAL IV5 active-set block-count mismatch "
                       "at epoch %d; -reindex/resync required\n", nEpoch);
                return false;
            }
            uint64_t nActiveTxCount = 0;
            for (std::vector<unsigned int>::const_iterator countIt =
                     state.vVNextActiveBlockTxCounts.begin();
                 countIt != state.vVNextActiveBlockTxCounts.end(); ++countIt)
                nActiveTxCount += *countIt;
            if (nActiveTxCount != state.vVNextActiveTxIds.size())
            {
                printf("LoadEpochStates: FATAL IV5 active-set transaction-count mismatch "
                       "at epoch %d; -reindex/resync required\n", nEpoch);
                return false;
            }

            std::map<uint256, CBlockIndex*>::const_iterator finalizedIt =
                mapBlockIndex.find(state.hashVNextFinalizedAnchor);
            if (finalizedIt == mapBlockIndex.end() || !finalizedIt->second ||
                finalizedIt->second->nHeight != state.nVNextFinalizedHeight ||
                state.nVNextFinalizedHeight != state.nFinalizedHeightAsOf)
            {
                printf("LoadEpochStates: FATAL IV5 finalized-anchor mismatch at epoch %d; "
                       "-reindex/resync required\n", nEpoch);
                return false;
            }

            CHashWriter activeSetHasher(SER_GETHASH, 0);
            activeSetHasher << std::string(
                "Innova/IV5/ActiveDAGTransactionSet/v1");
            activeSetHasher << state.hashBoundaryBlock << state.vBlockHashes;
            activeSetHasher << state.vVNextActiveBlockTxCounts;
            activeSetHasher << state.vVNextActiveTxIds;
            if (activeSetHasher.GetHash() != state.hashVNextActiveTxSet)
            {
                printf("LoadEpochStates: FATAL IV5 active-set commitment mismatch "
                       "at epoch %d; -reindex/resync required\n", nEpoch);
                return false;
            }
        }
    }
    for (std::map<int, CCurveTree>::const_iterator it = mapTrees.begin();
         it != mapTrees.end(); ++it)
    {
        if (!mapStates.count(it->first))
        {
            printf("LoadEpochStates: FATAL orphan curve snapshot for epoch %d; "
                   "-reindex/resync required\n", it->first);
            return false;
        }
    }

    // Epoch-state records must be dense from lowest to highest present epoch; an interior hole
    // refuses the load and forces -reindex. A non-zero lowest epoch is allowed.
    if (!mapStates.empty())
    {
        int nLo = mapStates.begin()->first;
        int nHi = mapStates.rbegin()->first;
        if ((int64_t)mapStates.size() != (int64_t)nHi - nLo + 1)
        {
            printf("LoadEpochStates: FATAL epoch-state gap -- loaded %d records spanning epochs "
                   "[%d..%d] (expected %d contiguous); refusing to run on a holed deterministic "
                   "finalized-height anchor; -reindex required\n",
                   (int)mapStates.size(), nLo, nHi, nHi - nLo + 1);
            return false;
        }

        int nPrevFinalized = 0;
        for (std::map<int, CEpochState>::const_iterator it = mapStates.begin();
             it != mapStates.end(); ++it)
        {
            if (it->second.nFinalizedHeightAsOf < nPrevFinalized)
            {
                printf("LoadEpochStates: FATAL finalized-height regression at epoch %d; "
                       "-reindex/resync required\n", it->first);
                return false;
            }
            nPrevFinalized = it->second.nFinalizedHeightAsOf;
        }
    }

    mapEpochState.swap(mapStates);
    mapEpochCurveTrees.swap(mapTrees);
    setEpochBoundaryBlocks.clear();
    for (std::map<int, CEpochState>::const_iterator it = mapEpochState.begin();
         it != mapEpochState.end(); ++it)
        setEpochBoundaryBlocks.insert(it->second.hashBoundaryBlock);

    if (!mapEpochState.empty() || !mapEpochCurveTrees.empty())
        printf("LoadEpochStates: loaded %d epoch states and %d curve-tree snapshots\n",
               (int)mapEpochState.size(), (int)mapEpochCurveTrees.size());

    return true;
}


size_t CDAGManager::GetLoadedEpochStateCount() const
{
    LOCK(cs_dag);
    return mapEpochState.size();
}

// ---------------------------------------------------------------------------
// CDAGManager: Rebuild Ordering
// ---------------------------------------------------------------------------

void CDAGManager::RebuildDAGOrder()
{
    LOCK(cs_dag);

    // Clear blue set cache to avoid stale entries during rebuild
    mapBlueSetCache.clear();
    mapDAGKnightAnchorCache.clear();
    mapDAGKnightPastCache.clear();

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
            if (mi->second->nHeight >= FORK_HEIGHT_DAGKNIGHT)
            {
                if (ColorBlockDAGKnight(mi->second))
                {
                    CBlockDAGData rebuilt;
                    if (GetDAGData(pair.second, rebuilt))
                        mi->second->nChainTrust = rebuilt.nDAGScore;
                }
            }
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

    if (pindexBest && pindexBest->nHeight >= FORK_HEIGHT_EPOCH_STATE_V3)
        nBestChainTrust = pindexBest->nChainTrust;

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
    mapDAGKnightAnchorCache.clear();
    mapDAGKnightPastCache.clear();

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
            if (mi->second->nHeight >= FORK_HEIGHT_DAGKNIGHT)
            {
                if (ColorBlockDAGKnight(mi->second))
                {
                    CBlockDAGData rebuilt;
                    if (GetDAGData(pair.second, rebuilt))
                        mi->second->nChainTrust = rebuilt.nDAGScore;
                }
            }
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

    if (pindexBest && pindexBest->nHeight >= FORK_HEIGHT_EPOCH_STATE_V3)
        nBestChainTrust = pindexBest->nChainTrust;

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

    // Write erasures and prune height to LevelDB atomically
    if (!txdb.TxnBegin())
        return false;

    for (const uint256& hash : vToErase)
    {
        if (!txdb.EraseDAGLinks(hash))
        {
            txdb.TxnAbort();
            return false;
        }
    }

    // Persist prune height so GetBlueSet boundary check survives restart
    if (!txdb.WriteDAGCleanHeight(nPruneBelow))
    {
        txdb.TxnAbort();
        return false;
    }

    if (!txdb.TxnCommit())
        return false;

    // Erase from memory only after LevelDB commit succeeds
    for (const uint256& hash : vToErase)
    {
        auto dit = mapDAGData.find(hash);
        if (dit != mapDAGData.end())
        {
            for (const uint256& hashParent : dit->second.vDAGParents)
            {
                auto pit = mapDAGData.find(hashParent);
                if (pit != mapDAGData.end())
                {
                    auto& children = pit->second.vDAGChildren;
                    children.erase(std::remove(children.begin(), children.end(), hash), children.end());
                    if (children.empty())
                        setDAGTips.insert(hashParent);
                }
                auto pendingIt = mapPendingChildrenByParent.find(hashParent);
                if (pendingIt != mapPendingChildrenByParent.end())
                {
                    pendingIt->second.erase(hash);
                    if (pendingIt->second.empty())
                        mapPendingChildrenByParent.erase(pendingIt);
                }
            }
            mapDAGData.erase(dit);
        }
        mapPendingChildrenByParent.erase(hash);
        setDAGTips.erase(hash);
        InvalidateBlueSetCacheForBlock(hash);
        nPruned++;
    }

    nPrunedBelowHeight = nPruneBelow;
    mapDAGKnightAnchorCache.clear();
    mapDAGKnightPastCache.clear();

    if (nPruned > 0)
        printf("PruneDAGData: pruned %d entries below height %d (%d remaining)\n",
               nPruned, nPruneBelow, (int)mapDAGData.size());

    return true;
}


// ---------------------------------------------------------------------------
// CDAGManager: Epoch State Computation
// ---------------------------------------------------------------------------

// Strongest tier first; at equal tier a note-weighted certificate outranks a transparent one.
// Pure in the certificates' bytes, so every node picks the same one.
static bool FinalityCertificateOutranks(const CFinalityTallyCertificate& a,
                                        const CFinalityTallyCertificate& b)
{
    if (a.nTier != b.nTier)
        return a.nTier > b.nTier;
    if (a.HasNoteWeight() != b.HasNoteWeight())
        return a.HasNoteWeight();
    return a.GetSignatureDigest() < b.GetSignatureDigest();
}

bool CDAGManager::BuildEpochStateV2Compat(int nEpoch, int nEpochInterval,
                                          const CBlockIndex* pAnchorTip,
                                          CEpochState& stateOut,
                                          CCurveTree& curveTreeOut,
                                          std::string& strError,
                                          const CEpochState* pPrevState,
                                          const CCurveTree* pPrevCurveTree) const
{
    LOCK(cs_dag);

    stateOut = CEpochState();
    curveTreeOut = CCurveTree();
    strError.clear();
    if (nEpoch < 0 || nEpochInterval <= 0)
    {
        strError = strprintf("invalid V2 epoch/interval (%d/%d)",
                             nEpoch, nEpochInterval);
        return false;
    }
    if ((pPrevState == NULL) != (pPrevCurveTree == NULL))
    {
        strError = "V2 predecessor state and curve snapshot must be supplied together";
        return false;
    }
    if (pPrevState && pPrevState->nEpoch != nEpoch - 1)
    {
        strError = strprintf("V2 epoch %d received predecessor epoch %d",
                             nEpoch, pPrevState->nEpoch);
        return false;
    }

    CEpochState state;
    state.nEpoch = nEpoch;
    // Use adjacent epoch boundaries so the epoch that contains the DAG fork is
    // truncated deterministically instead of extending across the fork.
    state.nHeightStart = GetEpochBoundaryHeight(nEpoch, nEpoch * nEpochInterval);
    int nNextEpochStart = GetEpochBoundaryHeight(nEpoch + 1, (nEpoch + 1) * nEpochInterval);
    if (nNextEpochStart > state.nHeightStart)
        state.nHeightEnd = nNextEpochStart - 1;
    else
        state.nHeightEnd = state.nHeightStart + nEpochInterval - 1;
    state.nBlockCount = 0;
    state.nTxCount = 0;
    state.nTotalTrust = 0;
    state.fFinalized = false;

    // Post-DAG epoch boundaries follow the selected-parent chain, not a
    // height-sorted side effect of local arrival order.
    CBlockIndex* pBoundary = NULL;
    // Deterministic anchor: post-FORK_HEIGHT_EPOCH_STATE_V2, order the epoch off the CANONICAL anchor
    // block the caller supplies (its committed selected-parent chain + vDAGParents), NOT the node-local
    // live best tip. GetDAGLinearOrder() is a pure function of its anchor, so this is the single change
    // that makes the epoch roots reorg-safe and identical across nodes. Pre-fork / no anchor keeps the
    // legacy live-tip derivation byte-for-byte (the fork gate is regtest-only for now).
    const bool fDeterministicAnchor =
        (state.nHeightEnd >= FORK_HEIGHT_EPOCH_STATE_V2) && (pAnchorTip != NULL);
    CBlockIndex* pBestTip = fDeterministicAnchor ? const_cast<CBlockIndex*>(pAnchorTip)
                                                 : SelectBestDAGTip();

    // ConnectBlock records finality carriers only along the canonical pprev chain, so build the
    // connected-carrier set from the canonical crossing anchor. Activation is per carrier height.
    std::set<uint256> setConnectedFinalityCarrierBlocks;
    if (IsConnectedFinalityCarrierActiveAtHeight(state.nHeightEnd))
    {
        if (!pAnchorTip || !pAnchorTip->phashBlock)
        {
            strError = strprintf("V2 epoch %d connected-finality carrier rule "
                                 "requires a canonical anchor", nEpoch);
            return false;
        }

        const CBlockIndex* pChain = pAnchorTip;
        bool fReachedEpochStart = false;
        while (pChain && pChain->nHeight >= state.nHeightStart)
        {
            if (!pChain->phashBlock)
            {
                strError = strprintf("V2 epoch %d canonical carrier chain has "
                                     "an unbound block at height %d",
                                     nEpoch, pChain->nHeight);
                return false;
            }
            if (pChain->nHeight <= state.nHeightEnd)
                setConnectedFinalityCarrierBlocks.insert(
                    pChain->GetBlockHash());
            if (pChain->nHeight == state.nHeightStart)
            {
                fReachedEpochStart = true;
                break;
            }
            if (!pChain->pprev ||
                pChain->pprev->nHeight != pChain->nHeight - 1)
            {
                strError = strprintf("V2 epoch %d canonical carrier chain is "
                                     "not contiguous below height %d",
                                     nEpoch, pChain->nHeight);
                return false;
            }
            pChain = pChain->pprev;
        }
        if (!fReachedEpochStart)
        {
            strError = strprintf("V2 epoch %d canonical carrier chain does not "
                                 "reach epoch start height %d",
                                 nEpoch, state.nHeightStart);
            return false;
        }
    }
    if (pBestTip && pBestTip->nHeight >= state.nHeightEnd)
    {
        CBlockIndex* pWalk = pBestTip;
        std::set<uint256> setVisited;
        while (pWalk && pWalk->nHeight > state.nHeightEnd && pWalk->phashBlock)
        {
            if (!setVisited.insert(pWalk->GetBlockHash()).second)
                break;
            uint256 hashParent = GetSelectedParent(pWalk->GetBlockHash());
            std::map<uint256, CBlockIndex*>::iterator miParent = mapBlockIndex.find(hashParent);
            if (miParent == mapBlockIndex.end())
                break;
            pWalk = miParent->second;
        }
        if (pWalk && pWalk->nHeight == state.nHeightEnd)
            pBoundary = pWalk;
    }
    // Legacy path only: FindBlockByHeight follows live pnext/best-chain links (node-local). In the
    // deterministic-anchor path the selected-parent walk above always lands on nHeightEnd (anchor height
    // >= nHeightEnd), so this fallback is unreachable there -- gate it out so it can never silently
    // reintroduce a live-tip dependency into the anchor-pure computation.
    if (!pBoundary && !fDeterministicAnchor)
        pBoundary = FindBlockByHeight(state.nHeightEnd);
    if (pBoundary && pBoundary->phashBlock)
        state.hashBoundaryBlock = pBoundary->GetBlockHash();
    if (fDeterministicAnchor && state.hashBoundaryBlock == 0)
    {
        strError = strprintf("V2 epoch %d anchor does not reach boundary height %d",
                             nEpoch, state.nHeightEnd);
        return false;
    }

    std::set<uint256> setOrdered;
    if (pBestTip && pBestTip->phashBlock)
    {
        std::vector<uint256> vOrder = GetDAGLinearOrder(pBestTip->GetBlockHash());
        for (const uint256& hashBlock : vOrder)
        {
            std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
            if (mi == mapBlockIndex.end())
                continue;
            if (mi->second->nHeight < state.nHeightStart || mi->second->nHeight > state.nHeightEnd)
                continue;
            if (mi->second->nHeight >= FORK_HEIGHT_DAG && mi->second->IsProofOfStake())
                continue;
            if (!setOrdered.insert(hashBlock).second)
                continue;
            state.vBlockHashes.push_back(hashBlock);
        }
    }

    if (fDeterministicAnchor)
    {
        // Canonical accounting: block-count + blue-trust over EXACTLY the anchor-ordered set
        // (state.vBlockHashes built above). The legacy mapDAGData sweep folds in every locally-seen
        // side-branch block in the height range and appends by a live-tip-derived nDAGOrder sort --
        // both node-local -- which would reintroduce the divergence this fork removes.
        for (const uint256& hashBlock : state.vBlockHashes)
        {
            std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
            if (mi == mapBlockIndex.end())
                continue;
            state.nBlockCount++;
            auto dit = mapDAGData.find(hashBlock);
            if (dit != mapDAGData.end() && dit->second.fBlue)
                state.nTotalTrust = state.nTotalTrust + mi->second->GetBlockTrust();
        }
    }
    else
    {
        // Include any DAG-era blocks missing from the selected order using stored
        // DAG order as deterministic fallback.
        std::vector<std::pair<int, uint256>> vEpochBlocks;
        for (const auto& pair : mapDAGData)
        {
            std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(pair.first);
            if (mi == mapBlockIndex.end())
                continue;

            int nBlockHeight = mi->second->nHeight;
            if (nBlockHeight >= state.nHeightStart && nBlockHeight <= state.nHeightEnd)
            {
                if (mi->second->nHeight >= FORK_HEIGHT_DAG && mi->second->IsProofOfStake())
                    continue;
                if (!setOrdered.count(pair.first))
                    vEpochBlocks.push_back(std::make_pair(pair.second.nDAGOrder, pair.first));
                state.nBlockCount++;

                if (pair.second.fBlue)
                    state.nTotalTrust = state.nTotalTrust + mi->second->GetBlockTrust();
            }
        }

        std::sort(vEpochBlocks.begin(), vEpochBlocks.end());
        for (const auto& pair : vEpochBlocks)
            state.vBlockHashes.push_back(pair.second);
    }

    // Epoch-root privacy state is derived from deterministic DAG order.
    // Starting from the previous persisted epoch snapshot avoids mutable
    // per-block curve-tree state after the epoch-root FCMP fork.
    CCurveTree epochCurveTree;
    bool fHavePriorEpochSnapshot = false;
    if (pPrevCurveTree)
    {
        epochCurveTree = *pPrevCurveTree;
        fHavePriorEpochSnapshot = true;
    }
    else
    {
        for (int nPrevEpoch = nEpoch - 1; nPrevEpoch >= 0; nPrevEpoch--)
        {
            std::map<int, CCurveTree>::const_iterator itTree =
                mapEpochCurveTrees.find(nPrevEpoch);
            if (itTree != mapEpochCurveTrees.end())
            {
                epochCurveTree = itTree->second;
                fHavePriorEpochSnapshot = true;
                break;
            }
        }
    }
    if (!fHavePriorEpochSnapshot)
    {
        CTxDB txdb("r");
        txdb.ReadCurveTree(epochCurveTree);
    }
    if (!epochCurveTree.IsEmpty())
        epochCurveTree.RebuildParentNodes();

    // Fail closed on an epoch-state gap: a missing predecessor with earlier epochs present
    // would reset the finalized height, HARD streak and nullifier-root chain. A missing
    // predecessor is legitimate only when nEpoch is the earliest epoch in the map.
    const CEpochState* pEffectivePrevState = pPrevState;
    if (!pEffectivePrevState && nEpoch > 0)
    {
        std::map<int, CEpochState>::const_iterator itPrev =
            mapEpochState.find(nEpoch - 1);
        if (itPrev != mapEpochState.end())
            pEffectivePrevState = &itPrev->second;
    }
    bool fHavePrevEpoch = pEffectivePrevState != NULL;
    if (nEpoch > 0 && !fHavePrevEpoch &&
        !mapEpochState.empty() && mapEpochState.begin()->first < nEpoch)
    {
        strError = strprintf("V2 epoch-state gap: missing predecessor epoch %d for epoch %d; "
                             "resync/-reindex required", nEpoch - 1, nEpoch);
        return false;
    }

    CHashWriter nullifierRootHasher(SER_GETHASH, 0);
    nullifierRootHasher << std::string("Innova/IDAG/EpochNullifierRoot/v1");
    if (fHavePrevEpoch)
        nullifierRootHasher << pEffectivePrevState->hashNullifierRoot;
    else
        nullifierRootHasher << uint256(0);
    nullifierRootHasher << nEpoch;

    std::set<uint256> setSeenShieldedNullifiers;
    CFinalityTallyCertificate bestCert;
    bool fHaveBestCert = false;
    bool fInsertEpochOutputs = fHavePriorEpochSnapshot || state.nHeightEnd >= FORK_HEIGHT_EPOCH_ROOT_FCMP;

    // Per-epoch finality vote-set accumulator: the votes embedded in this epoch's
    // own blocks (vote.nEpoch == nEpoch), deduped + sorted by nullifier (std::map
    // gives canonical order) so CheckTallyCertificate can reproduce the digest.
    std::map<uint256, uint256> mapEpochVoteLeaves;   // nullifier -> vote.hashBlock
    // F2 note-vote leaves, gathered from the epoch's own connected carriers exactly as
    // the transparent leaves above are. Inert before the note-vote fork.
    const bool fCommitNoteVotes = IsIV5NoteVoteActiveAtHeight(state.nHeightEnd);
    std::vector<CNoteFinalityVote> vEpochNoteVotes;

    for (const uint256& hashBlock : state.vBlockHashes)
    {
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi == mapBlockIndex.end())
        {
            strError = strprintf("V2 epoch %d lost ordered block index %s during build; "
                                 "-reindex/resync required", nEpoch,
                                 hashBlock.ToString().substr(0, 20).c_str());
            return false;
        }

        CBlock block;
        if (!block.ReadFromDisk(mi->second))
        {
            strError = strprintf("V2 epoch %d cannot read ordered block %s from disk; "
                                 "-reindex/resync required", nEpoch,
                                 hashBlock.ToString().substr(0, 20).c_str());
            return false;
        }
        std::set<uint256> setDAGSkippedTxs = GetDAGSkippedTxsForBlock(block, mi->second);
        CBlock activeBlock = GetDAGActiveBlock(block, setDAGSkippedTxs);

        for (const CTransaction& tx : activeBlock.vtx)
        {
            for (const CShieldedOutputDescription& output : tx.vShieldedOutput)
            {
                if (fInsertEpochOutputs)
                    epochCurveTree.InsertLeaf(output.cv);
            }

            for (const CShieldedSpendDescription& spend : tx.vShieldedSpend)
            {
                if (setSeenShieldedNullifiers.insert(spend.nullifier).second)
                    nullifierRootHasher << spend.nullifier;
            }
        }

        // A merge-only block skipped ConnectBlock's finality checks: once the connected-carrier rule
        // is active, exclude its vote/certificate outputs from the V2 finality commitment.
        if (IsConnectedFinalityCarrierActiveAtHeight(mi->second->nHeight) &&
            !setConnectedFinalityCarrierBlocks.count(hashBlock))
            continue;

        std::vector<CFinalityTallyCertificate> vCerts;
        FinalityEnvelopeDecodeResult certEnvelopeFailure = FINALITY_ENVELOPE_NO_MATCH;
        if (!ExtractFinalityTallyCertificatesFromBlockForHeight(
                activeBlock, mi->second->nHeight, vCerts,
                &certEnvelopeFailure))
        {
            strError = strprintf("V2 epoch %d block %s has invalid finality certificate envelope "
                                 "at height %d (decode=%d)",
                                 nEpoch, hashBlock.ToString().substr(0, 20).c_str(),
                                 mi->second->nHeight, (int)certEnvelopeFailure);
            return false;
        }
        for (const CFinalityTallyCertificate& cert : vCerts)
        {
            if (cert.nEpoch != nEpoch)
                continue;
            if (!fHaveBestCert || FinalityCertificateOutranks(cert, bestCert))
            {
                bestCert = cert;
                fHaveBestCert = true;
            }
        }

        std::vector<CFinalityVote> vVotes;
        FinalityEnvelopeDecodeResult voteEnvelopeFailure = FINALITY_ENVELOPE_NO_MATCH;
        if (!ExtractFinalityVotesFromBlockForHeight(
                activeBlock, mi->second->nHeight, vVotes,
                &voteEnvelopeFailure))
        {
            strError = strprintf("V2 epoch %d block %s has invalid finality vote envelope "
                                 "at height %d (decode=%d)",
                                 nEpoch, hashBlock.ToString().substr(0, 20).c_str(),
                                 mi->second->nHeight, (int)voteEnvelopeFailure);
            return false;
        }
        for (const CFinalityVote& vote : vVotes)
        {
            if (vote.nEpoch == nEpoch)
                mapEpochVoteLeaves[vote.nullifier] = vote.hashBlock;
        }

        if (fCommitNoteVotes)
        {
            std::vector<CNoteFinalityVote> vNoteVotes;
            FinalityEnvelopeDecodeResult noteEnvelopeFailure = FINALITY_ENVELOPE_NO_MATCH;
            if (!ExtractNoteFinalityVotesFromBlockForHeight(
                    activeBlock, mi->second->nHeight, vNoteVotes, &noteEnvelopeFailure))
            {
                strError = strprintf("V2 epoch %d block %s has invalid note vote envelope "
                                     "at height %d (decode=%d)",
                                     nEpoch, hashBlock.ToString().substr(0, 20).c_str(),
                                     mi->second->nHeight, (int)noteEnvelopeFailure);
                return false;
            }
            for (size_t i = 0; i < vNoteVotes.size(); i++)
            {
                if (vNoteVotes[i].nEpoch == nEpoch)
                    vEpochNoteVotes.push_back(vNoteVotes[i]);
            }
        }
    }

    if (!epochCurveTree.IsEmpty())
        epochCurveTree.RebuildParentNodes();
    state.hashCurveRoot = epochCurveTree.GetRoot();
    state.hashNullifierRoot = nullifierRootHasher.GetHash();

    // Non-chained: each epoch's coverage is independent, so the cert-side recompute
    // in CheckTallyCertificate needs only this epoch's votes (no prior-epoch lookup).
    CHashWriter voteSetHasher(SER_GETHASH, 0);
    voteSetHasher << std::string("Innova/IDAG/EpochVoteSetRoot/v1");
    voteSetHasher << nEpoch;
    for (std::map<uint256, uint256>::const_iterator it = mapEpochVoteLeaves.begin();
         it != mapEpochVoteLeaves.end(); ++it)
    {
        voteSetHasher << it->first;     // nullifier
        voteSetHasher << it->second;    // winning-block choice (vote.hashBlock)
    }
    if (fCommitNoteVotes)
    {
        // Counted, not carried: an equivocated tag counts for neither instance, so the
        // committed set has to be the one the tally can actually cover.
        std::vector<const CNoteFinalityVote*> vCarried;
        vCarried.reserve(vEpochNoteVotes.size());
        for (size_t i = 0; i < vEpochNoteVotes.size(); i++)
            vCarried.push_back(&vEpochNoteVotes[i]);
        std::map<uint256, const CNoteFinalityVote*> mapCountedNoteVotes;
        std::set<uint256> setEquivocatedNoteVotes;
        ResolveNoteVoteCounting(vCarried, mapCountedNoteVotes, setEquivocatedNoteVotes);
        for (std::map<uint256, const CNoteFinalityVote*>::const_iterator it =
                 mapCountedNoteVotes.begin(); it != mapCountedNoteVotes.end(); ++it)
        {
            voteSetHasher << it->first;             // note vote tag
            voteSetHasher << it->second->hashBlock; // winning-block choice
        }
    }
    state.hashVoteSetRoot = voteSetHasher.GetHash();

    // Deterministic per-epoch finality: a pure function of this epoch's connected
    // votes / tally certificate plus the prior epoch's persisted state -- NOT the
    // node-local live finalization streak. This guarantees every node computes the
    // same tier and the same monotonic finalized height, so private-vote / tally-cert
    // / FCMP-spend validation (which anchors to GetEpochForHeight(nFinalizedHeight))
    // is identical on all nodes and ConnectBlock stays deterministic.
    {
        // Tier from the epoch's own-block best cert, not the live cert map, so a late cert cannot make
        // the boundary and reorg-recompute paths persist different tiers.
        int nDetTier = 0; uint256 hashWinner = 0; int nWinnerHeight = 0; int nVoters = 0;
        g_finalityTracker.ComputeDeterministicEpochTier(nEpoch, fHaveBestCert, bestCert,
                                                        nDetTier, hashWinner, nWinnerHeight, nVoters);
        state.nFinalityTier = nDetTier;

        int nPrevHardCount = 0;
        int nPrevFinalizedHeight = 0;
        if (fHavePrevEpoch)
        {
            if (pEffectivePrevState->nFinalityTier >= FINALITY_HARD)
                nPrevHardCount = pEffectivePrevState->nConsecutiveHardCount;
            nPrevFinalizedHeight = pEffectivePrevState->nFinalizedHeightAsOf;
        }
        state.nConsecutiveHardCount = (nDetTier >= FINALITY_HARD) ? (nPrevHardCount + 1) : 0;

        // Finalized height is monotonic; advance it only when this epoch completes a
        // run of FINALITY_CONFIRMATION_EPOCHS consecutive HARD epochs.
        state.nFinalizedHeightAsOf = nPrevFinalizedHeight;
        if (state.nConsecutiveHardCount >= FINALITY_CONFIRMATION_EPOCHS &&
            state.nHeightEnd > state.nFinalizedHeightAsOf)
            state.nFinalizedHeightAsOf = state.nHeightEnd;
        state.fFinalized = (state.nHeightEnd > 0 && state.nFinalizedHeightAsOf >= state.nHeightEnd);
    }

    if (fHaveBestCert)
        state.hashFinalityCertificate = bestCert.GetHash();

    // Transaction counting deferred to RPC layer (getepochinfo) to avoid
    // blocking block processing with disk I/O at every epoch boundary.
    // nTxCount = -1 signals "not yet counted"; RPC can populate on demand.
    state.nTxCount = -1;

    stateOut = state;
    curveTreeOut = epochCurveTree;
    return true;
}

bool CDAGManager::ComputeEpochState(int nEpoch, int nEpochInterval,
                                    const CBlockIndex* pAnchorTip)
{
    CEpochState state;
    CCurveTree epochCurveTree;
    std::string strError;
    if (!BuildEpochStateV2Compat(nEpoch, nEpochInterval, pAnchorTip,
                                 state, epochCurveTree, strError))
        return error("ComputeEpochState: epoch %d build failed: %s",
                     nEpoch, strError.c_str());

    LOCK(cs_dag);
    mapEpochState[nEpoch] = state;
    mapEpochCurveTrees[nEpoch] = epochCurveTree;
    if (state.hashBoundaryBlock != 0)
        setEpochBoundaryBlocks.insert(state.hashBoundaryBlock);

    printf("ComputeEpochState: epoch %d (%d-%d), %d blocks, %d txs, curve_root=%s, finalized=%d\n",
           nEpoch, state.nHeightStart, state.nHeightEnd,
           state.nBlockCount, state.nTxCount,
           state.hashCurveRoot.ToString().substr(0,10).c_str(),
           state.fFinalized);
    return true;
}

bool CDAGManager::BuildEpochState(int nEpoch, int nEpochInterval,
                                  const CBlockIndex* pBoundary,
                                  CEpochState& stateOut,
                                  CCurveTree& curveTreeOut,
                                  std::string& strError,
                                  const CEpochState* pPrevState,
                                  const CCurveTree* pPrevCurveTree) const
{
    LOCK(cs_dag);

    stateOut = CEpochState();
    curveTreeOut = CCurveTree();
    strError.clear();

    if (nEpoch < 0 || nEpochInterval <= 0)
    {
        strError = strprintf("invalid epoch/interval (%d/%d)", nEpoch, nEpochInterval);
        return false;
    }

    CEpochState state;
    state.nEpoch = nEpoch;
    state.nHeightStart = GetEpochBoundaryHeight(nEpoch, nEpoch * nEpochInterval);
    state.nHeightEnd = GetEpochBoundaryHeight(nEpoch + 1, state.nHeightStart) - 1;
    if (state.nHeightEnd < state.nHeightStart ||
        nEpochInterval != state.nHeightEnd - state.nHeightStart + 1)
    {
        strError = strprintf("epoch %d interval mismatch: caller=%d canonical=%d (%d-%d)",
                             nEpoch, nEpochInterval,
                             state.nHeightEnd - state.nHeightStart + 1,
                             state.nHeightStart, state.nHeightEnd);
        return false;
    }
    if (!pBoundary || !pBoundary->phashBlock || pBoundary->nHeight != state.nHeightEnd)
    {
        strError = strprintf("epoch %d requires exact boundary height %d (got %d)",
                             nEpoch, state.nHeightEnd,
                             pBoundary ? pBoundary->nHeight : -1);
        return false;
    }

    state.hashBoundaryBlock = pBoundary->GetBlockHash();
    std::map<uint256, CBlockIndex*>::const_iterator miBoundary =
        mapBlockIndex.find(state.hashBoundaryBlock);
    if (miBoundary == mapBlockIndex.end() || miBoundary->second != pBoundary)
    {
        strError = strprintf("epoch %d boundary index %s is missing or non-canonical",
                             nEpoch, state.hashBoundaryBlock.ToString().substr(0, 20).c_str());
        return false;
    }

    // Schema V3 orders only from the exact epoch-end block; force V3 primary-parent and
    // height/hash merge ordering so the migration base inherits no legacy colouring state.
    const std::vector<uint256> vOrder =
        GetDAGLinearOrder(state.hashBoundaryBlock, 0, true);
    if (vOrder.empty())
    {
        strError = strprintf("epoch %d boundary produced an empty DAG order", nEpoch);
        return false;
    }

    std::set<uint256> setOrdered;
    bool fSawBoundary = false;
    for (std::vector<uint256>::const_iterator it = vOrder.begin(); it != vOrder.end(); ++it)
    {
        std::map<uint256, CBlockIndex*>::const_iterator mi = mapBlockIndex.find(*it);
        if (mi == mapBlockIndex.end() || !mi->second || !mi->second->phashBlock)
        {
            strError = strprintf("epoch %d DAG order references missing block index %s",
                                 nEpoch, it->ToString().substr(0, 20).c_str());
            return false;
        }
        const CBlockIndex* pindex = mi->second;
        if (pindex->nHeight < state.nHeightStart || pindex->nHeight > state.nHeightEnd)
            continue;
        if (pindex->nHeight >= FORK_HEIGHT_DAG && pindex->IsProofOfStake())
        {
            strError = strprintf("epoch %d order contains forbidden post-DAG PoS block %s",
                                 nEpoch, it->ToString().substr(0, 20).c_str());
            return false;
        }
        if (!setOrdered.insert(*it).second)
        {
            strError = strprintf("epoch %d DAG order contains duplicate block %s",
                                 nEpoch, it->ToString().substr(0, 20).c_str());
            return false;
        }
        state.vBlockHashes.push_back(*it);
        if (*it == state.hashBoundaryBlock)
            fSawBoundary = true;
    }
    if (!fSawBoundary || state.vBlockHashes.empty() ||
        state.vBlockHashes.back() != state.hashBoundaryBlock)
    {
        strError = strprintf("epoch %d exact boundary is absent or not terminal in DAG order", nEpoch);
        return false;
    }


    // Every pprev-chain block in the epoch appears exactly once in the DAG order and the chain is
    // height-contiguous; merge/sibling blocks contribute ordering only.
    std::set<uint256> setCanonicalConnectedBlocks;
    const CBlockIndex* pChain = pBoundary;
    while (pChain && pChain->nHeight >= state.nHeightStart)
    {
        if (!pChain->phashBlock || !setOrdered.count(pChain->GetBlockHash()))
        {
            strError = strprintf("epoch %d DAG order omits canonical block at height %d",
                                 nEpoch, pChain->nHeight);
            return false;
        }
        setCanonicalConnectedBlocks.insert(pChain->GetBlockHash());
        if (pChain->nHeight > state.nHeightStart &&
            (!pChain->pprev || pChain->pprev->nHeight != pChain->nHeight - 1))
        {
            strError = strprintf("epoch %d canonical block-index chain is non-contiguous at height %d",
                                 nEpoch, pChain->nHeight);
            return false;
        }
        pChain = pChain->pprev;
    }
    if (state.nHeightStart > 0 && (!pChain || pChain->nHeight != state.nHeightStart - 1))
    {
        strError = strprintf("epoch %d is missing the block immediately before its start", nEpoch);
        return false;
    }

    state.nBlockCount = (int)state.vBlockHashes.size();
    state.nTotalTrust = 0;
    for (std::vector<uint256>::const_iterator it = state.vBlockHashes.begin();
         it != state.vBlockHashes.end(); ++it)
    {
        std::map<uint256, CBlockIndex*>::const_iterator mi = mapBlockIndex.find(*it);
        std::map<uint256, CBlockDAGData>::const_iterator dit = mapDAGData.find(*it);
        if (mi == mapBlockIndex.end() ||
            (mi->second->nHeight >= FORK_HEIGHT_DAG && dit == mapDAGData.end()))
        {
            strError = strprintf("epoch %d is missing ordered DAG metadata for block %s",
                                 nEpoch, it->ToString().substr(0, 20).c_str());
            return false;
        }
        state.nTotalTrust = state.nTotalTrust + mi->second->GetBlockTrust();
    }

    if ((pPrevState == NULL) != (pPrevCurveTree == NULL))
    {
        strError = "predecessor state and curve snapshot must be supplied together";
        return false;
    }

    CEpochState prevState;
    CCurveTree epochCurveTree;
    bool fHavePredecessor = false;
    if (pPrevState && pPrevCurveTree)
    {
        prevState = *pPrevState;
        epochCurveTree = *pPrevCurveTree;
        fHavePredecessor = true;
    }
    else if (nEpoch > 0)
    {
        std::map<int, CEpochState>::const_iterator itState = mapEpochState.find(nEpoch - 1);
        std::map<int, CCurveTree>::const_iterator itTree = mapEpochCurveTrees.find(nEpoch - 1);
        if (itState != mapEpochState.end() && itTree != mapEpochCurveTrees.end())
        {
            prevState = itState->second;
            epochCurveTree = itTree->second;
            fHavePredecessor = true;
        }
    }

    if (nEpoch > 0 && !fHavePredecessor)
    {
        strError = strprintf("epoch %d is missing its immediate predecessor state/tree pair; "
                             "-reindex/resync required", nEpoch);
        return false;
    }
    if (fHavePredecessor)
    {
        if (prevState.nEpoch != nEpoch - 1 || prevState.hashBoundaryBlock == 0 ||
            prevState.nHeightEnd != state.nHeightStart - 1 ||
            prevState.nHeightStart !=
                GetEpochBoundaryHeight(nEpoch - 1, prevState.nHeightEnd))
        {
            strError = strprintf("epoch %d received non-contiguous/corrupt predecessor epoch %d",
                                 nEpoch, prevState.nEpoch);
            return false;
        }
        if (!pChain || !pChain->phashBlock ||
            prevState.hashBoundaryBlock != pChain->GetBlockHash())
        {
            strError = strprintf("epoch %d predecessor boundary %s does not match canonical "
                                 "block %s at height %d", nEpoch,
                                 prevState.hashBoundaryBlock.ToString().substr(0, 20).c_str(),
                                 (pChain && pChain->phashBlock)
                                     ? pChain->GetBlockHash().ToString().substr(0, 20).c_str()
                                     : "<missing>",
                                 state.nHeightStart - 1);
            return false;
        }
        if (epochCurveTree.nLeafCount == 0)
        {
            if (prevState.hashCurveRoot != 0)
            {
                strError = strprintf("epoch %d predecessor has empty tree but nonzero root", nEpoch);
                return false;
            }
        }
        else if (epochCurveTree.vLevels.empty() ||
                 epochCurveTree.vLevels[0].size() != epochCurveTree.nLeafCount ||
                 !epochCurveTree.RebuildParentNodes() ||
                 epochCurveTree.GetRoot() != prevState.hashCurveRoot)
        {
            strError = strprintf("epoch %d predecessor curve snapshot/root is corrupt", nEpoch);
            return false;
        }
    }

    const bool fBuildVNext = IsBoundaryBActiveAtHeight(state.nHeightEnd);
    PrivacyVNextEpochSeed vNextSeed;
    if (fBuildVNext)
    {
        if (!LoadPrivacyVNextEpochSeed(vNextSeed, strError))
        {
            strError = "IV5 epoch seed unavailable: " + strError;
            return false;
        }
        // Write at the current version, not a pinned one: a field added to the record
        // is only serialized when the version says it is there, so pinning this silently
        // drops every later addition. The one exception is a field a fork introduces:
        // the drawn committee does not exist below FORK_HEIGHT_IV5_NOTE_VOTE, and writing
        // its version there would change records the fork does not reach.
        state.nSerVersion = IsIV5NoteVoteActiveAtHeight(state.nHeightEnd)
                                ? EPOCHSTATE_SER_VERSION
                                : EPOCHSTATE_SER_VERSION_V5;
        state.vchVNextParameterDigest = vNextSeed.vchParameterDigest;
        if (fHavePredecessor &&
            prevState.nSerVersion >= EPOCHSTATE_SER_VERSION_V4)
        {
            // Width only. The value is the chain's, so holding it against a list
            // compiled into this build would stop an upgraded node from extending a
            // chain its peers extend fine.
            if (prevState.vchVNextParameterDigest.size() !=
                EPOCHSTATE_VNEXT_DIGEST_SIZE)
            {
                strError = "IV5 predecessor parameter digest is malformed";
                return false;
            }
            // Inherited, never restamped: the digest is fixed at the chain's first IV5 epoch so builds agree.
            state.vchVNextParameterDigest = prevState.vchVNextParameterDigest;
            state.vchVNextTreeState = prevState.vchVNextTreeState;
            state.vchVNextRoot = prevState.vchVNextRoot;
            state.nVNextTreeSize = prevState.nVNextTreeSize;
            state.vchVNextNullifierState =
                prevState.vchVNextNullifierState;
            state.hashVNextNullifierRoot =
                prevState.hashVNextNullifierRoot;
            state.nVNextNullifierCount =
                prevState.nVNextNullifierCount;
            // The pool balance is cumulative over the whole chain, not per epoch.
            state.nVNextPoolBalance = prevState.nVNextPoolBalance;
        }
        else
        {
            // The pool starts empty at activation, so the first epoch begins at zero.
            state.nVNextPoolBalance = 0;
            state.vchVNextTreeState = vNextSeed.vchTreeState;
            state.vchVNextRoot = vNextSeed.vchRoot;
            state.nVNextTreeSize = vNextSeed.nTreeSize;
            state.vchVNextNullifierState =
                vNextSeed.vchNullifierState;
            state.hashVNextNullifierRoot =
                uint256(vNextSeed.vchNullifierRoot);
            state.nVNextNullifierCount =
                vNextSeed.nNullifierCount;
        }
    }

    CHashWriter nullifierRootHasher(SER_GETHASH, 0);
    nullifierRootHasher << std::string("Innova/IDAG/EpochNullifierRoot/v1");
    nullifierRootHasher << (fHavePredecessor ? prevState.hashNullifierRoot : uint256(0));
    nullifierRootHasher << nEpoch;

    std::set<uint256> setSeenShieldedNullifiers;
    std::set<uint256> setVNextEpochNullifiers;
    std::map<uint256, CFinalityVote> mapEpochVotes;
    // F2: the epoch's own note-vote carriers. Read from the epoch's own blocks, like every
    // other leaf here, so the commitment stays a pure function of the anchor rather than of
    // the node-local counted view the tracker maintains.
    const bool fCommitNoteVotes = IsIV5NoteVoteActiveAtHeight(state.nHeightEnd);
    std::vector<CNoteFinalityVote> vEpochNoteVotes;
    CFinalityTallyCertificate bestCert;
    bool fHaveBestCert = false;

    for (std::vector<uint256>::const_iterator it = state.vBlockHashes.begin();
         it != state.vBlockHashes.end(); ++it)
    {
        std::map<uint256, CBlockIndex*>::const_iterator mi = mapBlockIndex.find(*it);
        if (mi == mapBlockIndex.end())
        {
            strError = strprintf("epoch %d lost ordered block index %s during build",
                                 nEpoch, it->ToString().substr(0, 20).c_str());
            return false;
        }

        CBlock block;
        if (!block.ReadFromDisk(mi->second))
        {
            strError = strprintf("epoch %d cannot read ordered block %s from disk; "
                                 "-reindex/resync required", nEpoch,
                                 it->ToString().substr(0, 20).c_str());
            return false;
        }
        // One derivation of a block's active set, shared with ConnectBlock.
        const std::set<uint256> setDAGSkippedTxs =
            GetDAGSkippedTxsForBlock(block, mi->second);
        const CBlock activeBlock = GetDAGActiveBlock(block, setDAGSkippedTxs);

        // A merge block is never connected, so none of its transaction effects may reach the epoch's
        // roots, pool, key images or id list.
        const bool fConnectedBlock = setCanonicalConnectedBlocks.count(*it) != 0;

        if (fBuildVNext)
        {
            const size_t nActiveTxs = fConnectedBlock ? activeBlock.vtx.size() : 0;
            if (state.vVNextActiveTxIds.size() + nActiveTxs >
                EPOCHSTATE_VNEXT_MAX_ACTIVE_TXS)
            {
                strError = strprintf(
                    "epoch %d IV5 active transaction set exceeds limit", nEpoch);
                return false;
            }
            state.vVNextActiveBlockTxCounts.push_back(
                static_cast<unsigned int>(nActiveTxs));
        }
        if (!fConnectedBlock)
            continue;

        for (std::vector<CTransaction>::const_iterator txit = activeBlock.vtx.begin();
             txit != activeBlock.vtx.end(); ++txit)
        {
            // Both replayers re-derive leaf positions from this list and a merge
            // block's transaction has no txindex entry to retrieve, so the list
            // must name exactly the transactions whose leaves the tree absorbed.
            if (fBuildVNext)
                state.vVNextActiveTxIds.push_back(txit->GetHash());
            for (std::vector<CShieldedOutputDescription>::const_iterator oit =
                     txit->vShieldedOutput.begin(); oit != txit->vShieldedOutput.end(); ++oit)
            {
                if (!epochCurveTree.InsertLeaf(oit->cv))
                {
                    strError = strprintf("epoch %d failed to insert curve-tree leaf", nEpoch);
                    return false;
                }
            }
            for (std::vector<CShieldedSpendDescription>::const_iterator sit =
                     txit->vShieldedSpend.begin(); sit != txit->vShieldedSpend.end(); ++sit)
            {
                if (setSeenShieldedNullifiers.insert(sit->nullifier).second)
                    nullifierRootHasher << sit->nullifier;
            }

            if (fBuildVNext && txit->IsPrivacyVNext())
            {
                PrivacyVNextStateEffects effects;
                const PrivacyVNextPayloadValidation validation =
                    ExtractPrivacyVNextPayloadEffects(
                        static_cast<uint32_t>(txit->nVersion),
                        txit->privacyVNext.vchPayload, effects);
                if (!validation.IsValid())
                {
                    strError = strprintf(
                        "epoch %d IV5 effects extraction failed for transaction %s: %s",
                        nEpoch, txit->GetHash().ToString().substr(0, 20).c_str(),
                        validation.strError.c_str());
                    return false;
                }
                // The leaves and pool delta are only valid against the transparent side they were proved over.
                std::string strBindingError;
                if (!CheckPrivacyVNextTransparentBinding(*txit, effects,
                                                         strBindingError))
                {
                    strError = strprintf(
                        "epoch %d IV5 transaction %s: %s", nEpoch,
                        txit->GetHash().ToString().substr(0, 20).c_str(),
                        strBindingError.c_str());
                    return false;
                }
                // The same rule ConnectBlock applies, from the same implementation, so
                // epoch build and block connect cannot disagree about a transaction.
                std::string strDigestError;
                if (!CheckPrivacyVNextParameterDigest(
                        effects, state.vchVNextParameterDigest, strDigestError))
                {
                    strError = strprintf(
                        "epoch %d IV5 transaction %s: %s", nEpoch,
                        txit->GetHash().ToString().substr(0, 20).c_str(),
                        strDigestError.c_str());
                    return false;
                }

                std::vector<unsigned char> nextState;
                std::vector<unsigned char> nextRoot;
                uint64_t nextSize = 0;
                if (!ApplyPrivacyVNextOutputLeaves(
                        state.vchVNextTreeState, effects.outputLeaves,
                        nextState, nextRoot, nextSize, strError))
                {
                    strError = "IV5 output-tree transition failed: " + strError;
                    return false;
                }
                state.vchVNextTreeState.swap(nextState);
                state.vchVNextRoot.swap(nextRoot);
                state.nVNextTreeSize = nextSize;

                // Track what the pool holds and refuse to let it go negative. Whatever a
                // proof does inside the pool, no more value can leave it than entered, so a
                // soundness failure is bounded by the deposits rather than the money supply.
                int64_t nPoolDelta = 0;
                std::string strPoolError;
                if (!GetPrivacyVNextPoolDelta(effects, nPoolDelta,
                                              strPoolError) ||
                    !ApplyPrivacyVNextPoolDelta(state.nVNextPoolBalance,
                                                nPoolDelta, strPoolError))
                {
                    strError = strprintf(
                        "epoch %d IV5 transaction %s: %s", nEpoch,
                        txit->GetHash().ToString().substr(0, 20).c_str(),
                        strPoolError.c_str());
                    return false;
                }

                uint64_t nextNullifierCount = 0;
                if (!ApplyPrivacyVNextNullifiers(
                        state.vchVNextNullifierState, effects.keyImages,
                        nextState, nextRoot, nextNullifierCount, strError))
                {
                    strError = "IV5 nullifier transition failed: " + strError;
                    return false;
                }
                if (state.vVNextEpochNullifiers.size() +
                        effects.keyImages.size() >
                    EPOCHSTATE_VNEXT_MAX_NULLIFIERS)
                {
                    strError = strprintf(
                        "epoch %d IV5 nullifier delta exceeds limit", nEpoch);
                    return false;
                }
                for (size_t i = 0; i < effects.keyImages.size(); ++i)
                {
                    const std::vector<unsigned char> encoded(
                        effects.keyImages[i].begin(), effects.keyImages[i].end());
                    const uint256 nullifier(encoded);
                    if (nullifier == 0 ||
                        !setVNextEpochNullifiers.insert(nullifier).second)
                    {
                        strError = strprintf(
                            "epoch %d IV5 active set contains duplicate/zero nullifier",
                            nEpoch);
                        return false;
                    }
                    state.vVNextEpochNullifiers.push_back(nullifier);
                }
                state.vchVNextNullifierState.swap(nextState);
                state.hashVNextNullifierRoot = uint256(nextRoot);
                state.nVNextNullifierCount = nextNullifierCount;
            }
        }

        std::vector<CFinalityTallyCertificate> vCerts;
        FinalityEnvelopeDecodeResult certEnvelopeFailure = FINALITY_ENVELOPE_NO_MATCH;
        if (!ExtractFinalityTallyCertificatesFromBlockForHeight(
                activeBlock, mi->second->nHeight, vCerts,
                &certEnvelopeFailure))
        {
            strError = strprintf("epoch %d block %s has invalid finality certificate envelope "
                                 "at height %d (decode=%d)",
                                 nEpoch, it->ToString().substr(0, 20).c_str(),
                                 mi->second->nHeight, (int)certEnvelopeFailure);
            return false;
        }
        for (std::vector<CFinalityTallyCertificate>::const_iterator cit = vCerts.begin();
             cit != vCerts.end(); ++cit)
        {
            if (cit->nEpoch != nEpoch)
                continue;
            if (!fHaveBestCert || FinalityCertificateOutranks(*cit, bestCert))
            {
                bestCert = *cit;
                fHaveBestCert = true;
            }
        }

        std::vector<CFinalityVote> vVotes;
        FinalityEnvelopeDecodeResult voteEnvelopeFailure = FINALITY_ENVELOPE_NO_MATCH;
        if (!ExtractFinalityVotesFromBlockForHeight(
                activeBlock, mi->second->nHeight, vVotes,
                &voteEnvelopeFailure))
        {
            strError = strprintf("epoch %d block %s has invalid finality vote envelope "
                                 "at height %d (decode=%d)",
                                 nEpoch, it->ToString().substr(0, 20).c_str(),
                                 mi->second->nHeight, (int)voteEnvelopeFailure);
            return false;
        }
        for (std::vector<CFinalityVote>::const_iterator vit = vVotes.begin();
             vit != vVotes.end(); ++vit)
        {
            if (vit->nEpoch == nEpoch)
                mapEpochVotes[vit->nullifier] = *vit;
        }

        if (fCommitNoteVotes)
        {
            std::vector<CNoteFinalityVote> vNoteVotes;
            FinalityEnvelopeDecodeResult noteEnvelopeFailure = FINALITY_ENVELOPE_NO_MATCH;
            if (!ExtractNoteFinalityVotesFromBlockForHeight(
                    activeBlock, mi->second->nHeight, vNoteVotes, &noteEnvelopeFailure))
            {
                strError = strprintf("epoch %d block %s has invalid note vote envelope "
                                     "at height %d (decode=%d)",
                                     nEpoch, it->ToString().substr(0, 20).c_str(),
                                     mi->second->nHeight, (int)noteEnvelopeFailure);
                return false;
            }
            for (size_t i = 0; i < vNoteVotes.size(); i++)
            {
                if (vNoteVotes[i].nEpoch == nEpoch)
                    vEpochNoteVotes.push_back(vNoteVotes[i]);
            }
        }
    }

    if (!epochCurveTree.IsEmpty() && !epochCurveTree.RebuildParentNodes())
    {
        strError = strprintf("epoch %d failed to rebuild curve-tree parents", nEpoch);
        return false;
    }
    state.hashCurveRoot = epochCurveTree.GetRoot();
    state.hashNullifierRoot = nullifierRootHasher.GetHash();

    CHashWriter voteSetHasher(SER_GETHASH, 0);
    voteSetHasher << std::string("Innova/IDAG/EpochVoteSetRoot/v1") << nEpoch;
    for (std::map<uint256, CFinalityVote>::const_iterator it = mapEpochVotes.begin();
         it != mapEpochVotes.end(); ++it)
        voteSetHasher << it->first << it->second.hashBlock;
    if (fCommitNoteVotes)
    {
        // Commit the counted note votes, not the carried ones: a tag counts iff every instance agrees,
        // so the result is order-independent.
        std::vector<const CNoteFinalityVote*> vCarried;
        vCarried.reserve(vEpochNoteVotes.size());
        for (size_t i = 0; i < vEpochNoteVotes.size(); i++)
            vCarried.push_back(&vEpochNoteVotes[i]);
        std::map<uint256, const CNoteFinalityVote*> mapCountedNoteVotes;
        std::set<uint256> setEquivocatedNoteVotes;
        ResolveNoteVoteCounting(vCarried, mapCountedNoteVotes, setEquivocatedNoteVotes);
        for (std::map<uint256, const CNoteFinalityVote*>::const_iterator it =
                 mapCountedNoteVotes.begin(); it != mapCountedNoteVotes.end(); ++it)
            voteSetHasher << it->first << it->second->hashBlock;
    }
    state.hashVoteSetRoot = voteSetHasher.GetHash();

    int nDetTier = FINALITY_NONE;
    if (fHaveBestCert)
    {
        nDetTier = bestCert.nTier;
        state.hashFinalityCertificate = bestCert.GetHash();
    }
    else
    {
        int64_t nEpochVoteWeight = 0;
        std::map<uint256, int64_t> mapBlockVoteWeight;
        std::set<CKeyID> setVoters;
        for (std::map<uint256, CFinalityVote>::const_iterator it = mapEpochVotes.begin();
             it != mapEpochVotes.end(); ++it)
        {
            const CFinalityVote& vote = it->second;
            if (vote.IsPrivate())
                continue;
            CPubKey pubkey(vote.vchPubKey);
            if (pubkey.IsValid())
                setVoters.insert(pubkey.GetID());
            if (vote.nVoteWeight <= 0)
                continue;
            if (nEpochVoteWeight <= MAX_MONEY - vote.nVoteWeight)
                nEpochVoteWeight += vote.nVoteWeight;
            else
                nEpochVoteWeight = MAX_MONEY;
            int64_t& nBlockWeight = mapBlockVoteWeight[vote.hashBlock];
            if (nBlockWeight <= MAX_MONEY - vote.nVoteWeight)
                nBlockWeight += vote.nVoteWeight;
            else
                nBlockWeight = MAX_MONEY;
        }
        if (nEpochVoteWeight > 0 && (int)setVoters.size() >= FINALITY_MIN_VOTERS)
        {
            uint256 hashWinner = 0;
            int64_t nWinnerWeight = 0;
            for (std::map<uint256, int64_t>::const_iterator it = mapBlockVoteWeight.begin();
                 it != mapBlockVoteWeight.end(); ++it)
            {
                if (it->second > nWinnerWeight ||
                    (it->second == nWinnerWeight && (hashWinner == 0 || it->first < hashWinner)))
                {
                    hashWinner = it->first;
                    nWinnerWeight = it->second;
                }
            }
            if (nWinnerWeight * 3 >= nEpochVoteWeight * 2)
                nDetTier = FINALITY_HARD;
            else if (nWinnerWeight * 2 > nEpochVoteWeight)
                nDetTier = FINALITY_SOFT;
            else if (nWinnerWeight * 3 >= nEpochVoteWeight)
                nDetTier = FINALITY_TENTATIVE;
        }
    }
    state.nFinalityTier = nDetTier;

    const int nPrevHardCount =
        (fHavePredecessor && prevState.nFinalityTier >= FINALITY_HARD)
            ? prevState.nConsecutiveHardCount : 0;
    state.nConsecutiveHardCount =
        (nDetTier >= FINALITY_HARD) ? nPrevHardCount + 1 : 0;
    state.nFinalizedHeightAsOf =
        fHavePredecessor ? prevState.nFinalizedHeightAsOf : 0;
    if (state.nConsecutiveHardCount >= FINALITY_CONFIRMATION_EPOCHS &&
        state.nHeightEnd > state.nFinalizedHeightAsOf)
        state.nFinalizedHeightAsOf = state.nHeightEnd;
    state.fFinalized = state.nHeightEnd > 0 &&
                       state.nFinalizedHeightAsOf >= state.nHeightEnd;
    state.nTxCount = -1;

    if (fBuildVNext)
    {
        state.nVNextFinalizedHeight = state.nFinalizedHeightAsOf;
        const CBlockIndex* pFinalized = pBoundary;
        while (pFinalized &&
               pFinalized->nHeight > state.nVNextFinalizedHeight)
            pFinalized = pFinalized->pprev;
        if (!pFinalized ||
            pFinalized->nHeight != state.nVNextFinalizedHeight ||
            !pFinalized->phashBlock)
        {
            strError = "IV5 finalized anchor is unavailable from epoch boundary";
            return false;
        }
        state.hashVNextFinalizedAnchor = pFinalized->GetBlockHash();

        CHashWriter activeSetHasher(SER_GETHASH, 0);
        activeSetHasher << std::string(
            "Innova/IV5/ActiveDAGTransactionSet/v1");
        activeSetHasher << state.hashBoundaryBlock << state.vBlockHashes;
        activeSetHasher << state.vVNextActiveBlockTxCounts;
        activeSetHasher << state.vVNextActiveTxIds;
        state.hashVNextActiveTxSet = activeSetHasher.GetHash();
    }

    stateOut = state;
    curveTreeOut = epochCurveTree;
    return true;
}

bool CDAGManager::WriteEpochState(CTxDB& txdb, int nEpoch)
{
    LOCK(cs_dag);

    auto it = mapEpochState.find(nEpoch);
    if (it == mapEpochState.end())
        return false;

    if (!txdb.WriteEpochState(nEpoch, it->second))
        return false;

    auto itTree = mapEpochCurveTrees.find(nEpoch);
    if (itTree != mapEpochCurveTrees.end())
    {
        if (!txdb.WriteCurveTreeAtEpoch(nEpoch, itTree->second))
            return false;
    }

    return true;
}

bool CDAGManager::WriteEpochState(CTxDB& txdb, const CEpochState& state,
                                  const CCurveTree& curveTree) const
{
    LOCK(cs_dag);
    if (state.nEpoch < 0 || state.hashBoundaryBlock == 0 ||
        state.nBlockCount < 0 || (size_t)state.nBlockCount != state.vBlockHashes.size())
        return false;

    CCurveTree checkedTree = curveTree;
    if (checkedTree.nLeafCount == 0)
    {
        if (state.hashCurveRoot != 0)
            return false;
    }
    else if (checkedTree.vLevels.empty() ||
             checkedTree.vLevels[0].size() != checkedTree.nLeafCount ||
             !checkedTree.RebuildParentNodes() ||
             checkedTree.GetRoot() != state.hashCurveRoot)
    {
        return false;
    }

    if (state.nSerVersion >= EPOCHSTATE_SER_VERSION_V4)
    {
        if (state.vchVNextTreeState.size() !=
                EPOCHSTATE_VNEXT_TREE_STATE_SIZE ||
            state.vchVNextNullifierState.size() !=
                EPOCHSTATE_VNEXT_NULLIFIER_STATE_SIZE ||
            state.vchVNextRoot.size() != EPOCHSTATE_VNEXT_DIGEST_SIZE ||
            state.vchVNextParameterDigest.size() !=
                EPOCHSTATE_VNEXT_DIGEST_SIZE ||
            state.hashVNextFinalizedAnchor == 0 ||
            state.hashVNextActiveTxSet == 0)
            return false;
        std::vector<unsigned char> checkedRoot;
        uint64_t checkedSize = 0;
        std::string treeError;
        if (!DecodePrivacyVNextTreeState(state.vchVNextTreeState,
                                         checkedRoot, checkedSize,
                                         treeError) ||
            checkedRoot != state.vchVNextRoot ||
            checkedSize != state.nVNextTreeSize)
            return false;
        std::vector<unsigned char> checkedNullifierRoot;
        uint64_t checkedNullifierCount = 0;
        if (!DecodePrivacyVNextNullifierState(
                state.vchVNextNullifierState, checkedNullifierRoot,
                checkedNullifierCount, treeError) ||
            uint256(checkedNullifierRoot) != state.hashVNextNullifierRoot ||
            checkedNullifierCount != state.nVNextNullifierCount ||
            state.vVNextEpochNullifiers.size() > checkedNullifierCount ||
            state.vVNextActiveBlockTxCounts.size() != state.vBlockHashes.size())
            return false;
        uint64_t nActiveTxCount = 0;
        for (std::vector<unsigned int>::const_iterator it =
                 state.vVNextActiveBlockTxCounts.begin();
             it != state.vVNextActiveBlockTxCounts.end(); ++it)
            nActiveTxCount += *it;
        if (nActiveTxCount != state.vVNextActiveTxIds.size())
            return false;
        std::set<uint256> checkedEpochNullifiers;
        for (std::vector<uint256>::const_iterator it =
                 state.vVNextEpochNullifiers.begin();
             it != state.vVNextEpochNullifiers.end(); ++it)
        {
            if (*it == 0 || !checkedEpochNullifiers.insert(*it).second)
                return false;
        }
        CHashWriter activeSetHasher(SER_GETHASH, 0);
        activeSetHasher << std::string(
            "Innova/IV5/ActiveDAGTransactionSet/v1");
        activeSetHasher << state.hashBoundaryBlock << state.vBlockHashes;
        activeSetHasher << state.vVNextActiveBlockTxCounts;
        activeSetHasher << state.vVNextActiveTxIds;
        if (activeSetHasher.GetHash() != state.hashVNextActiveTxSet)
            return false;
    }

    return txdb.WriteEpochState(state.nEpoch, state) &&
           txdb.WriteCurveTreeAtEpoch(state.nEpoch, curveTree);
}

bool CDAGManager::EraseEpochStateSuffix(CTxDB& txdb, int nFirstEpoch) const
{
    if (nFirstEpoch < 0 || !txdb.IsTxnActive())
    {
        printf("EraseEpochStateSuffix: FATAL invalid epoch %d or no active DB "
               "transaction; refusing non-atomic epoch-state deletion\n",
               nFirstEpoch);
        return false;
    }

    LOCK(cs_dag);

    // LevelDB is authoritative across restart; the live maps are derived caches and may
    // be incomplete. Discover and validate the committed namespaces before staging any
    // deletes, because the iterators read the committed database, not the pending batch.
    std::map<int, CEpochState> mapPersistedStates;
    std::map<int, CCurveTree> mapPersistedTrees;
    if (!txdb.IterateEpochStates(mapPersistedStates) ||
        !txdb.IterateCurveTreeEpochs(mapPersistedTrees))
    {
        printf("EraseEpochStateSuffix: FATAL unable to enumerate the durable "
               "epoch-state namespaces; refusing partial suffix deletion\n");
        return false;
    }

    if (mapPersistedStates.size() != mapPersistedTrees.size())
    {
        printf("EraseEpochStateSuffix: FATAL durable state/tree count mismatch "
               "(%d states, %d snapshots); refusing to repair consensus state "
               "implicitly\n", (int)mapPersistedStates.size(),
               (int)mapPersistedTrees.size());
        return false;
    }
    for (std::map<int, CEpochState>::const_iterator it =
             mapPersistedStates.begin();
         it != mapPersistedStates.end(); ++it)
    {
        if (!mapPersistedTrees.count(it->first))
        {
            printf("EraseEpochStateSuffix: FATAL durable epoch %d has no curve "
                   "snapshot; refusing implicit repair\n", it->first);
            return false;
        }
    }
    for (std::map<int, CCurveTree>::const_iterator it =
             mapPersistedTrees.begin();
         it != mapPersistedTrees.end(); ++it)
    {
        if (!mapPersistedStates.count(it->first))
        {
            printf("EraseEpochStateSuffix: FATAL durable curve snapshot %d has "
                   "no epoch state; refusing implicit repair\n", it->first);
            return false;
        }
    }

    if (mapEpochState.size() != mapEpochCurveTrees.size())
    {
        printf("EraseEpochStateSuffix: FATAL cached state/tree count mismatch "
               "(%d states, %d snapshots)\n", (int)mapEpochState.size(),
               (int)mapEpochCurveTrees.size());
        return false;
    }
    for (std::map<int, CEpochState>::const_iterator it = mapEpochState.begin();
         it != mapEpochState.end(); ++it)
    {
        if (!mapEpochCurveTrees.count(it->first))
        {
            printf("EraseEpochStateSuffix: FATAL cached epoch %d has no curve "
                   "snapshot\n", it->first);
            return false;
        }
    }

    std::set<int> setEpochs;
    for (std::map<int, CEpochState>::const_iterator it =
             mapPersistedStates.lower_bound(nFirstEpoch);
         it != mapPersistedStates.end(); ++it)
        setEpochs.insert(it->first);
    for (std::map<int, CCurveTree>::const_iterator it =
             mapPersistedTrees.lower_bound(nFirstEpoch);
         it != mapPersistedTrees.end(); ++it)
        setEpochs.insert(it->first);
    for (std::map<int, CEpochState>::const_iterator it = mapEpochState.lower_bound(nFirstEpoch);
         it != mapEpochState.end(); ++it)
        setEpochs.insert(it->first);
    for (std::map<int, CCurveTree>::const_iterator it = mapEpochCurveTrees.lower_bound(nFirstEpoch);
         it != mapEpochCurveTrees.end(); ++it)
        setEpochs.insert(it->first);
    for (std::set<int>::const_iterator it = setEpochs.begin(); it != setEpochs.end(); ++it)
    {
        if (!txdb.EraseEpochState(*it) || !txdb.EraseCurveTreeAtEpoch(*it))
        {
            printf("EraseEpochStateSuffix: FATAL failed to stage paired deletion "
                   "for epoch %d\n", *it);
            return false;
        }
    }
    return true;
}

static bool ValidateEpochStateBatchData(
    int nFirstEpoch, const std::map<int, CEpochState>& mapStates,
    const std::map<int, CCurveTree>& mapCurveTrees)
{
    if (nFirstEpoch < 0 || mapStates.size() != mapCurveTrees.size())
        return false;
    int nExpectedEpoch = nFirstEpoch;
    for (std::map<int, CEpochState>::const_iterator it = mapStates.begin();
         it != mapStates.end(); ++it, ++nExpectedEpoch)
    {
        std::map<int, CCurveTree>::const_iterator itTree = mapCurveTrees.find(it->first);
        if (it->first != nExpectedEpoch || it->second.nEpoch != it->first ||
            itTree == mapCurveTrees.end())
            return false;
        CCurveTree checkedTree = itTree->second;
        if (checkedTree.nLeafCount == 0)
        {
            if (it->second.hashCurveRoot != 0)
                return false;
        }
        else if (checkedTree.vLevels.empty() ||
                 checkedTree.vLevels[0].size() != checkedTree.nLeafCount ||
                 !checkedTree.RebuildParentNodes() ||
                 checkedTree.GetRoot() != it->second.hashCurveRoot)
            return false;
    }
    for (std::map<int, CCurveTree>::const_iterator it = mapCurveTrees.begin();
         it != mapCurveTrees.end(); ++it)
        if (!mapStates.count(it->first))
            return false;

    return true;
}

bool CDAGManager::ValidateEpochStateBatch(
    int nFirstEpoch,
    const std::map<int, CEpochState>& mapStates,
    const std::map<int, CCurveTree>& mapCurveTrees) const
{
    LOCK(cs_dag);
    return ValidateEpochStateBatchData(nFirstEpoch, mapStates, mapCurveTrees);
}

bool CDAGManager::InstallEpochStateBatch(
    int nFirstEpoch,
    const std::map<int, CEpochState>& mapStates,
    const std::map<int, CCurveTree>& mapCurveTrees)
{
    LOCK(cs_dag);
    if (!ValidateEpochStateBatchData(nFirstEpoch, mapStates, mapCurveTrees))
        return false;

    mapEpochState.erase(mapEpochState.lower_bound(nFirstEpoch), mapEpochState.end());
    mapEpochCurveTrees.erase(mapEpochCurveTrees.lower_bound(nFirstEpoch),
                             mapEpochCurveTrees.end());
    mapEpochState.insert(mapStates.begin(), mapStates.end());
    mapEpochCurveTrees.insert(mapCurveTrees.begin(), mapCurveTrees.end());

    setEpochBoundaryBlocks.clear();
    for (std::map<int, CEpochState>::const_iterator it = mapEpochState.begin();
         it != mapEpochState.end(); ++it)
        setEpochBoundaryBlocks.insert(it->second.hashBoundaryBlock);
    return true;
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

bool CDAGManager::TryGetDeterministicFinalizedHeight(int nUpToEpoch, int& nHeightOut) const
{
    LOCK(cs_dag);
    nHeightOut = 0;
    if (nUpToEpoch < 0)
        return true; // no completed epoch exists yet
    std::map<int, CEpochState>::const_iterator it = mapEpochState.find(nUpToEpoch);
    if (it == mapEpochState.end())
        return false;
    nHeightOut = it->second.nFinalizedHeightAsOf;
    return true;
}

bool CDAGManager::TryGetDeterministicFinalizedHeight(CTxDB& txdb, int nUpToEpoch,
                                                     int& nHeightOut) const
{
    nHeightOut = 0;
    if (nUpToEpoch < 0)
        return true;

    CEpochState state;
    if (!txdb.ReadEpochState(nUpToEpoch, state) || state.nEpoch != nUpToEpoch)
        return false;
    nHeightOut = state.nFinalizedHeightAsOf;
    return true;
}

int CDAGManager::GetDeterministicFinalizedHeight(int nUpToEpoch) const
{
    LOCK(cs_dag);
    for (int nEpoch = nUpToEpoch; nEpoch >= 0; --nEpoch)
    {
        std::map<int, CEpochState>::const_iterator it = mapEpochState.find(nEpoch);
        if (it != mapEpochState.end())
            return it->second.nFinalizedHeightAsOf;
    }
    return 0;
}

bool CDAGManager::GetFinalizedEpochStateAsOf(int nBlockHeight, CEpochState& stateOut) const
{
    LOCK(cs_dag);
    // Block-relative finalized epoch state: deterministic from the chain up to the
    // epoch preceding nBlockHeight's epoch (the latest fully-computed epoch), so a
    // block validates against the same finalized roots on every node.
    int nFinHeight = 0;
    if (!TryGetDeterministicFinalizedHeight(GetEpochForHeight(nBlockHeight) - 1,
                                            nFinHeight))
        return false;
    int nFinEpoch = GetEpochForHeight(nFinHeight);
    std::map<int, CEpochState>::const_iterator it = mapEpochState.find(nFinEpoch);
    if (it == mapEpochState.end())
        return false;
    stateOut = it->second;
    return true;
}

bool CDAGManager::GetFinalizedEpochStateAsOf(CTxDB& txdb, int nBlockHeight,
                                             CEpochState& stateOut) const
{
    bool fLocalFailure = false;
    return GetFinalizedEpochStateAsOf(txdb, nBlockHeight, stateOut,
                                      fLocalFailure);
}

// A miss is the chain's answer and reads the same on every node; anything else -- an
// I/O error, or bytes that will not decode -- is this node's own problem.
static bool EpochStateReadIsLocalFailure(CTxDB& txdb, int nEpoch)
{
    return txdb.ProbeEpochState(nEpoch) != TXDB_READ_NOT_FOUND;
}

bool CDAGManager::GetFinalizedEpochStateAsOf(CTxDB& txdb, int nBlockHeight,
                                             CEpochState& stateOut,
                                             bool& fLocalFailureOut) const
{
    fLocalFailureOut = false;
    const int nAsOfEpoch = GetEpochForHeight(nBlockHeight) - 1;
    int nFinHeight = 0;
    if (!TryGetDeterministicFinalizedHeight(txdb, nAsOfEpoch, nFinHeight))
    {
        fLocalFailureOut = EpochStateReadIsLocalFailure(txdb, nAsOfEpoch);
        return false;
    }

    const int nFinEpoch = GetEpochForHeight(nFinHeight);
    CEpochState state;
    if (!txdb.ReadEpochState(nFinEpoch, state) || state.nEpoch != nFinEpoch)
    {
        fLocalFailureOut = EpochStateReadIsLocalFailure(txdb, nFinEpoch);
        return false;
    }
    stateOut = state;
    return true;
}

bool ApplyPrivacyVNextPoolDelta(int64_t& nBalance, int64_t nDelta,
                                std::string& strErrorOut)
{
    strErrorOut.clear();
    if (nBalance < 0 || nBalance > MAX_MONEY)
    {
        strErrorOut = "the running IV5 pool balance is already out of range";
        return false;
    }
    if ((nDelta > 0 && nBalance > MAX_MONEY - nDelta) ||
        (nDelta < 0 && nBalance < std::numeric_limits<int64_t>::min() - nDelta))
    {
        strErrorOut = "the IV5 pool balance overflows";
        return false;
    }
    const int64_t nNext = nBalance + nDelta;
    if (nNext < 0)
    {
        strErrorOut = "takes more from the IV5 pool than it holds";
        return false;
    }
    if (nNext > MAX_MONEY)
    {
        strErrorOut = "the IV5 pool balance exceeds the money supply";
        return false;
    }
    nBalance = nNext;
    return true;
}

bool CDAGManager::GetFinalizedEpochStateAsOf(CTxDB& txdb, int nBlockHeight,
                                             int nEpochsBack,
                                             CEpochState& stateOut) const
{
    if (nEpochsBack < 0)
        return false;
    const int nAsOfEpoch = GetEpochForHeight(nBlockHeight) - 1;
    int nFinHeight = 0;
    if (!TryGetDeterministicFinalizedHeight(txdb, nAsOfEpoch, nFinHeight))
        return false;

    const int nFinEpoch = GetEpochForHeight(nFinHeight) - nEpochsBack;
    if (nFinEpoch < 0)
        return false;
    CEpochState state;
    if (!txdb.ReadEpochState(nFinEpoch, state) || state.nEpoch != nFinEpoch)
        return false;
    stateOut = state;
    return true;
}

bool CDAGManager::ValidateEpochStateTip(const CBlockIndex* pBest,
                                        std::string& strError) const
{
    LOCK(cs_dag);
    strError.clear();
    if (!pBest || !pBest->phashBlock)
    {
        strError = "best block index is missing";
        return false;
    }
    if (pBest->nHeight < FORK_HEIGHT_EPOCH_STATE_V3)
        return true;

    const int nActivationEpoch = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3);
    const int nMigrationEpoch = nActivationEpoch - 1;
    const int nTipEpoch = GetEpochForHeight(pBest->nHeight);
    const int nTipEpochEnd = GetEpochBoundaryHeight(nTipEpoch + 1, pBest->nHeight) - 1;
    const int nRequiredEpoch =
        (pBest->nHeight >= nTipEpochEnd) ? nTipEpoch : nTipEpoch - 1;

    if (nMigrationEpoch < 0 || nRequiredEpoch < nMigrationEpoch ||
        mapEpochState.empty() || mapEpochCurveTrees.empty())
    {
        strError = strprintf("V3 best height %d has no migration-base epoch state",
                             pBest->nHeight);
        return false;
    }
    if (mapEpochState.rbegin()->first != nRequiredEpoch ||
        mapEpochCurveTrees.rbegin()->first != nRequiredEpoch)
    {
        strError = strprintf("V3 best height %d requires highest completed epoch %d, "
                             "but state/tree persistence ends at %d/%d",
                             pBest->nHeight, nRequiredEpoch,
                             mapEpochState.rbegin()->first,
                             mapEpochCurveTrees.rbegin()->first);
        return false;
    }

    const auto canonicalAtHeight = [&](int nHeight) -> const CBlockIndex* {
        const CBlockIndex* pWalk = pBest;
        while (pWalk && pWalk->nHeight > nHeight)
        {
            if (!pWalk->pprev || pWalk->pprev->nHeight != pWalk->nHeight - 1)
                return NULL;
            pWalk = pWalk->pprev;
        }
        return (pWalk && pWalk->nHeight == nHeight) ? pWalk : NULL;
    };

    const int nEpochsToCheck[2] = { nMigrationEpoch, nRequiredEpoch };
    for (int i = 0; i < 2; ++i)
    {
        const int nEpoch = nEpochsToCheck[i];
        if (i == 1 && nEpoch == nEpochsToCheck[0])
            continue;
        std::map<int, CEpochState>::const_iterator itState = mapEpochState.find(nEpoch);
        std::map<int, CCurveTree>::const_iterator itTree = mapEpochCurveTrees.find(nEpoch);
        if (itState == mapEpochState.end() || itTree == mapEpochCurveTrees.end())
        {
            strError = strprintf("V3 epoch-state persistence is missing required epoch %d pair",
                                 nEpoch);
            return false;
        }
        const int nExpectedEnd = GetEpochBoundaryHeight(nEpoch + 1, pBest->nHeight) - 1;
        const CBlockIndex* pBoundary = canonicalAtHeight(nExpectedEnd);
        if (!pBoundary || !pBoundary->phashBlock ||
            itState->second.nHeightEnd != nExpectedEnd ||
            itState->second.hashBoundaryBlock != pBoundary->GetBlockHash())
        {
            strError = strprintf("epoch %d persisted boundary %s at height %d does not "
                                 "match hashBestChain's canonical boundary",
                                 nEpoch,
                                 itState->second.hashBoundaryBlock.ToString().substr(0, 20).c_str(),
                                 nExpectedEnd);
            return false;
        }
    }
    return true;
}

bool CDAGManager::GetLastFinalizedEpochState(CEpochState& stateOut,
                                             bool fRequireCurveRoot) const
{
    int nFinalizedEpoch = GetEpochForHeight(g_finalityTracker.GetFinalizedHeight());

    LOCK(cs_dag);

    for (int nEpoch = nFinalizedEpoch; nEpoch >= 0; nEpoch--)
    {
        std::map<int, CEpochState>::const_iterator it = mapEpochState.find(nEpoch);
        if (it == mapEpochState.end())
            continue;
        if (fRequireCurveRoot && it->second.hashCurveRoot == 0)
            continue;
        stateOut = it->second;
        return true;
    }

    return false;
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
// CDAGManager: DAGKNIGHT Adaptive Ordering
// ---------------------------------------------------------------------------

uint256 CDAGManager::GetDAGKnightSelectedParent(
    const std::vector<uint256>& vParents) const
{
    uint256 hashBest;
    uint256 nBestScore = 0;
    bool fBestPrimary = false;
    for (size_t i = 0; i < vParents.size(); ++i)
    {
        const uint256& hashParent = vParents[i];
        uint256 nParentScore = 0;
        std::map<uint256, CBlockDAGData>::const_iterator dit =
            mapDAGData.find(hashParent);
        if (dit != mapDAGData.end())
            nParentScore = dit->second.nDAGScore;
        else
        {
            std::map<uint256, CBlockIndex*>::const_iterator mi =
                mapBlockIndex.find(hashParent);
            if (mi != mapBlockIndex.end() && mi->second &&
                !(mi->second->nHeight >= FORK_HEIGHT_DAG &&
                  mi->second->IsProofOfStake()))
                nParentScore = mi->second->nChainTrust;
        }

        const bool fPrimary = (i == 0);
        if (hashBest == 0 || nParentScore > nBestScore ||
            (nParentScore == nBestScore && fPrimary && !fBestPrimary) ||
            (nParentScore == nBestScore && fPrimary == fBestPrimary &&
             hashParent < hashBest))
        {
            hashBest = hashParent;
            nBestScore = nParentScore;
            fBestPrimary = fPrimary;
        }
    }
    return hashBest;
}

bool CDAGManager::IsDAGAncestor(const uint256& hashAncestor,
                                const uint256& hashDescendant,
                                int nMaxDepth) const
{
    if (hashAncestor == hashDescendant)
        return true;
    std::map<uint256, CBlockIndex*>::const_iterator ai =
        mapBlockIndex.find(hashAncestor);
    std::map<uint256, CBlockIndex*>::const_iterator di =
        mapBlockIndex.find(hashDescendant);
    if (ai == mapBlockIndex.end() || di == mapBlockIndex.end() ||
        !ai->second || !di->second ||
        ai->second->nHeight >= di->second->nHeight)
        return false;

    const int nDescendantHeight = di->second->nHeight;
    std::queue<uint256> queue;
    std::set<uint256> visited;
    queue.push(hashDescendant);
    while (!queue.empty() &&
           visited.size() <= (size_t)DAGKNIGHT_MAX_ANCHOR_CANDIDATES)
    {
        const uint256 hash = queue.front();
        queue.pop();
        if (!visited.insert(hash).second)
            continue;
        std::map<uint256, CBlockIndex*>::const_iterator hi =
            mapBlockIndex.find(hash);
        if (hi != mapBlockIndex.end() && hi->second &&
            nDescendantHeight - hi->second->nHeight > nMaxDepth)
            continue;
        std::map<uint256, CBlockDAGData>::const_iterator dit =
            mapDAGData.find(hash);
        if (dit == mapDAGData.end())
            continue;
        for (std::vector<uint256>::const_iterator pit =
                 dit->second.vDAGParents.begin();
             pit != dit->second.vDAGParents.end(); ++pit)
        {
            if (*pit == hashAncestor)
                return true;
            if (!visited.count(*pit))
                queue.push(*pit);
        }
    }
    return false;
}

// The bounded past IsDAGAncestor compares against, materialised once per descendant.
// Same traversal as IsDAGAncestor (queue order, visited bound, height cut) without the
// early exit, so membership here equals that function's answer.
const std::set<uint256>& CDAGManager::GetBoundedPast(const uint256& hashDescendant,
                                                     int nDescendantHeight,
                                                     int nMaxDepth) const
{
    std::map<uint256, std::set<uint256> >::const_iterator cit =
        mapDAGKnightPastCache.find(hashDescendant);
    if (cit != mapDAGKnightPastCache.end())
        return cit->second;

    std::set<uint256> past;
    std::queue<uint256> queue;
    std::set<uint256> visited;
    queue.push(hashDescendant);
    while (!queue.empty() &&
           visited.size() <= (size_t)DAGKNIGHT_MAX_ANCHOR_CANDIDATES)
    {
        const uint256 hash = queue.front();
        queue.pop();
        if (!visited.insert(hash).second)
            continue;
        std::map<uint256, CBlockIndex*>::const_iterator hi =
            mapBlockIndex.find(hash);
        if (hi != mapBlockIndex.end() && hi->second &&
            nDescendantHeight - hi->second->nHeight > nMaxDepth)
            continue;
        std::map<uint256, CBlockDAGData>::const_iterator dit =
            mapDAGData.find(hash);
        if (dit == mapDAGData.end())
            continue;
        for (std::vector<uint256>::const_iterator pit =
                 dit->second.vDAGParents.begin();
             pit != dit->second.vDAGParents.end(); ++pit)
        {
            past.insert(*pit);
            if (!visited.count(*pit))
                queue.push(*pit);
        }
    }

    if (past.size() > DAGKNIGHT_PAST_SET_MAX)
    {
        setDAGKnightPastScratch.swap(past);
        return setDAGKnightPastScratch;
    }

    // A pure cache with no ordering role, so a wholesale drop is always admissible.
    if (mapDAGKnightPastCache.size() >= (size_t)DAGKNIGHT_PAST_CACHE_MAX)
        mapDAGKnightPastCache.clear();
    return mapDAGKnightPastCache.insert(
        std::make_pair(hashDescendant, past)).first->second;
}

// IsDAGAncestor over the bounded merge depth, answered from the cached past set.
bool CDAGManager::IsDAGAncestorWithinMergeDepth(const uint256& hashAncestor,
                                                const uint256& hashDescendant) const
{
    if (fDAGKnightUnoptimizedOrdering)
        return IsDAGAncestor(hashAncestor, hashDescendant, DAG_MERGE_DEPTH);

    if (hashAncestor == hashDescendant)
        return true;
    std::map<uint256, CBlockIndex*>::const_iterator ai =
        mapBlockIndex.find(hashAncestor);
    std::map<uint256, CBlockIndex*>::const_iterator di =
        mapBlockIndex.find(hashDescendant);
    if (ai == mapBlockIndex.end() || di == mapBlockIndex.end() ||
        !ai->second || !di->second ||
        ai->second->nHeight >= di->second->nHeight)
        return false;

    return GetBoundedPast(hashDescendant, di->second->nHeight,
                          DAG_MERGE_DEPTH).count(hashAncestor) != 0;
}

bool CDAGManager::CollectDAGKnightCandidates(
    const std::vector<uint256>& vParents,
    const uint256& hashSelectedParent,
    int nAnchorHeight,
    std::vector<uint256>& vCandidates,
    std::string& strError) const
{
    vCandidates.clear();
    strError.clear();
    std::queue<uint256> queue;
    for (std::vector<uint256>::const_iterator it = vParents.begin();
         it != vParents.end(); ++it)
        if (*it != hashSelectedParent)
            queue.push(*it);

    std::set<uint256> visited;
    const int nMinHeight = nAnchorHeight - DAG_MERGE_DEPTH;
    while (!queue.empty())
    {
        const uint256 hash = queue.front();
        queue.pop();
        if (!visited.insert(hash).second || hash == hashSelectedParent)
            continue;
        if (visited.size() > (size_t)DAGKNIGHT_MAX_ANCHOR_CANDIDATES)
        {
            strError = strprintf("DAGKNIGHT anchor merge set exceeds %d blocks",
                                 DAGKNIGHT_MAX_ANCHOR_CANDIDATES);
            vCandidates.clear();
            return false;
        }

        std::map<uint256, CBlockIndex*>::const_iterator mi =
            mapBlockIndex.find(hash);
        if (mi == mapBlockIndex.end() || !mi->second)
        {
            strError = "DAGKNIGHT anchor references unavailable merge history";
            vCandidates.clear();
            return false;
        }
        if (mi->second->nHeight < nMinHeight)
            continue;
        if (IsDAGAncestorWithinMergeDepth(hash, hashSelectedParent))
            continue;

        vCandidates.push_back(hash);
        std::map<uint256, CBlockDAGData>::const_iterator dit =
            mapDAGData.find(hash);
        if (dit == mapDAGData.end())
            continue;
        for (std::vector<uint256>::const_iterator pit =
                 dit->second.vDAGParents.begin();
             pit != dit->second.vDAGParents.end(); ++pit)
            if (!visited.count(*pit))
                queue.push(*pit);
    }

    std::sort(vCandidates.begin(), vCandidates.end(),
              [](const uint256& a, const uint256& b) {
                  std::map<uint256, CBlockIndex*>::const_iterator ai =
                      mapBlockIndex.find(a);
                  std::map<uint256, CBlockIndex*>::const_iterator bi =
                      mapBlockIndex.find(b);
                  const int ah = ai != mapBlockIndex.end() && ai->second
                                     ? ai->second->nHeight : -1;
                  const int bh = bi != mapBlockIndex.end() && bi->second
                                     ? bi->second->nHeight : -1;
                  return ah != bh ? ah < bh : a < b;
              });
    return true;
}

bool CDAGManager::CheckDAGKnightParentSet(
    const std::vector<uint256>& vParents, int nAnchorHeight,
    std::string& strError) const
{
    LOCK(cs_dag);
    if (vParents.empty())
    {
        strError = "DAGKNIGHT anchor has no primary parent";
        return false;
    }
    const uint256 hashSelected = GetDAGKnightSelectedParent(vParents);
    std::vector<uint256> vCandidates;
    return hashSelected != 0 &&
           CollectDAGKnightCandidates(vParents, hashSelected,
                                      nAnchorHeight, vCandidates, strError);
}

void CDAGManager::CacheDAGKnightAnchorState(
    const uint256& hashAnchor,
    const CDAGKnightAnchorState& state) const
{
    if (mapDAGKnightAnchorCache.size() >=
        (size_t)DAGKNIGHT_ANCHOR_CACHE_MAX)
    {
        int nAnchorHeight = 0;
        std::map<uint256, CBlockIndex*>::const_iterator ai =
            mapBlockIndex.find(hashAnchor);
        if (ai != mapBlockIndex.end() && ai->second)
            nAnchorHeight = ai->second->nHeight;
        const int nKeepHeight = nAnchorHeight - 2 * DAG_MERGE_DEPTH;
        for (std::map<uint256, CDAGKnightAnchorState>::iterator it =
                 mapDAGKnightAnchorCache.begin();
             it != mapDAGKnightAnchorCache.end() &&
             mapDAGKnightAnchorCache.size() >=
                 (size_t)(DAGKNIGHT_ANCHOR_CACHE_MAX / 2); )
        {
            std::map<uint256, CBlockIndex*>::const_iterator mi =
                mapBlockIndex.find(it->first);
            if (mi == mapBlockIndex.end() || !mi->second ||
                mi->second->nHeight < nKeepHeight)
                it = mapDAGKnightAnchorCache.erase(it);
            else
                ++it;
        }
        while (mapDAGKnightAnchorCache.size() >=
               (size_t)DAGKNIGHT_ANCHOR_CACHE_MAX)
            mapDAGKnightAnchorCache.erase(mapDAGKnightAnchorCache.begin());
    }
    mapDAGKnightAnchorCache[hashAnchor] = state;
}

bool CDAGManager::BuildDAGKnightAnchorState(
    const uint256& hashAnchor, CDAGKnightAnchorState& stateOut,
    std::string& strError) const
{
    std::map<uint256, CBlockDAGData>::const_iterator dit =
        mapDAGData.find(hashAnchor);
    std::map<uint256, CBlockIndex*>::const_iterator mi =
        mapBlockIndex.find(hashAnchor);
    if (dit == mapDAGData.end() || mi == mapBlockIndex.end() || !mi->second)
    {
        strError = "DAGKNIGHT anchor is unavailable";
        return false;
    }

    const CBlockDAGData& data = dit->second;
    stateOut = CDAGKnightAnchorState();
    if (data.vDAGParents.empty())
    {
        stateOut.nInferredK = DAGKNIGHT_K_FLOOR;
        stateOut.nScore = mi->second->GetBlockTrust();
        stateOut.vPressureSamples.push_back(DAGKNIGHT_K_FLOOR);
        stateOut.vBlueWindow.push_back(hashAnchor);
        stateOut.vOrderDelta.push_back(std::make_pair(hashAnchor, true));
        return true;
    }

    stateOut.hashSelectedParent =
        GetDAGKnightSelectedParent(data.vDAGParents);
    if (stateOut.hashSelectedParent == 0)
    {
        strError = "DAGKNIGHT selected parent is unavailable";
        return false;
    }

    const CDAGKnightAnchorState* pParentState = NULL;
    std::map<uint256, CBlockDAGData>::const_iterator pdit =
        mapDAGData.find(stateOut.hashSelectedParent);
    if (pdit != mapDAGData.end())
    {
        std::map<uint256, CDAGKnightAnchorState>::const_iterator psit =
            mapDAGKnightAnchorCache.find(stateOut.hashSelectedParent);
        if (psit == mapDAGKnightAnchorCache.end())
        {
            strError = "DAGKNIGHT selected-parent state is unavailable";
            return false;
        }
        pParentState = &psit->second;
        stateOut.nScore = pParentState->nScore;
        stateOut.vPressureSamples = pParentState->vPressureSamples;
        stateOut.vBlueWindow = pParentState->vBlueWindow;
    }
    else
    {
        std::map<uint256, CBlockIndex*>::const_iterator pi =
            mapBlockIndex.find(stateOut.hashSelectedParent);
        if (pi == mapBlockIndex.end() || !pi->second)
        {
            // Pruning retains the first surviving block's persisted cumulative
            // score/k as an authenticated local frontier while deleting older
            // DAG links and block indexes. Seed the disposable cache at that
            // frontier; descendants extend it without collapsing historical
            // work or requiring a chain/datadir reset.
            if (data.nDAGScore == 0 ||
                data.nInferredK < DAGKNIGHT_K_FLOOR ||
                data.nInferredK > DAGKNIGHT_K_CEILING)
            {
                strError = "DAGKNIGHT retained frontier lacks score/k state";
                return false;
            }
            stateOut.nScore = data.nDAGScore;
            stateOut.nInferredK = data.nInferredK;
            stateOut.vPressureSamples.push_back(
                (unsigned char)data.nInferredK);
            stateOut.vBlueWindow.push_back(hashAnchor);
            stateOut.vOrderDelta.push_back(
                std::make_pair(hashAnchor, true));
            return true;
        }
        if (pi->second->nHeight >= FORK_HEIGHT_DAG)
        {
            strError = "DAGKNIGHT selected-parent frontier is corrupt";
            return false;
        }
        stateOut.nScore = pi->second->nChainTrust;
    }

    std::vector<uint256> vCandidates;
    if (!CollectDAGKnightCandidates(data.vDAGParents,
                                    stateOut.hashSelectedParent,
                                    mi->second->nHeight,
                                    vCandidates, strError))
        return false;
    BlockProfileCount("dagk_candidates", (int64_t)vCandidates.size());
    BlockProfileCount("dagk_bluewindow", (int64_t)stateOut.vBlueWindow.size());

    // Anticone checks answer from the descendant's cached past, so each is a set lookup.
    int nPressure = 0;
    for (std::vector<uint256>::const_iterator cit = vCandidates.begin();
         cit != vCandidates.end(); ++cit)
    {
        int nAnticone = 0;
        for (std::vector<uint256>::const_iterator bit =
                 stateOut.vBlueWindow.begin();
             bit != stateOut.vBlueWindow.end(); ++bit)
        {
            if (!IsDAGAncestorWithinMergeDepth(*bit, *cit) &&
                !IsDAGAncestorWithinMergeDepth(*cit, *bit))
                ++nAnticone;
        }
        nPressure = std::max(nPressure, nAnticone);
    }
    int nSampleK = std::max(DAGKNIGHT_K_FLOOR,
                            std::min(DAGKNIGHT_K_CEILING,
                                     2 * nPressure + 1));
    stateOut.vPressureSamples.push_back((unsigned char)nSampleK);
    if (stateOut.vPressureSamples.size() >
        (size_t)DAGKNIGHT_K_SAMPLE_DEPTH)
        stateOut.vPressureSamples.erase(stateOut.vPressureSamples.begin());

    int nEMA = (int)stateOut.vPressureSamples[0] * 256;
    for (size_t i = 1; i < stateOut.vPressureSamples.size(); ++i)
        nEMA = ((256 - DAGKNIGHT_K_EMA_ALPHA) * nEMA +
                DAGKNIGHT_K_EMA_ALPHA *
                    (int)stateOut.vPressureSamples[i] * 256) / 256;
    stateOut.nInferredK = std::max(
        DAGKNIGHT_K_FLOOR,
        std::min(DAGKNIGHT_K_CEILING, (nEMA + 128) / 256));

    std::vector<std::pair<uint256, bool> > vColored;
    for (std::vector<uint256>::const_iterator cit = vCandidates.begin();
         cit != vCandidates.end(); ++cit)
    {
        int nAnticone = 0;
        for (std::vector<uint256>::const_iterator bit =
                 stateOut.vBlueWindow.begin();
             bit != stateOut.vBlueWindow.end(); ++bit)
        {
            if (!IsDAGAncestorWithinMergeDepth(*bit, *cit) &&
                !IsDAGAncestorWithinMergeDepth(*cit, *bit))
                ++nAnticone;
        }
        const bool fBlue = nAnticone <= stateOut.nInferredK;
        vColored.push_back(std::make_pair(*cit, fBlue));
        if (fBlue)
        {
            stateOut.vBlueWindow.push_back(*cit);
            std::map<uint256, CBlockIndex*>::const_iterator ci =
                mapBlockIndex.find(*cit);
            if (ci == mapBlockIndex.end() || !ci->second ||
                (ci->second->nHeight >= FORK_HEIGHT_DAG &&
                 !ci->second->IsProofOfWork()))
            {
                strError = "DAGKNIGHT candidate block index is invalid";
                return false;
            }
            stateOut.nScore = stateOut.nScore + ci->second->GetBlockTrust();
        }
    }

    std::sort(vColored.begin(), vColored.end(),
              [](const std::pair<uint256, bool>& a,
                 const std::pair<uint256, bool>& b) {
                  std::map<uint256, CBlockIndex*>::const_iterator ai =
                      mapBlockIndex.find(a.first);
                  std::map<uint256, CBlockIndex*>::const_iterator bi =
                      mapBlockIndex.find(b.first);
                  const int ah = ai != mapBlockIndex.end() && ai->second
                                     ? ai->second->nHeight : -1;
                  const int bh = bi != mapBlockIndex.end() && bi->second
                                     ? bi->second->nHeight : -1;
                  if (ah != bh) return ah < bh;
                  if (a.second != b.second) return a.second > b.second;
                  return a.first < b.first;
              });
    stateOut.vOrderDelta = vColored;
    stateOut.vOrderDelta.push_back(std::make_pair(hashAnchor, true));
    stateOut.vBlueWindow.push_back(hashAnchor);
    stateOut.nScore = stateOut.nScore + mi->second->GetBlockTrust();

    const int nMinBlueHeight =
        mi->second->nHeight - DAGKNIGHT_MAX_ANTICONE_WINDOW;
    std::vector<uint256> vBoundedBlue;
    std::set<uint256> setBlue;
    for (std::vector<uint256>::const_iterator it =
             stateOut.vBlueWindow.begin();
         it != stateOut.vBlueWindow.end(); ++it)
    {
        std::map<uint256, CBlockIndex*>::const_iterator bi =
            mapBlockIndex.find(*it);
        if (bi != mapBlockIndex.end() && bi->second &&
            bi->second->nHeight >= nMinBlueHeight &&
            setBlue.insert(*it).second)
            vBoundedBlue.push_back(*it);
    }
    stateOut.vBlueWindow.swap(vBoundedBlue);
    return true;
}

bool CDAGManager::EnsureDAGKnightAnchorState(
    const uint256& hashAnchor) const
{
    if (mapDAGKnightAnchorCache.count(hashAnchor))
        return true;

    std::vector<uint256> vBuild;
    std::set<uint256> setVisited;
    uint256 hash = hashAnchor;
    while (mapDAGData.count(hash) &&
           !mapDAGKnightAnchorCache.count(hash))
    {
        if (!setVisited.insert(hash).second)
            return false;
        vBuild.push_back(hash);
        std::map<uint256, CBlockDAGData>::const_iterator dit =
            mapDAGData.find(hash);
        if (dit->second.vDAGParents.empty())
            break;
        hash = GetDAGKnightSelectedParent(dit->second.vDAGParents);
        if (hash == 0)
            return false;
    }
    std::reverse(vBuild.begin(), vBuild.end());
    BlockProfileCount("dagk_states_built", (int64_t)vBuild.size());
    BlockProfileCount("dagk_ensure_calls", 1);
    for (std::vector<uint256>::const_iterator it = vBuild.begin();
         it != vBuild.end(); ++it)
    {
        CDAGKnightAnchorState state;
        std::string strError;
        if (!BuildDAGKnightAnchorState(*it, state, strError))
        {
            printf("EnsureDAGKnightAnchorState: %s for %s\n",
                   strError.c_str(), it->ToString().substr(0,20).c_str());
            return false;
        }
        CacheDAGKnightAnchorState(*it, state);
    }
    return mapDAGKnightAnchorCache.count(hashAnchor) != 0;
}

int CDAGManager::InferLocalK(const uint256& hashBlock) const
{
    if (!EnsureDAGKnightAnchorState(hashBlock))
        return 0;
    std::map<uint256, CDAGKnightAnchorState>::const_iterator it =
        mapDAGKnightAnchorCache.find(hashBlock);
    return it == mapDAGKnightAnchorCache.end() ? 0 : it->second.nInferredK;
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

    if (IsDAGAncestor(hashA, hashB, DAGKNIGHT_MAX_ANTICONE_WINDOW))
    {
        nConfidence = 1;
        return -1; // A precedes B
    }
    if (IsDAGAncestor(hashB, hashA, DAGKNIGHT_MAX_ANTICONE_WINDOW))
    {
        nConfidence = 1;
        return 1; // B precedes A
    }

    std::map<uint256, CBlockIndex*>::const_iterator ai = mapBlockIndex.find(hashA);
    std::map<uint256, CBlockIndex*>::const_iterator bi = mapBlockIndex.find(hashB);
    const int ah = ai != mapBlockIndex.end() && ai->second ? ai->second->nHeight : -1;
    const int bh = bi != mapBlockIndex.end() && bi->second ? bi->second->nHeight : -1;
    if (ah != bh)
    {
        nConfidence = abs(ah - bh);
        return ah < bh ? -1 : 1;
    }
    nConfidence = 0;
    return (hashA < hashB) ? -1 : 1;
}

bool CDAGManager::ColorBlockDAGKnight(CBlockIndex* pindex)
{
    LOCK(cs_dag);

    if (!pindex || !pindex->phashBlock)
        return false;
    if (pindex->nHeight >= FORK_HEIGHT_DAG && pindex->IsProofOfStake())
        return false;

    uint256 hash = pindex->GetBlockHash();
    auto it = mapDAGData.find(hash);
    if (it == mapDAGData.end())
        return false;

    mapDAGKnightAnchorCache.erase(hash);
    if (!EnsureDAGKnightAnchorState(hash))
        return false;
    std::map<uint256, CDAGKnightAnchorState>::const_iterator sit =
        mapDAGKnightAnchorCache.find(hash);
    if (sit == mapDAGKnightAnchorCache.end())
        return false;
    it->second.fBlue = true;
    it->second.nDAGScore = sit->second.nScore;
    it->second.nInferredK = sit->second.nInferredK;
    return true;
}

int CDAGManager::GetOrderConfidence(const uint256& hashBlock) const
{
    LOCK(cs_dag);

    auto it = mapDAGData.find(hashBlock);
    if (it == mapDAGData.end())
        return 0;

    return std::max(0, it->second.nInferredK);
}

bool CDAGManager::GetDAGKnightAnchorMetrics(
    const uint256& hashAnchor, uint256& hashSelectedParent,
    int& nInferredK, uint256& nScore,
    std::vector<std::pair<uint256, bool> >& vOrderColors) const
{
    LOCK(cs_dag);
    vOrderColors.clear();
    if (!EnsureDAGKnightAnchorState(hashAnchor))
        return false;

    std::vector<uint256> vChain;
    std::set<uint256> setChain;
    uint256 hash = hashAnchor;
    while (mapDAGData.count(hash) && setChain.insert(hash).second)
    {
        vChain.push_back(hash);
        std::map<uint256, CDAGKnightAnchorState>::const_iterator sit =
            mapDAGKnightAnchorCache.find(hash);
        if (sit == mapDAGKnightAnchorCache.end() ||
            sit->second.hashSelectedParent == 0)
            break;
        hash = sit->second.hashSelectedParent;
        if (!EnsureDAGKnightAnchorState(hash) && mapDAGData.count(hash))
            return false;
    }
    std::reverse(vChain.begin(), vChain.end());
    std::set<uint256> emitted;
    for (std::vector<uint256>::const_iterator it = vChain.begin();
         it != vChain.end(); ++it)
    {
        std::map<uint256, CDAGKnightAnchorState>::const_iterator sit =
            mapDAGKnightAnchorCache.find(*it);
        if (sit == mapDAGKnightAnchorCache.end())
            return false;
        for (std::vector<std::pair<uint256, bool> >::const_iterator oit =
                 sit->second.vOrderDelta.begin();
             oit != sit->second.vOrderDelta.end(); ++oit)
            if (emitted.insert(oit->first).second)
                vOrderColors.push_back(*oit);
    }

    std::map<uint256, CDAGKnightAnchorState>::const_iterator anchor =
        mapDAGKnightAnchorCache.find(hashAnchor);
    if (anchor == mapDAGKnightAnchorCache.end())
        return false;
    hashSelectedParent = anchor->second.hashSelectedParent;
    nInferredK = anchor->second.nInferredK;
    nScore = anchor->second.nScore;
    return true;
}
