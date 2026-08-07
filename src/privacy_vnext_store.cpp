// Copyright (c) 2026 The Innova developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "privacy_vnext_store.h"

#include <cstring>
#include <map>
#include <utility>

#include "dag.h"
#include "main.h"
#include "txdb-leveldb.h"
#include "util.h"

namespace
{

const size_t VNEXT_TREE_LAYERS = 8;
const size_t VNEXT_LEAF_SIZE = 96;
const size_t VNEXT_POINT_SIZE = 32;
const size_t VNEXT_GROW_BATCH = 16;

// Branch width at one level, alternating Selene and Helios with the tree layout.
size_t VNextCapacity(size_t nLevel)
{
    return (nLevel % 2 == 0) ? 38 : 18;
}

struct VNextBranch
{
    uint64_t nStart;
    uint64_t nLength;
};

// Derive each level's branch for one target. Mirrors the layout the Rust witness verifies
// against, so a mistake here cannot forge a path: it produces one that fails to fold.
bool VNextPathGeometry(uint64_t nTreeSize, uint64_t nTarget,
                       VNextBranch* pGeometry)
{
    if (nTarget >= nTreeSize)
        return false;
    uint64_t nChildren = nTreeSize;
    uint64_t nNode = nTarget;
    for (size_t nLevel = 0; nLevel < VNEXT_TREE_LAYERS; ++nLevel)
    {
        const uint64_t nCapacity = static_cast<uint64_t>(VNextCapacity(nLevel));
        const uint64_t nStart = (nNode / nCapacity) * nCapacity;
        if (nStart >= nChildren)
            return false;
        pGeometry[nLevel].nStart = nStart;
        pGeometry[nLevel].nLength =
            std::min(nCapacity, nChildren - nStart);
        nNode /= nCapacity;
        nChildren = (nChildren + nCapacity - 1) / nCapacity;
    }
    return nChildren == 1 && nNode == 0;
}

// Number of nodes a level holds for a given leaf count.
uint64_t VNextLevelCount(uint64_t nTreeSize, size_t nLevel)
{
    uint64_t nCount = nTreeSize;
    for (size_t i = 0; i <= nLevel; ++i)
    {
        const uint64_t nCapacity = static_cast<uint64_t>(VNextCapacity(i));
        nCount = (nCount + nCapacity - 1) / nCapacity;
    }
    return nCount;
}

} // namespace

bool ReadPrivacyVNextTreeStoreSize(CTxDB& txdb, uint64_t& nSizeOut)
{
    nSizeOut = 0;
    if (!txdb.ReadPrivacyVNextTreeStoreSize(nSizeOut))
        nSizeOut = 0;
    return true;
}

bool GrowPrivacyVNextTreeStore(CTxDB& txdb,
                               const std::vector<PrivacyVNextOutputLeaf>& leaves,
                               std::vector<unsigned char>& treeState,
                               std::string& strErrorOut)
{
    strErrorOut.clear();
    if (leaves.empty())
        return true;

    // The frontier says where the tree is; the store must already be at the same place or
    // its leaf indices would not be the ones consensus assigned.
    std::vector<unsigned char> vchRoot;
    uint64_t nFrontierSize = 0;
    if (!DecodePrivacyVNextTreeState(treeState, vchRoot, nFrontierSize,
                                     strErrorOut))
        return false;
    uint64_t nStored = 0;
    if (!txdb.ReadPrivacyVNextTreeStoreSize(nStored))
        nStored = 0;
    if (nStored != nFrontierSize)
    {
        strErrorOut = strprintf(
            "IV5 tree store holds %" PRIu64 " leaves but the frontier is at %" PRIu64,
            nStored, nFrontierSize);
        return false;
    }

    uint64_t nNext = nFrontierSize;
    for (size_t nOffset = 0; nOffset < leaves.size(); nOffset += VNEXT_GROW_BATCH)
    {
        const size_t nBatch =
            std::min(VNEXT_GROW_BATCH, leaves.size() - nOffset);
        const std::vector<PrivacyVNextOutputLeaf> vBatch(
            leaves.begin() + nOffset, leaves.begin() + nOffset + nBatch);

        std::vector<unsigned char> nextState;
        std::vector<unsigned char> nextRoot;
        uint64_t nNextSize = 0;
        std::vector<PrivacyVNextTreeNode> vNodes;
        if (!ExtendPrivacyVNextOutputLeaves(treeState, vBatch, nextState,
                                            nextRoot, nNextSize, vNodes,
                                            strErrorOut))
            return false;
        if (nNextSize != nNext + nBatch)
        {
            strErrorOut = "IV5 tree store grew to an unexpected size";
            return false;
        }

        for (size_t i = 0; i < nBatch; ++i)
        {
            std::vector<unsigned char> vchLeaf;
            vchLeaf.reserve(VNEXT_LEAF_SIZE);
            vchLeaf.insert(vchLeaf.end(), vBatch[i].owner.begin(),
                           vBatch[i].owner.end());
            vchLeaf.insert(vchLeaf.end(), vBatch[i].nullifierBase.begin(),
                           vBatch[i].nullifierBase.end());
            vchLeaf.insert(vchLeaf.end(), vBatch[i].commitment.begin(),
                           vBatch[i].commitment.end());
            if (!txdb.WritePrivacyVNextTreeLeaf(nNext + i, vchLeaf))
            {
                strErrorOut = "could not persist an IV5 tree leaf";
                return false;
            }
        }
        for (size_t i = 0; i < vNodes.size(); ++i)
        {
            const std::vector<unsigned char> vchPoint(vNodes[i].point.begin(),
                                                      vNodes[i].point.end());
            if (!txdb.WritePrivacyVNextTreeNode(vNodes[i].nLevel,
                                                vNodes[i].nIndex, vchPoint))
            {
                strErrorOut = "could not persist an IV5 tree node";
                return false;
            }
        }

        treeState.swap(nextState);
        nNext = nNextSize;
    }

    if (!txdb.WritePrivacyVNextTreeStoreSize(nNext))
    {
        strErrorOut = "could not persist the IV5 tree store size";
        return false;
    }
    return true;
}

bool TrimPrivacyVNextTreeStore(CTxDB& txdb, uint64_t nNewSize,
                               const std::vector<unsigned char>& treeState,
                               std::string& strErrorOut)
{
    strErrorOut.clear();

    uint64_t nStored = 0;
    if (!txdb.ReadPrivacyVNextTreeStoreSize(nStored))
        nStored = 0;
    if (nNewSize > nStored)
    {
        strErrorOut = "IV5 tree store cannot be trimmed upward";
        return false;
    }
    if (nNewSize == nStored)
        return true;

    // Lower the recorded size before erasing anything. The size marker must never claim
    // data the store no longer holds, or a crash mid-trim leaves reads running off the end;
    // stale leaves left above it are harmless and a later append overwrites them.
    if (!txdb.WritePrivacyVNextTreeStoreSize(nNewSize))
    {
        strErrorOut = "could not lower the IV5 tree store size";
        return false;
    }

    for (uint64_t nIndex = nNewSize; nIndex < nStored; ++nIndex)
    {
        if (!txdb.ErasePrivacyVNextTreeLeaf(nIndex))
        {
            strErrorOut = "could not erase a trimmed IV5 tree leaf";
            return false;
        }
    }
    for (size_t nLevel = 0; nLevel + 1 < VNEXT_TREE_LAYERS; ++nLevel)
    {
        const uint64_t nKeep = VNextLevelCount(nNewSize, nLevel);
        const uint64_t nHad = VNextLevelCount(nStored, nLevel);
        for (uint64_t nIndex = nKeep; nIndex < nHad; ++nIndex)
        {
            if (!txdb.ErasePrivacyVNextTreeNode(static_cast<int>(nLevel), nIndex))
            {
                strErrorOut = "could not erase a trimmed IV5 tree node";
                return false;
            }
        }
    }

    // Appending only ever leaves the last node of each level partial, so restoring the
    // rightmost spine restores the whole tree. An empty extension reports exactly that
    // spine for the frontier the caller rolled back to.
    std::vector<unsigned char> nextState;
    std::vector<unsigned char> nextRoot;
    uint64_t nNextSize = 0;
    std::vector<PrivacyVNextTreeNode> vNodes;
    if (!ExtendPrivacyVNextOutputLeaves(treeState,
                                        std::vector<PrivacyVNextOutputLeaf>(),
                                        nextState, nextRoot, nNextSize, vNodes,
                                        strErrorOut))
        return false;
    if (nNextSize != nNewSize)
    {
        strErrorOut = "IV5 rollback frontier does not match the trimmed size";
        return false;
    }
    for (size_t i = 0; i < vNodes.size(); ++i)
    {
        const std::vector<unsigned char> vchPoint(vNodes[i].point.begin(),
                                                  vNodes[i].point.end());
        if (!txdb.WritePrivacyVNextTreeNode(vNodes[i].nLevel, vNodes[i].nIndex,
                                            vchPoint))
        {
            strErrorOut = "could not restore an IV5 tree node";
            return false;
        }
    }
    return true;
}

bool CollectPrivacyVNextEpochLeaves(
    const CEpochState& state,
    std::vector<PrivacyVNextOutputLeaf>& vLeavesOut,
    std::string& strErrorOut)
{
    vLeavesOut.clear();
    strErrorOut.clear();

    for (size_t t = 0; t < state.vVNextActiveTxIds.size(); ++t)
    {
        const uint256& hashTx = state.vVNextActiveTxIds[t];
        CTransaction tx;
        uint256 hashBlock;
        if (!GetTransaction(hashTx, tx, hashBlock))
        {
            strErrorOut = strprintf("IV5 epoch transaction %s is not retrievable",
                                    hashTx.ToString().substr(0, 20).c_str());
            return false;
        }
        if (!tx.IsPrivacyVNext() || !tx.privacyVNext.IsPresent())
            continue;

        PrivacyVNextStateEffects effects;
        const PrivacyVNextPayloadValidation validation =
            ExtractPrivacyVNextPayloadEffects(
                static_cast<uint32_t>(tx.nVersion),
                tx.privacyVNext.vchPayload, effects);
        if (!validation.IsValid())
        {
            strErrorOut = "IV5 epoch payload does not revalidate: " +
                          validation.strError;
            return false;
        }
        vLeavesOut.insert(vLeavesOut.end(), effects.outputLeaves.begin(),
                          effects.outputLeaves.end());
    }
    return true;
}

bool SyncPrivacyVNextTreeStore(CTxDB& txdb, int nThroughEpoch,
                               std::string& strErrorOut)
{
    strErrorOut.clear();
    if (nThroughEpoch < 0)
        return true;

    CEpochState target;
    if (!g_dagManager.GetEpochState(nThroughEpoch, target))
        return true;
    if (target.nSerVersion < EPOCHSTATE_SER_VERSION_V4)
        return true;

    uint64_t nStored = 0;
    if (!txdb.ReadPrivacyVNextTreeStoreSize(nStored))
        nStored = 0;
    if (nStored == target.nVNextTreeSize)
        return true;

    // Resume from the epoch boundary the store already sits on. A store that sits between
    // two boundaries cannot be resumed, so it is trimmed back to the last one it passed.
    int nResume = -1;
    uint64_t nResumeSize = 0;
    std::vector<unsigned char> resumeState;
    if (nStored > 0)
    {
        for (int nEpoch = nThroughEpoch; nEpoch >= 0; --nEpoch)
        {
            CEpochState state;
            if (!g_dagManager.GetEpochState(nEpoch, state) ||
                state.nSerVersion < EPOCHSTATE_SER_VERSION_V4)
                continue;
            if (state.nVNextTreeSize > nStored)
                continue;
            nResume = nEpoch;
            nResumeSize = state.nVNextTreeSize;
            resumeState = state.vchVNextTreeState;
            break;
        }
    }
    if (nResume < 0)
    {
        PrivacyVNextEpochSeed seed;
        if (!LoadPrivacyVNextEpochSeed(seed, strErrorOut))
            return false;
        resumeState = seed.vchTreeState;
        nResumeSize = 0;
    }
    if (nStored != nResumeSize &&
        !TrimPrivacyVNextTreeStore(txdb, nResumeSize, resumeState, strErrorOut))
        return false;

    std::vector<unsigned char> treeState = resumeState;
    for (int nEpoch = nResume + 1; nEpoch <= nThroughEpoch; ++nEpoch)
    {
        CEpochState state;
        if (!g_dagManager.GetEpochState(nEpoch, state) ||
            state.nSerVersion < EPOCHSTATE_SER_VERSION_V4)
            continue;

        std::vector<PrivacyVNextOutputLeaf> vLeaves;
        if (!CollectPrivacyVNextEpochLeaves(state, vLeaves, strErrorOut))
            return false;
        if (!GrowPrivacyVNextTreeStore(txdb, vLeaves, treeState, strErrorOut))
            return false;
        if (treeState != state.vchVNextTreeState)
        {
            strErrorOut = strprintf(
                "IV5 tree store replay of epoch %d does not reproduce the epoch frontier",
                nEpoch);
            return false;
        }
    }

    uint64_t nFinal = 0;
    if (!txdb.ReadPrivacyVNextTreeStoreSize(nFinal))
        nFinal = 0;
    if (nFinal != target.nVNextTreeSize)
    {
        strErrorOut = strprintf(
            "IV5 tree store reached %" PRIu64 " leaves but epoch %d records %" PRIu64,
            nFinal, nThroughEpoch, target.nVNextTreeSize);
        return false;
    }
    return true;
}

bool ReadPrivacyVNextTreePaths(CTxDB& txdb, uint64_t nTreeSize,
                               const std::vector<unsigned char>& vchTreeState,
                               const std::vector<uint64_t>& vTargetLeafIndexes,
                               std::vector<unsigned char>& vchPathsOut,
                               std::string& strErrorOut)
{
    vchPathsOut.clear();
    strErrorOut.clear();
    if (vTargetLeafIndexes.empty())
    {
        strErrorOut = "IV5 path read needs at least one target";
        return false;
    }

    uint64_t nStored = 0;
    if (!txdb.ReadPrivacyVNextTreeStoreSize(nStored))
        nStored = 0;
    if (nStored < nTreeSize)
    {
        strErrorOut = strprintf(
            "IV5 tree store holds %" PRIu64 " leaves but the witness needs %" PRIu64,
            nStored, nTreeSize);
        return false;
    }

    // An empty extension of the anchor frontier reports that frontier's spine: one node
    // per level, exactly the nodes a later append would have overwritten in the store.
    std::map<std::pair<int, uint64_t>, std::vector<unsigned char> > mapFrontier;
    {
        std::vector<unsigned char> nextState;
        std::vector<unsigned char> nextRoot;
        uint64_t nNextSize = 0;
        std::vector<PrivacyVNextTreeNode> vSpine;
        if (!ExtendPrivacyVNextOutputLeaves(
                vchTreeState, std::vector<PrivacyVNextOutputLeaf>(), nextState,
                nextRoot, nNextSize, vSpine, strErrorOut))
            return false;
        if (nNextSize != nTreeSize)
        {
            strErrorOut = strprintf(
                "IV5 anchor frontier is at %" PRIu64 " but the witness needs %" PRIu64,
                nNextSize, nTreeSize);
            return false;
        }
        for (size_t i = 0; i < vSpine.size(); ++i)
            mapFrontier[std::make_pair((int)vSpine[i].nLevel, vSpine[i].nIndex)]
                .assign(vSpine[i].point.begin(), vSpine[i].point.end());
    }

    for (size_t t = 0; t < vTargetLeafIndexes.size(); ++t)
    {
        VNextBranch geometry[VNEXT_TREE_LAYERS];
        if (!VNextPathGeometry(nTreeSize, vTargetLeafIndexes[t], geometry))
        {
            strErrorOut = "IV5 witness target is outside the tree";
            return false;
        }

        for (uint64_t i = 0; i < geometry[0].nLength; ++i)
        {
            std::vector<unsigned char> vchLeaf;
            if (!txdb.ReadPrivacyVNextTreeLeaf(geometry[0].nStart + i, vchLeaf) ||
                vchLeaf.size() != VNEXT_LEAF_SIZE)
            {
                strErrorOut = strprintf("IV5 tree store is missing leaf %" PRIu64,
                                        geometry[0].nStart + i);
                return false;
            }
            vchPathsOut.insert(vchPathsOut.end(), vchLeaf.begin(), vchLeaf.end());
        }
        for (size_t nLevel = 1; nLevel < VNEXT_TREE_LAYERS; ++nLevel)
        {
            for (uint64_t i = 0; i < geometry[nLevel].nLength; ++i)
            {
                const std::pair<int, uint64_t> key(
                    static_cast<int>(nLevel - 1), geometry[nLevel].nStart + i);
                std::map<std::pair<int, uint64_t>,
                         std::vector<unsigned char> >::const_iterator itFrontier =
                    mapFrontier.find(key);
                if (itFrontier != mapFrontier.end() &&
                    itFrontier->second.size() == VNEXT_POINT_SIZE)
                {
                    vchPathsOut.insert(vchPathsOut.end(),
                                       itFrontier->second.begin(),
                                       itFrontier->second.end());
                    continue;
                }
                std::vector<unsigned char> vchPoint;
                if (!txdb.ReadPrivacyVNextTreeNode(
                        static_cast<int>(nLevel - 1),
                        geometry[nLevel].nStart + i, vchPoint) ||
                    vchPoint.size() != VNEXT_POINT_SIZE)
                {
                    strErrorOut = strprintf(
                        "IV5 tree store is missing node %u/%" PRIu64,
                        static_cast<unsigned>(nLevel - 1),
                        geometry[nLevel].nStart + i);
                    return false;
                }
                vchPathsOut.insert(vchPathsOut.end(), vchPoint.begin(),
                                   vchPoint.end());
            }
        }
    }
    return true;
}
