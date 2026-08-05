// Copyright (c) 2026 The Innova developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "privacy_vnext_store.h"

#include <cstring>

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

    if (!txdb.WritePrivacyVNextTreeStoreSize(nNewSize))
    {
        strErrorOut = "could not persist the trimmed IV5 tree store size";
        return false;
    }
    return true;
}

bool ReadPrivacyVNextTreePaths(CTxDB& txdb, uint64_t nTreeSize,
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
    if (nStored != nTreeSize)
    {
        strErrorOut = strprintf(
            "IV5 tree store holds %" PRIu64 " leaves but the witness needs %" PRIu64,
            nStored, nTreeSize);
        return false;
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
