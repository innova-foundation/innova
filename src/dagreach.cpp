// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "dagreach.h"

#include <algorithm>
#include <set>

static const uint64_t REACH_INTERVAL_MAX = (uint64_t)1 << 62;
static const size_t REACH_REMOVED_COMPACT = 4096;

void CDAGReachability::Clear()
{
    vNodes.clear();
    mapId.clear();
    Node root;
    root.nStart = 0;
    root.nEnd = REACH_INTERVAL_MAX;
    root.nNext = 1;
    root.nTreeParent = -1;
    root.fHasParents = false;
    vNodes.push_back(root);
    fDirty = false;
    fUsable = true;
    nRemoved = 0;
}

int CDAGReachability::GetOrAdd(const uint256& hash)
{
    std::map<uint256, int>::iterator it = mapId.find(hash);
    if (it != mapId.end())
        return it->second;
    Node node;
    node.nStart = node.nEnd = node.nNext = 0;
    node.nTreeParent = 0;
    node.fHasParents = false;
    vNodes.push_back(node);
    const int id = (int)vNodes.size() - 1;
    mapId[hash] = id;
    return id;
}

bool CDAGReachability::TreeAncestor(int a, int b) const
{
    return vNodes[a].nStart <= vNodes[b].nStart && vNodes[b].nEnd <= vNodes[a].nEnd;
}

bool CDAGReachability::Reach(int a, int b) const
{
    if (a == b || TreeAncestor(a, b))
        return true;
    const std::vector<int>& vFCS = vNodes[a].vFCS;
    // Last covering entry starting at or before b; disjoint intervals make it the only candidate.
    size_t lo = 0, hi = vFCS.size();
    while (lo < hi)
    {
        const size_t mid = (lo + hi) / 2;
        if (vNodes[vFCS[mid]].nStart <= vNodes[b].nStart)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo > 0 && TreeAncestor(vFCS[lo - 1], b);
}

bool CDAGReachability::AllocChild(int p, int c)
{
    Node& parent = vNodes[p];
    if (parent.nNext > parent.nEnd)
        return false;
    const uint64_t nRem = parent.nEnd - parent.nNext + 1;
    const uint64_t nSize = nRem - nRem / 4;
    Node& child = vNodes[c];
    child.nStart = parent.nNext;
    child.nEnd = parent.nNext + nSize - 1;
    child.nNext = child.nStart + 1;
    parent.nNext += nSize;
    return true;
}

// Adds b to the covering set of every block in its past that the tree parent does not reach.
void CDAGReachability::AddCovering(int b)
{
    const int tp = vNodes[b].nTreeParent;
    std::vector<int> vStack;
    std::set<int> setSeen;
    for (size_t i = 0; i < vNodes[b].vParents.size(); i++)
        if (vNodes[b].vParents[i] != tp)
            vStack.push_back(vNodes[b].vParents[i]);
    while (!vStack.empty())
    {
        const int x = vStack.back();
        vStack.pop_back();
        if (!setSeen.insert(x).second)
            continue;
        if (Reach(x, tp) || Reach(x, b))
            continue;
        std::vector<int>& vFCS = vNodes[x].vFCS;
        std::vector<int>::iterator pos = vFCS.begin();
        while (pos != vFCS.end() && vNodes[*pos].nStart < vNodes[b].nStart)
            ++pos;
        vFCS.insert(pos, b);
        for (size_t i = 0; i < vNodes[x].vParents.size(); i++)
            vStack.push_back(vNodes[x].vParents[i]);
    }
}

void CDAGReachability::AddVertex(const uint256& hash, const std::vector<uint256>& vParents)
{
    if (fDirty)
        return;
    std::map<uint256, int>::iterator it = mapId.find(hash);
    if (it != mapId.end())
    {
        // A re-added vertex with the same links adds no edge; anything else is a new edge.
        const Node& node = vNodes[it->second];
        bool fSame = node.fHasParents == !vParents.empty() && node.vParents.size() == vParents.size();
        for (size_t i = 0; fSame && i < vParents.size(); i++)
        {
            std::map<uint256, int>::const_iterator pit = mapId.find(vParents[i]);
            fSame = pit != mapId.end() && pit->second == node.vParents[i];
        }
        if (!fSame)
            fDirty = true;
        return;
    }
    if (vParents.empty())
    {
        const int id = GetOrAdd(hash);
        if (!AllocChild(0, id))
            fDirty = true;
        return;
    }
    std::vector<int> vIds;
    vIds.reserve(vParents.size());
    for (size_t i = 0; i < vParents.size(); i++)
    {
        const bool fKnown = mapId.count(vParents[i]) != 0;
        const int pid = GetOrAdd(vParents[i]);
        if (!fKnown && !AllocChild(0, pid))
        {
            fDirty = true;
            return;
        }
        vIds.push_back(pid);
    }
    const int id = GetOrAdd(hash);
    vNodes[id].fHasParents = true;
    vNodes[id].vParents = vIds;
    vNodes[id].nTreeParent = vIds[0];
    if (!AllocChild(vIds[0], id))
    {
        fDirty = true;
        return;
    }
    AddCovering(id);
}

void CDAGReachability::NoteRemoved(const uint256& hash)
{
    if (fDirty || !mapId.count(hash))
        return;
    if (++nRemoved > REACH_REMOVED_COMPACT && nRemoved > vNodes.size() / 2)
        fDirty = true;
}

void CDAGReachability::Rebuild(const std::vector<std::pair<uint256, const std::vector<uint256>*> >& vVertices)
{
    Clear();
    fUsable = false;
    for (size_t i = 0; i < vVertices.size(); i++)
        GetOrAdd(vVertices[i].first);
    for (size_t i = 0; i < vVertices.size(); i++)
    {
        const std::vector<uint256>& vParents = *vVertices[i].second;
        std::vector<int> vIds;
        for (size_t p = 0; p < vParents.size(); p++)
            vIds.push_back(GetOrAdd(vParents[p]));
        const int id = mapId[vVertices[i].first];
        vNodes[id].vParents = vIds;
        vNodes[id].fHasParents = !vIds.empty();
        vNodes[id].nTreeParent = vIds.empty() ? 0 : vIds[0];
    }

    // Topological order, parents first.
    const int n = (int)vNodes.size();
    std::vector<int> vPending(n, 0);
    std::vector<std::vector<int> > vChildren(n);
    for (int id = 1; id < n; id++)
    {
        std::set<int> setDistinct(vNodes[id].vParents.begin(), vNodes[id].vParents.end());
        vPending[id] = (int)setDistinct.size();
        for (std::set<int>::const_iterator it = setDistinct.begin(); it != setDistinct.end(); ++it)
            vChildren[*it].push_back(id);
    }
    std::vector<int> vOrder;
    vOrder.reserve(n);
    for (int id = 1; id < n; id++)
        if (vPending[id] == 0)
            vOrder.push_back(id);
    for (size_t i = 0; i < vOrder.size(); i++)
        for (size_t c = 0; c < vChildren[vOrder[i]].size(); c++)
            if (--vPending[vChildren[vOrder[i]][c]] == 0)
                vOrder.push_back(vChildren[vOrder[i]][c]);
    if ((int)vOrder.size() != n - 1)
        return;

    // Tree intervals sized by subtree, one share left free at each node for later children.
    std::vector<uint64_t> vSize(n, 1);
    std::vector<std::vector<int> > vTreeChildren(n);
    for (size_t i = vOrder.size(); i-- > 0; )
    {
        const int id = vOrder[i];
        vSize[vNodes[id].nTreeParent] += vSize[id];
    }
    for (size_t i = 0; i < vOrder.size(); i++)
        vTreeChildren[vNodes[vOrder[i]].nTreeParent].push_back(vOrder[i]);
    std::vector<int> vTop(1, 0);
    for (size_t i = 0; i < vOrder.size(); i++)
        vTop.push_back(vOrder[i]);
    for (size_t i = 0; i < vTop.size(); i++)
    {
        Node& node = vNodes[vTop[i]];
        const std::vector<int>& vKids = vTreeChildren[vTop[i]];
        if (vKids.empty())
            continue;
        const uint64_t nCap = node.nEnd - node.nStart;
        const uint64_t nUnit = nCap / vSize[vTop[i]];
        if (nUnit == 0)
            return;
        for (size_t k = 0; k < vKids.size(); k++)
        {
            Node& child = vNodes[vKids[k]];
            child.nStart = node.nNext;
            child.nEnd = node.nNext + nUnit * vSize[vKids[k]] - 1;
            child.nNext = child.nStart + 1;
            node.nNext = child.nEnd + 1;
        }
    }

    for (size_t i = 0; i < vOrder.size(); i++)
        if (vNodes[vOrder[i]].fHasParents)
            AddCovering(vOrder[i]);
    fUsable = true;
}

bool CDAGReachability::IsReachable(const uint256& hashAncestor, const uint256& hashDescendant) const
{
    if (hashAncestor == hashDescendant)
        return true;
    std::map<uint256, int>::const_iterator ai = mapId.find(hashAncestor);
    std::map<uint256, int>::const_iterator di = mapId.find(hashDescendant);
    if (ai == mapId.end() || di == mapId.end())
        return false;
    return Reach(ai->second, di->second);
}
