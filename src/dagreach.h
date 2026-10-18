// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef INN_DAGREACH_H
#define INN_DAGREACH_H

#include "uint256.h"

#include <map>
#include <stdint.h>
#include <utility>
#include <vector>

// Reachability index over the DAG parent links: intervals on a spanning tree (first
// parent) plus future-covering sets. Its edge set is a superset of the live graph
// (removals are kept), so a negative answer is exact for the live graph.
class CDAGReachability
{
public:
    CDAGReachability() { Clear(); }

    void Clear();
    void MarkDirty() { fDirty = true; }
    bool IsDirty() const { return fDirty; }
    bool IsUsable() const { return !fDirty && fUsable; }
    size_t Size() const { return vNodes.size(); }

    // Appends a vertex. Falls back to MarkDirty when it cannot be placed in place.
    void AddVertex(const uint256& hash, const std::vector<uint256>& vParents);
    // The vertex's links are gone from the live graph; the index keeps them (superset).
    void NoteRemoved(const uint256& hash);
    // Rebuilds from (vertex, parents) pairs. Cyclic or unplaceable input leaves it unusable.
    void Rebuild(const std::vector<std::pair<uint256, const std::vector<uint256>*> >& vVertices);

    // True iff hashAncestor is reachable from hashDescendant through parent links
    // (or the two are equal). Only meaningful while IsUsable().
    bool IsReachable(const uint256& hashAncestor, const uint256& hashDescendant) const;

private:
    struct Node
    {
        uint64_t nStart;
        uint64_t nEnd;
        uint64_t nNext;
        int nTreeParent;
        bool fHasParents;
        std::vector<int> vParents;
        std::vector<int> vFCS; // sorted by nStart, pairwise disjoint intervals
    };

    std::vector<Node> vNodes; // [0] is the virtual root
    std::map<uint256, int> mapId;
    bool fDirty;
    bool fUsable;
    size_t nRemoved;

    int GetOrAdd(const uint256& hash);
    bool TreeAncestor(int a, int b) const;
    bool Reach(int a, int b) const;
    bool AllocChild(int p, int c);
    void AddCovering(int b);
};

#endif // INN_DAGREACH_H
