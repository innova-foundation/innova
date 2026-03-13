// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_DAG_H
#define INN_DAG_H

#include "uint256.h"
#include "serialize.h"
#include "sync.h"
#include "script.h"

#include <vector>
#include <map>
#include <set>
#include <stdint.h>

class CBlockIndex;
class CTxDB;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

static const int MAX_DAG_PARENTS = 8;           // max parents per block (1 primary + 7 merge)
static const unsigned char DAG_PARENT_TAG[4] = { 0x49, 0x44, 0x41, 0x47 }; // "IDAG"
static const int GHOSTDAG_K = 3;                // anticone tolerance for blue coloring
static const int DAG_MERGE_DEPTH = 10;          // merge parents within this depth of primary
static const int DAG_PRUNE_DEPTH = 10000;       // prune DAG data older than this


// ---------------------------------------------------------------------------
// DAG Parent Commitment (coinbase OP_RETURN)
// ---------------------------------------------------------------------------

/** Compute hash of DAG parent list for validation */
uint256 ComputeDAGParentsHash(const std::vector<uint256>& vParents);

/** Extract DAG parent hashes from a coinbase OP_RETURN output.
 *  Returns empty vector if no DAG commitment found. */
std::vector<uint256> ExtractDAGParents(const CScript& scriptCoinbase);

/** Build a coinbase OP_RETURN script committing to DAG parents.
 *  Format: OP_RETURN <IDAG tag(4) || count(1) || hash1(32) || hash2(32) || ...> */
CScript BuildDAGParentScript(const std::vector<uint256>& vParents);


// ---------------------------------------------------------------------------
// Per-block DAG metadata (memory only — persisted separately via LevelDB)
// ---------------------------------------------------------------------------

struct CBlockDAGData
{
    std::vector<uint256> vDAGParents;    // parent block hashes (index 0 = primary parent)
    std::vector<uint256> vDAGChildren;   // children that reference this block as parent
    bool fBlue;                          // GHOSTDAG blue/red coloring
    uint256 nDAGScore;                   // cumulative blue-set trust score
    int nDAGOrder;                       // position in GHOSTDAG linear order

    CBlockDAGData()
    {
        fBlue = true;
        nDAGScore = 0;
        nDAGOrder = -1;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vDAGParents);
        READWRITE(vDAGChildren);
        READWRITE(fBlue);
        READWRITE(nDAGScore);
        READWRITE(nDAGOrder);
    )
};


// ---------------------------------------------------------------------------
// DAG Manager — holds all DAG state, drives GHOSTDAG coloring + ordering
// ---------------------------------------------------------------------------

class CDAGManager
{
public:
    mutable CCriticalSection cs_dag;

    CDAGManager() {}

    /** Initialize DAG data for a newly accepted block.
     *  Must be called under cs_main. Sets parents, registers children, updates tips. */
    bool InitBlockDAGData(CBlockIndex* pindex, const std::vector<uint256>& vParents);

    /** Get current DAG tips (blocks with no children). */
    std::vector<uint256> GetDAGTips() const;

    /** Select the best DAG tip using GHOSTDAG score. */
    CBlockIndex* SelectBestDAGTip() const;

    /** Get GHOSTDAG linear ordering from a given tip back to genesis. */
    std::vector<uint256> GetDAGLinearOrder(const uint256& hashTip) const;

    /** Compute DAG score for a block: sum of GetBlockTrust() for all blue ancestors. */
    uint256 ComputeDAGScore(CBlockIndex* pindex);

    /** GHOSTDAG blue-set coloring for a block. */
    void ColorBlock(CBlockIndex* pindex);

    /** Write DAG links for a block to LevelDB. */
    bool WriteDAGLinks(CTxDB& txdb, const uint256& hash);

    /** Load all DAG links from LevelDB into memory. */
    bool LoadDAGLinks(CTxDB& txdb);

    /** Rebuild GHOSTDAG ordering from loaded data. */
    void RebuildDAGOrder();

    /** Check if a block has DAG data. */
    bool HasDAGData(const uint256& hash) const;

    /** Get DAG data for a block (NULL if not found). */
    const CBlockDAGData* GetDAGData(const uint256& hash) const;

    /** Get the set of blocks that are DAG siblings of a given block
     *  (blocks at similar height that share some parents). */
    std::set<uint256> GetDAGSiblingBlocks(const uint256& hashBlock) const;

    /** Get the selected parent (highest-scoring parent) of a block. */
    uint256 GetSelectedParent(const uint256& hashBlock) const;

private:
    std::map<uint256, CBlockDAGData> mapDAGData;
    std::set<uint256> setDAGTips;

    /** Internal: get anticone of block X relative to a blue set */
    int AnticoneSize(const uint256& hashBlock, const std::set<uint256>& blueSet) const;

    /** Internal: collect blue set reachable from a block */
    std::set<uint256> GetBlueSet(const uint256& hashBlock) const;

    /** Internal: get all blocks reachable from a hash (bounded by depth) */
    std::set<uint256> GetPastSet(const uint256& hashBlock, int nMaxDepth) const;
};


extern CDAGManager g_dagManager;


#endif // INN_DAG_H
