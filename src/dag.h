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

static const int MAX_DAG_PARENTS = 32;          // max parents per block (1 primary + 31 merge)
static const unsigned char DAG_PARENT_TAG[4] = { 0x49, 0x44, 0x41, 0x47 }; // "IDAG"
static const int GHOSTDAG_K = 18;               // anticone tolerance for blue coloring (pre-DAGKNIGHT)
static const int DAG_MERGE_DEPTH = 64;          // merge parents within this depth of primary (~64s at 1s blocks)
static const int DAG_PRUNE_DEPTH = 100000;      // prune DAG data older than this (~28h at 1s blocks)

// IDAG Phase 4: DAGKNIGHT adaptive ordering constants
static const int DAGKNIGHT_MAX_ANTICONE_WINDOW = 64;  // max window for adaptive k estimation
static const int DAGKNIGHT_MIN_CONFIDENCE = 3;         // min supporting mass difference for confident ordering
static const int DAGKNIGHT_K_SAMPLE_DEPTH = 16;        // blocks to sample for k inference

// DAGKNIGHT k calibration bounds
// Floor: minimum k to tolerate network jitter at 1s block intervals
// Ceiling: maximum k to prevent overly permissive blue sets under attack
// At 1s blocks with ~2s propagation delay, expected parallelism ~2-3 blocks
// k should be at least 2x expected parallelism for safety margin
static const int DAGKNIGHT_K_FLOOR = 3;                // min inferred k (1s blocks, low latency)
static const int DAGKNIGHT_K_CEILING = 32;             // max inferred k (caps attack surface)
// Exponential moving average smoothing factor for k calibration (fixed-point, /256)
static const int DAGKNIGHT_K_EMA_ALPHA = 64;           // ~25% weight to new sample


// ---------------------------------------------------------------------------
// DAG Parent Commitment (coinbase OP_RETURN)
// ---------------------------------------------------------------------------

/** Extract DAG parent hashes from a coinbase OP_RETURN output.
 *  Returns empty vector if no DAG commitment found. */
std::vector<uint256> ExtractDAGParents(const CScript& scriptCoinbase);

/** Build a coinbase OP_RETURN script committing to DAG parents.
 *  Format: OP_RETURN <IDAG tag(4) || count(1) || hash1(32) || hash2(32) || ...> */
CScript BuildDAGParentScript(const std::vector<uint256>& vParents);


// ---------------------------------------------------------------------------
// Per-epoch DAG state (persisted to LevelDB)
// ---------------------------------------------------------------------------

struct CEpochState
{
    int nEpoch;
    uint256 hashBoundaryBlock;
    int nHeightStart;
    int nHeightEnd;
    std::vector<uint256> vBlockHashes;   // DAG-ordered block hashes in this epoch
    uint256 nTotalTrust;
    int nBlockCount;
    int nTxCount;
    bool fFinalized;

    CEpochState()
    {
        nEpoch = 0;
        nHeightStart = 0;
        nHeightEnd = 0;
        nTotalTrust = 0;
        nBlockCount = 0;
        nTxCount = 0;
        fFinalized = false;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nEpoch);
        READWRITE(hashBoundaryBlock);
        READWRITE(nHeightStart);
        READWRITE(nHeightEnd);
        READWRITE(vBlockHashes);
        READWRITE(nTotalTrust);
        READWRITE(nBlockCount);
        READWRITE(nTxCount);
        READWRITE(fFinalized);
    )
};


// ---------------------------------------------------------------------------
// Per-block DAG metadata (memory only — persisted separately via LevelDB)
// ---------------------------------------------------------------------------

struct CBlockDAGData
{
    std::vector<uint256> vDAGParents;    // parent block hashes (index 0 = primary parent)
    std::vector<uint256> vDAGChildren;   // children that reference this block as parent
    bool fBlue;                          // GHOSTDAG/DAGKNIGHT blue/red coloring
    uint256 nDAGScore;                   // cumulative blue-set trust score
    int nDAGOrder;                       // position in DAG linear order
    int nInferredK;                      // Phase 4: DAGKNIGHT-inferred k (-1 = GHOSTDAG era)

    CBlockDAGData()
    {
        fBlue = true;
        nDAGScore = 0;
        nDAGOrder = -1;
        nInferredK = -1;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vDAGParents);
        READWRITE(vDAGChildren);
        READWRITE(fBlue);
        READWRITE(nDAGScore);
        READWRITE(nDAGOrder);
        READWRITE(nInferredK);
    )
};


// ---------------------------------------------------------------------------
// DAG Manager — holds all DAG state, drives GHOSTDAG/DAGKNIGHT coloring + ordering
// ---------------------------------------------------------------------------

class CDAGManager
{
public:
    mutable CCriticalSection cs_dag;

    CDAGManager() : nPrunedBelowHeight(-1) {}

    /** Initialize DAG data for a newly accepted block.
     *  Must be called under cs_main. Sets parents, registers children, updates tips. */
    bool InitBlockDAGData(CBlockIndex* pindex, const std::vector<uint256>& vParents);

    /** Get current DAG tips (blocks with no children). */
    std::vector<uint256> GetDAGTips() const;

    /** Select the best DAG tip by score. */
    CBlockIndex* SelectBestDAGTip() const;

    /** Get DAG linear ordering from a given tip back to genesis.
     *  nMaxBlocks limits computation (0 = unlimited). */
    std::vector<uint256> GetDAGLinearOrder(const uint256& hashTip, int nMaxBlocks = 0) const;

    /** Compute DAG score for a block: sum of GetBlockTrust() for all blue ancestors. */
    uint256 ComputeDAGScore(CBlockIndex* pindex);

    /** GHOSTDAG blue-set coloring (used below FORK_HEIGHT_DAGKNIGHT). */
    void ColorBlock(CBlockIndex* pindex);

    /** DAGKNIGHT adaptive coloring for a block (Phase 4). */
    void ColorBlockDAGKnight(CBlockIndex* pindex);

    /** DAGKNIGHT pairwise ordering: -1 if A before B, +1 if B before A, 0 if unordered.
     *  nConfidence is set to the supporting mass difference. */
    int CompareBlockOrder(const uint256& hashA, const uint256& hashB, int& nConfidence) const;

    /** DAGKNIGHT: Get confidence level for a block's ordering position. */
    int GetOrderConfidence(const uint256& hashBlock) const;

    /** Write DAG links for a block to LevelDB. */
    bool WriteDAGLinks(CTxDB& txdb, const uint256& hash);

    /** Load all DAG links from LevelDB into memory. */
    bool LoadDAGLinks(CTxDB& txdb);

    /** Rebuild DAG ordering (GHOSTDAG/DAGKNIGHT) from loaded data. */
    void RebuildDAGOrder();

    /** Rebuild DAG ordering incrementally (only blocks above nCleanHeight). */
    void RebuildDAGOrderIncremental(int nCleanHeight);

    /** Prune DAG data below nHeight - DAG_PRUNE_DEPTH, preserving epoch boundaries. */
    bool PruneDAGData(CTxDB& txdb, int nHeight);

    /** Compute epoch state for a completed epoch. */
    bool ComputeEpochState(int nEpoch, int nEpochInterval);

    /** Write epoch state to LevelDB. */
    bool WriteEpochState(CTxDB& txdb, int nEpoch);

    /** Get epoch state (from memory cache). */
    bool GetEpochState(int nEpoch, CEpochState& stateOut) const;

    /** Get the number of in-memory DAG entries. */
    int GetDAGEntryCount() const;

    /** Get the lowest height of pruned data (-1 if no pruning). */
    int GetPrunedBelowHeight() const;

    /** Set pruned below height (used on startup to restore from LevelDB). */
    void SetPrunedBelowHeight(int nHeight);

    /** Check if a block has DAG data. */
    bool HasDAGData(const uint256& hash) const;

    /** Get DAG data for a block (returns false if not found). */
    bool GetDAGData(const uint256& hash, CBlockDAGData& dataOut) const;

    /** Get the set of blocks that are DAG siblings of a given block
     *  (blocks at similar height that share some parents). */
    std::set<uint256> GetDAGSiblingBlocks(const uint256& hashBlock) const;

    /** Get the selected parent (highest-scoring parent) of a block. */
    uint256 GetSelectedParent(const uint256& hashBlock) const;

    /** Remove DAG data for a block (used during reorg). */
    void RemoveBlockDAGData(const uint256& hashBlock);

private:
    std::map<uint256, CBlockDAGData> mapDAGData;
    std::set<uint256> setDAGTips;
    std::map<int, CEpochState> mapEpochState;
    std::set<uint256> setEpochBoundaryBlocks;
    int nPrunedBelowHeight;

    // Performance: LRU cache for blue sets (avoids recomputing expensive BFS)
    mutable std::map<uint256, std::set<uint256>> mapBlueSetCache;
    static const int BLUESET_CACHE_MAX = 128;

    /** Internal: get blue set with caching */
    std::set<uint256> GetBlueSetCached(const uint256& hashBlock) const;

    /** DAGKNIGHT: Infer local k from DAG neighborhood. */
    int InferLocalK(const uint256& hashBlock) const;

    /** DAGKNIGHT: Compute supporting mass of A over B (blocks seeing A but not B). */
    int SupportingMass(const uint256& hashA, const uint256& hashB) const;

    /** Internal: get anticone of block X relative to a blue set */
    int AnticoneSize(const uint256& hashBlock, const std::set<uint256>& blueSet) const;

    /** Internal: collect blue set reachable from a block */
    std::set<uint256> GetBlueSet(const uint256& hashBlock) const;

    /** Internal: get all blocks reachable from a hash (bounded by depth) */
    std::set<uint256> GetPastSet(const uint256& hashBlock, int nMaxDepth) const;
};


extern CDAGManager g_dagManager;


#endif // INN_DAG_H
