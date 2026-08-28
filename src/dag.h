// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_DAG_H
#define INN_DAG_H

#include "uint256.h"
#include "serialize.h"
#include "sync.h"
#include "script.h"
#include "curvetree.h"

#include <vector>
#include <map>
#include <set>
#include <string>
#include <stdint.h>

class CBlockIndex;
class CTxDB;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

static const int MAX_DAG_PARENTS = 32;          // max parents per block (1 primary + 31 merge)
static const unsigned char DAG_PARENT_TAG[4] = { 0x49, 0x44, 0x41, 0x47 }; // "IDAG"

// IDAG payload framing: 4 tag bytes then a one-octet parent count.
static const unsigned int DAG_PARENT_PAYLOAD_HEADER = 5;

// Below Boundary A the commitment is read back through CScript::GetOp, which
// refuses any push above MAX_SCRIPT_ELEMENT_SIZE, so the pre-A decoder cannot
// see a payload wider than that however many parents the count claims. Derive
// the pre-A ceiling from the same limit rather than restating it, so raising
// MAX_SCRIPT_ELEMENT_SIZE or the framing moves both sides together.
static const unsigned int MAX_DAG_PARENTS_PRE_BOUNDARY_A =
    (MAX_SCRIPT_ELEMENT_SIZE - DAG_PARENT_PAYLOAD_HEADER) / 32;
static const int GHOSTDAG_K = 18;               // anticone tolerance for blue coloring (pre-DAGKNIGHT)
static const int DAG_MERGE_DEPTH = 64;          // merge parents within this depth of primary (~64s at 1s blocks)
static const int DAG_PRUNE_DEPTH = 100000;      // prune DAG data older than this (~28h at 1s blocks)

// DAGKNIGHT adaptive ordering constants
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
static const int DAGKNIGHT_MAX_ANCHOR_CANDIDATES = 2048;
static const int DAGKNIGHT_ANCHOR_CACHE_MAX = 8192;
// Bounded past sets, keyed by descendant. One anchor's working set is its blue window
// (bounded by DAGKNIGHT_MAX_ANTICONE_WINDOW) plus its merge candidates, and consecutive
// anchors share nearly all of it, so a few hundred entries carry the reuse.
static const int DAGKNIGHT_PAST_CACHE_MAX = 512;
// Past sets larger than this are returned without being cached.
static const size_t DAGKNIGHT_PAST_SET_MAX = 1024;

static const int DAG_PARENT_CARRIER_SCHEMA_VERSION = 1;
static const char DAG_PARENT_CARRIER_SCHEMA[] = "boundary_a_canonical_v1";
static const char DAGKNIGHT_ORDERING_CONTRACT[] =
    "dagknight_adaptive_k_anchor_pure_v1";


// ---------------------------------------------------------------------------
// DAG Parent Commitment (coinbase OP_RETURN)
// ---------------------------------------------------------------------------

/** Extract DAG parent hashes from a coinbase OP_RETURN output.
 *  Returns empty vector if no DAG commitment found. */
std::vector<uint256> ExtractDAGParents(const CScript& scriptCoinbase);

enum DAGParentDecodeStatus
{
    DAG_PARENT_NOT_FOUND = 0,
    DAG_PARENT_VALID = 1,
    DAG_PARENT_MALFORMED = 2
};

/** Strict Boundary-A decoder. A matching IDAG payload must use the minimal
 *  canonical push, consume the entire script and payload, and contain 1..32
 *  unique non-zero parents. Non-IDAG OP_RETURN outputs are NOT_FOUND. */
DAGParentDecodeStatus DecodeCanonicalDAGParentScript(
    const CScript& script, std::vector<uint256>& vParents,
    std::string& strError);

/** Require exactly one strict IDAG commitment across the supplied scripts. */
bool ExtractCanonicalDAGParentCommitment(
    const std::vector<CScript>& vScripts,
    std::vector<uint256>& vParents,
    std::string& strError);

/** Read a block's committed parent set with the decoder its height selects
 *  (canonical from Boundary A, permissive first match below). All parent readers use
 *  this so validation and the index writer agree. */
bool ReadDAGParentCommitmentAtHeight(
    const std::vector<CScript>& vScripts,
    int nHeight,
    std::vector<uint256>& vParents,
    std::string& strError);

/** Parents a block at nHeight may commit to and still have its commitment read
 *  back by the decoder that validates at that height. AcceptBlock swaps decoders
 *  at Boundary A, and the pre-A one is the narrower of the two, so a producer
 *  that ignores the height can build a commitment its own validator refuses. */
unsigned int MaxDAGParentsAtHeight(int nHeight);

/** Build a coinbase OP_RETURN script committing to DAG parents.
 *  Format: OP_RETURN <IDAG tag(4) || count(1) || hash1(32) || hash2(32) || ...> */
CScript BuildDAGParentScript(const std::vector<uint256>& vParents);


// ---------------------------------------------------------------------------
// Per-epoch DAG state (persisted to LevelDB)
// ---------------------------------------------------------------------------

// Per-record serialization version for CEpochState. Legacy records (written before this byte was
// added) carry an implicit version 0; the DB reader (CTxDB::IterateEpochStates) reads the trailing
// byte tolerantly, mirroring the CBlockDAGData::nInferredK legacy-field pattern.
static const unsigned char EPOCHSTATE_SER_VERSION_V3 = 1;
static const unsigned char EPOCHSTATE_SER_VERSION_V4 = 2;
// V5 adds the running IV5 pool balance. Kept as its own version so a V4 record, which never
// carried the field, cannot be read as though it declared a zero balance.
static const unsigned char EPOCHSTATE_SER_VERSION_V5 = 3;
// V6 adds the drawn finality committee. The epoch that ends immediately before a term
// carries the seats that term serves under; every other epoch carries none. Its own
// version so a V5 record cannot be read as an epoch that deliberately seated nobody.
static const unsigned char EPOCHSTATE_SER_VERSION_V6 = 4;
static const unsigned char EPOCHSTATE_SER_VERSION = EPOCHSTATE_SER_VERSION_V6;
// DB-wide epoch-state schema marker (key "epochstateschema"). Absent/0 = pre-deterministic-anchor
// regime (records may have been computed off a node-local tip); EPOCHSTATE_SCHEMA_V2 = records are
// written under the deterministic anchor (post FORK_HEIGHT_EPOCH_STATE_V2). Gates the upgrade guard.
static const int EPOCHSTATE_SCHEMA_V2 = 2;
// V3 records are built from the exact canonical epoch-end block, staged without touching the
// in-memory cache, and committed with their matching curve snapshot and best-chain transition.
static const int EPOCHSTATE_SCHEMA_V3 = 3;
// Boundary B appends independently versioned IV5 accumulator/finality fields.
// Existing V3 records remain byte-identical and continue to deserialize as v1.
static const int EPOCHSTATE_SCHEMA_V4 = 4;
// The maximum committee this record can carry, so a corrupt or hostile record cannot
// make deserialization allocate without bound.
static const size_t EPOCHSTATE_MAX_COMMITTEE_SEATS = 64;
static const size_t EPOCHSTATE_VNEXT_TREE_STATE_SIZE = 300;
static const size_t EPOCHSTATE_VNEXT_NULLIFIER_STATE_SIZE = 44;
static const size_t EPOCHSTATE_VNEXT_DIGEST_SIZE = 32;
static const size_t EPOCHSTATE_VNEXT_MAX_ACTIVE_TXS = 65536;
static const size_t EPOCHSTATE_VNEXT_MAX_NULLIFIERS = 1048576;
// How many finalized epochs back a spend's proving anchor may sit (~30 min post-DAG),
// so a transaction crossing an epoch boundary before confirming stays valid.
static const int EPOCHSTATE_VNEXT_MAX_ANCHOR_AGE_EPOCHS = 6;

// Apply one IV5 tx's pool delta to a running balance. Returns false, leaving `nBalance`
// untouched, if the result would be negative, exceed the money supply, or overflow.
bool ApplyPrivacyVNextPoolDelta(int64_t& nBalance, int64_t nDelta,
                                std::string& strErrorOut);

struct CEpochState
{
    int nEpoch;
    uint256 hashBoundaryBlock;
    int nHeightStart;
    int nHeightEnd;
    std::vector<uint256> vBlockHashes;   // DAG-ordered block hashes in this epoch
    uint256 hashCurveRoot;
    uint256 hashNullifierRoot;
    uint256 hashVoteSetRoot;             // digest of finality votes embedded in this epoch's blocks
    uint256 hashFinalityCertificate;
    uint256 nTotalTrust;
    int nBlockCount;
    int nTxCount;
    int nFinalityTier;
    int nConsecutiveHardCount;
    bool fFinalized;
    // Deterministic finalized height as of this epoch (monotonic running max). A pure
    // function of the chain's connected per-epoch tiers, identical on every node, so
    // private-vote / tally-cert / FCMP-spend validation anchors deterministically.
    int nFinalizedHeightAsOf;
    // Record serialization version (trailing field; legacy records read back as 0). Not part of the
    // consensus root — purely a format tag so a future field-add can be detected across upgrades.
    unsigned char nSerVersion;
    // Schema-V4 extension. These fields are serialized only when nSerVersion
    // is EPOCHSTATE_SER_VERSION_V4, after the historical trailing version byte.
    std::vector<unsigned char> vchVNextTreeState;
    std::vector<unsigned char> vchVNextRoot;
    uint64_t nVNextTreeSize;
    std::vector<unsigned char> vchVNextNullifierState;
    uint256 hashVNextNullifierRoot;
    uint64_t nVNextNullifierCount;
    std::vector<uint256> vVNextEpochNullifiers;
    std::vector<unsigned char> vchVNextParameterDigest;
    uint256 hashVNextFinalizedAnchor;
    int nVNextFinalizedHeight;
    std::vector<unsigned int> vVNextActiveBlockTxCounts;
    std::vector<uint256> vVNextActiveTxIds;
    // Total value the IV5 pool holds: every shield adds, every unshield and fee subtracts.
    // Consensus refuses to let this go negative, so the pool can never pay out more than
    // was put into it however a proof behaves. Serialized from V5.
    int64_t nVNextPoolBalance;
    uint256 hashVNextActiveTxSet;
    // The finality committee drawn for the term that starts at nEpoch + 1, in seat
    // order (seat i is member index i). Only an epoch that ends a term's lead-in
    // carries seats; everywhere else this is empty and no committee exists.
    //
    // The draw is stored rather than recomputed on demand because it is only a term
    // constant if it is fixed once: registrations keep arriving and collateral keeps
    // being spent, so a resolver that redrew per block would hand out a different
    // committee mid-term and invalidate certificates its own peers already accepted.
    std::vector<std::vector<unsigned char> > vFinalityCommittee;  // 33-byte compressed
    int32_t nFinalityCommitteeM;

    CEpochState()
    {
        nEpoch = 0;
        hashBoundaryBlock = 0;
        hashCurveRoot = 0;
        hashNullifierRoot = 0;
        hashVoteSetRoot = 0;
        hashFinalityCertificate = 0;
        nHeightStart = 0;
        nHeightEnd = 0;
        nTotalTrust = 0;
        nBlockCount = 0;
        nTxCount = 0;
        nFinalityTier = 0;
        nConsecutiveHardCount = 0;
        fFinalized = false;
        nFinalizedHeightAsOf = 0;
        nSerVersion = EPOCHSTATE_SER_VERSION_V3;
        nFinalityCommitteeM = 0;
        nVNextTreeSize = 0;
        hashVNextNullifierRoot = 0;
        nVNextNullifierCount = 0;
        nVNextPoolBalance = 0;
        hashVNextFinalizedAnchor = 0;
        nVNextFinalizedHeight = 0;
        hashVNextActiveTxSet = 0;
    }

    /** Domain-separated digest of the canonical consensus fields (format tag excluded). */
    uint256 GetDigest() const;

    IMPLEMENT_SERIALIZE
    (
        CEpochState* pthis = const_cast<CEpochState*>(this);
        READWRITE(nEpoch);
        READWRITE(hashBoundaryBlock);
        READWRITE(nHeightStart);
        READWRITE(nHeightEnd);
        READWRITE(vBlockHashes);
        READWRITE(hashCurveRoot);
        READWRITE(hashNullifierRoot);
        READWRITE(hashVoteSetRoot);
        READWRITE(hashFinalityCertificate);
        READWRITE(nTotalTrust);
        READWRITE(nBlockCount);
        READWRITE(nTxCount);
        READWRITE(nFinalityTier);
        READWRITE(nConsecutiveHardCount);
        READWRITE(fFinalized);
        READWRITE(nFinalizedHeightAsOf);
        READWRITE(nSerVersion);   // trailing; legacy records lack it -> IterateEpochStates reads it tolerantly
        if (nSerVersion > EPOCHSTATE_SER_VERSION)
            throw std::ios_base::failure("unsupported epoch-state record version");
        if (nSerVersion >= EPOCHSTATE_SER_VERSION_V4)
        {
            nSerSize += ::SerReadWriteLimitedVector(
                s, pthis->vchVNextTreeState,
                EPOCHSTATE_VNEXT_TREE_STATE_SIZE,
                nType, nVersion, ser_action);
            nSerSize += ::SerReadWriteLimitedVector(
                s, pthis->vchVNextRoot, EPOCHSTATE_VNEXT_DIGEST_SIZE,
                nType, nVersion, ser_action);
            READWRITE(nVNextTreeSize);
            nSerSize += ::SerReadWriteLimitedVector(
                s, pthis->vchVNextNullifierState,
                EPOCHSTATE_VNEXT_NULLIFIER_STATE_SIZE,
                nType, nVersion, ser_action);
            READWRITE(hashVNextNullifierRoot);
            READWRITE(nVNextNullifierCount);
            nSerSize += ::SerReadWriteLimitedVector(
                s, pthis->vVNextEpochNullifiers,
                EPOCHSTATE_VNEXT_MAX_NULLIFIERS,
                nType, nVersion, ser_action);
            nSerSize += ::SerReadWriteLimitedVector(
                s, pthis->vchVNextParameterDigest,
                EPOCHSTATE_VNEXT_DIGEST_SIZE,
                nType, nVersion, ser_action);
            READWRITE(hashVNextFinalizedAnchor);
            READWRITE(nVNextFinalizedHeight);
            nSerSize += ::SerReadWriteLimitedVector(
                s, pthis->vVNextActiveBlockTxCounts,
                EPOCHSTATE_VNEXT_MAX_ACTIVE_TXS,
                nType, nVersion, ser_action);
            if (nSerVersion >= EPOCHSTATE_SER_VERSION_V5)
                READWRITE(nVNextPoolBalance);
            nSerSize += ::SerReadWriteLimitedVector(
                s, pthis->vVNextActiveTxIds,
                EPOCHSTATE_VNEXT_MAX_ACTIVE_TXS,
                nType, nVersion, ser_action);
            READWRITE(hashVNextActiveTxSet);
            if (nSerVersion >= EPOCHSTATE_SER_VERSION_V6)
            {
                nSerSize += ::SerReadWriteLimitedByteVectors(
                    s, pthis->vFinalityCommittee,
                    EPOCHSTATE_MAX_COMMITTEE_SEATS, 33,
                    nType, nVersion, ser_action);
                READWRITE(nFinalityCommitteeM);
            }
        }
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
    int nInferredK;                      // DAGKNIGHT-inferred k (-1 = GHOSTDAG era)

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
    std::vector<uint256> GetDAGLinearOrder(const uint256& hashTip, int nMaxBlocks = 0,
                                           bool fForceSchemaV3Order = false) const;

    /** Compute DAG score for a block: sum of GetBlockTrust() for all blue ancestors. */
    uint256 ComputeDAGScore(CBlockIndex* pindex);

    /** GHOSTDAG blue-set coloring (used below FORK_HEIGHT_DAGKNIGHT). */
    void ColorBlock(CBlockIndex* pindex);

    /** DAGKNIGHT adaptive coloring for a block. */
    bool ColorBlockDAGKnight(CBlockIndex* pindex);

    /** DAGKNIGHT pairwise ordering: -1 if A before B, +1 if B before A, 0 if unordered.
     *  nConfidence is set to the supporting mass difference. */
    int CompareBlockOrder(const uint256& hashA, const uint256& hashB, int& nConfidence) const;

    /** DAGKNIGHT: Get confidence level for a block's ordering position. */
    int GetOrderConfidence(const uint256& hashBlock) const;

    /** Validate the bounded anchor-local merge set before accepting a
     *  Boundary-A block. This is consensus resource-limit enforcement. */
    bool CheckDAGKnightParentSet(const std::vector<uint256>& vParents,
                                 int nAnchorHeight,
                                 std::string& strError) const;

    /** Return the complete anchor-derived order/color view used by tests,
     *  diagnostics and evidence generation. */
    bool GetDAGKnightAnchorMetrics(
        const uint256& hashAnchor, uint256& hashSelectedParent,
        int& nInferredK, uint256& nScore,
        std::vector<std::pair<uint256, bool> >& vOrderColors) const;

    /** Write DAG links for a block to LevelDB. */
    bool WriteDAGLinks(CTxDB& txdb, const uint256& hash);

    /** Load all DAG links from LevelDB into memory. */
    bool LoadDAGLinks(CTxDB& txdb);

    /** Load persisted epoch states and curve-tree snapshots from LevelDB. */
    bool LoadEpochStates(CTxDB& txdb);

    /** Rebuild DAG ordering (GHOSTDAG/DAGKNIGHT) from loaded data. */
    void RebuildDAGOrder();

    /** Rebuild DAG ordering incrementally (only blocks above nCleanHeight). */
    void RebuildDAGOrderIncremental(int nCleanHeight);

    /** Prune DAG data below nHeight - DAG_PRUNE_DEPTH, preserving epoch boundaries. */
    bool PruneDAGData(CTxDB& txdb, int nHeight);

    /** Legacy V2 computation, only for epochs ending below FORK_HEIGHT_EPOCH_STATE_V2
     *  (reads node-local fBlue). NULL pAnchorTip uses the legacy best-tip derivation. */
    bool ComputeEpochState(int nEpoch, int nEpochInterval, const CBlockIndex* pAnchorTip = NULL);

    /** Build schema-V2 bytes without touching the epoch cache. Optional predecessor
     *  inputs let a reorg build a contiguous suffix before commit. */
    bool BuildEpochStateV2Compat(int nEpoch, int nEpochInterval,
                                 const CBlockIndex* pAnchorTip,
                                 CEpochState& stateOut,
                                 CCurveTree& curveTreeOut,
                                 std::string& strError,
                                 const CEpochState* pPrevState = NULL,
                                 const CCurveTree* pPrevCurveTree = NULL) const;

    /** Build a V3 epoch state without changing any global or cached state. The boundary must be
     *  the exact canonical block at the epoch's final height. Optional predecessor arguments are
     *  used by an atomic multi-epoch reorg rebuild and must be supplied as a matching pair. */
    bool BuildEpochState(int nEpoch, int nEpochInterval, const CBlockIndex* pBoundary,
                         CEpochState& stateOut, CCurveTree& curveTreeOut,
                         std::string& strError,
                         const CEpochState* pPrevState = NULL,
                         const CCurveTree* pPrevCurveTree = NULL) const;

    /** Legacy V2 cache writer. */
    bool WriteEpochState(CTxDB& txdb, int nEpoch);

    /** Write one staged V3 state/snapshot pair into the caller's active DB transaction. */
    bool WriteEpochState(CTxDB& txdb, const CEpochState& state,
                         const CCurveTree& curveTree) const;

    /** Erase the persisted epoch suffix in the caller's active transaction. */
    bool EraseEpochStateSuffix(CTxDB& txdb, int nFirstEpoch) const;

    /** Validate a staged suffix completely before its durable DB commit. */
    bool ValidateEpochStateBatch(int nFirstEpoch,
                                 const std::map<int, CEpochState>& mapStates,
                                 const std::map<int, CCurveTree>& mapCurveTrees) const;

    /** Atomically replace the in-memory suffix after the caller's DB commit succeeds. */
    bool InstallEpochStateBatch(int nFirstEpoch,
                                const std::map<int, CEpochState>& mapStates,
                                const std::map<int, CCurveTree>& mapCurveTrees);

    /** Get epoch state (from memory cache). */
    bool GetEpochState(int nEpoch, CEpochState& stateOut) const;

    /** Number of epoch-state records loaded into the memory cache (used by the startup schema guard). */
    size_t GetLoadedEpochStateCount() const;

    /** Deterministic finalized height as of the exact requested completed epoch. Missing state is
     *  an error, distinct from the valid finalized height zero. */
    bool TryGetDeterministicFinalizedHeight(int nUpToEpoch, int& nHeightOut) const;

    /** Transaction-aware variant used while a best-chain/reorg WriteBatch contains staged
     *  epoch records that must be visible to ConnectBlock without installing global cache state. */
    bool TryGetDeterministicFinalizedHeight(CTxDB& txdb, int nUpToEpoch,
                                            int& nHeightOut) const;

    /** Non-consensus wrapper; consensus callers use TryGet.
     *  Pure function of the persisted per-epoch states; identical on every node.
     *  Returns 0 if nothing is finalized yet. */
    int GetDeterministicFinalizedHeight(int nUpToEpoch) const;

    /** Get the most recent finalized epoch state known to the DAG manager. */
    /** Most recent finalized epoch state. fRequireCurveRoot skips epochs with an empty
     *  legacy curve root; callers anchoring to the IV5 root must pass false. */
    bool GetLastFinalizedEpochState(CEpochState& stateOut,
                                    bool fRequireCurveRoot = true) const;

    /** Block-relative finalized epoch state: deterministic from the chain up to the
     *  epoch preceding nBlockHeight's epoch. Use this (not GetLastFinalizedEpochState)
     *  anywhere a block's contents are validated, so validation is node-independent. */
    bool GetFinalizedEpochStateAsOf(int nBlockHeight, CEpochState& stateOut) const;

    /** Resolve finalized state from the caller's transaction, including staged WriteBatch data. */
    bool GetFinalizedEpochStateAsOf(CTxDB& txdb, int nBlockHeight,
                                    CEpochState& stateOut) const;

    /** Same, reporting whether a failure was node-local. A record the chain has not
     *  written yet is absent on every node and must stay a consensus outcome; a record
     *  this node cannot read or decode is local and must not become one. */
    bool GetFinalizedEpochStateAsOf(CTxDB& txdb, int nBlockHeight,
                                    CEpochState& stateOut,
                                    bool& fLocalFailureOut) const;

    /** The finalized epoch state `nEpochsBack` epochs before the one nBlockHeight resolves to.
     *  The epoch number is derived from the chain, not from node-local state, so the set of
     *  states a block may be validated against is the same on every node. */
    bool GetFinalizedEpochStateAsOf(CTxDB& txdb, int nBlockHeight, int nEpochsBack,
                                    CEpochState& stateOut) const;

    /** Validate that V3 persistence ends at the exact completed epoch required by pBest and
     *  that both the migration-base and highest-required boundaries are on pBest's pprev chain. */
    bool ValidateEpochStateTip(const CBlockIndex* pBest, std::string& strError) const;

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
    struct CDAGKnightAnchorState
    {
        uint256 hashSelectedParent;
        uint256 nScore;
        int nInferredK;
        std::vector<unsigned char> vPressureSamples;
        std::vector<uint256> vBlueWindow;
        std::vector<std::pair<uint256, bool> > vOrderDelta;

        CDAGKnightAnchorState() : nScore(0), nInferredK(0) {}
    };

    std::map<uint256, CBlockDAGData> mapDAGData;
    std::set<uint256> setDAGTips;
    std::map<uint256, std::set<uint256>> mapPendingChildrenByParent;
    std::map<int, CEpochState> mapEpochState;
    std::map<int, CCurveTree> mapEpochCurveTrees;
    std::set<uint256> setEpochBoundaryBlocks;
    int nPrunedBelowHeight;

    // Performance: LRU cache for blue sets (avoids recomputing expensive BFS)
    mutable std::map<uint256, std::set<uint256>> mapBlueSetCache;
    static const int BLUESET_CACHE_MAX = 128;

    // Boundary-A DAGKNIGHT states are keyed by their immutable anchor. The
    // bounded cache is disposable: restart/reorg rebuild derives identical
    // bytes from persisted parent links and block indexes.
    mutable std::map<uint256, CDAGKnightAnchorState> mapDAGKnightAnchorCache;

    // Bounded past sets behind IsDAGAncestorWithinMergeDepth. Same derivation domain as
    // the anchor states -- a block's past -- so the two are invalidated together.
    mutable std::map<uint256, std::set<uint256> > mapDAGKnightPastCache;
    // Holds a past set too large to retain, for the caller that asked for it.
    mutable std::set<uint256> setDAGKnightPastScratch;

    /** Internal: get blue set with caching */
    std::set<uint256> GetBlueSetCached(const uint256& hashBlock) const;

    /** Internal: child/pending-child and cache maintenance helpers. */
    void AddChildNoDuplicate(std::vector<uint256>& vChildren, const uint256& hashChild) const;
    void InvalidateBlueSetCacheForBlock(const uint256& hashBlock) const;
    void RebuildPendingChildIndex();

    /** Drop the cached anchor states a change at hashRoot can alter: hashRoot and its
     *  transitive DAG descendants. Falls back to dropping the whole cache past a bound. */
    void InvalidateDAGKnightAnchorDescendants(const uint256& hashRoot) const;

    /** DAGKNIGHT: Infer local k from DAG neighborhood. */
    int InferLocalK(const uint256& hashBlock) const;

    uint256 GetDAGKnightSelectedParent(
        const std::vector<uint256>& vParents) const;
    bool IsDAGAncestor(const uint256& hashAncestor,
                       const uint256& hashDescendant,
                       int nMaxDepth) const;
    /** Bounded past of hashDescendant, cached. The returned reference is only valid until
     *  the next call, which may evict the cache, so consume it before asking again. */
    const std::set<uint256>& GetBoundedPast(const uint256& hashDescendant,
                                            int nDescendantHeight,
                                            int nMaxDepth) const;
    bool IsDAGAncestorWithinMergeDepth(const uint256& hashAncestor,
                                       const uint256& hashDescendant) const;
    bool CollectDAGKnightCandidates(
        const std::vector<uint256>& vParents,
        const uint256& hashSelectedParent,
        int nAnchorHeight,
        std::vector<uint256>& vCandidates,
        std::string& strError) const;
    bool EnsureDAGKnightAnchorState(const uint256& hashAnchor) const;
    bool BuildDAGKnightAnchorState(const uint256& hashAnchor,
                                   CDAGKnightAnchorState& stateOut,
                                   std::string& strError) const;
    void CacheDAGKnightAnchorState(
        const uint256& hashAnchor,
        const CDAGKnightAnchorState& state) const;

    /** Internal: get anticone of block X relative to a blue set */
    int AnticoneSize(const uint256& hashBlock, const std::set<uint256>& blueSet) const;

    /** Internal: collect blue set reachable from a block */
    std::set<uint256> GetBlueSet(const uint256& hashBlock) const;

    /** Internal: get all blocks reachable from a hash (bounded by depth) */
    std::set<uint256> GetPastSet(const uint256& hashBlock, int nMaxDepth) const;
};


extern CDAGManager g_dagManager;

// Anchor-cache differential test: when set, any DAG change drops every cached anchor
// state. Both paths must produce identical colouring, ordering, score and k.
extern bool fDAGKnightUnoptimizedOrdering;


#endif // INN_DAG_H
