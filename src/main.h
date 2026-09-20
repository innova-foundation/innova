// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2017-2021 The Denarius developers
// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_MAIN_H
#define BITCOIN_MAIN_H

#include "core.h"
#include "v5activation.h"
#include "bignum.h"
#include "sync.h"
#include "net.h"
#include "script.h"
#include "mstimestamp.h"
#include "scrypt.h"
#include "hashblock.h"
#include "shielded.h"
#include "nullstake.h"
#include "privacy_vnext_ffi.h"

#include <list>
#include <vector>

class CValidationState;
class CBestChainEffectJournal;

#define BLOCK_START_COLLATERALNODE_PAYMENTS_TESTNET 999999 // Disabled for clean IDAG public testnet launch
#define BLOCK_START_COLLATERALNODE_PAYMENTS 800 // Mainnet Collateralnode payments not enabled until block 800
#define BLOCK_START_COLLATERALNODE_DELAYPAY 2500 // Unused

//#define START_COLLATERALNODE_PAYMENTS_TESTNET 1519430400  //Sat, 24 Feb 2018 00:00:00 GMT
//#define START_COLLATERALNODE_PAYMENTS 1520985600  //Wed, 14 Mar 2018 00:00:00 GMT

static const int64_t COLLATERALN_COLLATERAL = (25000*COIN); // 25,000 INN
static const int64_t COLLATERALN_FEE = (0.010000*COIN); // 0.01 INN
static const int64_t POOL_FEE_AMOUNT = (0.1*COIN); // 0.1 INN
static const int64_t COLLATERALN_POOL_MAX = (51000*COIN); // 51,000 INN

#define MESSAGE_START_SIZE 4
typedef unsigned char MessageStartChars[MESSAGE_START_SIZE];

#define COLLATERALNODE_NOT_PROCESSED               0 // initial state
#define COLLATERALNODE_IS_CAPABLE                  1
#define COLLATERALNODE_NOT_CAPABLE                 2
#define COLLATERALNODE_STOPPED                     3
#define COLLATERALNODE_INPUT_TOO_NEW               4
#define COLLATERALNODE_PORT_NOT_OPEN               6
#define COLLATERALNODE_PORT_OPEN                   7
#define COLLATERALNODE_SYNC_IN_PROCESS             8
#define COLLATERALNODE_REMOTELY_ENABLED            9

class CWallet;
class CWalletTx;
class CBlock;
class CBlockIndex;
class CKeyItem;
class CReserveKey;
class COutPoint;

class CAddress;
class CInv;
class CRequestTracker;
class CNode;
class CFinalityVote;

// General Innova Block Values

// extern CFeeRate minRelayTxFee;
static const int ZERO_POW_BLOCK = 50000; // 50k blocks before Proof of Stake consensus, back to hybrid PoW/PoS at block 2000000, final reward 0.0001 INN per block
static const int FAIR_LAUNCH_BLOCK = 490; // Last Block until full block reward starts
// Pre-DAG: fixed 1 MB block size (legacy compatibility)
static const unsigned int MAX_BLOCK_SIZE_LEGACY = 1000000;

// Post-DAG: adaptive block size (Monero-inspired, tuned for 1s blocks)
static const unsigned int ADAPTIVE_BLOCK_CEILING = 8000000;       // 8 MB absolute hard ceiling
static const unsigned int ADAPTIVE_BLOCK_FLOOR = 300000;          // 300 KB penalty-free zone
static const unsigned int ADAPTIVE_MEDIAN_WINDOW = 1000;          // 1000-block short-term median (~17 min at 1s)
// Long-term median window. GetBlockIndexSizeBackfillDepth() is derived from it,
// so the two must move together.
static const unsigned int ADAPTIVE_LONG_MEDIAN_WINDOW = 50000;    // 50K-block long-term anchor (~14h at 1s)
static const unsigned int ADAPTIVE_LONG_MEDIAN_CAP = 50;          // short-term median <= 50x long-term median

// Effective block size: pre-DAG uses legacy, post-DAG uses adaptive
inline unsigned int GetMaxBlockSize(int nHeight)
{
    extern int GetForkHeightDAG();
    if (nHeight >= GetForkHeightDAG())
        return ADAPTIVE_BLOCK_CEILING;
    return MAX_BLOCK_SIZE_LEGACY;
}

// Pre-fork constants — used for all consensus checks before FORK_HEIGHT_DAG
static const unsigned int MAX_BLOCK_SIZE = MAX_BLOCK_SIZE_LEGACY;       // 1MB until DAG fork
static const unsigned int MAX_BLOCK_SIZE_GEN = MAX_BLOCK_SIZE / 2;
static const unsigned int MAX_STANDARD_TX_SIZE = MAX_BLOCK_SIZE_GEN / 5;
static const unsigned int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50;
static_assert(SHIELDED_TX_FIELD_MAX_WIRE_SIZE >= MAX_BLOCK_SIZE,
              "shielded read cap must preserve every basic-valid transaction");

// Post-fork limits (used via GetMaxBlockSize(nHeight) after DAG activation)
static const unsigned int MAX_BLOCK_SIGOPS_ADAPTIVE = ADAPTIVE_BLOCK_CEILING / 50;
/** The maximum number of sigops we're willing to relay/mine in a single tx */
static const unsigned int MAX_TX_SIGOPS = MAX_BLOCK_SIGOPS/5;
//static const unsigned int MAX_ORPHAN_TRANSACTIONS = MAX_BLOCK_SIZE/100; deprecated
/** Default for -maxorphantx, maximum number of orphan transactions kept in memory */
static const unsigned int DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100; // Was 10k
/** Default for -maxorphanblocks, maximum number of orphan blocks kept in memory */
static const unsigned int DEFAULT_MAX_ORPHAN_BLOCKS = 2500; // Increased for faster parallel sync
/** Default for -maxorphanmem, orphan pool ceiling in MB: the smallest power of two that holds
 *  one worst-case admitted block (up to ~28x its wire size).
 *  Pinned by orphan_pool_bound_tests/the_ceiling_holds_the_worst_admitted_block_at_the_measured_expansion. */
static const unsigned int DEFAULT_MAX_ORPHAN_BLOCKS_MEM = 256;
/** Floor for the effective -maxorphanmem ceiling, in megabytes: a sanity clamp
 *  on the knob. It sits below the low-memory soft-set so that profile gets the
 *  smaller pool it asks for instead of being clamped back up. */
static const unsigned int MIN_MAX_ORPHAN_BLOCKS_MEM = 32;
/** -maxorphanmem soft-set for the low-memory (hybrid SPV) profile, in megabytes.
 *  An ADAPTIVE_BLOCK_CEILING block exceeds it and is refused (unscored, re-asked). */
static const unsigned int LOWMEM_MAX_ORPHAN_BLOCKS_MEM = 64;
/** Percentage of the orphan byte ceiling one peer's held blocks may occupy, so one
 *  peer's never-draining orphans cannot pin the pool (byte pressure refuses, not
 *  evicts). Mirrors the entry bound's 750 of 2500; self-submitted blocks are exempt. */
static const unsigned int MAX_ORPHAN_MEM_SHARE_PER_PEER_PERCENT = 30;
/** Orphan block hold time in seconds, equal to TIMEOUT_INTERVAL; must exceed the entry-bound
 *  drain time (600 s). Pinned by orphan_pool_bound_tests/the_expiry_covers_an_honest_ancestor_fetch
 *  and .../an_orphan_older_than_the_expiry_is_dropped_and_a_younger_one_is_not. */
static const int64_t ORPHAN_BLOCK_EXPIRY_SECONDS = 20 * 60;
/** Base deferral added to a refused block's next request, in seconds. Doubles per
 *  refusal of the same hash so a full pool does not cause a re-request hot loop. */
static const int64_t ORPHAN_REFUSAL_BACKOFF_SECONDS = 8;
/** Doublings the deferral may take, so it tops out at 8 << 6 = 512 s. */
static const int ORPHAN_REFUSAL_BACKOFF_MAX_SHIFT = 6;
/** Cap on the refusal records held. Past it the base deferral is used and no
 *  record is kept, so the map cannot grow with the hashes offered. */
static const size_t MAX_ORPHAN_REFUSAL_RECORDS = 4096;
/** Cap on how far refusals push a hash's next request, in seconds; the record is keyed by
 *  hash, so one peer cannot delay a block for every peer.
 *  Pinned by orphan_pool_bound_tests/the_re_ask_deferral_is_capped_however_many_refusals_land. */
static const int64_t ORPHAN_REASK_MAX_DEFERRAL_SECONDS =
    ORPHAN_REFUSAL_BACKOFF_SECONDS << ORPHAN_REFUSAL_BACKOFF_MAX_SHIFT;
/** How long a block the pool can never hold is not requested, in seconds; lifted once its
 *  wait set is indexed. Pinned by orphan_pool_bound_tests/a_never_fits_block_is_not_re_asked_by_the_headers_path
 *  and .../a_never_fits_dag_orphan_is_not_re_asked_until_its_merge_parent_connects. */
static const int64_t ORPHAN_NEVER_FITS_SUPPRESS_SECONDS = 600;
/** Cap on the suppression records held, so the map cannot grow with the hashes a
 *  peer offers. Past it nothing is recorded and the hash is requested as before. */
static const size_t MAX_ORPHAN_NEVER_FITS_RECORDS = 4096;
/** How often the periodic sweep runs, in seconds. Parks sweep unconditionally,
 *  so this only covers a node that is not being offered blocks; it walks the
 *  pool and the message-handler loop calls it every turn, so it is spaced. */
static const int64_t ORPHAN_POOL_SWEEP_INTERVAL_SECONDS = 10;
/** Default for -maxmempool, maximum mempool size in MB */
static const unsigned int DEFAULT_MAX_MEMPOOL_SIZE = 300; // 300MB default
static const unsigned int MAX_INV_SZ = 50000;
static const unsigned int INV_RATE_LIMIT_WINDOW = 60;    // Time window in seconds
static const unsigned int INV_RATE_LIMIT_ITEMS = 2000;   // Max inv items per window (generous for sync)
static const int64_t MIN_TX_FEE = 1000;
static const int64_t MIN_NAME_FEE = 90000000; // 0.9 INN Name OP Miner Fee
static const int64_t NAME_FEE = 10000000; // 0.1 INN Name
static const CAmount MIN_TXOUT_AMOUNT = NAME_FEE;
static const int64_t MIN_TX_FEE_ANON = 10000;
static const int64_t MIN_RELAY_TX_FEE = MIN_TX_FEE;
static const int64_t MAX_MONEY = 18000000 * COIN; // 18,000,000 INN Innova Max
static const int64_t COIN_YEAR_REWARD = 0.06 * COIN; // 6% per year

static const int64_t MAINNET_POSFIX = 500; // Mainnet Proof of Stake update not enabled until block 500
static const int MN_ENFORCEMENT_ACTIVE_HEIGHT = 4500; // Enforce collateralnode payments after this height - BLOCK 4500
static const int MN_ENFORCEMENT_ACTIVE_HEIGHT_TESTNET = 999999; // Enforce CN payments after this height for Innova Testnet!

// Regtest-only collateralnode payment activation height (-regtestcnpayments).
// 0 leaves the mainnet era condition in force, which no regtest chain reaches,
// so the payment rules stay unreachable by default.
extern int nRegtestCNPaymentsHeight;

// First height at which a block owes a collateralnode payment. 0 means the
// network never enables them.
inline int GetCollateralnodePaymentEraHeight() {
    extern bool fRegTest;
    extern bool fTestNet;
    if (fTestNet) return BLOCK_START_COLLATERALNODE_PAYMENTS_TESTNET + 1;
    if (fRegTest) return nRegtestCNPaymentsHeight; // 0 unless rehearsing
    // Both mainnet floors, the higher binding. The shipped condition was
    // strictly greater, so the first paying height is one above it.
    return (BLOCK_START_COLLATERALNODE_PAYMENTS > 2085000
                ? BLOCK_START_COLLATERALNODE_PAYMENTS : 2085000) + 1;
}
#define COLLATERALNODE_PAYMENT_ERA_HEIGHT (GetCollateralnodePaymentEraHeight())

// The era condition, in one place. Producer and validator both read it, so a
// block cannot carry a payment the validator does not require or omit one it
// does.
inline bool CollateralnodePaymentsEnabledAtHeight(int nHeight) {
    const int nEra = GetCollateralnodePaymentEraHeight();
    return nEra > 0 && nHeight >= nEra;
}

// Height from which an unrecognised payee is refused rather than warned about.
// On mainnet payments begin long after enforcement, so paying implies enforced;
// the regtest knob keeps that composite by moving both to the same height.
inline int CollateralnodeEnforcementHeight() {
    extern bool fRegTest;
    extern bool fTestNet;
    if (fTestNet) return MN_ENFORCEMENT_ACTIVE_HEIGHT_TESTNET;
    if (fRegTest && nRegtestCNPaymentsHeight > 0) return nRegtestCNPaymentsHeight;
    return MN_ENFORCEMENT_ACTIVE_HEIGHT;
}

inline bool MoneyRange(int64_t nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }

/** Get the adaptive effective block size limit for a given height.
 *  Uses the median of recent block sizes with a penalty-free floor. */
unsigned int GetAdaptiveBlockSizeLimit(const CBlockIndex* pindex);

/** Calculate the block reward penalty for an oversized block (Monero-style quadratic).
 *  Returns the fraction of reward lost (0 = no penalty, COIN = 100% penalty). */
int64_t GetBlockSizePenalty(unsigned int nBlockSize, unsigned int nMedianSize);

/** Apply adaptive block size penalty to a reward amount. */
int64_t ApplyBlockSizePenalty(int64_t nReward, const CBlock& block, const CBlockIndex* pindexPrev);
bool CheckFinalityStakeProofsNotSpentInBlock(const CBlock& block, const std::vector<CFinalityVote>& vVotes);
/** Collect an IV5 transaction's payload key images as conflict
 *  tags, so DAG sibling-conflict resolution sees them alongside vin outpoints and
 *  legacy nullifiers. */
void AppendPrivacyVNextConflictTags(const CTransaction& tx,
                                    std::set<uint256>& setTagsOut);
bool TransactionConflictsWithDAGSiblingSpends(const CTransaction& tx,
                                              const std::set<COutPoint>& setDAGSpentOutputs,
                                              const std::set<uint256>& setDAGSpentNullifiers);
std::set<uint256> GetDAGSkippedTxsFromSiblingSpends(const CBlock& block,
                                                    const std::set<COutPoint>& setDAGSpentOutputs,
                                                    const std::set<uint256>& setDAGSpentNullifiers);
/** Which of two DAG siblings wins a spend conflict. Exported so the invariant that
 *  it reads nothing but committed (height, hash) can be pinned by a test. */
bool DAGSiblingPrecedesBlock(const uint256& hashBlock, const uint256& hashSibling);
/** The block's DAG-skipped transactions. *pfIncomplete is set when the set could not be
 *  fully derived on this node (missing vertex, unindexed or unreadable sibling); consensus
 *  callers refuse transiently rather than act on it. */
std::set<uint256> GetDAGSkippedTxsForBlock(const CBlock& block, const CBlockIndex* pindex,
                                           bool* pfIncomplete = NULL);
CBlock GetDAGActiveBlock(const CBlock& block, const std::set<uint256>& setDAGSkippedTxs);

// Fixed-input description binding a shielded-wallet recovery record to the exact
// pre-commit DAG-active transaction plan; the record stores only its digest.
struct CShieldedWalletEffectDigestEntry
{
    bool fConnect;
    uint256 hashBlock;
    std::set<uint256> setDAGSkippedTxs;

    CShieldedWalletEffectDigestEntry()
        : fConnect(false) {}

    CShieldedWalletEffectDigestEntry(
        bool fConnectIn, const uint256& hashBlockIn,
        const std::set<uint256>& setDAGSkippedTxsIn)
        : fConnect(fConnectIn), hashBlock(hashBlockIn),
          setDAGSkippedTxs(setDAGSkippedTxsIn) {}
};

uint256 ComputeShieldedWalletEffectPlanDigest(
    const std::vector<CShieldedWalletEffectDigestEntry>& vEntries);

// Threshold for nLockTime: below this value it is interpreted as block number, otherwise as UNIX timestamp.
static const unsigned int LOCKTIME_THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC

/** Maxiumum number of signature check operations in an IsStandard() P2SH script */
static const unsigned int MAX_P2SH_SIGOPS = 15;

static const uint256 hashGenesisBlock("0x000009bd42d259eb7031ae4f634aede1a690da795e5529786a72c3cd6d989995");
static const uint256 hashGenesisBlockTestNet("0x00004f9f245acf85d86878eff8f80cf47f7e563727531c21fa175a0fe503bf6b");
static const uint256 hashGenesisBlockRegTest("0x7d9f2da2e66d3ee806dce8231f5854a526a32db9c8b509410f652a101089c7d5");

inline const uint256& GetGenesisBlockHash()
{
    if (fRegTest) return hashGenesisBlockRegTest;
    if (fTestNet) return hashGenesisBlockTestNet;
    return hashGenesisBlock;
}

//inline bool IsProtocolV1RetargetingFixed(int nHeight) { return fTestNet || nHeight > 0; }
//inline bool IsProtocolV2(int nHeight) { return fTestNet || nHeight > 0; }
//inline bool V3(int64_t nTime) { return fTestNet || nTime > 1524196491; } //nTime April 20th 2018

// Hard fork height for tighter timestamp drift rules
inline int GetForkHeightTighterDrift() {
    extern bool fRegTest;
    extern bool fTestNet;
    return (fRegTest || fTestNet) ? 1 : ShiftMainnetV5Activation(7800000);
}
#define FORK_HEIGHT_TIGHTER_DRIFT (GetForkHeightTighterDrift())

// Hard fork height for collateralnode payment validation enhancements
inline int GetForkHeightCNPaymentValidation() {
    extern bool fRegTest;
    extern bool fTestNet;
    return (fRegTest || fTestNet) ? 1 : ShiftMainnetV5Activation(7800000);
}
#define FORK_HEIGHT_CN_PAYMENT_VALIDATION (GetForkHeightCNPaymentValidation())

// Minimum CN protocol version after fork (requires v4.3.9.5+)
// Forces CN operators to update to current software for continued payments
static const int FORK_MIN_CN_PROTO_VERSION = 43950;

// Regtest-only cold-staking activation height (-regtestcoldstaking). 0 leaves
// the gate at 1, and no coinstake can sit below height 1, so the pre-gate branch
// stays unreachable by default.
extern int nRegtestColdStakingHeight;

// Hard fork height for cold staking (P2CS) support
// In regtest/testnet mode, cold staking activates at block 1
inline int GetForkHeightColdStaking() {
    extern bool fRegTest;
    extern bool fTestNet;
    if (fRegTest && nRegtestColdStakingHeight > 0) return nRegtestColdStakingHeight;
    return (fRegTest || fTestNet) ? 1 : ShiftMainnetV5Activation(7800000);
}
#define FORK_HEIGHT_COLD_STAKING (GetForkHeightColdStaking())

// Hard fork height for shielded transactions (zk-SNARK privacy)
// In regtest/testnet mode, shielded transactions activate at block 1
inline int GetForkHeightShielded() {
    extern bool fRegTest;
    extern bool fTestNet;
    return (fRegTest || fTestNet) ? 1 : ShiftMainnetV5Activation(7810000);
}
#define FORK_HEIGHT_SHIELDED (GetForkHeightShielded())

// ANON_TXN_VERSION (1000) is retired on every network from genesis. A full
// replay of mainnet to 7,889,246 counted zero ring-signature transactions ever
// -- no outputs, no key images, nothing unclaimed -- so rejecting from height 0
// cannot change how any historical block validates. Returning 0 rather than
// deleting the checks keeps every >= site rejecting, including the consensus
// ones in ConnectInputs, ConnectBlock and AcceptBlock.
inline int GetForkHeightRingSigDeprecation() {
    return 0;
}
#define FORK_HEIGHT_RINGSIG_DEPRECATION (GetForkHeightRingSigDeprecation())

// Hard fork height for Dynamic Selective Privacy
// 3-bit nPrivacyMode field in SHIELDED_TX_VERSION_DSP_PROTOTYPE (2001)
inline int GetForkHeightDSP() {
    extern bool fRegTest;
    extern bool fTestNet;
    return (fRegTest || fTestNet) ? 2 : ShiftMainnetV5Activation(7815000);
}
#define FORK_HEIGHT_DSP (GetForkHeightDSP())

// Hard fork height for NullSend
inline int GetForkHeightNullSend() {
    extern bool fRegTest;
    extern bool fTestNet;
    return (fRegTest || fTestNet) ? 2 : ShiftMainnetV5Activation(7820000);
}
#define FORK_HEIGHT_NULLSEND (GetForkHeightNullSend())
#define FORK_HEIGHT_CJOIN FORK_HEIGHT_NULLSEND

// Hard fork height for FCMP++ validation
// same height as FORK_HEIGHT_FCMP (curvetree.h)
#define FORK_HEIGHT_FCMP_VALIDATION (FORK_HEIGHT_FCMP)

// Hard fork height for NullStake private staking
// shielded PoS via ZK kernel proofs
inline int GetForkHeightNullStake() {
    extern bool fRegTest;
    extern bool fTestNet;
    return (fRegTest || fTestNet) ? 3 : ShiftMainnetV5Activation(7825000);
}
#define FORK_HEIGHT_NULLSTAKE (GetForkHeightNullStake())

// Hard fork height for NullStake V2 ZK kernel privacy
// hides kernel params in AC proof
inline int GetForkHeightNullStakeV2() {
    extern bool fRegTest;
    extern bool fTestNet;
    return (fRegTest || fTestNet) ? 5 : ShiftMainnetV5Activation(7830000);
}
#define FORK_HEIGHT_NULLSTAKE_V2 (GetForkHeightNullStakeV2())

// Hard fork height for NullStake V3: Private Cold Staking
inline int GetForkHeightNullStakeV3() {
    extern bool fRegTest;
    extern bool fTestNet;
    return (fRegTest || fTestNet) ? 7 : ShiftMainnetV5Activation(7835000);
}
#define FORK_HEIGHT_NULLSTAKE_V3 (GetForkHeightNullStakeV3())

// Hard fork height for Chaumian CoinJoin/NullSend (blind signature protocol upgrade)
inline int GetForkHeightChaumianCJ()
{
    extern bool fRegTest;
    extern bool fTestNet;
    return (fRegTest || fTestNet) ? 8 : ShiftMainnetV5Activation(7840000);
}
#define FORK_HEIGHT_CHAUMIAN_CJ (GetForkHeightChaumianCJ())

// Coinbase millisecond-offset commitment (IMTS, 0..999): exactly one from this height,
// none below; unused in v5. -regtestmstimestamp overrides on regtest.
extern int nRegtestMsTimestampHeight;

inline int GetForkHeightMsTimestamp()
{
    extern bool fRegTest;
    extern bool fTestNet;
    if (fRegTest) return nRegtestMsTimestampHeight;
    if (fTestNet) return 30;    // pre-gate window, then a 30-block soak before DAG at 60
    return ShiftMainnetV5Activation(7920000);
}
#define FORK_HEIGHT_MS_TIMESTAMP (GetForkHeightMsTimestamp())

// Lowest height at which the below-gate absence rule is enforced: the v5 first
// gate on mainnet, so resync never applies it to history; 1 elsewhere.
inline int GetMsTimestampAbsenceFloor()
{
    extern bool fRegTest;
    extern bool fTestNet;
    if (fRegTest || fTestNet) return 1;
    return ShiftMainnetV5Activation(MAINNET_V5_ACTIVATION_BASE);
}

/** Rewrite or append the coinbase millisecond commitment for a final header time.
 *  Called by both producer paths; no-op below the gate. Defined in miner.cpp. */
void StampMsTimestampCommitment(CBlock* pblock, int nHeight);

// POEM entropy weighting
inline int GetForkHeightPoem()
{
    extern bool fRegTest;
    extern bool fTestNet;
    if (fRegTest) return 9;
    if (fTestNet) return 9;         // clean public IDAG testnet
    return ShiftMainnetV5Activation(7940000); // 140K after the base gate
}
#define FORK_HEIGHT_POEM (GetForkHeightPoem())

// PoS finality gadget
inline int GetForkHeightFinality()
{
    extern bool fRegTest;
    extern bool fTestNet;
    if (fRegTest) return 10;
    if (fTestNet) return 10;        // clean public IDAG testnet
    return ShiftMainnetV5Activation(7945000); // 5,000 blocks after POEM
}
#define FORK_HEIGHT_FINALITY (GetForkHeightFinality())

// Full DAG consensus and throughput scaling
inline int GetForkHeightDAG()
{
    extern bool fRegTest;
    extern bool fTestNet;
    if (fRegTest) return 11;
    if (fTestNet) return 60;        // clean public IDAG testnet after premine maturity
    return ShiftMainnetV5Activation(7950000); // 5,000 blocks after finality
}
#define FORK_HEIGHT_DAG (GetForkHeightDAG())

// Total-supply cap. From this height the block subsidy is clamped to the headroom
// left under the cap (zero past it); fees are unaffected. Activates with the DAG fork.
extern int nRegtestSupplyCapHeight;
inline int GetForkHeightSupplyCap()
{
    extern bool fRegTest;
    if (fRegTest && nRegtestSupplyCapHeight >= 0)
        return nRegtestSupplyCapHeight;
    return GetForkHeightDAG();
}
#define FORK_HEIGHT_SUPPLY_CAP (GetForkHeightSupplyCap())

inline bool IsSupplyCapActiveAtHeight(int nHeight)
{
    return nHeight >= FORK_HEIGHT_SUPPLY_CAP;
}

// The supply cap: MAX_MONEY, except -regtestsupplycap may lower it on regtest.
// The override can only lower the cap, so MoneyRange stays a superset.
extern int64_t nRegtestSupplyCapAmount;
inline int64_t GetSupplyCapAmount()
{
    extern bool fRegTest;
    if (fRegTest && nRegtestSupplyCapAmount > 0 && nRegtestSupplyCapAmount < MAX_MONEY)
        return nRegtestSupplyCapAmount;
    return MAX_MONEY;
}

// IDAG privacy root transition: FCMP spends bind to the last finalized
// epoch curve-tree snapshot instead of the mutable per-block tree.
inline int GetForkHeightEpochRootFCMP()
{
    extern bool fRegTest;
    extern bool fTestNet;
    if (fRegTest || fTestNet) return GetForkHeightDAG();
    return GetForkHeightDAG();        // mainnet: activate with the DAG fork
}
#define FORK_HEIGHT_EPOCH_ROOT_FCMP (GetForkHeightEpochRootFCMP())

// Per-epoch finality vote-set accumulator. CEpochState.hashVoteSetRoot commits the
// votes embedded in the epoch's blocks and CheckTallyCertificate requires a private
// cert to cover exactly that set. Fresh-chain only (no migration of epoch records).
inline int GetForkHeightVoteSetRoot()
{
    extern bool fRegTest;
    extern bool fTestNet;
    if (fRegTest || fTestNet) return GetForkHeightDAG();
    return GetForkHeightDAG();        // mainnet: pre-launch, activate with the DAG fork
}
#define FORK_HEIGHT_VOTESET_ROOT (GetForkHeightVoteSetRoot())

// Deterministic epoch-state anchor (v2): a pure function of a canonical anchor block,
// recomputed on reorg. Fresh-chain only; activates with the DAG fork.
inline int GetForkHeightEpochStateV2()
{
    return GetForkHeightDAG();
}
#define FORK_HEIGHT_EPOCH_STATE_V2 (GetForkHeightEpochStateV2())

// From this fork the V2 epoch builder commits carriers only from the connected pprev chain.
// Regtest activates two blocks after the DAG fork to exercise both paths in one epoch.
static const int TESTNET_CONNECTED_FINALITY_CARRIER_HEIGHT_UNSET = 0x7fffffff;
inline int GetForkHeightConnectedFinalityCarrier()
{
    extern bool fRegTest;
    if (fRegTest) return GetForkHeightDAG() + 2;
    return GetForkHeightDAG();
}
#define FORK_HEIGHT_CONNECTED_FINALITY_CARRIER (GetForkHeightConnectedFinalityCarrier())

inline bool IsConnectedFinalityCarrierConfigured()
{
    return FORK_HEIGHT_CONNECTED_FINALITY_CARRIER !=
           TESTNET_CONNECTED_FINALITY_CARRIER_HEIGHT_UNSET;
}

inline bool IsConnectedFinalityCarrierActiveAtHeight(int nHeight)
{
    return IsConnectedFinalityCarrierConfigured() &&
           nHeight >= FORK_HEIGHT_CONNECTED_FINALITY_CARRIER;
}

// Epoch-state schema V3. Must sit exactly one post-DAG epoch above the DAG fork so no
// DAG-era epoch uses BuildEpochStateV2Compat (v2compat_epoch_build_never_owns_a_dag_era_epoch).
static const int TESTNET_EPOCH_STATE_V3_HEIGHT_UNSET = 0x7fffffff;
// FORK_HEIGHT_DAG (60) + one post-DAG epoch (FINALITY_EPOCH_INTERVAL_POST_DAG, 300).
static const int TESTNET_EPOCH_STATE_V3_HEIGHT = 360;
inline int GetForkHeightEpochStateV3()
{
    extern bool fRegTest;
    extern bool fTestNet;
    if (fTestNet) return TESTNET_EPOCH_STATE_V3_HEIGHT;
    return GetForkHeightDAG() + 300;
}
#define FORK_HEIGHT_EPOCH_STATE_V3 (GetForkHeightEpochStateV3())

inline bool IsEpochStateV3Configured()
{
    return FORK_HEIGHT_EPOCH_STATE_V3 != TESTNET_EPOCH_STATE_V3_HEIGHT_UNSET;
}

// Boundary A: safe-IDAG activation. Co-activates epoch-state schema V3, strict
// canonical parent commitments and bounded DAGKNIGHT state, and quarantines the
// legacy privacy/proof encodings. Alias of the schema-V3 height.
inline int GetForkHeightBoundaryA()
{
    return GetForkHeightEpochStateV3();
}
#define FORK_HEIGHT_BOUNDARY_A (GetForkHeightBoundaryA())

// Boundary B restores the modes Boundary A quarantines. Alias of Boundary A, so a
// ladder re-base moves both; BoundaryOrderingHolds() requires B >= A.
// The height decides when the pool opens; proofs are always verified.
static const int PRIVACY_VNEXT_HEIGHT_UNSET = 0x7fffffff;
// Regtest-only rehearsal height for Boundary B (-regtestboundaryb); defaults to
// the sentinel.
extern int nRegtestBoundaryBHeight;

inline int GetForkHeightBoundaryB()
{
    extern bool fRegTest;
    return fRegTest ? nRegtestBoundaryBHeight : GetForkHeightBoundaryA();
}
#define FORK_HEIGHT_BOUNDARY_B (GetForkHeightBoundaryB())

inline bool IsBoundaryAConfigured()
{
    return FORK_HEIGHT_BOUNDARY_A != TESTNET_EPOCH_STATE_V3_HEIGHT_UNSET;
}

inline bool IsBoundaryAActiveAtHeight(int nHeight)
{
    return IsBoundaryAConfigured() && nHeight >= FORK_HEIGHT_BOUNDARY_A;
}

inline bool IsBoundaryBConfigured()
{
    return FORK_HEIGHT_BOUNDARY_B != PRIVACY_VNEXT_HEIGHT_UNSET;
}

inline bool IsBoundaryBActiveAtHeight(int nHeight)
{
    return IsBoundaryBConfigured() && nHeight >= FORK_HEIGHT_BOUNDARY_B;
}

// No height may have B live and A not. Unset boundaries are INT_MAX sentinels;
// equality is the shipping case.
inline bool BoundaryOrderingHolds()
{
    return FORK_HEIGHT_BOUNDARY_B >= FORK_HEIGHT_BOUNDARY_A;
}

// IV5 pool boundary: unshield retired and pool fees settle as a coinbase note. Both
// activate together, so this derives from Boundary B off regtest.
extern int nRegtestIV5FeeNoteHeight;

// Takes the Boundary-B height as an argument so the derivation is testable at
// heights the public networks do not carry.
inline int DeriveIV5FeeNoteHeight(int nBoundaryBHeight)
{
    return nBoundaryBHeight;
}

inline int GetForkHeightIV5FeeNote()
{
    extern bool fRegTest;
    return fRegTest ? nRegtestIV5FeeNoteHeight
                    : DeriveIV5FeeNoteHeight(GetForkHeightBoundaryB());
}
#define FORK_HEIGHT_IV5_FEE_NOTE (GetForkHeightIV5FeeNote())

// F2: note-weighted finality voting. One flag day carries the whole set -- the vote
// envelope, the share carrier with its VSS coefficients, the complaint object, the v4
// certificate and its coverage carve-out -- because every one of them is
// consensus-visible and retrofitting any of them would cost a second flag day on a chain
// that needs every node upgraded before the first.
//
// Transparent votes stay permanently valid on both sides of this height: they are the
// liveness floor a stalled committee falls back to.
//
// The pool must exist before a note can be voted, so this is scheduled after
// Assume-valid: the block whose ancestry this binary asserts was fully validated.
//
// A payload in a block that is an ANCESTOR of this hash may skip its proof verdicts during
// sync -- 97-98% of the cost of validating one. Everything else still runs: proof-of-work on
// every block, every structural rule, and the identical state computation.
//
// Ancestry, never height. A fork can reach any height it likes; it cannot put a block on the
// path to a hash shipped in the binary.
//
// The trust this buys back is real and worth stating: below this hash a node trusts the
// release rather than the mathematics, and GetPrivacyVNextPoolDelta reads the balance a
// payload DECLARES, whose proof is one of the verdicts skipped. -assumevalid=0 restores
// full verification. Only ever advance this to a block the project has itself validated in
// full, and re-cut it each release.
//
// Empty on testnet and regtest: they are rebuilt often and their history is not asserted.
static const char* const MAINNET_ASSUME_VALID_BLOCK =
    "0x00000000523d02837bf00acee580aa7e4443b6da34929b8b2caa7116e10c353a";  // 7,750,000

// Regtest-only rehearsal height for the note-vote lane (-regtestiv5notevote).
// init.cpp refuses a value below Boundary B.
extern int nRegtestIV5NoteVoteHeight;

/** Where the note-vote lane activates: 4,800 blocks past Boundary B, so the pool and the
 *  boundary have settled before any note votes. Shift-invariant, because Boundary B moves
 *  with the ladder and this rides it.
 *
 *  The gap is a whole number of post-DAG epochs (16 x FINALITY_EPOCH_INTERVAL_POST_DAG)
 *  and Boundary B is itself one epoch above the DAG gate, so the result opens an epoch on
 *  every network, so activation is uniform within every epoch. Two gates read this height:
 *  the per-block one, on a connect height, and the per-epoch one, on state.nHeightEnd,
 *  which decides whether an epoch state commits note-vote leaves and which serialization
 *  version it is written at. They agree for every block of an epoch only when the height
 *  opens one. Off a boundary the straddling epoch is written V6 while its whole 24-block
 *  vote window precedes activation, so it commits a note-vote epoch no vote could enter.
 *
 *  This is a derivation and not a literal on purpose. The height used to live only in
 *  prose, which is the shape that leaves a stale value behind the next time the ladder is
 *  re-based -- the 2026-09-13 re-base left three of those. The gap is the invariant; the
 *  height is what the gap produces. */
inline int DeriveIV5NoteVoteHeight(int nBoundaryBHeight)
{
    return nBoundaryBHeight + 4800;
}

inline int GetForkHeightIV5NoteVote()
{
    extern bool fRegTest;
    if (fRegTest)
        return nRegtestIV5NoteVoteHeight;
    // Scheduled on both value networks. What kept this at the sentinel was that a vote did
    // not prove its note unspent, so one note self-transferred voted once per transfer and
    // was paid each time. The vote now spends its note as an operation-10 payload, so a
    // second vote of the same note is a double spend the one spent-key path refuses.
    //
    // The same height turns on the drawn committee an epoch state carries, member-key
    // registration, and the minimum-weight floor on transparent votes: they are one flag
    // day because each is consensus-visible and none can be retrofitted separately.
    return DeriveIV5NoteVoteHeight(GetForkHeightBoundaryB());
}
#define FORK_HEIGHT_IV5_NOTE_VOTE (GetForkHeightIV5NoteVote())

inline bool IsIV5NoteVoteConfigured()
{
    return FORK_HEIGHT_IV5_NOTE_VOTE != PRIVACY_VNEXT_HEIGHT_UNSET;
}

inline bool IsIV5NoteVoteActiveAtHeight(int nHeight)
{
    return IsIV5NoteVoteConfigured() && nHeight >= FORK_HEIGHT_IV5_NOTE_VOTE;
}

inline bool IsIV5FeeNoteConfigured()
{
    return FORK_HEIGHT_IV5_FEE_NOTE != PRIVACY_VNEXT_HEIGHT_UNSET;
}

inline bool IsIV5FeeNoteActiveAtHeight(int nHeight)
{
    return IsIV5FeeNoteConfigured() && nHeight >= FORK_HEIGHT_IV5_FEE_NOTE;
}

// Public testnet/mainnet candidates stop creating and relaying legacy privacy
// transactions immediately, before the consensus boundary. Regtest retains
// the historical formats solely for deterministic replay and rejection tests.
inline bool IsLegacyPrivacyPolicyDisabled()
{
    extern bool fRegTest;
    return !fRegTest;
}

// A privacy-encoded coinstake must be unreachable on every public network at every height.
// The predicates below derive this from the gates; nullstake_finality_only_tests pins them.

// Legacy NullStake (2003/2004/2005). Rejected by CheckTransaction, AcceptBlock and
// ConnectInputs; ConnectBlock rejects all PoS blocks at or above the DAG gate. On
// mainnet [FORK_HEIGHT_NULLSTAKE, FORK_HEIGHT_DAG) is closed by the legacy-privacy policy.
inline bool IsNullStakeBlockProductionReachableAtHeight(int nHeight)
{
    if (IsLegacyPrivacyPolicyDisabled() || IsBoundaryAActiveAtHeight(nHeight))
        return false;
    if (nHeight >= FORK_HEIGHT_DAG)
        return false;
    return nHeight >= FORK_HEIGHT_NULLSTAKE;
}

// vNext NullStake (2008) is finality voting only: Boundary B >= A = DAG + 300, and PoS
// block production ends at the DAG gate. PrivateStakeIsFinalityOnly() checks the ordering.
inline bool IsPrivacyVNextCoinStakeReachableAtHeight(int nHeight)
{
    if (!IsBoundaryBActiveAtHeight(nHeight) || !IsShieldedVNextConsensusReady())
        return false;
    return nHeight < FORK_HEIGHT_DAG;
}

// Startup check of the ordering above: Boundary A must sit above the DAG gate.
inline bool PrivateStakeIsFinalityOnly()
{
    return BoundaryOrderingHolds() && FORK_HEIGHT_BOUNDARY_A > FORK_HEIGHT_DAG;
}

/** First schema-V3 suffix epoch affected by a reorg whose common ancestor is nForkHeight.
 *  The migration-base epoch is the lower bound because older V2 history is an immutable input. */
int GetFirstV3EpochStateRebuildEpoch(int nForkHeight);

/** First schema-V2 epoch whose linear boundary-crossing anchor can change after
 *  a reorg at nForkHeight. Pre-V2 history remains byte-for-byte legacy. */
int GetFirstV2EpochStateRebuildEpoch(int nForkHeight);

// Reachability of the legacy schema-V2 epoch builder. BuildEpochStateV2Compat reads
// node-local mapDAGData.fBlue into CEpochState::GetDigest(), so it must never build an
// epoch containing DAG-era blocks. Each of the three entry points calls its predicate.

/** AddToBlockIndex: builds the completed epoch whose whole range predates schema V2. */
bool V2CompatEpochBuildsAtIndexCrossing(int nHeight, int& nEpochOut);

/** SetBestChainInner: stages the completed V2-range epoch at its exact crossing block. */
bool V2CompatEpochStagesAtBestChainCrossing(int nHeight, int& nEpochOut);

/** Reorganize: the epoch range the connect loop may stage, given the reorg's endpoints.
 *  Returns false when the reorg takes the V3 path or predates V2 entirely. */
bool V2CompatReorgStagesEpochRange(int nOldTipHeight, int nNewTipHeight, int nForkHeight,
                                   int& nFirstEpochOut, int& nLastEpochOut);

/** Reorganize: whether the connect-loop block at nHeight stages an epoch in that range. */
bool V2CompatEpochStagesAtReorgCrossing(int nHeight, int nFirstStagedEpoch,
                                        int nLastV2EpochToStage, int& nEpochOut);

// Nullifier binding: above this height shielded spends and private finality
// votes must carry a note-bound nullifier proof. Testnet relaunches the shielded
// pool clean here. Mainnet MUST enforce it from the first height a shielded
// spend is possible (FORK_HEIGHT_SHIELDED): anchoring it to the later DAG fork
// would leave a window where an unbound nullifier could over-withdraw from the
// shielded pool (supply inflation).
inline int GetForkHeightNullifierBinding()
{
    extern bool fRegTest;
    extern bool fTestNet;
    if (fRegTest) return 8;          // active early so regtest exercises the rule
    if (fTestNet) return 400;        // future height: relaunch shielded pool clean here
    return GetForkHeightShielded();  // mainnet: born safe with the shielded pool
}
#define FORK_HEIGHT_NULLIFIER_BINDING (GetForkHeightNullifierBinding())

// NullStake V2/V3 kernel public-input pinning: above this height the kernel
// metadata fields (nBlockTimeFrom/nTxPrevOffset/nTxTimePrev/nVoutN) of V2/V3
// coinstakes and private finality votes are consensus-pinned to fixed values.
// The circuits take them as free public inputs and the curve-tree leaves carry
// no age metadata, so unpinned values allow coin-age forgery / kernel grinding
// and leak the staked note's creation block + position in the clear.
inline int GetForkHeightKernelPinning()
{
    extern bool fRegTest;
    extern bool fTestNet;
    if (fRegTest) return 8;           // active early so regtest exercises the rule
    if (fTestNet) return 450;         // after the connected epoch-360 votes, before the next boundary
    return GetForkHeightNullStakeV2(); // mainnet: pinned from V2 activation (no unpinned history)
}
#define FORK_HEIGHT_KERNEL_PINNING (GetForkHeightKernelPinning())

// Fixed synthetic coin age used by pinned V2/V3 kernels: every staked note
// claims exactly this age, so kernel weight reduces to note value only.
static const int64_t NULLSTAKE_PINNED_AGE = 30 * 24 * 60 * 60; // 30 days

// Consensus check for pinned V2/V3 kernel public inputs (see
// FORK_HEIGHT_KERNEL_PINNING). nTimeTx itself is cross-checked against the
// including block / epoch block by the caller.
inline bool CheckNullStakeKernelPinning(unsigned int nBlockTimeFrom,
                                        unsigned int nTxPrevOffset,
                                        unsigned int nTxTimePrev,
                                        unsigned int nVoutN,
                                        unsigned int nTimeTx)
{
    if ((int64_t)nTimeTx <= NULLSTAKE_PINNED_AGE)
        return false;
    if ((int64_t)nBlockTimeFrom != (int64_t)nTimeTx - NULLSTAKE_PINNED_AGE)
        return false;
    if (nTxTimePrev != nBlockTimeFrom)
        return false;
    if (nTxPrevOffset != 0)
        return false;
    if (nVoutN != 0)
        return false;
    return true;
}

// DAGKNIGHT adaptive ordering (replaces GHOSTDAG)
inline int GetForkHeightDAGKnight()
{
    extern bool fRegTest;
    extern bool fTestNet;
    if (fRegTest) return 13;
    if (fTestNet) return 62;        // clean public IDAG testnet after DAG activation
    return ShiftMainnetV5Activation(8000000); // 50,000 blocks after DAG
}
#define FORK_HEIGHT_DAGKNIGHT (GetForkHeightDAGKnight())

// Canonical-encoding enforcement for committee signatures, so a relayed certificate
// cannot be re-encoded to a different hash. Rides the first v5 gate.
inline int GetForkHeightCommitteeSigCanonical()
{
    extern bool fRegTest;
    extern bool fTestNet;
    if (fRegTest) return 1;
    if (fTestNet) return 1;
    return ShiftMainnetV5Activation(7800000);
}
#define FORK_HEIGHT_COMMITTEE_SIG_CANONICAL (GetForkHeightCommitteeSigCanonical())

inline int GetForkHeightTallyGovernance()
{
    extern bool fRegTest;
    extern bool fTestNet;
    if (fRegTest) return 8;
    if (fTestNet) return 660;        // live-chain activation at the epoch-2 boundary (tip ~430), reachable to exercise
    // Mainnet: co-activates with the DAG fork, the first height a private cert can exist.
    return GetForkHeightDAG();
}
#define FORK_HEIGHT_TALLY_GOVERNANCE (GetForkHeightTallyGovernance())

// M-of-N cold-staking gates, off the public ladder: they return the sentinel off regtest
// so the guarded paths fail closed.

// B2-e: half-aggregated Schnorr M-of-N shielded cold staking (public-signer tier).
inline int GetForkHeightNullStakeDelegSet()
{
    extern bool fRegTest;
    if (fRegTest) return 12;
    return PRIVACY_VNEXT_HEIGHT_UNSET;
}
#define FORK_HEIGHT_NULLSTAKE_DELEGSET (GetForkHeightNullStakeDelegSet())

// B2-e Phase 3c.4: owner-override reclaim of an idle M-of-N cold-stake note.
inline int GetForkHeightNullStakeReclaim()
{
    extern bool fRegTest;
    if (fRegTest) return 12;
    return PRIVACY_VNEXT_HEIGHT_UNSET;
}
#define FORK_HEIGHT_NULLSTAKE_RECLAIM (GetForkHeightNullStakeReclaim())

// B2-c: ZK-hidden-signer M-of-N tier (NULLSTAKE_AUTHMODE_B2C_HIDDEN). Must be
// >= FORK_HEIGHT_NULLSTAKE_DELEGSET. Gated at the consensus call sites, not the verifier.
inline int GetForkHeightNullStakeB2C()
{
    extern bool fRegTest;
    if (fRegTest) return 14;         // > DELEGSET(12), so e2e can exercise pre/post-B2C with one 2006 note
    return PRIVACY_VNEXT_HEIGHT_UNSET;
}
#define FORK_HEIGHT_NULLSTAKE_B2C (GetForkHeightNullStakeB2C())

// B2-e: blocks a spent cv3 leaf must sit un-restaked before an owner reclaim. Must exceed
// the realistic re-stake interval and be >> MIN_SHIELDED_SPEND_DEPTH. Only regtest reaches it.
inline int GetReclaimTimelock()
{
    extern bool fRegTest;
    extern bool fTestNet;
    if (fRegTest) return 20;         // short for regtest e2e
    if (fTestNet) return 720;
    return 43200;
}
#define RECLAIM_TIMELOCK (GetReclaimTimelock())

// Compile-time target spacing for persisted or consensus-adjacent code: nTargetSpacing is
// reassigned on regtest. Keep PRE_DAG_TARGET_SPACING in sync with its init value.
static const int64_t PRE_DAG_TARGET_SPACING = 15;
static const int64_t POST_DAG_TARGET_SPACING = 1;

// Blocks the post-DAG retarget observation spans. Timestamps are whole seconds, so a
// single 1s gap can never read below target; a window restores a clamp floor strictly
// below target (POST_DAG_RETARGET_WINDOW/4).
static const int POST_DAG_RETARGET_WINDOW = 60;

// IDAG: Fork-gated block time — 15s pre-DAG, 1s post-DAG
inline unsigned int GetTargetSpacingForHeight(int nHeight)
{
    extern bool fRegTest;
    extern unsigned int nTargetSpacing;
    if (fRegTest) return 1; // regtest always 1s
    if (nHeight >= FORK_HEIGHT_DAG) return 1; // 1-second blocks post-DAG
    return nTargetSpacing; // 15 seconds pre-DAG
}

// IDNS name reset: names registered before this height expire; 0 = no reset.
// Sits between the v5 first gate and the DAG gate. Changing it invalidates the
// persisted name cursor. -regtestidnsreset overrides on regtest (0 = no reset).
extern int nRegtestIDNSResetHeight;

inline int GetForkHeightIDNSReset() {
    extern bool fRegTest;
    extern bool fTestNet;
    if (fRegTest) return nRegtestIDNSResetHeight; // 0 unless rehearsing
    if (fTestNet) return 0;     // No reset in testnet (clean chain)
    return ShiftMainnetV5Activation(7900000); // Mainnet: between the v5 first gate and the DAG gate
}
#define FORK_HEIGHT_IDNS_RESET (GetForkHeightIDNSReset())

inline int64_t PastDrift(int64_t nTime, int nHeight) {
    if (nHeight >= FORK_HEIGHT_TIGHTER_DRIFT)
        return nTime - 2 * 60;  // 2 minutes after fork
    return nTime - 10 * 60;     // 10 minutes before fork
}

inline int64_t FutureDrift(int64_t nTime, int nHeight) {
    if (nHeight >= FORK_HEIGHT_TIGHTER_DRIFT)
        return nTime + 2 * 60;
    return nTime + 10 * 60;
}

// Legacy drift - use when height is unknown
inline int64_t PastDrift(int64_t nTime)   { return nTime - 10 * 60; } // up to 10 minutes from the past
inline int64_t FutureDrift(int64_t nTime) { return nTime + 10 * 60; } // up to 10 minutes from the future

//inline unsigned int GetTargetSpacing(int nHeight) { return IsProtocolV2(nHeight) ? 60 : 60; }

inline int64_t GetMNCollateral() { return 25000; }

extern CScript COINBASE_FLAGS;
extern CCriticalSection cs_main;
extern std::map<uint256, CBlockIndex*> mapBlockIndex;
extern std::set<std::pair<COutPoint, unsigned int> > setStakeSeen;
extern CBlockIndex* pindexGenesisBlock;
extern unsigned int nTargetSpacing;
extern unsigned int nStakeMinAge;
extern unsigned int nStakeMaxAge;
extern int64_t nLastCoinStakeSearchTime;
extern unsigned int nNodeLifespan;
extern bool CollateralNReorgBlock;
extern int nCoinbaseMaturity;
extern int nBestHeight;
extern uint256 nBestChainTrust;
extern uint256 nBestInvalidTrust;
extern uint256 hashBestChain;
extern CBlockIndex* pindexBest;
//extern unsigned int nTransactionsUpdated;
extern uint64_t nLastBlockTx;
extern uint64_t nLastBlockSize;
extern int64_t nLastCoinStakeSearchInterval;
extern const std::string strMessageMagic;
extern int64_t nTimeBestReceived;
extern CCriticalSection cs_setpwalletRegistered;
extern std::set<CWallet*> setpwalletRegistered;
extern unsigned char pchMessageStart[4];
/** One held orphan block: the block, the byte footprint charged for it, and the
 *  hash it is parked under. The size is stored once, here, so the pool total
 *  cannot drift away from the set of records it sums. */
struct COrphanBlock
{
    CBlock* pblock;
    size_t nFootprint;
    uint256 hashWaitedFor;
    int64_t nTimeParked;

    COrphanBlock() : pblock(NULL), nFootprint(0), nTimeParked(0) {}
    COrphanBlock(CBlock* pblockIn, size_t nFootprintIn, const uint256& hashWaitedForIn,
                 int64_t nTimeParkedIn)
        : pblock(pblockIn), nFootprint(nFootprintIn), hashWaitedFor(hashWaitedForIn),
          nTimeParked(nTimeParkedIn) {}
};

extern std::map<uint256, COrphanBlock> mapOrphanBlocks;
extern std::multimap<uint256, CBlock*> mapOrphanBlocksByPrev;
extern std::map<uint256, NodeId> mapOrphanBlocksByNode;
extern std::map<NodeId, int> mapOrphanCountByNode;
extern std::set<std::pair<COutPoint, unsigned int> > setStakeSeenOrphan;

// Release an orphan PoS kernel marker only when no stored orphan still references
// it, so an evicted orphan cannot leave a stale marker that rejects re-deliveries.
void EraseStakeSeenOrphanIfUnreferenced(const std::pair<COutPoint, unsigned int>& stake);

// Memory charged for holding one orphan: its wire size plus the per-object
// overhead of the vectors it deserialises into.
size_t OrphanBlockFootprint(const CBlock& block);

// Running total of the footprints of the held orphans, and the effective
// -maxorphanmem ceiling in bytes (clamped to MIN_MAX_ORPHAN_BLOCKS_MEM from
// below and to what a size_t can hold from above).
size_t GetOrphanBlocksFootprint();
size_t GetMaxOrphanBlocksFootprint();

// The share of that ceiling one peer's own held blocks may occupy.
size_t GetMaxOrphanBlocksFootprintPerPeer();

// Bytes charged to one owner. owner < 0 reads the bytes held for no peer.
size_t GetOrphanBlocksFootprintForNode(NodeId owner);

// How many owners currently carry charged bytes, so a test can see a bucket
// left behind for an owner that holds nothing.
size_t GetOrphanOwnerBucketCount();

// Re-derive the running totals from the records, for callers that replace the
// record set wholesale.
void RecomputeOrphanBlocksFootprint();

// The only two writers of the orphan tables. owner < 0 parks with no peer.
// False means the hash was already held: the block is deleted and nothing is
// stored, so the caller must not touch it again.
bool AddOrphanBlock(const uint256& hash, CBlock* pblock, const uint256& hashWaitedFor,
                    NodeId owner, size_t nFootprint);
bool EraseOrphanBlock(const uint256& hash, bool fEraseByPrevEntries);

// Record that a peer has gone. Called from the socket thread under cs_vNodes,
// which is taken after cs_main everywhere else, so it only notes the id under a
// leaf lock; the records are released on the next sweep, under cs_main.
void OrphanBlocksNodeDisconnected(NodeId owner);

// True while the pool still refuses to charge anything to this owner: the peer
// has departed and its CNode has not been destroyed, so a park issued before the
// departure was seen may still be in flight for it. Read under cs_orphanDeparted.
bool OrphanOwnerHasDeparted(NodeId owner);

// Owners currently carrying a departure marker, and a reset for callers that
// replace the pool state wholesale.
size_t GetOrphanDepartedOwnerCount();
void ClearOrphanDepartedOwners();

// Request suppression for a block the pool can never hold, keyed by hash and checked in
// CNode::AskFor. Lifted once every hash in vWaitedOn is indexed, or when the block parks.
void SuppressOrphanBlockRequest(const uint256& hash, int64_t nNow,
                                const std::vector<uint256>& vWaitedOn);
void LiftOrphanBlockRequestSuppression(const uint256& hash);
bool LiftOrphanBlockRequestSuppressionIfConnectable(const uint256& hash);
size_t GetOrphanBlockRequestSuppressionCount();
void ClearOrphanBlockRequestSuppression();

// Gap gate: a peer holding an orphan with unheld ancestors is asked only for those.
// Keyed by owner; republished on every ProcessBlock exit and sweep; read under a leaf lock.
void RecomputeOrphanGaps();
bool IsOrphanGapGatedPeer(NodeId owner);
bool IsOrphanGapHashForPeer(NodeId owner, const uint256& hash);
std::vector<uint256> GetOrphanGapHashesForPeer(NodeId owner);
std::map<NodeId, std::set<uint256> > GetOrphanGapSnapshot();
size_t GetOrphanGapHashCount();
size_t GetOrphanGapGatedPeerCount();
void ClearOrphanGaps();

// Deferred entries one getdata pass may skip for a gated peer before resuming on the
// next pass, bounding per-tick work on a queue that does not drain.
static const size_t MAX_GAP_DEFERRALS_PER_PASS = MAX_BLOCKS_IN_FLIGHT_PER_PEER;

// Drop every record a departed peer owns, releasing its bytes and its entry
// charge, so a host that reconnects under a fresh NodeId cannot accumulate a
// permanent share of the pool. Returns the number of records dropped.
size_t ReleaseDepartedOrphanOwners();

// Drop every record parked more than ORPHAN_BLOCK_EXPIRY_SECONDS ago. Returns
// the number dropped.
size_t ExpireOrphanBlocks(int64_t nNow);

// Both of the above. Runs before every park, and on a timer from the driver
// below so a quiescent node still releases.
size_t SweepOrphanPool(int64_t nNow);

// The timer. Called from the message-handler loop, which turns with no peers
// connected as well; takes cs_main itself and skips the pass if it is busy.
void PeriodicOrphanPoolSweep();

// Whether a block of this footprint could ever be parked for this owner. False
// means no drain and no expiry makes room for it, so the refusal suppresses the
// hash for every requester rather than only declining its own re-ask.
bool OrphanPoolCouldEverHold(size_t nFootprint, NodeId owner);

// Records behind the refusal backoff, and a reset for callers that replace the
// pool state wholesale.
size_t GetOrphanRefusalRecordCount();
void ClearOrphanRefusalRecords();

// The deferral the next refusal of this hash would apply, in seconds.
int64_t GetOrphanRefusalBackoff(const uint256& hash);

// Whether the deferral the last refusal of this hash set still stands at nNow.
// Leaf-locked, so a request path outside cs_main can ask before re-requesting a
// block the pool has already turned away.
bool IsOrphanRequestDeferred(const uint256& hash, int64_t nNow);

// Make room for one block of nIncomingFootprint bytes charged to owner (< 0 = self).
// The byte bound (and per-peer share) refuses and never evicts and is tested first;
// entry pressure (-maxorphanblocks) evicts. False means the caller must not park.
bool PruneOrphanBlocks(size_t nIncomingFootprint, NodeId owner);
extern std::map<int64_t, CAnonOutputCount> mapAnonOutputStats;

extern int nLastFinalizedHeight;
extern uint256 hashLastFinalized;
extern CCriticalSection cs_finality;

extern CBigNum bnProofOfWorkLimit;
extern CBigNum bnProofOfWorkLimitTestNet;

//extern CTxMemPool mempool;

// Settings
extern int64_t nTransactionFee;
extern int64_t nReserveBalance;
extern int64_t nMinimumInputValue;
extern bool fUseFastIndex;
extern bool fImporting;
extern bool fReindex;
extern bool fFullReplayVerify;
extern unsigned int nDerivationMethodIndex;
extern unsigned int nCoinCacheSize;

extern bool fEnforceCanonical;

extern bool fMinimizeCoinAge;

extern bool fSPVMode;
extern bool fSPVHeadersOnly;
extern int nSPVStartHeight;

extern bool fHybridSPV;
extern bool fSPVStakingEnabled;

enum StakingMode {
    STAKE_TRANSPARENT = 0,
    STAKE_NULLSTAKE = 1,
    STAKE_COLD = 2,
    STAKE_NULLSTAKE_COLD = 3
};

inline bool IsLegacyPrivateStakingMode(StakingMode eMode)
{
    return eMode == STAKE_NULLSTAKE ||
           eMode == STAKE_NULLSTAKE_COLD;
}

// Legacy private-staking encodings are kept for historical/regtest coverage only.
// Public wallet construction is disabled; Boundary A is a permanent cutoff.
inline bool IsLegacyPrivateStakeCreationAllowed(StakingMode eMode,
                                                 int nCandidateHeight)
{
    return !IsLegacyPrivateStakingMode(eMode) ||
           (!IsLegacyPrivacyPolicyDisabled() &&
            !IsBoundaryAActiveAtHeight(nCandidateHeight));
}

extern StakingMode nStakingMode;
extern CCriticalSection cs_stakingMode;

extern int64_t nMinTxFee;

// Minimum disk space required - used in CheckDiskSpace()
// static const uint64_t nMinDiskSpace = 13958643712; // 13 GB Minimum (revert for production - Innova chain is ~11.5-12.5GB)
static const uint64_t nMinDiskSpace = 524288000; // 500 MB Minimum (temporary for regtest/testing)

class CReserveKey;
class CTxDB;
class CTxIndex;
class CIncrementalMerkleTree;
class CCurveTree;

// Seed deterministic unspendable commitments at fork height for Lelantus anonymity set
bool SeedGenesisCommitments(CTxDB& txdb, CIncrementalMerkleTree& shieldedTree,
                            CCurveTree* pCurveTree,
                            bool fV3ShieldedPersistence = false);
// Validate and, for historical databases, atomically backfill the bounded
// reverse-index/height records for the deterministic genesis decoys.
bool ValidateAndMigrateShieldedGenesisCommitmentIndexes(CTxDB& txdb, std::string& strError);
// Validate the exact per-block DAG activation journal, or recover legacy
// canonical history in bounded crash-resumable chunks using transaction-index
// disk positions.  Never reconstructs from the mutable live DAG.
bool ValidateAndRecoverDAGActiveSetPersistence(CTxDB& txdb,
                                               std::string& strError);
// Replay the Boundary-B active chain against exact IV5 spent-key and output-owner
// ownership. This is startup validation only and never reconstructs or mutates records.
bool ValidatePrivacyVNextIndexPersistence(CTxDB& txdb,
                                          std::string& strError);

void RegisterWallet(CWallet* pwalletIn);
void UnregisterWallet(CWallet* pwalletIn);
void SyncWithWallets(const CTransaction& tx, const CBlock* pblock = NULL, bool fUpdate = false, bool fConnect = true);
bool ProcessBlock(CNode* pfrom, CBlock* pblock);
bool CheckDiskSpace(uint64_t nAdditionalBytes=0);
FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode="rb");
FILE* AppendBlockFile(unsigned int& nFileRet);
bool LoadBlockIndex(bool fAllowNew=true);
void PrintBlockTree();
CBlockIndex* FindBlockByHeight(int nHeight);
bool RebuildMainChainForwardLinks();
// invalidateblock / reconsiderblock RPC support (defined in main.cpp; assume cs_main held).
bool InvalidateBlock(CTxDB& txdb, CBlockIndex* pindex, std::string& strError);
bool ReconsiderBlock(CTxDB& txdb, CBlockIndex* pindex, std::string& strError, bool* pfFlagsCleared = NULL);

/** Why an index was flagged BLOCK_FAILED_VALID, persisted beside the flag and erased with
 *  it. The failing block can differ from the flagged one: a reorg that fails at an ancestor
 *  flags the candidate tip. */
struct CBlockFailReason
{
    uint256 hashFailedBlock;
    int nFailedHeight;
    std::string strReason;
    int64_t nTime;

    CBlockFailReason() : hashFailedBlock(0), nFailedHeight(-1), nTime(0) {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(hashFailedBlock);
        READWRITE(nFailedHeight);
        READWRITE(strReason);
        READWRITE(nTime);
    )
};
bool ProcessMessages(CNode* pfrom);
bool SendMessages(CNode* pto, bool fSendTrickle);
// BIP130 tip announcement: headers to a sendheaders peer, inv otherwise. Distinct
// from the vInventoryToSend queue, which answers requests and is always inv.
void PushBlockAnnouncement(CNode* pnode, const CBlock& header, bool fForce);
bool LoadExternalBlockFile(FILE* fileIn);

//void PushGetBlocks(CNode* pnode, CBlockIndex* pindexBegin, uint256 hashEnd);

// Age of the severity anchor, in epochs behind the evaluating node's epoch. Tolerated
// honest tip skew is LAG-1 epochs (600 blocks post-DAG, 120 pre-DAG). The grade only
// decides DAG merging; nothing is persisted.
static const int REORG_LATCH_ANCHOR_LAG_EPOCHS = 3;

// Verdict of the reorg finality guard (R-FIN-001). No verdict is persisted: a refusal
// is re-evaluated against the tip in force whenever a switch is next considered.
enum ReorgFinalityVerdict
{
    REORG_FINALITY_ALLOW = 0,
    // The attested block as of the current anchor is not an ancestor of the candidate,
    // but the lagged anchor's is: refuse this attempt without condemning the branch.
    REORG_FINALITY_REJECT_TRANSIENT,
    // Neither anchor's attested block is an ancestor of the candidate: a branch every
    // node inside the tolerated skew also refuses. The miner will not merge its tip.
    REORG_FINALITY_REJECT_PERMANENT,
    // Required epoch state is absent, or names a block this node cannot resolve; the
    // caller fails closed.
    REORG_FINALITY_STATE_MISSING,
};

// Reorg finality guard for Reorganize and SetBestChain: a candidate is refused iff the
// block attested finalized at epoch(nBestHeight)-1 is not on its pprev chain.
class CDAGManager;
class CBlockIndex;
ReorgFinalityVerdict CheckReorgAgainstFinality(const CDAGManager& dag,
                                               int nBestHeight, const CBlockIndex* pCandidate,
                                               int& nFinalCurOut, int& nFinalLatchOut,
                                               int& nAsOfEpochOut,
                                               uint256* phashFinalCurOut = NULL,
                                               uint256* phashFinalLatchOut = NULL);
ReorgFinalityVerdict CheckReorgAgainstFinality(int nBestHeight, const CBlockIndex* pCandidate,
                                               int& nFinalCurOut, int& nFinalLatchOut,
                                               int& nAsOfEpochOut,
                                               uint256* phashFinalCurOut = NULL,
                                               uint256* phashFinalLatchOut = NULL);

// Reaches the verdict for both reorg sites; never sets pfPermanentInvalid.
ReorgFinalityVerdict ApplyReorgFinalityGuard(const CDAGManager& dag,
                                             int nBestHeight, const CBlockIndex* pCandidate,
                                             bool* pfPermanentInvalid,
                                             int& nFinalCurOut, int& nFinalLatchOut,
                                             int& nAsOfEpochOut);
ReorgFinalityVerdict ApplyReorgFinalityGuard(int nBestHeight, const CBlockIndex* pCandidate,
                                             bool* pfPermanentInvalid,
                                             int& nFinalCurOut, int& nFinalLatchOut,
                                             int& nAsOfEpochOut);

/** Finality verdict for switching the best chain to pCandidate, against the current tip;
 *  never persisted. ALLOW for a candidate that extends the tip or a tip below the gate. */
ReorgFinalityVerdict BestChainSwitchVerdict(const CBlockIndex* pCandidate, int& nForkHeightOut,
                                            int& nFinalCurOut, int& nFinalLatchOut,
                                            int& nAsOfEpochOut);

bool CheckProofOfWork(uint256 hash, unsigned int nBits);
unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake);
// Pure retarget arithmetic: nActualSpan over nWindow blocks vs nEffectiveSpacing * nWindow.
// nWindow == 1 reproduces the pre-DAG single-gap rule exactly.
unsigned int ComputeRetargetedBits(unsigned int nPrevBits, int64_t nActualSpan,
                                   unsigned int nEffectiveSpacing, int nWindow,
                                   bool fTighterDrift, const CBigNum& bnTargetLimit);
// Issuance headroom under the supply cap, from pindexPrev->nMoneySupply only; INT64_MAX
// below the fork. nCommitted comes off first, so the subsidy yields.
int64_t GetRemainingIssuance(const CBlockIndex* pindexPrev, int64_t nCommitted);
int64_t ClampSubsidyToSupplyCap(int64_t nSubsidy, const CBlockIndex* pindexPrev, int64_t nCommitted);

// The subsidy schedule before any clamp, fee or penalty. See subsidy.h -- the
// finality reserve is a share of this, not of what a given block paid.
int64_t GetBlockSubsidySchedule(int nHeight);

// pindexPrev is the parent of the block being paid; no defaults, since a wrong parent or
// omitted settlement computes a different subsidy and splits the chain.
// Subsidy before fees at or above FORK_HEIGHT_DAG.
int64_t GetPostDagProofOfWorkSubsidy(int nHeight);
int64_t GetProofOfWorkReward(int nHeight, int64_t nFees, const CBlockIndex* pindexPrev, int64_t nCommitted);
int64_t GetProofOfStakeReward(int64_t nCoinAge, int64_t nFees, const CBlockIndex* pindexPrev, int64_t nCommitted);
unsigned int ComputeMinWork(unsigned int nBase, int64_t nTime);
unsigned int ComputeMinStake(unsigned int nBase, int64_t nTime, unsigned int nBlockTime);
int GetNumBlocksOfPeers();
bool IsSynchronized();
bool IsInitialBlockDownload();
std::string GetWarnings(std::string strFor);
bool GetTransaction(const uint256 &hash, CTransaction &tx, uint256 &hashBlock, bool s=false);

/** Digest an IV5 payload commits to so its transaction's transparent side cannot be
 *  rewritten after the proofs are made. Covers the input prevouts, the output vector and
 *  the lock time; see the definition in main.cpp for the scope's boundaries. */
uint256 GetPrivacyVNextTransparentBinding(const CTransaction& tx);

/** Hold an accepted payload's declared binding against the transaction carrying it.
 *  A mismatch is deterministic-invalid, never a local failure. */
bool CheckPrivacyVNextTransparentBinding(const CTransaction& tx,
                                         const PrivacyVNextStateEffects& effects,
                                         std::string& strError);

/** Check a payload's parameter digest against the chain's (finalized epoch state, or
 *  GENESIS_PARAMETER_DIGEST_SHA256 below the first IV5 epoch); never a self-derived value.
 *  A mismatch is deterministic-invalid. */
bool CheckPrivacyVNextParameterDigest(
    const PrivacyVNextStateEffects& effects,
    const std::vector<unsigned char>& vchChainDigest,
    std::string& strError);

/** Transparent value an IV5 tx absorbs into / releases from the pool; fee accounting must
 *  apply it wherever it applies nValueBalance. pnNoteVoteMintOut is the note-vote mint every
 *  fee accumulator must credit. Always verifies proofs. */
bool GetPrivacyVNextTransparentFlow(const CTransaction& tx,
                                    int64_t& nAbsorbedOut,
                                    int64_t& nReleasedOut,
                                    bool& fLocalFailure,
                                    std::string& strError,
                                    int64_t* pnDeclaredFeeOut = NULL,
                                    int64_t* pnDeclaredBalanceOut = NULL,
                                    int64_t* pnNoteVoteMintOut = NULL);

/** The same flow with the seven proof verdicts skipped, for ConnectBlock only. The
 *  caller must establish by ancestry (never height) that the block is at or below the
 *  assume-valid block; mempool and relay paths must not call this. */
bool GetPrivacyVNextTransparentFlowAssumeValid(const CTransaction& tx,
                                               int64_t& nAbsorbedOut,
                                               int64_t& nReleasedOut,
                                               bool& fLocalFailure,
                                               std::string& strError,
                                               int64_t* pnDeclaredFeeOut = NULL,
                                               int64_t* pnDeclaredBalanceOut = NULL,
                                               int64_t* pnNoteVoteMintOut = NULL);

/** What a payload may mint into the pool with no transparent side. Zero except for a
 *  note finality vote (op 10), where it is GetFinalityNoteVoteReward of the vote's epoch
 *  and must equal the declared transparent value balance exactly. */
bool GetPrivacyVNextNoteVoteMint(const PrivacyVNextStateEffects& effects,
                                 int64_t& nMintOut,
                                 std::string& strError);

/** The most a post-DAG block's transactions may pay out: value in, coinbase allowance,
 *  and the block's note-vote entitlements (reserve netted off the settlement, not new
 *  issuance). False on a negative operand or overflow. */
inline bool GetBlockValueOutCeiling(int64_t nValueIn, int64_t nAllowedCoinbase,
                                    int64_t nNoteVoteMint, int64_t& nCeilingOut)
{
    nCeilingOut = 0;
    if (nValueIn < 0 || nAllowedCoinbase < 0 || nNoteVoteMint < 0)
        return false;
    if (nValueIn > std::numeric_limits<int64_t>::max() - nAllowedCoinbase)
        return false;
    const int64_t nBase = nValueIn + nAllowedCoinbase;
    if (nNoteVoteMint > std::numeric_limits<int64_t>::max() - nBase)
        return false;
    nCeilingOut = nBase + nNoteVoteMint;
    return true;
}

/** Note votes connected in the inclusion window times the epoch entitlement, withheld from
 *  the transparent budget. pindexWindowTop is the settlement block's parent.
 *  fLocalFailure: a window block this node cannot read. */
bool GetPrivacyVNextNoteVoteMintTotal(const CBlockIndex* pindexWindowTop,
                                      int nSettlementEpoch,
                                      int64_t& nTotalOut,
                                      bool& fLocalFailure,
                                      std::string& strError);

/** Fee-exempt shapes: an IV5 attestation (no transparent side or pool flow) and a note
 *  finality vote (op 10, fee pinned to zero). Callers must still require a zero fee. */
bool IsPrivacyVNextFeeExemptShape(const CTransaction& tx);

/** Whether a transaction declares a note finality vote: a payload whose header names
 *  operation 10 and no transparent side. A header read, not a decoder: block assembly
 *  counts with it, consensus acts on the decoded effects. */
bool IsPrivacyVNextNoteVoteShape(const CTransaction& tx);

/** Pool delta of a payload's effects, range-checked before the subtraction rather
 *  than after it. PoolDelta() subtracts in int64_t, so the operands have to be
 *  bounded first or the result is already undefined by the time it is inspected. */
struct PrivacyVNextStateEffects;
/** The ancestry rule, with the hash supplied. A block qualifies only when it is the named
 *  block or lies on the selected-parent path to it. Exposed so the rule can be tested. */
bool IsPrivacyVNextAssumeValidAncestorOf(const uint256& hashAssumeValid,
                                         const CBlockIndex* pindex);

/** Whether this block is an ancestor of the configured assume-valid hash, and so may skip
 *  its payloads' proof verdicts. Ancestry, never height. */
bool IsPrivacyVNextAssumeValidAncestor(const CBlockIndex* pindex);

/** Background verification: re-proves the payloads assume-valid skipped. The set is
 *  derived from the same ancestry the gate uses, so nothing records which blocks were
 *  skipped; progress is one height. */
void ThreadPrivacyVNextBackgroundVerify(void* parg);
/** How long the background verification walk waits before its next pass: nothing when it
 *  found work and the tip stood still, the full interval otherwise. */
int64_t PrivacyVNextVerifyPacingMs(bool fWorkRemained, bool fTipMoved, int64_t nSleepMs);

/** Every payload in a window of blocks, in block order and then transaction order.
 *  The pointers are into the window, which must outlive the warm call it feeds. */
void CollectPrivacyVNextWarmSet(
    const std::vector<std::pair<int, CBlock> >& vWindow,
    std::vector<std::pair<uint32_t, const std::vector<unsigned char>*> >& vWarmOut);

bool RunPrivacyVNextBackgroundVerification(int nMaxBlocks, int& nVerifiedOut,
                                           std::string& strErrorOut);
int GetPrivacyVNextVerifiedHeight();

bool GetPrivacyVNextPoolDelta(const PrivacyVNextStateEffects& effects,
                              int64_t& nDeltaOut,
                              std::string& strError);

/** Apply one payload's collateral attestations to the watch set; the only writer of
 *  that index. An attestation's key image must never reach the spent-key index.
 *  `setBlockAttestations` catches repeats within the block. */
bool ConnectPrivacyVNextAttestations(CTxDB& txdb,
                                     const CTransaction& tx,
                                     const PrivacyVNextStateEffects& effects,
                                     int nHeight,
                                     bool fJustCheck,
                                     std::set<uint256>& setBlockAttestations,
                                     bool& fLocalFailure,
                                     std::string& strError);

/** Exact inverse of the connect transition: erase what this transaction wrote. */
bool DisconnectPrivacyVNextAttestations(CTxDB& txdb,
                                        const CTransaction& tx,
                                        const PrivacyVNextStateEffects& effects,
                                        std::string& strError);

/** Whether a collateralnode's note is registered now: attested on chain and unspent.
 *  Derived, never stored, so a spend is the deregistration. */
bool IsPrivacyVNextCollateralRegistered(
    CTxDB& txdb,
    const uint256& keyImage,
    CPrivacyVNextCollateralAttestation& attestedOut,
    bool& fLocalFailure);

/** One active registration in a height-anchored snapshot of the registry. */
struct CPrivacyVNextRegistryEntry
{
    uint256 keyImage;
    uint256 contextDigest;
    uint256 txnHash;
    int32_t nHeight;
    /** 33 bytes for a finality-committee member, empty for a collateralnode. */
    std::vector<unsigned char> vchMemberKey;

    CPrivacyVNextRegistryEntry()
        : keyImage(0), contextDigest(0), txnHash(0), nHeight(-1) {}

    bool IsFinalityMember() const
    {
        return vchMemberKey.size() == iv5::FINALITY_MEMBER_KEY_BYTES;
    }

    /** Key-image order, which is what makes a snapshot's sequence node independent. */
    bool operator<(const CPrivacyVNextRegistryEntry& other) const
    {
        return keyImage < other.keyImage;
    }
};

/** Registrations active as of nAnchorHeight, in key-image order.
 *
 *  Reads only the two indexes, which are exact functions of the ancestry connected
 *  so far, and never nBestHeight, pindexBest, the mempool or a live finality height:
 *  an anchor taken from what a node has seen rather than from what the block being
 *  validated descends from is what splits a chain.
 *
 *  Needs a CTxDB with no open write batch: an iterator cannot see pending writes and
 *  would answer differently from the point reads beside it. A finalized anchor wants
 *  committed state, so this is a constraint on the caller, not a limitation.
 *
 *  The caller owns the anchor. DrawFinalityCommitteeForTerm supplies the first height of
 *  epoch (term - FINALITY_COMMITTEE_DRAW_LAG_EPOCHS) and only after that epoch's own state
 *  reports it finalized, which is what keeps every row this reads below the depth a reorg
 *  may reach and therefore already committed rather than staged in someone's batch.
 *
 *  The spend filter is NOT anchored: a registration whose collateral was spent at any
 *  height up to the reading block drops out. That is deterministic per block and fixed for
 *  a term because the draw is taken once and stored, and it cannot be used to buy seats --
 *  removing rows only promotes the rows below the cut, never the remover's own. */
bool GetPrivacyVNextCollateralSnapshot(
    CTxDB& txdb,
    int nAnchorHeight,
    bool fMembersOnly,
    std::vector<CPrivacyVNextRegistryEntry>& vOut,
    bool& fLocalFailure,
    std::string& strError);

/** Refuse a payload declaring pool value leaving to the transparent side, from
 *  FORK_HEIGHT_IV5_FEE_NOTE on. Keyed on the declared balance, never the pool delta. */
bool CheckPrivacyVNextUnshieldRetired(int64_t nDeclaredBalance, int nHeight,
                                      std::string& strError);

/** Whether an IV5 tx still anchors inside the consensus window at nHeight. Block assembly
 *  must apply this: a mempool tx can age out before selection. */
bool CheckPrivacyVNextFinalizedAnchor(CTxDB& txdb, const CBlockIndex* pindexAnchorTip,
                                      int nHeight, const CTransaction& tx,
                                      std::string& strError);

/** Whether consensus accepts a spend anchored to this root and tree size at
 *  nContextHeight, judged by the code a connecting transaction is. nAnchorEpochOut is the
 *  newest accepted epoch carrying the pair, or -1. */
bool CheckPrivacyVNextSpendAnchor(CTxDB& txdb, int nContextHeight,
                                  const PrivacyVNextDigest& finalizedRoot,
                                  uint64_t nFinalizedTreeSize,
                                  const PrivacyVNextDigest& parameterDigest,
                                  int& nAnchorEpochOut, bool& fLocalFailure,
                                  std::string& strError);

/** Connect-time rules of a note finality vote (operation 10), judged at nContextHeight
 *  on the chain pindexAnchorTip heads: the lane's fork gate; the boundary the vote
 *  names is a post-DAG epoch boundary and the carrier chain's own ancestor at that
 *  height; the carrier sits inside [H_E, H_E + FINALITY_VOTE_INCLUSION_WINDOW); and the
 *  proof anchors to epoch state E-1, which is identified by its boundary block before
 *  its root is compared. fLocalFailure is a record this node cannot read. fUnavailable
 *  is a record that is another branch's or not yet installed here, which the caller
 *  retries and never scores. Neither is a verdict on the vote. */
bool ValidatePrivacyVNextNoteVoteContext(CTxDB& txdb,
                                         const CBlockIndex* pindexAnchorTip,
                                         int nContextHeight,
                                         const PrivacyVNextStateEffects& effects,
                                         bool& fLocalFailure,
                                         bool& fUnavailable,
                                         std::string& strError);

/** A note finality vote is carried by its payload alone: no transparent inputs or
 *  outputs. True for every other payload. */
bool CheckPrivacyVNextNoteVoteCarrier(const CTransaction& tx,
                                      const PrivacyVNextStateEffects& effects,
                                      std::string& strError);

/** The per-block and per-window caps on note finality votes, given the votes this
 *  block carries so far and the votes already connected in the window before it. */
bool CheckPrivacyVNextNoteVoteCaps(unsigned int nBlockVotes,
                                   unsigned int nPriorWindowVotes,
                                   std::string& strError);

/** Declared note finality votes in one block. */
unsigned int CountPrivacyVNextNoteVoteShapes(const CBlock& block);

/** Note finality votes on pindexFrom's chain at heights >= nBoundaryHeight, walking at most
 *  one inclusion window. False when a block cannot be read (local state, not a verdict). */
bool CountConnectedPrivacyVNextNoteVotes(const CBlockIndex* pindexFrom,
                                         int nBoundaryHeight,
                                         unsigned int nStopAfter,
                                         unsigned int& nCountOut,
                                         std::string& strError);

/** Outcome of recording one payload's spends in the spent-key index. */
enum PrivacyVNextSpendResult
{
    PRIVACY_VNEXT_SPEND_OK = 0,
    /** Refused identically everywhere: a key image repeated in the block or already consumed. */
    PRIVACY_VNEXT_SPEND_INVALID,
    /** The spent-key index cannot be read on this node. */
    PRIVACY_VNEXT_SPEND_INDEX_CORRUPT,
    /** The index write failed on this node. */
    PRIVACY_VNEXT_SPEND_WRITE_FAILED
};

/** Record one payload's key images as consumed at nHeight: the in-block and cross-block
 *  double-spend checks, then the height-stamped write unless fJustCheck. Every IV5
 *  spend, a note finality vote's included, passes through here and nowhere else. */
PrivacyVNextSpendResult ConnectPrivacyVNextSpentKeys(CTxDB& txdb,
                                                     const CTransaction& tx,
                                                     const PrivacyVNextStateEffects& effects,
                                                     int nHeight,
                                                     bool fJustCheck,
                                                     std::set<uint256>& setBlockKeyImages,
                                                     std::string& strError);

/** Outcome of undoing one payload's spends. */
enum PrivacyVNextUndoResult
{
    PRIVACY_VNEXT_UNDO_OK = 0,
    /** A record is missing, corrupt, or not the one this transaction wrote at nHeight. */
    PRIVACY_VNEXT_UNDO_MISMATCH,
    /** The erase failed on this node. */
    PRIVACY_VNEXT_UNDO_ERASE_FAILED
};

/** Exact inverse of ConnectPrivacyVNextSpentKeys: erase what it wrote, in reverse order,
 *  after checking each record is the one this transaction wrote at nHeight. */
PrivacyVNextUndoResult DisconnectPrivacyVNextSpentKeys(CTxDB& txdb,
                                                       const CTransaction& tx,
                                                       const PrivacyVNextStateEffects& effects,
                                                       int nHeight,
                                                       std::string& strError);
bool GetKeyImage(CTxDB* ptxdb, ec_point& keyImage, CKeyImageSpent& keyImageSpent, bool& fInMempool);
int GetAnonTxnPreImage(const CTransaction& tx, uint256& hashOut);
bool TxnHashInSystem(CTxDB* ptxdb, uint256& txnHash);
uint256 WantedByOrphan(const CBlock* pblockOrphan);
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake);
void StakeMiner(CWallet *pwallet);
void ResendWalletTransactions(bool fForce = false);
/** Per-loop node-global relay work; must run with no peer's cs_vSend held. */
void SendMessagesGlobal();

bool Finalise();
/** Persist the deferred wallet best-block locator, if one is pending. */
bool FlushWalletBestChainLocator(std::string& strErrorOut);
bool HasPendingWalletLocator();
int PendingWalletLocatorBlocks();

bool FindTransactionsByDestination(const CTxDestination &dest, std::vector<uint256> &vtxhash);


int GetInputAge(CTxIn& vin, CBlockIndex* pindex);
int GetInputAgeIX(uint256 nTXHash, CTxIn& vin);
int GetIXConfirmations(uint256 nTXHash);
/** Abort with a message */
bool AbortNode(const std::string &msg, const std::string &userMessage="");
/** Increase a node's misbehavior score. */
void Misbehaving(NodeId nodeid, int howmuch, const std::string& reason = "");
// The collateralnode share is reachable only through CBlockSubsidySplit (subsidy.h),
// so no site can size it against its own base.


bool IsStandardTx(const CTransaction& tx, std::string& reason);
bool IsFinalTx(const CTransaction &tx, int nBlockHeight = 0, int64_t nBlockTime = 0);

/** Get statistics from node state */
bool GetNodeStateStats(NodeId nodeid, CNodeStateStats &stats);

bool GetWalletFile(CWallet* pwallet, std::string &strWalletFileOut);

/** Position on disk for a particular transaction. */
class CDiskTxPos
{
public:
    unsigned int nFile;
    unsigned int nBlockPos;
    unsigned int nTxPos;

    CDiskTxPos()
    {
        SetNull();
    }

    CDiskTxPos(unsigned int nFileIn, unsigned int nBlockPosIn, unsigned int nTxPosIn)
    {
        nFile = nFileIn;
        nBlockPos = nBlockPosIn;
        nTxPos = nTxPosIn;
    }

    IMPLEMENT_SERIALIZE( READWRITE(FLATDATA(*this)); )
    void SetNull() { nFile = (unsigned int) -1; nBlockPos = 0; nTxPos = 0; }
    bool IsNull() const { return (nFile == (unsigned int) -1); }

    friend bool operator==(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return (a.nFile     == b.nFile &&
                a.nBlockPos == b.nBlockPos &&
                a.nTxPos    == b.nTxPos);
    }

    friend bool operator!=(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return !(a == b);
    }


    std::string ToString() const
    {
        if (IsNull())
            return "null";
        else
            return strprintf("(nFile=%u, nBlockPos=%u, nTxPos=%u)", nFile, nBlockPos, nTxPos);
    }

    void print() const
    {
        printf("%s", ToString().c_str());
    }
};

typedef std::map<uint256, std::pair<CTxIndex, CTransaction> > MapPrevTx;

// Exact chain effects of validating one historical ANON transaction, in the legacy
// on-disk encoding, persisted inside the enclosing best-chain LevelDB transaction.
class CLegacyAnonEffectPlan
{
public:
    int64_t nValueIn;
    std::vector<std::pair<ec_point, CKeyImageSpent> > vKeyImages;
    std::vector<std::pair<CPubKey, CAnonOutput> > vOutputs;

    CLegacyAnonEffectPlan() : nValueIn(0) {}

    void Clear()
    {
        nValueIn = 0;
        vKeyImages.clear();
        vOutputs.clear();
    }
};

//struct CMutableTransaction;
/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
public:
    static const int CURRENT_VERSION=1;
    int nVersion;
    unsigned int nTime; // Innova TXs require nTime
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    unsigned int nLockTime;

    // Distinct canonical envelope for SHIELDED_TX_VERSION_DSP. It remains
    // consensus inactive until Boundary B and never aliases legacy fields.
    CShieldedVNextEnvelope privacyVNext;

    // Shielded transaction components (populated when IsShielded())
    std::vector<CShieldedSpendDescription> vShieldedSpend;
    std::vector<CShieldedOutputDescription> vShieldedOutput;
    int64_t nValueBalance;  // Net value balance: positive = value leaving shielded pool (unshield), negative = value entering shielded pool (shield)
    CShieldedBindingSig bindingSig;
    uint8_t nPrivacyMode;   // DSP: 3-bit privacy mode (0-7), default 7 (fully private)

    // NullStake coinstake — only for SHIELDED_TX_VERSION_NULLSTAKE
    CNullStakeKernelProof nullstakeProof;

    // NullStake V2 coinstake — only for SHIELDED_TX_VERSION_NULLSTAKE_V2
    CNullStakeKernelProofV2 nullstakeProofV2;

    // NullStake V3 coinstake — only for SHIELDED_TX_VERSION_NULLSTAKE_COLD
    CNullStakeKernelProofV3 nullstakeProofV3;

    // B2-e Phase 3c.4 owner reclaim — only for SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM
    CNullStakeReclaimAuth reclaimAuth;

    // Denial-of-service detection:
    mutable int nDoS;
    bool DoS(int nDoSIn, bool fIn) const { nDoS += nDoSIn; return fIn; }

    CTransaction()
    {
        SetNull();
    }

    /** Convert a CMutableTransaction into a CTransaction. */
    //CTransaction(const CMutableTransaction &tx);

    IMPLEMENT_SERIALIZE
    (
        CTransaction* pthis = const_cast<CTransaction*>(this);
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nTime);
        READWRITE(vin);
        READWRITE(vout);
        READWRITE(nLockTime);
        if (this->nVersion == SHIELDED_TX_VERSION_DSP)
            READWRITE(privacyVNext);
        if (this->nVersion == SHIELDED_TX_VERSION || this->nVersion == SHIELDED_TX_VERSION_DSP_PROTOTYPE
            || this->nVersion == SHIELDED_TX_VERSION_FCMP || this->nVersion == SHIELDED_TX_VERSION_NULLSTAKE
            || this->nVersion == SHIELDED_TX_VERSION_NULLSTAKE_V2 || this->nVersion == SHIELDED_TX_VERSION_NULLSTAKE_COLD
            || this->nVersion == SHIELDED_TX_VERSION_MOFN_MINT
            || this->nVersion == SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM)
        {
            bool fVNextEnvelope = false;
            if (fRead)
            {
                pthis->privacyVNext.SetNull();
                unsigned char firstByte = 0;
                READWRITE(firstByte);
                if (firstByte == 0xff)
                {
                    nSerSize += pthis->privacyVNext.UnserializeAfterMarkerPrefix(
                        s, nType, nVersion, ser_action);
                    pthis->vShieldedSpend.clear();
                    pthis->vShieldedOutput.clear();
                    fVNextEnvelope = true;
                }
                else
                {
                    if (firstByte > MAX_SHIELDED_INPUTS)
                        throw std::ios_base::failure("legacy shielded input count exceeds consensus limit");
                    pthis->vShieldedSpend.resize(firstByte);
                    for (size_t i = 0; i < pthis->vShieldedSpend.size(); ++i)
                        READWRITE(pthis->vShieldedSpend[i]);
                }
            }
            else if (pthis->privacyVNext.IsPresent())
            {
                READWRITE(privacyVNext);
                fVNextEnvelope = true;
            }
            else
            {
                nSerSize += ::SerReadWriteLimitedVector(s, pthis->vShieldedSpend,
                                                         MAX_SHIELDED_INPUTS,
                                                         nType, nVersion, ser_action);
            }

            if (!fVNextEnvelope)
            {
                nSerSize += ::SerReadWriteLimitedVector(s, pthis->vShieldedOutput,
                                                         MAX_SHIELDED_OUTPUTS,
                                                         nType, nVersion, ser_action);
            READWRITE(nValueBalance);
            if (this->nVersion >= SHIELDED_TX_VERSION_DSP_PROTOTYPE)
            {
                READWRITE(nPrivacyMode);
                for (size_t i = 0; i < vShieldedSpend.size(); i++)
                {
                    READWRITE(vShieldedSpend[i].nPlaintextValue);
                    nSerSize += ::SerReadWriteLimitedVector(
                        s, pthis->vShieldedSpend[i].vchPlaintextBlind,
                        BLINDING_FACTOR_SIZE, nType, nVersion, ser_action);
                }
                for (size_t i = 0; i < vShieldedOutput.size(); i++)
                {
                    READWRITE(vShieldedOutput[i].nPlaintextValue);
                    nSerSize += ::SerReadWriteLimitedVector(
                        s, pthis->vShieldedOutput[i].vchPlaintextBlind,
                        BLINDING_FACTOR_SIZE, nType, nVersion, ser_action);
                    nSerSize += ::SerReadWriteLimitedVector(
                        s, pthis->vShieldedOutput[i].vchRecipientScript,
                        SHIELDED_TX_FIELD_MAX_WIRE_SIZE,
                        nType, nVersion, ser_action);
                }
            }
            // B2-e M-of-N mint output extension (version-gated, like the DSP fields): a per-output
            // type marker; marked outputs additionally carry the fresh value commitment Vv and the
            // 97-byte Okamoto (G,J) link. Existing shielded versions are byte-for-byte unchanged.
            if (this->nVersion == SHIELDED_TX_VERSION_MOFN_MINT)
            {
                for (size_t i = 0; i < vShieldedOutput.size(); i++)
                {
                    READWRITE(vShieldedOutput[i].nMofNType);
                    if (vShieldedOutput[i].nMofNType == 1)
                    {
                        READWRITE(vShieldedOutput[i].valueCommitmentVv);
                        nSerSize += ::SerReadWriteLimitedVector(
                            s, pthis->vShieldedOutput[i].vchMofNLink,
                            NULLSTAKE_MOFN_MINTLINK_SIZE,
                            nType, nVersion, ser_action);
                    }
                }
            }
            READWRITE(bindingSig);
            // NullStake V1 kernel proof (version 2003)
            if (this->nVersion == SHIELDED_TX_VERSION_NULLSTAKE)
            {
                READWRITE(nullstakeProof);
            }
            // NullStake V2 kernel proof (version 2004)
            if (this->nVersion == SHIELDED_TX_VERSION_NULLSTAKE_V2)
            {
                READWRITE(nullstakeProofV2);
            }
            // NullStake V3 kernel proof (version 2005 — private cold staking)
            if (this->nVersion == SHIELDED_TX_VERSION_NULLSTAKE_COLD)
            {
                READWRITE(nullstakeProofV3);
            }
            // B2-e Phase 3c.4 owner reclaim authorization (version 2007)
            if (this->nVersion == SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM)
            {
                READWRITE(reclaimAuth);
            }
            }
        }
    )

    void SetNull()
    {
        nVersion = CTransaction::CURRENT_VERSION;
        nTime = GetAdjustedTime();
        vin.clear();
        vout.clear();
        nLockTime = 0;
        privacyVNext.SetNull();
        nDoS = 0;  // Denial-of-service prevention
        vShieldedSpend.clear();
        vShieldedOutput.clear();
        nValueBalance = 0;
        nPrivacyMode = PRIVACY_MODE_FULL;
        bindingSig.bindingSig.vchSignature.clear();
    }

    bool IsNull() const
    {
        return (vin.empty() && vout.empty());
    }

    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }

    // Hash excluding the binding signature, used as sighash for binding sig creation/verification
    uint256 GetBindingSigHash() const
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << nVersion;
        ss << nTime;
        ss << vin;
        ss << vout;
        ss << nLockTime;
        if (nVersion == SHIELDED_TX_VERSION || nVersion == SHIELDED_TX_VERSION_DSP_PROTOTYPE
            || nVersion == SHIELDED_TX_VERSION_FCMP || nVersion == SHIELDED_TX_VERSION_NULLSTAKE
            || nVersion == SHIELDED_TX_VERSION_NULLSTAKE_V2 || nVersion == SHIELDED_TX_VERSION_NULLSTAKE_COLD
            || nVersion == SHIELDED_TX_VERSION_MOFN_MINT
            || nVersion == SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM)
        {
            ss << (unsigned int)vShieldedSpend.size();
            for (size_t i = 0; i < vShieldedSpend.size(); i++)
            {
                ss << vShieldedSpend[i].cv;
                ss << vShieldedSpend[i].anchor;
                ss << vShieldedSpend[i].nullifier;
                ss << vShieldedSpend[i].rangeProof;
                ss << vShieldedSpend[i].vchLelantusProof;
                ss << vShieldedSpend[i].vAnonSet;
                ss << vShieldedSpend[i].lelantusSerial;
                // DSP fields included in sighash to prevent mode/value malleability.
                if (nVersion >= SHIELDED_TX_VERSION_DSP_PROTOTYPE)
                {
                    ss << vShieldedSpend[i].nPlaintextValue;
                    ss << vShieldedSpend[i].vchPlaintextBlind;
                }
                // FCMP++ proof committed to binding sig hash
                if (nVersion >= SHIELDED_TX_VERSION_FCMP)
                {
                    bool fHasFCMP = !vShieldedSpend[i].fcmpProof.IsNull();
                    ss << fHasFCMP;
                    ss << vShieldedSpend[i].fcmpProof;
                    ss << vShieldedSpend[i].curveTreeRoot;
                }
            }
            // Output descriptions (includes DSP fields via serialization)
            ss << (unsigned int)vShieldedOutput.size();
            for (size_t i = 0; i < vShieldedOutput.size(); i++)
            {
                ss << vShieldedOutput[i].cv;
                ss << vShieldedOutput[i].cmu;
                ss << vShieldedOutput[i].vchEphemeralKey;
                ss << vShieldedOutput[i].vchEncCiphertext;
                ss << vShieldedOutput[i].vchOutCiphertext;
                ss << vShieldedOutput[i].rangeProof;
                if (nVersion >= SHIELDED_TX_VERSION_DSP_PROTOTYPE)
                {
                    ss << vShieldedOutput[i].nPlaintextValue;
                    ss << vShieldedOutput[i].vchPlaintextBlind;
                    ss << vShieldedOutput[i].vchRecipientScript;
                }
                // B2-e M-of-N mint fields committed to the binding-sig hash (INV-4): without this an
                // in-flight adversary could re-randomize cv3/Vv/link and permanently brick the note.
                if (nVersion == SHIELDED_TX_VERSION_MOFN_MINT)
                {
                    ss << vShieldedOutput[i].nMofNType;
                    if (vShieldedOutput[i].nMofNType == 1)
                    {
                        ss << vShieldedOutput[i].valueCommitmentVv;
                        ss << vShieldedOutput[i].vchMofNLink;
                    }
                }
            }
            ss << nValueBalance;
            if (nVersion == SHIELDED_TX_VERSION_DSP_PROTOTYPE || nVersion == SHIELDED_TX_VERSION_FCMP
                || nVersion == SHIELDED_TX_VERSION_NULLSTAKE || nVersion == SHIELDED_TX_VERSION_NULLSTAKE_V2
                || nVersion == SHIELDED_TX_VERSION_NULLSTAKE_COLD || nVersion == SHIELDED_TX_VERSION_MOFN_MINT
                || nVersion == SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM)
                ss << nPrivacyMode;
            // NullStake V1 coinstake proof committed to binding sig hash
            if (nVersion == SHIELDED_TX_VERSION_NULLSTAKE)
                ss << nullstakeProof;
            // NullStake V2 coinstake proof committed to binding sig hash
            if (nVersion == SHIELDED_TX_VERSION_NULLSTAKE_V2)
                ss << nullstakeProofV2;
            // NullStake V3 coinstake proof committed to binding sig hash
            if (nVersion == SHIELDED_TX_VERSION_NULLSTAKE_COLD)
                ss << nullstakeProofV3;
            // B2-e Phase 3c.4: the reclaim authorization (set + M + owner + delegationHash) is committed
            // here so the owner spend-auth signature (rk == vchPkOwner) binds the revealed set/owner and
            // cannot be re-targeted; vchRk / vchSpendAuthSig themselves are deliberately NOT in the sighash.
            if (nVersion == SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM)
                ss << reclaimAuth;
            // Deliberately omit bindingSig
        }
        return ss.GetHash();
    }

    bool IsFinal(int nBlockHeight=0, int64_t nBlockTime=0) const
    {
        AssertLockHeld(cs_main);
        // Time based nLockTime implemented in 0.1.6
        if (nLockTime == 0)
            return true;
        if (nBlockHeight == 0)
            nBlockHeight = nBestHeight;
        if (nBlockTime == 0)
            nBlockTime = GetAdjustedTime();
        if ((int64_t)nLockTime < ((int64_t)nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
            return true;
        for (const CTxIn& txin : vin)
            if (!txin.IsFinal())
                return false;
        return true;
    }

    bool IsNewerThan(const CTransaction& old) const
    {
        if (vin.size() != old.vin.size())
            return false;
        for (unsigned int i = 0; i < vin.size(); i++)
            if (vin[i].prevout != old.vin[i].prevout)
                return false;

        bool fNewer = false;
        unsigned int nLowest = std::numeric_limits<unsigned int>::max();
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            if (vin[i].nSequence != old.vin[i].nSequence)
            {
                if (vin[i].nSequence <= nLowest)
                {
                    fNewer = false;
                    nLowest = vin[i].nSequence;
                }
                if (old.vin[i].nSequence < nLowest)
                {
                    fNewer = true;
                    nLowest = old.vin[i].nSequence;
                }
            }
        }
        return fNewer;
    }

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull() && vout.size() >= 1);
    }

    bool IsCoinStake() const
    {
        // ppcoin: the coin stake transaction is marked with the first output empty
        // NullStake: shielded coinstake has no transparent inputs but has shielded spends
        if ((nVersion == SHIELDED_TX_VERSION_NULLSTAKE || nVersion == SHIELDED_TX_VERSION_NULLSTAKE_V2
             || nVersion == SHIELDED_TX_VERSION_NULLSTAKE_COLD)
            && !vShieldedSpend.empty() && vout.size() >= 1 && vout[0].IsEmpty())
            return true;
        return (vin.size() > 0 && (!vin[0].prevout.IsNull()) && vout.size() >= 2 && vout[0].IsEmpty());
    }

    bool HasStealthOutput() const;

    bool IsShielded() const
    {
        return IsLegacyShieldedTransactionVersion(nVersion) &&
               !privacyVNext.IsPresent();
    }

    bool IsPrivacyVNext() const
    {
        return nVersion == SHIELDED_TX_VERSION_DSP ||
               (IsLegacyShieldedTransactionVersion(nVersion) &&
                privacyVNext.IsPresent());
    }

    // B2-e Phase 3c.4: an owner-override reclaim of an idle M-of-N cold-stake note. NOT a coinstake
    // (deliberately excluded from IsCoinStake), so fValidatedCoinstake is always false for it.
    bool IsMofNReclaim() const
    {
        return nVersion == SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM &&
               !privacyVNext.IsPresent();
    }

    bool IsDSP() const
    {
        // Only the enumerated legacy shielded envelope carries the DSP fields;
        // reserved versions must not inherit them.
        return IsShielded() && nVersion >= SHIELDED_TX_VERSION_DSP_PROTOTYPE;
    }

    bool IsFCMP() const
    {
        return IsShielded() && nVersion >= SHIELDED_TX_VERSION_FCMP;
    }

    bool HasShieldedSpend() const
    {
        return !vShieldedSpend.empty();
    }

    bool HasShieldedOutput() const
    {
        return !vShieldedOutput.empty();
    }

    /** Check for standard transaction types
        @param[in] mapInputs	Map of previous transactions that have outputs we're spending
        @return True if all inputs (scriptSigs) use only standard transaction forms
        @see CTransaction::FetchInputs
    */
    bool AreInputsStandard(const CTransaction& tx, const MapPrevTx& mapInputs);

    /** Count ECDSA signature operations the old-fashioned (pre-0.6) way
        @return number of sigops this transaction's outputs will produce when spent
        @see CTransaction::FetchInputs
    */
    unsigned int GetLegacySigOpCount() const;

    /** Count ECDSA signature operations in pay-to-script-hash inputs.

        @param[in] mapInputs	Map of previous transactions that have outputs we're spending
        @return maximum number of sigops required to validate this transaction's inputs
        @see CTransaction::FetchInputs
     */
    unsigned int GetP2SHSigOpCount(const MapPrevTx& mapInputs) const;

    /** Amount of bitcoins spent by this transaction.
        @return sum of all outputs (note: does not include fees)
     */
    int64_t GetValueOut() const
    {
        int64_t nValueOut = 0;
        for (const CTxOut& txout : vout)
        {
            nValueOut += txout.nValue;
            if (!MoneyRange(txout.nValue) || !MoneyRange(nValueOut))
                throw std::runtime_error("CTransaction::GetValueOut() : value out of range");
        }
        return nValueOut;
    }

    /** Amount of bitcoins coming in to this transaction
        Note that lightweight clients may not know anything besides the hash of previous transactions,
        so may not be able to calculate this.

        @param[in] mapInputs	Map of previous transactions that have outputs we're spending
        @return	Sum of value of all inputs (scriptSigs)
        @see CTransaction::FetchInputs
     */
    int64_t GetValueIn(const MapPrevTx& mapInputs) const;

    int64_t GetMinFee(unsigned int nBlockSize=1, enum GetMinFee_mode mode=GMF_BLOCK, unsigned int nBytes = 0) const;

    bool ReadFromTDisk(const CDiskTxPos& postx);

    bool ReadFromDisk(CDiskTxPos pos, FILE** pfileRet=NULL)
    {
        CAutoFile filein = CAutoFile(OpenBlockFile(pos.nFile, 0, pfileRet ? "rb+" : "rb"), SER_DISK, CLIENT_VERSION);
        if (!filein)
            return error("CTransaction::ReadFromDisk() : OpenBlockFile failed");

        // Read transaction
        if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
            return error("CTransaction::ReadFromDisk() : fseek failed");

        try {
            filein >> *this;
        }
        catch (std::exception &e) {
            return error("%s() : deserialize or I/O error", __PRETTY_FUNCTION__);
        }

        // Return file pointer
        if (pfileRet)
        {
            if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
                return error("CTransaction::ReadFromDisk() : second fseek failed");
            *pfileRet = filein.release();
        }
        return true;
    }

    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return (a.nVersion  == b.nVersion &&
                a.nTime     == b.nTime &&
                a.vin       == b.vin &&
                a.vout      == b.vout &&
                a.nLockTime == b.nLockTime &&
                // compare full shielded contents (not just sizes)
                // and include binding signature for consensus correctness
                a.nValueBalance == b.nValueBalance &&
                a.GetHash() == b.GetHash());
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return !(a == b);
    }

    std::string ToStringShort() const
    {
        std::string str;
        str += strprintf("%s %s", GetHash().ToString().c_str(), IsCoinBase()? "base" : (IsCoinStake()? "stake" : "user"));
        return str;
    }

    std::string ToString() const
    {
        std::string str;
        str += IsCoinBase()? "Coinbase" : (IsCoinStake()? "Coinstake" : "CTransaction");
        str += strprintf("(hash=%s, nTime=%d, ver=%d, vin.size=%" PRIszu", vout.size=%" PRIszu", nLockTime=%d)\n",
            GetHash().ToString().substr(0,10).c_str(),
            nTime,
            nVersion,
            vin.size(),
            vout.size(),
            nLockTime);
        for (unsigned int i = 0; i < vin.size(); i++)
            str += "    " + vin[i].ToString() + "\n";
        for (unsigned int i = 0; i < vout.size(); i++)
            str += "    " + vout[i].ToString() + "\n";
        return str;
    }

    void print() const
    {
        printf("%s", ToString().c_str());
    }


    bool ReadFromDisk(CTxDB& txdb, COutPoint prevout, CTxIndex& txindexRet);
    bool ReadFromDisk(CTxDB& txdb, COutPoint prevout);
    bool ReadFromDisk(COutPoint prevout);
    // Fetch by hash. The outpoint overloads resolve an input and must reject an
    // out-of-range index; a fully shielded transaction carries no transparent
    // outputs, so that bound would make it unreadable.
    bool ReadFromDisk(CTxDB& txdb, const uint256& hashTx, CTxIndex& txindexRet);

    bool DisconnectInputs(CTxDB& txdb);

    /** Fetch from memory and/or disk. inputsRet keys are transaction hashes.

     @param[in] txdb	Transaction database
     @param[in] mapTestPool	List of pending changes to the transaction index database
     @param[in] fBlock	True if being called to add a new best-block to the chain
     @param[in] fMiner	True if being called by CreateNewBlock
     @param[out] inputsRet	Pointers to this transaction's inputs
     @param[out] fInvalid	returns true if transaction is invalid
     @return    Returns true if all inputs are in txdb or mapTestPool
     */
    bool FetchInputs(CTxDB& txdb, const std::map<uint256, CTxIndex>& mapTestPool,
                     bool fBlock, bool fMiner, MapPrevTx& inputsRet, bool& fInvalid);

    // Explicit-height validator used by consensus replay and relay policy.
    // Chain validation never consults the mempool; pBlockKeyImages supplies
    // the exact active-block duplicate set when non-null.
    bool CheckAnonInputs(
        CTxDB& txdb, int nCandidateHeight, int64_t& nSumValue,
        bool& fInvalid, bool fRelay,
        std::set<ec_point>* pBlockKeyImages = NULL,
        std::vector<std::pair<ec_point, CKeyImageSpent> >* pKeyImageEffects = NULL) const;
    // Source-compatible local-miner wrapper.  It is not used by block
    // consensus and never enables the relay-only mempool key-image view when
    // fCheckExists is false.
    bool CheckAnonInputs(CTxDB& txdb, int64_t& nSumValue,
                         bool& fInvalid, bool fCheckExists) const;
    bool BuildLegacyAnonEffectPlan(CTxDB& txdb, int nCandidateHeight,
                                   std::set<ec_point>& setBlockKeyImages,
                                   CLegacyAnonEffectPlan& plan,
                                   bool& fInvalid) const;

    /** Sanity check previous transactions, then, if all checks succeed,
        mark them as spent by this transaction.

        @param[in] inputs	Previous transactions (from FetchInputs)
        @param[out] mapTestPool	Keeps track of inputs that need to be updated on disk
        @param[in] posThisTx	Position of this transaction on disk
        @param[in] pindexBlock
        @param[in] fBlock	true if called from ConnectBlock
        @param[in] fMiner	true if called from CreateNewBlock
        @return Returns true if all checks succeed
     */
    bool ConnectInputs(CTxDB& txdb, MapPrevTx inputs,
                       std::map<uint256, CTxIndex>& mapTestPool, const CDiskTxPos& posThisTx,
                       const CBlockIndex* pindexBlock, bool fBlock, bool fMiner, unsigned int flags = STANDARD_SCRIPT_VERIFY_FLAGS, bool fValidateSig = true,
                       bool fValidatedCoinstake = false,
                       bool fAnonPrevalidated = false,
                       int nAnonCandidateHeight = -1,
                       int64_t nPrevalidatedAnonValueIn = 0);
    bool CheckTransaction() const;
    bool AcceptToMemoryPool(CTxDB& txdb, bool fCheckInputs=true, bool* pfMissingInputs=NULL, bool fOnlyCheckWithoutAdding=false);
    bool GetCoinAge(CTxDB& txdb, uint64_t& nCoinAge) const;  // ppcoin: get transaction coin age

    const CTxOut& GetOutputFor(const CTxIn& input, const MapPrevTx& inputs) const;
};

bool ApplyLegacyAnonEffectPlan(CTxDB& txdb,
                               const CLegacyAnonEffectPlan& plan,
                               std::string& strError);
bool DisconnectLegacyAnonChainState(CTxDB& txdb,
                                    const CTransaction& tx,
                                    int nBlockHeight,
                                    std::string& strError);


/** A mutable version of CTransaction. */
// struct CMutableTransaction
// {
//     int32_t nVersion;
//     uint32_t nTime;                    // Innova: transaction timestamp
//     std::vector<CTxIn> vin;
//     std::vector<CTxOut> vout;
//     uint32_t nLockTime;

//     IMPLEMENT_SERIALIZE
//     (
//         //nSerSize += SerReadWrite(s, *(CTransaction*)this, nType, nVersion, ser_action); maybe?
//         READWRITE(this->nVersion);
//         nVersion = this->nVersion;
//         READWRITE(nTime);
//         READWRITE(vin);
//         READWRITE(vout);
//         READWRITE(nLockTime);
//     )

//     CMutableTransaction();
//     CMutableTransaction(const CTransaction& tx);
//     CMutableTransaction(int nVersion, unsigned int nTime, const std::vector<CTxIn> vin, const std::vector<CTxOut> vout, unsigned int nLockTime)
//              : nVersion(nVersion), nTime(nTime), vin(vin), vout(vout), nLockTime(nLockTime)
//     {
//     }

//     /** Compute the hash of this CMutableTransaction. This is computed on the
//      * fly, as opposed to GetHash() in CTransaction, which uses a cached result.
//      */
//     uint256 GetHash() const;

//     CAmount GetMinFee(size_t nBlockSize=1) const
//     {
//         CTransaction tmp(*this);
//         size_t nBytes = ::GetSerializeSize(tmp, SER_NETWORK, PROTOCOL_VERSION);
//         return ::GetMinFee(nBytes, nBlockSize);
//     }
// };


/** A transaction with a merkle branch linking it to the block chain. */
class CMerkleTx : public CTransaction
{
private:
    /** Constant used in hashBlock to indicate tx has been abandoned */
    static const uint256 ABANDON_HASH;

    int GetDepthInMainChainINTERNAL(CBlockIndex* &pindexRet) const;
public:
    uint256 hashBlock;
    std::vector<uint256> vMerkleBranch;
    int nIndex;

    // memory only
    mutable bool fMerkleVerified;


    CMerkleTx()
    {
        Init();
    }

    CMerkleTx(const CTransaction& txIn) : CTransaction(txIn)
    {
        Init();
    }

    void Init()
    {
        hashBlock = 0;
        //hashBlock = uint256();
        nIndex = -1;
        fMerkleVerified = false;
    }


    IMPLEMENT_SERIALIZE
    (
        nSerSize += SerReadWrite(s, *(CTransaction*)this, nType, nVersion, ser_action);
        nVersion = this->nVersion;
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    )


    int SetMerkleBranch(const CBlock* pblock=NULL);

    // Return depth of transaction in blockchain:
    // -1  : not in blockchain, and not in memory pool (conflicted transaction)
    //  0  : in memory pool, waiting to be included in a block
    // >=1 : this many blocks deep in the main chain
    int GetDepthInMainChain(CBlockIndex* &pindexRet) const;
    int GetDepthInMainChain() const { CBlockIndex *pindexRet; return GetDepthInMainChain(pindexRet); }
    bool IsInMainChain() const { CBlockIndex *pindexRet; return GetDepthInMainChainINTERNAL(pindexRet) > 0; }
    int GetBlocksToMaturity() const;
    bool AcceptToMemoryPool(CTxDB& txdb);
    bool AcceptToMemoryPool();
    bool isAbandoned() const { return (hashBlock == ABANDON_HASH); }
    void setAbandoned() { hashBlock = ABANDON_HASH; }
};




/**  A txdb record that contains the disk location of a transaction and the
 * locations of transactions that spend its outputs.  vSpent is really only
 * used as a flag, but having the location is very helpful for debugging.
 */
class CTxIndex
{
public:
    CDiskTxPos pos;
    std::vector<CDiskTxPos> vSpent;

    CTxIndex()
    {
        SetNull();
    }

    CTxIndex(const CDiskTxPos& posIn, unsigned int nOutputs)
    {
        pos = posIn;
        vSpent.resize(nOutputs);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(pos);
        READWRITE(vSpent);
    )

    void SetNull()
    {
        pos.SetNull();
        vSpent.clear();
    }

    bool IsNull()
    {
        return pos.IsNull();
    }

    friend bool operator==(const CTxIndex& a, const CTxIndex& b)
    {
        return (a.pos    == b.pos &&
                a.vSpent == b.vSpent);
    }

    friend bool operator!=(const CTxIndex& a, const CTxIndex& b)
    {
        return !(a == b);
    }
    int GetDepthInMainChain() const;

};








/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 *
 * Blocks are appended to blk0001.dat files on disk.  Their location on disk
 * is indexed by CBlockIndex objects in memory.
 */
class CBlock
{
public:
    // header
    static const int CURRENT_VERSION=6;
    int nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;

    // network and disk
    std::vector<CTransaction> vtx;

    // ppcoin: block signature - signed by one of the coin base txout[N]'s owner
    std::vector<unsigned char> vchBlockSig;

    // memory only
    mutable std::vector<uint256> vMerkleTree;

    // Denial-of-service detection:
    mutable int nDoS;
    bool DoS(int nDoSIn, bool fIn) const { nDoS += nDoSIn; return fIn; }

    CBlock()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);

        // ConnectBlock depends on vtx following header to generate CDiskTxPos
        if (!(nType & (SER_GETHASH|SER_BLOCKHEADERONLY)))
        {
            READWRITE(vtx);
            READWRITE(vchBlockSig);
        }
        else if (fRead)
        {
            const_cast<CBlock*>(this)->vtx.clear();
            const_cast<CBlock*>(this)->vchBlockSig.clear();
        }
    )

    void SetNull()
    {
        nVersion = CBlock::CURRENT_VERSION;
        hashPrevBlock = 0;
        hashMerkleRoot = 0;
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        vtx.clear();
        vchBlockSig.clear();
        vMerkleTree.clear();
        nDoS = 0;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const
    {
        return GetPoWHash();
    }

    uint256 GetPoWHash() const
    {
        return Tribus(BEGIN(nVersion), END(nNonce));
        //return scrypt_blockhash(CVOIDBEGIN(nVersion));
    }

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    void UpdateTime(const CBlockIndex* pindexPrev);

    // entropy bit derived from block hash last bit.
    // Stakers have partial control over this bit via timestamp grinding.
    // This is a known limitation of NovaCoin-derived PoS (shared by all forks).
    // Mitigation: stake modifier checkpoint enforcement (MIN-NEW-1) limits impact.
    unsigned int GetStakeEntropyBit() const
    {
        // Take last bit of block hash as entropy bit
        unsigned int nEntropyBit = ((GetHash().Get64()) & 1llu);
        if (fDebug && GetBoolArg("-printstakemodifier"))
            printf("GetStakeEntropyBit: hashBlock=%s nEntropyBit=%u\n", GetHash().ToString().c_str(), nEntropyBit);
        return nEntropyBit;
    }

    // ppcoin: two types of block: proof-of-work or proof-of-stake
    bool IsProofOfStake() const
    {
        return (vtx.size() > 1 && vtx[1].IsCoinStake());
    }

    bool IsProofOfWork() const
    {
        return !IsProofOfStake();
    }

    std::pair<COutPoint, unsigned int> GetProofOfStake() const
    {
        if (!IsProofOfStake())
            return std::make_pair(COutPoint(), (unsigned int)0);
        // NullStake V1/V2/V3: no transparent inputs, use nullifier-derived outpoint
        if (vtx[1].nVersion == SHIELDED_TX_VERSION_NULLSTAKE
            || vtx[1].nVersion == SHIELDED_TX_VERSION_NULLSTAKE_V2
            || vtx[1].nVersion == SHIELDED_TX_VERSION_NULLSTAKE_COLD)
            return std::make_pair(COutPoint(vtx[1].GetHash(), 0), vtx[1].nTime);
        if (vtx[1].vin.empty())
            return std::make_pair(COutPoint(), (unsigned int)0);
        return std::make_pair(vtx[1].vin[0].prevout, vtx[1].nTime);
    }

    // ppcoin: get max transaction timestamp
    int64_t GetMaxTransactionTime() const
    {
        int64_t maxTransactionTime = 0;
        for (const CTransaction& tx : vtx)
            maxTransactionTime = std::max(maxTransactionTime, (int64_t)tx.nTime);
        return maxTransactionTime;
    }

    uint256 BuildMerkleTree() const
    {
        vMerkleTree.clear();
        for (const CTransaction& tx : vtx)
            vMerkleTree.push_back(tx.GetHash());
        int j = 0;
        for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
        {
            for (int i = 0; i < nSize; i += 2)
            {
                int i2 = std::min(i+1, nSize-1);
                vMerkleTree.push_back(Hash(BEGIN(vMerkleTree[j+i]),  END(vMerkleTree[j+i]),
                                           BEGIN(vMerkleTree[j+i2]), END(vMerkleTree[j+i2])));
            }
            j += nSize;
        }
        return (vMerkleTree.empty() ? 0 : vMerkleTree.back());
    }

    std::vector<uint256> GetMerkleBranch(int nIndex) const
    {
        if (vMerkleTree.empty())
            BuildMerkleTree();
        std::vector<uint256> vMerkleBranch;
        int j = 0;
        for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
        {
            int i = std::min(nIndex^1, nSize-1);
            vMerkleBranch.push_back(vMerkleTree[j+i]);
            nIndex >>= 1;
            j += nSize;
        }
        return vMerkleBranch;
    }

    static uint256 CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex)
    {
        // reject negative nIndex values
        if (nIndex < 0)
            return 0;
        for (const uint256& otherside : vMerkleBranch)
        {
            if (nIndex & 1)
                hash = Hash(BEGIN(otherside), END(otherside), BEGIN(hash), END(hash));
            else
                hash = Hash(BEGIN(hash), END(hash), BEGIN(otherside), END(otherside));
            nIndex >>= 1;
        }
        return hash;
    }


    bool WriteToDisk(unsigned int& nFileRet, unsigned int& nBlockPosRet)
    {
        // Open history file to append
        CAutoFile fileout = CAutoFile(AppendBlockFile(nFileRet), SER_DISK, CLIENT_VERSION);
        if (!fileout)
            return error("CBlock::WriteToDisk() : AppendBlockFile failed");

        // Write index header. The prefix is the byte count that follows;
        // BackfillBlockIndexSizes restores CBlockIndex::nSize from it.
        unsigned int nSize = fileout.GetSerializeSize(*this);
        fileout << FLATDATA(pchMessageStart) << nSize;

        // Write block
        long fileOutPos = ftell(fileout);
        if (fileOutPos < 0)
            return error("CBlock::WriteToDisk() : ftell failed");
        nBlockPosRet = fileOutPos;
        fileout << *this;

        // Flush stdio buffers and commit to disk before returning
        fflush(fileout);
        if (!IsInitialBlockDownload() || (nBestHeight+1) % 500 == 0)
            FileCommit(fileout);

        return true;
    }

    bool ReadFromDisk(unsigned int nFile, unsigned int nBlockPos, bool fReadTransactions=true)
    {
        SetNull();

        // Open history file to read
        CAutoFile filein = CAutoFile(OpenBlockFile(nFile, nBlockPos, "rb"), SER_DISK, CLIENT_VERSION);
        if (!filein)
            return error("CBlock::ReadFromDisk() : OpenBlockFile failed");
        if (!fReadTransactions)
            filein.nType |= SER_BLOCKHEADERONLY;

        // Read block
        try {
            filein >> *this;
        }
        catch (std::exception &e) {
            return error("%s() : deserialize or I/O error", __PRETTY_FUNCTION__);
        }

        // Check the header
        if (fReadTransactions && IsProofOfWork() && !CheckProofOfWork(GetPoWHash(), nBits))
            return error("CBlock::ReadFromDisk() : errors in block header");

        return true;
    }



    void print() const
    {
        printf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%" PRIszu", vchBlockSig=%s)\n",
            GetHash().ToString().c_str(),
            nVersion,
            hashPrevBlock.ToString().c_str(),
            hashMerkleRoot.ToString().c_str(),
            nTime, nBits, nNonce,
            vtx.size(),
            HexStr(vchBlockSig.begin(), vchBlockSig.end()).c_str());
        for (unsigned int i = 0; i < vtx.size(); i++)
        {
            printf("  ");
            vtx[i].print();
        }
        printf("  vMerkleTree: ");
        for (unsigned int i = 0; i < vMerkleTree.size(); i++)
            printf("%s ", vMerkleTree[i].ToString().substr(0,10).c_str());
        printf("\n");
    }


    bool DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex, bool fWriteNames = true);
    enum ConnectResult
    {
        CONNECT_RESULT_OK = 0,
        CONNECT_RESULT_INVALID,
        CONNECT_RESULT_TRANSIENT
    };

    bool ConnectBlock(CTxDB& txdb, CBlockIndex* pindex,
                      bool fJustCheck=false, bool fWriteNames = true,
                      ConnectResult* pResult = NULL);
    bool ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions=true);
    bool SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew, bool* pfPermanentInvalid = NULL,
                      CBlockFailReason* pFailReason = NULL);
    bool AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos, const uint256& hashProof);
    bool CheckBlock(bool fCheckPOW=true, bool fCheckMerkleRoot=true, bool fCheckSig=true) const;
    bool AcceptBlock();
    bool GetCoinAge(uint64_t& nCoinAge) const; // ppcoin: calculate total coin age spent in block
    bool SignBlock(CWallet& keystore, int64_t nFees);
    bool CheckBlockSignature() const;
	void RebuildAddressIndex(CTxDB& txdb);

private:
    bool SetBestChainInner(CTxDB& txdb, CBlockIndex *pindexNew,
                           bool* pfPermanentInvalid = NULL,
                           CBestChainEffectJournal* pCommittedEffects = NULL,
                           CBlockFailReason* pFailReason = NULL);
};

// Collateralnode payment rule (S4): its gate depends on the local clock, tip, CN list
// and mempool, so a rejection under it must stay in memory. Persisting
// BLOCK_FAILED_VALID would split the network along clock offsets.
int64_t CollateralnodePaymentWindowSeconds();
bool CollateralnodePaymentRuleApplies(bool fJustCheck, int64_t nBlockTime,
                                      int64_t nNow, bool fPaymentsEnabled);

// The cold-stake collateralnode payee check has the same shape: the expected payee
// comes from the gossiped winner schedule and the gossiped node list, so it runs
// only inside the same window and its refusal is not persistable either.
bool ColdStakeCNPayeeRuleApplies(bool fJustCheck, int nHeight, int64_t nCNPayment,
                                 int64_t nBlockTime, int64_t nNow);
bool ColdStakeCNPayeeIsRegistered(int nHeight, const CScript& payeeScript);

// Whether a ConnectBlock result may be recorded as BLOCK_FAILED_VALID. Reorganize
// and SetBestChainInner both call this so the persistence rule exists once.
bool ConnectResultMayPersistVerdict(CBlock::ConnectResult result);


// bool ReadBlockFromDisk(CBlock& block, const CDiskBlockPos& pos);
// bool ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex);



/** The block chain is a tree shaped structure starting with the
 * genesis block at the root, with each block potentially having multiple
 * candidates to be the next block.  pprev and pnext link a path through the
 * main/longest chain.  A blockindex may have multiple pprev pointing back
 * to it, but pnext will only point forward to the longest branch, or will
 * be null if the block is not part of the longest chain.
 */
class CBlockIndex
{
public:
    const uint256* phashBlock;
    CBlockIndex* pprev;
    CBlockIndex* pnext;
    CBlockIndex* pskip;
    unsigned int nFile;
    unsigned int nBlockPos;
    uint256 nChainTrust; // ppcoin: trust score of block chain
    int nHeight;

    int64_t nMint;
    int64_t nMoneySupply;

    // Number of transactions in this block.
    // Note: in a potential headers-first mode, this number cannot be relied upon
    unsigned int nTx;

    // (memory only) Number of transactions in the chain up to and including this block
    unsigned int nChainTx; // change to 64-bit type when necessary; won't happen before 2030

    // (memory only) Deterministic finalized height of this block's connected set, never the
    // node-local tip. Recomputed on connect and load; never serialized.
    int nFinalizedHeight;

    unsigned int nFlags;  // ppcoin: block index flags
    enum
    {
        BLOCK_PROOF_OF_STAKE = (1 << 0), // is proof-of-stake block
        BLOCK_STAKE_ENTROPY  = (1 << 1), // entropy bit for stake modifier
        BLOCK_STAKE_MODIFIER = (1 << 2), // regenerated stake modifier
        BLOCK_FAILED_VALID   = (1 << 3), // failed connect/reorg validity: keep index, never re-request/connect
        BLOCK_FAILED_CHILD   = (1 << 4), // descends from a BLOCK_FAILED_VALID block (invalidateblock taint)
    };

    uint64_t nStakeModifier; // hash modifier for proof-of-stake
    unsigned int nStakeModifierChecksum; // checksum of index; in-memeory only

    // proof-of-stake specific fields
    COutPoint prevoutStake;
    unsigned int nStakeTime;

    uint256 hashProof;

    // block header
    int nVersion;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;
    unsigned int nSize;   // serialized block size (for adaptive block sizing)
    // Millisecond offset past nTime, cached from the coinbase IMTS commitment
    // so a walk over the index need not re-read coinbases. Always 0 below
    // FORK_HEIGHT_MS_TIMESTAMP, where no commitment may exist.
    uint16_t nTimeMs;

    CBlockIndex()
    {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;
        pskip = NULL;
        nFile = 0;
        nBlockPos = 0;
        nHeight = 0;
        nChainTrust = 0;
        nMint = 0;
        nMoneySupply = 0;
        nFlags = 0;
        nStakeModifier = 0;
        nStakeModifierChecksum = 0;
        hashProof = 0;
        prevoutStake.SetNull();
        nStakeTime = 0;
        nSize = 0;
        nTimeMs = 0;
        nFinalizedHeight = 0;

        nVersion       = 0;
        hashMerkleRoot = 0;
        nTime          = 0;
        nBits          = 0;
        nNonce         = 0;
    }

    CBlockIndex(unsigned int nFileIn, unsigned int nBlockPosIn, CBlock& block)
    {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;
        pskip = NULL;
        nFile = nFileIn;
        nBlockPos = nBlockPosIn;
        nHeight = 0;
        nChainTrust = 0;
        nMint = 0;
        nMoneySupply = 0;
        nFlags = 0;
        nStakeModifier = 0;
        nStakeModifierChecksum = 0;
        hashProof = 0;
        nFinalizedHeight = 0;
        if (block.IsProofOfStake())
        {
            SetProofOfStake();
            if (block.vtx[1].nVersion == SHIELDED_TX_VERSION_NULLSTAKE)
            {
                // NullStake: no transparent inputs, use tx hash as prevout identifier
                prevoutStake = COutPoint(block.vtx[1].GetHash(), 0);
            }
            else
            {
                prevoutStake = block.vtx[1].vin[0].prevout;
            }
            nStakeTime = block.vtx[1].nTime;
        }
        else
        {
            prevoutStake.SetNull();
            nStakeTime = 0;
        }

        nVersion       = block.nVersion;
        hashMerkleRoot = block.hashMerkleRoot;
        nTime          = block.nTime;
        nBits          = block.nBits;
        nNonce         = block.nNonce;
        nSize          = ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION);
        // Set by AddToBlockIndex, which is the first point that knows nHeight
        // and so whether a commitment is required at all.
        nTimeMs        = 0;
    }

    CBlock GetBlockHeader() const
    {
        CBlock block;
        block.nVersion       = nVersion;
        if (pprev)
            block.hashPrevBlock = pprev->GetBlockHash();
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        return block;
    }

    uint256 GetBlockHash() const
    {
        return *phashBlock;
    }

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    // Full-precision block time. Below FORK_HEIGHT_MS_TIMESTAMP nTimeMs is 0,
    // so this is GetBlockTime() scaled and orders identically there.
    int64_t GetBlockTimeMs() const
    {
        return MsTimestampCombine(nTime, nTimeMs);
    }

    CBigNum GetBlockWork() const
    {
        CBigNum bnTarget;
        bnTarget.SetCompact(nBits);
        if (bnTarget <= 0)
            return 0;
        return (CBigNum(1)<<256) / (bnTarget+1);
    }

    uint256 GetBlockTrust() const;

    bool IsInMainChain() const
    {
        return (pnext || this == pindexBest);
    }

    void BuildSkip();
    CBlockIndex* GetAncestor(int nHeightTarget);
    const CBlockIndex* GetAncestor(int nHeightTarget) const;

    bool CheckIndex() const
    {
        return true;
    }

    int64_t GetPastTimeLimit() const
    {
        return GetMedianTimePast();
    }

    enum { nMedianTimeSpan=11 };

    int64_t GetMedianTimePast() const
    {
        int64_t pmedian[nMedianTimeSpan];
        int64_t* pbegin = &pmedian[nMedianTimeSpan];
        int64_t* pend = &pmedian[nMedianTimeSpan];

        const CBlockIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
            *(--pbegin) = pindex->GetBlockTime();

        std::sort(pbegin, pend);
        return pbegin[(pend - pbegin)/2];
    }

    /**
     * Returns true if there are nRequired or more blocks of minVersion or above
     * in the last nToCheck blocks, starting at pstart and going backwards.
     */
    static bool IsSuperMajority(int minVersion, const CBlockIndex* pstart,
                                unsigned int nRequired, unsigned int nToCheck);


    bool IsProofOfWork() const
    {
        return !(nFlags & BLOCK_PROOF_OF_STAKE);
    }

    bool IsProofOfStake() const
    {
        return (nFlags & BLOCK_PROOF_OF_STAKE);
    }

    void SetProofOfStake()
    {
        nFlags |= BLOCK_PROOF_OF_STAKE;
    }

    unsigned int GetStakeEntropyBit() const
    {
        return ((nFlags & BLOCK_STAKE_ENTROPY) >> 1);
    }

    bool SetStakeEntropyBit(unsigned int nEntropyBit)
    {
        if (nEntropyBit > 1)
            return false;
        nFlags |= (nEntropyBit? BLOCK_STAKE_ENTROPY : 0);
        return true;
    }

    bool GeneratedStakeModifier() const
    {
        return (nFlags & BLOCK_STAKE_MODIFIER);
    }

    void SetStakeModifier(uint64_t nModifier, bool fGeneratedStakeModifier)
    {
        nStakeModifier = nModifier;
        if (fGeneratedStakeModifier)
            nFlags |= BLOCK_STAKE_MODIFIER;
    }

    // Permanent-invalidity flags (persisted via nFlags in CDiskBlockIndex). A block that permanently
    // failed connect/reorg is KEPT in mapBlockIndex flagged (not deleted) so it is not re-requested +
    // re-validated forever, and its children are rejected. invalidateblock/reconsiderblock toggle these.
    bool IsInvalid() const { return (nFlags & (BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD)); }
    bool IsFailed() const { return (nFlags & BLOCK_FAILED_VALID); }
    void SetFailedValid() { nFlags |= BLOCK_FAILED_VALID; }
    void SetFailedChild() { nFlags |= BLOCK_FAILED_CHILD; }
    void ClearFailed() { nFlags &= ~(BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD); }

    std::string ToString() const
    {
        return strprintf("CBlockIndex(nprev=%p, pnext=%p, nFile=%u, nBlockPos=%-6u nHeight=%d, nMint=%s, nMoneySupply=%s, nFlags=(%s)(%d)(%s), nStakeModifier=%016llx, nStakeModifierChecksum=%08x, hashProof=%s, prevoutStake=(%s), nStakeTime=%u merkle=%s, hashBlock=%s)",
            pprev, pnext, nFile, nBlockPos, nHeight,
            FormatMoney(nMint).c_str(), FormatMoney(nMoneySupply).c_str(),
            GeneratedStakeModifier() ? "MOD" : "-", GetStakeEntropyBit(), IsProofOfStake()? "PoS" : "PoW",
            (unsigned long long)nStakeModifier, nStakeModifierChecksum,
            hashProof.ToString().c_str(),
            prevoutStake.ToString().c_str(), nStakeTime,
            hashMerkleRoot.ToString().c_str(),
            GetBlockHash().ToString().c_str());
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};



/** Used to marshal pointers into hashes for db storage. */
class CDiskBlockIndex : public CBlockIndex
{
private:
    uint256 blockHash;

public:
    uint256 hashPrev;
    uint256 hashNext;

    CDiskBlockIndex()
    {
        hashPrev = 0;
        hashNext = 0;
        blockHash = 0;
    }

    explicit CDiskBlockIndex(CBlockIndex* pindex) : CBlockIndex(*pindex)
    {
        hashPrev = (pprev ? pprev->GetBlockHash() : 0);
        hashNext = (pnext ? pnext->GetBlockHash() : 0);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);

        READWRITE(hashNext);
        READWRITE(nFile);
        READWRITE(nBlockPos);
        READWRITE(nHeight);
        READWRITE(nMint);
        READWRITE(nMoneySupply);
        READWRITE(nFlags);
        READWRITE(nStakeModifier);
        if (IsProofOfStake())
        {
            READWRITE(prevoutStake);
            READWRITE(nStakeTime);
        }
        else if (fRead)
        {
            const_cast<CDiskBlockIndex*>(this)->prevoutStake.SetNull();
            const_cast<CDiskBlockIndex*>(this)->nStakeTime = 0;
        }
        READWRITE(hashProof);

        // block header
        READWRITE(this->nVersion);
        READWRITE(hashPrev);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
        READWRITE(blockHash);
        // nSize is an optional trailing field; an older record ends at blockHash and
        // reads nSize = 0, which CTxDB::LoadBlockIndex backfills from the block file.
        if (!fRead)
            READWRITE(nSize);
        else if (SerBytesRemaining(s) >= sizeof(nSize))
            READWRITE(nSize);
        else
            const_cast<CDiskBlockIndex*>(this)->nSize = 0;
        // nTimeMs is a second optional trailing field after nSize. An older record
        // reads 0 and is not backfilled (nothing reads it in v5).
        if (!fRead)
            READWRITE(nTimeMs);
        else if (SerBytesRemaining(s) >= sizeof(nTimeMs))
            READWRITE(nTimeMs);
        else
            const_cast<CDiskBlockIndex*>(this)->nTimeMs = 0;
    )

    uint256 GetBlockHash() const
    {
        if (fUseFastIndex && (nTime < GetAdjustedTime() - 24 * 60 * 60) && blockHash != 0)
            return blockHash;

        CBlock block;
        block.nVersion        = nVersion;
        block.hashPrevBlock   = hashPrev;
        block.hashMerkleRoot  = hashMerkleRoot;
        block.nTime           = nTime;
        block.nBits           = nBits;
        block.nNonce          = nNonce;

        const_cast<CDiskBlockIndex*>(this)->blockHash = block.GetHash();

        return blockHash;
    }

    std::string ToString() const
    {
        std::string str = "CDiskBlockIndex(";
        str += CBlockIndex::ToString();
        str += strprintf("\n                hashBlock=%s, hashPrev=%s, hashNext=%s)",
            GetBlockHash().ToString().c_str(),
            hashPrev.ToString().c_str(),
            hashNext.ToString().c_str());
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};

/** Copy the persisted fields of a block-index record onto an in-memory index.
 *  pprev/pnext are resolved by the caller. */
inline void ApplyDiskBlockIndexFields(const CDiskBlockIndex& diskindex, CBlockIndex* pindexNew)
{
    pindexNew->nFile          = diskindex.nFile;
    pindexNew->nBlockPos      = diskindex.nBlockPos;
    pindexNew->nHeight        = diskindex.nHeight;
    pindexNew->nMint          = diskindex.nMint;
    pindexNew->nMoneySupply   = diskindex.nMoneySupply;
    pindexNew->nFlags         = diskindex.nFlags;
    pindexNew->nStakeModifier = diskindex.nStakeModifier;
    pindexNew->prevoutStake   = diskindex.prevoutStake;
    pindexNew->nStakeTime     = diskindex.nStakeTime;
    pindexNew->hashProof      = diskindex.hashProof;
    pindexNew->nVersion       = diskindex.nVersion;
    pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
    pindexNew->nTime          = diskindex.nTime;
    pindexNew->nBits          = diskindex.nBits;
    pindexNew->nNonce         = diskindex.nNonce;
    pindexNew->nSize          = diskindex.nSize;
    pindexNew->nTimeMs        = diskindex.nTimeMs;
}

/** How far below FORK_HEIGHT_DAG an adaptive-block-size window can reach. */
int GetBlockIndexSizeBackfillDepth();

/** Lowest height whose nSize can still enter an adaptive-block-size window.
 *  Both consumers refuse to run below FORK_HEIGHT_DAG, so no window can reach
 *  deeper than this, at any reorg depth. */
int GetBlockIndexSizeBackfillFloor();

/** True for an index that is missing nSize and is shallow enough for an
 *  adaptive-block-size window to reach it. */
bool BlockIndexNeedsSizeRestore(const CBlockIndex* pindex, int nFloor);

/** How many restored entries are re-measured against their own block data.
 *  Bounded because each check reads a whole block. */
static const size_t BLOCKINDEX_SIZE_RESTORE_VERIFY_SAMPLES = 16;

/** Restore nSize for indexes loaded without it, from the size prefix that
 *  CBlock::WriteToDisk stores ahead of every block. Fails closed when a sampled
 *  prefix does not match the block's own SER_NETWORK measure. */
bool BackfillBlockIndexSizes(const std::vector<CBlockIndex*>& vNeedSize,
                             int& nRestoredOut, std::string& strError);

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
class CBlockLocator
{
protected:
    std::vector<uint256> vHave;
public:

    CBlockLocator()
    {
    }

    explicit CBlockLocator(const CBlockIndex* pindex)
    {
        Set(pindex);
    }

    explicit CBlockLocator(uint256 hashBlock)
    {
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end())
            Set((*mi).second);
    }

    CBlockLocator(const std::vector<uint256>& vHaveIn)
    {
        vHave = vHaveIn;
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    )

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull()
    {
        return vHave.empty();
    }

    void Set(const CBlockIndex* pindex)
    {
        vHave.clear();
        if (!pindex)
        {
            vHave.push_back(GetGenesisBlockHash());
            return;
        }

        const CBlockIndex* pindexStart = pindex;
        int nStep = 1;
        int nHeight = pindex->nHeight;
        while (nHeight >= 0)
        {
            const CBlockIndex* pindexAtHeight = (nHeight == pindexStart->nHeight)
                ? pindexStart
                : pindexStart->GetAncestor(nHeight);
            if (!pindexAtHeight)
                break;
            vHave.push_back(pindexAtHeight->GetBlockHash());
            nHeight -= nStep;
            if (vHave.size() > 10)
                nStep *= 2;
        }
        vHave.push_back(GetGenesisBlockHash());
    }

    int GetDistanceBack()
    {
        // Retrace how far back it was in the sender's branch
        int nDistance = 0;
        int nStep = 1;
        for (const uint256& hash : vHave)
        {
            std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end())
            {
                CBlockIndex* pindex = (*mi).second;
                if (pindex->IsInMainChain())
                    return nDistance;
            }
            nDistance += nStep;
            if (nDistance > 10)
                nStep *= 2;
        }
        return nDistance;
    }

    CBlockIndex* GetBlockIndex()
    {
        // Find the first block the caller has in the main chain
        for (const uint256& hash : vHave)
        {
            std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end())
            {
                CBlockIndex* pindex = (*mi).second;
                if (pindex->IsInMainChain())
                    return pindex;
            }
        }
        return pindexGenesisBlock;
    }

    uint256 GetBlockHash()
    {
        // Find the first block the caller has in the main chain
        for (const uint256& hash : vHave)
        {
            std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end())
            {
                CBlockIndex* pindex = (*mi).second;
                if (pindex->IsInMainChain())
                    return hash;
            }
        }
        return GetGenesisBlockHash();
    }

    int GetHeight()
    {
        CBlockIndex* pindex = GetBlockIndex();
        if (!pindex)
            return 0;
        return pindex->nHeight;
    }
};


/** Capture information about block/transaction validation */
class CValidationState {
private:
    enum mode_state {
        MODE_VALID,   //! everything ok
        MODE_INVALID, //! network rule violation (DoS value may be set)
        MODE_ERROR,   //! run-time error
    } mode;
    int nDoS;
    std::string strRejectReason;
    unsigned char chRejectCode;
    bool corruptionPossible;
public:
    CValidationState() : mode(MODE_VALID), nDoS(0), chRejectCode(0), corruptionPossible(false) {}
    bool DoS(int level, bool ret = false,
             unsigned char chRejectCodeIn=0, std::string strRejectReasonIn="",
             bool corruptionIn=false) {
        chRejectCode = chRejectCodeIn;
        strRejectReason = strRejectReasonIn;
        corruptionPossible = corruptionIn;
        if (mode == MODE_ERROR)
            return ret;
        nDoS += level;
        mode = MODE_INVALID;
        return ret;
    }
    bool Invalid(bool ret = false,
                 unsigned char _chRejectCode=0, std::string _strRejectReason="") {
        return DoS(0, ret, _chRejectCode, _strRejectReason);
    }
    bool Error(std::string strRejectReasonIn="") {
        if (mode == MODE_VALID)
            strRejectReason = strRejectReasonIn;
        mode = MODE_ERROR;
        return false;
    }
    bool Abort(const std::string &msg) {
        AbortNode(msg);
        return Error(msg);
    }
    bool IsValid() const {
        return mode == MODE_VALID;
    }
    bool IsInvalid() const {
        return mode == MODE_INVALID;
    }
    bool IsError() const {
        return mode == MODE_ERROR;
    }
    bool IsInvalid(int &nDoSOut) const {
        if (IsInvalid()) {
            nDoSOut = nDoS;
            return true;
        }
        return false;
    }
    bool CorruptionPossible() const {
        return corruptionPossible;
    }
    unsigned char GetRejectCode() const { return chRejectCode; }
    std::string GetRejectReason() const { return strRejectReason; }
};

class CTxMemPool
{
private:
    // CTransaction tx;
    unsigned int nTransactionsUpdated;
public:
    mutable CCriticalSection cs;
    std::map<uint256, CTransaction> mapTx;
    std::map<COutPoint, CInPoint> mapNextTx;

    std::map<std::vector<uint8_t>, CKeyImageSpent> mapKeyImage;

    // Shielded nullifier tracking (prevents double-spend in mempool)
    std::map<uint256, CShieldedNullifierSpent> mapShieldedNullifier;

    // Privacy vNext uses a separate key-image generation and namespace. The
    // reverse map makes removal independent of re-running proof verification.
    std::map<uint256, CShieldedNullifierSpent> mapPrivacyVNextNullifier;
    std::map<uint256, std::vector<uint256> > mapPrivacyVNextTxNullifiers;

    // Output owners are reserved on the same terms as key images.
    // Pending collateral attestations, kept apart from spent-key reservations: an
    // attestation in flight must never keep a spend of the same note out of the mempool.
    std::map<uint256, CShieldedNullifierSpent> mapPrivacyVNextAttestation;
    std::map<uint256, std::vector<uint256> > mapPrivacyVNextTxAttestations;

    // A pending spend retires the note it names for registration, so an attestation of
    // the same key image can never connect behind it.
    bool HasPendingPrivacyVNextSpend(const uint256& keyImage) const;
    // Drop attestations made unconnectable by an accepted spend. The spend itself is
    // never delayed or refused for an attestation in flight.
    size_t EvictPrivacyVNextAttestationsSpentBy(
        const std::vector<uint256>& vKeyImages, const uint256& hashSpend);

    bool accept(CTxDB& txdb, CTransaction &tx,
                bool fCheckInputs, bool* pfMissingInputs, bool fOnlyCheckWithoutAdding=false);
    bool addUnchecked(const uint256& hash, CTransaction &tx);
    bool remove(const CTransaction &tx, bool fRecursive = false);
    bool removeConflicts(const CTransaction &tx);

    // DAG-aware mempool coordination
    std::set<uint256> setDAGSeenTxids;
    void RemoveDAGConflicts(const uint256& hashBlock);

    void clear();
    void queryHashes(std::vector<uint256>& vtxid);
    unsigned int GetTransactionsUpdated() const;
    void AddTransactionsUpdated(unsigned int n);

    unsigned long size() const
    {
        LOCK(cs);
        return mapTx.size();
    }

    size_t GetTotalMemoryUsage() const
    {
        LOCK(cs);
        size_t usage = 0;
        for (std::map<uint256, CTransaction>::const_iterator it = mapTx.begin(); it != mapTx.end(); ++it)
            usage += ::GetSerializeSize(it->second, SER_NETWORK, PROTOCOL_VERSION);
        return usage;
    }

    bool exists(uint256 hash) const
    {
        LOCK(cs);
        return (mapTx.count(hash) != 0);
    }

    bool lookup(uint256 hash, CTransaction& result) const
    {
        LOCK(cs);
        std::map<uint256, CTransaction>::const_iterator i = mapTx.find(hash);
        if (i == mapTx.end()) return false;
        result = i->second;
        return true;
    }

    bool insertKeyImage(const std::vector<uint8_t>& vchImage, CKeyImageSpent& kis)
    {
        LOCK(cs);

        mapKeyImage[vchImage] = kis;

        return true;
    }
    bool lookupKeyImage(const std::vector<uint8_t>& vchImage, CKeyImageSpent& result) const
    {
        LOCK(cs);

        std::map<std::vector<uint8_t>, CKeyImageSpent>::const_iterator it = mapKeyImage.find(vchImage);
        if (it == mapKeyImage.end())
            return false;

        result = it->second;

        return true;
    }

    bool insertShieldedNullifier(const uint256& nullifier, const CShieldedNullifierSpent& nfs)
    {
        LOCK(cs);
        mapShieldedNullifier[nullifier] = nfs;
        return true;
    }

    bool lookupShieldedNullifier(const uint256& nullifier, CShieldedNullifierSpent& result) const
    {
        LOCK(cs);
        std::map<uint256, CShieldedNullifierSpent>::const_iterator it = mapShieldedNullifier.find(nullifier);
        if (it == mapShieldedNullifier.end())
            return false;
        result = it->second;
        return true;
    }

    bool removeShieldedNullifier(const uint256& nullifier)
    {
        LOCK(cs);
        mapShieldedNullifier.erase(nullifier);
        return true;
    }
};

extern CTxMemPool mempool;

/** (try to) add transaction to memory pool **/

bool AcceptableInputs(CTxMemPool& pool, const CTransaction &txo, bool fLimitFree,
                        bool* pfMissingInputs);

#endif
