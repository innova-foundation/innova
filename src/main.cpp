// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2017-2021 The Denarius developers
// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "alert.h"
#include "bloom.h"
#include "checkpoints.h"
#include "db.h"
#include "txdb.h"
#include "verifycache.h"
#include "net.h"
#include "init.h"
#include "wallet.h"
#include "ui_interface.h"
#include "kernel.h"
#include "collateral.h"
#include "collateralnode.h"
#include "nullsend.h"
#include "spork.h"
#include "smessage.h"
#include "namecoin.h"
#include "dandelion.h"
#include "lelantus.h"
#include "curvetree.h"
#include "finality.h"
#include "subsidy.h"
#include "dag.h"
#include "blockprofile.h"
#include "privacy_vnext_ffi.h"
#include "privacy_vnext_store.h"
#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <algorithm>

#if BOOST_VERSION >= 107300
#include <boost/bind/bind.hpp>
using boost::placeholders::_1;
using boost::placeholders::_2;
#else
#include <boost/bind.hpp>
#endif

using namespace std;
namespace fs = boost::filesystem;

// Validate only the commitments named by this spend.  The reverse lookup is
// bounded by LELANTUS_MAX_SET_SIZE, and the forward read prevents a stale or
// corrupt reverse-index entry from authenticating a different commitment.
static bool CheckShieldedAnonSetChainState(
    CTxDB& txdb,
    const std::vector<CPedersenCommitment>& vAnonSet,
    std::string& strErrorOut)
{
    if (vAnonSet.size() > (size_t)LELANTUS_MAX_SET_SIZE)
    {
        strErrorOut = strprintf("anonymity set size %u exceeds maximum %u",
                                (unsigned int)vAnonSet.size(),
                                (unsigned int)LELANTUS_MAX_SET_SIZE);
        return false;
    }

    uint64_t nCommitmentCount = 0;
    if (!txdb.ReadShieldedCommitmentCount(nCommitmentCount))
    {
        strErrorOut = "shielded commitment count missing or unreadable";
        return false;
    }

    for (size_t i = 0; i < vAnonSet.size(); ++i)
    {
        uint64_t nCommitmentIndex = 0;
        if (!txdb.ReadShieldedCommitmentIndex(
                vAnonSet[i].vchCommitment, nCommitmentIndex))
        {
            strErrorOut = strprintf(
                "anonymity set commitment %u reverse index missing or unreadable",
                (unsigned int)i);
            return false;
        }
        if (nCommitmentIndex >= nCommitmentCount)
        {
            strErrorOut = strprintf(
                "anonymity set commitment %u reverse index %" PRIu64
                " is outside commitment count %" PRIu64,
                (unsigned int)i, nCommitmentIndex, nCommitmentCount);
            return false;
        }

        CPedersenCommitment indexedCommitment;
        if (!txdb.ReadShieldedCommitment(nCommitmentIndex,
                                         indexedCommitment))
        {
            strErrorOut = strprintf(
                "anonymity set commitment %u indexed value missing or unreadable",
                (unsigned int)i);
            return false;
        }
        if (indexedCommitment.vchCommitment !=
            vAnonSet[i].vchCommitment)
        {
            strErrorOut = strprintf(
                "anonymity set commitment %u reverse-index/value mismatch",
                (unsigned int)i);
            return false;
        }
    }

    return true;
}

// B2-e Phase 3c: the value commitment used for the binding signature + value balance (INV-1):
// the fresh 2-generator Vv for a 2006 M-of-N mint output, cv_plain_out for a 2005 M-of-N cold-stake
// coinstake re-mint, the raw cv otherwise -- see MofNOutputBindingCommitment below.

// B2-e: true when this shielded tx is a kernel-validated M-of-N cold-stake coinstake (vtx[1] of a PoS
// block, identified by the position-only fValidatedCoinstake flag -- NEVER tx shape). Its staked-note
// SPEND and ALL its re-minted OUTPUTS are bound to the single public delegation D =
// nullstakeProofV3.delegationHash (3c.2 principal-continuity: no value can leave the owner-bound D).
static inline bool IsMofNColdCoinstake(const CTransaction& tx, bool fValidatedCoinstake)
{
    return fValidatedCoinstake
        && tx.nVersion == SHIELDED_TX_VERSION_NULLSTAKE_COLD
        && tx.nullstakeProofV3.nThresholdM > 0;
}

// B2-e: the 2-generator value commitment for a shielded OUTPUT in the binding signature / value balance:
//   - a 2006 M-of-N mint output      -> its fresh Vv (INV-1);
//   - a 2005 M-of-N coinstake re-mint -> cv_plain_out = cv3 - D*J (3c.2: forces every re-minted output
//       under the owner-bound D; a wrong D leaves a J residual the range proof rejects, and the J terms
//       cancel the spend-side cv_plain so the homomorphic balance stays exact);
//   - any ordinary output             -> the raw cv.
// NEVER feed a 3-generator cv3 into the binding sig (its delegationHash*J residual breaks conservation).
static bool MofNOutputBindingCommitment(const CTransaction& tx, size_t i, bool fValidatedCoinstake,
                                        CPedersenCommitment& cvOut)
{
    const CShieldedOutputDescription& o = tx.vShieldedOutput[i];
    if (o.IsMofNMint())
    {
        cvOut = o.valueCommitmentVv;
        return true;
    }
    if (IsMofNColdCoinstake(tx, fValidatedCoinstake))
        return NullStakeMofNDeriveValueCommitment(o.cv, tx.nullstakeProofV3.delegationHash, cvOut);
    cvOut = o.cv;
    return true;
}

// B2-e Phase 3c.1: the 2-generator VALUE commitment for a shielded SPEND. For the staked note of an
// M-of-N cold-stake coinstake (vtx[1].vShieldedSpend[0]) it is cv_plain = cv3 - delegationHash*J; for
// every other spend it is the raw cv. The value-based spend checks (range proof, nullifier-binding,
// binding signature) use this; the MEMBERSHIP proofs (FCMP, Lelantus) MUST keep the raw cv3 leaf, and
// the spend-auth sig is cv-independent. The carve-out is gated ONLY by the kernel-validated position
// (fValidatedCoinstake, set only for vtx[1] of a PoS block), the cold-stake version, nThresholdM>0,
// and i==0 -- NEVER by tx shape. cv3 is pinned by the FCMP membership proof, so a wrong delegationHash
// leaves a J residual that every value check over cv_plain rejects (self-enforcing, fail-closed).
static bool MofNSpendValueCommitment(const CTransaction& tx, size_t i, bool fValidatedCoinstake,
                                     CPedersenCommitment& cvValueOut)
{
    cvValueOut = tx.vShieldedSpend[i].cv;
    if (fValidatedCoinstake
        && tx.nVersion == SHIELDED_TX_VERSION_NULLSTAKE_COLD
        && tx.nullstakeProofV3.nThresholdM > 0
        && i == 0)
    {
        return NullStakeMofNDeriveValueCommitment(tx.vShieldedSpend[i].cv,
                                                  tx.nullstakeProofV3.delegationHash, cvValueOut);
    }
    // B2-e Phase 3c.4: an owner reclaim (an ordinary tx, never fValidatedCoinstake) spends the idle cv3
    // note at spend[0] via the SAME cv_plain = cv3 - D*J derivation, using the reclaim's delegationHash.
    // This branch is reachable only once ConnectInputs's reclaim gates (D recompute, rk==owner + the
    // mandatory owner spend-auth sig, and the inactivity timelock) have passed.
    if (tx.nVersion == SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM && i == 0)
    {
        return NullStakeMofNDeriveValueCommitment(tx.vShieldedSpend[i].cv,
                                                  tx.reclaimAuth.delegationHash, cvValueOut);
    }
    return true;
}

// B2-e Phase 3c: validate the M-of-N mint extension on one shielded output (INV-2/5/9/10/11).
// Sets fIsMofN. For an M-of-N output it runs the two value-binding checks (range over Vv + the
// mandatory (G,J) link cv3<->Vv); the caller must NOT also run the normal range/plaintext path on
// such an output (it would run over cv3 and fail). For a normal output it only enforces that no
// M-of-N fields are present. Returns false (with strErr) on any malformed or failed M-of-N output.
static bool CheckMofNMintOutput(const CTransaction& tx, size_t i, bool fHideAmount,
                                int nHeight, bool& fIsMofN, std::string& strErr)
{
    const CShieldedOutputDescription& o = tx.vShieldedOutput[i];
    fIsMofN = false;

    // The M-of-N fields (marker, Vv, link) are serialized ONLY for marker==1 outputs of a MOFN_MINT
    // tx; in every other case they hold construction defaults that never reach the wire, so nMofNType
    // is the only authoritative signal. (A default CPedersenCommitment is a 33-zero point, NOT empty,
    // so an emptiness test on valueCommitmentVv is not a reliable "absent" check.)
    if (tx.nVersion != SHIELDED_TX_VERSION_MOFN_MINT)
    {
        if (o.nMofNType != 0)
        { strErr = "M-of-N marker on a non-mint tx version"; return false; }
        return true;
    }

    if (o.nMofNType == 0)
        return true;   // ordinary output inside a mint tx; carries no wire-level M-of-N data
    if (o.nMofNType != 1) { strErr = "invalid M-of-N output marker"; return false; }   // INV-5

    fIsMofN = true;
    if (nHeight < FORK_HEIGHT_NULLSTAKE_DELEGSET)                                       // INV-9
    { strErr = "M-of-N mint output before DELEGSET fork height"; return false; }
    if (!fHideAmount || o.nPlaintextValue != -1 || !o.vchPlaintextBlind.empty())        // INV-10
    { strErr = "M-of-N mint output must be hidden-amount"; return false; }
    if (o.cv.vchCommitment.size() != 33 || o.valueCommitmentVv.vchCommitment.size() != 33 ||
        o.vchMofNLink.size() != NULLSTAKE_MOFN_MINTLINK_SIZE)                           // INV-5 shape
    { strErr = "M-of-N mint output malformed shape"; return false; }
    if (!VerifyBulletproofRangeProof(o.valueCommitmentVv, o.rangeProof))                // INV-2(a)
    { strErr = "M-of-N mint Vv range proof failed"; return false; }
    if (!VerifyNullStakeMofNMintLink(o.cv, o.valueCommitmentVv, o.vchMofNLink))         // INV-2(b), MANDATORY
    { strErr = "M-of-N mint (G,J) value-binding link failed"; return false; }
    return true;
}

//
// Global state
//

CCriticalSection cs_setpwalletRegistered;
set<CWallet*> setpwalletRegistered;

CCriticalSection cs_main;

CTxMemPool mempool;
//unsigned int nTransactionsUpdated = 0;

map<uint256, CBlockIndex*> mapBlockIndex;
set<pair<COutPoint, unsigned int> > setStakeSeen;

CBigNum bnProofOfWorkLimit(~uint256(0) >> 20);      // "standard" scrypt target limit for proof of work, results with 0,000244140625 proof-of-work difficulty
CBigNum bnProofOfStakeLimit(~uint256(0) >> 20);
CBigNum bnProofOfStakeLimitTestNet(~uint256(0) >> 10); // 1024x easier for testnet
CBigNum bnProofOfWorkLimitTestNet(~uint256(0) >> 16);

/** Fees smaller than this (in innovai) are considered zero fee (for relaying and mining) */
// CFeeRate minRelayTxFee = CFeeRate(SUBCENT);

// Block Variables

unsigned int nTargetSpacing     = 15;               // 15 seconds
unsigned int nStakeMinAge       = 10 * 60 * 60;     // 10 hour min stake age
unsigned int nStakeMaxAge       = -1;               // unlimited (original behavior)
unsigned int nModifierInterval  = 10 * 60;          // time to elapse before new modifier is computed
int64_t nLastCoinStakeSearchTime = GetAdjustedTime();
int nCoinbaseMaturity = 65; //75 on Mainnet I n n o v a
CBlockIndex* pindexGenesisBlock = NULL;
int nRegtestBoundaryBHeight = PRIVACY_VNEXT_HEIGHT_UNSET;
int nRegtestSupplyCapHeight = -1;       // -1: follow the DAG fork like every other network
int64_t nRegtestSupplyCapAmount = 0;    // 0: no override, cap is MAX_MONEY
int nRegtestIV5FeeNoteHeight = PRIVACY_VNEXT_HEIGHT_UNSET;
int nRegtestIV5NoteVoteHeight = PRIVACY_VNEXT_HEIGHT_UNSET;
int nRegtestIDNSResetHeight = 0;
// Regtest millisecond-timestamp gate (-regtestmstimestamp). Defaults to the
// POEM rung so the regtest ladder exercises the rule without an override.
int nRegtestMsTimestampHeight = 9;
int nRegtestCNPaymentsHeight = 0;
int nRegtestColdStakingHeight = 0;
bool fRegtestShieldedVNextRehearsal = false;
bool fRegtestHoldPrivacyVNextLeafIndex = false;
int nBestHeight = -1;
bool CollateralNReorgBlock = true;
uint256 nBestChainTrust = 0;
uint256 nBestInvalidTrust = 0;

uint256 hashBestChain = 0;
CBlockIndex* pindexBest = NULL;
int64_t nTimeBestReceived = 0;

bool fImporting = false;
bool fReindex = false;
bool fFullReplayVerify = false;
bool fAddrIndex = false;

bool fSPVMode = false;
bool fSPVHeadersOnly = false;
int nSPVStartHeight = 0;

bool fHybridSPV = false;
bool fSPVStakingEnabled = false;
StakingMode nStakingMode = STAKE_TRANSPARENT;
CCriticalSection cs_stakingMode;

int nLastFinalizedHeight = 0;
uint256 hashLastFinalized = 0;
CCriticalSection cs_finality;

CMedianFilter<int> cPeerBlockCounts(5, 0); // Amount of blocks that other nodes claim to have

std::map<int64_t, CAnonOutputCount> mapAnonOutputStats;
//map<int64_t, CAnonOutputCount> mapAnonOutputStats; // display only, not 100% accurate, height could become inaccurate due to undos
map<uint256, CBlock*> mapOrphanBlocks;
multimap<uint256, CBlock*> mapOrphanBlocksByPrev;
map<uint256, NodeId> mapOrphanBlocksByNode;
map<NodeId, int> mapOrphanCountByNode;
static const int MAX_ORPHAN_BLOCKS_PER_PEER = 750;
set<pair<COutPoint, unsigned int> > setStakeSeenOrphan;

void EraseStakeSeenOrphanIfUnreferenced(const std::pair<COutPoint, unsigned int>& stake)
{
    if (!setStakeSeenOrphan.count(stake))
        return;
    for (std::map<uint256, CBlock*>::const_iterator mi = mapOrphanBlocks.begin();
         mi != mapOrphanBlocks.end(); ++mi)
    {
        const CBlock* orphan = mi->second;
        if (!orphan->IsProofOfStake() || orphan->vtx.size() < 2)
            continue;
        // The stake's second element is the coinstake nTime, which is readable
        // without work. GetProofOfStake() hashes the whole coinstake for the
        // NullStake versions, so only pay that once the cheap half matches.
        if (orphan->vtx[1].nTime != stake.second)
            continue;
        if (orphan->GetProofOfStake() == stake)
            return;
    }
    setStakeSeenOrphan.erase(stake);
}


map<uint256, CTransaction> mapOrphanTransactions;
map<uint256, set<uint256> > mapOrphanTransactionsByPrev;

// Constant stuff for coinbase transactions we create:
CScript COINBASE_FLAGS;

const string strMessageMagic = "Innova Signed Message:\n";

// Settings
int64_t nTransactionFee = MIN_TX_FEE;
int64_t nReserveBalance = 0;
int64_t nMinimumInputValue = 0;

unsigned int nCoinCacheSize = 5000;

extern enum Checkpoints::CPMode CheckpointsMode;

std::set<uint256> setValidatedTx;

CHooks* hooks; // This adds Innova Name DB hooks which allow splicing of code inside standard Innova functions.

//////////////////////////////////////////////////////////////////////////////
//
// dispatching functions
//

// These functions dispatch to one or all registered wallets

namespace {
struct CMainSignals {
    // Notifies listeners of updated transaction data (passing hash, transaction, and optionally the block it is found in.
    boost::signals2::signal<void (const CTransaction &, const CBlock *, bool)> SyncTransaction;
    // Notifies listeners of an erased transaction (currently disabled, requires transaction replacement).
    boost::signals2::signal<void (const uint256 &)> EraseTransaction;
    // Notifies listeners of an updated transaction without new data (for now: a coinbase potentially becoming visible).
    boost::signals2::signal<void (const uint256 &)> UpdatedTransaction;
    // Notifies listeners about an inventory item being seen on the network.
    boost::signals2::signal<void (const uint256 &)> Inventory;
    // Tells listeners to broadcast their data.
    boost::signals2::signal<void (bool)> Broadcast;

} g_signals;
}

void RegisterWallet(CWallet* pwalletIn) {
    g_signals.EraseTransaction.connect(boost::bind(&CWallet::EraseFromWallet, pwalletIn, _1));
    g_signals.UpdatedTransaction.connect(boost::bind(&CWallet::UpdatedTransaction, pwalletIn, _1));
    g_signals.Inventory.connect(boost::bind(&CWallet::Inventory, pwalletIn, _1));
    g_signals.Broadcast.connect(boost::bind(&CWallet::ResendWalletTransactions, pwalletIn, _1));
    {
            LOCK(cs_setpwalletRegistered);
            setpwalletRegistered.insert(pwalletIn);
    }
}

void UnregisterWallet(CWallet* pwalletIn) {
    g_signals.Broadcast.disconnect(boost::bind(&CWallet::ResendWalletTransactions, pwalletIn, _1));
    g_signals.Inventory.disconnect(boost::bind(&CWallet::Inventory, pwalletIn, _1));
    g_signals.UpdatedTransaction.disconnect(boost::bind(&CWallet::UpdatedTransaction, pwalletIn, _1));
    g_signals.EraseTransaction.disconnect(boost::bind(&CWallet::EraseFromWallet, pwalletIn, _1));
    {
            LOCK(cs_setpwalletRegistered);
            setpwalletRegistered.erase(pwalletIn);
    }
}


// check whether the passed transaction is from us
bool static IsFromMe(CTransaction& tx)
{
    for (CWallet* pwallet : setpwalletRegistered)
        if (pwallet->IsFromMe(tx))
            return true;
    return false;
}


// get the wallet transaction with the given hash (if it exists)
bool static GetTransaction(const uint256& hashTx, CWalletTx& wtx)
{
    for (CWallet* pwallet : setpwalletRegistered)
        if (pwallet->GetTransaction(hashTx,wtx))
            return true;
    return false;
}

// erases transaction with the given hash from all wallets
void static EraseFromWallets(uint256 hash)
{
    for (CWallet* pwallet : setpwalletRegistered)
        pwallet->EraseFromWallet(hash);
}

// Make sure all wallets know about the given transaction.  The checked form is
// used after a durable best-chain commit, where silently losing a wallet write
// would make the wallet locator lie about how far recovery has progressed.
static bool SyncWithWalletsChecked(const CTransaction& tx, const CBlock* pblock,
                                   bool fUpdate, bool fConnect,
                                   std::string& strErrorOut,
                                   const std::set<uint256>* pDAGSkippedTxs = NULL)
{
    strErrorOut.clear();
    if (!fConnect)
    {
        // ppcoin: wallets need to refund inputs when disconnecting coinstake
        if (tx.IsCoinStake())
        {
            for (CWallet* pwallet : setpwalletRegistered)
            {
                if (pwallet->IsFromMe(tx))
                {
                    std::string strWalletError;
                    if (!pwallet->DisableTransactionChecked(tx, strWalletError))
                    {
                        strErrorOut = strWalletError;
                        return false;
                    }
                }
            };
        };

        if (tx.nVersion == ANON_TXN_VERSION)
        {
            for (CWallet* pwallet : setpwalletRegistered)
            {
                if (!pwallet->UndoAnonTransaction(tx))
                {
                    strErrorOut = strprintf("failed to undo anonymous wallet transaction %s",
                                            tx.GetHash().ToString().substr(0, 20).c_str());
                    return false;
                }
            }
        };
        return true;
    };

    //uint256 hash = tx.GetHash();
    for (CWallet* pwallet : setpwalletRegistered)
    {
        std::string strWalletError;
        pwallet->AddToWalletIfInvolvingMe(tx, pblock, fUpdate, false,
                                          &strWalletError,
                                          pDAGSkippedTxs);
        if (!strWalletError.empty())
        {
            strErrorOut = strWalletError;
            return false;
        }
    }
    return true;
}

void SyncWithWallets(const CTransaction& tx, const CBlock* pblock,
                     bool fUpdate, bool fConnect)
{
    std::string strError;
    if (!SyncWithWalletsChecked(tx, pblock, fUpdate, fConnect, strError))
        error("SyncWithWallets() : %s", strError.c_str());
}

// notify wallets about a new best chain
static bool SetWalletBestChainChecked(const CBlockLocator& loc,
                                      std::string& strErrorOut)
{
    strErrorOut.clear();
    for (CWallet* pwallet : setpwalletRegistered)
    {
        if (!pwallet->SetBestChainChecked(loc))
        {
            strErrorOut = "failed to persist a wallet best-block locator";
            return false;
        }
    }
    return true;
}

// Deferred wallet best-block locator. Safe because the locator only lags the durable
// chain state and startup rescan catches it up; in-flight shielded state is covered by
// the LevelDB recovery outbox.
static const int WALLET_LOCATOR_BATCH_BLOCKS_DEFAULT = 1000;
static const int64_t WALLET_LOCATOR_BATCH_MAX_SECONDS = 30;

static bool g_fPendingWalletLocator = false;
static CBlockLocator g_pendingWalletLocator;
static int g_nPendingWalletLocatorBlocks = 0;
static int64_t g_nPendingWalletLocatorStarted = 0;

static int WalletLocatorBatchBlocks()
{
    static int nBatch = -1;
    if (nBatch < 0)
    {
        nBatch = (int)GetArg("-walletlocatorbatch",
                             WALLET_LOCATOR_BATCH_BLOCKS_DEFAULT);
        if (nBatch < 0)
            nBatch = 0;
    }
    return nBatch;
}

bool HasPendingWalletLocator()
{
    return g_fPendingWalletLocator;
}

int PendingWalletLocatorBlocks()
{
    return g_nPendingWalletLocatorBlocks;
}

// Same rule as the name-index cursor: flush on block count or on age, so a tip
// follower stays near-current without a separate steady-state path.
static bool WalletLocatorBatchDue()
{
    if (!g_fPendingWalletLocator)
        return false;
    if (WalletLocatorBatchBlocks() <= 0)
        return true;
    if (g_nPendingWalletLocatorBlocks >= WalletLocatorBatchBlocks())
        return true;
    return g_nPendingWalletLocatorStarted != 0 &&
           GetTime() - g_nPendingWalletLocatorStarted >=
               WALLET_LOCATOR_BATCH_MAX_SECONDS;
}

static void DeferWalletBestChain(const CBlockLocator& loc)
{
    g_pendingWalletLocator = loc;
    if (!g_fPendingWalletLocator)
    {
        g_fPendingWalletLocator = true;
        g_nPendingWalletLocatorBlocks = 0;
        g_nPendingWalletLocatorStarted = GetTime();
    }
    g_nPendingWalletLocatorBlocks++;
}

bool FlushWalletBestChainLocator(std::string& strErrorOut)
{
    strErrorOut.clear();
    if (!g_fPendingWalletLocator)
        return true;
    if (!SetWalletBestChainChecked(g_pendingWalletLocator, strErrorOut))
        return false;
    g_fPendingWalletLocator = false;
    g_nPendingWalletLocatorBlocks = 0;
    g_nPendingWalletLocatorStarted = 0;
    return true;
}

// notify wallets about an updated transaction
void static UpdatedTransaction(const uint256& hashTx)
{
    for (CWallet* pwallet : setpwalletRegistered)
        pwallet->UpdatedTransaction(hashTx);
}
/*
// dump all wallets
void static PrintWallets(const CBlock& block)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->PrintWallet(block);
} */

// notify wallets about an incoming inventory (for request counts)
void static Inventory(const uint256& hash)
{
    for (CWallet* pwallet : setpwalletRegistered)
        pwallet->Inventory(hash);
}

// ask wallets to resend their transactions
void ResendWalletTransactions(bool fForce)
{
    for (CWallet* pwallet : setpwalletRegistered)
        pwallet->ResendWalletTransactions(fForce);
}

bool Finalise()
{
    printf("Finalise()");

    // Join the wallet flusher before taking cs_main and before its chain/DB state is destroyed;
    // joining under cs_main could deadlock a flusher inside IsInitialBlockDownload().
    StopWalletDBFlushThread();

    LOCK(cs_main);

    SecureMsgShutdown();
    //nTransactionsUpdated++;
    mempool.AddTransactionsUpdated(1);

    // Persist the deferred locator while the wallet is still registered. A miss
    // here only costs a catch-up rescan on the next start, so it is not fatal.
    std::string strLocatorError;
    if (!FlushWalletBestChainLocator(strLocatorError))
        printf("Finalise() : could not persist the deferred wallet best-block "
               "locator: %s; the next start rescans from the last durable one\n",
               strLocatorError.c_str());

    bitdb.Flush(false);
    StopNode();
    bitdb.Flush(true);
    fs::remove(GetPidFile());
    UnregisterWallet(pwalletMain);
    delete pwalletMain;

    finaliseRingSigs();

    CTxDB().Close();


    return true;
}

bool AbortNode(const std::string &strMessage, const std::string &userMessage) {
    strMiscWarning = strMessage;
    printf("*** %s\n", strMessage.c_str());
	/*
    uiInterface.ThreadSafeMessageBox(
        userMessage.empty() ? _("Error: A fatal internal error occured, see debug.log for details") : userMessage,
        "", CClientUIInterface::MSG_ERROR);
		*/
    StartShutdown();
    return false;
}

bool GetNodeStateStats(NodeId nodeid, CNodeStateStats &stats)
{
    // TODO:
    return false;
}

//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
//

bool AddOrphanTx(const CTransaction& tx)
{
    uint256 hash = tx.GetHash();
    if (mapOrphanTransactions.count(hash))
        return false;

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 10,000 orphans, each of which is at most 5,000 bytes big is
    // at most 500 megabytes of orphans:

    size_t nSize = tx.GetSerializeSize(SER_NETWORK, CTransaction::CURRENT_VERSION);

    if (nSize > 5000)
    {
        printf("ignoring large orphan tx (size: %" PRIszu", hash: %s)\n", nSize, hash.ToString().substr(0,10).c_str());
        return false;
    };

    mapOrphanTransactions[hash] = tx;
    for (const CTxIn& txin : tx.vin)
        mapOrphanTransactionsByPrev[txin.prevout.hash].insert(hash);

    printf("stored orphan tx %s (mapsz %" PRIszu")\n", hash.ToString().substr(0,10).c_str(),
        mapOrphanTransactions.size());
    return true;
}

void static EraseOrphanTx(uint256 hash)
{
    if (!mapOrphanTransactions.count(hash))
        return;
    const CTransaction& tx = mapOrphanTransactions[hash];
    for (const CTxIn& txin : tx.vin)
    {
        mapOrphanTransactionsByPrev[txin.prevout.hash].erase(hash);
        if (mapOrphanTransactionsByPrev[txin.prevout.hash].empty())
            mapOrphanTransactionsByPrev.erase(txin.prevout.hash);
    }
    mapOrphanTransactions.erase(hash);
}

unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans)
{
    unsigned int nEvicted = 0;
    while (mapOrphanTransactions.size() > nMaxOrphans)
    {
        // Evict a random orphan:
        uint256 randomhash = GetRandHash();
        map<uint256, CTransaction>::iterator it = mapOrphanTransactions.lower_bound(randomhash);
        if (it == mapOrphanTransactions.end())
            it = mapOrphanTransactions.begin();
        EraseOrphanTx(it->first);
        ++nEvicted;
    }
    return nEvicted;
}







//////////////////////////////////////////////////////////////////////////////
//
// CTransaction and CTxIndex
//

// CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nTime(GetAdjustedTime()), nLockTime(0) {}
// CMutableTransaction::CMutableTransaction(const CTransaction& tx) : nVersion(tx.nVersion), nTime(tx.nTime), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime) {}

// uint256 CMutableTransaction::GetHash() const
// {
//     return SerializeHash(*this);
// }

// void CTransaction::UpdateHash() const
// {
//     *const_cast<uint256*>(&hash) = SerializeHash(*this);
// }

// CTransaction::CTransaction() : hash(0), nVersion(CTransaction::CURRENT_VERSION), nTime(GetAdjustedTime()), vin(), vout(), nLockTime(0) { }

// CTransaction::CTransaction(const CMutableTransaction &tx) : nVersion(tx.nVersion), nTime(tx.nTime), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime) {
//     UpdateHash();
// }



bool CTransaction::ReadFromDisk(CTxDB& txdb, COutPoint prevout, CTxIndex& txindexRet)
{
    SetNull();
    if (!txdb.ReadTxIndex(prevout.hash, txindexRet))
        return false;
    if (!ReadFromDisk(txindexRet.pos))
        return false;
    if (prevout.n >= vout.size())
    {
        SetNull();
        return false;
    }
    return true;
}

bool CTransaction::ReadFromDisk(CTxDB& txdb, COutPoint prevout)
{
    CTxIndex txindex;
    return ReadFromDisk(txdb, prevout, txindex);
}

bool CTransaction::ReadFromDisk(CTxDB& txdb, const uint256& hashTx, CTxIndex& txindexRet)
{
    SetNull();
    if (!txdb.ReadTxIndex(hashTx, txindexRet))
        return false;
    return ReadFromDisk(txindexRet.pos);
}

bool CTransaction::ReadFromDisk(COutPoint prevout)
{
    CTxDB txdb("r");
    CTxIndex txindex;
    return ReadFromDisk(txdb, prevout, txindex);
}

// bool CTransaction::IsStandard() const
// {
//     if (nVersion > CTransaction::CURRENT_VERSION)
//         return false;

//     BOOST_FOREACH(const CTxIn& txin, vin)
//     {
//         // Biggest 'standard' txin is a 3-signature 3-of-3 CHECKMULTISIG
//         // pay-to-script-hash, which is 3 ~80-byte signatures, 3
//         // ~65-byte public keys, plus a few script ops.
//         if (txin.scriptSig.size() > 500)
//             return false;
//         if (!txin.scriptSig.IsPushOnly())
//             return false;
//         if (fEnforceCanonical && !txin.scriptSig.HasCanonicalPushes()) {
//             return false;
//         }
//     }

//     unsigned int nDataOut = 0;
//     unsigned int nTxnOut = 0;

//     txnouttype whichType;
//     BOOST_FOREACH(const CTxOut& txout, vout) {
//         if (!::IsStandard(txout.scriptPubKey, whichType))
//             return false;
//         if (whichType == TX_NULL_DATA)
//         {
//             nDataOut++;
//         } else
//         {
//             if (txout.nValue == 0)
//                 return false;
//             nTxnOut++;
//         }
//         if (fEnforceCanonical && !txout.scriptPubKey.HasCanonicalPushes()) {
//             return false;
//         }
//     }

//     // only one OP_RETURN txout per txn out is permitted
//     if (nDataOut > nTxnOut) {
//         return false;
//     }

//     return true;
// }

bool IsStandardTx(const CTransaction& tx, string& reason)
{
    // IsShielded() is false once an IV5 payload is present, so an IV5 transaction has to be
    // admitted on its own terms or every one of them is nonstandard and never relays. Only
    // mainnet consults this, which is why the regtest and testnet paths never showed it.
    if (tx.nVersion > CTransaction::CURRENT_VERSION && tx.nVersion != ANON_TXN_VERSION &&
        tx.nVersion != NAMECOIN_TX_VERSION && !tx.IsShielded() && !tx.IsPrivacyVNext()) { //WIP
        reason = "version";
        return false;
    }

    // Treat non-final transactions as non-standard to prevent a specific type
    // of double-spend attack, as well as DoS attacks. (if the transaction
    // can't be mined, the attacker isn't expending resources broadcasting it)
    // Basically we don't want to propagate transactions that can't be included in
    // the next block.
    //
    // However, IsFinalTx() is confusing... Without arguments, it uses
    // chainActive.Height() to evaluate nLockTime; when a block is accepted, chainActive.Height()
    // is set to the value of nHeight in the block. However, when IsFinalTx()
    // is called within CBlock::AcceptBlock(), the height of the block *being*
    // evaluated is what is used. Thus if we want to know if a transaction can
    // be part of the *next* block, we need to call IsFinalTx() with one more
    // than chainActive.Height().
    //
    // Timestamps on the other hand don't get any special treatment, because we
    // can't know what timestamp the next block will have, and there aren't
    // timestamp applications where it matters.
    //if (!IsFinalTx(tx, nBestHeight + 1)) {
	  if (!tx.IsFinal(nBestHeight + 1)) {
        reason = "non-final";
        return false;
    }
    // nTime has different purpose from nLockTime but can be used in similar attacks
    if (tx.nTime > FutureDrift(GetAdjustedTime())) {
        reason = "time-too-new";
        return false;
    }

    // Extremely large transactions with lots of inputs can cost the network
    // almost as much to process as they cost the sender in fees, because
    // computing signature hashes is O(ninputs*txsize). Limiting transactions
    // to MAX_STANDARD_TX_SIZE mitigates CPU exhaustion attacks.
    unsigned int sz = tx.GetSerializeSize(SER_NETWORK, CTransaction::CURRENT_VERSION);
    if (sz >= MAX_STANDARD_TX_SIZE) {
        reason = "tx-size";
        return false;
    }

    for (const CTxIn& txin : tx.vin)
    {
        if (txin.IsAnonInput())
        {
            int nRingSize = txin.ExtractRingSize();

            if (tx.nVersion != ANON_TXN_VERSION
                || nRingSize < (int)MIN_RING_SIZE
                || nRingSize > (int)MAX_RING_SIZE
                || txin.scriptSig.size() > sizeof(COutPoint) + 2 + (33 + 32 + 32) * nRingSize)
            {
                printf("IsStandard() anon txin failed.\n");
                return false;
            };
            continue;
        };
        // Biggest 'standard' txin is a 15-of-15 P2SH multisig with compressed
        // keys. (remember the 520 byte limit on redeemScript size) That works
        // out to a (15*(33+1))+3=513 byte redeemScript, 513+1+15*(73+1)+3=1627
        // bytes of scriptSig, which we round off to 1650 bytes for some minor
        // future-proofing. That's also enough to spend a 20-of-20
        // CHECKMULTISIG scriptPubKey, though such a scriptPubKey is not
        // considered standard)
        if (txin.scriptSig.size() > 1650) {
            reason = "scriptsig-size";
            return false;
        }
        if (!txin.scriptSig.IsPushOnly()) {
            reason = "scriptsig-not-pushonly";
            return false;
        }
        if (!txin.scriptSig.HasCanonicalPushes()) {
            reason = "scriptsig-non-canonical-push";
            return false;
        }
    }

    unsigned int nDataOut = 0;
    unsigned int nTxnOut = 0;

    txnouttype whichType;
    for (const CTxOut& txout : tx.vout) {
        if (txout.IsAnonOutput())
        {
            if (tx.nVersion != ANON_TXN_VERSION
                || txout.nValue < 1
                || txout.scriptPubKey.size() > MIN_ANON_OUT_SIZE + MAX_ANON_NARRATION_SIZE)
            {
                printf("IsStandard() anon txout failed.\n");
                return false;
            }
            //nTxnOut++; anon outputs don't count (narrations are embedded in scriptPubKey)
            continue;
        };

         if (!::IsStandard(txout.scriptPubKey, whichType)) {
             reason = "scriptpubkey";
             return false;
         }
         if (whichType == TX_NULL_DATA)
         {
             nDataOut++;
         } else
         {
             if (txout.nValue == 0)
                 return false;
             nTxnOut++;
         }
         if (fEnforceCanonical && !txout.scriptPubKey.HasCanonicalPushes()) {
             reason = "scriptpubkey-non-canonical-push";
             return false;
         }
    }

    // only one OP_RETURN txout per txn out is permitted
    // An IV5 vout may be a single data stamp; the payload's transparent binding covers it.
    const bool fPrivacyVNextStamp = tx.IsPrivacyVNext() && nDataOut <= 1;
    if (nDataOut > nTxnOut && !fPrivacyVNextStamp) {
        reason = "multi-op-return";
        return false;
    }

    return true;
}

bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    AssertLockHeld(cs_main);
    // Time based nLockTime implemented in 0.1.6
    if (tx.nLockTime == 0)
        return true;
    if (nBlockHeight == 0)
        nBlockHeight = nBestHeight;
    if (nBlockTime == 0)
        nBlockTime = GetAdjustedTime();
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;
    for (const CTxIn& txin : tx.vin)
        if (!txin.IsFinal())
            return false;
    return true;
}

//
// Check transaction inputs, and make sure any
// pay-to-script-hash transactions are evaluating IsStandard scripts
//
// Why bother? To avoid denial-of-service attacks; an attacker
// can submit a standard HASH... OP_EQUAL transaction,
// which will get accepted into blocks. The redemption
// script can be anything; an attacker could use a very
// expensive-to-check-upon-redemption script like:
//   DUP CHECKSIG DROP ... repeated 100 times... OP_1
//
bool AreInputsStandard(const CTransaction& tx, const MapPrevTx& mapInputs)
{
    if (tx.IsCoinBase())
        return true; // Coinbases don't use vin normally

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        if (tx.nVersion == ANON_TXN_VERSION
            && tx.vin[i].IsAnonInput())
            continue;

        const CTxOut& prev = tx.GetOutputFor(tx.vin[i], mapInputs);

        vector<vector<unsigned char> > vSolutions;
        txnouttype whichType;
        // get the scriptPubKey corresponding to this input:
        const CScript& prevScript = prev.scriptPubKey;
        if (!Solver(prevScript, whichType, vSolutions))
            return false;
        int nArgsExpected = ScriptSigArgsExpected(whichType, vSolutions);
        if (nArgsExpected < 0)
            return false;

        // Transactions with extra stuff in their scriptSigs are
        // non-standard. Note that this EvalScript() call will
        // be quick, because if there are any operations
        // beside "push data" in the scriptSig
        // IsStandard() will have already returned false
        // and this method isn't called.
        vector<vector<unsigned char> > stack;
        if (!EvalScript(stack, tx.vin[i].scriptSig, tx, i, SCRIPT_VERIFY_NONE, 0))
            return false;

        if (whichType == TX_SCRIPTHASH)
        {
            if (stack.empty())
                return false;
            CScript subscript(stack.back().begin(), stack.back().end());
            vector<vector<unsigned char> > vSolutions2;
            txnouttype whichType2;
            if (Solver(subscript, whichType2, vSolutions2))
            {
                int tmpExpected = ScriptSigArgsExpected(whichType2, vSolutions2);
                if (tmpExpected < 0)
                    return false;
                nArgsExpected += tmpExpected;
            }
            else
            {
                // Any other Script with less than 15 sigops OK:
                unsigned int sigops = subscript.GetSigOpCount(true);
                if (sigops > MAX_P2SH_SIGOPS)
                    return false;
                // ... extra data left on the stack after execution is OK, too. Continue: returning
                // true would let one unknown redeem script skip policy checks for later inputs.
                continue;
            }
        }

        if (stack.size() != (unsigned int)nArgsExpected)
            return false;
    }

    return true;
}

bool CTransaction::HasStealthOutput() const
{
    // -- todo: scan without using GetOp

    std::vector<uint8_t> vchEphemPK;
    opcodetype opCode;

    for (vector<CTxOut>::const_iterator it = vout.begin(); it != vout.end(); ++it)
    {
        if (nVersion == ANON_TXN_VERSION
            && it->IsAnonOutput())
            continue;

        CScript::const_iterator itScript = it->scriptPubKey.begin();

        if (!it->scriptPubKey.GetOp(itScript, opCode, vchEphemPK)
            || opCode != OP_RETURN
            || !it->scriptPubKey.GetOp(itScript, opCode, vchEphemPK) // rule out np narrations
            || vchEphemPK.size() != ec_compressed_size)
            continue;

        return true;
    };

    return false;
};

unsigned int CTransaction::GetLegacySigOpCount() const
{
    unsigned int nSigOps = 0;
    for (const CTxIn& txin : vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    };
    for (const CTxOut& txout : vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    };
    return nSigOps;
}


int CMerkleTx::SetMerkleBranch(const CBlock* pblock)
{
    AssertLockHeld(cs_main);

    CBlock blockTmp;
    if (pblock == NULL)
    {
        // Load the block this tx is in
        CTxIndex txindex;
        if (!CTxDB("r").ReadTxIndex(GetHash(), txindex))
            return 0;
        if (!blockTmp.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos))
            return 0;
        pblock = &blockTmp;
    }

    // Update the tx's hashBlock
    hashBlock = pblock->GetHash();

    // Locate the transaction
    for (nIndex = 0; nIndex < (int)pblock->vtx.size(); nIndex++)
        if (pblock->vtx[nIndex] == *(CTransaction*)this)
            break;
    if (nIndex == (int)pblock->vtx.size())
    {
        vMerkleBranch.clear();
        nIndex = -1;
        printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
        return 0;
    }

    // Fill in merkle branch
    vMerkleBranch = pblock->GetMerkleBranch(nIndex);

    // Is the tx in a block that's in the main chain
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    if (!pindexBest)
        return 0;

    return pindexBest->nHeight - pindex->nHeight + 1;
}







// ---------------------------------------------------------------------------
// Adaptive Block Size (Monero-inspired, tuned for 1s DAG blocks)
// ---------------------------------------------------------------------------

unsigned int GetAdaptiveBlockSizeLimit(const CBlockIndex* pindex)
{
    if (!pindex)
        return MAX_BLOCK_SIZE_LEGACY;

    // Pre-DAG: fixed 1 MB
    if (pindex->nHeight < FORK_HEIGHT_DAG)
        return MAX_BLOCK_SIZE_LEGACY;

    // Walk back ADAPTIVE_MEDIAN_WINDOW blocks and collect sizes
    std::vector<unsigned int> vSizes;
    vSizes.reserve(ADAPTIVE_MEDIAN_WINDOW);
    const CBlockIndex* pWalk = pindex;

    for (unsigned int i = 0; i < ADAPTIVE_MEDIAN_WINDOW && pWalk; i++)
    {
        vSizes.push_back(pWalk->nSize > 0 ? pWalk->nSize : 1);
        pWalk = pWalk->pprev;
    }

    if (vSizes.empty())
        return ADAPTIVE_BLOCK_FLOOR;

    // Short-term median
    std::sort(vSizes.begin(), vSizes.end());
    unsigned int nShortMedian = vSizes[vSizes.size() / 2];

    // Apply floor: penalty-free zone
    if (nShortMedian < ADAPTIVE_BLOCK_FLOOR)
        nShortMedian = ADAPTIVE_BLOCK_FLOOR;

    // Long-term median anchor (independent window, starts after short-term window)
    std::vector<unsigned int> vLongSizes;
    // pWalk is already at the end of the short-term window — continue from there
    for (unsigned int i = 0; i < ADAPTIVE_LONG_MEDIAN_WINDOW && pWalk; i++)
    {
        vLongSizes.push_back(pWalk->nSize > 0 ? pWalk->nSize : 1);
        pWalk = pWalk->pprev;
    }

    if (!vLongSizes.empty())
    {
        std::sort(vLongSizes.begin(), vLongSizes.end());
        unsigned int nLongMedian = vLongSizes[vLongSizes.size() / 2];
        if (nLongMedian < ADAPTIVE_BLOCK_FLOOR)
            nLongMedian = ADAPTIVE_BLOCK_FLOOR;

        // Cap short-term median at ADAPTIVE_LONG_MEDIAN_CAP * long-term median (overflow-safe)
        uint64_t nCap64 = (uint64_t)nLongMedian * ADAPTIVE_LONG_MEDIAN_CAP;
        unsigned int nCap = (nCap64 > ADAPTIVE_BLOCK_CEILING) ? ADAPTIVE_BLOCK_CEILING : (unsigned int)nCap64;
        if (nShortMedian > nCap)
            nShortMedian = nCap;
    }

    // Effective limit = 2x median (max allowed size, matches Monero) — overflow-safe
    uint64_t nEffective64 = (uint64_t)nShortMedian * 2;
    unsigned int nEffectiveLimit = (nEffective64 > ADAPTIVE_BLOCK_CEILING) ? ADAPTIVE_BLOCK_CEILING : (unsigned int)nEffective64;

    // Clamp to ceiling
    if (nEffectiveLimit > ADAPTIVE_BLOCK_CEILING)
        nEffectiveLimit = ADAPTIVE_BLOCK_CEILING;

    return nEffectiveLimit;
}

int GetBlockIndexSizeBackfillDepth()
{
    // Deepest index a window reaches: one short plus one long window below FORK_HEIGHT_DAG,
    // plus one spare short window for growth.
    return (int)(ADAPTIVE_MEDIAN_WINDOW * 2 +
                 ADAPTIVE_LONG_MEDIAN_WINDOW + 1);
}

int GetBlockIndexSizeBackfillFloor()
{
    const int64_t nFloor = (int64_t)FORK_HEIGHT_DAG - GetBlockIndexSizeBackfillDepth();
    return nFloor < 0 ? 0 : (int)nFloor;
}

bool BlockIndexNeedsSizeRestore(const CBlockIndex* pindex, int nFloor)
{
    return pindex && pindex->nSize == 0 && pindex->nHeight >= nFloor;
}

// Re-measure one block against the size its prefix claims (SER_DISK vs the SER_NETWORK
// nSize a fresh sync assigns); a mismatch would give a restarted node a different size.
static bool VerifyStoredBlockSize(const CBlockIndex* pindex, unsigned int nStoredSize,
                                  std::string& strError)
{
    CAutoFile filein = CAutoFile(OpenBlockFile(pindex->nFile, pindex->nBlockPos, "rb"),
                                 SER_DISK, CLIENT_VERSION);
    if (!filein)
    {
        strError = strprintf("block %d: block data unreadable at file %u offset %u",
                             pindex->nHeight, pindex->nFile, pindex->nBlockPos);
        return false;
    }
    CBlock block;
    try
    {
        filein >> block;
    }
    catch (const std::exception&)
    {
        strError = strprintf("block %d: block data would not deserialize", pindex->nHeight);
        return false;
    }
    const unsigned int nMeasured = ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION);
    if (nMeasured != nStoredSize)
    {
        strError = strprintf("block %d: stored size %u but the block measures %u",
                             pindex->nHeight, nStoredSize, nMeasured);
        return false;
    }
    return true;
}

bool BackfillBlockIndexSizes(const std::vector<CBlockIndex*>& vNeedSize,
                             int& nRestoredOut, std::string& strError)
{
    nRestoredOut = 0;
    strError.clear();

    // Group by file/offset: the reads are sequential within a block file.
    std::vector<std::pair<std::pair<unsigned int, unsigned int>, CBlockIndex*> > vOrdered;
    vOrdered.reserve(vNeedSize.size());
    for (std::vector<CBlockIndex*>::const_iterator it = vNeedSize.begin();
         it != vNeedSize.end(); ++it)
    {
        CBlockIndex* pindex = *it;
        if (!pindex || pindex->nSize > 0)
            continue;
        // Header-only entries carry no block payload to measure.
        if (pindex->nFile == 0 || pindex->nBlockPos < 8)
            continue;
        vOrdered.push_back(std::make_pair(
            std::make_pair(pindex->nFile, pindex->nBlockPos), pindex));
    }
    std::sort(vOrdered.begin(), vOrdered.end());

    // Each verification reads a whole block, so spread a bounded number of them
    // across the set instead of re-measuring every entry.
    const size_t nStride = vOrdered.empty() ? 1 :
        (vOrdered.size() + BLOCKINDEX_SIZE_RESTORE_VERIFY_SAMPLES - 1) /
        BLOCKINDEX_SIZE_RESTORE_VERIFY_SAMPLES;

    unsigned int nOpenFile = 0;
    FILE* file = NULL;
    for (size_t i = 0; i < vOrdered.size(); i++)
    {
        CBlockIndex* pindex = vOrdered[i].second;
        if (file && nOpenFile != pindex->nFile)
        {
            fclose(file);
            file = NULL;
        }
        if (!file)
        {
            file = OpenBlockFile(pindex->nFile, 0, "rb");
            if (!file)
            {
                strError = strprintf("block file %u could not be opened", pindex->nFile);
                return false;
            }
            nOpenFile = pindex->nFile;
        }

        // WriteToDisk lays down the network magic and the serialized size
        // immediately before the block, so both sit at nBlockPos - 8.
        unsigned char pchHeader[8];
        if (fseek(file, (long)pindex->nBlockPos - 8, SEEK_SET) != 0 ||
            fread(pchHeader, 1, sizeof(pchHeader), file) != sizeof(pchHeader))
        {
            strError = strprintf("block %d: size prefix unreadable at file %u offset %u",
                                 pindex->nHeight, pindex->nFile, pindex->nBlockPos);
            fclose(file);
            return false;
        }
        if (memcmp(pchHeader, pchMessageStart, sizeof(pchMessageStart)) != 0)
        {
            strError = strprintf("block %d: bad network magic ahead of block data", pindex->nHeight);
            fclose(file);
            return false;
        }
        unsigned int nStoredSize = 0;
        memcpy(&nStoredSize, pchHeader + 4, 4);
        if (nStoredSize == 0 || nStoredSize > ADAPTIVE_BLOCK_CEILING)
        {
            strError = strprintf("block %d: stored size %u out of range", pindex->nHeight, nStoredSize);
            fclose(file);
            return false;
        }
        if ((i % nStride == 0 || i + 1 == vOrdered.size()) &&
            !VerifyStoredBlockSize(pindex, nStoredSize, strError))
        {
            fclose(file);
            return false;
        }
        pindex->nSize = nStoredSize;
        nRestoredOut++;
    }
    if (file)
        fclose(file);
    return true;
}

int64_t GetBlockSizePenalty(unsigned int nBlockSize, unsigned int nMedianSize)
{
    // No penalty if block is at or below the median
    if (nBlockSize <= nMedianSize || nMedianSize == 0)
        return 0;

    // Quadratic penalty: penalty = baseReward * ((blockSize / median) - 1)^2
    // Returns the penalty as a fraction of COIN (COIN = 100% of block reward lost)
    // At blockSize == 2 * median: penalty = COIN (100% — miner gets nothing)
    // Clamp ratio: block can't exceed 2x median by consensus, so cap at 2*COIN
    int64_t nRatio = ((int64_t)nBlockSize * COIN) / nMedianSize;
    if (nRatio > 2 * COIN)
        nRatio = 2 * COIN;
    int64_t nExcess = nRatio - COIN; // (blockSize/median - 1) * COIN
    if (nExcess <= 0)
        return 0;

    // penalty = excess^2 / COIN (quadratic, overflow-safe with clamped nExcess <= COIN)
    int64_t nPenalty = (nExcess * nExcess) / COIN;

    // Cap at COIN (100% penalty)
    if (nPenalty > COIN)
        nPenalty = COIN;

    return nPenalty;
}

/** Apply adaptive block size penalty to a reward. Returns adjusted reward.
 *  Must be called with the block being validated and its parent index. */
int64_t ApplyBlockSizePenalty(int64_t nReward, const CBlock& block, const CBlockIndex* pindexPrev)
{
    if (!pindexPrev || pindexPrev->nHeight + 1 < FORK_HEIGHT_DAG)
        return nReward;

    unsigned int nBlockBytes = ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION);
    // The adaptive limit is 2x median; the median is limit/2
    unsigned int nMedian = GetAdaptiveBlockSizeLimit(pindexPrev) / 2;
    if (nMedian < ADAPTIVE_BLOCK_FLOOR)
        nMedian = ADAPTIVE_BLOCK_FLOOR;

    int64_t nPenalty = GetBlockSizePenalty(nBlockBytes, nMedian);
    if (nPenalty > 0 && nReward > 0)
    {
        int64_t nPenaltyAmount = (nReward * nPenalty) / COIN;
        nReward -= nPenaltyAmount;
        if (nReward < 0) nReward = 0;
    }
    return nReward;
}


bool CTransaction::CheckTransaction() const
{
    if (IsPrivacyVNext())
    {
        // Coinbase and coinstake value is settled by subsidy rules, not ConnectInputs, so a
        // payload would credit the pool unbacked. Exception: from the fee-note fork a coinbase
        // carries the fee note; ConnectBlock enforces its block-level equality and height gate.
        if (IsCoinStake())
            return DoS(100, error("CTransaction::CheckTransaction() : IV5 payload cannot be coinstake"));

        // Versions 2000-2002 are legacy pool envelopes that block assembly never mines;
        // refuse them here so they cannot pin the mempool. One envelope per operation.
        if (nVersion >= SHIELDED_TX_VERSION && nVersion <= SHIELDED_TX_VERSION_FCMP)
            return DoS(100, error("CTransaction::CheckTransaction() : an IV5 payload "
                                  "may not ride legacy pool version %d", nVersion));

        const PrivacyVNextPayloadValidation validation =
            ValidatePrivacyVNextPayload(
                static_cast<uint32_t>(nVersion),
                privacyVNext.vchPayload);
        if (validation.fLocalFailure)
        {
            StartShutdown();
            return error("CTransaction::CheckTransaction() : local IV5 failure: %s",
                         validation.strError.c_str());
        }
        if (!validation.IsValid())
            return DoS(100, error("CTransaction::CheckTransaction() : %s",
                                  validation.strError.c_str()));
        if (!IsShieldedVNextConsensusReady())
            return DoS(100, error("CTransaction::CheckTransaction() : IV5 consensus implementation is inactive"));
        if (IsCoinBase())
        {
            PrivacyVNextStateEffects coinbaseEffects;
            const PrivacyVNextPayloadValidation coinbaseResult =
                ExtractPrivacyVNextPayloadEffects(static_cast<uint32_t>(nVersion),
                                                  privacyVNext.vchPayload,
                                                  coinbaseEffects);
            if (coinbaseResult.fLocalFailure)
            {
                StartShutdown();
                return error("CTransaction::CheckTransaction() : local IV5 failure: %s",
                             coinbaseResult.strError.c_str());
            }
            if (!coinbaseResult.IsValid())
                return DoS(100, error("CTransaction::CheckTransaction() : %s",
                                      coinbaseResult.strError.c_str()));
            if (!coinbaseEffects.keyImages.empty())
                return DoS(100, error("CTransaction::CheckTransaction() : coinbase IV5 payload spends notes"));
            if (coinbaseEffects.nFee != 0)
                return DoS(100, error("CTransaction::CheckTransaction() : coinbase IV5 payload charges a fee"));
            if (coinbaseEffects.nTransparentValueBalance <= 0)
                return DoS(100, error("CTransaction::CheckTransaction() : coinbase IV5 payload takes no value into the pool"));
        }
        // Value accounting picks one shape per transaction: a payload is settled
        // against the pool, legacy fields against nValueBalance. Carrying both
        // would leave the legacy side unvalidated and unaccounted.
        if (nValueBalance != 0 || !vShieldedSpend.empty() || !vShieldedOutput.empty())
            return DoS(100, error("CTransaction::CheckTransaction() : IV5 payload cannot carry legacy shielded fields"));
    }

    // Versions 2000--2007 never activated on a public network; their decoder is kept for
    // regtest coverage only and never yields consensus validity on mainnet/testnet.
    if (IsShielded() &&
        IsLegacyPrivacyPolicyDisabled())
        return DoS(100, error("CTransaction::CheckTransaction() : legacy shielded transaction version %d is disabled on public networks",
                              nVersion));

    // Basic checks that don't depend on any context
    if (vin.empty() && !IsShielded() && !IsPrivacyVNext())
        return DoS(10, error("CTransaction::CheckTransaction() : vin empty"));
    if (vout.empty() && !IsShielded() && !IsPrivacyVNext())
        return DoS(10, error("CTransaction::CheckTransaction() : vout empty"));
    // Size limits
    if (::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
        return DoS(100, error("CTransaction::CheckTransaction() : size limits failed"));

    // Check for negative or overflow output values
    int64_t nValueOut = 0;
    for (unsigned int i = 0; i < vout.size(); i++)
    {
        const CTxOut& txout = vout[i];
        if (txout.IsEmpty() && !IsCoinBase() && !IsCoinStake())
            return DoS(100, error("CTransaction::CheckTransaction() : txout empty for user transaction"));
        if (txout.nValue < 0)
            return DoS(100, error("CTransaction::CheckTransaction() : txout.nValue negative"));
        if (txout.nValue > MAX_MONEY)
            return DoS(100, error("CTransaction::CheckTransaction() : txout.nValue too high"));
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return DoS(100, error("CTransaction::CheckTransaction() : txout total out of range"));
    }

    // Check for duplicate inputs
    set<COutPoint> vInOutPoints;
    for (const CTxIn& txin : vin)
    {
        if (nVersion == ANON_TXN_VERSION
            && txin.IsAnonInput())
        {
            // -- blank the upper 3 bytes of n to prevent the same keyimage passing with different ring sizes
            COutPoint opTest = txin.prevout;
            opTest.n &= 0xFF;
            if (vInOutPoints.count(opTest))
            {
                if (fDebugRingSig)
                    printf("CheckTransaction() failed - found duplicate keyimage in txn %s\n", GetHash().ToString().c_str());
                return false;
            };
            vInOutPoints.insert(opTest);
            continue;
        };

        if (vInOutPoints.count(txin.prevout))
            return false;
        vInOutPoints.insert(txin.prevout);
    };

    if (nVersion == ANON_TXN_VERSION)
    {
        // -- Check for duplicate anon outputs
        // NOTE: is this necessary, duplicate coins would not be spendable anyway?
        set<CPubKey> vAnonOutPubkeys;
        CPubKey pkTest;
        for (const CTxOut& txout : vout)
        {
            if (!txout.IsAnonOutput())
                continue;

            const CScript &s = txout.scriptPubKey;
            pkTest = CPubKey(&s[2+1], 33);
            if (vAnonOutPubkeys.count(pkTest))
                return false;
            vAnonOutPubkeys.insert(pkTest);
        };
    };

    if (IsShielded())
    {
        if (IsCoinBase())
            return DoS(100, error("CTransaction::CheckTransaction() : shielded transaction cannot be coinbase"));
        if (IsCoinStake() && nVersion != SHIELDED_TX_VERSION_NULLSTAKE && nVersion != SHIELDED_TX_VERSION_NULLSTAKE_V2 && nVersion != SHIELDED_TX_VERSION_NULLSTAKE_COLD)
            return DoS(100, error("CTransaction::CheckTransaction() : shielded transaction cannot be coinstake"));

        // A NullStake coinstake only ever ADDS the stake reward to the shielded
        // pool (nValueBalance = -reward). A positive balance on a coinstake-shaped
        // tx is an unshield placed under the coinstake exemptions — reject it
        // shape-wide so it can never reach the exempted ConnectInputs paths.
        if (IsCoinStake() && nValueBalance > 0)
            return DoS(100, error("CTransaction::CheckTransaction() : coinstake with positive shielded value balance"));

        if (vShieldedSpend.empty() && vShieldedOutput.empty())
            return DoS(100, error("CTransaction::CheckTransaction() : shielded tx has no shielded components"));

        if (vShieldedSpend.size() > MAX_SHIELDED_INPUTS)
            return DoS(100, error("CTransaction::CheckTransaction() : too many shielded spends (%u > %u)",
                                  (unsigned int)vShieldedSpend.size(), (unsigned int)MAX_SHIELDED_INPUTS));
        if (vShieldedOutput.size() > MAX_SHIELDED_OUTPUTS)
            return DoS(100, error("CTransaction::CheckTransaction() : too many shielded outputs (%u > %u)",
                                  (unsigned int)vShieldedOutput.size(), (unsigned int)MAX_SHIELDED_OUTPUTS));

        for (const CShieldedOutputDescription& output : vShieldedOutput)
        {
            if (output.vchMofNLink.size() > NULLSTAKE_MOFN_MINTLINK_SIZE)
                return DoS(100, error("CTransaction::CheckTransaction() : shielded output M-of-N link too large (%u > %u)",
                                      (unsigned int)output.vchMofNLink.size(),
                                      (unsigned int)NULLSTAKE_MOFN_MINTLINK_SIZE));
        }

        if (nValueBalance < -MAX_MONEY || nValueBalance > MAX_MONEY)
            return DoS(100, error("CTransaction::CheckTransaction() : shielded nValueBalance out of range"));

        set<uint256> vNullifiers;
        for (const CShieldedSpendDescription& spend : vShieldedSpend)
        {
            if (spend.vchRk.size() > SHIELDED_SPEND_AUTH_KEY_MAX_SIZE)
                return DoS(100, error("CTransaction::CheckTransaction() : shielded spend rk too large (%u > %u)",
                                      (unsigned int)spend.vchRk.size(),
                                      (unsigned int)SHIELDED_SPEND_AUTH_KEY_MAX_SIZE));
            if (spend.vchSpendAuthSig.size() > SHIELDED_SPEND_AUTH_SIG_SIZE)
                return DoS(100, error("CTransaction::CheckTransaction() : shielded spend authorization signature too large (%u > %u)",
                                      (unsigned int)spend.vchSpendAuthSig.size(),
                                      (unsigned int)SHIELDED_SPEND_AUTH_SIG_SIZE));
            if (spend.vchLelantusProof.size() > SHIELDED_TX_FIELD_MAX_WIRE_SIZE)
                return DoS(100, error("CTransaction::CheckTransaction() : shielded spend Lelantus proof too large (%u > %u)",
                                      (unsigned int)spend.vchLelantusProof.size(),
                                      (unsigned int)SHIELDED_TX_FIELD_MAX_WIRE_SIZE));
            if (spend.vAnonSet.size() > (size_t)LELANTUS_MAX_SET_SIZE)
                return DoS(100, error("CTransaction::CheckTransaction() : shielded spend anonymity set too large (%u > %u)",
                                      (unsigned int)spend.vAnonSet.size(),
                                      (unsigned int)LELANTUS_MAX_SET_SIZE));
            if (spend.vchNullifierPoint.size() > NULLIFIER_POINT_SIZE)
                return DoS(100, error("CTransaction::CheckTransaction() : shielded spend nullifier point too large (%u > %u)",
                                      (unsigned int)spend.vchNullifierPoint.size(),
                                      (unsigned int)NULLIFIER_POINT_SIZE));
            if (spend.vchNullifierBindingProof.size() > NULLIFIER_BINDING_PROOF_SIZE)
                return DoS(100, error("CTransaction::CheckTransaction() : shielded spend nullifier binding proof too large (%u > %u)",
                                      (unsigned int)spend.vchNullifierBindingProof.size(),
                                      (unsigned int)NULLIFIER_BINDING_PROOF_SIZE));

            if (spend.nullifier == 0)
                return DoS(100, error("CTransaction::CheckTransaction() : zero shielded nullifier"));

            if (vNullifiers.count(spend.nullifier))
                return DoS(100, error("CTransaction::CheckTransaction() : duplicate shielded nullifier"));
            vNullifiers.insert(spend.nullifier);
        }

        if (IsDSP())
        {
            if (nBestHeight < FORK_HEIGHT_DSP)
                return DoS(100, error("CTransaction::CheckTransaction() : DSP transactions not active until height %d", FORK_HEIGHT_DSP));

            if (nPrivacyMode > PRIVACY_MODE_MASK)
                return DoS(100, error("CTransaction::CheckTransaction() : invalid privacy mode %d (max 7)", nPrivacyMode));

            bool fHideAmount   = DSP_HideAmount(nPrivacyMode);
            bool fHideSender   = DSP_HideSender(nPrivacyMode);
            bool fHideReceiver = DSP_HideReceiver(nPrivacyMode);

            for (size_t i = 0; i < vShieldedSpend.size(); i++)
            {
                const CShieldedSpendDescription& spend = vShieldedSpend[i];
                if (!fHideAmount)
                {
                    if (spend.nPlaintextValue < 0 || spend.nPlaintextValue > MAX_MONEY)
                        return DoS(100, error("CTransaction::CheckTransaction() : DSP spend %u invalid plaintext value", (unsigned int)i));
                    if (spend.vchPlaintextBlind.size() != 32)
                        return DoS(100, error("CTransaction::CheckTransaction() : DSP spend %u missing blinding factor", (unsigned int)i));
                }
                else
                {
                    if (spend.nPlaintextValue != -1)
                        return DoS(100, error("CTransaction::CheckTransaction() : DSP spend %u has plaintext value in hidden-amount mode", (unsigned int)i));
                    if (!spend.vchPlaintextBlind.empty())
                        return DoS(100, error("CTransaction::CheckTransaction() : DSP spend %u has blinding factor in hidden-amount mode", (unsigned int)i));
                }
                if (!fHideSender)
                {
                    if (!spend.vchLelantusProof.empty() || !spend.vAnonSet.empty())
                        return DoS(100, error("CTransaction::CheckTransaction() : DSP spend %u has Lelantus proof in public-sender mode", (unsigned int)i));
                }
            }

            for (size_t i = 0; i < vShieldedOutput.size(); i++)
            {
                const CShieldedOutputDescription& output = vShieldedOutput[i];
                if (!fHideAmount)
                {
                    if (output.nPlaintextValue < 0 || output.nPlaintextValue > MAX_MONEY)
                        return DoS(100, error("CTransaction::CheckTransaction() : DSP output %u invalid plaintext value", (unsigned int)i));
                    if (output.vchPlaintextBlind.size() != 32)
                        return DoS(100, error("CTransaction::CheckTransaction() : DSP output %u missing blinding factor", (unsigned int)i));
                }
                else
                {
                    if (output.nPlaintextValue != -1)
                        return DoS(100, error("CTransaction::CheckTransaction() : DSP output %u has plaintext value in hidden-amount mode", (unsigned int)i));
                    if (!output.vchPlaintextBlind.empty())
                        return DoS(100, error("CTransaction::CheckTransaction() : DSP output %u has blinding factor in hidden-amount mode", (unsigned int)i));
                }
                if (fHideReceiver)
                {
                    if (!output.vchRecipientScript.empty())
                        return DoS(100, error("CTransaction::CheckTransaction() : DSP output %u has public recipient in hidden-receiver mode", (unsigned int)i));
                }
            }
        }
    };

    if (IsCoinBase())
    {
        if (vin[0].scriptSig.size() < 2 || vin[0].scriptSig.size() > 100)
            return DoS(100, error("CTransaction::CheckTransaction() : coinbase script size is invalid"));
    }
    else
    {
        for (const CTxIn& txin : vin)
            if (txin.prevout.IsNull())
                return DoS(10, error("CTransaction::CheckTransaction() : prevout is null"));
    } //New ban code for hybrid collateralnodes and FMPS - Not for prime time yet, may or may not be used
	/*
	else
	{
		BOOST_FOREACH(const CTxIn& txin, vin)
			if (txin.prevout.IsBanned()){ // new function that checks if the txin.prevout matches an address
				txin.prevout.SetNull(); // this should set the UTXO to null
				return DoS(10, error("CheckTransaction(): You have been caught trying to cheat. Kthxbai"));
			}
	}
	*/
    //return hooks->CheckTransaction(*this);
    return true;
}

int64_t CTransaction::GetMinFee(unsigned int nBlockSize, enum GetMinFee_mode mode, unsigned int nBytes) const
{
    // Base fee is either MIN_TX_FEE or MIN_RELAY_TX_FEE for standard txns, and MIN_TX_FEE_ANON for anon txns

    if (nVersion == ANON_TXN_VERSION || IsShielded())
        mode = GMF_ANON;

    int64_t nBaseFee;
    switch (mode)
    {
        case GMF_RELAY: nBaseFee = MIN_RELAY_TX_FEE; break;
        case GMF_ANON:  nBaseFee = MIN_TX_FEE_ANON;  break;
        default:        nBaseFee = MIN_TX_FEE;       break;
    };

    unsigned int nNewBlockSize = nBlockSize + nBytes;
    int64_t nMinFee = (1 + (int64_t)nBytes / 1000) * nBaseFee;

    // To limit dust spam, require MIN_TX_FEE/MIN_RELAY_TX_FEE if any output is less than 0.01
    if (nMinFee < nBaseFee)
    {
        for (const CTxOut& txout : vout)
            if (txout.nValue < CENT)
                nMinFee = nBaseFee;
    };

    // Raise the price as the block approaches full
    if (mode != GMF_ANON && nBlockSize != 1 && nNewBlockSize >= MAX_BLOCK_SIZE_GEN/2)
    {
        if (nNewBlockSize >= MAX_BLOCK_SIZE_GEN)
            return MAX_MONEY;
        nMinFee *= MAX_BLOCK_SIZE_GEN / (MAX_BLOCK_SIZE_GEN - nNewBlockSize);
    };

    if (!MoneyRange(nMinFee))
        nMinFee = MAX_MONEY;
    return nMinFee;
}

// The chain context every payload must declare to be ours. Lives here because the
// genesis constants do; the FFI layer stamps it onto each validation request so the
// network id and genesis hash are consensus-checked with the rest of the header.
uint8_t PrivacyVNextLocalNetworkId()
{
    if (fRegTest)
        return 2;
    return fTestNet ? 1 : 0;
}

void PrivacyVNextLocalGenesis(unsigned char out[32])
{
    std::memcpy(out, GetGenesisBlockHash().begin(), 32);
}

// What an IV5 payload commits its transaction's transparent side to.
//
// The payload's signing hash covers the payload prefix, so anything placed in the prefix
// is covered by every proof the payload carries. This digest goes there, and consensus
// holds it against the transaction the payload arrives in.
//
// Scope is the input prevouts, the output vector and the lock time. A spend has no
// transparent input, so no SignatureHash covers it and its whole transparent surface is
// mutable: retargeting a scriptPubKey, restating an amount, appending an output or an
// input, or dropping either vector must all break this.
//
// Only the prevouts of vin, never the scriptSigs. A shield's inputs are signed over the
// whole serialized transaction, which already contains this payload, so binding a
// scriptSig would make the signature depend on a digest that depends on the signature.
// Prevouts carry no such cycle: the wallet fixes them before it proves, and signs after.
// A spend binds an empty vector, which is what makes it a spend -- an appended transparent
// input would otherwise let a third party attribute a private transfer to an address of
// their choosing.
//
// nTime is excluded on purpose: it is stamped at broadcast, after proving, so that the
// wallet's proving time does not become a fingerprint. It is inside the txid, so a spend's
// txid stays third-party mutable and nothing may key on it; the wallet retires notes by
// key image for that reason.
//
// An empty vector is not a special case; it hashes as a zero-length vector, which is what
// a shield's outputs and a spend's inputs commit to.
uint256 GetPrivacyVNextTransparentBinding(const CTransaction& tx)
{
    static const char* pszDomain = "Innova/IV5/TransparentBinding/v2";
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss.write(pszDomain, strlen(pszDomain));
    ss << (unsigned int)tx.vin.size();
    for (unsigned int i = 0; i < tx.vin.size(); i++)
        ss << tx.vin[i].prevout;
    ss << tx.vout;
    ss << tx.nLockTime;
    return ss.GetHash();
}

bool ConnectPrivacyVNextAttestations(CTxDB& txdb,
                                     const CTransaction& tx,
                                     const PrivacyVNextStateEffects& effects,
                                     int nHeight,
                                     bool fJustCheck,
                                     std::set<uint256>& setBlockAttestations,
                                     bool& fLocalFailure,
                                     std::string& strError)
{
    fLocalFailure = false;
    strError.clear();

    // The one place a member key becomes chain state, so the on-curve test the Rust
    // decoder cannot make belongs here. A key that names no point on secp256k1 can never
    // be encrypted to, so a registration carrying one would occupy a committee seat its
    // holder could never serve. Pure function of the payload bytes, so every node refuses
    // the same registrations.
    std::vector<unsigned char> vchMemberKey;
    if (effects.HasMemberKey())
    {
        // The registry exists to seat a committee that only note-weighted finality
        // uses, so it rides that fork and nothing else. Keyed on the extracted key
        // rather than on the payload's declared operation byte, because the header
        // read is not a decoder and consensus must gate on what was actually proved.
        if (!IsIV5NoteVoteActiveAtHeight(nHeight))
        {
            strError = "IV5 finality member registration is not active at this height";
            return false;
        }
        if (!IsPrivacyVNextMemberKeyOnCurve(effects.memberKey.data(),
                                            effects.memberKey.size()))
        {
            strError = "IV5 finality member registration key is not on secp256k1";
            return false;
        }
        vchMemberKey.assign(effects.memberKey.begin(), effects.memberKey.end());
    }

    for (size_t i = 0; i < effects.attestationKeyImages.size(); ++i)
    {
        uint256 keyImage;
        memcpy(keyImage.begin(), effects.attestationKeyImages[i].data(),
               effects.attestationKeyImages[i].size());
        if (!setBlockAttestations.insert(keyImage).second)
        {
            strError = strprintf("duplicate IV5 attestation %s in active DAG block",
                                 keyImage.ToString().substr(0,10).c_str());
            return false;
        }

        // An attestation over a spent note proves nothing about live collateral,
        // so the note must still be unspent when it is made.
        CPrivacyVNextNullifierSpent spent;
        const TxDBReadStatus spentStatus =
            txdb.ReadPrivacyVNextNullifierStatus(keyImage, spent);
        if (spentStatus == TXDB_READ_ERROR)
        {
            fLocalFailure = true;
            strError = strprintf(
                "corrupt IV5 spent-key index for %s; -reindex/resync required",
                keyImage.ToString().substr(0,10).c_str());
            return false;
        }
        if (spentStatus == TXDB_READ_FOUND)
        {
            strError = strprintf(
                "IV5 attestation %s names a note already spent by %s",
                keyImage.ToString().substr(0,10).c_str(),
                spent.txnHash.ToString().substr(0,10).c_str());
            return false;
        }

        // One node per note across both attestation operations. The record is never replaced and
        // is erased only by its own disconnect, so connect and disconnect stay exact inverses.
        CPrivacyVNextCollateralAttestation prior;
        const TxDBReadStatus watchStatus =
            txdb.ReadPrivacyVNextCollateralStatus(keyImage, prior);
        if (watchStatus == TXDB_READ_ERROR)
        {
            fLocalFailure = true;
            strError = strprintf(
                "corrupt IV5 collateral index for %s; -reindex/resync required",
                keyImage.ToString().substr(0,10).c_str());
            return false;
        }
        if (watchStatus == TXDB_READ_FOUND)
        {
            strError = strprintf(
                "IV5 collateral %s was already attested by %s",
                keyImage.ToString().substr(0,10).c_str(),
                prior.txnHash.ToString().substr(0,10).c_str());
            return false;
        }

        if (fJustCheck)
            continue;
        const CPrivacyVNextCollateralAttestation attested(
            tx.GetHash(),
            uint256(std::vector<unsigned char>(
                effects.registrationContext.begin(),
                effects.registrationContext.end())),
            nHeight,
            vchMemberKey);
        if (!txdb.WritePrivacyVNextCollateral(keyImage, attested))
        {
            fLocalFailure = true;
            strError = "IV5 collateral attestation write failed";
            return false;
        }
    }
    return true;
}

bool DisconnectPrivacyVNextAttestations(CTxDB& txdb,
                                        const CTransaction& tx,
                                        const PrivacyVNextStateEffects& effects,
                                        std::string& strError)
{
    strError.clear();
    for (size_t j = effects.attestationKeyImages.size(); j > 0; --j)
    {
        uint256 keyImage;
        memcpy(keyImage.begin(), effects.attestationKeyImages[j - 1].data(),
               effects.attestationKeyImages[j - 1].size());
        CPrivacyVNextCollateralAttestation attested;
        const TxDBReadStatus status =
            txdb.ReadPrivacyVNextCollateralStatus(keyImage, attested);
        if (status != TXDB_READ_FOUND || attested.txnHash != tx.GetHash())
        {
            strError = strprintf(
                "IV5 collateral undo record is %s or owned by another attestation for %s",
                status == TXDB_READ_NOT_FOUND ? "missing" :
                status == TXDB_READ_ERROR ? "corrupt" : "mismatched",
                keyImage.ToString().substr(0,10).c_str());
            return false;
        }
        if (!txdb.ErasePrivacyVNextCollateral(keyImage))
        {
            strError = "IV5 collateral erase failed";
            return false;
        }
    }
    return true;
}

bool IsPrivacyVNextCollateralRegistered(
    CTxDB& txdb,
    const uint256& keyImage,
    CPrivacyVNextCollateralAttestation& attestedOut,
    bool& fLocalFailure)
{
    attestedOut = CPrivacyVNextCollateralAttestation();
    fLocalFailure = false;

    const TxDBReadStatus watchStatus =
        txdb.ReadPrivacyVNextCollateralStatus(keyImage, attestedOut);
    if (watchStatus == TXDB_READ_ERROR)
    {
        fLocalFailure = true;
        return false;
    }
    if (watchStatus != TXDB_READ_FOUND)
        return false;

    CPrivacyVNextNullifierSpent spent;
    const TxDBReadStatus spentStatus =
        txdb.ReadPrivacyVNextNullifierStatus(keyImage, spent);
    if (spentStatus == TXDB_READ_ERROR)
    {
        fLocalFailure = true;
        return false;
    }
    // The spend is the deregistration. Nothing is erased for it: the record stays
    // and simply stops meaning "registered", which is what makes a reorg that
    // reorders the attestation and the spend land the same way on every node.
    return spentStatus != TXDB_READ_FOUND;
}

// Every registration still active as of nAnchorHeight, in key-image order.
//
// Both indexes this reads are exact functions of the ancestry connected so far, so two
// nodes connecting one block read the same rows and derive the same set. That is the whole
// determinism argument, and it is why nothing here consults nBestHeight, pindexBest, the
// mempool or any live finality height: an anchor taken from what a node has *seen* rather
// than from what the block it is validating descends from is the shape of the private
// finality split, and it is not repeated here.
//
// nAnchorHeight bounds the registrations by when they were recorded. The caller supplies
// it and owns the choice: the committee draw that follows this increment anchors it to the
// deterministic finalized height its epoch state carries, which is settled and cannot be
// reorged out from under a snapshot.
//
// fMembersOnly selects registrations that published a tally-encryption key -- the
// committee-eligible set. Without it the result is every collateral registration.
bool GetPrivacyVNextCollateralSnapshot(
    CTxDB& txdb,
    int nAnchorHeight,
    bool fMembersOnly,
    std::vector<CPrivacyVNextRegistryEntry>& vOut,
    bool& fLocalFailure,
    std::string& strError)
{
    vOut.clear();
    fLocalFailure = false;
    strError.clear();

    if (nAnchorHeight < 0)
    {
        strError = "an IV5 registration snapshot needs a nonnegative anchor height";
        return false;
    }

    // Needs a handle with no open batch: an iterator cannot see pending writes and would
    // otherwise disagree with the point reads below. A finalized anchor wants committed
    // state, so the block being connected passes a separate read handle rather than its
    // own write batch.
    std::vector<std::pair<uint256, CPrivacyVNextCollateralAttestation> > vRows;
    if (!txdb.EnumeratePrivacyVNextCollateral(vRows, strError))
    {
        fLocalFailure = true;
        strError = "IV5 collateral index cannot be read (" + strError + ")";
        return false;
    }

    for (size_t i = 0; i < vRows.size(); ++i)
    {
        const uint256& keyImage = vRows[i].first;
        const CPrivacyVNextCollateralAttestation& attested = vRows[i].second;
        if (attested.nHeight > nAnchorHeight)
            continue;
        if (fMembersOnly && !attested.IsFinalityMember())
            continue;

        CPrivacyVNextNullifierSpent spent;
        const TxDBReadStatus spentStatus =
            txdb.ReadPrivacyVNextNullifierStatus(keyImage, spent);
        if (spentStatus == TXDB_READ_ERROR)
        {
            fLocalFailure = true;
            strError = strprintf(
                "corrupt IV5 spent-key index for %s; -reindex/resync required",
                keyImage.ToString().substr(0,10).c_str());
            vOut.clear();
            return false;
        }
        // Spent means the collateral is gone, so the registration it backed is gone
        // with it -- but only a spend at or below the anchor height counts, exactly as
        // only a registration at or below it counts.
        //
        // Bare membership answers from whatever ancestry this node has committed,
        // which during a reorg is the branch being replaced: it would drop a row the
        // adopted branch never released while a node syncing that branch fresh keeps
        // it, and the draw is stored rather than rederived, so a resync would not
        // settle the disagreement. Every spend at or below the anchor is on ancestry
        // both nodes share.
        if (spentStatus == TXDB_READ_FOUND && spent.nHeight <= nAnchorHeight)
            continue;

        CPrivacyVNextRegistryEntry entry;
        entry.keyImage = keyImage;
        entry.contextDigest = attested.contextDigest;
        entry.txnHash = attested.txnHash;
        entry.nHeight = attested.nHeight;
        entry.vchMemberKey = attested.vchMemberKey;
        vOut.push_back(entry);
    }

    // Key-image order, so the set a caller sees does not depend on leveldb's iteration
    // order. The seed derivation and the draw that follow this increment consume this
    // sequence and must see one ordering on every node.
    std::sort(vOut.begin(), vOut.end());
    return true;
}

bool CheckPrivacyVNextTransparentBinding(const CTransaction& tx,
                                         const PrivacyVNextStateEffects& effects,
                                         std::string& strError)
{
    strError.clear();
    const uint256 expected = GetPrivacyVNextTransparentBinding(tx);
    if (!std::equal(effects.transparentBinding.begin(),
                    effects.transparentBinding.end(), expected.begin()))
    {
        strError = "IV5 payload does not bind this transaction's transparent side";
        return false;
    }
    return true;
}

bool CheckPrivacyVNextParameterDigest(
    const PrivacyVNextStateEffects& effects,
    const std::vector<unsigned char>& vchChainDigest,
    std::string& strError)
{
    strError.clear();
    // Only the digest the chain carries: admitting digests compiled into the binary would
    // make one block valid on some nodes and invalid on others.
    if (vchChainDigest.size() != effects.parameterDigest.size() ||
        !std::equal(effects.parameterDigest.begin(),
                    effects.parameterDigest.end(), vchChainDigest.begin()))
    {
        strError = "IV5 payload parameter digest is not the one this chain carries";
        return false;
    }
    return true;
}

static bool ValidatePrivacyVNextFinalizedContext(
    CTxDB& txdb, int nContextHeight,
    const PrivacyVNextStateEffects& effects,
    bool& fLocalFailure, std::string& strError)
{
    fLocalFailure = false;
    strError.clear();

    // The epoch state consulted is fixed by nContextHeight, so a not-yet-produced state is
    // the chain's answer; only an unreadable record is local.
    CEpochState finalizedState;
    if (!g_dagManager.GetFinalizedEpochStateAsOf(
            txdb, nContextHeight, finalizedState, fLocalFailure))
    {
        strError = fLocalFailure
                       ? "finalized epoch state cannot be read; -reindex/resync required"
                       : "no finalized epoch state exists at this height";
        return false;
    }

    std::vector<unsigned char> expectedRoot;
    std::vector<unsigned char> expectedParameterDigest;
    uint64_t nExpectedTreeSize = 0;
    if (finalizedState.nSerVersion >= EPOCHSTATE_SER_VERSION_V4)
    {
        // Whether the anchor epoch is finalized is chain state; the digest widths are
        // already enforced by the record decoder, so failing them means local damage.
        // The resolver returns either a finalized epoch or one deep enough to stand
        // without finality, so accept both here or it would reject its own choice.
        if (!finalizedState.fFinalized &&
            (finalizedState.nHeightEnd <= 0 ||
             nContextHeight - finalizedState.nHeightEnd <
                 EPOCHSTATE_VNEXT_MIN_UNFINALIZED_ANCHOR_DEPTH))
        {
            strError = strprintf(
                "the anchor epoch is neither finalized nor %d blocks deep",
                EPOCHSTATE_VNEXT_MIN_UNFINALIZED_ANCHOR_DEPTH);
            return false;
        }
        if (finalizedState.vchVNextRoot.size() !=
                EPOCHSTATE_VNEXT_DIGEST_SIZE ||
            finalizedState.vchVNextParameterDigest.size() !=
                EPOCHSTATE_VNEXT_DIGEST_SIZE)
        {
            fLocalFailure = true;
            strError = "persisted finalized IV5 epoch state is malformed";
            return false;
        }
        expectedRoot = finalizedState.vchVNextRoot;
        expectedParameterDigest = finalizedState.vchVNextParameterDigest;
        nExpectedTreeSize = finalizedState.nVNextTreeSize;
    }
    else
    {
        if (!effects.keyImages.empty())
        {
            strError = "no finalized IV5 root is available for a spend";
            return false;
        }
        PrivacyVNextEpochSeed seed;
        std::string strSeedError;
        if (!LoadPrivacyVNextEpochSeed(seed, strSeedError))
        {
            fLocalFailure = true;
            strError = "canonical IV5 bootstrap seed is unavailable: " +
                       strSeedError;
            return false;
        }
        expectedRoot = seed.vchRoot;
        expectedParameterDigest = seed.vchParameterDigest;
        nExpectedTreeSize = seed.nTreeSize;
    }

    // A spend may anchor to any of the last few finalized roots; the tree only grows and
    // double spends are caught by the nullifier set.
    bool fAnchorMatches =
        std::equal(effects.finalizedRoot.begin(), effects.finalizedRoot.end(),
                   expectedRoot.begin()) &&
        effects.nFinalizedTreeSize == nExpectedTreeSize;
    if (!fAnchorMatches &&
        finalizedState.nSerVersion >= EPOCHSTATE_SER_VERSION_V4)
    {
        for (int nBack = 1;
             !fAnchorMatches && nBack < EPOCHSTATE_VNEXT_MAX_ANCHOR_AGE_EPOCHS;
             ++nBack)
        {
            CEpochState olderState;
            bool fOlderLocalFailure = false;
            if (!g_dagManager.GetFinalizedEpochStateAsOf(txdb, nContextHeight,
                                                         nBack, olderState,
                                                         &fOlderLocalFailure))
            {
                if (fOlderLocalFailure)
                {
                    fLocalFailure = true;
                    strError = strprintf("epoch-state record %d back from the finalized epoch "
                                         "is unreadable on this node", nBack);
                    return false;
                }
                break;
            }
            // An older anchor is deeper than the one resolved above, so the same
            // finalized-or-deep rule applies and never admits anything shallower.
            const bool fOlderDeepEnough =
                olderState.nHeightEnd > 0 &&
                nContextHeight - olderState.nHeightEnd >=
                    EPOCHSTATE_VNEXT_MIN_UNFINALIZED_ANCHOR_DEPTH;
            if ((!olderState.fFinalized && !fOlderDeepEnough) ||
                olderState.nSerVersion < EPOCHSTATE_SER_VERSION_V4 ||
                olderState.vchVNextRoot.size() != EPOCHSTATE_VNEXT_DIGEST_SIZE ||
                olderState.vchVNextParameterDigest.size() !=
                    EPOCHSTATE_VNEXT_DIGEST_SIZE)
                continue;
            if (std::equal(effects.finalizedRoot.begin(),
                           effects.finalizedRoot.end(),
                           olderState.vchVNextRoot.begin()) &&
                effects.nFinalizedTreeSize == olderState.nVNextTreeSize)
            {
                fAnchorMatches = true;
                expectedParameterDigest = olderState.vchVNextParameterDigest;
            }
        }
    }
    if (!fAnchorMatches)
    {
        strError = "payload finalized root or tree size does not match consensus state";
        return false;
    }
    // Judged against the digest the anchor epoch carries, which is the same record on
    // every node at this height.
    return CheckPrivacyVNextParameterDigest(effects, expectedParameterDigest,
                                            strError);
}

// Whether an IV5 transaction's anchor is still inside the consensus window at a height;
// otherwise a miner keeps selecting a transaction its own ConnectBlock rejects.
bool CheckPrivacyVNextFinalizedAnchor(CTxDB& txdb, int nHeight,
                                      const CTransaction& tx,
                                      std::string& strError)
{
    strError.clear();
    if (!tx.IsPrivacyVNext())
        return true;

    PrivacyVNextStateEffects effects;
    const PrivacyVNextPayloadValidation validation =
        ExtractPrivacyVNextPayloadEffects(
            static_cast<uint32_t>(tx.nVersion), tx.privacyVNext.vchPayload,
            effects);
    if (!validation.IsValid())
    {
        strError = validation.strError;
        return false;
    }

    bool fLocalFailure = false;
    return ValidatePrivacyVNextFinalizedContext(txdb, nHeight, effects,
                                                fLocalFailure, strError);
}

bool GetPrivacyVNextPoolDelta(const PrivacyVNextStateEffects& effects,
                              int64_t& nDeltaOut,
                              std::string& strError)
{
    nDeltaOut = 0;
    strError.clear();

    const int64_t nBalance = effects.nTransparentValueBalance;
    if (nBalance == std::numeric_limits<int64_t>::min() ||
        !MoneyRange(nBalance < 0 ? -nBalance : nBalance))
    {
        strError = "IV5 transparent value balance is out of range";
        return false;
    }
    if (effects.nFee > (uint64_t)MAX_MONEY)
    {
        strError = "IV5 fee is out of range";
        return false;
    }
    // Both operands are in [-MAX_MONEY, MAX_MONEY], so the difference cannot overflow.
    nDeltaOut = nBalance - (int64_t)effects.nFee;
    return true;
}

bool CheckPrivacyVNextUnshieldRetired(int64_t nDeclaredBalance, int nHeight,
                                      std::string& strError)
{
    strError.clear();
    if (!IsIV5FeeNoteActiveAtHeight(nHeight))
        return true;
    if (nDeclaredBalance < 0)
    {
        strError = strprintf(
            "IV5 unshield is retired from height %d: payload declares %" PRId64
            " leaving the pool", FORK_HEIGHT_IV5_FEE_NOTE, -nDeclaredBalance);
        return false;
    }
    return true;
}

// Transparent value an IV5 transaction moves across the pool boundary. The pool delta
// is the pool's share; whatever the transparent side contributes beyond it is the fee.
bool GetPrivacyVNextTransparentFlow(const CTransaction& tx,
                                    int64_t& nAbsorbedOut,
                                    int64_t& nReleasedOut,
                                    bool& fLocalFailure,
                                    std::string& strError,
                                    int64_t* pnDeclaredFeeOut,
                                    int64_t* pnDeclaredBalanceOut)
{
    nAbsorbedOut = 0;
    nReleasedOut = 0;
    fLocalFailure = false;
    strError.clear();
    if (pnDeclaredFeeOut)
        *pnDeclaredFeeOut = 0;
    if (pnDeclaredBalanceOut)
        *pnDeclaredBalanceOut = 0;

    PrivacyVNextStateEffects effects;
    const PrivacyVNextPayloadValidation validation =
        ExtractPrivacyVNextPayloadEffects(
            static_cast<uint32_t>(tx.nVersion), tx.privacyVNext.vchPayload,
            effects);
    if (validation.fLocalFailure)
    {
        fLocalFailure = true;
        strError = validation.strError;
        return false;
    }
    if (!validation.IsValid())
    {
        strError = validation.strError;
        return false;
    }

    int64_t nDelta = 0;
    if (!GetPrivacyVNextPoolDelta(effects, nDelta, strError))
        return false;
    if (!MoneyRange(nDelta < 0 ? -nDelta : nDelta))
    {
        strError = "IV5 pool delta is out of range";
        return false;
    }
    // Every IV5 shape is checked, not just the releasing ones: released value is safe only
    // if the payload named the outputs that receive it.
    if (!CheckPrivacyVNextTransparentBinding(tx, effects, strError))
        return false;

    // GetPrivacyVNextPoolDelta has already range-checked both fields.
    if (pnDeclaredFeeOut)
        *pnDeclaredFeeOut = (int64_t)effects.nFee;
    if (pnDeclaredBalanceOut)
        *pnDeclaredBalanceOut = effects.nTransparentValueBalance;

    if (nDelta > 0)
        nAbsorbedOut = nDelta;
    else
        nReleasedOut = -nDelta;
    return true;
}

// An attestation has no transparent side and no pool flow, so it pays no fee; callers
// pair this with a computed fee of zero.
bool IsPrivacyVNextFeeExemptShape(const CTransaction& tx)
{
    if (!tx.IsPrivacyVNext() || tx.privacyVNext.vchPayload.empty())
        return false;
    if (!tx.vin.empty() || !tx.vout.empty())
        return false;
    uint8_t nOperation = 0;
    uint8_t nDisclosureMask = 0;
    if (!iv5::ReadDeclaredEnvelope(&tx.privacyVNext.vchPayload[0],
                                   tx.privacyVNext.vchPayload.size(),
                                   nOperation, nDisclosureMask))
        return false;
    return iv5::IsAttestationOperation(nOperation);
}

bool CTxMemPool::accept(CTxDB& txdb, CTransaction &tx, bool fCheckInputs,
                        bool* pfMissingInputs, bool fOnlyCheckWithoutAdding)
{
    AssertLockHeld(cs_main);
    printf("CTxMemPool::accept, fCheckInputs = %d, fOnlyCheckWithoutAdding = %d, ver=%d, vin=%u, vout=%u, vSS=%u, vSO=%u\n",
           fCheckInputs, fOnlyCheckWithoutAdding, tx.nVersion, (unsigned)tx.vin.size(),
           (unsigned)tx.vout.size(), (unsigned)tx.vShieldedSpend.size(), (unsigned)tx.vShieldedOutput.size());
    if (pfMissingInputs)
        *pfMissingInputs = false;

    const int nEffectiveMempoolHeight =
        nBestHeight == std::numeric_limits<int>::max()
            ? nBestHeight : nBestHeight + 1;
    int64_t nValidatedAnonValueIn = 0;
    std::vector<std::pair<ec_point, CKeyImageSpent> >
        vAnonRelayKeyImages;
    std::vector<uint256> vPrivacyVNextKeyImages;
    std::vector<uint256> vPrivacyVNextOutputBases;
    std::vector<uint256> vPrivacyVNextAttestations;
    if (tx.nVersion == ANON_TXN_VERSION &&
        (IsLegacyPrivacyPolicyDisabled() ||
         nEffectiveMempoolHeight >= FORK_HEIGHT_RINGSIG_DEPRECATION))
        return error("CTxMemPool::accept() : legacy ANON relay is permanently disabled");
    if (tx.IsShielded() &&
        (IsLegacyPrivacyPolicyDisabled() ||
         IsBoundaryAActiveAtHeight(nEffectiveMempoolHeight)))
        return error("CTxMemPool::accept() : legacy shielded/privacy relay is disabled pending privacy vNext");
    if (tx.IsPrivacyVNext() &&
        (!IsBoundaryBActiveAtHeight(nEffectiveMempoolHeight) ||
         !IsShieldedVNextConsensusReady()))
        return error("CTxMemPool::accept() : privacy-vNext is inactive before Boundary B");

    size_t nMaxMempoolSize = GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
    if (GetTotalMemoryUsage() >= nMaxMempoolSize)
        return error("CTxMemPool::accept() : mempool full (%" PRIu64" bytes)", (uint64_t)nMaxMempoolSize);

    if (!tx.CheckTransaction())
        return error("CTxMemPool::accept() : CheckTransaction failed");

    if (tx.IsPrivacyVNext())
    {
        PrivacyVNextStateEffects effects;
        const PrivacyVNextPayloadValidation validation =
            ExtractPrivacyVNextPayloadEffects(
                static_cast<uint32_t>(tx.nVersion),
                tx.privacyVNext.vchPayload, effects);
        if (validation.fLocalFailure)
        {
            StartShutdown();
            return error("CTxMemPool::accept() : local IV5 payload-effects failure: %s",
                         validation.strError.c_str());
        }
        if (!validation.IsValid())
            return error("CTxMemPool::accept() : invalid IV5 payload effects: %s",
                         validation.strError.c_str());

        std::string strBindingError;
        if (!CheckPrivacyVNextTransparentBinding(tx, effects, strBindingError))
            return tx.DoS(100, error("CTxMemPool::accept() : %s",
                                     strBindingError.c_str()));

        // Judged at the height this transaction would occupy, not the tip: one
        // accepted before the fork must not be relayable into a block after it.
        std::string strRetiredError;
        if (!CheckPrivacyVNextUnshieldRetired(effects.nTransparentValueBalance,
                                              nEffectiveMempoolHeight,
                                              strRetiredError))
            return error("CTxMemPool::accept() : %s", strRetiredError.c_str());

        bool fContextLocalFailure = false;
        std::string strContextError;
        if (!ValidatePrivacyVNextFinalizedContext(
                txdb, nEffectiveMempoolHeight, effects,
                fContextLocalFailure, strContextError))
        {
            if (fContextLocalFailure)
                StartShutdown();
            return error("CTxMemPool::accept() : IV5 finalized context rejected: %s",
                         strContextError.c_str());
        }

        std::set<uint256> setTransactionKeyImages;
        vPrivacyVNextKeyImages.reserve(effects.keyImages.size());
        for (size_t i = 0; i < effects.keyImages.size(); ++i)
        {
            uint256 keyImage;
            memcpy(keyImage.begin(), effects.keyImages[i].data(),
                   effects.keyImages[i].size());
            if (!setTransactionKeyImages.insert(keyImage).second)
                return error("CTxMemPool::accept() : duplicate IV5 spent key %s",
                             keyImage.ToString().substr(0,10).c_str());

            CPrivacyVNextNullifierSpent spent;
            const TxDBReadStatus status =
                txdb.ReadPrivacyVNextNullifierStatus(keyImage, spent);
            if (status == TXDB_READ_ERROR)
            {
                StartShutdown();
                return error("CTxMemPool::accept() : IV5 spent-key index is corrupt for %s; "
                             "-reindex/resync required",
                             keyImage.ToString().substr(0,10).c_str());
            }
            if (status == TXDB_READ_FOUND)
                return error("CTxMemPool::accept() : IV5 spent key %s was already consumed by %s",
                             keyImage.ToString().substr(0,10).c_str(),
                             spent.txnHash.ToString().substr(0,10).c_str());
            vPrivacyVNextKeyImages.push_back(keyImage);
        }

        // Judged at the height this transaction would occupy, mirroring what
        // ConnectPrivacyVNextAttestations enforces: a member registration relayed
        // before the note-vote fork is one a miner would build an unconnectable
        // block around.
        if (effects.HasMemberKey() &&
            (!IsIV5NoteVoteActiveAtHeight(nEffectiveMempoolHeight) ||
             !IsPrivacyVNextMemberKeyOnCurve(effects.memberKey.data(),
                                             effects.memberKey.size())))
            return error("CTxMemPool::accept() : IV5 finality member registration is "
                         "inactive at this height or names no point on secp256k1");

        // An attestation the chain would refuse is worth no relay either, and a
        // miner that built on one would produce a block every peer rejects.
        std::set<uint256> setTransactionAttestations;
        vPrivacyVNextAttestations.reserve(effects.attestationKeyImages.size());
        for (size_t i = 0; i < effects.attestationKeyImages.size(); ++i)
        {
            uint256 keyImage;
            memcpy(keyImage.begin(), effects.attestationKeyImages[i].data(),
                   effects.attestationKeyImages[i].size());
            if (!setTransactionAttestations.insert(keyImage).second)
                return error("CTxMemPool::accept() : duplicate IV5 attestation %s",
                             keyImage.ToString().substr(0,10).c_str());

            CPrivacyVNextNullifierSpent spent;
            const TxDBReadStatus spentStatus =
                txdb.ReadPrivacyVNextNullifierStatus(keyImage, spent);
            if (spentStatus == TXDB_READ_ERROR)
            {
                StartShutdown();
                return error("CTxMemPool::accept() : IV5 spent-key index is corrupt for %s; "
                             "-reindex/resync required",
                             keyImage.ToString().substr(0,10).c_str());
            }
            if (spentStatus == TXDB_READ_FOUND)
                return error("CTxMemPool::accept() : IV5 attestation %s names a note already "
                             "spent by %s",
                             keyImage.ToString().substr(0,10).c_str(),
                             spent.txnHash.ToString().substr(0,10).c_str());

            CPrivacyVNextCollateralAttestation attested;
            const TxDBReadStatus watchStatus =
                txdb.ReadPrivacyVNextCollateralStatus(keyImage, attested);
            if (watchStatus == TXDB_READ_ERROR)
            {
                StartShutdown();
                return error("CTxMemPool::accept() : IV5 collateral index is corrupt for %s; "
                             "-reindex/resync required",
                             keyImage.ToString().substr(0,10).c_str());
            }
            if (watchStatus == TXDB_READ_FOUND)
                return error("CTxMemPool::accept() : IV5 collateral %s was already attested by %s",
                             keyImage.ToString().substr(0,10).c_str(),
                             attested.txnHash.ToString().substr(0,10).c_str());
            vPrivacyVNextAttestations.push_back(keyImage);
        }

        // Relaying an owner the chain already carries would only produce a
        // transaction every miner's ConnectBlock refuses.
        std::set<uint256> setTransactionOutputBases;
        vPrivacyVNextOutputBases.reserve(effects.outputLeaves.size());
        for (size_t i = 0; i < effects.outputLeaves.size(); ++i)
        {
            uint256 base;
            memcpy(base.begin(), effects.outputLeaves[i].nullifierBase.data(),
                   effects.outputLeaves[i].nullifierBase.size());
            if (!setTransactionOutputBases.insert(base).second)
                return error("CTxMemPool::accept() : duplicate IV5 output owner %s",
                             base.ToString().substr(0,10).c_str());

            CShieldedNullifierSpent created;
            const TxDBReadStatus status =
                txdb.ReadPrivacyVNextOutputBaseStatus(base, created);
            if (status == TXDB_READ_ERROR)
            {
                StartShutdown();
                return error("CTxMemPool::accept() : IV5 output-base index is corrupt for %s; "
                             "-reindex/resync required",
                             base.ToString().substr(0,10).c_str());
            }
            if (status == TXDB_READ_FOUND)
                return error("CTxMemPool::accept() : IV5 output owner %s was already issued by %s",
                             base.ToString().substr(0,10).c_str(),
                             created.txnHash.ToString().substr(0,10).c_str());
            vPrivacyVNextOutputBases.push_back(base);
        }
    }

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return tx.DoS(100, error("CTxMemPool::accept() : coinbase as individual tx"));

    // ppcoin: coinstake is also only valid in a block, not as a loose transaction
    if (tx.IsCoinStake())
        return tx.DoS(100, error("CTxMemPool::accept() : coinstake as individual tx"));

    // A name op's scripts are nonstandard, so it is exempt only if it carries an operation
    // connect would index at the candidate height. The fee half is checked below.
    string strNameReason;
    const bool isNameTx =
        tx.nVersion == NAMECOIN_TX_VERSION &&
        hooks->CheckNameTxShape(tx, nBestHeight + 1, strNameReason);
    if (tx.nVersion == NAMECOIN_TX_VERSION && !isNameTx)
        return error("CTxMemPool::accept() : name transaction %s rejected: %s",
                     tx.GetHash().ToString().substr(0,10).c_str(),
                     strNameReason.c_str());

    // Rather not work on nonstandard transactions (unless -testnet)
    string reason;
    if (!fTestNet && !IsStandardTx(tx, reason) && !isNameTx) //!IsStandardTx(tx, reason)
        return error("CTxMemPool::accept() : nonstandard transaction type");

    // Do we already have it?
    uint256 hash = tx.GetHash();
    {
        LOCK(cs);
        if (mapTx.count(hash))
            return false;
        // Reject txids already included in a DAG sibling block
        if (setDAGSeenTxids.count(hash))
            return error("CTxMemPool::accept() : tx %s already in DAG sibling block", hash.ToString().substr(0, 20).c_str());
        for (std::vector<uint256>::const_iterator it =
                 vPrivacyVNextKeyImages.begin();
             it != vPrivacyVNextKeyImages.end(); ++it)
        {
            std::map<uint256, CShieldedNullifierSpent>::const_iterator spentIt =
                mapPrivacyVNextNullifier.find(*it);
            if (spentIt != mapPrivacyVNextNullifier.end())
                return error("CTxMemPool::accept() : IV5 spent key %s is reserved by %s",
                             it->ToString().substr(0,10).c_str(),
                             spentIt->second.txnHash.ToString().substr(0,10).c_str());
        }
        for (std::vector<uint256>::const_iterator it =
                 vPrivacyVNextAttestations.begin();
             it != vPrivacyVNextAttestations.end(); ++it)
        {
            std::map<uint256, CShieldedNullifierSpent>::const_iterator attIt =
                mapPrivacyVNextAttestation.find(*it);
            if (attIt != mapPrivacyVNextAttestation.end())
                return error("CTxMemPool::accept() : IV5 collateral %s is reserved by %s",
                             it->ToString().substr(0,10).c_str(),
                             attIt->second.txnHash.ToString().substr(0,10).c_str());
            // A pending spend of the same note retires it: the attestation can never
            // connect after that spend, and a miner that put both in one block, spend
            // first, would build a block its own ConnectBlock rejects.
            if (HasPendingPrivacyVNextSpend(*it))
                return error("CTxMemPool::accept() : IV5 collateral %s is already being "
                             "spent by %s",
                             it->ToString().substr(0,10).c_str(),
                             mapPrivacyVNextNullifier[*it].txnHash
                                 .ToString().substr(0,10).c_str());
        }
        for (std::vector<uint256>::const_iterator it =
                 vPrivacyVNextOutputBases.begin();
             it != vPrivacyVNextOutputBases.end(); ++it)
        {
            std::map<uint256, CShieldedNullifierSpent>::const_iterator baseIt =
                mapPrivacyVNextOutputBase.find(*it);
            if (baseIt != mapPrivacyVNextOutputBase.end())
                return error("CTxMemPool::accept() : IV5 output owner %s is reserved by %s",
                             it->ToString().substr(0,10).c_str(),
                             baseIt->second.txnHash.ToString().substr(0,10).c_str());
        }
    }

    if (txdb.ContainsTx(hash))
        return false;

    // Check for conflicts with in-memory transactions
    CTransaction* ptxOld = NULL;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        COutPoint outpoint = tx.vin[i].prevout;
        if (mapNextTx.count(outpoint))
        {
            // Disable replacement feature for now
            return false;

            // Allow replacing with a newer version of the same transaction
            if (i != 0)
                return false;
            ptxOld = mapNextTx[outpoint].ptx;
            if (ptxOld->IsFinal())
                return false;
            if (!tx.IsNewerThan(*ptxOld))
                return false;
            for (unsigned int i = 0; i < tx.vin.size(); i++)
            {
                COutPoint outpoint = tx.vin[i].prevout;
                if (!mapNextTx.count(outpoint) || mapNextTx[outpoint].ptx != ptxOld)
                    return false;
            }
            break;
        }
    }

    {
        MapPrevTx mapInputs;
        //map<uint256, CTxIndex> mapUnused;
		std::map<uint256, CTxIndex> mapUnused;
        bool fInvalid = false;
        int64_t nFees;
        if (!tx.FetchInputs(txdb, mapUnused, false, false, mapInputs, fInvalid))
        {
            if (fInvalid)
            {
                if (fDebug)
                    return error("CTxMemPool::accept() : FetchInputs found invalid tx %s", hash.ToString().substr(0,10).c_str());
                else return false;
            }

            if (pfMissingInputs)
                *pfMissingInputs = true;
            return false;
        }
            // Check for non-standard pay-to-script-hash in inputs
            if (!AreInputsStandard(tx, mapInputs) && !fTestNet && !isNameTx)
                return error("CTxMemPool::accept() : nonstandard transaction input");

            nFees = tx.GetValueIn(mapInputs) - tx.GetValueOut();

            if (tx.IsShielded() && tx.nValueBalance != 0)
                nFees += tx.nValueBalance;

            if (tx.IsPrivacyVNext())
            {
                // Same counterparty rule the block accounting uses: without it a
                // shield's transparent inputs read as an enormous fee.
                int64_t nAbsorbed = 0;
                int64_t nReleased = 0;
                bool fFlowLocalFailure = false;
                std::string strFlowError;
                if (!GetPrivacyVNextTransparentFlow(tx, nAbsorbed, nReleased,
                                                    fFlowLocalFailure, strFlowError))
                {
                    if (fFlowLocalFailure)
                        StartShutdown();
                    return error("CTxMemPool::accept() : IV5 pool flow rejected: %s",
                                 strFlowError.c_str());
                }
                if (nReleased > MAX_MONEY - nFees)
                    return error("CTxMemPool::accept() : IV5 released value overflow");
                nFees += nReleased;
                nFees -= nAbsorbed;
                if (nFees < 0)
                    return error("CTxMemPool::accept() : IV5 transaction does not cover its pool flow");
            }

            GetMinFee_mode feeMode = GMF_RELAY;

            if (tx.nVersion == ANON_TXN_VERSION)
            {
                if (nEffectiveMempoolHeight >=
                        FORK_HEIGHT_RINGSIG_DEPRECATION)
                    return error("CTxMemPool::accept() : ring signature transactions (ANON_TXN_VERSION) deprecated after height %d. Use shielded transactions.", FORK_HEIGHT_RINGSIG_DEPRECATION);

                if (!tx.CheckAnonInputs(
                        txdb, nEffectiveMempoolHeight,
                        nValidatedAnonValueIn, fInvalid, true, NULL,
                        &vAnonRelayKeyImages))
                {
                    if (fInvalid)
                        return error("CTxMemPool::accept() : CheckAnonInputs found invalid tx %s", hash.ToString().substr(0,10).c_str());
                    if (pfMissingInputs)
                        *pfMissingInputs = true;
                    return false;
                };

                if (nValidatedAnonValueIn < 0 ||
                    nFees > MAX_MONEY - nValidatedAnonValueIn)
                    return error("CTxMemPool::accept() : anonymous input value overflow");
                nFees += nValidatedAnonValueIn;

                feeMode = GMF_ANON;
            };

            if (tx.IsShielded())
            {
                if (pindexBest && pindexBest->nHeight < FORK_HEIGHT_SHIELDED)
                    return error("CTxMemPool::accept() : shielded tx rejected before fork height %d", FORK_HEIGHT_SHIELDED);

                const bool fStrictV3Anchors =
                    nEffectiveMempoolHeight >= FORK_HEIGHT_EPOCH_STATE_V3;

                for (const CShieldedSpendDescription& spend : tx.vShieldedSpend)
                {
                    CShieldedNullifierSpent nfs;
                    if (txdb.ReadShieldedNullifier(spend.nullifier, nfs))
                        return error("CTxMemPool::accept() : shielded nullifier %s already spent",
                                     spend.nullifier.ToString().substr(0,10).c_str());

                    CShieldedNullifierSpent nfsMem;
                    if (lookupShieldedNullifier(spend.nullifier, nfsMem))
                        return error("CTxMemPool::accept() : shielded nullifier %s already in mempool",
                                     spend.nullifier.ToString().substr(0,10).c_str());

                    int nAnchorHeight = 0;
                    if (fStrictV3Anchors)
                    {
                        const TxDBReadStatus anchorStatus =
                            txdb.ReadShieldedAnchorStatus(spend.anchor);
                        if (anchorStatus == TXDB_READ_ERROR)
                            return error("CTxMemPool::accept() : shielded anchor %s record is corrupt/unreadable; -reindex/resync required",
                                         spend.anchor.ToString().substr(0,10).c_str());
                        if (anchorStatus == TXDB_READ_NOT_FOUND)
                            return error("CTxMemPool::accept() : shielded anchor %s not found",
                                         spend.anchor.ToString().substr(0,10).c_str());
                        if (txdb.ReadShieldedAnchorHeightStatus(
                                spend.anchor, nAnchorHeight) != TXDB_READ_FOUND ||
                            nAnchorHeight < FORK_HEIGHT_SHIELDED ||
                            nAnchorHeight > nBestHeight)
                            return error("CTxMemPool::accept() : shielded anchor %s height is missing/corrupt; -reindex/resync required",
                                         spend.anchor.ToString().substr(0,10).c_str());
                        if (nBestHeight - nAnchorHeight < MIN_SHIELDED_SPEND_DEPTH)
                            return error("CTxMemPool::accept() : shielded anchor %s too recent (height=%d, need %d confirmations)",
                                         spend.anchor.ToString().substr(0,10).c_str(),
                                         nAnchorHeight, MIN_SHIELDED_SPEND_DEPTH);
                    }
                    else
                    {
                        if (!txdb.ReadShieldedAnchor(spend.anchor))
                            return error("CTxMemPool::accept() : shielded anchor %s not found",
                                         spend.anchor.ToString().substr(0,10).c_str());
                        if (txdb.ReadShieldedAnchorHeight(spend.anchor,
                                                         nAnchorHeight) &&
                            nBestHeight - nAnchorHeight < MIN_SHIELDED_SPEND_DEPTH)
                            return error("CTxMemPool::accept() : shielded anchor %s too recent (height=%d, need %d confirmations)",
                                         spend.anchor.ToString().substr(0,10).c_str(),
                                         nAnchorHeight, MIN_SHIELDED_SPEND_DEPTH);
                    }
                }

                int64_t nTransparentIn = tx.GetValueIn(mapInputs);
                int64_t nTransparentOut = tx.GetValueOut();

                int64_t nEffectiveIn = nTransparentIn;
                if (tx.nValueBalance > 0)
                {
                    if (nEffectiveIn > MAX_MONEY - tx.nValueBalance)
                        return error("CTxMemPool::accept() : nEffectiveIn overflow");
                    nEffectiveIn += tx.nValueBalance;
                }

                int64_t nEffectiveOut = nTransparentOut;
                if (tx.nValueBalance < 0)
                {
                    if (tx.nValueBalance == std::numeric_limits<int64_t>::min())
                        return error("CTxMemPool::accept() : nValueBalance is INT64_MIN");
                    int64_t nAbsBalance = -tx.nValueBalance;
                    if (nEffectiveOut > MAX_MONEY - nAbsBalance)
                        return error("CTxMemPool::accept() : nEffectiveOut overflow");
                    nEffectiveOut += nAbsBalance;
                }

                if (nEffectiveIn < nEffectiveOut)
                    return error("CTxMemPool::accept() : shielded value balance mismatch (in=%" PRId64 " out=%" PRId64 ")",
                                 nEffectiveIn, nEffectiveOut);

                nFees = nEffectiveIn - nEffectiveOut;

                if (!CZKContext::IsInitialized())
                    return error("CTxMemPool::accept() : ZK context not initialized, cannot validate shielded tx");

                {
                    uint256 sighash = tx.GetBindingSigHash();

                    bool fHideAmount   = tx.IsDSP() ? DSP_HideAmount(tx.nPrivacyMode)   : true;
                    bool fHideSender   = tx.IsDSP() ? DSP_HideSender(tx.nPrivacyMode)   : true;

                    if (nBestHeight >= FORK_HEIGHT_FCMP_VALIDATION && !tx.vShieldedSpend.empty()
                        && tx.nVersion < SHIELDED_TX_VERSION_FCMP)
                    {
                        return error("CTxMemPool::accept() : tx version %d with shielded spends rejected after FCMP fork (need version >= %d)",
                                     tx.nVersion, SHIELDED_TX_VERSION_FCMP);
                    }

                    for (size_t i = 0; i < tx.vShieldedSpend.size(); i++)
                    {
                        // An owner reclaim (2007) spends a 3-generator cv3 leaf; its value proofs verify over
                        // cv_plain = cv3 - D*J, as in ConnectInputs. Other spends use the raw commitment. The
                        // reclaim gates are still enforced by ConnectInputs.
                        CPedersenCommitment cvSpendValue;
                        if (!MofNSpendValueCommitment(tx, i, false, cvSpendValue))
                            return error("CTxMemPool::accept() : shielded spend %d value commitment derivation failed", (int)i);

                        if (fHideAmount)
                        {
                            if (!VerifyBulletproofRangeProof(cvSpendValue, tx.vShieldedSpend[i].rangeProof))
                                return error("CTxMemPool::accept() : shielded spend %d range proof failed", (int)i);
                        }
                        else
                        {
                            if (!VerifyPedersenCommitment(tx.vShieldedSpend[i].cv,
                                                           tx.vShieldedSpend[i].nPlaintextValue,
                                                           tx.vShieldedSpend[i].vchPlaintextBlind))
                                return error("CTxMemPool::accept() : DSP spend %d commitment opening proof failed", (int)i);
                        }

                        if (tx.vShieldedSpend[i].vchSpendAuthSig.empty() || tx.vShieldedSpend[i].vchRk.empty())
                            return error("CTxMemPool::accept() : shielded spend %d missing spend auth signature or rk", (int)i);

                        if (!VerifySpendAuthSignature(tx.vShieldedSpend[i].vchRk, sighash, tx.vShieldedSpend[i].vchSpendAuthSig))
                            return error("CTxMemPool::accept() : shielded spend %d spend auth signature failed", (int)i);

                        if (fHideSender)
                        {
                            if (tx.vShieldedSpend[i].vchLelantusProof.empty() || tx.vShieldedSpend[i].vAnonSet.empty())
                                return error("CTxMemPool::accept() : shielded spend %d missing mandatory Lelantus proof", (int)i);

                            if ((int)tx.vShieldedSpend[i].vAnonSet.size() < LELANTUS_MIN_SET_SIZE)
                                return error("CTxMemPool::accept() : shielded spend %d anonymity set size %d below minimum %d",
                                             (int)i, (int)tx.vShieldedSpend[i].vAnonSet.size(), LELANTUS_MIN_SET_SIZE);

                            {
                                {
                                    CTxDB txdb("r");
                                    std::string strAnonSetError;
                                    if (!CheckShieldedAnonSetChainState(
                                            txdb,
                                            tx.vShieldedSpend[i].vAnonSet,
                                            strAnonSetError))
                                        return error("CTxMemPool::accept() : shielded spend %d %s",
                                                     (int)i, strAnonSetError.c_str());
                                }

                                CAnonymitySet anonSet;
                                anonSet.vCommitments = tx.vShieldedSpend[i].vAnonSet;
                                CLelantusProof proof;
                                proof.vchProof = tx.vShieldedSpend[i].vchLelantusProof;
                                proof.serialNumber = tx.vShieldedSpend[i].lelantusSerial;

                                if (!VerifyLelantusProof(anonSet, proof, tx.vShieldedSpend[i].cv))
                                    return error("CTxMemPool::accept() : shielded spend %d Lelantus proof failed", (int)i);
                            }
                        }

                        // FCMP path proofs are unverifiable; such a spend is never relayable.
                        if (tx.nVersion >= SHIELDED_TX_VERSION_FCMP && nBestHeight >= FORK_HEIGHT_FCMP_VALIDATION)
                            return error("CTxMemPool::accept() : shielded spend %d FCMP-era membership is unverifiable; the encoding is permanently invalid", (int)i);

                        // Nullifier binding, mirrored from ConnectInputs so an
                        // unbound spend is dropped before relay. Gate on the
                        // height the tx would confirm at (next block).
                        if (nBestHeight + 1 >= FORK_HEIGHT_NULLIFIER_BINDING)
                        {
                            const CShieldedSpendDescription& sp = tx.vShieldedSpend[i];
                            if (sp.vchNullifierPoint.size() != NULLIFIER_POINT_SIZE ||
                                sp.vchNullifierBindingProof.size() != NULLIFIER_BINDING_PROOF_SIZE)
                                return error("CTxMemPool::accept() : shielded spend %d missing nullifier binding proof (required post-fork)", (int)i);
                            if (sp.nullifier != NullifierTagFromPoint(sp.vchNullifierPoint))
                                return error("CTxMemPool::accept() : shielded spend %d nullifier does not match bound note", (int)i);
                            if (!VerifyNullifierBindingProof(cvSpendValue, sp.vchNullifierPoint, sighash, sp.vchNullifierBindingProof, nBestHeight + 1))
                                return error("CTxMemPool::accept() : shielded spend %d nullifier binding proof failed", (int)i);
                        }

                        if (fDebug)
                            printf("CTxMemPool::accept() : spend %d passed all checks\n", (int)i);
                    }

                    if (fDebug)
                        printf("CTxMemPool::accept() : verifying output proofs\n");
                    for (size_t i = 0; i < tx.vShieldedOutput.size(); i++)
                    {
                        bool fIsMofN = false; std::string strMofN;
                        if (!CheckMofNMintOutput(tx, i, fHideAmount, nBestHeight + 1, fIsMofN, strMofN))
                            return error("CTxMemPool::accept() : shielded output %d: %s", (int)i, strMofN.c_str());
                        if (fIsMofN)
                            continue;   // value bound by range-over-Vv + the (G,J) link (CheckMofNMintOutput)
                        if (fHideAmount)
                        {
                            if (!VerifyBulletproofRangeProof(tx.vShieldedOutput[i].cv, tx.vShieldedOutput[i].rangeProof))
                                return error("CTxMemPool::accept() : shielded output %d range proof failed", (int)i);
                        }
                        else
                        {
                            if (!VerifyPedersenCommitment(tx.vShieldedOutput[i].cv,
                                                           tx.vShieldedOutput[i].nPlaintextValue,
                                                           tx.vShieldedOutput[i].vchPlaintextBlind))
                                return error("CTxMemPool::accept() : DSP output %d commitment opening proof failed", (int)i);
                        }
                    }

                    if (!fHideAmount)
                    {
                        int64_t nPlainIn = 0, nPlainOut = 0;
                        for (size_t i = 0; i < tx.vShieldedSpend.size(); i++)
                            nPlainIn += tx.vShieldedSpend[i].nPlaintextValue;
                        for (size_t i = 0; i < tx.vShieldedOutput.size(); i++)
                            nPlainOut += tx.vShieldedOutput[i].nPlaintextValue;
                        if (nPlainIn - nPlainOut != tx.nValueBalance)
                            return error("CTxMemPool::accept() : DSP plaintext value balance mismatch (in=%" PRId64 " out=%" PRId64 " balance=%" PRId64 ")",
                                         nPlainIn, nPlainOut, tx.nValueBalance);
                    }

                    if (fDebug)
                        printf("CTxMemPool::accept() : output proofs passed\n");

                    if (tx.bindingSig.IsNull())
                        return error("CTxMemPool::accept() : shielded tx missing mandatory binding signature");

                    {
                        std::vector<CPedersenCommitment> vInCommits, vOutCommits;
                        for (size_t i = 0; i < tx.vShieldedSpend.size(); i++)
                        {
                            CPedersenCommitment cvIn;   // cv_plain for a 2007 reclaim spend[0] (mirror ConnectInputs); cv otherwise
                            if (!MofNSpendValueCommitment(tx, i, false, cvIn))
                                return error("CTxMemPool::accept() : shielded spend %d value commitment derivation failed", (int)i);
                            vInCommits.push_back(cvIn);
                        }
                        for (size_t i = 0; i < tx.vShieldedOutput.size(); i++)
                        {
                            CPedersenCommitment cvOut;   // Vv for a 2006 M-of-N mint output (INV-1); cv otherwise
                            if (!MofNOutputBindingCommitment(tx, i, false, cvOut))
                                return error("CTxMemPool::accept() : M-of-N output %d value commitment derivation failed", (int)i);
                            vOutCommits.push_back(cvOut);
                        }

                        if (!VerifyBindingSignature(vInCommits, vOutCommits, tx.nValueBalance, sighash, tx.bindingSig.bindingSig))
                            return error("CTxMemPool::accept() : shielded binding signature verification failed");
                    }
                }
            };

            // Note: if you modify this code to accept non-standard transactions, then
            // you should add code here to check that the transaction does a
            // reasonable number of ECDSA signature verifications.

            unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            // Don't accept it if it can't get into a block

            int64_t txMinFee = tx.GetMinFee(1000, feeMode, nSize);

            const bool fFeeExempt = nFees == 0 && IsPrivacyVNextFeeExemptShape(tx);

            // The name rate replaces the ordinary minimum only for the ops that
            // owe it, and only once the tx is shown to have paid it.
            bool fPaidNameFee = false;
            if (isNameTx)
            {
                string strFeeReason;
                if (!hooks->CheckNameTxFee(tx, nFees, fPaidNameFee, strFeeReason))
                    return error("CTxMemPool::accept() : name transaction %s rejected: %s",
                                 hash.ToString().substr(0,10).c_str(),
                                 strFeeReason.c_str());
            }

            if (nFees < txMinFee && !fPaidNameFee && !fFeeExempt)
            {
                return error("CTxMemPool::accept() : not enough fees %s, %" PRId64" < %" PRId64,
                             hash.ToString().c_str(),
                             nFees, txMinFee);
            };

            // Continuously rate-limit free transactions
            // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
            // be annoying or make others' transactions take longer to confirm.
            if (nFees < MIN_RELAY_TX_FEE)
            {
                static CCriticalSection cs;
                static double dFreeCount;
                static int64_t nLastTime;
                int64_t nNow = GetTime();

                {
                    LOCK(cs);
                    // Use an exponentially decaying ~10-minute window:
                    dFreeCount *= pow(1.0 - 1.0/600.0, (double)(nNow - nLastTime));
                    nLastTime = nNow;
                    // -limitfreerelay unit is thousand-bytes-per-minute
                    // At default rate it would take over a month to fill 1GB
                    if (dFreeCount > GetArg("-limitfreerelay", 15)*10*1000 && !IsFromMe(tx))
                        return error("CTxMemPool::accept() : free transaction rejected by rate limiter");
                    if (fDebug)
                        printf("Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
                    dFreeCount += nSize;
                }
            };

            // Check against previous transactions
            // This is done last to help prevent CPU exhaustion denial-of-service attacks.
            printf("CTxMemPool::accept() : calling ConnectInputs for %s\n", hash.ToString().substr(0,10).c_str());
            const bool fAnonPrevalidated =
                tx.nVersion == ANON_TXN_VERSION;
            if (!tx.ConnectInputs(
                    txdb, mapInputs, mapUnused, CDiskTxPos(1,1,1),
                    pindexBest, false, false, STANDARD_SCRIPT_VERIFY_FLAGS,
                    true, false, fAnonPrevalidated,
                    nEffectiveMempoolHeight, nValidatedAnonValueIn))
            {
                return error("CTxMemPool::accept() : ConnectInputs failed %s", hash.ToString().substr(0,10).c_str());
            };
        };

    // Do not write to memory if read only mode.
    if(!fOnlyCheckWithoutAdding)
    {
        // Store transaction in memory
        {
            LOCK(cs);
            if (ptxOld) {
                printf("CTxMemPool::accept() : replacing tx %s with new version\n", ptxOld->GetHash().ToString().c_str());
                remove(*ptxOld);
            }

            if (tx.IsPrivacyVNext())
                EvictPrivacyVNextAttestationsSpentBy(vPrivacyVNextKeyImages, hash);

            addUnchecked(hash, tx);

            if (tx.IsPrivacyVNext())
            {
                mapPrivacyVNextTxNullifiers[hash] = vPrivacyVNextKeyImages;
                for (size_t i = 0; i < vPrivacyVNextKeyImages.size(); ++i)
                {
                    CShieldedNullifierSpent spent;
                    spent.txnHash = hash;
                    spent.nIndex = i;
                    mapPrivacyVNextNullifier[vPrivacyVNextKeyImages[i]] = spent;
                }
                mapPrivacyVNextTxOutputBases[hash] = vPrivacyVNextOutputBases;
                for (size_t i = 0; i < vPrivacyVNextOutputBases.size(); ++i)
                {
                    CShieldedNullifierSpent created;
                    created.txnHash = hash;
                    created.nIndex = i;
                    mapPrivacyVNextOutputBase[vPrivacyVNextOutputBases[i]] = created;
                }
                mapPrivacyVNextTxAttestations[hash] = vPrivacyVNextAttestations;
                for (size_t i = 0; i < vPrivacyVNextAttestations.size(); ++i)
                {
                    CShieldedNullifierSpent attested;
                    attested.txnHash = hash;
                    attested.nIndex = i;
                    mapPrivacyVNextAttestation[vPrivacyVNextAttestations[i]] = attested;
                }
            }

            if (tx.nVersion == ANON_TXN_VERSION)
            {
                for (std::vector<std::pair<ec_point, CKeyImageSpent> >::const_iterator it =
                         vAnonRelayKeyImages.begin();
                     it != vAnonRelayKeyImages.end(); ++it)
                    mapKeyImage[it->first] = it->second;
            }

            if (tx.IsShielded())
            {
                for (unsigned int i = 0; i < tx.vShieldedSpend.size(); i++)
                {
                    CShieldedNullifierSpent nfs;
                    nfs.txnHash = hash;
                    nfs.nIndex = i;
                    insertShieldedNullifier(tx.vShieldedSpend[i].nullifier, nfs);
                }
            }

            //Add the TX to our Pending Names in Name DB
            hooks->AddToPendingNames(tx);
        }

        ///// are we sure this is ok when loading transactions or restoring block txes
        // If updated, erase old tx from wallet
        if (ptxOld)
            EraseFromWallets(ptxOld->GetHash());

        printf("CTxMemPool::accept() : accepted %s (poolsz %" PRIszu")\n", hash.ToString().substr(0,10).c_str(), mapTx.size());
    }
    return true;
}

bool CTransaction::AcceptToMemoryPool(CTxDB& txdb,  bool fCheckInputs, bool* pfMissingInputs, bool fOnlyCheckWithoutAdding)
{
    return mempool.accept(txdb, *this, fCheckInputs, pfMissingInputs, fOnlyCheckWithoutAdding);
}

bool AcceptableInputs(CTxMemPool& pool, const CTransaction &txo, bool fLimitFree,
                        bool* pfMissingInputs)
{
    AssertLockHeld(cs_main);
    if (pfMissingInputs)
        *pfMissingInputs = false;

    CTransaction tx(txo);

    if (!tx.CheckTransaction())
        return error("AcceptableInputs : CheckTransaction failed");

    if (tx.IsShielded())
        return error("AcceptableInputs : shielded transactions require full validation");

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return tx.DoS(100, error("AcceptableInputs : coinbase as individual tx"));

    // ppcoin: coinstake is also only valid in a block, not as a loose transaction
    if (tx.IsCoinStake())
        return tx.DoS(100, error("AcceptableInputs : coinstake as individual tx"));

    // Rather not work on nonstandard transactions (unless -testnet)
    string reason;
    if (false && !fTestNet && !IsStandardTx(tx, reason))
        return error("AcceptableInputs : nonstandard transaction");

    // is it already in the memory pool?
    uint256 hash = tx.GetHash();
    if (pool.exists(hash))
        return false;

    // Check for conflicts with in-memory transactions
    {
    LOCK(pool.cs); // protect pool.mapNextTx
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        COutPoint outpoint = tx.vin[i].prevout;
        if (pool.mapNextTx.count(outpoint))
        {
            // Disable replacement feature for now
            return false;
        }
    }
    }

    {
        CTxDB txdb("r");

        // do we already have it?
        if (txdb.ContainsTx(hash))
            return false;

        MapPrevTx mapInputs;
        map<uint256, CTxIndex> mapUnused;
        bool fInvalid = false;
        if (!tx.FetchInputs(txdb, mapUnused, false, false, mapInputs, fInvalid))
        {
            if (fInvalid)
            {
                if (fDebugNet)
                    return error("AcceptableInputs : FetchInputs found invalid tx %s",
                                 hash.ToString().substr(0,10).c_str());
                return false;
            }
            if (pfMissingInputs)
                *pfMissingInputs = true;
            return false;
        }

        // Check for non-standard pay-to-script-hash in inputs
        //if (!fTestNet() && !tx.AreInputsStandard(mapInputs))
          //  return error("AcceptToMemoryPool : nonstandard transaction input");

	    // Check that the transaction doesn't have an excessive number of
        // sigops, making it impossible to mine. Since the coinbase transaction
        // itself can contain sigops MAX_TX_SIGOPS is less than
        // MAX_BLOCK_SIGOPS; we still consider this an invalid rather than
        // merely non-standard transaction.
	    unsigned int nSigOps = tx.GetLegacySigOpCount();
	    nSigOps += tx.GetP2SHSigOpCount(mapInputs);
        if (nSigOps > MAX_TX_SIGOPS)
            return tx.DoS(0,
                          error("AcceptToMemoryPool : too many sigops %s, %d > %d",
                                hash.ToString().c_str(), nSigOps, MAX_TX_SIGOPS));

        int64_t nFees = tx.GetValueIn(mapInputs)-tx.GetValueOut();
        unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);

        // Don't accept it if it can't get into a block
        int64_t txMinFee = tx.GetMinFee(1000, GMF_RELAY, nSize);
        if ((fLimitFree && nFees < txMinFee) || (!fLimitFree && nFees < MIN_TX_FEE))
            return error("AcceptableInputs : not enough fees %s, %ld < %ld",
                         hash.ToString().c_str(),
                         nFees, txMinFee);

        // Continuously rate-limit free transactions
        // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
        // be annoying or make others' transactions take longer to confirm.
        if (fLimitFree && nFees < MIN_RELAY_TX_FEE)
        {
            static CCriticalSection csFreeLimiter;
            static double dFreeCount;
            static int64_t nLastTime;
            int64_t nNow = GetTime();

            LOCK(csFreeLimiter);

            // Use an exponentially decaying ~10-minute window:
            dFreeCount *= pow(1.0 - 1.0/600.0, (double)(nNow - nLastTime));
            nLastTime = nNow;
            // -limitfreerelay unit is thousand-bytes-per-minute
            // At default rate it would take over a month to fill 1GB
            if (dFreeCount > GetArg("-limitfreerelay", 15)*10*1000)
                return error("AcceptableInputs : free transaction rejected by rate limiter");
            printf("mempool: Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
            dFreeCount += nSize;
        }

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        const int nCandidateHeight =
            nBestHeight == std::numeric_limits<int>::max()
                ? nBestHeight : nBestHeight + 1;
        if (!tx.ConnectInputs(
                txdb, mapInputs, mapUnused, CDiskTxPos(1,1,1),
                pindexBest, true, false, STANDARD_SCRIPT_VERIFY_FLAGS,
                false, false, false, nCandidateHeight, 0))
        {
            return error("AcceptableInputs : ConnectInputs failed %s", hash.ToString().c_str());
        }
    }

	//Minimize debug spam
    if (fDebug) {
        printf("mempool: AcceptableInputs : accepted %s (poolsz %lu)\n",
               hash.ToString().substr(0,10).c_str(),
               pool.mapTx.size());
    }
    return true;
}

int GetInputAge(CTxIn& vin, CBlockIndex* pindex)
{
    const uint256& prevHash = vin.prevout.hash;
    CTransaction tx;
    uint256 hashBlock;
    bool fFound = GetTransaction(prevHash, tx, hashBlock);
    if(fFound)
    {
    if(mapBlockIndex.find(hashBlock) != mapBlockIndex.end())
    {
        return pindex->nHeight - mapBlockIndex[hashBlock]->nHeight;
    }
    else
        return 0;
    }
    else
        return 0;
}

unsigned int CTxMemPool::GetTransactionsUpdated() const
{
    LOCK(cs);
    return nTransactionsUpdated;
}

void CTxMemPool::AddTransactionsUpdated(unsigned int n)
{
    LOCK(cs);
    nTransactionsUpdated += n;
}

bool CTxMemPool::addUnchecked(const uint256& hash, CTransaction &tx)
{
    // Add to memory pool without checking anything.  Don't call this directly,
    // call CTxMemPool::accept to properly check the transaction first.
    {
        mapTx[hash] = tx;
        for (unsigned int i = 0; i < tx.vin.size(); i++)
            mapNextTx[tx.vin[i].prevout] = CInPoint(&mapTx[hash], i);
        nTransactionsUpdated++;
    }
    return true;
}


bool CTxMemPool::HasPendingPrivacyVNextSpend(const uint256& keyImage) const
{
    LOCK(cs);
    return mapPrivacyVNextNullifier.count(keyImage) != 0;
}

// An attestation is only ever refused or dropped for a spend, never the other way
// round: the spend is an ordinary transaction consensus does not delay, and it is
// itself the deregistration.
size_t CTxMemPool::EvictPrivacyVNextAttestationsSpentBy(
    const std::vector<uint256>& vKeyImages, const uint256& hashSpend)
{
    LOCK(cs);
    std::set<uint256> setDoomed;
    for (size_t i = 0; i < vKeyImages.size(); ++i)
    {
        std::map<uint256, CShieldedNullifierSpent>::const_iterator attIt =
            mapPrivacyVNextAttestation.find(vKeyImages[i]);
        if (attIt != mapPrivacyVNextAttestation.end())
            setDoomed.insert(attIt->second.txnHash);
    }

    size_t nRemoved = 0;
    for (std::set<uint256>::const_iterator it = setDoomed.begin();
         it != setDoomed.end(); ++it)
    {
        std::map<uint256, CTransaction>::const_iterator txIt = mapTx.find(*it);
        if (txIt == mapTx.end())
            continue;
        // remove() erases the map entry and then reads the transaction it was handed,
        // so it must not be the one still living in the map.
        const CTransaction doomed = txIt->second;
        printf("CTxMemPool: dropping IV5 attestation %s; %s spends the collateral it "
               "names\n", it->ToString().substr(0,10).c_str(),
               hashSpend.ToString().substr(0,10).c_str());
        if (remove(doomed))
            nRemoved++;
    }
    return nRemoved;
}

bool CTxMemPool::remove(const CTransaction &tx, bool fRecursive)
{
    // Remove transaction from memory pool
    {
        LOCK(cs);
        uint256 hash = tx.GetHash();
        if (mapTx.count(hash))
        {
            if (fRecursive)
            {
                for (unsigned int i = 0; i < tx.vout.size(); i++)
                {
                    std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(COutPoint(hash, i));
                    if (it != mapNextTx.end())
                        remove(*it->second.ptx, true);
                };
            };
            for (const CTxIn& txin : tx.vin)
                mapNextTx.erase(txin.prevout);
            mapTx.erase(hash);

            if (tx.nVersion == ANON_TXN_VERSION)
            {
                // -- remove key images
                for (unsigned int i = 0; i < tx.vin.size(); ++i)
                {
                    const CTxIn& txin = tx.vin[i];

                    if (!txin.IsAnonInput())
                        continue;

                    ec_point vchImage;
                    txin.ExtractKeyImage(vchImage);

                    mapKeyImage.erase(vchImage);
                };
            };

            if (tx.IsShielded())
            {
                for (const CShieldedSpendDescription& spend : tx.vShieldedSpend)
                {
                    removeShieldedNullifier(spend.nullifier);
                }
            };

            if (tx.IsPrivacyVNext())
            {
                std::map<uint256, std::vector<uint256> >::iterator reverseIt =
                    mapPrivacyVNextTxNullifiers.find(hash);
                if (reverseIt == mapPrivacyVNextTxNullifiers.end())
                {
                    StartShutdown();
                    printf("CTxMemPool::remove: missing IV5 reverse reservation for %s\n",
                           hash.ToString().substr(0,10).c_str());
                }
                else
                {
                    for (std::vector<uint256>::const_iterator it =
                             reverseIt->second.begin();
                         it != reverseIt->second.end(); ++it)
                    {
                        std::map<uint256, CShieldedNullifierSpent>::iterator spentIt =
                            mapPrivacyVNextNullifier.find(*it);
                        if (spentIt == mapPrivacyVNextNullifier.end() ||
                            spentIt->second.txnHash != hash)
                        {
                            StartShutdown();
                            printf("CTxMemPool::remove: mismatched IV5 reservation %s for %s\n",
                                   it->ToString().substr(0,10).c_str(),
                                   hash.ToString().substr(0,10).c_str());
                            continue;
                        }
                        mapPrivacyVNextNullifier.erase(spentIt);
                    }
                    mapPrivacyVNextTxNullifiers.erase(reverseIt);
                }

                std::map<uint256, std::vector<uint256> >::iterator baseReverseIt =
                    mapPrivacyVNextTxOutputBases.find(hash);
                if (baseReverseIt == mapPrivacyVNextTxOutputBases.end())
                {
                    StartShutdown();
                    printf("CTxMemPool::remove: missing IV5 output-base reservation for %s\n",
                           hash.ToString().substr(0,10).c_str());
                }
                else
                {
                    for (std::vector<uint256>::const_iterator it =
                             baseReverseIt->second.begin();
                         it != baseReverseIt->second.end(); ++it)
                    {
                        std::map<uint256, CShieldedNullifierSpent>::iterator baseIt =
                            mapPrivacyVNextOutputBase.find(*it);
                        if (baseIt == mapPrivacyVNextOutputBase.end() ||
                            baseIt->second.txnHash != hash)
                        {
                            StartShutdown();
                            printf("CTxMemPool::remove: mismatched IV5 output-base reservation %s for %s\n",
                                   it->ToString().substr(0,10).c_str(),
                                   hash.ToString().substr(0,10).c_str());
                            continue;
                        }
                        mapPrivacyVNextOutputBase.erase(baseIt);
                    }
                    mapPrivacyVNextTxOutputBases.erase(baseReverseIt);
                }

                std::map<uint256, std::vector<uint256> >::iterator attReverseIt =
                    mapPrivacyVNextTxAttestations.find(hash);
                if (attReverseIt == mapPrivacyVNextTxAttestations.end())
                {
                    StartShutdown();
                    printf("CTxMemPool::remove: missing IV5 attestation reservation for %s\n",
                           hash.ToString().substr(0,10).c_str());
                }
                else
                {
                    for (std::vector<uint256>::const_iterator it =
                             attReverseIt->second.begin();
                         it != attReverseIt->second.end(); ++it)
                    {
                        std::map<uint256, CShieldedNullifierSpent>::iterator attIt =
                            mapPrivacyVNextAttestation.find(*it);
                        if (attIt == mapPrivacyVNextAttestation.end() ||
                            attIt->second.txnHash != hash)
                        {
                            StartShutdown();
                            printf("CTxMemPool::remove: mismatched IV5 attestation reservation %s for %s\n",
                                   it->ToString().substr(0,10).c_str(),
                                   hash.ToString().substr(0,10).c_str());
                            continue;
                        }
                        mapPrivacyVNextAttestation.erase(attIt);
                    }
                    mapPrivacyVNextTxAttestations.erase(attReverseIt);
                }
            }

            nTransactionsUpdated++;
        };
    }
    return true;
}

bool CTxMemPool::removeConflicts(const CTransaction &tx)
{
    // Remove transactions which depend on inputs of tx, recursively
    LOCK(cs);
    for (const CTxIn &txin : tx.vin) {
        std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(txin.prevout);
        if (it != mapNextTx.end()) {
            const CTransaction &txConflict = *it->second.ptx;
            if (txConflict != tx)
                remove(txConflict, true);
        }
    }

    if (tx.IsShielded())
    {
        for (const CShieldedSpendDescription& spend : tx.vShieldedSpend)
        {
            for (std::map<uint256, CTransaction>::iterator mi = mapTx.begin(); mi != mapTx.end(); )
            {
                const CTransaction& txPool = mi->second;
                if (txPool.GetHash() == tx.GetHash()) { ++mi; continue; }
                if (!txPool.IsShielded()) { ++mi; continue; }

                bool fConflict = false;
                for (const CShieldedSpendDescription& poolSpend : txPool.vShieldedSpend)
                {
                    if (poolSpend.nullifier == spend.nullifier)
                    {
                        fConflict = true;
                        break;
                    }
                }
                if (fConflict)
                {
                    CTransaction txToRemove = txPool;
                    ++mi;
                    remove(txToRemove, true);
                }
                else
                {
                    ++mi;
                }
            }
        }
    }

    if (tx.IsPrivacyVNext())
    {
        PrivacyVNextStateEffects effects;
        const PrivacyVNextPayloadValidation validation =
            ExtractPrivacyVNextPayloadEffects(
                static_cast<uint32_t>(tx.nVersion),
                tx.privacyVNext.vchPayload, effects);
        if (!validation.IsValid())
        {
            StartShutdown();
            return error("CTxMemPool::removeConflicts: accepted IV5 payload cannot be decoded");
        }
        for (size_t i = 0; i < effects.keyImages.size(); ++i)
        {
            uint256 keyImage;
            memcpy(keyImage.begin(), effects.keyImages[i].data(),
                   effects.keyImages[i].size());
            std::map<uint256, CShieldedNullifierSpent>::const_iterator spentIt =
                mapPrivacyVNextNullifier.find(keyImage);
            if (spentIt == mapPrivacyVNextNullifier.end() ||
                spentIt->second.txnHash == tx.GetHash())
                continue;
            std::map<uint256, CTransaction>::const_iterator txIt =
                mapTx.find(spentIt->second.txnHash);
            if (txIt != mapTx.end())
            {
                const CTransaction txToRemove = txIt->second;
                remove(txToRemove, true);
            }
        }
        // A spend of an attested note is legitimate and simply deregisters the node,
        // but a second attestation of the same note is not, so only a pending
        // attestation is evicted here and never a pending spend.
        for (size_t i = 0; i < effects.attestationKeyImages.size(); ++i)
        {
            uint256 keyImage;
            memcpy(keyImage.begin(), effects.attestationKeyImages[i].data(),
                   effects.attestationKeyImages[i].size());
            std::map<uint256, CShieldedNullifierSpent>::const_iterator attIt =
                mapPrivacyVNextAttestation.find(keyImage);
            if (attIt == mapPrivacyVNextAttestation.end() ||
                attIt->second.txnHash == tx.GetHash())
                continue;
            std::map<uint256, CTransaction>::const_iterator txIt =
                mapTx.find(attIt->second.txnHash);
            if (txIt != mapTx.end())
            {
                const CTransaction txToRemove = txIt->second;
                remove(txToRemove, true);
            }
        }
        for (size_t i = 0; i < effects.outputLeaves.size(); ++i)
        {
            uint256 base;
            memcpy(base.begin(), effects.outputLeaves[i].nullifierBase.data(),
                   effects.outputLeaves[i].nullifierBase.size());
            std::map<uint256, CShieldedNullifierSpent>::const_iterator baseIt =
                mapPrivacyVNextOutputBase.find(base);
            if (baseIt == mapPrivacyVNextOutputBase.end() ||
                baseIt->second.txnHash == tx.GetHash())
                continue;
            std::map<uint256, CTransaction>::const_iterator txIt =
                mapTx.find(baseIt->second.txnHash);
            if (txIt != mapTx.end())
            {
                const CTransaction txToRemove = txIt->second;
                remove(txToRemove, true);
            }
        }
    }

    return true;
}

// Remove mempool transactions that appear in a DAG sibling block
void CTxMemPool::RemoveDAGConflicts(const uint256& hashBlock)
{
    CBlock block;
    std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return;

    if (!block.ReadFromDisk(mi->second))
        return;

    LOCK(cs);

    // Cap setDAGSeenTxids to prevent unbounded memory growth
    static const size_t MAX_DAG_SEEN_TXIDS = 100000;
    if (setDAGSeenTxids.size() > MAX_DAG_SEEN_TXIDS)
        setDAGSeenTxids.clear(); // periodic reset when cap exceeded

    int nRemoved = 0;
    for (const CTransaction& tx : block.vtx)
    {
        uint256 txHash = tx.GetHash();
        setDAGSeenTxids.insert(txHash);

        if (mapTx.count(txHash))
        {
            // Full cleanup: mapTx, mapNextTx, mapShieldedNullifier
            CTransaction txCopy = mapTx[txHash];

            for (const CTxIn& txin : txCopy.vin)
                mapNextTx.erase(txin.prevout);

            // Clean up shielded nullifiers
            for (const CShieldedSpendDescription& spend : txCopy.vShieldedSpend)
                mapShieldedNullifier.erase(spend.nullifier);

            std::map<uint256, std::vector<uint256> >::iterator reverseIt =
                mapPrivacyVNextTxNullifiers.find(txHash);
            if (reverseIt != mapPrivacyVNextTxNullifiers.end())
            {
                for (std::vector<uint256>::const_iterator it =
                         reverseIt->second.begin();
                     it != reverseIt->second.end(); ++it)
                {
                    std::map<uint256, CShieldedNullifierSpent>::iterator spentIt =
                        mapPrivacyVNextNullifier.find(*it);
                    if (spentIt != mapPrivacyVNextNullifier.end() &&
                        spentIt->second.txnHash == txHash)
                        mapPrivacyVNextNullifier.erase(spentIt);
                }
                mapPrivacyVNextTxNullifiers.erase(reverseIt);
            }

            std::map<uint256, std::vector<uint256> >::iterator baseReverseIt =
                mapPrivacyVNextTxOutputBases.find(txHash);
            if (baseReverseIt != mapPrivacyVNextTxOutputBases.end())
            {
                for (std::vector<uint256>::const_iterator it =
                         baseReverseIt->second.begin();
                     it != baseReverseIt->second.end(); ++it)
                {
                    std::map<uint256, CShieldedNullifierSpent>::iterator baseIt =
                        mapPrivacyVNextOutputBase.find(*it);
                    if (baseIt != mapPrivacyVNextOutputBase.end() &&
                        baseIt->second.txnHash == txHash)
                        mapPrivacyVNextOutputBase.erase(baseIt);
                }
                mapPrivacyVNextTxOutputBases.erase(baseReverseIt);
            }

            std::map<uint256, std::vector<uint256> >::iterator attReverseIt =
                mapPrivacyVNextTxAttestations.find(txHash);
            if (attReverseIt != mapPrivacyVNextTxAttestations.end())
            {
                for (std::vector<uint256>::const_iterator it =
                         attReverseIt->second.begin();
                     it != attReverseIt->second.end(); ++it)
                {
                    std::map<uint256, CShieldedNullifierSpent>::iterator attIt =
                        mapPrivacyVNextAttestation.find(*it);
                    if (attIt != mapPrivacyVNextAttestation.end() &&
                        attIt->second.txnHash == txHash)
                        mapPrivacyVNextAttestation.erase(attIt);
                }
                mapPrivacyVNextTxAttestations.erase(attReverseIt);
            }

            mapTx.erase(txHash);
            nRemoved++;
            ++nTransactionsUpdated;
        }
    }

    if (nRemoved > 0)
        printf("RemoveDAGConflicts: removed %d txs from mempool (sibling block %s)\n",
               nRemoved, hashBlock.ToString().substr(0, 20).c_str());
}

void CTxMemPool::clear()
{
    LOCK(cs);
    mapTx.clear();
    mapNextTx.clear();
    mapKeyImage.clear();
    mapShieldedNullifier.clear();
    mapPrivacyVNextNullifier.clear();
    mapPrivacyVNextTxNullifiers.clear();
    mapPrivacyVNextOutputBase.clear();
    mapPrivacyVNextTxOutputBases.clear();
    mapPrivacyVNextAttestation.clear();
    mapPrivacyVNextTxAttestations.clear();
    setDAGSeenTxids.clear();
    ++nTransactionsUpdated;
}

void CTxMemPool::queryHashes(std::vector<uint256>& vtxid)
{
    vtxid.clear();

    LOCK(cs);
    vtxid.reserve(mapTx.size());
    for (map<uint256, CTransaction>::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
        vtxid.push_back((*mi).first);
}

int CMerkleTx::GetDepthInMainChainINTERNAL(CBlockIndex* &pindexRet) const
{
    if (hashBlock == 0 || nIndex == -1)
        return 0;
    AssertLockHeld(cs_main);

    // Find the block it claims to be in
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    // Make sure the merkle branch connects to this block
    if (!fMerkleVerified)
    {
        if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot)
            return 0;
        fMerkleVerified = true;
    }

    pindexRet = pindex;
    if (!pindexBest)
        return 0;
    return pindexBest->nHeight - pindex->nHeight + 1;
}

int CMerkleTx::GetDepthInMainChain(CBlockIndex* &pindexRet) const
{
    AssertLockHeld(cs_main);
    int nResult = GetDepthInMainChainINTERNAL(pindexRet);
    if (nResult == 0 && !mempool.exists(GetHash()))
        return -1; // Not in chain, not in mempool

    return nResult;
}

int CMerkleTx::GetBlocksToMaturity() const
{
    if (!(IsCoinBase() || IsCoinStake()))
        return 0;
    // A generated output is spendable only once GetDepthInMainChain() exceeds
    // nCoinbaseMaturity, matching ConnectInputs.
    int nWalletMaturity =
        fRegTest ? nCoinbaseMaturity + 1 : nCoinbaseMaturity + 10;
    return max(0, nWalletMaturity - GetDepthInMainChain());
}


bool CMerkleTx::AcceptToMemoryPool(CTxDB& txdb)
{
    return CTransaction::AcceptToMemoryPool(txdb);
}

bool CMerkleTx::AcceptToMemoryPool()
{
    CTxDB txdb("r");
    return AcceptToMemoryPool(txdb);
}

bool CWalletTx::AcceptWalletTransaction(CTxDB& txdb)
{

    {
        // Add previous supporting transactions first
        for (CMerkleTx& tx : vtxPrev)
        {
            if (!(tx.IsCoinBase() || tx.IsCoinStake()))
            {
                uint256 hash = tx.GetHash();
                if (!mempool.exists(hash) && !txdb.ContainsTx(hash))
                    tx.AcceptToMemoryPool(txdb);
            }
        }
        return AcceptToMemoryPool(txdb);
    }
    return false;
}

bool CWalletTx::AcceptWalletTransaction()
{
    CTxDB txdb("r");
    return AcceptWalletTransaction(txdb);
}

int CTxIndex::GetDepthInMainChain() const
{
    // Read block header
    CBlock block;
    if (!block.ReadFromDisk(pos.nFile, pos.nBlockPos, false))
        return 0;
    // Find the block in the index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(block.GetHash());
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;
    return 1 + nBestHeight - pindex->nHeight;
}

// Return transaction in tx, and if it was found inside a block, its hash is placed in hashBlock
bool GetTransaction(const uint256 &hash, CTransaction &tx, uint256 &hashBlock, bool s)
{
    {
        if(s)
        {
          LOCK(cs_main);
          {
            if (mempool.lookup(hash, tx))
            {
                return true;
            }
          }
        }
        CTxDB txdb("r");
        CTxIndex txindex;
        if (tx.ReadFromDisk(txdb, hash, txindex))
        {
            CBlock block;
            if (block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
                hashBlock = block.GetHash();
            return true;
        }
    }
    return false;
}

bool GetKeyImage(CTxDB* ptxdb, ec_point& keyImage, CKeyImageSpent& keyImageSpent, bool& fInMempool)
{
    AssertLockHeld(cs_main);


    // -- check txdb first
    fInMempool = false;
    if (ptxdb->ReadKeyImage(keyImage, keyImageSpent))
        return true;

    if (mempool.lookupKeyImage(keyImage, keyImageSpent))
    {
        fInMempool = true;
        return true;
    };

    return false;
};

bool TxnHashInSystem(CTxDB* ptxdb, uint256& txnHash)
{
    // -- is the transaction hash known in the system

    AssertLockHeld(cs_main);

    // TODO: thin mode

    if (mempool.exists(txnHash))
        return true;

    CTxIndex txnIndex;
    if (ptxdb->ReadTxIndex(txnHash, txnIndex))
    {
        if (txnIndex.GetDepthInMainChain() > 0)
            return true;
    };

    return false;
};

//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

// bool ReadBlockFromDisk(CBlock& block, const CDiskBlockPos& pos)
// {
//     block.SetNull();

//     // Open history file to read
//     CAutoFile filein(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION);
//     if (filein.IsNull())
//         return error("ReadBlockFromDisk : OpenBlockFile failed");

//     // Read block
//     try {
//         filein >> block;
//     }
//     catch (std::exception &e) {
//         return error("%s : Deserialize or I/O error - %s", __func__, e.what());
//     }

//     // Check the header
//     if (block.IsProofOfWork() && !CheckProofOfWork(block.GetHash(), block.nBits))
//         return error("ReadBlockFromDisk : Errors in block header");

//     return true;
// }

// bool ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex)
// {
//     if (!ReadBlockFromDisk(block, pindex->nBlockPos))
//         return false;
//     if (block.GetHash() != pindex->GetBlockHash())
//         return error("ReadBlockFromDisk(CBlock&, CBlockIndex*) : GetHash() doesn't match index");
//     return true;
// }

bool RebuildMainChainForwardLinks()
{
    if (pindexBest == NULL)
        return pindexGenesisBlock == NULL;

    // Collect the walk before touching anything. The old order cleared every
    // pnext first, so a walk that failed left the index worse than it found it
    // and the node had nothing to fall back on.
    std::vector<CBlockIndex*> vChain;
    CBlockIndex* pindex = pindexBest;
    while (pindex->pprev)
    {
        if (pindex->pprev->nHeight >= pindex->nHeight)
        {
            printf("RebuildMainChainForwardLinks() : invalid height link %d -> %d at %s; "
                   "keeping the stored forward links\n",
                   pindex->pprev->nHeight, pindex->nHeight,
                   pindex->GetBlockHash().ToString().substr(0, 20).c_str());
            return true;
        }
        vChain.push_back(pindex);
        pindex = pindex->pprev;
    }

    if (pindex != pindexGenesisBlock)
    {
        printf("RebuildMainChainForwardLinks() : best chain stops at height %d (%s) instead of "
               "genesis after %d links; keeping the stored forward links\n",
               pindex->nHeight, pindex->GetBlockHash().ToString().substr(0, 20).c_str(),
               (int)vChain.size());
        return true;
    }

    // Count what was wrong before overwriting it, so only real repairs are reported.
    int nRepaired = 0;
    for (size_t i = 0; i < vChain.size(); ++i)
        if (vChain[i]->pprev->pnext != vChain[i])
            nRepaired++;

    for (PAIRTYPE(const uint256, CBlockIndex*)& item : mapBlockIndex)
        item.second->pnext = NULL;
    for (size_t i = 0; i < vChain.size(); ++i)
        vChain[i]->pprev->pnext = vChain[i];

    if (nRepaired > 0)
        printf("Rebuilt %d main-chain forward links (%d were missing or wrong)\n",
               (int)vChain.size(), nRepaired);
    return true;
}

static CBlockIndex* pblockindexFBBHLast;

namespace {

static int InvertLowestOne(int n)
{
    return n & (n - 1);
}

static int GetSkipHeight(int height)
{
    if (height < 2)
        return 0;
    return (height & 1)
        ? InvertLowestOne(InvertLowestOne(height - 1)) + 1
        : InvertLowestOne(height);
}

} // namespace

void CBlockIndex::BuildSkip()
{
    if (pprev)
        pskip = pprev->GetAncestor(GetSkipHeight(nHeight));
    else
        pskip = NULL;
}

const CBlockIndex* CBlockIndex::GetAncestor(int nHeightTarget) const
{
    if (nHeightTarget > nHeight || nHeightTarget < 0)
        return NULL;

    const CBlockIndex* pindexWalk = this;
    int nHeightWalk = nHeight;
    while (nHeightWalk > nHeightTarget)
    {
        int nHeightSkip = GetSkipHeight(nHeightWalk);
        int nHeightSkipPrev = GetSkipHeight(nHeightWalk - 1);
        if (pindexWalk->pskip &&
            (nHeightSkip == nHeightTarget ||
             (nHeightSkip > nHeightTarget &&
              !(nHeightSkipPrev < nHeightSkip - 2 &&
                nHeightSkipPrev >= nHeightTarget))))
        {
            pindexWalk = pindexWalk->pskip;
            nHeightWalk = nHeightSkip;
        }
        else
        {
            // A holed index can end a chain early. The old locator walk stopped
            // on a null pprev; keep that rather than dereferencing it below.
            if (!pindexWalk->pprev)
                return pindexWalk;
            pindexWalk = pindexWalk->pprev;
            --nHeightWalk;
        }
    }
    return pindexWalk;
}

CBlockIndex* CBlockIndex::GetAncestor(int nHeightTarget)
{
    return const_cast<CBlockIndex*>(static_cast<const CBlockIndex*>(this)->GetAncestor(nHeightTarget));
}

CBlockIndex* FindBlockByHeight(int nHeight)
{
    CBlockIndex *pblockindex;
    if (nHeight < nBestHeight / 2)
        pblockindex = pindexGenesisBlock;
    else
        pblockindex = pindexBest;
    if (pblockindexFBBHLast && abs(nHeight - pblockindex->nHeight) > abs(nHeight - pblockindexFBBHLast->nHeight))
        pblockindex = pblockindexFBBHLast;
    while (pblockindex->nHeight > nHeight)
        pblockindex = pblockindex->pprev;
    while (pblockindex->nHeight < nHeight)
        pblockindex = pblockindex->pnext;
    pblockindexFBBHLast = pblockindex;
    return pblockindex;
}

bool CBlock::ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions)
{
    if (!fReadTransactions)
    {
        *this = pindex->GetBlockHeader();
        return true;
    }
    if (!ReadFromDisk(pindex->nFile, pindex->nBlockPos, fReadTransactions))
        return false;
    if (GetHash() != pindex->GetBlockHash())
        return error("CBlock::ReadFromDisk() : GetHash() doesn't match index");
    return true;
}

uint256 static GetOrphanRoot(const CBlock* pblock)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblock->hashPrevBlock))
        pblock = mapOrphanBlocks[pblock->hashPrevBlock];
    return pblock->GetHash();
}

// ppcoin: find block wanted by given orphan block
uint256 WantedByOrphan(const CBlock* pblockOrphan)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblockOrphan->hashPrevBlock))
        pblockOrphan = mapOrphanBlocks[pblockOrphan->hashPrevBlock];
    return pblockOrphan->hashPrevBlock;
}

// Remove a random orphan block (which does not have any dependent orphans).
void PruneOrphanBlocks()
{
    if (mapOrphanBlocksByPrev.size() <= (size_t)std::max((int64_t)0, GetArg("-maxorphanblocks", DEFAULT_MAX_ORPHAN_BLOCKS)))
        return;

    unsigned char randBytes[4];
    unsigned int randVal;
    if (RAND_bytes(randBytes, sizeof(randBytes)) != 1) {
        randVal = GetTime() ^ (unsigned int)mapOrphanBlocksByPrev.size();
    } else {
        randVal = (randBytes[0] << 24) | (randBytes[1] << 16) |
                  (randBytes[2] << 8) | randBytes[3];
    }
    int pos = randVal % mapOrphanBlocksByPrev.size();
    std::multimap<uint256, CBlock*>::iterator it = mapOrphanBlocksByPrev.begin();
    while (pos--) it++;

    // As long as this block has other orphans depending on it, move to one of those successors.
    do {
        std::multimap<uint256, CBlock*>::iterator it2 = mapOrphanBlocksByPrev.find(it->second->GetHash());
        if (it2 == mapOrphanBlocksByPrev.end())
            break;
        it = it2;
    } while(1);

    uint256 hash = it->second->GetHash();
    const bool fIsProofOfStake = it->second->IsProofOfStake();
    const std::pair<COutPoint, unsigned int> stake = it->second->GetProofOfStake();
    delete it->second;
    mapOrphanBlocksByPrev.erase(it);
    mapOrphanBlocks.erase(hash);

    map<uint256, NodeId>::iterator nodeIt = mapOrphanBlocksByNode.find(hash);
    if (nodeIt != mapOrphanBlocksByNode.end()) {
        mapOrphanCountByNode[nodeIt->second]--;
        mapOrphanBlocksByNode.erase(nodeIt);
    }

    // A pruned orphan must release its stake marker, otherwise later
    // re-deliveries of the same block are rejected as duplicate proof-of-stake
    // orphan even though no stored orphan still references it.  Only release
    // the kernel when no other stored orphan still references it.
    if (fIsProofOfStake)
        EraseStakeSeenOrphanIfUnreferenced(stake);
}

// The parent fetch paths request and serve merge parents by this list, so they
// read it with the same height-selected decoder the validity gate and the index
// writer use. A reader of its own would chase a parent set no rule checked.
static std::vector<uint256> GetDAGParentsFromBlock(const CBlock& block, int nHeight)
{
    std::vector<uint256> vDAGParents;

    if (block.vtx.empty())
        return vDAGParents;

    std::vector<CScript> vScripts;
    for (std::vector<CTxOut>::const_iterator it = block.vtx[0].vout.begin();
         it != block.vtx[0].vout.end(); ++it)
        vScripts.push_back(it->scriptPubKey);

    std::string strDAGError;
    if (!ReadDAGParentCommitmentAtHeight(vScripts, nHeight, vDAGParents,
                                         strDAGError))
        vDAGParents.clear();

    return vDAGParents;
}

static std::vector<uint256> GetMissingDAGMergeParents(const CBlock& block)
{
    std::vector<uint256> vMissing;

    std::map<uint256, CBlockIndex*>::iterator miPrev = mapBlockIndex.find(block.hashPrevBlock);
    if (miPrev == mapBlockIndex.end())
        return vMissing;

    int nHeight = miPrev->second->nHeight + 1;
    if (nHeight < FORK_HEIGHT_DAG)
        return vMissing;

    std::vector<uint256> vDAGParents = GetDAGParentsFromBlock(block, nHeight);
    for (unsigned int j = 1; j < vDAGParents.size(); j++)
    {
        if (mapBlockIndex.count(vDAGParents[j]))
            continue;

        if (std::find(vMissing.begin(), vMissing.end(), vDAGParents[j]) == vMissing.end())
            vMissing.push_back(vDAGParents[j]);
    }

    return vMissing;
}

static void QueueBlockInventory(CNode* pfrom, const uint256& hash, std::set<uint256>& setQueued)
{
    if (!pfrom)
        return;

    if (!setQueued.insert(hash).second)
        return;

    CInv inv(MSG_BLOCK, hash);
    LOCK(pfrom->cs_inventory);
    pfrom->vInventoryToSend.push_back(inv);
}

void PushBlockAnnouncement(CNode* pnode, const CBlock& header, bool fForce)
{
    if (!pnode)
        return;

    CInv inv(MSG_BLOCK, header.GetHash());
    if (pnode->fPreferHeaders)
    {
        if (!fForce)
        {
            LOCK(pnode->cs_inventory);
            if (pnode->setInventoryKnown.count(inv))
                return;
        }
        std::vector<CBlock> vHeaders;
        vHeaders.push_back(header);
        pnode->PushMessage("headers", vHeaders);
        return;
    }

    LOCK(pnode->cs_inventory);
    if (fForce || !pnode->setInventoryKnown.count(inv))
        pnode->vInventoryToSend.push_back(inv);
}

// Ceiling on side-block inventory one getblocks may assemble: the walk reads each block
// from disk under cs_main on the message handler thread.
static const size_t MAX_DAG_SIDE_INV_PER_GETBLOCKS = 2000;

static void QueueDAGSideBlockWithAncestors(CNode* pfrom, const uint256& hash, std::set<uint256>& setQueued, std::set<uint256>& setVisiting, int nDepth)
{
    if (!pfrom || nDepth > DAG_MERGE_DEPTH)
        return;

    // Already queued for this request: skip, or shared side blocks are re-walked once per
    // merge parent reaching them (exponential).
    if (setQueued.count(hash))
        return;
    if (setQueued.size() >= MAX_DAG_SIDE_INV_PER_GETBLOCKS)
        return;

    std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
    if (mi == mapBlockIndex.end())
        return;

    CBlockIndex* pindex = mi->second;
    if (pindex->IsInMainChain())
        return;

    if (!setVisiting.insert(hash).second)
        return;

    CBlock block;
    if (!block.ReadFromDisk(pindex))
    {
        setVisiting.erase(hash);
        return;
    }

    std::map<uint256, CBlockIndex*>::iterator miPrev = mapBlockIndex.find(block.hashPrevBlock);
    if (miPrev != mapBlockIndex.end() && !miPrev->second->IsInMainChain())
        QueueDAGSideBlockWithAncestors(pfrom, block.hashPrevBlock, setQueued, setVisiting, nDepth + 1);

    std::vector<uint256> vDAGParents = GetDAGParentsFromBlock(block, pindex->nHeight);
    for (unsigned int i = 1; i < vDAGParents.size(); i++)
        QueueDAGSideBlockWithAncestors(pfrom, vDAGParents[i], setQueued, setVisiting, nDepth + 1);

    QueueBlockInventory(pfrom, hash, setQueued);
    setVisiting.erase(hash);
}

static void QueueDAGMergeParentInventories(CNode* pfrom, CBlockIndex* pindex, std::set<uint256>& setQueued)
{
    if (!pfrom || !pindex || pindex->nHeight < FORK_HEIGHT_DAG)
        return;

    CBlock block;
    if (!block.ReadFromDisk(pindex))
        return;

    std::vector<uint256> vDAGParents = GetDAGParentsFromBlock(block, pindex->nHeight);
    std::set<uint256> setVisiting;
    for (unsigned int i = 1; i < vDAGParents.size(); i++)
        QueueDAGSideBlockWithAncestors(pfrom, vDAGParents[i], setQueued, setVisiting, 0);
}

// Finality rewards are minted once per epoch at the settlement height
// (CheckFinalitySettlementOutputs), not per carrier block.

bool CheckFinalityStakeProofsNotSpentInBlock(const CBlock& block, const std::vector<CFinalityVote>& vVotes)
{
    if (vVotes.empty())
        return true;

    std::set<COutPoint> setSpentInBlock;
    for (const CTransaction& tx : block.vtx)
    {
        if (tx.IsCoinBase())
            continue;
        for (const CTxIn& txin : tx.vin)
            setSpentInBlock.insert(txin.prevout);
    }

    for (const CFinalityVote& vote : vVotes)
    {
        if (vote.IsPrivate())
            continue;
        for (const COutPoint& proof : vote.vStakeProof)
        {
            if (setSpentInBlock.count(proof))
                return error("CheckFinalityStakeProofsNotSpentInBlock() : finality stake proof spent in same block");
        }
    }

    return true;
}

// An IV5 transaction's conflict tags live in its payload, not in vin or
// vShieldedSpend. Collecting them keeps the double-spend view of a DAG sibling
// set complete; a payload that does not decode contributes nothing, and the
// block carrying it is rejected by the validation that decodes it again.
//
// Output owners are tagged as well as key images, because consensus refuses a
// second issue of an owner already on chain. Without this an owner reissued
// across siblings would kill the later block rather than the later transaction,
// which is the same block-destruction lever a cross-sibling double spend would
// be. The owner tag is domain separated so it can never alias a key image; the
// key-image tag stays the raw point, because the skipped-transaction set it
// feeds is consensus state.
void AppendPrivacyVNextConflictTags(const CTransaction& tx,
                                    std::set<uint256>& setTagsOut)
{
    if (!tx.IsPrivacyVNext() || !tx.privacyVNext.IsPresent())
        return;

    PrivacyVNextStateEffects effects;
    const PrivacyVNextPayloadValidation validation =
        ExtractPrivacyVNextPayloadEffects(
            static_cast<uint32_t>(tx.nVersion), tx.privacyVNext.vchPayload,
            effects);
    if (!validation.IsValid())
        return;

    for (size_t i = 0; i < effects.keyImages.size(); ++i)
    {
        uint256 keyImage;
        memcpy(keyImage.begin(), effects.keyImages[i].data(),
               effects.keyImages[i].size());
        setTagsOut.insert(keyImage);
    }

    for (size_t i = 0; i < effects.outputLeaves.size(); ++i)
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << std::string("Innova/IV5/OutputOwnerConflictTag/v1");
        ss.write((const char*)effects.outputLeaves[i].nullifierBase.data(),
                 effects.outputLeaves[i].nullifierBase.size());
        setTagsOut.insert(ss.GetHash());
    }

    // Two attestations of one note across siblings conflict. Domain-separated from the
    // key-image tag, so an attestation and a spend of the same note do not.
    for (size_t i = 0; i < effects.attestationKeyImages.size(); ++i)
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << std::string("Innova/IV5/CollateralAttestationConflictTag/v1");
        ss.write((const char*)effects.attestationKeyImages[i].data(),
                 effects.attestationKeyImages[i].size());
        setTagsOut.insert(ss.GetHash());
    }
}

bool TransactionConflictsWithDAGSiblingSpends(const CTransaction& tx,
                                              const std::set<COutPoint>& setDAGSpentOutputs,
                                              const std::set<uint256>& setDAGSpentNullifiers)
{
    if (tx.IsCoinBase() || tx.IsCoinStake())
        return false;

    for (const CTxIn& txin : tx.vin)
        if (setDAGSpentOutputs.count(txin.prevout))
            return true;

    for (const CShieldedSpendDescription& spend : tx.vShieldedSpend)
        if (setDAGSpentNullifiers.count(spend.nullifier))
            return true;

    // Without this an IV5 double-spend across siblings kills the later block
    // instead of the later transaction, which lets anyone destroy an honest
    // miner's block by broadcasting two spends of one note to disjoint peers.
    std::set<uint256> setTags;
    AppendPrivacyVNextConflictTags(tx, setTags);
    for (std::set<uint256>::const_iterator it = setTags.begin();
         it != setTags.end(); ++it)
        if (setDAGSpentNullifiers.count(*it))
            return true;

    return false;
}

// Sibling precedence is a consensus input, so it uses only committed data: (height,
// hash), which is total and topologically consistent. nDAGOrder is node-local. Only
// reachable from FORK_HEIGHT_DAG upward.
bool DAGSiblingPrecedesBlock(const uint256& hashBlock,
                             const uint256& hashSibling)
{
    std::map<uint256, CBlockIndex*>::const_iterator miBlock = mapBlockIndex.find(hashBlock);
    std::map<uint256, CBlockIndex*>::const_iterator miSibling = mapBlockIndex.find(hashSibling);
    const int nBlockHeight =
        (miBlock != mapBlockIndex.end() && miBlock->second) ? miBlock->second->nHeight : -1;
    const int nSiblingHeight =
        (miSibling != mapBlockIndex.end() && miSibling->second) ? miSibling->second->nHeight : -1;
    return nSiblingHeight != nBlockHeight
               ? nSiblingHeight < nBlockHeight
               : hashSibling < hashBlock;
}

std::set<uint256> GetDAGSkippedTxsFromSiblingSpends(const CBlock& block,
                                                    const std::set<COutPoint>& setDAGSpentOutputs,
                                                    const std::set<uint256>& setDAGSpentNullifiers)
{
    std::set<uint256> setDAGSkippedTxs;
    bool fChanged = true;

    while (fChanged)
    {
        fChanged = false;
        for (const CTransaction& tx : block.vtx)
        {
            if (tx.IsCoinBase() || tx.IsCoinStake())
                continue;

            uint256 hashTx = tx.GetHash();
            if (setDAGSkippedTxs.count(hashTx))
                continue;

            bool fSkip = TransactionConflictsWithDAGSiblingSpends(tx, setDAGSpentOutputs, setDAGSpentNullifiers);
            if (!fSkip)
            {
                for (const CTxIn& txin : tx.vin)
                {
                    if (setDAGSkippedTxs.count(txin.prevout.hash))
                    {
                        fSkip = true;
                        break;
                    }
                }
            }

            if (fSkip && setDAGSkippedTxs.insert(hashTx).second)
                fChanged = true;
        }
    }

    return setDAGSkippedTxs;
}

static std::set<uint256> GetDAGSkippedTxsForBlockInternal(const CBlock& block,
                                                          const CBlockIndex* pindex,
                                                          std::map<uint256, std::set<uint256> >& mapSkipCache,
                                                          std::set<uint256>& setVisiting,
                                                          bool* pfIncomplete)
{
    std::set<uint256> setDAGSkippedTxs;
    if (!pindex || pindex->nHeight < FORK_HEIGHT_DAG || !pindex->phashBlock)
        return setDAGSkippedTxs;

    uint256 hashBlock = pindex->GetBlockHash();
    std::map<uint256, std::set<uint256> >::const_iterator miCached = mapSkipCache.find(hashBlock);
    if (miCached != mapSkipCache.end())
        return miCached->second;
    if (setVisiting.count(hashBlock))
        return setDAGSkippedTxs;
    setVisiting.insert(hashBlock);

    std::set<COutPoint> setDAGSpentOutputs;
    std::set<uint256> setDAGSpentNullifiers;

    // Anything this set depends on that is missing here -- a vertex, a sibling's index or
    // its body -- is reported instead of shrinking the set: every other node computes the
    // full set, and a smaller one connects a transaction they skipped.
    std::set<uint256> siblings = g_dagManager.GetDAGSiblingBlocks(hashBlock, pfIncomplete);

    for (const uint256& hashSibling : siblings)
    {
        if (!DAGSiblingPrecedesBlock(hashBlock, hashSibling))
            continue;

        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashSibling);
        if (mi == mapBlockIndex.end())
        {
            if (pfIncomplete)
                *pfIncomplete = true;
            continue;
        }

        CBlock sibBlock;
        if (!sibBlock.ReadFromDisk(mi->second))
        {
            if (pfIncomplete)
                *pfIncomplete = true;
            continue;
        }

        std::set<uint256> setSiblingSkippedTxs =
            GetDAGSkippedTxsForBlockInternal(sibBlock, mi->second, mapSkipCache, setVisiting,
                                             pfIncomplete);

        for (const CTransaction& sibTx : sibBlock.vtx)
        {
            if (sibTx.IsCoinBase() || sibTx.IsCoinStake() || setSiblingSkippedTxs.count(sibTx.GetHash()))
                continue;
            for (const CTxIn& txin : sibTx.vin)
                setDAGSpentOutputs.insert(txin.prevout);
            for (const CShieldedSpendDescription& spend : sibTx.vShieldedSpend)
                setDAGSpentNullifiers.insert(spend.nullifier);
            AppendPrivacyVNextConflictTags(sibTx, setDAGSpentNullifiers);
        }
    }

    if (!setDAGSpentOutputs.empty() || !setDAGSpentNullifiers.empty())
        setDAGSkippedTxs = GetDAGSkippedTxsFromSiblingSpends(block, setDAGSpentOutputs, setDAGSpentNullifiers);

    mapSkipCache[hashBlock] = setDAGSkippedTxs;
    setVisiting.erase(hashBlock);
    return setDAGSkippedTxs;
}

std::set<uint256> GetDAGSkippedTxsForBlock(const CBlock& block, const CBlockIndex* pindex,
                                           bool* pfIncomplete)
{
    if (pfIncomplete)
        *pfIncomplete = false;
    std::map<uint256, std::set<uint256> > mapSkipCache;
    std::set<uint256> setVisiting;
    return GetDAGSkippedTxsForBlockInternal(block, pindex, mapSkipCache, setVisiting, pfIncomplete);
}

uint256 ComputeShieldedWalletEffectPlanDigest(
    const std::vector<CShieldedWalletEffectDigestEntry>& vEntries)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("Innova shielded wallet recovery plan v1");
    ss << (uint64_t)vEntries.size();
    for (std::vector<CShieldedWalletEffectDigestEntry>::const_iterator it =
             vEntries.begin(); it != vEntries.end(); ++it)
    {
        ss << (unsigned char)(it->fConnect ? 1 : 0);
        ss << it->hashBlock;
        ss << std::vector<uint256>(it->setDAGSkippedTxs.begin(),
                                  it->setDAGSkippedTxs.end());
    }
    return ss.GetHash();
}

CBlock GetDAGActiveBlock(const CBlock& block, const std::set<uint256>& setDAGSkippedTxs)
{
    if (setDAGSkippedTxs.empty())
        return block;

    CBlock activeBlock = block;
    std::vector<CTransaction> vActiveTx;
    vActiveTx.reserve(activeBlock.vtx.size());
    for (const CTransaction& tx : activeBlock.vtx)
    {
        if (!setDAGSkippedTxs.count(tx.GetHash()))
            vActiveTx.push_back(tx);
    }
    activeBlock.vtx.swap(vActiveTx);
    return activeBlock;
}

namespace
{
static const size_t DAG_ACTIVE_SET_RECOVERY_CHUNK = 512;

CBlockIndex* GetAncestorAtHeight(CBlockIndex* pindex, int nHeight)
{
    if (nHeight < 0)
        return NULL;
    while (pindex && pindex->nHeight > nHeight)
        pindex = pindex->pprev;
    return pindex && pindex->nHeight == nHeight ? pindex : NULL;
}

CBlockIndex* FindCommonPrimaryAncestor(CBlockIndex* a, CBlockIndex* b)
{
    while (a && b && a->nHeight > b->nHeight)
        a = a->pprev;
    while (a && b && b->nHeight > a->nHeight)
        b = b->pprev;
    while (a && b && a != b)
    {
        a = a->pprev;
        b = b->pprev;
    }
    return a == b ? a : NULL;
}

bool ValidateDAGActiveSetTipBinding(CTxDB& txdb,
                                    CBlockIndex* pindexTip,
                                    std::string& strError)
{
    strError.clear();
    if (!pindexTip || pindexTip->nHeight < FORK_HEIGHT_DAG)
        return true;
    if (!pindexTip->phashBlock)
    {
        strError = "canonical DAG tip has no block hash";
        return false;
    }
    CBlock block;
    if (!block.ReadFromDisk(pindexTip, true) ||
        block.GetHash() != pindexTip->GetBlockHash() ||
        block.BuildMerkleTree() != pindexTip->hashMerkleRoot)
    {
        strError = "canonical DAG tip block data is missing or corrupt";
        return false;
    }
    std::set<uint256> setSkipped;
    const TxDBReadStatus status =
        txdb.ReadDAGSkippedTxsStatus(block, setSkipped, strError);
    if (status != TXDB_READ_FOUND)
    {
        if (strError.empty())
            strError = status == TXDB_READ_NOT_FOUND
                ? "canonical DAG tip active set is missing"
                : "canonical DAG tip active set is corrupt";
        return false;
    }
    return true;
}

bool ProveLegacyCanonicalBlockFullyActive(
    CTxDB& txdb, const CBlock& block, const CBlockIndex* pindex,
    std::string& strError)
{
    strError.clear();
    if (!pindex || !pindex->phashBlock || block.vtx.empty() ||
        block.GetHash() != pindex->GetBlockHash() ||
        block.BuildMerkleTree() != block.hashMerkleRoot ||
        block.hashMerkleRoot != pindex->hashMerkleRoot)
    {
        strError = "legacy DAG active-set recovery received mismatched block data";
        return false;
    }

    const uint64_t nHeaderBytes = ::GetSerializeSize(
        CBlock(), SER_DISK, CLIENT_VERSION);
    const uint64_t nEmptyVectorBytes = 2 * GetSizeOfCompactSize(0);
    if (nHeaderBytes < nEmptyVectorBytes)
    {
        strError = "legacy DAG active-set recovery block-header size underflow";
        return false;
    }
    uint64_t nTxPos = (uint64_t)pindex->nBlockPos + nHeaderBytes -
                      nEmptyVectorBytes +
                      GetSizeOfCompactSize(block.vtx.size());
    std::set<uint256> setSeenTx;
    for (std::vector<CTransaction>::const_iterator it = block.vtx.begin();
         it != block.vtx.end(); ++it)
    {
        const uint256 hashTx = it->GetHash();
        if (!setSeenTx.insert(hashTx).second)
        {
            strError = strprintf(
                "height %d contains duplicate transaction %s; its historical "
                "active instance is ambiguous",
                pindex->nHeight, hashTx.ToString().substr(0, 20).c_str());
            return false;
        }
        const uint64_t nTxSize = ::GetSerializeSize(
            *it, SER_DISK, CLIENT_VERSION);
        if (nTxPos > std::numeric_limits<unsigned int>::max() ||
            nTxSize > std::numeric_limits<unsigned int>::max() - nTxPos)
        {
            strError = strprintf(
                "height %d transaction positions overflow the legacy disk format",
                pindex->nHeight);
            return false;
        }

        CTxIndex txindex;
        const TxDBReadStatus status =
            txdb.ReadTxIndexStatus(hashTx, txindex);
        if (status != TXDB_READ_FOUND)
        {
            // NOT_FOUND is deliberately not interpreted as "skipped".  It can
            // equally mean an active tx-index record was lost.  No historical
            // arrival-order evidence survives elsewhere in the legacy DB.
            strError = strprintf(
                "height %d transaction %s has %s transaction-index state; "
                "cannot prove historically skipped versus missing/corrupt active "
                "state without guessing from the current DAG",
                pindex->nHeight, hashTx.ToString().substr(0, 20).c_str(),
                status == TXDB_READ_NOT_FOUND ? "no" : "corrupt");
            return false;
        }
        const CDiskTxPos expected(pindex->nFile, pindex->nBlockPos,
                                  (unsigned int)nTxPos);
        if (txindex.pos != expected)
        {
            strError = strprintf(
                "height %d transaction %s index points to a different disk "
                "position; duplicate/overwritten versus inactive history is ambiguous",
                pindex->nHeight, hashTx.ToString().substr(0, 20).c_str());
            return false;
        }
        if (txindex.vSpent.size() != it->vout.size())
        {
            strError = strprintf(
                "height %d transaction %s index output count is corrupt",
                pindex->nHeight, hashTx.ToString().substr(0, 20).c_str());
            return false;
        }
        nTxPos += nTxSize;
    }
    return true;
}

bool CommitDAGActiveSetBuildMarker(CTxDB& txdb,
                                   CDAGActiveSetBuildRecord record,
                                   std::string& strError)
{
    if (!txdb.TxnBegin())
    {
        strError = "could not begin DAG active-set recovery marker transaction";
        return false;
    }
    if (!txdb.WriteDAGActiveSetBuild(record))
    {
        txdb.TxnAbort();
        strError = "could not stage DAG active-set recovery marker";
        return false;
    }
    if (!txdb.TxnCommit(true))
    {
        strError = "could not durably commit DAG active-set recovery marker";
        return false;
    }
    return true;
}
} // namespace

bool ValidateAndRecoverDAGActiveSetPersistence(CTxDB& txdb,
                                               std::string& strError)
{
    LOCK(cs_main);
    strError.clear();
    if (!pindexBest || !pindexBest->phashBlock)
        return true;

    uint256 hashDurableBest;
    if (!txdb.ReadHashBestChain(hashDurableBest) ||
        hashDurableBest != pindexBest->GetBlockHash())
    {
        strError = "DAG active-set recovery target is not the durable best chain";
        return false;
    }

    CShieldedWalletRecoveryRecord pendingWalletRecovery;
    const TxDBReadStatus walletStatus =
        txdb.ReadShieldedWalletRecoveryStatus(pendingWalletRecovery);
    if (walletStatus == TXDB_READ_ERROR)
    {
        strError = "shielded-wallet recovery marker is corrupt during DAG active-set validation";
        return false;
    }

    uint256 hashRecordedBest;
    const TxDBReadStatus bestStatus =
        txdb.ReadDAGActiveSetBest(hashRecordedBest);
    if (bestStatus == TXDB_READ_ERROR)
    {
        strError = "DAG active-set completed-tip marker is corrupt";
        return false;
    }
    CDAGActiveSetBuildRecord build;
    const TxDBReadStatus buildStatus = txdb.ReadDAGActiveSetBuild(build);
    if (buildStatus == TXDB_READ_ERROR)
    {
        strError = "DAG active-set recovery-progress marker is corrupt";
        return false;
    }

    std::string strCoverageError;
    const bool fCompletedAtCurrentTip =
        bestStatus == TXDB_READ_FOUND &&
        hashRecordedBest == hashDurableBest;
    // The completed marker, tip record and hashBestChain share every chain WriteBatch, so a
    // matching marker proves coverage; per-block reads still fail closed.
    if (fCompletedAtCurrentTip &&
        ValidateDAGActiveSetTipBinding(
            txdb, pindexBest, strCoverageError))
    {
        if (buildStatus == TXDB_READ_FOUND)
        {
            if (!txdb.TxnBegin())
            {
                strError = "could not begin stale DAG recovery-marker cleanup";
                return false;
            }
            if (!txdb.EraseDAGActiveSetBuild())
            {
                txdb.TxnAbort();
                strError = "could not stage stale DAG recovery-marker cleanup";
                return false;
            }
            if (!txdb.TxnCommit(true))
            {
                strError = "could not commit stale DAG recovery-marker cleanup";
                return false;
            }
        }
        return true;
    }

    if (walletStatus == TXDB_READ_FOUND)
    {
        strError = strprintf(
            "DAG active-set persistence needs repair (%s), but a committed "
            "shielded-wallet transition is pending; disconnected-block plans "
            "cannot be reconstructed from the current transaction index",
            strCoverageError.empty() ? "best-tip marker mismatch"
                                     : strCoverageError.c_str());
        return false;
    }

    // A tip below the DAG fork has no variable activation sets.  Stamp it
    // directly; this also gives downgrade detection before activation.
    if (pindexBest->nHeight < FORK_HEIGHT_DAG)
    {
        if (!txdb.TxnBegin())
        {
            strError = "could not begin pre-DAG active-set marker transaction";
            return false;
        }
        if (!txdb.WriteDAGActiveSetBest(hashDurableBest) ||
            (buildStatus == TXDB_READ_FOUND &&
             !txdb.EraseDAGActiveSetBuild()))
        {
            txdb.TxnAbort();
            strError = "could not stage pre-DAG active-set marker";
            return false;
        }
        if (!txdb.TxnCommit(true))
        {
            strError = "could not commit pre-DAG active-set marker";
            return false;
        }
        return true;
    }

    bool fResumeBuild = false;
    if (buildStatus == TXDB_READ_FOUND &&
        build.hashTargetBest == hashDurableBest &&
        build.nTargetHeight == pindexBest->nHeight)
    {
        CBlockIndex* pTrusted = GetAncestorAtHeight(
            pindexBest, build.nTrustedBaseHeight);
        CBlockIndex* pNext = GetAncestorAtHeight(
            pindexBest, build.nNextHeight);
        if ((build.nTrustedBaseHeight < 0 ||
             (pTrusted && pTrusted->GetBlockHash() == build.hashTrustedBase)) &&
            (build.nNextHeight < 0 ||
             (pNext && pNext->GetBlockHash() == build.hashNextBlock)))
            fResumeBuild = true;
    }

    if (!fResumeBuild)
    {
        int nTrustedBaseHeight = FORK_HEIGHT_DAG - 1;
        CBlockIndex* pTrustedBase = GetAncestorAtHeight(
            pindexBest, nTrustedBaseHeight);
        int nMode = DAG_ACTIVE_SET_BUILD_REBUILD_SUFFIX;
        if (fCompletedAtCurrentTip)
        {
            // The marker matches but an interior record is absent/corrupt.
            // Retain every individually exact record and recover only holes.
            nMode = DAG_ACTIVE_SET_BUILD_REPAIR_CANONICAL;
        }
        else if (bestStatus == TXDB_READ_FOUND)
        {
            std::map<uint256, CBlockIndex*>::const_iterator itOld =
                mapBlockIndex.find(hashRecordedBest);
            if (itOld != mapBlockIndex.end() && itOld->second)
            {
                CBlockIndex* pCommon = FindCommonPrimaryAncestor(
                    pindexBest, itOld->second);
                if (pCommon && pCommon->nHeight > nTrustedBaseHeight)
                {
                    std::string strTrustedCoverageError;
                    if (!ValidateDAGActiveSetTipBinding(
                            txdb, pCommon, strTrustedCoverageError))
                    {
                        strError = strprintf(
                            "previously completed DAG active-set prefix is no longer exact: %s",
                            strTrustedCoverageError.c_str());
                        return false;
                    }
                    nTrustedBaseHeight = pCommon->nHeight;
                    pTrustedBase = pCommon;
                }
            }
        }
        if (!pTrustedBase || !pTrustedBase->phashBlock)
        {
            strError = strprintf(
                "canonical chain is truncated before DAG recovery base height %d",
                nTrustedBaseHeight);
            return false;
        }

        build = CDAGActiveSetBuildRecord();
        build.nMode = nMode;
        build.hashTargetBest = hashDurableBest;
        build.nTargetHeight = pindexBest->nHeight;
        build.hashTrustedBase = pTrustedBase->GetBlockHash();
        build.nTrustedBaseHeight = nTrustedBaseHeight;
        build.hashNextBlock = build.hashTargetBest;
        build.nNextHeight = build.nTargetHeight;
        if (!CommitDAGActiveSetBuildMarker(txdb, build, strError))
            return false;
    }

    CBlockIndex* pNext = GetAncestorAtHeight(
        pindexBest, build.nNextHeight);
    if (!pNext || !pNext->phashBlock ||
        pNext->GetBlockHash() != build.hashNextBlock)
    {
        strError = "DAG active-set recovery progress is not on the canonical chain";
        return false;
    }
    if (build.nTrustedBaseHeight >= FORK_HEIGHT_DAG)
    {
        CBlockIndex* pTrustedBase = GetAncestorAtHeight(
            pindexBest, build.nTrustedBaseHeight);
        std::string strTrustedCoverageError;
        if (!pTrustedBase ||
            !ValidateDAGActiveSetTipBinding(
                txdb, pTrustedBase, strTrustedCoverageError))
        {
            strError = strprintf(
                "DAG active-set recovery trusted prefix is incomplete%s%s",
                strTrustedCoverageError.empty() ? "" : ": ",
                strTrustedCoverageError.c_str());
            return false;
        }
    }

    // Walk the target tip's pprev chain newest to oldest; the records are independent, and
    // persisted pnext pointers are not trusted.
    CBlockIndex* pCursor = pNext;
    while (build.nNextHeight > build.nTrustedBaseHeight)
    {
        if (fRequestShutdown)
        {
            strError = "shutdown requested during DAG active-set recovery";
            return false;
        }
        if (!txdb.TxnBegin())
        {
            strError = "could not begin DAG active-set recovery chunk";
            return false;
        }
        bool fChunkOK = true;
        size_t nChunkCount = 0;
        for (; pCursor &&
               pCursor->nHeight > build.nTrustedBaseHeight &&
               nChunkCount < DAG_ACTIVE_SET_RECOVERY_CHUNK;
             ++nChunkCount)
        {
            CBlockIndex* pindex = pCursor;
            if (!pindex->phashBlock ||
                pindex->nHeight != build.nNextHeight ||
                pindex->GetBlockHash() != build.hashNextBlock)
            {
                strError = "canonical DAG recovery pprev suffix is truncated/non-contiguous";
                fChunkOK = false;
                break;
            }
            CBlock block;
            if (!block.ReadFromDisk(pindex, true) ||
                block.GetHash() != pindex->GetBlockHash() ||
                block.BuildMerkleTree() != pindex->hashMerkleRoot)
            {
                strError = strprintf(
                    "cannot read/verify canonical block at height %d during DAG active-set recovery",
                    pindex->nHeight);
                fChunkOK = false;
                break;
            }

            bool fHaveExactRecord = false;
            if (build.nMode == DAG_ACTIVE_SET_BUILD_REPAIR_CANONICAL)
            {
                std::set<uint256> setExisting;
                std::string strReadError;
                fHaveExactRecord = txdb.ReadDAGSkippedTxsStatus(
                    block, setExisting, strReadError) == TXDB_READ_FOUND;
            }
            if (!fHaveExactRecord)
            {
                if (!ProveLegacyCanonicalBlockFullyActive(
                        txdb, block, pindex, strError))
                {
                    fChunkOK = false;
                    break;
                }
                std::string strWriteError;
                if (!txdb.WriteDAGSkippedTxs(
                        block, std::set<uint256>(), strWriteError))
                {
                    strError = strprintf(
                        "failed to stage recovered active set at height %d: %s",
                        pindex->nHeight, strWriteError.c_str());
                    fChunkOK = false;
                    break;
                }
            }
            pCursor = pindex->pprev;
            if (!pCursor || !pCursor->phashBlock)
            {
                strError = "canonical DAG recovery pprev suffix ended before its trusted base";
                fChunkOK = false;
                break;
            }
            build.hashNextBlock = pCursor->GetBlockHash();
            build.nNextHeight = pCursor->nHeight;
        }
        if (fChunkOK && nChunkCount == 0)
        {
            strError = "canonical DAG recovery made no bounded progress";
            fChunkOK = false;
        }
        if (!fChunkOK || !txdb.WriteDAGActiveSetBuild(build))
        {
            txdb.TxnAbort();
            if (fChunkOK)
                strError = "failed to stage DAG active-set recovery progress";
            return false;
        }
        if (!txdb.TxnCommit(true))
        {
            strError = "failed to durably commit DAG active-set recovery chunk";
            return false;
        }
        printf("DAG active-set recovery: next height %d (trusted base %d, target %d)\n",
               build.nNextHeight, build.nTrustedBaseHeight,
               build.nTargetHeight);
    }
    if (build.nNextHeight != build.nTrustedBaseHeight ||
        build.hashNextBlock != build.hashTrustedBase)
    {
        strError = "DAG active-set recovery did not reach its target tip";
        return false;
    }

    if (!ValidateDAGActiveSetTipBinding(
            txdb, pindexBest, strCoverageError))
    {
        strError = strprintf(
            "DAG active-set recovery completed an invalid suffix: %s",
            strCoverageError.c_str());
        return false;
    }
    uint256 hashBestCheck;
    if (!txdb.ReadHashBestChain(hashBestCheck) ||
        hashBestCheck != build.hashTargetBest ||
        pindexBest->GetBlockHash() != build.hashTargetBest)
    {
        strError = "durable best changed during DAG active-set recovery";
        return false;
    }
    if (!txdb.TxnBegin())
    {
        strError = "could not begin DAG active-set recovery finalization";
        return false;
    }
    if (!txdb.WriteDAGActiveSetBest(build.hashTargetBest) ||
        !txdb.EraseDAGActiveSetBuild())
    {
        txdb.TxnAbort();
        strError = "could not stage DAG active-set recovery finalization";
        return false;
    }
    if (!txdb.TxnCommit(true))
    {
        strError = "could not durably finalize DAG active-set recovery";
        return false;
    }
    printf("DAG active-set recovery complete at height %d (%s)\n",
           pindexBest->nHeight,
           pindexBest->GetBlockHash().ToString().substr(0, 20).c_str());
    return true;
}

// Issuance headroom under the supply cap for the block extending pindexPrev. Reads only
// pindexPrev->nMoneySupply, a fold over the block's ancestors, so it is deterministic.
int64_t GetRemainingIssuance(const CBlockIndex* pindexPrev, int64_t nCommitted)
{
    // Height of the block being paid, taken from its own parent rather than the tip.
    const int nHeight = pindexPrev ? pindexPrev->nHeight + 1 : 0;
    if (!IsSupplyCapActiveAtHeight(nHeight))
        return std::numeric_limits<int64_t>::max();

    const int64_t nCap = GetSupplyCapAmount();
    const int64_t nSupply = pindexPrev ? pindexPrev->nMoneySupply : 0;
    if (nSupply >= nCap)
        return 0;
    int64_t nRemaining = nCap - nSupply;
    if (nCommitted > 0)
        nRemaining = (nCommitted >= nRemaining) ? 0 : nRemaining - nCommitted;
    return nRemaining;
}

int64_t ClampSubsidyToSupplyCap(int64_t nSubsidy, const CBlockIndex* pindexPrev, int64_t nCommitted)
{
    if (nSubsidy <= 0)
        return nSubsidy;
    const int64_t nRemaining = GetRemainingIssuance(pindexPrev, nCommitted);
    return (nSubsidy > nRemaining) ? nRemaining : nSubsidy;
}

// The block subsidy schedule: height in, issuance out. No fees, supply clamp or size
// penalty, so the finality reserve can be a share of it at any height.

// One rung of the post-DAG proof-of-work ladder: the last height it pays,
// counted in PRE-DAG-cadence blocks past FORK_HEIGHT_DAG, and the reward the
// pre-DAG cadence assigns it.
//
// GetPostDagProofOfWorkSubsidy stretches the boundary by the block-spacing ratio
// and divides the reward by the same ratio, so a rung keeps the wall-clock span
// and the total payout the pre-DAG schedule promised. Storing the offset rather
// than the absolute height makes the ladder shift-invariant: moving
// MAINNET_V5_ACTIVATION_SHIFT moves every boundary with the fork.
struct PoWPostDagTier
{
    int nOffsetLast;    // last height, in pre-DAG-cadence blocks past the fork
    int64_t nSubsidy;   // pre-DAG-cadence reward, before the spacing divisor
};

// Mainnet. Every rung the 15s schedule placed above the DAG fork, as an offset
// from it. Re-derived for FORK_HEIGHT_DAG = 8,220,000: the 8,250,000 and
// 8,500,000 rungs now sit above the gate, so they belong here rather than in the
// pre-DAG ladder. Stretched, they end at 8,670,000 and 12,420,000.
static const PoWPostDagTier vPoWPostDagMainnet[] = {
    {   30000,  20000000 },   // 0.2  INN (was <= 8,250,000)
    {  280000,  15000000 },   // 0.15     (was <= 8,500,000)
    {  530000,  10000000 },   // 0.1      (was <= 8,750,000)
    {  780000,   5000000 },   // 0.05     (was <= 9,000,000)
    { 1030000,   1000000 },   // 0.01     (was <= 9,250,000)
    { 1280000,   5000000 },   // 0.05     (was <= 9,500,000)
    { 1530000,  10000000 },   // 0.1      (was <= 9,750,000)
    { 1780000,  20000000 },   // 0.2      (was <= 10,000,000)
};
static const int64_t nPoWPostDagTailMainnet = 10000;      // 0.0001

// Testnet: mainnet's rung rewards over rungs a hundredth as long (666666 satoshi a block
// on the first rung).
static const PoWPostDagTier vPoWPostDagTestnet[] = {
    {   2000,  10000000 },
    {   4500,   5000000 },
    {   7000,   1000000 },
    {   9500,   5000000 },
    {  12000,  10000000 },
    {  14500,  20000000 },
};
static const int64_t nPoWPostDagTailTestnet = 10000;

// Regtest: the same rung shape, first post-fork rung paying exactly the pre-fork 50 INN,
// over rungs short enough to mine across.
static const PoWPostDagTier vPoWPostDagRegtest[] = {
    {  20,  75000000000LL },   //  750 INN -> 50 INN after the divisor
    {  40,  37500000000LL },   //  375     -> 25
    {  60,   7500000000LL },   //   75     ->  5
    {  80,  37500000000LL },   //  375     -> 25
    { 100,  75000000000LL },   //  750     -> 50
    { 120, 150000000000LL },   // 1500     -> 100
};
// Regtest's tail funds harnesses, it does not model scarcity. The chain is a
// fixture rebuilt from genesis every run, so a decaying tail buys nothing and
// costs the multi-epoch harnesses their funding: the last rung ends at 1811 and
// the committee harness has to hold six 25,000 INN collateral registrations by
// height 4051, which a 0.05 INN tail cannot reach at any reachable height.
// 500 INN a block clears that with room for the harness to grow, and still
// leaves the MAX_MONEY clamp unreached until ~37,600 -- an order of magnitude
// deeper than any harness in contrib/test mines. Mainnet and testnet keep their
// own tails above; this constant is read only when fRegTest is set.
static const int64_t nPoWPostDagTailRegtest = 750000000000LL;  // 7500 -> 500

static const PoWPostDagTier* GetPoWPostDagLadder(size_t& nCount, int64_t& nTail)
{
    if (fRegTest)
    {
        nCount = ARRAYLEN(vPoWPostDagRegtest);
        nTail = nPoWPostDagTailRegtest;
        return vPoWPostDagRegtest;
    }
    if (fTestNet)
    {
        nCount = ARRAYLEN(vPoWPostDagTestnet);
        nTail = nPoWPostDagTailTestnet;
        return vPoWPostDagTestnet;
    }
    nCount = ARRAYLEN(vPoWPostDagMainnet);
    nTail = nPoWPostDagTailMainnet;
    return vPoWPostDagMainnet;
}

// Post-DAG PoW subsidy, before fees, on every network. Rewards are divided by the
// spacing ratio (PRE_DAG_TARGET_SPACING / GetTargetSpacingForHeight) and rung
// boundaries stretched by the same ratio, preserving wall-clock issuance.
int64_t GetPostDagProofOfWorkSubsidy(int nHeight)
{
    const int64_t nPostSpacing = (int64_t)GetTargetSpacingForHeight(nHeight);
    size_t nCount = 0;
    int64_t nSubsidy = 0;
    const PoWPostDagTier* pLadder = GetPoWPostDagLadder(nCount, nSubsidy);

    for (size_t i = 0; i < nCount; i++)
    {
        const int64_t nLast = (int64_t)FORK_HEIGHT_DAG +
            (int64_t)pLadder[i].nOffsetLast * PRE_DAG_TARGET_SPACING / nPostSpacing;
        if ((int64_t)nHeight <= nLast)
        {
            nSubsidy = pLadder[i].nSubsidy;
            break;
        }
    }

    return nSubsidy * nPostSpacing / PRE_DAG_TARGET_SPACING;
}


int64_t GetBlockSubsidySchedule(int nHeight)
{
  int64_t nSubsidy = 1 * COIN;

  // Shared by every network from its own DAG fork height. Kept ahead of the
  // per-network ladders below so those describe pre-DAG emission only.
  if (nHeight >= FORK_HEIGHT_DAG)
  {
      nSubsidy = GetPostDagProofOfWorkSubsidy(nHeight);

      if (fDebug && GetBoolArg("-printcreation"))
          printf("GetBlockSubsidySchedule() : create=%s nSubsidy=%" PRId64"\n", FormatMoney(nSubsidy).c_str(), nSubsidy);

      return nSubsidy;
  }

  // use nHeight parameter instead of pindexBest->nHeight
  // to correctly compute reward during validation of non-tip blocks
  if (fRegTest) {
       // Regtest: simple flat reward for easy testing (similar to Bitcoin regtest)
       if (nHeight == 0)
           nSubsidy = 0;  // Genesis block has no spendable reward
       else
           nSubsidy = 50 * COIN;  // 50 INN per block

       return nSubsidy;
  } else if (fTestNet) {
       if (nHeight == 1)
           nSubsidy = 1000000 * COIN;  // 10m INN Premine for Testnet for testing
       else if (nHeight <= FAIR_LAUNCH_BLOCK) // Block 490, Instamine prevention
           nSubsidy = 1 * COIN/2;
       else if (nHeight <= 5000)
           nSubsidy = 10 * COIN;
       else // Block 5000
           nSubsidy = 0;

       return nSubsidy;
   } else {
  // use nHeight parameter throughout
  if (nHeight == 1)
      nSubsidy = 10350000 * COIN;  //Swap amount for Innova Chain v0.12 + Founders Fund 2.25 million
    else if (nHeight <= FAIR_LAUNCH_BLOCK) // Block 490, Instamine prevention
      nSubsidy = 0.165 * COIN/2;
    else if (nHeight <= 5000)
      nSubsidy = 0.33 * COIN;
    else if (nHeight <= 10000)
      nSubsidy = 0.66 * COIN;
    else if (nHeight <= 15000)
      nSubsidy = 0.99 * COIN;
    else if (nHeight <= 20000)
      nSubsidy = 1.32 * COIN;
    else if (nHeight <= 25000)
      nSubsidy = 1.65 * COIN;
    else if (nHeight <= 27500)
      nSubsidy = 1.485 * COIN;
    else if (nHeight <= 30000)
      nSubsidy = 1.32 * COIN;
    else if (nHeight <= 32500)
      nSubsidy = 1.155 * COIN;
    else if (nHeight <= 35000)
      nSubsidy = 0.99 * COIN;
    else if (nHeight <= 37500)
      nSubsidy = 0.825 * COIN;
    else if (nHeight <= 40000)
      nSubsidy = 0.66 * COIN;
    else if (nHeight <= 42500)
      nSubsidy = 0.495 * COIN;
    else if (nHeight <= 45000)
      nSubsidy = 0.33 * COIN;
    else if (nHeight <= 47500)
      nSubsidy = 0.165 * COIN;
    else if (nHeight <= 50000)
      nSubsidy = 0.0825 * COIN;
    else if (nHeight > ZERO_POW_BLOCK && nHeight < 2000000)
      nSubsidy = 0 * COIN;
    else if (nHeight > 2000000 && nHeight <= 2080000) // Hard Fork roll back - Innova Foundation Fund hack
      nSubsidy = 1 * COIN;
    else if (nHeight <= 2150000)
      nSubsidy = 0.5 * COIN;
    else if (nHeight <= 2400000)
      nSubsidy = 0.1 * COIN;
    else if (nHeight <= 2700000) // New PoW Structure restarts here
      nSubsidy = 0.0001 * COIN;
    else if (nHeight <= 2750000) // 0.15 Coin PoW Reward to release 7,500 INN in 50,000 blocks
      nSubsidy = 0.15 * COIN;
    else if (nHeight <= 3000000) // 0.2 Coin PoW Reward to release 50,000 INN in 250,000 blocks
      nSubsidy = 0.2 * COIN;
    else if (nHeight <= 3250000) // 0.25 Coin PoW Reward to release 62,500 INN in 250,000 blocks
      nSubsidy = 0.25 * COIN;
    else if (nHeight <= 3500000) // 0.5 Coin PoW Reward to release 125,000 INN in 250,000 blocks
      nSubsidy = 0.5 * COIN;
    else if (nHeight <= 3750000) // 0.75 Coin PoW Reward to release 187,500 INN in 250,000 blocks
      nSubsidy = 0.75 * COIN;
    else if (nHeight <= 4000000) // 0.5 Coin PoW Reward to release 125,000 INN in 250,000 blocks
      nSubsidy = 0.5 * COIN;
    else if (nHeight <= 4025000) // 1 Coin PoW Reward for peak payout in new cycle to release 1 CollateralNode in 25,000 blocks!!
      nSubsidy = 1 * COIN;
    else if (nHeight <= 4250000) // 0.5 Coin PoW Reward to release 112,500 INN in 225,000 blocks
      nSubsidy = 0.5 * COIN;
    else if (nHeight <= 4500000) // 0.25 Coin PoW Reward to release 62,500 INN in 250,000 blocks
      nSubsidy = 0.25 * COIN;
    else if (nHeight <= 4750000) // 0.2 Coin PoW Reward to release 50,000 INN in 250,000 blocks
      nSubsidy = 0.2 * COIN;
    else if (nHeight <= 5000000) // 0.15 Coin PoW Reward to release 37,500 INN in 250,000 blocks
      nSubsidy = 0.15 * COIN;
    else if (nHeight <= 5250000) // 0.1 Coin PoW Reward to release 1 CollateralNode in 250,000 blocks
      nSubsidy = 0.1 * COIN;
    else if (nHeight <= 5500000) // 0.05 Coin PoW Reward to release 12,500 INN in 250,000 blocks
      nSubsidy = 0.05 * COIN;
    else if (nHeight <= 5750000) // 0.01 Coin PoW Reward to release 2,500 INN in 250,000 blocks
      nSubsidy = 0.01 * COIN;
    else if (nHeight <= 6000000) // 0.1 Coin PoW Reward for peak payout in new cycle to release 1 Collateral Node in 250,000 blocks
      nSubsidy = 0.1 * COIN;
    else if (nHeight <= 6250000) // 0.15 Coin PoW Reward to release 37,500 INN in 250,000 blocks
      nSubsidy = 0.15 * COIN;
    else if (nHeight <= 6500000) // 0.2 Coin PoW Reward to release 50,000 INN in 250,000 blocks
      nSubsidy = 0.2 * COIN;
    else if (nHeight <= 6750000) // 0.25 Coin PoW Reward to release 62,500 INN in 250,000 blocks
      nSubsidy = 0.25 * COIN;
    else if (nHeight <= 7000000) // 0.5 Coin PoW Reward to release 125,000 INN in 250,000 blocks
      nSubsidy = 0.5 * COIN;
    else if (nHeight <= 7250000) // 0.75 Coin PoW Reward to release 187,500 INN in 250,000 blocks
      nSubsidy = 0.75 * COIN;
    else if (nHeight <= 7500000) // 0.5 Coin PoW Reward to release 125,000 INN in 250,000 blocks
      nSubsidy = 0.5 * COIN;
    else if (nHeight <= 7525000) // 1 Coin PoW Reward for peak payout in new cycle to release 1 CollateralNode in 25,000 blocks!!
      nSubsidy = 1 * COIN;
    else if (nHeight <= 7750000) // 0.5 Coin PoW Reward to release 112,500 INN in 225,000 blocks
      nSubsidy = 0.5 * COIN;
    else if (nHeight <= 8000000) // 0.25 Coin PoW Reward to release 62,500 INN in 250,000 blocks
      nSubsidy = 0.25 * COIN;
    else if (nHeight <= 8250000) // 0.2 Coin PoW Reward to release 50,000 INN in 250,000 blocks
      nSubsidy = 0.2 * COIN;
    else if (nHeight <= 8500000) // 0.15 Coin PoW Reward to release 37,500 INN in 250,000 blocks
      nSubsidy = 0.15 * COIN;
    else
      // Unreachable at the current fork height: the post-DAG path above
      // intercepts everything from 8,130,000 on, so this ladder is only ever
      // asked for heights the 8,250,000 rung already covers. Left as the 15s
      // schedule's next rung so it stays correct if the fork moves up.
      nSubsidy = 10000000; // 0.1 INN

      return nSubsidy;
    }
}

// PoW coinbase reward: the schedule, clamped to the issuance headroom, plus fees.
// nCommitted (the finality settlement payout, itself clamped) comes off the headroom
// first, so the subsidy yields to it.
int64_t GetProofOfWorkReward(int nHeight, int64_t nFees, const CBlockIndex* pindexPrev, int64_t nCommitted)
{
    int64_t nSubsidy = ClampSubsidyToSupplyCap(GetBlockSubsidySchedule(nHeight), pindexPrev, nCommitted);

    if (fDebug && GetBoolArg("-printcreation"))
        printf("GetProofOfWorkReward() : create=%s nSubsidy=%" PRId64"\n", FormatMoney(nSubsidy).c_str(), nSubsidy);

    return nSubsidy + nFees;
}

const int YEARLY_BLOCKCOUNT = 2103792; // Amount of Blocks per year

// Proof of Stake miner's coin stake reward based on coin age spent (coin-days)
int64_t GetProofOfStakeReward(int64_t nCoinAge, int64_t nFees, const CBlockIndex* pindexPrev, int64_t nCommitted)
{
    // Height of the block being paid, from its own parent, never the node's tip.
    const int nHeight = pindexPrev ? pindexPrev->nHeight + 1 : 0;

    // Unreachable: YEARLY_BLOCKCOUNT * 9000 == 18,934,128,000, and nHeight is an int.
    // Retained because it states the intended shape -- past the cutoff, fees only --
    // which is what the supply cap below actually delivers.
    if ((int64_t)nHeight > (int64_t)YEARLY_BLOCKCOUNT * 9000) // It's Over 9000!! [years] - Vegeta
        return nFees;

    int64_t nRewardCoinYear;
    nRewardCoinYear = COIN_YEAR_REWARD; // 0.06 6%

    int64_t nSubsidy;
    nSubsidy = nCoinAge / 365 * nRewardCoinYear + nCoinAge % 365 * nRewardCoinYear / 365;

    // Total-supply cap. Coin-age carries no height bound, so this is the only
    // thing that ever stops the stake subsidy. Fees are added after the clamp and
    // keep paying at and past the cap.
    nSubsidy = ClampSubsidyToSupplyCap(nSubsidy, pindexPrev, nCommitted);

    if (fDebug && GetBoolArg("-printcreation"))
        printf("GetProofOfStakeReward(): create=%s nCoinAge=%" PRId64"\n", FormatMoney(nSubsidy).c_str(), nCoinAge);

    return nSubsidy + nFees;
}

static const int64_t nTargetTimespan = 30;

//
// maximum nBits value could possible be required nTime after
//
unsigned int ComputeMaxBits(CBigNum bnTargetLimit, unsigned int nBase, int64_t nTime)
{
    CBigNum bnResult;
    bnResult.SetCompact(nBase);
    bnResult *= 2;
    while (nTime > 0 && bnResult < bnTargetLimit)
    {
        // Maximum 200% adjustment per day...
        bnResult *= 2;
        nTime -= 24 * 60 * 60;
    }
    if (bnResult > bnTargetLimit)
        bnResult = bnTargetLimit;
    return bnResult.GetCompact();
}

//
// minimum amount of work that could possibly be required nTime after
// minimum proof-of-work required was nBase
//
unsigned int ComputeMinWork(unsigned int nBase, int64_t nTime)
{
    return ComputeMaxBits(bnProofOfWorkLimit, nBase, nTime);
}

//
// minimum amount of stake that could possibly be required nTime after
// minimum proof-of-stake required was nBase
//
unsigned int ComputeMinStake(unsigned int nBase, int64_t nTime, unsigned int nBlockTime)
{
    return ComputeMaxBits(bnProofOfStakeLimit, nBase, nTime);
}


// ppcoin: find last block index up to pindex
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
        pindex = pindex->pprev;
    return pindex;
}

unsigned int ComputeRetargetedBits(unsigned int nPrevBits, int64_t nActualSpan,
                                   unsigned int nEffectiveSpacing, int nWindow,
                                   bool fTighterDrift, const CBigNum& bnTargetLimit)
{
    if (nWindow < 1) nWindow = 1;
    int64_t nTargetSpan = (int64_t)nEffectiveSpacing * nWindow;

    // Clamp the observation (tighter bounds post-fork, negative-only pre-fork)
    if (!fTighterDrift)
    {
        if (nActualSpan < 0)
            nActualSpan = nTargetSpan;
    }
    else
    {
        const int nClampFactor = 4;
        int64_t nMinSpan = nTargetSpan / nClampFactor;
        if (nMinSpan < 1) nMinSpan = 1;
        int64_t nMaxSpan = nTargetSpan * nClampFactor;

        if (nActualSpan < nMinSpan)
        {
            if (nActualSpan < 0)
                printf("WARNING: ComputeRetargetedBits() : negative actual span %" PRId64 " (clamping to %" PRId64 ")\n",
                       nActualSpan, nMinSpan);
            nActualSpan = nMinSpan;
        }
        if (nActualSpan > nMaxSpan)
            nActualSpan = nMaxSpan;
    }

    CBigNum bnNew;
    bnNew.SetCompact(nPrevBits);
    int64_t nSmoothTimespan = fTighterDrift ? 180 : nTargetTimespan;
    int64_t nInterval = nSmoothTimespan / nEffectiveSpacing;
    bnNew *= ((nInterval - 1) * nTargetSpan + nActualSpan + nActualSpan);
    bnNew /= ((nInterval + 1) * nTargetSpan);

    if (bnNew <= 0 || bnNew > bnTargetLimit)
        bnNew = bnTargetLimit;

    return bnNew.GetCompact();
}

unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake)
{
    CBigNum bnTargetLimit = fProofOfStake ? bnProofOfStakeLimit : bnProofOfWorkLimit;

    if (pindexLast == NULL)
        return bnTargetLimit.GetCompact(); // genesis block

    // Regtest does not retarget: nBits is pinned at the limit, so the post-DAG window
    // below cannot ramp difficulty.
    if (fRegTest)
        return bnTargetLimit.GetCompact();

    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
    if (pindexPrev->pprev == NULL)
        return bnTargetLimit.GetCompact(); // first block
    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);
    if (pindexPrevPrev->pprev == NULL)
        return bnTargetLimit.GetCompact(); // second block

    int nNextHeight = pindexLast->nHeight + 1;
    unsigned int nEffectiveSpacing = GetTargetSpacingForHeight(nNextHeight);
    bool fTighterDrift = (nNextHeight >= FORK_HEIGHT_TIGHTER_DRIFT);

    // Observation window. Pre-DAG it is 1, bit-identical to the old retarget. Post-DAG a
    // 1s gap is at timestamp resolution, so a window is needed for difficulty to tighten;
    // it only spans blocks at or after the DAG fork.
    int nWindow = 1;
    const CBlockIndex* pindexWindow = pindexPrevPrev;
    if (nNextHeight >= FORK_HEIGHT_DAG)
    {
        int nAvailable = pindexPrev->nHeight - FORK_HEIGHT_DAG;
        int nWant = std::min(POST_DAG_RETARGET_WINDOW, nAvailable);
        while (nWindow < nWant && pindexWindow->pprev)
        {
            const CBlockIndex* pindexStep = GetLastBlockIndex(pindexWindow->pprev, fProofOfStake);
            if (pindexStep == NULL || pindexStep->pprev == NULL)
                break;
            pindexWindow = pindexStep;
            nWindow++;
        }
    }

    int64_t nActualSpan = pindexPrev->GetBlockTime() - pindexWindow->GetBlockTime();

    return ComputeRetargetedBits(pindexPrev->nBits, nActualSpan, nEffectiveSpacing,
                                 nWindow, fTighterDrift, bnTargetLimit);
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits)
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    // Check range
    if (bnTarget <= 0 || bnTarget > bnProofOfWorkLimit)
        return error("CheckProofOfWork() : nBits below minimum work");

    // Check proof of work matches claimed amount
    if (hash > bnTarget.getuint256())
        return error("CheckProofOfWork() : hash doesn't match nBits");

    return true;
}

// Return maximum amount of blocks that other nodes claim to have
int GetNumBlocksOfPeers()
{
    int nPeerHeight = -1;
    int64_t nNow = GetTime();
    TRY_LOCK(cs_vNodes, lockNodes);
    if (lockNodes)
    {
        for (CNode* pnode : vNodes)
        {
            if (!pnode || pnode->fClient)
                continue;
            if (pnode->nBestKnownHeight > 0 && pnode->nLastHeightUpdate > 0 && nNow - pnode->nLastHeightUpdate <= 120)
                nPeerHeight = std::max(nPeerHeight, pnode->nBestKnownHeight);
        }
    }
    if (nPeerHeight >= 0)
        return std::max(nPeerHeight, Checkpoints::GetTotalBlocksEstimate());
    return std::max(cPeerBlockCounts.median(), Checkpoints::GetTotalBlocksEstimate());
}

bool IsSynchronized() {
  static bool rc = false;
  if(rc == false) rc = !IsInitialBlockDownload();
  return rc;
}

bool ValidatePrivacyVNextIndexPersistence(
    CTxDB& txdb, std::string& strError)
{
    LOCK(cs_main);
    strError.clear();
    if (!pindexBest || !pindexBest->phashBlock ||
        !IsBoundaryBActiveAtHeight(pindexBest->nHeight))
        return true;

    std::vector<CBlockIndex*> vBoundaryBChain;
    for (CBlockIndex* pindex = pindexBest;
         pindex && IsBoundaryBActiveAtHeight(pindex->nHeight);
         pindex = pindex->pprev)
        vBoundaryBChain.push_back(pindex);
    std::reverse(vBoundaryBChain.begin(), vBoundaryBChain.end());

    std::set<uint256> setExpectedKeyImages;
    std::set<uint256> setExpectedOutputBases;
    std::set<uint256> setExpectedAttestations;
    for (std::vector<CBlockIndex*>::const_iterator blockIt =
             vBoundaryBChain.begin();
         blockIt != vBoundaryBChain.end(); ++blockIt)
    {
        CBlockIndex* pindex = *blockIt;
        CBlock block;
        if (!block.ReadFromDisk(pindex, true) ||
            block.GetHash() != pindex->GetBlockHash() ||
            block.BuildMerkleTree() != pindex->hashMerkleRoot)
        {
            strError = strprintf("Boundary-B block %d is unavailable or corrupt",
                                 pindex->nHeight);
            return false;
        }

        std::set<uint256> setSkipped;
        if (pindex->nHeight >= FORK_HEIGHT_DAG)
        {
            std::string strActiveSetError;
            const TxDBReadStatus status = txdb.ReadDAGSkippedTxsStatus(
                block, setSkipped, strActiveSetError);
            if (status != TXDB_READ_FOUND)
            {
                strError = strprintf(
                    "Boundary-B DAG active set is missing/corrupt at height %d%s%s",
                    pindex->nHeight,
                    strActiveSetError.empty() ? "" : ": ",
                    strActiveSetError.c_str());
                return false;
            }
        }
        const CBlock activeBlock = GetDAGActiveBlock(block, setSkipped);
        for (std::vector<CTransaction>::const_iterator txIt =
                 activeBlock.vtx.begin();
             txIt != activeBlock.vtx.end(); ++txIt)
        {
            const CTransaction& tx = *txIt;
            if (!tx.IsPrivacyVNext())
                continue;
            PrivacyVNextStateEffects effects;
            const PrivacyVNextPayloadValidation validation =
                ExtractPrivacyVNextPayloadEffects(
                    static_cast<uint32_t>(tx.nVersion),
                    tx.privacyVNext.vchPayload, effects);
            if (!validation.IsValid())
            {
                strError = strprintf(
                    "accepted IV5 payload %s cannot be replayed: %s",
                    tx.GetHash().ToString().substr(0,10).c_str(),
                    validation.strError.c_str());
                return false;
            }
            std::string strBindingError;
            if (!CheckPrivacyVNextTransparentBinding(tx, effects,
                                                     strBindingError))
            {
                strError = strprintf(
                    "accepted IV5 payload %s: %s",
                    tx.GetHash().ToString().substr(0,10).c_str(),
                    strBindingError.c_str());
                return false;
            }

            bool fContextLocalFailure = false;
            std::string strContextError;
            if (!ValidatePrivacyVNextFinalizedContext(
                    txdb, pindex->nHeight, effects,
                    fContextLocalFailure, strContextError))
            {
                strError = strprintf(
                    "accepted IV5 payload %s has invalid finalized context: %s",
                    tx.GetHash().ToString().substr(0,10).c_str(),
                    strContextError.c_str());
                return false;
            }

            for (size_t i = 0; i < effects.keyImages.size(); ++i)
            {
                uint256 keyImage;
                memcpy(keyImage.begin(), effects.keyImages[i].data(),
                       effects.keyImages[i].size());
                if (!setExpectedKeyImages.insert(keyImage).second)
                {
                    strError = strprintf(
                        "duplicate IV5 spent key %s in active chain",
                        keyImage.ToString().substr(0,10).c_str());
                    return false;
                }
                CPrivacyVNextNullifierSpent spent;
                const TxDBReadStatus status =
                    txdb.ReadPrivacyVNextNullifierStatus(keyImage, spent);
                if (status != TXDB_READ_FOUND ||
                    spent.txnHash != tx.GetHash() || spent.nIndex != i ||
                    spent.nHeight != pindex->nHeight)
                {
                    strError = strprintf(
                        "IV5 spent-key record %s is missing, corrupt, misplaced, or owned "
                        "by another input",
                        keyImage.ToString().substr(0,10).c_str());
                    return false;
                }
            }

            for (size_t i = 0; i < effects.attestationKeyImages.size(); ++i)
            {
                uint256 keyImage;
                memcpy(keyImage.begin(),
                       effects.attestationKeyImages[i].data(),
                       effects.attestationKeyImages[i].size());
                if (!setExpectedAttestations.insert(keyImage).second)
                {
                    strError = strprintf(
                        "duplicate IV5 attestation %s in active chain",
                        keyImage.ToString().substr(0,10).c_str());
                    return false;
                }
                CPrivacyVNextCollateralAttestation attested;
                const TxDBReadStatus status =
                    txdb.ReadPrivacyVNextCollateralStatus(keyImage, attested);
                if (status != TXDB_READ_FOUND ||
                    attested.txnHash != tx.GetHash())
                {
                    strError = strprintf(
                        "IV5 collateral record %s is missing, corrupt, or owned by "
                        "another attestation",
                        keyImage.ToString().substr(0,10).c_str());
                    return false;
                }
            }

            for (size_t i = 0; i < effects.outputLeaves.size(); ++i)
            {
                uint256 base;
                memcpy(base.begin(),
                       effects.outputLeaves[i].nullifierBase.data(),
                       effects.outputLeaves[i].nullifierBase.size());
                if (!setExpectedOutputBases.insert(base).second)
                {
                    strError = strprintf(
                        "duplicate IV5 output owner %s in active chain",
                        base.ToString().substr(0,10).c_str());
                    return false;
                }
                CShieldedNullifierSpent created;
                const TxDBReadStatus status =
                    txdb.ReadPrivacyVNextOutputBaseStatus(base, created);
                if (status != TXDB_READ_FOUND ||
                    created.txnHash != tx.GetHash() || created.nIndex != i)
                {
                    strError = strprintf(
                        "IV5 output-base record %s is missing, corrupt, or owned by another output",
                        base.ToString().substr(0,10).c_str());
                    return false;
                }
            }
        }
    }

    uint64_t nPersistedCount = 0;
    if (!txdb.CountPrivacyVNextNullifiers(nPersistedCount, strError))
        return false;
    if (nPersistedCount != setExpectedKeyImages.size())
    {
        strError = strprintf(
            "IV5 spent-key index count mismatch (persisted=%" PRIu64 ", expected=%" PRIu64 ")",
            nPersistedCount,
            static_cast<uint64_t>(setExpectedKeyImages.size()));
        return false;
    }

    uint64_t nPersistedBases = 0;
    if (!txdb.CountPrivacyVNextOutputBases(nPersistedBases, strError))
        return false;
    if (nPersistedBases != setExpectedOutputBases.size())
    {
        strError = strprintf(
            "IV5 output-base index count mismatch (persisted=%" PRIu64 ", expected=%" PRIu64 ")",
            nPersistedBases,
            static_cast<uint64_t>(setExpectedOutputBases.size()));
        return false;
    }

    uint64_t nPersistedAttestations = 0;
    if (!txdb.CountPrivacyVNextCollateral(nPersistedAttestations, strError))
        return false;
    if (nPersistedAttestations != setExpectedAttestations.size())
    {
        strError = strprintf(
            "IV5 collateral index count mismatch (persisted=%" PRIu64 ", expected=%" PRIu64 ")",
            nPersistedAttestations,
            static_cast<uint64_t>(setExpectedAttestations.size()));
        return false;
    }
    return true;
}

bool IsInitialBlockDownload()
{
    if (fRegTest && pindexBest != NULL)
        return false;
    if (fImporting || fReindex || pindexBest == NULL)
        return true;

    if (nBestHeight < Checkpoints::GetTotalBlocksEstimate())
        return true;

    int64_t nNow = GetTime();
    int nFreshPeerHeight = -1;
    int64_t nFreshPeerLastBlockRecv = 0;
    bool fActiveCatchup = false;
    {
        TRY_LOCK(cs_vNodes, lockNodes);
        if (lockNodes)
        {
            for (CNode* pnode : vNodes)
            {
                if (!pnode || pnode->fClient)
                    continue;

                pnode->ExpireBlockInFlight(nNow);

                bool fFreshHeight = pnode->nBestKnownHeight > 0 &&
                                    pnode->nLastHeightUpdate > 0 &&
                                    nNow - pnode->nLastHeightUpdate <= 120;
                if (fFreshHeight)
                    nFreshPeerHeight = std::max(nFreshPeerHeight, pnode->nBestKnownHeight);

                if (pnode->nLastBlockRecv > nFreshPeerLastBlockRecv)
                    nFreshPeerLastBlockRecv = pnode->nLastBlockRecv;

                // Deliberately not gated on fFreshHeight. nLastHeightUpdate only moves when
                // a peer's height RISES, so a peer sitting at the tip goes stale after 120s
                // and stops counting -- which said a node thousands of blocks behind was not
                // in initial download, so it stopped clearing per-peer orphan counts and
                // began scoring the one peer that could help it as misbehaving. Outstanding
                // requests to a peer we know is ahead is catch-up whether or not its height
                // moved recently, and it cannot be claimed by an idle peer: something has to
                // actually be in flight.
                bool fPeerHasWork = pnode->nBestKnownHeight > nBestHeight + 2;
                if (fPeerHasWork && (!pnode->setBlocksInFlight.empty() || !pnode->mapAskFor.empty()))
                    fActiveCatchup = true;
            }
        }
    }

    unsigned int nTargetSpacing = GetTargetSpacingForHeight(nBestHeight + 1);
    int nLagTolerance = (nTargetSpacing <= 1) ? (int)GetArg("-ibdheightlag", 8) : nCoinbaseMaturity * 2;
    if (nFreshPeerHeight > nBestHeight + nLagTolerance)
        return true;

    if (fActiveCatchup)
        return true;

    int64_t nLocalLastBlockRecv = nTimeBestReceived > 0 ? nTimeBestReceived : pindexBest->GetBlockTime();
    int64_t nStaleSeconds = (nTargetSpacing <= 1) ? GetArg("-ibdstaleseconds", 30) : 300;
    if (nFreshPeerHeight > nBestHeight &&
        nFreshPeerLastBlockRecv > nLocalLastBlockRecv + 2 &&
        nNow - nLocalLastBlockRecv > nStaleSeconds)
        return true;

    return false;

}

void static InvalidChainFound(CBlockIndex* pindexNew)
{
    if (pindexNew->nChainTrust > nBestInvalidTrust)
    {
        nBestInvalidTrust = pindexNew->nChainTrust;
        CTxDB().WriteBestInvalidTrust(CBigNum(nBestInvalidTrust));
        if (pindexBest)
        {
            static int64_t nLastInvalidChainNotify = 0;
            int64_t nNow = GetTime();
            if (nNow - nLastInvalidChainNotify >= 5)
            {
                nLastInvalidChainNotify = nNow;
                uiInterface.NotifyBlocksChanged(pindexBest->nHeight, GetNumBlocksOfPeers());
            }
        }
    }

    uint256 nBestInvalidBlockTrust = (pindexNew->nHeight != 0 && pindexNew->pprev != NULL) ? (pindexNew->nChainTrust - pindexNew->pprev->nChainTrust) : pindexNew->nChainTrust;

    printf("InvalidChainFound: invalid block=%s  height=%d  trust=%s  blocktrust=%" PRId64"  date=%s\n",
      pindexNew->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->nHeight,
      CBigNum(pindexNew->nChainTrust).ToString().c_str(), nBestInvalidBlockTrust.Get64(),
      DateTimeStrFormat("%x %H:%M:%S", pindexNew->GetBlockTime()).c_str());
    if (pindexBest)
    {
        uint256 nBestBlockTrust = (pindexBest->nHeight != 0 && pindexBest->pprev != NULL) ? (pindexBest->nChainTrust - pindexBest->pprev->nChainTrust) : pindexBest->nChainTrust;
        printf("InvalidChainFound:  current best=%s  height=%d  trust=%s  blocktrust=%" PRId64"  date=%s\n",
          hashBestChain.ToString().substr(0,20).c_str(), nBestHeight,
          CBigNum(pindexBest->nChainTrust).ToString().c_str(),
          nBestBlockTrust.Get64(),
          DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());
    }
}


void CBlock::UpdateTime(const CBlockIndex* pindexPrev)
{
    nTime = max(GetBlockTime(), GetAdjustedTime());
}





// Requires cs_main.
void Misbehaving(NodeId pnode, int howmuch, const std::string& reason)
{
    if (howmuch == 0)
        return;

    LOCK(cs_vNodes);
    for (CNode* pn : vNodes)
    {
        if(pn->GetId() == pnode)
        {
            LOCK(pn->cs_nMisbehavior);
            pn->nMisbehavior += howmuch;
            int banscore = GetArg("-banscore", 100);
            if (pn->nMisbehavior >= banscore)
            {
                printf("Misbehaving: %s (%d -> %d) BAN THRESHOLD EXCEEDED%s%s\n",
                       pn->addrName.c_str(), pn->nMisbehavior-howmuch, pn->nMisbehavior,
                       reason.empty() ? "" : " reason=", reason.empty() ? "" : reason.c_str());
                pn->MarkDisconnect("ban-threshold-exceeded");
            }
            else
                printf("Misbehaving: %s (%d -> %d)%s%s\n",
                       pn->addrName.c_str(), pn->nMisbehavior-howmuch, pn->nMisbehavior,
                       reason.empty() ? "" : " reason=", reason.empty() ? "" : reason.c_str());

            break;
        }
    }
}





bool CTransaction::DisconnectInputs(CTxDB& txdb)
{
    //hooks->DisconnectInputs(*this); //Disconnect Name DB Inputs

    // Relinquish previous transactions' spent pointers
    if (!IsCoinBase())
    {
        for (const CTxIn& txin : vin)
        {
            // ANON prevouts encode a key image and ring size, not a
            // transaction-index outpoint.  Their exact chain record is undone
            // by DisconnectLegacyAnonChainState in the enclosing block batch.
            if (nVersion == ANON_TXN_VERSION && txin.IsAnonInput())
                continue;
            COutPoint prevout = txin.prevout;

            // Get prev txindex from disk
            CTxIndex txindex;
            if (!txdb.ReadTxIndex(prevout.hash, txindex))
                return error("DisconnectInputs() : ReadTxIndex failed");

            if (prevout.n >= txindex.vSpent.size())
                return error("DisconnectInputs() : prevout.n out of range");

            // Mark outpoint as not spent
            txindex.vSpent[prevout.n].SetNull();

            // Write back
            if (!txdb.UpdateTxIndex(prevout.hash, txindex))
                return error("DisconnectInputs() : UpdateTxIndex failed");
        }
    }

    // Remove transaction from index
    // This can fail if a duplicate of this transaction was in a chain that got
    // reorganized away. This is only possible if this transaction was completely
    // spent, so erasing it would be a no-op anyway.
    txdb.EraseTxIndex(*this);

    return true;
}


bool CTransaction::FetchInputs(CTxDB& txdb, const map<uint256, CTxIndex>& mapTestPool,
                               bool fBlock, bool fMiner, MapPrevTx& inputsRet, bool& fInvalid)
{
    // FetchInputs can return false either because we just haven't seen some inputs
    // (in which case the transaction should be stored as an orphan)
    // or because the transaction is malformed (in which case the transaction should
    // be dropped).  If tx is definitely invalid, fInvalid will be set to true.
    fInvalid = false;

    if (IsCoinBase())
        return true; // Coinbase transactions have no inputs to fetch.

    for (unsigned int i = 0; i < vin.size(); i++)
    {
        if (nVersion == ANON_TXN_VERSION
            && vin[i].IsAnonInput())
            continue;

        COutPoint prevout = vin[i].prevout;
        if (inputsRet.count(prevout.hash))
            continue; // Got it already

        // Read txindex
        CTxIndex& txindex = inputsRet[prevout.hash].first;
        bool fFound = true;
        if ((fBlock || fMiner) && mapTestPool.count(prevout.hash))
        {
            // Get txindex from current proposed changes
            txindex = mapTestPool.find(prevout.hash)->second;
        }
        else
        {
            // Read txindex from txdb
            fFound = txdb.ReadTxIndex(prevout.hash, txindex);
        }
        if (!fFound && (fBlock || fMiner))
            return fMiner ? false : error("FetchInputs() : %s prev tx %s index entry not found", GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());

        // Read txPrev
        CTransaction& txPrev = inputsRet[prevout.hash].second;
        if (!fFound || txindex.pos == CDiskTxPos(1,1,1))
        {
            // Get prev tx from single transactions in memory
            if (!mempool.lookup(prevout.hash, txPrev))
                return error("FetchInputs() : %s mempool Tx prev not found %s", GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());
            if (!fFound)
                txindex.vSpent.resize(txPrev.vout.size());
        }
        else
        {
            // Get prev tx from disk
            if (!txPrev.ReadFromDisk(txindex.pos))
                return error("FetchInputs() : %s ReadFromDisk prev tx %s failed", GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());
        }
    }

    // Make sure all prevout.n indexes are valid:
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        if (nVersion == ANON_TXN_VERSION
            && vin[i].IsAnonInput())
            continue;

        const COutPoint prevout = vin[i].prevout;
        if (inputsRet.count(prevout.hash) == 0)
            return DoS(100, error("ConnectInputs() : missing input %s", prevout.hash.ToString().substr(0,10).c_str()));
        const CTxIndex& txindex = inputsRet[prevout.hash].first;
        const CTransaction& txPrev = inputsRet[prevout.hash].second;
        if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
        {
            // Revisit this if/when transaction replacement is implemented and allows
            // adding inputs:
            fInvalid = true;
            if (fDebugNet)
                return DoS(100, error("FetchInputs() : %s prevout.n out of range %d %" PRIszu" %" PRIszu" prev tx %s\n%s", GetHash().ToString().substr(0,10).c_str(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString().substr(0,10).c_str(), txPrev.ToString().c_str()));
            return DoS(100, false);

        }
    }

    return true;
}

// Ring Signatures - I n n o v a
int GetAnonTxnPreImage(const CTransaction& tx, uint256& hashOut)
{
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << tx.nVersion;
    ss << tx.nTime;
    for (uint32_t i = 0; i < tx.vin.size(); ++i)
    {
        const CTxIn& txin = tx.vin[i];
        ss << txin.prevout; // key image only

        const int nRingSize = txin.ExtractRingSize();
        if (nRingSize < 0 ||
            (size_t)nRingSize >
                (std::numeric_limits<size_t>::max() - 2) /
                    ec_compressed_size)
        {
            printf("anonymous preimage has invalid ring size %d at input %u\n",
                   nRingSize, i);
            return 1;
        }
        const size_t nPubkeyBytes =
            (size_t)nRingSize * ec_compressed_size;
        if (txin.scriptSig.size() < 2 + nPubkeyBytes)
        {
            printf("scriptSig is too small, input %u, ring size %d.\n",
                   i, nRingSize);
            return 1;
        }
        if (nPubkeyBytes > 0)
            ss.write((const char*)&txin.scriptSig[2], nPubkeyBytes);
    }

    for (uint32_t i = 0; i < tx.vout.size(); ++i)
        ss << tx.vout[i];
    ss << tx.nLockTime;
    hashOut = ss.GetHash();
    return 0;
}

static bool LegacyAnonRecordsEqual(const CKeyImageSpent& a,
                                   const CKeyImageSpent& b)
{
    return a.txnHash == b.txnHash &&
           a.inputNo == b.inputNo &&
           a.nValue == b.nValue;
}

static bool LegacyAnonRecordsEqual(const CAnonOutput& a,
                                   const CAnonOutput& b)
{
    return a.outpoint == b.outpoint &&
           a.nValue == b.nValue &&
           a.nBlockHeight == b.nBlockHeight &&
           a.nCompromised == b.nCompromised;
}

static bool LegacyAnonOutputMatureAtCandidate(const CAnonOutput& output,
                                               int nCandidateHeight)
{
    if (output.nBlockHeight <= 0 || nCandidateHeight <= 0)
        return false;
    const int64_t nPredecessorHeight = (int64_t)nCandidateHeight - 1;
    return nPredecessorHeight - output.nBlockHeight >=
           MIN_ANON_SPEND_DEPTH;
}

static int LegacyAnonMaxRingSizeAtCandidate(int nCandidateHeight)
{
    // MAX_RING_SIZE_OLD applied only while the predecessor was genesis; keyed on the
    // candidate height, not the live tip.
    return nCandidateHeight <= 1 ? (int)MAX_RING_SIZE_OLD
                                 : (int)MAX_RING_SIZE;
}

static bool CheckAnonInputAB(CTxDB &txdb, const CTxIn &txin, int i,
                             int nRingSize,
                             std::vector<uint8_t> &vchImage,
                             uint256 &preimage, int64_t &nCoinValue,
                             int nCandidateHeight, bool& fInvalid)
{
    const CScript &s = txin.scriptSig;

    CPubKey pkRingCoin;
    CAnonOutput ao;
    CTxIndex txindex;

    ec_point pSigC;
    pSigC.resize(ec_secret_size);
    memcpy(&pSigC[0], &s[2], ec_secret_size);
    const unsigned char *pSigS    = &s[2 + ec_secret_size];
    const unsigned char *pPubkeys = &s[2 + ec_secret_size + ec_secret_size * nRingSize];
    for (int ri = 0; ri < nRingSize; ++ri)
    {
        pkRingCoin = CPubKey(&pPubkeys[ri * ec_compressed_size], ec_compressed_size);
        const TxDBReadStatus outputStatus =
            txdb.ReadAnonOutputStatus(pkRingCoin, ao);
        if (outputStatus != TXDB_READ_FOUND)
        {
            printf("CheckAnonInputsAB(): Error input %d, element %d AnonOutput %s %s.\n",
                   i, ri, HexStr(pkRingCoin.Raw()).c_str(),
                   outputStatus == TXDB_READ_NOT_FOUND
                       ? "not found" : "corrupt/unreadable");
            if (outputStatus == TXDB_READ_NOT_FOUND)
                fInvalid = true;
            return false;
        };

        if (nCoinValue == -1)
        {
            nCoinValue = ao.nValue;
        } else
        if (nCoinValue != ao.nValue)
        {
            printf("CheckAnonInputsAB(): Error input %d, element %d ring amount mismatch %" PRId64 ", %" PRId64 ".\n",
                   i, ri, nCoinValue, ao.nValue);
            fInvalid = true;
            return false;
        };

        if (!LegacyAnonOutputMatureAtCandidate(ao, nCandidateHeight))
        {
            printf("CheckAnonInputsAB(): Error input %d, element %d depth < MIN_ANON_SPEND_DEPTH.\n", i, ri);
            fInvalid = true;
            return false;
        };
    };

    if (verifyRingSignatureAB(vchImage, preimage, nRingSize, pPubkeys, pSigC, pSigS) != 0)
    {
        printf("CheckAnonInputsAB(): Error input %d verifyRingSignatureAB() failed.\n", i);
        fInvalid = true;
        return false;
    };

    return true;
};

bool CTransaction::CheckAnonInputs(
    CTxDB& txdb, int nCandidateHeight, int64_t& nSumValue,
    bool& fInvalid, bool fRelay,
    std::set<ec_point>* pBlockKeyImages,
    std::vector<std::pair<ec_point, CKeyImageSpent> >* pKeyImageEffects) const
{
    AssertLockHeld(cs_main);
    fInvalid = false;
    nSumValue = 0;
    if (pKeyImageEffects)
        pKeyImageEffects->clear();

    if (nVersion != ANON_TXN_VERSION)
    {
        printf("CheckAnonInputs(): called for non-ANON transaction.\n");
        fInvalid = true;
        return false;
    }
    if (nCandidateHeight < 0)
    {
        printf("CheckAnonInputs(): candidate height is unavailable.\n");
        return false;
    }
    if (nCandidateHeight >= FORK_HEIGHT_RINGSIG_DEPRECATION)
    {
        printf("CheckAnonInputs(): ANON transaction is retired at candidate height %d.\n",
               nCandidateHeight);
        fInvalid = true;
        return false;
    }

    uint256 preimage;
    if (GetAnonTxnPreImage(*this, preimage) != 0)
    {
        printf("CheckAnonInputs(): Error GetTxnPreImage() failed.\n");
        fInvalid = true; return false;
    };

    uint256 txnHash = GetHash();

    for (uint32_t i = 0; i < vin.size(); i++)
    {
        const CTxIn &txin = vin[i];

        if (!txin.IsAnonInput())
            continue;

        const CScript &s = txin.scriptSig;

        std::vector<uint8_t> vchImage;
        txin.ExtractKeyImage(vchImage);

        if (pBlockKeyImages &&
            !pBlockKeyImages->insert(vchImage).second)
        {
            printf("CheckAnonInputs(): duplicate key image %s in active block.\n",
                   HexStr(vchImage).c_str());
            fInvalid = true;
            return false;
        }

        CKeyImageSpent spentKeyImage;
        const TxDBReadStatus keyImageStatus =
            txdb.ReadKeyImageStatus(vchImage, spentKeyImage);
        if (keyImageStatus == TXDB_READ_ERROR)
        {
            printf("CheckAnonInputs(): key-image record is corrupt/unreadable.\n");
            return false;
        }
        bool fHaveKeyImage = keyImageStatus == TXDB_READ_FOUND;
        bool fKeyImageFromMempool = false;
        if (!fHaveKeyImage && fRelay &&
            mempool.lookupKeyImage(vchImage, spentKeyImage))
        {
            fHaveKeyImage = true;
            fKeyImageFromMempool = true;
        }
        if (fHaveKeyImage)
        {
            // Idempotent validation of the same transaction is permitted; a key image owned by any
            // other transaction/input is spent. The chain path never consults mempool or live-chain lookups.
            if (spentKeyImage.txnHash == txnHash &&
                spentKeyImage.inputNo == i)
            {
                if (fDebugRingSig)
                    printf("Input %d keyimage %s matches txn %s.\n", i, HexStr(vchImage).c_str(), txnHash.ToString().c_str());
            }
            else
            {
                printf("CheckAnonInputs(): Error input %d keyimage %s already spent.\n",
                       i, HexStr(vchImage).c_str());
                fInvalid = true;
                return false;
            }
        }

        int64_t nCoinValue = -1;
        int nRingSize = txin.ExtractRingSize();
        if (nRingSize < (int)MIN_RING_SIZE
          ||nRingSize > LegacyAnonMaxRingSizeAtCandidate(nCandidateHeight))
        {
            printf("CheckAnonInputs(): Error input %d ringsize %d not in range [%d, %d].\n", i, nRingSize, MIN_RING_SIZE, MAX_RING_SIZE);
            fInvalid = true; return false;
        };


        if (nRingSize > 1 && s.size() == 2 + ec_secret_size + (ec_secret_size + ec_compressed_size) * nRingSize)
        {
            // ringsig AB
            if (!CheckAnonInputAB(txdb, txin, i, nRingSize, vchImage,
                                  preimage, nCoinValue, nCandidateHeight,
                                  fInvalid))
            {
                return false;
            };

            if (nCoinValue < 0 || nCoinValue > MAX_MONEY - nSumValue)
            {
                printf("CheckAnonInputs(): anonymous input sum overflow.\n");
                fInvalid = true;
                return false;
            }
            nSumValue += nCoinValue;

            CKeyImageSpent expected;
            expected.txnHash = txnHash;
            expected.inputNo = i;
            expected.nValue = nCoinValue;
            if (fHaveKeyImage &&
                !LegacyAnonRecordsEqual(spentKeyImage, expected))
            {
                printf("CheckAnonInputs(): key-image metadata mismatch for input %d%s.\n",
                       i, fKeyImageFromMempool ? " in mempool" : " on disk");
                if (fKeyImageFromMempool)
                    fInvalid = true;
                return false;
            }
            if (pKeyImageEffects)
                pKeyImageEffects->push_back(
                    std::make_pair(vchImage, expected));
            continue;
        };

        if (s.size() < 2 + (ec_compressed_size + ec_secret_size + ec_secret_size) * nRingSize)
        {
            printf("CheckAnonInputs(): Error input %d scriptSig too small.\n", i);
            fInvalid = true; return false;
        };


        CPubKey pkRingCoin;
        CAnonOutput ao;
        CTxIndex txindex;
        const unsigned char* pPubkeys = &s[2];
        const unsigned char* pSigc    = &s[2 + ec_compressed_size * nRingSize];
        const unsigned char* pSigr    = &s[2 + (ec_compressed_size + ec_secret_size) * nRingSize];
        for (int ri = 0; ri < nRingSize; ++ri)
        {
            pkRingCoin = CPubKey(&pPubkeys[ri * ec_compressed_size], ec_compressed_size);
            const TxDBReadStatus outputStatus =
                txdb.ReadAnonOutputStatus(pkRingCoin, ao);
            if (outputStatus != TXDB_READ_FOUND)
            {
                printf("CheckAnonInputs(): Error input %d, element %d AnonOutput %s %s.\n",
                       i, ri, HexStr(pkRingCoin.Raw()).c_str(),
                       outputStatus == TXDB_READ_NOT_FOUND
                           ? "not found" : "corrupt/unreadable");
                if (outputStatus == TXDB_READ_NOT_FOUND)
                    fInvalid = true;
                return false;
            };

            if (nCoinValue == -1)
            {
                nCoinValue = ao.nValue;
            } else
            if (nCoinValue != ao.nValue)
            {
                printf("CheckAnonInputs(): Error input %d, element %d ring amount mismatch %" PRId64 ", %" PRId64 ".\n",
                       i, ri, nCoinValue, ao.nValue);
                fInvalid = true; return false;
            };

            if (!LegacyAnonOutputMatureAtCandidate(ao, nCandidateHeight))
            {
                printf("CheckAnonInputs(): Error input %d, element %d depth < MIN_ANON_SPEND_DEPTH.\n", i, ri);
                fInvalid = true; return false;
            };
        };

        if (verifyRingSignature(vchImage, preimage, nRingSize, pPubkeys, pSigc, pSigr) != 0)
        {
            printf("CheckAnonInputs(): Error input %d verifyRingSignature() failed.\n", i);
            fInvalid = true; return false;
        };

        if (nCoinValue < 0 || nCoinValue > MAX_MONEY - nSumValue)
        {
            printf("CheckAnonInputs(): anonymous input sum overflow.\n");
            fInvalid = true;
            return false;
        }
        nSumValue += nCoinValue;

        CKeyImageSpent expected;
        expected.txnHash = txnHash;
        expected.inputNo = i;
        expected.nValue = nCoinValue;
        if (fHaveKeyImage && !LegacyAnonRecordsEqual(spentKeyImage, expected))
        {
            printf("CheckAnonInputs(): key-image metadata mismatch for input %d%s.\n",
                   i, fKeyImageFromMempool ? " in mempool" : " on disk");
            // Disk mismatch for the same tx/input is local corruption.  Relay
            // metadata mismatch is a conflicting transaction and is invalid.
            if (fKeyImageFromMempool)
                fInvalid = true;
            return false;
        }
        if (pKeyImageEffects)
            pKeyImageEffects->push_back(
                std::make_pair(vchImage, expected));
    }

    return true;
}

bool CTransaction::CheckAnonInputs(CTxDB& txdb, int64_t& nSumValue,
                                   bool& fInvalid,
                                   bool fCheckExists) const
{
    // Compatibility for local block-template code.  Consensus callers use
    // the explicit-height overload above.  Mempool visibility is enabled only
    // for the historical relay call (fCheckExists=true).
    const int nCandidateHeight =
        nBestHeight == std::numeric_limits<int>::max()
            ? nBestHeight : nBestHeight + 1;
    return CheckAnonInputs(txdb, nCandidateHeight, nSumValue, fInvalid,
                           fCheckExists, NULL, NULL);
}

bool CTransaction::BuildLegacyAnonEffectPlan(
    CTxDB& txdb, int nCandidateHeight,
    std::set<ec_point>& setBlockKeyImages,
    CLegacyAnonEffectPlan& plan, bool& fInvalid) const
{
    AssertLockHeld(cs_main);
    plan.Clear();
    fInvalid = false;

    if (nVersion != ANON_TXN_VERSION)
    {
        fInvalid = true;
        return false;
    }
    if (nCandidateHeight >= FORK_HEIGHT_RINGSIG_DEPRECATION)
    {
        fInvalid = true;
        return false;
    }

    // Publish block-local key images only after the entire transaction and
    // output plan succeeds.  A failed transaction cannot leave partial state
    // in the caller's duplicate set.
    std::set<ec_point> setCandidateKeyImages(setBlockKeyImages);
    if (!CheckAnonInputs(txdb, nCandidateHeight, plan.nValueIn,
                         fInvalid, false, &setCandidateKeyImages,
                         &plan.vKeyImages))
        return false;

    const uint256 hashTx = GetHash();
    for (uint32_t i = 0; i < vout.size(); ++i)
    {
        const CTxOut& txout = vout[i];
        if (!txout.IsAnonOutput())
            continue;

        const CPubKey pkCoin = txout.ExtractAnonPk();
        COutPoint outpoint(hashTx, i);
        const CAnonOutput expected(outpoint, txout.nValue,
                                   nCandidateHeight, 0);
        CAnonOutput existing;
        const TxDBReadStatus status =
            txdb.ReadAnonOutputStatus(pkCoin, existing);
        if (status == TXDB_READ_ERROR)
        {
            printf("BuildLegacyAnonEffectPlan(): anon-output record is corrupt/unreadable.\n");
            return false;
        }
        if (status == TXDB_READ_FOUND &&
            !LegacyAnonRecordsEqual(existing, expected))
        {
            // A legacy unconfirmed wallet residue used height zero.  Repair it
            // only when every consensus-visible identity/value field matches;
            // any other same-key record is a conflict or local corruption.
            const bool fRepairableLegacyResidue =
                existing.outpoint == expected.outpoint &&
                existing.nValue == expected.nValue &&
                existing.nBlockHeight == 0 &&
                existing.nCompromised == expected.nCompromised;
            if (!fRepairableLegacyResidue)
            {
                if (existing.outpoint != expected.outpoint)
                    fInvalid = true;
                printf("BuildLegacyAnonEffectPlan(): conflicting anon output %s.\n",
                       HexStr(pkCoin.Raw()).c_str());
                return false;
            }
        }
        plan.vOutputs.push_back(std::make_pair(pkCoin, expected));
    }

    setBlockKeyImages.swap(setCandidateKeyImages);
    return true;
}

bool ApplyLegacyAnonEffectPlan(CTxDB& txdb,
                               const CLegacyAnonEffectPlan& plan,
                               std::string& strError)
{
    strError.clear();
    if (!txdb.IsTxnActive())
    {
        strError = "legacy ANON effects require the outer chain transaction";
        return false;
    }
    for (std::vector<std::pair<ec_point, CKeyImageSpent> >::const_iterator it =
             plan.vKeyImages.begin(); it != plan.vKeyImages.end(); ++it)
    {
        CKeyImageSpent existing;
        const TxDBReadStatus status =
            txdb.ReadKeyImageStatus(it->first, existing);
        if (status == TXDB_READ_ERROR)
        {
            strError = "legacy ANON key-image record is corrupt/unreadable";
            return false;
        }
        if (status == TXDB_READ_FOUND)
        {
            if (!LegacyAnonRecordsEqual(existing, it->second))
            {
                strError = "legacy ANON key-image record changed after validation";
                return false;
            }
            continue;
        }
        if (!txdb.WriteKeyImage(it->first, it->second))
        {
            strError = "failed to stage legacy ANON key-image record";
            return false;
        }
    }

    for (std::vector<std::pair<CPubKey, CAnonOutput> >::const_iterator it =
             plan.vOutputs.begin(); it != plan.vOutputs.end(); ++it)
    {
        CAnonOutput existing;
        const TxDBReadStatus status =
            txdb.ReadAnonOutputStatus(it->first, existing);
        if (status == TXDB_READ_ERROR)
        {
            strError = "legacy ANON output record is corrupt/unreadable";
            return false;
        }
        if (status == TXDB_READ_FOUND &&
            LegacyAnonRecordsEqual(existing, it->second))
            continue;
        if (status == TXDB_READ_FOUND)
        {
            const bool fRepairableLegacyResidue =
                existing.outpoint == it->second.outpoint &&
                existing.nValue == it->second.nValue &&
                existing.nBlockHeight == 0 &&
                existing.nCompromised == it->second.nCompromised;
            if (!fRepairableLegacyResidue)
            {
                strError = "legacy ANON output record changed after validation";
                return false;
            }
        }
        if (!txdb.WriteAnonOutput(it->first, it->second))
        {
            strError = "failed to stage legacy ANON output record";
            return false;
        }
    }
    return true;
}

static bool ReadLegacyAnonInputValueForDisconnect(
    CTxDB& txdb, const CTxIn& txin, int nBlockHeight,
    int64_t& nValue, std::string& strError)
{
    nValue = -1;
    const int nRingSize = txin.ExtractRingSize();
    if (nRingSize < (int)MIN_RING_SIZE ||
        nRingSize > LegacyAnonMaxRingSizeAtCandidate(nBlockHeight))
    {
        strError = "legacy ANON disconnect has invalid ring size";
        return false;
    }

    const CScript& script = txin.scriptSig;
    const size_t nABSize = 2 + ec_secret_size +
        (ec_secret_size + ec_compressed_size) * (size_t)nRingSize;
    const bool fAB = nRingSize > 1 && script.size() == nABSize;
    const size_t nStandardMinimum = 2 +
        (ec_compressed_size + ec_secret_size + ec_secret_size) *
            (size_t)nRingSize;
    if (!fAB && script.size() < nStandardMinimum)
    {
        strError = "legacy ANON disconnect script is truncated";
        return false;
    }
    const size_t nPubkeyOffset = fAB
        ? 2 + ec_secret_size + ec_secret_size * (size_t)nRingSize
        : 2;

    for (int ri = 0; ri < nRingSize; ++ri)
    {
        const size_t offset = nPubkeyOffset +
            (size_t)ri * ec_compressed_size;
        if (offset > script.size() ||
            script.size() - offset < ec_compressed_size)
        {
            strError = "legacy ANON disconnect pubkey layout is truncated";
            return false;
        }
        const CPubKey pkCoin(&script[offset], ec_compressed_size);
        CAnonOutput output;
        if (txdb.ReadAnonOutputStatus(pkCoin, output) != TXDB_READ_FOUND)
        {
            strError = "legacy ANON disconnect ring output is missing/corrupt";
            return false;
        }
        if (nValue == -1)
            nValue = output.nValue;
        else if (nValue != output.nValue)
        {
            strError = "legacy ANON disconnect ring values disagree";
            return false;
        }
    }
    return nValue >= 0;
}

bool DisconnectLegacyAnonChainState(CTxDB& txdb,
                                    const CTransaction& tx,
                                    int nBlockHeight,
                                    std::string& strError)
{
    strError.clear();
    if (tx.nVersion != ANON_TXN_VERSION)
        return true;
    if (!txdb.IsTxnActive())
    {
        strError = "legacy ANON rollback requires the outer chain transaction";
        return false;
    }

    const uint256 hashTx = tx.GetHash();
    for (int i = (int)tx.vin.size() - 1; i >= 0; --i)
    {
        const CTxIn& txin = tx.vin[i];
        if (!txin.IsAnonInput())
            continue;

        ec_point keyImage;
        txin.ExtractKeyImage(keyImage);
        int64_t nValue = -1;
        if (!ReadLegacyAnonInputValueForDisconnect(
                txdb, txin, nBlockHeight, nValue, strError))
            return false;

        CKeyImageSpent expected;
        expected.txnHash = hashTx;
        expected.inputNo = i;
        expected.nValue = nValue;
        CKeyImageSpent existing;
        if (txdb.ReadKeyImageStatus(keyImage, existing) !=
                TXDB_READ_FOUND ||
            !LegacyAnonRecordsEqual(existing, expected))
        {
            strError = "legacy ANON disconnect key-image record is missing/corrupt/mismatched";
            return false;
        }
        if (!txdb.EraseKeyImage(keyImage))
        {
            strError = "failed to stage legacy ANON key-image erase";
            return false;
        }
    }

    for (int i = (int)tx.vout.size() - 1; i >= 0; --i)
    {
        const CTxOut& txout = tx.vout[i];
        if (!txout.IsAnonOutput())
            continue;
        const CPubKey pkCoin = txout.ExtractAnonPk();
        COutPoint outpoint(hashTx, i);
        const CAnonOutput expected(outpoint, txout.nValue,
                                   nBlockHeight, 0);
        CAnonOutput existing;
        if (txdb.ReadAnonOutputStatus(pkCoin, existing) !=
                TXDB_READ_FOUND ||
            !LegacyAnonRecordsEqual(existing, expected))
        {
            strError = "legacy ANON disconnect output record is missing/corrupt/mismatched";
            return false;
        }
        if (!txdb.EraseAnonOutput(pkCoin))
        {
            strError = "failed to stage legacy ANON output erase";
            return false;
        }
    }
    return true;
}

const CTxOut& CTransaction::GetOutputFor(const CTxIn& input, const MapPrevTx& inputs) const
{
    MapPrevTx::const_iterator mi = inputs.find(input.prevout.hash);
    if (mi == inputs.end())
        throw std::runtime_error("CTransaction::GetOutputFor() : prevout.hash not found");

    const CTransaction& txPrev = (mi->second).second;
    if (input.prevout.n >= txPrev.vout.size())
        throw std::runtime_error("CTransaction::GetOutputFor() : prevout.n out of range");

    return txPrev.vout[input.prevout.n];
}

int64_t CTransaction::GetValueIn(const MapPrevTx& inputs) const
{
    if (IsCoinBase())
        return 0;

    int64_t nResult = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        if (nVersion == ANON_TXN_VERSION
            && vin[i].IsAnonInput())
        {
            continue;
        };
        nResult += GetOutputFor(vin[i], inputs).nValue;
    };

    return nResult;
}

unsigned int CTransaction::GetP2SHSigOpCount(const MapPrevTx& inputs) const
{
    if (IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        if (nVersion == ANON_TXN_VERSION
            && vin[i].IsAnonInput())
            continue;
        const CTxOut& prevout = GetOutputFor(vin[i], inputs);
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(vin[i].scriptSig);
    };

    return nSigOps;
}

bool CTransaction::ConnectInputs(CTxDB& txdb, MapPrevTx inputs, map<uint256, CTxIndex>& mapTestPool, const CDiskTxPos& posThisTx,
    const CBlockIndex* pindexBlock, bool fBlock, bool fMiner, unsigned int flags, bool fValidateSig,
    bool fValidatedCoinstake, bool fAnonPrevalidated,
    int nAnonCandidateHeight, int64_t nPrevalidatedAnonValueIn)
{
    // Take over previous transactions' spent pointers
    // fBlock is true when this is called from AcceptBlock when a new best-block is added to the blockchain
    // fMiner is true when called from the internal bitcoin miner
    // ... both are false when called from CTransaction::AcceptToMemoryPool
    if (!IsCoinBase())
    {
        const int nContextHeight = pindexBlock ? pindexBlock->nHeight : nBestHeight;
        // Fork gates use the carrying block's height; the mempool and miner pass the previous
        // index, so at the activation height a transaction can clear their gate and fail here.
        int nInclusionHeight = nAnonCandidateHeight;
        if (nInclusionHeight < 0)
        {
            nInclusionHeight = nContextHeight;
            if (!fBlock && nInclusionHeight < std::numeric_limits<int>::max())
                ++nInclusionHeight;
        }
        if (IsShielded() &&
            (IsLegacyPrivacyPolicyDisabled() ||
             IsBoundaryAActiveAtHeight(nInclusionHeight)))
            return DoS(100, error("ConnectInputs() : legacy shielded transaction version %d is disabled in this network/era",
                                  nVersion));
        if (IsPrivacyVNext() &&
            (!IsBoundaryBActiveAtHeight(nInclusionHeight) ||
             !IsShieldedVNextConsensusReady()))
            return DoS(100, error("ConnectInputs() : privacy-vNext is inactive before Boundary B"));
        // Coinstake exemptions below may only be claimed by the kernel-validated
        // vtx[1] of a proof-of-stake block (fValidatedCoinstake, set by
        // ConnectBlock). Pre-DAG heights keep the historical shape-keyed
        // behavior so existing chains revalidate unchanged.
        const bool fCoinStakeExempt = IsCoinStake() &&
            (fValidatedCoinstake || nContextHeight < FORK_HEIGHT_DAG);
        // vector<CTransaction> vTxPrev;
        // vector<CTxIndex> vTxindex;
        int64_t nValueIn = 0;
        int64_t nFees = 0;
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            if (nVersion == ANON_TXN_VERSION && vin[i].IsAnonInput())
                continue;
            COutPoint prevout = vin[i].prevout;
            if (inputs.count(prevout.hash) == 0)
                return DoS(100, error("ConnectInputs() : missing input %s", prevout.hash.ToString().c_str()));
            CTxIndex& txindex = inputs[prevout.hash].first;
            CTransaction& txPrev = inputs[prevout.hash].second;

            if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
                return DoS(100, error("ConnectInputs() : %s prevout.n out of range %d %" PRIszu" %" PRIszu" prev tx %s\n%s", GetHash().ToString().substr(0,10).c_str(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString().substr(0,10).c_str(), txPrev.ToString().c_str()));

            // If prev is coinbase or coinstake, check that it's matured
            if (txPrev.IsCoinBase() || txPrev.IsCoinStake())
                for (const CBlockIndex* pindex = pindexBlock; pindex && pindexBlock->nHeight - pindex->nHeight < nCoinbaseMaturity; pindex = pindex->pprev)
                    if (pindex->nBlockPos == txindex.pos.nBlockPos && pindex->nFile == txindex.pos.nFile)
                        return error("ConnectInputs() : tried to spend %s at depth %d", txPrev.IsCoinBase() ? "coinbase" : "coinstake", pindexBlock->nHeight - pindex->nHeight);

            // ppcoin: check transaction timestamp
            if (txPrev.nTime > nTime)
                return DoS(100, error("ConnectInputs() : transaction timestamp earlier than input transaction"));

            // Check for negative or overflow input values
            nValueIn += txPrev.vout[prevout.n].nValue;
            if (!MoneyRange(txPrev.vout[prevout.n].nValue) || !MoneyRange(nValueIn))
                return DoS(100, error("ConnectInputs() : txin values out of range"));

        }
        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            if (nVersion == ANON_TXN_VERSION
                && vin[i].IsAnonInput())
                continue;
            COutPoint prevout = vin[i].prevout;
            if (inputs.count(prevout.hash) == 0)
                return DoS(100, error("ConnectInputs() : missing input %s", prevout.hash.ToString().c_str()));
            CTxIndex& txindex = inputs[prevout.hash].first;
            CTransaction& txPrev = inputs[prevout.hash].second;

            // Check for conflicts (double-spend)
            // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
            // for an attacker to attempt to split the network.
            if (!txindex.vSpent[prevout.n].IsNull())
            {
                printf("WARNING: ConnectInputs() : %s double-spend attempt at %s\n",
                       GetHash().ToString().substr(0,10).c_str(), txindex.vSpent[prevout.n].ToString().c_str());
                return DoS(100, error("ConnectInputs() : %s prev tx already used at %s", GetHash().ToString().substr(0,10).c_str(), txindex.vSpent[prevout.n].ToString().c_str()));
            }

            {
            // Skip ECDSA signature verification when connecting blocks (fBlock=true)
            // before the last blockchain checkpoint. This is safe because block merkle hashes are
            // still computed and checked, and any change will be caught at the next checkpoint.
            // -fullreplayverify forces full ECDSA verification of all historic blocks (used by
            // -replayblocks to re-validate mainnet history end to end, not just to the checkpoint).
            if (!(fBlock && !fFullReplayVerify && (nBestHeight < Checkpoints::GetTotalBlocksEstimate())))
            {
                // Verify signature
                bool fSigOk;
                {
                    BLOCK_PHASE(BP_SIGVERIFY);
                    fSigOk = VerifySignature(txPrev, *this, i, flags, 0);
                }
                if (!fSigOk)
                {
                    if (flags & STANDARD_NOT_MANDATORY_VERIFY_FLAGS) {
                    // Check whether the failure was caused by a
                    // non-mandatory script verification check, such as
                    // non-null dummy arguments;
                    // if so, don't trigger DoS protection to
                    // avoid splitting the network between upgraded and
                    // non-upgraded nodes.
                    if (VerifySignature(txPrev, *this, i, flags & ~STANDARD_NOT_MANDATORY_VERIFY_FLAGS, 0))
                        return error("ConnectInputs() : %s non-mandatory VerifySignature failed", GetHash().ToString().c_str());
                    }
                    // Failures of other flags indicate a transaction that is
                    // invalid in new blocks, e.g. a invalid P2SH. We DoS ban
                    // such nodes as they are not following the protocol. That
                    // said during an upgrade careful thought should be taken
                    // as to the correct behavior - we may want to continue
                    // peering with non-upgraded nodes even after a soft-fork
                    // super-majority vote has passed.
                    return DoS(100,error("ConnectInputs() : %s VerifySignature failed", GetHash().ToString().substr(0,10).c_str()));
                }
            }
            }
            // Mark outpoints as spent
            txindex.vSpent[prevout.n] = posThisTx;

            // Write back
            if (fBlock || fMiner)
            {
                mapTestPool[prevout.hash] = txindex;
            }
            //Push txPrev and txindex to vTxPrev and VTxIndex
            // vTxPrev.push_back(txPrev);
            // vTxindex.push_back(txindex);
        }
        //vector<nameTempProxy>& vName
        //If it can't connect inputs return false to the Name DB
        // if (!hooks->ConnectInputs(txdb, mapTestPool, *this, posThisTx, pindexBlock, fBlock, fMiner, flags, vName)) {
        //     return false;
        // }

        if (nVersion == ANON_TXN_VERSION)
        {
            if (nAnonCandidateHeight < 0 && pindexBlock)
            {
                nAnonCandidateHeight = pindexBlock->nHeight;
                if (fMiner && nAnonCandidateHeight <
                                  std::numeric_limits<int>::max())
                    ++nAnonCandidateHeight;
            }
            if (nAnonCandidateHeight < 0)
                return error("ConnectInputs() : ANON candidate height is unavailable");
            if (nAnonCandidateHeight >= FORK_HEIGHT_RINGSIG_DEPRECATION)
                return DoS(100, error("ConnectInputs() : ring signature transactions deprecated after height %d", FORK_HEIGHT_RINGSIG_DEPRECATION));

            if (fAnonPrevalidated)
            {
                if (nPrevalidatedAnonValueIn < 0 ||
                    nPrevalidatedAnonValueIn > MAX_MONEY - nValueIn)
                    return DoS(100, error("ConnectInputs() : prevalidated anonymous input value is out of range"));
                nValueIn += nPrevalidatedAnonValueIn;
            }
            else
            {
                int64_t nSumAnon = 0;
                bool fInvalid = false;
                if (!CheckAnonInputs(txdb, nAnonCandidateHeight, nSumAnon,
                                     fInvalid, false, NULL, NULL))
                    return fInvalid
                        ? DoS(100, error("ConnectInputs() : CheckAnonInputs found invalid tx %s",
                                         GetHash().ToString().substr(0,10).c_str()))
                        : error("ConnectInputs() : CheckAnonInputs could not read chain state for %s",
                                GetHash().ToString().substr(0,10).c_str());
                if (nSumAnon < 0 || nSumAnon > MAX_MONEY - nValueIn)
                    return DoS(100, error("ConnectInputs() : anonymous input value overflow"));
                nValueIn += nSumAnon;
            }
        };

        if (IsShielded())
        {
            if (pindexBlock && pindexBlock->nHeight < FORK_HEIGHT_SHIELDED)
                return DoS(100, error("ConnectInputs() : shielded tx before activation height %d", FORK_HEIGHT_SHIELDED));

            int nAnchorValidationHeight = pindexBlock
                ? pindexBlock->nHeight : nBestHeight;
            if (!fBlock && nAnchorValidationHeight <
                               std::numeric_limits<int>::max())
                ++nAnchorValidationHeight;
            const bool fStrictV3Anchors =
                nAnchorValidationHeight >= FORK_HEIGHT_EPOCH_STATE_V3;

            for (const CShieldedSpendDescription& spend : vShieldedSpend)
            {
                CShieldedNullifierSpent nfs;
                if (txdb.ReadShieldedNullifier(spend.nullifier, nfs))
                    return DoS(100, error("ConnectInputs() : shielded nullifier %s already spent in tx %s",
                                          spend.nullifier.ToString().substr(0,10).c_str(),
                                          nfs.txnHash.ToString().substr(0,10).c_str()));

                int nAnchorHeight = 0;
                if (fStrictV3Anchors)
                {
                    const TxDBReadStatus anchorStatus =
                        txdb.ReadShieldedAnchorStatus(spend.anchor);
                    if (anchorStatus == TXDB_READ_ERROR)
                        return error("ConnectInputs() : shielded anchor %s record is corrupt/unreadable; -reindex/resync required",
                                     spend.anchor.ToString().substr(0,10).c_str());
                    if (anchorStatus == TXDB_READ_NOT_FOUND)
                        return DoS(100, error("ConnectInputs() : shielded anchor %s not found",
                                              spend.anchor.ToString().substr(0,10).c_str()));
                    if (txdb.ReadShieldedAnchorHeightStatus(
                            spend.anchor, nAnchorHeight) != TXDB_READ_FOUND ||
                        nAnchorHeight < FORK_HEIGHT_SHIELDED ||
                        (pindexBlock && nAnchorHeight > pindexBlock->nHeight))
                        return error("ConnectInputs() : shielded anchor %s height is missing/corrupt; -reindex/resync required",
                                     spend.anchor.ToString().substr(0,10).c_str());
                    if (pindexBlock &&
                        pindexBlock->nHeight - nAnchorHeight <
                            MIN_SHIELDED_SPEND_DEPTH)
                        return DoS(100, error("ConnectInputs() : shielded anchor %s too recent (height=%d, block=%d, need %d)",
                                              spend.anchor.ToString().substr(0,10).c_str(),
                                              nAnchorHeight, pindexBlock->nHeight, MIN_SHIELDED_SPEND_DEPTH));
                }
                else
                {
                    if (!txdb.ReadShieldedAnchor(spend.anchor))
                        return DoS(100, error("ConnectInputs() : shielded anchor %s not found",
                                              spend.anchor.ToString().substr(0,10).c_str()));
                    if (pindexBlock && txdb.ReadShieldedAnchorHeight(
                            spend.anchor, nAnchorHeight) &&
                        pindexBlock->nHeight - nAnchorHeight <
                            MIN_SHIELDED_SPEND_DEPTH)
                        return DoS(100, error("ConnectInputs() : shielded anchor %s too recent (height=%d, block=%d, need %d)",
                                              spend.anchor.ToString().substr(0,10).c_str(),
                                              nAnchorHeight, pindexBlock->nHeight, MIN_SHIELDED_SPEND_DEPTH));
                }
            }

            if (nValueBalance > 0)
            {
                if (nValueIn > MAX_MONEY - nValueBalance)
                    return DoS(100, error("ConnectInputs() : nValueIn overflow with shielded balance"));
                nValueIn += nValueBalance;
            }
            if (nValueBalance == std::numeric_limits<int64_t>::min())
                return DoS(100, error("ConnectInputs() : nValueBalance is INT64_MIN"));
            int64_t nShieldedAbsorbed = (nValueBalance < 0) ? (-nValueBalance) : 0;

            if (GetValueOut() > MAX_MONEY - nShieldedAbsorbed)
                return DoS(100, error("ConnectInputs() : GetValueOut + nShieldedAbsorbed overflow"));

            // Validated NullStake coinstakes are exempt: the reward enters the
            // shielded pool from block subsidy, not from transparent inputs. The
            // reward amount is validated separately in ConnectBlock() against
            // GetProofOfStakeReward().
            if ((nVersion != SHIELDED_TX_VERSION_NULLSTAKE && nVersion != SHIELDED_TX_VERSION_NULLSTAKE_V2 && nVersion != SHIELDED_TX_VERSION_NULLSTAKE_COLD) || !fCoinStakeExempt)
            {
                if (nValueIn < GetValueOut() + nShieldedAbsorbed)
                    return DoS(100, error("ConnectInputs() : %s shielded value balance failed (in=%" PRId64 " out=%" PRId64 " shielded=%" PRId64 ")",
                                          GetHash().ToString().substr(0,10).c_str(),
                                          nValueIn, GetValueOut(), nShieldedAbsorbed));
            }

            // use DoS(100) to ban peers sending shielded tx when ZK unavailable
            if (!CZKContext::IsInitialized())
                return DoS(100, error("ConnectInputs() : ZK context not initialized, cannot validate shielded tx"));

            {
                uint256 sighash = GetBindingSigHash();

                // DSP mode flags (default to fully private for v2000)
                bool fHideAmount   = IsDSP() ? DSP_HideAmount(nPrivacyMode)   : true;
                bool fHideSender   = IsDSP() ? DSP_HideSender(nPrivacyMode)   : true;

                int nBlockHeight = pindexBlock ? pindexBlock->nHeight : nBestHeight;

                // Post-fork enforcement: after FCMP fork, reject old tx versions with shielded spends
                if (nBlockHeight >= FORK_HEIGHT_FCMP_VALIDATION && !vShieldedSpend.empty()
                    && nVersion < SHIELDED_TX_VERSION_FCMP)
                {
                    return DoS(100, error("ConnectInputs() : tx version %d with shielded spends rejected after FCMP fork (need version >= %d)",
                                          nVersion, SHIELDED_TX_VERSION_FCMP));
                }

                // B2-e Phase 3c.4: owner-reclaim gates. A reclaim (version 2007) spends an idle cv3 note by
                // OWNER authority instead of the M-of-N quorum. These fail-closed checks gate the cv_plain
                // carve-out (MofNSpendValueCommitment) so it is reachable ONLY for a real, timelocked,
                // owner-signed reclaim -- the spend-lock is not re-opened for an attacker.
                if (IsMofNReclaim())
                {
                    if (nBlockHeight < FORK_HEIGHT_NULLSTAKE_RECLAIM)
                        return DoS(100, error("ConnectInputs() : owner reclaim before fork height"));
                    if (vShieldedSpend.empty())
                        return DoS(100, error("ConnectInputs() : owner reclaim has no shielded spend"));
                    if (reclaimAuth.vchPkOwner.size() != 33)
                        return DoS(100, error("ConnectInputs() : owner reclaim invalid owner pubkey"));
                    // (a) the revealed set+M+owner must recompute to the spent note's delegation hash D
                    // (the note's J-coefficient); a substituted set/owner leaves a J residual the cv_plain
                    // value checks reject.
                    uint256 dRecomputed;
                    if (!ComputeNullStakeV3DelegationSetHash(reclaimAuth.vStakerSet, reclaimAuth.nThresholdM,
                                                             reclaimAuth.vchPkOwner, dRecomputed)
                        || dRecomputed != reclaimAuth.delegationHash)
                        return DoS(100, error("ConnectInputs() : owner reclaim delegation hash mismatch"));
                    // (b) owner authorization: the mandatory spend-auth signature (verified in the spend
                    // loop below) must be under rk == vchPkOwner, making it a proof of knowledge of the
                    // owner secret key. A third party knows the public set+owner but not the owner key.
                    if (vShieldedSpend[0].vchRk != reclaimAuth.vchPkOwner)
                        return DoS(100, error("ConnectInputs() : owner reclaim spend key is not the owner key"));
                    // (c) inactivity timelock: the spent cv3 leaf must have been on-chain (un-restaked) for
                    // at least RECLAIM_TIMELOCK blocks. Staking re-mints the note (fresh leaf), so an actively
                    // staked note never ages this far. Deterministic on nBlockHeight; fail closed if the
                    // leaf's age cannot be established (missing / stale-after-reorg index).
                    {
                        uint64_t nLeafIdx = 0, nLeafCount = 0;
                        if (!txdb.ReadShieldedCommitmentIndex(vShieldedSpend[0].cv.vchCommitment, nLeafIdx))
                            return DoS(100, error("ConnectInputs() : owner reclaim leaf not found for timelock"));
                        txdb.ReadShieldedCommitmentCount(nLeafCount);
                        if (nLeafIdx >= nLeafCount)
                            return DoS(100, error("ConnectInputs() : owner reclaim leaf index out of range"));
                        CPedersenCommitment cvBack;
                        if (!txdb.ReadShieldedCommitment(nLeafIdx, cvBack)
                            || cvBack.vchCommitment != vShieldedSpend[0].cv.vchCommitment)
                            return DoS(100, error("ConnectInputs() : owner reclaim leaf index stale (reorg)"));
                        int nLeafHeight = 0;
                        if (!txdb.ReadShieldedCommitmentHeight(nLeafIdx, nLeafHeight))
                            return DoS(100, error("ConnectInputs() : owner reclaim leaf insertion height missing"));
                        if (nBlockHeight - nLeafHeight < RECLAIM_TIMELOCK)
                            return DoS(100, error("ConnectInputs() : owner reclaim before inactivity timelock"));
                    }
                }

                for (size_t i = 0; i < vShieldedSpend.size(); i++)
                {
                    // B2-e Phase 3c.1: the value-based checks (range, nullifier-binding, binding sig)
                    // use cv_plain = cv3 - delegationHash*J for an M-of-N cold-stake coinstake's staked
                    // note; the FCMP/Lelantus MEMBERSHIP proofs keep the raw cv3 leaf below.
                    CPedersenCommitment cvSpendValue;
                    if (!MofNSpendValueCommitment(*this, i, fValidatedCoinstake, cvSpendValue))
                        return DoS(100, error("ConnectInputs() : shielded spend %d M-of-N cv_plain derivation failed", (int)i));

                    if (fHideAmount)
                    {
                        if (!VerifyBulletproofRangeProof(cvSpendValue, vShieldedSpend[i].rangeProof))
                            return DoS(100, error("ConnectInputs() : shielded spend %d range proof failed", (int)i));
                    }
                    else
                    {
                        if (!VerifyPedersenCommitment(cvSpendValue,
                                                       vShieldedSpend[i].nPlaintextValue,
                                                       vShieldedSpend[i].vchPlaintextBlind))
                            return DoS(100, error("ConnectInputs() : DSP spend %d commitment opening proof failed", (int)i));
                    }

                    if (vShieldedSpend[i].vchSpendAuthSig.empty() || vShieldedSpend[i].vchRk.empty())
                        return DoS(100, error("ConnectInputs() : shielded spend %d missing spend auth sig or rk", (int)i));

                    if (!VerifySpendAuthSignature(vShieldedSpend[i].vchRk, sighash, vShieldedSpend[i].vchSpendAuthSig))
                        return DoS(100, error("ConnectInputs() : shielded spend %d spend auth sig failed", (int)i));

                    if (fHideSender)
                    {
                        if (vShieldedSpend[i].vchLelantusProof.empty() || vShieldedSpend[i].vAnonSet.empty())
                            return DoS(100, error("ConnectInputs() : shielded spend %d missing mandatory Lelantus proof", (int)i));

                        if ((int)vShieldedSpend[i].vAnonSet.size() < LELANTUS_MIN_SET_SIZE)
                            return DoS(100, error("ConnectInputs() : shielded spend %d anonymity set size %d below minimum %d",
                                                  (int)i, (int)vShieldedSpend[i].vAnonSet.size(), LELANTUS_MIN_SET_SIZE));

                        {
                            {
                                std::string strAnonSetError;
                                if (!CheckShieldedAnonSetChainState(
                                        txdb, vShieldedSpend[i].vAnonSet,
                                        strAnonSetError))
                                    return DoS(100, error("ConnectInputs() : shielded spend %d %s",
                                                          (int)i, strAnonSetError.c_str()));
                            }

                            CAnonymitySet anonSet;
                            anonSet.vCommitments = vShieldedSpend[i].vAnonSet;
                            CLelantusProof proof;
                            proof.vchProof = vShieldedSpend[i].vchLelantusProof;
                            proof.serialNumber = vShieldedSpend[i].lelantusSerial;

                            if (!VerifyLelantusProof(anonSet, proof, vShieldedSpend[i].cv))
                                return DoS(100, error("ConnectInputs() : shielded spend %d Lelantus proof failed", (int)i));
                        }
                    }

                    // FCMP path proofs are unverifiable; such a spend never connects.
                    if (nVersion >= SHIELDED_TX_VERSION_FCMP && nBlockHeight >= FORK_HEIGHT_FCMP_VALIDATION)
                        return DoS(100, error("ConnectInputs() : shielded spend %d FCMP-era membership is unverifiable; the encoding is permanently invalid", (int)i));

                    // Nullifier must be bound to the spent note (no re-spend under
                    // a different nullifier). No coinstake exemption: a NullStake
                    // coinstake spends a real note too, and an exemption keyed on
                    // tx shape is claimable by a coinstake-shaped tx placed at
                    // vtx[>=2] of a proof-of-work block.
                    if (nBlockHeight >= FORK_HEIGHT_NULLIFIER_BINDING)
                    {
                        const CShieldedSpendDescription& sp = vShieldedSpend[i];
                        if (sp.vchNullifierPoint.size() != NULLIFIER_POINT_SIZE ||
                            sp.vchNullifierBindingProof.size() != NULLIFIER_BINDING_PROOF_SIZE)
                            return DoS(100, error("ConnectInputs() : shielded spend %d missing nullifier binding proof (required post-fork)", (int)i));
                        if (sp.nullifier != NullifierTagFromPoint(sp.vchNullifierPoint))
                            return DoS(100, error("ConnectInputs() : shielded spend %d nullifier does not match bound note", (int)i));
                        // B2-e Phase 3c.1: bind the nullifier to the value commitment cv_plain (NOT cv3) for an
                        // M-of-N stake spend. This MUST be re-run over cv_plain, never skipped: dropping it would
                        // let the staked note be re-spent under a mismatched nullifier (infinite-stake / double-spend).
                        if (!VerifyNullifierBindingProof(cvSpendValue, sp.vchNullifierPoint, sighash, sp.vchNullifierBindingProof, fBlock ? nBlockHeight : nBlockHeight + 1))
                            return DoS(100, error("ConnectInputs() : shielded spend %d nullifier binding proof failed", (int)i));
                    }
                }
                for (size_t i = 0; i < vShieldedOutput.size(); i++)
                {
                    bool fIsMofN = false; std::string strMofN;
                    // Gate the M-of-N mint-output fork at the EFFECTIVE mining height: the actual block
                    // height when connecting a block (deterministic, consensus), or tip+1 in the mempool
                    // (where the tx will be mined next), matching the mempool-accept direct check.
                    int nMofNGateHeight = fBlock ? nBlockHeight : nBlockHeight + 1;
                    if (!CheckMofNMintOutput(*this, i, fHideAmount, nMofNGateHeight, fIsMofN, strMofN))
                        return DoS(100, error("ConnectInputs() : shielded output %d: %s", (int)i, strMofN.c_str()));
                    if (fIsMofN)
                        continue;   // 2006 mint output: value bound by range-over-Vv + the (G,J) link

                    if (IsMofNColdCoinstake(*this, fValidatedCoinstake))
                    {
                        // 3c.2 continuity: every re-minted output is a cv3 under the public delegation D.
                        // Force hidden-amount (a plaintext output would bypass the J-residual check), then
                        // verify the range proof over cv_plain_out = cv3 - D*J; a wrong D leaves a J residual
                        // the 2-generator range proof rejects (fail-closed), so value cannot leave D.
                        if (!fHideAmount)
                            return DoS(100, error("ConnectInputs() : M-of-N coinstake output %d must be hidden-amount", (int)i));
                        CPedersenCommitment cvOutValue;
                        if (!NullStakeMofNDeriveValueCommitment(vShieldedOutput[i].cv, nullstakeProofV3.delegationHash, cvOutValue))
                            return DoS(100, error("ConnectInputs() : M-of-N coinstake output %d cv_plain derivation failed", (int)i));
                        if (!VerifyBulletproofRangeProof(cvOutValue, vShieldedOutput[i].rangeProof))
                            return DoS(100, error("ConnectInputs() : M-of-N coinstake output %d continuity range proof failed", (int)i));
                        continue;
                    }

                    if (fHideAmount)
                    {
                        if (!VerifyBulletproofRangeProof(vShieldedOutput[i].cv, vShieldedOutput[i].rangeProof))
                            return DoS(100, error("ConnectInputs() : shielded output %d range proof failed", (int)i));
                    }
                    else
                    {
                        if (!VerifyPedersenCommitment(vShieldedOutput[i].cv,
                                                       vShieldedOutput[i].nPlaintextValue,
                                                       vShieldedOutput[i].vchPlaintextBlind))
                            return DoS(100, error("ConnectInputs() : DSP output %d commitment opening proof failed", (int)i));
                    }
                }
                // 3c.2: an M-of-N cold-stake coinstake must keep ALL value inside D-bound shielded outputs --
                // no value-bearing transparent vout (only the empty coinstake marker vout[0] is permitted),
                // so neither principal nor the minted reward can be skimmed to a transparent output.
                if (IsMofNColdCoinstake(*this, fValidatedCoinstake))
                {
                    for (size_t k = 0; k < vout.size(); k++)
                        if (vout[k].nValue > 0)
                            return DoS(100, error("ConnectInputs() : M-of-N coinstake has a value-bearing transparent output"));
                }

                if (!fHideAmount)
                {
                    int64_t nPlainIn = 0, nPlainOut = 0;
                    for (size_t i = 0; i < vShieldedSpend.size(); i++)
                        nPlainIn += vShieldedSpend[i].nPlaintextValue;
                    for (size_t i = 0; i < vShieldedOutput.size(); i++)
                        nPlainOut += vShieldedOutput[i].nPlaintextValue;
                    if (nPlainIn - nPlainOut != nValueBalance)
                        return DoS(100, error("ConnectInputs() : DSP plaintext value balance mismatch"));
                }

                if (bindingSig.IsNull())
                    return DoS(100, error("ConnectInputs() : shielded tx missing mandatory binding signature"));

                {
                    std::vector<CPedersenCommitment> vInCommits, vOutCommits;
                    for (size_t i = 0; i < vShieldedSpend.size(); i++)
                    {
                        // cv_plain for the M-of-N stake spend (INV-1): cv3 would inject a delegationHash*J
                        // residual that breaks the homomorphic value balance. Outputs already use Vv below.
                        CPedersenCommitment cvIn;
                        if (!MofNSpendValueCommitment(*this, i, fValidatedCoinstake, cvIn))
                            return DoS(100, error("ConnectInputs() : binding-sig M-of-N cv_plain derivation failed"));
                        vInCommits.push_back(cvIn);
                    }
                    for (size_t i = 0; i < vShieldedOutput.size(); i++)
                    {
                        // Vv for a 2006 mint output; cv_plain_out = cv3 - D*J for a 2005 M-of-N coinstake
                        // re-mint (3c.2 -- cancels the spend-side cv_plain so the balance stays exact); cv otherwise.
                        CPedersenCommitment cvOut;
                        if (!MofNOutputBindingCommitment(*this, i, fValidatedCoinstake, cvOut))
                            return DoS(100, error("ConnectInputs() : M-of-N output %d value commitment derivation failed (binding sig)", (int)i));
                        vOutCommits.push_back(cvOut);
                    }

                    if (!VerifyBindingSignature(vInCommits, vOutCommits, nValueBalance, sighash, bindingSig.bindingSig))
                        return DoS(100, error("ConnectInputs() : shielded binding signature verification failed"));
                }
            }
        };

        if (!fCoinStakeExempt)
        {
            int64_t nEffectiveOut = GetValueOut();
            if (IsShielded() && nValueBalance < 0)
                nEffectiveOut += (-nValueBalance); // shielded value absorbed from transparent

            int64_t nEffectiveIn = nValueIn;
            int64_t nDeclaredPayloadFee = 0;
            if (IsPrivacyVNext())
            {
                int64_t nAbsorbed = 0;
                int64_t nReleased = 0;
                int64_t nDeclaredBalance = 0;
                bool fFlowLocalFailure = false;
                std::string strFlowError;
                if (!GetPrivacyVNextTransparentFlow(*this, nAbsorbed, nReleased,
                                                    fFlowLocalFailure, strFlowError,
                                                    &nDeclaredPayloadFee,
                                                    &nDeclaredBalance))
                {
                    if (fFlowLocalFailure)
                    {
                        StartShutdown();
                        return error("ConnectInputs() : local IV5 pool-flow failure for %s: %s",
                                     GetHash().ToString().substr(0,10).c_str(),
                                     strFlowError.c_str());
                    }
                    return DoS(100, error("ConnectInputs() : %s IV5 pool flow rejected: %s",
                                          GetHash().ToString().substr(0,10).c_str(),
                                          strFlowError.c_str()));
                }
                std::string strRetiredError;
                if (!CheckPrivacyVNextUnshieldRetired(nDeclaredBalance,
                                                      nInclusionHeight,
                                                      strRetiredError))
                    return DoS(100, error("ConnectInputs() : %s",
                                          strRetiredError.c_str()));
                if (nAbsorbed > MAX_MONEY - nEffectiveOut)
                    return DoS(100, error("ConnectInputs() : IV5 absorbed value overflow"));
                nEffectiveOut += nAbsorbed;
                if (nReleased > MAX_MONEY - nEffectiveIn)
                    return DoS(100, error("ConnectInputs() : IV5 released value overflow"));
                nEffectiveIn += nReleased;
            }

            if (nEffectiveIn < nEffectiveOut)
                return DoS(100, error("ConnectInputs() : %s value in < value out", GetHash().ToString().substr(0,10).c_str()));

            // Tally transaction fees
            int64_t nTxFee = nEffectiveIn - nEffectiveOut;
            if (nTxFee < 0)
                return DoS(100, error("ConnectInputs() : %s nTxFee < 0", GetHash().ToString().substr(0,10).c_str()));

            // From the fee-note fork the coinbase allowance drops the declared IV5 fees and the fee
            // note credits them back; the declared fee must therefore be covered by the inputs.
            if (IsPrivacyVNext() &&
                IsIV5FeeNoteActiveAtHeight(nInclusionHeight) &&
                nTxFee < nDeclaredPayloadFee)
                return DoS(100, error("ConnectInputs() : %s declares an IV5 fee of %" PRId64
                                      " but its transparent side pays %" PRId64,
                                      GetHash().ToString().substr(0,10).c_str(),
                                      nDeclaredPayloadFee, nTxFee));

            // enforce transaction fees for every block
            // An IV5 attestation has no transparent side or pool flow, so it pays no fee.
            const bool fAttestationNoFee =
                nTxFee == 0 && IsPrivacyVNextFeeExemptShape(*this);
            if (nTxFee < GetMinFee() && !fAttestationNoFee)
                return fBlock? DoS(100, error("ConnectInputs() : %s not paying required fee=%s, paid=%s", GetHash().ToString().substr(0,10).c_str(), FormatMoney(GetMinFee()).c_str(), FormatMoney(nTxFee).c_str())) : false;

            nFees += nTxFee;
            if (!MoneyRange(nFees))
                return DoS(100, error("ConnectInputs() : nFees out of range"));
        }
    }

    return true;
}

bool CBlock::DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex, bool fWriteNames)
{
    // Name, wallet and UI effects are journaled by best-chain callers and replayed after
    // commit; the argument is kept for source compatibility and never dispatches here.
    (void)fWriteNames;
    std::set<uint256> setDAGSkippedTxs;
    if (pindex && pindex->nHeight >= FORK_HEIGHT_DAG)
    {
        std::string strActiveSetError;
        const TxDBReadStatus status = txdb.ReadDAGSkippedTxsStatus(
            *this, setDAGSkippedTxs, strActiveSetError);
        if (status != TXDB_READ_FOUND)
            return error("DisconnectBlock() : exact connect-time DAG active set is %s%s%s; "
                         "refusing mutable-DAG recomputation (-reindex/resync required)",
                         status == TXDB_READ_NOT_FOUND ? "missing" : "corrupt",
                         strActiveSetError.empty() ? "" : ": ",
                         strActiveSetError.c_str());
    }
    CBlock activeBlock = GetDAGActiveBlock(*this, setDAGSkippedTxs);

    // Decode finality carriers before staging any disconnect mutation, under the schema of
    // the block's own height; a malformed carrier is never read as "no vote".
    std::vector<CFinalityTallyCertificate> vFinalityCerts;
    std::vector<CFinalityVote> vFinalityVotes;
    FinalityEnvelopeDecodeResult certEnvelopeFailure = FINALITY_ENVELOPE_NO_MATCH;
    FinalityEnvelopeDecodeResult voteEnvelopeFailure = FINALITY_ENVELOPE_NO_MATCH;
    if (!ExtractFinalityTallyCertificatesFromBlockForHeight(
            activeBlock, pindex->nHeight, vFinalityCerts,
            &certEnvelopeFailure))
        return error("DisconnectBlock() : invalid finality certificate envelope for height %d (decode=%d)",
                     pindex->nHeight, (int)certEnvelopeFailure);
    if (!ExtractFinalityVotesFromBlockForHeight(
            activeBlock, pindex->nHeight, vFinalityVotes,
            &voteEnvelopeFailure))
        return error("DisconnectBlock() : invalid finality vote envelope for height %d (decode=%d)",
                     pindex->nHeight, (int)voteEnvelopeFailure);
    std::vector<CNoteFinalityVote> vNoteFinalityVotes;
    FinalityEnvelopeDecodeResult noteVoteEnvelopeFailure = FINALITY_ENVELOPE_NO_MATCH;
    if (!ExtractNoteFinalityVotesFromBlockForHeight(
            activeBlock, pindex->nHeight, vNoteFinalityVotes,
            &noteVoteEnvelopeFailure))
        return error("DisconnectBlock() : invalid note finality vote envelope for height %d (decode=%d)",
                     pindex->nHeight, (int)noteVoteEnvelopeFailure);

    // Reverse the pool in the exact order ConnectBlock applied it. A deposit
    // followed by a release is valid forward but underflows if undone in the
    // same order.
    const bool fUndoPrivacyVNextPool =
        pindex && IsBoundaryBActiveAtHeight(pindex->nHeight);
    int64_t nPrivacyVNextPool = 0;
    if (fUndoPrivacyVNextPool &&
        txdb.ReadPrivacyVNextPoolValueStatus(nPrivacyVNextPool) !=
            TXDB_READ_FOUND)
        return error("DisconnectBlock() : missing IV5 pool balance record; "
                     "-reindex/resync required");

    // Disconnect in reverse order
    for (int i = vtx.size()-1; i >= 0; i--)
    {
        if (setDAGSkippedTxs.count(vtx[i].GetHash()))
            continue;
        if (vtx[i].nVersion == ANON_TXN_VERSION)
        {
            std::string strAnonDisconnectError;
            if (!DisconnectLegacyAnonChainState(
                    txdb, vtx[i], pindex->nHeight,
                    strAnonDisconnectError))
                return error("DisconnectBlock() : legacy ANON chain-state rollback failed for %s: %s",
                             vtx[i].GetHash().ToString().substr(0,10).c_str(),
                             strAnonDisconnectError.c_str());
        }
        if (vtx[i].IsPrivacyVNext())
        {
            PrivacyVNextStateEffects effects;
            const PrivacyVNextPayloadValidation validation =
                ExtractPrivacyVNextPayloadEffects(
                    static_cast<uint32_t>(vtx[i].nVersion),
                    vtx[i].privacyVNext.vchPayload, effects);
            if (!validation.IsValid())
            {
                StartShutdown();
                return error("DisconnectBlock() : accepted IV5 payload cannot be decoded: %s; "
                             "local state is inconsistent (-reindex/resync required)",
                             validation.strError.c_str());
            }

            // Exact reverse of the connect order: output bases were written last.
            for (size_t j = effects.outputLeaves.size(); j > 0; --j)
            {
                uint256 base;
                memcpy(base.begin(),
                       effects.outputLeaves[j - 1].nullifierBase.data(),
                       effects.outputLeaves[j - 1].nullifierBase.size());
                CShieldedNullifierSpent created;
                const TxDBReadStatus status =
                    txdb.ReadPrivacyVNextOutputBaseStatus(base, created);
                if (status != TXDB_READ_FOUND ||
                    created.txnHash != vtx[i].GetHash() ||
                    created.nIndex != j - 1)
                {
                    StartShutdown();
                    return error("DisconnectBlock() : IV5 output-base undo record is %s or "
                                 "owned by another output for %s (-reindex/resync required)",
                                 status == TXDB_READ_NOT_FOUND ? "missing" :
                                 status == TXDB_READ_ERROR ? "corrupt" : "mismatched",
                                 base.ToString().substr(0,10).c_str());
                }
                if (!txdb.ErasePrivacyVNextOutputBase(base))
                    return error("DisconnectBlock() : IV5 output-base erase failed");
            }

            // Exact reverse of the connect order: attestations were written after
            // the spent keys and before the output bases.
            {
                std::string strAttestError;
                if (!DisconnectPrivacyVNextAttestations(txdb, vtx[i], effects,
                                                        strAttestError))
                {
                    StartShutdown();
                    return error("DisconnectBlock() : %s (-reindex/resync required)",
                                 strAttestError.c_str());
                }
            }

            for (size_t j = effects.keyImages.size(); j > 0; --j)
            {
                uint256 keyImage;
                memcpy(keyImage.begin(), effects.keyImages[j - 1].data(),
                       effects.keyImages[j - 1].size());
                CPrivacyVNextNullifierSpent spent;
                const TxDBReadStatus status =
                    txdb.ReadPrivacyVNextNullifierStatus(keyImage, spent);
                // The height is part of what connecting this block wrote, so undoing
                // it has to find the height it wrote and no other: a record placed at
                // a different height belongs to a block this one is not.
                if (status != TXDB_READ_FOUND ||
                    spent.txnHash != vtx[i].GetHash() ||
                    spent.nIndex != j - 1 ||
                    spent.nHeight != pindex->nHeight)
                {
                    StartShutdown();
                    return error("DisconnectBlock() : IV5 spent-key undo record is %s or "
                                 "owned by another input for %s (-reindex/resync required)",
                                 status == TXDB_READ_NOT_FOUND ? "missing" :
                                 status == TXDB_READ_ERROR ? "corrupt" : "mismatched",
                                 keyImage.ToString().substr(0,10).c_str());
                }
                if (!txdb.ErasePrivacyVNextNullifier(keyImage))
                    return error("DisconnectBlock() : IV5 spent-key erase failed");
            }

            if (fUndoPrivacyVNextPool)
            {
                int64_t nDelta = 0;
                std::string strPoolError;
                if (!GetPrivacyVNextPoolDelta(effects, nDelta, strPoolError) ||
                    !ApplyPrivacyVNextPoolDelta(nPrivacyVNextPool, -nDelta,
                                                strPoolError))
                {
                    StartShutdown();
                    return error("DisconnectBlock() : IV5 pool reversal for %s "
                                 "is inconsistent (-reindex/resync required)",
                                 vtx[i].GetHash().ToString().substr(0,10).c_str());
                }
            }
        }
        if (!vtx[i].DisconnectInputs(txdb))
            return false;
    }

    if (fUndoPrivacyVNextPool &&
        !txdb.WritePrivacyVNextPoolValue(nPrivacyVNextPool))
        return error("DisconnectBlock() : IV5 pool balance write failed");

    if (pindex->nHeight >= FORK_HEIGHT_DAG)
    {
        if (!vFinalityCerts.empty() &&
            !g_finalityTracker.DisconnectBlockTallyCertificates(txdb, pindex->GetBlockHash(), vFinalityCerts))
            return error("DisconnectBlock() : DisconnectBlockTallyCertificates failed");

        std::vector<CFinalityTallyShare> vFinalityShares = ExtractFinalityTallySharesFromBlock(activeBlock);
        if (!vFinalityShares.empty() &&
            !g_finalityTracker.DisconnectBlockTallyShares(txdb, pindex->GetBlockHash(), vFinalityShares))
            return error("DisconnectBlock() : DisconnectBlockTallyShares failed");

        if (!vFinalityVotes.empty() &&
            !g_finalityTracker.DisconnectBlockVotes(txdb, pindex->GetBlockHash(), vFinalityVotes))
            return error("DisconnectBlock() : DisconnectBlockVotes failed");

        if (!vNoteFinalityVotes.empty() &&
            !g_finalityTracker.DisconnectBlockNoteVotes(txdb, pindex->GetBlockHash(), vNoteFinalityVotes))
            return error("DisconnectBlock() : DisconnectBlockNoteVotes failed");
    }

    if (pindex->nHeight >= FORK_HEIGHT_SHIELDED)
    {
        bool fV3ShieldedPersistence = false;
        std::string strIndexModeError;
        if (!txdb.ResolveShieldedCommitmentIndexV3Mode(
                pindex->nHeight, FORK_HEIGHT_EPOCH_STATE_V3,
                fV3ShieldedPersistence, strIndexModeError))
            return error("DisconnectBlock() : %s; -reindex/resync required",
                         strIndexModeError.c_str());

        int64_t nShieldedPool = 0;
        if (!txdb.ReadShieldedPoolValue(nShieldedPool))
            return error("DisconnectBlock() : missing shielded pool value");
        // Reverse the exact state-transition order used by ConnectBlock.  A
        // deposit followed by a withdrawal can be valid in forward order but
        // underflow if its deltas are undone in that same order.
        for (std::vector<CTransaction>::const_reverse_iterator txIt =
                 activeBlock.vtx.rbegin();
             txIt != activeBlock.vtx.rend(); ++txIt)
        {
            const CTransaction& tx = *txIt;
            if (!tx.IsShielded())
                continue;

            for (const CShieldedSpendDescription& spend : tx.vShieldedSpend)
            {
                if (!txdb.EraseShieldedNullifier(spend.nullifier))
                    return error("DisconnectBlock() : EraseShieldedNullifier failed");
            }

            if (tx.nValueBalance == std::numeric_limits<int64_t>::min() ||
                (tx.nValueBalance > 0 &&
                 nShieldedPool > MAX_MONEY - tx.nValueBalance) ||
                (tx.nValueBalance < 0 &&
                 nShieldedPool < -tx.nValueBalance))
                return error("DisconnectBlock() : shielded pool reversal overflow");
            nShieldedPool += tx.nValueBalance; // reverse the subtraction done in ConnectBlock
        }
        if (!MoneyRange(nShieldedPool) || !txdb.WriteShieldedPoolValue(nShieldedPool))
            return error("DisconnectBlock() : WriteShieldedPoolValue failed");

        CIncrementalMerkleTree currentTree;
        if (!txdb.ReadShieldedTree(currentTree))
            return error("DisconnectBlock() : missing current shielded tree");
        uint256 currentRoot = currentTree.Root();
        if (fV3ShieldedPersistence)
        {
            int nCurrentRootHeight = -1;
            if (txdb.ReadShieldedAnchorStatus(currentRoot) !=
                    TXDB_READ_FOUND ||
                txdb.ReadShieldedAnchorHeightStatus(
                    currentRoot, nCurrentRootHeight) != TXDB_READ_FOUND ||
                nCurrentRootHeight < FORK_HEIGHT_SHIELDED ||
                nCurrentRootHeight > pindex->nHeight)
                return error("DisconnectBlock() : current V3 shielded anchor pair missing/corrupt; -reindex/resync required");

            // A block with no outputs repeats its predecessor's root.  Keep
            // that still-live anchor and its original height; only remove a
            // root which first appeared in the block being disconnected.
            if (nCurrentRootHeight == pindex->nHeight &&
                (!txdb.EraseShieldedAnchor(currentRoot) ||
                 !txdb.EraseShieldedAnchorHeight(currentRoot)))
                return error("DisconnectBlock() : failed to erase V3 shielded anchor pair");
        }
        else if (!txdb.EraseShieldedAnchor(currentRoot))
        {
            return error("DisconnectBlock() : EraseShieldedAnchor failed");
        }

        CIncrementalMerkleTree prevTree;
        if (!txdb.ReadShieldedTreeAtBlock(pindex->GetBlockHash(), prevTree))
            return error("DisconnectBlock() : missing predecessor shielded-tree snapshot");
        if (!txdb.WriteShieldedTree(prevTree))
            return error("DisconnectBlock() : WriteShieldedTree failed");
        if (!txdb.EraseShieldedTreeAtBlock(pindex->GetBlockHash()))
            return error("DisconnectBlock() : EraseShieldedTreeAtBlock failed");
        if (fV3ShieldedPersistence &&
            pindex->nHeight != FORK_HEIGHT_SHIELDED)
        {
            const uint256 prevRoot = prevTree.Root();
            int nPrevRootHeight = -1;
            if (txdb.ReadShieldedAnchorStatus(prevRoot) !=
                    TXDB_READ_FOUND ||
                txdb.ReadShieldedAnchorHeightStatus(
                    prevRoot, nPrevRootHeight) != TXDB_READ_FOUND ||
                nPrevRootHeight < FORK_HEIGHT_SHIELDED ||
                nPrevRootHeight > pindex->nHeight - 1)
                return error("DisconnectBlock() : predecessor V3 shielded anchor pair missing/corrupt; -reindex/resync required");
        }

        // Erase the per-leaf records for leaves this block
        // added before shrinking the count. Missing records are corruption, not
        // a reason to reconstruct a partial commitment set.
        {
            uint64_t nOldCommitCount = 0;
            if (!txdb.ReadShieldedCommitmentCount(nOldCommitCount) ||
                nOldCommitCount < prevTree.Size() ||
                (fV3ShieldedPersistence &&
                 nOldCommitCount != currentTree.Size()))
                return error("DisconnectBlock() : corrupt shielded commitment count");
            for (uint64_t ci = nOldCommitCount;
                 ci-- > prevTree.Size(); )
            {
                CPedersenCommitment staleCommit;
                if (!txdb.ReadShieldedCommitment(ci, staleCommit))
                    return error("DisconnectBlock() : missing shielded commitment during rollback");
                std::string strIndexError;
                if (fV3ShieldedPersistence)
                {
                    if (!txdb.PopShieldedCommitmentIndexV3(
                            ci, staleCommit, strIndexError))
                        return error("DisconnectBlock() : V3 shielded reverse-index rollback failed at %" PRIu64 ": %s",
                                     ci, strIndexError.c_str());
                }
                else if (!txdb.EraseShieldedCommitmentIndex(
                             staleCommit.vchCommitment))
                {
                    return error("DisconnectBlock() : legacy shielded reverse-index erase failed");
                }
                if (
                    !txdb.EraseShieldedCommitmentHeight(ci) ||
                    !txdb.EraseShieldedCommitment(ci))
                    return error("DisconnectBlock() : incomplete shielded commitment rollback");
            }

            if (!txdb.WriteShieldedCommitmentCount(prevTree.Size()))
                return error("DisconnectBlock() : WriteShieldedCommitmentCount failed");
        }

        if (pindex->nHeight >= FORK_HEIGHT_FCMP &&
            pindex->nHeight < FORK_HEIGHT_EPOCH_ROOT_FCMP)
        {
            CCurveTree restoredCurveTree;
            if (txdb.ReadCurveTreeAtBlock(pindex->GetBlockHash(), restoredCurveTree))
            {
                if (!txdb.WriteCurveTree(restoredCurveTree))
                    return error("DisconnectBlock() : WriteCurveTree failed");
            }
            else
            {
                return error("DisconnectBlock() : missing predecessor curve-tree snapshot; "
                             "-reindex/resync required");
            }
            if (!txdb.EraseCurveTreeAtBlock(pindex->GetBlockHash()))
                return error("DisconnectBlock() : EraseCurveTreeAtBlock failed");
        }
    }

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev)
    {
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = 0;
        if (!txdb.WriteBlockIndex(blockindexPrev))
            return error("DisconnectBlock() : WriteBlockIndex failed");
    }

    return true;
}

bool static BuildAddrIndex(const CScript &script, std::vector<uint160>& addrIds)
{
    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();
    std::vector<unsigned char> data;
    opcodetype opcode;
    bool fHaveData = false;
    while (pc < pend) {
        script.GetOp(pc, opcode, data);
        if (0 <= opcode && opcode <= OP_PUSHDATA4 && data.size() >= 8) { // data element
            uint160 addrid = 0;
            if (data.size() <= 20) {
                memcpy(&addrid, &data[0], data.size());
            } else {
                addrid = Hash160(data);
            }
            addrIds.push_back(addrid);
            fHaveData = true;
        }
    }
    if (!fHaveData) {
        uint160 addrid = Hash160(script);
	addrIds.push_back(addrid);
        return true;
    }
    else
    {
	if(addrIds.size() > 0)
	    return true;
	else
  	    return false;
    }
}

bool FindTransactionsByDestination(const CTxDestination &dest, std::vector<uint256> &vtxhash) {
    uint160 addrid = 0;
    const CKeyID *pkeyid = boost::get<CKeyID>(&dest);
    if (pkeyid)
        addrid = static_cast<uint160>(*pkeyid);
    if (!addrid) {
        const CScriptID *pscriptid = boost::get<CScriptID>(&dest);
        if (pscriptid)
            addrid = static_cast<uint160>(*pscriptid);
    }
    if (!addrid)
    {
        printf("FindTransactionsByDestination(): Couldn't parse dest into addrid\n");
        return false;
    }

    LOCK(cs_main);
    CTxDB txdb("r");
    if(!txdb.ReadAddrIndex(addrid, vtxhash))
    {
	printf("FindTransactionsByDestination(): txdb.ReadAddrIndex failed\n");
	return false;
    }
    return true;
}

void CBlock::RebuildAddressIndex(CTxDB& txdb)
{
    for (CTransaction& tx : vtx)
    {
        uint256 hashTx = tx.GetHash();
	// inputs
	if(!tx.IsCoinBase())
	{
            MapPrevTx mapInputs;
	    map<uint256, CTxIndex> mapQueuedChangesT;
	    bool fInvalid;
            if (!tx.FetchInputs(txdb, mapQueuedChangesT, true, false, mapInputs, fInvalid))
                return;

	    MapPrevTx::const_iterator mi;
	    for(MapPrevTx::const_iterator mi = mapInputs.begin(); mi != mapInputs.end(); ++mi)
	    {
		    for (const CTxOut &atxout : (*mi).second.second.vout)
		    {
			std::vector<uint160> addrIds;
			if(BuildAddrIndex(atxout.scriptPubKey, addrIds))
			{
                    for (uint160 addrId : addrIds)
		            {
			            if(!txdb.WriteAddrIndex(addrId, hashTx))
				            printf("RebuildAddressIndex(): txins WriteAddrIndex failed addrId: %s txhash: %s\n", addrId.ToString().c_str(), hashTx.ToString().c_str());
                    }
			}
		    }
	    }

        }
	// outputs
	for (const CTxOut &atxout : tx.vout) {
	    std::vector<uint160> addrIds;
        if(BuildAddrIndex(atxout.scriptPubKey, addrIds))
	    {
		for (uint160 addrId : addrIds)
		{
		    if(!txdb.WriteAddrIndex(addrId, hashTx))
		        printf("RebuildAddressIndex(): txouts WriteAddrIndex failed addrId: %s txhash: %s\n", addrId.ToString().c_str(), hashTx.ToString().c_str());
        }
	    }
	}
    }
}

static int64_t nTimeVerify = 0;
static int64_t nTimeConnect = 0;
static int64_t nTimeIndex = 0;
static int64_t nTimeCallbacks = 0;
static int64_t nTimeTotal = 0;

static bool ComputeShieldedGenesisCommitment(int nSeed,
                                             CPedersenCommitment& commitmentOut)
{
    CHashWriter ssBlind(SER_GETHASH, 0);
    ssBlind << std::string("Innova_Genesis_Seed_");
    ssBlind << nSeed;
    uint256 blindHash = ssBlind.GetHash();
    std::vector<unsigned char> vchBlind(blindHash.begin(),
                                         blindHash.begin() + 32);
    return CreateBlindCommitment(vchBlind, commitmentOut);
}

bool ValidateAndMigrateShieldedGenesisCommitmentIndexes(
    CTxDB& txdb, std::string& strError)
{
    strError.clear();
    if (!pindexBest || pindexBest->nHeight < FORK_HEIGHT_SHIELDED)
        return true;

    if (!txdb.TxnBegin())
    {
        strError = "could not begin genesis commitment-index migration transaction";
        return false;
    }

    uint64_t nCommitmentCount = 0;
    if (!txdb.ReadShieldedCommitmentCount(nCommitmentCount) ||
        nCommitmentCount < (uint64_t)LELANTUS_GENESIS_SEED_COUNT)
    {
        txdb.TxnAbort();
        strError = "missing or truncated shielded commitment count";
        return false;
    }

    unsigned int nFilled = 0;
    for (int i = 0; i < LELANTUS_GENESIS_SEED_COUNT; ++i)
    {
        CPedersenCommitment expectedCommitment;
        if (!ComputeShieldedGenesisCommitment(i, expectedCommitment))
        {
            txdb.TxnAbort();
            strError = strprintf("could not recompute deterministic genesis commitment %d", i);
            return false;
        }

        CPedersenCommitment storedCommitment;
        if (!txdb.ReadShieldedCommitment((uint64_t)i, storedCommitment))
        {
            txdb.TxnAbort();
            strError = strprintf("genesis commitment value %d is missing or unreadable", i);
            return false;
        }
        if (storedCommitment.vchCommitment !=
            expectedCommitment.vchCommitment)
        {
            txdb.TxnAbort();
            strError = strprintf("genesis commitment value %d is not canonical", i);
            return false;
        }

        if (txdb.HasShieldedCommitmentIndex(
                expectedCommitment.vchCommitment))
        {
            uint64_t nStoredIndex = 0;
            if (!txdb.ReadShieldedCommitmentIndex(
                    expectedCommitment.vchCommitment, nStoredIndex) ||
                nStoredIndex != (uint64_t)i)
            {
                txdb.TxnAbort();
                strError = strprintf("genesis commitment reverse index %d is unreadable or conflicting", i);
                return false;
            }
        }
        else
        {
            if (!txdb.WriteShieldedCommitmentIndex(
                    expectedCommitment.vchCommitment, (uint64_t)i))
            {
                txdb.TxnAbort();
                strError = strprintf("could not backfill genesis commitment reverse index %d", i);
                return false;
            }
            ++nFilled;
        }

        if (txdb.HasShieldedCommitmentHeight((uint64_t)i))
        {
            int nStoredHeight = -1;
            if (!txdb.ReadShieldedCommitmentHeight((uint64_t)i,
                                                   nStoredHeight) ||
                nStoredHeight != FORK_HEIGHT_SHIELDED)
            {
                txdb.TxnAbort();
                strError = strprintf("genesis commitment height %d is unreadable or conflicting", i);
                return false;
            }
        }
        else
        {
            if (!txdb.WriteShieldedCommitmentHeight(
                    (uint64_t)i, FORK_HEIGHT_SHIELDED))
            {
                txdb.TxnAbort();
                strError = strprintf("could not backfill genesis commitment height %d", i);
                return false;
            }
            ++nFilled;
        }
    }

    if (!txdb.TxnCommit())
    {
        strError = "could not commit genesis commitment-index migration";
        return false;
    }

    if (nFilled > 0)
        printf("Shielded: atomically backfilled %u deterministic genesis index records\n",
               nFilled);
    return true;
}

// Seed deterministic unspendable commitments at fork height for Lelantus anonymity set.
// Each seed: blind_i = SHA256("Innova_Genesis_Seed_" || i), cv_i = blind_i * G (zero value),
// cmu_i = SHA256("Innova_Genesis_Seed_CMU_" || i). Unspendable: no spending key, no nullifier derivation.
bool SeedGenesisCommitments(CTxDB& txdb,
                            CIncrementalMerkleTree& shieldedTree,
                            CCurveTree* pCurveTree,
                            bool fV3ShieldedPersistence)
{
    for (int i = 0; i < LELANTUS_GENESIS_SEED_COUNT; i++)
    {
        CPedersenCommitment cv;
        if (!ComputeShieldedGenesisCommitment(i, cv))
            return error("SeedGenesisCommitments() : CreateBlindCommitment failed for seed %d", i);

        // Deterministic note commitment (Merkle leaf)
        CHashWriter ssCmu(SER_GETHASH, 0);
        ssCmu << std::string("Innova_Genesis_Seed_CMU_");
        ssCmu << i;
        uint256 cmu = ssCmu.GetHash();

        // Append to Merkle tree and write to commitment DB
        if (!shieldedTree.Append(cmu))
            return error("SeedGenesisCommitments() : Merkle append failed for seed %d", i);
        uint64_t nCommitIdx = shieldedTree.Size() - 1;
        if (nCommitIdx != (uint64_t)i)
            return error("SeedGenesisCommitments() : unexpected seed index %" PRIu64 " for seed %d",
                         nCommitIdx, i);
        if (!txdb.WriteShieldedCommitment(nCommitIdx, cv))
            return error("SeedGenesisCommitments() : WriteShieldedCommitment failed for seed %d", i);
        if (fV3ShieldedPersistence)
        {
            std::string strIndexError;
            if (!txdb.PushShieldedCommitmentIndexV3(
                    nCommitIdx, cv, strIndexError))
                return error("SeedGenesisCommitments() : V3 reverse-index push failed for seed %d: %s",
                             i, strIndexError.c_str());
        }
        else if (!txdb.WriteShieldedCommitmentIndex(
                     cv.vchCommitment, nCommitIdx))
        {
            return error("SeedGenesisCommitments() : WriteShieldedCommitmentIndex failed for seed %d", i);
        }
        if (!txdb.WriteShieldedCommitmentHeight(nCommitIdx, FORK_HEIGHT_SHIELDED))
            return error("SeedGenesisCommitments() : WriteShieldedCommitmentHeight failed for seed %d", i);

        if (pCurveTree && !pCurveTree->InsertLeaf(cv))
            return error("SeedGenesisCommitments() : curve-tree insertion failed for seed %d", i);
    }

    if (fDebug)
        printf("SeedGenesisCommitments() : seeded %d genesis commitments for Lelantus anonymity set\n",
               LELANTUS_GENESIS_SEED_COUNT);
    return true;
}


// The coinstake's allowance: one subsidy, split at payment. Post-DAG PoS blocks are
// rejected, so the finality reserve is zero here; routed through the split anyway.
static CBlockSubsidySplit GetCoinStakeSubsidySplit(uint64_t nCoinAge, int64_t nFees,
                                                   const CBlock& block, const CBlockIndex* pindex)
{
    const int64_t nSubsidy = GetProofOfStakeReward((int64_t)nCoinAge, 0, pindex->pprev, 0);
    const int64_t nTotal = ApplyBlockSizePenalty(nSubsidy + nFees, block, pindex->pprev);
    int64_t nIssuance = ApplyBlockSizePenalty(nSubsidy, block, pindex->pprev);
    if (nIssuance > nTotal)
        nIssuance = nTotal;
    return CBlockSubsidySplit::ForBlock(pindex->nHeight, nIssuance, nTotal - nIssuance,
                                        CollateralnodeShare::Paid);
}

// Collateralnode payment rule: node-local gate, node-local verdict (wall clock, own tip,
// gossiped list, mempool). A rejection under this gate must not reach the block index.
int64_t CollateralnodePaymentWindowSeconds()
{
    return 20 * (int64_t)nCoinbaseMaturity;
}

bool CollateralnodePaymentRuleApplies(bool fJustCheck, int64_t nBlockTime,
                                      int64_t nNow, bool fPaymentsEnabled)
{
    return !fJustCheck && fPaymentsEnabled &&
           nBlockTime > nNow - CollateralnodePaymentWindowSeconds();
}

// The cold-stake CN payee check reads the same gossiped state, so it carries the same
// window. fPaymentsEnabled is true: the fork height scopes activation.
bool ColdStakeCNPayeeRuleApplies(bool fJustCheck, int nHeight, int64_t nCNPayment,
                                 int64_t nBlockTime, int64_t nNow)
{
    return nCNPayment > 0 && nHeight >= FORK_HEIGHT_CN_PAYMENT_VALIDATION &&
           CollateralnodePaymentRuleApplies(fJustCheck, nBlockTime, nNow, true);
}

// Whether this node's gossiped view recognises the payee. Not derivable from the chain,
// so two nodes can answer differently for the same block.
bool ColdStakeCNPayeeIsRegistered(int nHeight, const CScript& payeeScript)
{
    CScript expectedPayee;
    if (collateralnodePayments.GetBlockPayee(nHeight, expectedPayee) &&
        payeeScript == expectedPayee)
        return true;

    LOCK(cs_collateralnodes);
    for (CCollateralNode& mn : vecCollateralnodes)
    {
        if (!mn.IsEnabled())
            continue;
        CScript mnPayee;
        mnPayee.SetDestination(mn.pubkey.GetID());
        if (payeeScript == mnPayee)
            return true;
    }
    return false;
}

// Whether a ConnectBlock result may be persisted as BLOCK_FAILED_VALID: only a
// DoS-scored verdict every node reproduces. Both best-chain sites call this.
bool ConnectResultMayPersistVerdict(CBlock::ConnectResult result)
{
    return result == CBlock::CONNECT_RESULT_INVALID;
}

bool CBlock::ConnectBlock(CTxDB& txdb, CBlockIndex* pindex, bool fJustCheck,
                          bool fWriteNames, ConnectResult* pResult)
{
    // Name, wallet, UI and notification effects are replayed by best-chain callers after the
    // durable tip is published; the argument is kept for source compatibility.
    (void)fWriteNames;
    // Consensus-invalid is the default; only a site identifying a local read/write/resource
    // condition downgrades it.
    if (pResult)
        *pResult = CONNECT_RESULT_INVALID;
    const auto TransientFailure = [&](bool fReturn) -> bool {
        if (pResult)
            *pResult = CONNECT_RESULT_TRANSIENT;
        return fReturn;
    };
    const auto Connected = [&]() -> bool {
        if (pResult)
            *pResult = CONNECT_RESULT_OK;
        return true;
    };
    // A verdict persists only if the site scored it. Every deterministic rejection here
    // is a DoS(...) return, so an INVALID result reached without raising nDoS came from a
    // bare return -- a clock or local read condition -- and is downgraded on exit.
    struct CVerdictScopeGuard
    {
        ConnectResult* pResult;
        const CBlock& block;
        const int nDoSAtEntry;
        ~CVerdictScopeGuard()
        {
            if (pResult && *pResult == CONNECT_RESULT_INVALID && block.nDoS <= nDoSAtEntry)
                *pResult = CONNECT_RESULT_TRANSIENT;
        }
    } verdictGuard = { pResult, *this, nDoS };

    BLOCK_PHASE(BP_CONNECTBLOCK);
    if (!fJustCheck)
        BlockProfileNoteHeight(pindex->nHeight);
    int64_t nConnectBlockStart = GetTimeMillis();
    int64_t nConnectCheckStart = GetTimeMillis();

    // Check it again in case a previous version let a bad block in, but skip BlockSig checking
    if (!CheckBlock(!fJustCheck, !fJustCheck, false))
        return false;
    int64_t nConnectCheckMs = GetTimeMillis() - nConnectCheckStart;

    if (pindex->nHeight >= FORK_HEIGHT_DAG && IsProofOfStake())
        return DoS(100, error("ConnectBlock() : proof-of-stake blocks are not allowed after DAG fork"));

    // Defense in depth (mirrors AcceptBlock): no coinstake of any shape outside
    // vtx[1] of a proof-of-stake block. Scanned over the RAW tx list — a
    // DAG-skipped coinstake must still invalidate the block.
    if (pindex->nHeight >= FORK_HEIGHT_SHIELDED)
    {
        for (unsigned int i = 2; i < vtx.size(); i++)
            if (vtx[i].IsCoinStake())
                return DoS(100, error("ConnectBlock() : coinstake at tx index %u (only vtx[1] of a proof-of-stake block may be a coinstake)", i));
    }

    // strict script verification post-fork
    unsigned int flags = SCRIPT_VERIFY_NONE;

    if (pindex->nHeight == 2080000 && GetHash() == uint256("0x000000001f9f67efdef5c02fc3da51f308011443c9e5dae6a79a11dba88525e8"))
        return DoS(100, error("ConnectBlock() : reject block from bad chain"));

    // Strict script verification after fork height
    if (pindex->nHeight >= FORK_HEIGHT_TIGHTER_DRIFT)
    {
        flags = MANDATORY_SCRIPT_VERIFY_FLAGS |
                SCRIPT_VERIFY_STRICTENC |
                SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    }

    //// issue here: it doesn't know the version
    unsigned int nTxPos;
    if (fJustCheck)
        // FetchInputs treats CDiskTxPos(1,1,1) as a special "refer to memorypool" indicator
        // Since we're just checking the block and not actually connecting it, it might not (and probably shouldn't) be on the disk to get the transaction from
        nTxPos = 1;
    else
        nTxPos = pindex->nBlockPos + ::GetSerializeSize(CBlock(), SER_DISK, CLIENT_VERSION) - (2 * GetSizeOfCompactSize(0)) + GetSizeOfCompactSize(vtx.size());

    map<uint256, CTxIndex> mapQueuedChanges;
    int64_t nFees = 0;
    int64_t nValueIn = 0;
    int64_t nValueOut = 0;
    int64_t nAmountBurned = 0;
    int64_t nStakeReward = 0;
    // Declared IV5 fees of this block's active transactions. From the fee-note fork
    // on this sum leaves the transparent coinbase allowance and is the exact value a
    // coinbase note may credit to the pool. One derivation feeds both.
    int64_t nIV5FeeSum = 0;
    unsigned int nSigOps = 0;

    //DiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(vtx.size()));
    CDiskTxPos pos(pindex->nFile, pindex->nBlockPos, nTxPos);
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    vPos.reserve(vtx.size());

    std::vector<CAmount> vFees (vtx.size(), 0);

    // IDAG: skipped transactions are a deterministic inactive subgraph.
    // Every consensus consumer below must use this same filtered block view.
    bool fSkipSetIncomplete = false;
    std::set<uint256> setDAGSkippedTxs = GetDAGSkippedTxsForBlock(*this, pindex, &fSkipSetIncomplete);
    if (fSkipSetIncomplete)
        return TransientFailure(error("ConnectBlock() : DAG sibling set for %s is incomplete on this node "
                                      "(missing vertex or unreadable sibling)",
                                      pindex->GetBlockHash().ToString().substr(0,20).c_str()));
    if (!setDAGSkippedTxs.empty())
    {
        for (const CTransaction& tx : vtx)
        {
            if (setDAGSkippedTxs.count(tx.GetHash()) && hooks->IsNameTx(tx.nVersion))
                return DoS(100, error("ConnectBlock() : DAG conflict in name transaction %s",
                                      tx.GetHash().ToString().substr(0,10).c_str()));
        }
    }
    CBlock activeBlock = GetDAGActiveBlock(*this, setDAGSkippedTxs);

    std::vector<CFinalityVote> vFinalityVotes;
    FinalityEnvelopeDecodeResult voteEnvelopeFailure = FINALITY_ENVELOPE_NO_MATCH;
    if (!ExtractFinalityVotesFromBlockForHeight(
            activeBlock, pindex->nHeight, vFinalityVotes,
            &voteEnvelopeFailure))
        return DoS(100, error(
            "ConnectBlock() : invalid finality vote envelope for height %d (decode=%d)",
            pindex->nHeight, (int)voteEnvelopeFailure));
    std::string strFinalityCapacityError;
    if (!g_finalityTracker.CheckCanonicalVoteSetCapacity(
            vFinalityVotes, pindex->nHeight, &strFinalityCapacityError))
        return DoS(100, error(
            "ConnectBlock() : canonical finality vote capacity exceeded: %s",
            strFinalityCapacityError.c_str()));
    if (!vFinalityVotes.empty() && (pindex->nHeight < FORK_HEIGHT_DAG || IsProofOfStake()))
        return DoS(100, error("ConnectBlock() : finality votes are only valid in post-DAG proof-of-work blocks"));
    std::vector<CNoteFinalityVote> vNoteFinalityVotes;
    FinalityEnvelopeDecodeResult noteVoteEnvelopeFailure = FINALITY_ENVELOPE_NO_MATCH;
    if (!ExtractNoteFinalityVotesFromBlockForHeight(
            activeBlock, pindex->nHeight, vNoteFinalityVotes,
            &noteVoteEnvelopeFailure))
        return DoS(100, error(
            "ConnectBlock() : invalid note finality vote envelope for height %d (decode=%d)",
            pindex->nHeight, (int)noteVoteEnvelopeFailure));
    if (!vNoteFinalityVotes.empty() && IsProofOfStake())
        return DoS(100, error("ConnectBlock() : note finality votes are only valid in proof-of-work blocks"));
    if (vNoteFinalityVotes.size() > (size_t)FINALITY_MAX_BLOCK_NOTE_VOTES)
        return DoS(100, error("ConnectBlock() : too many note finality votes in block"));
    std::vector<CFinalityTallyShare> vFinalityShares = ExtractFinalityTallySharesFromBlock(activeBlock);
    if (!vFinalityShares.empty() && (pindex->nHeight < FORK_HEIGHT_DAG || IsProofOfStake()))
        return DoS(100, error("ConnectBlock() : finality tally shares are only valid in post-DAG proof-of-work blocks"));
    std::vector<CFinalityTallyCertificate> vFinalityCerts;
    FinalityEnvelopeDecodeResult certEnvelopeFailure = FINALITY_ENVELOPE_NO_MATCH;
    if (!ExtractFinalityTallyCertificatesFromBlockForHeight(
            activeBlock, pindex->nHeight, vFinalityCerts,
            &certEnvelopeFailure))
        return DoS(100, error(
            "ConnectBlock() : invalid finality certificate envelope for height %d (decode=%d)",
            pindex->nHeight, (int)certEnvelopeFailure));
    if (!vFinalityCerts.empty() && (pindex->nHeight < FORK_HEIGHT_DAG || IsProofOfStake()))
        return DoS(100, error("ConnectBlock() : finality tally certificates are only valid in post-DAG proof-of-work blocks"));

    // FCMP-era shielded spends (curve-tree path proofs) are rejected here. Versions at or
    // above FCMP with no shielded spend, including 2008, are untouched.
    if (pindex->nHeight >= FORK_HEIGHT_FCMP_VALIDATION)
    {
        for (unsigned int i = 1; i < activeBlock.vtx.size(); i++)
        {
            const CTransaction& tx = activeBlock.vtx[i];
            if (tx.nVersion >= SHIELDED_TX_VERSION_FCMP && !tx.vShieldedSpend.empty())
                return DoS(100, error("ConnectBlock() : tx %d carries an FCMP-era shielded spend whose membership is unverifiable; the encoding is permanently invalid", i));
        }
    }

    std::set<uint256> setBlockNullifiers;
    std::set<ec_point> setBlockAnonKeyImages;

    int64_t nTransparentValidateMicros = 0;
    int64_t nShieldedValidateMicros = 0;
    int64_t nPrivateStakeValidateMicros = 0;
    int64_t nAnonValidateMicros = 0;
    unsigned int nTransparentValidateCount = 0;
    unsigned int nShieldedValidateCount = 0;
    unsigned int nPrivateStakeValidateCount = 0;
    unsigned int nAnonValidateCount = 0;

    for (CTransaction& tx : vtx)
    {
        //const CTransaction &tx = vtx[i];
        int64_t nTxValidateStart = GetTimeMicros();
        uint256 hashTx = tx.GetHash();
        unsigned int nTxSize = ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);

        // Skip transactions whose inputs/nullifiers conflict with earlier DAG siblings.
        if (!tx.IsCoinBase() && setDAGSkippedTxs.count(hashTx))
        {
            if (fDebug)
                printf("ConnectBlock() : DAG conflict skip tx %s\n",
                       hashTx.ToString().substr(0, 20).c_str());
            if (!fJustCheck)
                nTxPos += nTxSize;
            pos.nTxPos += nTxSize;
            continue;
        }

        // Do not allow blocks that contain transactions which 'overwrite' older transactions,
        // unless those are already completely spent.
        // If such overwrites are allowed, coinbases and transactions depending upon those
        // can be duplicated to remove the ability to spend the first instance -- even after
        // being sent to another address.
        // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
        // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
        // already refuses previously-known transaction ids entirely.
        // This rule was originally applied all blocks whose timestamp was after March 15, 2012, 0:00 UTC.
        // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
        // two in the chain that violate it. This prevents exploiting the issue against nodes in their
        // initial block download.
        CTxIndex txindexOld;
        if (txdb.ReadTxIndex(hashTx, txindexOld)) {
            for (CDiskTxPos &pos : txindexOld.vSpent)
                if (pos.IsNull())
                    return DoS(100, error("ConnectBlock() : transaction %s overwrites an unspent transaction",
                                          hashTx.ToString().substr(0,10).c_str()));
        }

        nSigOps += tx.GetLegacySigOpCount();
        if (nSigOps > MAX_BLOCK_SIGOPS)
            return DoS(100, error("ConnectBlock() : too many sigops"));

        CDiskTxPos posThisTx(pindex->nFile, pindex->nBlockPos, nTxPos);
        if (!fJustCheck)
            nTxPos += nTxSize;

        MapPrevTx mapInputs;
        CLegacyAnonEffectPlan anonEffectPlan;
        bool fHaveAnonEffectPlan = false;
        if (tx.IsCoinBase())
        {
            int64_t nCoinbaseValue;
            try {
                nCoinbaseValue = tx.GetValueOut();
            } catch (const std::runtime_error& e) {
                return DoS(100, error("ConnectBlock() : coinbase GetValueOut overflow: %s", e.what()));
            }
            nValueOut += nCoinbaseValue;
            // A coinbase fee note takes value into the pool, where it still exists.
            // Counting only the transparent claim here would shrink the money supply
            // by the note's amount on every block that carries one.
            if (tx.IsPrivacyVNext())
            {
                int64_t nCoinbaseAbsorbed = 0;
                int64_t nCoinbaseReleased = 0;
                bool fFlowLocalFailure = false;
                std::string strFlowError;
                if (!GetPrivacyVNextTransparentFlow(tx, nCoinbaseAbsorbed,
                                                    nCoinbaseReleased,
                                                    fFlowLocalFailure, strFlowError))
                {
                    if (fFlowLocalFailure)
                    {
                        StartShutdown();
                        return TransientFailure(error(
                            "ConnectBlock() : local IV5 pool-flow failure for the coinbase: %s",
                            strFlowError.c_str()));
                    }
                    return DoS(100, error("ConnectBlock() : coinbase IV5 pool flow rejected: %s",
                                          strFlowError.c_str()));
                }
                if (nCoinbaseAbsorbed > std::numeric_limits<int64_t>::max() - nValueOut)
                    return DoS(100, error("ConnectBlock() : coinbase IV5 absorbed value overflow"));
                nValueOut += nCoinbaseAbsorbed;
            }
        }
        else
        {
            bool fInvalid;
            bool fFetchOk;
            {
                BLOCK_PHASE(BP_FETCHINPUTS);
                fFetchOk = tx.FetchInputs(txdb, mapQueuedChanges, true, false, mapInputs, fInvalid);
            }
            if (!fFetchOk)
            {
                if (fInvalid)
                    return DoS(100, error("ConnectBlock() : FetchInputs found invalid transaction %s",
                                          hashTx.ToString().substr(0,10).c_str()));
                return TransientFailure(error("ConnectBlock() : FetchInputs could not read inputs for %s",
                                              hashTx.ToString().substr(0,10).c_str()));
            }

            for (const CShieldedSpendDescription& spend : tx.vShieldedSpend)
            {
                if (!setBlockNullifiers.insert(spend.nullifier).second)
                    return DoS(100, error("ConnectBlock() : duplicate nullifier %s across txs in block",
                                          spend.nullifier.ToString().substr(0,10).c_str()));
            }

            // Add in sigops done by pay-to-script-hash inputs;
            // this is to prevent a "rogue miner" from creating
            // an incredibly-expensive-to-validate block.
            nSigOps += tx.GetP2SHSigOpCount(mapInputs);
            if (nSigOps > MAX_BLOCK_SIGOPS)
                return DoS(100, error("ConnectBlock() : too many sigops"));

            int64_t nTxValueIn = tx.GetValueIn(mapInputs);
            int64_t nTxValueOut = tx.GetValueOut();

            if (tx.nVersion == ANON_TXN_VERSION)
            {
                // reject ring sig txs in blocks after deprecation fork
                if (pindex->nHeight >= FORK_HEIGHT_RINGSIG_DEPRECATION)
                    return DoS(100, error("ConnectBlock() : ring signature transactions deprecated after height %d", FORK_HEIGHT_RINGSIG_DEPRECATION));

                if (!tx.BuildLegacyAnonEffectPlan(
                        txdb, pindex->nHeight, setBlockAnonKeyImages,
                        anonEffectPlan, fInvalid))
                {
                    if (fInvalid)
                        return DoS(100, error("ConnectBlock() : legacy ANON effect plan is invalid for tx %s",
                                              tx.GetHash().ToString().substr(0,10).c_str()));
                    return TransientFailure(error("ConnectBlock() : legacy ANON effect plan could not read exact chain state for %s",
                                                  tx.GetHash().ToString().substr(0,10).c_str()));
                }

                if (anonEffectPlan.nValueIn < 0 ||
                    anonEffectPlan.nValueIn > MAX_MONEY - nTxValueIn)
                    return DoS(100, error("ConnectBlock() : legacy ANON input value overflow"));
                nTxValueIn += anonEffectPlan.nValueIn;
                fHaveAnonEffectPlan = true;
            }

            if (tx.IsShielded())
            {
                if (tx.nValueBalance > 0)
                {
                    if (tx.nValueBalance > std::numeric_limits<int64_t>::max() - nTxValueIn)
                        return DoS(100, error("ConnectBlock() : shielded value balance overflow (unshield)"));
                    nTxValueIn += tx.nValueBalance;
                }
                else if (tx.nValueBalance < 0)
                {
                    if (tx.nValueBalance == std::numeric_limits<int64_t>::min())
                        return DoS(100, error("ConnectBlock() : shielded value balance INT64_MIN"));
                    int64_t nAbsBalance = -tx.nValueBalance;
                    if (nAbsBalance > std::numeric_limits<int64_t>::max() - nTxValueOut)
                        return DoS(100, error("ConnectBlock() : shielded value balance overflow (shield)"));
                    nTxValueOut += nAbsBalance;
                }
            }

            if (tx.IsPrivacyVNext())
            {
                // The pool's share is the IV5 transaction's counterparty; without it a shield's inputs
                // would look like surplus payable to the miner as fee.
                int64_t nAbsorbed = 0;
                int64_t nReleased = 0;
                int64_t nDeclaredPayloadFee = 0;
                bool fFlowLocalFailure = false;
                std::string strFlowError;
                if (!GetPrivacyVNextTransparentFlow(tx, nAbsorbed, nReleased,
                                                    fFlowLocalFailure, strFlowError,
                                                    &nDeclaredPayloadFee))
                {
                    if (fFlowLocalFailure)
                    {
                        StartShutdown();
                        return TransientFailure(error(
                            "ConnectBlock() : local IV5 pool-flow failure for %s: %s",
                            tx.GetHash().ToString().substr(0,10).c_str(),
                            strFlowError.c_str()));
                    }
                    return DoS(100, error("ConnectBlock() : IV5 pool flow rejected for %s: %s",
                                          tx.GetHash().ToString().substr(0,10).c_str(),
                                          strFlowError.c_str()));
                }
                if (nDeclaredPayloadFee > std::numeric_limits<int64_t>::max() - nIV5FeeSum)
                    return DoS(100, error("ConnectBlock() : IV5 fee sum overflow"));
                nIV5FeeSum += nDeclaredPayloadFee;
                if (nAbsorbed > std::numeric_limits<int64_t>::max() - nTxValueOut)
                    return DoS(100, error("ConnectBlock() : IV5 absorbed value overflow"));
                nTxValueOut += nAbsorbed;
                if (nReleased > std::numeric_limits<int64_t>::max() - nTxValueIn)
                    return DoS(100, error("ConnectBlock() : IV5 released value overflow"));
                nTxValueIn += nReleased;
            }

            if (nTxValueIn > std::numeric_limits<int64_t>::max() - nValueIn)
                return DoS(100, error("ConnectBlock() : block value-in overflow"));
            if (nTxValueOut > std::numeric_limits<int64_t>::max() - nValueOut)
                return DoS(100, error("ConnectBlock() : block value-out overflow"));
            nValueIn += nTxValueIn;
            nValueOut += nTxValueOut;
            for (const CTxOut& out : tx.vout) {
              if(out.scriptPubKey.IsUnspendable())
                nAmountBurned += out.nValue;
            }
            if (!tx.IsCoinStake()) {
                nFees += nTxValueIn - nTxValueOut;
            }
            if (tx.IsCoinStake())
                nStakeReward = nTxValueOut - nTxValueIn;

            // The coinstake exemptions inside ConnectInputs may only be claimed
            // by the kernel-validated coinstake: vtx[1] of a proof-of-stake
            // block. A coinstake-shaped tx anywhere else gets full ordinary-tx
            // validation.
            bool fValidatedCoinstake = IsProofOfStake() && (&tx == &vtx[1]);
            const int nTxDoSBeforeConnect = tx.nDoS;
            bool fConnectOk;
            {
                BLOCK_PHASE(BP_CONNECTINPUTS);
                fConnectOk = tx.ConnectInputs(txdb, mapInputs, mapQueuedChanges,
                                              posThisTx, pindex, true, false, flags, true,
                                              fValidatedCoinstake,
                                              fHaveAnonEffectPlan, pindex->nHeight,
                                              anonEffectPlan.nValueIn);
            }
            if (!fConnectOk)
            {
                if (tx.nDoS > nTxDoSBeforeConnect)
                    return DoS(tx.nDoS - nTxDoSBeforeConnect, false);
                return TransientFailure(error("ConnectBlock() : ConnectInputs failed without a deterministic-invalid result for %s",
                                              hashTx.ToString().substr(0,10).c_str()));
            }

            if (fHaveAnonEffectPlan && !fJustCheck)
            {
                std::string strAnonEffectError;
                if (!ApplyLegacyAnonEffectPlan(txdb, anonEffectPlan,
                                               strAnonEffectError))
                    return TransientFailure(error(
                        "ConnectBlock() : failed to stage legacy ANON chain effects for %s: %s",
                        hashTx.ToString().substr(0,10).c_str(),
                        strAnonEffectError.c_str()));
            }

            int64_t nTxValidateMicros = GetTimeMicros() - nTxValidateStart;
            if (tx.IsCoinStake() && (tx.nVersion == SHIELDED_TX_VERSION_NULLSTAKE ||
                                     tx.nVersion == SHIELDED_TX_VERSION_NULLSTAKE_V2 ||
                                     tx.nVersion == SHIELDED_TX_VERSION_NULLSTAKE_COLD))
            {
                nPrivateStakeValidateMicros += nTxValidateMicros;
                nPrivateStakeValidateCount++;
            }
            else if (tx.IsShielded())
            {
                nShieldedValidateMicros += nTxValidateMicros;
                nShieldedValidateCount++;
            }
            else if (tx.nVersion == ANON_TXN_VERSION)
            {
                nAnonValidateMicros += nTxValidateMicros;
                nAnonValidateCount++;
            }
            else
            {
                nTransparentValidateMicros += nTxValidateMicros;
                nTransparentValidateCount++;
            }
        }

        mapQueuedChanges[hashTx] = CTxIndex(posThisTx, tx.vout.size());

        vPos.push_back(std::make_pair(tx.GetHash(), pos));
        // pos.nTxOffset += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);
        pos.nTxPos += nTxSize;
    }

    //int64_t nTime1 = GetTimeMicros(); nTimeConnect += nTime1 - nTimeStart;
    //LogPrint("bench", "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) [%.2fs]\n", (unsigned)vtx.size(), 0.001 * (nTime1 - nTimeStart), 0.001 * (nTime1 - nTimeStart) / vtx.size(), nInputs <= 1 ? 0 : 0.001 * (nTime1 - nTimeStart) / (nInputs-1), nTimeConnect * 0.000001);

    // if (!control.Wait())
    //     return state.DoS(100, false);
    // int64_t nTime2 = GetTimeMicros(); nTimeVerify += nTime2 - nTimeStart;
    // LogPrint("bench", "    - Verify %u txins: %.2fms (%.3fms/txin) [%.2fs]\n", nInputs - 1, 0.001 * (nTime2 - nTimeStart), nInputs <= 1 ? 0 : 0.001 * (nTime2 - nTimeStart) / (nInputs-1), nTimeVerify * 0.000001);


    // Extra coinbase money this block is allowed to mint on top of the block subsidy.
    // Non-zero on exactly one block per epoch -- the settlement block below.
    int64_t nFinalityRewardOut = 0;
    if (!vFinalityVotes.empty())
    {
        if (!CheckFinalityStakeProofsNotSpentInBlock(activeBlock, vFinalityVotes))
            return DoS(100, error("ConnectBlock() : finality stake proof spent in including block"));
        std::string strVoteCommitError;
        if (!CheckFinalityVoteCommitments(activeBlock, vFinalityVotes, &strVoteCommitError))
            return DoS(100, error("ConnectBlock() : finality vote commitments invalid: %s", strVoteCommitError.c_str()));
        for (const CFinalityVote& vote : vFinalityVotes)
        {
            std::string strVoteError;
            FinalityResult voteResult = FINALITY_RESULT_INVALID;
            if (!g_finalityTracker.CheckVote(vote, txdb, &strVoteError,
                                             CFinalityVoteContext::Connect(pindex),
                                             &voteResult))
            {
                if (voteResult == FINALITY_RESULT_LOCAL_STATE)
                    return TransientFailure(error(
                        "ConnectBlock() : finality vote local state unavailable: %s",
                        strVoteError.c_str()));
                return DoS(100, error("ConnectBlock() : finality vote invalid: %s",
                                      strVoteError.c_str()));
            }
        }
    }

    // Per-epoch finality-reward settlement. Every counted epoch-E vote is paid exactly
    // once, in the canonical block at H_E + FINALITY_VOTE_INCLUSION_WINDOW, from the
    // frozen vote set the epoch's own window blocks committed. Re-carrying a vote across
    // several canonical window blocks changes nothing: the settlement dedupes by
    // nullifier, and no other block is allowed any finality reward at all.
    //
    // The payout is derived from the ancestor chain (GatherFinalitySettlementVotes),
    // never from mutable tracker state such as mapConnectedVotes, so producer and
    // validator compute the same coinbase allowance. Coupling a money allowance to
    // order-dependent live state is what produced the reward-base mismatch and the
    // private-finality ConnectBlock split; the settlement set is anchor-pure instead.
    //
    // Reorg: the mint is an ordinary coinbase output, so it reverses through the normal
    // UTXO disconnect. The settlement block's ancestors ARE the window blocks, so the
    // window can never be reorged out from under a still-connected settlement block.
    // Whatever block becomes canonical at this height re-derives the set from ITS
    // ancestors and re-pays accordingly. DisconnectBlockVotes is decoupled from payment.
    //
    // Private tier: vSettlementVotes already carries both tiers. The private leg plugs in
    // at this same call, alongside CheckFinalitySettlementOutputs -- see the PRIVATE-TIER
    // PLUG-IN POINT in BuildFinalitySettlementOutputs (finality.cpp). It mints sealed
    // reward notes, so it lands in the shielded-pool delta rather than in
    // nFinalityRewardOut, and it is inert until the note-tally layer is wired.
    {
        int nSettlementEpoch = -1;
        if (IsFinalitySettlementHeight(pindex->nHeight, &nSettlementEpoch))
        {
            std::vector<CFinalityVote> vSettlementVotes;
            std::string strSettleError;
            bool fSettleLocalFailure = false;
            if (!GatherFinalitySettlementVotes(pindex->pprev, nSettlementEpoch, vSettlementVotes,
                                               &strSettleError, &fSettleLocalFailure))
            {
                // An unreadable window block is this node's block file; every other
                // refusal is a property of the ancestor chain.
                if (fSettleLocalFailure)
                    return TransientFailure(error("ConnectBlock() : finality settlement set unreadable: %s",
                                                  strSettleError.c_str()));
                return DoS(100, error("ConnectBlock() : finality settlement set unavailable: %s", strSettleError.c_str()));
            }
            const int64_t nSettlementBudget =
                GetClampedFinalitySettlementBudget(pindex->pprev, nSettlementEpoch);
            if (!CheckFinalitySettlementOutputs(activeBlock, vSettlementVotes, nSettlementBudget,
                                                nFinalityRewardOut, &strSettleError))
                return DoS(100, error("ConnectBlock() : finality settlement outputs invalid: %s", strSettleError.c_str()));
        }
    }

    for (const CFinalityTallyCertificate& cert : vFinalityCerts)
    {
        std::string strCertError;
        if (!cert.IsValidBasic(&strCertError))
            return DoS(100, error("ConnectBlock() : finality tally certificate invalid: %s", strCertError.c_str()));
        if (GetEpochForHeight(cert.nHeight) != cert.nEpoch ||
            GetEpochBoundaryHeight(cert.nEpoch, cert.nHeight) != cert.nHeight)
            return DoS(100, error("ConnectBlock() : finality tally certificate has wrong epoch boundary"));
    }
    for (const CFinalityTallyShare& share : vFinalityShares)
    {
        // Strict vote resolution (connected votes or this block's votes only):
        // pending relay state differs between nodes, so consulting it here
        // would make block validity node-dependent and allow chain splits.
        std::string strShareError;
        if (!g_finalityTracker.CheckTallyShare(share, &strShareError, &vFinalityVotes, false, pindex->nHeight))
            return DoS(100, error("ConnectBlock() : finality tally share invalid: %s", strShareError.c_str()));
    }

    // From the fee-note fork the coinbase may carry one note worth exactly the declared IV5
    // fees, and the transparent allowance drops the same sum. This equality is the only
    // thing backing the note.
    const bool fIV5FeeNoteFork = IsIV5FeeNoteActiveAtHeight(pindex->nHeight);
    if (vtx[0].IsPrivacyVNext())
    {
        if (!fIV5FeeNoteFork)
            return DoS(100, error("ConnectBlock() : coinbase IV5 payload before height %d",
                                  FORK_HEIGHT_IV5_FEE_NOTE));

        // The fee note's mask is pinned: its amount is public via the block equality, and a
        // free choice would fingerprint the producer.
        uint8_t nCoinbaseMask = 0;
        if (vtx[0].privacyVNext.vchPayload.empty() ||
            !iv5::CoinbaseFeeNoteEnvelopeAllows(&vtx[0].privacyVNext.vchPayload[0],
                                                vtx[0].privacyVNext.vchPayload.size(),
                                                nCoinbaseMask))
            return DoS(100, error("ConnectBlock() : coinbase IV5 note does not declare the "
                                  "fee note's disclosure mask %d",
                                  (int)iv5::COINBASE_FEE_NOTE_DISCLOSURE_MASK));

        PrivacyVNextStateEffects coinbaseEffects;
        const PrivacyVNextPayloadValidation coinbaseValidation =
            ExtractPrivacyVNextPayloadEffects(
                static_cast<uint32_t>(vtx[0].nVersion),
                vtx[0].privacyVNext.vchPayload, coinbaseEffects);
        if (coinbaseValidation.fLocalFailure)
        {
            StartShutdown();
            return TransientFailure(error(
                "ConnectBlock() : local IV5 payload-effects failure for the coinbase: %s",
                coinbaseValidation.strError.c_str()));
        }
        if (!coinbaseValidation.IsValid())
            return DoS(100, error("ConnectBlock() : invalid coinbase IV5 payload effects: %s",
                                  coinbaseValidation.strError.c_str()));

        if (!coinbaseEffects.keyImages.empty())
            return DoS(100, error("ConnectBlock() : coinbase IV5 payload spends notes"));
        if (coinbaseEffects.nFee != 0)
            return DoS(100, error("ConnectBlock() : coinbase IV5 payload charges a fee"));
        if (nIV5FeeSum <= 0)
            return DoS(100, error("ConnectBlock() : coinbase IV5 note in a block with no IV5 fees"));
        if (coinbaseEffects.nTransparentValueBalance != nIV5FeeSum)
            return DoS(100, error("ConnectBlock() : coinbase IV5 note declares %" PRId64
                                  " against a block IV5 fee sum of %" PRId64,
                                  coinbaseEffects.nTransparentValueBalance, nIV5FeeSum));
    }

    if (IsProofOfWork())
    {
        // Historical compatibility: the original code used pindexBest->nHeight
        // (which equals pindex->nHeight - 1 during sequential block connection)
        // instead of the block's own height. The entire reward schedule was built
        // with this off-by-one behavior. Preserve it for historical blocks.
        int nRewardHeight = pindex->nHeight;
        if (pindex->nHeight < FORK_HEIGHT_TIGHTER_DRIFT && pindex->nHeight > 0)
            nRewardHeight = pindex->nHeight - 1;
        int64_t nAllowedFees = nFees;
        if (fIV5FeeNoteFork)
        {
            // ConnectInputs holds every payload's declared fee at or below what its
            // transparent side actually handed over, so this subtraction cannot go
            // negative on a block whose transactions all connected.
            if (nIV5FeeSum > nFees)
                return DoS(100, error("ConnectBlock() : block IV5 fee sum %" PRId64
                                      " exceeds the fees it collected %" PRId64,
                                      nIV5FeeSum, nFees));
            nAllowedFees -= nIV5FeeSum;
        }
        // One subsidy, split at payment; the settlement is netted off the headroom first.
        int64_t nSubsidy = GetProofOfWorkReward(nRewardHeight, 0, pindex->pprev, nFinalityRewardOut);

        // Adaptive block size penalty (post-DAG): applied to the whole allowance and to the
        // issuance leg; truncation lands in the fee leg.
        int64_t nBlockValue = ApplyBlockSizePenalty(nSubsidy + nAllowedFees, *this, pindex->pprev);
        int64_t nIssuance = ApplyBlockSizePenalty(nSubsidy, *this, pindex->pprev);
        if (nIssuance > nBlockValue)
            nIssuance = nBlockValue;

        // PaidToBlock() is Producer() + Collateralnode(), which is the same number
        // whichever collateralnode mode is asked for -- the mode only decides how
        // that number is divided, and this check is on the total.
        const CBlockSubsidySplit subsidySplit =
            CBlockSubsidySplit::ForBlock(pindex->nHeight, nIssuance, nBlockValue - nIssuance,
                                         CollateralnodeShare::Paid);

        // Check coinbase reward. The finality reserve is withheld, so the allowance is the
        // block's own paid shares plus the settlement leg.
        if (subsidySplit.PaidToBlock() > MAX_MONEY - nFinalityRewardOut)
            return DoS(50, error("ConnectBlock() : finality reward overflow"));
        int64_t nAllowedCoinbase = subsidySplit.PaidToBlock() + nFinalityRewardOut;

        if (vtx[0].GetValueOut() > nAllowedCoinbase)
            return DoS(50, error("ConnectBlock() : coinbase reward exceeded (actual=%" PRId64" vs calculated=%" PRId64")",
                   vtx[0].GetValueOut(),
                   nAllowedCoinbase));

        // Block-level value conservation: no combination of per-tx exemptions
        // may create value beyond the coinbase allowance. nValueIn/nValueOut
        // already include the shielded value-balance flows of every active tx.
        if (pindex->nHeight >= FORK_HEIGHT_DAG)
        {
            if (nValueIn > std::numeric_limits<int64_t>::max() - nAllowedCoinbase)
                return DoS(100, error("ConnectBlock() : block value conservation overflow"));
            if (nValueOut > nValueIn + nAllowedCoinbase)
                return DoS(100, error("ConnectBlock() : block mints value (out=%" PRId64 " in=%" PRId64 " allowed_coinbase=%" PRId64 ")",
                                      nValueOut, nValueIn, nAllowedCoinbase));
        }
    }
    if (IsProofOfStake())
    {
        if (nStakeReward == 0 && !vtx[1].IsCoinStake())
            return DoS(100, error("ConnectBlock() : PoS block but vtx[1] is not coinstake"));

        if (vtx[1].nVersion == SHIELDED_TX_VERSION_NULLSTAKE_V2)
        {
            if (pindex->nHeight < FORK_HEIGHT_NULLSTAKE_V2)
                return DoS(100, error("ConnectBlock() : NullStake V2 coinstake before fork height"));

            if (vtx[1].nullstakeProofV2.IsNull())
                return DoS(100, error("ConnectBlock() : NullStake V2 kernel proof missing"));

            if (vtx[1].vShieldedSpend.empty())
                return DoS(100, error("ConnectBlock() : NullStake V2 coinstake has no shielded spends"));

            if (vtx[1].nullstakeProofV2.nTimeTx != nTime)
                return DoS(100, error("ConnectBlock() : NullStake V2 nTimeTx %" PRId64 " != block time %" PRId64,
                                       (int64_t)vtx[1].nullstakeProofV2.nTimeTx, (int64_t)nTime));

            if (pindex->pprev)
            {
                if (vtx[1].nullstakeProofV2.nStakeModifier != pindex->pprev->nStakeModifier)
                    return DoS(100, error("ConnectBlock() : NullStake V2 stake modifier mismatch (proof=0x%016" PRIx64 " chain=0x%016" PRIx64 ")",
                                           vtx[1].nullstakeProofV2.nStakeModifier, pindex->pprev->nStakeModifier));
            }

            // Pinned kernel metadata: the circuit takes these as free public
            // inputs and the curve tree carries no age data, so unpinned values
            // allow coin-age forgery / kernel grinding and leak the staked
            // note's origin block + position.
            if (pindex->nHeight >= FORK_HEIGHT_KERNEL_PINNING &&
                !CheckNullStakeKernelPinning(vtx[1].nullstakeProofV2.nBlockTimeFrom,
                                             vtx[1].nullstakeProofV2.nTxPrevOffset,
                                             vtx[1].nullstakeProofV2.nTxTimePrev,
                                             vtx[1].nullstakeProofV2.nVoutN,
                                             vtx[1].nullstakeProofV2.nTimeTx))
                return DoS(100, error("ConnectBlock() : NullStake V2 kernel metadata not pinned"));

            if (!VerifyNullStakeKernelProofV2(vtx[1].nullstakeProofV2,
                                              vtx[1].vShieldedSpend[0].cv,
                                              nBits, pindex->nHeight))
                return DoS(100, error("ConnectBlock() : NullStake V2 kernel proof invalid"));

            // Legacy NullStake membership rested on the FCMP path-proof layer,
            // which is gone. The coinstake still parses; nothing can show it
            // spends a note in the tree, so the encoding is never valid.
            // Nothing below this return runs, the stake-reward bound included;
            // a membership check put back here brings that bound back with it.
            return DoS(100, error("ConnectBlock() : NullStake V2 stake note membership is unverifiable; the coinstake encoding is permanently invalid"));

            uint64_t nCoinAge = 1;  // Minimum coin-day for V2
            int64_t nCalculatedStakeReward = GetCoinStakeSubsidySplit(nCoinAge, nFees, *this, pindex).PaidToBlock();
            if (nStakeReward > nCalculatedStakeReward)
                return DoS(100, error("ConnectBlock() : NullStake V2 coinstake pays too much(actual=%" PRId64" vs calculated=%" PRId64")", nStakeReward, nCalculatedStakeReward));
        }
        else if (vtx[1].nVersion == SHIELDED_TX_VERSION_NULLSTAKE_COLD)
        {
            if (pindex->nHeight < FORK_HEIGHT_NULLSTAKE_V3)
                return DoS(100, error("ConnectBlock() : NullStake V3 cold stake coinstake before fork height"));

            // B2-e: half-aggregated M-of-N (nThresholdM > 0) cold staking activates only at
            // the DELEGSET fork. Before it, only the legacy 1-of-1 (nThresholdM == 0) is valid.
            if (vtx[1].nullstakeProofV3.nThresholdM > 0 &&
                pindex->nHeight < FORK_HEIGHT_NULLSTAKE_DELEGSET)
                return DoS(100, error("ConnectBlock() : NullStake V3 M-of-N coinstake before DELEGSET fork height"));
            // B2-c: the ZK-hidden-signer tier (nAuthMode == B2C_HIDDEN) activates only at the B2C fork.
            // Defense-in-depth on the coinstake path (the live B2-c staking path is the finality vote).
            if (vtx[1].nullstakeProofV3.nThresholdM > 0 &&
                vtx[1].nullstakeProofV3.nAuthMode == NULLSTAKE_AUTHMODE_B2C_HIDDEN &&
                pindex->nHeight < FORK_HEIGHT_NULLSTAKE_B2C)
                return DoS(100, error("ConnectBlock() : NullStake V3 B2-c hidden coinstake before B2C fork height"));

            if (vtx[1].nullstakeProofV3.IsNull())
                return DoS(100, error("ConnectBlock() : NullStake V3 kernel proof missing"));

            if (vtx[1].vShieldedSpend.empty())
                return DoS(100, error("ConnectBlock() : NullStake V3 coinstake has no shielded spends"));

            if (vtx[1].nullstakeProofV3.acProof.GetProofSize() > BPAC_V3_MAX_PROOF_SIZE)
                return DoS(100, error("ConnectBlock() : NullStake V3 proof exceeds size limit (%u > %u)",
                                       (unsigned int)vtx[1].nullstakeProofV3.acProof.GetProofSize(),
                                       (unsigned int)BPAC_V3_MAX_PROOF_SIZE));

            // B2-e/B2-c: bound the M-of-N vectors before the kernel verifier (defense in depth; the tier
            // verifiers also enforce these). Branch on nAuthMode so the bounds match the tier the verifier
            // dispatches to -- otherwise a B2-c hidden proof (empty half-agg triple) would be wrongly
            // rejected here before the tier-aware verifier runs.
            if (vtx[1].nullstakeProofV3.nThresholdM > 0)
            {
                const CNullStakeKernelProofV3& mp = vtx[1].nullstakeProofV3;
                bool fBounds = mp.nThresholdM <= MAX_NULLSTAKE_MOFN_MEMBERS &&
                               !mp.vStakerSet.empty() && mp.vStakerSet.size() <= MAX_NULLSTAKE_MOFN_MEMBERS &&
                               mp.nThresholdM <= mp.vStakerSet.size();
                if (mp.nAuthMode == NULLSTAKE_AUTHMODE_B2C_HIDDEN)
                {
                    // Hidden tier: the public half-agg triple MUST be empty; carries a hiddenAuth blob.
                    fBounds = fBounds &&
                              mp.vSignerPubKeys.empty() && mp.vSignerRPoints.empty() &&
                              mp.vchAggregatedSScalar.empty() &&
                              !mp.hiddenAuth.IsNull() &&
                              mp.hiddenAuth.GetProofSize() <= NULLSTAKE_B2C_MAX_AUTH_SIZE;
                }
                else
                {
                    // Public half-agg tier: the M signer vectors + the aggregated s-scalar.
                    fBounds = fBounds &&
                              mp.vSignerPubKeys.size() >= mp.nThresholdM &&
                              mp.vSignerPubKeys.size() <= MAX_NULLSTAKE_MOFN_SIGNERS &&
                              mp.vSignerRPoints.size() == mp.vSignerPubKeys.size() &&
                              mp.vchAggregatedSScalar.size() == 32;
                }
                if (!fBounds)
                    return DoS(100, error("ConnectBlock() : NullStake V3 M-of-N structural bounds violated"));
            }

            if (vtx[1].nullstakeProofV3.nTimeTx != nTime)
                return DoS(100, error("ConnectBlock() : NullStake V3 nTimeTx %" PRId64 " != block time %" PRId64,
                                       (int64_t)vtx[1].nullstakeProofV3.nTimeTx, (int64_t)nTime));

            {
                uint256 zeroHash;
                memset(zeroHash.begin(), 0, 32);
                if (vtx[1].nullstakeProofV3.delegationHash == zeroHash)
                    return DoS(100, error("ConnectBlock() : NullStake V3 delegation hash is zero"));
            }

            // 1-of-1 carries a 33-byte pk_stake; an M-of-N proof carries an EMPTY pk_stake
            // (it has a staker SET, bounded above) and the M-of-N verifier requires it empty,
            // so this structural check applies only to the legacy 1-of-1 path.
            if (vtx[1].nullstakeProofV3.nThresholdM == 0 &&
                vtx[1].nullstakeProofV3.vchPkStake.size() != 33)
                return DoS(100, error("ConnectBlock() : NullStake V3 pk_stake invalid size"));
            if (vtx[1].nullstakeProofV3.vchPkOwner.size() != 33)
                return DoS(100, error("ConnectBlock() : NullStake V3 pk_owner invalid size"));

            if (pindex->pprev)
            {
                if (vtx[1].nullstakeProofV3.nStakeModifier != pindex->pprev->nStakeModifier)
                    return DoS(100, error("ConnectBlock() : NullStake V3 stake modifier mismatch (proof=0x%016" PRIx64 " chain=0x%016" PRIx64 ")",
                                           vtx[1].nullstakeProofV3.nStakeModifier, pindex->pprev->nStakeModifier));
            }

            // Pinned kernel metadata (same rationale as V2).
            if (pindex->nHeight >= FORK_HEIGHT_KERNEL_PINNING &&
                !CheckNullStakeKernelPinning(vtx[1].nullstakeProofV3.nBlockTimeFrom,
                                             vtx[1].nullstakeProofV3.nTxPrevOffset,
                                             vtx[1].nullstakeProofV3.nTxTimePrev,
                                             vtx[1].nullstakeProofV3.nVoutN,
                                             vtx[1].nullstakeProofV3.nTimeTx))
                return DoS(100, error("ConnectBlock() : NullStake V3 kernel metadata not pinned"));

            if (!VerifyNullStakeKernelProofV3(vtx[1].nullstakeProofV3,
                                              vtx[1].vShieldedSpend[0].cv,
                                              nBits, pindex->nHeight))
                return DoS(100, error("ConnectBlock() : NullStake V3 kernel proof invalid"));

            // Legacy NullStake membership rested on the FCMP path-proof layer,
            // which is gone. The coinstake still parses; nothing can show it
            // spends a note in the tree, so the encoding is never valid.
            // Nothing below this return runs, the stake-reward bound included;
            // a membership check put back here brings that bound back with it.
            return DoS(100, error("ConnectBlock() : NullStake V3 stake note membership is unverifiable; the coinstake encoding is permanently invalid"));

            // V3 reward: same conservative approach as V2
            uint64_t nCoinAge = 1;
            int64_t nCalculatedStakeReward = GetCoinStakeSubsidySplit(nCoinAge, nFees, *this, pindex).PaidToBlock();
            if (nStakeReward > nCalculatedStakeReward)
                return DoS(100, error("ConnectBlock() : NullStake V3 coinstake pays too much(actual=%" PRId64" vs calculated=%" PRId64")", nStakeReward, nCalculatedStakeReward));
        }
        else if (vtx[1].nVersion == SHIELDED_TX_VERSION_NULLSTAKE)
        {
            if (pindex->nHeight < FORK_HEIGHT_NULLSTAKE)
                return DoS(100, error("ConnectBlock() : NullStake coinstake before fork height"));

            if (vtx[1].nullstakeProof.IsNull())
                return DoS(100, error("ConnectBlock() : NullStake kernel proof missing"));

            if (vtx[1].vShieldedSpend.empty())
                return DoS(100, error("ConnectBlock() : NullStake coinstake has no shielded spends"));

            if (vtx[1].nullstakeProof.nTimeTx != nTime)
                return DoS(100, error("ConnectBlock() : NullStake nTimeTx %" PRId64 " != block time %" PRId64,
                                       (int64_t)vtx[1].nullstakeProof.nTimeTx, (int64_t)nTime));

            if (vtx[1].nullstakeProof.nBlockTimeFrom >= vtx[1].nullstakeProof.nTimeTx)
                return DoS(100, error("ConnectBlock() : NullStake nBlockTimeFrom >= nTimeTx"));

            {
                int64_t nStakeAge = (int64_t)vtx[1].nullstakeProof.nTimeTx - (int64_t)vtx[1].nullstakeProof.nBlockTimeFrom;
                if (nStakeAge < nStakeMinAge)
                    return DoS(100, error("ConnectBlock() : NullStake stake age %" PRId64 " < minimum %" PRId64, nStakeAge, (int64_t)nStakeMinAge));
                if (nStakeAge > 365 * 24 * 60 * 60)
                    return DoS(50, error("ConnectBlock() : NullStake stake age %" PRId64 " exceeds 1 year", nStakeAge));
            }

            {
                bool fFoundBlockTime = false;
                CBlockIndex* pBlockFrom = NULL;
                CBlockIndex* pWalk = pindex->pprev;
                // increase lookback to cover nStakeMaxAge (90 days)
                // With 15s blocks: 90 days = 518,400 blocks. Use 600,000 for margin.
                // Was 1000 which only covered ~4.2 hours -- far less than 10-hour nStakeMinAge
                for (int i = 0; i < 600000 && pWalk != NULL; i++, pWalk = pWalk->pprev)
                {
                    if ((int64_t)pWalk->nTime == (int64_t)vtx[1].nullstakeProof.nBlockTimeFrom)
                    {
                        fFoundBlockTime = true;
                        pBlockFrom = pWalk;
                        break;
                    }
                }
                if (!fFoundBlockTime || pBlockFrom == NULL)
                    return DoS(100, error("ConnectBlock() : NullStake nBlockTimeFrom does not match any recent block"));

                // verify stake modifier matches chain state
                uint64_t nExpectedStakeModifier = 0;
                int nStakeModifierHeight = 0;
                int64_t nStakeModifierTime = 0;
                if (!GetKernelStakeModifier(pBlockFrom->GetBlockHash(), nExpectedStakeModifier,
                                            nStakeModifierHeight, nStakeModifierTime, false))
                    return DoS(100, error("ConnectBlock() : Failed to get stake modifier for NullStake proof"));

                if (vtx[1].nullstakeProof.nStakeModifier != nExpectedStakeModifier)
                    return DoS(100, error("ConnectBlock() : NullStake stake modifier mismatch (proof=0x%016" PRIx64 " chain=0x%016" PRIx64 ")",
                                          vtx[1].nullstakeProof.nStakeModifier, nExpectedStakeModifier));
            }

            int64_t nWeight = GetWeight((int64_t)vtx[1].nullstakeProof.nBlockTimeFrom,
                                         (int64_t)vtx[1].nullstakeProof.nTimeTx);

            if (!VerifyNullStakeKernelProof(vtx[1].nullstakeProof,
                                            vtx[1].vShieldedSpend[0].cv,
                                            nBits, nWeight))
                return DoS(100, error("ConnectBlock() : NullStake kernel proof invalid"));

            // Legacy NullStake membership rested on the FCMP path-proof layer,
            // which is gone. The coinstake still parses; nothing can show it
            // spends a note in the tree, so the encoding is never valid.
            // Nothing below this return runs, the stake-reward bound included;
            // a membership check put back here brings that bound back with it.
            return DoS(100, error("ConnectBlock() : NullStake stake note membership is unverifiable; the coinstake encoding is permanently invalid"));

            uint64_t nCoinAge = nWeight > 0 ? (uint64_t)nWeight : 1;
            int64_t nCalculatedStakeReward = GetCoinStakeSubsidySplit(nCoinAge, nFees, *this, pindex).PaidToBlock();
            if (nStakeReward > nCalculatedStakeReward)
                return DoS(100, error("ConnectBlock() : NullStake coinstake pays too much(actual=%" PRId64" vs calculated=%" PRId64")", nStakeReward, nCalculatedStakeReward));
        }
        else
        {
            uint64_t nCoinAge;
            if (!vtx[1].GetCoinAge(txdb, nCoinAge))
                return TransientFailure(error("ConnectBlock() : %s unable to get coin age for coinstake",
                                              vtx[1].GetHash().ToString().substr(0,10).c_str()));

            int64_t nCalculatedStakeReward = GetCoinStakeSubsidySplit(nCoinAge, nFees, *this, pindex).PaidToBlock();

            if (nStakeReward > nCalculatedStakeReward)
                return DoS(100, error("ConnectBlock() : coinstake pays too much(actual=%" PRId64" vs calculated=%" PRId64")", nStakeReward, nCalculatedStakeReward));
        }

        // Reject shielded coinstake unless NullStake version is allowed
        if (pindex->nHeight >= FORK_HEIGHT_SHIELDED)
        {
            if (vtx[1].IsShielded())
            {
                // Post-IDAG NullStake votes for finality and does not produce blocks. Already refused
                // by CheckTransaction, AcceptBlock and ConnectInputs; this restates it.
                if (!IsNullStakeBlockProductionReachableAtHeight(pindex->nHeight))
                    return DoS(100, error("ConnectBlock() : NullStake block production is unreachable at height %d (private stake is finality-voting only)", pindex->nHeight));

                // After the V2 fork, reject V1 proofs (they leak UTXO identity)
                bool fNullStakeAllowed = (vtx[1].nVersion == SHIELDED_TX_VERSION_NULLSTAKE && pindex->nHeight >= FORK_HEIGHT_NULLSTAKE && pindex->nHeight < FORK_HEIGHT_NULLSTAKE_V2)
                    || (vtx[1].nVersion == SHIELDED_TX_VERSION_NULLSTAKE_V2 && pindex->nHeight >= FORK_HEIGHT_NULLSTAKE_V2)
                    || (vtx[1].nVersion == SHIELDED_TX_VERSION_NULLSTAKE_COLD && pindex->nHeight >= FORK_HEIGHT_NULLSTAKE_V3);
                if (!fNullStakeAllowed)
                    return DoS(100, error("ConnectBlock() : shielded transaction cannot be coinstake (Layer 2)"));
            }

            // The vNext envelope carries NullStake only as finality votes; a coinstake-shaped v2008
            // is refused by height so no builder can restore block production through it.
            if (vtx[1].IsPrivacyVNext() &&
                !IsPrivacyVNextCoinStakeReachableAtHeight(pindex->nHeight))
                return DoS(100, error("ConnectBlock() : privacy-vNext transaction cannot be coinstake at height %d (private stake is finality-voting only)", pindex->nHeight));

            // Reject coinstake inputs from shielded transactions
            if (vtx[1].nVersion != SHIELDED_TX_VERSION_NULLSTAKE && vtx[1].nVersion != SHIELDED_TX_VERSION_NULLSTAKE_V2 && vtx[1].nVersion != SHIELDED_TX_VERSION_NULLSTAKE_COLD)
            {
                MapPrevTx mapShieldedCheck;
                bool fShieldedInvalid = false;
                if (vtx[1].FetchInputs(txdb, mapQueuedChanges, true, false, mapShieldedCheck, fShieldedInvalid))
                {
                    for (unsigned int j = 0; j < vtx[1].vin.size(); j++)
                    {
                        const COutPoint& prevout = vtx[1].vin[j].prevout;
                        if (mapShieldedCheck.count(prevout.hash))
                        {
                            const CTransaction& txPrev = mapShieldedCheck[prevout.hash].second;
                            if (txPrev.IsShielded())
                                return DoS(100, error("ConnectBlock() : coinstake input from shielded transaction (Layer 3)"));
                        }
                    }
                }
            }
        }

        if (pindex->nHeight >= FORK_HEIGHT_COLD_STAKING)
        {
            CTransaction& coinstake = vtx[1];

            bool fHasColdStakeInput = false;
            CScript coldStakeScript;
            int64_t nP2CSInputValue = 0;

            MapPrevTx mapColdInputs;
            bool fInvalid = false;
            if (coinstake.FetchInputs(txdb, mapQueuedChanges, true, false, mapColdInputs, fInvalid))
            {
                for (unsigned int j = 0; j < coinstake.vin.size(); j++)
                {
                    const COutPoint& prevout = coinstake.vin[j].prevout;
                    if (mapColdInputs.count(prevout.hash))
                    {
                        const CTransaction& txPrev = mapColdInputs[prevout.hash].second;
                        if (prevout.n < txPrev.vout.size())
                        {
                            const CScript& prevScript = txPrev.vout[prevout.n].scriptPubKey;
                            if (IsPayToColdStaking(prevScript))
                            {
                                if (!fHasColdStakeInput)
                                {
                                    fHasColdStakeInput = true;
                                    coldStakeScript = prevScript;
                                }
                                else if (prevScript != coldStakeScript)
                                {
                                    return DoS(100, error("ConnectBlock() : cold stake inputs use different P2CS scripts"));
                                }
                                if (txPrev.vout[prevout.n].nValue < 0 || nP2CSInputValue + txPrev.vout[prevout.n].nValue < nP2CSInputValue)
                                    return DoS(100, error("ConnectBlock() : cold stake input value overflow"));
                                nP2CSInputValue += txPrev.vout[prevout.n].nValue;
                            }
                        }
                    }
                }
            }

            if (fHasColdStakeInput)
            {
                int64_t nP2CSOutputValue = 0;

                for (unsigned int i = 1; i < coinstake.vout.size(); i++)
                {
                    if (coinstake.vout[i].IsEmpty())
                        continue;

                    if (coinstake.vout[i].scriptPubKey == coldStakeScript)
                    {
                        if (coinstake.vout[i].nValue < 0 || nP2CSOutputValue + coinstake.vout[i].nValue < nP2CSOutputValue)
                            return DoS(100, error("ConnectBlock() : cold stake output value overflow"));
                        nP2CSOutputValue += coinstake.vout[i].nValue;
                        continue;
                    }

                    if (i == coinstake.vout.size() - 1 && !IsPayToColdStaking(coinstake.vout[i].scriptPubKey))
                    {
                        int64_t nCNPayment = coinstake.vout[i].nValue;
                        if (nCNPayment < 0 || !MoneyRange(nCNPayment))
                            return DoS(100, error("ConnectBlock() : cold stake CN payment out of range"));
                        if (nP2CSOutputValue > MAX_MONEY - nCNPayment)
                            return DoS(100, error("ConnectBlock() : cold stake total output overflow"));
                        int64_t nTotalOutput = nP2CSOutputValue + nCNPayment;
                        if (nTotalOutput < nP2CSInputValue)
                            return DoS(100, error("ConnectBlock() : cold stake output less than input"));
                        int64_t nReward = nTotalOutput - nP2CSInputValue;
                        if (!MoneyRange(nReward))
                            return DoS(100, error("ConnectBlock() : cold stake reward out of range"));

                        if (nReward > 0 && nCNPayment > 0 && (nCNPayment / 3 > nReward / 10 + 1))
                            return DoS(100, error("ConnectBlock() : cold stake CN payment %" PRId64 " exceeds 30%% of reward %" PRId64,
                                                  nCNPayment, nReward));

                        // The payee comes from gossiped state, so it has the same node-local gate as the
                        // payment rule and its refusal is never written into the block index.
                        if (ColdStakeCNPayeeRuleApplies(fJustCheck, pindex->nHeight, nCNPayment,
                                                        pindex->GetBlockTime(), GetTime()) &&
                            !ColdStakeCNPayeeIsRegistered(pindex->nHeight,
                                                          coinstake.vout[i].scriptPubKey))
                        {
                            return TransientFailure(error("ConnectBlock() : cold stake CN payment to invalid payee (not a registered collateralnode)"));
                        }
                        continue;
                    }

                    return DoS(100, error("ConnectBlock() : cold stake output %u does not match P2CS input script", i));
                }

                if (nP2CSOutputValue < nP2CSInputValue)
                    return DoS(100, error("ConnectBlock() : cold stake P2CS output value (%" PRId64 ") less than input value (%" PRId64 ")",
                                          nP2CSOutputValue, nP2CSInputValue));
            }
        }
        else
        {
            const CTransaction& coinstake = vtx[1];
            for (unsigned int i = 0; i < coinstake.vout.size(); i++)
            {
                if (IsPayToColdStaking(coinstake.vout[i].scriptPubKey))
                    return DoS(100, error("ConnectBlock() : cold staking output not allowed before fork height %d", FORK_HEIGHT_COLD_STAKING));
            }
        }
    }

    const bool CollateralnodePayments =
        CollateralnodePaymentsEnabledAtHeight(pindex->nHeight);
    bool fIsInitialDownload = IsInitialBlockDownload();

    if(fDebug) { printf("CheckBlock() : Collateralnode payments %s\n",
                        CollateralnodePayments ? "enabled" : "disabled"); }

    if (CollateralnodePaymentRuleApplies(fJustCheck, pindex->GetBlockTime(), GetTime(),
                                         CollateralnodePayments))
    {
        LOCK2(cs_main, mempool.cs);

        CScript burnPayee;
        CBitcoinAddress burnDestination;
        burnDestination.SetString(fTestNet ? "8TestXXXXXXXXXXXXXXXXXXXXXXXXbCvpq" : "INNXXXXXXXXXXXXXXXXXXXXXXXXXZeeDTw");
        burnPayee = GetScriptForDestination(burnDestination.Get());

        const int nCNEnforcementHeight = CollateralnodeEnforcementHeight();

        if(IsProofOfStake() && pindexBest != NULL){
            // (reward goes entirely to shielded pool, no MN payment)
            if (vtx[1].nVersion == SHIELDED_TX_VERSION_NULLSTAKE || vtx[1].nVersion == SHIELDED_TX_VERSION_NULLSTAKE_V2 || vtx[1].nVersion == SHIELDED_TX_VERSION_NULLSTAKE_COLD)
            {
                // NullStake/V3: no collateralnode payments
            }
            else if(pindexBest->GetBlockHash() == hashPrevBlock){

                // make sure the ranks are updated to prev block
                GetCollateralnodeRanks(pindexBest);
                // Calculate Coin Age for Collateralnode Reward Calculation
                uint64_t nCoinAge;
                if (!vtx[1].GetCoinAge(txdb, nCoinAge))
                    return TransientFailure(error("CheckBlock-POS : %s unable to get coin age for coinstake, Can't Calculate Collateralnode Reward\n",
                                                  vtx[1].GetHash().ToString().substr(0,10).c_str()));
                const CBlockSubsidySplit stakeSplit = GetCoinStakeSubsidySplit(nCoinAge, nFees, *this, pindex);
                int64_t nCalculatedStakeReward = stakeSplit.PaidToBlock();

                // Expected collateralnode payment: the split's own leg, never a share
                // this site sized against a base it picked itself.
                int64_t collateralnodePaymentAmount = stakeSplit.Collateralnode();

                // If we don't already have its previous block, skip collateralnode payment step
                if (pindex != NULL)
                {
                    bool foundPaymentAmount = false;
                    bool foundPayee = false;
                    bool paymentOK = false;

                    CScript payee;
                    if(fDebug) { printf("CheckBlock-POS() : Using collateralnode payments for block %d\n", pindex->nHeight); }

                    // Check transaction for payee and if contains collateralnode reward payment
                    if(fDebug) { printf("CheckBlock-POS(): Transaction 1 Size : %zu\n", vtx[1].vout.size()); }
                    if(fDebug) { printf("CheckBlock-POS() : Expected Collateralnode reward of: %" PRId64 "\n", collateralnodePaymentAmount); }
                    for (unsigned int i = 0; i < vtx[1].vout.size(); i++) {
                        if(fDebug) { printf("CheckBlock-POS() : Payment vout number: %u , Amount: %" PRId64 "\n", i, vtx[1].vout[i].nValue); }
                        if(vtx[1].vout[i].nValue == collateralnodePaymentAmount )
                        {
                            foundPaymentAmount = true;
                            payee = vtx[1].vout[i].scriptPubKey;
                            CScript pubScript;

                            if (pubScript == payee) {
                                printf("CheckBlock-POS() : Found collateralnode payment: %s INN to anonymous payee.\n", FormatMoney(vtx[1].vout[i].nValue).c_str());
                                foundPayee = true;
                            } else if (payee == burnPayee) {
                                printf("CheckBlock-POS() : Found collateralnode payment: %s INN to burn address.\n", FormatMoney(vtx[1].vout[i].nValue).c_str());
                                foundPayee = true;
                            } else {
                                CTxDestination mnDest;
                                ExtractDestination(vtx[1].vout[i].scriptPubKey, mnDest);
                                CBitcoinAddress mnAddress(mnDest);
                                if (fDebug) printf("CheckBlock-POS() : Found collateralnode payment: %s INN to %s.\n",FormatMoney(vtx[1].vout[i].nValue).c_str(), mnAddress.ToString().c_str());
                                for (CCollateralNode& mn : vecCollateralnodes)
                                {
                                    pubScript = GetScriptForDestination(mn.pubkey.GetID());
                                    CTxDestination address1;
                                    ExtractDestination(pubScript, address1);
                                    CBitcoinAddress address2(address1);

                                    if (vtx[1].vout[i].scriptPubKey == pubScript)
                                    {
                                        int64_t value = vtx[1].vout[i].nValue;
                                        if (fDebug) printf("CheckBlock-POS() : Collateralnode PoS payee found at block %d: %s who got paid %s INN rate:%" PRId64" rank:%d lastpaid:%d\n", pindex->nHeight, address2.ToString().c_str(), FormatMoney(value).c_str(), mn.payRate, mn.nRank, mn.nBlockLastPaid);

                                        if (!fIsInitialDownload) {
                                            if (!CheckPoSCNPayment(pindex, vtx[1].vout[i].nValue, mn)) // CheckPoSCNPayment()
                                            {
                                                if (pindex->nHeight >= nCNEnforcementHeight) {
                                                    printf("CheckBlock-POS() : Out-of-cycle CollateralNode payment detected, rejecting block. rank:%d value:%s avg:%s payRate:%s payCount:%d\n",mn.nRank,FormatMoney(mn.payValue).c_str(),FormatMoney(nAverageCNIncome).c_str(),FormatMoney(mn.payRate).c_str(), mn.payCount);
                                                } else {
                                                    printf("CheckBlock-POS(): This collateralnode payment is too aggressive and will be accepted after block %d\n", nCNEnforcementHeight);
                                                }
                                                //break;
                                            } else {
                                                if (fDebug) printf("CheckBlock-POS() : Payment meets rate requirement: payee has earnt %s against average %s\n",FormatMoney(mn.payValue).c_str(),FormatMoney(nAverageCNIncome).c_str());
                                            }
                                        } else {
                                            if (fDebug) printf("CheckBlock-POS() : Wallet currently in startup mode, ignoring rate requirements.");
                                        }
                                        // add mn payment data
                                        mn.nBlockLastPaid = pindex->nHeight;
                                        CCollateralNPayData data;
                                        data.height = pindex->nHeight;
                                        data.amount = value;
                                        data.hash = pindex->GetBlockHash();
                                        mn.payData.push_back(data);
                                        mn.SetPayRate(pindex->nHeight);
                                        foundPayee = true;
                                        paymentOK = true;
                                        break;
                                    }
                                }
                                // if payee not found in mn list, check if the pubkey holds a 5K transaction
                                if (!foundPayee) {
                                    if (FindCNPayment(payee, pindex)) {
                                        if (fDebug) printf("CheckBlock-POS() : WARNING: Payee was not found in MN list, but confirmed to hold collateral.\n");
                                        foundPayee = true;
                                    }
                                }
                            }
                        }
                    }



                    if (!foundPayee) {
                        if (pindex->nHeight >= nCNEnforcementHeight) {
                                    LOCK(cs_vNodes);
                                    for (CNode* pnode : vNodes)
                                    {
                                        if (pnode->nVersion >= colLateralPool.PROTOCOL_VERSION) {
                                                printf("Asking for Collateralnode list from %s\n",pnode->addr.ToStringIPPort().c_str());
                                                pnode->PushMessage("iseg", CTxIn()); //request full mn list
                                                pnode->nLastDseg = GetTime();
                                        }
                                    }
                            return TransientFailure(error("CheckBlock-POS() : collateralnode payee is not present in the local list yet"));
                        } else {
                            if (fDebug) printf("WARNING: Did not find this payee in the collateralnode list, this block will not be accepted after block %d\n", nCNEnforcementHeight);
                            foundPayee = true;
                        }
                    } else if (paymentOK) {
                        if (pindex->nHeight >= nCNEnforcementHeight) {
                            if (fDebug) printf("CheckBlock-POS() : This payment has been determined as legitimate, and will be allowed.\n");
                        } else {
                            if (fDebug) printf("CheckBlock-POS() : This payment has been determined as legitimate, and will be allowed after block %d.\n", nCNEnforcementHeight);
                        }
                    }

                    if(!(foundPaymentAmount && foundPayee)) {
                        CTxDestination address1;
                        ExtractDestination(payee, address1);
                        CBitcoinAddress address2(address1);
                        if(fDebug) { printf("CheckBlock-POS() : Couldn't find collateralnode payment(%d|%" PRId64 ") or payee(%d|%s) nHeight %d. \n", foundPaymentAmount, collateralnodePaymentAmount, foundPayee, address2.ToString().c_str(), pindex->nHeight+1); }
                        // Node-local verdict: refuse this attempt without writing it down.
                        return TransientFailure(error("CheckBlock-POS() : Couldn't find collateralnode payment or payee"));
                    } else {
                        if(fDebug) { printf("CheckBlock-POS() : Found collateralnode payment %d\n", pindex->nHeight+1); }
                    }
                } else {
                    if(fDebug) { printf("CheckBlock-POS() : Is initial download, skipping collateralnode payment check %d\n", pindexBest->nHeight+1); }
                }
            } else {
                if(fDebug) { printf("CheckBlock-POS() : Skipping collateralnode payment check - nHeight %d Hash %s\n", pindex->nHeight, GetHash().ToString().c_str()); }
            }
        }else if(IsProofOfWork() && pindexBest != NULL){
            if(pindexBest->GetBlockHash() == hashPrevBlock){

                // make sure the ranks are updated
                GetCollateralnodeRanks(pindexBest);

                // Subsidy only: the finality settlement in the coinbase is owed to voters. Uses the
                // same nFinalityRewardOut as the coinbase cap so miner and validator agree.
                int64_t nCNPaymentBase =
                    FinalityCollateralnodePaymentBase(vtx[0].GetValueOut(), nFinalityRewardOut);
                int64_t collateralnodePaymentAmount =
                    CBlockSubsidySplit::CollateralnodeShareOfBase(nCNPaymentBase);

                // If we don't already have its previous block, skip collateralnode payment step
                if (pindex != NULL)
                {
                    bool foundPaymentAmount = false;
                    bool foundPayee = false;
                    bool paymentOK = true;
                    CScript payee;

                    if(fDebug) { printf("CheckBlock-POW() : Using non-specific collateralnode payments %d\n", pindex->nHeight); }

                    // Check transaction for payee and if contains collateralnode reward payment
                    if (fDebug) { printf("CheckBlock-POW(): Transaction 0 Size : %zu\n", vtx[0].vout.size()); }
                    if (fDebug) { printf("CheckBlock-POW() : Expected Collateralnode reward of: %" PRId64 "\n", collateralnodePaymentAmount); }
                    for (unsigned int i = 0; i < vtx[0].vout.size(); i++) {
                        if(fDebug) { printf("CheckBlock-POW() : Payment vout number: %u , Amount: %lld\n",
                                             i, (long long)vtx[0].vout[i].nValue); }
                        if(vtx[0].vout[i].nValue == collateralnodePaymentAmount )
                        {
                            CTxDestination mnDest;
                            payee = vtx[0].vout[i].scriptPubKey;
                            ExtractDestination(payee, mnDest);
                            CBitcoinAddress mnAddress(mnDest);
                            if (fDebug) printf("CheckBlock-POW() : Found collateralnode payment: %s INN to %s.\n",FormatMoney(vtx[0].vout[i].nValue).c_str(), mnAddress.ToString().c_str());

                            foundPaymentAmount = true;

                            CScript pubScript;

                            // Checked before the list walk: an empty local list
                            // must not push a burn payment onto the chain scan.
                            if (payee == burnPayee) {
                                printf("CheckBlock-POW() : Found collateralnode payment: %s INN to burn address.\n", FormatMoney(vtx[0].vout[i].nValue).c_str());
                                foundPayee = true;
                                continue;
                            }

                            for (CCollateralNode& mn : vecCollateralnodes)
                            {
                                pubScript = GetScriptForDestination(mn.pubkey.GetID());
                                CTxDestination address1;
                                ExtractDestination(pubScript, address1);
                                CBitcoinAddress address2(address1);

                                if (payee == pubScript)
                                {
                                    if (fDebug) printf("CheckBlock-POW() : Collateralnode PoW payee found at block %d: %s who got paid %s INN rate:%s rank:%d lastpaid:%d\n", pindex->nHeight, address2.ToString().c_str(), FormatMoney(vtx[0].vout[i].nValue).c_str(), FormatMoney(mn.payRate).c_str(), mn.nRank, mn.nBlockLastPaid);
                                    if (!fIsInitialDownload) {
                                        if (!CheckCNPayment(pindex, vtx[0].vout[i].nValue, mn)) // if MN is being paid and it's bottom 50% ranked, don't let it be paid.
                                        {
                                            if (pindex->nHeight >= nCNEnforcementHeight)
                                            {
                                                printf("CheckBlock-POW() : Collateralnode overpayment detected, rejecting block. rank:%d value:%s avg:%s payRate:%s payCount:%d\n",mn.nRank,FormatMoney(mn.payValue).c_str(),FormatMoney(nAverageCNIncome).c_str(),FormatMoney(mn.payRate).c_str(), mn.payCount);
                                            } else {
                                                printf("WARNING: This collateralnode payment is too aggressive and will not be accepted after block %d\n", nCNEnforcementHeight);
                                            }
                                            //break;
                                        } else {
                                            if (fDebug) printf("CheckBlock-POW() : Payment meets rate requirement: payee has earnt %s against average %s\n",FormatMoney(mn.payValue).c_str(),FormatMoney(nAverageCNIncome).c_str());
                                        }
                                    } else {
                                        if (fDebug) printf("CheckBlock-POW() : Wallet currently in startup mode, ignoring rate requirements.");
                                    }

                                    mn.nBlockLastPaid = pindex->nHeight;
                                    CCollateralNPayData data;
                                    data.height = pindex->nHeight;
                                    data.amount = vtx[0].vout[i].nValue;
                                    data.hash = pindex->GetBlockHash();
                                    mn.payData.push_back(data);
                                    mn.SetPayRate(pindex->nHeight);
                                    foundPayee = true;
                                    paymentOK = true;
                                    break;
                                }
                            }

                            // if payee not found in mn list, check if the pubkey holds a 5K transaction
                            if (!foundPayee) {
                                if (FindCNPayment(payee, pindex)) {
                                    if (fDebug) printf("CheckBlock-POW() : WARNING: Payee was not found in MN list, but confirmed to hold collateral.\n");
                                    foundPayee = true;
                                }
                            }
                        }
                    }

                    if (!foundPayee) {
                        if (pindex->nHeight >= nCNEnforcementHeight) {
                                LOCK(cs_vNodes);
                                for (CNode* pnode : vNodes)
                                {
                                    if (pnode->nVersion >= colLateralPool.PROTOCOL_VERSION) {
                                            printf("Asking for Collateralnode list from %s\n",pnode->addr.ToStringIPPort().c_str());
                                            pnode->PushMessage("iseg", CTxIn()); //request full mn list
                                            pnode->nLastDseg = GetTime();
                                    }
                                }
                                return TransientFailure(error("CheckBlock-POW() : collateralnode payee is not present in the local list yet"));
                        } else {
                            if (fDebug) printf("WARNING: Did not find this payee in  the collateralnode list, this block will not be accepted after block %d\n", nCNEnforcementHeight);
                            foundPayee = true;
                        }
                    } else if (paymentOK) {
                        if (pindex->nHeight >= nCNEnforcementHeight) {
                            if (fDebug) printf("CheckBlock-POW() : This payment has been determined as legitimate, and will be allowed.\n");
                        } else {
                            if (fDebug) printf("CheckBlock-POW() : This payment has been determined as legitimate, and will be allowed after block %d.\n", nCNEnforcementHeight);
                        }
                    }

                    if(fDebug) {printf("CheckBlock-POW(): foundPaymentAmount= %i ; foundPayee = %i\n", foundPaymentAmount, foundPayee); }
                    if(!(foundPaymentAmount && foundPayee)) {
                        CScript payee;
                        CTxDestination address1;
                        ExtractDestination(payee, address1);
                        CBitcoinAddress address2(address1);
                        if(fDebug) { printf("CheckBlock-POW() : Couldn't find collateralnode payment(%d|%" PRId64 ") or payee(%d|%s) nHeight %d. \n", foundPaymentAmount, collateralnodePaymentAmount, foundPayee, address2.ToString().c_str(), pindex->nHeight+1); }
                        // Node-local verdict: refuse this attempt without writing it down.
                        return TransientFailure(error("CheckBlock-POW() : Couldn't find collateralnode payment or payee"));
                    } else {
                        if(fDebug) { printf("CheckBlock-POW() : Found collateralnode payment %d\n", pindex->nHeight+1); }
                    }
                } else {
                    if(fDebug) { printf("CheckBlock-POW() : Is initial download, skipping collateralnode payment check %d\n", pindex->nHeight+1); }
                }
            } else {
                if(fDebug) { printf("CheckBlock-POW() : Skipping collateralnode payment check - nHeight %d Hash %s\n", pindex->nHeight+1, GetHash().ToString().c_str()); }
            }
        }

         else {
            if(fDebug) { printf("CheckBlock() : pindex is null, skipping collateralnode payment check\n"); }
        }
    } else {
        if(fDebug) {
                printf("CheckBlock() : skipping collateralnode payment checks\n");
        }
    }

    if (IsBoundaryBActiveAtHeight(pindex->nHeight))
    {
        // Verify the block's payloads concurrently before validating them in order. Each
        // costs tens of milliseconds cold, so a block of them cannot be connected serially
        // inside a block interval during a sync, where nothing has been seen before. This
        // only fills the effects cache; every consensus decision still happens below, in
        // order, and an invalid payload is simply left uncached for that loop to reject.
        {
            std::vector<std::pair<uint32_t, const std::vector<unsigned char>*> > vWarm;
            vWarm.reserve(activeBlock.vtx.size());
            for (const CTransaction& tx : activeBlock.vtx)
            {
                if (tx.IsPrivacyVNext() && tx.privacyVNext.IsPresent())
                    vWarm.push_back(std::make_pair(
                        static_cast<uint32_t>(tx.nVersion),
                        &tx.privacyVNext.vchPayload));
            }
            WarmPrivacyVNextEffectsCache(
                vWarm, (int)GetArg("-parverify", 0));
        }

        // Enforce the pool balance where released value is credited, so the offending block is
        // rejected rather than the later epoch build failing.
        int64_t nPrivacyVNextPool = 0;
        {
            const TxDBReadStatus poolStatus =
                txdb.ReadPrivacyVNextPoolValueStatus(nPrivacyVNextPool);
            if (poolStatus == TXDB_READ_ERROR ||
                (poolStatus == TXDB_READ_NOT_FOUND &&
                 pindex->nHeight != FORK_HEIGHT_BOUNDARY_B))
                return TransientFailure(error(
                    "ConnectBlock() : IV5 pool balance record is %s; "
                    "-reindex/resync required",
                    poolStatus == TXDB_READ_ERROR ? "corrupt" : "missing"));
            if (poolStatus == TXDB_READ_NOT_FOUND)
                nPrivacyVNextPool = 0;
        }

        std::set<uint256> setBlockPrivacyVNextNullifiers;
        std::set<uint256> setBlockPrivacyVNextOutputBases;
        std::set<uint256> setBlockPrivacyVNextAttestations;
        for (const CTransaction& tx : activeBlock.vtx)
        {
            if (!tx.IsPrivacyVNext())
                continue;

            PrivacyVNextStateEffects effects;
            const PrivacyVNextPayloadValidation validation =
                ExtractPrivacyVNextPayloadEffects(
                    static_cast<uint32_t>(tx.nVersion),
                    tx.privacyVNext.vchPayload, effects);
            if (validation.fLocalFailure)
            {
                StartShutdown();
                return TransientFailure(error(
                    "ConnectBlock() : local IV5 payload-effects failure: %s",
                    validation.strError.c_str()));
            }
            if (!validation.IsValid())
                return DoS(100, error("ConnectBlock() : invalid IV5 payload effects: %s",
                                      validation.strError.c_str()));

            // Ahead of anything that consumes the payload's value: a rewritten
            // transparent side makes every number below describe a different
            // transaction from the one the proofs cover.
            std::string strBindingError;
            if (!CheckPrivacyVNextTransparentBinding(tx, effects, strBindingError))
                return DoS(100, error("ConnectBlock() : %s for %s",
                                      strBindingError.c_str(),
                                      tx.GetHash().ToString().substr(0,10).c_str()));

            std::string strRetiredError;
            if (!CheckPrivacyVNextUnshieldRetired(
                    effects.nTransparentValueBalance, pindex->nHeight,
                    strRetiredError))
                return DoS(100, error("ConnectBlock() : %s for %s",
                                      strRetiredError.c_str(),
                                      tx.GetHash().ToString().substr(0,10).c_str()));

            bool fContextLocalFailure = false;
            std::string strContextError;
            if (!ValidatePrivacyVNextFinalizedContext(
                    txdb, pindex->nHeight, effects,
                    fContextLocalFailure, strContextError))
            {
                if (fContextLocalFailure)
                {
                    StartShutdown();
                    return TransientFailure(error(
                        "ConnectBlock() : local IV5 finalized-context failure: %s",
                        strContextError.c_str()));
                }
                return DoS(100, error(
                    "ConnectBlock() : IV5 finalized context rejected: %s",
                    strContextError.c_str()));
            }

            int64_t nPoolDelta = 0;
            std::string strPoolError;
            if (!GetPrivacyVNextPoolDelta(effects, nPoolDelta, strPoolError) ||
                !ApplyPrivacyVNextPoolDelta(nPrivacyVNextPool, nPoolDelta,
                                            strPoolError))
                return DoS(100, error("ConnectBlock() : IV5 transaction %s %s",
                                      tx.GetHash().ToString().substr(0,10).c_str(),
                                      strPoolError.c_str()));

            for (size_t i = 0; i < effects.keyImages.size(); ++i)
            {
                uint256 keyImage;
                memcpy(keyImage.begin(), effects.keyImages[i].data(),
                       effects.keyImages[i].size());
                if (!setBlockPrivacyVNextNullifiers.insert(keyImage).second)
                    return DoS(100, error(
                        "ConnectBlock() : duplicate IV5 spent key %s in active DAG block",
                        keyImage.ToString().substr(0,10).c_str()));

                CPrivacyVNextNullifierSpent prior;
                const TxDBReadStatus status =
                    txdb.ReadPrivacyVNextNullifierStatus(keyImage, prior);
                if (status == TXDB_READ_ERROR)
                {
                    StartShutdown();
                    return TransientFailure(error(
                        "ConnectBlock() : corrupt IV5 spent-key index for %s; "
                        "-reindex/resync required",
                        keyImage.ToString().substr(0,10).c_str()));
                }
                if (status == TXDB_READ_FOUND)
                    return DoS(100, error(
                        "ConnectBlock() : IV5 spent key %s was already consumed by %s",
                        keyImage.ToString().substr(0,10).c_str(),
                        prior.txnHash.ToString().substr(0,10).c_str()));

                if (!fJustCheck)
                {
                    // The height this key was consumed at, so a reader anchored to a
                    // settled height can ask whether the spend is inside its anchor
                    // instead of whether this node happens to hold the record.
                    CPrivacyVNextNullifierSpent spent;
                    spent.txnHash = tx.GetHash();
                    spent.nIndex = i;
                    spent.nHeight = pindex->nHeight;
                    if (!txdb.WritePrivacyVNextNullifier(keyImage, spent))
                        return TransientFailure(error(
                            "ConnectBlock() : IV5 spent-key write failed"));
                }
            }

            // A collateral attestation names a note without consuming it, so its
            // key image goes to the watch set and never to the spent-key index
            // above; a note recorded there can never move again.
            {
                bool fAttestLocalFailure = false;
                std::string strAttestError;
                if (!ConnectPrivacyVNextAttestations(
                        txdb, tx, effects, pindex->nHeight, fJustCheck,
                        setBlockPrivacyVNextAttestations, fAttestLocalFailure,
                        strAttestError))
                {
                    if (fAttestLocalFailure)
                    {
                        StartShutdown();
                        return TransientFailure(error(
                            "ConnectBlock() : %s", strAttestError.c_str()));
                    }
                    return DoS(100, error("ConnectBlock() : %s",
                                          strAttestError.c_str()));
                }
            }

            // Owner uniqueness is enforced where value enters the pool, because that
            // is the only point at which it can still be refused. I = Hp(O), so a
            // second leaf carrying an owner already on chain shares the first leaf's
            // key image: whichever is spent first consumes both, and unshield is
            // retired, so the other one's value is destroyed with no way back.
            for (size_t i = 0; i < effects.outputLeaves.size(); ++i)
            {
                uint256 base;
                memcpy(base.begin(), effects.outputLeaves[i].nullifierBase.data(),
                       effects.outputLeaves[i].nullifierBase.size());
                if (!setBlockPrivacyVNextOutputBases.insert(base).second)
                    return DoS(100, error(
                        "ConnectBlock() : duplicate IV5 output owner %s in active DAG block",
                        base.ToString().substr(0,10).c_str()));

                CShieldedNullifierSpent prior;
                const TxDBReadStatus status =
                    txdb.ReadPrivacyVNextOutputBaseStatus(base, prior);
                if (status == TXDB_READ_ERROR)
                {
                    StartShutdown();
                    return TransientFailure(error(
                        "ConnectBlock() : corrupt IV5 output-base index for %s; "
                        "-reindex/resync required",
                        base.ToString().substr(0,10).c_str()));
                }
                if (status == TXDB_READ_FOUND)
                    return DoS(100, error(
                        "ConnectBlock() : IV5 output owner %s was already issued by %s",
                        base.ToString().substr(0,10).c_str(),
                        prior.txnHash.ToString().substr(0,10).c_str()));

                if (!fJustCheck)
                {
                    CShieldedNullifierSpent created;
                    created.txnHash = tx.GetHash();
                    created.nIndex = i;
                    if (!txdb.WritePrivacyVNextOutputBase(base, created))
                        return TransientFailure(error(
                            "ConnectBlock() : IV5 output-base write failed"));
                }
            }
        }

        // Written on every Boundary-B block, so a later block can tell a pool that
        // is genuinely empty from a record this node never had.
        if (!fJustCheck && !txdb.WritePrivacyVNextPoolValue(nPrivacyVNextPool))
            return TransientFailure(error(
                "ConnectBlock() : IV5 pool balance write failed"));
    }

    if (pindex->nHeight >= FORK_HEIGHT_SHIELDED && !fJustCheck)
    {
        CIncrementalMerkleTree shieldedTree;
        if (pindex->pprev && !txdb.ReadShieldedTree(shieldedTree) &&
            pindex->nHeight != FORK_HEIGHT_SHIELDED)
            return TransientFailure(error("ConnectBlock() : missing predecessor shielded tree; "
                                          "-reindex/resync required"));

        if (pindex->nHeight == FORK_HEIGHT_EPOCH_STATE_V3)
        {
            const uint256 predecessorRoot = shieldedTree.Root();
            int nPredecessorRootHeight = -1;
            if (!pindex->pprev ||
                txdb.ReadShieldedAnchorStatus(predecessorRoot) !=
                    TXDB_READ_FOUND ||
                txdb.ReadShieldedAnchorHeightStatus(
                    predecessorRoot, nPredecessorRootHeight) !=
                    TXDB_READ_FOUND ||
                nPredecessorRootHeight < FORK_HEIGHT_SHIELDED ||
                nPredecessorRootHeight > pindex->pprev->nHeight)
                return TransientFailure(error("ConnectBlock() : V3 activation predecessor shielded anchor pair missing/corrupt; -reindex/resync required"));

            std::string strIndexError;
            if (!txdb.InitializeShieldedCommitmentIndexV3(
                    pindex->GetBlockHash(), strIndexError))
                return TransientFailure(error("ConnectBlock() : V3 shielded reverse-index activation failed: %s",
                                              strIndexError.c_str()));
        }

        bool fV3ShieldedPersistence = false;
        std::string strIndexModeError;
        if (!txdb.ResolveShieldedCommitmentIndexV3Mode(
                pindex->nHeight, FORK_HEIGHT_EPOCH_STATE_V3,
                fV3ShieldedPersistence, strIndexModeError))
            return TransientFailure(error("ConnectBlock() : %s; -reindex/resync required",
                                          strIndexModeError.c_str()));

        if (!txdb.WriteShieldedTreeAtBlock(pindex->GetBlockHash(), shieldedTree))
            return TransientFailure(error("ConnectBlock() : WriteShieldedTreeAtBlock failed"));

        CCurveTree curveTree;
        bool fMutableCurveTree = (pindex->nHeight >= FORK_HEIGHT_FCMP &&
                                  pindex->nHeight < FORK_HEIGHT_EPOCH_ROOT_FCMP);
        if (fMutableCurveTree && pindex->pprev &&
            !txdb.ReadCurveTree(curveTree) && pindex->nHeight != FORK_HEIGHT_FCMP)
            return TransientFailure(error("ConnectBlock() : missing predecessor curve tree; "
                                          "-reindex/resync required"));

        if (fMutableCurveTree &&
            !txdb.WriteCurveTreeAtBlock(pindex->GetBlockHash(), curveTree))
            return TransientFailure(error("ConnectBlock() : WriteCurveTreeAtBlock failed"));

        // Seed genesis commitments at the fork activation block
        // These provide the initial Lelantus anonymity set (16 unspendable decoys)
        if (pindex->nHeight == FORK_HEIGHT_SHIELDED)
        {
            CCurveTree* pCurveTreePtr = fMutableCurveTree ? &curveTree : nullptr;
            if (!SeedGenesisCommitments(txdb, shieldedTree, pCurveTreePtr,
                                        fV3ShieldedPersistence))
                return TransientFailure(error("ConnectBlock() : SeedGenesisCommitments failed"));
        }

        int64_t nShieldedPool = 0;
        if (!txdb.ReadShieldedPoolValue(nShieldedPool) &&
            pindex->nHeight != FORK_HEIGHT_SHIELDED)
            return TransientFailure(error("ConnectBlock() : missing predecessor shielded pool value; "
                                          "-reindex/resync required"));

        // Catch cross-tx nullifier duplicates within this block
        std::set<uint256> setBlockNullifiers;

        for (const CTransaction& tx : activeBlock.vtx)
        {
            if (!tx.IsShielded())
                continue;

            for (unsigned int i = 0; i < tx.vShieldedSpend.size(); i++)
            {
                if (!setBlockNullifiers.insert(tx.vShieldedSpend[i].nullifier).second)
                    return DoS(100, error("ConnectBlock() : duplicate nullifier %s across transactions in block",
                                          tx.vShieldedSpend[i].nullifier.ToString().substr(0,10).c_str()));

                CShieldedNullifierSpent nfs;
                nfs.txnHash = tx.GetHash();
                nfs.nIndex = i;
                if (!txdb.WriteShieldedNullifier(tx.vShieldedSpend[i].nullifier, nfs))
                    return TransientFailure(error("ConnectBlock() : WriteShieldedNullifier failed"));
            }

            // Append note commitments to the Merkle tree and commitment index
            for (const CShieldedOutputDescription& output : tx.vShieldedOutput)
            {
                if (!shieldedTree.Append(output.cmu))
                    return DoS(100, error("ConnectBlock() : shielded Merkle tree capacity exhausted"));

                // Index Pedersen commitment for Lelantus anonymity set construction
                uint64_t nCommitIdx = shieldedTree.Size() - 1;
                if (!txdb.WriteShieldedCommitment(nCommitIdx, output.cv))
                    return TransientFailure(error("ConnectBlock() : WriteShieldedCommitment failed"));

                if (!txdb.WriteShieldedCommitmentHeight(nCommitIdx, pindex->nHeight))
                    return TransientFailure(error("ConnectBlock() : WriteShieldedCommitmentHeight failed"));
                if (fV3ShieldedPersistence)
                {
                    std::string strIndexError;
                    if (!txdb.PushShieldedCommitmentIndexV3(
                            nCommitIdx, output.cv, strIndexError))
                        return TransientFailure(error("ConnectBlock() : V3 shielded reverse-index push failed: %s",
                                                      strIndexError.c_str()));
                }
                else if (!txdb.WriteShieldedCommitmentIndex(
                             output.cv.vchCommitment, nCommitIdx))
                {
                    return TransientFailure(error("ConnectBlock() : WriteShieldedCommitmentIndex failed"));
                }

                if (fMutableCurveTree && !curveTree.InsertLeaf(output.cv))
                    return TransientFailure(error("ConnectBlock() : curve-tree leaf insertion failed after proof validation"));
            }

            if (tx.nValueBalance == std::numeric_limits<int64_t>::min() ||
                (tx.nValueBalance > 0 && nShieldedPool < tx.nValueBalance) ||
                (tx.nValueBalance < 0 &&
                 nShieldedPool > MAX_MONEY + tx.nValueBalance))
                return DoS(100, error("ConnectBlock() : shielded pool balance overflow/"
                                      "underflow, inflation detected"));
            nShieldedPool -= tx.nValueBalance;
            if (!MoneyRange(nShieldedPool))
                return DoS(100, error("ConnectBlock() : shielded pool out of range (%" PRId64
                                      "), inflation detected", nShieldedPool));
        }

        if (!txdb.WriteShieldedTree(shieldedTree))
            return TransientFailure(error("ConnectBlock() : WriteShieldedTree failed"));
        if (!txdb.WriteShieldedCommitmentCount(shieldedTree.Size()))
            return TransientFailure(error("ConnectBlock() : WriteShieldedCommitmentCount failed"));

        if (fMutableCurveTree)
        {
            if (!txdb.WriteCurveTree(curveTree))
                return TransientFailure(error("ConnectBlock() : WriteCurveTree failed"));
        }

        uint256 treeRoot = shieldedTree.Root();
        if (fV3ShieldedPersistence)
        {
            const TxDBReadStatus anchorStatus =
                txdb.ReadShieldedAnchorStatus(treeRoot);
            if (anchorStatus == TXDB_READ_ERROR)
                return TransientFailure(error("ConnectBlock() : shielded anchor record corrupt/unreadable; -reindex/resync required"));
            if (anchorStatus == TXDB_READ_FOUND)
            {
                int nExistingHeight = -1;
                if (txdb.ReadShieldedAnchorHeightStatus(
                        treeRoot, nExistingHeight) != TXDB_READ_FOUND ||
                    nExistingHeight < FORK_HEIGHT_SHIELDED ||
                    nExistingHeight > pindex->nHeight)
                    return TransientFailure(error("ConnectBlock() : existing V3 shielded anchor height missing/corrupt; -reindex/resync required"));
            }
            else
            {
                // Overwrite any height-only residue from a disconnected legacy
                // branch; a newly active anchor starts aging at this block.
                if (!txdb.WriteShieldedAnchor(treeRoot) ||
                    !txdb.WriteShieldedAnchorHeight(treeRoot,
                                                     pindex->nHeight))
                    return TransientFailure(error("ConnectBlock() : WriteShieldedAnchor pair failed"));
            }
        }
        else
        {
            if (!txdb.WriteShieldedAnchor(treeRoot))
                return TransientFailure(error("ConnectBlock() : WriteShieldedAnchor failed"));
            // Only write anchor height for NEW anchors (don't reset age each block)
            int nExistingHeight = 0;
            if (!txdb.ReadShieldedAnchorHeight(treeRoot, nExistingHeight) &&
                !txdb.WriteShieldedAnchorHeight(treeRoot, pindex->nHeight))
                return TransientFailure(error("ConnectBlock() : WriteShieldedAnchorHeight failed"));
        }

        if (!txdb.WriteShieldedPoolValue(nShieldedPool))
            return TransientFailure(error("ConnectBlock() : WriteShieldedPoolValue failed"));


        if (fDebug)
            printf("ConnectBlock() : shielded tree root=%s, pool=%" PRId64 "\n",
                   treeRoot.ToString().substr(0,10).c_str(), nShieldedPool);
    }

    // ppcoin: track money supply and mint amount info
    pindex->nMint = nValueOut - nValueIn + nFees;
    pindex->nMoneySupply = (pindex->pprev? pindex->pprev->nMoneySupply : 0) + nValueOut - nValueIn;
    pindex->nMoneySupply -= nAmountBurned;
    if (pindex->nMoneySupply < 0)
        return DoS(100, error("ConnectBlock() : negative money supply at height %d", pindex->nHeight));

    if (!fJustCheck && !vFinalityVotes.empty())
    {
        FinalityResult finalityResult = FINALITY_RESULT_INVALID;
        if (!g_finalityTracker.ConnectBlockVotes(
                txdb, pindex->GetBlockHash(), vFinalityVotes,
                CFinalityVoteContext::Connect(pindex), &finalityResult))
        {
            if (finalityResult == FINALITY_RESULT_LOCAL_STATE)
                return TransientFailure(error(
                    "ConnectBlock() : ConnectBlockVotes local state/persistence failure"));
            return DoS(100, error(
                "ConnectBlock() : ConnectBlockVotes deterministic validation failure"));
        }
    }
    if (!fJustCheck && !vNoteFinalityVotes.empty())
    {
        FinalityResult finalityResult = FINALITY_RESULT_INVALID;
        if (!g_finalityTracker.ConnectBlockNoteVotes(
                txdb, pindex->GetBlockHash(), vNoteFinalityVotes,
                CFinalityVoteContext::Connect(pindex), &finalityResult))
        {
            if (finalityResult == FINALITY_RESULT_LOCAL_STATE)
                return TransientFailure(error(
                    "ConnectBlock() : ConnectBlockNoteVotes local state/persistence failure"));
            return DoS(100, error(
                "ConnectBlock() : ConnectBlockNoteVotes deterministic validation failure"));
        }
    }
    if (!fJustCheck && !vFinalityShares.empty())
    {
        FinalityResult finalityResult = FINALITY_RESULT_INVALID;
        if (!g_finalityTracker.ConnectBlockTallyShares(
                txdb, pindex->GetBlockHash(), vFinalityShares,
                pindex->nHeight, &finalityResult))
        {
            if (finalityResult == FINALITY_RESULT_LOCAL_STATE)
                return TransientFailure(error(
                    "ConnectBlock() : ConnectBlockTallyShares local state/persistence failure"));
            return DoS(100, error(
                "ConnectBlock() : ConnectBlockTallyShares deterministic validation failure"));
        }
    }
    if (!fJustCheck && !vFinalityCerts.empty())
    {
        FinalityResult finalityResult = FINALITY_RESULT_INVALID;
        if (!g_finalityTracker.ConnectBlockTallyCertificates(
                txdb, pindex->GetBlockHash(), vFinalityCerts,
                pindex->nHeight, &finalityResult))
        {
            if (finalityResult == FINALITY_RESULT_LOCAL_STATE)
                return TransientFailure(error(
                    "ConnectBlock() : ConnectBlockTallyCertificates local state/persistence failure"));
            return DoS(100, error(
                "ConnectBlock() : ConnectBlockTallyCertificates deterministic validation failure"));
        }
    }

    // innova: collect valid name tx
    // NOTE: tx.UpdateCoins should not affect this loop, probably...
    // vector<nameTempProxy> vName;
    // for (unsigned int i=0; i<vtx.size(); i++)
    // {
    //     if (fDebug) printf("ConnectBlock() for Name Index\n");
    //     const CTransaction &tx = vtx[i];
    //     //if (!tx.IsCoinBase()) //|| !tx.IsCoinStake()
    //     //hooks->CheckInputs(tx, pindex, vName, vPos[i].second, vFees[i]); // collect valid name tx to vName
    //     // hooks->CheckInputs(txdb, mapTestPool, tx, vPos[i].second, pindexBlock)
    // }

    if (!txdb.WriteBlockIndex(CDiskBlockIndex(pindex)))
        return TransientFailure(error("Connect() : WriteBlockIndex for pindex failed"));

    if (fJustCheck)
    {
        if (fDebug && GetBoolArg("-showtimers", false))
            printf("ConnectBlock: height=%d justcheck total=%" PRId64"ms check=%" PRId64"ms tx_transparent=%u/%" PRId64"us tx_shielded=%u/%" PRId64"us tx_anon=%u/%" PRId64"us tx_privstake=%u/%" PRId64"us\n",
                   pindex->nHeight, GetTimeMillis() - nConnectBlockStart, nConnectCheckMs,
                   nTransparentValidateCount, nTransparentValidateMicros,
                   nShieldedValidateCount, nShieldedValidateMicros,
                   nAnonValidateCount, nAnonValidateMicros,
                   nPrivateStakeValidateCount, nPrivateStakeValidateMicros);
        return Connected();
    }

    // Write queued txindex changes
    {
        BLOCK_PHASE(BP_TXINDEX_WRITE);
        for (map<uint256, CTxIndex>::iterator mi = mapQueuedChanges.begin(); mi != mapQueuedChanges.end(); ++mi)
        {
            if (!txdb.UpdateTxIndex((*mi).first, (*mi).second))
                return TransientFailure(error("ConnectBlock() : UpdateTxIndex failed"));
        }
    }
    if(GetBoolArg("-addrindex", false))
    {
        // Write Address Index
        for (CTransaction& tx : vtx)
        {
            uint256 hashTx = tx.GetHash();
            if (setDAGSkippedTxs.count(hashTx))
                continue;
        // inputs
        if(!tx.IsCoinBase())
        {
                MapPrevTx mapInputs;
            map<uint256, CTxIndex> mapQueuedChangesT;
            bool fInvalid;
                if (!tx.FetchInputs(txdb, mapQueuedChangesT, true, false, mapInputs, fInvalid))
                    return TransientFailure(error("ConnectBlock() : address-index input read failed"));

            MapPrevTx::const_iterator mi;
            for(MapPrevTx::const_iterator mi = mapInputs.begin(); mi != mapInputs.end(); ++mi)
            {
                for (const CTxOut &atxout : (*mi).second.second.vout)
                {
                std::vector<uint160> addrIds;
                if(BuildAddrIndex(atxout.scriptPubKey, addrIds))
                {
                        for (uint160 addrId : addrIds)
                        {
                        if(!txdb.WriteAddrIndex(addrId, hashTx))
                            return TransientFailure(error("ConnectBlock(): txins WriteAddrIndex failed addrId: %s txhash: %s",
                                                          addrId.ToString().c_str(), hashTx.ToString().c_str()));
                        }
                }
                }
            }

            }

        // outputs
        for (const CTxOut &atxout : tx.vout) {
            std::vector<uint160> addrIds;
                if(BuildAddrIndex(atxout.scriptPubKey, addrIds))
            {
            for (uint160 addrId : addrIds)
            {
                if(!txdb.WriteAddrIndex(addrId, hashTx))
                    return TransientFailure(error("ConnectBlock(): txouts WriteAddrIndex failed addrId: %s txhash: %s",
                                                  addrId.ToString().c_str(), hashTx.ToString().c_str()));
                    }
            }
        }
        }
    }

    if (pindex->nHeight >= FORK_HEIGHT_DAG)
    {
        std::string strActiveSetError;
        if (!txdb.WriteDAGSkippedTxs(
                *this, setDAGSkippedTxs, strActiveSetError))
            return TransientFailure(error(
                "ConnectBlock() : could not persist exact DAG active set: %s",
                strActiveSetError.c_str()));
    }

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev)
    {
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = pindex->GetBlockHash();
        if (!txdb.WriteBlockIndex(blockindexPrev))
            return TransientFailure(error("ConnectBlock() : WriteBlockIndex failed"));
    }

    if (fDebug && GetBoolArg("-showtimers", false))
        printf("ConnectBlock: height=%d total=%" PRId64"ms check=%" PRId64"ms tx_transparent=%u/%" PRId64"us tx_shielded=%u/%" PRId64"us tx_anon=%u/%" PRId64"us tx_privstake=%u/%" PRId64"us\n",
               pindex->nHeight, GetTimeMillis() - nConnectBlockStart, nConnectCheckMs,
               nTransparentValidateCount, nTransparentValidateMicros,
               nShieldedValidateCount, nShieldedValidateMicros,
               nAnonValidateCount, nAnonValidateMicros,
               nPrivateStakeValidateCount, nPrivateStakeValidateMicros);

    return Connected();
}

int GetFirstV3EpochStateRebuildEpoch(int nForkHeight)
{
    const int nMigrationEpoch = GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V3) - 1;
    const int nFirstChangedEpoch = GetEpochForHeight(nForkHeight + 1);
    return std::max(nMigrationEpoch, nFirstChangedEpoch);
}

int GetFirstV2EpochStateRebuildEpoch(int nForkHeight)
{
    return std::max(GetEpochForHeight(FORK_HEIGHT_EPOCH_STATE_V2),
                    GetEpochForHeight(nForkHeight));
}

// Legacy schema-V2 builder reachability. See the block comment in main.h: each of the
// three call sites gates on the matching predicate here so there is one definition of
// which epochs the fBlue-ordered builder may own.

static bool IsEpochCrossingHeight(int nHeight, int& nCompletedEpochOut, int& nEpochEndOut)
{
    nCompletedEpochOut = -1;
    nEpochEndOut = -1;
    if (nHeight <= 0)
        return false;
    const int nCurrentEpoch = GetEpochForHeight(nHeight);
    const int nPreviousEpoch = GetEpochForHeight(nHeight - 1);
    if (nCurrentEpoch <= nPreviousEpoch)
        return false;
    nCompletedEpochOut = nPreviousEpoch;
    nEpochEndOut = GetEpochBoundaryHeight(nPreviousEpoch + 1, nHeight) - 1;
    return true;
}

bool V2CompatEpochBuildsAtIndexCrossing(int nHeight, int& nEpochOut)
{
    nEpochOut = -1;
    if (nHeight >= FORK_HEIGHT_EPOCH_STATE_V3)
        return false;
    int nCompletedEpoch = -1;
    int nEpochEnd = -1;
    if (!IsEpochCrossingHeight(nHeight, nCompletedEpoch, nEpochEnd))
        return false;
    // V2-range epochs are staged by the best-chain / reorg paths instead, so that
    // their state, tree and schema share the best-chain transaction.
    if (nEpochEnd >= FORK_HEIGHT_EPOCH_STATE_V2)
        return false;
    nEpochOut = nCompletedEpoch;
    return true;
}

bool V2CompatEpochStagesAtBestChainCrossing(int nHeight, int& nEpochOut)
{
    nEpochOut = -1;
    if (nHeight >= FORK_HEIGHT_EPOCH_STATE_V3)
        return false;
    int nCompletedEpoch = -1;
    int nEpochEnd = -1;
    if (!IsEpochCrossingHeight(nHeight, nCompletedEpoch, nEpochEnd))
        return false;
    if (nEpochEnd < FORK_HEIGHT_EPOCH_STATE_V2)
        return false;
    nEpochOut = nCompletedEpoch;
    return true;
}

bool V2CompatReorgStagesEpochRange(int nOldTipHeight, int nNewTipHeight, int nForkHeight,
                                   int& nFirstEpochOut, int& nLastEpochOut)
{
    nFirstEpochOut = -1;
    nLastEpochOut = -1;
    const bool fV3EpochReorg =
        (nOldTipHeight >= FORK_HEIGHT_EPOCH_STATE_V3) ||
        (nNewTipHeight >= FORK_HEIGHT_EPOCH_STATE_V3);
    const bool fV2EpochReorg = !fV3EpochReorg &&
        ((nOldTipHeight >= FORK_HEIGHT_EPOCH_STATE_V2) ||
         (nNewTipHeight >= FORK_HEIGHT_EPOCH_STATE_V2));
    if (!fV2EpochReorg)
        return false;
    // V2 commits an epoch when the first block of the next epoch arrives. The exact
    // crossing block is part of the V2 anchor, so an epoch whose final block is the
    // fork point is affected as well.
    nFirstEpochOut = GetFirstV2EpochStateRebuildEpoch(nForkHeight);
    nLastEpochOut = GetEpochForHeight(nNewTipHeight) - 1;
    return true;
}

bool V2CompatEpochStagesAtReorgCrossing(int nHeight, int nFirstStagedEpoch,
                                        int nLastV2EpochToStage, int& nEpochOut)
{
    nEpochOut = -1;
    int nCompletedEpoch = -1;
    int nEpochEnd = -1;
    if (!IsEpochCrossingHeight(nHeight, nCompletedEpoch, nEpochEnd))
        return false;
    if (nCompletedEpoch < nFirstStagedEpoch || nCompletedEpoch > nLastV2EpochToStage)
        return false;
    nEpochOut = nCompletedEpoch;
    return true;
}

static bool StageV2EpochStateAtCrossing(
    CTxDB& txdb, CBlockIndex* pCrossing, int nEpoch, int nFirstEpoch,
    std::map<int, CEpochState>& mapStagedEpochStates,
    std::map<int, CCurveTree>& mapStagedEpochTrees,
    std::string& strError)
{
    strError.clear();
    if (!pCrossing || !pCrossing->phashBlock || nEpoch < nFirstEpoch)
    {
        strError = "invalid V2 boundary-crossing stage request";
        return false;
    }

    const int nEpochStart = GetEpochBoundaryHeight(nEpoch, pCrossing->nHeight);
    const int nEpochEnd = GetEpochBoundaryHeight(nEpoch + 1, pCrossing->nHeight) - 1;
    if (pCrossing->nHeight != nEpochEnd + 1 ||
        GetEpochForHeight(pCrossing->nHeight) <= nEpoch)
    {
        strError = strprintf("V2 epoch %d requires canonical crossing height %d (got %d)",
                             nEpoch, nEpochEnd + 1, pCrossing->nHeight);
        return false;
    }

    const CEpochState* pPrevState = NULL;
    const CCurveTree* pPrevTree = NULL;
    if (nEpoch > nFirstEpoch)
    {
        std::map<int, CEpochState>::const_iterator itState =
            mapStagedEpochStates.find(nEpoch - 1);
        std::map<int, CCurveTree>::const_iterator itTree =
            mapStagedEpochTrees.find(nEpoch - 1);
        if (itState == mapStagedEpochStates.end() ||
            itTree == mapStagedEpochTrees.end())
        {
            strError = strprintf("V2 staged predecessor pair missing for epoch %d", nEpoch);
            return false;
        }
        pPrevState = &itState->second;
        pPrevTree = &itTree->second;
    }

    CEpochState state;
    CCurveTree tree;
    if (!g_dagManager.BuildEpochStateV2Compat(
            nEpoch, nEpochEnd - nEpochStart + 1, pCrossing,
            state, tree, strError, pPrevState, pPrevTree))
        return false;
    if (!g_dagManager.WriteEpochState(txdb, state, tree))
    {
        strError = strprintf("V2 state/tree write failed for epoch %d", nEpoch);
        return false;
    }

    mapStagedEpochStates[nEpoch] = state;
    mapStagedEpochTrees[nEpoch] = tree;
    return true;
}

static bool StageEpochStateRange(CTxDB& txdb, CBlockIndex* pTip,
                                 int nFirstEpoch, int nLastEpoch,
                                 std::map<int, CEpochState>& mapStagedEpochStates,
                                 std::map<int, CCurveTree>& mapStagedEpochTrees,
                                 std::string& strError)
{
    strError.clear();
    if (!pTip || !pTip->phashBlock || nFirstEpoch < 0 || nLastEpoch < nFirstEpoch)
    {
        strError = "invalid staged epoch range";
        return false;
    }

    for (int nEpoch = nFirstEpoch; nEpoch <= nLastEpoch; ++nEpoch)
    {
        const int nEpochStart = GetEpochBoundaryHeight(nEpoch, pTip->nHeight);
        const int nEpochEnd = GetEpochBoundaryHeight(nEpoch + 1, pTip->nHeight) - 1;
        CBlockIndex* pBoundary = pTip;
        while (pBoundary && pBoundary->nHeight > nEpochEnd)
            pBoundary = pBoundary->pprev;
        if (!pBoundary || pBoundary->nHeight != nEpochEnd)
        {
            strError = strprintf("missing canonical boundary at height %d for epoch %d",
                                 nEpochEnd, nEpoch);
            return false;
        }

        const CEpochState* pPrevState = NULL;
        const CCurveTree* pPrevTree = NULL;
        if (nEpoch > nFirstEpoch)
        {
            std::map<int, CEpochState>::const_iterator itPrevState =
                mapStagedEpochStates.find(nEpoch - 1);
            std::map<int, CCurveTree>::const_iterator itPrevTree =
                mapStagedEpochTrees.find(nEpoch - 1);
            if (itPrevState == mapStagedEpochStates.end() ||
                itPrevTree == mapStagedEpochTrees.end())
            {
                strError = strprintf("staged predecessor pair missing for epoch %d", nEpoch);
                return false;
            }
            pPrevState = &itPrevState->second;
            pPrevTree = &itPrevTree->second;
        }

        CEpochState state;
        CCurveTree tree;
        if (!g_dagManager.BuildEpochState(nEpoch, nEpochEnd - nEpochStart + 1,
                                          pBoundary, state, tree, strError,
                                          pPrevState, pPrevTree))
            return false;
        // The epoch that ends a term's lead-in carries that term's drawn committee.
        // Seated here, in the same transaction that writes the record, so the draw
        // happens exactly once per term on every node instead of once per validation.
        bool fCommitteeLocalFailure = false;
        if (!SeatFinalityCommitteeForEpochState(txdb, state, fCommitteeLocalFailure,
                                                strError))
        {
            strError = strprintf("committee draw for epoch %d failed: %s", nEpoch,
                                 strError.c_str());
            return false;
        }
        if (!g_dagManager.WriteEpochState(txdb, state, tree))
        {
            strError = strprintf("state/tree write failed for epoch %d", nEpoch);
            return false;
        }
        mapStagedEpochStates[nEpoch] = state;
        mapStagedEpochTrees[nEpoch] = tree;
    }
    return true;
}

static void PublishDurablyCommittedBest(CBlockIndex* pindexCommitted)
{
    if (!pindexCommitted || !pindexCommitted->phashBlock)
        return;
    hashBestChain = pindexCommitted->GetBlockHash();
    pindexBest = pindexCommitted;
    pblockindexFBBHLast = NULL;
    nBestHeight = pindexCommitted->nHeight;
    nBestChainTrust = pindexCommitted->nChainTrust;
    nTimeBestReceived = GetTime();

    // Every durable tip is reported to the vote producers here, the one place all tip
    // paths publish, so no epoch boundary goes unobserved.
    NotifyFinalityTipChanged(pindexCommitted->nHeight);
}

static void RestoreCommittedFinalityOrShutdown(const char* pszContext)
{
    if (g_finalityTracker.RestoreCommittedStateAfterAbort())
        return;
    printf("%s: FATAL could not restore committed finality state after transaction "
           "failure; shutting down for -reindex/resync\n", pszContext);
    StartShutdown();
}

static void RefreshCommittedShieldedPoolOrShutdown(CTxDB& txdb,
                                                    CBlockIndex* pindexCommitted,
                                                    const char* pszContext)
{
    if (!pindexCommitted || pindexCommitted->nHeight < FORK_HEIGHT_SHIELDED)
    {
        nShieldedPoolValue = 0;
        return;
    }
    int64_t nCommittedPool = 0;
    if (!txdb.ReadShieldedPoolValue(nCommittedPool) || !MoneyRange(nCommittedPool))
    {
        printf("%s: FATAL committed shielded pool value is missing/out of range; "
               "publishing durable best and shutting down for -reindex/resync\n",
               pszContext);
        PublishDurablyCommittedBest(pindexCommitted);
        StartShutdown();
        return;
    }
    nShieldedPoolValue = nCommittedPool;
}

/** Ordered effects and recovery locator for one chain transaction, all prepared before
 *  TxnCommit; replayed before any later postponed reconnect transaction begins. */
class CBestChainEffectJournal
{
private:
    struct Entry
    {
        CBlockIndex* pindex;
        bool fConnect;
        CBlock block;
        std::set<uint256> setDAGSkippedTxs;

        Entry(CBlockIndex* pindexIn, bool fConnectIn,
              const CBlock& blockIn,
              const std::set<uint256>& setDAGSkippedTxsIn)
            : pindex(pindexIn), fConnect(fConnectIn), block(blockIn),
              setDAGSkippedTxs(setDAGSkippedTxsIn) {}
    };

    std::vector<Entry> vEntries;
    CBlockLocator locator;
    CShieldedWalletRecoveryRecord recoveryRecord;
    bool fPrepared;
    bool fCommitted;

    bool PrepareEntry(CTxDB& txdb, CBlockIndex* pindex, bool fConnect)
    {
        if (!pindex || !pindex->phashBlock)
            return false;
        CBlock block;
        if (!block.ReadFromDisk(pindex, true) ||
            block.GetHash() != pindex->GetBlockHash())
            return false;
        std::set<uint256> setDAGSkippedTxs;
        if (pindex->nHeight >= FORK_HEIGHT_DAG)
        {
            std::string strActiveSetError;
            const TxDBReadStatus status = txdb.ReadDAGSkippedTxsStatus(
                block, setDAGSkippedTxs, strActiveSetError);
            if (status != TXDB_READ_FOUND)
            {
                printf("PrepareBestChainEffects: exact DAG active set is %s "
                       "at height %d%s%s\n",
                       status == TXDB_READ_NOT_FOUND ? "missing" : "corrupt",
                       pindex->nHeight,
                       strActiveSetError.empty() ? "" : ": ",
                       strActiveSetError.c_str());
                return false;
            }
        }
        vEntries.push_back(Entry(pindex, fConnect, block,
                                 setDAGSkippedTxs));
        return true;
    }

    bool PrepareRecoveryRecord(CBlockIndex* pindexOldTip,
                               CBlockIndex* pindexFork,
                               CBlockIndex* pindexNewTip,
                               size_t nDisconnect,
                               size_t nConnect)
    {
        if (!pindexNewTip || !pindexNewTip->phashBlock ||
            (pindexOldTip && !pindexOldTip->phashBlock) ||
            (pindexFork && !pindexFork->phashBlock) ||
            (nDisconnect == 0 && nConnect == 0) ||
            nDisconnect > std::numeric_limits<uint32_t>::max() ||
            nConnect > std::numeric_limits<uint32_t>::max())
            return false;

        std::vector<CShieldedWalletEffectDigestEntry> vDigestEntries;
        vDigestEntries.reserve(vEntries.size());
        for (std::vector<Entry>::const_iterator it = vEntries.begin();
             it != vEntries.end(); ++it)
        {
            if (!it->pindex || !it->pindex->phashBlock)
                return false;
            vDigestEntries.push_back(CShieldedWalletEffectDigestEntry(
                it->fConnect, it->pindex->GetBlockHash(),
                it->setDAGSkippedTxs));
        }

        recoveryRecord = CShieldedWalletRecoveryRecord();
        recoveryRecord.nSchema = SHIELDED_WALLET_RECOVERY_SCHEMA;
        recoveryRecord.hashOldTip = pindexOldTip
            ? pindexOldTip->GetBlockHash() : uint256(0);
        recoveryRecord.hashFork = pindexFork
            ? pindexFork->GetBlockHash() : uint256(0);
        recoveryRecord.hashNewTip = pindexNewTip->GetBlockHash();
        recoveryRecord.nDisconnect = (uint32_t)nDisconnect;
        recoveryRecord.nConnect = (uint32_t)nConnect;
        recoveryRecord.hashEffectPlan =
            ComputeShieldedWalletEffectPlanDigest(vDigestEntries);
        return recoveryRecord.IsValid();
    }

    // A shielded scan failure is recorded for rescan and never stops the node: its inputs
    // are peer-published bytes.
    static void WalletScanDegraded(const Entry& entry, CWallet* pwallet,
                                   const char* pszReason)
    {
        const int nHeight = entry.pindex ? entry.pindex->nHeight : -1;
        printf("ReplayBestChainEffects: shielded wallet %s scan failed for block at "
               "height %d: %s. The chain transition stands; this wallet's view of "
               "that block is incomplete. Run z_rescaniv5 to reprocess it.\n",
               entry.fConnect ? "connect" : "disconnect", nHeight, pszReason);
        if (pwallet && nHeight >= 0)
            pwallet->MarkPrivacyVNextScanGap(nHeight);
    }

    bool FailClosed(const Entry& entry, const char* pszReason) const
    {
        const int nHeight = entry.pindex ? entry.pindex->nHeight : -1;
        printf("ReplayBestChainEffects: FATAL post-commit %s effect failed for "
               "block at height %d: %s. The chain transition is already "
               "durable and will NOT be rolled back; shutting down. Rebuild "
               "innovanamesindex.dat/wallet state from the committed chain or "
               "restart with -reindex/resync.\n",
               entry.fConnect ? "connect" : "disconnect",
               nHeight, pszReason);
        StartShutdown();
        return false;
    }

public:
    CBestChainEffectJournal()
        : fPrepared(false), fCommitted(false) {}

    bool PrepareConnect(CTxDB& txdb, CBlockIndex* pindex)
    {
        Clear();
        try
        {
            vEntries.reserve(1);
            locator.Set(pindex);
            if (!PrepareEntry(txdb, pindex, true))
            {
                Clear();
                return false;
            }
            if (!PrepareRecoveryRecord(pindex ? pindex->pprev : NULL,
                                       pindex ? pindex->pprev : NULL,
                                       pindex, 0, 1))
            {
                Clear();
                return false;
            }
            fPrepared = true;
            return true;
        }
        catch (...)
        {
            Clear();
            return false;
        }
    }

    bool PrepareReorg(CTxDB& txdb,
                      const std::vector<CBlockIndex*>& vDisconnect,
                      const std::vector<CBlockIndex*>& vConnect,
                      CBlockIndex* pindexTip)
    {
        Clear();
        try
        {
            if (vConnect.size() > vEntries.max_size() ||
                vDisconnect.size() > vEntries.max_size() - vConnect.size())
                return false;
            vEntries.reserve(vDisconnect.size() + vConnect.size());
            locator.Set(pindexTip);
            for (std::vector<CBlockIndex*>::const_iterator it =
                     vDisconnect.begin(); it != vDisconnect.end(); ++it)
            {
                if (!PrepareEntry(txdb, *it, false))
                {
                    Clear();
                    return false;
                }
            }
            for (std::vector<CBlockIndex*>::const_iterator it =
                     vConnect.begin(); it != vConnect.end(); ++it)
            {
                if (!PrepareEntry(txdb, *it, true))
                {
                    Clear();
                    return false;
                }
            }
            CBlockIndex* pindexFork = NULL;
            if (!vDisconnect.empty())
                pindexFork = vDisconnect.back()->pprev;
            else if (!vConnect.empty())
                pindexFork = vConnect.front()->pprev;
            CBlockIndex* pindexOldTip = !vDisconnect.empty()
                ? vDisconnect.front() : pindexFork;
            if (!PrepareRecoveryRecord(pindexOldTip, pindexFork, pindexTip,
                                       vDisconnect.size(), vConnect.size()))
            {
                Clear();
                return false;
            }
            fPrepared = true;
            return true;
        }
        catch (...)
        {
            Clear();
            return false;
        }
    }

    void MarkCommitted()
    {
        if (fPrepared)
            fCommitted = true;
    }

    bool IsEmpty() const
    {
        return vEntries.empty() && !fPrepared && !fCommitted;
    }

    const CBlockLocator& GetLocator() const
    {
        return locator;
    }

    const CShieldedWalletRecoveryRecord& GetRecoveryRecord() const
    {
        return recoveryRecord;
    }

    void Clear()
    {
        vEntries.clear();
        locator.SetNull();
        recoveryRecord = CShieldedWalletRecoveryRecord();
        fPrepared = false;
        fCommitted = false;
    }

    bool Replay(CTxDB& txdb) const
    {
        if (!fPrepared || !fCommitted)
        {
            printf("ReplayBestChainEffects: FATAL attempted to replay an "
                   "uncommitted effect batch; shutting down\n");
            StartShutdown();
            return false;
        }

        bool fTouchedShieldedWallet = false;
        for (std::vector<Entry>::const_iterator it = vEntries.begin();
             it != vEntries.end(); ++it)
        {
            const Entry& entry = *it;
            if (!entry.pindex || !entry.pindex->phashBlock)
                return FailClosed(entry, "missing committed block index");

            try
            {
                if (!entry.fConnect &&
                    entry.pindex->nHeight >= FORK_HEIGHT_SHIELDED)
                    fTouchedShieldedWallet = true;
                if (entry.fConnect)
                {
                    std::string strNameError;
                    // The name index has its own Berkeley DB transaction. Replay the exact block transition
                    // (with the persisted DAG skip set) so mutations, cursor and progress commit together.
                    if (entry.pindex->nHeight >= RELEASE_HEIGHT)
                    {
                        BLOCK_PHASE(BP_NAME_INDEX);
                        // A block with no name operation writes only the cursor and progress marker; defer
                        // them to one flush. A block with one flushes first and takes the per-block path.
                        if (NameIndexBatchingEnabled() &&
                            BlockHasNoNameEffects(entry.block,
                                                  entry.setDAGSkippedTxs))
                        {
                            if (!DeferNameIndexCursor(
                                    entry.block, entry.pindex,
                                    entry.setDAGSkippedTxs, strNameError))
                                return FailClosed(entry, strNameError.c_str());
                        }
                        else
                        {
                            if (!FlushNameIndexCursorBatch(strNameError))
                                return FailClosed(entry, strNameError.c_str());
                            if (!ApplyNameIndexConnectBlock(
                                    txdb, entry.pindex,
                                    entry.setDAGSkippedTxs, strNameError))
                                return FailClosed(entry, strNameError.c_str());
                        }
                    }
                    else
                    {
                        BLOCK_PHASE(BP_NAME_INDEX);
                        if (!FlushNameIndexCursorBatch(strNameError))
                            return FailClosed(entry, strNameError.c_str());
                        if (!CommitNameIndexTip(entry.pindex, strNameError))
                            return FailClosed(entry, strNameError.c_str());
                    }

                    {
                        BLOCK_PHASE(BP_WALLET_SYNC);
                        for (std::vector<CTransaction>::const_iterator txIt =
                                 entry.block.vtx.begin();
                             txIt != entry.block.vtx.end(); ++txIt)
                        {
                            if (entry.setDAGSkippedTxs.count(txIt->GetHash()))
                                continue;
                            std::string strWalletError;
                            if (!SyncWithWalletsChecked(*txIt, &entry.block, true,
                                                        true, strWalletError,
                                                        &entry.setDAGSkippedTxs))
                                return FailClosed(entry, strWalletError.c_str());
                        }
                    }

                    // Shielded outputs are found by trial-decrypting the block's payloads, which the
                    // per-transaction sync above does not do. Mirrors the disconnect side.
                    if (entry.pindex->nHeight >= FORK_HEIGHT_SHIELDED)
                    {
                        BLOCK_PHASE(BP_SHIELD_SCAN);
                        for (CWallet* pwallet : setpwalletRegistered)
                        {
                            std::string strWalletError;
                            if (!pwallet->ScanBlockForShieldedNotesChecked(
                                    entry.block, entry.pindex, strWalletError))
                                WalletScanDegraded(entry, pwallet,
                                                   strWalletError.c_str());
                        }
                    }

                    uiInterface.NotifyRanksUpdated();
                }
                else
                {
                    // Commits the disconnect's mutations, predecessor cursor and progress in one Berkeley DB
                    // transaction, bound to the same connect-time DAG skip set.
                    std::string strNameError;
                    // A disconnect reads the index it is undoing, so any
                    // deferred cursor must be durable before it runs.
                    if (!FlushNameIndexCursorBatch(strNameError))
                        return FailClosed(entry, strNameError.c_str());
                    if (entry.pindex->nHeight >= RELEASE_HEIGHT)
                    {
                        if (!ApplyNameIndexDisconnectBlock(
                                entry.block, entry.pindex,
                                entry.setDAGSkippedTxs, strNameError))
                            return FailClosed(entry, strNameError.c_str());
                    }
                    else if (!CommitNameIndexTip(entry.pindex->pprev,
                                                 strNameError))
                        return FailClosed(entry, strNameError.c_str());

                    if (entry.pindex->nHeight >= FORK_HEIGHT_SHIELDED)
                    {
                        for (CWallet* pwallet : setpwalletRegistered)
                        {
                            std::string strWalletError;
                            if (!pwallet->DisconnectShieldedBlockRecoveryChecked(
                                    entry.block, entry.setDAGSkippedTxs,
                                    entry.pindex, strWalletError))
                                WalletScanDegraded(entry, pwallet,
                                                   strWalletError.c_str());
                        }
                    }

                    for (std::vector<CTransaction>::const_iterator txIt =
                             entry.block.vtx.begin();
                         txIt != entry.block.vtx.end(); ++txIt)
                    {
                        if (entry.setDAGSkippedTxs.count(txIt->GetHash()))
                            continue;
                        std::string strWalletError;
                        if (!SyncWithWalletsChecked(*txIt, &entry.block, false,
                                                    false, strWalletError))
                            return FailClosed(entry, strWalletError.c_str());
                    }
                }
            }
            catch (const std::exception& e)
            {
                return FailClosed(entry, e.what());
            }
            catch (...)
            {
                return FailClosed(entry, "unknown post-commit exception");
            }
        }

        if (fTouchedShieldedWallet)
        {
            const Entry& context = vEntries.back();
            try
            {
                if (!pindexBest || !pindexBest->phashBlock)
                    return FailClosed(context, "missing canonical tip during shielded wallet reconciliation");
                for (CWallet* pwallet : setpwalletRegistered)
                {
                    std::string strWalletError;
                    if (!pwallet->ReconcileShieldedNoteSpentStateChecked(
                            txdb, pindexBest->nHeight, strWalletError))
                        return FailClosed(context, strWalletError.c_str());
                }
            }
            catch (const std::exception& e)
            {
                return FailClosed(context, e.what());
            }
            catch (...)
            {
                return FailClosed(context, "unknown shielded wallet reconciliation exception");
            }
        }
        return true;
    }
};

static bool SameShieldedWalletRecoveryRecord(
    const CShieldedWalletRecoveryRecord& a,
    const CShieldedWalletRecoveryRecord& b)
{
    return a.nSchema == b.nSchema &&
           a.hashOldTip == b.hashOldTip &&
           a.hashFork == b.hashFork &&
           a.hashNewTip == b.hashNewTip &&
           a.nDisconnect == b.nDisconnect &&
           a.nConnect == b.nConnect &&
           a.hashEffectPlan == b.hashEffectPlan;
}

static bool ClearCommittedShieldedWalletRecovery(
    CTxDB& txdb, const CShieldedWalletRecoveryRecord& expected,
    const char* pszContext)
{
    // Wallet/name Berkeley DB uses DB_TXN_WRITE_NOSYNC.  Force its committed
    // log records durable before deleting the LevelDB outbox; otherwise a
    // power loss could retain the acknowledgement but lose wallet mutations.
    if (!bitdb.FlushLog())
    {
        printf("%s: FATAL could not flush auxiliary Berkeley DB logs before "
               "shielded-wallet recovery acknowledgement; shutting down\n",
               pszContext);
        StartShutdown();
        return false;
    }

    CShieldedWalletRecoveryRecord persisted;
    if (txdb.ReadShieldedWalletRecoveryStatus(persisted) !=
            TXDB_READ_FOUND ||
        !SameShieldedWalletRecoveryRecord(persisted, expected))
    {
        printf("%s: FATAL shielded-wallet recovery outbox is missing, corrupt, "
               "or does not match the committed transition; shutting down\n",
               pszContext);
        StartShutdown();
        return false;
    }
    if (!txdb.TxnBegin())
    {
        printf("%s: FATAL could not begin shielded-wallet recovery outbox "
               "clear transaction; shutting down\n", pszContext);
        StartShutdown();
        return false;
    }
    if (!txdb.EraseShieldedWalletRecovery())
    {
        txdb.TxnAbort();
        printf("%s: FATAL could not stage shielded-wallet recovery outbox "
               "clear; shutting down\n", pszContext);
        StartShutdown();
        return false;
    }
    if (!txdb.TxnCommit(true))
    {
        printf("%s: FATAL could not commit shielded-wallet recovery outbox "
               "clear; shutting down\n", pszContext);
        StartShutdown();
        return false;
    }
    return true;
}

static bool PublishAndReplayCommittedEffects(CTxDB& txdb,
                                             CBlockIndex* pindexCommitted,
                                             CBestChainEffectJournal& effects,
                                             const char* pszContext)
{
    // The chain transaction is already durable.  Publish exactly that tip
    // before callbacks inspect globals, but never report a callback failure as
    // block invalidity or try to roll the transaction back.
    PublishDurablyCommittedBest(pindexCommitted);
    mempool.AddTransactionsUpdated(1);

    if (fShutdown)
    {
        printf("%s: shutdown requested after chain commit; leaving auxiliary "
               "recovery markers behind the durable tip\n", pszContext);
        effects.Clear();
        return false;
    }

    if (!effects.Replay(txdb))
    {
        effects.Clear();
        return false;
    }

    // Flush once the batch reaches its block count or its age bound, for catch-up and tip
    // following alike.
    if (NameIndexCursorBatchDue())
    {
        BLOCK_PHASE(BP_NAME_INDEX);
        std::string strNameError;
        if (!FlushNameIndexCursorBatch(strNameError))
        {
            printf("%s: FATAL could not flush the deferred name-index cursor "
                   "after a durable chain commit: %s; shutting down. The "
                   "index rebuilds from the committed chain on restart\n",
                   pszContext, strNameError.c_str());
            StartShutdown();
            effects.Clear();
            return false;
        }
    }

    try
    {
        BLOCK_PHASE(BP_WALLET_LOCATOR);
        std::string strWalletError;
        DeferWalletBestChain(effects.GetLocator());
        if (WalletLocatorBatchDue() &&
            !FlushWalletBestChainLocator(strWalletError))
        {
            printf("%s: FATAL %s after durable chain commit; shutting down "
                   "with the prior wallet locator retained for rescan\n",
                   pszContext, strWalletError.c_str());
            StartShutdown();
            effects.Clear();
            return false;
        }
    }
    catch (const std::exception& e)
    {
        printf("%s: FATAL wallet locator exception after durable chain "
               "commit: %s; shutting down for rescan\n",
               pszContext, e.what());
        StartShutdown();
        effects.Clear();
        return false;
    }
    catch (...)
    {
        printf("%s: FATAL unknown wallet locator exception after durable "
               "chain commit; shutting down for rescan\n", pszContext);
        StartShutdown();
        effects.Clear();
        return false;
    }

    bool fRecoveryCleared;
    {
        BLOCK_PHASE(BP_RECOVERY_CLEAR);
        fRecoveryCleared = ClearCommittedShieldedWalletRecovery(
            txdb, effects.GetRecoveryRecord(), pszContext);
    }
    if (!fRecoveryCleared)
    {
        effects.Clear();
        return false;
    }

    effects.Clear();
    return true;
}

// Reorg finality guard (R-FIN-001), shared by Reorganize and CBlock::SetBestChain.
//
// The anchor stays derived from the evaluating node's own tip. It cannot be taken from
// the candidate branch or the fork point: the evidence that a height is finalized lives
// on the chain being abandoned, so any anchor computed purely from data at or below the
// fork point is vacuous, and a candidate-derived anchor is both attacker-selectable (the
// attacker picks the branch length, hence the epoch) and unavailable -- epoch state is
// staged as blocks connect, so a candidate that has crossed a boundary this node has not
// completed has no state to read and the guard would fail closed onto the losing branch.
//
// What is fixed instead is the severity. Two anchors are computed: the current one, as of
// epoch(tip)-1, which decides rejection, and a lagged one, REORG_LATCH_ANCHOR_LAG_EPOCHS-1
// epochs older, which decides whether the rejection is persisted. Inside the band the
// verdict is a plain rejection that latches nothing and hardens on its own once the lagged
// anchor advances past the fork point. BLOCK_FAILED_VALID survives restart and is cleared
// only by reconsiderblock, so the persisted half is the half that has to agree.
//
// The guarantee, with F(k) the finalized height as of epoch k and L the lag: node A latches
// only when f < F(e(A)-L), node B allows only when f >= F(e(B)-1), so a fork that one
// condemns and the other follows needs F(e(B)-1) < F(e(A)-L). F is non-decreasing in epoch,
// so that needs e(A)-e(B) > L-1: no such pair exists between tips within L-1 epochs. The
// clamp below is load-bearing for it -- it is what makes f < latch imply f < cur.
//
// The tolerance is quantitative, not absolute. An anchor every node agrees on regardless of
// tip does not exist here (a node holds F(k) only for epochs it has completed), so past L-1
// epochs of skew the pair returns. L is the knob; raising it costs one more epoch of the
// branch staying re-requestable before a condemnation hardens.
ReorgFinalityVerdict CheckReorgAgainstFinality(const CDAGManager& dag,
                                               int nBestHeight, int nForkHeight,
                                               int& nFinalCurOut, int& nFinalLatchOut,
                                               int& nAsOfEpochOut)
{
    nFinalCurOut = 0;
    nFinalLatchOut = 0;
    nAsOfEpochOut = GetEpochForHeight(nBestHeight) - 1;

    if (nBestHeight < FORK_HEIGHT_FINALITY)
        return REORG_FINALITY_ALLOW;

    // One expression for the latch epoch, so the two lookup paths cannot drift apart.
    const int nLatchEpoch = nAsOfEpochOut - (REORG_LATCH_ANCHOR_LAG_EPOCHS - 1);

    if (nBestHeight >= FORK_HEIGHT_EPOCH_STATE_V3)
    {
        if (!dag.TryGetDeterministicFinalizedHeight(nAsOfEpochOut, nFinalCurOut))
            return REORG_FINALITY_STATE_MISSING;
        // A missing lagged record is the bottom edge of epoch-state history, not corruption:
        // LoadEpochStates fails closed on interior holes, so absent here means no record was
        // ever written. Degrade to "nothing latchable yet" rather than failing closed, which
        // would brick every node for the first few epochs after the V3 gate.
        if (!dag.TryGetDeterministicFinalizedHeight(nLatchEpoch, nFinalLatchOut))
            nFinalLatchOut = 0;
    }
    else
    {
        nFinalCurOut = dag.GetDeterministicFinalizedHeight(nAsOfEpochOut);
        nFinalLatchOut = dag.GetDeterministicFinalizedHeight(nLatchEpoch);
    }

    // Monotone by the loader's regression check; clamp so a latch can never outrun the
    // anchor that gates rejection.
    if (nFinalLatchOut > nFinalCurOut)
        nFinalLatchOut = nFinalCurOut;

    if (nFinalCurOut <= 0 || nForkHeight >= nFinalCurOut)
        return REORG_FINALITY_ALLOW;
    if (nForkHeight < nFinalLatchOut)
        return REORG_FINALITY_REJECT_PERMANENT;
    return REORG_FINALITY_REJECT_TRANSIENT;
}

ReorgFinalityVerdict CheckReorgAgainstFinality(int nBestHeight, int nForkHeight,
                                               int& nFinalCurOut, int& nFinalLatchOut,
                                               int& nAsOfEpochOut)
{
    return CheckReorgAgainstFinality(g_dagManager, nBestHeight, nForkHeight,
                                     nFinalCurOut, nFinalLatchOut, nAsOfEpochOut);
}

// Records the verdict as well as reaching it, so neither call site carries its own copy
// of the persistence rule. Only REJECT_PERMANENT may set the flag: it is the one verdict
// every node within REORG_LATCH_ANCHOR_LAG_EPOCHS-1 epochs of this tip also reaches, and
// BLOCK_FAILED_VALID is serialized and cleared only by reconsiderblock.
ReorgFinalityVerdict ApplyReorgFinalityGuard(const CDAGManager& dag,
                                             int nBestHeight, int nForkHeight,
                                             bool* pfPermanentInvalid,
                                             int& nFinalCurOut, int& nFinalLatchOut,
                                             int& nAsOfEpochOut)
{
    const ReorgFinalityVerdict verdict = CheckReorgAgainstFinality(
        dag, nBestHeight, nForkHeight, nFinalCurOut, nFinalLatchOut, nAsOfEpochOut);
    if (verdict == REORG_FINALITY_REJECT_PERMANENT && pfPermanentInvalid)
        *pfPermanentInvalid = true;
    return verdict;
}

ReorgFinalityVerdict ApplyReorgFinalityGuard(int nBestHeight, int nForkHeight,
                                             bool* pfPermanentInvalid,
                                             int& nFinalCurOut, int& nFinalLatchOut,
                                             int& nAsOfEpochOut)
{
    return ApplyReorgFinalityGuard(g_dagManager, nBestHeight, nForkHeight, pfPermanentInvalid,
                                   nFinalCurOut, nFinalLatchOut, nAsOfEpochOut);
}

// The fork point of a candidate tip with the current best chain: the common ancestor of
// pCandidate and pindexBest, NULL when there is none. One walk for every reorg verdict.
static const CBlockIndex* ForkPointWithBestChain(const CBlockIndex* pCandidate)
{
    const CBlockIndex* pa = pCandidate;
    const CBlockIndex* pb = pindexBest;
    while (pa && pb && pa != pb)
    {
        if (pa->nHeight > pb->nHeight)
            pa = pa->pprev;
        else if (pb->nHeight > pa->nHeight)
            pb = pb->pprev;
        else
        {
            pa = pa->pprev;
            pb = pb->pprev;
        }
    }
    return (pa && pa == pb) ? pa : NULL;
}

// No common ancestor is unreachable with a single genesis; the value then cannot be
// rejected, so a caller's missing-state fail-closed still runs.
static int ForkHeightWithBestChain(const CBlockIndex* pCandidate)
{
    const CBlockIndex* pFork = ForkPointWithBestChain(pCandidate);
    return pFork ? pFork->nHeight : std::numeric_limits<int>::max();
}

// The finality verdict for switching the best chain to pCandidate, against the current tip
// and never persisted. Extending the tip, or a tip below the gate, is switchable outright.
ReorgFinalityVerdict BestChainSwitchVerdict(const CBlockIndex* pCandidate, int& nForkHeightOut,
                                            int& nFinalCurOut, int& nFinalLatchOut,
                                            int& nAsOfEpochOut)
{
    nForkHeightOut = std::numeric_limits<int>::max();
    nFinalCurOut = 0;
    nFinalLatchOut = 0;
    nAsOfEpochOut = 0;
    if (!pindexBest || !pCandidate || pCandidate->pprev == pindexBest ||
        pindexBest->nHeight < FORK_HEIGHT_FINALITY)
        return REORG_FINALITY_ALLOW;
    nForkHeightOut = ForkHeightWithBestChain(pCandidate);
    return CheckReorgAgainstFinality(pindexBest->nHeight, nForkHeightOut,
                                     nFinalCurOut, nFinalLatchOut, nAsOfEpochOut);
}

bool static Reorganize(CTxDB& txdb, CBlockIndex* pindexNew,
                       bool* pfPermanentInvalid, bool* pfChainStateMutated,
                       CBestChainEffectJournal* pCommittedEffects)
{
    if (pfPermanentInvalid)
        *pfPermanentInvalid = false;
    if (pfChainStateMutated)
        *pfChainStateMutated = false;
    printf("REORGANIZE\n");

    {
        // Deterministic-ONLY anchor: the node-local live streak GetFinalizedHeight() must never enter
        // this decision. It can transiently stall below the deterministic value (out-of-order vote
        // arrival resets the consecutive-HARD streak) and it differs between nodes, so folding it in
        // reintroduces path-dependent state into a consensus reorg. Severity is split by anchor age in
        // CheckReorgAgainstFinality so nodes within REORG_LATCH_ANCHOR_LAG_EPOCHS-1 epochs of
        // each other cannot latch pfPermanentInvalid on different reorgs.
        if (pindexBest && pindexBest->nHeight >= FORK_HEIGHT_FINALITY)
        {
            const int nForkHeight = ForkHeightWithBestChain(pindexNew);
            int nFinalCur = 0, nFinalLatch = 0, nAsOfEpoch = 0;
            const ReorgFinalityVerdict verdict = ApplyReorgFinalityGuard(
                pindexBest->nHeight, nForkHeight, pfPermanentInvalid,
                nFinalCur, nFinalLatch, nAsOfEpoch);
            if (verdict == REORG_FINALITY_STATE_MISSING)
                return error("Reorganize() : missing deterministic finalized-height state for "
                             "epoch %d; -reindex/resync required", nAsOfEpoch);
            if (verdict != REORG_FINALITY_ALLOW)
            {
                return error("Reorganize() : rejected - fork point height %d is below finalized "
                             "height %d (latch anchor %d, %s); candidate %s at height %d",
                             nForkHeight, nFinalCur, nFinalLatch,
                             verdict == REORG_FINALITY_REJECT_PERMANENT ? "permanent"
                                                                        : "retryable",
                             pindexNew->GetBlockHash().ToString().substr(0,20).c_str(),
                             pindexNew->nHeight);
            }
        }
    }

    // Find the fork
    CBlockIndex* pfork = pindexBest;
    CBlockIndex* plonger = pindexNew;
    while (pfork != plonger)
    {
        while (plonger->nHeight > pfork->nHeight)
            if (!(plonger = plonger->pprev))
                return error("Reorganize() : plonger->pprev is null");
        if (pfork == plonger)
            break;
        if (!(pfork = pfork->pprev))
            return error("Reorganize() : pfork->pprev is null");
    }

    // List of what to disconnect
    vector<CBlockIndex*> vDisconnect;
    for (CBlockIndex* pindex = pindexBest; pindex != pfork; pindex = pindex->pprev)
        vDisconnect.push_back(pindex);

    // List of what to connect
    vector<CBlockIndex*> vConnect;
    for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
        vConnect.push_back(pindex);
    reverse(vConnect.begin(), vConnect.end());

    printf("REORGANIZE: Disconnect %" PRIszu" blocks; %s..%s\n", vDisconnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), pindexBest->GetBlockHash().ToString().substr(0,20).c_str());
    printf("REORGANIZE: Connect %" PRIszu" blocks; %s..%s\n", vConnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->GetBlockHash().ToString().substr(0,20).c_str());

    // Stage the affected V3 suffix before ConnectBlock; reads through this CTxDB see the
    // active WriteBatch without exposing uncommitted epoch state in the global cache.
    std::map<int, CEpochState> mapStagedEpochStates;
    std::map<int, CCurveTree> mapStagedEpochTrees;
    int nFirstStagedEpoch = -1;
    int nLastV2EpochToStage = -1;
    const int nOldTipHeight = pindexBest ? pindexBest->nHeight : -1;
    const bool fV3EpochReorg =
        nOldTipHeight >= FORK_HEIGHT_EPOCH_STATE_V3 ||
        pindexNew->nHeight >= FORK_HEIGHT_EPOCH_STATE_V3;
    const bool fV2EpochReorg = !fV3EpochReorg &&
        (nOldTipHeight >= FORK_HEIGHT_EPOCH_STATE_V2 ||
         pindexNew->nHeight >= FORK_HEIGHT_EPOCH_STATE_V2);
    if (fV3EpochReorg)
    {
        nFirstStagedEpoch = GetFirstV3EpochStateRebuildEpoch(pfork->nHeight);
        const int nTipEpoch = GetEpochForHeight(pindexNew->nHeight);
        const int nTipEpochEnd =
            GetEpochBoundaryHeight(nTipEpoch + 1, pindexNew->nHeight) - 1;
        const int nLastCompleteEpoch =
            (pindexNew->nHeight >= nTipEpochEnd) ? nTipEpoch : nTipEpoch - 1;

        if (!g_dagManager.EraseEpochStateSuffix(txdb, nFirstStagedEpoch))
            return error("Reorganize() : failed to erase stale epoch-state suffix from epoch %d",
                         nFirstStagedEpoch);
        if (nFirstStagedEpoch <= nLastCompleteEpoch)
        {
            std::string strEpochError;
            if (!StageEpochStateRange(txdb, pindexNew, nFirstStagedEpoch,
                                      nLastCompleteEpoch, mapStagedEpochStates,
                                      mapStagedEpochTrees, strEpochError))
                return error("Reorganize() : V3 epoch suffix build failed: %s",
                             strEpochError.c_str());
        }
        const int nEpochSchema = IsBoundaryBActiveAtHeight(pindexNew->nHeight)
            ? EPOCHSTATE_SCHEMA_V4 : EPOCHSTATE_SCHEMA_V3;
        if (!txdb.WriteEpochStateSchema(nEpochSchema))
            return error("Reorganize() : V3 epoch schema write failed");
    }
    else if (fV2EpochReorg)
    {
        if (!V2CompatReorgStagesEpochRange(nOldTipHeight, pindexNew->nHeight,
                                           pfork->nHeight, nFirstStagedEpoch,
                                           nLastV2EpochToStage))
            return error("Reorganize() : V2 epoch staging range disagreed with the reorg gate");
    }

    // Disconnect shorter branch
    list<CTransaction> vResurrect;
    for (CBlockIndex* pindex : vDisconnect)
    {
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return error("Reorganize() : ReadFromDisk for disconnect failed");
        if (pfChainStateMutated)
            *pfChainStateMutated = true;
        if (!block.DisconnectBlock(txdb, pindex))
            return error("Reorganize() : DisconnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());

        // Queue memory transactions to resurrect.
        // We only do this for blocks after the last checkpoint (reorganisation before that
        // point should only happen with -reindex/-loadblock, or a misbehaving peer.
        BOOST_REVERSE_FOREACH(const CTransaction& tx, block.vtx)
            if (!(tx.IsCoinBase() || tx.IsCoinStake()) && pindex->nHeight > Checkpoints::GetTotalBlocksEstimate())
                vResurrect.push_front(tx);
    }

    // Connect longer branch
    vector<CTransaction> vDelete;
    for (unsigned int i = 0; i < vConnect.size(); i++)
    {
        CBlockIndex* pindex = vConnect[i];
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return error("Reorganize() : ReadFromDisk for connect failed");

        if (!IsInitialBlockDownload()) GetCollateralnodeRanks(pindex); // recalculate ranks for the this block hash if required

        int nReorgV2Epoch = -1;
        if (fV2EpochReorg &&
            V2CompatEpochStagesAtReorgCrossing(pindex->nHeight, nFirstStagedEpoch,
                                               nLastV2EpochToStage, nReorgV2Epoch))
        {
            std::string strEpochError;
            if (!StageV2EpochStateAtCrossing(
                    txdb, pindex, nReorgV2Epoch, nFirstStagedEpoch,
                    mapStagedEpochStates, mapStagedEpochTrees, strEpochError))
                return error("Reorganize() : V2 epoch %d build failed: %s",
                             nReorgV2Epoch, strEpochError.c_str());
        }

        if (pindex->nHeight >= FORK_HEIGHT_EPOCH_STATE_V2)
        {
            const int nAsOfEpoch = GetEpochForHeight(pindex->nHeight) - 1;
            if (!g_dagManager.TryGetDeterministicFinalizedHeight(
                    txdb, nAsOfEpoch, pindex->nFinalizedHeight))
                return error("Reorganize() : staged deterministic finalized-height state "
                             "missing for epoch %d", nAsOfEpoch);
        }

        if (pfChainStateMutated)
            *pfChainStateMutated = true;
        CBlock::ConnectResult connectResult = CBlock::CONNECT_RESULT_INVALID;
        if (!block.ConnectBlock(txdb, pindex, false, true, &connectResult))
        {
            if (pfPermanentInvalid &&
                ConnectResultMayPersistVerdict(connectResult))
                *pfPermanentInvalid = true;
            return error("Reorganize() : ConnectBlock %s failed (%s)",
                         pindex->GetBlockHash().ToString().substr(0,20).c_str(),
                         connectResult == CBlock::CONNECT_RESULT_TRANSIENT
                             ? "local/transient" : "consensus-invalid");
        }

        // Queue memory transactions to delete
        for (const CTransaction& tx : block.vtx)
            vDelete.push_back(tx);
    }

    if (fV2EpochReorg)
    {
        const size_t nExpectedStates = nFirstStagedEpoch <= nLastV2EpochToStage
            ? (size_t)(nLastV2EpochToStage - nFirstStagedEpoch + 1) : 0;
        if (mapStagedEpochStates.size() != nExpectedStates ||
            mapStagedEpochTrees.size() != nExpectedStates)
            return error("Reorganize() : V2 staged suffix is incomplete (%d/%d, expected %d)",
                         (int)mapStagedEpochStates.size(),
                         (int)mapStagedEpochTrees.size(), (int)nExpectedStates);

        // Delete the whole old suffix, then re-append the canonical staged pairs, so a
        // shortening reorg leaves no stale records.
        if (!g_dagManager.EraseEpochStateSuffix(txdb, nFirstStagedEpoch))
            return error("Reorganize() : failed to erase stale V2 suffix from epoch %d",
                         nFirstStagedEpoch);
        for (std::map<int, CEpochState>::const_iterator it =
                 mapStagedEpochStates.begin();
             it != mapStagedEpochStates.end(); ++it)
        {
            std::map<int, CCurveTree>::const_iterator itTree =
                mapStagedEpochTrees.find(it->first);
            if (itTree == mapStagedEpochTrees.end() ||
                !g_dagManager.WriteEpochState(txdb, it->second, itTree->second))
                return error("Reorganize() : V2 suffix rewrite failed for epoch %d",
                             it->first);
        }
        if (!txdb.WriteEpochStateSchema(EPOCHSTATE_SCHEMA_V2))
            return error("Reorganize() : V2 epoch schema write failed");
    }

    // The new branch's DAG vertices and all changed parent child-lists share the
    // disconnect/connect/best-chain transaction. This also covers the newest block,
    // whose eager AddToBlockIndex DAG write is deferred when it can become best.
    for (std::vector<CBlockIndex*>::const_iterator bit = vConnect.begin();
         bit != vConnect.end(); ++bit)
    {
        CBlockIndex* pindex = *bit;
        if (!pindex || pindex->nHeight < FORK_HEIGHT_DAG || !pindex->phashBlock)
            continue;
        CBlockDAGData dagData;
        const uint256 hashBlock = pindex->GetBlockHash();
        if (!g_dagManager.GetDAGData(hashBlock, dagData) ||
            !g_dagManager.WriteDAGLinks(txdb, hashBlock))
            return error("Reorganize() : DAG link write failed for %s",
                         hashBlock.ToString().substr(0,20).c_str());
        for (std::vector<uint256>::const_iterator pit = dagData.vDAGParents.begin();
             pit != dagData.vDAGParents.end(); ++pit)
        {
            if (g_dagManager.HasDAGData(*pit) && !g_dagManager.WriteDAGLinks(txdb, *pit))
                return error("Reorganize() : parent DAG link write failed for %s",
                             pit->ToString().substr(0,20).c_str());
        }
    }

    if (nFirstStagedEpoch >= 0 &&
        !g_dagManager.ValidateEpochStateBatch(nFirstStagedEpoch,
                                              mapStagedEpochStates,
                                              mapStagedEpochTrees))
        return error("Reorganize() : staged epoch suffix failed pre-commit validation");
    if (!pCommittedEffects || !pCommittedEffects->IsEmpty() ||
        !pCommittedEffects->PrepareReorg(txdb, vDisconnect, vConnect,
                                         pindexNew))
        return error("Reorganize() : could not prebuild committed effect batch");
    if (!txdb.WriteShieldedWalletRecovery(
            pCommittedEffects->GetRecoveryRecord()))
    {
        pCommittedEffects->Clear();
        return error("Reorganize() : shielded-wallet recovery outbox write failed");
    }
    if (!txdb.WriteDAGActiveSetBest(pindexNew->GetBlockHash()))
    {
        pCommittedEffects->Clear();
        return error("Reorganize() : DAG active-set best-tip write failed");
    }
    if (!txdb.WriteHashBestChain(pindexNew->GetBlockHash()))
    {
        pCommittedEffects->Clear();
        return error("Reorganize() : WriteHashBestChain failed");
    }

    // Make sure it's successfully written to disk before changing memory structure
    if (!txdb.TxnCommit(true))
    {
        pCommittedEffects->Clear();
        return error("Reorganize() : TxnCommit failed");
    }

    // The effect batch and its final wallet locator were fully allocated before
    // commit.  Marking it durable cannot allocate or throw.
    pCommittedEffects->MarkCommitted();

    RefreshCommittedShieldedPoolOrShutdown(txdb, pindexNew, "Reorganize()");

    if (nFirstStagedEpoch >= 0 &&
        !g_dagManager.InstallEpochStateBatch(nFirstStagedEpoch, mapStagedEpochStates,
                                             mapStagedEpochTrees))
    {
        printf("Reorganize() : FATAL committed epoch suffix failed impossible "
               "post-commit install; publishing durable best and shutting down for restart\n");
        PublishDurablyCommittedBest(pindexNew);
        StartShutdown();
    }

    // Clear setStakeSeen so disconnected stakes don't block the new branch
    for (CBlockIndex* pindex : vDisconnect)
    {
        if (pindex->IsProofOfStake())
            setStakeSeen.erase(make_pair(pindex->prevoutStake, pindex->nStakeTime));
    }

    // Accepted DAG blocks remain part of the DAG across a best-chain reorg. Erasing the
    // disconnected branch made restart/order depend on which branch happened to be best first.

    // Disconnect shorter branch
    for (CBlockIndex* pindex : vDisconnect)
        if (pindex->pprev)
            pindex->pprev->pnext = NULL;

    // Connect longer branch
    for (CBlockIndex* pindex : vConnect)
        if (pindex->pprev)
            pindex->pprev->pnext = pindex;

    // Resurrect memory transactions, re-validate shielded anchors
    for (CTransaction& tx : vResurrect)
    {
        if (tx.IsShielded())
        {
            bool fValidAnchors = true;
            for (const CShieldedSpendDescription& spend : tx.vShieldedSpend)
            {
                if (!txdb.ReadShieldedAnchor(spend.anchor))
                {
                    fValidAnchors = false;
                    if (fDebug)
                        printf("Reorganize() : dropping shielded tx %s - anchor %s no longer valid\n",
                               tx.GetHash().ToString().substr(0,10).c_str(),
                               spend.anchor.ToString().substr(0,10).c_str());
                    break;
                }
            }
            if (!fValidAnchors)
                continue; // Don't resurrect this tx - anchors are invalid
        }
        tx.AcceptToMemoryPool(txdb);
    }

    // Delete redundant memory transactions that are in the connected branch
    for (CTransaction& tx : vDelete) {
        mempool.remove(tx);
        mempool.removeConflicts(tx);
    }

    CollateralNReorgBlock = true;
    printf("REORGANIZE: done\n");

    return true;
}


// Called from inside SetBestChain: attaches a block to the new best chain being built
bool CBlock::SetBestChainInner(CTxDB& txdb, CBlockIndex *pindexNew,
                               bool* pfPermanentInvalid,
                               CBestChainEffectJournal* pCommittedEffects)
{
    uint256 hash = GetHash();
    std::map<int, CEpochState> mapStagedEpochStates;
    std::map<int, CCurveTree> mapStagedEpochTrees;
    int nFirstStagedEpoch = -1;

    // V2 commits the completed epoch at the first block of the next epoch, inside this
    // best-chain transaction; the cache is published only after commit.
    int nBestChainV2Epoch = -1;
    if (V2CompatEpochStagesAtBestChainCrossing(pindexNew->nHeight, nBestChainV2Epoch))
    {
        if (!g_dagManager.EraseEpochStateSuffix(txdb, nBestChainV2Epoch))
        {
            txdb.TxnAbort();
            return error("SetBestChainInner() : failed to erase stale V2 suffix at epoch %d",
                         nBestChainV2Epoch);
        }
        std::string strEpochError;
        if (!StageV2EpochStateAtCrossing(
                txdb, pindexNew, nBestChainV2Epoch, nBestChainV2Epoch,
                mapStagedEpochStates, mapStagedEpochTrees, strEpochError))
        {
            txdb.TxnAbort();
            return error("SetBestChainInner() : V2 epoch %d build failed: %s",
                         nBestChainV2Epoch, strEpochError.c_str());
        }
        if (!txdb.WriteEpochStateSchema(EPOCHSTATE_SCHEMA_V2))
        {
            txdb.TxnAbort();
            return error("SetBestChainInner() : V2 epoch schema write failed");
        }
        nFirstStagedEpoch = nBestChainV2Epoch;
    }

    // At the activation block, build the V3 migration base for the preceding epoch with the
    // exact-boundary builder into this WriteBatch; the global cache changes only on commit.
    if (pindexNew->nHeight == FORK_HEIGHT_EPOCH_STATE_V3)
    {
        const int nMigrationEpoch = GetEpochForHeight(pindexNew->nHeight) - 1;
        const int nMigrationEnd =
            GetEpochBoundaryHeight(nMigrationEpoch + 1, pindexNew->nHeight) - 1;
        if (!pindexNew->pprev || pindexNew->pprev->nHeight != nMigrationEnd)
        {
            txdb.TxnAbort();
            return error("SetBestChainInner() : missing exact V3 migration boundary at height %d",
                         nMigrationEnd);
        }
        if (!g_dagManager.EraseEpochStateSuffix(txdb, nMigrationEpoch))
        {
            txdb.TxnAbort();
            return error("SetBestChainInner() : failed to erase migration-base suffix");
        }
        std::string strEpochError;
        if (!StageEpochStateRange(txdb, pindexNew->pprev, nMigrationEpoch,
                                  nMigrationEpoch, mapStagedEpochStates,
                                  mapStagedEpochTrees, strEpochError))
        {
            txdb.TxnAbort();
            return error("SetBestChainInner() : V3 migration-base build failed: %s",
                         strEpochError.c_str());
        }
        nFirstStagedEpoch = nMigrationEpoch;
    }

    if (pindexNew->nHeight >= FORK_HEIGHT_EPOCH_STATE_V2)
    {
        const int nAsOfEpoch = GetEpochForHeight(pindexNew->nHeight) - 1;
        if (!g_dagManager.TryGetDeterministicFinalizedHeight(
                txdb, nAsOfEpoch, pindexNew->nFinalizedHeight))
        {
            txdb.TxnAbort();
            return error("SetBestChainInner() : missing staged deterministic finalized-height "
                         "state for epoch %d", nAsOfEpoch);
        }
    }

    // ConnectBlock classifies deterministic invalidity separately from local
    // read/write/resource failure.  Only the former may poison the block index.
    ConnectResult connectResult = CONNECT_RESULT_INVALID;
    if (!ConnectBlock(txdb, pindexNew, false, true, &connectResult))
    {
        txdb.TxnAbort();
        RestoreCommittedFinalityOrShutdown("SetBestChainInner()");
        if (ConnectResultMayPersistVerdict(connectResult))
        {
            InvalidChainFound(pindexNew);
            if (pfPermanentInvalid)
                *pfPermanentInvalid = true;
        }
        return false;
    }

    // Persist the accepted DAG vertex and changed parent child-lists in the same
    // transaction as the best-chain pointer. AddToBlockIndex deliberately defers
    // these writes for a candidate that is about to become best.
    if (pindexNew->nHeight >= FORK_HEIGHT_DAG)
    {
        CBlockDAGData dagData;
        if (!g_dagManager.GetDAGData(hash, dagData) ||
            !g_dagManager.WriteDAGLinks(txdb, hash))
        {
            txdb.TxnAbort();
            RestoreCommittedFinalityOrShutdown("SetBestChainInner()");
            return error("SetBestChainInner() : DAG link write failed for %s",
                         hash.ToString().substr(0,20).c_str());
        }
        for (std::vector<uint256>::const_iterator it = dagData.vDAGParents.begin();
             it != dagData.vDAGParents.end(); ++it)
        {
            if (g_dagManager.HasDAGData(*it) && !g_dagManager.WriteDAGLinks(txdb, *it))
            {
                txdb.TxnAbort();
                RestoreCommittedFinalityOrShutdown("SetBestChainInner()");
                return error("SetBestChainInner() : parent DAG link write failed for %s",
                             it->ToString().substr(0,20).c_str());
            }
        }
    }

    // Complete a V3 epoch on its exact final block. Build into locals, write the
    // state/tree/schema into this active best-chain batch, and expose it in memory
    // only after TxnCommit succeeds below.
    if (pindexNew->nHeight >= FORK_HEIGHT_EPOCH_STATE_V3)
    {
        const int nEpoch = GetEpochForHeight(pindexNew->nHeight);
        const int nEpochEnd = GetEpochBoundaryHeight(nEpoch + 1, pindexNew->nHeight) - 1;
        if (pindexNew->nHeight == nEpochEnd)
        {
            if (!g_dagManager.EraseEpochStateSuffix(txdb, nEpoch))
            {
                txdb.TxnAbort();
                RestoreCommittedFinalityOrShutdown("SetBestChainInner()");
                return error("SetBestChainInner() : failed to erase stale V3 suffix at epoch %d",
                             nEpoch);
            }
            std::string strEpochError;
            bool fEpochOk;
            {
                BLOCK_PHASE(BP_EPOCH_BUILD);
                fEpochOk = StageEpochStateRange(txdb, pindexNew, nEpoch, nEpoch,
                                                mapStagedEpochStates, mapStagedEpochTrees,
                                                strEpochError);
            }
            if (!fEpochOk)
            {
                txdb.TxnAbort();
                RestoreCommittedFinalityOrShutdown("SetBestChainInner()");
                return error("SetBestChainInner() : V3 epoch %d build failed: %s",
                             nEpoch, strEpochError.c_str());
            }
            nFirstStagedEpoch = nEpoch;
        }
        const int nEpochSchema = IsBoundaryBActiveAtHeight(pindexNew->nHeight)
            ? EPOCHSTATE_SCHEMA_V4 : EPOCHSTATE_SCHEMA_V3;
        if (!txdb.WriteEpochStateSchema(nEpochSchema))
        {
            txdb.TxnAbort();
            RestoreCommittedFinalityOrShutdown("SetBestChainInner()");
            return error("SetBestChainInner() : V3 epoch schema write failed");
        }
    }
    if (nFirstStagedEpoch >= 0 &&
        !g_dagManager.ValidateEpochStateBatch(nFirstStagedEpoch,
                                              mapStagedEpochStates,
                                              mapStagedEpochTrees))
    {
        txdb.TxnAbort();
        RestoreCommittedFinalityOrShutdown("SetBestChainInner()");
        return error("SetBestChainInner() : staged epoch suffix failed pre-commit validation");
    }
    if (!pCommittedEffects || !pCommittedEffects->IsEmpty() ||
        !pCommittedEffects->PrepareConnect(txdb, pindexNew))
    {
        txdb.TxnAbort();
        RestoreCommittedFinalityOrShutdown("SetBestChainInner()");
        return error("SetBestChainInner() : could not prebuild committed effect batch");
    }
    if (!txdb.WriteShieldedWalletRecovery(
            pCommittedEffects->GetRecoveryRecord()))
    {
        pCommittedEffects->Clear();
        txdb.TxnAbort();
        RestoreCommittedFinalityOrShutdown("SetBestChainInner()");
        return error("SetBestChainInner() : shielded-wallet recovery outbox write failed");
    }
    if (!txdb.WriteDAGActiveSetBest(hash))
    {
        pCommittedEffects->Clear();
        txdb.TxnAbort();
        RestoreCommittedFinalityOrShutdown("SetBestChainInner()");
        return error("SetBestChainInner() : DAG active-set best-tip write failed");
    }
    if (!txdb.WriteHashBestChain(hash))
    {
        pCommittedEffects->Clear();
        txdb.TxnAbort();
        RestoreCommittedFinalityOrShutdown("SetBestChainInner()");
        return error("SetBestChainInner() : WriteHashBestChain failed");
    }
    bool fCommitOk;
    {
        BLOCK_PHASE(BP_DB_COMMIT);
        fCommitOk = txdb.TxnCommit(true);
    }
    if (!fCommitOk)
    {
        pCommittedEffects->Clear();
        RestoreCommittedFinalityOrShutdown("SetBestChainInner()");
        return error("SetBestChain() : TxnCommit failed");
    }

    pCommittedEffects->MarkCommitted();

    RefreshCommittedShieldedPoolOrShutdown(txdb, pindexNew,
                                            "SetBestChainInner()");

    if (nFirstStagedEpoch >= 0 &&
        !g_dagManager.InstallEpochStateBatch(nFirstStagedEpoch, mapStagedEpochStates,
                                             mapStagedEpochTrees))
    {
        printf("SetBestChainInner() : FATAL committed epoch suffix failed impossible "
               "post-commit install; publishing durable best and shutting down for restart\n");
        PublishDurablyCommittedBest(pindexNew);
        StartShutdown();
    }

    if (pindexNew->pprev)
        pindexNew->pprev->pnext = pindexNew;

    // Delete redundant memory transactions
    for (CTransaction& tx : vtx)
        mempool.remove(tx);

    // Remove txs from DAG sibling blocks
    if (pindexNew->nHeight >= FORK_HEIGHT_DAG)
    {
        std::set<uint256> siblings = g_dagManager.GetDAGSiblingBlocks(hash);
        for (const uint256& hashSibling : siblings)
            mempool.RemoveDAGConflicts(hashSibling);
    }

    return true;
}

bool CBlock::SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew, bool* pfPermanentInvalid)
{
    BLOCK_PHASE(BP_SETBESTCHAIN);
    if (pfPermanentInvalid) *pfPermanentInvalid = false;
    const bool fIsInitialDownload = IsInitialBlockDownload();
    uint256 hash = GetHash();
    CBestChainEffectJournal committedEffects;
    CShieldedWalletRecoveryRecord pendingRecovery;
    const TxDBReadStatus pendingRecoveryStatus =
        txdb.ReadShieldedWalletRecoveryStatus(pendingRecovery);
    if (pendingRecoveryStatus == TXDB_READ_ERROR)
        return error("SetBestChain() : shielded-wallet recovery outbox is corrupt; restart for recovery or -reindex/resync");
    if (pendingRecoveryStatus == TXDB_READ_FOUND)
        return error("SetBestChain() : shielded-wallet recovery is still pending; refusing a later chain transition");
    if (!txdb.TxnBegin())
        return error("SetBestChain() : TxnBegin failed");

    if (pindexGenesisBlock == NULL && hash == GetGenesisBlockHash())
    {
        if (!committedEffects.PrepareConnect(txdb, pindexNew))
        {
            txdb.TxnAbort();
            return error("SetBestChain() : could not prebuild genesis effect batch");
        }
        if (!txdb.WriteShieldedWalletRecovery(
                committedEffects.GetRecoveryRecord()))
        {
            committedEffects.Clear();
            txdb.TxnAbort();
            return error("SetBestChain() : genesis shielded-wallet recovery outbox write failed");
        }
        if (!txdb.WriteDAGActiveSetBest(hash))
        {
            committedEffects.Clear();
            txdb.TxnAbort();
            return error("SetBestChain() : genesis DAG active-set best-tip write failed");
        }
        if (!txdb.WriteHashBestChain(hash))
        {
            committedEffects.Clear();
            txdb.TxnAbort();
            return error("SetBestChain() : genesis WriteHashBestChain failed");
        }
        if (!txdb.TxnCommit(true))
        {
            committedEffects.Clear();
            return error("SetBestChain() : genesis TxnCommit failed");
        }
        committedEffects.MarkCommitted();
        RefreshCommittedShieldedPoolOrShutdown(txdb, pindexNew,
                                                "SetBestChain(genesis)");
        pindexGenesisBlock = pindexNew;
    }
    else if (hashPrevBlock == hashBestChain)
    {
        if (!SetBestChainInner(txdb, pindexNew, pfPermanentInvalid,
                               &committedEffects))
            return error("SetBestChain() : SetBestChainInner failed");
    }
    else
    {
        {
            // Same guard as Reorganize, same shared decision: a sub-finalized reorg can never
            // re-anchor a finalized epoch's roots. Deterministic-ONLY -- never mix the node-local
            // live finalized height in. Only a fork below the LAGGED anchor is condemned
            // permanently, because that is the only verdict every node within the tolerated
            // skew agrees on; inside the band the block is rejected but left re-requestable.
            if (pindexBest && pindexBest->nHeight >= FORK_HEIGHT_FINALITY)
            {
                {
                    const int nForkHeight = ForkHeightWithBestChain(pindexNew);
                    int nFinalCur = 0, nFinalLatch = 0, nAsOfEpoch = 0;
                    const ReorgFinalityVerdict verdict = ApplyReorgFinalityGuard(
                        pindexBest->nHeight, nForkHeight, pfPermanentInvalid,
                        nFinalCur, nFinalLatch, nAsOfEpoch);
                    if (verdict == REORG_FINALITY_STATE_MISSING)
                    {
                        txdb.TxnAbort();
                        return error("SetBestChain() : missing deterministic finalized-height state "
                                     "for epoch %d; -reindex/resync required", nAsOfEpoch);
                    }
                    if (verdict != REORG_FINALITY_ALLOW)
                    {
                        txdb.TxnAbort();
                        return error("SetBestChain() : rejected reorg - fork height %d below "
                                     "finalized height %d (latch anchor %d, %s); candidate %s "
                                     "at height %d",
                                     nForkHeight, nFinalCur, nFinalLatch,
                                     verdict == REORG_FINALITY_REJECT_PERMANENT ? "permanent"
                                                                                : "retryable",
                                     pindexNew->GetBlockHash().ToString().substr(0,20).c_str(),
                                     pindexNew->nHeight);
                    }
                }
            }
        }

        // the first block in the new chain that will cause it to become the new best chain
        CBlockIndex *pindexIntermediate = pindexNew;

        // list of blocks that need to be connected afterwards
        std::vector<CBlockIndex*> vpindexSecondary;

        // Reorganize is costly in terms of db load, as it works in a single db transaction.
        // Try to limit how much needs to be done inside
        while (pindexIntermediate->pprev && pindexIntermediate->pprev->nChainTrust > pindexBest->nChainTrust)
        {
            vpindexSecondary.push_back(pindexIntermediate);
            pindexIntermediate = pindexIntermediate->pprev;
        }

        if (!vpindexSecondary.empty())
            printf("Postponing %" PRIszu" reconnects\n", vpindexSecondary.size());

        // Switch to new best branch
        bool fReorgPermanentInvalid = false;
        bool fReorgChainStateMutated = false;
        if (!Reorganize(txdb, pindexIntermediate, &fReorgPermanentInvalid,
                        &fReorgChainStateMutated, &committedEffects))
        {
            txdb.TxnAbort();
            if (fReorgChainStateMutated)
                RestoreCommittedFinalityOrShutdown("SetBestChain()/Reorganize");
            if (fReorgPermanentInvalid)
            {
                InvalidChainFound(pindexNew);
                if (pfPermanentInvalid) *pfPermanentInvalid = true;
            }
            return error("SetBestChain() : Reorganize failed");
        }

        CBlockIndex* pindexCommittedBest = pindexIntermediate;
        if (!PublishAndReplayCommittedEffects(
                txdb, pindexCommittedBest, committedEffects,
                "SetBestChain()/Reorganize"))
        {
            printf("SetBestChain: reorganization is durable at height %d, but "
                   "post-commit recovery is required; suppressing later reconnects\n",
                   pindexCommittedBest->nHeight);
            return true;
        }

        // Connect further blocks
        BOOST_REVERSE_FOREACH(CBlockIndex *pindex, vpindexSecondary)
        {
            CBlock block;
            if (!block.ReadFromDisk(pindex))
            {
                printf("SetBestChain() : ReadFromDisk failed\n");
                break;
            }
            if (!txdb.TxnBegin()) {
                printf("SetBestChain() : TxnBegin 2 failed\n");
                break;
            }
            // errors now are not fatal, we still did a reorganisation to a new chain in a valid way
            if (!block.SetBestChainInner(txdb, pindex, NULL,
                                         &committedEffects))
                break;
            pindexCommittedBest = pindex;
            if (!PublishAndReplayCommittedEffects(
                    txdb, pindexCommittedBest, committedEffects,
                    "SetBestChain()/postponed reconnect"))
            {
                printf("SetBestChain: postponed reconnect is durable at height %d, "
                       "but post-commit recovery is required; suppressing later reconnects\n",
                       pindexCommittedBest->nHeight);
                return true;
            }
        }

        // A postponed reconnect may fail after the reorg transaction has already
        // committed. Publish only the last actually committed tip; advertising the
        // original pindexNew here made memory/wallet state outrun hashBestChain on disk.
        if (pindexCommittedBest != pindexNew)
        {
            printf("SetBestChain() : stopped postponed reconnects at committed height %d\n",
                   pindexCommittedBest->nHeight);
            pindexNew = pindexCommittedBest;
            hash = pindexNew->GetBlockHash();
        }


    }

    // Linear and genesis paths still have their single prebuilt batch here.
    // Reorg and postponed-reconnect batches were applied immediately above.
    {
        BLOCK_PHASE(BP_EFFECTS);
        if (!committedEffects.IsEmpty() &&
            !PublishAndReplayCommittedEffects(txdb, pindexNew, committedEffects,
                                              "SetBestChain()"))
        {
            printf("SetBestChain: durable tip published, but auxiliary post-commit "
                   "effects are incomplete; suppressing further notifications while "
                   "shutdown proceeds\n");
            return true;
        }
    }

    uint256 nBestBlockTrust = (pindexBest->nHeight != 0 && pindexBest->pprev != NULL) ? (pindexBest->nChainTrust - pindexBest->pprev->nChainTrust) : pindexBest->nChainTrust;

    printf("SetBestChain: new best=%s  height=%d  trust=%s  blocktrust=%" PRId64"  date=%s\n",
      hashBestChain.ToString().substr(0,20).c_str(), nBestHeight,
      CBigNum(nBestChainTrust).ToString().c_str(),
      nBestBlockTrust.Get64(),
      DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());

    nTimeBestReceived = GetTime();

    if (IsBoundaryBActiveAtHeight(nBestHeight))
    {
      const int nStoreEpoch = GetEpochForHeight(nBestHeight) - 1;

      // Keep the derived IV5 tree store level with the epoch chain; a failure is reported and
      // retried on the next block, never failing the tip.
      if (!fIsInitialDownload)
      {
        // An anchor that has aged out of the window can never come back, so the
        // transaction holding it is unminable and only occupies the pool.
        {
            std::vector<CTransaction> vStaleAnchors;
            {
                LOCK(mempool.cs);
                for (std::map<uint256, CTransaction>::const_iterator it =
                         mempool.mapTx.begin();
                     it != mempool.mapTx.end(); ++it)
                {
                    if (!it->second.IsPrivacyVNext())
                        continue;
                    std::string strAnchorError;
                    if (!CheckPrivacyVNextFinalizedAnchor(
                            txdb, nBestHeight + 1, it->second, strAnchorError))
                        vStaleAnchors.push_back(it->second);
                }
            }
            for (size_t i = 0; i < vStaleAnchors.size(); ++i)
            {
                printf("SetBestChain: evicting IV5 tx %s, anchor is outside the "
                       "window at height %d\n",
                       vStaleAnchors[i].GetHash().ToString().substr(0,10).c_str(),
                       nBestHeight + 1);
                mempool.remove(vStaleAnchors[i]);
            }
        }

        std::string strStoreError;
        BLOCK_PHASE(BP_IV5_TREE);
        if (!SyncPrivacyVNextTreeStore(txdb, nStoreEpoch, strStoreError))
            printf("SetBestChain: IV5 tree store did not reach epoch %d: %s\n",
                   nStoreEpoch, strStoreError.c_str());
      }

      // Assign leaf indices even during initial download: an epoch passed unassigned is never
      // revisited. Wallet bookkeeping must not fail the tip.
      if (!IsPrivacyVNextLeafIndexAssignmentHeld())
      {
        LOCK(cs_setpwalletRegistered);
        for (CWallet* pwallet : setpwalletRegistered)
        {
            std::string strWalletError;
            if (!pwallet->AssignPrivacyVNextLeafIndices(nStoreEpoch, strWalletError))
                printf("SetBestChain: IV5 wallet leaf indices through epoch %d: %s\n",
                       nStoreEpoch, strWalletError.c_str());
        }
      }
    }

    // Check the version of the last 100 blocks to see if we need to upgrade:
    if (!fIsInitialDownload)
    {
        int nUpgraded = 0;
        const CBlockIndex* pindex = pindexBest;
        for (int i = 0; i < 100 && pindex != NULL; i++)
        {
            if (pindex->nVersion > CBlock::CURRENT_VERSION)
                ++nUpgraded;
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0)
            printf("SetBestChain: %d of last 100 blocks above version %d\n", nUpgraded, CBlock::CURRENT_VERSION);
        if (nUpgraded > 100/2)
            // strMiscWarning is read by GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
            strMiscWarning = _("Warning: This version is obsolete, upgrade required!");
    }

    std::string strCmd = GetArg("-blocknotify", "");

    if (!fIsInitialDownload && !strCmd.empty())
    {
        boost::replace_all(strCmd, "%s", hashBestChain.GetHex());
        boost::thread t(runCommand, strCmd); // thread runs free
    }

    return true;
}

// ppcoin: total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.
bool CTransaction::GetCoinAge(CTxDB& txdb, uint64_t& nCoinAge) const
{
    CBigNum bnCentSecond = 0;  // coin age in the unit of cent-seconds
    nCoinAge = 0;

    if (IsCoinBase())
        return true;

    for (const CTxIn& txin : vin)
    {
        // First try finding the previous transaction in database
        CTransaction txPrev;
        CTxIndex txindex;
        if (!txPrev.ReadFromDisk(txdb, txin.prevout, txindex))
            continue;  // previous transaction not in main chain
        if (nTime < txPrev.nTime)
            return false;  // Transaction timestamp violation

        // Read block header
        CBlock block;
        if (!block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
            return false; // unable to read block of previous transaction
        if (block.GetBlockTime() + nStakeMinAge > nTime)
            continue; // only count coins meeting min age requirement

        int64_t nValueIn = txPrev.vout[txin.prevout.n].nValue;
        // Cap coin age to 1 year (post-fork only)
        int64_t nTimeDiff = nTime - txPrev.nTime;
        if (nBestHeight >= FORK_HEIGHT_TIGHTER_DRIFT && nTimeDiff > 365 * 24 * 60 * 60)
            nTimeDiff = 365 * 24 * 60 * 60;
        bnCentSecond += CBigNum(nValueIn) * nTimeDiff / CENT;

        if (fDebug && GetBoolArg("-printcoinage"))
            printf("coin age nValueIn=%" PRId64" nTimeDiff=%d bnCentSecond=%s\n", nValueIn, nTime - txPrev.nTime, bnCentSecond.ToString().c_str());
    }

    CBigNum bnCoinDay = bnCentSecond * CENT / COIN / (24 * 60 * 60);
    if (fDebug && GetBoolArg("-printcoinage"))
        printf("coin age bnCoinDay=%s\n", bnCoinDay.ToString().c_str());
    nCoinAge = bnCoinDay.getuint64();
    return true;
}

// ppcoin: total coin age spent in block, in the unit of coin-days.
bool CBlock::GetCoinAge(uint64_t& nCoinAge) const
{
    nCoinAge = 0;

    CTxDB txdb("r");
    for (const CTransaction& tx : vtx)
    {
        uint64_t nTxCoinAge;
        if (tx.GetCoinAge(txdb, nTxCoinAge))
            nCoinAge += nTxCoinAge;
        else
            return false;
    }

    if (nCoinAge == 0) // block coin age minimum 1 coin-day
        nCoinAge = 1;
    if (fDebug && GetBoolArg("-printcoinage"))
        printf("block coin age total nCoinDays=%" PRId64"\n", nCoinAge);
    return true;
}

// ---------------------------------------------------------------------------
// Block-index invalidation / best-valid-chain reselection (invalidateblock RPC).
// All three assume cs_main is held (the RPCs run unlocked=false -> LOCK2(cs_main, wallet)).
// ---------------------------------------------------------------------------

// Switch to the highest-trust non-invalid block that has block data on disk, if it beats the current
// tip. Mirrors the native selection rule (nChainTrust > nBestChainTrust), which also excludes interior
// best-chain nodes. Used by both invalidateblock (after rollback) and reconsiderblock.
static bool ReselectBestValidChain(CTxDB& txdb)
{
    // Every index that beats the tip, heaviest first, with the same tie-break as the
    // DAG tip selection. The first one this node may switch to is taken; a heavier
    // index whose fork lies below the finality anchor is passed over, not attempted.
    std::vector<CBlockIndex*> vCandidates;
    for (map<uint256, CBlockIndex*>::iterator it = mapBlockIndex.begin(); it != mapBlockIndex.end(); ++it)
    {
        CBlockIndex* p = it->second;
        if (!p || p->IsInvalid() || p->nChainTrust <= nBestChainTrust)
            continue;
        if (p->nFile == 0 && p->nBlockPos == 0 && p != pindexGenesisBlock)
            continue; // header-only / no block data -> cannot be connected
        if (p->nHeight >= FORK_HEIGHT_DAG && !p->IsProofOfStake() &&
            !g_dagManager.HasDAGData(p->GetBlockHash()))
            continue; // no vertex: its trust is not comparable to the DAG-scored tips
        vCandidates.push_back(p);
    }
    std::sort(vCandidates.begin(), vCandidates.end(),
              [](const CBlockIndex* a, const CBlockIndex* b) {
                  if (a->nChainTrust != b->nChainTrust)
                      return a->nChainTrust > b->nChainTrust;
                  if (a->nHeight != b->nHeight)
                      return a->nHeight > b->nHeight;
                  return a->GetBlockHash() < b->GetBlockHash();
              });
    for (size_t i = 0; i < vCandidates.size(); i++)
    {
        CBlockIndex* pbest = vCandidates[i];
        int nForkHeight = 0, nFinalCur = 0, nFinalLatch = 0, nAsOfEpoch = 0;
        const ReorgFinalityVerdict switchVerdict = BestChainSwitchVerdict(
            pbest, nForkHeight, nFinalCur, nFinalLatch, nAsOfEpoch);
        if (switchVerdict == REORG_FINALITY_STATE_MISSING)
            return error("ReselectBestValidChain() : missing deterministic finalized-height state "
                         "for epoch %d; resync required", nAsOfEpoch);
        if (switchVerdict != REORG_FINALITY_ALLOW)
        {
            printf("ReselectBestValidChain() : %s at height %d outweighs the tip but forks at %d "
                   "below finalized height %d; passed over\n",
                   pbest->GetBlockHash().ToString().substr(0,20).c_str(), pbest->nHeight,
                   nForkHeight, nFinalCur);
            continue;
        }
        CBlock block;
        if (!block.ReadFromDisk(pbest))
            return error("ReselectBestValidChain() : ReadFromDisk failed for %s",
                         pbest->GetBlockHash().ToString().substr(0,20).c_str());
        return block.SetBestChain(txdb, pbest);
    }
    return true; // nothing switchable beats the current tip -> no-op
}

// pindex first, then every descendant whose flag state an invalidate (unflagged) or a
// reconsider (flagged) would change. O(N * depth-from-target); fine for an admin RPC.
static void CollectFailedSubtree(CBlockIndex* pindex, bool fInvalidate, std::vector<CBlockIndex*>& vOut)
{
    vOut.push_back(pindex);
    for (map<uint256, CBlockIndex*>::iterator it = mapBlockIndex.begin(); it != mapBlockIndex.end(); ++it)
    {
        CBlockIndex* p = it->second;
        if (!p || p == pindex)
            continue;
        if (fInvalidate ? p->IsInvalid() : !p->IsInvalid())
            continue;
        for (CBlockIndex* q = p->pprev; q && q->nHeight >= pindex->nHeight; q = q->pprev)
        {
            if (q == pindex)
            {
                vOut.push_back(p);
                break;
            }
        }
    }
}

// Taint pindex (BLOCK_FAILED_VALID) and every descendant (BLOCK_FAILED_CHILD), or clear both.
// Collects the changed indexes for persistence.
static void MarkFailedSubtree(CBlockIndex* pindex, bool fInvalidate, std::vector<CBlockIndex*>& vChanged)
{
    CollectFailedSubtree(pindex, fInvalidate, vChanged);
    for (size_t i = 0; i < vChanged.size(); i++)
    {
        if (!fInvalidate)
            vChanged[i]->ClearFailed();
        else if (i == 0)
            vChanged[i]->SetFailedValid();
        else
            vChanged[i]->SetFailedChild();
    }
}

// A retained post-DAG PoW index must carry its DAG vertex; clearing the flag of one
// without it would leave a state LoadDAGLinks refuses, so refuse with nothing changed.
static bool SubtreeHasDAGVertices(const std::vector<CBlockIndex*>& vIndexes, std::string& strError)
{
    const int nPrunedBelow = g_dagManager.GetPrunedBelowHeight();
    for (size_t i = 0; i < vIndexes.size(); i++)
    {
        const CBlockIndex* p = vIndexes[i];
        if (p->nHeight < FORK_HEIGHT_DAG || p->nHeight < nPrunedBelow || p->IsProofOfStake())
            continue;
        if (!g_dagManager.HasDAGData(p->GetBlockHash()))
        {
            strError = strprintf("block %s at height %d has no DAG vertex; restart the node to "
                                 "rebuild it from disk, then retry",
                                 p->GetBlockHash().ToString().c_str(), p->nHeight);
            return false;
        }
    }
    return true;
}

// Mark a block permanently invalid, roll the active chain back off it if present, re-select the best
// valid chain. Returns false (with strError) if a finality guard forbids the rollback.
bool InvalidateBlock(CTxDB& txdb, CBlockIndex* pindex, std::string& strError)
{
    VerifyProofCacheClear();
    ClearPrivacyVNextEffectsCache();
    if (!pindex)
        { strError = "null block index"; return false; }
    if (pindex == pindexGenesisBlock)
        { strError = "cannot invalidate the genesis block"; return false; }

    std::vector<CBlockIndex*> vChanged;
    MarkFailedSubtree(pindex, true, vChanged);

    // If it is on the active chain, roll the tip back to its parent (ancestor target -> Reorganize
    // pure-rollback, exactly as setbestblockbyheight relies on). Finality guards may reject this.
    if (pindex->IsInMainChain() && pindex->pprev)
    {
        CBlock block;
        if (!block.ReadFromDisk(pindex->pprev))
            { strError = "ReadFromDisk failed for parent of invalidated block"; return false; }
        if (!block.SetBestChain(txdb, pindex->pprev))
            { strError = "rollback rejected (a finality guard may forbid invalidating a finalized-or-lower block)"; return false; }
    }

    InvalidChainFound(pindex);

    if (txdb.TxnBegin())
    {
        for (size_t i = 0; i < vChanged.size(); i++)
            txdb.WriteBlockIndex(CDiskBlockIndex(vChanged[i]));
        txdb.TxnCommit();
    }

    if (!ReselectBestValidChain(txdb))
        { strError = "reselection of best valid chain failed"; return false; }
    return true;
}

// Clear the invalid marks on a block and its descendant subtree, then re-select the best valid chain.
// Nothing changes when the subtree is refused; *pfFlagsCleared tells a caller whether the flags
// were committed when the reselection afterwards fails.
bool ReconsiderBlock(CTxDB& txdb, CBlockIndex* pindex, std::string& strError, bool* pfFlagsCleared)
{
    if (pfFlagsCleared)
        *pfFlagsCleared = false;
    VerifyProofCacheClear();
    ClearPrivacyVNextEffectsCache();
    if (!pindex)
        { strError = "null block index"; return false; }

    std::vector<CBlockIndex*> vChanged;
    CollectFailedSubtree(pindex, false, vChanged);
    if (!SubtreeHasDAGVertices(vChanged, strError))
        return false;
    for (size_t i = 0; i < vChanged.size(); i++)
        vChanged[i]->ClearFailed();

    if (txdb.TxnBegin())
    {
        for (size_t i = 0; i < vChanged.size(); i++)
            txdb.WriteBlockIndex(CDiskBlockIndex(vChanged[i]));
        txdb.TxnCommit();
    }
    if (pfFlagsCleared)
        *pfFlagsCleared = true;

    if (!ReselectBestValidChain(txdb))
        { strError = "reselection of best valid chain failed"; return false; }
    return true;
}

bool CBlock::AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos, const uint256& hashProof)
{
    BLOCK_PHASE(BP_ADDINDEX);
    int64_t nAddStart = GetTimeMillis();
    int64_t nDAGInitMs = 0;
    int64_t nDAGColorMs = 0;
    int64_t nDAGWriteMs = 0;

    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return error("AddToBlockIndex() : %s already exists", hash.ToString().substr(0,20).c_str());

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(nFile, nBlockPos, *this);
    if (!pindexNew)
        return error("AddToBlockIndex() : new CBlockIndex failed");
    pindexNew->phashBlock = &hash;
    map<uint256, CBlockIndex*>::iterator miPrev = mapBlockIndex.find(hashPrevBlock);
    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        if (pindexNew->pprev->nHeight < 0)
            return error("AddToBlockIndex() : pprev has invalid height %d", pindexNew->pprev->nHeight);
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
    }

    if (pindexNew->nHeight >= FORK_HEIGHT_DAG && pindexNew->IsProofOfStake())
        return error("AddToBlockIndex() : proof-of-stake block at post-DAG height %d", pindexNew->nHeight);

    // ppcoin: compute chain trust score
    pindexNew->nChainTrust = (pindexNew->pprev ? pindexNew->pprev->nChainTrust : 0) + pindexNew->GetBlockTrust();

    // ppcoin: compute stake entropy bit for stake modifier
    if (!pindexNew->SetStakeEntropyBit(GetStakeEntropyBit()))
        return error("AddToBlockIndex() : SetStakeEntropyBit() failed");

    // Record proof hash value
    pindexNew->hashProof = hashProof;

    // ppcoin: compute stake modifier
    uint64_t nStakeModifier = 0;
    bool fGeneratedStakeModifier = false;
    if (!ComputeNextStakeModifier(pindexNew->pprev, nStakeModifier, fGeneratedStakeModifier))
        return error("AddToBlockIndex() : ComputeNextStakeModifier() failed");
    pindexNew->SetStakeModifier(nStakeModifier, fGeneratedStakeModifier);
    pindexNew->nStakeModifierChecksum = GetStakeModifierChecksum(pindexNew);
    if (!CheckStakeModifierCheckpoints(pindexNew->nHeight, pindexNew->nStakeModifierChecksum))
        return error("AddToBlockIndex() : Rejected by stake modifier checkpoint height=%d, modifier=0x%016" PRIx64, pindexNew->nHeight, nStakeModifier);

    // Add to mapBlockIndex
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    if (pindexNew->IsProofOfStake())
        setStakeSeen.insert(make_pair(pindexNew->prevoutStake, pindexNew->nStakeTime));
    pindexNew->phashBlock = &((*mi).first);
    pindexNew->BuildSkip();

    // Persistence waits for DAG init and score selection, so the index commits with its DAG
    // records (here for a side block, in SetBestChain's batch for a best-block candidate).
    CTxDB txdb;
    bool fDAGDataInitialized = false;
    bool fBlockIndexPersisted = false;
    // Whether this block is attempted as the new tip. A heavier index forking below the
    // finality anchor is kept as a side block, never flagged or erased.
    bool fAttemptBestChain = false;
    int nSwitchAsOfEpoch = 0;
    const auto EvaluateBestChainSwitch = [&]() {
        fAttemptBestChain = pindexNew->nChainTrust > nBestChainTrust;
        if (!fAttemptBestChain || hashPrevBlock == hashBestChain)
            return true;
        int nForkHeight = 0, nFinalCur = 0, nFinalLatch = 0, nAsOfEpoch = 0;
        const ReorgFinalityVerdict switchVerdict = BestChainSwitchVerdict(
            pindexNew, nForkHeight, nFinalCur, nFinalLatch, nAsOfEpoch);
        if (switchVerdict == REORG_FINALITY_STATE_MISSING)
        {
            nSwitchAsOfEpoch = nAsOfEpoch;
            return false;
        }
        if (switchVerdict != REORG_FINALITY_ALLOW)
        {
            fAttemptBestChain = false;
            printf("AddToBlockIndex() : %s at height %d outweighs the tip but forks at %d below "
                   "finalized height %d (latch anchor %d, %s); kept as a side block\n",
                   hash.ToString().substr(0,20).c_str(), pindexNew->nHeight, nForkHeight,
                   nFinalCur, nFinalLatch,
                   switchVerdict == REORG_FINALITY_REJECT_PERMANENT ? "permanent" : "retryable");
        }
        return true;
    };
    bool fResolvedLateDAGChildren = false;
    std::vector<uint256> vDAGParents;

    const auto CleanupUncommittedIndex = [&]() {
        if (fDAGDataInitialized)
            g_dagManager.RemoveBlockDAGData(hash);
        mapBlockIndex.erase(hash);
        if (pindexNew->IsProofOfStake())
            setStakeSeen.erase(make_pair(pindexNew->prevoutStake,
                                         pindexNew->nStakeTime));
        delete pindexNew;
    };

    // Cache the millisecond offset AcceptBlock validated through the same reader; below
    // the gate it stays 0.
    if (pindexNew->nHeight >= FORK_HEIGHT_MS_TIMESTAMP)
    {
        std::vector<CScript> vMsScripts;
        for (std::vector<CTxOut>::const_iterator it = vtx[0].vout.begin();
             it != vtx[0].vout.end(); ++it)
            vMsScripts.push_back(it->scriptPubKey);
        uint16_t nMs = 0;
        std::string strMsError;
        if (!ExtractCanonicalMsTimestampCommitment(vMsScripts, nMs, strMsError))
        {
            CleanupUncommittedIndex();
            return error("AddToBlockIndex() : %s", strMsError.c_str());
        }
        pindexNew->nTimeMs = nMs;
    }

    // Initialize DAG data for post-fork blocks
    if (pindexNew->nHeight >= FORK_HEIGHT_DAG && pindexNew->IsProofOfWork())
    {
        // Read the commitment with the decoder this height selects, the same one AcceptBlock
        // validated with.
        std::vector<CScript> vScripts;
        for (std::vector<CTxOut>::const_iterator it = vtx[0].vout.begin();
             it != vtx[0].vout.end(); ++it)
            vScripts.push_back(it->scriptPubKey);
        std::string strDAGError;
        if (!ReadDAGParentCommitmentAtHeight(vScripts, pindexNew->nHeight,
                                             vDAGParents, strDAGError))
        {
            CleanupUncommittedIndex();
            return error("AddToBlockIndex() : %s", strDAGError.c_str());
        }
        else
        {
            int64_t nDAGTimer = GetTimeMillis();
            {
            BLOCK_PHASE(BP_DAG_INIT);
            if (!g_dagManager.InitBlockDAGData(pindexNew, vDAGParents))
            {
                CleanupUncommittedIndex();
                return error("AddToBlockIndex() : InitBlockDAGData failed");
            }
            fDAGDataInitialized = true;
            {
                CBlockDAGData initializedData;
                fResolvedLateDAGChildren =
                    g_dagManager.GetDAGData(hash, initializedData) &&
                    !initializedData.vDAGChildren.empty();
            }
            }
            nDAGInitMs = GetTimeMillis() - nDAGTimer;

            nDAGTimer = GetTimeMillis();
            {
            BLOCK_PHASE(BP_DAG_COLOR);
            if (pindexNew->nHeight >= FORK_HEIGHT_DAGKNIGHT)
            {
                if (!g_dagManager.ColorBlockDAGKnight(pindexNew))
                {
                    CleanupUncommittedIndex();
                    return error("AddToBlockIndex() : anchor-pure DAGKNIGHT coloring failed");
                }
            }
            else
                g_dagManager.ColorBlock(pindexNew);
            }
            nDAGColorMs = GetTimeMillis() - nDAGTimer;

            // Use DAG score for best-chain comparison
            uint256 nDAGScore = g_dagManager.ComputeDAGScore(pindexNew);
            pindexNew->nChainTrust = nDAGScore;
            if (fResolvedLateDAGChildren &&
                pindexNew->nHeight >= FORK_HEIGHT_EPOCH_STATE_V3)
            {
                {
                    BLOCK_PHASE(BP_DAG_ORDER);
                    g_dagManager.RebuildDAGOrderIncremental(pindexNew->nHeight - 1);
                }
                pindexNew->nChainTrust = g_dagManager.ComputeDAGScore(pindexNew);
            }

            if (!EvaluateBestChainSwitch())
            {
                CleanupUncommittedIndex();
                return error("AddToBlockIndex() : missing deterministic finalized-height state "
                             "for epoch %d; resync required", nSwitchAsOfEpoch);
            }

            // Remove DAG sibling txs from mempool
            std::set<uint256> siblings = g_dagManager.GetDAGSiblingBlocks(hash);
            for (const uint256& hashSibling : siblings)
                mempool.RemoveDAGConflicts(hashSibling);

            // Epoch state computation and pruning at epoch boundaries
            if (pindexNew->nHeight > 0)
            {
                // Epochs predating V2 keep AddToBlockIndex timing; V2-range epochs are staged by
                // SetBestChainInner/Reorganize inside the best-chain transaction.
                int nCompletedEpoch = -1;
                if (V2CompatEpochBuildsAtIndexCrossing(pindexNew->nHeight, nCompletedEpoch))
                {
                    int nEpochStart = GetEpochBoundaryHeight(nCompletedEpoch, pindexNew->nHeight);
                    int nEpochEnd = GetEpochBoundaryHeight(nCompletedEpoch + 1, pindexNew->nHeight) - 1;
                    int nEpochInterval = (nEpochEnd >= nEpochStart) ? (nEpochEnd - nEpochStart + 1) : GetEpochInterval(nEpochStart);

                    bool fEpochV2 =
                        (pindexNew->nHeight >= FORK_HEIGHT_EPOCH_STATE_V2);
                    if (!fEpochV2 ||
                        (hashPrevBlock == hashBestChain && fAttemptBestChain))
                    {
                        const CBlockIndex* pV2Anchor = fEpochV2 ? pindexNew : NULL;
                        if (!g_dagManager.ComputeEpochState(
                                nCompletedEpoch, nEpochInterval, pV2Anchor))
                        {
                            CleanupUncommittedIndex();
                            return error("AddToBlockIndex() : V2 epoch %d build failed",
                                         nCompletedEpoch);
                        }

                        CTxDB txdbEpoch;
                        if (!txdbEpoch.TxnBegin())
                        {
                            CleanupUncommittedIndex();
                            return error("AddToBlockIndex() : V2 epoch TxnBegin failed");
                        }
                        if (!g_dagManager.WriteEpochState(txdbEpoch, nCompletedEpoch) ||
                            (fEpochV2 &&
                             !txdbEpoch.WriteEpochStateSchema(EPOCHSTATE_SCHEMA_V2)))
                        {
                            txdbEpoch.TxnAbort();
                            CleanupUncommittedIndex();
                            return error("AddToBlockIndex() : V2 epoch state/schema write failed");
                        }
                        if (!txdbEpoch.TxnCommit())
                        {
                            CleanupUncommittedIndex();
                            return error("AddToBlockIndex() : V2 epoch TxnCommit failed");
                        }
                    }
                }

                // Cache the deterministic finalized height as of this block. The
                // consensus source for anchoring is GetDeterministicFinalizedHeight();
                // this per-index value mirrors it for RPC/observability and reorg-safe
                // pprev lookups.
                const int nAsOfEpoch = GetEpochForHeight(pindexNew->nHeight) - 1;
                if (pindexNew->nHeight >= FORK_HEIGHT_EPOCH_STATE_V3)
                {
                    // The activation block's migration base is staged inside
                    // SetBestChainInner/Reorganize and is not globally visible yet.
                    if (pindexNew->nHeight == FORK_HEIGHT_EPOCH_STATE_V3)
                        pindexNew->nFinalizedHeight = 0;
                    else if (!g_dagManager.TryGetDeterministicFinalizedHeight(
                                 nAsOfEpoch, pindexNew->nFinalizedHeight))
                    {
                        if (fAttemptBestChain)
                        {
                            CleanupUncommittedIndex();
                            return error("AddToBlockIndex() : missing deterministic finalized-height "
                                         "state for epoch %d; resync required", nAsOfEpoch);
                        }
                        pindexNew->nFinalizedHeight = 0;
                    }
                }
                else
                    pindexNew->nFinalizedHeight =
                        g_dagManager.GetDeterministicFinalizedHeight(nAsOfEpoch);
            }
        }
    }

    LOCK(cs_main);

    if (!fDAGDataInitialized && !EvaluateBestChainSwitch())
    {
        CleanupUncommittedIndex();
        return error("AddToBlockIndex() : missing deterministic finalized-height state for "
                     "epoch %d; resync required", nSwitchAsOfEpoch);
    }

    if (fDAGDataInitialized && !fAttemptBestChain)
    {
        // A side branch must survive restart immediately, but its index and
        // DAG graph are one invariant and therefore one transaction.
        const int64_t nDAGTimer = GetTimeMillis();
        BLOCK_PHASE(BP_DAG_WRITE);
        CTxDB txdbDAG;
        if (!txdbDAG.TxnBegin())
        {
            CleanupUncommittedIndex();
            return error("AddToBlockIndex() : side-index/DAG TxnBegin failed");
        }
        if (!txdbDAG.WriteBlockIndex(CDiskBlockIndex(pindexNew)) ||
            !g_dagManager.WriteDAGLinks(txdbDAG, hash))
        {
            txdbDAG.TxnAbort();
            CleanupUncommittedIndex();
            return error("AddToBlockIndex() : side-index/DAG write failed");
        }
        for (std::vector<uint256>::const_iterator it = vDAGParents.begin();
             it != vDAGParents.end(); ++it)
        {
            if (g_dagManager.HasDAGData(*it) &&
                !g_dagManager.WriteDAGLinks(txdbDAG, *it))
            {
                txdbDAG.TxnAbort();
                CleanupUncommittedIndex();
                return error("AddToBlockIndex() : parent DAG link write failed");
            }
        }
        if (!txdbDAG.TxnCommit())
        {
            CleanupUncommittedIndex();
            return error("AddToBlockIndex() : side-index/DAG TxnCommit failed");
        }
        fBlockIndexPersisted = true;
        nDAGWriteMs = GetTimeMillis() - nDAGTimer;
    }
    else if (!fDAGDataInitialized)
    {
        // Preserve the legacy pre-DAG persistence timing.  Best-candidate DAG
        // blocks intentionally fall through so ConnectBlock, DAG links and the
        // best-chain pointer share SetBestChain's transaction.
        CTxDB txdbIndex;
        if (!txdbIndex.TxnBegin())
        {
            CleanupUncommittedIndex();
            return error("AddToBlockIndex() : block-index TxnBegin failed");
        }
        if (!txdbIndex.WriteBlockIndex(CDiskBlockIndex(pindexNew)))
        {
            txdbIndex.TxnAbort();
            CleanupUncommittedIndex();
            return error("AddToBlockIndex() : WriteBlockIndex failed");
        }
        if (!txdbIndex.TxnCommit())
        {
            CleanupUncommittedIndex();
            return error("AddToBlockIndex() : block-index TxnCommit failed");
        }
        fBlockIndexPersisted = true;
    }

    // New best
    if (fAttemptBestChain)
    {
        bool fPermanentInvalid = false;
        if (!SetBestChain(txdb, pindexNew, &fPermanentInvalid))
        {
            if (fPermanentInvalid)
            {
                // Permanent consensus invalidity: KEEP the index in mapBlockIndex flagged failed --
                // deleting it flips AlreadyHave() back to "don't have it" so the block is re-inv'd,
                // re-downloaded and re-validated forever (the stuck-node re-request loop). The index was
                // possibly persisted WITHOUT the failed bit, so re-write it WITH the bit so the mark
                // survives restart. Do NOT erase setStakeSeen (retain duplicate-stake detection); leave
                // the index in mapBlockIndex (AlreadyHave stays true; children are rejected in AcceptBlock).
                pindexNew->SetFailedValid();
                CTxDB txdbFail;
                bool fFailedIndexCommitted = false;
                if (txdbFail.TxnBegin())
                {
                    bool fWritesOK =
                        txdbFail.WriteBlockIndex(CDiskBlockIndex(pindexNew));
                    if (fDAGDataInitialized)
                    {
                        fWritesOK = g_dagManager.WriteDAGLinks(txdbFail, hash) && fWritesOK;
                        for (std::vector<uint256>::const_iterator it = vDAGParents.begin();
                             it != vDAGParents.end(); ++it)
                            if (g_dagManager.HasDAGData(*it))
                                fWritesOK = g_dagManager.WriteDAGLinks(txdbFail, *it) &&
                                            fWritesOK;
                    }
                    if (fWritesOK)
                        fFailedIndexCommitted = txdbFail.TxnCommit();
                    else
                        txdbFail.TxnAbort();
                }
                if (!fFailedIndexCommitted)
                {
                    printf("AddToBlockIndex() : FATAL could not persist the permanent-invalid "
                           "index/DAG vertex for %s; shutting down\n",
                           hash.ToString().substr(0,20).c_str());
                    StartShutdown();
                }
                return false;
            }

            // Transient (DB / resource) failure: preserve the original delete-based retry path so a later
            // attempt can re-accept the block cleanly (A1 / resource recovery).
            if (fDAGDataInitialized)
                g_dagManager.RemoveBlockDAGData(hash);

            if (fBlockIndexPersisted)
            {
                CTxDB txdbIndexClean;
                if (!txdbIndexClean.EraseBlockIndex(hash))
                {
                    printf("AddToBlockIndex() : FATAL could not erase transient block index %s; "
                           "shutting down\n", hash.ToString().substr(0,20).c_str());
                    StartShutdown();
                }
            }
            mapBlockIndex.erase(hash);
            if (pindexNew->IsProofOfStake())
                setStakeSeen.erase(make_pair(pindexNew->prevoutStake, pindexNew->nStakeTime));
            delete pindexNew;
            return false;
        }
    }

    // A late merge parent repairs its children's V3 scores; re-run selection now so arrival
    // order and restart converge on the same tip.
    if (fResolvedLateDAGChildren && pindexNew->nHeight >= FORK_HEIGHT_EPOCH_STATE_V3)
    {
        CBlockIndex* pLateBest = g_dagManager.SelectBestDAGTip();
        bool fLateSwitchable = pLateBest && pLateBest != pindexBest &&
                               !pLateBest->IsInvalid() &&
                               pLateBest->nChainTrust > nBestChainTrust;
        if (fLateSwitchable)
        {
            // Same decision as above: a late best tip this node may not follow is left
            // where it is, never flagged for the verdict.
            int nForkHeight = 0, nFinalCur = 0, nFinalLatch = 0, nAsOfEpoch = 0;
            const ReorgFinalityVerdict lateVerdict = BestChainSwitchVerdict(
                pLateBest, nForkHeight, nFinalCur, nFinalLatch, nAsOfEpoch);
            if (lateVerdict != REORG_FINALITY_ALLOW)
            {
                fLateSwitchable = false;
                printf("AddToBlockIndex() : late best tip %s at height %d is not switchable "
                       "(fork %d, finalized %d, latch %d, %s); staying on the current tip\n",
                       pLateBest->GetBlockHash().ToString().substr(0,20).c_str(),
                       pLateBest->nHeight, nForkHeight, nFinalCur, nFinalLatch,
                       lateVerdict == REORG_FINALITY_STATE_MISSING ? "finalized-height state missing"
                       : lateVerdict == REORG_FINALITY_REJECT_PERMANENT ? "permanent" : "retryable");
            }
        }
        if (fLateSwitchable)
        {
            CBlock lateBestBlock;
            bool fLatePermanentInvalid = false;
            if (!lateBestBlock.ReadFromDisk(pLateBest) ||
                !lateBestBlock.SetBestChain(txdb, pLateBest, &fLatePermanentInvalid))
            {
                if (fLatePermanentInvalid)
                {
                    const uint256 hashLate = pLateBest->GetBlockHash();
                    // Vertex and parent links were persisted by the side-block commit;
                    // only the flag changes.
                    pLateBest->SetFailedValid();
                    CTxDB txdbLateFail;
                    bool fLateFailureCommitted = false;
                    if (txdbLateFail.TxnBegin())
                    {
                        bool fWritesOK =
                            txdbLateFail.WriteBlockIndex(CDiskBlockIndex(pLateBest));
                        if (fWritesOK)
                            fLateFailureCommitted = txdbLateFail.TxnCommit();
                        else
                            txdbLateFail.TxnAbort();
                    }
                    if (!fLateFailureCommitted)
                    {
                        printf("AddToBlockIndex() : FATAL could not persist late-parent "
                               "invalid-index/DAG cleanup for %s; shutting down\n",
                               hashLate.ToString().substr(0,20).c_str());
                        StartShutdown();
                    }
                }
                else
                    printf("AddToBlockIndex() : late-parent best-tip reselection deferred after "
                           "transient read/DB failure\n");
            }
        }
    }

    // Pruning keeps hostile DAG growth bounded under V3; it runs only after a successful
    // boundary crossing.
    if (pindexNew == pindexBest && pindexNew->nHeight > 0 &&
        GetEpochForHeight(pindexNew->nHeight) >
            GetEpochForHeight(pindexNew->nHeight - 1))
    {
        CTxDB txdbPrune;
        if (!g_dagManager.PruneDAGData(txdbPrune, pindexNew->nHeight))
        {
            printf("AddToBlockIndex() : FATAL DAG prune persistence failed at height %d; "
                   "shutting down to avoid unbounded DAG growth\n", pindexNew->nHeight);
            StartShutdown();
        }
    }

    if (pindexNew == pindexBest)
    {
        // Notify UI to display prev block's coinbase if it was ours
        static uint256 hashPrevBestCoinBase;
        UpdatedTransaction(hashPrevBestCoinBase);
        hashPrevBestCoinBase = vtx[0].GetHash();
    }

    {
        static int64_t nLastNotifyTime = 0;
        static int nLastNotifyHeight = 0;
        int64_t nNow = GetTimeMillis();
        int nHeight = pindexNew->nHeight;
        bool fNotify = !IsInitialBlockDownload()
                       || (nNow - nLastNotifyTime > 2000)   // at least every 2 seconds
                       || (nHeight - nLastNotifyHeight >= 500); // or every 500 blocks
        if (fNotify)
        {
            uiInterface.NotifyBlocksChanged(nHeight, GetNumBlocksOfPeers());
            nLastNotifyTime = nNow;
            nLastNotifyHeight = nHeight;
        }
    }

    if (fDebug && GetBoolArg("-showtimers", false))
        printf("AddToBlockIndex: height=%d total=%" PRId64"ms dag_init=%" PRId64"ms dag_color=%" PRId64"ms dag_write=%" PRId64"ms\n",
               pindexNew->nHeight, GetTimeMillis() - nAddStart, nDAGInitMs, nDAGColorMs, nDAGWriteMs);

    return true;
}




bool CBlock::CheckBlock(bool fCheckPOW, bool fCheckMerkleRoot, bool fCheckSig) const
{
    BLOCK_PHASE(BP_CHECKBLOCK);
    // These are checks that are independent of context
    // that can be verified before saving an orphan block.

    // Size limits (ceiling as sanity check; height-aware limit enforced in AcceptBlock)
    if (vtx.empty() || vtx.size() > ADAPTIVE_BLOCK_CEILING || ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > ADAPTIVE_BLOCK_CEILING)
        return DoS(100, error("CheckBlock() : size limits failed"));

    // Check proof of work matches claimed amount
    if (fCheckPOW && IsProofOfWork())
    {
        BLOCK_PHASE(BP_POW);
        if (!CheckProofOfWork(GetPoWHash(), nBits))
            return DoS(50, error("CheckBlock() : proof of work failed"));
    }

    // Check timestamp
    if (GetBlockTime() > FutureDrift(GetAdjustedTime()))
        return error("CheckBlock() : block timestamp too far in the future");

    // First transaction must be coinbase, the rest must not be
    if (vtx.empty() || !vtx[0].IsCoinBase())
        return DoS(100, error("CheckBlock() : first tx is not coinbase"));
    for (unsigned int i = 1; i < vtx.size(); i++)
        if (vtx[i].IsCoinBase())
            return DoS(100, error("CheckBlock() : more than one coinbase"));

    // Check coinbase timestamp
    if (GetBlockTime() > FutureDrift((int64_t)vtx[0].nTime))
        return DoS(50, error("CheckBlock() : coinbase timestamp is too early"));

    // A coinstake may only ever appear as vtx[1] (which is what makes the block
    // proof-of-stake). This scan must NOT be gated on IsProofOfStake(): a
    // coinstake-shaped tx at index >= 2 of a proof-of-WORK block would otherwise
    // skip every coinstake validation path while still claiming the coinstake
    // exemptions in ConnectInputs (value conservation, shielded value balance,
    // nullifier binding) — i.e. the supply could increase beyond the subsidy.
    // NullStake-shaped coinstakes are rejected at any height (none exist in valid
    // history outside vtx[1]); the classic shape is additionally height-gated in
    // AcceptBlock/ConnectBlock.
    for (unsigned int i = 2; i < vtx.size(); i++)
    {
        if (!vtx[i].IsCoinStake())
            continue;
        if (vtx[i].nVersion == SHIELDED_TX_VERSION_NULLSTAKE ||
            vtx[i].nVersion == SHIELDED_TX_VERSION_NULLSTAKE_V2 ||
            vtx[i].nVersion == SHIELDED_TX_VERSION_NULLSTAKE_COLD)
            return DoS(100, error("CheckBlock() : NullStake coinstake at tx index %u (only vtx[1] of a proof-of-stake block may be a coinstake)", i));
    }

    if (IsProofOfStake())
    {
        // Coinbase output should be empty if proof-of-stake block
        // Post-DAG: allow additional zero-value OP_RETURN outputs for DAG parent commitment
        if (!vtx[0].vout[0].IsEmpty())
            return DoS(100, error("CheckBlock() : coinbase vout[0] not empty for proof-of-stake block"));
        // Cap extra outputs (1 empty + up to 2 OP_RETURN for DAG/data)
        if (vtx[0].vout.size() > 3)
            return DoS(100, error("CheckBlock() : too many coinbase outputs (%d) for proof-of-stake block", (int)vtx[0].vout.size()));
        if (vtx[0].vout.size() > 1)
        {
            for (unsigned int i = 1; i < vtx[0].vout.size(); i++)
            {
                if (vtx[0].vout[i].nValue != 0)
                    return DoS(100, error("CheckBlock() : non-zero coinbase output[%d] in proof-of-stake block", i));
                // Must be OP_RETURN (DAG commitment or similar data-carrying output)
                if (vtx[0].vout[i].scriptPubKey.size() < 1 || vtx[0].vout[i].scriptPubKey[0] != OP_RETURN)
                    return DoS(100, error("CheckBlock() : non-OP_RETURN extra coinbase output[%d] in proof-of-stake block", i));
            }
        }

        // Second transaction must be coinstake, the rest must not be
        if (vtx.empty() || !vtx[1].IsCoinStake())
            return DoS(100, error("CheckBlock() : second tx is not coinstake"));
        for (unsigned int i = 2; i < vtx.size(); i++)
        {
            if (vtx[i].IsCoinStake())
                return DoS(100, error("CheckBlock() : more than one coinstake"));
        }

		// Check coinstake timestamp
		if (!CheckCoinStakeTimestamp(GetBlockTime(), (int64_t)vtx[1].nTime))
			return DoS(50, error("CheckBlock() : coinstake timestamp violation nTimeBlock=%" PRId64" nTimeTx=%u", GetBlockTime(), vtx[1].nTime));

		// Check proof-of-stake block signature
		if (fCheckSig && !CheckBlockSignature())
            return DoS(100, error("CheckBlock() : bad proof-of-stake block signature"));
	}

    // Check transactions
    {
    BLOCK_PHASE(BP_CHECKTX);
    for (const CTransaction& tx : vtx)
    {
        if (!tx.CheckTransaction())
            return DoS(tx.nDoS, error("CheckBlock() : CheckTransaction failed"));

        // ppcoin: check transaction timestamp
        if (GetBlockTime() < (int64_t)tx.nTime)
            return DoS(50, error("CheckBlock() : block timestamp earlier than transaction timestamp"));
    }
    }

    // Check for duplicate txids. This is caught by ConnectInputs(),
    // but catching it earlier avoids a potential DoS attack:
    set<uint256> uniqueTx;
    for (const CTransaction& tx : vtx)
    {
        uniqueTx.insert(tx.GetHash());
    }
    if (uniqueTx.size() != vtx.size())
        return DoS(100, error("CheckBlock() : duplicate transaction"));

    unsigned int nSigOps = 0;
    for (const CTransaction& tx : vtx)
    {
        nSigOps += tx.GetLegacySigOpCount();
    }
    if (nSigOps > MAX_BLOCK_SIGOPS_ADAPTIVE)
        return DoS(100, error("CheckBlock() : out-of-bounds SigOpCount"));

    // Check merkle root
    if (fCheckMerkleRoot)
    {
        BLOCK_PHASE(BP_MERKLE);
        if (hashMerkleRoot != BuildMerkleTree())
            return DoS(100, error("CheckBlock() : hashMerkleRoot mismatch"));
    }


    return true;
}

bool CBlock::AcceptBlock()
{
    AssertLockHeld(cs_main);
    BLOCK_PHASE(BP_ACCEPTBLOCK);
    int64_t nAcceptStart = GetTimeMillis();

    if (nVersion > CURRENT_VERSION)
        return DoS(100, error("AcceptBlock() : reject unknown block version %d", nVersion));

    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return error("AcceptBlock() : block already in mapBlockIndex");

    // Get prev block index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashPrevBlock);
    if (mi == mapBlockIndex.end())
        return DoS(10, error("AcceptBlock() : prev block not found"));
    CBlockIndex* pindexPrev = (*mi).second;
    // Reject any block that builds on a permanently-invalid parent. Previously a connect-failed block was
    // DELETED, so a child's prev was "not found" and the child orphaned. Now the failed parent stays in
    // mapBlockIndex (to stop the re-request loop / support invalidateblock), so a child would find its
    // prev -- guard here or a peer could re-feed the invalidated chain and re-connect on top of it.
    if (pindexPrev->IsInvalid()) // node-local flag: the relayer is not scored
        return error("AcceptBlock() : prev block %s is marked failed/invalid",
                     hashPrevBlock.ToString().substr(0,20).c_str());
    int nHeight = pindexPrev->nHeight+1;

    if (nHeight >= FORK_HEIGHT_DAG && IsProofOfStake())
        return DoS(100, error("AcceptBlock() : proof-of-stake blocks are not allowed after DAG fork height %d", FORK_HEIGHT_DAG));

    // No coinstake of ANY shape may appear outside vtx[1] of a proof-of-stake
    // block (see CheckBlock; the classic shape needs the height gate because
    // pre-v5 history was never validated under this rule).
    if (nHeight >= FORK_HEIGHT_SHIELDED)
    {
        for (unsigned int i = 2; i < vtx.size(); i++)
            if (vtx[i].IsCoinStake())
                return DoS(100, error("AcceptBlock() : coinstake at tx index %u (only vtx[1] of a proof-of-stake block may be a coinstake)", i));
    }

    // Block size enforcement (height-aware)
    {
        unsigned int nBlockBytes = ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
        if (nHeight < FORK_HEIGHT_DAG)
        {
            // Pre-fork: strict 1MB limit (matches old wallet consensus)
            if (nBlockBytes > MAX_BLOCK_SIZE_LEGACY)
                return DoS(100, error("AcceptBlock() : block size %u exceeds legacy limit %u at height %d",
                                      nBlockBytes, MAX_BLOCK_SIZE_LEGACY, nHeight));
        }
        else
        {
            // Post-fork: adaptive limit
            unsigned int nAdaptiveLimit = GetAdaptiveBlockSizeLimit(pindexPrev);
            if (nBlockBytes > nAdaptiveLimit)
                return DoS(50, error("AcceptBlock() : block size %u exceeds adaptive limit %u at height %d",
                                      nBlockBytes, nAdaptiveLimit, nHeight));
        }
    }

    // Check proof-of-work or proof-of-stake
    unsigned int nComputedBits = GetNextTargetRequired(pindexPrev, IsProofOfStake());
    if (nBits != nComputedBits)
        return DoS(100, error("AcceptBlock() : incorrect %s", IsProofOfWork() ? "proof-of-work" : "proof-of-stake"));

    if (GetBlockTime() <= pindexPrev->GetPastTimeLimit() || FutureDrift(GetBlockTime(), nHeight) < pindexPrev->GetBlockTime())
        return error("AcceptBlock() : block's timestamp is too early");

    // Check that all transactions are finalized
    for (const CTransaction& tx : vtx)
        //if (!tx.IsFinal(nHeight, GetBlockTime()))
		  if (!tx.IsFinal(nHeight, GetBlockTime()))
            return DoS(10, error("AcceptBlock() : contains a non-final transaction"));

    // Check that the block chain matches the known block chain up to a checkpoint
    if (!Checkpoints::CheckHardened(nHeight, hash))
        return DoS(100, error("AcceptBlock() : rejected by hardened checkpoint lock-in at %d", nHeight));

    uint256 hashProof;
    // Verify hash target and signature of coinstake tx
    if (IsProofOfStake())
    {
        uint256 targetProofOfStake;
        //if (!CheckProofOfStake(pindexPrev, vtx[1], nBits, hashProof, targetProofOfStake))
		if (!CheckProofOfStake(vtx[1], nBits, hashProof, targetProofOfStake, nHeight))
        {
            // Only penalize outside IBD (PoS verification needs UTXOs)
            if (!IsInitialBlockDownload())
            {
                return DoS(50, error("AcceptBlock() : check proof-of-stake failed for block %s (peer penalized)",
                                     hash.ToString().c_str()));
            }
			printf("WARNING: AcceptBlock(): check proof-of-stake failed for block %s (IBD - no penalty)\n", hash.ToString().c_str());
			return false;
        }
    }
    // PoW is checked in CheckBlock()
    if (IsProofOfWork())
    {
        hashProof = GetPoWHash();
    }

    // Boundary A permanently freezes all legacy privacy/proof transaction
    // formats.  Keep pre-A blocks byte-compatible for historical replay, but
    // reject the old identifiers in every newly connected A-or-later block.
    if (nHeight >= FORK_HEIGHT_RINGSIG_DEPRECATION ||
        IsLegacyPrivacyPolicyDisabled() ||
        IsBoundaryAActiveAtHeight(nHeight))
    {
        for (unsigned int i = 0; i < vtx.size(); i++)
        {
            if (vtx[i].nVersion == ANON_TXN_VERSION &&
                nHeight >= FORK_HEIGHT_RINGSIG_DEPRECATION)
                return DoS(100, error("AcceptBlock() : ring signature transaction (ANON_TXN_VERSION) in block at height %d after deprecation height %d",
                                       nHeight, FORK_HEIGHT_RINGSIG_DEPRECATION));
            if (vtx[i].IsShielded() &&
                (IsLegacyPrivacyPolicyDisabled() ||
                 IsBoundaryAActiveAtHeight(nHeight)))
                return DoS(100, error("AcceptBlock() : legacy shielded transaction version %d is disabled in this network/era at height %d",
                                      vtx[i].nVersion, nHeight));
        }
    }

    for (unsigned int i = 0; i < vtx.size(); ++i)
        if (vtx[i].IsPrivacyVNext() &&
            (!IsBoundaryBActiveAtHeight(nHeight) ||
             !IsShieldedVNextConsensusReady()))
            return DoS(100, error("AcceptBlock() : privacy-vNext is inactive before Boundary B"));

    bool cpSatisfies = Checkpoints::CheckSync(hash, pindexPrev);

    // Check that the block satisfies synchronized checkpoint
    if (CheckpointsMode == Checkpoints::STRICT && !cpSatisfies)
        return error("AcceptBlock() : rejected by synchronized checkpoint");

    if (CheckpointsMode == Checkpoints::ADVISORY && !cpSatisfies)
        strMiscWarning = _("WARNING: syncronized checkpoint violation detected, but skipped!");

    // Enforce rule that the coinbase starts with serialized block height
    CScript expect = CScript() << nHeight;
    if (vtx[0].vin[0].scriptSig.size() < expect.size() ||
        !std::equal(expect.begin(), expect.end(), vtx[0].vin[0].scriptSig.begin()))
        return DoS(100, error("AcceptBlock() : block height mismatch in coinbase (height=%d prev=%s expected=%s actual=%s)",
                              nHeight,
                              hashPrevBlock.ToString().substr(0, 20).c_str(),
                              HexStr(expect).c_str(),
                              HexStr(vtx[0].vin[0].scriptSig).c_str()));

    // Validate the millisecond-timestamp commitment in the coinbase OP_RETURN.
    // Presence, uniqueness and range only: nothing downstream consumes the
    // offset, and no second-resolution rule is relaxed by it.
    {
        std::vector<CScript> vMsScripts;
        for (std::vector<CTxOut>::const_iterator it = vtx[0].vout.begin();
             it != vtx[0].vout.end(); ++it)
            vMsScripts.push_back(it->scriptPubKey);

        if (nHeight >= FORK_HEIGHT_MS_TIMESTAMP)
        {
            uint16_t nMs = 0;
            std::string strMsError;
            if (!ExtractCanonicalMsTimestampCommitment(vMsScripts, nMs, strMsError))
                return DoS(100, error("AcceptBlock() : %s", strMsError.c_str()));
        }
        else if (nHeight >= GetMsTimestampAbsenceFloor() &&
                 MsTimestampCommitmentPresent(vMsScripts))
        {
            return DoS(100, error("AcceptBlock() : IMTS commitment at height %d, below the millisecond-timestamp fork height %d",
                                  nHeight, FORK_HEIGHT_MS_TIMESTAMP));
        }
    }

    // Validate DAG parent commitment in coinbase OP_RETURN
    if (nHeight >= FORK_HEIGHT_DAG)
    {
        std::vector<uint256> vDAGParents;
        {
            std::vector<CScript> vScripts;
            for (std::vector<CTxOut>::const_iterator it = vtx[0].vout.begin();
                 it != vtx[0].vout.end(); ++it)
                vScripts.push_back(it->scriptPubKey);
            std::string strDAGError;
            if (!ReadDAGParentCommitmentAtHeight(vScripts, nHeight, vDAGParents,
                                                 strDAGError))
                return DoS(100, error("AcceptBlock() : %s", strDAGError.c_str()));
        }

        if (vDAGParents.size() > (unsigned int)MAX_DAG_PARENTS)
            return DoS(100, error("AcceptBlock() : too many DAG parents (%d > %d)", (int)vDAGParents.size(), MAX_DAG_PARENTS));

        // Primary parent (index 0) must match hashPrevBlock
        if (vDAGParents[0] != hashPrevBlock)
            return DoS(100, error("AcceptBlock() : DAG primary parent %s != hashPrevBlock %s",
                                   vDAGParents[0].ToString().substr(0, 20).c_str(),
                                   hashPrevBlock.ToString().substr(0, 20).c_str()));

        // Validate merge parents
        for (unsigned int i = 1; i < vDAGParents.size(); i++)
        {
            // No self-reference
            if (vDAGParents[i] == hash)
                return DoS(100, error("AcceptBlock() : DAG parent[%d] is self-reference", i));

            // Must exist in block index
            // Defer a child whose committed parent is absent at every post-DAG height: it would be
            // coloured against an incomplete parent set and never recoloured below V3. Not scored.
            if (!mapBlockIndex.count(vDAGParents[i]))
                return error("AcceptBlock() : DAG merge parent[%d] %s is not available; "
                             "defer the child until every committed parent is present",
                             i, vDAGParents[i].ToString().substr(0, 20).c_str());

            // Merge parent must have lower height
            CBlockIndex* pMergeParent = mapBlockIndex[vDAGParents[i]];
            if (pMergeParent->nHeight >= nHeight)
                return DoS(100, error("AcceptBlock() : DAG merge parent[%d] height %d >= block height %d",
                                       i, pMergeParent->nHeight, nHeight));
            if (pMergeParent->nHeight >= FORK_HEIGHT_DAG && pMergeParent->IsProofOfStake())
                return DoS(100, error("AcceptBlock() : DAG merge parent[%d] is proof-of-stake", i));

            // Merge parent within DAG_MERGE_DEPTH of primary parent
            if (pindexPrev->nHeight - pMergeParent->nHeight > DAG_MERGE_DEPTH)
                return DoS(50, error("AcceptBlock() : DAG merge parent[%d] too deep (%d below primary)",
                                      i, pindexPrev->nHeight - pMergeParent->nHeight));

            // No duplicate parents
            for (unsigned int j = 0; j < i; j++)
            {
                if (vDAGParents[j] == vDAGParents[i])
                    return DoS(100, error("AcceptBlock() : duplicate DAG parent at index %d and %d", j, i));
            }
        }

        if (IsBoundaryAActiveAtHeight(nHeight))
        {
            std::string strDAGKnightError;
            if (!g_dagManager.CheckDAGKnightParentSet(
                    vDAGParents, nHeight, strDAGKnightError))
                return DoS(100, error("AcceptBlock() : %s",
                                      strDAGKnightError.c_str()));
        }
    }

    // Write block to history file
    if (!CheckDiskSpace(::GetSerializeSize(*this, SER_DISK, CLIENT_VERSION)))
        return error("AcceptBlock() : out of disk space");
    unsigned int nFile = -1;
    unsigned int nBlockPos = 0;
    int64_t nWriteDiskStart = GetTimeMillis();
    {
        BLOCK_PHASE(BP_WRITEDISK);
        if (!WriteToDisk(nFile, nBlockPos))
            return error("AcceptBlock() : WriteToDisk failed");
    }
    int64_t nWriteDiskMs = GetTimeMillis() - nWriteDiskStart;
    int64_t nAddIndexStart = GetTimeMillis();
    if (!AddToBlockIndex(nFile, nBlockPos, hashProof))
        return error("AcceptBlock() : AddToBlockIndex failed");
    int64_t nAddIndexMs = GetTimeMillis() - nAddIndexStart;

    // Relay inventory, but don't relay old inventory during initial block download
    int nBlockEstimate = Checkpoints::GetTotalBlocksEstimate();
    if (hashBestChain == hash)
    {
        LOCK(cs_vNodes);
        for (CNode* pnode : vNodes)
        {
            int nPeerHeight = pnode->nBestKnownHeight >= 0 ? pnode->nBestKnownHeight : pnode->nChainHeight;
            if (nBestHeight <= (nPeerHeight != -1 ? nPeerHeight - 2000 : nBlockEstimate))
                continue;

            CBlock header;
            header.nVersion = nVersion;
            header.hashPrevBlock = hashPrevBlock;
            header.hashMerkleRoot = hashMerkleRoot;
            header.nTime = nTime;
            header.nBits = nBits;
            header.nNonce = nNonce;
            PushBlockAnnouncement(pnode, header, false);
        }
    }

    // ppcoin: check pending sync-checkpoint
    Checkpoints::AcceptPendingSyncCheckpoint();

    if (fDebug && GetBoolArg("-showtimers", false))
        printf("AcceptBlock: height=%d total=%" PRId64"ms write_disk=%" PRId64"ms add_index=%" PRId64"ms\n",
               nHeight, GetTimeMillis() - nAcceptStart, nWriteDiskMs, nAddIndexMs);

    return true;
}

uint256 CBlockIndex::GetBlockTrust() const
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    if (bnTarget <= 0)
        return 0;

    if (nHeight >= FORK_HEIGHT_DAG && IsProofOfStake())
        return 0;

    if (nHeight >= FORK_HEIGHT_POEM)
        return GetBlockEntropy((IsProofOfStake() && nHeight < FORK_HEIGHT_DAG) ? hashProof : *phashBlock);

    return ((CBigNum(1)<<256) / (bnTarget+1)).getuint256();
}

bool CBlockIndex::IsSuperMajority(int minVersion, const CBlockIndex* pstart, unsigned int nRequired, unsigned int nToCheck)
{
    unsigned int nFound = 0;
    for (unsigned int i = 0; i < nToCheck && nFound < nRequired && pstart != NULL; i++)
    {
        if (pstart->nVersion >= minVersion)
            ++nFound;
        pstart = pstart->pprev;
    }
    return (nFound >= nRequired);
}

bool ProcessBlock(CNode* pfrom, CBlock* pblock)
{
    AssertLockHeld(cs_main);

    BLOCK_PHASE(BP_PROCESSBLOCK);
    int64_t nStartTime = GetTimeMillis();
    // Check for duplicate
    uint256 hash = pblock->GetHash();
    if (pfrom != NULL && pindexBest != NULL && pindexBest->GetBlockTime() < GetTime() - 300 && fDebug)
        printf("sync: ProcessBlock %s from %s (height %d)\n", hash.ToString().substr(0,20).c_str(), pfrom->addrName.c_str(), nBestHeight);
    if (mapBlockIndex.count(hash))
        return error("ProcessBlock() : already have block %d %s", mapBlockIndex[hash]->nHeight, hash.ToString().substr(0,20).c_str());
    if (mapOrphanBlocks.count(hash))
        return error("ProcessBlock() : already have block (orphan) %s", hash.ToString().substr(0,20).c_str());

    // ppcoin: check proof-of-stake
    // Limited duplicity on stake: prevents block flood attack
    // Duplicate stake allowed only when there is orphan child block
    if (pblock->IsProofOfStake() && setStakeSeen.count(pblock->GetProofOfStake()) && !mapOrphanBlocksByPrev.count(hash) && !Checkpoints::WantedByPendingSyncCheckpoint(hash))
        return error("ProcessBlock() : duplicate proof-of-stake (%s, %d) for block %s", pblock->GetProofOfStake().first.ToString().c_str(), pblock->GetProofOfStake().second, hash.ToString().c_str());

    if (pblock->IsProofOfStake() && mapBlockIndex.count(pblock->hashPrevBlock))
    {
        CBlockIndex* pindexPrev = mapBlockIndex[pblock->hashPrevBlock];
        if (pindexPrev && pindexPrev->nHeight + 1 >= FORK_HEIGHT_DAG)
        {
            if (pfrom)
                pfrom->Misbehaving(100, "proof-of-stake block after DAG fork");
            return error("ProcessBlock() : proof-of-stake block after DAG fork");
        }
    }

    // Preliminary checks
    int64_t nCheckStart = GetTimeMillis();
    if (!pblock->CheckBlock())
        return error("ProcessBlock() : CheckBlock FAILED");
    int64_t nCheckMs = GetTimeMillis() - nCheckStart;

    CBlockIndex* pcheckpoint = Checkpoints::GetLastSyncCheckpoint();
    if (pcheckpoint && pblock->hashPrevBlock != hashBestChain && !Checkpoints::WantedByPendingSyncCheckpoint(hash))
    {
        // Extra checks to prevent "fill up memory by spamming with bogus blocks"
        int64_t deltaTime = pblock->GetBlockTime() - pcheckpoint->nTime;
        CBigNum bnNewBlock;
        bnNewBlock.SetCompact(pblock->nBits);
        CBigNum bnRequired;

        if (pblock->IsProofOfStake())
            bnRequired.SetCompact(ComputeMinStake(GetLastBlockIndex(pcheckpoint, true)->nBits, deltaTime, pblock->nTime));
        else
            bnRequired.SetCompact(ComputeMinWork(GetLastBlockIndex(pcheckpoint, false)->nBits, deltaTime));

        if (bnNewBlock > bnRequired)
        {
            // A catching-up peer relaying an unattachable block is normal; reject without scoring.
            if (pfrom && !IsInitialBlockDownload())
                pfrom->Misbehaving(100, "block has too little work/stake");
            return error("ProcessBlock() : block with too little %s", pblock->IsProofOfStake()? "proof-of-stake" : "proof-of-work");
        }
    }

    // Innova: ask for pending sync-checkpoint if any
    if (!IsInitialBlockDownload()){

        Checkpoints::AskForPendingSyncCheckpoint(pfrom);

        CScript payee;

        if (!fImporting && !fReindex && pindexBest->nHeight > Checkpoints::GetTotalBlocksEstimate()){
            if(collateralnodePayments.GetBlockPayee(pindexBest->nHeight, payee)){
                // MAYBE NEEDS TO BE REWORKED
                //UPDATE COLLATERALNODE LAST PAID TIME
                // CCollateralnode* pmn = mnodeman.Find(vin);
                // if(pmn != NULL) {
                //     pmn->nLastPaid = GetAdjustedTime();
                // }

                printf("ProcessBlock() : Got BlockPayee for block : - %d\n", pindexBest->nHeight);
            }

            colLateralPool.CheckTimeout();
            colLateralPool.NewBlock();
            collateralnodePayments.ProcessBlock((pindexBest->nHeight)+10);

        }

    }

    // Hold blocks whose primary parent is known but whose DAG
    // merge parents are still in flight. Without this, live DAG sync can
    // incorrectly DoS-score peers for ordinary out-of-order delivery.
    if (pindexBest && pindexBest->nHeight + 1 >= FORK_HEIGHT_DAG && mapBlockIndex.count(pblock->hashPrevBlock))
    {
        std::vector<uint256> vMissingDAGParents = GetMissingDAGMergeParents(*pblock);
        if (!vMissingDAGParents.empty())
        {
            if (fDebug)
                printf("ProcessBlock: DAG ORPHAN BLOCK %s, missing merge parent=%s\n",
                       hash.ToString().substr(0,20).c_str(),
                       vMissingDAGParents[0].ToString().substr(0,20).c_str());

            PruneOrphanBlocks();

            if (pfrom)
            {
                int nOrphansFromPeer = mapOrphanCountByNode[pfrom->GetId()];
                if (nOrphansFromPeer >= MAX_ORPHAN_BLOCKS_PER_PEER)
                {
                    pfrom->PushGetBlocks(pindexBest, uint256(0));

                    if (IsInitialBlockDownload())
                        return error("ProcessBlock() : peer %d exceeded DAG orphan limit (IBD, no penalty) %s", pfrom->GetId(), hash.ToString().substr(0,20).c_str());
                    pfrom->Misbehaving(1, "DAG orphan limit exceeded");
                    return error("ProcessBlock() : peer %d exceeded DAG orphan limit %s", pfrom->GetId(), hash.ToString().substr(0,20).c_str());
                }
            }

            CBlock* pblock2 = new CBlock(*pblock);
            mapOrphanBlocks.insert(make_pair(hash, pblock2));
            mapOrphanBlocksByPrev.insert(make_pair(vMissingDAGParents[0], pblock2));

            if (pfrom)
            {
                mapOrphanBlocksByNode[hash] = pfrom->GetId();
                mapOrphanCountByNode[pfrom->GetId()]++;
                for (const uint256& hashMissing : vMissingDAGParents)
                    pfrom->AskFor(CInv(MSG_BLOCK, hashMissing));
            }
            return true;
        }
    }

    // If don't already have its previous block, shunt it off to holding area until we get it
    if (!mapBlockIndex.count(pblock->hashPrevBlock)) //pblock->hashPrevBlock != 0 &&
    {
        if (fDebug)
            printf("ProcessBlock: ORPHAN BLOCK, prev=%s\n", pblock->hashPrevBlock.ToString().substr(0,20).c_str());
            //LogPrintf("ProcessBlock: ORPHAN BLOCK %lu, prev=%s\n", (unsigned long)mapOrphanBlocks.size(), pblock->hashPrevBlock.ToString());

        PruneOrphanBlocks();

        if (IsInitialBlockDownload()) {
            static int64_t nLastOrphanCountClear = 0;
            int64_t nNow = GetTime();
            if (nNow - nLastOrphanCountClear > 30) {
                mapOrphanCountByNode.clear();
                nLastOrphanCountClear = nNow;
                if (fDebug)
                    printf("IBD: Cleared per-peer orphan counts to prevent sync stall\n");
            }
        }

        if (pfrom) {
            int nOrphansFromPeer = mapOrphanCountByNode[pfrom->GetId()];
            if (nOrphansFromPeer >= MAX_ORPHAN_BLOCKS_PER_PEER) {
                pfrom->PushGetBlocks(pindexBest, uint256(0));

                if (IsInitialBlockDownload()) {
                    return error("ProcessBlock() : peer %d exceeded orphan limit (IBD, no penalty) %s", pfrom->GetId(), hash.ToString().substr(0,20).c_str());
                }
                pfrom->Misbehaving(1, "orphan block limit exceeded");
                return error("ProcessBlock() : peer %d exceeded orphan limit %s", pfrom->GetId(), hash.ToString().substr(0,20).c_str());
            }
        }

        // ppcoin: check proof-of-stake
        if (pblock->IsProofOfStake())
        {
            // Limited duplicity on stake: prevents block flood attack
            // Duplicate stake allowed only when there is orphan child block
            if (setStakeSeenOrphan.count(pblock->GetProofOfStake()) && !mapOrphanBlocksByPrev.count(hash) && !Checkpoints::WantedByPendingSyncCheckpoint(hash))
                return error("ProcessBlock() : duplicate proof-of-stake (%s, %d) for orphan block %s", pblock->GetProofOfStake().first.ToString().c_str(), pblock->GetProofOfStake().second, hash.ToString().c_str());
            else
                setStakeSeenOrphan.insert(pblock->GetProofOfStake());
        }
        CBlock* pblock2 = new CBlock(*pblock);
        mapOrphanBlocks.insert(make_pair(hash, pblock2));
        mapOrphanBlocksByPrev.insert(make_pair(pblock2->hashPrevBlock, pblock2));

        if (pfrom) {
            mapOrphanBlocksByNode[hash] = pfrom->GetId();
            mapOrphanCountByNode[pfrom->GetId()]++;
        }

        // Ask this guy to fill in what we're missing
        if (pfrom)
        {
            pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(pblock2));
			//PushGetBlocks(pfrom, pindexBest, GetOrphanRoot(pblock2));
            // ppcoin: getblocks may not obtain the ancestor block rejected
            // earlier by duplicate-stake check so we ask for it again directly
            pfrom->AskFor(CInv(MSG_BLOCK, WantedByOrphan(pblock2)));
        }
        return true;
    }

    // Store to disk
    int64_t nAcceptStart = GetTimeMillis();
    if (!pblock->AcceptBlock())
        return error("ProcessBlock() : AcceptBlock FAILED");
    int64_t nAcceptMs = GetTimeMillis() - nAcceptStart;

    // Recursively process any orphan blocks that depended on this one
    vector<uint256> vWorkQueue;
    vWorkQueue.push_back(hash);
    for (unsigned int i = 0; i < vWorkQueue.size(); i++)
    {
        uint256 hashPrev = vWorkQueue[i];
        for (multimap<uint256, CBlock*>::iterator mi = mapOrphanBlocksByPrev.lower_bound(hashPrev);
             mi != mapOrphanBlocksByPrev.upper_bound(hashPrev);
             ++mi)
        {
            CBlock* pblockOrphan = (*mi).second;
            uint256 orphanHash = pblockOrphan->GetHash();
            std::vector<uint256> vMissingDAGParents = GetMissingDAGMergeParents(*pblockOrphan);
            if (!vMissingDAGParents.empty())
            {
                if (fDebug)
                    printf("ProcessBlock: DAG orphan %s still missing merge parent %s\n",
                           orphanHash.ToString().substr(0,20).c_str(),
                           vMissingDAGParents[0].ToString().substr(0,20).c_str());
                mapOrphanBlocksByPrev.insert(make_pair(vMissingDAGParents[0], pblockOrphan));
                if (pfrom)
                {
                    for (const uint256& hashMissing : vMissingDAGParents)
                        pfrom->AskFor(CInv(MSG_BLOCK, hashMissing));
                }
                continue;
            }
            if (pblockOrphan->AcceptBlock())
                vWorkQueue.push_back(orphanHash);
            mapOrphanBlocks.erase(orphanHash);
            // Release the stake marker only when no other stored orphan still
            // references the kernel (duplicate stakes are allowed on the
            // orphan path while an orphan child depends on the block).
            if (pblockOrphan->IsProofOfStake())
                EraseStakeSeenOrphanIfUnreferenced(pblockOrphan->GetProofOfStake());

            map<uint256, NodeId>::iterator nodeIt = mapOrphanBlocksByNode.find(orphanHash);
            if (nodeIt != mapOrphanBlocksByNode.end()) {
                mapOrphanCountByNode[nodeIt->second]--;
                mapOrphanBlocksByNode.erase(nodeIt);
            }

            delete pblockOrphan;
        }
        mapOrphanBlocksByPrev.erase(hashPrev);
    }

    if (fDebug && GetBoolArg("-showtimers", false)) {
        printf("ProcessBlock: ACCEPTED total=%" PRId64"ms check=%" PRId64"ms accept=%" PRId64"ms\n",
               GetTimeMillis() - nStartTime, nCheckMs, nAcceptMs);
    } else {
        if (fDebug) printf("ProcessBlock: ACCEPTED\n");
    }

    // ppcoin: if responsible for sync-checkpoint send it
    if (pfrom && !CSyncCheckpoint::strMasterPrivKey.empty())
        Checkpoints::SendSyncCheckpoint(Checkpoints::AutoSelectSyncCheckpoint()->GetBlockHash());

    return true;
}

// novacoin: attempt to generate suitable proof-of-stake
bool CBlock::SignBlock(CWallet& wallet, int64_t nFees)
{
    // if we are trying to sign
    //    something except proof-of-stake block template
    if (!vtx[0].vout[0].IsEmpty())
        return false;

    // if we are trying to sign
    //    a complete proof-of-stake block
    if (IsProofOfStake())
        return true;

    // nLastCoinStakeSearchTime = GetAdjustedTime(); // startup timestamp
    // nLastCoinStakeSearchTime = pindexBest->GetBlockTime(); // time of the last block in our index

    CKey key;
    CTransaction txCoinStake; // make a new transaction.
    int64_t nSearchTime = txCoinStake.nTime; // search to current time

    if (fDebug && GetBoolArg("-printcoinstake")) printf ("searchtime %" PRId64 " to %" PRId64 " \n", nSearchTime, nLastCoinStakeSearchTime);
    if (nSearchTime > nLastCoinStakeSearchTime)
    {
        if (fDebug && GetBoolArg("-printcoinstake")) printf ("nSearchTime %" PRId64 " > nLastCoinStakeSearchTime %" PRId64 "\n", nSearchTime, nLastCoinStakeSearchTime);
        if (wallet.CreateCoinStake(wallet, nBits, nSearchTime-nLastCoinStakeSearchTime, nFees, txCoinStake, key))
        {
            if (fDebug && GetBoolArg("-printcoinstake")) printf ("CreateCoinStake succeeded \n");
            if (txCoinStake.nTime >= max(pindexBest->GetPastTimeLimit()+1, PastDrift(pindexBest->GetBlockTime(), pindexBest->nHeight + 1)))
            {
                if (fDebug && GetBoolArg("-printcoinstake")) printf ("txCoinStake.nTime >= max(pindexBest->GetPastTimeLimit()+1, PastDrift(pindexBest->GetBlockTime()))");
                // make sure coinstake would meet timestamp protocol
                //    as it would be the same as the block timestamp
                vtx[0].nTime = nTime = txCoinStake.nTime;
                nTime = max(pindexBest->GetPastTimeLimit()+1, GetMaxTransactionTime());
                nTime = max(GetBlockTime(), PastDrift(pindexBest->GetBlockTime(), pindexBest->nHeight + 1));

                // we have to make sure that we have no future timestamps in
                //    our transactions set
                for (vector<CTransaction>::iterator it = vtx.begin(); it != vtx.end();)
                    if (it->nTime > nTime) { it = vtx.erase(it); } else { ++it; }

                vtx.insert(vtx.begin() + 1, txCoinStake);
                // The kernel moved nTime after assembly; re-derive the offset before the merkle root.
                // Skipped for an IV5 coinbase, whose payload binds that output.
                if (vtx[0].IsPrivacyVNext())
                    printf("SignBlock: keeping the template millisecond offset; "
                           "the coinbase carries an IV5 payload\n");
                else
                    StampMsTimestampCommitment(this, pindexBest->nHeight + 1);
                hashMerkleRoot = BuildMerkleTree();

                // append a signature to our block
                return key.Sign(GetHash(), vchBlockSig);
            }
        }
        nLastCoinStakeSearchInterval = nSearchTime - nLastCoinStakeSearchTime;
        nLastCoinStakeSearchTime = nSearchTime;
        if (fDebug && GetBoolArg("-printcoinstake")) printf ("CreateCoinStake failed at %" PRId64 ". Try again in %" PRId64 "\n", nLastCoinStakeSearchTime, nLastCoinStakeSearchInterval);
    }

    return false;
}

bool CBlock::CheckBlockSignature() const
{
    if (IsProofOfWork())
        return vchBlockSig.empty();

    // NullStake V1/V2: verify block signature against rk from the first shielded spend
    if (vtx[1].nVersion == SHIELDED_TX_VERSION_NULLSTAKE || vtx[1].nVersion == SHIELDED_TX_VERSION_NULLSTAKE_V2)
    {
        if (vchBlockSig.empty())
            return false;

        if (vtx[1].vShieldedSpend.empty() || vtx[1].vShieldedSpend[0].vchRk.empty())
            return false;

        if (vtx[1].vShieldedSpend[0].vchRk.size() != 33 && vtx[1].vShieldedSpend[0].vchRk.size() != 65)
            return false;

        CPubKey rkPubKey(vtx[1].vShieldedSpend[0].vchRk);
        if (!rkPubKey.IsValid() || !rkPubKey.IsFullyValid())
            return false;

        return rkPubKey.Verify(GetHash(), vchBlockSig);
    }

    // NullStake V3 (Private Cold Staking): verify the block signature against pk_stake (1-of-1)
    // or, for B2-e M-of-N, against any member of the committed staker set.
    if (vtx[1].nVersion == SHIELDED_TX_VERSION_NULLSTAKE_COLD)
    {
        if (vchBlockSig.empty())
            return false;

        const CNullStakeKernelProofV3& p = vtx[1].nullstakeProofV3;

        if (p.nThresholdM > 0)
        {
            // M-of-N has no single staking key. The block producer is a hot-wallet member of
            // the staker set; require the block signature to verify against ANY committed set
            // member. The M-of-N authorization of the stake itself is enforced separately in
            // the kernel proof (VerifyNullStakeMofNKernelProofV3); this only ties the block to
            // a legitimate set member so a non-member cannot stuff the coinstake into a block.
            for (size_t i = 0; i < p.vStakerSet.size(); i++)
            {
                if (p.vStakerSet[i].size() != 33)
                    continue;
                CPubKey member(p.vStakerSet[i]);
                if (member.IsValid() && member.IsFullyValid() && member.Verify(GetHash(), vchBlockSig))
                    return true;
            }
            return false;
        }

        if (p.vchPkStake.size() != 33)
            return false;

        CPubKey pkStake(p.vchPkStake);
        if (!pkStake.IsValid() || !pkStake.IsFullyValid())
            return false;

        return pkStake.Verify(GetHash(), vchBlockSig);
    }

    vector<valtype> vSolutions;
    txnouttype whichType;

    const CTxOut& txout = vtx[1].vout[1];

    if (!Solver(txout.scriptPubKey, whichType, vSolutions))
        return false;

    if (whichType == TX_PUBKEY)
    {
        valtype& vchPubKey = vSolutions[0];
        return CPubKey(vchPubKey).Verify(GetHash(), vchBlockSig);
    }

    if (whichType == TX_COLDSTAKE)
    {
        const CScript& scriptSig = vtx[1].vin[0].scriptSig;
        CScript::const_iterator pc = scriptSig.begin();
        opcodetype opcode;
        valtype vchSig, vchFlag, vchPubKey;

        if (!scriptSig.GetOp(pc, opcode, vchSig))
            return false;
        if (!scriptSig.GetOp(pc, opcode, vchFlag))
            return false;
        if (!scriptSig.GetOp(pc, opcode, vchPubKey))
            return false;

        CPubKey pubkey(vchPubKey);
        if (!pubkey.IsValid())
            return false;

        CKeyID stakerKeyID = CKeyID(uint160(vSolutions[0]));
        if (pubkey.GetID() != stakerKeyID)
            return false;

        return pubkey.Verify(GetHash(), vchBlockSig);
    }

    return false;
}

bool CheckDiskSpace(uint64_t nAdditionalBytes)
{
    uint64_t nFreeBytesAvailable = fs::space(GetDataDir()).available;

    // Check for nMinDiskSpace bytes
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
    {
        fShutdown = true;
        string strMessage = _("Warning: Disk space is low!");
        strMiscWarning = strMessage;
        printf("*** %s\n", strMessage.c_str());
        uiInterface.ThreadSafeMessageBox(strMessage, "Innova", CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
        StartShutdown();
        return false;
    }
    return true;
}

static unsigned int nCurrentBlockFile = 1;

static fs::path BlockFilePath(unsigned int nFile)
{
    string strBlockFn = strprintf("blk%04u.dat", nFile);
    return GetDataDir() / strBlockFn;
}

FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode)
{
    if ((nFile < 1) || (nFile == (unsigned int) -1))
        return NULL;
    FILE* file = fopen(BlockFilePath(nFile).string().c_str(), pszMode);
    if (!file)
        return NULL;
    if (nBlockPos != 0 && !strchr(pszMode, 'a') && !strchr(pszMode, 'w'))
    {
        if (fseek(file, nBlockPos, SEEK_SET) != 0)
        {
            fclose(file);
            return NULL;
        }
    }
    return file;
}

FILE* AppendBlockFile(unsigned int& nFileRet)
{
    nFileRet = 0;
    while (true)
    {
        FILE* file = OpenBlockFile(nCurrentBlockFile, 0, "ab");
        if (!file)
            return NULL;
        if (fseek(file, 0, SEEK_END) != 0)
            return NULL;
        // FAT32 file size max 4GB, fseek and ftell max 2GB, so we must stay under 2GB
        if (ftell(file) < (long)(0x7F000000 - MAX_SIZE))
        {
            nFileRet = nCurrentBlockFile;
            return file;
        }
        fclose(file);
        nCurrentBlockFile++;
    }
}

bool LoadBlockIndex(bool fAllowNew)
{
    LOCK(cs_main);

    if (fRegTest)
    {
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;

        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        nStakeMinAge = 0;
        nCoinbaseMaturity = 1;
        nTargetSpacing = 1;
    }
    else if (fTestNet)
    {
        pchMessageStart[0] = 0x9b;
        pchMessageStart[1] = 0x1d;
        pchMessageStart[2] = 0xfc;
        pchMessageStart[3] = 0x26;

        bnProofOfWorkLimit = bnProofOfWorkLimitTestNet; // 16 bits PoW target limit for testnet
        bnProofOfStakeLimit = bnProofOfStakeLimitTestNet; // much easier PoS for testnet
        nStakeMinAge = 1 * 60; // test net min age is 1 minute
        nCoinbaseMaturity = 15; // test maturity is 15 blocks
    };

    //
    // Load block index
    //
    CTxDB txdb("cr+");
    if (!txdb.LoadBlockIndex())
        return false;

    //
    // Init with genesis block
    //
    if (mapBlockIndex.empty())
    {
        if (!fAllowNew)
            return false;

        // With IDNS active from genesis, create the auxiliary database before AddToBlockIndex
        // commits genesis; the chain effect journal opens it read-only.
        if (RELEASE_HEIGHT == 0)
        {
            std::string strNameIndexBootstrapError;
            if (!CommitNameIndexTip(NULL, strNameIndexBootstrapError))
                return error("LoadBlockIndex() : could not initialize the "
                             "genesis name-index cursor: %s",
                             strNameIndexBootstrapError.c_str());
        }

        if(fRegTest)
        {
            const char* pszTimestampRegTest = "Innova RegTest Mode";
            CTransaction txNewRegTest;

            txNewRegTest.nTime = 1296688602;
            txNewRegTest.vin.resize(1);
            txNewRegTest.vout.resize(1);
            txNewRegTest.vin[0].scriptSig = CScript() << 0 << CBigNum(42) << vector<unsigned char>((const unsigned char*)pszTimestampRegTest, (const unsigned char*)pszTimestampRegTest + strlen(pszTimestampRegTest));
            txNewRegTest.vout[0].SetEmpty();

            CBlock blockRegTest;
            blockRegTest.vtx.push_back(txNewRegTest);
            blockRegTest.hashPrevBlock = 0;
            blockRegTest.hashMerkleRoot = blockRegTest.BuildMerkleTree();
            blockRegTest.nTime    = 1296688602;
            blockRegTest.nVersion = 1;
            blockRegTest.nBits    = bnProofOfWorkLimit.GetCompact();
            blockRegTest.nNonce   = 2;

            printf("RegTest blockRegTest.GetHash() == %s\n", blockRegTest.GetHash().ToString().c_str());
            printf("RegTest blockRegTest.hashMerkleRoot == %s\n", blockRegTest.hashMerkleRoot.ToString().c_str());
            printf("RegTest blockRegTest.nBits = 0x%08x\n", blockRegTest.nBits);

            unsigned int nFile;
            unsigned int nBlockPos;
            if (!blockRegTest.WriteToDisk(nFile, nBlockPos))
                return error("RegTestLoadBlockIndex() : writing genesis block to disk failed");

            uint256 hashRegTestGenesis = blockRegTest.GetHash();
            if (!blockRegTest.AddToBlockIndex(nFile, nBlockPos, hashRegTestGenesis))
                return error("RegTestLoadBlockIndex() : genesis block not accepted");

            if (!Checkpoints::WriteSyncCheckpoint(hashRegTestGenesis))
                return error("RegTestLoadBlockIndex() : failed to init sync checkpoint");

            printf("RegTest genesis block initialized: %s\n", hashRegTestGenesis.ToString().c_str());
        }
        else if(fTestNet)
        {
            const char* pszTimestampTestNet = "Innova Public IDAG Hidden Finality Testnet | May 26 2026 | Epoch-Root FCMP";
            CTransaction txNewTestNet;

            txNewTestNet.nTime = 1779753600;
            txNewTestNet.vin.resize(1);
            txNewTestNet.vout.resize(1);
            txNewTestNet.vin[0].scriptSig = CScript() << 0 << CBigNum(42) << vector<unsigned char>((const unsigned char*)pszTimestampTestNet, (const unsigned char*)pszTimestampTestNet + strlen(pszTimestampTestNet));
            txNewTestNet.vout[0].SetEmpty();

            CBlock blocktest;
            blocktest.vtx.push_back(txNewTestNet);
            blocktest.hashPrevBlock = 0;
            blocktest.hashMerkleRoot = blocktest.BuildMerkleTree();
            blocktest.nTime    = 1779753600;
            blocktest.nVersion = 1;
            blocktest.nBits    = bnProofOfWorkLimit.GetCompact();
            blocktest.nNonce   = 127761;

            if (false && (blocktest.GetHash() != hashGenesisBlockTestNet))
            {
            // This will figure out a valid hash and Nonce if you're
            // creating a different genesis block:
                uint256 hashTarget = CBigNum().SetCompact(blocktest.nBits).getuint256();
                while (blocktest.GetHash() > hashTarget)
                {
                    ++blocktest.nNonce;
                    if (blocktest.nNonce == 0)
                    {
                        printf("NONCE WRAPPED, incrementing time");
                        ++blocktest.nTime;
                    }
                }
            }
            blocktest.print();
            printf("TestNet blocktest.GetHash() == %s\n", blocktest.GetHash().ToString().c_str());
            printf("TestNet blocktest.hashMerkleRoot == %s\n", blocktest.hashMerkleRoot.ToString().c_str());
            printf("TestNet blocktest.nTime = %u \n", blocktest.nTime);
            printf("TestNet blocktest.nNonce = %u \n", blocktest.nNonce);


            //// debug print
            if (blocktest.hashMerkleRoot != uint256("0xa18a28c4cde90e5c637c63715018a466511dd22eccd8f371512eec3074b1b19d"))
                return error("TestNetLoadBlockIndex() : invalid testnet genesis merkle root %s", blocktest.hashMerkleRoot.ToString().c_str());
            blocktest.print();
            if (blocktest.GetHash() != hashGenesisBlockTestNet)
                return error("TestNetLoadBlockIndex() : invalid testnet genesis hash %s", blocktest.GetHash().ToString().c_str());
            if (!blocktest.CheckBlock())
                return error("TestNetLoadBlockIndex() : testnet genesis block validation failed");

            // -- debug print
            if (fDebugChain)
            {
                printf("Initialised Innova TestNet genesis block:\n");
                blocktest.print();
            };

            // Start new block file
            unsigned int nFile;
            unsigned int nBlockPos;
            if (!blocktest.WriteToDisk(nFile, nBlockPos))
                return error("TestNetLoadBlockIndex() : writing genesis block to disk failed");
            if (!blocktest.AddToBlockIndex(nFile, nBlockPos, hashGenesisBlockTestNet))
                return error("TestNetLoadBlockIndex() : Testnet genesis block not accepted");

            // ppcoin: initialize synchronized checkpoint
            if (!Checkpoints::WriteSyncCheckpoint(hashGenesisBlockTestNet))
                return error("TestNetLoadBlockIndex() : failed to init sync checkpoint");

        } else {

            const char* pszTimestamp = "Innova Blockchain starts on 12/10/2019";
            CTransaction txNew;
            txNew.nTime = 1576002227;
            txNew.vin.resize(1);
            txNew.vout.resize(1);
            txNew.vin[0].scriptSig = CScript() << 0 << CBigNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
            txNew.vout[0].SetEmpty();

            CBlock block;
            block.vtx.push_back(txNew);
            block.hashPrevBlock = 0;
            block.hashMerkleRoot = block.BuildMerkleTree();
            block.nTime    = 1576002227;
            block.nVersion = 1;
            block.nBits    = bnProofOfWorkLimit.GetCompact();
            block.nNonce   = 253080;

            if (false && (block.GetHash() != hashGenesisBlock)) {
            // This will figure out a valid hash and Nonce if you're
            // creating a different genesis block:
                uint256 hashTarget = CBigNum().SetCompact(block.nBits).getuint256();
                while (block.GetHash() > hashTarget)
                {
                    ++block.nNonce;
                    if (block.nNonce == 0)
                    {
                        printf("NONCE WRAPPED, incrementing time");
                        ++block.nTime;
                    }
                }
            }
            block.print();
            printf("block.GetHash() == %s\n", block.GetHash().ToString().c_str());
            printf("block.hashMerkleRoot == %s\n", block.hashMerkleRoot.ToString().c_str());
            printf("block.nTime = %u \n", block.nTime);
            printf("block.nNonce = %u \n", block.nNonce);


            //// debug print
            assert(block.hashMerkleRoot == uint256("0x7fe3177ea86b03a9c8773b32a3db36f32f4011bec4a0724032c36bc1c9d569a0"));
            block.print();
            assert(block.GetHash() == hashGenesisBlock);
            assert(block.CheckBlock());

            // -- debug print
            if (fDebugChain)
            {
                printf("Initialised genesis block:\n");
                block.print();
            };

            // Start new block file
            unsigned int nFile;
            unsigned int nBlockPos;
            if (!block.WriteToDisk(nFile, nBlockPos))
                return error("LoadBlockIndex() : writing genesis block to disk failed");
            if (!block.AddToBlockIndex(nFile, nBlockPos, hashGenesisBlock))
                return error("LoadBlockIndex() : genesis block not accepted");

            // ppcoin: initialize synchronized checkpoint
            if (!Checkpoints::WriteSyncCheckpoint(hashGenesisBlock))
                return error("LoadBlockIndex() : failed to init sync checkpoint");
        }
    }

    string strPubKey = "";

    // if checkpoint master key changed must reset sync-checkpoint
    if (!txdb.ReadCheckpointPubKey(strPubKey) || strPubKey != CSyncCheckpoint::strMasterPubKey)
    {
        // write checkpoint master key to db
        txdb.TxnBegin();
        if (!txdb.WriteCheckpointPubKey(CSyncCheckpoint::strMasterPubKey))
            return error("LoadBlockIndex() : failed to write new checkpoint master key to db");
        if (!txdb.TxnCommit())
            return error("LoadBlockIndex() : failed to commit new checkpoint master key to db");
        if ((!fTestNet) && (!fRegTest) && !Checkpoints::ResetSyncCheckpoint())
            return error("LoadBlockIndex() : failed to reset sync-checkpoint");
    }

    return true;
}



void PrintBlockTree()
{
    AssertLockHeld(cs_main);
    // pre-compute tree structure
    map<CBlockIndex*, vector<CBlockIndex*> > mapNext;
    for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
    {
        CBlockIndex* pindex = (*mi).second;
        mapNext[pindex->pprev].push_back(pindex);
        // test
        //while (rand() % 3 == 0)
        //    mapNext[pindex->pprev].push_back(pindex);
    }

    vector<pair<int, CBlockIndex*> > vStack;
    vStack.push_back(make_pair(0, pindexGenesisBlock));

    int nPrevCol = 0;
    while (!vStack.empty())
    {
        int nCol = vStack.back().first;
        CBlockIndex* pindex = vStack.back().second;
        vStack.pop_back();

        // print split or gap
        if (nCol > nPrevCol)
        {
            for (int i = 0; i < nCol-1; i++)
                printf("| ");
            printf("|\\\n");
        }
        else if (nCol < nPrevCol)
        {
            for (int i = 0; i < nCol; i++)
                printf("| ");
            printf("|\n");
       }
        nPrevCol = nCol;

        // print columns
        for (int i = 0; i < nCol; i++)
            printf("| ");

        // print item
        CBlock block;
        block.ReadFromDisk(pindex);
        printf("%d (%u,%u) %s  %08x  %s  mint %7s  tx %" PRIszu"",
            pindex->nHeight,
            pindex->nFile,
            pindex->nBlockPos,
            block.GetHash().ToString().c_str(),
            block.nBits,
            DateTimeStrFormat("%x %H:%M:%S", block.GetBlockTime()).c_str(),
            FormatMoney(pindex->nMint).c_str(),
            block.vtx.size());

        //PrintWallets(block);

        // put the main time-chain first
        vector<CBlockIndex*>& vNext = mapNext[pindex];
        for (unsigned int i = 0; i < vNext.size(); i++)
        {
            if (vNext[i]->pnext)
            {
                swap(vNext[0], vNext[i]);
                break;
            }
        }

        // iterate children
        for (unsigned int i = 0; i < vNext.size(); i++)
            vStack.push_back(make_pair(nCol+i, vNext[i]));
    }
}

// A frame carrying the genesis block is already indexed, so ProcessBlock
// rejects it. That is not an import failure and must not fail the replay gate.
static bool ImportFrameIsIndexedGenesis(const CBlock& block)
{
    return pindexGenesisBlock != NULL &&
           block.GetHash() == GetGenesisBlockHash();
}

bool LoadExternalBlockFile(FILE* fileIn)
{
    int64_t nStart = GetTimeMillis();

    int nLoaded = 0;
    int nFailed = 0;
    int nSkipped = 0;
    {
        LOCK(cs_main);
        CAutoFile blkdat(fileIn, SER_DISK, CLIENT_VERSION);
        unsigned int nPos = 0;
        while (nPos != (unsigned int)-1 && blkdat.good() && !fRequestShutdown)
        {
            unsigned char pchData[65536];
            do {
                fseek(blkdat, nPos, SEEK_SET);
                int nRead = fread(pchData, 1, sizeof(pchData), blkdat);
                if (nRead <= 8)
                {
                    nPos = (unsigned int)-1;
                    break;
                }
                void* nFind = memchr(pchData, pchMessageStart[0], nRead+1-sizeof(pchMessageStart));
                if (nFind)
                {
                    if (memcmp(nFind, pchMessageStart, sizeof(pchMessageStart))==0)
                    {
                        nPos += ((unsigned char*)nFind - pchData) + sizeof(pchMessageStart);
                        break;
                    }
                    nPos += ((unsigned char*)nFind - pchData) + 1;
                }
                else
                    nPos += sizeof(pchData) - sizeof(pchMessageStart) + 1;
            } while(!fRequestShutdown);
            if (nPos == (unsigned int)-1)
                break;
            // Process each frame inside its own try, and ALWAYS advance nPos past a
            // rejected/corrupt frame, so one bad frame can neither abort the rest of
            // the file nor make the scanner re-walk block content as if it were magic.
            try {
                fseek(blkdat, nPos, SEEK_SET);
                unsigned int nSize = 0;
                blkdat >> nSize;
                if (nSize == 0 || nSize > ADAPTIVE_BLOCK_CEILING)
                {
                    nPos += 4;          // bogus size: skip the field and resync on the next magic
                    nFailed++;
                    continue;
                }
                CBlock block;
                blkdat >> block;
                nPos += 4 + nSize;      // advance regardless of accept/reject
                if (ProcessBlock(NULL, &block))
                    nLoaded++;
                else if (ImportFrameIsIndexedGenesis(block))
                    nSkipped++;
                else
                {
                    nFailed++;
                    printf("LoadExternalBlockFile: REJECTED %s (prev %s) -- see the "
                           "preceding error for the failing check\n",
                           block.GetHash().ToString().c_str(),
                           block.hashPrevBlock.ToString().c_str());
                }
            }
            catch (std::exception &e) {
                printf("%s() : frame near pos %u skipped: %s\n", __PRETTY_FUNCTION__, nPos, e.what());
                nPos += 4;              // resync past the bad frame
                nFailed++;
            }
            if (((nLoaded + nFailed) % 10000) == 0 && (nLoaded + nFailed) > 0)
                printf("LoadExternalBlockFile: %d loaded, %d failed (%" PRId64"ms)\n",
                       nLoaded, nFailed, GetTimeMillis() - nStart);
        }
    }
    printf("Loaded %i blocks (%i failed, %i already-indexed genesis) from external file in %" PRId64"ms\n",
           nLoaded, nFailed, nSkipped, GetTimeMillis() - nStart);
    // Import is the only cold connect-from-genesis path, and the node may exit
    // before RPC is reachable, so emit the phase breakdown here as well.
    if (fBlockProfile)
        printf("%s", BlockProfileReport().c_str());
    // A history-replay gate is evidence only when every framed block was
    // accepted.  Partial import with one or more rejected/corrupt frames must
    // never be reported as a successful replay.
    return (nLoaded + nSkipped) > 0 && nFailed == 0 && !fRequestShutdown;
}

//////////////////////////////////////////////////////////////////////////////
//
// CAlert
//

extern map<uint256, CAlert> mapAlerts;
extern CCriticalSection cs_mapAlerts;

string GetWarnings(string strFor)
{
    int nPriority = 0;
    string strStatusBar;
    string strRPC;

    if (GetBoolArg("-testsafemode"))
        strRPC = "test";

    // Misc warnings like out of disk space and clock is wrong
    if (strMiscWarning != "")
    {
        nPriority = 1000;
        strStatusBar = strMiscWarning;
    }

    // if detected invalid checkpoint enter safe mode
    if (Checkpoints::hashInvalidCheckpoint != 0)
    {
        nPriority = 3000;
        strStatusBar = strRPC = _("WARNING: Invalid checkpoint found! Displayed transactions may not be correct! You may need to upgrade, or notify developers.");
    }

    // Alerts
    {
        LOCK(cs_mapAlerts);
        for (PAIRTYPE(const uint256, CAlert)& item : mapAlerts)
        {
            const CAlert& alert = item.second;
            if (alert.AppliesToMe() && alert.nPriority > nPriority)
            {
                nPriority = alert.nPriority;
                strStatusBar = alert.strStatusBar;
                if (nPriority > 1000)
                    strRPC = strStatusBar;
            }
        }
    }

    if (strFor == "statusbar")
        return strStatusBar;
    else if (strFor == "rpc")
        return strRPC;
    assert(!"GetWarnings() : invalid parameter");
    return "error";
}








//////////////////////////////////////////////////////////////////////////////
//
// Messages
//


bool static AlreadyHave(CTxDB& txdb, const CInv& inv)
{
    switch (inv.type)
    {
    case MSG_TX:
        {
        bool txInMap = false;
        txInMap = mempool.exists(inv.hash);
        return txInMap ||
               mapOrphanTransactions.count(inv.hash) ||
               txdb.ContainsTx(inv.hash);
        }

    case MSG_BLOCK:
        return mapBlockIndex.count(inv.hash) ||
               mapOrphanBlocks.count(inv.hash);
    case MSG_SPORK:
        return mapSporks.count(inv.hash);
    case MSG_COLLATERALNODE_WINNER:
        return mapSeenCollateralnodeVotes.count(inv.hash);
    }
    // Don't know what it is, just say we already got one
    return true;
}

void static ProcessGetData(CNode* pfrom)
{
    if (fDebugNet)
      printf("ProcessGetData\n");

    std::deque<CInv>::iterator it = pfrom->vRecvGetData.begin();

    vector<CInv> vNotFound;

    LOCK(cs_main);

    int nBlockBatchLimit = 1;
    if (pindexBest && pindexBest->nHeight >= FORK_HEIGHT_DAG)
        nBlockBatchLimit = GetArg("-getdatablockbatch", 16);
    if (nBlockBatchLimit < 1)
        nBlockBatchLimit = 1;
    if (nBlockBatchLimit > 128)
        nBlockBatchLimit = 128;
    int nBlocksServed = 0;

    while (it != pfrom->vRecvGetData.end()) {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->nSendSize >= SendBufferSize())
            break;

        if (fShutdown)
            return;

        const CInv &inv = *it;
        {
            boost::this_thread::interruption_point();
            it++;

            if (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK)
            {
                bool send = false;
                // Send block from disk
                map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(inv.hash);
                if (mi != mapBlockIndex.end())
                {
                    send = true;
                    CBlock block;
                    block.ReadFromDisk((*mi).second);

                    if (inv.type == MSG_FILTERED_BLOCK)
                    {
                        LOCK(pfrom->cs_filter);
                        if (pfrom->pfilter)
                        {
                            CMerkleBlock merkleBlock(block, *pfrom->pfilter);
                            pfrom->PushMessage("merkleblock", merkleBlock);
                            typedef std::pair<unsigned int, uint256> PairType;
                            for (const PairType& pair : merkleBlock.vMatchedTxn)
                                if (!pfrom->setInventoryKnown.count(CInv(MSG_TX, pair.second)))
                                    pfrom->PushMessage("tx", block.vtx[pair.first]);
                        }
                    }
                    else
                    {
                        pfrom->PushMessage("block", block);
                    }

                    // Trigger them to send a getblocks request for the next batch of inventory
                    if (inv.hash == pfrom->hashContinue)
                    {
                        // Bypass PushInventory, this must send even if redundant,
                        // and we want it right after the last block so they don't
                        // wait for other stuff first.
                        vector<CInv> vInv;
                        vInv.push_back(CInv(MSG_BLOCK, hashBestChain));
                        pfrom->PushMessage("inv", vInv);
                        pfrom->hashContinue = 0;
                    }
                }
                // disconnect node in case we have reached the outbound limit for serving historical blocks
                static const int nOneWeek = 7 * 24 * 60 * 60; // assume > 1 week = historical
                if (send && CNode::OutboundTargetReached(true) &&
                (
                    ((pindexBest != NULL) &&
                    (pindexBest->GetBlockTime() - mi->second->GetBlockTime() > nOneWeek)) ||
                    inv.type == MSG_BLOCK
                    ) && !pfrom->fWhitelisted)
                {
                    printf("net historical block serving limit reached, disconnected peer=%d\n", pfrom->GetId());

                    //disconnect node
                    pfrom->MarkDisconnect("historical-block-serving-limit");
                    send = false;
                }
            }
            else if (inv.IsKnownType())
            {
                // Send stream from relay memory
                bool pushed = false;
                if (inv.type == MSG_TX && (fDebugNet || GetBoolArg("-debugtxrelay", false)))
                    printf("TXRELAY getdata tx=%s peer=%s\n",
                           inv.hash.ToString().substr(0,10).c_str(),
                           pfrom->addr.ToString().c_str());
                {
                    LOCK(cs_mapRelay);
                    map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
                    if (mi != mapRelay.end()) {
                        pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                        pushed = true;
                        if (inv.type == MSG_TX && (fDebugNet || GetBoolArg("-debugtxrelay", false)))
                            printf("TXRELAY serve-relay tx=%s peer=%s\n",
                                   inv.hash.ToString().substr(0,10).c_str(),
                                   pfrom->addr.ToString().c_str());
                    }
                }
                if (!pushed && inv.type == MSG_TX) {
                    if(mapCollateralNBroadcastTxes.count(inv.hash)){
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss <<
                            mapCollateralNBroadcastTxes[inv.hash].tx <<
                            mapCollateralNBroadcastTxes[inv.hash].vin <<
                            mapCollateralNBroadcastTxes[inv.hash].vchSig <<
                            mapCollateralNBroadcastTxes[inv.hash].sigTime;

                        pfrom->PushMessage("dstx", ss);
                        pushed = true;
                    } else {
                        CTransaction tx;
                        if (mempool.lookup(inv.hash, tx)) {
                            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                            ss.reserve(1000);
                            ss << tx;
                            pfrom->PushMessage("tx", ss);
                            pushed = true;
                            if (fDebugNet || GetBoolArg("-debugtxrelay", false))
                                printf("TXRELAY serve-mempool tx=%s peer=%s\n",
                                       inv.hash.ToString().substr(0,10).c_str(),
                                       pfrom->addr.ToString().c_str());
                        }
                    }
                }
                if (!pushed && inv.type == MSG_SPORK) {
                    if(mapSporks.count(inv.hash)){
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << mapSporks[inv.hash];
                        pfrom->PushMessage("spork", ss);
                        pushed = true;
                    }
                }
                if (!pushed && inv.type == MSG_COLLATERALNODE_WINNER) {
                    if(mapSeenCollateralnodeVotes.count(inv.hash)){
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        int a = 0;
                        ss.reserve(1000);
                        ss << mapSeenCollateralnodeVotes[inv.hash] << a;
                        pfrom->PushMessage("mnw", ss);
                        pushed = true;
                    }
                }
                if (!pushed) {
                    vNotFound.push_back(inv);
                    if (inv.type == MSG_TX && (fDebugNet || GetBoolArg("-debugtxrelay", false)))
                        printf("TXRELAY notfound tx=%s peer=%s\n",
                               inv.hash.ToString().substr(0,10).c_str(),
                               pfrom->addr.ToString().c_str());
                }
            }

            // Track requests for our stuff.
            g_signals.Inventory(inv.hash);

            if (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK)
            {
                nBlocksServed++;
                if (nBlocksServed >= nBlockBatchLimit)
                    break;
            }
        }
    }

    pfrom->vRecvGetData.erase(pfrom->vRecvGetData.begin(), it);

    if (!vNotFound.empty()) {
        // Let the peer know that we didn't find what it asked for, so it doesn't
        // have to wait around forever. Currently only SPV clients actually care
        // about this message: it's needed when they are recursively walking the
        // dependencies of relevant unconfirmed transactions. SPV clients want to
        // do that because they want to know about (and store and rebroadcast and
        // risk analyze) the dependencies of transactions relevant to them, without
        // having to download the entire memory pool.
        pfrom->PushMessage("notfound", vNotFound);
    }
}

// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ASCII, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.
unsigned char pchMessageStart[4] = { 0xfa, 0xf4, 0x3f, 0xb7 };

bool static ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv, int64_t nTimeReceived)
{
    static map<CService, CPubKey> mapReuseKey;
    RandAddSeedPerfmon();
    if (fDebugNet)
        printf("received: %s (%" PRIszu" bytes)\n", strCommand.c_str(), vRecv.size());
    if (mapArgs.count("-dropmessagestest") && GetRand(atoi(mapArgs["-dropmessagestest"])) == 0)
    {
        printf("dropmessagestest DROPPING RECV MESSAGE\n");
        return true;
    }

    if (strCommand == "version")
    {
        // Each connection can only send one version message
        if (pfrom->nVersion != 0)
        {
            pfrom->Misbehaving(1, "duplicate version message");
            return false;
        }

        int64_t nTime;
        CAddress addrMe;
        CAddress addrFrom;
        uint64_t nNonce = 1;
        vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;

        // Old Node Versioning with Block Height Code
        bool oldVersion = false;

        if (pfrom->nVersion < MIN_PEER_PROTO_VERSION)
            oldVersion = true;

        /*
        if (pfrom->nVersion < PROTO_VERSION)
        {
            // disconnect from peers older than this proto version
            printf("partner %s using obsolete version %i; disconnecting\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
            pfrom->MarkDisconnect("proto-version-too-old");
            return false;
        }*/

        if (pfrom->nVersion == 10300)
            pfrom->nVersion = 300;
        if (!vRecv.empty())
            vRecv >> addrFrom >> nNonce;
        if (!vRecv.empty())
        {
            vRecv >> pfrom->strSubVer;
            if (pfrom->strSubVer.size() > 256)
                pfrom->strSubVer.resize(256);
        }
        if (!vRecv.empty())
        {
            vRecv >> pfrom->nChainHeight;
            pfrom->UpdateBestKnownBlock(pfrom->nChainHeight, uint256(0));
        }

        // Disconnect if the peer's subversion is < /Innovai:3.3.9.14/
        // Leaving this out for now until new update is out for a bit
        // if (pfrom->strSubVer != "/Innovai:3.3.9.14/")
        //     oldVersion = true;

        // print the current pfrom->strSubVer
        printf("ProcessMessage(): peer=%s using SubVer=%s, oldVersion=%s\n", pfrom->addr.ToString().c_str(), pfrom->strSubVer.c_str(), oldVersion ? "true" : "false");

        if (oldVersion == true)
        {
          printf("Partner %s using obsolete version %i; DISCONNECTING\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
          pfrom->MarkDisconnect("subver-obsolete");
          if (pfrom->fColLateralMaster)
              printf("Masternode hosting node version was obsolete. This masternode should be removed from the list\n");
          return false;
        }

        // if (pfrom->nSendBytes >= 1000000) // New arg flag per peer 1MB 1000000 bytes
        // {
        //     printf("data sent by peer = %i, disconnecting\n", pfrom->nSendBytes);
        //     printf("disconnecting node from max outbound per peer target: %s\n", pfrom->addr.ToString().c_str());
        //     pfrom->fDisconnect = true;
        //     return false;
        // }

        if (pfrom->fInbound && addrMe.IsRoutable())
        {
            pfrom->addrLocal = addrMe;
            SeenLocal(addrMe);
        }

        // Disconnect if we connected to ourself
        if (nNonce == nLocalHostNonce && nNonce > 1)
        {
            printf("connected to self at %s, disconnecting\n", pfrom->addr.ToString().c_str());
            pfrom->MarkDisconnect("connected-to-self");
            return true;
        }

        // record my external IP reported by peer
        if (addrFrom.IsRoutable() && addrMe.IsRoutable())
            addrSeenByPeer = addrMe;


        pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);

        if (GetBoolArg("-synctime", true))
            AddTimeData(pfrom->addr, nTime);

        // Change version
        pfrom->PushMessage("verack");
        pfrom->ssSend.SetVersion(min(pfrom->nVersion, PROTOCOL_VERSION));

        if (!pfrom->fInbound)
        {
            // Advertise our address
            if (!fNoListen && !IsInitialBlockDownload())
            {
                CAddress addr = GetLocalAddress(&pfrom->addr);
                if (addr.IsRoutable())
                    pfrom->PushAddress(addr);
            }

            // Get recent addresses
            if (pfrom->fOneShot || pfrom->nVersion >= CADDR_TIME_VERSION || addrman.size() < 1000)
            {
                pfrom->PushMessage("getaddr");
                pfrom->fGetAddr = true;
            }
            addrman.Good(pfrom->addr);
        } else {
            if (((CNetAddr)pfrom->addr) == (CNetAddr)addrFrom)
            {
                addrman.Add(addrFrom, addrFrom);
                addrman.Good(addrFrom);
            }
        }

        // Ask every node for the collateralnode list straight away
        pfrom->PushMessage("iseg", CTxIn());

        // Ask every eligible network peer for catch-up work. Per-peer
        // PushGetBlocks throttling keeps reconnect loops from spamming.
        if (!pfrom->fClient && !pfrom->fOneShot &&
            (pfrom->nBestKnownHeight < 0 || pfrom->nBestKnownHeight > (nBestHeight - 144)) &&
            (pfrom->nVersion < NOBLKS_VERSION_START ||
             pfrom->nVersion >= NOBLKS_VERSION_END))
        {
            pfrom->PushGetBlocks(pindexBest, uint256(0));
            pfrom->PushMessage("getheaders", CBlockLocator(pindexBest), uint256(0));
        }

        // Relay alerts
        {
            LOCK(cs_mapAlerts);
            for (PAIRTYPE(const uint256, CAlert)& item : mapAlerts)
                item.second.RelayTo(pfrom);
        }

        // Relay sync-checkpoint
        {
            LOCK(Checkpoints::cs_hashSyncCheckpoint);
            if (!Checkpoints::checkpointMessage.IsNull())
                Checkpoints::checkpointMessage.RelayTo(pfrom);
        }

        pfrom->fSuccessfullyConnected = true;
        pfrom->fRelayTxes = true;

        printf("receive version message: version %d, blocks=%d, us=%s, them=%s, peer=%s\n", pfrom->nVersion, pfrom->nChainHeight, addrMe.ToString().c_str(), addrFrom.ToString().c_str(), pfrom->addr.ToString().c_str());

        cPeerBlockCounts.input(pfrom->nBestKnownHeight >= 0 ? pfrom->nBestKnownHeight : pfrom->nChainHeight);

        // ppcoin: ask for pending sync-checkpoint if any
        if (!IsInitialBlockDownload())
            Checkpoints::AskForPendingSyncCheckpoint(pfrom);
    }


    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else, as it is sent as soon as the socket opens
        pfrom->Misbehaving(1, "message before version");
        if (fDebug) printf("net: received an out-of-sequence %s from peer at %s\n", strCommand.c_str(), pfrom->addr.ToString().c_str());
        // Do not disconnect when the version is queued but not dispatched: fDisconnect stops
        // ProcessMessages from ever reading it.
        if (pfrom->nMisbehavior > 10 || pfrom->nTimeConnected < GetTime() - 10)
            pfrom->MarkDisconnect("message-before-version");
        return false;
    }


    else if (strCommand == "verack")
    {
        pfrom->SetRecvVersion(min(pfrom->nVersion, PROTOCOL_VERSION));
        printf("net: received verack from peer version %d (recvVersion: %d) at %s\n", pfrom->nVersion, pfrom->nRecvVersion, pfrom->addr.ToString().c_str());

        pfrom->PushMessage("sendheaders");

        if (fSPVMode)
        {
            printf("SPV: Requesting headers from peer %s\n", pfrom->addr.ToString().c_str());
            pfrom->PushMessage("getheaders", CBlockLocator(pindexBest), uint256(0));
        }
    }


    else if (strCommand == "sendheaders")
    {
        LOCK(cs_main);
        pfrom->fPreferHeaders = true;
        if (fDebug)
            printf("peer=%s enabled headers-first announcements\n", pfrom->addr.ToString().c_str());
    }


    else if (strCommand == "addr")
    {
        vector<CAddress> vAddr;
        vRecv >> vAddr;

        // Don't want addr from older versions unless seeding
        if (pfrom->nVersion < CADDR_TIME_VERSION && addrman.size() > 1000)
            return true;
        if (vAddr.size() > 1000)
        {
            pfrom->Misbehaving(20, "addr message too large");
            return error("message addr size() = %" PRIszu"", vAddr.size());
        }

        // Store the new addresses
        vector<CAddress> vAddrOk;
        int64_t nNow = GetAdjustedTime();
        int64_t nSince = nNow - 10 * 60;
        for (CAddress& addr : vAddr)
        {
            if (fShutdown)
                return true;
            if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
                addr.nTime = nNow - 5 * 24 * 60 * 60;
            pfrom->AddAddressKnown(addr);
            bool fReachable = IsReachable(addr);
            if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable())
            {
                // Relay to a limited number of other nodes
                {
                    LOCK(cs_vNodes);
                    // Use deterministic randomness to send to the same nodes for 24 hours
                    // at a time so the setAddrKnowns of the chosen nodes prevent repeats
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        hashSalt = GetRandHash();
                    uint64_t hashAddr = addr.GetHash();
                    uint256 hashRand = hashSalt ^ (hashAddr<<32) ^ ((GetTime()+hashAddr)/(24*60*60));
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    multimap<uint256, CNode*> mapMix;
                    for (CNode* pnode : vNodes)
                    {
                        if (pnode->nVersion < CADDR_TIME_VERSION)
                            continue;
                        unsigned int nPointer;
                        memcpy(&nPointer, &pnode, sizeof(nPointer));
                        uint256 hashKey = hashRand ^ nPointer;
                        hashKey = Hash(BEGIN(hashKey), END(hashKey));
                        mapMix.insert(make_pair(hashKey, pnode));
                    }
                    int nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)
                    for (multimap<uint256, CNode*>::iterator mi = mapMix.begin(); mi != mapMix.end() && nRelayNodes-- > 0; ++mi)
                        ((*mi).second)->PushAddress(addr);
                }
            }
            // Do not store addresses outside our network
            if (fReachable)
                vAddrOk.push_back(addr);
        }
        addrman.Add(vAddrOk, pfrom->addr, 2 * 60 * 60);
        if (vAddr.size() < 1000)
            pfrom->fGetAddr = false;
        if (pfrom->fOneShot) {
            printf("DEBUG-DISCONNECT fOneShot peer=%s\n", pfrom->addr.ToString().c_str());
            pfrom->MarkDisconnect("one-shot-complete");
        }
    }

    else if (strCommand == "inv")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            pfrom->Misbehaving(20, "inv message too large");
            return error("message inv size() = %" PRIszu"", vInv.size());
        }

        if (!pfrom->fWhitelisted)
        {
            int64_t nNow = GetTime();
            if (nNow - pfrom->nInvWindowStart >= (int64_t)INV_RATE_LIMIT_WINDOW)
            {
                pfrom->nInvCount = 0;
                pfrom->nInvWindowStart = nNow;
            }
            pfrom->nInvCount += vInv.size();

            bool fSyncing = IsInitialBlockDownload() ||
                            (pindexBest != NULL && pindexBest->GetBlockTime() < GetTime() - 300);
            if (pfrom->nInvCount > INV_RATE_LIMIT_ITEMS && !fSyncing)
            {
                pfrom->Misbehaving(25, "inv rate limit exceeded");
                if (fDebug)
                    printf("inv rate limit exceeded: peer=%s count=%" PRIu64" in %" PRId64"s\n",
                           pfrom->addr.ToString().c_str(), pfrom->nInvCount,
                           nNow - pfrom->nInvWindowStart + INV_RATE_LIMIT_WINDOW);
            }
        }

        unsigned int nLastBlock = (unsigned int)(-1);
        int nBlockCount = 0;
        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++) {
            if (vInv[nInv].type == MSG_BLOCK)
                nBlockCount++;
            if (vInv[vInv.size() - 1 - nInv].type == MSG_BLOCK && nLastBlock == (unsigned int)(-1)) {
                nLastBlock = vInv.size() - 1 - nInv;
            }
        }

        if (nBlockCount > 0)
        {
            pfrom->nBlocksReceivedInBatch = 0;
            pfrom->nExpectedBatchSize = nBlockCount;
            pfrom->fPrefetchSent = false;
            if (nLastBlock != (unsigned int)(-1))
                pfrom->hashLastBlockInBatch = vInv[nLastBlock].hash;
            if (fDebug)
                printf("Prefetch: New batch of %d blocks, last=%s\n", nBlockCount,
                       pfrom->hashLastBlockInBatch.ToString().substr(0,20).c_str());
        }

        LOCK(cs_main);
        CTxDB txdb("r");

        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++)
        {
            const CInv &inv = vInv[nInv];

            if (fShutdown)
                return true;

            boost::this_thread::interruption_point();
            pfrom->AddInventoryKnown(inv);

            bool fAlreadyHave = AlreadyHave(txdb, inv);
            if (inv.type == MSG_BLOCK)
            {
                std::map<uint256, CBlockIndex*>::iterator miKnown = mapBlockIndex.find(inv.hash);
                if (miKnown != mapBlockIndex.end())
                    pfrom->UpdateBestKnownBlock(miKnown->second->nHeight, inv.hash);
            }
            if (fDebugNet)
                printf("  got inventory: %s  %s\n", inv.ToString().c_str(), fAlreadyHave ? "have" : "new");
            if (inv.type == MSG_TX && (fDebugNet || GetBoolArg("-debugtxrelay", false)))
                printf("TXRELAY inv tx=%s peer=%s have=%d\n",
                       inv.hash.ToString().substr(0,10).c_str(),
                       pfrom->addr.ToString().c_str(),
                       fAlreadyHave);
            if (inv.type == MSG_BLOCK && pindexBest != NULL && pindexBest->GetBlockTime() < GetTime() - 300 && fDebug)
                printf("sync inv: %s %s from %s\n", inv.ToString().c_str(), fAlreadyHave ? "HAVE" : "NEW", pfrom->addrName.c_str());

            if (!fAlreadyHave)
                pfrom->AskFor(inv);
            else if (inv.type == MSG_BLOCK && mapOrphanBlocks.count(inv.hash)) {
                pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(mapOrphanBlocks[inv.hash]));
				//PushGetBlocks(pfrom, pindexBest, GetOrphanRoot(mapOrphanBlocks[inv.hash]));
            } else if (nInv == nLastBlock) {
                // In case we are on a very long side-chain, it is possible that we already have
                // the last block in an inv bundle sent in response to getblocks. Try to detect
                // this situation and push another getblocks to continue.
                pfrom->PushGetBlocks(mapBlockIndex[inv.hash], uint256(0));
				//PushGetBlocks(pfrom, mapBlockIndex[inv.hash], uint256(0));
                if (fDebugNet)
                    printf("force request: %s\n", inv.ToString().c_str());
            }

            // Queue pressure is local backpressure, not peer misbehavior.
            if (pfrom->nSendSize >= SendBufferSize()) {
                if (fDebugNet)
                    printf("inv processing paused: send buffer size() = %" PRIszu" peer=%s\n",
                           pfrom->nSendSize, pfrom->addrName.c_str());
                break;
            }

            // Track requests for our stuff
            g_signals.Inventory(inv.hash);
        }
    }


    else if (strCommand == "getdata")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        printf("received getdata (%" PRIszu" invsz)\n", vInv.size());
        if (vInv.size() > MAX_INV_SZ)
        {
            pfrom->Misbehaving(20, "getdata message too large");
            return error("message getdata size() = %" PRIszu"", vInv.size());
        }

        if (fDebugNet || (vInv.size() != 1))
            printf("received getdata (%" PRIszu" invsz)\n", vInv.size());

        pfrom->vRecvGetData.insert(pfrom->vRecvGetData.end(), vInv.begin(), vInv.end());
        ProcessGetData(pfrom);
    }


    else if (strCommand == "getblocks")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        LOCK(cs_main);

        // Find the last block the caller has in the main chain
        CBlockIndex* pindex = locator.GetBlockIndex();

        // Send the rest of the chain
        if (pindex)
            pindex = pindex->pnext;
        int nLimit = 1000;
        std::set<uint256> setQueuedDAGParents;
        if (fDebugNet) printf("getblocks %d to %s limit %d\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0,20).c_str(), nLimit);
        for (; pindex; pindex = pindex->pnext)
        {
            if (pindex->GetBlockHash() == hashStop)
            {
                if (fDebugNet) printf("  getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0,20).c_str());
                // ppcoin: tell downloading node about the latest block if it's
                // without risk being rejected due to stake connection check
                if (hashStop != hashBestChain && pindex->GetBlockTime() + nStakeMinAge > pindexBest->GetBlockTime())
                    pfrom->PushInventory(CInv(MSG_BLOCK, hashBestChain));
                break;
            }
            QueueDAGMergeParentInventories(pfrom, pindex, setQueuedDAGParents);
            {
                CInv inv(MSG_BLOCK, pindex->GetBlockHash());
                LOCK(pfrom->cs_inventory);
                pfrom->vInventoryToSend.push_back(inv);
            }
            if (--nLimit <= 0)
            {
                // When this block is requested, we'll send an inv that'll make them
                // getblocks the next batch of inventory.
                if (fDebugNet) printf("  getblocks stopping at limit %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0,20).c_str());
                pfrom->hashContinue = pindex->GetBlockHash();
                break;
            }
        }
    }
    else if (strCommand == "checkpoint")
    {
        CSyncCheckpoint checkpoint;
        vRecv >> checkpoint;

        if (checkpoint.ProcessSyncCheckpoint(pfrom))
        {
            // Relay
            pfrom->hashCheckpointKnown = checkpoint.hashCheckpoint;
            LOCK(cs_vNodes);
            for (CNode* pnode : vNodes)
                checkpoint.RelayTo(pnode);
        }
    }

    else if (strCommand == "getheaders")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        LOCK(cs_main);

        CBlockIndex* pindex = NULL;
        if (locator.IsNull())
        {
            // If locator is null, return the hashStop block
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashStop);
            if (mi == mapBlockIndex.end())
                return true;
            pindex = (*mi).second;
        }
        else
        {
            // Find the last block the caller has in the main chain
            pindex = locator.GetBlockIndex();
            if (pindex)
                pindex = pindex->pnext;
        }

        vector<CBlock> vHeaders;
        int nLimit = 2000;
        if (fDebugNet) printf("getheaders %d to %s\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0,20).c_str());
        for (; pindex; pindex = pindex->pnext)
        {
            vHeaders.push_back(pindex->GetBlockHeader());
            if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
                break;
        }
        pfrom->PushMessage("headers", vHeaders);
    }

    else if (strCommand == "headers")
    {
        std::vector<CBlock> vHeaders;
        vRecv >> vHeaders;

        if (vHeaders.empty())
            return true;

        if (vHeaders.size() > 2000)
        {
            pfrom->Misbehaving(20, "headers message too large");
            return error("headers message size > 2000");
        }

        LOCK(cs_main);

        if (fDebug)
            printf("Received %u headers from peer %s\n", (unsigned int)vHeaders.size(), pfrom->addr.ToString().c_str());

        CBlockIndex* pindexLast = NULL;
        uint256 hashPrevHeader;
        int nPrevHeaderHeight = -1;
        bool fHavePrevHeader = false;
        for (const CBlock& header : vHeaders)
        {
            uint256 hash = header.GetHash();

            if (mapBlockIndex.count(hash))
            {
                pindexLast = mapBlockIndex[hash];
                pfrom->UpdateBestKnownBlock(pindexLast->nHeight, hash);
                hashPrevHeader = hash;
                nPrevHeaderHeight = pindexLast->nHeight;
                fHavePrevHeader = true;
                continue;
            }

            CBlockIndex* pindexPrev = NULL;
            int nParentHeight = -1;
            if (mapBlockIndex.count(header.hashPrevBlock))
            {
                pindexPrev = mapBlockIndex[header.hashPrevBlock];
                nParentHeight = pindexPrev->nHeight;
            }
            else if (fHavePrevHeader && header.hashPrevBlock == hashPrevHeader)
            {
                nParentHeight = nPrevHeaderHeight;
            }
            else
            {
                if (fDebug) printf("Header %s has unknown parent %s, waiting for in-flight blocks\n",
                       hash.ToString().substr(0,20).c_str(),
                       header.hashPrevBlock.ToString().substr(0,20).c_str());
                pfrom->PushGetBlocks(pindexBest, uint256(0));
                break;
            }

            int nHeaderHeight = nParentHeight + 1;
            pfrom->UpdateBestKnownBlock(nHeaderHeight, hash);

            // PoS blocks have nNonce==0 in legacy headers, but post-DAG all
            // headers must be valid PoW headers.
            if (nHeaderHeight >= FORK_HEIGHT_DAG || header.nNonce != 0)
            {
                if (!CheckProofOfWork(hash, header.nBits))
                {
                    pfrom->Misbehaving(100, "header invalid proof of work");
                    return error("header %s has invalid proof of work", hash.ToString().c_str());
                }
            }

            if (header.GetBlockTime() > FutureDrift(GetAdjustedTime()))
            {
                pfrom->Misbehaving(10, "header timestamp too far in future");
                return error("header %s timestamp too far in future", hash.ToString().c_str());
            }

            if (fSPVMode)
            {
                if (!pindexPrev)
                {
                    pfrom->PushGetBlocks(pindexBest, uint256(0));
                    break;
                }
                CBlockIndex* pindexNew = new CBlockIndex();
                pindexNew->phashBlock = &(mapBlockIndex.insert(make_pair(hash, pindexNew)).first->first);
                pindexNew->pprev = pindexPrev;
                pindexNew->nHeight = nHeaderHeight;
                pindexNew->nVersion = header.nVersion;
                pindexNew->hashMerkleRoot = header.hashMerkleRoot;
                pindexNew->nTime = header.nTime;
                pindexNew->nBits = header.nBits;
                pindexNew->nNonce = header.nNonce;
                pindexNew->nFile = 0;
                pindexNew->nBlockPos = 0;
                // Locators walk this index by skip pointer. Without one here the
                // header chain falls back to a per-block pprev walk.
                pindexNew->BuildSkip();

                pindexNew->nChainTrust = pindexPrev->nChainTrust + pindexNew->GetBlockTrust();

                if (pindexNew->nChainTrust > nBestChainTrust)
                {
                    pindexPrev->pnext = pindexNew;
                    pindexBest = pindexNew;
                    hashBestChain = hash;
                    nBestHeight = pindexNew->nHeight;
                    nBestChainTrust = pindexNew->nChainTrust;
                    nTimeBestReceived = GetTime();
                }

                pindexLast = pindexNew;

                if (fDebugNet && pindexNew->nHeight % 1000 == 0)
                    printf("SPV: Processed header at height %d\n", pindexNew->nHeight);
            }
            else
            {
                // A block already held as an orphan is not missing, so it is not
                // requested again: re-requesting held orphans is what produced the
                // "already have block (orphan)" deliveries by the hundred thousand.
                // The request goes through AskFor so it shares the one per-peer
                // window with every other block request, and only for headers within
                // that window of the tip -- a header further out cannot connect until
                // the tip advances anyway. Marking headers in flight directly, with no
                // window, pinned the in-flight set near two thousand, the getdata flush
                // then never drained AskFor, and the merge parents a DAG orphan asks
                // for were never sent: that is what kept a node's tip parked with the
                // next block already in hand.
                if (!mapOrphanBlocks.count(hash) &&
                    nHeaderHeight <= nBestHeight + (int)MAX_BLOCKS_IN_FLIGHT_PER_PEER)
                    pfrom->AskFor(CInv(MSG_BLOCK, hash));
                if (pindexPrev)
                    pindexLast = pindexPrev;
            }

            hashPrevHeader = hash;
            nPrevHeaderHeight = nHeaderHeight;
            fHavePrevHeader = true;
        }

        // Continue header sync only in SPV mode; a stuck full node would be handed the same
        // headers on every reply.
        if (fSPVMode && pindexLast && vHeaders.size() >= 2000)
        {
            pfrom->PushMessage("getheaders", CBlockLocator(pindexBest), uint256(0));
            pfrom->PushGetBlocks(pindexBest, uint256(0));
        }

        if (fSPVMode && pindexLast && pindexLast == pindexBest)
        {
            printf("SPV: Headers synced to height %d, ready to request transactions\n", nBestHeight);
        }
    }

    else if (strCommand == "tx")
    {
        vector<uint256> vWorkQueue;
        vector<uint256> vEraseQueue;
        CTxDB txdb("r");
        CTransaction tx;
        vRecv >> tx;

        CInv inv(MSG_TX, tx.GetHash());
        pfrom->AddInventoryKnown(inv);
        bool fTxRelayDebug = fDebugNet || GetBoolArg("-debugtxrelay", false);
        if (fTxRelayDebug)
            printf("TXRELAY recv tx=%s peer=%s vin=%u vout=%u\n",
                   inv.hash.ToString().substr(0,10).c_str(),
                   pfrom->addr.ToString().c_str(),
                   (unsigned)tx.vin.size(),
                   (unsigned)tx.vout.size());

        bool fMissingInputs = false;
        if (tx.AcceptToMemoryPool(txdb, true, &fMissingInputs))
        {
            if (fTxRelayDebug)
                printf("TXRELAY accept tx=%s peer=%s\n",
                       inv.hash.ToString().substr(0,10).c_str(),
                       pfrom->addr.ToString().c_str());
            SyncWithWallets(tx, NULL, true);
            RelayTransaction(tx, inv.hash);
            {
                LOCK(cs_mapAlreadyAskedFor);
                mapAlreadyAskedFor.erase(inv);
            }
            vWorkQueue.push_back(inv.hash);
            vEraseQueue.push_back(inv.hash);

            // Recursively process any orphan transactions that depended on this one
            for (unsigned int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hashPrev = vWorkQueue[i];
                for (set<uint256>::iterator mi = mapOrphanTransactionsByPrev[hashPrev].begin();
                     mi != mapOrphanTransactionsByPrev[hashPrev].end();
                     ++mi)
                {
                    const uint256& orphanTxHash = *mi;
                    CTransaction& orphanTx = mapOrphanTransactions[orphanTxHash];
                    bool fMissingInputs2 = false;

                    if (orphanTx.AcceptToMemoryPool(txdb, true, &fMissingInputs2))
                    {
                        printf("   accepted orphan tx %s\n", orphanTxHash.ToString().substr(0,10).c_str());
                        SyncWithWallets(orphanTx, NULL, true);
                        RelayTransaction(orphanTx, orphanTxHash);
                        {
                            LOCK(cs_mapAlreadyAskedFor);
                            mapAlreadyAskedFor.erase(CInv(MSG_TX, orphanTxHash));
                        }
                        vWorkQueue.push_back(orphanTxHash);
                        vEraseQueue.push_back(orphanTxHash);
                    }
                    else if (!fMissingInputs2)
                    {
                        // invalid orphan
                        vEraseQueue.push_back(orphanTxHash);
                        printf("   removed invalid orphan tx %s\n", orphanTxHash.ToString().substr(0,10).c_str());
                    }
                }
            }

            for (uint256 hash : vEraseQueue)
                EraseOrphanTx(hash);
        }
        else if (fMissingInputs)
        {
            if (fTxRelayDebug)
                printf("TXRELAY orphan tx=%s peer=%s\n",
                       inv.hash.ToString().substr(0,10).c_str(),
                       pfrom->addr.ToString().c_str());
            AddOrphanTx(tx);

            // DoS prevention: do not allow mapOrphanTransactions to grow unbounded
            //unsigned int nEvicted = LimitOrphanTxSize(MAX_ORPHAN_TRANSACTIONS);
            unsigned int nMaxOrphanTx = (unsigned int)std::max((int64_t)0, GetArg("-maxorphantx", DEFAULT_MAX_ORPHAN_TRANSACTIONS));
            unsigned int nEvicted = LimitOrphanTxSize(nMaxOrphanTx);

            if (nEvicted > 0)
                printf("mapOrphan overflow, removed %u tx\n", nEvicted);
        }
        else if (fTxRelayDebug)
        {
            printf("TXRELAY reject tx=%s peer=%s dos=%d\n",
                   inv.hash.ToString().substr(0,10).c_str(),
                   pfrom->addr.ToString().c_str(),
                   tx.nDoS);
        }
        if (tx.nDoS) pfrom->Misbehaving(tx.nDoS, "transaction validation DoS score");
    }


    else if (strCommand == "block")
    {
        CBlock block;
        vRecv >> block;
        uint256 hashBlock = block.GetHash();

        if (fDebugNet) printf("received block %s\n", hashBlock.ToString().substr(0,20).c_str());
        // block.print();

        CInv inv(MSG_BLOCK, hashBlock);
        pfrom->AddInventoryKnown(inv);

        pfrom->ClearBlockInFlight(hashBlock);

        LOCK(cs_main);
        bool fAccepted = ProcessBlock(pfrom, &block);
        if (fAccepted)
        {
            pfrom->nLastBlockRecv = GetTime();
            std::map<uint256, CBlockIndex*>::iterator miAccepted = mapBlockIndex.find(hashBlock);
            if (miAccepted != mapBlockIndex.end())
                pfrom->UpdateBestKnownBlock(miAccepted->second->nHeight, hashBlock);
            if (pfrom->nBestKnownHeight > pfrom->nChainHeight)
                pfrom->nChainHeight = pfrom->nBestKnownHeight;
            LOCK(cs_mapAlreadyAskedFor);
            mapAlreadyAskedFor.erase(inv);
        }

        if (block.nDoS)
            pfrom->Misbehaving(block.nDoS, "block validation DoS score");

        // Chain sync forward after accepting a new block, bounded so duplicate
        // orphan/header churn cannot amplify getblocks/getheaders loops.
        if (fAccepted && pfrom->ShouldRequestBlockCatchup())
        {
            pfrom->PushGetBlocks(pindexBest, uint256(0));
            if (pfrom->fPreferHeaders)
                pfrom->PushMessage("getheaders", CBlockLocator(pindexBest), uint256(0));
        }

        if (fSecMsgEnabled)
            SecureMsgScanBlock(block);

        if (IsInitialBlockDownload() && pfrom->nExpectedBatchSize > 0)
        {
            pfrom->nBlocksReceivedInBatch++;

            int nPrefetchThreshold = (pfrom->nExpectedBatchSize * 3) / 4;

            if (!pfrom->fPrefetchSent && pfrom->nBlocksReceivedInBatch >= nPrefetchThreshold)
            {
                if (pfrom->hashLastBlockInBatch != 0 && mapBlockIndex.count(pfrom->hashLastBlockInBatch))
                {
                    CBlockIndex* pindexLast = mapBlockIndex[pfrom->hashLastBlockInBatch];
                    pfrom->PushGetBlocks(pindexLast, uint256(0));
                    pfrom->fPrefetchSent = true;
                    if (fDebug)
                        printf("Prefetch: Requesting next batch at %d/%d blocks (from height %d)\n",
                               pfrom->nBlocksReceivedInBatch, pfrom->nExpectedBatchSize, pindexLast->nHeight);
                }
                else if (pindexBest)
                {
                    pfrom->PushGetBlocks(pindexBest, uint256(0));
                    pfrom->fPrefetchSent = true;
                    if (fDebug)
                        printf("Prefetch: Requesting next batch at %d/%d blocks (fallback from best height %d)\n",
                               pfrom->nBlocksReceivedInBatch, pfrom->nExpectedBatchSize, pindexBest->nHeight);
                }
            }
        }
    }


    else if (strCommand == "getaddr")
    {
        // Don't return addresses older than nCutOff timestamp
        int64_t nCutOff = GetTime() - (nNodeLifespan * 24 * 60 * 60);
        pfrom->vAddrToSend.clear();
        vector<CAddress> vAddr = addrman.GetAddr();
        for (const CAddress &addr : vAddr)
            if(addr.nTime > nCutOff)
                pfrom->PushAddress(addr);
    }


    else if (strCommand == "mempool")
    {
        std::vector<uint256> vtxid;
        mempool.queryHashes(vtxid);
        vector<CInv> vInv;
        for (unsigned int i = 0; i < vtxid.size(); i++) {
            CInv inv(MSG_TX, vtxid[i]);
            vInv.push_back(inv);
            if (i == (MAX_INV_SZ - 1))
                    break;
        }
        if (vInv.size() > 0)
            pfrom->PushMessage("inv", vInv);
    }


    else if (strCommand == "checkorder")
    {
        uint256 hashReply;
        vRecv >> hashReply;

        if (!GetBoolArg("-allowreceivebyip"))
        {
            pfrom->PushMessage("reply", hashReply, (int)2, string(""));
            return true;
        }

        CWalletTx order;
        vRecv >> order;

        /// we have a chance to check the order here

        // Keep giving the same key to the same ip until they use it
        if (!mapReuseKey.count(pfrom->addr))
            pwalletMain->GetKeyFromPool(mapReuseKey[pfrom->addr], true);

        // Send back approval of order and pubkey to use
        CScript scriptPubKey;
        scriptPubKey << mapReuseKey[pfrom->addr] << OP_CHECKSIG;
        pfrom->PushMessage("reply", hashReply, (int)0, scriptPubKey);
    }


    else if (strCommand == "reply")
    {
        uint256 hashReply;
        vRecv >> hashReply;

        CRequestTracker tracker;
        {
            LOCK(pfrom->cs_mapRequests);
            map<uint256, CRequestTracker>::iterator mi = pfrom->mapRequests.find(hashReply);
            if (mi != pfrom->mapRequests.end())
            {
                tracker = (*mi).second;
                pfrom->mapRequests.erase(mi);
            }
        }
        if (!tracker.IsNull())
            tracker.fn(tracker.param1, vRecv);
    }


    else if (strCommand == "ping")
    {
        if (pfrom->nVersion > BIP0031_VERSION)
        {
            uint64_t nonce = 0;
            vRecv >> nonce;
            // Echo the message back with the nonce. This allows for two useful features:
            //
            // 1) A remote node can quickly check if the connection is operational
            // 2) Remote nodes can measure the latency of the network thread. If this node
            //    is overloaded it won't respond to pings quickly and the remote node can
            //    avoid sending us more work, like chain download requests.
            //
            // The nonce stops the remote getting confused between different pings: without
            // it, if the remote node sends a ping once per second and this node takes 5
            // seconds to respond to each, the 5th ping the remote sends would appear to
            // return very quickly.
            pfrom->PushMessage("pong", nonce);
        }
    }


    else if (strCommand == "pong")
    {
        int64_t pingUsecEnd = nTimeReceived;
        uint64_t nonce = 0;
        size_t nAvail = vRecv.in_avail();
        bool bPingFinished = false;
        std::string sProblem;

        if (nAvail >= sizeof(nonce)) {
            vRecv >> nonce;

            // Only process pong message if there is an outstanding ping (old ping without nonce should never pong)
            if (pfrom->nPingNonceSent != 0) {
                if (nonce == pfrom->nPingNonceSent) {
                    // Matching pong received, this ping is no longer outstanding
                    bPingFinished = true;
                    int64_t pingUsecTime = pingUsecEnd - pfrom->nPingUsecStart;
                    if (pingUsecTime > 0) {
                        // Successful ping time measurement, replace previous
                        pfrom->nPingUsecTime = pingUsecTime;
                        if (fDebug) { printf("Ping time for peer %s: %.1f msec\n", pfrom->addr.ToString().c_str(), ((double)pfrom->nPingUsecTime) / 1000.0); }
                    } else {
                        // This should never happen
                        sProblem = "Timing mishap";
                    }
                } else {
                    // Nonce mismatches are normal when pings are overlapping
                    sProblem = "Nonce mismatch";
                    if (nonce == 0) {
                        // This is most likely a bug in another implementation somewhere, cancel this ping
                        bPingFinished = true;
                        sProblem = "Nonce zero";
                    }
                }
            } else {
                sProblem = "Unsolicited pong without ping";
            }
        } else {
            // This is most likely a bug in another implementation somewhere, cancel this ping
            bPingFinished = true;
            sProblem = "Short payload";
        }

        if (!(sProblem.empty())) {
            printf("pong %s %s: %s, %" PRIx64" expected, %" PRIx64" received, %zu bytes\n"
                , pfrom->addr.ToString().c_str()
                , pfrom->strSubVer.c_str()
                , sProblem.c_str()
                , pfrom->nPingNonceSent
                , nonce
                , nAvail);
        }
        if (bPingFinished) {
            pfrom->nPingNonceSent = 0;
        }
    }


    else if (strCommand == "alert")
    {
        CAlert alert;
        vRecv >> alert;

        uint256 alertHash = alert.GetHash();
        if (pfrom->setKnown.count(alertHash) == 0)
        {
            if (alert.ProcessAlert())
            {
                // Relay
                pfrom->setKnown.insert(alertHash);
                {
                    LOCK(cs_vNodes);
                    for (CNode* pnode : vNodes)
                        alert.RelayTo(pnode);
                }
            }
            else {
                // Small DoS penalty so peers that send us lots of
                // duplicate/expired/invalid-signature/whatever alerts
                // eventually get banned.
                // This isn't a Misbehaving(100) (immediate ban) because the
                // peer might be an older or different implementation with
                // a different signature key, etc.
                pfrom->Misbehaving(10, "invalid alert");
            }
        }
    }


    else if (strCommand == "filterload")
    {
        if (vRecv.size() > MAX_BLOOM_FILTER_SIZE + 100)  // +100 for serialization overhead
        {
            pfrom->Misbehaving(100, "filterload message too large");
            return false;
        }
        CBloomFilter filter;
        vRecv >> filter;

        if (!filter.IsWithinSizeConstraints())
        {
            pfrom->Misbehaving(100, "bloom filter outside size constraints");
        }
        else
        {
            LOCK(pfrom->cs_filter);
            delete pfrom->pfilter;
            pfrom->pfilter = new CBloomFilter(filter);
            pfrom->pfilter->UpdateEmptyFull();
        }
        pfrom->fRelayTxes = true;
    }


    else if (strCommand == "filteradd")
    {
        std::vector<unsigned char> vData;
        vRecv >> vData;

        if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE)
        {
            pfrom->Misbehaving(100, "filteradd element too large");
        }
        else
        {
            LOCK(pfrom->cs_filter);
            if (pfrom->pfilter)
            {
                pfrom->pfilter->insert(vData);
            }
            else
            {
                pfrom->Misbehaving(100, "filteradd without loaded filter");
            }
        }
    }


    else if (strCommand == "filterclear")
    {
        LOCK(pfrom->cs_filter);
        delete pfrom->pfilter;
        pfrom->pfilter = new CBloomFilter();
        pfrom->fRelayTxes = true;
    }


    else if (strCommand == "merkleblock")
    {
        CMerkleBlock merkleBlock;
        vRecv >> merkleBlock;
        std::vector<uint256> vMatch;
        if (merkleBlock.txn.ExtractMatches(vMatch) != merkleBlock.header.hashMerkleRoot)
        {
            pfrom->Misbehaving(100, "merkleblock invalid merkle root");
            return error("merkleblock: Invalid merkle root");
        }

        if (fDebug)
            printf("SPV: Received merkleblock with %u matched transactions\n", (unsigned int)vMatch.size());

        if (fHybridSPV && pwalletMain)
        {
            uint256 hashBlock = Tribus(BEGIN(merkleBlock.header.nVersion), END(merkleBlock.header.nNonce));

            int nHeight = 0;
            bool fBlockInBestChain = false;
            {
                LOCK(cs_main);
                if (mapBlockIndex.count(hashBlock))
                {
                    CBlockIndex* pblockindex = mapBlockIndex[hashBlock];
                    nHeight = pblockindex->nHeight;
                    if (pindexBest && nHeight <= pindexBest->nHeight)
                    {
                        CBlockIndex* pcheck = pindexBest;
                        while (pcheck && pcheck->nHeight > nHeight)
                            pcheck = pcheck->pprev;
                        fBlockInBestChain = (pcheck && pcheck->GetBlockHash() == hashBlock);
                    }
                }
            }

            if (!fBlockInBestChain)
            {
                if (fDebug)
                    printf("SPV: Ignoring merkleblock for block not in best chain: %s\n", hashBlock.ToString().c_str());
            }
            else
            {
                CPartialMerkleTree txnCopy = merkleBlock.txn;
                std::vector<uint256> vMatchCopy;
                txnCopy.ExtractMatches(vMatchCopy);

                for (const uint256& txhash : vMatch)
                {
                    int nTxIndex = -1;
                    for (int i = 0; i < (int)vMatchCopy.size(); i++)
                    {
                        if (vMatchCopy[i] == txhash)
                        {
                            nTxIndex = i;
                            break;
                        }
                    }

                    LOCK(pwalletMain->cs_wallet);
                    std::map<uint256, CWalletTx>::iterator wit = pwalletMain->mapWallet.find(txhash);
                    if (wit != pwalletMain->mapWallet.end())
                    {
                        const CWalletTx& wtx = wit->second;
                        for (unsigned int n = 0; n < wtx.vout.size(); n++)
                        {
                            if (pwalletMain->IsMine(wtx.vout[n]))
                            {
                                COutPoint outpoint(txhash, n);
                                SPVUtxo utxo(txhash, n, wtx.vout[n].nValue,
                                             nHeight, hashBlock, wtx.nTime,
                                             wtx.vout[n].scriptPubKey);
                                utxo.hashMerkleRoot = merkleBlock.header.hashMerkleRoot;
                                utxo.nTxIndex = nTxIndex;
                                utxo.fHaveBlock = true;
                                utxo.fVerified = (nTxIndex >= 0 && nHeight > 0);
                                pwalletMain->UpdateSPVUtxo(outpoint, utxo);
                            }
                        }
                    }
                }
            }
        }
    }


    else
    {
        if (fSecMsgEnabled)
            SecureMsgReceiveData(pfrom, strCommand, vRecv);

        //ProcessMessageCollateralN(pfrom, strCommand, vRecv);
        ProcessMessageCollateralnode(pfrom, strCommand, vRecv);
        ProcessMessageNullSend(pfrom, strCommand, vRecv);
        ProcessMessageFinality(pfrom, strCommand, vRecv);
        //ProcessSpork(pfrom, strCommand, vRecv);

        // DAG tips exchange
        if (strCommand == "getdagtips")
        {
            LOCK(cs_main);
            if (pindexBest && pindexBest->nHeight >= FORK_HEIGHT_DAG)
            {
                std::vector<uint256> vTips = g_dagManager.GetDAGTips();
                pfrom->PushMessage("dagtips", vTips);
            }
        }
        else if (strCommand == "dagtips")
        {
            std::vector<uint256> vTips;
            vRecv >> vTips;

            if (vTips.size() > (unsigned int)(MAX_DAG_PARENTS * 3))
            {
                pfrom->Misbehaving(20, "dagtips message too large");
            }
            else
            {
                LOCK(cs_main);
                for (const uint256& hashTip : vTips)
                {
                    if (!mapBlockIndex.count(hashTip))
                        pfrom->AskFor(CInv(MSG_BLOCK, hashTip));
                }
            }
        }

        // Ignore unknown commands for extensibility
    }


    // Update the last seen time for this node's address
    if (pfrom->fNetworkNode)
        if (strCommand == "version" || strCommand == "addr" || strCommand == "inv" || strCommand == "getdata" || strCommand == "ping")
            AddressCurrentlyConnected(pfrom->addr);


    return true;
}

// requires LOCK(cs_vRecvMsg)
bool ProcessMessages(CNode* pfrom)
{
    //if (fDebug)
    //    printf("ProcessMessages(%zu messages)\n", pfrom->vRecvMsg.size());

    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (4) checksum
    //  (x) data
    //
    bool fOk = true;

    if (!pfrom->vRecvGetData.empty() && pfrom->nSendSize < SendBufferSize())
        ProcessGetData(pfrom);

    // Preserve response ordering while getdata can make progress. If the send
    // queue is full, continue processing inbound messages so backpressure does
    // not deadlock block/header relay behind pending getdata.
    if (!pfrom->vRecvGetData.empty() && pfrom->nSendSize < SendBufferSize())
    {
        // Returning here skips the inbound queue; if vRecvGetData never drains, this peer's
        // version is never handled and its receive queue grows without bound.
        pfrom->nGetDataDeferrals++;
        if (fDebugNet && (pfrom->nGetDataDeferrals % 200) == 0)
            printf("processmsgs: deferred for getdata %" PRId64" times peer=%s version=%d "
                   "getdata=%u recvqueue=%u sendsize=%u\n",
                   pfrom->nGetDataDeferrals, pfrom->addr.ToString().c_str(), pfrom->nVersion,
                   (unsigned int)pfrom->vRecvGetData.size(), (unsigned int)pfrom->vRecvMsg.size(),
                   (unsigned int)pfrom->nSendSize);
        return fOk;
    }
    pfrom->nGetDataDeferrals = 0;

    std::deque<CNetMessage>::iterator it = pfrom->vRecvMsg.begin();
    while (!pfrom->fDisconnect && it != pfrom->vRecvMsg.end()) {
        // get next message
        CNetMessage& msg = *it;

        //if (fDebug)
        //    printf("ProcessMessages(message %u msgsz, %zu bytes, complete:%s)\n",
        //            msg.hdr.nMessageSize, msg.vRecv.size(),
        //            msg.complete() ? "Y" : "N");

        // end, if an incomplete message is found
        if (!msg.complete())
        {
            // The only silent exit, a break: one message that never completes stops every later
            // message from this peer until the 90s timeout.
            if (fDebugNet && it == pfrom->vRecvMsg.begin())
                printf("processmsgs: head incomplete peer=%s cmd=%s hdrpos=%u datapos=%u of %u queued=%u\n",
                       pfrom->addr.ToString().c_str(),
                       msg.in_data ? msg.hdr.GetCommand().c_str() : "<header>",
                       msg.nHdrPos, msg.nDataPos,
                       msg.in_data ? msg.hdr.nMessageSize : 0,
                       (unsigned int)pfrom->vRecvMsg.size());
            break;
        }

        // at this point, any failure means we can delete the current message
        it++;

        // Scan for message start
        if (memcmp(msg.hdr.pchMessageStart, pchMessageStart, sizeof(pchMessageStart)) != 0) {
            printf("\n\nPROCESSMESSAGE: INVALID MESSAGESTART\n\n");
            fOk = false;
            break;
        }

        // Read header
        CMessageHeader& hdr = msg.hdr;
        if (!hdr.IsValid())
        {
            printf("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n", hdr.GetCommand().c_str());
            continue;
        }
        string strCommand = hdr.GetCommand();

        // Message size
        unsigned int nMessageSize = hdr.nMessageSize;

        // Checksum
        CDataStream& vRecv = msg.vRecv;
        uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
        unsigned int nChecksum = 0;
        memcpy(&nChecksum, &hash, sizeof(nChecksum));
        if (nChecksum != hdr.nChecksum)
        {
            printf("ProcessMessages(%s, %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n",
               strCommand.c_str(), nMessageSize, nChecksum, hdr.nChecksum);
            continue;
        }

        // Process message
        bool fRet = false;
        try
        {
            fRet = ProcessMessage(pfrom, strCommand, vRecv, msg.nTime);
            boost::this_thread::interruption_point();
        }
        catch (std::ios_base::failure& e)
        {
            if (strstr(e.what(), "end of data"))
            {
				if(fDebug)
					// Allow exceptions from under-length message on vRecv
					printf("ProcessMessages(%s, %u bytes) : Exception '%s' caught, normally caused by a message being shorter than its stated length\n", strCommand.c_str(), nMessageSize, e.what());
            }
            else if (strstr(e.what(), "size too large"))
            {
                printf("ProcessMessages(%s, %u bytes) : Oversized data from peer=%s - '%s'\n",
                       strCommand.c_str(), nMessageSize, pfrom->addr.ToString().c_str(), e.what());
                Misbehaving(pfrom->GetId(), 50, "oversized message deserialization");  // Severe penalty for oversized messages
            }
            else if (strstr(e.what(), "non-canonical"))
            {
                printf("ProcessMessages(%s, %u bytes) : Non-canonical encoding from peer=%s - '%s'\n",
                       strCommand.c_str(), nMessageSize, pfrom->addr.ToString().c_str(), e.what());
                Misbehaving(pfrom->GetId(), 20, "non-canonical message encoding");  // Penalty for non-canonical encoding
            }
            else
            {
                PrintExceptionContinue(&e, "ProcessMessages()");
            }
        }
        catch (boost::thread_interrupted) {
            throw;
        }
        catch (std::exception& e) {
            PrintExceptionContinue(&e, "ProcessMessages()");
        } catch (...) {
            PrintExceptionContinue(NULL, "ProcessMessages()");
        }

        if (!fRet)
            printf("ProcessMessage(%s, %u bytes) FAILED\n", strCommand.c_str(), nMessageSize);

        break;
    }

    // In case the connection got shut down, its receive buffer was wiped
    if (!pfrom->fDisconnect)
        pfrom->vRecvMsg.erase(pfrom->vRecvMsg.begin(), it);

    return fOk;
}


// Node-global periodic work fans out to every peer, so it must not run from
// SendMessages under cs_vSend (inverts the cs_vNodes -> cs_vSend order).
void SendMessagesGlobal()
{
    TRY_LOCK(cs_main, lockMain);
    if (!lockMain)
        return;

    if (dandelionState.IsEnabled())
    {
        std::vector<int> vPeerIds;
        {
            TRY_LOCK(cs_vNodes, lockNodes);
            if (lockNodes)
            {
                for (CNode* pnode : vNodes)
                    vPeerIds.push_back(pnode->GetId());
            }
        }
        if (!vPeerIds.empty())
            dandelionRouter.UpdateEpoch(GetTime(), vPeerIds);

        std::vector<uint256> vFluff = dandelionState.CheckStemTimeouts(GetTime());
        for (const uint256& txHash : vFluff)
        {
            CInv inv(MSG_TX, txHash);
            bool fHaveRelay = false;
            {
                LOCK(cs_mapRelay);
                std::map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
                if (mi != mapRelay.end())
                    fHaveRelay = true;
            }
            if (fHaveRelay)
                RelayInventory(inv, true);
        }
    }

    // Resend wallet transactions that haven't gotten in a block yet
    // Except during reindex, importing and IBD, when old wallet
    // transactions become unconfirmed and spams other nodes.
    if (!fReindex && !IsInitialBlockDownload())
        ResendWalletTransactions();
}

bool SendMessages(CNode* pto, bool fSendTrickle)
{
    if (pto->nVersion == 0)
        return true;

    bool pingSend = false;
    if (pto->fPingQueued) {
        pingSend = true;
    }
    if (pto->nPingNonceSent == 0 && pto->nPingUsecStart + PING_INTERVAL * 1000000 < GetTimeMicros()) {
        pingSend = true;
    }
    if (pingSend) {
        uint64_t nonce = 0;
        while (nonce == 0) {
            RAND_bytes((unsigned char*)&nonce, sizeof(nonce));
        }
        pto->fPingQueued = false;
        pto->nPingUsecStart = GetTimeMicros();
        if (pto->nVersion > BIP0031_VERSION) {
            pto->nPingNonceSent = nonce;
            pto->PushMessage("ping", nonce);
        } else {
            pto->nPingNonceSent = 0;
            pto->PushMessage("ping");
        }
    }

    {
        int64_t nNow = GetTime();
        int64_t nTimeSinceBlock = nNow - (pto->nLastBlockRecv > 0 ? pto->nLastBlockRecv : pto->nTimeConnected);
        CBlockIndex* pBest = pindexBest;
        int nHeight = nBestHeight;
        int nPeerHeight = pto->nBestKnownHeight >= 0 ? pto->nBestKnownHeight : pto->nChainHeight;
        bool fPeerAhead = (nPeerHeight > nHeight);
        bool fWeAhead = (nPeerHeight >= 0 && nHeight > nPeerHeight);
        bool fStaleBlockInFlight = false;
        int64_t nOldestBlockInFlight = 0;
        pto->ExpireBlockInFlight(nNow);
        {
            TRY_LOCK(cs_main, lockMain);
            if (lockMain)
            {
                for (std::map<uint256, int64_t>::iterator it = pto->mapBlockInFlightSince.begin();
                     it != pto->mapBlockInFlightSince.end(); )
                {
                    if (mapBlockIndex.count(it->first))
                    {
                        pto->setBlocksInFlight.erase(it->first);
                        it = pto->mapBlockInFlightSince.erase(it);
                        continue;
                    }
                    if (nOldestBlockInFlight == 0 || it->second < nOldestBlockInFlight)
                        nOldestBlockInFlight = it->second;
                    ++it;
                }
            }
        }
        if (nOldestBlockInFlight > 0 && nNow - nOldestBlockInFlight > 15)
        {
            fStaleBlockInFlight = true;
        }

        static std::map<std::string, int64_t> mapLastStallRecovery;
        bool fThrottle = (mapLastStallRecovery.count(pto->addrName) &&
                          nNow - mapLastStallRecovery[pto->addrName] < 15);

        if (!fImporting && !fReindex && (fPeerAhead || fWeAhead || fStaleBlockInFlight) &&
            nTimeSinceBlock > 15 && !fThrottle)
        {
            mapLastStallRecovery[pto->addrName] = nNow;
            pto->nLastBlockRecv = nNow;
            {
                LOCK(cs_mapAlreadyAskedFor);
                for (auto it = mapAlreadyAskedFor.begin(); it != mapAlreadyAskedFor.end(); )
                {
                    if (it->first.type == MSG_BLOCK)
                        it = mapAlreadyAskedFor.erase(it);
                    else
                        ++it;
                }
            }
            if (pBest != NULL)
            {
                if (fWeAhead)
                    PushBlockAnnouncement(pto, pBest->GetBlockHeader(), true);
                else
                    pto->PushGetBlocks(pBest, uint256(0));
            }
            if (fDebug)
                printf("Sync stall recovery: peer=%s ch=%d our=%d stall=%ds reason=%s in_flight=%u\n",
                       pto->addrName.c_str(), nPeerHeight, nHeight, (int)nTimeSinceBlock,
                       fPeerAhead ? "peer-ahead" : (fWeAhead ? "we-ahead" : "stale-block-in-flight"),
                       (unsigned int)pto->setBlocksInFlight.size());
        }
    }


    //
    // getblocks: handled OUTSIDE cs_main to prevent IBD stall when GUI
    // thread holds cs_main (Qt refreshWallet LOCK2).  CBlockLocator
    // construction only reads pprev pointers — same pattern used by the
    // sync-stall-recovery path above.
    //
    if (pto->fStartSync && !fImporting && !fReindex) {
        pto->fStartSync = false;
        pto->PushGetBlocks(pindexBest, uint256(0));
    }

    {
        int n = pto->getBlocksIndex.size();
        for (int i = 0; i < n; i++)
        {
            if (fDebugNet) printf("Pushing getblocks %s to %s\n\n",pto->getBlocksIndex[i]->ToString().c_str(),pto->getBlocksHash[i].ToString().c_str());
            pto->PushMessage("getblocks", CBlockLocator(pto->getBlocksIndex[i]), pto->getBlocksHash[i]);
        }
        pto->getBlocksIndex.clear();
        pto->getBlocksHash.clear();
    }

    TRY_LOCK(cs_main, lockMain);
    // Everything below is skipped when cs_main is busy; count the misses so a starved
    // inventory flush is visible.
    {
        static int64_t nSendLockTries = 0, nSendLockMisses = 0, nLastSendLockLog = 0;
        nSendLockTries++;
        if (!lockMain)
            nSendLockMisses++;
        const int64_t nNowLog = GetTime();
        if (fDebugNet && nSendLockTries >= 20 && nNowLog - nLastSendLockLog >= 10)
        {
            nLastSendLockLog = nNowLog;
            printf("sendmsgs: cs_main unavailable on %" PRId64"/%" PRId64" attempts (%d%%)\n",
                   nSendLockMisses, nSendLockTries,
                   (int)((nSendLockMisses * 100) / nSendLockTries));
            nSendLockTries = 0;
            nSendLockMisses = 0;
        }
    }
    if (lockMain) {

        // Address refresh broadcast
        static int64_t nLastRebroadcast;
        if (!IsInitialBlockDownload() && (GetTime() - nLastRebroadcast > 24 * 60 * 60))
        {
            {
                TRY_LOCK(cs_vNodes, lockNodes);
                if (lockNodes)
                {
                    for (CNode* pnode : vNodes)
                    {
                        // Periodically clear setAddrKnown to allow refresh broadcasts
                        if (nLastRebroadcast)
                            pnode->setAddrKnown.clear();

                        // Rebroadcast our address
                        if (!fNoListen)
                        {
                            CAddress addr = GetLocalAddress(&pnode->addr);
                            if (addr.IsRoutable())
                                pnode->PushAddress(addr);
                        }
                    }
                    nLastRebroadcast = GetTime();
                }
            }
        }

        //
        // Message: addr
        //
        if (fSendTrickle)
        {
            vector<CAddress> vAddr;
            vAddr.reserve(pto->vAddrToSend.size());
            for (const CAddress& addr : pto->vAddrToSend)
            {
                // returns true if wasn't already contained in the set
                if (pto->setAddrKnown.insert(addr).second)
                {
                    vAddr.push_back(addr);
                    // receiver rejects addr messages larger than 1000
                    if (vAddr.size() >= 1000)
                    {
                        pto->PushMessage("addr", vAddr);
                        vAddr.clear();
                    }
                }
            }
            pto->vAddrToSend.clear();
            if (!vAddr.empty())
                pto->PushMessage("addr", vAddr);
        }

        //
        // Message: inventory
        //
        vector<CInv> vInv; // explicit requests, always sent as inv; tips use PushBlockAnnouncement
        vector<CInv> vInvWait;
        {
            LOCK(pto->cs_inventory);
            vInv.reserve(pto->vInventoryToSend.size());
            vInvWait.reserve(pto->vInventoryToSend.size());
            for (const CInv& inv : pto->vInventoryToSend)
            {
                bool fForceInventory = pto->setInventoryForce.count(inv) != 0;
                if (!fForceInventory && pto->setInventoryKnown.count(inv))
                    continue;

                // trickle out tx inv to protect privacy
                if (!fForceInventory && inv.type == MSG_TX && !fSendTrickle)
                {
                    // 1/4 of tx invs blast to all immediately
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        hashSalt = GetRandHash();
                    uint256 hashRand = inv.hash ^ hashSalt;
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    bool fTrickleWait = ((hashRand & 3) != 0);

                    // always trickle our own transactions
                    if (!fTrickleWait)
                    {
                        CWalletTx wtx;
                        if (GetTransaction(inv.hash, wtx))
                            if (wtx.fFromMe)
                                fTrickleWait = true;
                    }

                    if (fTrickleWait)
                    {
                        vInvWait.push_back(inv);
                        continue;
                    }
                }

                // returns true if wasn't already contained in the set
                bool fKnownInserted = pto->setInventoryKnown.insert(inv).second;
                if (fForceInventory || fKnownInserted)
                {
                    vInv.push_back(inv);
                    if (vInv.size() >= 1000)
                    {
                        pto->PushMessage("inv", vInv);
                        vInv.clear();
                    }
                }
                if (fForceInventory)
                    pto->setInventoryForce.erase(inv);
            }
            pto->vInventoryToSend = vInvWait;
        }
        if (!vInv.empty())
            pto->PushMessage("inv", vInv);


        // getdata moved outside cs_main (below) for IBD reliability

        if (fSecMsgEnabled)
            SecureMsgSendData(pto, fSendTrickle);
    }

    //
    // getdata: flush pending requests outside cs_main.
    // Uses its own TRY_LOCK for AlreadyHave; if cs_main is unavailable
    // the request is sent anyway (duplicate receipt is harmless).
    //
    {
        vector<CInv> vGetData;
        int64_t nNow = GetTime() * 1000000;
        pto->ExpireBlockInFlight();
        while (!pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow)
        {
            CInv inv = (*pto->mapAskFor.begin()).second;
            bool fSkip = false;
            bool fBlockRequest = (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK);
            if (fBlockRequest)
            {
                if (pto->IsBlockInFlight(inv.hash))
                {
                    pto->mapAskFor.erase(pto->mapAskFor.begin());
                    continue;
                }
                if (pto->setBlocksInFlight.size() >= MAX_BLOCKS_IN_FLIGHT_PER_PEER)
                {
                    // Preserve queued request order at the inflight cap: the front request stays next
                    // eligible, never re-added with a postponed timestamp.
                    break;
                }
            }
            {
                TRY_LOCK(cs_main, lockMain);
                if (lockMain)
                {
                    CTxDB txdb("r");
                    fSkip = AlreadyHave(txdb, inv);
                }
            }
            if (!fSkip)
            {
                if (fDebugNet)
                    printf("sending getdata: %s\n", inv.ToString().c_str());
                vGetData.push_back(inv);
                if (fBlockRequest)
                    pto->MarkBlockInFlight(inv.hash);
                if (vGetData.size() >= 1000)
                {
                    pto->PushMessage("getdata", vGetData);
                    vGetData.clear();
                }
            }
            {
                LOCK(cs_mapAlreadyAskedFor);
                mapAlreadyAskedFor[inv] = nNow;
            }
            pto->mapAskFor.erase(pto->mapAskFor.begin());
        }
        if (!vGetData.empty())
            pto->PushMessage("getdata", vGetData);
    }



    return true;
}

