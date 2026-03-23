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
#include "dag.h"
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
int nBestHeight = -1;
bool CollateralNReorgBlock = true;
uint256 nBestChainTrust = 0;
uint256 nBestInvalidTrust = 0;

uint256 hashBestChain = 0;
CBlockIndex* pindexBest = NULL;
int64_t nTimeBestReceived = 0;

bool fImporting = false;
bool fReindex = false;
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
    // Notifies listeners of a new active block chain.
    boost::signals2::signal<void (const CBlockLocator &)> SetBestChain;
    // Notifies listeners about an inventory item being seen on the network.
    boost::signals2::signal<void (const uint256 &)> Inventory;
    // Tells listeners to broadcast their data.
    boost::signals2::signal<void (bool)> Broadcast;

} g_signals;
}

void RegisterWallet(CWallet* pwalletIn) {
    g_signals.EraseTransaction.connect(boost::bind(&CWallet::EraseFromWallet, pwalletIn, _1));
    g_signals.UpdatedTransaction.connect(boost::bind(&CWallet::UpdatedTransaction, pwalletIn, _1));
    g_signals.SetBestChain.connect(boost::bind(&CWallet::SetBestChain, pwalletIn, _1));
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
    g_signals.SetBestChain.disconnect(boost::bind(&CWallet::SetBestChain, pwalletIn, _1));
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

// make sure all wallets know about the given transaction, in the given block
void SyncWithWallets(const CTransaction& tx, const CBlock* pblock, bool fUpdate, bool fConnect)
{
    if (!fConnect)
    {
        // ppcoin: wallets need to refund inputs when disconnecting coinstake
        if (tx.IsCoinStake())
        {
            for (CWallet* pwallet : setpwalletRegistered)
            {
                if (pwallet->IsFromMe(tx))
                    pwallet->DisableTransaction(tx);
            };
        };

        if (tx.nVersion == ANON_TXN_VERSION)
        {
            for (CWallet* pwallet : setpwalletRegistered)
                pwallet->UndoAnonTransaction(tx);
        };
        return;
    };

    //uint256 hash = tx.GetHash();
    for (CWallet* pwallet : setpwalletRegistered)
        pwallet->AddToWalletIfInvolvingMe(tx, pblock, fUpdate);
}

// notify wallets about a new best chain
void static SetBestChain(const CBlockLocator& loc)
{
    for (CWallet* pwallet : setpwalletRegistered)
        pwallet->SetBestChain(loc);
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

    LOCK(cs_main);

    SecureMsgShutdown();
    //nTransactionsUpdated++;
    mempool.AddTransactionsUpdated(1);
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
    if (tx.nVersion > CTransaction::CURRENT_VERSION && tx.nVersion != ANON_TXN_VERSION && tx.nVersion != NAMECOIN_TX_VERSION && !tx.IsShielded()) { //WIP
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
    if (nDataOut > nTxnOut) {
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
                // ... extra data left on the stack after execution is OK, too:
                return (sigops <= MAX_P2SH_SIGOPS);
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
    unsigned int nLongSamples = std::min(ADAPTIVE_LONG_MEDIAN_WINDOW, (unsigned int)50000);
    for (unsigned int i = 0; i < nLongSamples && pWalk; i++)
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
    // Basic checks that don't depend on any context
    if (vin.empty() && !IsShielded())
        return DoS(10, error("CTransaction::CheckTransaction() : vin empty"));
    if (vout.empty() && !IsShielded())
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

        if (vShieldedSpend.empty() && vShieldedOutput.empty())
            return DoS(100, error("CTransaction::CheckTransaction() : shielded tx has no shielded components"));

        if (vShieldedSpend.size() > MAX_SHIELDED_INPUTS)
            return DoS(100, error("CTransaction::CheckTransaction() : too many shielded spends (%u > %u)",
                                  (unsigned int)vShieldedSpend.size(), (unsigned int)MAX_SHIELDED_INPUTS));
        if (vShieldedOutput.size() > MAX_SHIELDED_OUTPUTS)
            return DoS(100, error("CTransaction::CheckTransaction() : too many shielded outputs (%u > %u)",
                                  (unsigned int)vShieldedOutput.size(), (unsigned int)MAX_SHIELDED_OUTPUTS));

        if (nValueBalance < -MAX_MONEY || nValueBalance > MAX_MONEY)
            return DoS(100, error("CTransaction::CheckTransaction() : shielded nValueBalance out of range"));

        set<uint256> vNullifiers;
        for (const CShieldedSpendDescription& spend : vShieldedSpend)
        {
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
                if (!fHideReceiver)
                {
                    if (!output.vchEncCiphertext.empty())
                        return DoS(100, error("CTransaction::CheckTransaction() : DSP output %u has ciphertext in public-receiver mode", (unsigned int)i));
                    if (output.vchRecipientScript.empty())
                        return DoS(100, error("CTransaction::CheckTransaction() : DSP output %u missing recipient in public-receiver mode", (unsigned int)i));
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

bool CTxMemPool::accept(CTxDB& txdb, CTransaction &tx, bool fCheckInputs,
                        bool* pfMissingInputs, bool fOnlyCheckWithoutAdding)
{
    AssertLockHeld(cs_main);
    printf("CTxMemPool::accept, fCheckInputs = %d, fOnlyCheckWithoutAdding = %d, ver=%d, vin=%u, vout=%u, vSS=%u, vSO=%u\n",
           fCheckInputs, fOnlyCheckWithoutAdding, tx.nVersion, (unsigned)tx.vin.size(),
           (unsigned)tx.vout.size(), (unsigned)tx.vShieldedSpend.size(), (unsigned)tx.vShieldedOutput.size());
    if (pfMissingInputs)
        *pfMissingInputs = false;

    size_t nMaxMempoolSize = GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
    if (GetTotalMemoryUsage() >= nMaxMempoolSize)
        return error("CTxMemPool::accept() : mempool full (%" PRIu64" bytes)", (uint64_t)nMaxMempoolSize);

    if (!tx.CheckTransaction())
        return error("CTxMemPool::accept() : CheckTransaction failed");

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return tx.DoS(100, error("CTxMemPool::accept() : coinbase as individual tx"));

    // ppcoin: coinstake is also only valid in a block, not as a loose transaction
    if (tx.IsCoinStake())
        return tx.DoS(100, error("CTxMemPool::accept() : coinstake as individual tx"));

    //bool isNameTx = hooks->IsNameFeeEnough(txdb, tx); //accept name tx with correct fee.
    bool isNameTx = tx.nVersion == NAMECOIN_TX_VERSION;
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
        // IDAG Phase 3: Reject txids already included in a DAG sibling block
        if (setDAGSeenTxids.count(hash))
            return error("CTxMemPool::accept() : tx %s already in DAG sibling block", hash.ToString().substr(0, 20).c_str());
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

            GetMinFee_mode feeMode = GMF_RELAY;

            if (tx.nVersion == ANON_TXN_VERSION)
            {
                if (nBestHeight >= FORK_HEIGHT_RINGSIG_DEPRECATION)
                    return error("CTxMemPool::accept() : ring signature transactions (ANON_TXN_VERSION) deprecated after height %d. Use shielded transactions.", FORK_HEIGHT_RINGSIG_DEPRECATION);

                int64_t nSumAnon;
                if (!tx.CheckAnonInputs(txdb, nSumAnon, fInvalid, true))
                {
                    if (fInvalid)
                        return error("CTxMemPool::accept() : CheckAnonInputs found invalid tx %s", hash.ToString().substr(0,10).c_str());
                    if (pfMissingInputs)
                        *pfMissingInputs = true;
                    return false;
                };

                nFees += nSumAnon;

                feeMode = GMF_ANON;
            };

            if (tx.IsShielded())
            {
                if (pindexBest && pindexBest->nHeight < FORK_HEIGHT_SHIELDED)
                    return error("CTxMemPool::accept() : shielded tx rejected before fork height %d", FORK_HEIGHT_SHIELDED);

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

                    if (!txdb.ReadShieldedAnchor(spend.anchor))
                        return error("CTxMemPool::accept() : shielded anchor %s not found",
                                     spend.anchor.ToString().substr(0,10).c_str());
                    int nAnchorHeight = 0;
                    if (txdb.ReadShieldedAnchorHeight(spend.anchor, nAnchorHeight))
                    {
                        if (nBestHeight - nAnchorHeight < MIN_SHIELDED_SPEND_DEPTH)
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

                    if (tx.nVersion >= SHIELDED_TX_VERSION_FCMP && nBestHeight >= FORK_HEIGHT_FCMP_VALIDATION
                        && !tx.vShieldedSpend.empty())
                    {
                        for (size_t j = 0; j < tx.vShieldedSpend.size(); j++)
                        {
                            if (tx.vShieldedSpend[j].fcmpProof.IsNull())
                                return error("CTxMemPool::accept() : FCMP version tx spend %u missing mandatory FCMP proof", (unsigned)j);
                        }
                    }

                    CCurveTreeNode fcmpRootNode;
                    if (tx.nVersion >= SHIELDED_TX_VERSION_FCMP && nBestHeight >= FORK_HEIGHT_FCMP_VALIDATION
                        && !tx.vShieldedSpend.empty())
                    {
                        CCurveTree memCurveTree;
                        CTxDB txdb("r");
                        txdb.ReadCurveTree(memCurveTree);
                        memCurveTree.RebuildParentNodes();
                        fcmpRootNode = memCurveTree.GetRootNode();
                    }

                    for (size_t i = 0; i < tx.vShieldedSpend.size(); i++)
                    {
                        if (fHideAmount)
                        {
                            if (!VerifyBulletproofRangeProof(tx.vShieldedSpend[i].cv, tx.vShieldedSpend[i].rangeProof))
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
                                // Verify all vAnonSet commitments exist on-chain
                                {
                                    CTxDB txdb("r");
                                    std::set<std::vector<unsigned char>> setChainCommitments;
                                    uint64_t nCommitCount = 0;
                                    txdb.ReadShieldedCommitmentCount(nCommitCount);
                                    for (uint64_t ci = 0; ci < nCommitCount; ci++)
                                    {
                                        CPedersenCommitment chainCommit;
                                        if (txdb.ReadShieldedCommitment(ci, chainCommit))
                                            setChainCommitments.insert(chainCommit.vchCommitment);
                                    }

                                    for (size_t j = 0; j < tx.vShieldedSpend[i].vAnonSet.size(); j++)
                                    {
                                        if (setChainCommitments.find(tx.vShieldedSpend[i].vAnonSet[j].vchCommitment) == setChainCommitments.end())
                                            return error("CTxMemPool::accept() : shielded spend %d anonymity set commitment %d not found in chain state", (int)i, (int)j);
                                    }
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

                        // FCMP++ proof: required after FORK_HEIGHT_FCMP_VALIDATION for FCMP tx versions
                        if (tx.nVersion >= SHIELDED_TX_VERSION_FCMP && nBestHeight >= FORK_HEIGHT_FCMP_VALIDATION)
                        {
                            if (tx.vShieldedSpend[i].fcmpProof.IsNull())
                                return error("CTxMemPool::accept() : shielded spend %d missing FCMP++ proof (required post-fork)", (int)i);

                            if (!VerifyFCMPProof(fcmpRootNode, tx.vShieldedSpend[i].fcmpProof, tx.vShieldedSpend[i].cv))
                                return error("CTxMemPool::accept() : shielded spend %d FCMP++ proof failed", (int)i);
                        }

                        if (fDebug)
                            printf("CTxMemPool::accept() : spend %d passed all checks\n", (int)i);
                    }

                    if (fDebug)
                        printf("CTxMemPool::accept() : verifying output proofs\n");
                    for (size_t i = 0; i < tx.vShieldedOutput.size(); i++)
                    {
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
                            vInCommits.push_back(tx.vShieldedSpend[i].cv);
                        for (size_t i = 0; i < tx.vShieldedOutput.size(); i++)
                            vOutCommits.push_back(tx.vShieldedOutput[i].cv);

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

            if (nFees < txMinFee && !isNameTx)
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
            if (!tx.ConnectInputs(txdb, mapInputs, mapUnused, CDiskTxPos(1,1,1), pindexBest, false, false))
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
            addUnchecked(hash, tx);

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
                if (fDebugNet) return error("AcceptableInputs : FetchInputs found invalid tx %s", hash.ToString().substr(0,10).c_str());
                return false;
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
        if (!tx.ConnectInputs(txdb, mapInputs, mapUnused, CDiskTxPos(1,1,1), pindexBest, true, false, STANDARD_SCRIPT_VERIFY_FLAGS, false))
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

    return true;
}

// IDAG Phase 3: Remove mempool transactions that appear in a DAG sibling block
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
    return max(0, (nCoinbaseMaturity+10) - GetDepthInMainChain());
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
        if (tx.ReadFromDisk(txdb, COutPoint(hash, 0), txindex))
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

static CBlockIndex* pblockindexFBBHLast;
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
void static PruneOrphanBlocks()
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
    delete it->second;
    mapOrphanBlocksByPrev.erase(it);
    mapOrphanBlocks.erase(hash);

    map<uint256, NodeId>::iterator nodeIt = mapOrphanBlocksByNode.find(hash);
    if (nodeIt != mapOrphanBlocksByNode.end()) {
        mapOrphanCountByNode[nodeIt->second]--;
        mapOrphanBlocksByNode.erase(nodeIt);
    }
}

// Proof of Work miner's coin base reward
int64_t GetProofOfWorkReward(int nHeight, int64_t nFees)
{
  int64_t nSubsidy = 1 * COIN;

  // use nHeight parameter instead of pindexBest->nHeight
  // to correctly compute reward during validation of non-tip blocks
  if (fRegTest) {
       // Regtest: simple flat reward for easy testing (similar to Bitcoin regtest)
       if (nHeight == 0)
           nSubsidy = 0;  // Genesis block has no spendable reward
       else
           nSubsidy = 50 * COIN;  // 50 INN per block

       if (fDebug && GetBoolArg("-printcreation"))
           printf("GetProofOfWorkReward() : create=%s nSubsidy=%" PRId64"\n", FormatMoney(nSubsidy).c_str(), nSubsidy);

       return nSubsidy + nFees;
  } else if (fTestNet) {
       if (nHeight == 1)
           nSubsidy = 1000000 * COIN;  // 10m INN Premine for Testnet for testing
       else if (nHeight <= FAIR_LAUNCH_BLOCK) // Block 490, Instamine prevention
           nSubsidy = 1 * COIN/2;
       else if (nHeight <= 5000)
           nSubsidy = 10 * COIN;
       else if (nHeight > 5000) // Block 5000
           nSubsidy = 0;
     else if (nHeight > 10000)
          nSubsidy = 10000; // PoW Reward 0.0001

       if (fDebug && GetBoolArg("-printcreation"))
           printf("GetProofOfWorkReward() : create=%s nSubsidy=%" PRId64"\n", FormatMoney(nSubsidy).c_str(), nSubsidy);

       return nSubsidy + nFees;
   } else {
  // use nHeight parameter throughout (was pindexBest->nHeight)
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
    else if (nHeight <= 8750000) // 0.1 Coin PoW Reward to release 1 CollateralNode in 250,000 blocks
      nSubsidy = 0.1 * COIN;
    else if (nHeight <= 9000000) // 0.05 Coin PoW Reward to release 12,500 INN in 250,000 blocks
      nSubsidy = 0.05 * COIN;
    else if (nHeight <= 9250000) // 0.01 Coin PoW Reward to release 2,500 INN in 250,000 blocks
      nSubsidy = 0.01 * COIN;
    else if (nHeight <= 9500000) // 0.05 Coin PoW Reward to release 12,500 INN in 250,000 blocks
      nSubsidy = 0.05 * COIN;
    else if (nHeight <= 9750000) // 0.1 Coin PoW Reward to release 1 CollateralNode in 250,000 blocks
      nSubsidy = 0.1 * COIN;
    else if (nHeight <= 10000000) // 0.2 Coin PoW Reward to release 50,000 INN in 250,000 blocks
      nSubsidy = 0.2 * COIN;
    else if (nHeight >= 10000000) // 0.0001 Coin PoW Reward to release ~200 INN per year
      nSubsidy = 0.0001 * COIN; // Final PoW Reward 0.0001 INN @ block 10 mln

    if (fDebug && GetBoolArg("-printcreation"))
      printf("GetProofOfWorkReward() : create=%s nSubsidy=%" PRId64"\n", FormatMoney(nSubsidy).c_str(), nSubsidy);

      return nSubsidy + nFees;
    }
}

const int YEARLY_BLOCKCOUNT = 2103792; // Amount of Blocks per year

// Proof of Stake miner's coin stake reward based on coin age spent (coin-days)
int64_t GetProofOfStakeReward(int64_t nCoinAge, int64_t nFees)
{
    // CON-AUDIT-2: Guard pindexBest NULL, use nBestHeight for reward calculation
    int nHeight = 0;
    {
        LOCK(cs_main);
        if (pindexBest)
            nHeight = pindexBest->nHeight;
    }
    if (nHeight > (YEARLY_BLOCKCOUNT*9000)) // It's Over 9000!! [years] - Vegeta
        return nFees;

    int64_t nRewardCoinYear;
    nRewardCoinYear = COIN_YEAR_REWARD; // 0.06 6%

    int64_t nSubsidy;
    nSubsidy = nCoinAge / 365 * nRewardCoinYear + nCoinAge % 365 * nRewardCoinYear / 365;

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

unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake)
{
    CBigNum bnTargetLimit = fProofOfStake ? bnProofOfStakeLimit : bnProofOfWorkLimit;

    if (pindexLast == NULL)
        return bnTargetLimit.GetCompact(); // genesis block

    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
    if (pindexPrev->pprev == NULL)
        return bnTargetLimit.GetCompact(); // first block
    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);
    if (pindexPrevPrev->pprev == NULL)
        return bnTargetLimit.GetCompact(); // second block

    int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();

    // Clamp nActualSpacing (tighter bounds post-fork, negative-only pre-fork)
    int nNextHeight = pindexLast->nHeight + 1;
    unsigned int nEffectiveSpacing = GetTargetSpacingForHeight(nNextHeight);

    if (nNextHeight < FORK_HEIGHT_TIGHTER_DRIFT)
    {
        if (nActualSpacing < 0)
            nActualSpacing = nEffectiveSpacing;
    }
    else
    {
        int64_t nMinSpacing = (int64_t)nEffectiveSpacing / 10;
        if (nMinSpacing < 1) nMinSpacing = 1;
        int64_t nMaxSpacing = (int64_t)nEffectiveSpacing * 10;

        if (nActualSpacing < nMinSpacing)
        {
            if (nActualSpacing < 0)
                printf("WARNING: GetNextTargetRequired() : negative actual spacing %" PRId64 " (clamping to %" PRId64 ")\n",
                       nActualSpacing, nMinSpacing);
            nActualSpacing = nMinSpacing;
        }
        if (nActualSpacing > nMaxSpacing)
            nActualSpacing = nMaxSpacing;
    }

    // ppcoin: target change every block
    // ppcoin: retarget with exponential moving toward target spacing
    CBigNum bnNew;
    bnNew.SetCompact(pindexPrev->nBits);
    int64_t nInterval = nTargetTimespan / nEffectiveSpacing;
    bnNew *= ((nInterval - 1) * nEffectiveSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * nEffectiveSpacing);

    if (bnNew <= 0 || bnNew > bnTargetLimit)
        bnNew = bnTargetLimit;

    return bnNew.GetCompact();
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
    return std::max(cPeerBlockCounts.median(), Checkpoints::GetTotalBlocksEstimate());
}

bool IsSynchronized() {
  static bool rc = false;
  if(rc == false) rc = !IsInitialBlockDownload();
  return rc;
}

bool IsInitialBlockDownload()
{
    if (fRegTest && pindexBest != NULL)
        return false;
    if (pindexBest == NULL || nBestHeight < Checkpoints::GetTotalBlocksEstimate() || nBestHeight < (GetNumBlocksOfPeers() - nCoinbaseMaturity*2))
        return true;
    static int64_t nLastUpdate;
    static CBlockIndex* pindexLastBest;
    static bool lockIBDState = false;
        if (lockIBDState)
            return false;
    if (pindexBest != pindexLastBest)
    {
        pindexLastBest = pindexBest;
        nLastUpdate = GetTime();
    }

    bool state = (GetTime() - nLastUpdate < 5 &&
            pindexBest->GetBlockTime() < (GetTime() - 300)); // last block is more than 5 minutes old

    if (state)
    {
        lockIBDState = true;
        // do stuff required at end of sync
        GetCollateralnodeRanks(pindexBest);
    }
    return state;

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
void Misbehaving(NodeId pnode, int howmuch)
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
                printf("Misbehaving: %s (%d -> %d) BAN THRESHOLD EXCEEDED\n", pn->addrName.c_str(), pn->nMisbehavior-howmuch, pn->nMisbehavior);
                pn->fDisconnect = true;
            }
            else
                printf("Misbehaving: %s (%d -> %d)\n", pn->addrName.c_str(), pn->nMisbehavior-howmuch, pn->nMisbehavior);

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
static bool CheckAnonInputAB(CTxDB &txdb, const CTxIn &txin, int i, int nRingSize, std::vector<uint8_t> &vchImage, uint256 &preimage, int64_t &nCoinValue)
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
        if (!txdb.ReadAnonOutput(pkRingCoin, ao))
        {
            printf("CheckAnonInputsAB(): Error input %d, element %d AnonOutput %s not found.\n", i, ri);
            return false;
        };

        if (nCoinValue == -1)
        {
            nCoinValue = ao.nValue;
        } else
        if (nCoinValue != ao.nValue)
        {
            printf("CheckAnonInputsAB(): Error input %d, element %d ring amount mismatch %d, %d.\n", i, ri, nCoinValue, ao.nValue);
            return false;
        };

        if (ao.nBlockHeight == 0
            || nBestHeight - ao.nBlockHeight < MIN_ANON_SPEND_DEPTH)
        {
            printf("CheckAnonInputsAB(): Error input %d, element %d depth < MIN_ANON_SPEND_DEPTH.\n", i, ri);
            return false;
        };
    };

    if (verifyRingSignatureAB(vchImage, preimage, nRingSize, pPubkeys, pSigC, pSigS) != 0)
    {
        printf("CheckAnonInputsAB(): Error input %d verifyRingSignatureAB() failed.\n", i);
        return false;
    };

    return true;
};

bool CTransaction::CheckAnonInputs(CTxDB& txdb, int64_t& nSumValue, bool& fInvalid, bool fCheckExists)
{
    AssertLockHeld(cs_main);
    // - fCheckExists should only run for anonInputs entering this node

    fInvalid = false;

    nSumValue = 0;

    uint256 preimage;
    if (pwalletMain->GetTxnPreImage(*this, preimage) != 0)
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

        CKeyImageSpent spentKeyImage;
        bool fInMemPool;
        if (GetKeyImage(&txdb, vchImage, spentKeyImage, fInMemPool))
        {
            // -- this can happen for transactions created by the local node
            if (spentKeyImage.txnHash == txnHash)
            {
                if (fDebugRingSig)
                    printf("Input %d keyimage %s matches txn %s.\n", i, HexStr(vchImage).c_str(), txnHash.ToString().c_str());
            } else
            {
                if (fCheckExists
                    && !TxnHashInSystem(&txdb, spentKeyImage.txnHash))
                {
                    printf("CheckAnonInputs(): Warning input %d keyimage %s spent by unknown txn %s - rejecting for safety.\n",
                           i, HexStr(vchImage).c_str(), spentKeyImage.txnHash.ToString().c_str());
                    fInvalid = true; return false;
                } else
                {
                    printf("CheckAnonInputs(): Error input %d keyimage %s already spent.\n", i, HexStr(vchImage).c_str());
                    fInvalid = true; return false;
                };
            };
        };

        int64_t nCoinValue = -1;
        int nRingSize = txin.ExtractRingSize();
        if (nRingSize < (int)MIN_RING_SIZE
          ||nRingSize > (pindexBest->nHeight ? (int)MAX_RING_SIZE : (int)MAX_RING_SIZE_OLD))
        {
            printf("CheckAnonInputs(): Error input %d ringsize %d not in range [%d, %d].\n", i, nRingSize, MIN_RING_SIZE, MAX_RING_SIZE);
            fInvalid = true; return false;
        };


        if (nRingSize > 1 && s.size() == 2 + ec_secret_size + (ec_secret_size + ec_compressed_size) * nRingSize)
        {
            // ringsig AB
            if (!CheckAnonInputAB(txdb, txin, i, nRingSize, vchImage, preimage, nCoinValue))
            {
                fInvalid = true; return false;
            };

            nSumValue += nCoinValue;
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
            if (!txdb.ReadAnonOutput(pkRingCoin, ao))
            {
                printf("CheckAnonInputs(): Error input %d, element %d AnonOutput %s not found.\n", i, ri);
                fInvalid = true; return false;
            };

            if (nCoinValue == -1)
            {
                nCoinValue = ao.nValue;
            } else
            if (nCoinValue != ao.nValue)
            {
                printf("CheckAnonInputs(): Error input %d, element %d ring amount mismatch %d, %d.\n", i, ri, nCoinValue, ao.nValue);
                fInvalid = true; return false;
            };

            if (ao.nBlockHeight == 0
                || nBestHeight - ao.nBlockHeight < MIN_ANON_SPEND_DEPTH)
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

        nSumValue += nCoinValue;
    };

    return true;
};

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
    const CBlockIndex* pindexBlock, bool fBlock, bool fMiner, unsigned int flags, bool fValidateSig, bool fSkipFCMP)
{
    // Take over previous transactions' spent pointers
    // fBlock is true when this is called from AcceptBlock when a new best-block is added to the blockchain
    // fMiner is true when called from the internal bitcoin miner
    // ... both are false when called from CTransaction::AcceptToMemoryPool
    if (!IsCoinBase())
    {
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
            if (!(fBlock && (nBestHeight < Checkpoints::GetTotalBlocksEstimate())))
            {
                // Verify signature
                if (!VerifySignature(txPrev, *this, i, flags, 0))
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
            if (pindexBlock && pindexBlock->nHeight >= FORK_HEIGHT_RINGSIG_DEPRECATION)
                return DoS(100, error("ConnectInputs() : ring signature transactions deprecated after height %d", FORK_HEIGHT_RINGSIG_DEPRECATION));

            int64_t nSumAnon;
            bool fInvalid;
            if (!CheckAnonInputs(txdb, nSumAnon, fInvalid, true))
            {
                //if (fInvalid)
                DoS(100, error("ConnectInputs() : CheckAnonInputs found invalid tx %s", GetHash().ToString().substr(0,10).c_str()));
            };

            nValueIn += nSumAnon;
        };

        if (IsShielded())
        {
            if (pindexBlock && pindexBlock->nHeight < FORK_HEIGHT_SHIELDED)
                return DoS(100, error("ConnectInputs() : shielded tx before activation height %d", FORK_HEIGHT_SHIELDED));

            for (const CShieldedSpendDescription& spend : vShieldedSpend)
            {
                CShieldedNullifierSpent nfs;
                if (txdb.ReadShieldedNullifier(spend.nullifier, nfs))
                    return DoS(100, error("ConnectInputs() : shielded nullifier %s already spent in tx %s",
                                          spend.nullifier.ToString().substr(0,10).c_str(),
                                          nfs.txnHash.ToString().substr(0,10).c_str()));

                if (!txdb.ReadShieldedAnchor(spend.anchor))
                    return DoS(100, error("ConnectInputs() : shielded anchor %s not found",
                                          spend.anchor.ToString().substr(0,10).c_str()));
                int nAnchorHeight = 0;
                if (pindexBlock && txdb.ReadShieldedAnchorHeight(spend.anchor, nAnchorHeight))
                {
                    if (pindexBlock->nHeight - nAnchorHeight < MIN_SHIELDED_SPEND_DEPTH)
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

            // NullStake coinstakes are exempt: the reward enters the shielded pool
            // from block subsidy, not from transparent inputs. The reward amount
            // is validated separately in ConnectBlock() against GetProofOfStakeReward().
            if ((nVersion != SHIELDED_TX_VERSION_NULLSTAKE && nVersion != SHIELDED_TX_VERSION_NULLSTAKE_V2 && nVersion != SHIELDED_TX_VERSION_NULLSTAKE_COLD) || !IsCoinStake())
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

                CCurveTreeNode ciRootNode;
                if (nVersion >= SHIELDED_TX_VERSION_FCMP && nBlockHeight >= FORK_HEIGHT_FCMP_VALIDATION
                    && !vShieldedSpend.empty())
                {
                    CCurveTree ciCurveTree;
                    txdb.ReadCurveTree(ciCurveTree);
                    ciCurveTree.RebuildParentNodes();
                    ciRootNode = ciCurveTree.GetRootNode();
                }

                for (size_t i = 0; i < vShieldedSpend.size(); i++)
                {
                    if (fHideAmount)
                    {
                        if (!VerifyBulletproofRangeProof(vShieldedSpend[i].cv, vShieldedSpend[i].rangeProof))
                            return DoS(100, error("ConnectInputs() : shielded spend %d range proof failed", (int)i));
                    }
                    else
                    {
                        if (!VerifyPedersenCommitment(vShieldedSpend[i].cv,
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
                                std::set<std::vector<unsigned char>> setChainCommitments;
                                uint64_t nCommitCount = 0;
                                txdb.ReadShieldedCommitmentCount(nCommitCount);
                                for (uint64_t ci = 0; ci < nCommitCount; ci++)
                                {
                                    CPedersenCommitment chainCommit;
                                    if (txdb.ReadShieldedCommitment(ci, chainCommit))
                                        setChainCommitments.insert(chainCommit.vchCommitment);
                                }

                                for (size_t j = 0; j < vShieldedSpend[i].vAnonSet.size(); j++)
                                {
                                    if (setChainCommitments.find(vShieldedSpend[i].vAnonSet[j].vchCommitment) == setChainCommitments.end())
                                        return DoS(100, error("ConnectInputs() : shielded spend %d anonymity set commitment %d not in chain state", (int)i, (int)j));
                                }
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

                    // FCMP++ proof: required after FORK_HEIGHT_FCMP_VALIDATION for FCMP tx versions
                    if (!fSkipFCMP && nVersion >= SHIELDED_TX_VERSION_FCMP && nBlockHeight >= FORK_HEIGHT_FCMP_VALIDATION)
                    {
                        if (vShieldedSpend[i].fcmpProof.IsNull())
                            return DoS(100, error("ConnectInputs() : shielded spend %d missing FCMP++ proof (required post-fork)", (int)i));

                        if (!VerifyFCMPProof(ciRootNode, vShieldedSpend[i].fcmpProof, vShieldedSpend[i].cv))
                            return DoS(100, error("ConnectInputs() : shielded spend %d FCMP++ proof failed", (int)i));
                    }
                }
                for (size_t i = 0; i < vShieldedOutput.size(); i++)
                {
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
                        vInCommits.push_back(vShieldedSpend[i].cv);
                    for (size_t i = 0; i < vShieldedOutput.size(); i++)
                        vOutCommits.push_back(vShieldedOutput[i].cv);

                    if (!VerifyBindingSignature(vInCommits, vOutCommits, nValueBalance, sighash, bindingSig.bindingSig))
                        return DoS(100, error("ConnectInputs() : shielded binding signature verification failed"));
                }
            }
        };

        if (!IsCoinStake())
        {
            int64_t nEffectiveOut = GetValueOut();
            if (IsShielded() && nValueBalance < 0)
                nEffectiveOut += (-nValueBalance); // shielded value absorbed from transparent

            if (nValueIn < nEffectiveOut)
                return DoS(100, error("ConnectInputs() : %s value in < value out", GetHash().ToString().substr(0,10).c_str()));

            // Tally transaction fees
            int64_t nTxFee = nValueIn - nEffectiveOut;
            if (nTxFee < 0)
                return DoS(100, error("ConnectInputs() : %s nTxFee < 0", GetHash().ToString().substr(0,10).c_str()));

            // enforce transaction fees for every block
            if (nTxFee < GetMinFee())
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
    // Disconnect in reverse order
    for (int i = vtx.size()-1; i >= 0; i--)
        if (!vtx[i].DisconnectInputs(txdb))
            return false;

    if (pindex->nHeight >= FORK_HEIGHT_SHIELDED)
    {
        for (const CTransaction& tx : vtx)
        {
            if (!tx.IsShielded())
                continue;

            for (const CShieldedSpendDescription& spend : tx.vShieldedSpend)
            {
                txdb.EraseShieldedNullifier(spend.nullifier);
            }

            int64_t nShieldedPool = 0;
            txdb.ReadShieldedPoolValue(nShieldedPool);
            nShieldedPool += tx.nValueBalance; // reverse the subtraction done in ConnectBlock
            txdb.WriteShieldedPoolValue(nShieldedPool);
            nShieldedPoolValue = nShieldedPool;
        }

        CIncrementalMerkleTree currentTree;
        if (txdb.ReadShieldedTree(currentTree))
        {
            uint256 currentRoot = currentTree.Root();
            txdb.EraseShieldedAnchor(currentRoot);
        }

        CIncrementalMerkleTree prevTree;
        if (txdb.ReadShieldedTreeAtBlock(pindex->GetBlockHash(), prevTree))
        {
            txdb.WriteShieldedTree(prevTree);

            txdb.WriteShieldedCommitmentCount(prevTree.Size());
        }

        if (pindex->nHeight >= FORK_HEIGHT_FCMP)
        {
            CCurveTree restoredCurveTree;
            if (txdb.ReadCurveTreeAtBlock(pindex->GetBlockHash(), restoredCurveTree))
            {
                txdb.WriteCurveTree(restoredCurveTree);
            }
            else
            {
                // fallback: O(n) rebuild
                printf("DisconnectBlock() : WARNING - Curve Tree snapshot not found for block %s, falling back to O(n) rebuild\n",
                       pindex->GetBlockHash().ToString().substr(0,16).c_str());
                uint64_t nRestoredCount = prevTree.Size();
                for (uint64_t i = 0; i < nRestoredCount; i++)
                {
                    CPedersenCommitment commit;
                    if (txdb.ReadShieldedCommitment(i, commit))
                        restoredCurveTree.InsertLeaf(commit);
                }
                txdb.WriteCurveTree(restoredCurveTree);
            }
            txdb.EraseCurveTreeAtBlock(pindex->GetBlockHash());
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

    // innova: undo name transactions in reverse order
    for (int i = vtx.size() - 1; i >= 0; i--)
        hooks->DisconnectInputs(vtx[i]);

    // ppcoin: clean up wallet after disconnecting coinstake
    for (CTransaction& tx : vtx)
        SyncWithWallets(tx, this, false, false);

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

// Seed deterministic unspendable commitments at fork height for Lelantus anonymity set.
// Each seed: blind_i = SHA256("Innova_Genesis_Seed_" || i), cv_i = blind_i * G (zero value),
// cmu_i = SHA256("Innova_Genesis_Seed_CMU_" || i). Unspendable: no spending key, no nullifier derivation.
bool SeedGenesisCommitments(CTxDB& txdb, CIncrementalMerkleTree& shieldedTree, CCurveTree* pCurveTree)
{
    for (int i = 0; i < LELANTUS_GENESIS_SEED_COUNT; i++)
    {
        // Deterministic blinding factor
        CHashWriter ssBlind(SER_GETHASH, 0);
        ssBlind << std::string("Innova_Genesis_Seed_");
        ssBlind << i;
        uint256 blindHash = ssBlind.GetHash();
        std::vector<unsigned char> vchBlind(blindHash.begin(), blindHash.begin() + 32);

        CPedersenCommitment cv;
        if (!CreateBlindCommitment(vchBlind, cv))
            return error("SeedGenesisCommitments() : CreateBlindCommitment failed for seed %d", i);

        // Deterministic note commitment (Merkle leaf)
        CHashWriter ssCmu(SER_GETHASH, 0);
        ssCmu << std::string("Innova_Genesis_Seed_CMU_");
        ssCmu << i;
        uint256 cmu = ssCmu.GetHash();

        // Append to Merkle tree and write to commitment DB
        shieldedTree.Append(cmu);
        uint64_t nCommitIdx = shieldedTree.Size() - 1;
        if (!txdb.WriteShieldedCommitment(nCommitIdx, cv))
            return error("SeedGenesisCommitments() : WriteShieldedCommitment failed for seed %d", i);

        if (pCurveTree)
            pCurveTree->InsertLeaf(cv);
    }

    if (fDebug)
        printf("SeedGenesisCommitments() : seeded %d genesis commitments for Lelantus anonymity set\n",
               LELANTUS_GENESIS_SEED_COUNT);
    return true;
}

bool CBlock::ConnectBlock(CTxDB& txdb, CBlockIndex* pindex, bool fJustCheck, bool fWriteNames)
{
    // Check it again in case a previous version let a bad block in, but skip BlockSig checking
    if (!CheckBlock(!fJustCheck, !fJustCheck, false))
        return false;

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

    int64_t nTimeStart = GetTimeMicros();
    map<uint256, CTxIndex> mapQueuedChanges;
    int64_t nFees = 0;
    int64_t nValueIn = 0;
    int64_t nValueOut = 0;
    int64_t nAmountBurned = 0;
    int64_t nStakeReward = 0;
    unsigned int nSigOps = 0;

    //DiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(vtx.size()));
    CDiskTxPos pos(pindex->nFile, pindex->nBlockPos, nTxPos);
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    vPos.reserve(vtx.size());

    std::vector<CAmount> vFees (vtx.size(), 0);

    bool fFCMPBatchVerified = false;
    if (pindex->nHeight >= FORK_HEIGHT_FCMP_VALIDATION)
    {
        std::vector<CFCMPProof> vBlockProofs;
        std::vector<CPedersenCommitment> vBlockCommitments;

        for (unsigned int i = 1; i < vtx.size(); i++)
        {
            if (vtx[i].nVersion >= SHIELDED_TX_VERSION_FCMP)
            {
                if (vtx[i].vShieldedSpend.size() > 1000)
                    return DoS(100, error("ConnectBlock() : tx %d has too many shielded spends (%u)", i, (unsigned int)vtx[i].vShieldedSpend.size()));

                for (const auto& spend : vtx[i].vShieldedSpend)
                {
                    if (spend.fcmpProof.IsNull())
                        return DoS(100, error("ConnectBlock() : tx %d spend missing FCMP++ proof", i));
                    vBlockProofs.push_back(spend.fcmpProof);
                    vBlockCommitments.push_back(spend.cv);
                }
            }
        }

        if (!vBlockProofs.empty())
        {
            CCurveTree curveTree;
            // check ReadCurveTree return value
            if (!txdb.ReadCurveTree(curveTree))
                return DoS(100, error("ConnectBlock() : failed to read curve tree from database"));
            curveTree.RebuildParentNodes();
            CCurveTreeNode root = curveTree.GetRootNode();

            if (!BatchVerifyFCMPProofs(root, vBlockProofs, vBlockCommitments))
                return DoS(100, error("ConnectBlock() : batch FCMP++ proof verification failed"));

            fFCMPBatchVerified = true;

            if (fDebug)
                printf("ConnectBlock() : batch verified %d FCMP++ proofs\n", (int)vBlockProofs.size());
        }
    }

    std::set<uint256> setBlockNullifiers;

    // IDAG: Collect spent outputs from DAG sibling blocks (lower hash = canonical earlier)
    // Transactions conflicting with already-spent outputs from siblings are skipped
    std::set<COutPoint> setDAGSpentOutputs;
    bool fDAGActive = (pindex->nHeight >= FORK_HEIGHT_DAG);
    if (fDAGActive && pindex->phashBlock)
    {
        std::set<uint256> siblings = g_dagManager.GetDAGSiblingBlocks(pindex->GetBlockHash());
        for (const uint256& hashSibling : siblings)
        {
            // Only consider siblings with lower block hash (deterministic canonical ordering)
            if (hashSibling >= pindex->GetBlockHash())
                continue; // this sibling comes after us in canonical order, skip

            // Load sibling block and collect its spent outputs
            std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashSibling);
            if (mi == mapBlockIndex.end())
                continue;
            CBlock sibBlock;
            if (!sibBlock.ReadFromDisk(mi->second))
                continue;

            for (const CTransaction& sibTx : sibBlock.vtx)
            {
                if (sibTx.IsCoinBase() || sibTx.IsCoinStake())
                    continue;
                for (const CTxIn& txin : sibTx.vin)
                    setDAGSpentOutputs.insert(txin.prevout);
            }
        }
    }

    for (CTransaction& tx : vtx)
    {
        //const CTransaction &tx = vtx[i];
        uint256 hashTx = tx.GetHash();

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
                    return false;
        }

        nSigOps += tx.GetLegacySigOpCount();
        if (nSigOps > MAX_BLOCK_SIGOPS)
            return DoS(100, error("ConnectBlock() : too many sigops"));

        CDiskTxPos posThisTx(pindex->nFile, pindex->nBlockPos, nTxPos);
        if (!fJustCheck)
            nTxPos += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);

        MapPrevTx mapInputs;
        if (tx.IsCoinBase())
        {
            int64_t nCoinbaseValue;
            try {
                nCoinbaseValue = tx.GetValueOut();
            } catch (const std::runtime_error& e) {
                return DoS(100, error("ConnectBlock() : coinbase GetValueOut overflow: %s", e.what()));
            }
            nValueOut += nCoinbaseValue;
        }
        else
        {
            // IDAG Phase 2: Skip transactions whose inputs conflict with DAG siblings
            if (fDAGActive && !tx.IsCoinStake())
            {
                bool fConflict = false;
                for (const CTxIn& txin : tx.vin)
                {
                    if (setDAGSpentOutputs.count(txin.prevout))
                    {
                        fConflict = true;
                        break;
                    }
                }
                if (fConflict)
                {
                    if (fDebug)
                        printf("ConnectBlock() : DAG conflict skip tx %s (inputs spent by sibling)\n",
                               hashTx.ToString().substr(0, 20).c_str());
                    // Skip this tx but don't fail the block
                    nTxPos += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);
                    pos.nTxPos += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);
                    continue;
                }
            }

            bool fInvalid;
            if (!tx.FetchInputs(txdb, mapQueuedChanges, true, false, mapInputs, fInvalid))
                return false;

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

                int64_t nSumAnon;
                if (!tx.CheckAnonInputs(txdb, nSumAnon, fInvalid, true))
                {
                    if (fInvalid)
                        return error("ConnectBlock() : CheckAnonInputs found invalid tx %s", tx.GetHash().ToString().substr(0,10).c_str());
                    return false;
                };

                nTxValueIn += nSumAnon;
            };

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

            if (!tx.ConnectInputs(txdb, mapInputs, mapQueuedChanges, posThisTx, pindex, true, false, flags, true, fFCMPBatchVerified))
                return false;
        }

        mapQueuedChanges[hashTx] = CTxIndex(posThisTx, tx.vout.size());

        vPos.push_back(std::make_pair(tx.GetHash(), pos));
        // pos.nTxOffset += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);
        pos.nTxPos += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);
    }

    //int64_t nTime1 = GetTimeMicros(); nTimeConnect += nTime1 - nTimeStart;
    //LogPrint("bench", "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) [%.2fs]\n", (unsigned)vtx.size(), 0.001 * (nTime1 - nTimeStart), 0.001 * (nTime1 - nTimeStart) / vtx.size(), nInputs <= 1 ? 0 : 0.001 * (nTime1 - nTimeStart) / (nInputs-1), nTimeConnect * 0.000001);

    // if (!control.Wait())
    //     return state.DoS(100, false);
    // int64_t nTime2 = GetTimeMicros(); nTimeVerify += nTime2 - nTimeStart;
    // LogPrint("bench", "    - Verify %u txins: %.2fms (%.3fms/txin) [%.2fs]\n", nInputs - 1, 0.001 * (nTime2 - nTimeStart), nInputs <= 1 ? 0 : 0.001 * (nTime2 - nTimeStart) / (nInputs-1), nTimeVerify * 0.000001);


    if (IsProofOfWork())
    {
        // Historical compatibility: the original code used pindexBest->nHeight
        // (which equals pindex->nHeight - 1 during sequential block connection)
        // instead of the block's own height. The entire reward schedule was built
        // with this off-by-one behavior. Preserve it for historical blocks.
        int nRewardHeight = pindex->nHeight;
        if (pindex->nHeight < FORK_HEIGHT_TIGHTER_DRIFT && pindex->nHeight > 0)
            nRewardHeight = pindex->nHeight - 1;
        int64_t nReward = GetProofOfWorkReward(nRewardHeight, nFees);

        // Adaptive block size penalty (post-DAG): reduce allowed reward for oversized blocks
        nReward = ApplyBlockSizePenalty(nReward, *this, pindex->pprev);

        // Check coinbase reward
        if (vtx[0].GetValueOut() > nReward)
            return DoS(50, error("ConnectBlock() : coinbase reward exceeded (actual=%" PRId64" vs calculated=%" PRId64")",
                   vtx[0].GetValueOut(),
                   nReward));
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

            if (!VerifyNullStakeKernelProofV2(vtx[1].nullstakeProofV2,
                                              vtx[1].vShieldedSpend[0].cv,
                                              nBits))
                return DoS(100, error("ConnectBlock() : NullStake V2 kernel proof invalid"));

            CCurveTree nullstakeTree;
            if (!txdb.ReadCurveTree(nullstakeTree))
                return DoS(100, error("ConnectBlock() : failed to read curve tree for NullStake V2"));
            nullstakeTree.RebuildParentNodes();

            CCurveTreeNode nullstakeRoot = nullstakeTree.GetRootNode();
            if (vtx[1].vShieldedSpend[0].fcmpProof.IsNull())
                return DoS(100, error("ConnectBlock() : NullStake V2 stake FCMP proof missing"));
            if (!VerifyFCMPProof(nullstakeRoot, vtx[1].vShieldedSpend[0].fcmpProof,
                                  vtx[1].vShieldedSpend[0].cv))
                return DoS(100, error("ConnectBlock() : NullStake V2 stake FCMP proof invalid"));

            uint64_t nCoinAge = 1;  // Minimum coin-day for V2
            int64_t nCalculatedStakeReward = ApplyBlockSizePenalty(GetProofOfStakeReward(nCoinAge, nFees), *this, pindex->pprev);
            if (nStakeReward > nCalculatedStakeReward)
                return DoS(100, error("ConnectBlock() : NullStake V2 coinstake pays too much(actual=%" PRId64" vs calculated=%" PRId64")", nStakeReward, nCalculatedStakeReward));
        }
        else if (vtx[1].nVersion == SHIELDED_TX_VERSION_NULLSTAKE_COLD)
        {
            if (pindex->nHeight < FORK_HEIGHT_NULLSTAKE_V3)
                return DoS(100, error("ConnectBlock() : NullStake V3 cold stake coinstake before fork height"));

            if (vtx[1].nullstakeProofV3.IsNull())
                return DoS(100, error("ConnectBlock() : NullStake V3 kernel proof missing"));

            if (vtx[1].vShieldedSpend.empty())
                return DoS(100, error("ConnectBlock() : NullStake V3 coinstake has no shielded spends"));

            // V3 proof size limit: 1024-constraint circuit → ~1,082 byte proof max
            if (vtx[1].nullstakeProofV3.acProof.GetProofSize() > 2048)
                return DoS(100, error("ConnectBlock() : NullStake V3 proof exceeds size limit (%u > 2048)",
                                       (unsigned int)vtx[1].nullstakeProofV3.acProof.GetProofSize()));

            if (vtx[1].nullstakeProofV3.nTimeTx != nTime)
                return DoS(100, error("ConnectBlock() : NullStake V3 nTimeTx %" PRId64 " != block time %" PRId64,
                                       (int64_t)vtx[1].nullstakeProofV3.nTimeTx, (int64_t)nTime));

            {
                uint256 zeroHash;
                memset(zeroHash.begin(), 0, 32);
                if (vtx[1].nullstakeProofV3.delegationHash == zeroHash)
                    return DoS(100, error("ConnectBlock() : NullStake V3 delegation hash is zero"));
            }

            if (vtx[1].nullstakeProofV3.vchPkStake.size() != 33)
                return DoS(100, error("ConnectBlock() : NullStake V3 pk_stake invalid size"));

            if (pindex->pprev)
            {
                if (vtx[1].nullstakeProofV3.nStakeModifier != pindex->pprev->nStakeModifier)
                    return DoS(100, error("ConnectBlock() : NullStake V3 stake modifier mismatch (proof=0x%016" PRIx64 " chain=0x%016" PRIx64 ")",
                                           vtx[1].nullstakeProofV3.nStakeModifier, pindex->pprev->nStakeModifier));
            }

            if (!VerifyNullStakeKernelProofV3(vtx[1].nullstakeProofV3,
                                              vtx[1].vShieldedSpend[0].cv,
                                              nBits))
                return DoS(100, error("ConnectBlock() : NullStake V3 kernel proof invalid"));

            CCurveTree nullstakeV3Tree;
            if (!txdb.ReadCurveTree(nullstakeV3Tree))
                return DoS(100, error("ConnectBlock() : failed to read curve tree for NullStake V3"));
            nullstakeV3Tree.RebuildParentNodes();

            CCurveTreeNode nullstakeV3Root = nullstakeV3Tree.GetRootNode();
            if (vtx[1].vShieldedSpend[0].fcmpProof.IsNull())
                return DoS(100, error("ConnectBlock() : NullStake V3 stake FCMP proof missing"));
            if (!VerifyFCMPProof(nullstakeV3Root, vtx[1].vShieldedSpend[0].fcmpProof,
                                  vtx[1].vShieldedSpend[0].cv))
                return DoS(100, error("ConnectBlock() : NullStake V3 stake FCMP proof invalid"));

            // V3 reward: same conservative approach as V2
            uint64_t nCoinAge = 1;
            int64_t nCalculatedStakeReward = ApplyBlockSizePenalty(GetProofOfStakeReward(nCoinAge, nFees), *this, pindex->pprev);
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

            CCurveTree nullstakeTree;
            if (!txdb.ReadCurveTree(nullstakeTree))
                return DoS(100, error("ConnectBlock() : failed to read curve tree for NullStake"));
            nullstakeTree.RebuildParentNodes();

            CCurveTreeNode nullstakeRoot = nullstakeTree.GetRootNode();
            if (vtx[1].vShieldedSpend[0].fcmpProof.IsNull())
                return DoS(100, error("ConnectBlock() : NullStake stake FCMP proof missing"));
            if (!VerifyFCMPProof(nullstakeRoot, vtx[1].vShieldedSpend[0].fcmpProof,
                                  vtx[1].vShieldedSpend[0].cv))
                return DoS(100, error("ConnectBlock() : NullStake stake FCMP proof invalid"));

            uint64_t nCoinAge = nWeight > 0 ? (uint64_t)nWeight : 1;
            int64_t nCalculatedStakeReward = ApplyBlockSizePenalty(GetProofOfStakeReward(nCoinAge, nFees), *this, pindex->pprev);
            if (nStakeReward > nCalculatedStakeReward)
                return DoS(100, error("ConnectBlock() : NullStake coinstake pays too much(actual=%" PRId64" vs calculated=%" PRId64")", nStakeReward, nCalculatedStakeReward));
        }
        else
        {
            uint64_t nCoinAge;
            if (!vtx[1].GetCoinAge(txdb, nCoinAge))
                return error("ConnectBlock() : %s unable to get coin age for coinstake", vtx[1].GetHash().ToString().substr(0,10).c_str());

            int64_t nCalculatedStakeReward = ApplyBlockSizePenalty(GetProofOfStakeReward(nCoinAge, nFees), *this, pindex->pprev);

            if (nStakeReward > nCalculatedStakeReward)
                return DoS(100, error("ConnectBlock() : coinstake pays too much(actual=%" PRId64" vs calculated=%" PRId64")", nStakeReward, nCalculatedStakeReward));
        }

        // Reject shielded coinstake unless NullStake version is allowed
        if (pindex->nHeight >= FORK_HEIGHT_SHIELDED)
        {
            if (vtx[1].IsShielded())
            {
                // PRIV-AUDIT-3: After V2 fork, reject V1 proofs (they leak UTXO identity)
                bool fNullStakeAllowed = (vtx[1].nVersion == SHIELDED_TX_VERSION_NULLSTAKE && pindex->nHeight >= FORK_HEIGHT_NULLSTAKE && pindex->nHeight < FORK_HEIGHT_NULLSTAKE_V2)
                    || (vtx[1].nVersion == SHIELDED_TX_VERSION_NULLSTAKE_V2 && pindex->nHeight >= FORK_HEIGHT_NULLSTAKE_V2)
                    || (vtx[1].nVersion == SHIELDED_TX_VERSION_NULLSTAKE_COLD && pindex->nHeight >= FORK_HEIGHT_NULLSTAKE_V3);
                if (!fNullStakeAllowed)
                    return DoS(100, error("ConnectBlock() : shielded transaction cannot be coinstake (Layer 2)"));
            }

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

                        // Verify CN payment goes to a legitimate collateralnode (post-fork only)
                        if (nCNPayment > 0 && pindex->nHeight >= FORK_HEIGHT_CN_PAYMENT_VALIDATION)
                        {
                            CScript expectedPayee;
                            bool fValidCNPayee = false;

                            if (collateralnodePayments.GetBlockPayee(pindex->nHeight, expectedPayee))
                            {
                                fValidCNPayee = (coinstake.vout[i].scriptPubKey == expectedPayee);
                            }

                            // Fallback: check against active collateralnodes
                            if (!fValidCNPayee && vecCollateralnodes.size() > 0)
                            {
                                LOCK(cs_collateralnodes);
                                for (CCollateralNode& mn : vecCollateralnodes)
                                {
                                    if (mn.IsEnabled())
                                    {
                                        CScript mnPayee;
                                        mnPayee.SetDestination(mn.pubkey.GetID());
                                        if (coinstake.vout[i].scriptPubKey == mnPayee)
                                        {
                                            fValidCNPayee = true;
                                            break;
                                        }
                                    }
                                }
                            }

                            if (!fValidCNPayee)
                                return DoS(100, error("ConnectBlock() : cold stake CN payment to invalid payee (not a registered collateralnode)"));
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

    bool CollateralnodePayments = false;
    bool fIsInitialDownload = IsInitialBlockDownload();

    if (fTestNet) {
        if (pindex->nHeight > BLOCK_START_COLLATERALNODE_PAYMENTS_TESTNET){
            CollateralnodePayments = true;
            if(fDebug) { printf("CheckBlock() : Collateralnode payments enabled\n"); }
        }else{
            CollateralnodePayments = false;
            if(fDebug) { printf("CheckBlock() : Collateralnode payments disabled\n"); }
        }
    } else {
        if (pindex->nHeight > BLOCK_START_COLLATERALNODE_PAYMENTS && pindex->nHeight > 2085000){
            CollateralnodePayments = true;
            if(fDebug) { printf("CheckBlock() : Collateralnode payments enabled\n"); }
        }else{
            CollateralnodePayments = false;
            if(fDebug) { printf("CheckBlock() : Collateralnode payments disabled\n"); }
        }
    }

    if(!fJustCheck && pindex->GetBlockTime() > GetTime() - 20*nCoinbaseMaturity && CollateralnodePayments == true)
    {
        LOCK2(cs_main, mempool.cs);

        CScript burnPayee;
        CBitcoinAddress burnDestination;
        burnDestination.SetString(fTestNet ? "8TestXXXXXXXXXXXXXXXXXXXXXXXXbCvpq" : "INNXXXXXXXXXXXXXXXXXXXXXXXXXZeeDTw");
        burnPayee = GetScriptForDestination(burnDestination.Get());

        int nCNEnforcementHeight = fTestNet ? MN_ENFORCEMENT_ACTIVE_HEIGHT_TESTNET : MN_ENFORCEMENT_ACTIVE_HEIGHT;

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
                    return error("CheckBlock-POS : %s unable to get coin age for coinstake, Can't Calculate Collateralnode Reward\n", vtx[1].GetHash().ToString().substr(0,10).c_str());
                int64_t nCalculatedStakeReward = ApplyBlockSizePenalty(GetProofOfStakeReward(nCoinAge, nFees), *this, pindex->pprev);

                // Calculate expected collateralnodePaymentAmmount
                int64_t collateralnodePaymentAmount = GetCollateralnodePayment(pindex->nHeight, nCalculatedStakeReward);

                // If we don't already have its previous block, skip collateralnode payment step
                if (pindex != NULL)
                {
                    bool foundPaymentAmount = false;
                    bool foundPayee = false;
                    bool paymentOK = false;

                    CScript payee;
                    if(fDebug) { printf("CheckBlock-POS() : Using collateralnode payments for block %ld\n", pindex->nHeight); }

                    // Check transaction for payee and if contains collateralnode reward payment
                    if(fDebug) { printf("CheckBlock-POS(): Transaction 1 Size : %i\n", vtx[1].vout.size()); }
                    if(fDebug) { printf("CheckBlock-POS() : Expected Collateralnode reward of: %ld\n", collateralnodePaymentAmount); }
                    for (unsigned int i = 0; i < vtx[1].vout.size(); i++) {
                        if(fDebug) { printf("CheckBlock-POS() : Payment vout number: %i , Amount: %ld\n",i, vtx[1].vout[i].nValue); }
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
                            return error("CheckBlock-POS() : Did not find this payee in the collateralnode list. Requesting list update and rejecting block.");
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
                        if(fDebug) { printf("CheckBlock-POS() : Couldn't find collateralnode payment(%d|%ld) or payee(%d|%s) nHeight %d. \n", foundPaymentAmount, collateralnodePaymentAmount, foundPayee, address2.ToString().c_str(), pindex->nHeight+1); }
                        return DoS(100, error("CheckBlock-POS() : Couldn't find collateralnode payment or payee"));
                    } else {
                        if(fDebug) { printf("CheckBlock-POS() : Found collateralnode payment %d\n", pindex->nHeight+1); }
                    }
                } else {
                    if(fDebug) { printf("CheckBlock-POS() : Is initial download, skipping collateralnode payment check %ld\n", pindexBest->nHeight+1); }
                }
            } else {
                if(fDebug) { printf("CheckBlock-POS() : Skipping collateralnode payment check - nHeight %ld Hash %s\n", pindex->nHeight, GetHash().ToString().c_str()); }
            }
        }else if(IsProofOfWork() && pindexBest != NULL){
            if(pindexBest->GetBlockHash() == hashPrevBlock){

                // make sure the ranks are updated
                GetCollateralnodeRanks(pindexBest);

                int64_t collateralnodePaymentAmount = GetCollateralnodePayment(pindex->nHeight, vtx[0].GetValueOut());

                // If we don't already have its previous block, skip collateralnode payment step
                if (pindex != NULL)
                {
                    bool foundPaymentAmount = false;
                    bool foundPayee = false;
                    bool paymentOK = true;
                    CScript payee;

                    if(fDebug) { printf("CheckBlock-POW() : Using non-specific collateralnode payments %ld\n", pindex->nHeight); }

                    // Check transaction for payee and if contains collateralnode reward payment
                    if (fDebug) { printf("CheckBlock-POW(): Transaction 0 Size : %i\n", vtx[0].vout.size()); }
                    if (fDebug) { printf("CheckBlock-POW() : Expected Collateralnode reward of: %ld\n", collateralnodePaymentAmount); }
                    for (unsigned int i = 0; i < vtx[0].vout.size(); i++) {
                        if(fDebug) { printf("CheckBlock-POW() : Payment vout number: %i , Amount: %lld\n",i, vtx[0].vout[i].nValue); }
                        if(vtx[0].vout[i].nValue == collateralnodePaymentAmount )
                        {
                            CTxDestination mnDest;
                            payee = vtx[0].vout[i].scriptPubKey;
                            ExtractDestination(payee, mnDest);
                            CBitcoinAddress mnAddress(mnDest);
                            if (fDebug) printf("CheckBlock-POW() : Found collateralnode payment: %s INN to %s.\n",FormatMoney(vtx[0].vout[i].nValue).c_str(), mnAddress.ToString().c_str());

                            foundPaymentAmount = true;

                            CScript pubScript;

                            for (CCollateralNode& mn : vecCollateralnodes)
                            {
                                pubScript = GetScriptForDestination(mn.pubkey.GetID());
                                CTxDestination address1;
                                ExtractDestination(pubScript, address1);
                                CBitcoinAddress address2(address1);

                                if (payee == pubScript)
                                {
                                    if (fDebug) printf("CheckBlock-POW() : Collateralnode PoW payee found at block %d: %s who got paid %s INN rate:%" PRId64" rank:%d lastpaid:%d\n", pindex->nHeight, address2.ToString().c_str(), FormatMoney(vtx[0].vout[i].nValue).c_str(), FormatMoney(mn.payRate).c_str(), mn.nRank, mn.nBlockLastPaid);
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
                                } else if (payee == burnPayee) {
                                    printf("CheckBlock-POW() : Found collateralnode payment: %s INN to burn address.\n", FormatMoney(vtx[0].vout[i].nValue).c_str());
                                    foundPayee = true;
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
                                return error("CheckBlock-POW() : Did not find this payee in the collateralnode list, rejecting block.");
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
                        if(fDebug) { printf("CheckBlock-POW() : Couldn't find collateralnode payment(%d|%ld) or payee(%d|%s) nHeight %d. \n", foundPaymentAmount, collateralnodePaymentAmount, foundPayee, address2.ToString().c_str(), pindex->nHeight+1); }
                        return DoS(100, error("CheckBlock-POW() : Couldn't find collateralnode payment or payee"));
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

    if (pindex->nHeight >= FORK_HEIGHT_SHIELDED && !fJustCheck)
    {
        CIncrementalMerkleTree shieldedTree;
        if (pindex->pprev)
            txdb.ReadShieldedTree(shieldedTree); // OK if not found (empty tree)

        txdb.WriteShieldedTreeAtBlock(pindex->GetBlockHash(), shieldedTree);

        CCurveTree curveTree;
        if (pindex->nHeight >= FORK_HEIGHT_FCMP && pindex->pprev)
            txdb.ReadCurveTree(curveTree); // OK if not found (empty)

        if (pindex->nHeight >= FORK_HEIGHT_FCMP)
            txdb.WriteCurveTreeAtBlock(pindex->GetBlockHash(), curveTree);

        // Seed genesis commitments at the fork activation block
        // These provide the initial Lelantus anonymity set (16 unspendable decoys)
        if (pindex->nHeight == FORK_HEIGHT_SHIELDED)
        {
            CCurveTree* pCurveTreePtr = (pindex->nHeight >= FORK_HEIGHT_FCMP) ? &curveTree : nullptr;
            if (!SeedGenesisCommitments(txdb, shieldedTree, pCurveTreePtr))
                return error("ConnectBlock() : SeedGenesisCommitments failed");
        }

        int64_t nShieldedPool = 0;
        txdb.ReadShieldedPoolValue(nShieldedPool); // OK if not found (zero)

        // Catch cross-tx nullifier duplicates within this block
        std::set<uint256> setBlockNullifiers;

        for (const CTransaction& tx : vtx)
        {
            if (!tx.IsShielded())
                continue;

            for (unsigned int i = 0; i < tx.vShieldedSpend.size(); i++)
            {
                if (!setBlockNullifiers.insert(tx.vShieldedSpend[i].nullifier).second)
                    return error("ConnectBlock() : duplicate nullifier %s across transactions in block",
                                 tx.vShieldedSpend[i].nullifier.ToString().substr(0,10).c_str());

                CShieldedNullifierSpent nfs;
                nfs.txnHash = tx.GetHash();
                nfs.nIndex = i;
                if (!txdb.WriteShieldedNullifier(tx.vShieldedSpend[i].nullifier, nfs))
                    return error("ConnectBlock() : WriteShieldedNullifier failed");
            }

            // Append note commitments to the Merkle tree and commitment index
            for (const CShieldedOutputDescription& output : tx.vShieldedOutput)
            {
                shieldedTree.Append(output.cmu);

                // Index Pedersen commitment for Lelantus anonymity set construction
                uint64_t nCommitIdx = shieldedTree.Size() - 1;
                if (!txdb.WriteShieldedCommitment(nCommitIdx, output.cv))
                    return error("ConnectBlock() : WriteShieldedCommitment failed");

                if (!txdb.WriteShieldedCommitmentHeight(nCommitIdx, pindex->nHeight))
                    return error("ConnectBlock() : WriteShieldedCommitmentHeight failed");
                // Reverse index for spend validation
                if (!txdb.WriteShieldedCommitmentIndex(output.cv.vchCommitment, nCommitIdx))
                    return error("ConnectBlock() : WriteShieldedCommitmentIndex failed");

                if (pindex->nHeight >= FORK_HEIGHT_FCMP)
                    curveTree.InsertLeaf(output.cv);
            }

            nShieldedPool -= tx.nValueBalance;

            if (nShieldedPool < 0)
                return error("ConnectBlock() : shielded pool would go negative (%" PRId64 "), inflation detected", nShieldedPool);
        }

        if (!txdb.WriteShieldedTree(shieldedTree))
            return error("ConnectBlock() : WriteShieldedTree failed");
        if (!txdb.WriteShieldedCommitmentCount(shieldedTree.Size()))
            return error("ConnectBlock() : WriteShieldedCommitmentCount failed");

        if (pindex->nHeight >= FORK_HEIGHT_FCMP)
        {
            if (!txdb.WriteCurveTree(curveTree))
                return error("ConnectBlock() : WriteCurveTree failed");
        }

        uint256 treeRoot = shieldedTree.Root();
        if (!txdb.WriteShieldedAnchor(treeRoot))
            return error("ConnectBlock() : WriteShieldedAnchor failed");
        // Only write anchor height for NEW anchors (don't reset age each block)
        {
            int nExistingHeight = 0;
            if (!txdb.ReadShieldedAnchorHeight(treeRoot, nExistingHeight))
            {
                if (!txdb.WriteShieldedAnchorHeight(treeRoot, pindex->nHeight))
                    return error("ConnectBlock() : WriteShieldedAnchorHeight failed");
            }
        }

        if (!txdb.WriteShieldedPoolValue(nShieldedPool))
            return error("ConnectBlock() : WriteShieldedPoolValue failed");

        nShieldedPoolValue = nShieldedPool;

        if (fDebug)
            printf("ConnectBlock() : shielded tree root=%s, pool=%" PRId64 "\n",
                   treeRoot.ToString().substr(0,10).c_str(), nShieldedPool);
    }

    // ppcoin: track money supply and mint amount info
    pindex->nMint = nValueOut - nValueIn + nFees;
    pindex->nMoneySupply = (pindex->pprev? pindex->pprev->nMoneySupply : 0) + nValueOut - nValueIn;
    pindex->nMoneySupply -= nAmountBurned;
    if (pindex->nMoneySupply < 0)
        return error("ConnectBlock() : negative money supply at height %d", pindex->nHeight);

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
        return error("Connect() : WriteBlockIndex for pindex failed");

    if (fJustCheck)
        return true;

    // Write queued txindex changes
    for (map<uint256, CTxIndex>::iterator mi = mapQueuedChanges.begin(); mi != mapQueuedChanges.end(); ++mi)
    {
        if (!txdb.UpdateTxIndex((*mi).first, (*mi).second))
            return error("ConnectBlock() : UpdateTxIndex failed");
    }
    if(GetBoolArg("-addrindex", false))
    {
        // Write Address Index
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
                    return false;

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
                            printf("ConnectBlock(): txins WriteAddrIndex failed addrId: %s txhash: %s\n", addrId.ToString().c_str(), hashTx.ToString().c_str());
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
                    printf("ConnectBlock(): txouts WriteAddrIndex failed addrId: %s txhash: %s\n", addrId.ToString().c_str(), hashTx.ToString().c_str());
                    }
            }
        }
        }
    }

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev)
    {
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = pindex->GetBlockHash();
        if (!txdb.WriteBlockIndex(blockindexPrev))
            return error("ConnectBlock() : WriteBlockIndex failed");
    }

    // Check Name Release Height to Connect Blocks
    if (pindex->nHeight >= RELEASE_HEIGHT) {
        // add names to innovanamesindex.dat
        hooks->ConnectBlock(txdb, pindex);
    }

    // Watch for transactions paying to me
    for (CTransaction& tx : vtx)
        SyncWithWallets(tx, this, true);

    // update the UI about the new block
    uiInterface.NotifyRanksUpdated();

    return true;
}

bool static Reorganize(CTxDB& txdb, CBlockIndex* pindexNew)
{
    printf("REORGANIZE\n");

    {
        int nFinalHeight = g_finalityTracker.GetFinalizedHeight();
        if (nFinalHeight > 0 && pindexBest && pindexBest->nHeight >= FORK_HEIGHT_FINALITY)
        {
            CBlockIndex* pCheck = pindexBest;
            CBlockIndex* pLonger = pindexNew;
            while (pCheck != pLonger)
            {
                while (pLonger && pLonger->nHeight > pCheck->nHeight)
                    pLonger = pLonger->pprev;
                if (pCheck == pLonger)
                    break;
                if (pCheck)
                    pCheck = pCheck->pprev;
            }
            if (pCheck && pCheck->nHeight < nFinalHeight)
            {
                return error("Reorganize() : rejected — fork point height %d is below finalized height %d",
                             pCheck->nHeight, nFinalHeight);
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



    // Disconnect shorter branch
    list<CTransaction> vResurrect;
    for (CBlockIndex* pindex : vDisconnect)
    {
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return error("Reorganize() : ReadFromDisk for disconnect failed");
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

        if (!block.ConnectBlock(txdb, pindex))
        {
            // Invalid block
            return error("Reorganize() : ConnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());
        }

        // Queue memory transactions to delete
        for (const CTransaction& tx : block.vtx)
            vDelete.push_back(tx);
    }
    if (!txdb.WriteHashBestChain(pindexNew->GetBlockHash()))
        return error("Reorganize() : WriteHashBestChain failed");

    // Make sure it's successfully written to disk before changing memory structure
    if (!txdb.TxnCommit())
        return error("Reorganize() : TxnCommit failed");

    // Clear setStakeSeen so disconnected stakes don't block the new branch
    for (CBlockIndex* pindex : vDisconnect)
    {
        if (pindex->IsProofOfStake())
            setStakeSeen.erase(make_pair(pindex->prevoutStake, pindex->nStakeTime));
    }

    // IDAG: Clean up DAG data for disconnected blocks
    // Phase 1: Batch all LevelDB erasures atomically
    {
        CTxDB txdbDAGClean;
        txdbDAGClean.TxnBegin();
        for (auto rit = vDisconnect.rbegin(); rit != vDisconnect.rend(); ++rit)
        {
            CBlockIndex* pindex = *rit;
            if (pindex->nHeight >= FORK_HEIGHT_DAG && pindex->phashBlock)
                txdbDAGClean.EraseDAGLinks(pindex->GetBlockHash());
        }
        txdbDAGClean.TxnCommit();
    }
    // Phase 2: Memory cleanup after LevelDB commit (reverse order: children first)
    bool fDAGReorg = false;
    for (auto rit = vDisconnect.rbegin(); rit != vDisconnect.rend(); ++rit)
    {
        CBlockIndex* pindex = *rit;
        if (pindex->nHeight >= FORK_HEIGHT_DAG && pindex->phashBlock)
        {
            g_dagManager.RemoveBlockDAGData(pindex->GetBlockHash());
            fDAGReorg = true;
        }
    }
    // Re-color DAG blocks above fork point to ensure consistency with fresh-synced nodes
    if (fDAGReorg && pfork)
        g_dagManager.RebuildDAGOrderIncremental(pfork->nHeight);

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
bool CBlock::SetBestChainInner(CTxDB& txdb, CBlockIndex *pindexNew)
{
    uint256 hash = GetHash();

    // Adding to current best branch
    if (!ConnectBlock(txdb, pindexNew) || !txdb.WriteHashBestChain(hash))
    {
        txdb.TxnAbort();
        InvalidChainFound(pindexNew);
        return false;
    }
    if (!txdb.TxnCommit())
        return error("SetBestChain() : TxnCommit failed");

    if (pindexNew->pprev)
        pindexNew->pprev->pnext = pindexNew;

    // Delete redundant memory transactions
    for (CTransaction& tx : vtx)
        mempool.remove(tx);

    // IDAG Phase 3: Remove txs from DAG sibling blocks
    if (pindexNew->nHeight >= FORK_HEIGHT_DAG)
    {
        std::set<uint256> siblings = g_dagManager.GetDAGSiblingBlocks(hash);
        for (const uint256& hashSibling : siblings)
            mempool.RemoveDAGConflicts(hashSibling);
    }

    return true;
}

bool CBlock::SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew)
{
    uint256 hash = GetHash();
    if (!txdb.TxnBegin())
        return error("SetBestChain() : TxnBegin failed");

    if (pindexGenesisBlock == NULL && hash == GetGenesisBlockHash())
    {
        txdb.WriteHashBestChain(hash);
        if (!txdb.TxnCommit())
            return error("SetBestChain() : TxnCommit failed");
        pindexGenesisBlock = pindexNew;
    }
    else if (hashPrevBlock == hashBestChain)
    {
        if (!SetBestChainInner(txdb, pindexNew))
            return error("SetBestChain() : SetBestChainInner failed");
    }
    else
    {
        {
            int nFinalHeight = g_finalityTracker.GetFinalizedHeight();
            if (nFinalHeight > 0 && pindexBest && pindexBest->nHeight >= FORK_HEIGHT_FINALITY)
            {
                CBlockIndex* pWalk = pindexNew;
                while (pWalk && pWalk->nHeight > nBestHeight)
                    pWalk = pWalk->pprev;
                CBlockIndex* pOld = pindexBest;
                while (pOld && pWalk && pOld != pWalk)
                {
                    if (pOld->nHeight > pWalk->nHeight)
                        pOld = pOld->pprev;
                    else if (pWalk->nHeight > pOld->nHeight)
                        pWalk = pWalk->pprev;
                    else
                    {
                        pOld = pOld->pprev;
                        pWalk = pWalk->pprev;
                    }
                }
                if (pOld && pOld->nHeight < nFinalHeight)
                {
                    txdb.TxnAbort();
                    return error("SetBestChain() : rejected reorg — fork below finalized height %d", nFinalHeight);
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
        if (!Reorganize(txdb, pindexIntermediate))
        {
            txdb.TxnAbort();
            InvalidChainFound(pindexNew);
            return error("SetBestChain() : Reorganize failed");
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
            if (!block.SetBestChainInner(txdb, pindex))
                break;
        }


    }

    // Update best block in wallet (so we can detect restored wallets)
    bool fIsInitialDownload = IsInitialBlockDownload();
    if (!fIsInitialDownload)
    {
        const CBlockLocator locator(pindexNew);
        ::SetBestChain(locator);
    }

    // New best block
    hashBestChain = hash;
    pindexBest = pindexNew;
    pblockindexFBBHLast = NULL;
    nBestHeight = pindexBest->nHeight;
    nBestChainTrust = pindexNew->nChainTrust;
    nTimeBestReceived = GetTime();
    mempool.AddTransactionsUpdated(1);

    uint256 nBestBlockTrust = (pindexBest->nHeight != 0 && pindexBest->pprev != NULL) ? (pindexBest->nChainTrust - pindexBest->pprev->nChainTrust) : pindexBest->nChainTrust;

    printf("SetBestChain: new best=%s  height=%d  trust=%s  blocktrust=%" PRId64"  date=%s\n",
      hashBestChain.ToString().substr(0,20).c_str(), nBestHeight,
      CBigNum(nBestChainTrust).ToString().c_str(),
      nBestBlockTrust.Get64(),
      DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());

    {
        LOCK(cs_vNodes);
        for (CNode* pnode : vNodes)
        {
            if (pnode->nVersion != 0)
                pnode->PushInventory(CInv(MSG_BLOCK, hashBestChain));
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

bool CBlock::AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos, const uint256& hashProof)
{
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

    // Write to disk block index
    CTxDB txdb;
    if (!txdb.TxnBegin())
        return false;
    txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));
    if (!txdb.TxnCommit())
        return false;

    // IDAG Phase 2: Initialize DAG data for post-fork blocks
    if (pindexNew->nHeight >= FORK_HEIGHT_DAG)
    {
        // Extract DAG parents from coinbase OP_RETURN
        std::vector<uint256> vDAGParents;
        for (unsigned int i = 0; i < vtx[0].vout.size(); i++)
        {
            vDAGParents = ExtractDAGParents(vtx[0].vout[i].scriptPubKey);
            if (!vDAGParents.empty())
                break;
        }

        if (!vDAGParents.empty())
        {
            g_dagManager.InitBlockDAGData(pindexNew, vDAGParents);

            // IDAG Phase 4: Fork-gate between GHOSTDAG and DAGKNIGHT coloring
            if (pindexNew->nHeight >= FORK_HEIGHT_DAGKNIGHT)
                g_dagManager.ColorBlockDAGKnight(pindexNew);
            else
                g_dagManager.ColorBlock(pindexNew);

            CTxDB txdbDAG;
            if (txdbDAG.TxnBegin())
            {
                g_dagManager.WriteDAGLinks(txdbDAG, hash);
                // Also update parent entries (new child link)
                for (const uint256& hashParent : vDAGParents)
                    g_dagManager.WriteDAGLinks(txdbDAG, hashParent);
                txdbDAG.TxnCommit();
            }

            // Use DAG score for best-chain comparison
            uint256 nDAGScore = g_dagManager.ComputeDAGScore(pindexNew);
            pindexNew->nChainTrust = nDAGScore;

            // IDAG Phase 3: Remove DAG sibling txs from mempool
            std::set<uint256> siblings = g_dagManager.GetDAGSiblingBlocks(hash);
            for (const uint256& hashSibling : siblings)
                mempool.RemoveDAGConflicts(hashSibling);

            // IDAG Phase 3: Epoch state computation + pruning at epoch boundaries
            int nEpochInterval = GetEpochInterval(pindexNew->nHeight);
            if (pindexNew->nHeight % nEpochInterval == 0 && pindexNew->nHeight > 0)
            {
                int nCompletedEpoch = (pindexNew->nHeight / nEpochInterval) - 1;
                if (nCompletedEpoch >= 0)
                {
                    g_dagManager.ComputeEpochState(nCompletedEpoch, nEpochInterval);

                    CTxDB txdbEpoch;
                    if (txdbEpoch.TxnBegin())
                    {
                        g_dagManager.WriteEpochState(txdbEpoch, nCompletedEpoch);
                        txdbEpoch.TxnCommit();
                    }
                }

                // Prune old DAG data periodically
                CTxDB txdbPrune;
                g_dagManager.PruneDAGData(txdbPrune, pindexNew->nHeight);
            }
        }
    }

    LOCK(cs_main);

    // New best
    if (pindexNew->nChainTrust > nBestChainTrust)
        if (!SetBestChain(txdb, pindexNew))
            return false;

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
    return true;
}




bool CBlock::CheckBlock(bool fCheckPOW, bool fCheckMerkleRoot, bool fCheckSig) const
{
    // These are checks that are independent of context
    // that can be verified before saving an orphan block.

    // Size limits (ceiling as sanity check; height-aware limit enforced in AcceptBlock)
    if (vtx.empty() || vtx.size() > ADAPTIVE_BLOCK_CEILING || ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > ADAPTIVE_BLOCK_CEILING)
        return DoS(100, error("CheckBlock() : size limits failed"));

    // Check proof of work matches claimed amount
    if (fCheckPOW && IsProofOfWork() && !CheckProofOfWork(GetPoWHash(), nBits))
        return DoS(50, error("CheckBlock() : proof of work failed"));

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
            if (vtx[i].IsCoinStake())
                return DoS(100, error("CheckBlock() : more than one coinstake"));

		// Check coinstake timestamp
		if (!CheckCoinStakeTimestamp(GetBlockTime(), (int64_t)vtx[1].nTime))
			return DoS(50, error("CheckBlock() : coinstake timestamp violation nTimeBlock=%" PRId64" nTimeTx=%u", GetBlockTime(), vtx[1].nTime));

		// Check proof-of-stake block signature
		if (fCheckSig && !CheckBlockSignature())
            return DoS(100, error("CheckBlock() : bad proof-of-stake block signature"));
	}

    // Check transactions
    for (const CTransaction& tx : vtx)
    {
        if (!tx.CheckTransaction())
            return DoS(tx.nDoS, error("CheckBlock() : CheckTransaction failed"));

        // ppcoin: check transaction timestamp
        if (GetBlockTime() < (int64_t)tx.nTime)
            return DoS(50, error("CheckBlock() : block timestamp earlier than transaction timestamp"));
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
    if (fCheckMerkleRoot && hashMerkleRoot != BuildMerkleTree())
        return DoS(100, error("CheckBlock() : hashMerkleRoot mismatch"));


    return true;
}

bool CBlock::AcceptBlock()
{
    AssertLockHeld(cs_main);

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
    int nHeight = pindexPrev->nHeight+1;

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
    if (nBits != GetNextTargetRequired(pindexPrev, IsProofOfStake()))
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
		if (!CheckProofOfStake(vtx[1], nBits, hashProof, targetProofOfStake))
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

    // Reject ring signature transactions after deprecation height
    if (nHeight >= FORK_HEIGHT_RINGSIG_DEPRECATION)
    {
        for (unsigned int i = 0; i < vtx.size(); i++)
        {
            if (vtx[i].nVersion == ANON_TXN_VERSION)
                return DoS(100, error("AcceptBlock() : ring signature transaction (ANON_TXN_VERSION) in block at height %d after deprecation height %d",
                                       nHeight, FORK_HEIGHT_RINGSIG_DEPRECATION));
        }
    }

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
        return DoS(100, error("AcceptBlock() : block height mismatch in coinbase"));

    // IDAG Phase 2: Validate DAG parent commitment in coinbase OP_RETURN
    if (nHeight >= FORK_HEIGHT_DAG)
    {
        // Search coinbase outputs for DAG parent commitment
        std::vector<uint256> vDAGParents;
        for (unsigned int i = 0; i < vtx[0].vout.size(); i++)
        {
            vDAGParents = ExtractDAGParents(vtx[0].vout[i].scriptPubKey);
            if (!vDAGParents.empty())
                break;
        }

        if (vDAGParents.empty())
            return DoS(100, error("AcceptBlock() : post-DAG-fork block missing DAG parent commitment"));

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
            if (!mapBlockIndex.count(vDAGParents[i]))
                return DoS(10, error("AcceptBlock() : DAG merge parent[%d] %s not found",
                                      i, vDAGParents[i].ToString().substr(0, 20).c_str()));

            // Merge parent must have lower height
            CBlockIndex* pMergeParent = mapBlockIndex[vDAGParents[i]];
            if (pMergeParent->nHeight >= nHeight)
                return DoS(100, error("AcceptBlock() : DAG merge parent[%d] height %d >= block height %d",
                                       i, pMergeParent->nHeight, nHeight));

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
    }

    // Write block to history file
    if (!CheckDiskSpace(::GetSerializeSize(*this, SER_DISK, CLIENT_VERSION)))
        return error("AcceptBlock() : out of disk space");
    unsigned int nFile = -1;
    unsigned int nBlockPos = 0;
    if (!WriteToDisk(nFile, nBlockPos))
        return error("AcceptBlock() : WriteToDisk failed");
    if (!AddToBlockIndex(nFile, nBlockPos, hashProof))
        return error("AcceptBlock() : AddToBlockIndex failed");

    // Relay inventory, but don't relay old inventory during initial block download
    int nBlockEstimate = Checkpoints::GetTotalBlocksEstimate();
    if (hashBestChain == hash)
    {
        LOCK(cs_vNodes);
        for (CNode* pnode : vNodes)
            if (nBestHeight > (pnode->nChainHeight != -1 ? pnode->nChainHeight - 2000 : nBlockEstimate))
                pnode->PushInventory(CInv(MSG_BLOCK, hash));
    }

    // ppcoin: check pending sync-checkpoint
    Checkpoints::AcceptPendingSyncCheckpoint();

    return true;
}

uint256 CBlockIndex::GetBlockTrust() const
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    if (bnTarget <= 0)
        return 0;

    if (nHeight >= FORK_HEIGHT_POEM)
        return GetBlockEntropy(IsProofOfStake() ? hashProof : *phashBlock);

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


    // Preliminary checks
    if (!pblock->CheckBlock())
        return error("ProcessBlock() : CheckBlock FAILED");

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
            if (pfrom)
                pfrom->Misbehaving(100);
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

    // IDAG Phase 2: Request missing merge parents without orphaning the block
    if (pindexBest && pindexBest->nHeight + 1 >= FORK_HEIGHT_DAG && mapBlockIndex.count(pblock->hashPrevBlock))
    {
        // Primary parent exists — check merge parents in coinbase OP_RETURN
        for (unsigned int i = 0; i < pblock->vtx[0].vout.size(); i++)
        {
            std::vector<uint256> vDAGParents = ExtractDAGParents(pblock->vtx[0].vout[i].scriptPubKey);
            if (!vDAGParents.empty())
            {
                for (unsigned int j = 1; j < vDAGParents.size(); j++)
                {
                    if (!mapBlockIndex.count(vDAGParents[j]) && pfrom)
                    {
                        pfrom->AskFor(CInv(MSG_BLOCK, vDAGParents[j]));
                        if (fDebug)
                            printf("ProcessBlock: requesting missing DAG merge parent %s\n",
                                   vDAGParents[j].ToString().substr(0, 20).c_str());
                    }
                }
                break;
            }
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
                    return error("ProcessBlock() : peer %d exceeded orphan limit (IBD, no penalty)", pfrom->GetId());
                }
                pfrom->Misbehaving(1);
                return error("ProcessBlock() : peer %d exceeded orphan limit", pfrom->GetId());
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
            if (!IsInitialBlockDownload())
                pfrom->AskFor(CInv(MSG_BLOCK, WantedByOrphan(pblock2)));
        }
        return true;
    }

    // Store to disk
    if (!pblock->AcceptBlock())
        return error("ProcessBlock() : AcceptBlock FAILED");

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
            if (pblockOrphan->AcceptBlock())
                vWorkQueue.push_back(orphanHash);
            mapOrphanBlocks.erase(orphanHash);
            setStakeSeenOrphan.erase(pblockOrphan->GetProofOfStake());

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
        printf("ProcessBlock: ACCEPTED (%" PRId64"ms)\n", GetTimeMillis() - nStartTime);
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

    if (fDebug && GetBoolArg("-printcoinstake")) printf ("searchtime %ld to %ld \n",nSearchTime,nLastCoinStakeSearchTime);
    if (nSearchTime > nLastCoinStakeSearchTime)
    {
        if (fDebug && GetBoolArg("-printcoinstake")) printf ("nSearchTime %ld > nLastCoinStakeSearchTime %ld\n",nSearchTime,nLastCoinStakeSearchTime);
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
                hashMerkleRoot = BuildMerkleTree();

                // append a signature to our block
                return key.Sign(GetHash(), vchBlockSig);
            }
        }
        nLastCoinStakeSearchInterval = nSearchTime - nLastCoinStakeSearchTime;
        nLastCoinStakeSearchTime = nSearchTime;
        if (fDebug && GetBoolArg("-printcoinstake")) printf ("CreateCoinStake failed at %ld. Try again in %ld\n",nLastCoinStakeSearchTime,nLastCoinStakeSearchInterval);
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

    // NullStake V3 (Private Cold Staking): verify block signature against pk_stake
    if (vtx[1].nVersion == SHIELDED_TX_VERSION_NULLSTAKE_COLD)
    {
        if (vchBlockSig.empty())
            return false;

        if (vtx[1].nullstakeProofV3.vchPkStake.size() != 33)
            return false;

        CPubKey pkStake(vtx[1].nullstakeProofV3.vchPkStake);
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
        pchMessageStart[0] = 0x27;
        pchMessageStart[1] = 0x43;
        pchMessageStart[2] = 0x35;
        pchMessageStart[3] = 0x4b;

        bnProofOfWorkLimit = bnProofOfWorkLimitTestNet; // 16 bits PoW target limit for testnet
        nStakeMinAge = 1 * 60 * 60; // test net min age is 1 hours like mainnet
        nCoinbaseMaturity = 65; // test maturity is 65 blocks
    };

    //
    // Load block index
    //
    CTxDB txdb("cr+");
    if (!txdb.LoadBlockIndex())
        return false;
    if (!pwalletMain->CacheAnonStats())
        printf("CacheAnonStats() failed.\n");

    //
    // Init with genesis block
    //
    if (mapBlockIndex.empty())
    {
        if (!fAllowNew)
            return false;

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
            const char* pszTimestampTestNet = "Innova Testnet V2 Relaunch | March 2026 | CircuitBreaker";
            CTransaction txNewTestNet;

            txNewTestNet.nTime = 1774163076;
            txNewTestNet.vin.resize(1);
            txNewTestNet.vout.resize(1);
            txNewTestNet.vin[0].scriptSig = CScript() << 0 << CBigNum(42) << vector<unsigned char>((const unsigned char*)pszTimestampTestNet, (const unsigned char*)pszTimestampTestNet + strlen(pszTimestampTestNet));
            txNewTestNet.vout[0].SetEmpty();

            CBlock blocktest;
            blocktest.vtx.push_back(txNewTestNet);
            blocktest.hashPrevBlock = 0;
            blocktest.hashMerkleRoot = blocktest.BuildMerkleTree();
            blocktest.nTime    = 1774163076;
            blocktest.nVersion = 1;
            blocktest.nBits    = bnProofOfWorkLimit.GetCompact();
            blocktest.nNonce   = 161933;

            if (false && (blocktest.GetHash() != hashGenesisBlockTestNet)) {
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
            assert(blocktest.hashMerkleRoot == uint256("0x33c0940923bea3aed04ed77da7499b06ceda2c9e1f9b1ebde56ef8b2aec05fb4"));
            blocktest.print();
            assert(blocktest.GetHash() == hashGenesisBlockTestNet);
            assert(blocktest.CheckBlock());

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

bool LoadExternalBlockFile(FILE* fileIn)
{
    int64_t nStart = GetTimeMillis();

    int nLoaded = 0;
    {
        LOCK(cs_main);
        try {
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
                fseek(blkdat, nPos, SEEK_SET);
                unsigned int nSize;
                blkdat >> nSize;
                if (nSize > 0 && nSize <= MAX_BLOCK_SIZE)
                {
                    CBlock block;
                    blkdat >> block;
                    if (ProcessBlock(NULL,&block))
                    {
                        nLoaded++;
                        nPos += 4 + nSize;
                    }
                }
            }
        }
        catch (std::exception &e) {
            printf("%s() : Deserialize or I/O error caught during load: %s\n",
                   __PRETTY_FUNCTION__, e.what());
        }
    }
    printf("Loaded %i blocks from external file in %" PRId64"ms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
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
                    pfrom->fDisconnect = true;
                    send = false;
                }
            }
            else if (inv.IsKnownType())
            {
                // Send stream from relay memory
                bool pushed = false;
                /*{
                    LOCK(cs_mapRelay);
                    map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
                    if (mi != mapRelay.end()) {
                        pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                        pushed = true;
                    }
                }*/
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
                }
            }

            // Track requests for our stuff.
            g_signals.Inventory(inv.hash);

            if (inv.type == MSG_BLOCK /* || inv.type == MSG_FILTERED_BLOCK */)
                break;
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
            pfrom->Misbehaving(1);
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
            pfrom->fDisconnect = true;
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
            vRecv >> pfrom->nChainHeight;

        // Disconnect if the peer's subversion is < /Innovai:3.3.9.14/
        // Leaving this out for now until new update is out for a bit
        // if (pfrom->strSubVer != "/Innovai:3.3.9.14/")
        //     oldVersion = true;

        // print the current pfrom->strSubVer
        printf("ProcessMessage(): peer=%s using SubVer=%s, oldVersion=%s\n", pfrom->addr.ToString().c_str(), pfrom->strSubVer.c_str(), oldVersion ? "true" : "false");

        if (oldVersion == true)
        {
          printf("Partner %s using obsolete version %i; DISCONNECTING\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
          pfrom->fDisconnect = true;
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
            pfrom->fDisconnect = true;
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

        // Ask the first connected node for block updates
        static int nAskedForBlocks = 0;
        if (!pfrom->fClient && !pfrom->fOneShot &&
            (pfrom->nChainHeight > (nBestHeight - 144)) &&
            (pfrom->nVersion < NOBLKS_VERSION_START ||
             pfrom->nVersion >= NOBLKS_VERSION_END) &&
             (nAskedForBlocks < 1 || vNodes.size() <= 1))
        {
            nAskedForBlocks++;
            pfrom->PushGetBlocks(pindexBest, uint256(0));
			//PushGetBlocks(pfrom, pindexBest, uint256(0));
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

        cPeerBlockCounts.input(pfrom->nChainHeight);

        // ppcoin: ask for pending sync-checkpoint if any
        if (!IsInitialBlockDownload())
            Checkpoints::AskForPendingSyncCheckpoint(pfrom);
    }


    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else, as it is sent as soon as the socket opens
        pfrom->Misbehaving(1);
        if (fDebug) printf("net: received an out-of-sequence %s from peer at %s\n", strCommand.c_str(), pfrom->addr.ToString().c_str());
        if (pfrom->nMisbehavior > 10 || pfrom->nTimeConnected < GetTime() - 10)
            pfrom->fDisconnect = true; // Disconnect them so we can reconnect and try for another version message
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
            pfrom->Misbehaving(20);
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
        if (pfrom->fOneShot)
            pfrom->fDisconnect = true;
    }

    else if (strCommand == "inv")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            pfrom->Misbehaving(20);
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
                pfrom->Misbehaving(25);
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
            if (fDebugNet)
                printf("  got inventory: %s  %s\n", inv.ToString().c_str(), fAlreadyHave ? "have" : "new");
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

            // Don't bother if send buffer is too full to respond anyway
            if (pfrom->nSendSize >= SendBufferSize()) {
                pfrom->Misbehaving(50);
                return error("send buffer size() = %" PRIszu"", pfrom->nSendSize);
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
            pfrom->Misbehaving(20);
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
            pfrom->Misbehaving(20);
            return error("headers message size > 2000");
        }

        LOCK(cs_main);

        if (fDebug)
            printf("Received %u headers from peer %s\n", (unsigned int)vHeaders.size(), pfrom->addr.ToString().c_str());

        CBlockIndex* pindexLast = NULL;
        std::vector<CInv> vGetData;
        for (const CBlock& header : vHeaders)
        {
            uint256 hash = header.GetHash();

            if (mapBlockIndex.count(hash))
            {
                pindexLast = mapBlockIndex[hash];
                continue;
            }

            if (mapBlockIndex.count(header.hashPrevBlock) == 0)
            {
                if (fDebug) printf("Header %s has unknown parent %s, waiting for in-flight blocks\n",
                       hash.ToString().substr(0,20).c_str(),
                       header.hashPrevBlock.ToString().substr(0,20).c_str());
                // Rely on post-block-acceptance getheaders to chain sync forward
                break;
            }

            CBlockIndex* pindexPrev = mapBlockIndex[header.hashPrevBlock];

            // PoS blocks have nNonce==0; can't use IsProofOfStake() here because
            // vtx is empty in headers-only messages (no transactions to check)
            if (header.nNonce != 0)
            {
                if (!CheckProofOfWork(hash, header.nBits))
                {
                    pfrom->Misbehaving(100);
                    return error("header %s has invalid proof of work", hash.ToString().c_str());
                }
            }

            if (header.GetBlockTime() > FutureDrift(GetAdjustedTime()))
            {
                pfrom->Misbehaving(10);
                return error("header %s timestamp too far in future", hash.ToString().c_str());
            }

            if (fSPVMode)
            {
                CBlockIndex* pindexNew = new CBlockIndex();
                pindexNew->phashBlock = &(mapBlockIndex.insert(make_pair(hash, pindexNew)).first->first);
                pindexNew->pprev = pindexPrev;
                pindexNew->nHeight = pindexPrev->nHeight + 1;
                pindexNew->nVersion = header.nVersion;
                pindexNew->hashMerkleRoot = header.hashMerkleRoot;
                pindexNew->nTime = header.nTime;
                pindexNew->nBits = header.nBits;
                pindexNew->nNonce = header.nNonce;
                pindexNew->nFile = 0;
                pindexNew->nBlockPos = 0;

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
                // Request full block data, skip if already in-flight
                if (pfrom->setBlocksInFlight.count(hash))
                {
                    if (fDebug)
                        printf("Header block %s already in-flight, skipping\n",
                               hash.ToString().substr(0,20).c_str());
                    pindexLast = pindexPrev;
                    continue;
                }
                if (fDebug)
                    printf("Header announced block %s (parent height %d), requesting full block\n",
                           hash.ToString().substr(0,20).c_str(), pindexPrev->nHeight);
                vGetData.push_back(CInv(MSG_BLOCK, hash));
                pfrom->setBlocksInFlight.insert(hash);
                pindexLast = pindexPrev;
            }
        }

        // In full node mode, request full blocks for announced headers
        if (!fSPVMode && !vGetData.empty())
        {
            if (fDebug)
                printf("Requesting %u full blocks from peer %s via getdata\n",
                       (unsigned int)vGetData.size(), pfrom->addr.ToString().c_str());
            pfrom->PushMessage("getdata", vGetData);
        }

        // Only request more headers for large batches (IBD catch-up)
        if (pindexLast && !IsInitialBlockDownload())
        {
            if (vHeaders.size() >= 2000)
                pfrom->PushMessage("getheaders", CBlockLocator(pindexBest), uint256(0));
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

        bool fMissingInputs = false;
        if (tx.AcceptToMemoryPool(txdb, &fMissingInputs))
        {
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

                    if (orphanTx.AcceptToMemoryPool(txdb, &fMissingInputs2))
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
            AddOrphanTx(tx);

            // DoS prevention: do not allow mapOrphanTransactions to grow unbounded
            //unsigned int nEvicted = LimitOrphanTxSize(MAX_ORPHAN_TRANSACTIONS);
            unsigned int nMaxOrphanTx = (unsigned int)std::max((int64_t)0, GetArg("-maxorphantx", DEFAULT_MAX_ORPHAN_TRANSACTIONS));
            unsigned int nEvicted = LimitOrphanTxSize(nMaxOrphanTx);

            if (nEvicted > 0)
                printf("mapOrphan overflow, removed %u tx\n", nEvicted);
        }
        if (tx.nDoS) pfrom->Misbehaving(tx.nDoS);
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

        pfrom->setBlocksInFlight.erase(hashBlock);

        LOCK(cs_main);
        bool fAccepted = ProcessBlock(pfrom, &block);
        if (fAccepted)
        {
            pfrom->nLastBlockRecv = GetTime();
            if (nBestHeight >= pfrom->nChainHeight)
                pfrom->nChainHeight = nBestHeight + 1;
            LOCK(cs_mapAlreadyAskedFor);
            mapAlreadyAskedFor.erase(inv);
        }

        if (block.nDoS)
            pfrom->Misbehaving(block.nDoS);

        // Chain sync forward after accepting a new block
        if (fAccepted && pfrom->fPreferHeaders)
            pfrom->PushMessage("getheaders", CBlockLocator(pindexBest), uint256(0));

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
                        if (fDebug) { printf("Ping time for peer %s: %d msec\n", pfrom->addr.ToString().c_str(), (((double)pfrom->nPingUsecTime) / 1e6)); }
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
                pfrom->Misbehaving(10);
            }
        }
    }


    else if (strCommand == "filterload")
    {
        if (vRecv.size() > MAX_BLOOM_FILTER_SIZE + 100)  // +100 for serialization overhead
        {
            pfrom->Misbehaving(100);
            return false;
        }
        CBloomFilter filter;
        vRecv >> filter;

        if (!filter.IsWithinSizeConstraints())
        {
            pfrom->Misbehaving(100);
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
            pfrom->Misbehaving(100);
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
                pfrom->Misbehaving(100);
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
            pfrom->Misbehaving(100);
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

        // IDAG Phase 2: DAG tips exchange
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
                pfrom->Misbehaving(20);
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

    if (!pfrom->vRecvGetData.empty())
        ProcessGetData(pfrom);

    // this maintains the order of responses
    if (!pfrom->vRecvGetData.empty()) return fOk;

    std::deque<CNetMessage>::iterator it = pfrom->vRecvMsg.begin();
    while (!pfrom->fDisconnect && it != pfrom->vRecvMsg.end()) {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->nSendSize >= SendBufferSize())
            break;

        // get next message
        CNetMessage& msg = *it;

        //if (fDebug)
        //    printf("ProcessMessages(message %u msgsz, %zu bytes, complete:%s)\n",
        //            msg.hdr.nMessageSize, msg.vRecv.size(),
        //            msg.complete() ? "Y" : "N");

        // end, if an incomplete message is found
        if (!msg.complete())
            break;

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
                Misbehaving(pfrom->GetId(), 50);  // Severe penalty for oversized messages
            }
            else if (strstr(e.what(), "non-canonical"))
            {
                printf("ProcessMessages(%s, %u bytes) : Non-canonical encoding from peer=%s - '%s'\n",
                       strCommand.c_str(), nMessageSize, pfrom->addr.ToString().c_str(), e.what());
                Misbehaving(pfrom->GetId(), 20);  // Penalty for non-canonical encoding
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
        bool fBehind = (pBest != NULL && pBest->GetBlockTime() < nNow - 300) ||
                       (pto->nChainHeight > nHeight + 1);

        static std::map<std::string, int64_t> mapLastStallRecovery;
        bool fThrottle = (mapLastStallRecovery.count(pto->addrName) &&
                          nNow - mapLastStallRecovery[pto->addrName] < 15);

        if (!fImporting && !fReindex && fBehind && nTimeSinceBlock > 15 && !fThrottle)
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
                pto->PushMessage("getblocks", CBlockLocator(pBest), uint256(0));
            if (fDebug)
                printf("Sync stall recovery: peer=%s ch=%d our=%d stall=%ds\n",
                       pto->addrName.c_str(), pto->nChainHeight, nHeight, (int)nTimeSinceBlock);
        }
    }


    TRY_LOCK(cs_main, lockMain);
    if (lockMain) {

        if (dandelionState.IsEnabled())
        {
            std::vector<int> vPeerIds;
            {
                LOCK(cs_vNodes);
                for (CNode* pnode : vNodes)
                    vPeerIds.push_back(pnode->GetId());
            }
            dandelionRouter.UpdateEpoch(GetTime(), vPeerIds);

            std::vector<uint256> vFluff = dandelionState.CheckStemTimeouts(GetTime());
            for (const uint256& txHash : vFluff)
            {
                LOCK(cs_mapRelay);
                CInv inv(MSG_TX, txHash);
                if (mapRelay.count(inv))
                    RelayInventory(inv);
            }
        }

        if (pto->fStartSync && !fImporting && !fReindex) {
            pto->fStartSync = false;
            pto->PushGetBlocks(pindexBest, uint256(0));
        }

        // Resend wallet transactions that haven't gotten in a block yet
        // Except during reindex, importing and IBD, when old wallet
        // transactions become unconfirmed and spams other nodes.
        if (!fReindex && !IsInitialBlockDownload())
        {
            ResendWalletTransactions();
        }

        // Address refresh broadcast
        static int64_t nLastRebroadcast;
        if (!IsInitialBlockDownload() && (GetTime() - nLastRebroadcast > 24 * 60 * 60))
        {
            {
                LOCK(cs_vNodes);
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
            }
            nLastRebroadcast = GetTime();
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
        // Message: getblocks
        //

        int n = pto->getBlocksIndex.size();
        for (int i = 0; i < n; i++)
        {
            if (fDebugNet) printf("Pushing getblocks %s to %s\n\n",pto->getBlocksIndex[i]->ToString().c_str(),pto->getBlocksHash[i].ToString().c_str());
            pto->PushMessage("getblocks", CBlockLocator(pto->getBlocksIndex[i]), pto->getBlocksHash[i]);
        }
        pto->getBlocksIndex.clear();
        pto->getBlocksHash.clear();

        //
        // Message: inventory
        //
        vector<CInv> vInv;
        vector<CInv> vInvWait;
        vector<CBlock> vBlockHeaders;
        {
            LOCK(pto->cs_inventory);
            vInv.reserve(pto->vInventoryToSend.size());
            vInvWait.reserve(pto->vInventoryToSend.size());
            for (const CInv& inv : pto->vInventoryToSend)
            {
                if (pto->setInventoryKnown.count(inv))
                    continue;

                // trickle out tx inv to protect privacy
                if (inv.type == MSG_TX && !fSendTrickle)
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
                if (pto->setInventoryKnown.insert(inv).second)
                {
                    if (inv.type == MSG_BLOCK && pto->fPreferHeaders)
                    {
                        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(inv.hash);
                        if (mi != mapBlockIndex.end())
                        {
                            CBlockIndex* pindex = (*mi).second;
                            vBlockHeaders.push_back(pindex->GetBlockHeader());
                        }
                    }
                    else
                    {
                        vInv.push_back(inv);
                    }
                    if (vInv.size() >= 1000)
                    {
                        pto->PushMessage("inv", vInv);
                        vInv.clear();
                    }
                }
            }
            pto->vInventoryToSend = vInvWait;
        }
        if (!vInv.empty())
            pto->PushMessage("inv", vInv);
        if (!vBlockHeaders.empty())
            pto->PushMessage("headers", vBlockHeaders);


        //
        // Message: getdata
        //
        vector<CInv> vGetData;
        int64_t nNow = GetTime() * 1000000;
        CTxDB txdb("r");
        while (!pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow)
        {
            const CInv& inv = (*pto->mapAskFor.begin()).second;
            if (!AlreadyHave(txdb, inv))
            {
                if (fDebugNet)
                    printf("sending getdata: %s\n", inv.ToString().c_str());
                vGetData.push_back(inv);
                if (vGetData.size() >= 1000)
                {
                    pto->PushMessage("getdata", vGetData);
                    vGetData.clear();
                }
                {
                    LOCK(cs_mapAlreadyAskedFor);
                    mapAlreadyAskedFor[inv] = nNow;
                }
            }
            pto->mapAskFor.erase(pto->mapAskFor.begin());
        }
        if (!vGetData.empty())
            pto->PushMessage("getdata", vGetData);

        if (fSecMsgEnabled)
            SecureMsgSendData(pto, fSendTrickle);
    }



    return true;
}

int64_t GetCollateralnodePayment(int nHeight, int64_t blockValue)
{
    if (blockValue <= 0)
        return 0;
    return (blockValue / 100) * 65 + ((blockValue % 100) * 65) / 100;
}
