// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "txdb-leveldb.h"
#include "wallet.h"
#include "walletdb.h"
#include "innovarpc.h"
#include "shielded.h"
#include "nullsend.h"
#include "zkproof.h"
#include "bulletproof_ac.h"
#include "lelantus.h"
#include "dandelion.h"
#include "init.h"
#include "base58.h"
#include "dag.h"
#include "privacy_vnext_store.h"
#include "finality.h"
#include "privacy_vnext/iv5_protocol.h"
#include "privacy_vnext_ffi.h"

#include <string>
#include <sstream>
#include <algorithm>
#include <limits>
#include <openssl/rand.h>

using namespace json_spirit;
using namespace std;

extern CWallet* pwalletMain;

static string ShieldedAddressToString(const CShieldedPaymentAddress& addr)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << addr;
    vector<unsigned char> vch(ss.begin(), ss.end());
    return EncodeBase58Check(vch);
}

static bool StringToShieldedAddress(const string& str, CShieldedPaymentAddress& addr)
{
    vector<unsigned char> vch;
    if (!DecodeBase58Check(str, vch))
        return false;
    try
    {
        CDataStream ss(vch, SER_NETWORK, PROTOCOL_VERSION);
        ss >> addr;
    }
    catch (...)
    {
        return false;
    }
    return true;
}

static bool LoadWalletFCMPProofTree(CTxDB& txdb, int nCurrentHeight,
                                    CCurveTree& treeOut,
                                    uint256& hashRootOut,
                                    std::string& strErrorOut)
{
    if (nCurrentHeight >= FORK_HEIGHT_EPOCH_ROOT_FCMP)
    {
        // Block-relative deterministic anchor (matches LoadFCMPValidationRoot), not the
        // node-local live finalized tip, so the created spend validates on every node.
        CEpochState finalizedEpochState;
        if (!g_dagManager.GetFinalizedEpochStateAsOf(nCurrentHeight, finalizedEpochState))
        {
            strErrorOut = "No finalized epoch curve-tree root is available yet";
            return false;
        }
        if (!txdb.ReadCurveTreeAtEpoch(finalizedEpochState.nEpoch, treeOut))
        {
            strErrorOut = "Finalized epoch curve-tree snapshot is missing";
            return false;
        }
        if (!treeOut.IsEmpty())
            treeOut.RebuildParentNodes();
        hashRootOut = treeOut.GetRoot();
        if (hashRootOut == 0 || hashRootOut != finalizedEpochState.hashCurveRoot)
        {
            strErrorOut = "Finalized epoch curve-tree snapshot root mismatch";
            return false;
        }
        return true;
    }

    if (!txdb.ReadCurveTree(treeOut))
    {
        strErrorOut = "Mutable curve tree is missing";
        return false;
    }
    if (!treeOut.IsEmpty())
        treeOut.RebuildParentNodes();
    hashRootOut = treeOut.GetRoot();
    return true;
}

struct ShieldedSpendabilityContext
{
    int nCurrentHeight;
    bool fRequireFCMP;
    bool fHasFCMPTree;
    CCurveTree fcmpTree;
    uint256 hashFCMPRoot;
    std::string strFCMPError;

    ShieldedSpendabilityContext()
        : nCurrentHeight(0), fRequireFCMP(false), fHasFCMPTree(false), hashFCMPRoot(0)
    {
    }
};

struct ShieldedNoteSpendability
{
    int nConfirmations;
    bool fMinConfSpendable;
    bool fFCMPSpendable;
    bool fSpendable;
    std::string strPendingReason;

    ShieldedNoteSpendability()
        : nConfirmations(0), fMinConfSpendable(false),
          fFCMPSpendable(false), fSpendable(false)
    {
    }
};

static int GetShieldedNoteConfirmations(const CWallet::CShieldedWalletNote& wnote,
                                        int nCurrentHeight)
{
    if (wnote.nHeight <= 0 || nCurrentHeight < wnote.nHeight)
        return 0;
    return nCurrentHeight - wnote.nHeight + 1;
}

static ShieldedSpendabilityContext BuildShieldedSpendabilityContext(int nCurrentHeight)
{
    ShieldedSpendabilityContext ctx;
    ctx.nCurrentHeight = nCurrentHeight;
    ctx.fRequireFCMP = (nCurrentHeight >= FORK_HEIGHT_FCMP_VALIDATION);
    ctx.hashFCMPRoot = 0;

    if (ctx.fRequireFCMP)
    {
        CTxDB txdb("r");
        ctx.fHasFCMPTree = LoadWalletFCMPProofTree(txdb, nCurrentHeight,
                                                   ctx.fcmpTree,
                                                   ctx.hashFCMPRoot,
                                                   ctx.strFCMPError);
    }
    else
    {
        ctx.fHasFCMPTree = true;
    }

    return ctx;
}

static ShieldedNoteSpendability GetShieldedNoteSpendability(
    const CWallet::CShieldedWalletNote& wnote,
    const ShieldedSpendabilityContext& ctx)
{
    ShieldedNoteSpendability status;
    status.nConfirmations = GetShieldedNoteConfirmations(wnote, ctx.nCurrentHeight);
    status.fMinConfSpendable = (status.nConfirmations >= MIN_SHIELDED_SPEND_DEPTH);
    status.fFCMPSpendable = true;

    if (ctx.fRequireFCMP)
    {
        status.fFCMPSpendable = false;

        CPedersenCommitment cv;
        if (!wnote.note.GetPedersenCommitment(cv))
        {
            status.strPendingReason = "missing_commitment_blinding_factor";
        }
        else if (!ctx.fHasFCMPTree || ctx.fcmpTree.IsEmpty() || ctx.hashFCMPRoot == 0)
        {
            status.strPendingReason = "awaiting_finalized_epoch_curve_tree";
        }
        else if (ctx.fcmpTree.FindLeafIndex(cv) < 0)
        {
            status.strPendingReason = "awaiting_finalized_epoch_curve_tree";
        }
        else
        {
            status.fFCMPSpendable = true;
        }
    }

    status.fSpendable = status.fMinConfSpendable && status.fFCMPSpendable;
    if (!status.fMinConfSpendable)
        status.strPendingReason = "awaiting_min_confirmations";
    else if (!status.fFCMPSpendable && status.strPendingReason.empty())
        status.strPendingReason = "awaiting_finalized_epoch_curve_tree";
    else if (status.fSpendable)
        status.strPendingReason.clear();

    return status;
}

static std::string FormatShieldedSpendabilityError(const ShieldedSpendabilityContext& ctx,
                                                   int64_t nSpendable,
                                                   int64_t nPending,
                                                   int64_t nNeeded)
{
    return strprintf("%s: spendable=%s pending=%s needed=%s",
                     ctx.fRequireFCMP ? "Insufficient FCMP-finalized shielded balance"
                                      : "Insufficient shielded balance",
                     FormatMoney(nSpendable).c_str(),
                     FormatMoney(nPending).c_str(),
                     FormatMoney(nNeeded).c_str());
}

static void SetPublicShieldedRecipient(CShieldedOutputDescription& output,
                                       const CShieldedPaymentAddress& addr)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << addr;
    output.vchRecipientScript.assign(ss.begin(), ss.end());
}

// A set bit hides that field, so the flags read the mask inverted.
void PrivacyVNextDisclosureToJSON(uint8_t nDisclosureMask, Object& out)
{
    out.push_back(Pair("disclosure_mask", (int)nDisclosureMask));
    out.push_back(Pair("discloses_sender",
                       (nDisclosureMask & iv5::DISCLOSURE_HIDE_SENDER) == 0));
    out.push_back(Pair("discloses_receiver",
                       (nDisclosureMask & iv5::DISCLOSURE_HIDE_RECEIVER) == 0));
    out.push_back(Pair("discloses_amount",
                       (nDisclosureMask & iv5::DISCLOSURE_HIDE_AMOUNT) == 0));
}

static void RequireLegacyPrivacyCreationEnabled()
{
    const int nCandidateHeight = pindexBest ? pindexBest->nHeight + 1 : 0;
    if (IsLegacyPrivacyPolicyDisabled() ||
        IsBoundaryAActiveAtHeight(nCandidateHeight))
        throw JSONRPCError(
            RPC_METHOD_NOT_FOUND,
            "Legacy shielded, NullStake, private-finality, and NullSend creation is disabled; privacy vNext is not active");
}

Value z_createiv5seed(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "z_createiv5seed\n"
            "Creates the wallet's encrypted generation-1 IV5 seed.\n"
            "The wallet must be encrypted, unlocked, and backed up after creation.\n"
            "This prepares key material only; IV5 transaction construction remains inactive.\n");

    EnsureWalletIsUnlocked();

    std::string error;
    if (!pwalletMain->CreatePrivacyVNextSeed(error))
        throw JSONRPCError(RPC_WALLET_ERROR, error);

    Object result;
    result.push_back(Pair("created", true));
    result.push_back(Pair("generation", 1));
    result.push_back(Pair("next_address_index", 0));
    result.push_back(Pair("secret_exported", false));
    result.push_back(Pair("transactions_active", IsShieldedVNextConsensusReady()));
    return result;
}

Value z_exportiv5seed(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "z_exportiv5seed\n"
            "Returns the wallet's IV5 seed as hex, with the number of addresses issued\n"
            "under it. The seed and that count restore every IV5 note this wallet can\n"
            "hold: keep it as secret as the wallet passphrase.\n");

    EnsureWalletIsUnlocked();

    CKeyingMaterial seed;
    if (!pwalletMain->GetPrivacyVNextSeed(seed))
        throw JSONRPCError(RPC_WALLET_ERROR, "this wallet holds no unlocked IV5 seed");

    Object result;
    result.push_back(Pair("seed", HexStr(seed.begin(), seed.end())));
    result.push_back(Pair("generation", 1));
    result.push_back(Pair("address_index_count",
                          (int64_t)pwalletMain->GetPrivacyVNextScanIndexCount()));
    return result;
}

Value z_importiv5seed(const Array& params, bool fHelp)
{
    if (fHelp || params.empty() || params.size() > 3)
        throw runtime_error(
            "z_importiv5seed <seedhex> [addressindexcount] [rescan=true]\n"
            "Restores an IV5 seed exported by z_exportiv5seed into a wallet that has\n"
            "none. Notes are recovered from the chain by the rescan, not from the seed,\n"
            "so a wallet with an existing seed is refused rather than overwritten.\n");

    EnsureWalletIsUnlocked();

    const std::string strSeed = params[0].get_str();
    if (strSeed.size() != 64 || !IsHex(strSeed))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "an IV5 seed is 64 hex characters");
    const std::vector<unsigned char> vchSeed = ParseHex(strSeed);
    CKeyingMaterial seed(vchSeed.begin(), vchSeed.end());

    uint32_t nAddressIndexHint = 0;
    if (params.size() > 1)
    {
        const int64_t nHint = params[1].get_int64();
        if (nHint < 0 || nHint > (int64_t)PRIVACY_VNEXT_MAX_ISSUED_ADDRESSES)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("addressindexcount must be between 0 and %u",
                                         PRIVACY_VNEXT_MAX_ISSUED_ADDRESSES));
        nAddressIndexHint = (uint32_t)nHint;
    }
    const bool fRescan = params.size() > 2 ? params[2].get_bool() : true;

    std::string strError;
    if (!pwalletMain->ImportPrivacyVNextSeed(seed, nAddressIndexHint, strError))
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    Object result;
    result.push_back(Pair("imported", true));
    result.push_back(Pair("address_index_count", (int64_t)nAddressIndexHint));
    if (fRescan)
    {
        int nBlocks = 0;
        std::string strRescanError;
        if (!pwalletMain->RescanPrivacyVNextBlocks(0, nBlocks, strRescanError))
            throw JSONRPCError(RPC_WALLET_ERROR,
                               "seed imported but the rescan failed: " + strRescanError);
        result.push_back(Pair("blocks_rescanned", nBlocks));
    }
    result.push_back(Pair("rescanned", fRescan));
    result.push_back(Pair("notes", (int64_t)pwalletMain->GetPrivacyVNextNoteCount()));
    return result;
}

Value z_rescaniv5(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "z_rescaniv5 [fromheight]\n"
            "Reprocesses the IV5 payloads of connected blocks from <fromheight>.\n"
            "Defaults to the lowest height this wallet is known to have left unscanned,\n"
            "or 0 if none is recorded. Detection is the only way a note is ever found,\n"
            "so this is the recovery path for a block skipped while the wallet was\n"
            "locked or for a seed imported after the fact.\n");

    EnsureWalletIsUnlocked();

    int nFromHeight = pwalletMain->GetPrivacyVNextScanGapHeight();
    if (nFromHeight < 0)
        nFromHeight = 0;
    if (params.size() > 0)
    {
        const int64_t nRequested = params[0].get_int64();
        if (nRequested < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "fromheight must not be negative");
        nFromHeight = (int)std::min<int64_t>(nRequested, std::numeric_limits<int>::max());
    }

    const int64_t nBefore = (int64_t)pwalletMain->GetPrivacyVNextNoteCount();
    int nBlocks = 0;
    std::string strError;
    if (!pwalletMain->RescanPrivacyVNextBlocks(nFromHeight, nBlocks, strError))
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    Object result;
    result.push_back(Pair("from_height", nFromHeight));
    result.push_back(Pair("blocks_rescanned", nBlocks));
    result.push_back(Pair("notes_before", nBefore));
    result.push_back(Pair("notes_after",
                          (int64_t)pwalletMain->GetPrivacyVNextNoteCount()));
    result.push_back(Pair("scan_gap_height",
                          pwalletMain->GetPrivacyVNextScanGapHeight()));
    return result;
}

Value z_getnewiv5address(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "z_getnewiv5address\n"
            "Returns a new generation-1 IV5 address from the encrypted wallet seed.\n"
            "The derived address is returned only after its index is durably committed.\n"
            "This allocates an address only; IV5 transaction construction remains inactive.\n");

    EnsureWalletIsUnlocked();

    std::string address;
    std::string error;
    uint32_t index = 0;
    if (!pwalletMain->GenerateNewPrivacyVNextAddress(0, address, index, error))
        throw JSONRPCError(RPC_WALLET_ERROR, error);

    Object result;
    result.push_back(Pair("address", address));
    result.push_back(Pair("address_type", 0));
    result.push_back(Pair("address_index", (int64_t)index));
    result.push_back(Pair("generation", 1));
    result.push_back(Pair("transactions_active", IsShieldedVNextConsensusReady()));
    return result;
}

Value z_getnewaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "z_getnewaddress\n"
            "Returns a new shielded payment address.\n");

    RequireLegacyPrivacyCreationEnabled();

    EnsureWalletIsUnlocked();

    CShieldedPaymentAddress addr = pwalletMain->GenerateNewShieldedAddress();
    return ShieldedAddressToString(addr);
}

Value z_listaddresses(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "z_listaddresses\n"
            "Returns the list of shielded addresses belonging to the wallet.\n");

    Array ret;
    LOCK(pwalletMain->cs_shielded);
    for (const auto& pair : pwalletMain->mapShieldedSpendingKeys)
    {
        ret.push_back(ShieldedAddressToString(pair.first));
    }
    for (const auto& pair : pwalletMain->mapShieldedViewingKeys)
    {
        if (pwalletMain->mapShieldedSpendingKeys.count(pair.first) == 0)
            ret.push_back(ShieldedAddressToString(pair.first));
    }
    return ret;
}

Value z_getbalance(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "z_getbalance [address]\n"
            "Returns the shielded balance.\n"
            "If address is specified, returns balance for that shielded address only.\n");

    if (params.size() == 1)
    {
        string strAddr = params[0].get_str();
        CShieldedPaymentAddress addr;
        if (!StringToShieldedAddress(strAddr, addr))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid shielded address");

        LOCK(pwalletMain->cs_shielded);
        int64_t nBalance = 0;
        for (const CWallet::CShieldedWalletNote& wnote : pwalletMain->vShieldedNotes)
        {
            if (!wnote.fSpent && wnote.note.addr == addr)
                nBalance += wnote.note.nValue;
        }
        return ValueFromAmount(nBalance);
    }

    return ValueFromAmount(pwalletMain->GetShieldedBalance());
}

Value z_gettotalbalance(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "z_gettotalbalance\n"
            "Returns object with transparent and shielded balances.\n");

    Object obj;
    obj.push_back(Pair("transparent", ValueFromAmount(pwalletMain->GetBalance())));
    obj.push_back(Pair("shielded", ValueFromAmount(pwalletMain->GetShieldedBalance())));
    obj.push_back(Pair("total", ValueFromAmount(pwalletMain->GetBalance() + pwalletMain->GetShieldedBalance())));
    return obj;
}

Value z_shield(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "z_shield <fromaddress> <amount> [zaddress]\n"
            "Shield transparent coins to a shielded address.\n"
            "If zaddress is not specified, a new shielded address is created.\n"
            "\nCreates a shielded transaction with Pedersen commitments and Bulletproof range proofs.\n");

    RequireLegacyPrivacyCreationEnabled();

    EnsureWalletIsUnlocked();

    if (!CZKContext::IsInitialized())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "ZK proof context not initialized");

    int nCurrentHeight = pindexBest ? pindexBest->nHeight : 0;
    if (nCurrentHeight < FORK_HEIGHT_SHIELDED)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Shielded transactions are not yet active");

    string strFromAddr = params[0].get_str();
    int64_t nAmount = AmountFromValue(params[1]);

    bool fFilterByAddress = (strFromAddr != "*");
    if (fFilterByAddress)
    {
        CBitcoinAddress fromAddress(strFromAddr);
        if (!fromAddress.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid from address");
    }

    if (nAmount <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");
    if (nAmount < MIN_TX_FEE_SHIELDED)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Amount too small (minimum 0.001 INN)");
    if (nAmount > MAX_MONEY)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Amount exceeds maximum (18M INN)");

    CShieldedPaymentAddress zAddr;
    if (params.size() >= 3)
    {
        string strZAddr = params[2].get_str();
        if (!StringToShieldedAddress(strZAddr, zAddr))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid shielded address");
    }
    else
    {
        zAddr = pwalletMain->GenerateNewShieldedAddress();
    }

    CShieldedNote note;
    note.addr = zAddr;
    note.nValue = nAmount;

    unsigned char rnd[32];
    if (RAND_bytes(rnd, 32) != 1)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate randomness");
    memcpy(note.rho.begin(), rnd, 32);

    if (RAND_bytes(rnd, 32) != 1)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate randomness");
    memcpy(note.rcm.begin(), rnd, 32);
    OPENSSL_cleanse(rnd, 32);

    if (!note.GenerateBlindingFactor())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate blinding factor");

    CPedersenCommitment cv;
    if (!note.GetPedersenCommitment(cv))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create Pedersen commitment");

    CBulletproofRangeProof rangeProof;
    if (!CreateBulletproofRangeProof(note.nValue, note.vchBlind, cv, rangeProof))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create range proof");

    uint256 cmu = note.GetCommitment();

    vector<unsigned char> vchEphemeralKey, vchEncCiphertext;
    if (!EncryptShieldedNote(note, zAddr, vchEphemeralKey, vchEncCiphertext))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to encrypt note");

    CShieldedOutputDescription output;
    output.cv = cv;
    output.cmu = cmu;
    output.vchEphemeralKey = vchEphemeralKey;
    output.vchEncCiphertext = vchEncCiphertext;
    output.rangeProof = rangeProof;

    {
        LOCK(pwalletMain->cs_shielded);
        if (!pwalletMain->mapShieldedSpendingKeys.empty())
        {
            const CShieldedSpendingKey& sk = pwalletMain->mapShieldedSpendingKeys.begin()->second;
            EncryptShieldedNoteForSender(note, sk.ovk, cv.GetHash(), cmu, vchEphemeralKey, output.vchOutCiphertext);
        }
    } // cs_shielded released here before wallet operations

    CWalletTx wtxNew;
    wtxNew.BindWallet(pwalletMain);
    wtxNew.nVersion = SHIELDED_TX_VERSION;
    wtxNew.nTime = GetAdjustedTime();
    wtxNew.vShieldedOutput.push_back(output);
    wtxNew.nValueBalance = -nAmount; // Negative = value entering shielded pool

    int64_t nFeeRequired = MIN_TX_FEE_SHIELDED;
    int64_t nChange = 0;
    CReserveKey reservekey(pwalletMain);

    static const int MAX_SHIELD_FEE_RETRIES = 10;
    for (int nFeeRetry = 0; nFeeRetry < MAX_SHIELD_FEE_RETRIES; nFeeRetry++)
    {
    wtxNew.vin.clear();
    wtxNew.vout.clear();

    int64_t nTotalNeeded = nAmount + nFeeRequired;

    set<pair<const CWalletTx*, unsigned int>> setCoins;
    int64_t nValueIn = 0;
    vector<COutput> vCoins;
    pwalletMain->AvailableCoins(vCoins);
    vCoins.erase(remove_if(vCoins.begin(), vCoins.end(), [](const COutput& out) {
        if (!(out.tx->IsCoinBase() || out.tx->IsCoinStake()))
            return false;
        return out.nDepth <= nCoinbaseMaturity;
    }), vCoins.end());

    if (fFilterByAddress)
    {
        vector<COutput> vFilteredCoins;
        for (const COutput& out : vCoins)
        {
            CTxDestination dest;
            if (ExtractDestination(out.tx->vout[out.i].scriptPubKey, dest))
            {
                CBitcoinAddress coinAddr(dest);
                if (coinAddr.ToString() == strFromAddr)
                    vFilteredCoins.push_back(out);
            }
        }
        vCoins = vFilteredCoins;
    }

    if (!pwalletMain->SelectCoinsMinConf(nTotalNeeded, wtxNew.nTime, 1, 10, vCoins, setCoins, nValueIn))
        if (!pwalletMain->SelectCoinsMinConf(nTotalNeeded, wtxNew.nTime, 1, 1, vCoins, setCoins, nValueIn))
            if (!pwalletMain->SelectCoinsMinConf(nTotalNeeded, wtxNew.nTime, 0, 1, vCoins, setCoins, nValueIn))
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                    strprintf("Insufficient funds: need %" PRId64 " but only have available coins",
                              nTotalNeeded));

    for (const auto& coin : setCoins)
        wtxNew.vin.push_back(CTxIn(coin.first->GetHash(), coin.second));

    nChange = nValueIn - nTotalNeeded;
    if (nChange > 0)
    {
        CPubKey vchPubKey;
        if (!reservekey.GetReservedKey(vchPubKey))
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Keypool ran out");
        CScript scriptChange;
        scriptChange.SetDestination(vchPubKey.GetID());
        wtxNew.vout.push_back(CTxOut(nChange, scriptChange));
    }

    int nIn = 0;
    for (const auto& coin : setCoins)
    {
        if (!SignSignature(*pwalletMain, *coin.first, wtxNew, nIn++))
        {
            reservekey.ReturnKey();
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign transparent input");
        }
    }

    {
        unsigned int nBytes = ::GetSerializeSize(*(CTransaction*)&wtxNew, SER_NETWORK, PROTOCOL_VERSION);
        int64_t nMinFee = wtxNew.GetMinFee(1, GMF_SEND, nBytes);
        if (nFeeRequired < nMinFee)
        {
            nFeeRequired = nMinFee;
            reservekey.ReturnKey();
            continue; // Retry with higher fee
        }
    }

    vector<vector<unsigned char>> vInputBlinds;
    vector<vector<unsigned char>> vOutputBlinds;
    vOutputBlinds.push_back(note.vchBlind);

    vector<unsigned char> feeBlind(32, 0);
    vInputBlinds.push_back(feeBlind);

    uint256 sighash = wtxNew.GetBindingSigHash();
    CBindingSignature bindingSig;
    CreateBindingSignature(vInputBlinds, vOutputBlinds, sighash, bindingSig);
    wtxNew.bindingSig.bindingSig = bindingSig;

    if (!pwalletMain->CommitTransaction(wtxNew, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to commit shielded transaction");

    break; // Success - exit fee retry loop
    } // end fee retry loop

    Object result;
    result.push_back(Pair("txid", wtxNew.GetHash().GetHex()));
    result.push_back(Pair("zaddress", ShieldedAddressToString(zAddr)));
    result.push_back(Pair("amount", ValueFromAmount(nAmount)));
    result.push_back(Pair("fee", ValueFromAmount(nFeeRequired)));
    result.push_back(Pair("change", ValueFromAmount(nChange)));
    result.push_back(Pair("commitment", cmu.GetHex()));
    result.push_back(Pair("range_proof_size", (int)rangeProof.GetSize()));
    result.push_back(Pair("proof_system", "Bulletproofs++ (Pedersen + secp256k1)"));

    return result;
}

Value z_unshield(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 3)
        throw runtime_error(
            "z_unshield <zaddress> <toaddress> <amount>\n"
            "Unshield coins from a shielded address to a transparent address.\n"
            "\nCreates an unshielding transaction with Bulletproof range proofs.\n");

    RequireLegacyPrivacyCreationEnabled();

    EnsureWalletIsUnlocked();

    if (!CZKContext::IsInitialized())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "ZK proof context not initialized");

    int nCurrentHeight = pindexBest ? pindexBest->nHeight : 0;
    if (nCurrentHeight < FORK_HEIGHT_SHIELDED)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Shielded transactions are not yet active");

    string strZAddr = params[0].get_str();
    string strToAddr = params[1].get_str();
    int64_t nAmount = AmountFromValue(params[2]);

    if (nAmount <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");
    if (nAmount > MAX_MONEY)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Amount exceeds maximum allowed");

    CShieldedPaymentAddress zAddr;
    if (!StringToShieldedAddress(strZAddr, zAddr))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid shielded address");

    ShieldedSpendabilityContext spendability = BuildShieldedSpendabilityContext(nCurrentHeight);

    int64_t nAvailable = 0;
    int64_t nPending = 0;
    vector<size_t> vSelectedIndices;
    vector<CWallet::CShieldedWalletNote> vSelectedNotes;
    CShieldedSpendingKey sk;
    CShieldedFullViewingKey fvk;

    {
        LOCK(pwalletMain->cs_shielded);
        if (!pwalletMain->HaveShieldedSpendingKey(zAddr))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or unknown shielded address");

        for (size_t i = 0; i < pwalletMain->vShieldedNotes.size(); i++)
        {
            CWallet::CShieldedWalletNote& wnote = pwalletMain->vShieldedNotes[i];
            if (!wnote.fSpent && wnote.note.addr == zAddr)
            {
                ShieldedNoteSpendability noteStatus = GetShieldedNoteSpendability(wnote, spendability);
                if (!noteStatus.fSpendable)
                {
                    nPending += wnote.note.nValue;
                    continue;
                }

                nAvailable += wnote.note.nValue;
                vSelectedIndices.push_back(i);
                if (nAvailable >= nAmount + MIN_TX_FEE_SHIELDED)
                    break;
            }
        }

        if (nAvailable < nAmount + MIN_TX_FEE_SHIELDED)
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                FormatShieldedSpendabilityError(spendability, nAvailable, nPending,
                                                nAmount + MIN_TX_FEE_SHIELDED));

        sk = pwalletMain->mapShieldedSpendingKeys[zAddr];
        DeriveShieldedFullViewingKey(sk, fvk);

        {
            CWalletDB walletdb(pwalletMain->strWalletFile);
            for (size_t idx : vSelectedIndices)
            {
                const CWallet::CShieldedWalletNote& sn = pwalletMain->vShieldedNotes[idx];
                if (!walletdb.WriteShieldedNoteSpent(sn.txhash, sn.nPosition, true))
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to persist note spent flag");
            }
        }

        for (size_t idx : vSelectedIndices)
        {
            pwalletMain->vShieldedNotes[idx].fSpent = true;
            vSelectedNotes.push_back(pwalletMain->vShieldedNotes[idx]);
        }
    } // cs_shielded released here

    try
    {

    CTransaction txNew;
    bool fUseFCMP = (nCurrentHeight >= FORK_HEIGHT_FCMP_VALIDATION);
    txNew.nVersion = fUseFCMP ? SHIELDED_TX_VERSION_FCMP : SHIELDED_TX_VERSION;
    txNew.nTime = GetAdjustedTime();

    if (fUseFCMP)
        txNew.nPrivacyMode = PRIVACY_MODE_FULL;

    vector<vector<unsigned char>> vInputBlinds;
    vector<int64_t> vSpendValues;           // per-spend note value (binding proof)
    vector<vector<unsigned char>> vSpendBlinds; // per-spend note blind (binding proof)

    for (size_t i = 0; i < vSelectedNotes.size(); i++)
    {
        CWallet::CShieldedWalletNote& wnote = vSelectedNotes[i];

        CShieldedSpendDescription spend;

        if (wnote.note.vchBlind.empty())
            wnote.note.GenerateBlindingFactor(); // Legacy notes may not have blinds

        if (!wnote.note.GetPedersenCommitment(spend.cv))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create spend commitment");

        if (!CreateBulletproofRangeProof(wnote.note.nValue, wnote.note.vchBlind, spend.cv, spend.rangeProof))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create spend range proof");

        if (!ApplyShieldedSpendNullifier(spend, wnote.note, fvk.nk,
                nCurrentHeight + 1 >= FORK_HEIGHT_NULLIFIER_BINDING))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to set shielded spend nullifier");
        {
            CTxDB txdb("r");
            CIncrementalMerkleTree tree;

            int nAnchorHeight = nCurrentHeight - MIN_SHIELDED_SPEND_DEPTH;
            if (nAnchorHeight < 0) nAnchorHeight = 0;
            CBlockIndex* pAnchorBlock = FindBlockByHeight(nAnchorHeight);
            if (pAnchorBlock)
            {
                CIncrementalMerkleTree oldTree;
                if (txdb.ReadShieldedTreeAtBlock(pAnchorBlock->GetBlockHash(), oldTree))
                {
                    tree = oldTree;
                    if (fDebug)
                        printf("z_unshield: using anchor from height %d\n", nAnchorHeight);
                }
                else
                {
                    throw JSONRPCError(RPC_DATABASE_ERROR,
                        strprintf("Missing shielded-tree snapshot at anchor height %d; "
                                  "reindex/resync required", nAnchorHeight));
                }
            }
            else
            {
                if (!txdb.ReadShieldedTree(tree))
                    throw JSONRPCError(RPC_DATABASE_ERROR,
                        "Missing current shielded tree; reindex/resync required");
            }
            spend.anchor = tree.Root();

            vector<CPedersenCommitment> vAllCommitments;
            uint64_t nGlobalOutputIndex = 0;
            std::string strSampleError;
            if (!txdb.ReadBoundedLelantusCommitments(
                    spend.cv, vAllCommitments, nGlobalOutputIndex,
                    strSampleError))
                throw JSONRPCError(RPC_DATABASE_ERROR,
                    strprintf("Unable to sample shielded commitments: %s; "
                              "reindex/resync may be required",
                              strSampleError.c_str()));

            if (fDebug)
                printf("z_unshield: uniformly sampled %d commitments; real index=%" PRIu64 "\n",
                       (int)vAllCommitments.size(), nGlobalOutputIndex);

            CAnonymitySet anonSet;
            if (!BuildAnonymitySet(spend.cv, vAllCommitments, spend.anchor,
                                    nCurrentHeight, anonSet))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to build Lelantus anonymity set");

            int nRealIndex = anonSet.FindIndex(spend.cv);
            if (nRealIndex < 0)
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Own commitment not found in Lelantus anonymity set");

            CLelantusProof lelantusProof;
            int64_t nSerialIdx = (nCurrentHeight >= FORK_HEIGHT_SERIAL_V2)
                ? (int64_t)nGlobalOutputIndex : -1;
            uint256 serial = ComputeLelantusSerial(sk.skSpend, wnote.note.rho, spend.cv, nSerialIdx);

            if (!CreateLelantusProof(anonSet, nRealIndex, wnote.note.nValue,
                                      wnote.note.vchBlind, serial, lelantusProof))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create Lelantus proof");

            spend.vchLelantusProof = lelantusProof.vchProof;
            spend.lelantusSerial = serial;
            spend.vAnonSet = anonSet.vCommitments;
        }

        if (fUseFCMP)
        {
            if (!spendability.fHasFCMPTree || spendability.fcmpTree.IsEmpty())
                throw JSONRPCError(RPC_INTERNAL_ERROR,
                    spendability.strFCMPError.empty() ? "Curve tree is empty, cannot create FCMP proof"
                                                      : spendability.strFCMPError);

            int64_t nLeafIdx = spendability.fcmpTree.FindLeafIndex(spend.cv);
            if (nLeafIdx < 0)
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Spend %d commitment not found in curve tree", (int)i));

            // Retired: no membership proof can be built for a legacy
            // shielded spend, and consensus rejects one without a proof.
            throw JSONRPCError(RPC_INVALID_REQUEST,
                               "legacy shielded spends are retired: the in-tree path-proof layer has been removed");

            spend.curveTreeRoot = spendability.hashFCMPRoot;

            if (fDebug)
                printf("z_unshield: created FCMP proof for spend %d (leaf index %lld, tree size %llu)\n",
                       (int)i, (long long)nLeafIdx,
                       (unsigned long long)spendability.fcmpTree.nLeafCount);
        }

        txNew.vShieldedSpend.push_back(spend);
        vInputBlinds.push_back(wnote.note.vchBlind);
        vSpendValues.push_back(wnote.note.nValue);
        vSpendBlinds.push_back(wnote.note.vchBlind);
    }

    unsigned int nEstimatedKB = 2 + (unsigned int)txNew.vShieldedSpend.size() * 4;
    int64_t nFee = std::max(MIN_TX_FEE_SHIELDED, (int64_t)(1 + nEstimatedKB) * MIN_TX_FEE_ANON);

    if (nAvailable < nAmount + nFee)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
            strprintf("Insufficient shielded balance for size-based fee: available=%" PRId64 " needed=%" PRId64 " (amount=%" PRId64 " fee=%" PRId64 ")",
                      nAvailable, nAmount + nFee, nAmount, nFee));

    txNew.nValueBalance = nAmount + nFee;

    int64_t nChange = nAvailable - nAmount - nFee;
    vector<vector<unsigned char>> vOutputBlinds;

    if (nChange > 0)
    {
        CShieldedNote changeNote;
        changeNote.addr = zAddr;
        changeNote.nValue = nChange;

        unsigned char rnd[32];
        if (RAND_bytes(rnd, 32) != 1)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate randomness for change note");
        memcpy(changeNote.rho.begin(), rnd, 32);
        if (RAND_bytes(rnd, 32) != 1)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate randomness for change note");
        memcpy(changeNote.rcm.begin(), rnd, 32);
        OPENSSL_cleanse(rnd, 32);
        if (!changeNote.GenerateBlindingFactor())
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate blinding factor for change note");

        CPedersenCommitment changeCv;
        if (!changeNote.GetPedersenCommitment(changeCv))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create Pedersen commitment for change note");

        CBulletproofRangeProof changeProof;
        if (!CreateBulletproofRangeProof(changeNote.nValue, changeNote.vchBlind, changeCv, changeProof))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create range proof for change note");

        CShieldedOutputDescription changeOutput;
        changeOutput.cv = changeCv;
        changeOutput.cmu = changeNote.GetCommitment();
        changeOutput.rangeProof = changeProof;

        EncryptShieldedNote(changeNote, zAddr, changeOutput.vchEphemeralKey, changeOutput.vchEncCiphertext);
        EncryptShieldedNoteForSender(changeNote, sk.ovk, changeCv.GetHash(), changeOutput.cmu,
                                      changeOutput.vchEphemeralKey, changeOutput.vchOutCiphertext);

        txNew.vShieldedOutput.push_back(changeOutput);
        vOutputBlinds.push_back(changeNote.vchBlind);
    }

    CBitcoinAddress destAddr(strToAddr);
    if (!destAddr.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid destination address");

    CScript scriptPubKey;
    scriptPubKey.SetDestination(destAddr.Get());
    txNew.vout.push_back(CTxOut(nAmount, scriptPubKey));

    {
        uint256 spendSighash = txNew.GetBindingSigHash();
        for (size_t i = 0; i < txNew.vShieldedSpend.size(); i++)
        {
            if (!CreateSpendAuthSignature(sk.skSpend, spendSighash,
                                           txNew.vShieldedSpend[i].vchRk,
                                           txNew.vShieldedSpend[i].vchSpendAuthSig))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create spend auth signature");
        }
    }

    uint256 sighash = txNew.GetBindingSigHash();
    if (!FinalizeShieldedSpendBindings(txNew.vShieldedSpend, vSpendValues, vSpendBlinds, sighash,
                                       nCurrentHeight + 1 >= FORK_HEIGHT_NULLIFIER_BINDING))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create shielded nullifier binding proof");
    CBindingSignature bindingSig;
    CreateBindingSignature(vInputBlinds, vOutputBlinds, sighash, bindingSig);
    txNew.bindingSig.bindingSig = bindingSig;

    CWalletTx wtxNew(pwalletMain, txNew);
    CReserveKey reservekey(pwalletMain);

    if (!pwalletMain->CommitTransaction(wtxNew, reservekey))
    {
        LOCK(pwalletMain->cs_shielded);
        for (size_t i = 0; i < vSelectedIndices.size(); i++)
            pwalletMain->vShieldedNotes[vSelectedIndices[i]].fSpent = false;
        {
            CWalletDB walletdb(pwalletMain->strWalletFile);
            for (size_t i = 0; i < vSelectedIndices.size(); i++)
            {
                const CWallet::CShieldedWalletNote& sn = pwalletMain->vShieldedNotes[vSelectedIndices[i]];
                walletdb.WriteShieldedNoteSpent(sn.txhash, sn.nPosition, false);
            }
        }
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to commit unshield transaction");
    }
    Object result;
    result.push_back(Pair("txid", wtxNew.GetHash().GetHex()));
    result.push_back(Pair("from_zaddress", ShieldedAddressToString(zAddr)));
    result.push_back(Pair("to_address", strToAddr));
    result.push_back(Pair("amount", ValueFromAmount(nAmount)));
    result.push_back(Pair("fee", ValueFromAmount(nFee)));
    result.push_back(Pair("change", ValueFromAmount(nChange)));
    result.push_back(Pair("spends", (int)wtxNew.vShieldedSpend.size()));
    result.push_back(Pair("outputs", (int)wtxNew.vShieldedOutput.size()));
    result.push_back(Pair("proof_system", fUseFCMP ? "FCMP++ (Bulletproofs + Curve Tree)" : "Bulletproofs++ (Pedersen + secp256k1)"));
    result.push_back(Pair("tx_version", (int)wtxNew.nVersion));

    return result;

    } // end try
    catch (...)
    {
        {
            LOCK(pwalletMain->cs_shielded);
            for (size_t i = 0; i < vSelectedIndices.size(); i++)
                pwalletMain->vShieldedNotes[vSelectedIndices[i]].fSpent = false;
            {
                CWalletDB walletdb(pwalletMain->strWalletFile);
                for (size_t i = 0; i < vSelectedIndices.size(); i++)
                {
                    const CWallet::CShieldedWalletNote& sn = pwalletMain->vShieldedNotes[vSelectedIndices[i]];
                    walletdb.WriteShieldedNoteSpent(sn.txhash, sn.nPosition, false);
                }
            }
        }
        throw; // re-throw the original exception
    }
}

Value z_send(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 4)
        throw runtime_error(
            "z_send <fromaddress> <toaddress> <amount> [privacymode=7]\n"
            "Send from a shielded address to any address with selectable privacy.\n"
            "\nprivacymode is a 3-bit value (0-7):\n"
            "  Bit 0 (1): Hide sender (Lelantus proof)\n"
            "  Bit 1 (2): Hide receiver (encrypted output)\n"
            "  Bit 2 (4): Hide amount (range proof)\n"
            "\nMode 0: Fully transparent  Mode 7: Fully private (default)\n"
            "Mode 1: Hidden sender      Mode 4: Hidden amount\n"
            "Mode 3: Hidden parties      Mode 5: Hidden sender+amount\n");

    RequireLegacyPrivacyCreationEnabled();

    EnsureWalletIsUnlocked();

    if (!CZKContext::IsInitialized())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "ZK proof context not initialized");

    int nCurrentHeight = pindexBest ? pindexBest->nHeight : 0;
    if (nCurrentHeight < FORK_HEIGHT_DSP)
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("DSP not active until height %d", FORK_HEIGHT_DSP));

    string strFromAddr = params[0].get_str();
    string strToAddr = params[1].get_str();
    int64_t nAmount = AmountFromValue(params[2]);

    uint8_t nMode = PRIVACY_MODE_FULL;
    if (params.size() >= 4)
        nMode = (uint8_t)params[3].get_int();

    if (nMode > PRIVACY_MODE_MASK)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Privacy mode must be 0-7");
    if (nAmount <= 0 || nAmount > MAX_MONEY)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");

    bool fHideSender   = DSP_HideSender(nMode);
    bool fHideReceiver = DSP_HideReceiver(nMode);
    bool fHideAmount   = DSP_HideAmount(nMode);

    CShieldedPaymentAddress zFromAddr;
    if (!StringToShieldedAddress(strFromAddr, zFromAddr))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "From address must be a shielded address");

    bool fToShielded = false;
    CShieldedPaymentAddress zToAddr;
    CBitcoinAddress tToAddr;
    CScript destScript;

    if (StringToShieldedAddress(strToAddr, zToAddr))
    {
        fToShielded = true;
    }
    else
    {
        tToAddr = CBitcoinAddress(strToAddr);
        if (!tToAddr.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid destination address");
        destScript.SetDestination(tToAddr.Get());
    }

    ShieldedSpendabilityContext spendability = BuildShieldedSpendabilityContext(nCurrentHeight);

    int64_t nAvailable = 0;
    int64_t nPending = 0;
    vector<size_t> vSelectedIndices;
    vector<CWallet::CShieldedWalletNote> vSelectedNotes;
    CShieldedSpendingKey sk;
    CShieldedFullViewingKey fvk;

    {
        LOCK(pwalletMain->cs_shielded);
        if (!pwalletMain->HaveShieldedSpendingKey(zFromAddr))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or unknown shielded address");

        for (size_t i = 0; i < pwalletMain->vShieldedNotes.size(); i++)
        {
            CWallet::CShieldedWalletNote& wnote = pwalletMain->vShieldedNotes[i];
            if (!wnote.fSpent && wnote.note.addr == zFromAddr)
            {
                ShieldedNoteSpendability noteStatus = GetShieldedNoteSpendability(wnote, spendability);
                if (!noteStatus.fSpendable)
                {
                    nPending += wnote.note.nValue;
                    continue;
                }

                nAvailable += wnote.note.nValue;
                vSelectedIndices.push_back(i);
                if (nAvailable >= nAmount + MIN_TX_FEE_SHIELDED)
                    break;
            }
        }

        if (nAvailable < nAmount + MIN_TX_FEE_SHIELDED)
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                FormatShieldedSpendabilityError(spendability, nAvailable, nPending,
                                                nAmount + MIN_TX_FEE_SHIELDED));

        sk = pwalletMain->mapShieldedSpendingKeys[zFromAddr];
        DeriveShieldedFullViewingKey(sk, fvk);

        {
            CWalletDB walletdb(pwalletMain->strWalletFile);
            for (size_t idx : vSelectedIndices)
            {
                const CWallet::CShieldedWalletNote& sn = pwalletMain->vShieldedNotes[idx];
                if (!walletdb.WriteShieldedNoteSpent(sn.txhash, sn.nPosition, true))
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to persist note spent flag");
            }
        }

        for (size_t idx : vSelectedIndices)
        {
            pwalletMain->vShieldedNotes[idx].fSpent = true;
            vSelectedNotes.push_back(pwalletMain->vShieldedNotes[idx]);
        }
    }

    try
    {

    CTransaction txNew;
    bool fUseFCMP = (nCurrentHeight >= FORK_HEIGHT_FCMP_VALIDATION);
    txNew.nVersion = fUseFCMP ? SHIELDED_TX_VERSION_FCMP : SHIELDED_TX_VERSION_DSP_PROTOTYPE;
    txNew.nTime = GetAdjustedTime();
    txNew.nPrivacyMode = nMode;

    vector<vector<unsigned char>> vInputBlinds;
    vector<int64_t> vSpendValues;
    vector<vector<unsigned char>> vSpendBlinds;

    for (size_t i = 0; i < vSelectedNotes.size(); i++)
    {
        CWallet::CShieldedWalletNote& wnote = vSelectedNotes[i];
        CShieldedSpendDescription spend;

        if (wnote.note.vchBlind.empty())
            wnote.note.GenerateBlindingFactor();

        if (!wnote.note.GetPedersenCommitment(spend.cv))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create spend commitment");

        if (fHideAmount)
        {
            if (!CreateBulletproofRangeProof(wnote.note.nValue, wnote.note.vchBlind, spend.cv, spend.rangeProof))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create spend range proof");
            spend.nPlaintextValue = -1;
        }
        else
        {
            spend.nPlaintextValue = wnote.note.nValue;
            spend.vchPlaintextBlind = wnote.note.vchBlind;
        }

        if (!ApplyShieldedSpendNullifier(spend, wnote.note, fvk.nk,
                nCurrentHeight + 1 >= FORK_HEIGHT_NULLIFIER_BINDING))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to set shielded spend nullifier");

        if (fHideSender)
        {
            CTxDB txdb("r");
            CIncrementalMerkleTree tree;

            int nAnchorHeight = nCurrentHeight - MIN_SHIELDED_SPEND_DEPTH;
            if (nAnchorHeight < 0) nAnchorHeight = 0;
            CBlockIndex* pAnchorBlock = FindBlockByHeight(nAnchorHeight);
            if (pAnchorBlock)
            {
                CIncrementalMerkleTree oldTree;
                if (txdb.ReadShieldedTreeAtBlock(pAnchorBlock->GetBlockHash(), oldTree))
                    tree = oldTree;
                else
                    throw JSONRPCError(RPC_DATABASE_ERROR,
                        "Missing shielded-tree anchor snapshot; reindex/resync required");
            }
            else
            {
                if (!txdb.ReadShieldedTree(tree))
                    throw JSONRPCError(RPC_DATABASE_ERROR,
                        "Missing current shielded tree; reindex/resync required");
            }
            spend.anchor = tree.Root();

            vector<CPedersenCommitment> vAllCommitments;
            uint64_t nGlobalOutputIndex = 0;
            std::string strSampleError;
            if (!txdb.ReadBoundedLelantusCommitments(
                    spend.cv, vAllCommitments, nGlobalOutputIndex,
                    strSampleError))
                throw JSONRPCError(RPC_DATABASE_ERROR,
                    strprintf("Unable to sample shielded commitments: %s; "
                              "reindex/resync may be required",
                              strSampleError.c_str()));

            CAnonymitySet anonSet;
            if (!BuildAnonymitySet(spend.cv, vAllCommitments, spend.anchor,
                                    nCurrentHeight, anonSet))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to build Lelantus anonymity set");

            int nRealIndex = anonSet.FindIndex(spend.cv);
            if (nRealIndex < 0)
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Own commitment not found in Lelantus anonymity set");

            CLelantusProof lelantusProof;
            int64_t nSerialIdx = (nCurrentHeight >= FORK_HEIGHT_SERIAL_V2)
                ? (int64_t)nGlobalOutputIndex : -1;
            uint256 serial = ComputeLelantusSerial(sk.skSpend, wnote.note.rho, spend.cv, nSerialIdx);

            if (!CreateLelantusProof(anonSet, nRealIndex, wnote.note.nValue,
                                      wnote.note.vchBlind, serial, lelantusProof))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create Lelantus proof");

            spend.vchLelantusProof = lelantusProof.vchProof;
            spend.lelantusSerial = serial;
            spend.vAnonSet = anonSet.vCommitments;
        }
        else
        {
            CTxDB txdb("r");
            CIncrementalMerkleTree tree;
            int nAnchorHeight = nCurrentHeight - MIN_SHIELDED_SPEND_DEPTH;
            if (nAnchorHeight < 0) nAnchorHeight = 0;
            CBlockIndex* pAnchorBlock = FindBlockByHeight(nAnchorHeight);
            if (pAnchorBlock)
            {
                CIncrementalMerkleTree oldTree;
                if (txdb.ReadShieldedTreeAtBlock(pAnchorBlock->GetBlockHash(), oldTree))
                    tree = oldTree;
                else
                    throw JSONRPCError(RPC_DATABASE_ERROR,
                        "Missing shielded-tree anchor snapshot; reindex/resync required");
            }
            else
            {
                if (!txdb.ReadShieldedTree(tree))
                    throw JSONRPCError(RPC_DATABASE_ERROR,
                        "Missing current shielded tree; reindex/resync required");
            }
            spend.anchor = tree.Root();
            int64_t nSerialIdx2 = -1;
            if (nCurrentHeight >= FORK_HEIGHT_SERIAL_V2)
            {
                uint64_t nIndexed = 0;
                CPedersenCommitment indexedCommitment;
                if (!txdb.ReadShieldedCommitmentIndex(spend.cv.vchCommitment, nIndexed) ||
                    nIndexed > (uint64_t)std::numeric_limits<int64_t>::max() ||
                    !txdb.ReadShieldedCommitment(nIndexed, indexedCommitment) ||
                    !(indexedCommitment == spend.cv))
                    throw JSONRPCError(RPC_DATABASE_ERROR,
                        "Shielded commitment reverse index is missing/corrupt; "
                        "reindex/resync required");
                nSerialIdx2 = (int64_t)nIndexed;
            }
            spend.lelantusSerial = ComputeLelantusSerial(sk.skSpend, wnote.note.rho, spend.cv, nSerialIdx2);
        }

        if (fUseFCMP)
        {
            if (!spendability.fHasFCMPTree || spendability.fcmpTree.IsEmpty())
                throw JSONRPCError(RPC_INTERNAL_ERROR,
                    spendability.strFCMPError.empty() ? "Curve tree is empty, cannot create FCMP proof"
                                                      : spendability.strFCMPError);

            int64_t nLeafIdx = spendability.fcmpTree.FindLeafIndex(spend.cv);
            if (nLeafIdx < 0)
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Spend %d commitment not found in curve tree", (int)i));

            // Retired: no membership proof can be built for a legacy
            // shielded spend, and consensus rejects one without a proof.
            throw JSONRPCError(RPC_INVALID_REQUEST,
                               "legacy shielded spends are retired: the in-tree path-proof layer has been removed");

            spend.curveTreeRoot = spendability.hashFCMPRoot;

            if (fDebug)
                printf("z_send: created FCMP proof for spend %d (leaf index %lld, tree size %llu)\n",
                       (int)i, (long long)nLeafIdx,
                       (unsigned long long)spendability.fcmpTree.nLeafCount);
        }

        txNew.vShieldedSpend.push_back(spend);
        vInputBlinds.push_back(wnote.note.vchBlind);
        vSpendValues.push_back(wnote.note.nValue);
        vSpendBlinds.push_back(wnote.note.vchBlind);
    }

    int64_t nChange = nAvailable - nAmount - MIN_TX_FEE_SHIELDED;
    vector<vector<unsigned char>> vOutputBlinds;

    if (fToShielded)
    {
        txNew.nValueBalance = MIN_TX_FEE_SHIELDED;

        CShieldedNote outNote;
        outNote.addr = zToAddr;
        outNote.nValue = nAmount;

        unsigned char rnd[32];
        if (RAND_bytes(rnd, 32) != 1)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate randomness");
        memcpy(outNote.rho.begin(), rnd, 32);
        if (RAND_bytes(rnd, 32) != 1)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate randomness");
        memcpy(outNote.rcm.begin(), rnd, 32);
        OPENSSL_cleanse(rnd, 32);
        if (!outNote.GenerateBlindingFactor())
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate blinding factor");

        CPedersenCommitment outCv;
        if (!outNote.GetPedersenCommitment(outCv))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create output commitment");

        CShieldedOutputDescription output;
        output.cv = outCv;
        output.cmu = outNote.GetCommitment();

        if (fHideAmount)
        {
            CBulletproofRangeProof outProof;
            if (!CreateBulletproofRangeProof(outNote.nValue, outNote.vchBlind, outCv, outProof))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create output range proof");
            output.rangeProof = outProof;
            output.nPlaintextValue = -1;
        }
        else
        {
            output.nPlaintextValue = outNote.nValue;
            output.vchPlaintextBlind = outNote.vchBlind;
        }

        if (!EncryptShieldedNote(outNote, zToAddr, output.vchEphemeralKey, output.vchEncCiphertext))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to encrypt output note");
        if (!EncryptShieldedNoteForSender(outNote, sk.ovk, outCv.GetHash(), output.cmu,
                                          output.vchEphemeralKey, output.vchOutCiphertext))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to encrypt output note for sender");
        if (!fHideReceiver)
            SetPublicShieldedRecipient(output, zToAddr);

        txNew.vShieldedOutput.push_back(output);
        vOutputBlinds.push_back(outNote.vchBlind);
    }
    else
    {
        txNew.nValueBalance = nAmount + MIN_TX_FEE_SHIELDED;
        txNew.vout.push_back(CTxOut(nAmount, destScript));
    }

    if (nChange > 0)
    {
        CShieldedNote changeNote;
        changeNote.addr = zFromAddr;
        changeNote.nValue = nChange;

        unsigned char rnd[32];
        if (RAND_bytes(rnd, 32) != 1)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate randomness for change");
        memcpy(changeNote.rho.begin(), rnd, 32);
        if (RAND_bytes(rnd, 32) != 1)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate randomness for change");
        memcpy(changeNote.rcm.begin(), rnd, 32);
        OPENSSL_cleanse(rnd, 32);
        if (!changeNote.GenerateBlindingFactor())
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate blinding factor for change");

        CPedersenCommitment changeCv;
        if (!changeNote.GetPedersenCommitment(changeCv))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create change commitment");

        CShieldedOutputDescription changeOutput;
        changeOutput.cv = changeCv;
        changeOutput.cmu = changeNote.GetCommitment();

        if (fHideAmount)
        {
            CBulletproofRangeProof changeProof;
            if (!CreateBulletproofRangeProof(changeNote.nValue, changeNote.vchBlind, changeCv, changeProof))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create change range proof");
            changeOutput.rangeProof = changeProof;
            changeOutput.nPlaintextValue = -1;
        }
        else
        {
            changeOutput.nPlaintextValue = changeNote.nValue;
            changeOutput.vchPlaintextBlind = changeNote.vchBlind;
        }

        if (!EncryptShieldedNote(changeNote, zFromAddr, changeOutput.vchEphemeralKey, changeOutput.vchEncCiphertext))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to encrypt change note");
        if (!EncryptShieldedNoteForSender(changeNote, sk.ovk, changeCv.GetHash(), changeOutput.cmu,
                                          changeOutput.vchEphemeralKey, changeOutput.vchOutCiphertext))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to encrypt change note for sender");
        if (!fHideSender && !fHideReceiver)
            SetPublicShieldedRecipient(changeOutput, zFromAddr);

        txNew.vShieldedOutput.push_back(changeOutput);
        vOutputBlinds.push_back(changeNote.vchBlind);
    }

    {
        uint256 spendSighash = txNew.GetBindingSigHash();
        for (size_t i = 0; i < txNew.vShieldedSpend.size(); i++)
        {
            if (!CreateSpendAuthSignature(sk.skSpend, spendSighash,
                                           txNew.vShieldedSpend[i].vchRk,
                                           txNew.vShieldedSpend[i].vchSpendAuthSig))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create spend auth signature");
        }
    }

    uint256 sighash = txNew.GetBindingSigHash();
    if (!FinalizeShieldedSpendBindings(txNew.vShieldedSpend, vSpendValues, vSpendBlinds, sighash,
                                       nCurrentHeight + 1 >= FORK_HEIGHT_NULLIFIER_BINDING))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create shielded nullifier binding proof");
    CBindingSignature bindSig;
    CreateBindingSignature(vInputBlinds, vOutputBlinds, sighash, bindSig);
    txNew.bindingSig.bindingSig = bindSig;

    CWalletTx wtxNew(pwalletMain, txNew);
    CReserveKey reservekey(pwalletMain);

    if (!pwalletMain->CommitTransaction(wtxNew, reservekey))
    {
        LOCK(pwalletMain->cs_shielded);
        for (size_t i = 0; i < vSelectedIndices.size(); i++)
            pwalletMain->vShieldedNotes[vSelectedIndices[i]].fSpent = false;
        {
            CWalletDB walletdb(pwalletMain->strWalletFile);
            for (size_t i = 0; i < vSelectedIndices.size(); i++)
            {
                const CWallet::CShieldedWalletNote& sn = pwalletMain->vShieldedNotes[vSelectedIndices[i]];
                walletdb.WriteShieldedNoteSpent(sn.txhash, sn.nPosition, false);
            }
        }
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to commit DSP transaction");
    }

    Object result;
    result.push_back(Pair("txid", wtxNew.GetHash().GetHex()));
    result.push_back(Pair("privacy_mode", (int)nMode));
    result.push_back(Pair("hide_sender", fHideSender));
    result.push_back(Pair("hide_receiver", fHideReceiver));
    result.push_back(Pair("hide_amount", fHideAmount));
    result.push_back(Pair("amount", ValueFromAmount(nAmount)));
    result.push_back(Pair("fee", ValueFromAmount(MIN_TX_FEE_SHIELDED)));
    result.push_back(Pair("spends", (int)wtxNew.vShieldedSpend.size()));
    result.push_back(Pair("outputs", (int)wtxNew.vShieldedOutput.size()));

    return result;

    }
    catch (...)
    {
        {
            LOCK(pwalletMain->cs_shielded);
            for (size_t i = 0; i < vSelectedIndices.size(); i++)
                pwalletMain->vShieldedNotes[vSelectedIndices[i]].fSpent = false;
            {
                CWalletDB walletdb(pwalletMain->strWalletFile);
                for (size_t i = 0; i < vSelectedIndices.size(); i++)
                {
                    const CWallet::CShieldedWalletNote& sn = pwalletMain->vShieldedNotes[vSelectedIndices[i]];
                    walletdb.WriteShieldedNoteSpent(sn.txhash, sn.nPosition, false);
                }
            }
        }
        throw;
    }
}

Value z_listunspent(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "z_listunspent\n"
            "Returns array of unspent shielded notes.\n");

    Array results;
    int nCurrentHeight = pindexBest ? pindexBest->nHeight : 0;
    ShieldedSpendabilityContext spendability = BuildShieldedSpendabilityContext(nCurrentHeight);

    LOCK(pwalletMain->cs_shielded);
    for (const CWallet::CShieldedWalletNote& wnote : pwalletMain->vShieldedNotes)
    {
        if (wnote.fSpent)
            continue;

        ShieldedNoteSpendability noteStatus = GetShieldedNoteSpendability(wnote, spendability);

        Object entry;
        entry.push_back(Pair("txid", wnote.txhash.GetHex()));
        entry.push_back(Pair("amount", ValueFromAmount(wnote.note.nValue)));
        entry.push_back(Pair("address", ShieldedAddressToString(wnote.note.addr)));
        entry.push_back(Pair("height", wnote.nHeight));
        entry.push_back(Pair("confirmations", noteStatus.nConfirmations));
        entry.push_back(Pair("minconf_spendable", noteStatus.fMinConfSpendable));
        entry.push_back(Pair("fcmp_spendable", noteStatus.fFCMPSpendable));
        entry.push_back(Pair("spendable", noteStatus.fSpendable));
        entry.push_back(Pair("pending_reason", noteStatus.strPendingReason));
        results.push_back(entry);
    }
    return results;
}

Value z_validateaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "z_validateaddress <zaddress>\n"
            "Return information about the given shielded address.\n");

    string strAddr = params[0].get_str();
    CShieldedPaymentAddress addr;
    bool fValid = StringToShieldedAddress(strAddr, addr);

    Object ret;
    ret.push_back(Pair("isvalid", fValid));
    if (fValid)
    {
        ret.push_back(Pair("address", strAddr));
        LOCK(pwalletMain->cs_shielded);
        ret.push_back(Pair("ismine", pwalletMain->HaveShieldedSpendingKey(addr)));
        ret.push_back(Pair("iswatchonly", !pwalletMain->HaveShieldedSpendingKey(addr) &&
                                           pwalletMain->HaveShieldedViewingKey(addr)));
    }
    return ret;
}

Value z_exportkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "z_exportkey <zaddress>\n"
            "Reveals the spending key corresponding to 'zaddress'.\n");

    EnsureWalletIsUnlocked();

    string strAddr = params[0].get_str();
    CShieldedPaymentAddress addr;
    if (!StringToShieldedAddress(strAddr, addr))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid shielded address");

    LOCK(pwalletMain->cs_shielded);
    if (!pwalletMain->HaveShieldedSpendingKey(addr))
        throw JSONRPCError(RPC_WALLET_ERROR, "Spending key for this address is not available");

    const CShieldedSpendingKey& sk = pwalletMain->mapShieldedSpendingKeys[addr];
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << sk;
    vector<unsigned char> vch(ss.begin(), ss.end());
    std::string strEncoded = EncodeBase58Check(vch);
    OPENSSL_cleanse(&vch[0], vch.size());
    if (ss.size() > 0)
        OPENSSL_cleanse(&ss[0], ss.size());
    return strEncoded;
}

Value z_importkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "z_importkey <key>\n"
            "Adds a shielded spending key to the wallet.\n");

    EnsureWalletIsUnlocked();

    string strKey = params[0].get_str();
    vector<unsigned char> vch;
    if (!DecodeBase58Check(strKey, vch))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid spending key encoding");

    CShieldedSpendingKey sk;
    try
    {
        CDataStream ss(vch, SER_NETWORK, PROTOCOL_VERSION);
        ss >> sk;
    }
    catch (...)
    {
        if (!vch.empty()) OPENSSL_cleanse(&vch[0], vch.size());
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid spending key data");
    }
    if (!vch.empty()) OPENSSL_cleanse(&vch[0], vch.size());

    CShieldedFullViewingKey fvk;
    DeriveShieldedFullViewingKey(sk, fvk);
    CShieldedIncomingViewingKey ivk;
    DeriveShieldedIncomingViewingKey(fvk, ivk);

    vector<unsigned char> d;
    GenerateShieldedDiversifier(d);
    CShieldedPaymentAddress addr;
    DeriveShieldedPaymentAddress(ivk, d, addr);

    LOCK(pwalletMain->cs_shielded);
    pwalletMain->AddShieldedSpendingKey(addr, sk);

    return ShieldedAddressToString(addr);
}

Value z_exportviewingkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "z_exportviewingkey <zaddress>\n"
            "Reveals the incoming viewing key corresponding to 'zaddress'.\n");

    EnsureWalletIsUnlocked();

    string strAddr = params[0].get_str();
    CShieldedPaymentAddress addr;
    if (!StringToShieldedAddress(strAddr, addr))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid shielded address");

    LOCK(pwalletMain->cs_shielded);
    if (!pwalletMain->HaveShieldedViewingKey(addr))
        throw JSONRPCError(RPC_WALLET_ERROR, "Viewing key for this address is not available");

    const CShieldedIncomingViewingKey& ivk = pwalletMain->mapShieldedViewingKeys[addr];
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << ivk;
    vector<unsigned char> vch(ss.begin(), ss.end());
    string strResult = EncodeBase58Check(vch);
    OPENSSL_cleanse(vch.data(), vch.size());
    return strResult;
}

Value z_importviewingkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "z_importviewingkey <key>\n"
            "Adds a shielded incoming viewing key (watch-only) to the wallet.\n");

    string strKey = params[0].get_str();
    vector<unsigned char> vch;
    if (!DecodeBase58Check(strKey, vch))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid viewing key encoding");

    CShieldedIncomingViewingKey ivk;
    try
    {
        CDataStream ss(vch, SER_NETWORK, PROTOCOL_VERSION);
        ss >> ivk;
    }
    catch (...)
    {
        OPENSSL_cleanse(vch.data(), vch.size());
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid viewing key data");
    }
    OPENSSL_cleanse(vch.data(), vch.size());

    vector<unsigned char> d;
    GenerateShieldedDiversifier(d);
    CShieldedPaymentAddress addr;
    DeriveShieldedPaymentAddress(ivk, d, addr);

    LOCK(pwalletMain->cs_shielded);
    pwalletMain->AddShieldedViewingKey(addr, ivk);

    return ShieldedAddressToString(addr);
}

Value z_shieldall(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "z_shieldall [fromaddress] [maxinputs]\n"
            "Moves transparent coins into the IV5 private pool.\n"
            "\nSweeps only one transparent address per call, so a single transaction never\n"
            "groups addresses the chain has not already grouped. Omit fromaddress to shield\n"
            "the address holding the most value. The whole selected value moves: there is no\n"
            "transparent change output.\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\": \"...\",        (string) the shield transaction\n"
            "  \"address\": \"...\",     (string) the transparent address swept\n"
            "  \"inputs\": n,          (numeric) outputs consumed\n"
            "  \"shielded\": x.xxx,    (numeric) value moved into the pool\n"
            "  \"remaining\": n        (numeric) outputs still unshielded at that address\n"
            "}\n");

    // The transaction being built lands in the next block, so gate on the height it
    // would occupy. Gating on the tip refuses a transaction consensus would accept in
    // the activation block itself.
    if (!IsBoundaryBActiveAtHeight(pindexBest ? pindexBest->nHeight + 1 : 0) ||
        !IsShieldedVNextConsensusReady())
        throw JSONRPCError(RPC_INVALID_REQUEST,
                           "the IV5 pool is not active on this network yet");

    EnsureWalletIsUnlocked();

    std::string strFrom;
    if (params.size() > 0)
        strFrom = params[0].get_str();
    size_t nMaxInputs = PRIVACY_VNEXT_SHIELD_MAX_INPUTS;
    if (params.size() > 1)
    {
        const int64_t nRequested = params[1].get_int64();
        if (nRequested < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "maxinputs must be at least one");
        nMaxInputs = (size_t)nRequested;
    }

    // No address given: sweep the one holding the most.
    if (strFrom.empty())
    {
        std::map<std::string, int64_t> mapByAddress;
        std::vector<COutput> vCoins;
        pwalletMain->AvailableCoins(vCoins, true);
        for (size_t i = 0; i < vCoins.size(); ++i)
        {
            if (!vCoins[i].fSpendable)
                continue;
            CTxDestination dest;
            if (!ExtractDestination(vCoins[i].tx->vout[vCoins[i].i].scriptPubKey, dest))
                continue;
            mapByAddress[CBitcoinAddress(dest).ToString()] +=
                vCoins[i].tx->vout[vCoins[i].i].nValue;
        }
        int64_t nBest = 0;
        for (std::map<std::string, int64_t>::const_iterator it = mapByAddress.begin();
             it != mapByAddress.end(); ++it)
        {
            if (it->second > nBest)
            {
                nBest = it->second;
                strFrom = it->first;
            }
        }
        if (strFrom.empty())
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                               "no spendable transparent outputs to shield");
    }

    CWalletTx wtx;
    int64_t nShielded = 0;
    size_t nInputs = 0;
    std::string strError;
    if (!pwalletMain->CreatePrivacyVNextShield(strFrom, nMaxInputs, true, wtx,
                                               nShielded, nInputs, strError))
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    // Report what is left at that address so a caller can loop until it reaches zero.
    int64_t nRemaining = 0;
    {
        CBitcoinAddress addr(strFrom);
        CScript scriptFrom;
        scriptFrom.SetDestination(addr.Get());
        std::vector<COutput> vCoins;
        pwalletMain->AvailableCoins(vCoins, true);
        for (size_t i = 0; i < vCoins.size(); ++i)
        {
            if (vCoins[i].fSpendable &&
                vCoins[i].tx->vout[vCoins[i].i].scriptPubKey == scriptFrom)
                ++nRemaining;
        }
    }

    Object result;
    result.push_back(Pair("txid", wtx.GetHash().GetHex()));
    result.push_back(Pair("address", strFrom));
    result.push_back(Pair("inputs", (int64_t)nInputs));
    result.push_back(Pair("shielded", ValueFromAmount(nShielded)));
    result.push_back(Pair("remaining", (int64_t)nRemaining));
    return result;
}

// One transparent address and what a migration still has to do about it.
struct PoolMigrationCandidate
{
    std::string strAddress;
    int64_t nSelectable;   // value the next shield from this address would carry
    int64_t nTotal;        // spendable value sitting at the address
    int64_t nOutputs;
};

// Grouped by script, since the shield builder selects on script equality. Re-derived from
// spendable outputs before every transaction, so an interrupted run resumes without a cursor.
static void SurveyPoolMigration(size_t nMaxInputs,
                                std::vector<PoolMigrationCandidate>& vCandidatesOut,
                                int64_t& nUnaddressedOutputsOut,
                                int64_t& nUnaddressedValueOut)
{
    vCandidatesOut.clear();
    nUnaddressedOutputsOut = 0;
    nUnaddressedValueOut = 0;

    std::map<CScript, std::vector<int64_t> > mapByScript;
    std::vector<COutput> vCoins;
    pwalletMain->AvailableCoins(vCoins, true);
    for (size_t i = 0; i < vCoins.size(); ++i)
    {
        if (!vCoins[i].fSpendable)
            continue;
        const CTxOut& out = vCoins[i].tx->vout[vCoins[i].i];
        mapByScript[out.scriptPubKey].push_back(out.nValue);
    }

    for (std::map<CScript, std::vector<int64_t> >::iterator it = mapByScript.begin();
         it != mapByScript.end(); ++it)
    {
        int64_t nTotal = 0;
        for (size_t i = 0; i < it->second.size(); ++i)
            nTotal += it->second[i];

        // Scripts that do not round-trip through an address (cold-stake, bare pubkey) cannot be
        // built from; counted and reported, not dropped.
        CTxDestination dest;
        CScript scriptRoundTrip;
        if (ExtractDestination(it->first, dest))
            scriptRoundTrip.SetDestination(dest);
        if (scriptRoundTrip != it->first)
        {
            nUnaddressedOutputsOut += (int64_t)it->second.size();
            nUnaddressedValueOut += nTotal;
            continue;
        }

        // Largest first, matching the builder's selection.
        std::vector<int64_t> vValues = it->second;
        std::sort(vValues.begin(), vValues.end(),
                  [](int64_t a, int64_t b) { return a > b; });
        if (vValues.size() > nMaxInputs)
            vValues.resize(nMaxInputs);

        PoolMigrationCandidate c;
        c.strAddress = CBitcoinAddress(dest).ToString();
        c.nSelectable = 0;
        for (size_t i = 0; i < vValues.size(); ++i)
            c.nSelectable += vValues[i];
        c.nTotal = nTotal;
        c.nOutputs = (int64_t)it->second.size();
        vCandidatesOut.push_back(c);
    }
}

Value z_migratetopool(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "z_migratetopool [maxtransactions] [maxinputspertx]\n"
            "Moves this wallet's transparent coins into the IV5 private pool.\n"
            "\nSends one transaction per transparent address, never one that spends from\n"
            "two, so the migration does not tell the chain which addresses share an owner.\n"
            "An address holding more outputs than one transaction can carry is swept over\n"
            "several, largest value first.\n"
            "\nBounded, not background: it sends at most maxtransactions (default 10) and\n"
            "returns. Nothing is remembered between calls -- the work left is read back off\n"
            "the wallet's own unspent outputs -- so calling again continues, and an\n"
            "interrupted run resumes with no recovery step. Drive it from a loop while\n"
            "\"more\" is true.\n"
            "\nAn address whose value does not cover the flat shield fee cannot be moved at\n"
            "all. It is skipped and reported under \"skipped\", never retried within a call,\n"
            "so a loop on \"more\" terminates instead of spinning on it.\n"
            "\nResult:\n"
            "{\n"
            "  \"sent\": n,                    (numeric) transactions sent by this call\n"
            "  \"transactions\": [             (array) one entry per transaction sent\n"
            "    {\"txid\":\"...\", \"address\":\"...\", \"inputs\":n, \"shielded\":x.xxx, \"fee\":x.xxx}\n"
            "  ],\n"
            "  \"shielded\": x.xxx,            (numeric) value moved into the pool\n"
            "  \"fees\": x.xxx,                (numeric) fees paid\n"
            "  \"addresses_remaining\": n,     (numeric) addresses another call would sweep\n"
            "  \"outputs_remaining\": n,       (numeric) their unspent outputs\n"
            "  \"value_remaining\": x.xxx,     (numeric) their value\n"
            "  \"unsweepable_addresses\": n,   (numeric) addresses no call can move\n"
            "  \"unsweepable_outputs\": n,     (numeric) their unspent outputs\n"
            "  \"unsweepable_value\": x.xxx,   (numeric) their value\n"
            "  \"unaddressed_outputs\": n,     (numeric) outputs no address names\n"
            "  \"unaddressed_value\": x.xxx,   (numeric) their value\n"
            "  \"skipped\": [                  (array) why each unsweepable address stayed\n"
            "    {\"address\":\"...\", \"outputs\":n, \"value\":x.xxx, \"reason\":\"...\"}\n"
            "  ],\n"
            "  \"more\": true|false,           (boolean) another call would send more\n"
            "  \"complete\": true|false        (boolean) nothing transparent is left at all\n"
            "}\n");

    // Gate on the next block's height, not the tip.
    if (!IsBoundaryBActiveAtHeight(pindexBest ? pindexBest->nHeight + 1 : 0) ||
        !IsShieldedVNextConsensusReady())
        throw JSONRPCError(RPC_INVALID_REQUEST,
                           "the IV5 pool is not active on this network yet");

    EnsureWalletIsUnlocked();

    // Builder precondition, checked once rather than failing per address.
    if (!pwalletMain->IsPrivacyVNextSeedUnlocked())
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "this wallet holds no unlocked IV5 seed; run z_createiv5seed first");

    size_t nMaxTxns = PRIVACY_VNEXT_MIGRATE_DEFAULT_TXNS;
    if (params.size() > 0)
    {
        const int64_t nRequested = params[0].get_int64();
        if (nRequested < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "maxtransactions must be at least one");
        if (nRequested > (int64_t)PRIVACY_VNEXT_MIGRATE_MAX_TXNS)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("maxtransactions is capped at %u so one call stays bounded",
                                         (unsigned)PRIVACY_VNEXT_MIGRATE_MAX_TXNS));
        nMaxTxns = (size_t)nRequested;
    }

    size_t nMaxInputs = PRIVACY_VNEXT_SHIELD_MAX_INPUTS;
    if (params.size() > 1)
    {
        const int64_t nRequested = params[1].get_int64();
        if (nRequested < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "maxinputspertx must be at least one");
        // Clamped as the builder clamps it.
        nMaxInputs = (size_t)std::min<int64_t>(nRequested,
                                               (int64_t)PRIVACY_VNEXT_SHIELD_MAX_INPUTS);
    }

    const int64_t nFee = MIN_TX_FEE_SHIELDED;

    Array arrSent;
    int64_t nMovedTotal = 0;
    int64_t nFeesTotal = 0;
    // A failed address is never retried in this call, so the loop terminates.
    std::map<std::string, std::string> mapGaveUp;

    while (arrSent.size() < nMaxTxns)
    {
        std::vector<PoolMigrationCandidate> vCandidates;
        int64_t nUnaddressedOutputs = 0;
        int64_t nUnaddressedValue = 0;
        SurveyPoolMigration(nMaxInputs, vCandidates, nUnaddressedOutputs, nUnaddressedValue);

        // Largest selectable value first.
        const PoolMigrationCandidate* pNext = NULL;
        for (size_t i = 0; i < vCandidates.size(); ++i)
        {
            // Strictly greater, matching the builder: a group worth exactly the fee is refused.
            if (vCandidates[i].nSelectable <= nFee)
                continue;
            if (mapGaveUp.count(vCandidates[i].strAddress))
                continue;
            if (!pNext || vCandidates[i].nSelectable > pNext->nSelectable)
                pNext = &vCandidates[i];
        }
        if (!pNext)
            break;

        const std::string strFrom = pNext->strAddress;
        CWalletTx wtx;
        int64_t nShielded = 0;
        size_t nInputs = 0;
        std::string strError;
        if (!pwalletMain->CreatePrivacyVNextShield(strFrom, nMaxInputs, true, wtx,
                                                   nShielded, nInputs, strError))
        {
            // A build failure skips the address without aborting the run.
            mapGaveUp[strFrom] = strError;
            continue;
        }

        nMovedTotal += nShielded;
        nFeesTotal += nFee;

        Object objTx;
        objTx.push_back(Pair("txid", wtx.GetHash().GetHex()));
        objTx.push_back(Pair("address", strFrom));
        objTx.push_back(Pair("inputs", (int64_t)nInputs));
        objTx.push_back(Pair("shielded", ValueFromAmount(nShielded)));
        objTx.push_back(Pair("fee", ValueFromAmount(nFee)));
        arrSent.push_back(objTx);
    }

    // Final survey: what a fresh call would act on.
    std::vector<PoolMigrationCandidate> vFinal;
    int64_t nUnaddressedOutputs = 0;
    int64_t nUnaddressedValue = 0;
    SurveyPoolMigration(nMaxInputs, vFinal, nUnaddressedOutputs, nUnaddressedValue);

    int64_t nAddrRemaining = 0, nOutRemaining = 0, nValueRemaining = 0;
    int64_t nStuckAddrs = 0, nStuckOutputs = 0, nStuckValue = 0;
    Array arrSkipped;
    std::set<std::string> setReported;
    for (size_t i = 0; i < vFinal.size(); ++i)
    {
        const PoolMigrationCandidate& c = vFinal[i];
        std::map<std::string, std::string>::const_iterator itGaveUp =
            mapGaveUp.find(c.strAddress);
        const bool fSweepable = c.nSelectable > nFee && itGaveUp == mapGaveUp.end();
        if (fSweepable)
        {
            ++nAddrRemaining;
            nOutRemaining += c.nOutputs;
            nValueRemaining += c.nTotal;
            continue;
        }
        ++nStuckAddrs;
        nStuckOutputs += c.nOutputs;
        nStuckValue += c.nTotal;
        setReported.insert(c.strAddress);

        Object objSkip;
        objSkip.push_back(Pair("address", c.strAddress));
        objSkip.push_back(Pair("outputs", c.nOutputs));
        objSkip.push_back(Pair("value", ValueFromAmount(c.nTotal)));
        objSkip.push_back(Pair("reason",
            itGaveUp != mapGaveUp.end()
                ? itGaveUp->second
                : strprintf("%s does not cover the %s shield fee",
                            FormatMoney(c.nSelectable).c_str(),
                            FormatMoney(nFee).c_str())));
        arrSkipped.push_back(objSkip);
    }

    // Report addresses whose build failed after inputs were marked spent; they no longer
    // appear in the survey.
    for (std::map<std::string, std::string>::const_iterator it = mapGaveUp.begin();
         it != mapGaveUp.end(); ++it)
    {
        if (setReported.count(it->first))
            continue;
        ++nStuckAddrs;
        Object objSkip;
        objSkip.push_back(Pair("address", it->first));
        objSkip.push_back(Pair("outputs", (int64_t)0));
        objSkip.push_back(Pair("value", ValueFromAmount(0)));
        objSkip.push_back(Pair("reason", it->second));
        arrSkipped.push_back(objSkip);
    }

    Object result;
    result.push_back(Pair("sent", (int64_t)arrSent.size()));
    result.push_back(Pair("transactions", arrSent));
    result.push_back(Pair("shielded", ValueFromAmount(nMovedTotal)));
    result.push_back(Pair("fees", ValueFromAmount(nFeesTotal)));
    result.push_back(Pair("addresses_remaining", nAddrRemaining));
    result.push_back(Pair("outputs_remaining", nOutRemaining));
    result.push_back(Pair("value_remaining", ValueFromAmount(nValueRemaining)));
    result.push_back(Pair("unsweepable_addresses", nStuckAddrs));
    result.push_back(Pair("unsweepable_outputs", nStuckOutputs));
    result.push_back(Pair("unsweepable_value", ValueFromAmount(nStuckValue)));
    result.push_back(Pair("unaddressed_outputs", nUnaddressedOutputs));
    result.push_back(Pair("unaddressed_value", ValueFromAmount(nUnaddressedValue)));
    result.push_back(Pair("skipped", arrSkipped));
    // "more": call again; "complete": nothing left, including fee-limited residue.
    result.push_back(Pair("more", nAddrRemaining > 0));
    result.push_back(Pair("complete",
                          nAddrRemaining == 0 && nStuckAddrs == 0 && nUnaddressedOutputs == 0));
    return result;
}

Value z_iv5transfer(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "z_iv5transfer <toaddress> <amount> [disclosure]\n"
            "Spends shielded notes to another IV5 address.\n"
            "\nNothing crosses the transparent boundary, so the transaction has no\n"
            "transparent input or output. Change returns to this wallet as a second\n"
            "note.\n"
            "\n<disclosure> is a three-bit mask; each SET bit hides that field. It\n"
            "defaults to 7, which reveals nothing. Clearing bit 1 publishes the\n"
            "spending authority of each note consumed, bit 2 the recipient address of\n"
            "each output, and bit 4 the amount of each output. Everything published\n"
            "is proved against what the transaction already commits to, so a\n"
            "disclosure cannot name a different address or amount.\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\": \"...\",             (string) the transfer transaction\n"
            "  \"amount\": x.xxx,           (numeric) value sent\n"
            "  \"fee\": x.xxx,              (numeric) fee paid\n"
            "  \"notes\": n,                (numeric) notes consumed\n"
            "  \"disclosure_mask\": n,      (numeric) the mask the payload declares\n"
            "  \"discloses_sender\": bool,  (boolean) spend authorities are published\n"
            "  \"discloses_receiver\": bool,(boolean) recipient addresses are published\n"
            "  \"discloses_amount\": bool   (boolean) output amounts are published\n"
            "}\n");

    // The transaction being built lands in the next block, so gate on the height it
    // would occupy. Gating on the tip refuses a transaction consensus would accept in
    // the activation block itself.
    if (!IsBoundaryBActiveAtHeight(pindexBest ? pindexBest->nHeight + 1 : 0) ||
        !IsShieldedVNextConsensusReady())
        throw JSONRPCError(RPC_INVALID_REQUEST,
                           "the IV5 pool is not active on this network yet");

    EnsureWalletIsUnlocked();

    const std::string strTo = params[0].get_str();
    const int64_t nAmount = AmountFromValue(params[1]);
    // Default: disclose nothing.
    int nDisclosure = iv5::WALLET_DEFAULT_DISCLOSURE_MASK;
    if (params.size() > 2)
    {
        nDisclosure = params[2].get_int();
        if (nDisclosure < 0 || nDisclosure > iv5::DISCLOSURE_MASK)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "disclosure must be a three-bit mask, 0 to 7");
    }
    const uint8_t nMask = (uint8_t)nDisclosure;

    CWalletTx wtx;
    int64_t nFee = 0;
    size_t nNotes = 0;
    std::string strError;
    if (!pwalletMain->CreatePrivacyVNextTransfer(strTo, nAmount, nMask, true,
                                                 wtx, nFee, nNotes, strError))
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    Object result;
    result.push_back(Pair("txid", wtx.GetHash().GetHex()));
    result.push_back(Pair("amount", ValueFromAmount(nAmount)));
    result.push_back(Pair("fee", ValueFromAmount(nFee)));
    result.push_back(Pair("notes", (int64_t)nNotes));
    PrivacyVNextDisclosureToJSON(nMask, result);
    return result;
}

Value z_iv5unshield(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "z_iv5unshield <toaddress> <amount>\n"
            "Spends shielded notes back out to a transparent address.\n"
            "\nThe amount and the receiving address are public, as they must be to\n"
            "land in a transparent output. Which notes paid for it is not, and any\n"
            "change stays in the pool.\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\": \"...\",     (string) the unshield transaction\n"
            "  \"address\": \"...\",  (string) the transparent address paid\n"
            "  \"amount\": x.xxx,   (numeric) value released from the pool\n"
            "  \"fee\": x.xxx,      (numeric) fee paid\n"
            "  \"notes\": n         (numeric) notes consumed\n"
            "}\n");

    // The transaction being built lands in the next block, so gate on the height it
    // would occupy. Gating on the tip refuses a transaction consensus would accept in
    // the activation block itself.
    if (!IsBoundaryBActiveAtHeight(pindexBest ? pindexBest->nHeight + 1 : 0) ||
        !IsShieldedVNextConsensusReady())
        throw JSONRPCError(RPC_INVALID_REQUEST,
                           "the IV5 pool is not active on this network yet");

    EnsureWalletIsUnlocked();

    const std::string strTo = params[0].get_str();
    const int64_t nAmount = AmountFromValue(params[1]);

    CWalletTx wtx;
    int64_t nFee = 0;
    size_t nNotes = 0;
    std::string strError;
    if (!pwalletMain->CreatePrivacyVNextUnshield(strTo, nAmount, true, wtx, nFee,
                                                 nNotes, strError))
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    Object result;
    result.push_back(Pair("txid", wtx.GetHash().GetHex()));
    result.push_back(Pair("address", strTo));
    result.push_back(Pair("amount", ValueFromAmount(nAmount)));
    result.push_back(Pair("fee", ValueFromAmount(nFee)));
    result.push_back(Pair("notes", (int64_t)nNotes));
    return result;
}

Value z_getshieldedinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "z_getshieldedinfo\n"
            "Returns an object containing shielded transaction information.\n");

    Object obj;

    int nCurrentHeight = pindexBest ? pindexBest->nHeight : 0;
    const bool fLegacyConsensusActive =
        nCurrentHeight >= FORK_HEIGHT_SHIELDED &&
        !IsLegacyPrivacyPolicyDisabled() &&
        !IsBoundaryAActiveAtHeight(nCurrentHeight);
    const bool fActive = fLegacyConsensusActive;
    PrivacyVNextAbiInfo vnextAbi;
    const bool fVNextAbiLinked = LoadPrivacyVNextAbiInfo(vnextAbi);
    const bool fVNextReady = IsShieldedVNextConsensusReady() &&
                             fVNextAbiLinked &&
                             vnextAbi.nConsensusActive != 0 &&
                             vnextAbi.nConsensusCapabilities != 0;

    obj.push_back(Pair("shielded_active", fActive));
    obj.push_back(Pair("legacy_shielded_consensus_active", fLegacyConsensusActive));
    obj.push_back(Pair("legacy_shielded_creation_enabled", fActive));
    obj.push_back(Pair("fork_height", FORK_HEIGHT_SHIELDED));
    obj.push_back(Pair("current_height", nCurrentHeight));
    obj.push_back(Pair("blocks_until_activation",
                       std::max(0, FORK_HEIGHT_SHIELDED - nCurrentHeight)));
    obj.push_back(Pair("boundary_a_activation_height", FORK_HEIGHT_BOUNDARY_A));
    obj.push_back(Pair("boundary_a_configured", IsBoundaryAConfigured()));
    obj.push_back(Pair("boundary_a_active", IsBoundaryAActiveAtHeight(nCurrentHeight)));
    obj.push_back(Pair("boundary_b_activation_height", FORK_HEIGHT_BOUNDARY_B));
    obj.push_back(Pair("boundary_b_configured", IsBoundaryBConfigured()));
    obj.push_back(Pair("boundary_b_active", IsBoundaryBActiveAtHeight(nCurrentHeight)));
    obj.push_back(Pair("legacy_transaction_versions", std::string("2000-2007")));
    obj.push_back(Pair("privacy_vnext_transaction_version", SHIELDED_TX_VERSION_DSP));
    obj.push_back(Pair("privacy_vnext_consensus_ready", fVNextReady));
    // Whether consensus will accept an IV5 transaction right now. This is not the same
    // question as the product declaring itself consensus-active: the linked ABI reports
    // consensus-active zero until that is separately reviewed, so the field above stays
    // false on a rehearsal network where payloads are in fact being accepted.
    obj.push_back(Pair("privacy_vnext_transactions_accepted",
                       IsShieldedVNextConsensusReady()));
    obj.push_back(Pair("privacy_vnext_abi_linked", fVNextAbiLinked));
    obj.push_back(Pair("privacy_vnext_abi_status",
                       fVNextAbiLinked ? std::string("linked_fail_closed")
                                       : std::string("local_failure")));
    obj.push_back(Pair("privacy_vnext_abi_error", vnextAbi.strError));
    obj.push_back(Pair("privacy_vnext_abi_version",
                       (int)vnextAbi.nAbiVersion));
    obj.push_back(Pair("privacy_vnext_abi_sha256", vnextAbi.strAbiSha256));
    obj.push_back(Pair("privacy_vnext_parameter_digest",
                       vnextAbi.strParameterDigest));
    obj.push_back(Pair("privacy_vnext_provenance_digest",
                       vnextAbi.strProvenanceDigest));
    obj.push_back(Pair("privacy_vnext_upstream_revision",
                       vnextAbi.strUpstreamRevision));
    obj.push_back(Pair("privacy_vnext_payload_schema",
                       (int)vnextAbi.nPayloadSchema));
    obj.push_back(Pair("privacy_vnext_implemented_capabilities",
                       (int)vnextAbi.nImplementedCapabilities));
    obj.push_back(Pair("privacy_vnext_consensus_capabilities",
                       (int)vnextAbi.nConsensusCapabilities));
    // Tree from the finalized epoch; store size is the node-local index, reported separately.
    std::string strVNextTreeRoot;
    int64_t nVNextTreeSize = 0;
    int64_t nVNextStoreSize = 0;
    {
        LOCK(cs_main);
        const int nStoreEpoch = GetEpochForHeight(nBestHeight) - 1;
        CEpochState vnextEpoch;
        if (nStoreEpoch >= 0 &&
            g_dagManager.GetEpochState(nStoreEpoch, vnextEpoch) &&
            vnextEpoch.nSerVersion >= EPOCHSTATE_SER_VERSION_V4)
        {
            strVNextTreeRoot = HexStr(vnextEpoch.vchVNextRoot);
            nVNextTreeSize = (int64_t)vnextEpoch.nVNextTreeSize;
        }
        CTxDB txdb("r");
        uint64_t nStored = 0;
        if (ReadPrivacyVNextTreeStoreSize(txdb, nStored))
            nVNextStoreSize = (int64_t)nStored;
    }
    obj.push_back(Pair("privacy_vnext_tree_root", strVNextTreeRoot));
    obj.push_back(Pair("privacy_vnext_tree_size", nVNextTreeSize));
    obj.push_back(Pair("privacy_vnext_tree_store_size", nVNextStoreSize));
    // Pool total for all holders; privacy_vnext_balance is this wallet's.
    {
        int64_t nVNextPool = 0;
        CTxDB txdb("r");
        const TxDBReadStatus poolStatus =
            txdb.ReadPrivacyVNextPoolValueStatus(nVNextPool);
        obj.push_back(Pair("privacy_vnext_pool_value",
                           poolStatus == TXDB_READ_FOUND
                               ? ValueFromAmount(nVNextPool) : Value::null));
    }
    obj.push_back(Pair("privacy_vnext_fee_note_height", FORK_HEIGHT_IV5_FEE_NOTE));
    obj.push_back(Pair("privacy_vnext_fee_note_active",
                       IsIV5FeeNoteActiveAtHeight(nBestHeight)));
    obj.push_back(Pair("privacy_vnext_max_anchor_age_epochs",
                       EPOCHSTATE_VNEXT_MAX_ANCHOR_AGE_EPOCHS));
    if (pwalletMain)
    {
        obj.push_back(Pair("privacy_vnext_balance",
                           ValueFromAmount(pwalletMain->GetPrivacyVNextBalance())));
        obj.push_back(Pair("privacy_vnext_unconfirmed_balance",
                           ValueFromAmount(pwalletMain->GetPrivacyVNextUnconfirmedBalance())));
        obj.push_back(Pair("privacy_vnext_note_count",
                           (int64_t)pwalletMain->GetPrivacyVNextNoteCount()));
        obj.push_back(Pair("privacy_vnext_seed_unlocked",
                           pwalletMain->IsPrivacyVNextSeedUnlocked()));
        // Lowest unscanned height; -1 means none (else run z_rescaniv5).
        obj.push_back(Pair("privacy_vnext_scan_gap_height",
                           pwalletMain->GetPrivacyVNextScanGapHeight()));
    }
    obj.push_back(Pair("privacy_vnext_max_inputs",
                       (int)vnextAbi.nMaxInputs));
    obj.push_back(Pair("privacy_vnext_max_outputs",
                       (int)vnextAbi.nMaxOutputs));
    obj.push_back(Pair("privacy_vnext_max_payload_bytes",
                       (int)vnextAbi.nMaxPayloadBytes));
    Array requiredOperations;
    requiredOperations.push_back("shield");
    requiredOperations.push_back("unshield");
    requiredOperations.push_back("transfer");
    requiredOperations.push_back("nullsend");
    requiredOperations.push_back("delegation_create");
    requiredOperations.push_back("m_of_n_mint");
    requiredOperations.push_back("reclaim");
    requiredOperations.push_back("conditional_migration");
    // Empty until IV5 consensus is ready.
    obj.push_back(Pair("privacy_vnext_supported_operations",
                       fVNextReady ? requiredOperations : Array()));
    obj.push_back(Pair("privacy_vnext_required_operations", requiredOperations));
    obj.push_back(Pair("privacy_vnext_note_operations", requiredOperations));
    Array finalityProfiles;
    finalityProfiles.push_back("none");
    finalityProfiles.push_back("nullstake_v1");
    finalityProfiles.push_back("nullstake_v2");
    finalityProfiles.push_back("nullstake_v3");
    obj.push_back(Pair("privacy_vnext_finality_profiles", finalityProfiles));
    Array authorizationModes;
    authorizationModes.push_back("owner");
    authorizationModes.push_back("cold_staker");
    authorizationModes.push_back("m_of_n_public_signers");
    authorizationModes.push_back("m_of_n_hidden_signers");
    obj.push_back(Pair("privacy_vnext_authorization_modes", authorizationModes));
    Array finalityObjects;
    finalityObjects.push_back("none");
    finalityObjects.push_back("vote");
    finalityObjects.push_back("tally_share");
    finalityObjects.push_back("certificate");
    // Retired; number 4 stays reserved.
    finalityObjects.push_back("committee_rotation");
    obj.push_back(Pair("privacy_vnext_finality_objects", finalityObjects));
    obj.push_back(Pair("privacy_vnext_required_privacy_modes",
                       (int)SHIELDED_VNEXT_PRIVACY_MODE_COUNT));
    Array requiredDisclosureModes;
    for (int mode = PRIVACY_MODE_TRANSPARENT; mode <= PRIVACY_MODE_FULL; ++mode)
        requiredDisclosureModes.push_back(mode);
    obj.push_back(Pair("privacy_vnext_required_disclosure_modes",
                       requiredDisclosureModes));
    // Release-evidence field; fixed protocol contract.
    obj.push_back(Pair("privacy_vnext_disclosure_modes",
                       requiredDisclosureModes));
    // Mask used when the caller passes none.
    obj.push_back(Pair("privacy_vnext_wallet_default_disclosure_mask",
                       (int)iv5::WALLET_DEFAULT_DISCLOSURE_MASK));
    obj.push_back(Pair("privacy_vnext_required_nullstake_generations",
                       (int)SHIELDED_VNEXT_NULLSTAKE_GENERATION_COUNT));
    Array requiredNullStakeGenerations;
    requiredNullStakeGenerations.push_back((int)SHIELDED_VNEXT_NULLSTAKE_V1);
    requiredNullStakeGenerations.push_back((int)SHIELDED_VNEXT_NULLSTAKE_V2);
    requiredNullStakeGenerations.push_back((int)SHIELDED_VNEXT_NULLSTAKE_V3);
    obj.push_back(Pair("privacy_vnext_required_nullstake_generation_ids",
                       requiredNullStakeGenerations));
    obj.push_back(Pair("privacy_vnext_nullstake_generation_ids",
                       requiredNullStakeGenerations));
    obj.push_back(Pair("privacy_vnext_tree_layers",
                       (int)SHIELDED_VNEXT_TREE_LAYERS));
    obj.push_back(Pair("privacy_vnext_membership_scope",
                       std::string("full_chain_finalized_root")));
    obj.push_back(Pair("privacy_vnext_post_dag_staking_role",
                       std::string("finality")));
    obj.push_back(Pair("privacy_vnext_wallet_migration_state",
                       std::string("unavailable")));
    const bool fHaveVNextSeed = pwalletMain && pwalletMain->HasPrivacyVNextSeed();
    const bool fVNextSeedUnlocked = pwalletMain &&
                                    pwalletMain->IsPrivacyVNextSeedUnlocked();
    obj.push_back(Pair("privacy_vnext_wallet_seed_present", fHaveVNextSeed));
    obj.push_back(Pair("privacy_vnext_wallet_seed_unlocked", fVNextSeedUnlocked));
    obj.push_back(Pair("privacy_vnext_wallet_seed_generation",
                       fHaveVNextSeed ? 1 : 0));
    obj.push_back(Pair("privacy_vnext_wallet_address_generation_available",
                       fHaveVNextSeed && fVNextSeedUnlocked));
    obj.push_back(Pair("privacy_vnext_wallet_key_management_state",
                       !fHaveVNextSeed
                           ? std::string("not_initialized")
                           : (fVNextSeedUnlocked ? std::string("ready")
                                                 : std::string("locked"))));
    obj.push_back(Pair("legacy_privacy_retired",
                       IsLegacyPrivacyPolicyDisabled() ||
                       IsBoundaryAActiveAtHeight(nCurrentHeight)));
    obj.push_back(Pair("legacy_privacy_encoding_quarantined",
                       IsLegacyPrivacyPolicyDisabled() ||
                       IsBoundaryAActiveAtHeight(nCurrentHeight)));
    obj.push_back(Pair("privacy_protocol_status",
                       (IsBoundaryBActiveAtHeight(nCurrentHeight) && fVNextReady)
                           ? std::string("privacy_vnext_active")
                           : (IsBoundaryAActiveAtHeight(nCurrentHeight)
                                  ? std::string("legacy_frozen_privacy_vnext_unavailable")
                                  : (IsLegacyPrivacyPolicyDisabled()
                                         ? std::string("legacy_policy_disabled_privacy_vnext_unavailable")
                                         : std::string("regtest_legacy_testing_only")))));

    bool fDSPActive = nCurrentHeight >= FORK_HEIGHT_DSP &&
                      !IsLegacyPrivacyPolicyDisabled() &&
                      !IsBoundaryAActiveAtHeight(nCurrentHeight);
    obj.push_back(Pair("dsp_active", fDSPActive));
    obj.push_back(Pair("dsp_fork_height", FORK_HEIGHT_DSP));
    obj.push_back(Pair("dsp_privacy_modes", 8));

    int64_t nPoolValue = 0;
    bool fHavePoolValue = false;
    {
        CTxDB txdb("r");
        fHavePoolValue = txdb.ReadShieldedPoolValue(nPoolValue);
    }
    if (fLegacyConsensusActive && (!fHavePoolValue || !MoneyRange(nPoolValue)))
        throw JSONRPCError(RPC_DATABASE_ERROR,
            "Shielded pool state is missing/corrupt; reindex/resync required");
    obj.push_back(Pair("shielded_pool_value", ValueFromAmount(nPoolValue)));

    CIncrementalMerkleTree tree;
    bool fHaveTree = false;
    {
        CTxDB txdb("r");
        fHaveTree = txdb.ReadShieldedTree(tree);
    }
    if (fLegacyConsensusActive && !fHaveTree)
        throw JSONRPCError(RPC_DATABASE_ERROR,
            "Shielded commitment tree is missing; reindex/resync required");
    obj.push_back(Pair("shielded_state_healthy",
                       !fLegacyConsensusActive || (fHavePoolValue && fHaveTree)));
    obj.push_back(Pair("commitment_tree_size", (int)tree.nSize));
    if (tree.nSize > 0)
        obj.push_back(Pair("best_anchor", tree.Root().GetHex()));

    if (pwalletMain)
    {
        LOCK(pwalletMain->cs_shielded);
        obj.push_back(Pair("shielded_addresses", (int)pwalletMain->mapShieldedSpendingKeys.size()));
        obj.push_back(Pair("viewing_only_addresses",
            (int)(pwalletMain->mapShieldedViewingKeys.size() - pwalletMain->mapShieldedSpendingKeys.size())));
        obj.push_back(Pair("shielded_balance", ValueFromAmount(pwalletMain->GetShieldedBalance())));

        int nUnspentNotes = 0;
        int nSpentNotes = 0;
        for (const CWallet::CShieldedWalletNote& wnote : pwalletMain->vShieldedNotes)
        {
            if (wnote.fSpent)
                nSpentNotes++;
            else
                nUnspentNotes++;
        }
        obj.push_back(Pair("unspent_notes", nUnspentNotes));
        obj.push_back(Pair("spent_notes", nSpentNotes));
    }

    obj.push_back(Pair("phase", 2));
    obj.push_back(Pair("proof_system", std::string("legacy_historical_only")));
    obj.push_back(Pair("zk_context_active", CZKContext::IsInitialized()));
    obj.push_back(Pair("shielded_staking", false));

    if (pwalletMain)
    {
        LOCK(pwalletMain->cs_shielded);
        obj.push_back(Pair("silent_payment_keys", (int)pwalletMain->vSilentPaymentKeys.size()));
    }

    obj.push_back(Pair("dandelion_enabled", dandelionState.IsEnabled()));
    obj.push_back(Pair("dandelion_stem_count", dandelionState.GetStemCount()));

    return obj;
}

Value z_migrateanon(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "z_migrateanon [zaddress]\n"
            "Migrate all unspent ring signature (anon) outputs to the shielded pool.\n"
            "If zaddress is not specified, a new shielded address is created.\n"
            "This is needed after ring signature deprecation to move funds to the shielded system.\n"
            "\nResult:\n"
            "{\n"
            "  \"migrated\": n,         (numeric) number of anon outputs migrated\n"
            "  \"total_amount\": x.xxx, (numeric) total amount migrated\n"
            "  \"txids\": [...]         (array) transaction IDs of migration transactions\n"
            "  \"zaddress\": \"...\"      (string) shielded address funds were sent to\n"
            "}\n");

    RequireLegacyPrivacyCreationEnabled();

    EnsureWalletIsUnlocked();

    if (!CZKContext::IsInitialized())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "ZK proof context not initialized");

    int nCurrentHeight = pindexBest ? pindexBest->nHeight : 0;
    if (nCurrentHeight < FORK_HEIGHT_SHIELDED)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Shielded transactions are not yet active");

    CShieldedPaymentAddress zAddr;
    if (params.size() >= 1)
    {
        string strZAddr = params[0].get_str();
        if (!StringToShieldedAddress(strZAddr, zAddr))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid shielded address");
    }
    else
    {
        zAddr = pwalletMain->GenerateNewShieldedAddress();
    }

    std::list<COwnedAnonOutput> lUnspent;
    if (pwalletMain->ListUnspentAnonOutputs(lUnspent, true) != 0)
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to list unspent anon outputs");

    if (lUnspent.empty())
        throw JSONRPCError(RPC_WALLET_ERROR, "No unspent anon outputs to migrate");

    Array txids;
    int64_t nTotalMigrated = 0;
    int nMigrated = 0;

    for (std::list<COwnedAnonOutput>::const_iterator it = lUnspent.begin(); it != lUnspent.end(); ++it)
    {
        const COwnedAnonOutput& oao = *it;

        std::map<uint256, CWalletTx>::const_iterator mi = pwalletMain->mapWallet.find(oao.outpoint.hash);
        if (mi == pwalletMain->mapWallet.end())
            continue;

        const CWalletTx& wtx = mi->second;
        if (wtx.vout.size() <= oao.outpoint.n)
            continue;

        int64_t nValue = wtx.vout[oao.outpoint.n].nValue;
        if (nValue <= MIN_TX_FEE_SHIELDED)
            continue; // skip dust

        Array shieldParams;
        CTxDestination address;
        if (ExtractDestination(wtx.vout[oao.outpoint.n].scriptPubKey, address))
        {
            CBitcoinAddress addr(address);
            shieldParams.push_back(addr.ToString());
        }
        else
        {
            continue;
        }

        int64_t nShieldAmount = nValue - MIN_TX_FEE_SHIELDED;
        if (nShieldAmount <= 0)
            continue;

        shieldParams.push_back(ValueFromAmount(nShieldAmount));
        shieldParams.push_back(ShieldedAddressToString(zAddr));

        try
        {
            Value result = z_shield(shieldParams, false);
            if (result.type() == obj_type)
            {
                Object obj = result.get_obj();
                for (unsigned int i = 0; i < obj.size(); i++)
                {
                    if (obj[i].name_ == "txid")
                        txids.push_back(obj[i].value_);
                }
            }
            nTotalMigrated += nShieldAmount;
            nMigrated++;
        }
        catch (const std::exception& e)
        {
            printf("z_migrateanon: failed to shield output %s:%d: %s\n",
                   oao.outpoint.hash.ToString().c_str(), oao.outpoint.n, e.what());
            continue;
        }
    }

    Object result;
    result.push_back(Pair("migrated", nMigrated));
    result.push_back(Pair("total_amount", ValueFromAmount(nTotalMigrated)));
    result.push_back(Pair("txids", txids));
    result.push_back(Pair("zaddress", ShieldedAddressToString(zAddr)));

    if (nMigrated == 0)
        throw JSONRPCError(RPC_WALLET_ERROR, "No anon outputs could be migrated. Outputs may not have extractable addresses.");

    return result;
}

Value sp_getnewaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "sp_getnewaddress\n"
            "Returns a new silent payment address.\n");

    EnsureWalletIsUnlocked();

    CSilentPaymentAddress addr;
    if (!pwalletMain->GenerateNewSilentPaymentKey(addr))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate silent payment key or derive address");

    return addr.ToString();
}

Value sp_listaddresses(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "sp_listaddresses\n"
            "Returns all silent payment addresses.\n");

    Array ret;
    LOCK(pwalletMain->cs_shielded);
    for (const CSilentPaymentKey& key : pwalletMain->vSilentPaymentKeys)
    {
        CSilentPaymentAddress addr;
        if (key.GetAddress(addr))
        {
            Object entry;
            entry.push_back(Pair("address", addr.ToString()));
            ret.push_back(entry);
        }
    }
    return ret;
}

Value sp_send(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 2)
        throw runtime_error(
            "sp_send <silent_payment_address> <amount>\n"
            "Send coins to a silent payment address.\n"
            "\nArguments:\n"
            "1. silent_payment_address  (string, required) Recipient's silent payment address\n"
            "2. amount                  (numeric, required) Amount in INN to send\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\": \"...\",            (string) Transaction ID\n"
            "  \"silent_address\": \"...\",  (string) Recipient address used\n"
            "  \"amount\": n,              (numeric) Amount sent\n"
            "  \"fee\": n,                 (numeric) Fee paid\n"
            "  \"output_pubkey\": \"...\"   (string) One-time output public key (hex)\n"
            "}\n"
        );

    EnsureWalletIsUnlocked();

    CSilentPaymentAddress spAddr;
    if (!spAddr.FromString(params[0].get_str()))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid silent payment address");

    int64_t nAmount = AmountFromValue(params[1]);

    CWalletTx wtxNew;
    wtxNew.BindWallet(pwalletMain);
    CReserveKey reservekey(pwalletMain);

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        CTxDB txdb("r");

        int64_t nFeeRet = nTransactionFee;
        static const int MAX_FEE_RETRIES = 20;
        for (int nFeeRetry = 0; nFeeRetry < MAX_FEE_RETRIES; nFeeRetry++)
        {
            wtxNew.vin.clear();
            wtxNew.vout.clear();
            wtxNew.fFromMe = true;

            int64_t nTotalNeeded = nAmount + nFeeRet;

            set<pair<const CWalletTx*, unsigned int> > setCoins;
            int64_t nValueIn = 0;

            if (!pwalletMain->SelectCoins2(nTotalNeeded, wtxNew.nTime, setCoins, nValueIn))
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

            vector<vector<unsigned char> > vInputPrivKeys;
            for (const auto& coin : setCoins)
            {
                const CScript& prevScript = coin.first->vout[coin.second].scriptPubKey;
                CTxDestination dest;
                if (!ExtractDestination(prevScript, dest))
                    throw JSONRPCError(RPC_WALLET_ERROR, "Cannot extract destination from input");
                const CKeyID* pKeyID = boost::get<CKeyID>(&dest);
                if (!pKeyID)
                    throw JSONRPCError(RPC_WALLET_ERROR, "Input is not a standard key destination");
                CKey key;
                if (!pwalletMain->GetKey(*pKeyID, key))
                    throw JSONRPCError(RPC_WALLET_ERROR, "Cannot get private key for input");
                if (!key.IsValid() || key.size() != 32)
                    throw JSONRPCError(RPC_WALLET_ERROR, "Private key invalid or wrong size");
                vInputPrivKeys.push_back(vector<unsigned char>(key.begin(), key.end()));
            }

            vector<unsigned char> vchSenderSecretSum;
            if (!ComputeInputPrivKeySum(vInputPrivKeys, vchSenderSecretSum))
            {
                for (auto& k : vInputPrivKeys) OPENSSL_cleanse(k.data(), k.size());
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to compute input key sum");
            }
            for (auto& k : vInputPrivKeys) OPENSSL_cleanse(k.data(), k.size());

            vector<unsigned char> vchOutputPubKey;
            if (!DeriveSilentPaymentOutput(vchSenderSecretSum, spAddr, 0, vchOutputPubKey))
            {
                OPENSSL_cleanse(vchSenderSecretSum.data(), vchSenderSecretSum.size());
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to derive silent payment output");
            }
            OPENSSL_cleanse(vchSenderSecretSum.data(), vchSenderSecretSum.size());

            CScript scriptPayee;
            scriptPayee << vchOutputPubKey << OP_CHECKSIG;

            wtxNew.vout.push_back(CTxOut(nAmount, scriptPayee));

            int64_t nChange = nValueIn - nAmount - nFeeRet;
            if (nFeeRet < MIN_TX_FEE && nChange > 0 && nChange < CENT)
            {
                int64_t nMoveToFee = min(nChange, MIN_TX_FEE - nFeeRet);
                nChange -= nMoveToFee;
                nFeeRet += nMoveToFee;
            }

            if (nChange > 0)
            {
                CPubKey vchPubKey;
                if (!reservekey.GetReservedKey(vchPubKey))
                    throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
                CScript scriptChange;
                scriptChange.SetDestination(vchPubKey.GetID());
                wtxNew.vout.push_back(CTxOut(nChange, scriptChange));
            }
            else
            {
                reservekey.ReturnKey();
            }

            for (const auto& coin : setCoins)
                wtxNew.vin.push_back(CTxIn(coin.first->GetHash(), coin.second));

            int nIn = 0;
            for (const auto& coin : setCoins)
            {
                if (!SignSignature(*pwalletMain, *coin.first, wtxNew, nIn++))
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign transaction");
            }

            unsigned int nBytes = ::GetSerializeSize(*(CTransaction*)&wtxNew, SER_NETWORK, PROTOCOL_VERSION);
            if (nBytes >= MAX_BLOCK_SIZE_GEN / 5)
                throw JSONRPCError(RPC_WALLET_ERROR, "Transaction too large");

            int64_t nPayFee = nTransactionFee * (1 + (int64_t)nBytes / 1000);
            int64_t nMinFee = wtxNew.GetMinFee(1, GMF_SEND, nBytes);

            if (nFeeRet < max(nPayFee, nMinFee))
            {
                nFeeRet = max(nPayFee, nMinFee);
                continue;
            }

            wtxNew.AddSupportingTransactions(txdb);
            wtxNew.fTimeReceivedIsTxTime = true;

            if (!pwalletMain->CommitTransaction(wtxNew, reservekey))
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to commit transaction");

            Object result;
            result.push_back(Pair("txid", wtxNew.GetHash().GetHex()));
            result.push_back(Pair("silent_address", params[0].get_str()));
            result.push_back(Pair("amount", ValueFromAmount(nAmount)));
            result.push_back(Pair("fee", ValueFromAmount(nFeeRet)));
            result.push_back(Pair("output_pubkey", HexStr(vchOutputPubKey)));
            return result;
        }

        throw JSONRPCError(RPC_WALLET_ERROR, "Fee estimation failed after maximum retries");
    }

    throw JSONRPCError(RPC_INTERNAL_ERROR, "Unexpected sp_send exit");
}


Value z_nullsend(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 5)
        throw runtime_error(
            "z_nullsend <fromaddress> <amount> [privacymode=7] [poolsize=5] [timeout=300]\n"
            "Participate in a NullSend mixing session.\n"
            "\nArguments:\n"
            "1. fromaddress      (string, required) Shielded address to spend from\n"
            "2. amount           (numeric, required) Amount to mix (INN)\n"
            "3. privacymode      (numeric, optional, default=7) Privacy mode (0-7)\n"
            "4. poolsize         (numeric, optional, default=5) Target number of participants (2-16)\n"
            "5. timeout          (numeric, optional, default=300) Max wait time in seconds\n"
            "\nResult:\n"
            "{\n"
            "  \"session\": n,           (numeric) Session ID\n"
            "  \"status\": \"...\",       (string) Current status\n"
            "  \"participants\": n,      (numeric) Number of participants\n"
            "  \"privacy_mode\": n       (numeric) Privacy mode used\n"
            "}\n"
        );

    RequireLegacyPrivacyCreationEnabled();

    int nCurrentHeight = nBestHeight;
    if (nCurrentHeight < FORK_HEIGHT_NULLSEND)
        throw JSONRPCError(RPC_MISC_ERROR, strprintf("NullSend not active until block %d (current: %d)", FORK_HEIGHT_NULLSEND, nCurrentHeight));

    std::string strFromAddr = params[0].get_str();
    int64_t nAmount = AmountFromValue(params[1]);
    uint8_t nPrivacyMode = (params.size() > 2) ? (uint8_t)params[2].get_int64() : PRIVACY_MODE_FULL;
    int nPoolSize = (params.size() > 3) ? (int)params[3].get_int64() : NULLSEND_DEFAULT_PARTICIPANTS;
    int nTimeout = (params.size() > 4) ? (int)params[4].get_int64() : NULLSEND_QUEUE_TIMEOUT;

    if (nPrivacyMode > 7)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Privacy mode must be 0-7");
    if (nPoolSize < NULLSEND_MIN_PARTICIPANTS || nPoolSize > NULLSEND_MAX_PARTICIPANTS)
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Pool size must be %d-%d", NULLSEND_MIN_PARTICIPANTS, NULLSEND_MAX_PARTICIPANTS));

    CShieldedPaymentAddress zFromAddr;
    if (!StringToShieldedAddress(strFromAddr, zFromAddr))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid shielded address");

    CWallet* pwallet = pwalletMain;
    if (!pwallet)
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not available");

    CShieldedSpendingKey sk;
    {
        LOCK(pwallet->cs_shielded);
        bool fFound = false;
        for (const auto& keypair : pwallet->mapShieldedSpendingKeys)
        {
            CShieldedFullViewingKey fvk;
            DeriveShieldedFullViewingKey(keypair.second, fvk);
            CShieldedIncomingViewingKey ivk;
            DeriveShieldedIncomingViewingKey(fvk, ivk);
            CShieldedPaymentAddress derivedAddr;
            DeriveShieldedPaymentAddress(ivk, keypair.first.vchDiversifier, derivedAddr);
            if (derivedAddr == zFromAddr)
            {
                sk = keypair.second;
                fFound = true;
                break;
            }
        }
        if (!fFound)
            throw JSONRPCError(RPC_WALLET_ERROR, "Spending key not found for this address");
    }

    int nSessionID;
    {
        LOCK(cs_nullsend);
        // Owner-locked: this RPC builds proofs outside cs_nullsend, so the
        // session must reject remote registrations in the meantime.
        nSessionID = nullSendPool.NewSession(nPrivacyMode, nPoolSize, true);
    }

    CNullSendEntry myEntry;
    myEntry.nSessionID = nSessionID;
    myEntry.nPrivacyMode = nPrivacyMode;

    bool fHideSender = DSP_HideSender(nPrivacyMode);
    bool fHideReceiver = DSP_HideReceiver(nPrivacyMode);
    bool fHideAmount = DSP_HideAmount(nPrivacyMode);

    ShieldedSpendabilityContext spendability = BuildShieldedSpendabilityContext(nCurrentHeight);

    std::vector<CWallet::CShieldedWalletNote> vSpendNotes;
    int64_t nTotalInput = 0;
    int64_t nPending = 0;
    {
        LOCK(pwallet->cs_shielded);
        for (const CWallet::CShieldedWalletNote& wnote : pwallet->vShieldedNotes)
        {
            if (wnote.fSpent) continue;
            if (!(wnote.note.addr == zFromAddr)) continue;

            ShieldedNoteSpendability noteStatus = GetShieldedNoteSpendability(wnote, spendability);
            if (!noteStatus.fSpendable)
            {
                nPending += wnote.note.nValue;
                continue;
            }

            vSpendNotes.push_back(wnote);
            nTotalInput += wnote.note.nValue;
            if (nTotalInput >= nAmount + NULLSEND_FEE)
                break;
        }
    }

    if (nTotalInput < nAmount + NULLSEND_FEE)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
            FormatShieldedSpendabilityError(spendability, nTotalInput, nPending,
                                            nAmount + NULLSEND_FEE));

    std::vector<std::vector<unsigned char>> vInputBlinds;
    std::vector<std::vector<unsigned char>> vOutputBlinds;
    std::vector<int64_t> vInputValues;
    CShieldedFullViewingKey fvk;
    DeriveShieldedFullViewingKey(sk, fvk);

    for (size_t nSpendIdx = 0; nSpendIdx < vSpendNotes.size(); nSpendIdx++)
    {
        CWallet::CShieldedWalletNote& wnote = vSpendNotes[nSpendIdx];
        CShieldedSpendDescription spend;

        if (wnote.note.vchBlind.empty())
            wnote.note.GenerateBlindingFactor();

        if (!wnote.note.GetPedersenCommitment(spend.cv))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create spend commitment");

        if (!ApplyShieldedSpendNullifier(spend, wnote.note, fvk.nk,
                nCurrentHeight + 1 >= FORK_HEIGHT_NULLIFIER_BINDING))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to set shielded spend nullifier");

        if (fHideSender)
        {
            CTxDB txdb("r");
            CIncrementalMerkleTree tree;

            int nAnchorHeight = nCurrentHeight - MIN_SHIELDED_SPEND_DEPTH;
            if (nAnchorHeight < 0) nAnchorHeight = 0;
            CBlockIndex* pAnchorBlock = FindBlockByHeight(nAnchorHeight);
            if (pAnchorBlock)
            {
                CIncrementalMerkleTree oldTree;
                if (txdb.ReadShieldedTreeAtBlock(pAnchorBlock->GetBlockHash(), oldTree))
                    tree = oldTree;
                else
                    throw JSONRPCError(RPC_DATABASE_ERROR,
                        "Missing shielded-tree anchor snapshot; reindex/resync required");
            }
            else
            {
                if (!txdb.ReadShieldedTree(tree))
                    throw JSONRPCError(RPC_DATABASE_ERROR,
                        "Missing current shielded tree; reindex/resync required");
            }
            spend.anchor = tree.Root();

            std::vector<CPedersenCommitment> vAllCommitments;
            uint64_t nGlobalOutputIndex = 0;
            std::string strSampleError;
            if (!txdb.ReadBoundedLelantusCommitments(
                    spend.cv, vAllCommitments, nGlobalOutputIndex,
                    strSampleError))
                throw JSONRPCError(RPC_DATABASE_ERROR,
                    strprintf("Unable to sample shielded commitments: %s; "
                              "reindex/resync may be required",
                              strSampleError.c_str()));

            CAnonymitySet anonSet;
            if (!BuildAnonymitySet(spend.cv, vAllCommitments, spend.anchor,
                                    nCurrentHeight, anonSet))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to build anonymity set");

            for (const CPedersenCommitment& c : anonSet.vCommitments)
                spend.vAnonSet.push_back(c);

            int nRealIndex = anonSet.FindIndex(spend.cv);
            if (nRealIndex < 0)
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Real commitment not found in anonymity set");

            CLelantusProof proof;
            int64_t nSerialIdx = (nCurrentHeight >= FORK_HEIGHT_SERIAL_V2)
                ? (int64_t)nGlobalOutputIndex : -1;
            uint256 serial = ComputeLelantusSerial(sk.skSpend, wnote.note.rho, spend.cv, nSerialIdx);
            if (!CreateLelantusProof(anonSet, nRealIndex, wnote.note.nValue,
                                      wnote.note.vchBlind, serial, proof))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create Lelantus proof");
            spend.vchLelantusProof = proof.vchProof;
            spend.lelantusSerial = proof.serialNumber;
        }
        else
        {
            CTxDB txdb("r");
            CIncrementalMerkleTree tree;
            int nAnchorHeight2 = nCurrentHeight - MIN_SHIELDED_SPEND_DEPTH;
            if (nAnchorHeight2 < 0) nAnchorHeight2 = 0;
            CBlockIndex* pAnchorBlock2 = FindBlockByHeight(nAnchorHeight2);
            if (pAnchorBlock2)
            {
                CIncrementalMerkleTree oldTree;
                if (txdb.ReadShieldedTreeAtBlock(pAnchorBlock2->GetBlockHash(), oldTree))
                    tree = oldTree;
                else
                    throw JSONRPCError(RPC_DATABASE_ERROR,
                        "Missing shielded-tree anchor snapshot; reindex/resync required");
            }
            else
            {
                if (!txdb.ReadShieldedTree(tree))
                    throw JSONRPCError(RPC_DATABASE_ERROR,
                        "Missing current shielded tree; reindex/resync required");
            }
            spend.anchor = tree.Root();
            int64_t nSerialIdx2 = -1;
            if (nCurrentHeight >= FORK_HEIGHT_SERIAL_V2)
            {
                uint64_t nIndexed = 0;
                CPedersenCommitment indexedCommitment;
                if (!txdb.ReadShieldedCommitmentIndex(spend.cv.vchCommitment, nIndexed) ||
                    nIndexed > (uint64_t)std::numeric_limits<int64_t>::max() ||
                    !txdb.ReadShieldedCommitment(nIndexed, indexedCommitment) ||
                    !(indexedCommitment == spend.cv))
                    throw JSONRPCError(RPC_DATABASE_ERROR,
                        "Shielded commitment reverse index is missing/corrupt; "
                        "reindex/resync required");
                nSerialIdx2 = (int64_t)nIndexed;
            }
            spend.lelantusSerial = ComputeLelantusSerial(sk.skSpend, wnote.note.rho, spend.cv, nSerialIdx2);
        }

        if (fHideAmount)
        {
            CBulletproofRangeProof rangeProof;
            if (!CreateBulletproofRangeProof(wnote.note.nValue, wnote.note.vchBlind,
                                              spend.cv, rangeProof))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create range proof");
            spend.rangeProof = rangeProof;
            spend.nPlaintextValue = -1;
        }
        else
        {
            spend.nPlaintextValue = wnote.note.nValue;
            spend.vchPlaintextBlind = wnote.note.vchBlind;
        }

        if (spendability.fRequireFCMP)
        {
            if (!spendability.fHasFCMPTree || spendability.fcmpTree.IsEmpty())
                throw JSONRPCError(RPC_INTERNAL_ERROR,
                    spendability.strFCMPError.empty() ? "Curve tree is empty, cannot create FCMP proof"
                                                      : spendability.strFCMPError);

            int64_t nLeafIdx = spendability.fcmpTree.FindLeafIndex(spend.cv);
            if (nLeafIdx < 0)
                throw JSONRPCError(RPC_INTERNAL_ERROR,
                    strprintf("Spend %d commitment not found in curve tree", (int)nSpendIdx));

            // Retired: no membership proof can be built for a legacy
            // shielded spend, and consensus rejects one without a proof.
            throw JSONRPCError(RPC_INVALID_REQUEST,
                               "legacy shielded spends are retired: the in-tree path-proof layer has been removed");

            spend.curveTreeRoot = spendability.hashFCMPRoot;

            if (fDebug)
                printf("z_nullsend: created FCMP proof for spend %d (leaf index %lld, tree size %llu)\n",
                       (int)nSpendIdx, (long long)nLeafIdx,
                       (unsigned long long)spendability.fcmpTree.nLeafCount);
        }

        myEntry.vMySpends.push_back(spend);
        vInputBlinds.push_back(wnote.note.vchBlind);
        vInputValues.push_back(wnote.note.nValue);
    }

    int64_t nChange = nTotalInput - nAmount - NULLSEND_FEE;

    {
        CShieldedNote outNote;
        outNote.addr = zFromAddr;
        outNote.nValue = nAmount;
        unsigned char rnd[32];
        if (RAND_bytes(rnd, 32) != 1)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate randomness");
        memcpy(outNote.rho.begin(), rnd, 32);
        if (RAND_bytes(rnd, 32) != 1)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate randomness");
        memcpy(outNote.rcm.begin(), rnd, 32);
        OPENSSL_cleanse(rnd, 32);
        outNote.GenerateBlindingFactor();

        CPedersenCommitment outCv;
        outNote.GetPedersenCommitment(outCv);

        CShieldedOutputDescription output;
        output.cv = outCv;
        output.cmu = outNote.GetCommitment();

        if (fHideAmount)
        {
            CBulletproofRangeProof outProof;
            CreateBulletproofRangeProof(outNote.nValue, outNote.vchBlind, outCv, outProof);
            output.rangeProof = outProof;
            output.nPlaintextValue = -1;
        }
        else
        {
            output.nPlaintextValue = outNote.nValue;
            output.vchPlaintextBlind = outNote.vchBlind;
        }

        if (!EncryptShieldedNote(outNote, zFromAddr, output.vchEphemeralKey, output.vchEncCiphertext))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to encrypt NullSend output note");
        if (!EncryptShieldedNoteForSender(outNote, sk.ovk, outCv.GetHash(), output.cmu,
                                          output.vchEphemeralKey, output.vchOutCiphertext))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to encrypt NullSend output note for sender");
        if (!fHideSender && !fHideReceiver)
            SetPublicShieldedRecipient(output, zFromAddr);

        myEntry.vMyOutputs.push_back(output);
        vOutputBlinds.push_back(outNote.vchBlind);
    }

    if (nChange > 0)
    {
        CShieldedNote changeNote;
        changeNote.addr = zFromAddr;
        changeNote.nValue = nChange;
        unsigned char rnd[32];
        if (RAND_bytes(rnd, 32) != 1)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate randomness");
        memcpy(changeNote.rho.begin(), rnd, 32);
        if (RAND_bytes(rnd, 32) != 1)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate randomness");
        memcpy(changeNote.rcm.begin(), rnd, 32);
        OPENSSL_cleanse(rnd, 32);
        changeNote.GenerateBlindingFactor();

        CPedersenCommitment changeCv;
        changeNote.GetPedersenCommitment(changeCv);

        CShieldedOutputDescription changeOutput;
        changeOutput.cv = changeCv;
        changeOutput.cmu = changeNote.GetCommitment();

        if (fHideAmount)
        {
            CBulletproofRangeProof changeProof;
            CreateBulletproofRangeProof(changeNote.nValue, changeNote.vchBlind, changeCv, changeProof);
            changeOutput.rangeProof = changeProof;
            changeOutput.nPlaintextValue = -1;
        }
        else
        {
            changeOutput.nPlaintextValue = changeNote.nValue;
            changeOutput.vchPlaintextBlind = changeNote.vchBlind;
        }

        if (!EncryptShieldedNote(changeNote, zFromAddr, changeOutput.vchEphemeralKey, changeOutput.vchEncCiphertext))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to encrypt NullSend change note");
        if (!EncryptShieldedNoteForSender(changeNote, sk.ovk, changeCv.GetHash(), changeOutput.cmu,
                                          changeOutput.vchEphemeralKey, changeOutput.vchOutCiphertext))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to encrypt NullSend change note for sender");
        if (!fHideSender && !fHideReceiver)
            SetPublicShieldedRecipient(changeOutput, zFromAddr);

        myEntry.vMyOutputs.push_back(changeOutput);
        vOutputBlinds.push_back(changeNote.vchBlind);
    }

    myEntry.nMyValueBalance = NULLSEND_FEE;

    nullSendClient.Reset();
    nullSendClient.vMyInputBlinds = vInputBlinds;
    nullSendClient.vMyOutputBlinds = vOutputBlinds;
    nullSendClient.vMyInputValues = vInputValues;
    nullSendClient.myEntry = myEntry;
    nullSendClient.nCurrentSession = nSessionID;

    {
        LOCK(cs_nullsend);
        auto it = nullSendPool.mapSessions.find(nSessionID);
        if (it == nullSendPool.mapSessions.end())
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Session not found");

        if (it->second.fChaumian)
        {
            it->second.fChaumian = false;
            it->second.SetState(NULLSEND_STATE_ACCEPTING);
        }

        if (!it->second.AcceptEntry(myEntry, NULL) || it->second.vParticipants.empty())
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to accept direct NullSend entry");

        if ((int)it->second.vParticipants.size() >= NULLSEND_MIN_PARTICIPANTS)
        {
            it->second.nTargetParticipants = (int)it->second.vParticipants.size();
        }

        if (it->second.nState == NULLSEND_STATE_ACCEPTING)
        {
            it->second.nTargetParticipants = 1;
            it->second.SetState(NULLSEND_STATE_NONCE_COMMIT);
        }

        std::vector<unsigned char> vchNonce, vchNoncePoint;
        if (!GenerateMuSigNonce(vchNonce, vchNoncePoint))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate nonce");

        uint256 commitment = ComputeNonceCommitment(vchNoncePoint);

        it->second.vParticipants[0].vchNoncePoint = vchNoncePoint;
        it->second.ProcessNonceCommit(0, commitment);

        if (it->second.nState != NULLSEND_STATE_PARTIAL_SIG)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Session did not advance to partial sig state");

        std::vector<unsigned char> vchPartialSig;
        if (!CreatePartialBindingSig(vchNonce, vInputBlinds, vOutputBlinds,
                                      it->second.vchChallenge, vchPartialSig))
        {
            OPENSSL_cleanse(vchNonce.data(), vchNonce.size());
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create partial signature");
        }

        OPENSSL_cleanse(vchNonce.data(), vchNonce.size());

        CNullSendPartialSig sigMsg;
        sigMsg.nSessionID = nSessionID;
        sigMsg.nParticipantID = 0;
        sigMsg.vchPartialSig = vchPartialSig;

        uint256 spendSighash = it->second.sighash;
        bool fBindingActive = nCurrentHeight + 1 >= FORK_HEIGHT_NULLIFIER_BINDING;
        for (size_t i = 0; i < myEntry.vMySpends.size(); i++)
        {
            std::vector<unsigned char> vchRk, vchSig;
            if (!CreateSpendAuthSignature(sk.skSpend, spendSighash, vchRk, vchSig))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create spend auth sig");
            sigMsg.vSpendAuthSigs.push_back(vchSig);
            sigMsg.vSpendRks.push_back(vchRk);

            if (fBindingActive)
            {
                std::vector<unsigned char> vchBindProof;
                if (!CreateNullifierBindingProof(vInputValues[i], vInputBlinds[i],
                                                 myEntry.vMySpends[i].cv,
                                                 myEntry.vMySpends[i].vchNullifierPoint,
                                                 spendSighash, vchBindProof))
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create nullifier binding proof");
                sigMsg.vNullifierBindingProofs.push_back(vchBindProof);
            }
        }

        it->second.ProcessPartialSig(0, sigMsg);

        if (it->second.nState != NULLSEND_STATE_SUCCESS)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "NullSend finalization failed");

        Object result;
        result.push_back(Pair("txid", it->second.finalTx.GetHash().ToString()));
        result.push_back(Pair("session", nSessionID));
        result.push_back(Pair("participants", (int)it->second.vParticipants.size()));
        result.push_back(Pair("privacy_mode", (int)nPrivacyMode));
        result.push_back(Pair("amount", ValueFromAmount(nAmount)));
        result.push_back(Pair("fee", ValueFromAmount(NULLSEND_FEE)));
        result.push_back(Pair("spends", (int)it->second.finalTx.vShieldedSpend.size()));
        result.push_back(Pair("outputs", (int)it->second.finalTx.vShieldedOutput.size()));
        return result;
    }
}

Value z_nullsendinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "z_nullsendinfo\n"
            "Returns information about active NullSend sessions.\n"
        );

    LOCK(cs_nullsend);

    Object result;
    const int nCandidateHeight =
        nBestHeight == std::numeric_limits<int>::max()
            ? nBestHeight : nBestHeight + 1;
    const bool fNullSendActive = IsLegacyNullSendEnabledAtHeight(nBestHeight);
    result.push_back(Pair("nullsend_active", fNullSendActive));
    result.push_back(Pair("legacy_retired", !fNullSendActive &&
                          (IsLegacyPrivacyPolicyDisabled() ||
                           IsBoundaryAActiveAtHeight(nCandidateHeight))));
    result.push_back(Pair("fork_height", FORK_HEIGHT_NULLSEND));
    result.push_back(Pair("current_height", nBestHeight));
    result.push_back(Pair("active_sessions", (int)nullSendPool.mapSessions.size()));
    result.push_back(Pair("queue_size", (int)vecNullSendQueue.size()));

    Array sessions;
    for (const auto& pair : nullSendPool.mapSessions)
    {
        const CNullSendSession& s = pair.second;
        Object sObj;
        sObj.push_back(Pair("session_id", s.nSessionID));
        sObj.push_back(Pair("state", s.nState));
        sObj.push_back(Pair("participants", (int)s.vParticipants.size()));
        sObj.push_back(Pair("target", s.nTargetParticipants));
        sObj.push_back(Pair("privacy_mode", (int)s.nPrivacyMode));
        sessions.push_back(sObj);
    }
    result.push_back(Pair("sessions", sessions));

    return result;
}


Value n_delegatestake(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "n_delegatestake <zaddr> [amount] [staker_pubkey]\n"
            "\nCreate a cold staking delegation voucher for a shielded address.\n"
            "\nThe owner creates this voucher and gives it to the staker (offline).\n"
            "\nArguments:\n"
            "1. zaddr          (string, required) Owner's shielded address\n"
            "2. amount          (numeric, optional, default=0) Max delegated amount (0=unlimited)\n"
            "3. staker_pubkey   (string, optional) Staker's transparent pubkey (for encryption)\n"
            "\nResult: hex-encoded delegation voucher\n");

    RequireLegacyPrivacyCreationEnabled();

    if (!pwalletMain)
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not available");

    EnsureWalletIsUnlocked();

    string strZAddr = params[0].get_str();
    int64_t nDelegateAmount = 0;
    if (params.size() > 1)
        nDelegateAmount = AmountFromValue(params[1]);

    LOCK2(cs_main, pwalletMain->cs_wallet);
    LOCK(pwalletMain->cs_shielded);

    bool fFoundKey = false;
    CShieldedSpendingKey sk;
    CShieldedPaymentAddress zAddrObj;
    for (std::map<CShieldedPaymentAddress, CShieldedSpendingKey>::iterator it = pwalletMain->mapShieldedSpendingKeys.begin();
         it != pwalletMain->mapShieldedSpendingKeys.end(); ++it)
    {
        CDataStream ssAddr(SER_NETWORK, PROTOCOL_VERSION);
        ssAddr << it->first;
        std::string strAddr = HexStr(ssAddr.begin(), ssAddr.end());
        if (strAddr == strZAddr || strZAddr == "*")
        {
            fFoundKey = true;
            sk = it->second;
            zAddrObj = it->first;
            break;
        }
    }
    if (!fFoundKey)
        throw JSONRPCError(RPC_WALLET_ERROR, "No shielded spending key found for address: " + strZAddr);

    uint256 skStake;
    if (!DeriveStakingKey(sk.skSpend, skStake))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to derive staking key");

    std::vector<unsigned char> vchPkStake;
    if (!DeriveStakingPubKey(skStake, vchPkStake))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to derive staking pubkey");

    CColdStakeDelegation deleg;
    deleg.vchPkStake = vchPkStake;
    deleg.nDelegateAmount = nDelegateAmount;

    deleg.vchSkStakeEnc.resize(32);
    memcpy(deleg.vchSkStakeEnc.data(), skStake.begin(), 32);

    CHashWriter ssOwner(SER_GETHASH, 0);
    ssOwner << zAddrObj;
    deleg.hashOwner = ssOwner.GetHash();

    deleg.ownerAddr = zAddrObj;
    deleg.ownerOvk = sk.ovk;

    CKey ownerKey;
    ownerKey.Set(sk.skSpend.begin(), sk.skSpend.end(), true);
    CPubKey ownerPubKey = ownerKey.GetPubKey();
    deleg.vchPkOwner.assign(ownerPubKey.begin(), ownerPubKey.end());

    {
        CHashWriter ssSig(SER_GETHASH, 0);
        ssSig << deleg.vchPkStake;
        ssSig << deleg.vchPkOwner;
        ssSig << deleg.vchSkStakeEnc;
        ssSig << deleg.nDelegateAmount;
        ssSig << deleg.hashOwner;
        uint256 hashSig = ssSig.GetHash();
        ownerKey.Sign(hashSig, deleg.vchOwnerSig);
    }

    pwalletMain->AddColdStakeDelegation(deleg);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << deleg;
    string strHex = HexStr(ss.begin(), ss.end());

    OPENSSL_cleanse(skStake.begin(), 32);

    Object result;
    result.push_back(Pair("voucher", strHex));
    result.push_back(Pair("delegation_hash", deleg.GetDelegationHash().GetHex()));
    result.push_back(Pair("pk_stake", HexStr(vchPkStake)));
    result.push_back(Pair("delegate_amount", ValueFromAmount(nDelegateAmount)));
    return result;
}


// B2-e Phase 3c.5: mint an M-of-N cold-stake note. The note's curve-tree leaf is the value-hiding
// 3-generator commitment cv3 = value*H + blind*G + D*J, with the value bound by a fresh 2-generator
// commitment Vv (range-proven) plus the Okamoto (G,J) link. The note is encrypted to the owner so the
// owner can later reclaim it. Funded from transparent coins (like z_shield).
Value z_mintmofncoldstake(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 5)
        throw runtime_error(
            "z_mintmofncoldstake <fromaddress> <amount> <ownerzaddress> <stakerpubkeys> <threshold_m>\n"
            "Mint a B2-e M-of-N cold-stake note (a value-hiding cv3 leaf) funded from transparent coins.\n"
            "stakerpubkeys is a JSON array of N compressed (33-byte hex) staker public keys; threshold_m is M.\n"
            "The note is staking-delegated to any M of the set and owner-reclaimable after the inactivity\n"
            "timelock. Returns the txid, the cv3 leaf, and the delegation hash.\n");

    RequireLegacyPrivacyCreationEnabled();

    EnsureWalletIsUnlocked();
    if (!CZKContext::IsInitialized())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "ZK proof context not initialized");

    int nCurrentHeight = pindexBest ? pindexBest->nHeight : 0;
    if (nCurrentHeight + 1 < FORK_HEIGHT_NULLSTAKE_DELEGSET)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "M-of-N cold staking not yet active at this height");

    string strFromAddr = params[0].get_str();
    int64_t nAmount = AmountFromValue(params[1]);
    string strOwnerZAddr = params[2].get_str();
    Array arrPubKeys = params[3].get_array();
    int nThresholdM = params[4].get_int();

    if (nAmount < MIN_TX_FEE_SHIELDED || nAmount > MAX_MONEY)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");

    bool fFilterByAddress = (strFromAddr != "*");

    // Owner key from the owner z-address spending key (so the owner can sign a future reclaim with rk==ownerPubKey).
    CShieldedPaymentAddress ownerZAddr;
    if (!StringToShieldedAddress(strOwnerZAddr, ownerZAddr))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid owner z-address");
    CShieldedSpendingKey sk;
    {
        LOCK(pwalletMain->cs_shielded);
        std::map<CShieldedPaymentAddress, CShieldedSpendingKey>::iterator it =
            pwalletMain->mapShieldedSpendingKeys.find(ownerZAddr);
        if (it == pwalletMain->mapShieldedSpendingKeys.end())
            throw JSONRPCError(RPC_WALLET_ERROR, "No spending key for owner z-address (owner must be a wallet address to reclaim)");
        sk = it->second;
    }

    CKey ownerKey;
    ownerKey.Set(sk.skSpend.begin(), sk.skSpend.end(), true);
    CPubKey ownerPubKey = ownerKey.GetPubKey();
    std::vector<unsigned char> vchPkOwner(ownerPubKey.begin(), ownerPubKey.end());
    if (vchPkOwner.size() != 33)
        throw JSONRPCError(RPC_WALLET_ERROR, "Owner pubkey not compressed");

    // Parse + canonicalize the staker set (sorted, dedup) to match the consensus set-hash.
    std::vector<std::vector<unsigned char> > vStakerSet;
    for (size_t i = 0; i < arrPubKeys.size(); i++)
    {
        std::vector<unsigned char> pk = ParseHex(arrPubKeys[i].get_str());
        if (pk.size() != 33)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Each staker pubkey must be 33-byte compressed hex");
        // A non-point member can never sign and would make the threshold unreachable.
        if (!CPubKey(pk).IsFullyValid())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Each staker pubkey must be a valid curve point");
        vStakerSet.push_back(pk);
    }
    std::sort(vStakerSet.begin(), vStakerSet.end());
    vStakerSet.erase(std::unique(vStakerSet.begin(), vStakerSet.end()), vStakerSet.end());
    if (vStakerSet.empty() || vStakerSet.size() > MAX_NULLSTAKE_MOFN_MEMBERS)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid staker set size");
    if (nThresholdM < 1 || (unsigned)nThresholdM > vStakerSet.size())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid threshold M");

    uint256 D;
    if (!ComputeNullStakeV3DelegationSetHash(vStakerSet, (unsigned)nThresholdM, vchPkOwner, D))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to compute delegation hash");

    // The cold-stake note (encrypted to the owner).
    CShieldedNote note;
    note.addr = ownerZAddr;
    note.nValue = nAmount;
    {
        unsigned char rnd[32];
        if (RAND_bytes(rnd, 32) != 1) throw JSONRPCError(RPC_INTERNAL_ERROR, "rng");
        memcpy(note.rho.begin(), rnd, 32);
        if (RAND_bytes(rnd, 32) != 1) throw JSONRPCError(RPC_INTERNAL_ERROR, "rng");
        memcpy(note.rcm.begin(), rnd, 32);
        OPENSSL_cleanse(rnd, 32);
    }
    if (!note.GenerateBlindingFactor())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate blinding factor");

    // cv3 leaf = value*H + blind*G + D*J.
    CPedersenCommitment cv3;
    if (!CreateNullStakeMofNCommitment(note.nValue, note.vchBlind, D, cv3))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to build cv3 commitment");

    // Fresh 2-generator value commitment Vv + range proof over Vv + the Okamoto (G,J) link to cv3.
    std::vector<unsigned char> blindV(32, 0);
    if (RAND_bytes(blindV.data(), 32) != 1) throw JSONRPCError(RPC_INTERNAL_ERROR, "rng");
    CPedersenCommitment Vv;
    if (!CreatePedersenCommitment(note.nValue, blindV, Vv))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to build value commitment");
    CBulletproofRangeProof rangeProof;
    if (!CreateBulletproofRangeProof(note.nValue, blindV, Vv, rangeProof))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to build range proof");
    std::vector<unsigned char> link;
    if (!CreateNullStakeMofNMintLink(cv3, Vv, note.vchBlind, blindV, D, link))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to build mint link");

    // cmu = SHA256d(cv3) (INV-8) so the owner's wallet can match the note to its cv3 leaf, NOT cv_plain.
    uint256 cmu = cv3.GetHash();

    std::vector<unsigned char> vchEphemeralKey, vchEncCiphertext;
    if (!EncryptShieldedNote(note, ownerZAddr, vchEphemeralKey, vchEncCiphertext))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to encrypt note");

    CShieldedOutputDescription output;
    output.cv = cv3;
    output.cmu = cmu;
    output.vchEphemeralKey = vchEphemeralKey;
    output.vchEncCiphertext = vchEncCiphertext;
    output.rangeProof = rangeProof;
    output.nMofNType = 1;
    output.valueCommitmentVv = Vv;
    output.vchMofNLink = link;
    EncryptShieldedNoteForSender(note, sk.ovk, cv3.GetHash(), cmu, vchEphemeralKey, output.vchOutCiphertext);

    CWalletTx wtxNew;
    wtxNew.BindWallet(pwalletMain);
    wtxNew.nVersion = SHIELDED_TX_VERSION_MOFN_MINT;
    wtxNew.nTime = GetAdjustedTime();
    wtxNew.nPrivacyMode = PRIVACY_MODE_FULL;
    wtxNew.vShieldedOutput.push_back(output);
    wtxNew.nValueBalance = -nAmount;

    int64_t nFeeRequired = MIN_TX_FEE_SHIELDED;
    CReserveKey reservekey(pwalletMain);

    static const int MAX_SHIELD_FEE_RETRIES = 10;
    for (int nFeeRetry = 0; nFeeRetry < MAX_SHIELD_FEE_RETRIES; nFeeRetry++)
    {
        wtxNew.vin.clear();
        wtxNew.vout.clear();

        int64_t nTotalNeeded = nAmount + nFeeRequired;
        set<pair<const CWalletTx*, unsigned int>> setCoins;
        int64_t nValueIn = 0;
        vector<COutput> vCoins;
        pwalletMain->AvailableCoins(vCoins);
        vCoins.erase(remove_if(vCoins.begin(), vCoins.end(), [](const COutput& out) {
            if (!(out.tx->IsCoinBase() || out.tx->IsCoinStake())) return false;
            return out.nDepth <= nCoinbaseMaturity;
        }), vCoins.end());
        if (fFilterByAddress)
        {
            vector<COutput> vFiltered;
            for (const COutput& out : vCoins)
            {
                CTxDestination dest;
                if (ExtractDestination(out.tx->vout[out.i].scriptPubKey, dest)
                    && CBitcoinAddress(dest).ToString() == strFromAddr)
                    vFiltered.push_back(out);
            }
            vCoins = vFiltered;
        }

        if (!pwalletMain->SelectCoinsMinConf(nTotalNeeded, wtxNew.nTime, 1, 10, vCoins, setCoins, nValueIn)
            && !pwalletMain->SelectCoinsMinConf(nTotalNeeded, wtxNew.nTime, 1, 1, vCoins, setCoins, nValueIn)
            && !pwalletMain->SelectCoinsMinConf(nTotalNeeded, wtxNew.nTime, 0, 1, vCoins, setCoins, nValueIn))
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

        for (const auto& coin : setCoins)
            wtxNew.vin.push_back(CTxIn(coin.first->GetHash(), coin.second));

        int64_t nChange = nValueIn - nTotalNeeded;
        if (nChange > 0)
        {
            CPubKey vchPubKey;
            if (!reservekey.GetReservedKey(vchPubKey))
                throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Keypool ran out");
            CScript scriptChange;
            scriptChange.SetDestination(vchPubKey.GetID());
            wtxNew.vout.push_back(CTxOut(nChange, scriptChange));
        }

        int nIn = 0;
        for (const auto& coin : setCoins)
            if (!SignSignature(*pwalletMain, *coin.first, wtxNew, nIn++))
            { reservekey.ReturnKey(); throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign transparent input"); }

        {
            unsigned int nBytes = ::GetSerializeSize(*(CTransaction*)&wtxNew, SER_NETWORK, PROTOCOL_VERSION);
            int64_t nMinFee = wtxNew.GetMinFee(1, GMF_SEND, nBytes);
            if (nFeeRequired < nMinFee) { nFeeRequired = nMinFee; reservekey.ReturnKey(); continue; }
        }

        // Binding signature: the M-of-N output's value commitment for the balance is Vv (its blind is
        // blindV), NOT cv3 -- so the binding sig is over blindV (matching the consensus INV-1 carve-out).
        vector<vector<unsigned char>> vInputBlinds, vOutputBlinds;
        vOutputBlinds.push_back(blindV);
        vInputBlinds.push_back(vector<unsigned char>(32, 0));   // fee blind placeholder

        uint256 sighash = wtxNew.GetBindingSigHash();
        CBindingSignature bindingSig;
        CreateBindingSignature(vInputBlinds, vOutputBlinds, sighash, bindingSig);
        wtxNew.bindingSig.bindingSig = bindingSig;

        if (!pwalletMain->CommitTransaction(wtxNew, reservekey))
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to commit M-of-N mint transaction");
        break;
    }

    // Record the delegation so the wallet can later recognize, stake, and reclaim this note.
    CMofNDelegation md;
    md.delegationHash = D;
    md.vStakerSet = vStakerSet;
    md.nThresholdM = (unsigned)nThresholdM;
    md.vchPkOwner = vchPkOwner;
    md.ownerAddr = ownerZAddr;
    md.ownerOvk = sk.ovk;
    pwalletMain->AddMofNDelegation(md);

    Object result;
    result.push_back(Pair("txid", wtxNew.GetHash().GetHex()));
    result.push_back(Pair("cv3", HexStr(cv3.vchCommitment)));
    result.push_back(Pair("delegation_hash", D.GetHex()));
    result.push_back(Pair("threshold_m", nThresholdM));
    result.push_back(Pair("set_size", (int)vStakerSet.size()));
    return result;
}


// B2-e Phase 3c.5: generate (or import) an M-of-N staker MEMBER key. The half-aggregated Schnorr
// public key is used in z_mintmofncoldstake's staker set; the secret is held by this wallet so it can
// co-produce M-of-N private finality votes for notes delegated to this member (M signers each hold one).
Value n_newmofnmemberkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "n_newmofnmemberkey [secrethex]\n"
            "Generate (or, if a 32-byte secret hex is given, import) an M-of-N staker member key.\n"
            "Returns the 33-byte half-agg public key to place in z_mintmofncoldstake's staker set; the\n"
            "secret is held by this wallet so it can co-produce M-of-N finality votes for that delegation.\n");

    EnsureWalletIsUnlocked();
    if (!CZKContext::IsInitialized())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "ZK proof context not initialized");

    uint256 secret;
    if (params.size() == 1)
    {
        std::vector<unsigned char> vch = ParseHex(params[0].get_str());
        if (vch.size() != 32)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "secret must be 32-byte hex");
        memcpy(secret.begin(), vch.data(), 32);
    }
    else
    {
        unsigned char rnd[32];
        if (RAND_bytes(rnd, 32) != 1)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "rng");
        memcpy(secret.begin(), rnd, 32);
        OPENSSL_cleanse(rnd, 32);
    }

    std::vector<unsigned char> vchPubKey;
    if (!HalfAggStakeDerivePubKey(secret, vchPubKey) || vchPubKey.size() != 33)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to derive member public key");
    pwalletMain->AddMofNMemberKey(vchPubKey, secret);

    Object result;
    result.push_back(Pair("memberpubkey", HexStr(vchPubKey)));
    return result;
}


// B2-e Phase 3c.4: owner-reclaim an idle M-of-N cold-stake note (cv3 leaf) back to a transparent address,
// by OWNER authority, after the inactivity timelock. Builds a version-2007 tx that the reclaim consensus
// gates (D recompute, owner spend-auth rk==vchPkOwner, timelock) accept. Mirrors z_unshield, diverging for
// the cv3/cv_plain split (value proofs over cv_plain = cv3 - D*J, membership over cv3) and skipping Lelantus.
Value z_reclaimmofncoldstake(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "z_reclaimmofncoldstake <delegationhash> <toaddress>\n"
            "Owner-reclaim an idle M-of-N cold-stake note back to a transparent address after the inactivity\n"
            "timelock. Spends the note by owner authority (no M-of-N quorum). Full-note reclaim (value - fee).\n");

    RequireLegacyPrivacyCreationEnabled();

    EnsureWalletIsUnlocked();
    if (!CZKContext::IsInitialized())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "ZK proof context not initialized");

    int nCurrentHeight = pindexBest ? pindexBest->nHeight : 0;
    if (nCurrentHeight + 1 < FORK_HEIGHT_NULLSTAKE_RECLAIM)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "M-of-N owner reclaim is not yet active");
    if (nCurrentHeight < FORK_HEIGHT_FCMP_VALIDATION)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "FCMP validation is not yet active");

    std::string strD = params[0].get_str();
    if (strD.size() != 64 || ParseHex(strD).size() != 32)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "delegationhash must be 64-char hex");
    uint256 D;
    D.SetHex(strD);

    std::string strToAddr = params[1].get_str();
    CBitcoinAddress destAddr(strToAddr);
    if (!destAddr.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid destination address");

    ShieldedSpendabilityContext spendability = BuildShieldedSpendabilityContext(nCurrentHeight);

    CMofNDelegation deleg;
    CShieldedSpendingKey sk;
    CShieldedFullViewingKey fvk;
    CWallet::CShieldedWalletNote selNote;
    size_t selIdx = 0;
    CPedersenCommitment cv3;
    bool fFound = false;

    {
        LOCK(pwalletMain->cs_shielded);
        std::map<uint256, CMofNDelegation>::iterator itD = pwalletMain->mapMofNDelegations.find(D);
        if (itD == pwalletMain->mapMofNDelegations.end())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown delegation hash (not held by this wallet)");
        deleg = itD->second;
        if (!pwalletMain->HaveShieldedSpendingKey(deleg.ownerAddr))
            throw JSONRPCError(RPC_WALLET_ERROR, "No owner spending key for this delegation (cannot authorize the reclaim)");
        sk = pwalletMain->mapShieldedSpendingKeys[deleg.ownerAddr];
        DeriveShieldedFullViewingKey(sk, fvk);

        for (size_t i = 0; i < pwalletMain->vShieldedNotes.size(); i++)
        {
            CWallet::CShieldedWalletNote& wnote = pwalletMain->vShieldedNotes[i];
            if (wnote.fSpent || !(wnote.note.addr == deleg.ownerAddr) || wnote.note.nValue <= 0)
                continue;
            if (wnote.note.vchBlind.empty())
                wnote.note.GenerateBlindingFactor();
            CPedersenCommitment cv3try;
            if (!CreateNullStakeMofNCommitment(wnote.note.nValue, wnote.note.vchBlind, D, cv3try))
                continue;
            if (spendability.fcmpTree.FindLeafIndex(cv3try) < 0)
                continue;   // not this delegation's on-chain leaf
            if (wnote.nHeight <= 0 || nCurrentHeight - wnote.nHeight < RECLAIM_TIMELOCK)
                continue;   // inactivity timelock not yet met
            selNote = wnote;
            selIdx = i;
            cv3 = cv3try;
            fFound = true;
            break;
        }
        if (!fFound)
            throw JSONRPCError(RPC_WALLET_ERROR,
                "No timelock-aged unspent M-of-N note found for this delegation (note may be too young or already spent)");

        {
            CWalletDB walletdb(pwalletMain->strWalletFile);
            if (!walletdb.WriteShieldedNoteSpent(selNote.txhash, selNote.nPosition, true))
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to persist note spent flag");
        }
        pwalletMain->vShieldedNotes[selIdx].fSpent = true;
    } // cs_shielded released

    try
    {
        CTransaction txNew;
        txNew.nVersion = SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM;
        txNew.nTime = GetAdjustedTime();
        // Hide the amount but NOT the sender: Lelantus is impossible for a cv3 note (its anon-set members are
        // cv3 leaves, not cv_plain), and the reclaim reveals cv3 in the clear for the timelock lookup anyway.
        txNew.nPrivacyMode = PRIVACY_HIDE_AMOUNT;

        // reclaimAuth must be populated before the sighash (GetBindingSigHash commits it for version 2007).
        txNew.reclaimAuth.delegationHash = D;
        txNew.reclaimAuth.vStakerSet = deleg.vStakerSet;
        txNew.reclaimAuth.nThresholdM = deleg.nThresholdM;
        txNew.reclaimAuth.vchPkOwner = deleg.vchPkOwner;

        CPedersenCommitment cvPlain;
        if (!NullStakeMofNDeriveValueCommitment(cv3, D, cvPlain))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to derive cv_plain for reclaim");

        CShieldedSpendDescription spend;
        spend.cv = cv3;   // the real on-chain leaf (timelock + FCMP key on this)
        // range proof over cv_plain (matches ConnectInputs + the mempool carve-out)
        if (!CreateBulletproofRangeProof(selNote.note.nValue, selNote.note.vchBlind, cvPlain, spend.rangeProof))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create reclaim range proof");
        if (!ApplyShieldedSpendNullifier(spend, selNote.note, fvk.nk,
                nCurrentHeight + 1 >= FORK_HEIGHT_NULLIFIER_BINDING))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to set reclaim nullifier");

        // Anchor from an on-chain tree snapshot (mempool validates it exists + is deep enough).
        {
            CTxDB txdb("r");
            CIncrementalMerkleTree tree;
            int nAnchorHeight = nCurrentHeight - MIN_SHIELDED_SPEND_DEPTH;
            if (nAnchorHeight < 0) nAnchorHeight = 0;
            CBlockIndex* pAnchorBlock = FindBlockByHeight(nAnchorHeight);
            if (pAnchorBlock)
            {
                CIncrementalMerkleTree oldTree;
                if (txdb.ReadShieldedTreeAtBlock(pAnchorBlock->GetBlockHash(), oldTree))
                    tree = oldTree;
                else
                    throw JSONRPCError(RPC_DATABASE_ERROR,
                        "Missing shielded-tree anchor snapshot; reindex/resync required");
            }
            else
            {
                if (!txdb.ReadShieldedTree(tree))
                    throw JSONRPCError(RPC_DATABASE_ERROR,
                        "Missing current shielded tree; reindex/resync required");
            }
            spend.anchor = tree.Root();
        }

        // FCMP membership over cv3 (the real leaf).
        if (!spendability.fHasFCMPTree || spendability.fcmpTree.IsEmpty())
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                spendability.strFCMPError.empty() ? "Curve tree is empty" : spendability.strFCMPError);
        int64_t nLeafIdx = spendability.fcmpTree.FindLeafIndex(spend.cv);
        if (nLeafIdx < 0)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Reclaim note leaf not found in curve tree");
        // Retired: no membership proof can be built for a legacy
        // shielded spend, and consensus rejects one without a proof.
        throw JSONRPCError(RPC_INVALID_REQUEST,
                           "legacy shielded spends are retired: the in-tree path-proof layer has been removed");
        spend.curveTreeRoot = spendability.hashFCMPRoot;

        txNew.vShieldedSpend.push_back(spend);

        unsigned int nEstimatedKB = 2 + 4;
        int64_t nFee = std::max(MIN_TX_FEE_SHIELDED, (int64_t)(1 + nEstimatedKB) * MIN_TX_FEE_ANON);
        if (selNote.note.nValue <= nFee)
            throw JSONRPCError(RPC_WALLET_ERROR, "Note value is below the reclaim fee");
        int64_t nOut = selNote.note.nValue - nFee;
        txNew.nValueBalance = selNote.note.nValue;   // whole note leaves the shielded pool

        CScript scriptPubKey;
        scriptPubKey.SetDestination(destAddr.Get());
        txNew.vout.push_back(CTxOut(nOut, scriptPubKey));

        uint256 sighash = txNew.GetBindingSigHash();

        // OWNER authorization: signing with the owner z-addr's spend key yields vchRk == vchPkOwner.
        if (!CreateSpendAuthSignature(sk.skSpend, sighash,
                                       txNew.vShieldedSpend[0].vchRk,
                                       txNew.vShieldedSpend[0].vchSpendAuthSig))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create owner spend-auth signature");
        if (txNew.vShieldedSpend[0].vchRk != deleg.vchPkOwner)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Owner spend key does not match delegation owner (internal)");

        // Nullifier-binding over cv_plain (do NOT use FinalizeShieldedSpendBindings -- it binds over spend.cv=cv3).
        if (nCurrentHeight + 1 >= FORK_HEIGHT_NULLIFIER_BINDING)
        {
            if (!CreateNullifierBindingProof(selNote.note.nValue, selNote.note.vchBlind, cvPlain,
                                             txNew.vShieldedSpend[0].vchNullifierPoint, sighash,
                                             txNew.vShieldedSpend[0].vchNullifierBindingProof))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create reclaim nullifier binding proof");
        }

        // Value-balance binding: input opens over cv_plain (value*H + blind*G); no shielded outputs.
        std::vector<std::vector<unsigned char> > vInputBlinds(1, selNote.note.vchBlind);
        std::vector<std::vector<unsigned char> > vOutputBlinds;
        CBindingSignature bindingSig;
        CreateBindingSignature(vInputBlinds, vOutputBlinds, sighash, bindingSig);
        txNew.bindingSig.bindingSig = bindingSig;

        CWalletTx wtxNew(pwalletMain, txNew);
        CReserveKey reservekey(pwalletMain);
        if (!pwalletMain->CommitTransaction(wtxNew, reservekey))
        {
            LOCK(pwalletMain->cs_shielded);
            pwalletMain->vShieldedNotes[selIdx].fSpent = false;
            CWalletDB walletdb(pwalletMain->strWalletFile);
            walletdb.WriteShieldedNoteSpent(selNote.txhash, selNote.nPosition, false);
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to commit reclaim transaction");
        }

        Object result;
        result.push_back(Pair("txid", wtxNew.GetHash().GetHex()));
        result.push_back(Pair("delegation_hash", D.GetHex()));
        result.push_back(Pair("cv3", HexStr(cv3.vchCommitment)));
        result.push_back(Pair("to_address", strToAddr));
        result.push_back(Pair("amount", ValueFromAmount(nOut)));
        result.push_back(Pair("fee", ValueFromAmount(nFee)));
        result.push_back(Pair("tx_version", (int)txNew.nVersion));
        return result;
    }
    catch (...)
    {
        LOCK(pwalletMain->cs_shielded);
        pwalletMain->vShieldedNotes[selIdx].fSpent = false;
        CWalletDB walletdb(pwalletMain->strWalletFile);
        walletdb.WriteShieldedNoteSpent(selNote.txhash, selNote.nPosition, false);
        throw;
    }
}


Value n_importdelegation(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "n_importdelegation <voucher_hex>\n"
            "\nImport a cold staking delegation voucher (staker side).\n"
            "\nArguments:\n"
            "1. voucher_hex    (string, required) Hex-encoded delegation voucher from n_delegatestake\n"
            "\nResult: delegation info\n");

    if (!pwalletMain)
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not available");

    string strHex = params[0].get_str();
    std::vector<unsigned char> vchData = ParseHex(strHex);
    if (vchData.empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid hex string");

    CDataStream ss(vchData, SER_NETWORK, PROTOCOL_VERSION);
    CColdStakeDelegation deleg;
    try {
        ss >> deleg;
    } catch (const std::exception& e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, string("Failed to deserialize delegation: ") + e.what());
    }

    if (deleg.IsNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Delegation is null/empty");

    if (deleg.vchPkStake.size() != 33)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid pk_stake size");

    if (deleg.vchOwnerSig.empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Delegation voucher has no owner signature");
    if (deleg.vchOwnerSig.size() < 8 || deleg.vchOwnerSig.size() > 72)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid owner signature size");

    if (deleg.vchPkOwner.size() != 33)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Missing or invalid owner pubkey in delegation voucher");

    {
        CHashWriter ssSig(SER_GETHASH, 0);
        ssSig << deleg.vchPkStake;
        ssSig << deleg.vchPkOwner;
        ssSig << deleg.vchSkStakeEnc;
        ssSig << deleg.nDelegateAmount;
        ssSig << deleg.hashOwner;
        uint256 hashSig = ssSig.GetHash();

        CPubKey ownerPubKey(deleg.vchPkOwner);
        if (!ownerPubKey.IsValid())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Owner pubkey in voucher is invalid");

        if (!ownerPubKey.Verify(hashSig, deleg.vchOwnerSig))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Owner signature verification failed — delegation may be forged");
    }

    if (deleg.nDelegateAmount < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative delegation amount");

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (!pwalletMain->ImportColdStakeDelegation(deleg))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to import delegation");

    Object result;
    result.push_back(Pair("status", "imported"));
    result.push_back(Pair("delegation_hash", deleg.GetDelegationHash().GetHex()));
    result.push_back(Pair("delegate_amount", ValueFromAmount(deleg.nDelegateAmount)));
    result.push_back(Pair("hash_owner", deleg.hashOwner.GetHex()));
    return result;
}


Value n_revokecoldstake(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "n_revokecoldstake <zaddr>\n"
            "\nRevoke a cold staking delegation.\n"
            "\nArguments:\n"
            "1. zaddr          (string, required) Owner's shielded address\n"
            "\nNote: Revocation removes the delegation from the wallet.\n"
            "To prevent the staker from creating further blocks, spend the\n"
            "delegated notes using z_send (this invalidates the staker's FCMP proofs).\n");

    RequireLegacyPrivacyCreationEnabled();

    if (!pwalletMain)
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not available");

    LOCK2(cs_main, pwalletMain->cs_wallet);
    LOCK(pwalletMain->cs_shielded);

    string strZAddr = params[0].get_str();
    uint256 hashOwnerTarget;
    bool fFoundAddr = false;

    for (std::map<CShieldedPaymentAddress, CShieldedSpendingKey>::iterator it = pwalletMain->mapShieldedSpendingKeys.begin();
         it != pwalletMain->mapShieldedSpendingKeys.end(); ++it)
    {
        CDataStream ssAddr(SER_NETWORK, PROTOCOL_VERSION);
        ssAddr << it->first;
        std::string strAddr = HexStr(ssAddr.begin(), ssAddr.end());
        if (strAddr == strZAddr || strZAddr == "*")
        {
            CHashWriter ssOwner(SER_GETHASH, 0);
            ssOwner << it->first;
            hashOwnerTarget = ssOwner.GetHash();
            fFoundAddr = true;
            break;
        }
    }
    if (!fFoundAddr)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Shielded address not found in wallet: " + strZAddr);

    std::map<uint256, CColdStakeDelegation>::iterator it = pwalletMain->mapColdStakeDelegations.find(hashOwnerTarget);
    if (it == pwalletMain->mapColdStakeDelegations.end())
        throw JSONRPCError(RPC_WALLET_ERROR, "No delegation found for address: " + strZAddr);

    if (!pwalletMain->RevokeColdStakeDelegation(hashOwnerTarget))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to revoke delegation");

    Object result;
    result.push_back(Pair("status", "revoked"));
    return result;
}


Value n_coldstakeinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "n_coldstakeinfo\n"
            "\nList active cold staking delegations.\n");

    if (!pwalletMain)
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet not available");

    LOCK(pwalletMain->cs_shielded);

    Array delegations;
    for (std::map<uint256, CColdStakeDelegation>::const_iterator it = pwalletMain->mapColdStakeDelegations.begin();
         it != pwalletMain->mapColdStakeDelegations.end(); ++it)
    {
        const CColdStakeDelegation& deleg = it->second;
        Object dObj;
        dObj.push_back(Pair("hash_owner", deleg.hashOwner.GetHex()));
        dObj.push_back(Pair("delegation_hash", deleg.GetDelegationHash().GetHex()));
        dObj.push_back(Pair("pk_stake", HexStr(deleg.vchPkStake)));
        dObj.push_back(Pair("delegate_amount", ValueFromAmount(deleg.nDelegateAmount)));
        dObj.push_back(Pair("has_staking_key", deleg.vchSkStakeEnc.size() == 32));
        delegations.push_back(dObj);
    }

    Object result;
    result.push_back(Pair("count", (int)pwalletMain->mapColdStakeDelegations.size()));
    result.push_back(Pair("delegations", delegations));
    return result;
}
