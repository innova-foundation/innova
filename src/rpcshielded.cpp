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
#include "lelantus.h"
#include "dandelion.h"
#include "init.h"
#include "base58.h"

#include <string>
#include <sstream>
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

Value z_getnewaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "z_getnewaddress\n"
            "Returns a new shielded payment address.\n");

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

    int64_t nAvailable = 0;
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
                int nConfirms = nCurrentHeight - wnote.nHeight + 1;
                if (nConfirms >= MIN_SHIELDED_SPEND_DEPTH)
                {
                    nAvailable += wnote.note.nValue;
                    vSelectedIndices.push_back(i);
                    if (nAvailable >= nAmount + MIN_TX_FEE_SHIELDED)
                        break;
                }
            }
        }

        if (nAvailable < nAmount + MIN_TX_FEE_SHIELDED)
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                strprintf("Insufficient shielded balance: available=%" PRId64 " needed=%" PRId64,
                          nAvailable, nAmount + MIN_TX_FEE_SHIELDED));

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

        spend.nullifier = wnote.note.GetNullifier(fvk.nk);
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
                    txdb.ReadShieldedTree(tree);
                    if (fDebug)
                        printf("z_unshield: WARNING: no tree snapshot at height %d, using current\n", nAnchorHeight);
                }
            }
            else
            {
                txdb.ReadShieldedTree(tree);
            }
            spend.anchor = tree.Root();

            vector<CPedersenCommitment> vAllCommitments;
            txdb.ReadAllShieldedCommitments(vAllCommitments);

            if (fDebug)
                printf("z_unshield: pool has %d commitments\n", (int)vAllCommitments.size());

            bool fFound = false;
            int64_t nGlobalOutputIndex = -1;
            for (size_t ci = 0; ci < vAllCommitments.size(); ci++)
            {
                if (vAllCommitments[ci] == spend.cv) { fFound = true; nGlobalOutputIndex = (int64_t)ci; break; }
            }
            if (fDebug)
                printf("z_unshield: spend cv found in pool: %s\n", fFound ? "YES" : "NO");

            CAnonymitySet anonSet;
            if (!BuildAnonymitySet(spend.cv, vAllCommitments, spend.anchor,
                                    nCurrentHeight, anonSet))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to build Lelantus anonymity set");

            int nRealIndex = anonSet.FindIndex(spend.cv);
            if (nRealIndex < 0)
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Own commitment not found in Lelantus anonymity set");

            CLelantusProof lelantusProof;
            int64_t nSerialIdx = (nCurrentHeight >= FORK_HEIGHT_SERIAL_V2) ? nGlobalOutputIndex : -1;
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
            CTxDB txdb("r");
            CCurveTree fcmpTree;
            txdb.ReadCurveTree(fcmpTree);
            fcmpTree.RebuildParentNodes();

            if (fcmpTree.IsEmpty())
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Curve tree is empty, cannot create FCMP proof");

            int64_t nLeafIdx = fcmpTree.FindLeafIndex(spend.cv);
            if (nLeafIdx < 0)
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Spend %d commitment not found in curve tree", (int)i));

            if (!CreateFCMPProof(fcmpTree, (uint64_t)nLeafIdx, wnote.note.vchBlind,
                                  wnote.note.nValue, spend.cv, spend.fcmpProof))
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Failed to create FCMP proof for spend %d", (int)i));

            spend.curveTreeRoot = fcmpTree.GetRoot();

            if (fDebug)
                printf("z_unshield: created FCMP proof for spend %d (leaf index %ld, tree size %lu)\n",
                       (int)i, nLeafIdx, fcmpTree.nLeafCount);
        }

        txNew.vShieldedSpend.push_back(spend);
        vInputBlinds.push_back(wnote.note.vchBlind);
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

    int64_t nAvailable = 0;
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
                int nConfirms = nCurrentHeight - wnote.nHeight + 1;
                if (nConfirms >= MIN_SHIELDED_SPEND_DEPTH)
                {
                    nAvailable += wnote.note.nValue;
                    vSelectedIndices.push_back(i);
                    if (nAvailable >= nAmount + MIN_TX_FEE_SHIELDED)
                        break;
                }
            }
        }

        if (nAvailable < nAmount + MIN_TX_FEE_SHIELDED)
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                strprintf("Insufficient shielded balance: available=%" PRId64 " needed=%" PRId64,
                          nAvailable, nAmount + MIN_TX_FEE_SHIELDED));

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
    txNew.nVersion = fUseFCMP ? SHIELDED_TX_VERSION_FCMP : SHIELDED_TX_VERSION_DSP;
    txNew.nTime = GetAdjustedTime();
    txNew.nPrivacyMode = nMode;

    vector<vector<unsigned char>> vInputBlinds;

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
            // PRIV-AUDIT-8: Do not include blinding factor in non-full-privacy spends
            // The blinding factor is secret; only the plaintext value is revealed
        }

        spend.nullifier = wnote.note.GetNullifier(fvk.nk);

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
                    txdb.ReadShieldedTree(tree);
            }
            else
                txdb.ReadShieldedTree(tree);
            spend.anchor = tree.Root();

            vector<CPedersenCommitment> vAllCommitments;
            txdb.ReadAllShieldedCommitments(vAllCommitments);

            int64_t nGlobalOutputIndex = -1;
            for (size_t ci = 0; ci < vAllCommitments.size(); ci++)
            {
                if (vAllCommitments[ci] == spend.cv) { nGlobalOutputIndex = (int64_t)ci; break; }
            }

            CAnonymitySet anonSet;
            if (!BuildAnonymitySet(spend.cv, vAllCommitments, spend.anchor,
                                    nCurrentHeight, anonSet))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to build Lelantus anonymity set");

            int nRealIndex = anonSet.FindIndex(spend.cv);
            if (nRealIndex < 0)
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Own commitment not found in Lelantus anonymity set");

            CLelantusProof lelantusProof;
            int64_t nSerialIdx = (nCurrentHeight >= FORK_HEIGHT_SERIAL_V2) ? nGlobalOutputIndex : -1;
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
                    txdb.ReadShieldedTree(tree);
            }
            else
                txdb.ReadShieldedTree(tree);
            spend.anchor = tree.Root();
            int64_t nSerialIdx2 = -1;
            if (nCurrentHeight >= FORK_HEIGHT_SERIAL_V2)
            {
                vector<CPedersenCommitment> vAllCmts;
                txdb.ReadAllShieldedCommitments(vAllCmts);
                for (size_t ci = 0; ci < vAllCmts.size(); ci++)
                {
                    if (vAllCmts[ci] == spend.cv) { nSerialIdx2 = (int64_t)ci; break; }
                }
            }
            spend.lelantusSerial = ComputeLelantusSerial(sk.skSpend, wnote.note.rho, spend.cv, nSerialIdx2);
        }

        if (fUseFCMP)
        {
            CTxDB txdb("r");
            CCurveTree fcmpTree;
            txdb.ReadCurveTree(fcmpTree);
            fcmpTree.RebuildParentNodes();

            if (fcmpTree.IsEmpty())
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Curve tree is empty, cannot create FCMP proof");

            int64_t nLeafIdx = fcmpTree.FindLeafIndex(spend.cv);
            if (nLeafIdx < 0)
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Spend %d commitment not found in curve tree", (int)i));

            if (!CreateFCMPProof(fcmpTree, (uint64_t)nLeafIdx, wnote.note.vchBlind,
                                  wnote.note.nValue, spend.cv, spend.fcmpProof))
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Failed to create FCMP proof for spend %d (leaf index %ld)",
                                                                  (int)i, nLeafIdx));

            spend.curveTreeRoot = fcmpTree.GetRoot();

            if (fDebug)
                printf("z_send: created FCMP proof for spend %d (leaf index %ld, tree size %lu)\n",
                       (int)i, nLeafIdx, fcmpTree.nLeafCount);
        }

        txNew.vShieldedSpend.push_back(spend);
        vInputBlinds.push_back(wnote.note.vchBlind);
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

        if (fHideReceiver)
        {
            EncryptShieldedNote(outNote, zToAddr, output.vchEphemeralKey, output.vchEncCiphertext);
            EncryptShieldedNoteForSender(outNote, sk.ovk, outCv.GetHash(), output.cmu,
                                          output.vchEphemeralKey, output.vchOutCiphertext);
        }
        else
        {
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << outNote;
            output.vchRecipientScript.assign(ss.begin(), ss.end());
        }

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

        if (fHideReceiver)
        {
            EncryptShieldedNote(changeNote, zFromAddr, changeOutput.vchEphemeralKey, changeOutput.vchEncCiphertext);
            EncryptShieldedNoteForSender(changeNote, sk.ovk, changeCv.GetHash(), changeOutput.cmu,
                                          changeOutput.vchEphemeralKey, changeOutput.vchOutCiphertext);
        }
        else
        {
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << changeNote;
            changeOutput.vchRecipientScript.assign(ss.begin(), ss.end());
        }

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
    LOCK(pwalletMain->cs_shielded);
    for (const CWallet::CShieldedWalletNote& wnote : pwalletMain->vShieldedNotes)
    {
        if (wnote.fSpent)
            continue;

        Object entry;
        entry.push_back(Pair("txid", wnote.txhash.GetHex()));
        entry.push_back(Pair("amount", ValueFromAmount(wnote.note.nValue)));
        entry.push_back(Pair("address", ShieldedAddressToString(wnote.note.addr)));
        entry.push_back(Pair("height", wnote.nHeight));
        entry.push_back(Pair("confirmations", (pindexBest ? pindexBest->nHeight - wnote.nHeight + 1 : 0)));
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

Value z_getshieldedinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "z_getshieldedinfo\n"
            "Returns an object containing shielded transaction information.\n");

    Object obj;

    int nCurrentHeight = pindexBest ? pindexBest->nHeight : 0;
    bool fActive = nCurrentHeight >= FORK_HEIGHT_SHIELDED;

    obj.push_back(Pair("shielded_active", fActive));
    obj.push_back(Pair("fork_height", FORK_HEIGHT_SHIELDED));
    obj.push_back(Pair("current_height", nCurrentHeight));
    obj.push_back(Pair("blocks_until_activation", fActive ? 0 : FORK_HEIGHT_SHIELDED - nCurrentHeight));

    bool fDSPActive = nCurrentHeight >= FORK_HEIGHT_DSP;
    obj.push_back(Pair("dsp_active", fDSPActive));
    obj.push_back(Pair("dsp_fork_height", FORK_HEIGHT_DSP));
    obj.push_back(Pair("dsp_privacy_modes", 8));

    int64_t nPoolValue = 0;
    {
        CTxDB txdb("r");
        txdb.ReadShieldedPoolValue(nPoolValue);
    }
    obj.push_back(Pair("shielded_pool_value", ValueFromAmount(nPoolValue)));

    CIncrementalMerkleTree tree;
    {
        CTxDB txdb("r");
        txdb.ReadShieldedTree(tree);
    }
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
    obj.push_back(Pair("proof_system", CZKContext::IsInitialized() ?
        "Bulletproofs++ (Pedersen + secp256k1, no trusted setup)" :
        "SHA256-simplified (ZK context not initialized)"));
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

    if (nBestHeight < FORK_HEIGHT_NULLSEND)
        throw JSONRPCError(RPC_MISC_ERROR, strprintf("NullSend not active until block %d (current: %d)", FORK_HEIGHT_NULLSEND, nBestHeight));

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
    {
        std::vector<unsigned char> vchAddr;
        if (!DecodeBase58(strFromAddr, vchAddr) || vchAddr.size() < 44)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid shielded address");
        CDataStream ss(vchAddr, SER_NETWORK, PROTOCOL_VERSION);
        ss >> zFromAddr;
    }

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
        nSessionID = nullSendPool.NewSession(nPrivacyMode, nPoolSize);
    }

    CNullSendEntry myEntry;
    myEntry.nSessionID = nSessionID;
    myEntry.nPrivacyMode = nPrivacyMode;

    bool fHideSender = DSP_HideSender(nPrivacyMode);
    bool fHideReceiver = DSP_HideReceiver(nPrivacyMode);
    bool fHideAmount = DSP_HideAmount(nPrivacyMode);

    std::vector<CWallet::CShieldedWalletNote> vSpendNotes;
    int64_t nTotalInput = 0;
    {
        LOCK(pwallet->cs_shielded);
        for (const CWallet::CShieldedWalletNote& wnote : pwallet->vShieldedNotes)
        {
            if (wnote.fSpent) continue;
            if ((nBestHeight - wnote.nHeight) < 10) continue;

            vSpendNotes.push_back(wnote);
            nTotalInput += wnote.note.nValue;
            if (nTotalInput >= nAmount + NULLSEND_FEE)
                break;
        }
    }

    if (nTotalInput < nAmount + NULLSEND_FEE)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
            strprintf("Insufficient shielded balance: available=%" PRId64 " needed=%" PRId64,
                       nTotalInput, nAmount + NULLSEND_FEE));

    std::vector<std::vector<unsigned char>> vInputBlinds;
    std::vector<std::vector<unsigned char>> vOutputBlinds;
    CShieldedFullViewingKey fvk;
    DeriveShieldedFullViewingKey(sk, fvk);

    for (const CWallet::CShieldedWalletNote& wnote : vSpendNotes)
    {
        CShieldedSpendDescription spend;
        spend.cv = CPedersenCommitment();
        wnote.note.GetPedersenCommitment(*(CPedersenCommitment*)&spend.cv);
        spend.nullifier = wnote.note.GetNullifier(fvk.nk);

            if (fHideSender)
        {
            CTxDB txdb("r");
            CIncrementalMerkleTree tree;

            int nAnchorHeight = nBestHeight - MIN_SHIELDED_SPEND_DEPTH;
            if (nAnchorHeight < 0) nAnchorHeight = 0;
            CBlockIndex* pAnchorBlock = FindBlockByHeight(nAnchorHeight);
            if (pAnchorBlock)
            {
                CIncrementalMerkleTree oldTree;
                if (txdb.ReadShieldedTreeAtBlock(pAnchorBlock->GetBlockHash(), oldTree))
                    tree = oldTree;
                else
                    txdb.ReadShieldedTree(tree);
            }
            else
                txdb.ReadShieldedTree(tree);
            spend.anchor = tree.Root();

            std::vector<CPedersenCommitment> vAllCommitments;
            txdb.ReadAllShieldedCommitments(vAllCommitments);

            int64_t nGlobalOutputIndex = -1;
            for (size_t ci = 0; ci < vAllCommitments.size(); ci++)
            {
                if (vAllCommitments[ci] == spend.cv) { nGlobalOutputIndex = (int64_t)ci; break; }
            }

            CAnonymitySet anonSet;
            if (!BuildAnonymitySet(spend.cv, vAllCommitments, spend.anchor,
                                    nBestHeight, anonSet))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to build anonymity set");

            for (const CPedersenCommitment& c : anonSet.vCommitments)
                spend.vAnonSet.push_back(c);

            int nRealIndex = anonSet.FindIndex(spend.cv);
            if (nRealIndex < 0)
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Real commitment not found in anonymity set");

            CLelantusProof proof;
            int64_t nSerialIdx = (nBestHeight >= FORK_HEIGHT_SERIAL_V2) ? nGlobalOutputIndex : -1;
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
            int nAnchorHeight2 = nBestHeight - MIN_SHIELDED_SPEND_DEPTH;
            if (nAnchorHeight2 < 0) nAnchorHeight2 = 0;
            CBlockIndex* pAnchorBlock2 = FindBlockByHeight(nAnchorHeight2);
            if (pAnchorBlock2)
            {
                CIncrementalMerkleTree oldTree;
                if (txdb.ReadShieldedTreeAtBlock(pAnchorBlock2->GetBlockHash(), oldTree))
                    tree = oldTree;
                else
                    txdb.ReadShieldedTree(tree);
            }
            else
                txdb.ReadShieldedTree(tree);
            spend.anchor = tree.Root();
            int64_t nSerialIdx2 = -1;
            if (nBestHeight >= FORK_HEIGHT_SERIAL_V2)
            {
                std::vector<CPedersenCommitment> vAllCmts;
                txdb.ReadAllShieldedCommitments(vAllCmts);
                for (size_t ci = 0; ci < vAllCmts.size(); ci++)
                {
                    if (vAllCmts[ci] == spend.cv) { nSerialIdx2 = (int64_t)ci; break; }
                }
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

        myEntry.vMySpends.push_back(spend);
        vInputBlinds.push_back(wnote.note.vchBlind);
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

        if (fHideReceiver)
        {
            EncryptShieldedNote(outNote, zFromAddr, output.vchEphemeralKey, output.vchEncCiphertext);
            EncryptShieldedNoteForSender(outNote, sk.ovk, outCv.GetHash(), output.cmu,
                                          output.vchEphemeralKey, output.vchOutCiphertext);
        }
        else
        {
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << outNote;
            output.vchRecipientScript.assign(ss.begin(), ss.end());
        }

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

        if (fHideReceiver)
        {
            EncryptShieldedNote(changeNote, zFromAddr, changeOutput.vchEphemeralKey, changeOutput.vchEncCiphertext);
            EncryptShieldedNoteForSender(changeNote, sk.ovk, changeCv.GetHash(), changeOutput.cmu,
                                          changeOutput.vchEphemeralKey, changeOutput.vchOutCiphertext);
        }
        else
        {
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << changeNote;
            changeOutput.vchRecipientScript.assign(ss.begin(), ss.end());
        }

        myEntry.vMyOutputs.push_back(changeOutput);
        vOutputBlinds.push_back(changeNote.vchBlind);
    }

    myEntry.nMyValueBalance = NULLSEND_FEE;

    nullSendClient.Reset();
    nullSendClient.vMyInputBlinds = vInputBlinds;
    nullSendClient.vMyOutputBlinds = vOutputBlinds;
    nullSendClient.myEntry = myEntry;
    nullSendClient.nCurrentSession = nSessionID;

    {
        LOCK(cs_nullsend);
        auto it = nullSendPool.mapSessions.find(nSessionID);
        if (it == nullSendPool.mapSessions.end())
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Session not found");

        it->second.AcceptEntry(myEntry, NULL);

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
        for (size_t i = 0; i < myEntry.vMySpends.size(); i++)
        {
            std::vector<unsigned char> vchRk, vchSig;
            if (!CreateSpendAuthSignature(sk.skSpend, spendSighash, vchRk, vchSig))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create spend auth sig");
            sigMsg.vSpendAuthSigs.push_back(vchSig);
            sigMsg.vSpendRks.push_back(vchRk);
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
    result.push_back(Pair("nullsend_active", nBestHeight >= FORK_HEIGHT_NULLSEND));
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
