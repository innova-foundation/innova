// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Regtest builder for fee-exempt migration shields. Test tooling, not a wallet path.

#include "main.h"
#include "txdb-leveldb.h"
#include "wallet.h"
#include "innovarpc.h"
#include "init.h"
#include "dag.h"
#include "privacy_vnext/iv5_protocol.h"
#include "privacy_vnext_builder.h"
#include "privacy_vnext_ffi.h"
#include "privacy_vnext_store.h"

#include <cstring>

using namespace json_spirit;
using namespace std;

extern bool fRegTest;
uint8_t PrivacyVNextNetworkIdForWallet();

Value iv5migrationshield(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "iv5migrationshield [{\"txid\":\"id\",\"vout\":n},...] [fee=0] [outputs=1]\n"
            "Regtest only. Builds and signs a shield of exactly these wallet outpoints into\n"
            "one self-pay note with the given payload fee. Returns the hex; not broadcast.\n");
    if (!fRegTest)
        throw JSONRPCError(RPC_INVALID_REQUEST, "iv5migrationshield is regtest only");
    if (!IsBoundaryBActiveAtHeight(pindexBest ? pindexBest->nHeight + 1 : 0) ||
        !IsShieldedVNextConsensusReady())
        throw JSONRPCError(RPC_INVALID_REQUEST, "the IV5 pool is not active");
    EnsureWalletIsUnlocked();

    const Array& outpoints = params[0].get_array();
    const int64_t nFee = params.size() > 1 ? params[1].get_int64() : 0;
    const int nOutputs = params.size() > 2 ? params[2].get_int() : 1;
    if (nFee < 0 || nOutputs < 1 || nOutputs > 2)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "bad fee or output count");

    CKeyingMaterial seed;
    if (!pwalletMain->GetPrivacyVNextSeed(seed) || seed.size() != 32)
        throw JSONRPCError(RPC_WALLET_ERROR, "the wallet has no unlocked IV5 seed");

    std::vector<unsigned char> vchRoot, vchParameterDigest;
    uint64_t nTreeSize = 0;
    std::string strError;
    {
        LOCK(cs_main);
        CTxDB txdb("r");
        CEpochState finalized;
        if (g_dagManager.GetFinalizedEpochStateAsOf(txdb, nBestHeight, finalized) &&
            finalized.nSerVersion >= EPOCHSTATE_SER_VERSION_V4 &&
            finalized.vchVNextRoot.size() == EPOCHSTATE_VNEXT_DIGEST_SIZE)
        {
            vchRoot = finalized.vchVNextRoot;
            nTreeSize = finalized.nVNextTreeSize;
            vchParameterDigest = finalized.vchVNextParameterDigest;
        }
        else
        {
            PrivacyVNextEpochSeed epochSeed;
            if (!LoadPrivacyVNextEpochSeed(epochSeed, strError))
                throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
            vchRoot = epochSeed.vchRoot;
            nTreeSize = epochSeed.nTreeSize;
            vchParameterDigest = epochSeed.vchParameterDigest;
        }
    }
    if (vchRoot.size() != 32)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "IV5 finalized root is unavailable");

    CTransaction txNew;
    txNew.nVersion = SHIELDED_TX_VERSION_DSP;
    std::vector<CScript> vScripts;
    int64_t nIn = 0;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        for (size_t i = 0; i < outpoints.size(); ++i)
        {
            const Object& o = outpoints[i].get_obj();
            const uint256 hash(find_value(o, "txid").get_str());
            const int n = find_value(o, "vout").get_int();
            std::map<uint256, CWalletTx>::const_iterator it = pwalletMain->mapWallet.find(hash);
            if (it == pwalletMain->mapWallet.end() || n < 0 ||
                n >= (int)it->second.vout.size())
                throw JSONRPCError(RPC_INVALID_PARAMETER, "outpoint not in wallet");
            txNew.vin.push_back(CTxIn(hash, n));
            vScripts.push_back(it->second.vout[n].scriptPubKey);
            nIn += it->second.vout[n].nValue;
        }
    }
    if (nIn <= nFee)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "inputs do not cover the fee");

    PrivacyVNextDigest seedDigest;
    std::memcpy(seedDigest.data(), &seed[0], 32);
    PrivacyVNextDigest genesis;
    const uint256 hashGenesis = GetGenesisBlockHash();
    std::memcpy(genesis.data(), hashGenesis.begin(), 32);
    const uint8_t nNetwork = PrivacyVNextNetworkIdForWallet();

    PrivacyVNextDigest binding;
    const uint256 hashBinding = GetPrivacyVNextTransparentBinding(txNew);
    std::memcpy(binding.data(), hashBinding.begin(), 32);

    PrivacyVNextDerivedKeys keys;
    const uint32_t nChangeIndex = PrivacyVNextChangeIndexFor(
        genesis, nNetwork, binding, std::vector<PrivacyVNextDigest>());
    if (!DerivePrivacyVNextChangeKeys(seedDigest, genesis, nNetwork, nChangeIndex, keys,
                                      strError))
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);

    std::vector<PrivacyVNextNewOutput> vOutputs(nOutputs);
    for (size_t i = 0; i < vOutputs.size(); ++i)
    {
        vOutputs[i].recipient.nNetwork = nNetwork;
        vOutputs[i].recipient.nAddressType = 0;
        vOutputs[i].recipient.spendPublic = keys.spendPublic;
        vOutputs[i].recipient.viewPublic = keys.viewPublic;
    }
    const int64_t nShielded = nIn - nFee;
    vOutputs[0].nAmount = nShielded / nOutputs + nShielded % nOutputs;
    if (nOutputs == 2)
        vOutputs[1].nAmount = nShielded / nOutputs;

    PrivacyVNextDigest finalizedRoot;
    std::memcpy(finalizedRoot.data(), &vchRoot[0], 32);
    std::vector<unsigned char> vchPayload;
    if (!BuildPrivacyVNextShieldPayload(nNetwork, iv5::WALLET_DEFAULT_DISCLOSURE_MASK,
                                        genesis, keys.outgoingViewSecret, finalizedRoot,
                                        nTreeSize, binding, (uint64_t)nIn, (uint64_t)nFee,
                                        vOutputs, vchPayload, strError, &vchParameterDigest))
        throw JSONRPCError(RPC_INTERNAL_ERROR, strError);
    txNew.privacyVNext.vchPayload = vchPayload;
    txNew.nTime = GetAdjustedTime();
    if (GetPrivacyVNextTransparentBinding(txNew) != hashBinding)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "transparent binding moved");

    {
        LOCK(pwalletMain->cs_wallet);
        for (size_t i = 0; i < vScripts.size(); ++i)
            if (!SignSignature(*pwalletMain, vScripts[i], txNew, (int)i))
                throw JSONRPCError(RPC_WALLET_ERROR, "failed to sign an input");
    }

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << txNew;
    Object result;
    result.push_back(Pair("txid", txNew.GetHash().GetHex()));
    result.push_back(Pair("hex", HexStr(ss.begin(), ss.end())));
    result.push_back(Pair("shielded", ValueFromAmount(nShielded)));
    return result;
}

Value getforkinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getforkinfo\n"
            "Returns the mergeset fork and transparent migration window heights.\n"
            "\nResult:\n"
            "{\n"
            "  \"height\": n,                       (numeric) current block height\n"
            "  \"mergeset_fork_height\": n,         (numeric) mergeset activation height\n"
            "  \"mergeset_blocks_left\": n,         (numeric) blocks until activation, 0 once active\n"
            "  \"mergeset_active\": true|false,\n"
            "  \"migration_start_height\": n,       (numeric) first height of the free migration window\n"
            "  \"migration_end_height\": n,         (numeric) first height the window is closed\n"
            "  \"migration_active\": true|false,\n"
            "  \"migration_wallet_end_height\": n,  (numeric) last height wallets build free migrations\n"
            "  \"migration_free_per_block\": n,     (numeric) free migrations one block confirms\n"
            "  \"client_version\": \"...\"\n"
            "}\n");

    const int nHeight = nBestHeight;
    const int nMergeset = FORK_HEIGHT_MERGESET;
    const int nMigrationEnd = GetMigrationEndHeight();
    Object result;
    result.push_back(Pair("height", nHeight));
    result.push_back(Pair("mergeset_fork_height", nMergeset));
    result.push_back(Pair("mergeset_blocks_left",
                          IsMergesetConfigured() && nHeight < nMergeset ? nMergeset - nHeight : 0));
    result.push_back(Pair("mergeset_active", IsMergesetActiveAtHeight(nHeight)));
    result.push_back(Pair("migration_start_height", FORK_HEIGHT_MIGRATION));
    result.push_back(Pair("migration_end_height", nMigrationEnd));
    result.push_back(Pair("migration_active", IsMigrationActiveAtHeight(nHeight)));
    result.push_back(Pair("migration_wallet_end_height", nMigrationEnd - MIGRATION_WALLET_END_MARGIN));
    result.push_back(Pair("migration_free_per_block", (int)MIGRATION_MAX_PER_BLOCK));
    result.push_back(Pair("client_version", FormatFullVersion()));
    return result;
}
