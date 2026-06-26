// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "db.h"
#include "txdb.h"
#include "init.h"
#include "miner.h"
#include "collateralnode.h"
#include "innovarpc.h"
#include "finality.h"
#include "dag.h"
#include "base58.h"

static CCriticalSection cs_getwork;

using namespace json_spirit;
using namespace std;

static std::string MiningFinalityTierName(FinalityTier tier)
{
    if (tier == FINALITY_HARD) return "hard";
    if (tier == FINALITY_SOFT) return "soft";
    if (tier == FINALITY_TENTATIVE) return "tentative";
    return "none";
}

Value gethashespersec(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "gethashespersec\n"
            "Returns a recent hashes per second performance measurement while generating.");

    return GetPoWMHashPS() / 1000;
}

Value getsubsidy(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getsubsidy [nTarget]\n"
            "Returns proof-of-work subsidy value for the specified value of target.");

    int nShowHeight;
    if (params.size() > 0)
        nShowHeight = atoi(params[0].get_str());
    else
        nShowHeight = nBestHeight+1; // block currently being solved

    return (uint64_t)GetProofOfWorkReward(nShowHeight, 0);
}

Value getmininginfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getmininginfo\n"
            "Returns an object containing mining-related information.");

    uint64_t nMinWeight = 0, nMaxWeight = 0, nWeight = 0;
    pwalletMain->GetStakeWeight(*pwalletMain, nMinWeight, nMaxWeight, nWeight);

    Object obj, diff, weight;
    obj.push_back(Pair("blocks",        (int)nBestHeight));
    obj.push_back(Pair("currentblocksize",(uint64_t)nLastBlockSize));
    obj.push_back(Pair("currentblocktx",(uint64_t)nLastBlockTx));

    diff.push_back(Pair("proof-of-work",  GetDifficulty()));
    diff.push_back(Pair("proof-of-stake", GetDifficulty(GetLastBlockIndex(pindexBest, true))));

    diff.push_back(Pair("search-interval",      (int)nLastCoinStakeSearchInterval));
    obj.push_back(Pair("difficulty",    diff));

    obj.push_back(Pair("blockvalue",    (uint64_t)GetProofOfWorkReward(nBestHeight+1, 0)));
    obj.push_back(Pair("netmhashps",     GetPoWMHashPS()));

    obj.push_back(Pair("netstakeweight", GetPoSKernelPS()));
    obj.push_back(Pair("errors",        GetWarnings("statusbar")));
    obj.push_back(Pair("pooledtx",      (uint64_t)mempool.size()));

    weight.push_back(Pair("minimum",    (uint64_t)nMinWeight));
    weight.push_back(Pair("maximum",    (uint64_t)nMaxWeight));
    weight.push_back(Pair("combined",  (uint64_t)nWeight));
    obj.push_back(Pair("stakeweight", weight));

    obj.push_back(Pair("stakeinterest",    (uint64_t)COIN_YEAR_REWARD));
    obj.push_back(Pair("testnet",       fTestNet));
    obj.push_back(Pair("cpumining",     fCPUMining));
    obj.push_back(Pair("cputhreads",    nCPUMinerThreads));
    return obj;
}

Value getstakinginfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getstakinginfo\n"
            "Returns an object containing staking-related information.");

    uint64_t nMinWeight = 0, nMaxWeight = 0, nWeight = 0;
    pwalletMain->GetStakeWeight(*pwalletMain, nMinWeight, nMaxWeight, nWeight);

    double dNetworkWeight = GetPoSKernelPS();
    uint64_t nNetworkWeight = (uint64_t)dNetworkWeight;
    bool fPoSBlockProduction = nBestHeight + 1 < FORK_HEIGHT_DAG;
    bool staking = fPoSBlockProduction && nLastCoinStakeSearchInterval && nWeight;
    int64_t nExpectedTime = -1;
    if (staking && nWeight > 0 && dNetworkWeight > 0.0)
    {
        unsigned int nSpacing = GetTargetSpacingForHeight(nBestHeight + 1);
        double dExpectedTime = (double)nSpacing * dNetworkWeight / (double)nWeight;
        if (dExpectedTime < 1.0)
            nExpectedTime = 1;
        else
            nExpectedTime = (int64_t)(dExpectedTime + 0.999999);
    }

    Object obj;

    obj.push_back(Pair("enabled", GetBoolArg("-staking", true)));
    obj.push_back(Pair("staking", staking));
    obj.push_back(Pair("pos_block_production", fPoSBlockProduction));
    obj.push_back(Pair("finality_voting", nBestHeight >= FORK_HEIGHT_DAG && !GetBoolArg("-nofinalityvoting", false)));
    obj.push_back(Pair("errors", GetWarnings("statusbar")));

    obj.push_back(Pair("currentblocksize", (uint64_t)nLastBlockSize));
    obj.push_back(Pair("currentblocktx", (uint64_t)nLastBlockTx));
    obj.push_back(Pair("pooledtx", (uint64_t)mempool.size()));

    obj.push_back(Pair("difficulty", GetDifficulty(GetLastBlockIndex(pindexBest, true))));
    obj.push_back(Pair("search-interval", (int)nLastCoinStakeSearchInterval));

    obj.push_back(Pair("weight", (uint64_t)nWeight));
    obj.push_back(Pair("netstakeweight", nNetworkWeight));

    obj.push_back(Pair("expectedtime", nExpectedTime));

    return obj;
}

Value getfinalitystakinginfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getfinalitystakinginfo\n"
            "Returns transparent finality staking status for the post-DAG finality voter.\n");

    int nHeight = 0;
    int nEpoch = 0;
    int nEpochBoundary = 0;
    int nEpochProgress = 0;
    int64_t nEpochBlockTime = 0;
    {
        LOCK(cs_main);
        if (pindexBest)
        {
            nHeight = pindexBest->nHeight;
            nEpoch = GetEpochForHeight(nHeight);
            nEpochBoundary = GetEpochBoundaryHeight(nEpoch, nHeight);
            nEpochProgress = nHeight - nEpochBoundary;
            CBlockIndex* pEpochBlock = FindBlockByHeight(nEpochBoundary);
            nEpochBlockTime = pEpochBlock ? pEpochBlock->GetBlockTime() : pindexBest->GetBlockTime();
        }
    }

    int64_t nEligibleWeight = 0;
    int nEligibleUtxos = 0;
    std::set<CKeyID> setVoterKeys;

    if (pwalletMain)
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        std::vector<COutput> vCoins;
        pwalletMain->AvailableCoins(vCoins);
        CTxDB txdb("r");
        for (const COutput& out : vCoins)
        {
            if (!out.tx || out.i < 0 || (unsigned int)out.i >= out.tx->vout.size())
                continue;
            const CTxOut& txout = out.tx->vout[out.i];
            if (txout.nValue <= 0 || !MoneyRange(txout.nValue))
                continue;

            CTxDestination dest;
            if (!ExtractDestination(txout.scriptPubKey, dest))
                continue;
            CKeyID keyID;
            if (!CBitcoinAddress(dest).GetKeyID(keyID))
                continue;
            CKey key;
            if (!pwalletMain->GetKey(keyID, key))
                continue;

            CTxIndex txindex;
            if (!txdb.ReadTxIndex(out.tx->GetHash(), txindex))
                continue;
            if ((unsigned int)out.i >= txindex.vSpent.size() || !txindex.vSpent[out.i].IsNull())
                continue;

            CBlock blockFrom;
            if (!blockFrom.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
                continue;
            if (blockFrom.GetBlockTime() + nStakeMinAge > nEpochBlockTime)
                continue;

            nEligibleUtxos++;
            setVoterKeys.insert(keyID);
            if (nEligibleWeight <= MAX_MONEY - txout.nValue)
                nEligibleWeight += txout.nValue;
            else
                nEligibleWeight = MAX_MONEY;
        }
    }

    Object obj;
    obj.push_back(Pair("enabled", !GetBoolArg("-nofinalityvoting", false)));
    obj.push_back(Pair("dag_active", nHeight >= FORK_HEIGHT_DAG));
    obj.push_back(Pair("pos_block_production", nHeight < FORK_HEIGHT_DAG));
    obj.push_back(Pair("dag_block_producer", std::string("pow")));
    obj.push_back(Pair("height", nHeight));
    obj.push_back(Pair("epoch", nEpoch));
    obj.push_back(Pair("epoch_boundary_height", nEpochBoundary));
    obj.push_back(Pair("epoch_progress", nEpochProgress));
    obj.push_back(Pair("vote_window", FINALITY_VOTE_WINDOW));
    obj.push_back(Pair("eligible_weight", FormatMoney(nEligibleWeight)));
    obj.push_back(Pair("eligible_utxos", nEligibleUtxos));
    obj.push_back(Pair("eligible_keys", (int)setVoterKeys.size()));
    obj.push_back(Pair("pending_votes", g_finalityTracker.GetPendingVoteCount()));
    obj.push_back(Pair("pending_rewards", FormatMoney(g_finalityTracker.GetPendingRewardTotal())));
    obj.push_back(Pair("expected_epoch_reward", FormatMoney(GetFinalityVoteReward(nEligibleWeight, GetEpochInterval(nHeight)))));
    obj.push_back(Pair("finality_tier", MiningFinalityTierName(g_finalityTracker.GetFinalityTier())));
    obj.push_back(Pair("consecutive_hard_epochs", g_finalityTracker.GetConsecutiveHardEpochCount()));
    obj.push_back(Pair("finalized_epoch", GetEpochForHeight(g_finalityTracker.GetFinalizedHeight())));
    obj.push_back(Pair("finalized_hash", g_finalityTracker.GetFinalizedHash().GetHex()));
    obj.push_back(Pair("finality_model", std::string("active-epoch-committed-weight")));
    obj.push_back(Pair("absolute_stake_floor", false));
    obj.push_back(Pair("private_finality_mode", std::string("hidden-weight-nullstake")));
    obj.push_back(Pair("tally_certificate_required_for_private_votes", true));
    CFinalityTallyConfig tallyConfig = GetFinalityTallyConfig();
    obj.push_back(Pair("private_promotion_enabled", nHeight >= FORK_HEIGHT_DAG && tallyConfig.CanRelayPrivateVotes()));
    obj.push_back(Pair("tally_mode", tallyConfig.strMode));
    obj.push_back(Pair("tally_mode_valid", tallyConfig.fModeValid));
    obj.push_back(Pair("tally_pubkey_configured", tallyConfig.fPubKeyConfigured));
    obj.push_back(Pair("tally_committee_valid", tallyConfig.fCommitteeValid));
    obj.push_back(Pair("tally_privkey_configured", tallyConfig.fPrivKeyConfigured));
    obj.push_back(Pair("tally_privkey_valid", tallyConfig.fPrivKeyValid));
    obj.push_back(Pair("tally_threshold", GetArg("-finalitytallythreshold", "")));
    obj.push_back(Pair("tally_threshold_valid", tallyConfig.fThresholdValid));
    obj.push_back(Pair("tally_threshold_m", tallyConfig.nThresholdM));
    obj.push_back(Pair("tally_committee_size", tallyConfig.nThresholdN));
    obj.push_back(Pair("tally_configured_pubkeys", (int)tallyConfig.vCommitteePubKeys.size()));
    obj.push_back(Pair("tally_committee_set_hash", tallyConfig.committeeSetHash.GetHex()));
    obj.push_back(Pair("tally_local_committee_index", tallyConfig.nLocalCommitteeIndex));
    obj.push_back(Pair("tally_encrypted_shares_ready", tallyConfig.fEncryptedTallyReady));
    int nDecryptableTallyShares = CountDecryptableFinalityTallyShares(nEpoch);
    int nTallyAggregatePartials = g_finalityTracker.GetEpochTallyAggregatePartialCount(nEpoch);
    obj.push_back(Pair("tally_decryptable_shares", nDecryptableTallyShares));
    obj.push_back(Pair("tally_aggregate_partials", nTallyAggregatePartials));
    obj.push_back(Pair("tally_certificate_production_enabled", nHeight >= FORK_HEIGHT_DAG && tallyConfig.CanProduceCertificates()));

    int nTransparentVotes = 0;
    int nPrivateVotes = 0;
    g_finalityTracker.GetEpochVoteModeCounts(nEpoch, nTransparentVotes, nPrivateVotes);
    obj.push_back(Pair("transparent_votes", nTransparentVotes));
    obj.push_back(Pair("private_votes", nPrivateVotes));
    obj.push_back(Pair("tally_shares", g_finalityTracker.GetEpochTallyShareCount(nEpoch)));

    std::vector<CFinalityTallyCertificate> vCerts = g_finalityTracker.GetEpochTallyCertificates(nEpoch);
    std::vector<CFinalityTallyCertificate> vPendingCerts =
        g_finalityTracker.GetPendingTallyCertificatesForBlock(nHeight + 1);
    Array certs;
    bool fHavePrivateCert = false;
    bool fHavePendingPrivateCert = false;
    int nTallyCertificateVersion = 0;
    std::string strTallyCertificateSource = "none";
    for (const CFinalityTallyCertificate& cert : vCerts)
    {
        Object certObj;
        certObj.push_back(Pair("hash", cert.GetHash().GetHex()));
        certObj.push_back(Pair("version", cert.nVersion));
        certObj.push_back(Pair("tier", MiningFinalityTierName((FinalityTier)cert.nTier)));
        certObj.push_back(Pair("private_weight", cert.HasPrivateWeight()));
        certObj.push_back(Pair("source", std::string("epoch-tracker")));
        certObj.push_back(Pair("tally_share_hashes", (int)cert.vTallyShareHashes.size()));
        certObj.push_back(Pair("curve_root", cert.hashCurveRoot.GetHex()));
        certObj.push_back(Pair("nullifier_root", cert.hashNullifierRoot.GetHex()));
        certObj.push_back(Pair("committee_set_hash", cert.committeeSetHash.GetHex()));
        certs.push_back(certObj);
        if (cert.HasPrivateWeight())
        {
            fHavePrivateCert = true;
            nTallyCertificateVersion = cert.nVersion;
            strTallyCertificateSource = "connected";
        }
    }
    for (const CFinalityTallyCertificate& cert : vPendingCerts)
    {
        if (cert.nEpoch != nEpoch || !cert.HasPrivateWeight())
            continue;
        fHavePendingPrivateCert = true;
        if (!fHavePrivateCert)
        {
            nTallyCertificateVersion = cert.nVersion;
            strTallyCertificateSource = "pending";
        }
    }
    obj.push_back(Pair("tally_certificates", certs));
    obj.push_back(Pair("private_certificate_present", fHavePrivateCert));
    obj.push_back(Pair("pending_private_certificate_present", fHavePendingPrivateCert));
    obj.push_back(Pair("tally_certificate_version", nTallyCertificateVersion));
    obj.push_back(Pair("tally_certificate_source", strTallyCertificateSource));
    std::string strPrivatePromotionStatus = "waiting-for-shares";
    if (nHeight < FORK_HEIGHT_DAG)
        strPrivatePromotionStatus = "inactive-pre-dag";
    else if (!tallyConfig.CanRelayPrivateVotes())
        strPrivatePromotionStatus = "committee-config-invalid";
    else if (!tallyConfig.CanProduceCertificates())
        strPrivatePromotionStatus = "waiting-for-local-committee-key";
    else if (fHavePrivateCert)
        strPrivatePromotionStatus = "connected-certificate";
    else if (fHavePendingPrivateCert)
        strPrivatePromotionStatus = "pending-certificate";
    else if (nDecryptableTallyShares > 0 || nTallyAggregatePartials > 0)
        strPrivatePromotionStatus = "collecting-partials";
    obj.push_back(Pair("private_promotion_status", strPrivatePromotionStatus));

    CEpochState currentEpochState;
    if (g_dagManager.GetEpochState(nEpoch, currentEpochState))
    {
        obj.push_back(Pair("epoch_curve_root", currentEpochState.hashCurveRoot.GetHex()));
        obj.push_back(Pair("epoch_nullifier_root", currentEpochState.hashNullifierRoot.GetHex()));
        obj.push_back(Pair("epoch_finality_certificate", currentEpochState.hashFinalityCertificate.GetHex()));
    }
    else
    {
        uint256 hashZero = 0;
        obj.push_back(Pair("epoch_curve_root", hashZero.GetHex()));
        obj.push_back(Pair("epoch_nullifier_root", hashZero.GetHex()));
        obj.push_back(Pair("epoch_finality_certificate", hashZero.GetHex()));
        obj.push_back(Pair("epoch_root_status", std::string("not_computed")));
    }
    return obj;
}

Value getworkex(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "getworkex [data, coinbase]\n"
            "If [data, coinbase] is not specified, returns extended work data.\n"
        );

    if (vNodes.empty())
        throw JSONRPCError(-9, "Innova is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(-10, "Innova is downloading blocks...");

    LOCK(cs_getwork);

    typedef map<uint256, pair<CBlock*, CScript> > mapNewBlock_t;
    static mapNewBlock_t mapNewBlock;
    static vector<CBlock*> vNewBlock;
    static CReserveKey reservekey(pwalletMain);

    if (params.size() == 0)
    {
        // Update block
        static unsigned int nTransactionsUpdatedLast;
        static CBlockIndex* pindexPrev;
        static int64_t nStart;
        static CBlock* pblock;
        if (pindexPrev != pindexBest ||
            (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60))
        {
            if (pindexPrev != pindexBest)
            {
                // Deallocate old blocks since they're obsolete now
                mapNewBlock.clear();
                BOOST_FOREACH(CBlock* pblock, vNewBlock)
                    delete pblock;
                vNewBlock.clear();
            }
            nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
            pindexPrev = pindexBest;
            nStart = GetTime();

            // Create new block
            pblock = CreateNewBlock(pwalletMain);
            if (!pblock)
                throw JSONRPCError(-7, "Out of memory");
            vNewBlock.push_back(pblock);
        }

        // Update nTime
        pblock->nTime = max(pindexPrev->GetPastTimeLimit()+1, GetAdjustedTime());
        pblock->nNonce = 0;

        // Update nExtraNonce
        static unsigned int nExtraNonce = 0;
        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        // Save
        mapNewBlock[pblock->hashMerkleRoot] = make_pair(pblock, pblock->vtx[0].vin[0].scriptSig);

        // Prebuild hash buffers
        char pmidstate[32];
        char pdata[128];
        char phash1[64];
        FormatHashBuffers(pblock, pmidstate, pdata, phash1);

        uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

        CTransaction coinbaseTx = pblock->vtx[0];
        std::vector<uint256> merkle = pblock->GetMerkleBranch(0);

        Object result;
        result.push_back(Pair("data",     HexStr(BEGIN(pdata), END(pdata))));
        result.push_back(Pair("target",   HexStr(BEGIN(hashTarget), END(hashTarget))));

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << coinbaseTx;
        result.push_back(Pair("coinbase", HexStr(ssTx.begin(), ssTx.end())));

        Array merkle_arr;

        BOOST_FOREACH(uint256 merkleh, merkle) {
            merkle_arr.push_back(HexStr(BEGIN(merkleh), END(merkleh)));
        }

        result.push_back(Pair("merkle", merkle_arr));


        return result;
    }
    else
    {
        // Parse parameters
        vector<unsigned char> vchData = ParseHex(params[0].get_str());
        vector<unsigned char> coinbase;

        if(params.size() == 2)
            coinbase = ParseHex(params[1].get_str());

        if (vchData.size() != 128)
            throw JSONRPCError(-8, "Invalid parameter");

        CBlock* pdata = (CBlock*)&vchData[0];

        // Byte reverse
        for (int i = 0; i < 128/4; i++)
            ((unsigned int*)pdata)[i] = ByteReverse(((unsigned int*)pdata)[i]);

        // Get saved block
        if (!mapNewBlock.count(pdata->hashMerkleRoot))
            return false;
        CBlock* pblock = mapNewBlock[pdata->hashMerkleRoot].first;

        pblock->nTime = pdata->nTime;
        pblock->nNonce = pdata->nNonce;

        if(coinbase.size() == 0)
            pblock->vtx[0].vin[0].scriptSig = mapNewBlock[pdata->hashMerkleRoot].second;
        else
        {
            // Deserialize miner-provided coinbase. Security: CheckWork validates the block.
            try {
                CDataStream ss(coinbase, SER_NETWORK, PROTOCOL_VERSION);
                ss >> pblock->vtx[0];
                if (!pblock->vtx[0].IsCoinBase())
                    throw JSONRPCError(-8, "Invalid coinbase transaction");
            } catch (const std::exception& e) {
                throw JSONRPCError(-8, std::string("Coinbase deserialization failed: ") + e.what());
            }
        }

        pblock->hashMerkleRoot = pblock->BuildMerkleTree();

        return CheckWork(pblock, *pwalletMain, reservekey);
    }
}


Value getwork(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getwork [data]\n"
            "If [data] is not specified, returns formatted hash data to work on:\n"
            "  \"midstate\" : precomputed hash state after hashing the first half of the data (DEPRECATED)\n" // deprecated
            "  \"data\" : block data\n"
            "  \"hash1\" : formatted hash buffer for second hash (DEPRECATED)\n" // deprecated
            "  \"target\" : little endian hash target\n"
            "If [data] is specified, tries to solve the block and returns true if it was successful.");

    if (vNodes.empty())
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Innova is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Innova is downloading blocks...");

    LOCK(cs_getwork);

    typedef map<uint256, pair<CBlock*, CScript> > mapNewBlock_t;
    static mapNewBlock_t mapNewBlock;
    static vector<CBlock*> vNewBlock;
    static CReserveKey reservekey(pwalletMain);

    if (params.size() == 0)
    {
        // Update block
        static unsigned int nTransactionsUpdatedLast;
        static CBlockIndex* pindexPrev;
        static int64_t nStart;
        static CBlock* pblock;
        if (pindexPrev != pindexBest ||
            (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60))
        {
            if (pindexPrev != pindexBest)
            {
                // Deallocate old blocks since they're obsolete now
                mapNewBlock.clear();
                BOOST_FOREACH(CBlock* pblock, vNewBlock)
                    delete pblock;
                vNewBlock.clear();
            }

            // Clear pindexPrev so future getworks make a new block, despite any failures from here on
            pindexPrev = NULL;

            // Store the pindexBest used before CreateNewBlock, to avoid races
            nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
            CBlockIndex* pindexPrevNew = pindexBest;
            nStart = GetTime();

            // Create new block
            pblock = CreateNewBlock(pwalletMain);
            if (!pblock)
                throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");
            vNewBlock.push_back(pblock);

            // Need to update only after we know CreateNewBlock succeeded
            pindexPrev = pindexPrevNew;
        }

        // Update nTime
        pblock->UpdateTime(pindexPrev);
        pblock->nNonce = 0;

        // Update nExtraNonce
        static unsigned int nExtraNonce = 0;
        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        // Save
        mapNewBlock[pblock->hashMerkleRoot] = make_pair(pblock, pblock->vtx[0].vin[0].scriptSig);

        // Pre-build hash buffers
        char pmidstate[32];
        char pdata[128];
        char phash1[64];
        FormatHashBuffers(pblock, pmidstate, pdata, phash1);

        uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

        Object result;
        result.push_back(Pair("midstate", HexStr(BEGIN(pmidstate), END(pmidstate)))); // deprecated
        result.push_back(Pair("data",     HexStr(BEGIN(pdata), END(pdata))));
        result.push_back(Pair("hash1",    HexStr(BEGIN(phash1), END(phash1)))); // deprecated
        result.push_back(Pair("target",   HexStr(BEGIN(hashTarget), END(hashTarget))));
        return result;
    }
    else
    {
        // Parse parameters
        vector<unsigned char> vchData = ParseHex(params[0].get_str());
        if (vchData.size() != 128)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
        CBlock* pdata = (CBlock*)&vchData[0];

        // Byte reverse
        for (int i = 0; i < 128/4; i++)
            ((unsigned int*)pdata)[i] = ByteReverse(((unsigned int*)pdata)[i]);

        // Get saved block
        if (!mapNewBlock.count(pdata->hashMerkleRoot))
            return false;
        CBlock* pblock = mapNewBlock[pdata->hashMerkleRoot].first;

        pblock->nTime = pdata->nTime;
        pblock->nNonce = pdata->nNonce;
        pblock->vtx[0].vin[0].scriptSig = mapNewBlock[pdata->hashMerkleRoot].second;
        pblock->hashMerkleRoot = pblock->BuildMerkleTree();

        return CheckWork(pblock, *pwalletMain, reservekey);
    }
}


static int MiningThreadCountFromParam(const Array& params, size_t index)
{
    int nThreads = 1;
    if (params.size() > index)
        nThreads = params[index].get_int();
    if (nThreads < 1)
        nThreads = 1;
    if (nThreads > 16)
        nThreads = 16;
    return nThreads;
}

Value setgenerate(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "setgenerate <generate> [blocks] [threads]\n"
            "Start or stop background CPU mining (regtest/testnet only).\n"
            "<generate> true to start mining, false to stop.\n"
            "[blocks] number of blocks to mine (default: 0 = unlimited).\n"
            "[threads] number of CPU miner threads (default: 1, max: 16).\n"
            "Returns immediately. Use getblockcount to monitor progress.");

    bool fGenerate = params[0].get_bool();

    if (!fRegTest && !fTestNet)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "setgenerate is only available in regtest/testnet mode");

    if (!fGenerate)
    {
        fCPUMining = false;
        nCPUMineTarget = 0;
        Object result;
        result.push_back(Pair("mining", false));
        return result;
    }

    if (fCPUMining)
    {
        fCPUMining = false;
        MilliSleep(600);
    }

    int nBlocks = 0;
    if (params.size() > 1)
        nBlocks = params[1].get_int();
    int nThreads = MiningThreadCountFromParam(params, 2);

    nCPUMineTarget = nBlocks;
    nCPUMinerThreads = nThreads;
    fCPUMining = true;

    bool fStarted = false;
    for (int i = 0; i < nThreads; i++)
    {
        if (NewThread(ThreadCPUMiner, pwalletMain))
        {
            fStarted = true;
        }
        else
        {
            printf("Error: NewThread(ThreadCPUMiner) failed for thread %d\n", i);
        }
    }
    if (!fStarted)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to start mining thread");

    Object result;
    result.push_back(Pair("mining", true));
    result.push_back(Pair("target_blocks", nBlocks == 0 ? 0 : nBlocks));
    result.push_back(Pair("threads", nThreads));
    result.push_back(Pair("height", nBestHeight));
    return result;
}

Value startmining(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "startmining [threads]\n"
            "Start background CPU PoW mining (testnet/regtest only).\n"
            "[threads] Number of mining threads (default: 1).");

    if (!fRegTest && !fTestNet)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "startmining is only available in regtest/testnet mode");

    if (fCPUMining)
        throw JSONRPCError(RPC_MISC_ERROR, "CPU mining is already running");

    int nThreads = MiningThreadCountFromParam(params, 0);

    nCPUMinerThreads = nThreads;
    nCPUMineTarget = 0;
    fCPUMining = true;

    for (int i = 0; i < nThreads; i++)
    {
        if (!NewThread(ThreadCPUMiner, pwalletMain))
            printf("Error: NewThread(ThreadCPUMiner) failed for thread %d\n", i);
    }

    Object result;
    result.push_back(Pair("mining", true));
    result.push_back(Pair("threads", nThreads));
    result.push_back(Pair("network", fTestNet ? "testnet" : "regtest"));
    return result;
}

Value stopmining(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "stopmining\n"
            "Stop background CPU PoW mining.");

    if (!fCPUMining)
        throw JSONRPCError(RPC_MISC_ERROR, "CPU mining is not running");

    fCPUMining = false;
    nCPUMineTarget = 0;

    Object result;
    result.push_back(Pair("mining", false));
    return result;
}

Value getblocktemplate(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getblocktemplate [params]\n"
            "Returns data needed to construct a block to work on:\n"
            "  \"version\" : block version\n"
            "  \"previousblockhash\" : hash of current highest block\n"
            "  \"transactions\" : contents of non-coinbase transactions that should be included in the next block\n"
            "  \"coinbaseaux\" : data that should be included in coinbase\n"
            "  \"coinbasevalue\" : maximum allowable input to coinbase transaction, including the generation award and transaction fees\n"
            "  \"target\" : hash target\n"
            "  \"mintime\" : minimum timestamp appropriate for next block\n"
            "  \"curtime\" : current timestamp\n"
            "  \"mutable\" : list of ways the block template may be changed\n"
            "  \"noncerange\" : range of valid nonces\n"
            "  \"sigoplimit\" : limit of sigops in blocks\n"
            "  \"sizelimit\" : limit of block size\n"
            "  \"bits\" : compressed target of next block\n"
            "  \"height\" : height of the next block\n"
            "  \"payee\" : required payee\n"
            "  \"payee_amount\" : required amount to pay\n"
			      "  \"collateralnode_payments\" : true|false,         (boolean) true, if collateralnode payments are enabled"
            "  \"enforce_collateralnode_payments\" : true|false  (boolean) true, if collateralnode payments are enforced"
            "  \"masternode_payments\" : true|false,         (boolean) true, if collateralnode payments are enabled"
            "  \"enforce_masternode_payments\" : true|false  (boolean) true, if collateralnode payments are enforced"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");

    std::string strMode = "template";
    if (params.size() > 0)
    {
        const Object& oparam = params[0].get_obj();
        const Value& modeval = find_value(oparam, "mode");
        if (modeval.type() == str_type)
            strMode = modeval.get_str();
        else if (modeval.type() == null_type)
        {
            /* Do nothing */
        }
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
    }

    if (strMode != "template")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");

    if (vNodes.empty())
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Innova is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Innova is downloading blocks...");

    static CReserveKey reservekey(pwalletMain);

    // Update block
    static unsigned int nTransactionsUpdatedLast;
    static CBlockIndex* pindexPrev;
    static int64_t nStart;
    static CBlock* pblock;
    if (pindexPrev != pindexBest ||
        (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 5))
    {
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = NULL;

        // Store the pindexBest used before CreateNewBlock, to avoid races
        nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
        CBlockIndex* pindexPrevNew = pindexBest;
        nStart = GetTime();

        // Create new block
        if(pblock)
        {
            delete pblock;
            pblock = NULL;
        }
        pblock = CreateNewBlock(pwalletMain);
        if (!pblock)
            throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");

        // Need to update only after we know CreateNewBlock succeeded
        pindexPrev = pindexPrevNew;
    }

    // Update nTime
    pblock->UpdateTime(pindexPrev);
    pblock->nNonce = 0;

    Array transactions;
    map<uint256, int64_t> setTxIndex;
    int i = 0;
    CTxDB txdb("r");
    for (CTransaction& tx : pblock->vtx)
    {
        uint256 txHash = tx.GetHash();
        setTxIndex[txHash] = i++;

        if (tx.IsCoinBase() || tx.IsCoinStake())
            continue;

        Object entry;

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << tx;
        entry.push_back(Pair("data", HexStr(ssTx.begin(), ssTx.end())));

        entry.push_back(Pair("hash", txHash.GetHex()));

        MapPrevTx mapInputs;
        map<uint256, CTxIndex> mapUnused;
        bool fInvalid = false;
        if (tx.FetchInputs(txdb, mapUnused, false, false, mapInputs, fInvalid))
        {
            entry.push_back(Pair("fee", (int64_t)(tx.GetValueIn(mapInputs) - tx.GetValueOut())));

            Array deps;
            BOOST_FOREACH (MapPrevTx::value_type& inp, mapInputs)
            {
                if (setTxIndex.count(inp.first))
                    deps.push_back(setTxIndex[inp.first]);
            }
            entry.push_back(Pair("depends", deps));

            int64_t nSigOps = tx.GetLegacySigOpCount();
            nSigOps += tx.GetP2SHSigOpCount(mapInputs);
            entry.push_back(Pair("sigops", nSigOps));
        }

        transactions.push_back(entry);
    }

    Object aux;
    aux.push_back(Pair("flags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end())));

    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

    static Array aMutable;
    if (aMutable.empty())
    {
        aMutable.push_back("time");
        aMutable.push_back("transactions");
        aMutable.push_back("prevblock");
    }

	CScript payee;

    Object result;
    result.push_back(Pair("version", pblock->nVersion));
    result.push_back(Pair("previousblockhash", pblock->hashPrevBlock.GetHex()));
    result.push_back(Pair("transactions", transactions));
    result.push_back(Pair("coinbaseaux", aux));
	  result.push_back(Pair("coinbasevalue", (int64_t)pblock->vtx[0].GetValueOut()));
    result.push_back(Pair("target", hashTarget.GetHex()));
    result.push_back(Pair("mintime", (int64_t)pindexPrev->GetPastTimeLimit()+1));
    result.push_back(Pair("mutable", aMutable));
    result.push_back(Pair("noncerange", "00000000ffffffff"));
    result.push_back(Pair("sigoplimit", (int64_t)MAX_BLOCK_SIGOPS));
    result.push_back(Pair("sizelimit", (int64_t)MAX_BLOCK_SIZE));
    result.push_back(Pair("curtime", (int64_t)pblock->nTime));
    result.push_back(Pair("bits", HexBits(pblock->nBits)));
    result.push_back(Pair("height", (int64_t)(pindexPrev->nHeight+1)));


    // ---- Collateralnode info ---

    bool bCollateralnodePayments = false;

    if(fTestNet) {
        if(pindexPrev->nHeight+1 >= BLOCK_START_COLLATERALNODE_PAYMENTS_TESTNET) bCollateralnodePayments = true;
    } else {
        if(pindexPrev->nHeight+1 >= BLOCK_START_COLLATERALNODE_PAYMENTS && pindexPrev->nHeight+1 >= 2085000) bCollateralnodePayments = true;
    }
    if(fDebug && fDebugCN) { printf("GetBlockTemplate(): Collateralnode Payments : %i\n", bCollateralnodePayments); }

    if(!collateralnodePayments.GetBlockPayee(pindexPrev->nHeight+1, payee)){
        //no collateralnode detected
		bool found = false;
                if (vecCollateralnodes.size() > 0) {
                GetCollateralnodeRanks(pindexBest);
                BOOST_FOREACH(PAIRTYPE(int, CCollateralNode*)& s, vecCollateralnodeScores)
                {
                        if (s.second->nBlockLastPaid < pindexBest->nHeight - 10) {
                                payee.SetDestination(s.second->pubkey.GetID());
                                found = true;
                                break;
                        }
                }
                }
                if (found) {
                    printf("CreateNewBlock: Found a collateralnode to pay: %s\n",payee.ToString(true).c_str());
                } else {
                    printf("CreateNewBlock: Failed to detect collateralnode to pay\n");
                    // pay the burn address if it can't detect
                    if (fDebug) printf("CreateNewBlock(): Failed to detect collateralnode to pay, burning coins.");
                    std::string burnAddress;
                    if (fTestNet) burnAddress = "8TestXXXXXXXXXXXXXXXXXXXXXXXXbCvpq";
                    else burnAddress = "INNXXXXXXXXXXXXXXXXXXXXXXXXXZeeDTw";
                    CBitcoinAddress burnAddr;
                    burnAddr.SetString(burnAddress);
                    payee = GetScriptForDestination(burnAddr.Get());
                }
    }
    if (fDebug && fDebugNet) printf("getblock : payee = %i, bCollateralnode = %i\n",payee != CScript(),bCollateralnodePayments);
    if(payee != CScript()){
		CTxDestination address1;
		ExtractDestination(payee, address1);
		CBitcoinAddress address2(address1);
		result.push_back(Pair("payee", address2.ToString().c_str()));
		result.push_back(Pair("payee_amount", (int64_t)GetCollateralnodePayment(pindexPrev->nHeight+1, pblock->vtx[0].GetValueOut())));
	  } else {
        result.push_back(Pair("payee", fTestNet ? "8TestXXXXXXXXXXXXXXXXXXXXXXXXbCvpq" : "INNXXXXXXXXXXXXXXXXXXXXXXXXXZeeDTw"));
	result.push_back(Pair("payee_amount", (int64_t)GetCollateralnodePayment(pindexPrev->nHeight+1, pblock->vtx[0].GetValueOut())));
    }

	  result.push_back(Pair("collateralnode_payments", bCollateralnodePayments));
    result.push_back(Pair("enforce_collateralnode_payments", bCollateralnodePayments));
    result.push_back(Pair("masternode_payments", bCollateralnodePayments));
    result.push_back(Pair("enforce_masternode_payments", bCollateralnodePayments));

    return result;
}

Value submitblock(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "submitblock <hex data> [optional-params-obj]\n"
            "[optional-params-obj] parameter is currently ignored.\n"
            "Attempts to submit new block to network.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");

    vector<unsigned char> blockData(ParseHex(params[0].get_str()));
    CDataStream ssBlock(blockData, SER_NETWORK, PROTOCOL_VERSION);
    CBlock block;
    try {
        ssBlock >> block;
    }
    catch (std::exception &e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }

    bool fAccepted = ProcessBlock(NULL, &block);
    if (!fAccepted)
        return "rejected";

    return Value::null;
}
