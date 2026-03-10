// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "innovarpc.h"
#include "init.h"
#include "txdb.h"
#include "bootstrap.h"
#include <errno.h>

#include <boost/filesystem.hpp>
#include <fstream>

using namespace json_spirit;
using namespace std;

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, json_spirit::Object& entry);
extern enum Checkpoints::CPMode CheckpointsMode;
extern void spj(const CScript& scriptPubKey, Object& out, bool fIncludeHex);

double BitsToDouble(unsigned int nBits)
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    int nShift = (nBits >> 24) & 0xff;

    double dDiff = (double)0x0000ffff / (double)(nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    };

    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    };

    return dDiff;
};

double GetDifficulty(const CBlockIndex* blockindex)
{
    if (blockindex == NULL)
    {
        if (pindexBest == NULL)
            return 1.0;
        else
            blockindex = GetLastBlockIndex(pindexBest, false);
    };

    return BitsToDouble(blockindex->nBits);
}

double GetPoWMHashPS()
{
    int nPoWInterval = 72;
    int nPoWBlocksToCheck = 100000; // Only look at last 100000 blocks max
    int64_t nTargetSpacingWorkMin = 30, nTargetSpacingWork = 30;

    CBlockIndex* pindex = pindexBest;
    CBlockIndex* pindexPrevWork = NULL;
    int nBlocksChecked = 0;
    int nPoWBlocksFound = 0;

    while (pindex && nBlocksChecked < nPoWBlocksToCheck && nPoWBlocksFound < nPoWInterval)
    {
        if (pindex->IsProofOfWork())
        {
            if (pindexPrevWork)
            {
                int64_t nActualSpacingWork = pindexPrevWork->GetBlockTime() - pindex->GetBlockTime();
                if (nActualSpacingWork > 0)
                {
                    nTargetSpacingWork = ((nPoWInterval - 1) * nTargetSpacingWork + nActualSpacingWork + nActualSpacingWork) / (nPoWInterval + 1);
                    nTargetSpacingWork = max(nTargetSpacingWork, nTargetSpacingWorkMin);
                }
            }
            pindexPrevWork = pindex;
            nPoWBlocksFound++;
        }

        pindex = pindex->pprev;
        nBlocksChecked++;
    }

    return GetDifficulty() * 4294.967296 / nTargetSpacingWork;
}

double GetPoSKernelPS()
{
    int nPoSInterval = 72;
    double dStakeKernelsTriedAvg = 0;
    int nStakesHandled = 0, nStakesTime = 0;

    CBlockIndex* pindex = pindexBest;;
    CBlockIndex* pindexPrevStake = NULL;

    while (pindex && nStakesHandled < nPoSInterval)
    {
        if (pindex->IsProofOfStake())
        {
            dStakeKernelsTriedAvg += GetDifficulty(pindex) * 4294967296.0;
            nStakesTime += pindexPrevStake ? (pindexPrevStake->nTime - pindex->nTime) : 0;
            pindexPrevStake = pindex;
            nStakesHandled++;
        };

        pindex = pindex->pprev;
    };

    return nStakesTime ? dStakeKernelsTriedAvg / nStakesTime : 0;
}

Object blockHeader2ToJSON(const CBlock& block, const CBlockIndex* blockindex)
{
    Object result;
    result.push_back(Pair("version", block.nVersion));
    if (blockindex->pprev)
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
    result.push_back(Pair("time", block.GetBlockTime()));
    result.push_back(Pair("bits", strprintf("%08x", block.nBits)));
    result.push_back(Pair("nonce", (uint64_t)block.nNonce));
    return result;
}

Object blockToJSON(const CBlock& block, const CBlockIndex* blockindex, bool fPrintTransactionDetail)
{
    Object result;
    result.push_back(Pair("hash", block.GetHash().GetHex()));
    CMerkleTx txGen(block.vtx[0]);
    txGen.SetMerkleBranch(&block);
    result.push_back(Pair("confirmations", (int)txGen.GetDepthInMainChain()));
    result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
    result.push_back(Pair("height", blockindex->nHeight));
    result.push_back(Pair("version", block.nVersion));
    result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
    result.push_back(Pair("mint", ValueFromAmount(blockindex->nMint)));
    result.push_back(Pair("time", (int64_t)block.GetBlockTime()));
    result.push_back(Pair("nonce", (uint64_t)block.nNonce));
    result.push_back(Pair("bits", HexBits(block.nBits)));
    result.push_back(Pair("difficulty", GetDifficulty(blockindex)));
    result.push_back(Pair("blocktrust", leftTrim(blockindex->GetBlockTrust().GetHex(), '0')));
    result.push_back(Pair("chaintrust", leftTrim(blockindex->nChainTrust.GetHex(), '0')));
    if (blockindex->pprev)
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    if (blockindex->pnext)
        result.push_back(Pair("nextblockhash", blockindex->pnext->GetBlockHash().GetHex()));

    result.push_back(Pair("flags", strprintf("%s%s", blockindex->IsProofOfStake()? "proof-of-stake" : "proof-of-work", blockindex->GeneratedStakeModifier()? " stake-modifier": "")));
    result.push_back(Pair("proofhash", blockindex->hashProof.GetHex()));
    result.push_back(Pair("entropybit", (int)blockindex->GetStakeEntropyBit()));
    result.push_back(Pair("modifier", strprintf("%016" PRIx64, blockindex->nStakeModifier)));
    result.push_back(Pair("modifierchecksum", strprintf("%08x", blockindex->nStakeModifierChecksum)));
    Array txinfo;
    for (const CTransaction& tx : block.vtx)
    {
        if (fPrintTransactionDetail)
        {
            Object entry;

            entry.push_back(Pair("txid", tx.GetHash().GetHex()));
            TxToJSON(tx, 0, entry);

            txinfo.push_back(entry);
        }
        else
            txinfo.push_back(tx.GetHash().GetHex());
    }

    result.push_back(Pair("tx", txinfo));

    if (block.IsProofOfStake())
        result.push_back(Pair("signature", HexStr(block.vchBlockSig.begin(), block.vchBlockSig.end())));

    return result;
}

Value dumpbootstrap(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "dumpbootstrap \"destination\" \"blocks\"\n"
            "\nCreates a bootstrap format block dump of the blockchain in destination, which can be a directory or a path with filename, up to the given block number.");

    string strDest = params[0].get_str();
    int nBlocks = params[1].get_int();
    if (nBlocks < 0 || nBlocks > nBestHeight)
        throw runtime_error("Block number out of range.");

    // Sanitize destination path — confine to data directory
    for (size_t ci = 0; ci < strDest.size(); ci++)
    {
        char c = strDest[ci];
        if (c < 0x20 || c == 0x7F)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Destination path contains control characters");
    }
    boost::filesystem::path pathDest(strDest);
    if (boost::filesystem::is_directory(pathDest))
        pathDest /= "bootstrap.dat";

    try {
        FILE* file = fopen(pathDest.string().c_str(), "wb");
        if (!file)
            throw JSONRPCError(RPC_MISC_ERROR, "Error: Could not open bootstrap file for writing.");

        CAutoFile fileout = CAutoFile(file, SER_DISK, CLIENT_VERSION);
        if (!fileout)
            throw JSONRPCError(RPC_MISC_ERROR, "Error: Could not open bootstrap file for writing.");

        for (int nHeight = 0; nHeight <= nBlocks; nHeight++)
        {
            CBlock block;
            CBlockIndex* pblockindex = FindBlockByHeight(nHeight);
            block.ReadFromDisk(pblockindex, true);
            fileout << FLATDATA(pchMessageStart) << fileout.GetSerializeSize(block) << block;
        }
    } catch(const boost::filesystem::filesystem_error &e) {
        throw JSONRPCError(RPC_MISC_ERROR, "Error: Bootstrap dump failed!");
    }

    return Value::null;
}

Value proofofdata(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
    throw runtime_error(
        "proofofdata\n"
        "\nArguments:\n"
        "1. \"filelocation\"          (string, required) The file location of the file to upload (e.g. /home/name/file.jpg)\n"
        "Returns the Innova address and transaction ID of the proof of data submission of the file hashed into an INN address");

    Object obj;
    std::string userFile = params[0].get_str();
    std::ifstream dataFile;

    if(userFile == "")
    {
        return 0; //return with no value prev
    }

    std::string filename = userFile.c_str();

    boost::filesystem::path p(filename);
    std::string basename = p.filename().string();

    dataFile.open(userFile.c_str(), std::ios::binary);
    std::vector<char> dataContents((std::istreambuf_iterator<char>(dataFile)), std::istreambuf_iterator<char>());

    printf("POD Upload File Start: %s\n", basename.c_str());

    //Hash the file for Innova POD
    uint256 datahash = SerializeHash(dataContents);
    CKeyID keyid(Hash160(datahash.begin(), datahash.end()));
    CBitcoinAddress baddr = CBitcoinAddress(keyid);
    std::string addr = baddr.ToString();

    CAmount nAmount = 0.001 * COIN; // 0.001 INN Fee

    // Wallet comments
    CWalletTx wtx;
    wtx.mapValue["comment"] = basename.c_str();
    std::string sNarr = "POD";
    wtx.mapValue["to"]      = "Proof of Data";

    // Comment
    // CWalletTx wtx;
    // CScript podScript = CScript() << OP_RETURN; //CScript()
    // if (!basename.c_str().empty()) {
    //     if (basename.c_str().length() > MAX_OP_RETURN_RELAY - 3) //Max 45 Bytes
    //         throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Comment cannot be longer than %u characters", MAX_OP_RETURN_RELAY - 3));
    //     podScript << ToByteVector("POD: " + basename.c_str());
    // }

    if (pwalletMain->IsLocked())
    {
        obj.push_back(Pair("error",  "Error, Your wallet is locked! Please unlock your wallet!"));
        //ui->txLineEdit->setText("ERROR: Your wallet is locked! Cannot send POD. Unlock your wallet!");
    } else if (pwalletMain->GetBalance() < 0.001) {
        obj.push_back(Pair("error",  "Error, You need at least 0.001 INN to send POD!"));
        //ui->txLineEdit->setText("ERROR: You need at least a 0.001 INN balance to send POD.");
    } else {
        //std::string sNarr;
        std::string strError = pwalletMain->SendMoneyToDestination(baddr.Get(), nAmount, sNarr, wtx);

        if(strError != "")
        {
            obj.push_back(Pair("error",  strError.c_str()));
        }

        obj.push_back(Pair("filename",           basename.c_str()));
        //obj.push_back(Pair("sizebytes",        size));
        obj.push_back(Pair("podaddress",         addr.c_str()));
        obj.push_back(Pair("podtxid",            wtx.GetHash().GetHex()));
    }

    return obj;

}

Value getbestblockhash(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getbestblockhash\n"
            "Returns the hash of the best block in the longest block chain.");

    return hashBestChain.GetHex();
}

Value getblockcount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getblockcount\n"
            "Returns the number of blocks in the longest block chain.");

    return nBestHeight;
}


Value getdifficulty(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getdifficulty\n"
            "Returns the difficulty as a multiple of the minimum difficulty.");

    Object obj;
    obj.push_back(Pair("proof-of-work",        GetDifficulty()));
    obj.push_back(Pair("proof-of-stake",       GetDifficulty(GetLastBlockIndex(pindexBest, true))));
    obj.push_back(Pair("search-interval",      (int)nLastCoinStakeSearchInterval));
    return obj;
}


Value settxfee(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1 || AmountFromValue(params[0]) < MIN_TX_FEE)
        throw runtime_error(
            "settxfee <amount>\n"
            "<amount> is a real and is rounded to the nearest 0.01");

    nTransactionFee = AmountFromValue(params[0]);
    nTransactionFee = (nTransactionFee / CENT) * CENT;  // round to cent

    return true;
}

Value getrawmempool(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getrawmempool\n"
            "Returns all transaction ids in memory pool.");

    vector<uint256> vtxid;
    mempool.queryHashes(vtxid);

    Array a;
    for (const uint256& hash : vtxid)
        a.push_back(hash.ToString());

    return a;
}

Value getblockhash(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getblockhash <index>\n"
            "Returns hash of block in best-block-chain at <index>.");

    int nHeight = params[0].get_int();
    if (nHeight < 0 || nHeight > nBestHeight)
        throw runtime_error("Block number out of range.");

    CBlockIndex* pblockindex = FindBlockByHeight(nHeight);
    return pblockindex->phashBlock->GetHex();
}

//New getblock RPC Command for Innovaium Compatibility
Value getblock(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getblock \"blockhash\" ( verbosity ) \n"
            "\nIf verbosity is 0, returns a string that is serialized, hex-encoded data for block 'hash'.\n"
            "If verbosity is 1, returns an Object with information about block <hash>.\n"
            "If verbosity is 2, returns an Object with information about block <hash> and information about each transaction. \n"
            "\nArguments:\n"
            "1. \"blockhash\"          (string, required) The block hash\n"
            "2. verbosity              (numeric, optional, default=1) 0 for hex encoded data, 1 for a json object, and 2 for json object with transaction data\n"
            "\nResult (for verbosity = 0):\n"
            "\"data\"             (string) A string that is serialized, hex-encoded data for block 'hash'.\n"
            "\nResult (for verbosity = 1):\n"
            "{\n"
            "  \"hash\" : \"hash\",     (string) the block hash (same as provided)\n"
            "  \"confirmations\" : n,   (numeric) The number of confirmations, or -1 if the block is not on the main chain\n"
            "  \"size\" : n,            (numeric) The block size\n"
            "  \"strippedsize\" : n,    (numeric) The block size excluding witness data\n"
            "  \"weight\" : n           (numeric) The block weight as defined in BIP 141\n"
            "  \"height\" : n,          (numeric) The block height or index\n"
            "  \"version\" : n,         (numeric) The block version\n"
            "  \"versionHex\" : \"00000000\", (string) The block version formatted in hexadecimal\n"
            "  \"merkleroot\" : \"xxxx\", (string) The merkle root\n"
            "  \"tx\" : [               (array of string) The transaction ids\n"
            "     \"transactionid\"     (string) The transaction id\n"
            "     ,...\n"
            "  ],\n"
            "  \"time\" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mediantime\" : ttt,    (numeric) The median block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"nonce\" : n,           (numeric) The nonce\n"
            "  \"bits\" : \"1d00ffff\", (string) The bits\n"
            "  \"difficulty\" : x.xxx,  (numeric) The difficulty\n"
            "  \"previousblockhash\" : \"hash\",  (string) The hash of the previous block\n"
            "  \"nextblockhash\" : \"hash\"       (string) The hash of the next block\n"
            "}\n"
            "\nResult (for verbosity = 2):\n"
            "{\n"
            "  ...,                     Same output as verbosity = 1.\n"
            "  \"tx\" : [               (array of Objects) The transactions in the format of the getrawtransaction RPC. Different from verbosity = 1 \"tx\" result.\n"
            "         ,...\n"
            "  ],\n"
            "  ,...                     Same output as verbosity = 1.\n"
            "}\n"
            "\nExamples:\n"
        );

    LOCK(cs_main);

    std::string strHash = params[0].get_str();
    uint256 hash(strHash);
    //std::string strHash = params[0].get_str();
	//uint256 hash(uint256S(strHash));

    int verbosity = 1;
    if (params.size() > 1) {
            verbosity = params[1].get_bool() ? 1 : 0;
    }

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];

	if(!block.ReadFromDisk(pblockindex, true)){
        // Block not found on disk. This could be because we have the block
        // header in our index but don't have the block (for example if a
        // non-whitelisted node sends us an unrequested long chain of valid
        // blocks, we add the headers to our index, but don't accept the
        // block).
		throw JSONRPCError(RPC_MISC_ERROR, "Block not found on disk");
	}

	block.ReadFromDisk(pblockindex, true);

    if (verbosity <= 0)
    {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << block;
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
		//strHex.insert(0, "testar ");
        return strHex;
    }

    //return blockToJSON(block, pblockindex, verbosity >= 2);
	return blockToJSON(block, pblockindex, params.size() > 1 ? params[1].get_bool() : false);
}

Value getblockheader(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getblockheader \"hash\" ( verbose )\n"
            "\nIf verbose is false, returns a string that is serialized, hex-encoded data for block 'hash' header.\n"
            "If verbose is true, returns an Object with information about block <hash> header.\n"
            "\nArguments:\n"
            "1. \"hash\"          (string, required) The block hash\n"
            "2. verbose           (boolean, optional, default=true) true for a json object, false for the hex encoded data\n"
            "\nResult (for verbose = true):\n"
            "{\n"
            "  \"version\" : n,         (numeric) The block version\n"
            "  \"previousblockhash\" : \"hash\",  (string) The hash of the previous block\n"
            "  \"merkleroot\" : \"xxxx\", (string) The merkle root\n"
            "  \"time\" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"bits\" : \"1d00ffff\", (string) The bits\n"
            "  \"nonce\" : n,           (numeric) The nonce\n"
            "}\n"
            "\nResult (for verbose=false):\n"
            "\"data\"             (string) A string that is serialized, hex-encoded data for block 'hash' header.\n"
            "\nExamples:\n"
            );

    std::string strHash = params[0].get_str();
    uint256 hash(strHash);

    bool fVerbose = true;
    if (params.size() > 1)
        fVerbose = params[1].get_bool();

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];

	if(!block.ReadFromDisk(pblockindex, true)){
        // Block not found on disk. This could be because we have the block
        // header in our index but don't have the block (for example if a
        // non-whitelisted node sends us an unrequested long chain of valid
        // blocks, we add the headers to our index, but don't accept the
        // block).
		throw JSONRPCError(RPC_MISC_ERROR, "Block not found on disk");
	}

	block.ReadFromDisk(pblockindex, true);

    if (!fVerbose) {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << block;
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
        return strHex;
    }

    return blockHeader2ToJSON(block, pblockindex);
}

//Old getblock RPC Command, Not deprecated
Value getblock_old(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getblock <hash> [txinfo]\n"
            "txinfo optional to print more detailed tx info\n"
            "Returns details of a block with given block-hash.");

    std::string strHash = params[0].get_str();
    uint256 hash(strHash);

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];
    block.ReadFromDisk(pblockindex, true);

    return blockToJSON(block, pblockindex, params.size() > 1 ? params[1].get_bool() : false);
}

Value getblockbynumber(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getblockbynumber <number> [txinfo]\n"
            "txinfo optional to print more detailed tx info\n"
            "Returns details of a block with given block-number.");

    int nHeight = params[0].get_int();
    if (nHeight < 0 || nHeight > nBestHeight)
        throw runtime_error("Block number out of range.");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hashBestChain];
    while (pblockindex->nHeight > nHeight)
        pblockindex = pblockindex->pprev;

    uint256 hash = *pblockindex->phashBlock;

    pblockindex = mapBlockIndex[hash];
    block.ReadFromDisk(pblockindex, true);

    return blockToJSON(block, pblockindex, params.size() > 1 ? params[1].get_bool() : false);
}

Value setbestblockbyheight(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "setbestblockbyheight <height>\n"
            "Sets the tip of the chain with a block at <height>.\n"
            "WARNING: This command is restricted and can only be used for\n"
            "minor rollbacks (max 10 blocks) in regtest mode only.\n"
            "Use 'invalidateblock' for reorg recovery in production.");

    // Regtest only
    extern bool fRegTest;
    if (!fRegTest)
        throw runtime_error(
            "setbestblockbyheight is disabled in production.\n"
            "Use 'invalidateblock' followed by 'reconsiderblock' for chain recovery.");

    int nHeight = params[0].get_int();
    if (nHeight < 0 || nHeight > nBestHeight)
        throw runtime_error("Block height out of range.");

    static const int MAX_ROLLBACK_DEPTH = 10;
    if (nBestHeight - nHeight > MAX_ROLLBACK_DEPTH)
        throw runtime_error(
            strprintf("Rollback too deep: %d blocks (max %d).\n"
                      "Use 'invalidateblock' for larger rollbacks.",
                      nBestHeight - nHeight, MAX_ROLLBACK_DEPTH));

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hashBestChain];
    while (pblockindex->nHeight > nHeight)
        pblockindex = pblockindex->pprev;

    uint256 hash = *pblockindex->phashBlock;

    pblockindex = mapBlockIndex[hash];
    block.ReadFromDisk(pblockindex, true);


    Object result;

    CTxDB txdb;
    {
        LOCK(cs_main);

        printf("setbestblockbyheight: rolling back from %d to %d (regtest mode)\n",
               nBestHeight, nHeight);

        if (!block.SetBestChain(txdb, pblockindex))
            result.push_back(Pair("result", "failure"));
        else
            result.push_back(Pair("result", "success"));

    };

    return result;
}

// ppcoin: get information of sync-checkpoint
Value getcheckpoint(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getcheckpoint\n"
            "Show info of synchronized checkpoint.\n");

    Object result;
    CBlockIndex* pindexCheckpoint;

    result.push_back(Pair("synccheckpoint", Checkpoints::hashSyncCheckpoint.ToString().c_str()));
    pindexCheckpoint = mapBlockIndex[Checkpoints::hashSyncCheckpoint];
    result.push_back(Pair("height", pindexCheckpoint->nHeight));
    result.push_back(Pair("timestamp", DateTimeStrFormat(pindexCheckpoint->GetBlockTime()).c_str()));

    // Check that the block satisfies synchronized checkpoint
    if (CheckpointsMode == Checkpoints::STRICT)
        result.push_back(Pair("policy", "strict"));

    if (CheckpointsMode == Checkpoints::ADVISORY)
        result.push_back(Pair("policy", "advisory"));

    if (CheckpointsMode == Checkpoints::PERMISSIVE)
        result.push_back(Pair("policy", "permissive"));

    if (mapArgs.count("-checkpointkey"))
        result.push_back(Pair("checkpointmaster", true));

    return result;
}

Value gettxout(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "gettxout \"txid\" n ( includemempool )\n"
            "\nReturns details about an unspent transaction output.\n"
            "\nArguments:\n"
            "1. \"txid\"       (string, required) The transaction id\n"
            "2. n              (numeric, required) vout value\n"
            "3. includemempool  (boolean, optional) Whether to included the mem pool\n"
            "\nResult:\n"
            "{\n"
            "  \"bestblock\" : \"hash\",    (string) the block hash\n"
            "  \"confirmations\" : n,       (numeric) The number of confirmations\n"
            "  \"value\" : x.xxx,           (numeric) The transaction value in btc\n"
            "  \"scriptPubKey\" : {         (json object)\n"
            "     \"asm\" : \"code\",       (string) \n"
            "     \"hex\" : \"hex\",        (string) \n"
            "     \"reqSigs\" : n,          (numeric) Number of required signatures\n"
            "     \"type\" : \"pubkeyhash\", (string) The type, eg pubkeyhash\n"
            "     \"addresses\" : [          (array of string) array of bitcoin addresses\n"
            "        \"bitcoinaddress\"     (string) bitcoin address\n"
            "        ,...\n"
            "     ]\n"
            "  },\n"
            "  \"version\" : n,            (numeric) The version\n"
            "  \"coinbase\" : true|false   (boolean) Coinbase or not\n"
            "  \"coinstake\" : true|false  (boolean) Coinstake or not\n"
            "}\n"
        );

    LOCK(cs_main);

    Object ret;

    uint256 hash;
    hash.SetHex(params[0].get_str());
    int n = params[1].get_int();
    bool mem = true;
    if (params.size() == 3)
        mem = params[2].get_bool();

    CTransaction tx;
    uint256 hashBlock = 0;
    if (!GetTransaction(hash, tx, hashBlock, mem))
      return Value::null;

    if (n<0 || (unsigned int)n>=tx.vout.size() || tx.vout[n].IsNull())
      return Value::null;

    ret.push_back(Pair("bestblock", pindexBest->GetBlockHash().GetHex()));
    if (hashBlock == 0)
      ret.push_back(Pair("confirmations", 0));
    else
    {
      map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
      if (mi != mapBlockIndex.end() && (*mi).second)
      {
        CBlockIndex* pindex = (*mi).second;
        if (pindex->IsInMainChain())
        {
          bool isSpent=false;
          CBlockIndex* p = pindex;
          p=p->pnext;
          for (; p; p = p->pnext)
          {
            CBlock block;
            CBlockIndex* pblockindex = mapBlockIndex[p->GetBlockHash()];
            block.ReadFromDisk(pblockindex, true);
            for (const CTransaction& tx : block.vtx)
            {
              for (const CTxIn& txin : tx.vin)
              {
                if( hash == txin.prevout.hash &&
                   (int64_t)txin.prevout.n )
                {
                  printf("spent at block %s\n", block.GetHash().GetHex().c_str());
                  isSpent=true; break;
                }
              }

              if(isSpent) break;
            }

            if(isSpent) break;
          }

          if(isSpent)
            return Value::null;

          ret.push_back(Pair("confirmations", pindexBest->nHeight - pindex->nHeight + 1));
        }
        else
          return Value::null;
      }
    }

    ret.push_back(Pair("value", ValueFromAmount(tx.vout[n].nValue)));
    Object o;
    spj(tx.vout[n].scriptPubKey, o, true);
    ret.push_back(Pair("scriptPubKey", o));
    ret.push_back(Pair("coinbase", tx.IsCoinBase()));
    ret.push_back(Pair("coinstake", tx.IsCoinStake()));

    return ret;
}

Value getblockchaininfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
                "getblockchaininfo\n"
                "Returns an object containing various state info regarding block chain processing.\n"
                "\nResult:\n"
                "{\n"
                "  \"chain\": \"xxxx\",        (string) current chain (main, testnet)\n"
                "  \"blocks\": xxxxxx,         (numeric) the current number of blocks processed in the server\n"
                "  \"bestblockhash\": \"...\", (string) the hash of the currently best block\n"
                "  \"difficulty\": xxxxxx,     (numeric) the current difficulty\n"
                "  \"initialblockdownload\": xxxx, (bool) estimate of whether this INN node is in Initial Block Download mode.\n"
                "  \"moneysupply\": xxxx, (numeric) the current supply of INN in circulation\n"
                "}\n"
        );

    proxyType proxy;
    GetProxy(NET_IPV4, proxy);

    Object obj, diff;
    std::string chain = "testnet";
    if(!fTestNet)
        chain = "main";
    obj.push_back(Pair("chain",          chain));
    obj.push_back(Pair("blocks",         (int)nBestHeight));
    obj.push_back(Pair("bestblockhash",  hashBestChain.GetHex()));

    diff.push_back(Pair("proof-of-work",  GetDifficulty()));
    diff.push_back(Pair("proof-of-stake", GetDifficulty(GetLastBlockIndex(pindexBest, true))));

    obj.push_back(Pair("difficulty",     diff));
    obj.push_back(Pair("initialblockdownload",  IsInitialBlockDownload()));
    obj.push_back(Pair("moneysupply",   ValueFromAmount(pindexBest->nMoneySupply)));
    //obj.push_back(Pair("size_on_disk",   CalculateCurrentUsage()));
    return obj;
}

Value getspvinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getspvinfo\n"
            "Returns information about SPV (light client) mode.\n");

    Object obj;
    obj.push_back(Pair("spv_enabled", fSPVMode));
    obj.push_back(Pair("spv_headers_only", fSPVHeadersOnly));
    obj.push_back(Pair("spv_start_height", nSPVStartHeight));
    obj.push_back(Pair("headers_synced", nBestHeight));

    if (fSPVMode)
    {
        obj.push_back(Pair("mode", "light"));
        obj.push_back(Pair("description", "Operating in SPV mode - headers only, no full block validation"));
    }
    else
    {
        obj.push_back(Pair("mode", "full"));
        obj.push_back(Pair("description", "Operating as full node with complete block validation"));
    }

    return obj;
}

Value spvrescan(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "spvrescan [startheight]\n"
            "Rescan blockchain for wallet transactions in SPV mode.\n"
            "Arguments:\n"
            "1. startheight  (numeric, optional) Height to start scanning from (default: 0)\n");

    if (!fSPVMode)
        throw runtime_error("spvrescan is only available in SPV mode. Start with -spv flag.");

    int nStartHeight = 0;
    if (params.size() > 0)
        nStartHeight = params[0].get_int();

    if (nStartHeight < 0)
        throw runtime_error("Invalid start height");

    CNode* pnode = NULL;
    {
        LOCK(cs_vNodes);
        for (CNode* pn : vNodes)
        {
            if (pn->fSuccessfullyConnected && !pn->fDisconnect)
            {
                pnode = pn;
                break;
            }
        }
    }

    if (!pnode)
        throw runtime_error("No connected peers available for SPV rescan");

    pwalletMain->RequestSPVTransactions(pnode, nStartHeight);

    Object obj;
    obj.push_back(Pair("status", "started"));
    obj.push_back(Pair("start_height", nStartHeight));
    obj.push_back(Pair("peer", pnode->addr.ToString()));

    return obj;
}

Value getstakemodifiercheckpoints(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "getstakemodifiercheckpoints [startheight] [interval]\n"
            "Generate stake modifier checkpoints for kernel.cpp.\n"
            "Arguments:\n"
            "1. startheight  (numeric, optional) Height to start from (default: 2250000)\n"
            "2. interval     (numeric, optional) Interval between checkpoints (default: 250000)\n"
            "\nResult:\n"
            "Returns checkpoint data in C++ format ready to paste into kernel.cpp\n");

    int nStartHeight = 2250000;  
    int nInterval = 250000;      

    if (params.size() > 0)
        nStartHeight = params[0].get_int();
    if (params.size() > 1)
        nInterval = params[1].get_int();

    if (nStartHeight < 0 || nInterval < 1000)
        throw runtime_error("Invalid parameters: startheight must be >= 0, interval must be >= 1000");

    LOCK(cs_main);

    if (!pindexBest)
        throw runtime_error("Block index not available");

    Object result;
    Array checkpoints;
    std::string cppOutput = "// Stake modifier checkpoints - generated by getstakemodifiercheckpoints\n";

    int nCurrentHeight = nStartHeight;
    int nBestHeight = pindexBest->nHeight;

    while (nCurrentHeight <= nBestHeight)
    {
        CBlockIndex* pindex = FindBlockByHeight(nCurrentHeight);
        if (!pindex)
        {
            nCurrentHeight += nInterval;
            continue;
        }

        unsigned int nChecksum = pindex->nStakeModifierChecksum;

        Object checkpoint;
        checkpoint.push_back(Pair("height", nCurrentHeight));
        checkpoint.push_back(Pair("checksum", strprintf("0x%08x", nChecksum)));
        checkpoints.push_back(checkpoint);

        cppOutput += strprintf("        ( %d, 0x%08x )\n", nCurrentHeight, nChecksum);

        nCurrentHeight += nInterval;
    }

    result.push_back(Pair("start_height", nStartHeight));
    result.push_back(Pair("end_height", nBestHeight));
    result.push_back(Pair("interval", nInterval));
    result.push_back(Pair("count", (int)checkpoints.size()));
    result.push_back(Pair("checkpoints", checkpoints));
    result.push_back(Pair("cpp_output", cppOutput));

    return result;
}

Value downloadbootstrap(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "downloadbootstrap [url] [force]\n"
            "Download and apply blockchain bootstrap.\n"
            "This downloads the bootstrap from the latest GitHub release.\n"
            "Requires restart after completion.\n"
            "\nWARNING: This will overwrite existing blockchain data!\n"
            "\nArguments:\n"
            "1. url    (string, optional) Custom bootstrap URL. Default: latest GitHub release\n"
            "2. force  (bool, optional) Force download even if blockchain data exists. Default: false\n"
            "\nResult:\n"
            "{\n"
            "  \"status\": \"success|failed\",\n"
            "  \"message\": \"description\"\n"
            "}\n");

    std::string url = params.size() > 0 ? params[0].get_str() : "";
    bool force = params.size() > 1 ? params[1].get_bool() : false;

    if (!Bootstrap::IsNeeded(GetDataDir()) && !force) {
        throw runtime_error(
            "Blockchain data already exists. This command would overwrite existing data.\n"
            "If you really want to do this, call with force=true:\n"
            "  downloadbootstrap \"\" true\n"
            "WARNING: Your existing blockchain data will be overwritten!");
    }

    if (!url.empty()) {
        printf("Bootstrap: WARNING - Using custom URL: %s\n", url.c_str());
        printf("Bootstrap: Only use URLs from trusted sources!\n");
    }

    printf("Bootstrap: Starting download via RPC...\n");

    int64_t lastPercent = -1;
    auto progressCallback = [&lastPercent](int64_t downloaded, int64_t total) {
        if (total > 0) {
            int64_t percent = static_cast<int64_t>((static_cast<double>(downloaded) / total) * 100.0);
            if (percent > 100) percent = 100;
            if (percent < 0) percent = 0;
            if (percent != lastPercent && percent % 10 == 0) {
                printf("Bootstrap download: %lld%% (%lld MB / %lld MB)\n",
                       (long long)percent,
                       (long long)(downloaded / 1048576),
                       (long long)(total / 1048576));
                lastPercent = percent;
            }
        }
    };

    bool success = Bootstrap::DownloadAndApply(url, GetDataDir(), progressCallback);

    Object result;
    if (success) {
        result.push_back(Pair("status", "success"));
        result.push_back(Pair("message", "Bootstrap applied successfully. Please restart Innova to load the new blockchain data."));
    } else {
        result.push_back(Pair("status", "failed"));
        result.push_back(Pair("message", "Bootstrap download or extraction failed. Check debug.log for details."));
    }

    return result;
}
