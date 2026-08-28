// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "innovarpc.h"
#include "init.h"
#include "txdb.h"
#include "bootstrap.h"
#include "finality.h"
#include "subsidy.h"
#include "dag.h"
#include "blockprofile.h"
#include "base58.h"
#include "net.h"
#include "ringsig.h"
#include "pod.h"
#include <errno.h>

#include <algorithm>
#include <boost/filesystem.hpp>
#include <fstream>
#include <map>
#include <set>

using namespace json_spirit;
using namespace std;

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, json_spirit::Object& entry);
extern enum Checkpoints::CPMode CheckpointsMode;
extern void spj(const CScript& scriptPubKey, Object& out, bool fIncludeHex);

static std::string FinalityTierName(FinalityTier tier)
{
    if (tier == FINALITY_HARD) return "hard";
    if (tier == FINALITY_SOFT) return "soft";
    if (tier == FINALITY_TENTATIVE) return "tentative";
    return "none";
}

static int EpochStateSchemaForHeight(int nHeight)
{
    if (nHeight >= FORK_HEIGHT_EPOCH_STATE_V3)
        return EPOCHSTATE_SCHEMA_V3;
    if (nHeight >= FORK_HEIGHT_EPOCH_STATE_V2)
        return EPOCHSTATE_SCHEMA_V2;
    return 0;
}

static std::string EpochStateAnchorRuleForHeight(int nHeight)
{
    if (nHeight >= FORK_HEIGHT_EPOCH_STATE_V3)
        return "canonical_epoch_end_boundary_v3";
    if (nHeight >= FORK_HEIGHT_EPOCH_STATE_V2)
        return "canonical_anchor_v2";
    return "legacy_live_dag_tip";
}

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

    if (blockindex->nHeight >= FORK_HEIGHT_POEM)
    {
        uint256 hashProofVal = (blockindex->IsProofOfStake() && blockindex->nHeight < FORK_HEIGHT_DAG) ? blockindex->hashProof : block.GetHash();
        result.push_back(Pair("entropy", GetBlockEntropy(hashProofVal).GetHex()));
    }

    if (blockindex->nHeight >= FORK_HEIGHT_FINALITY)
    {
        result.push_back(Pair("finalized", g_finalityTracker.IsFinalized(blockindex->nHeight)));
        std::vector<CFinalityVote> vFinalityVotes;
        FinalityEnvelopeDecodeResult voteEnvelopeFailure = FINALITY_ENVELOPE_NO_MATCH;
        if (!ExtractFinalityVotesFromBlockForHeight(
                block, blockindex->nHeight, vFinalityVotes,
                &voteEnvelopeFailure))
            throw JSONRPCError(RPC_DATABASE_ERROR,
                               strprintf("stored block has invalid finality vote envelope (decode=%d)",
                                         (int)voteEnvelopeFailure));
        Array voteArray;
        int64_t nFinalityVoteValue = 0;   // rewards of the votes this block carries
        int64_t nFinalityReward = 0;      // finality value this block actually mints
        for (const CFinalityVote& vote : vFinalityVotes)
        {
            Object voteObj;
            std::string strMode = "transparent";
            if (vote.nProofMode == FINALITY_PROOF_NULLSTAKE_V2)
                strMode = "nullstake_v2";
            else if (vote.nProofMode == FINALITY_PROOF_NULLSTAKE_V3_COLD)
                strMode = "nullstake_v3_cold";
            voteObj.push_back(Pair("proof_mode", strMode));
            if (vote.nProofMode == FINALITY_PROOF_NULLSTAKE_V3_COLD &&
                vote.privateProof.nullStakeV3Proof.nThresholdM > 0)
                voteObj.push_back(Pair("auth_mode",
                    vote.privateProof.nullStakeV3Proof.nAuthMode == NULLSTAKE_AUTHMODE_B2C_HIDDEN
                        ? std::string("b2c_hidden") : std::string("b2e_public")));
            voteObj.push_back(Pair("epoch", vote.nEpoch));
            voteObj.push_back(Pair("height", vote.nHeight));
            voteObj.push_back(Pair("block_hash", vote.hashBlock.GetHex()));
            voteObj.push_back(Pair("nullifier", vote.nullifier.GetHex()));
            if (vote.IsPrivate())
            {
                voteObj.push_back(Pair("weight_hidden", true));
                voteObj.push_back(Pair("reward_hidden", true));
                voteObj.push_back(Pair("curve_root", vote.privateProof.hashCurveRoot.GetHex()));
                voteObj.push_back(Pair("nullifier_root", vote.privateProof.hashNullifierRoot.GetHex()));
                voteObj.push_back(Pair("weight_commitment", vote.privateProof.stakeWeightCommitment.GetHash().GetHex()));
                voteObj.push_back(Pair("reward_commitment", vote.privateProof.rewardCommitment.GetHash().GetHex()));
            }
            else
            {
                voteObj.push_back(Pair("weight", FormatMoney(vote.nVoteWeight)));
                voteObj.push_back(Pair("reward", FormatMoney(vote.nReward)));
                CPubKey pubkey(vote.vchPubKey);
                if (pubkey.IsValid())
                    voteObj.push_back(Pair("voter", CBitcoinAddress(pubkey.GetID()).ToString()));
                voteObj.push_back(Pair("stake_utxos", (int)vote.vStakeProof.size()));
            }
            voteArray.push_back(voteObj);
            if (vote.nReward > 0 && nFinalityVoteValue <= MAX_MONEY - vote.nReward)
                nFinalityVoteValue += vote.nReward;
        }
        result.push_back(Pair("finality_votes", voteArray));
        // What this block CARRIES (informational) versus what it MINTS. Carrying a vote
        // mints nothing; the whole epoch is paid at its settlement height.
        result.push_back(Pair("finality_vote_value_carried", FormatMoney(nFinalityVoteValue)));
        int nSettlementEpoch = -1;
        if (IsFinalitySettlementHeight(blockindex->nHeight, &nSettlementEpoch))
        {
            std::vector<CFinalityVote> vSettlementVotes;
            std::vector<CTxOut> vSettlementLeg;
            if (GatherFinalitySettlementVotes(blockindex->pprev, nSettlementEpoch, vSettlementVotes) &&
                BuildFinalitySettlementOutputs(vSettlementVotes,
                                               GetClampedFinalitySettlementBudget(
                                                   blockindex->pprev, nSettlementEpoch),
                                               vSettlementLeg, nFinalityReward))
            {
                Object settleObj;
                settleObj.push_back(Pair("epoch", nSettlementEpoch));
                settleObj.push_back(Pair("counted_votes", (int)vSettlementVotes.size()));
                settleObj.push_back(Pair("paid_voters", (int)vSettlementLeg.size()));
                settleObj.push_back(Pair("total", FormatMoney(nFinalityReward)));
                result.push_back(Pair("finality_settlement", settleObj));
            }
        }
        result.push_back(Pair("finality_reward", FormatMoney(nFinalityReward)));
        std::vector<CFinalityTallyShare> vShares = ExtractFinalityTallySharesFromBlock(block);
        Array shareArray;
        for (const CFinalityTallyShare& share : vShares)
        {
            Object shareObj;
            shareObj.push_back(Pair("hash", share.GetHash().GetHex()));
            shareObj.push_back(Pair("version", share.nVersion));
            shareObj.push_back(Pair("epoch", share.nEpoch));
            shareObj.push_back(Pair("vote_nullifier", share.voteNullifier.GetHex()));
            shareObj.push_back(Pair("block_hash", share.hashBlock.GetHex()));
            shareObj.push_back(Pair("curve_root", share.hashCurveRoot.GetHex()));
            shareObj.push_back(Pair("nullifier_root", share.hashNullifierRoot.GetHex()));
            shareObj.push_back(Pair("committee_set_hash", share.committeeSetHash.GetHex()));
            shareObj.push_back(Pair("encrypted_recipients", (int)share.vEncryptedRecipientShares.size()));
            shareArray.push_back(shareObj);
        }
        result.push_back(Pair("finality_tally_shares", shareArray));
        std::vector<CFinalityTallyCertificate> vCerts;
        FinalityEnvelopeDecodeResult certEnvelopeFailure = FINALITY_ENVELOPE_NO_MATCH;
        if (!ExtractFinalityTallyCertificatesFromBlockForHeight(
                block, blockindex->nHeight, vCerts,
                &certEnvelopeFailure))
            throw JSONRPCError(RPC_DATABASE_ERROR,
                               strprintf("stored block has invalid finality certificate envelope (decode=%d)",
                                         (int)certEnvelopeFailure));
        Array certArray;
        for (const CFinalityTallyCertificate& cert : vCerts)
        {
            Object certObj;
            certObj.push_back(Pair("hash", cert.GetHash().GetHex()));
            certObj.push_back(Pair("version", cert.nVersion));
            certObj.push_back(Pair("signer_count", (int)cert.vSignerIndexes.size()));
            certObj.push_back(Pair("epoch", cert.nEpoch));
            certObj.push_back(Pair("height", cert.nHeight));
            certObj.push_back(Pair("block_hash", cert.hashBlock.GetHex()));
            certObj.push_back(Pair("tier", FinalityTierName((FinalityTier)cert.nTier)));
            certObj.push_back(Pair("private_weight", cert.HasPrivateWeight()));
            certObj.push_back(Pair("vote_nullifiers", (int)cert.vVoteNullifiers.size()));
            certObj.push_back(Pair("curve_root", cert.hashCurveRoot.GetHex()));
            certObj.push_back(Pair("nullifier_root", cert.hashNullifierRoot.GetHex()));
            certObj.push_back(Pair("committee_set_hash", cert.committeeSetHash.GetHex()));
            certObj.push_back(Pair("active_weight_commitment", cert.activeWeightCommitment.GetHash().GetHex()));
            certObj.push_back(Pair("winning_weight_commitment", cert.winningWeightCommitment.GetHash().GetHex()));
            certArray.push_back(certObj);
        }
        result.push_back(Pair("finality_tally_certificates", certArray));
    }

    // DAG metadata
    if (blockindex->nHeight >= FORK_HEIGHT_DAG && blockindex->phashBlock)
    {
        result.push_back(Pair("dag_block_producer", std::string("pow")));
        result.push_back(Pair("pos_block_production", false));
        CBlockDAGData dagData;
        if (g_dagManager.GetDAGData(blockindex->GetBlockHash(), dagData))
        {
            Array dagparents;
            for (const uint256& hp : dagData.vDAGParents)
                dagparents.push_back(hp.GetHex());
            result.push_back(Pair("dagparents", dagparents));

            Array dagchildren;
            for (const uint256& hc : dagData.vDAGChildren)
                dagchildren.push_back(hc.GetHex());
            result.push_back(Pair("dagchildren", dagchildren));

            result.push_back(Pair("dagblue", dagData.fBlue));
            result.push_back(Pair("dagscore", dagData.nDAGScore.GetHex()));
            result.push_back(Pair("dagorder", dagData.nDAGOrder));
            if (!dagData.vDAGParents.empty())
                result.push_back(Pair("selected_parent", dagData.vDAGParents[0].GetHex()));
            result.push_back(Pair("epoch", GetEpochForHeight(blockindex->nHeight)));
        }
    }

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

// Resolves the user's first argument into something a stamp can be checked against.
enum PodTargetKind
{
    POD_TARGET_NONE = 0,
    POD_TARGET_DIGEST,
    POD_TARGET_FILE,
    POD_TARGET_CID,
};

// fFileAllowed is false unless -enablefilerpc is set. The filesystem is not
// probed at all in that case: a stat here would answer "does this path exist"
// for any RPC caller, which is the disclosure the flag exists to prevent.
static PodTargetKind PodClassifyTarget(const std::string& strTarget, bool fFileAllowed)
{
    if (strTarget.empty())
        return POD_TARGET_NONE;
    // A bare SHA-256 wins over a same-named file; say so in the help.
    if (strTarget.size() == 64 && IsHex(strTarget))
        return POD_TARGET_DIGEST;
    if (fFileAllowed)
    {
        boost::system::error_code ec;
        if (boost::filesystem::is_regular_file(boost::filesystem::path(strTarget), ec))
            return POD_TARGET_FILE;
    }
    std::vector<unsigned char> vLocator;
    if (PodCidToLocator(strTarget, vLocator))
        return POD_TARGET_CID;
    return POD_TARGET_NONE;
}

Value proofofdata(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "proofofdata <filelocation> [blinded] [frompool]\n"
            "\nAnchors a SHA-256 digest of a local file in an OP_RETURN output on the Innova\n"
            "chain, so the file's existence at that block's time can be proven later.\n"
            "The file is hashed locally and is never uploaded anywhere.\n"
            "\nArguments:\n"
            "1. \"filelocation\"   (string, required) Path to the file, read by this node.\n"
            "2. blinded           (boolean, optional, default=true) Publish\n"
            "                     SHA-256(SHA-256(file) || salt) rather than the file's plain\n"
            "                     SHA-256. Save the returned salt: without it the stamp cannot\n"
            "                     be proven, and it is stored only in this wallet.\n"
            "3. frompool          (boolean, optional, default=false) Fund the stamp from\n"
            "                     shielded notes instead of transparent coins.\n"
            "\nWith blinded=false the on-chain digest is exactly what `sha256sum` prints, so\n"
            "anyone can verify the stamp with coreutils and a block explorer - but the digest\n"
            "then identifies the file to anyone who already holds a copy of it.\n"
            "\nThe stamp costs a normal transaction fee. The 0.01 INN it moves is paid back to\n"
            "this wallet; nothing is burned.\n"
            "\nA transparent stamp names the address that paid it, so every stamp an address\n"
            "makes is linkable to the others and to that address's whole transaction history.\n"
            "With frompool=true the stamp is carried by a shielded transfer: it has no input\n"
            "or output address at all, and two stamps from the same wallet are unlinkable.\n"
            "The digest, the stamp's existence and its block time stay public either way.\n"
            "\nThis command reads a path on the node's filesystem and requires -enablefilerpc=1.\n"
            "Verify a stamp with podverify.\n");

    PodRequireFileRpc("proofofdata");

    if (!pwalletMain)
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is not available.");

    std::string strFile = params[0].get_str();
    if (strFile.empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "filelocation is empty.");

    bool fBlinded = true;
    if (params.size() > 1)
        fBlinded = params[1].get_bool();

    bool fFromPool = false;
    if (params.size() > 2)
        fFromPool = params[2].get_bool();

    boost::filesystem::path p(strFile);
    std::string strBase = p.filename().string();

    std::vector<unsigned char> vFileDigest;
    std::string strError;
    if (!PodHashFile(strFile, vFileDigest, strError))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strError);

    std::vector<unsigned char> vSalt;
    std::vector<unsigned char> vStampDigest = vFileDigest;
    int nType = POD_TYPE_PLAIN;
    if (fBlinded)
    {
        nType = POD_TYPE_BLINDED;
        vSalt = PodNewSalt();
        vStampDigest = PodBlindDigest(vFileDigest, vSalt);
    }

    CWalletTx wtx;
    wtx.mapValue["comment"] = strBase;
    wtx.mapValue["to"] = "Proof of Data";
    wtx.mapValue["podsha256"] = HexStr(vFileDigest.begin(), vFileDigest.end());
    if (fBlinded)
        wtx.mapValue["podsalt"] = HexStr(vSalt.begin(), vSalt.end());

    strError = PodCreateStamp(pwalletMain, nType, vStampDigest,
                              std::vector<unsigned char>(), wtx, fFromPool);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    Object obj;
    obj.push_back(Pair("filename",   strBase));
    obj.push_back(Pair("type",       PodTypeName(nType)));
    obj.push_back(Pair("filesha256", HexStr(vFileDigest.begin(), vFileDigest.end())));
    if (fBlinded)
        obj.push_back(Pair("salt",   HexStr(vSalt.begin(), vSalt.end())));
    obj.push_back(Pair("stampdigest", HexStr(vStampDigest.begin(), vStampDigest.end())));
    obj.push_back(Pair("podtxid",    wtx.GetHash().GetHex()));
    obj.push_back(Pair("funding",    fFromPool ? "shielded" : "transparent"));
    if (fBlinded)
        obj.push_back(Pair("warning",
            "Save the salt. Without it this stamp proves nothing about the file."));
    return obj;
}

Value podverify(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "podverify <file|sha256-hex|cid> <txid> [salt-hex] [cid]\n"
            "\nChecks that a transaction carries a proof-of-data stamp for the given target,\n"
            "and reports the block time the stamp is anchored to.\n"
            "\nArguments:\n"
            "1. \"target\"   (string, required) One of:\n"
            "                 - a path to a file on this node (hashed locally),\n"
            "                 - a 64-character SHA-256 hex digest, as printed by sha256sum,\n"
            "                 - an IPFS CIDv0, for stamps whose only binding is a CID.\n"
            "               A 64-hex string is always read as a digest, never as a filename.\n"
            "2. \"txid\"     (string, required) The stamp transaction id.\n"
            "3. \"salt-hex\" (string, optional) 32-byte salt, required for a blinded stamp.\n"
            "4. \"cid\"      (string, optional) CIDv0 to compare against a hyperfile stamp's\n"
            "               locator, when the target is a file or a digest. A digest match with\n"
            "               a locator mismatch is reported as verified with a stale locator.\n"
            "\nA file-path target reads a path on the node's filesystem and requires\n"
            "-enablefilerpc=1. Digest and CID targets need no flag, so a stamp can always be\n"
            "checked by anyone holding the digest.\n"
            "\nThe attested time is the time of the block containing the transaction, not the\n"
            "nTime the transaction claims for itself.\n"
            "\nStamps made before this release carry no digest on chain: they pay an address\n"
            "derived from Hash160 of the digest. Those are reported with \"legacy\": true and\n"
            "bind only 160 bits; the digest itself is not recoverable from the chain. A legacy\n"
            "file stamp can only be checked by supplying the file, and a legacy hyperfile stamp\n"
            "only by supplying its CID.\n");

    uint256 hashTx;
    hashTx.SetHex(params[1].get_str());

    const bool fFileAllowed = GetBoolArg("-enablefilerpc", false);
    std::string strTarget = params[0].get_str();
    PodTargetKind kind = PodClassifyTarget(strTarget, fFileAllowed);
    if (kind == POD_TARGET_NONE)
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            fFileAllowed
                ? "target is not a readable file, a 64-character SHA-256 hex digest, or a CIDv0."
                : "target is not a 64-character SHA-256 hex digest or a CIDv0. A file-path "
                  "target requires -enablefilerpc=1.");

    std::vector<unsigned char> vSalt;
    if (params.size() > 2 && !params[2].get_str().empty())
    {
        std::string strSalt = params[2].get_str();
        if (strSalt.size() != POD_SALT_SIZE * 2 || !IsHex(strSalt))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "salt-hex must be 32 bytes of hex.");
        vSalt = ParseHex(strSalt);
    }

    // Target digests. The file form yields both the modern SHA-256 and the digest
    // the legacy path used, so one call answers either stamp shape. It is computed
    // before any lock is taken: the file is streamed twice and may be any size.
    std::vector<unsigned char> vTargetSha256;
    uint256 hashLegacy = 0;
    bool fHaveLegacyDigest = false;
    std::vector<unsigned char> vTargetLocator;

    if (kind == POD_TARGET_DIGEST)
    {
        vTargetSha256 = ParseHex(strTarget);
    }
    else if (kind == POD_TARGET_FILE)
    {
        std::string strError;
        if (!PodHashFile(strTarget, vTargetSha256, strError))
            throw JSONRPCError(RPC_INVALID_PARAMETER, strError);
        if (!PodLegacyHashFile(strTarget, hashLegacy, strError))
            throw JSONRPCError(RPC_INVALID_PARAMETER, strError);
        fHaveLegacyDigest = true;
    }
    else // POD_TARGET_CID
    {
        PodCidToLocator(strTarget, vTargetLocator);
    }

    if (params.size() > 3 && !params[3].get_str().empty())
    {
        if (kind == POD_TARGET_CID)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "The target is already a CID; do not pass a fourth argument.");
        if (!PodCidToLocator(params[3].get_str(), vTargetLocator))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "cid is not a CIDv0 sha2-256 multihash.");
    }

    // Chain reads from here down. podverify never touches the wallet, so its
    // dispatch row is unlocked and only cs_main is taken.
    LOCK(cs_main);

    CTransaction tx;
    uint256 hashBlock = 0;
    if (!GetTransaction(hashTx, tx, hashBlock, true))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No transaction with that txid.");

    Object obj;
    obj.push_back(Pair("txid", hashTx.GetHex()));

    CPodStamp stamp;
    bool fHaveStamp = PodFindStamp(tx, stamp);
    bool fMatch = false;
    std::string strNote;

    if (fHaveStamp)
    {
        obj.push_back(Pair("legacy", false));
        obj.push_back(Pair("stampversion", stamp.nStampVersion));
        obj.push_back(Pair("type", PodTypeName(stamp.nType)));
        obj.push_back(Pair("typeid", stamp.nType));
        obj.push_back(Pair("vout", stamp.nOut));
        obj.push_back(Pair("stampdigest", HexStr(stamp.vDigest.begin(), stamp.vDigest.end())));

        std::string strCid = PodLocatorToCid(stamp.vLocator);
        if (!strCid.empty())
            obj.push_back(Pair("locatorcid", strCid));

        if (stamp.nStampVersion != (int)POD_STAMP_VERSION)
        {
            strNote = "Stamp version is not understood by this build; digest not compared.";
        }
        else if (kind == POD_TARGET_CID)
        {
            // A CID binds the locator only. It is a retrieval hint, never the proof.
            fMatch = (!stamp.vLocator.empty() && stamp.vLocator == vTargetLocator);
            obj.push_back(Pair("locatormatch", fMatch));
            strNote = fMatch
                ? "Locator matches, but the locator is only a retrieval hint. Supply the file "
                  "or its SHA-256 to check the digest, which is what actually binds."
                : "Locator does not match, or the stamp carries none. Supply the file or its "
                  "SHA-256 to check the digest, which is what actually binds.";
        }
        else if (stamp.nType == POD_TYPE_PLAIN || stamp.nType == POD_TYPE_HYPERFILE)
        {
            fMatch = (vTargetSha256 == stamp.vDigest);
            if (!vSalt.empty())
                strNote = "This stamp is not blinded; the salt was ignored.";
        }
        else if (stamp.nType == POD_TYPE_BLINDED)
        {
            if (vSalt.empty())
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "This is a blinded stamp; salt-hex is required to verify it.");
            fMatch = (PodBlindDigest(vTargetSha256, vSalt) == stamp.vDigest);
        }
        else
        {
            strNote = "Stamp type is not understood by this build; digest not compared.";
        }

        // A hyperfile stamp whose digest matches is proven even if the CID rotated.
        if (stamp.nType == POD_TYPE_HYPERFILE && kind != POD_TARGET_CID
            && !vTargetLocator.empty())
        {
            const bool fLocatorMatch = (stamp.vLocator == vTargetLocator);
            obj.push_back(Pair("locatormatch", fLocatorMatch));
            if (fMatch && !fLocatorMatch)
                strNote = "Verified; locator stale. The digest binds, so the stamp still proves "
                          "the file even though the CID on chain is not the one supplied.";
        }
    }
    else
    {
        // Legacy: the chain holds Hash160(digest) inside a P2PKH output, not the digest.
        obj.push_back(Pair("legacy", true));
        obj.push_back(Pair("type", "legacy-address"));

        CKeyID keyidTarget;
        bool fHaveTargetKey = false;
        if (kind == POD_TARGET_FILE && fHaveLegacyDigest)
        {
            keyidTarget = CKeyID(Hash160(hashLegacy.begin(), hashLegacy.end()));
            fHaveTargetKey = true;
        }
        else if (kind == POD_TARGET_CID)
        {
            keyidTarget = CKeyID(Hash160(strTarget.begin(), strTarget.end()));
            fHaveTargetKey = true;
        }
        else
        {
            strNote = "This transaction carries no on-chain digest, and a legacy stamp cannot "
                      "be checked from a bare SHA-256: the legacy digest is a double-SHA-256 "
                      "over a length-prefixed copy of the file. Supply the file itself, or the "
                      "CID for a legacy hyperfile stamp.";
        }

        if (fHaveTargetKey)
        {
            for (unsigned int i = 0; i < tx.vout.size(); i++)
            {
                CTxDestination dest;
                if (!ExtractDestination(tx.vout[i].scriptPubKey, dest))
                    continue;
                const CKeyID* pkeyid = boost::get<CKeyID>(&dest);
                if (pkeyid && *pkeyid == keyidTarget)
                {
                    fMatch = true;
                    obj.push_back(Pair("vout", (int)i));
                    break;
                }
            }
            obj.push_back(Pair("podaddress", CBitcoinAddress(keyidTarget).ToString()));
            if (fMatch)
                strNote = "Legacy stamp. The chain holds only Hash160 of the digest, so this "
                          "binds 160 bits, not 256, and the digest itself is not on chain.";
        }
    }

    obj.push_back(Pair("match", fMatch));

    // Anchoring. The block's time is the attested time; the transaction's own
    // nTime is chosen by its sender and proves nothing.
    CBlockIndex* pindex = NULL;
    if (hashBlock != 0)
    {
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end() && mi->second->IsInMainChain())
            pindex = mi->second;
    }

    if (pindex)
    {
        obj.push_back(Pair("blockhash", hashBlock.GetHex()));
        obj.push_back(Pair("height", pindex->nHeight));
        obj.push_back(Pair("blocktime", (boost::int64_t)pindex->GetBlockTime()));
        obj.push_back(Pair("confirmations", nBestHeight - pindex->nHeight + 1));

        int nFinalizedHeight = 0;
        const int nCompletedEpoch = GetEpochForHeight(nBestHeight) - 1;
        const bool fHaveFinalized = nCompletedEpoch >= 0
            && g_dagManager.TryGetDeterministicFinalizedHeight(nCompletedEpoch, nFinalizedHeight);
        if (fHaveFinalized)
        {
            obj.push_back(Pair("finalizedheight", nFinalizedHeight));
            obj.push_back(Pair("finalized", pindex->nHeight <= nFinalizedHeight));
        }
        else
        {
            obj.push_back(Pair("finalized", false));
            obj.push_back(Pair("finalizednote",
                "No completed epoch state; this node cannot say whether the block is finalized."));
        }
    }
    else if (hashBlock != 0)
    {
        obj.push_back(Pair("blockhash", hashBlock.GetHex()));
        obj.push_back(Pair("confirmations", 0));
        obj.push_back(Pair("finalized", false));
        obj.push_back(Pair("blocknote", "Containing block is not in the main chain."));
    }
    else
    {
        obj.push_back(Pair("confirmations", 0));
        obj.push_back(Pair("finalized", false));
        obj.push_back(Pair("blocknote",
            "Transaction is unconfirmed; it attests to no time until it is in a block."));
    }

    obj.push_back(Pair("txntime", (boost::int64_t)tx.nTime));
    if (!strNote.empty())
        obj.push_back(Pair("note", strNote));
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

Value getblockprofile(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getblockprofile [reset]\n"
            "Per-phase block-connect timings accumulated since the last reset.\n"
            "Requires -blockprofile at startup.");

    const bool fReset = params.size() > 0 && params[0].get_bool();
    Object obj;
    obj.push_back(Pair("enabled", fBlockProfile));
    obj.push_back(Pair("report", BlockProfileReport()));
    if (fReset)
        BlockProfileReset();
    return obj;
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
            "2. verbosity              (numeric or boolean, optional, default=1) 0 for hex encoded data, 1 for a json object, and 2 for json object with transaction data; false/true are accepted as 0/1\n"
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

    // Documented 0/1/2. Boolean callers predate the numeric form and still work:
    // false is 0, true is 1.
    int verbosity = 1;
    if (params.size() > 1) {
        if (params[1].type() == bool_type)
            verbosity = params[1].get_bool() ? 1 : 0;
        else
            verbosity = params[1].get_int();
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

    return blockToJSON(block, pblockindex, verbosity >= 2);
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

Value invalidateblock(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "invalidateblock \"hash\"\n"
            "Permanently marks a block as invalid, as if it violated a consensus rule.\n"
            "Disconnects it (and its descendants) from the active chain if present, and\n"
            "re-selects the best valid chain. Use 'reconsiderblock' to undo. A finality\n"
            "guard will reject invalidating a finalized-or-lower block.");

    LOCK(cs_main);
    uint256 hash(params[0].get_str());
    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
    CBlockIndex* pindex = mapBlockIndex[hash];

    CTxDB txdb;
    std::string strError;
    if (!InvalidateBlock(txdb, pindex, strError))
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    return Value::null;
}

Value reconsiderblock(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "reconsiderblock \"hash\"\n"
            "Removes invalidity status from a block and its descendant subtree, allowing\n"
            "them to be reconsidered for the best chain. Undoes 'invalidateblock'.");

    LOCK(cs_main);
    uint256 hash(params[0].get_str());
    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
    CBlockIndex* pindex = mapBlockIndex[hash];

    CTxDB txdb;
    std::string strError;
    if (!ReconsiderBlock(txdb, pindex, strError))
        throw JSONRPCError(RPC_MISC_ERROR, strError);
    return Value::null;
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

namespace
{
struct V5PrototypeVersionInventory
{
    int64_t nTransactions;
    int64_t nSpends;
    int64_t nOutputs;
    int64_t nPoolDelta;

    V5PrototypeVersionInventory()
        : nTransactions(0), nSpends(0), nOutputs(0), nPoolDelta(0)
    {
    }
};

static bool V5InventoryAddMoney(int64_t& total, int64_t value)
{
    if (total < 0 || value < 0 || value > MAX_MONEY - total)
        return false;
    total += value;
    return true;
}

static bool V5InventoryLegacyRingValue(
    const CTxIn& txin,
    const std::map<std::vector<unsigned char>, int64_t>& anonOutputs,
    int64_t& valueOut, std::string& errorOut)
{
    valueOut = -1;
    errorOut.clear();
    const int nRingSize = txin.ExtractRingSize();
    if (nRingSize <= 0)
    {
        errorOut = "invalid v1000 ring size";
        return false;
    }

    const CScript& script = txin.scriptSig;
    const size_t ringSize = (size_t)nRingSize;
    const size_t abSize = 2 + ec_secret_size +
        (ec_secret_size + ec_compressed_size) * ringSize;
    const bool isAB = nRingSize > 1 && script.size() == abSize;
    const size_t standardMinimum = 2 +
        (ec_compressed_size + ec_secret_size + ec_secret_size) * ringSize;
    if (!isAB && script.size() < standardMinimum)
    {
        errorOut = "truncated v1000 ring script";
        return false;
    }
    const size_t pubkeyOffset = isAB
        ? 2 + ec_secret_size + ec_secret_size * ringSize
        : 2;

    for (size_t i = 0; i < ringSize; ++i)
    {
        const size_t offset = pubkeyOffset + i * ec_compressed_size;
        if (offset > script.size() ||
            script.size() - offset < ec_compressed_size)
        {
            errorOut = "truncated v1000 ring pubkey layout";
            return false;
        }
        const std::vector<unsigned char> pubkey(
            script.begin() + offset,
            script.begin() + offset + ec_compressed_size);
        const std::map<std::vector<unsigned char>, int64_t>::const_iterator it =
            anonOutputs.find(pubkey);
        if (it == anonOutputs.end())
        {
            errorOut = "v1000 ring references an unavailable output";
            return false;
        }
        if (valueOut == -1)
            valueOut = it->second;
        else if (valueOut != it->second)
        {
            errorOut = "v1000 ring members disagree on value";
            return false;
        }
    }
    if (valueOut < 0 || !MoneyRange(valueOut))
    {
        errorOut = "v1000 ring value is outside the money range";
        return false;
    }
    return true;
}
}

Value getv5migrationinventory(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1 || !params[0].get_bool())
        throw runtime_error(
            "getv5migrationinventory true\n"
            "Performs a full, read-only replay inventory of the locked active "
            "chain. The explicit true acknowledges that block connection is "
            "paused for the duration.\n");

    LOCK(cs_main);
    if (!pindexBest || !pindexGenesisBlock)
        throw JSONRPCError(RPC_DATABASE_ERROR,
                           "active chain is unavailable");

    std::vector<CBlockIndex*> chain;
    for (CBlockIndex* pindex = pindexBest; pindex; pindex = pindex->pprev)
        chain.push_back(pindex);
    std::reverse(chain.begin(), chain.end());
    if (chain.empty() || chain.front() != pindexGenesisBlock)
        throw JSONRPCError(RPC_DATABASE_ERROR,
                           "active chain does not reach the configured genesis");

    std::map<std::vector<unsigned char>, int64_t> anonOutputs;
    std::set<std::vector<unsigned char> > anonKeyImages;
    std::set<uint256> prototypeNullifiers;
    int64_t legacyTransactions = 0;
    int64_t legacyOutputCount = 0;
    int64_t legacyInputCount = 0;
    int64_t legacyCreated = 0;
    int64_t legacySpent = 0;
    int64_t prototypeTransactions = 0;
    int64_t prototypeSpendCount = 0;
    int64_t prototypeOutputCount = 0;
    int64_t prototypePool = 0;
    int64_t preBindingSpendCount = 0;
    int64_t boundSpendCount = 0;
    int earliestPrototypeHeight = -1;
    int latestPrototypeHeight = -1;
    V5PrototypeVersionInventory versions[8];

    CHashWriter activeChainDigest(SER_GETHASH, 0);
    CHashWriter migrationSourceDigest(SER_GETHASH, 0);
    activeChainDigest << std::string("Innova/V5/ActiveChainInventory/v1");
    migrationSourceDigest << std::string("Innova/V5/MigrationSources/v1");
    activeChainDigest << GetGenesisBlockHash();
    migrationSourceDigest << GetGenesisBlockHash();

    for (size_t chainPosition = 0; chainPosition < chain.size(); ++chainPosition)
    {
        CBlockIndex* pindex = chain[chainPosition];
        if (pindex->nHeight != (int)chainPosition)
            throw JSONRPCError(RPC_DATABASE_ERROR,
                               "active chain height sequence is not contiguous");
        CBlock block;
        if (!block.ReadFromDisk(pindex, true))
            throw JSONRPCError(
                RPC_DATABASE_ERROR,
                strprintf("cannot read active block at height %d", pindex->nHeight));
        if (block.GetHash() != pindex->GetBlockHash())
            throw JSONRPCError(
                RPC_DATABASE_ERROR,
                strprintf("active block hash mismatch at height %d", pindex->nHeight));

        activeChainDigest << pindex->nHeight << pindex->GetBlockHash();
        for (size_t txPosition = 0; txPosition < block.vtx.size(); ++txPosition)
        {
            const CTransaction& tx = block.vtx[txPosition];
            const uint256 txid = tx.GetHash();
            if (tx.nVersion == ANON_TXN_VERSION)
            {
                ++legacyTransactions;
                migrationSourceDigest << pindex->nHeight << (uint32_t)txPosition
                                      << tx.nVersion << txid;
                for (size_t input = 0; input < tx.vin.size(); ++input)
                {
                    const CTxIn& txin = tx.vin[input];
                    if (!txin.IsAnonInput())
                        continue;
                    std::vector<unsigned char> keyImage;
                    txin.ExtractKeyImage(keyImage);
                    if (!anonKeyImages.insert(keyImage).second)
                        throw JSONRPCError(
                            RPC_DATABASE_ERROR,
                            strprintf("duplicate v1000 key image at height %d",
                                      pindex->nHeight));
                    int64_t value = -1;
                    std::string error;
                    if (!V5InventoryLegacyRingValue(
                            txin, anonOutputs, value, error))
                        throw JSONRPCError(
                            RPC_DATABASE_ERROR,
                            strprintf("%s at height %d tx %s input %u",
                                      error.c_str(), pindex->nHeight,
                                      txid.GetHex().c_str(), (unsigned int)input));
                    if (!V5InventoryAddMoney(legacySpent, value))
                        throw JSONRPCError(RPC_DATABASE_ERROR,
                                           "v1000 spent-value overflow");
                    ++legacyInputCount;
                }
                for (size_t output = 0; output < tx.vout.size(); ++output)
                {
                    const CTxOut& txout = tx.vout[output];
                    if (!txout.IsAnonOutput())
                        continue;
                    const std::vector<unsigned char> pubkey =
                        txout.ExtractAnonPk().Raw();
                    if (!MoneyRange(txout.nValue) || txout.nValue < 0)
                        throw JSONRPCError(RPC_DATABASE_ERROR,
                                           "v1000 output value is invalid");
                    if (!anonOutputs.insert(
                            std::make_pair(pubkey, txout.nValue)).second)
                        throw JSONRPCError(
                            RPC_DATABASE_ERROR,
                            strprintf("duplicate v1000 output key at height %d",
                                      pindex->nHeight));
                    if (!V5InventoryAddMoney(legacyCreated, txout.nValue))
                        throw JSONRPCError(RPC_DATABASE_ERROR,
                                           "v1000 created-value overflow");
                    ++legacyOutputCount;
                }
                continue;
            }

            if (!IsLegacyShieldedTransactionVersion(tx.nVersion))
                continue;

            const int versionIndex = tx.nVersion - SHIELDED_TX_VERSION;
            V5PrototypeVersionInventory& version = versions[versionIndex];
            ++version.nTransactions;
            version.nSpends += (int64_t)tx.vShieldedSpend.size();
            version.nOutputs += (int64_t)tx.vShieldedOutput.size();
            ++prototypeTransactions;
            prototypeSpendCount += (int64_t)tx.vShieldedSpend.size();
            prototypeOutputCount += (int64_t)tx.vShieldedOutput.size();
            if (earliestPrototypeHeight < 0)
                earliestPrototypeHeight = pindex->nHeight;
            latestPrototypeHeight = pindex->nHeight;
            migrationSourceDigest << pindex->nHeight << (uint32_t)txPosition
                                  << tx.nVersion << txid;

            if (tx.nValueBalance < -MAX_MONEY ||
                tx.nValueBalance > MAX_MONEY)
                throw JSONRPCError(RPC_DATABASE_ERROR,
                                   "prototype value balance is invalid");
            const int64_t poolDelta = -tx.nValueBalance;
            if ((poolDelta > 0 && version.nPoolDelta > MAX_MONEY - poolDelta) ||
                (poolDelta < 0 && version.nPoolDelta < -MAX_MONEY - poolDelta))
                throw JSONRPCError(RPC_DATABASE_ERROR,
                                   "prototype per-version pool delta overflow");
            version.nPoolDelta += poolDelta;
            if (poolDelta >= 0)
            {
                if (!V5InventoryAddMoney(prototypePool, poolDelta))
                    throw JSONRPCError(RPC_DATABASE_ERROR,
                                       "prototype pool value overflow");
            }
            else
            {
                const int64_t leavingPool = -poolDelta;
                if (prototypePool < leavingPool)
                    throw JSONRPCError(
                        RPC_DATABASE_ERROR,
                        strprintf("prototype pool underflow at height %d",
                                  pindex->nHeight));
                prototypePool -= leavingPool;
            }

            for (size_t spend = 0; spend < tx.vShieldedSpend.size(); ++spend)
            {
                const CShieldedSpendDescription& description =
                    tx.vShieldedSpend[spend];
                if (!prototypeNullifiers.insert(description.nullifier).second)
                    throw JSONRPCError(
                        RPC_DATABASE_ERROR,
                        strprintf("duplicate prototype nullifier at height %d",
                                  pindex->nHeight));
                if (pindex->nHeight < FORK_HEIGHT_NULLIFIER_BINDING)
                {
                    ++preBindingSpendCount;
                }
                else
                {
                    if (!description.HasNullifierBinding())
                        throw JSONRPCError(
                            RPC_DATABASE_ERROR,
                            strprintf("missing post-binding proof at height %d",
                                      pindex->nHeight));
                    ++boundSpendCount;
                }
            }
        }
    }

    if (legacySpent > legacyCreated)
        throw JSONRPCError(RPC_DATABASE_ERROR,
                           "v1000 aggregate pool underflow");
    const int64_t legacyUnclaimed = legacyCreated - legacySpent;
    const bool ambiguousPrototype =
        prototypePool > 0 && preBindingSpendCount > 0;

    std::string prototypeClass = "zero";
    if (prototypePool > 0)
        prototypeClass = ambiguousPrototype
            ? "ambiguous_pre_binding"
            : "bound_nullifier";
    else if (preBindingSpendCount > 0)
        prototypeClass = "zero_with_pre_binding_history";

    std::string inventoryGate = "clear";
    if (ambiguousPrototype)
        inventoryGate = "no_go_ambiguous_prototype";
    else if (legacyUnclaimed > 0 && prototypePool > 0)
        inventoryGate = "v1000_and_prototype_adapters_required";
    else if (legacyUnclaimed > 0)
        inventoryGate = "v1000_claim_required";
    else if (prototypePool > 0)
        inventoryGate = "prototype_adapter_required";

    Object legacy;
    legacy.push_back(Pair("transaction_count", legacyTransactions));
    legacy.push_back(Pair("output_count", legacyOutputCount));
    legacy.push_back(Pair("key_image_count", legacyInputCount));
    legacy.push_back(Pair("created_atomic", legacyCreated));
    legacy.push_back(Pair("spent_atomic", legacySpent));
    legacy.push_back(Pair("unclaimed_atomic", legacyUnclaimed));
    legacy.push_back(Pair("unclaimed", FormatMoney(legacyUnclaimed)));
    legacy.push_back(Pair("claim_rule",
                          std::string("exact_output_historical_key_image")));

    Array versionArray;
    for (int i = 0; i < 8; ++i)
    {
        Object version;
        version.push_back(Pair("version", SHIELDED_TX_VERSION + i));
        version.push_back(Pair("transaction_count", versions[i].nTransactions));
        version.push_back(Pair("spend_count", versions[i].nSpends));
        version.push_back(Pair("output_count", versions[i].nOutputs));
        version.push_back(Pair("pool_delta_atomic", versions[i].nPoolDelta));
        versionArray.push_back(version);
    }

    Object prototype;
    prototype.push_back(Pair("classification", prototypeClass));
    prototype.push_back(Pair("transaction_count", prototypeTransactions));
    prototype.push_back(Pair("spend_count", prototypeSpendCount));
    prototype.push_back(Pair("output_count", prototypeOutputCount));
    prototype.push_back(Pair("pre_binding_spend_count", preBindingSpendCount));
    prototype.push_back(Pair("bound_spend_count", boundSpendCount));
    prototype.push_back(Pair("pool_atomic", prototypePool));
    prototype.push_back(Pair("pool", FormatMoney(prototypePool)));
    prototype.push_back(Pair("earliest_height", earliestPrototypeHeight));
    prototype.push_back(Pair("latest_height", latestPrototypeHeight));
    prototype.push_back(Pair("versions", versionArray));

    const std::string network = fRegTest
        ? "regtest" : (fTestNet ? "testnet" : "mainnet");
    Object result;
    result.push_back(Pair("schema_version", 1));
    result.push_back(Pair("contract_sha256",
                          std::string(iv5::PROTOCOL_CONTRACT_SHA256)));
    result.push_back(Pair("network", network));
    result.push_back(Pair("genesis_hash", GetGenesisBlockHash().GetHex()));
    result.push_back(Pair("tip_height", pindexBest->nHeight));
    result.push_back(Pair("tip_hash", pindexBest->GetBlockHash().GetHex()));
    result.push_back(Pair("active_chain_digest",
                          activeChainDigest.GetHash().GetHex()));
    result.push_back(Pair("migration_source_digest",
                          migrationSourceDigest.GetHash().GetHex()));
    result.push_back(Pair("nullifier_binding_height",
                          FORK_HEIGHT_NULLIFIER_BINDING));
    result.push_back(Pair("integrity", std::string("exact")));
    result.push_back(Pair("v1000", legacy));
    result.push_back(Pair("prototype_2000_2007", prototype));
    result.push_back(Pair("boundary_b_inventory_gate", inventoryGate));
    result.push_back(Pair("boundary_b_inventory_clear",
                          inventoryGate == "clear"));
    return result;
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


Value getfinalityinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getfinalityinfo\n"
            "Returns information about the PoS finality gadget.\n");

    Object result;

    int nCurrentHeight = 0;
    int64_t nSupply = 0;
    {
        LOCK(cs_main);
        if (pindexBest)
        {
            nCurrentHeight = pindexBest->nHeight;
            nSupply = pindexBest->nMoneySupply;
        }
    }

    int nCurrentEpoch = GetEpochForHeight(nCurrentHeight);
    int nFinalizedHeight = g_finalityTracker.GetFinalizedHeight();
    uint256 hashFinalized = g_finalityTracker.GetFinalizedHash();
    int nVoteCount = g_finalityTracker.GetEpochVoteCount(nCurrentEpoch);
    int64_t nVoteWeight = g_finalityTracker.GetEpochVoteWeight(nCurrentEpoch);

    int nVoterCount = g_finalityTracker.GetEpochVoterCount(nCurrentEpoch);
    FinalityTier tier = g_finalityTracker.GetFinalityTier();
    int nTransparentVotes = 0;
    int nPrivateVotes = 0;
    g_finalityTracker.GetEpochVoteModeCounts(nCurrentEpoch, nTransparentVotes, nPrivateVotes);

    // Legacy live-tracker fields kept for compatibility; consensus uses the exact
    // completed-epoch lookup and treats a missing state as an error, never height zero.
    const int nCompletedEpoch = nCurrentEpoch - 1;
    const int nCompletedHeight = nCompletedEpoch >= 0
        ? GetEpochBoundaryHeight(nCurrentEpoch, nCurrentHeight) - 1 : -1;
    const int nRequiredEpochSchema = nCompletedHeight >= 0
        ? EpochStateSchemaForHeight(nCompletedHeight) : 0;
    int nPersistedEpochSchema = 0;
    bool fHaveEpochSchemaMarker = false;
    TxDBReadStatus shieldedRecoveryStatus = TXDB_READ_NOT_FOUND;
    TxDBReadStatus dagRecoveryStatus = TXDB_READ_NOT_FOUND;
    {
        CTxDB txdbEpochSchema("r");
        fHaveEpochSchemaMarker = txdbEpochSchema.ReadEpochStateSchema(nPersistedEpochSchema);
        CShieldedWalletRecoveryRecord shieldedRecovery;
        CDAGActiveSetBuildRecord dagRecovery;
        shieldedRecoveryStatus =
            txdbEpochSchema.ReadShieldedWalletRecoveryStatus(shieldedRecovery);
        dagRecoveryStatus = txdbEpochSchema.ReadDAGActiveSetBuild(dagRecovery);
    }
    int nDeterministicFinalizedHeight = 0;
    const bool fHaveDeterministicFinalizedHeight = nCompletedEpoch >= 0 &&
        g_dagManager.TryGetDeterministicFinalizedHeight(
            nCompletedEpoch, nDeterministicFinalizedHeight);
    CEpochState completedEpochState;
    const bool fHaveCompletedEpochState = nCompletedEpoch >= 0 &&
        g_dagManager.GetEpochState(nCompletedEpoch, completedEpochState);

    std::string strEpochStateHealth = "ok";
    if (!IsBoundaryAConfigured())
        strEpochStateHealth = "v3_activation_unset";
    else if (nRequiredEpochSchema == 0)
        strEpochStateHealth = "pre_activation";
    else if (!fHaveEpochSchemaMarker)
        strEpochStateHealth = "schema_marker_missing";
    else if (nPersistedEpochSchema < nRequiredEpochSchema)
        strEpochStateHealth = "schema_upgrade_required";
    else if (!fHaveCompletedEpochState || !fHaveDeterministicFinalizedHeight)
        strEpochStateHealth = "missing_completed_epoch";

    std::string strMigrationState = "recovery_idle";
    if (shieldedRecoveryStatus == TXDB_READ_ERROR ||
        dagRecoveryStatus == TXDB_READ_ERROR)
        strMigrationState = "corrupt_or_unreadable";
    else if (shieldedRecoveryStatus == TXDB_READ_FOUND ||
             dagRecoveryStatus == TXDB_READ_FOUND)
        strMigrationState = "recovery_pending";

    const bool fBoundaryAActive = IsBoundaryAActiveAtHeight(nCurrentHeight);
    const bool fBoundaryBActive = IsBoundaryBActiveAtHeight(nCurrentHeight) &&
                                  IsShieldedVNextConsensusReady();
    const std::string strLegacyAnonStatus =
        nCurrentHeight >= FORK_HEIGHT_RINGSIG_DEPRECATION
            ? "historical_only"
            : (IsLegacyPrivacyPolicyDisabled()
                   ? "policy_disabled_pending_retirement"
                   : "regtest_historical_testing");
    const std::string strPrivacyStatus = fBoundaryBActive
        ? "privacy_vnext_active"
        : (fBoundaryAActive
               ? "legacy_frozen_privacy_vnext_unavailable"
               : (IsLegacyPrivacyPolicyDisabled()
                      ? "legacy_policy_disabled_privacy_vnext_unavailable"
                      : "regtest_legacy_testing_only"));

    result.push_back(Pair("height", nCurrentHeight));
    result.push_back(Pair("epoch", nCurrentEpoch));
    result.push_back(Pair("epoch_interval", GetEpochInterval(nCurrentHeight)));
    result.push_back(Pair("finalized_height", nFinalizedHeight));
    result.push_back(Pair("finalized_hash", hashFinalized.GetHex()));
    result.push_back(Pair("finalized_epoch", GetEpochForHeight(nFinalizedHeight)));
    result.push_back(Pair("current_epoch_votes", nVoteCount));
    result.push_back(Pair("current_epoch_voters", nVoterCount));
    result.push_back(Pair("transparent_votes", nTransparentVotes));
    result.push_back(Pair("private_votes", nPrivateVotes));
    result.push_back(Pair("current_epoch_transparent_weight", FormatMoney(nVoteWeight)));
    result.push_back(Pair("current_epoch_weight", FormatMoney(nVoteWeight)));
    Array voters;
    std::vector<CKeyID> vVoters = g_finalityTracker.GetEpochVoters(nCurrentEpoch);
    for (const CKeyID& keyID : vVoters)
        voters.push_back(CBitcoinAddress(keyID).ToString());
    result.push_back(Pair("voters", voters));
    result.push_back(Pair("pending_votes", g_finalityTracker.GetPendingVoteCount()));
    result.push_back(Pair("pending_rewards", FormatMoney(g_finalityTracker.GetPendingRewardTotal())));
    result.push_back(Pair("money_supply", FormatMoney(nSupply)));
    result.push_back(Pair("candidate_build_identifier", FormatFullVersion()));
    result.push_back(Pair("boundary_a_activation_height", FORK_HEIGHT_BOUNDARY_A));
    result.push_back(Pair("boundary_a_configured", IsBoundaryAConfigured()));
    result.push_back(Pair("boundary_a_active", fBoundaryAActive));
    result.push_back(Pair("boundary_b_activation_height", FORK_HEIGHT_BOUNDARY_B));
    result.push_back(Pair("boundary_b_configured", IsBoundaryBConfigured()));
    result.push_back(Pair("boundary_b_active", fBoundaryBActive));
    result.push_back(Pair("serializer_schema_version",
                          DAG_PARENT_CARRIER_SCHEMA_VERSION));
    result.push_back(Pair("serializer_schema",
                          fBoundaryAActive
                              ? std::string(DAG_PARENT_CARRIER_SCHEMA)
                              : std::string("legacy_v5_decode")));
    result.push_back(Pair("boundary_a_carrier_schema",
                          std::string(DAG_PARENT_CARRIER_SCHEMA)));
    result.push_back(Pair("boundary_a_carrier_schema_version",
                          DAG_PARENT_CARRIER_SCHEMA_VERSION));
    result.push_back(Pair("boundary_a_carrier_tag",
                          std::string("49444147")));
    result.push_back(Pair("boundary_a_carrier_exactly_one", true));
    result.push_back(Pair("boundary_a_carrier_max_parents",
                          MAX_DAG_PARENTS));
    result.push_back(Pair("boundary_a_dagknight_contract",
                          std::string(DAGKNIGHT_ORDERING_CONTRACT)));
    result.push_back(Pair("migration_state", strMigrationState));
    result.push_back(Pair("legacy_anon_status", strLegacyAnonStatus));
    result.push_back(Pair("privacy_protocol_status", strPrivacyStatus));
    result.push_back(Pair("privacy_vnext_required_privacy_modes",
                          (int)SHIELDED_VNEXT_PRIVACY_MODE_COUNT));
    Array requiredDisclosureModes;
    for (int mode = PRIVACY_MODE_TRANSPARENT; mode <= PRIVACY_MODE_FULL; ++mode)
        requiredDisclosureModes.push_back(mode);
    result.push_back(Pair("privacy_vnext_required_disclosure_modes",
                          requiredDisclosureModes));
    result.push_back(Pair("privacy_vnext_disclosure_modes",
                          requiredDisclosureModes));
    result.push_back(Pair("privacy_vnext_required_nullstake_generations",
                          (int)SHIELDED_VNEXT_NULLSTAKE_GENERATION_COUNT));
    Array requiredNullStakeGenerations;
    requiredNullStakeGenerations.push_back((int)SHIELDED_VNEXT_NULLSTAKE_V1);
    requiredNullStakeGenerations.push_back((int)SHIELDED_VNEXT_NULLSTAKE_V2);
    requiredNullStakeGenerations.push_back((int)SHIELDED_VNEXT_NULLSTAKE_V3);
    result.push_back(Pair("privacy_vnext_required_nullstake_generation_ids",
                          requiredNullStakeGenerations));
    result.push_back(Pair("privacy_vnext_nullstake_generation_ids",
                          requiredNullStakeGenerations));
    result.push_back(Pair("privacy_vnext_tree_layers",
                          (int)SHIELDED_VNEXT_TREE_LAYERS));
    result.push_back(Pair("privacy_vnext_membership_scope",
                          std::string("full_chain_finalized_root")));
    result.push_back(Pair("privacy_vnext_post_dag_staking_role",
                          std::string("finality")));
    result.push_back(Pair("epoch_state_health", strEpochStateHealth));
    result.push_back(Pair("epoch_state_schema_version", nPersistedEpochSchema));
    result.push_back(Pair("epoch_state_required_schema_version", nRequiredEpochSchema));
    result.push_back(Pair("epoch_state_schema_marker_present", fHaveEpochSchemaMarker));
    result.push_back(Pair("epoch_state_anchor_rule",
                          EpochStateAnchorRuleForHeight(nCurrentHeight)));
    result.push_back(Pair("epoch_state_records",
                          (int)g_dagManager.GetLoadedEpochStateCount()));
    result.push_back(Pair("epoch_state_latest_completed_epoch", nCompletedEpoch));
    result.push_back(Pair("epoch_state_digest", fHaveCompletedEpochState
                          ? completedEpochState.GetDigest().GetHex() : uint256(0).GetHex()));
    result.push_back(Pair("epoch_curve_root", fHaveCompletedEpochState
                          ? completedEpochState.hashCurveRoot.GetHex() : uint256(0).GetHex()));
    result.push_back(Pair("epoch_nullifier_root", fHaveCompletedEpochState
                          ? completedEpochState.hashNullifierRoot.GetHex() : uint256(0).GetHex()));
    result.push_back(Pair("epoch_vote_set_root", fHaveCompletedEpochState
                          ? completedEpochState.hashVoteSetRoot.GetHex() : uint256(0).GetHex()));
    result.push_back(Pair("deterministic_finalized_height_available",
                          fHaveDeterministicFinalizedHeight));
    result.push_back(Pair("deterministic_finalized_height",
                          fHaveDeterministicFinalizedHeight
                              ? nDeterministicFinalizedHeight : 0));
    result.push_back(Pair("deterministic_finalized_epoch",
                          fHaveDeterministicFinalizedHeight
                              ? GetEpochForHeight(nDeterministicFinalizedHeight) : 0));

    // Finality tier info
    result.push_back(Pair("finality_tier", FinalityTierName(tier)));
    result.push_back(Pair("consecutive_hard_epochs", g_finalityTracker.GetConsecutiveHardEpochCount()));
    result.push_back(Pair("finality_model", std::string("active-epoch-committed-weight")));
    result.push_back(Pair("absolute_stake_floor", false));
    result.push_back(Pair("private_finality_mode", fBoundaryBActive
                          ? std::string("privacy_vnext")
                          : std::string("disabled")));
    result.push_back(Pair("tally_certificate_required_for_private_votes", true));
    CFinalityTallyConfig tallyConfig = GetFinalityTallyConfig();
    result.push_back(Pair("private_promotion_enabled", fBoundaryBActive && tallyConfig.CanRelayPrivateVotes()));
    result.push_back(Pair("tally_mode", tallyConfig.strMode));
    result.push_back(Pair("tally_mode_valid", tallyConfig.fModeValid));
    result.push_back(Pair("tally_pubkey_configured", tallyConfig.fPubKeyConfigured));
    result.push_back(Pair("tally_committee_valid", tallyConfig.fCommitteeValid));
    result.push_back(Pair("tally_privkey_configured", tallyConfig.fPrivKeyConfigured));
    result.push_back(Pair("tally_privkey_valid", tallyConfig.fPrivKeyValid));
    result.push_back(Pair("tally_threshold", GetArg("-finalitytallythreshold", "")));
    result.push_back(Pair("tally_threshold_valid", tallyConfig.fThresholdValid));
    result.push_back(Pair("tally_threshold_m", tallyConfig.nThresholdM));
    result.push_back(Pair("tally_committee_size", tallyConfig.nThresholdN));
    result.push_back(Pair("tally_configured_pubkeys", (int)tallyConfig.vCommitteePubKeys.size()));
    result.push_back(Pair("tally_committee_set_hash", tallyConfig.committeeSetHash.GetHex()));
    result.push_back(Pair("tally_local_committee_index", tallyConfig.nLocalCommitteeIndex));
    result.push_back(Pair("tally_encrypted_shares_ready", tallyConfig.fEncryptedTallyReady));
    {
        // The committee governing the current epoch, as the chain resolves it. Nothing
        // here is configured: the seats come out of the collateral registry draw.
        CTxDB txdbCommittee("r");
        std::vector<CPubKey> vSeats; int nSeatM = 0; uint256 seatSetHash;
        const bool fSeated = GetCanonicalFinalityCommittee(txdbCommittee, nCurrentEpoch,
                                                           vSeats, nSeatM, seatSetHash);
        result.push_back(Pair("committee_source", std::string("collateral_registry_draw")));
        result.push_back(Pair("committee_term_epoch", GetFinalityCommitteeTermEpoch(nCurrentEpoch)));
        result.push_back(Pair("committee_term_epochs", GetFinalityCommitteeTermEpochs()));
        result.push_back(Pair("committee_seated", fSeated));
        result.push_back(Pair("committee_set_hash", fSeated ? seatSetHash.GetHex() : std::string("")));
        result.push_back(Pair("committee_threshold_m", nSeatM));
        result.push_back(Pair("committee_seat_count", (int)vSeats.size()));
        Array seatArray;
        for (size_t i = 0; i < vSeats.size(); i++)
            seatArray.push_back(HexStr(vSeats[i].Raw()));
        result.push_back(Pair("committee_seats", seatArray));

        // The draw for the term the next epoch would open, so an operator can see a
        // thin registry coming rather than discover it at the boundary.
        CFinalityCommitteeDraw draw;
        bool fDrawLocalFailure = false;
        std::string strDrawError;
        const int nNextTerm = GetFinalityCommitteeTermEpoch(nCurrentEpoch) +
                              GetFinalityCommitteeTermEpochs();
        if (DrawFinalityCommitteeForTerm(txdbCommittee, txdbCommittee, nNextTerm, draw,
                                          fDrawLocalFailure, strDrawError))
        {
            Object next;
            next.push_back(Pair("term_epoch", draw.nTermEpoch));
            next.push_back(Pair("anchor_epoch", draw.nAnchorEpoch));
            next.push_back(Pair("anchor_height", draw.nAnchorHeight));
            next.push_back(Pair("registry_rows", (int)draw.nRegistrySize));
            next.push_back(Pair("rows_required",
                                GetFinalityCommitteeSeats() *
                                    FINALITY_COMMITTEE_MIN_REGISTRY_MULTIPLE));
            next.push_back(Pair("seated", draw.fSeated));
            next.push_back(Pair("set_hash", draw.fSeated ? draw.setHash.GetHex() : std::string("")));
            result.push_back(Pair("committee_next_term_draw", next));
        }
    }
    int nDecryptableTallyShares = CountDecryptableFinalityTallyShares(nCurrentEpoch);
    int nTallyAggregatePartials = g_finalityTracker.GetEpochTallyAggregatePartialCount(nCurrentEpoch);
    result.push_back(Pair("tally_decryptable_shares", nDecryptableTallyShares));
    result.push_back(Pair("tally_aggregate_partials", nTallyAggregatePartials));
    result.push_back(Pair("tally_certificate_production_enabled",
                          fBoundaryBActive &&
                          nCurrentHeight >= FORK_HEIGHT_DAG &&
                          tallyConfig.CanProduceCertificates()));
    result.push_back(Pair("current_epoch_tally_shares", g_finalityTracker.GetEpochTallyShareCount(nCurrentEpoch)));

    std::vector<CFinalityTallyCertificate> vCerts = g_finalityTracker.GetEpochTallyCertificates(nCurrentEpoch);
    std::vector<CFinalityTallyCertificate> vPendingCerts =
        g_finalityTracker.GetPendingTallyCertificatesForBlock(nCurrentHeight + 1);
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
        certObj.push_back(Pair("tier", FinalityTierName((FinalityTier)cert.nTier)));
        certObj.push_back(Pair("private_weight", cert.HasPrivateWeight()));
        certObj.push_back(Pair("source", std::string("epoch-tracker")));
        certObj.push_back(Pair("vote_nullifiers", (int)cert.vVoteNullifiers.size()));
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
        if (cert.nEpoch != nCurrentEpoch || !cert.HasPrivateWeight())
            continue;
        fHavePendingPrivateCert = true;
        if (!fHavePrivateCert)
        {
            nTallyCertificateVersion = cert.nVersion;
            strTallyCertificateSource = "pending";
        }
    }
    result.push_back(Pair("tally_certificates", certs));
    result.push_back(Pair("private_certificate_present", fHavePrivateCert));
    result.push_back(Pair("pending_private_certificate_present", fHavePendingPrivateCert));
    result.push_back(Pair("tally_certificate_version", nTallyCertificateVersion));
    result.push_back(Pair("tally_certificate_source", strTallyCertificateSource));
    std::string strPrivatePromotionStatus = "waiting-for-shares";
    if (!fBoundaryBActive)
        strPrivatePromotionStatus = "disabled-pending-privacy-vnext";
    else if (nCurrentHeight < FORK_HEIGHT_DAG)
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
    result.push_back(Pair("private_promotion_status", strPrivatePromotionStatus));

    CEpochState currentEpochState;
    if (g_dagManager.GetEpochState(nCurrentEpoch, currentEpochState))
    {
        result.push_back(Pair("epoch_curve_root", currentEpochState.hashCurveRoot.GetHex()));
        result.push_back(Pair("epoch_nullifier_root", currentEpochState.hashNullifierRoot.GetHex()));
        result.push_back(Pair("epoch_finality_certificate", currentEpochState.hashFinalityCertificate.GetHex()));
    }
    else
    {
        uint256 hashZero = 0;
        result.push_back(Pair("epoch_curve_root", hashZero.GetHex()));
        result.push_back(Pair("epoch_nullifier_root", hashZero.GetHex()));
        result.push_back(Pair("epoch_finality_certificate", hashZero.GetHex()));
        result.push_back(Pair("epoch_root_status", std::string("not_computed")));
    }
    CEpochState finalizedEpochState;
    int nFinalizedEpoch = GetEpochForHeight(nFinalizedHeight);
    if (g_dagManager.GetEpochState(nFinalizedEpoch, finalizedEpochState))
        result.push_back(Pair("finalized_epoch_root", finalizedEpochState.hashCurveRoot.GetHex()));
    else
    {
        uint256 hashZero = 0;
        result.push_back(Pair("finalized_epoch_root", hashZero.GetHex()));
    }

    result.push_back(Pair("min_voters", FINALITY_MIN_VOTERS));
    result.push_back(Pair("fork_active", nCurrentHeight >= FORK_HEIGHT_FINALITY));

    return result;
}


Value submitfinalitytallyshare(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "submitfinalitytallyshare <hex-serialized-share>\n"
            "Regtest-only: submit a serialized CFinalityTallyShare for deterministic finality tests.\n");

    if (!fRegTest)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "submitfinalitytallyshare is only available in regtest mode");

    std::vector<unsigned char> vchData = ParseHexV(params[0], "hex-serialized-share");
    CFinalityTallyShare share;
    try {
        CDataStream ssData(vchData, SER_NETWORK, PROTOCOL_VERSION);
        ssData >> share;
    } catch (const std::exception& e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, std::string("tally share decode failed: ") + e.what());
    }

    std::string strError;
    if (!g_finalityTracker.CheckTallyShare(share, &strError))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("invalid finality tally share: %s", strError.c_str()));

    bool fAdded = g_finalityTracker.AddTallyShare(share, false);
    uint256 hashShare = share.GetHash();
    if (fAdded)
    {
        CTxDB txdb("r+");
        if (!txdb.WriteFinalityTallyShare(hashShare, share))
            throw JSONRPCError(RPC_DATABASE_ERROR, "failed to persist finality tally share");

        LOCK(cs_vNodes);
        for (CNode* pnode : vNodes)
            pnode->PushMessage("ftshare", share);
    }

    Object result;
    result.push_back(Pair("accepted", fAdded));
    result.push_back(Pair("duplicate", !fAdded));
    result.push_back(Pair("hash", hashShare.GetHex()));
    result.push_back(Pair("epoch", share.nEpoch));
    result.push_back(Pair("vote_nullifier", share.voteNullifier.GetHex()));
    return result;
}


Value submitfinalitytallycert(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "submitfinalitytallycert <hex-serialized-certificate>\n"
            "Regtest-only: submit a serialized CFinalityTallyCertificate for deterministic finality tests.\n");

    if (!fRegTest)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "submitfinalitytallycert is only available in regtest mode");

    std::vector<unsigned char> vchData = ParseHexV(params[0], "hex-serialized-certificate");
    CFinalityTallyCertificate cert;
    try {
        CDataStream ssData(vchData, SER_NETWORK, PROTOCOL_VERSION);
        bool fCanonical = false;
        {
            LOCK(cs_main);
            fCanonical = UseCanonicalFinalityTrafficForTip(nBestHeight);
        }
        if (fCanonical)
        {
            CCanonicalFinalityTallyCertificateEnvelope envelope;
            ssData >> envelope;
            if (!envelope.ToLogical(cert))
                throw std::ios_base::failure("invalid canonical tally certificate envelope");
        }
        else
        {
            ssData >> cert;
            cert.fCanonicalEnvelope = false;
        }
        if (!ssData.empty())
            throw std::ios_base::failure("trailing tally certificate bytes");
    } catch (const std::exception& e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, std::string("tally certificate decode failed: ") + e.what());
    }

    CTxDB txdb("r");
    std::string strError;
    if (!g_finalityTracker.CheckTallyCertificate(cert, txdb, &strError))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("invalid finality tally certificate: %s", strError.c_str()));

    bool fAdded = g_finalityTracker.AddTallyCertificate(cert, false);
    uint256 hashCert = cert.GetHash();
    if (fAdded)
        RelayFinalityTallyCertificate(cert);

    Object result;
    result.push_back(Pair("accepted", fAdded));
    result.push_back(Pair("duplicate", !fAdded));
    result.push_back(Pair("hash", hashCert.GetHex()));
    result.push_back(Pair("epoch", cert.nEpoch));
    result.push_back(Pair("version", cert.nVersion));
    result.push_back(Pair("private_weight", cert.HasPrivateWeight()));
    return result;
}


Value isblockfinalized(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "isblockfinalized <hash>\n"
            "Returns whether a block is below the finalized height.\n");

    uint256 hash;
    hash.SetHex(params[0].get_str());

    LOCK(cs_main);

    std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
    if (mi == mapBlockIndex.end())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlockIndex* pindex = mi->second;
    bool fFinalized = g_finalityTracker.IsFinalized(pindex->nHeight);

    Object result;
    result.push_back(Pair("hash", hash.GetHex()));
    result.push_back(Pair("height", pindex->nHeight));
    result.push_back(Pair("finalized", fFinalized));
    result.push_back(Pair("finalized_height", g_finalityTracker.GetFinalizedHeight()));

    return result;
}


// ---------------------------------------------------------------------------
// DAG RPC commands
// ---------------------------------------------------------------------------

Value getdaginfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getdaginfo\n"
            "Returns information about the DAG consensus state.\n");

    LOCK(cs_main);

    Object result;

    int nCurrentHeight = pindexBest ? pindexBest->nHeight : 0;
    result.push_back(Pair("dag_active", nCurrentHeight >= FORK_HEIGHT_DAG));
    result.push_back(Pair("fork_height", FORK_HEIGHT_DAG));
    result.push_back(Pair("current_height", nCurrentHeight));
    result.push_back(Pair("dag_block_producer", std::string("pow")));
    result.push_back(Pair("pos_block_production", nCurrentHeight < FORK_HEIGHT_DAG));

    std::vector<uint256> vTips = g_dagManager.GetDAGTips();
    result.push_back(Pair("dag_tips", (int)vTips.size()));

    result.push_back(Pair("max_parents", MAX_DAG_PARENTS));
    result.push_back(Pair("merge_depth", DAG_MERGE_DEPTH));

    // DAGKNIGHT info
    bool fDAGKnightActive = nCurrentHeight >= FORK_HEIGHT_DAGKNIGHT;
    bool fBoundaryAActive = IsBoundaryAActiveAtHeight(nCurrentHeight);
    result.push_back(Pair("dagknight_active", fDAGKnightActive));
    result.push_back(Pair("dagknight_fork_height", FORK_HEIGHT_DAGKNIGHT));
    result.push_back(Pair("boundary_a_activation_height", FORK_HEIGHT_BOUNDARY_A));
    result.push_back(Pair("boundary_a_configured", IsBoundaryAConfigured()));
    result.push_back(Pair("boundary_a_active", fBoundaryAActive));
    result.push_back(Pair("parent_commitment_schema",
                          std::string(DAG_PARENT_CARRIER_SCHEMA)));
    result.push_back(Pair("parent_commitment_schema_version",
                          DAG_PARENT_CARRIER_SCHEMA_VERSION));
    result.push_back(Pair("parent_commitment_tag", std::string("49444147")));
    result.push_back(Pair("parent_commitment_exactly_one", true));
    result.push_back(Pair("parent_commitment_min_parents", 1));
    result.push_back(Pair("parent_commitment_max_parents", MAX_DAG_PARENTS));
    result.push_back(Pair("parent_commitment_strict_active", fBoundaryAActive));
    result.push_back(Pair("dagknight_contract",
                          std::string(DAGKNIGHT_ORDERING_CONTRACT)));
    result.push_back(Pair("dagknight_anchor_pure", true));
    result.push_back(Pair("dagknight_k_floor", DAGKNIGHT_K_FLOOR));
    result.push_back(Pair("dagknight_k_ceiling", DAGKNIGHT_K_CEILING));

    if (fDAGKnightActive)
        result.push_back(Pair("ordering_algorithm",
                              std::string(DAGKNIGHT_ORDERING_CONTRACT)));
    else
        result.push_back(Pair("ordering_algorithm", std::string("GHOSTDAG")));

    result.push_back(Pair("ghostdag_k", GHOSTDAG_K));

    // Epoch and pruning info
    result.push_back(Pair("epoch_interval", GetEpochInterval(nCurrentHeight)));
    int nCurrentEpoch = GetEpochForHeight(nCurrentHeight);
    result.push_back(Pair("current_epoch", nCurrentEpoch));
    result.push_back(Pair("dag_entries", g_dagManager.GetDAGEntryCount()));
    int nPrunedBelow = g_dagManager.GetPrunedBelowHeight();
    result.push_back(Pair("pruned_below", nPrunedBelow));
    result.push_back(Pair("finality_tier", FinalityTierName(g_finalityTracker.GetFinalityTier())));
    result.push_back(Pair("consecutive_hard_epochs", g_finalityTracker.GetConsecutiveHardEpochCount()));
    result.push_back(Pair("finalized_height", g_finalityTracker.GetFinalizedHeight()));
    result.push_back(Pair("finalized_hash", g_finalityTracker.GetFinalizedHash().GetHex()));

    CEpochState currentEpochState;
    if (g_dagManager.GetEpochState(nCurrentEpoch, currentEpochState))
    {
        result.push_back(Pair("epoch_curve_root", currentEpochState.hashCurveRoot.GetHex()));
        result.push_back(Pair("epoch_nullifier_root", currentEpochState.hashNullifierRoot.GetHex()));
        result.push_back(Pair("epoch_finality_certificate", currentEpochState.hashFinalityCertificate.GetHex()));
    }
    else
    {
        uint256 hashZero = 0;
        result.push_back(Pair("epoch_curve_root", hashZero.GetHex()));
        result.push_back(Pair("epoch_nullifier_root", hashZero.GetHex()));
        result.push_back(Pair("epoch_finality_certificate", hashZero.GetHex()));
        result.push_back(Pair("epoch_root_status", std::string("not_computed")));
    }

    // Adaptive block size info
    unsigned int nAdaptiveLimit = pindexBest ? GetAdaptiveBlockSizeLimit(pindexBest) : MAX_BLOCK_SIZE_LEGACY;
    result.push_back(Pair("adaptive_block_limit", (int)nAdaptiveLimit));
    result.push_back(Pair("adaptive_block_ceiling", (int)ADAPTIVE_BLOCK_CEILING));
    result.push_back(Pair("adaptive_block_floor", (int)ADAPTIVE_BLOCK_FLOOR));

    uint256 hashAnchorSelectedParent = 0;
    uint256 nAnchorScore = 0;
    uint256 hashAnchorOrderDigest = 0;
    int nAnchorInferredK = -1;
    int nAnchorOrderCount = 0;
    int nAnchorBlueCount = 0;
    int nBestParentCount = 0;
    bool fAnchorMetricsAvailable = false;
    std::string strBestParentCommitment;
    CBlockIndex* pBestTip = g_dagManager.SelectBestDAGTip();
    if (pBestTip && pBestTip->phashBlock)
    {
        result.push_back(Pair("best_dag_tip", pBestTip->GetBlockHash().GetHex()));
        uint256 nScore = g_dagManager.ComputeDAGScore(pBestTip);
        result.push_back(Pair("best_dag_score", nScore.GetHex()));

        if (fDAGKnightActive)
        {
            CBlockDAGData tipData;
            if (g_dagManager.GetDAGData(pBestTip->GetBlockHash(), tipData))
            {
                nBestParentCount = (int)tipData.vDAGParents.size();
                const CScript parentCommitment =
                    BuildDAGParentScript(tipData.vDAGParents);
                strBestParentCommitment = HexStr(
                    parentCommitment.begin(), parentCommitment.end());

                std::vector<std::pair<uint256, bool> > vOrderColors;
                if (g_dagManager.GetDAGKnightAnchorMetrics(
                        pBestTip->GetBlockHash(), hashAnchorSelectedParent,
                        nAnchorInferredK, nAnchorScore, vOrderColors))
                {
                    CHashWriter digest(SER_GETHASH, 0);
                    digest << std::string(
                        "Innova/IDAG/DAGKnightAnchorMetrics/v1");
                    digest << pBestTip->GetBlockHash()
                           << hashAnchorSelectedParent
                           << nAnchorInferredK << nAnchorScore;
                    for (std::vector<std::pair<uint256, bool> >::const_iterator it =
                             vOrderColors.begin();
                         it != vOrderColors.end(); ++it)
                    {
                        digest << it->first << it->second;
                        if (it->second)
                            ++nAnchorBlueCount;
                    }
                    nAnchorOrderCount = (int)vOrderColors.size();
                    hashAnchorOrderDigest = digest.GetHash();
                    fAnchorMetricsAvailable = true;
                }
            }
        }
    }

    result.push_back(Pair("anchor_metrics_available", fAnchorMetricsAvailable));
    result.push_back(Pair("anchor_selected_parent",
                          hashAnchorSelectedParent.GetHex()));
    result.push_back(Pair("anchor_score", nAnchorScore.GetHex()));
    result.push_back(Pair("anchor_inferred_k", nAnchorInferredK));
    result.push_back(Pair("anchor_order_count", nAnchorOrderCount));
    result.push_back(Pair("anchor_blue_count", nAnchorBlueCount));
    result.push_back(Pair("anchor_order_digest",
                          hashAnchorOrderDigest.GetHex()));
    result.push_back(Pair("best_parent_count", nBestParentCount));
    result.push_back(Pair("best_parent_commitment_hex",
                          strBestParentCommitment));
    result.push_back(Pair("inferred_k", nAnchorInferredK));
    result.push_back(Pair("inferred_k_error", !fAnchorMetricsAvailable));

    return result;
}

Value getepochinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getepochinfo [epoch]\n"
            "Returns information about a DAG epoch.\n"
            "If epoch is omitted, returns the current epoch.\n");

    LOCK(cs_main);

    int nCurrentHeight = pindexBest ? pindexBest->nHeight : 0;
    int nEpoch;

    if (params.size() > 0)
    {
        nEpoch = params[0].get_int();
        if (nEpoch < 0 || nEpoch > 100000000)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "epoch out of range (0-100000000)");
    }
    else
        nEpoch = GetEpochForHeight(nCurrentHeight);

    Object result;
    result.push_back(Pair("epoch", nEpoch));
    result.push_back(Pair("epoch_interval", GetEpochInterval(nCurrentHeight)));

    CEpochState state;
    if (g_dagManager.GetEpochState(nEpoch, state))
    {
        result.push_back(Pair("height_start", state.nHeightStart));
        result.push_back(Pair("height_end", state.nHeightEnd));
        result.push_back(Pair("boundary_block", state.hashBoundaryBlock.GetHex()));
        result.push_back(Pair("block_count", state.nBlockCount));

        // Tx count computed on demand (deferred from epoch computation for performance)
        int nTxCount = state.nTxCount;
        if (nTxCount < 0)
        {
            nTxCount = 0;
            for (const uint256& bh : state.vBlockHashes)
            {
                std::map<uint256, CBlockIndex*>::iterator bmi = mapBlockIndex.find(bh);
                if (bmi != mapBlockIndex.end())
                {
                    CBlock block;
                    if (block.ReadFromDisk(bmi->second))
                        nTxCount += (int)block.vtx.size();
                }
            }
        }
        result.push_back(Pair("tx_count", nTxCount));
        result.push_back(Pair("total_trust", state.nTotalTrust.GetHex()));
        result.push_back(Pair("finalized", state.fFinalized));
        result.push_back(Pair("curve_root", state.hashCurveRoot.GetHex()));
        result.push_back(Pair("nullifier_root", state.hashNullifierRoot.GetHex()));
        result.push_back(Pair("vote_set_root", state.hashVoteSetRoot.GetHex()));
        result.push_back(Pair("finality_certificate", state.hashFinalityCertificate.GetHex()));
        result.push_back(Pair("finality_tier", FinalityTierName((FinalityTier)state.nFinalityTier)));
        result.push_back(Pair("consecutive_hard_epochs", state.nConsecutiveHardCount));
        result.push_back(Pair("finalized_height_as_of", state.nFinalizedHeightAsOf));
        result.push_back(Pair("schema_version", EpochStateSchemaForHeight(state.nHeightEnd)));
        result.push_back(Pair("anchor_rule", EpochStateAnchorRuleForHeight(state.nHeightEnd)));
        result.push_back(Pair("epoch_state_digest", state.GetDigest().GetHex()));

        Array blocks;
        for (const uint256& hash : state.vBlockHashes)
            blocks.push_back(hash.GetHex());
        result.push_back(Pair("blocks", blocks));

        // IV5 accumulators, with per-block active-tx counts aligned with "blocks". A merge
        // block contributes zero: it is never connected.
        if (state.nSerVersion >= EPOCHSTATE_SER_VERSION_V4)
        {
            result.push_back(Pair("iv5_tree_root",
                                  HexStr(state.vchVNextRoot)));
            result.push_back(Pair("iv5_tree_size",
                                  (int64_t)state.nVNextTreeSize));
            result.push_back(Pair("iv5_nullifier_count",
                                  (int64_t)state.nVNextNullifierCount));
            result.push_back(Pair("iv5_active_tx_count",
                                  (int64_t)state.vVNextActiveTxIds.size()));
            Array activeCounts;
            for (std::vector<unsigned int>::const_iterator it =
                     state.vVNextActiveBlockTxCounts.begin();
                 it != state.vVNextActiveBlockTxCounts.end(); ++it)
                activeCounts.push_back((int64_t)*it);
            result.push_back(Pair("iv5_active_block_tx_counts", activeCounts));
            if (state.nSerVersion >= EPOCHSTATE_SER_VERSION_V5)
                result.push_back(Pair("iv5_pool_balance",
                                      ValueFromAmount(state.nVNextPoolBalance)));
        }
    }
    else
    {
        // Epoch not yet computed — return estimated range
        int nEstStart = GetEpochBoundaryHeight(nEpoch, nCurrentHeight);
        int nNextStart = GetEpochBoundaryHeight(nEpoch + 1, nCurrentHeight);
        int nEstEnd = (nNextStart > nEstStart) ? (nNextStart - 1) : (nEstStart + GetEpochInterval(nEstStart) - 1);
        uint256 hashZero = 0;
        result.push_back(Pair("height_start", nEstStart));
        result.push_back(Pair("height_end", nEstEnd));
        result.push_back(Pair("curve_root", hashZero.GetHex()));
        result.push_back(Pair("nullifier_root", hashZero.GetHex()));
        result.push_back(Pair("vote_set_root", hashZero.GetHex()));
        result.push_back(Pair("finality_certificate", hashZero.GetHex()));
        result.push_back(Pair("finality_tier", std::string("none")));
        result.push_back(Pair("consecutive_hard_epochs", 0));
        result.push_back(Pair("finalized_height_as_of", 0));
        result.push_back(Pair("schema_version", EpochStateSchemaForHeight(nEstEnd)));
        result.push_back(Pair("anchor_rule", EpochStateAnchorRuleForHeight(nEstEnd)));
        result.push_back(Pair("epoch_state_digest", hashZero.GetHex()));
        result.push_back(Pair("status", "not_computed"));
    }

    return result;
}

Value getdagtips(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getdagtips\n"
            "Returns the current DAG tip block hashes.\n");

    LOCK(cs_main);

    std::vector<uint256> vTips = g_dagManager.GetDAGTips();

    Array result;
    for (const uint256& hash : vTips)
    {
        Object tip;
        tip.push_back(Pair("hash", hash.GetHex()));

        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end())
        {
            CBlockIndex* pindex = mi->second;
            tip.push_back(Pair("height", pindex->nHeight));
            tip.push_back(Pair("time", (int64_t)pindex->nTime));

            CBlockDAGData tipData;
            if (g_dagManager.GetDAGData(hash, tipData))
            {
                tip.push_back(Pair("blue", tipData.fBlue));
                tip.push_back(Pair("score", tipData.nDAGScore.GetHex()));
                tip.push_back(Pair("parents", (int)tipData.vDAGParents.size()));
            }
        }
        result.push_back(tip);
    }

    return result;
}

Value getdagorder(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getdagorder [count]\n"
            "Returns the DAG linear ordering of blocks from the best tip.\n"
            "Optional count limits the number of blocks returned (default: 100).\n");

    int nCount = 100;
    if (params.size() > 0)
        nCount = params[0].get_int();
    if (nCount <= 0 || nCount > 1000)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "count must be 1-1000");

    LOCK(cs_main);

    CBlockIndex* pBestTip = g_dagManager.SelectBestDAGTip();
    if (!pBestTip || !pBestTip->phashBlock)
        throw JSONRPCError(RPC_MISC_ERROR, "No DAG tips available");

    std::vector<uint256> vOrder = g_dagManager.GetDAGLinearOrder(pBestTip->GetBlockHash(), nCount);

    Array result;
    int nStart = (int)vOrder.size() > nCount ? (int)vOrder.size() - nCount : 0;
    for (int i = nStart; i < (int)vOrder.size(); i++)
    {
        Object entry;
        entry.push_back(Pair("order", i));
        entry.push_back(Pair("hash", vOrder[i].GetHex()));

        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(vOrder[i]);
        if (mi != mapBlockIndex.end())
        {
            entry.push_back(Pair("height", mi->second->nHeight));
            entry.push_back(Pair("is_pow", mi->second->IsProofOfWork()));
        }

        CBlockDAGData orderData;
        if (g_dagManager.GetDAGData(vOrder[i], orderData))
        {
            entry.push_back(Pair("blue", orderData.fBlue));
            if (orderData.nInferredK >= 0)
                entry.push_back(Pair("inferred_k", orderData.nInferredK));
        }

        result.push_back(entry);
    }

    return result;
}

Value getdagconfidence(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getdagconfidence <blockhash> [comparehash]\n"
            "Returns DAGKNIGHT confidence information for a block.\n"
            "If comparehash is provided, returns pairwise ordering confidence.\n");

    LOCK(cs_main);

    if (!pindexBest || pindexBest->nHeight < FORK_HEIGHT_DAGKNIGHT)
        throw JSONRPCError(RPC_MISC_ERROR, "DAGKNIGHT not yet active");

    uint256 hashBlock;
    hashBlock.SetHex(params[0].get_str());

    Object result;
    result.push_back(Pair("block", hashBlock.GetHex()));

    CBlockDAGData blockData;
    if (!g_dagManager.GetDAGData(hashBlock, blockData))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in DAG");

    result.push_back(Pair("blue", blockData.fBlue));
    result.push_back(Pair("score", blockData.nDAGScore.GetHex()));
    result.push_back(Pair("inferred_k", blockData.nInferredK));
    result.push_back(Pair("order_confidence", g_dagManager.GetOrderConfidence(hashBlock)));

    if (params.size() > 1)
    {
        uint256 hashCompare;
        hashCompare.SetHex(params[1].get_str());

        int nConfidence = 0;
        int nOrder = g_dagManager.CompareBlockOrder(hashBlock, hashCompare, nConfidence);

        Object compare;
        compare.push_back(Pair("compare_block", hashCompare.GetHex()));
        compare.push_back(Pair("order", nOrder == -1 ? "before" : (nOrder == 1 ? "after" : "unordered")));
        compare.push_back(Pair("confidence", nConfidence));
        result.push_back(Pair("pairwise", compare));
    }

    return result;
}
