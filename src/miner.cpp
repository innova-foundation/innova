// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2013 The NovaCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txdb.h"
#include "miner.h"
#include "kernel.h"
#include "collateralnode.h"
#include "dag.h"
#include "mstimestamp.h"
#include "finality.h"
#include "subsidy.h"
#include "namecoin.h"

#include <memory>

using namespace std;

//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

extern unsigned int nMinerSleep;

// Key images a payload consumes, and the ones it only names. A collateral attestation
// names one without spending it, so the two sets are reported apart.
static bool ReadPrivacyVNextTxKeyImages(const CTransaction& tx,
                                        std::vector<uint256>& vSpentOut,
                                        std::vector<uint256>& vAttestedOut)
{
    vSpentOut.clear();
    vAttestedOut.clear();
    if (!tx.IsPrivacyVNext())
        return true;

    PrivacyVNextStateEffects effects;
    const PrivacyVNextPayloadValidation validation =
        ExtractPrivacyVNextPayloadEffects(
            static_cast<uint32_t>(tx.nVersion), tx.privacyVNext.vchPayload,
            effects);
    if (!validation.IsValid())
        return false;

    for (size_t i = 0; i < effects.keyImages.size(); ++i)
    {
        uint256 keyImage;
        std::memcpy(keyImage.begin(), effects.keyImages[i].data(), 32);
        vSpentOut.push_back(keyImage);
    }
    for (size_t i = 0; i < effects.attestationKeyImages.size(); ++i)
    {
        uint256 keyImage;
        std::memcpy(keyImage.begin(), effects.attestationKeyImages[i].data(), 32);
        vAttestedOut.push_back(keyImage);
    }
    return true;
}

static bool TransactionSpendsAnyOutpoint(const CTransaction& tx,
                                         const std::set<COutPoint>& setOutpoints)
{
    if (setOutpoints.empty())
        return false;

    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        if (setOutpoints.count(txin.prevout))
            return true;
    }
    return false;
}

int static FormatHashBlocks(void* pbuffer, unsigned int len)
{
    unsigned char* pdata = (unsigned char*)pbuffer;
    unsigned int blocks = 1 + ((len + 8) / 64);
    unsigned char* pend = pdata + 64 * blocks;
    memset(pdata + len, 0, 64 * blocks - len);
    pdata[len] = 0x80;
    unsigned int bits = len * 8;
    pend[-1] = (bits >> 0) & 0xff;
    pend[-2] = (bits >> 8) & 0xff;
    pend[-3] = (bits >> 16) & 0xff;
    pend[-4] = (bits >> 24) & 0xff;
    return blocks;
}

static const unsigned int pSHA256InitState[8] =
{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

void SHA256Transform(void* pstate, void* pinput, const void* pinit)
{
    SHA256_CTX ctx;
    unsigned char data[64];

    SHA256_Init(&ctx);

    for (int i = 0; i < 16; i++)
        ((uint32_t*)data)[i] = ByteReverse(((uint32_t*)pinput)[i]);

    for (int i = 0; i < 8; i++)
        ctx.h[i] = ((uint32_t*)pinit)[i];

    SHA256_Update(&ctx, data, sizeof(data));
    for (int i = 0; i < 8; i++)
        ((uint32_t*)pstate)[i] = ctx.h[i];
}

// Some explaining would be appreciated
class COrphan
{
public:
    CTransaction* ptx;
    set<uint256> setDependsOn;
    double dPriority;
    double dFeePerKb;
    int64_t nFee;

    COrphan(CTransaction* ptxIn)
    {
        ptx = ptxIn;
        dPriority = dFeePerKb = 0;
        nFee = 0;
    }

    COrphan(double dPriority_, double dFeePerKb_, int64_t nFee_, CTransaction* ptxIn)
    {
        dPriority = dPriority_;
        dFeePerKb = dFeePerKb_;
        nFee = nFee_;
        ptx = ptxIn;
     }

    void print() const
    {
        printf("COrphan(hash=%s, dPriority=%.1f, dFeePerKb=%.1f)\n",
               ptx->GetHash().ToString().substr(0,10).c_str(), dPriority, dFeePerKb);
        BOOST_FOREACH(uint256 hash, setDependsOn)
            printf("   setDependsOn %s\n", hash.ToString().substr(0,10).c_str());
    }
};


uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;
int64_t nLastCoinStakeSearchInterval = 0;

// We want to sort transactions by priority and fee, so:
typedef boost::tuple<double, double, int64_t, CTransaction*> TxPriority;
class TxPriorityCompare
{
    bool byFee;
public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) { }
    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee)
        {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        }
        else
        {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

static CScript CoinbaseHeightScript(int nHeight)
{
    return CScript() << nHeight;
}

static bool CoinbaseStartsWithHeight(const CBlock* pblock, int nHeight)
{
    if (!pblock || pblock->vtx.empty() || pblock->vtx[0].vin.empty())
        return false;

    CScript expect = CoinbaseHeightScript(nHeight);
    const CScript& scriptSig = pblock->vtx[0].vin[0].scriptSig;
    return scriptSig.size() >= expect.size() &&
           std::equal(expect.begin(), expect.end(), scriptSig.begin());
}

static bool IsPostDAGProofOfStakeIndex(const CBlockIndex* pindex)
{
    return pindex && pindex->nHeight >= FORK_HEIGHT_DAG && pindex->IsProofOfStake();
}

static bool IsBetterPoWTemplateParent(const CBlockIndex* pCandidate, const CBlockIndex* pBest)
{
    if (!pCandidate)
        return false;
    // Refuse invalidated blocks and their descendants; building on them yields blocks
    // this node's own ConnectBlock rejects.
    if (pCandidate->IsInvalid())
        return false;
    if (IsPostDAGProofOfStakeIndex(pCandidate))
        return false;
    if (!pBest)
        return true;
    if (pCandidate->nChainTrust != pBest->nChainTrust)
        return pCandidate->nChainTrust > pBest->nChainTrust;
    if (pCandidate->nHeight != pBest->nHeight)
        return pCandidate->nHeight > pBest->nHeight;
    if (pCandidate->phashBlock && pBest->phashBlock)
        return pCandidate->GetBlockHash() < pBest->GetBlockHash();
    return pCandidate->phashBlock && !pBest->phashBlock;
}

static CBlockIndex* SelectBestPoWTemplateParent(CBlockIndex* pPreferred)
{
    CBlockIndex* pBest = NULL;

    if (IsBetterPoWTemplateParent(pPreferred, pBest))
        pBest = pPreferred;

    CBlockIndex* pWalk = pindexBest;
    while (IsPostDAGProofOfStakeIndex(pWalk))
        pWalk = pWalk->pprev;
    if (IsBetterPoWTemplateParent(pWalk, pBest))
        pBest = pWalk;

    for (std::map<uint256, CBlockIndex*>::const_iterator mi = mapBlockIndex.begin();
         mi != mapBlockIndex.end(); ++mi)
    {
        if (IsBetterPoWTemplateParent(mi->second, pBest))
            pBest = mi->second;
    }

    return pBest;
}

// Millisecond offset for a template whose header time is already fixed. pblock->nTime is
// clamped (median, newest tx, PoS kernel time), so the difference is clamped to 0..999.
static uint16_t MsTimestampOffsetForTemplate(unsigned int nBlockTime)
{
    const int64_t nAdjustMs = (GetAdjustedTime() - GetTime()) * 1000;
    int64_t nOffset = GetTimeMillis() + nAdjustMs - (int64_t)nBlockTime * 1000;
    if (nOffset < 0)
        nOffset = 0;
    if (nOffset > (int64_t)MS_TIMESTAMP_MAX)
        nOffset = (int64_t)MS_TIMESTAMP_MAX;
    return (uint16_t)nOffset;
}

// Rewrite the template's commitment once the header time is final. The
// encoding is fixed length, so the placeholder the coinbase already carries
// keeps the reward's block-size accounting correct whatever the value is.
void StampMsTimestampCommitment(CBlock* pblock, int nHeight)
{
    if (nHeight < FORK_HEIGHT_MS_TIMESTAMP || pblock->vtx.empty())
        return;
    const CScript scriptMs =
        BuildMsTimestampScript(MsTimestampOffsetForTemplate(pblock->nTime));
    for (unsigned int i = 0; i < pblock->vtx[0].vout.size(); i++)
    {
        uint16_t nExisting = 0;
        std::string strError;
        if (DecodeCanonicalMsTimestampScript(pblock->vtx[0].vout[i].scriptPubKey,
                                             nExisting, strError) !=
            MS_TIMESTAMP_NOT_FOUND)
        {
            pblock->vtx[0].vout[i].scriptPubKey = scriptMs;
            return;
        }
    }
    CTxOut msOut;
    msOut.nValue = 0;
    msOut.scriptPubKey = scriptMs;
    pblock->vtx[0].vout.push_back(msOut);
}

// CreateNewBlock: create new block (without proof-of-work/proof-of-stake)
CBlock* CreateNewBlock(CWallet* pwallet, bool fProofOfStake, int64_t* pFees)
{
    // Create new block
    unique_ptr<CBlock> pblock(new CBlock());
    if (!pblock.get())
        return NULL;

    CBlockIndex* pindexPrev;
    {
        LOCK2(cs_main, g_dagManager.cs_dag);
        pindexPrev = g_dagManager.SelectBestDAGTip();
        if (!fProofOfStake && pindexBest && pindexBest->nHeight + 1 >= FORK_HEIGHT_DAG)
        {
            CBlockIndex* pindexDAGTip = pindexPrev;
            pindexPrev = SelectBestPoWTemplateParent(pindexPrev);
            if (pindexPrev && pindexDAGTip && pindexPrev != pindexDAGTip)
            {
                printf("CreateNewBlock: selected PoW template parent height=%d hash=%s over DAG tip height=%d hash=%s\n",
                       pindexPrev->nHeight,
                       pindexPrev->GetBlockHash().ToString().substr(0,20).c_str(),
                       pindexDAGTip->nHeight,
                       pindexDAGTip->GetBlockHash().ToString().substr(0,20).c_str());
            }
        }
        else if (pindexPrev && pindexBest && pindexBest->IsProofOfWork() && pindexPrev->nHeight < pindexBest->nHeight)
            pindexPrev = pindexBest;
        if (!pindexPrev)
            pindexPrev = pindexBest;
    }
    if (!pindexPrev)
    {
        printf("CreateNewBlock: ERROR: pindexPrev is NULL\n");
        return NULL;
    }

    int payments = 1;
    // Create coinbase tx
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);


    int nHeight = pindexPrev->nHeight+1; // height of new block
    if (fProofOfStake && nHeight >= FORK_HEIGHT_DAG)
    {
        if (fDebug && GetBoolArg("-printcoinstake"))
            printf("CreateNewBlock: refusing proof-of-stake block template at post-DAG height %d\n", nHeight);
        return NULL;
    }

    if (!fProofOfStake)
    {
        // Height first in coinbase required for block.version=2.
        txNew.vin[0].scriptSig = CoinbaseHeightScript(nHeight);
        if (txNew.vin[0].scriptSig.size() > 100)
        {
            printf("CreateNewBlock() : coinbase scriptSig too large (%d bytes)\n", (int)txNew.vin[0].scriptSig.size());
            return NULL;
        }

        CReserveKey reservekey(pwallet);
        CPubKey pubkey;
        if (!reservekey.GetReservedKey(pubkey))
            return NULL;
        txNew.vout[0].scriptPubKey.SetDestination(pubkey.GetID());
    }
    else
    {
        // Height first in coinbase required for block.version=2
        txNew.vin[0].scriptSig = CoinbaseHeightScript(nHeight) + COINBASE_FLAGS;
        if (txNew.vin[0].scriptSig.size() > 100)
        {
            printf("CreateNewBlock() : coinbase scriptSig too large (%d bytes)\n", (int)txNew.vin[0].scriptSig.size());
            return NULL;
        }

        txNew.vout[0].SetEmpty();
    }

    std::vector<uint256> vDAGParentsForBlock;

    // Add DAG parent commitment to coinbase
    if (nHeight >= FORK_HEIGHT_DAG)
    {
        // Primary parent = pindexPrev
        if (pindexPrev->phashBlock)
            vDAGParentsForBlock.push_back(pindexPrev->GetBlockHash());

        // Collect merge parents from DAG tips (cs_main for mapBlockIndex access)
        {
            LOCK2(cs_main, g_dagManager.cs_dag);
            std::vector<uint256> vTips = g_dagManager.GetDAGTips();

            std::vector<std::pair<uint256, uint256>> vTipScores;
            for (const uint256& hashTip : vTips)
            {
                if (pindexPrev->phashBlock && hashTip == pindexPrev->GetBlockHash())
                    continue; // skip primary parent
                std::map<uint256, CBlockIndex*>::iterator miTip = mapBlockIndex.find(hashTip);
                if (miTip == mapBlockIndex.end() || miTip->second == NULL)
                    continue;
                CBlockIndex* pTip = miTip->second;
                if (pTip != pindexBest && pTip->nChainTrust > nBestChainTrust)
                    continue;
                uint256 nScore = g_dagManager.ComputeDAGScore(pTip);
                vTipScores.push_back(std::make_pair(nScore, hashTip));
            }
            std::sort(vTipScores.begin(), vTipScores.end(),
                      [](const std::pair<uint256, uint256>& a, const std::pair<uint256, uint256>& b) {
                          if (a.first != b.first)
                              return a.first > b.first; // higher score first
                          return a.second < b.second;   // deterministic tiebreak
                      });

            for (const auto& pair : vTipScores)
            {
                // Cap on the height's own decoder: below Boundary A the commitment is read
                // through CScript::GetOp and a wider one does not decode.
                if (vDAGParentsForBlock.size() >= MaxDAGParentsAtHeight(nHeight))
                    break;

                const uint256& hashTip = pair.second;

                // Merge parent must exist and be within DAG_MERGE_DEPTH
                std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashTip);
                if (mi == mapBlockIndex.end() || mi->second == NULL)
                    continue;
                CBlockIndex* pTip = mi->second;
                if (pTip != pindexBest && pTip->nChainTrust > nBestChainTrust)
                    continue;
                if (pTip->nHeight < pindexPrev->nHeight - DAG_MERGE_DEPTH)
                    continue;
                if (pTip->nHeight >= nHeight)
                    continue;

                vDAGParentsForBlock.push_back(hashTip);
            }
        }

        if (!vDAGParentsForBlock.empty())
        {
            CScript dagScript = BuildDAGParentScript(vDAGParentsForBlock);
            if (dagScript.size() > 0)
            {
                CTxOut dagOut;
                dagOut.nValue = 0;
                dagOut.scriptPubKey = dagScript;
                txNew.vout.push_back(dagOut);
            }
        }
    }

    // Placeholder millisecond commitment, re-stamped below once the header
    // time is final. It is carried from here so the coinbase reaching the
    // reward's block-size accounting is the one that ships.
    if (nHeight >= FORK_HEIGHT_MS_TIMESTAMP)
    {
        CTxOut msOut;
        msOut.nValue = 0;
        msOut.scriptPubKey = BuildMsTimestampScript(0);
        txNew.vout.push_back(msOut);
    }

    // Add our coinbase tx as first transaction
    pblock->vtx.push_back(txNew);

    // Largest block you're willing to create (adaptive post-DAG):
    unsigned int nAdaptiveLimit = GetAdaptiveBlockSizeLimit(pindexPrev);
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", nAdaptiveLimit / 2);
    // Limit to between 1K and the adaptive ceiling (underflow-safe)
    unsigned int nMaxAllowed = (nAdaptiveLimit > 1000) ? (nAdaptiveLimit - 1000) : 1000;
    nBlockMaxSize = std::max((unsigned int)1000, std::min(nMaxAllowed, nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", 27000);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", 0);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // start collateralnode payments -- the same era condition the validator reads
    bool bCollateralNodePayment = false;

	//Only if it isn't Proof of Stake?
	if (!fProofOfStake)
    {
        bCollateralNodePayment = CollateralnodePaymentsEnabledAtHeight(nHeight);
        if(fDebug && fDebugCN) { printf("CreateNewBlock(): Collateralnode Payments : %i\n", bCollateralNodePayment); }
	}

    // Fee-per-kilobyte amount considered the same as "free"
    // Be careful setting this: if you set it to zero then
    // a transaction spammer can cheaply fill blocks using
    // 1-innovai-fee transactions. It should be set above the real
    // cost to you of processing a transaction.
    int64_t nMinTxFee = MIN_TX_FEE;
    if (mapArgs.count("-mintxfee"))
        ParseMoney(mapArgs["-mintxfee"], nMinTxFee);

    pblock->nBits = GetNextTargetRequired(pindexPrev, fProofOfStake);

    std::vector<CFinalityVote> vFinalityVotesForBlock;
    std::set<COutPoint> setFinalityStakeProofOutpoints;
    if (!fProofOfStake && nHeight >= FORK_HEIGHT_DAG)
    {
        vFinalityVotesForBlock = g_finalityTracker.GetPendingVotesForBlock(nHeight);

        // Drop votes that no longer pass consensus validation (e.g. stake
        // proof spent since relay). ConnectBlock re-checks every embedded
        // vote and rejects the whole block on failure, so a stale pending
        // vote would make every template we produce unmineable.
        {
            CTxDB txdbVoteCheck("r");
            std::vector<CFinalityVote> vValidVotes;
            vValidVotes.reserve(vFinalityVotesForBlock.size());
            BOOST_FOREACH(const CFinalityVote& vote, vFinalityVotesForBlock)
            {
                if (vote.IsPrivate() &&
                    (IsLegacyPrivacyPolicyDisabled() ||
                     IsBoundaryAActiveAtHeight(nHeight)))
                    continue;
                std::string strVoteError;
                if (!g_finalityTracker.CheckVote(vote, txdbVoteCheck, &strVoteError,
                                                 CFinalityVoteContext::Build(pindexPrev)))
                {
                    printf("CreateNewBlock: excluding stale finality vote %s: %s\n",
                           vote.nullifier.ToString().substr(0,20).c_str(), strVoteError.c_str());
                    continue;
                }
                vValidVotes.push_back(vote);
            }
            vFinalityVotesForBlock.swap(vValidVotes);
        }

        BOOST_FOREACH(const CFinalityVote& vote, vFinalityVotesForBlock)
        {
            if (vote.IsPrivate())
                continue;
            BOOST_FOREACH(const COutPoint& proof, vote.vStakeProof)
                setFinalityStakeProofOutpoints.insert(proof);
        }
    }

    // Per-epoch finality-reward settlement. At H_E + FINALITY_VOTE_INCLUSION_WINDOW the
    // epoch's vote set is frozen, and this block owes every counted transparent voter
    // exactly one payment. Derive it from the SAME committed set ConnectBlock will use
    // (the ancestor window blocks), never from tracker state, so the template's coinbase
    // allowance matches the validator's. Carrying a vote pays nothing on any other block.
    std::vector<CTxOut> vFinalitySettlementOutputs;
    int64_t nFinalitySettlementTotal = 0;
    if (!fProofOfStake)
    {
        int nSettlementEpoch = -1;
        if (IsFinalitySettlementHeight(nHeight, &nSettlementEpoch))
        {
            std::vector<CFinalityVote> vSettlementVotes;
            std::string strSettleError;
            // Same budget function the validator calls, off the same parent: the
            // reserve earlier blocks withheld, clamped to the issuance headroom.
            const int64_t nSettlementBudget =
                GetClampedFinalitySettlementBudget(pindexPrev, nSettlementEpoch);
            if (!GatherFinalitySettlementVotes(pindexPrev, nSettlementEpoch, vSettlementVotes, &strSettleError) ||
                !BuildFinalitySettlementOutputs(vSettlementVotes, nSettlementBudget,
                                                vFinalitySettlementOutputs,
                                                nFinalitySettlementTotal, &strSettleError))
            {
                // Fail closed: every validator would reject a template without the settlement.
                printf("CreateNewBlock: cannot build finality settlement for epoch %d at height %d: %s\n",
                       nSettlementEpoch, nHeight, strSettleError.c_str());
                return NULL;
            }

            // Reserve room up front: the settlement outputs are mandatory, so transaction
            // selection must not be able to crowd them out of the block.
            unsigned int nSettlementSize = 0;
            for (const CTxOut& out : vFinalitySettlementOutputs)
                nSettlementSize += ::GetSerializeSize(out, SER_NETWORK, PROTOCOL_VERSION);
            if (nSettlementSize + 1000 < nBlockMaxSize)
                nBlockMaxSize -= nSettlementSize;
            else
                nBlockMaxSize = 1000;
            nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);
            nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);
        }
    }

    // Collect memory pool transactions into the block
    int64_t nFees = 0;
    // Declared IV5 fees of the selected transactions. Post-fork they settle in the pool,
    // so they leave the transparent allowance exactly as ConnectBlock drops them.
    int64_t nIV5FeeSum = 0;
    {
        LOCK2(cs_main, mempool.cs);
        CTxDB txdb("r");

        if(bCollateralNodePayment) {
            bool hasPayment = true;
            //spork
            bool found = false;
            CScript payee;
            if(!collateralnodePayments.GetBlockPayee(pindexPrev->nHeight+1, payee)){
                found = false;
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
                    if (fDebug && fDebugCN) printf("CreateNewBlock: Found a collateralnode to pay: %s\n",payee.ToString(true).c_str());
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

            if(hasPayment){
                payments = txNew.vout.size() + 1;
                if (fDebug && fDebugNet) printf("CreateNewBlock(): Payment Size: %i\n", payments);
                pblock->vtx[0].vout.resize(payments);

                pblock->vtx[0].vout[payments-1].scriptPubKey = payee;
                pblock->vtx[0].vout[payments-1].nValue = 0;

                CTxDestination address1;
                ExtractDestination(payee, address1);
                CBitcoinAddress address2(address1);

                if (fDebug && fDebugCN) printf("CreateNewBlock(): Collateralnode payment to %s\n", address2.ToString().c_str());
            }
        }

        // Priority order to process transactions
        list<COrphan> vOrphan; // list memory doesn't move
        map<uint256, vector<COrphan*> > mapDependers;

        // Collect txids and spent inputs from DAG sibling
        // blocks to avoid duplicates and fee accounting drift. ConnectBlock
        // skips transactions whose inputs were already spent by earlier DAG
        // siblings, so CreateNewBlock must exclude them before adding their
        // fees to the coinbase value.
        std::set<uint256> setDAGSiblingTxids;
        std::set<COutPoint> setDAGSiblingSpentOutpoints;
        std::set<uint256> setDAGSiblingSpentTags;
        if (nHeight >= FORK_HEIGHT_DAG && pindexPrev->phashBlock)
        {
            std::set<uint256> siblings;
            std::set<uint256> candidateParents(vDAGParentsForBlock.begin(), vDAGParentsForBlock.end());
            if (candidateParents.empty())
                candidateParents.insert(pindexPrev->GetBlockHash());

            BOOST_FOREACH(const uint256& hashParent, candidateParents)
            {
                CBlockDAGData parentDagData;
                if (g_dagManager.GetDAGData(hashParent, parentDagData))
                {
                    BOOST_FOREACH(const uint256& hashChild, parentDagData.vDAGChildren)
                        siblings.insert(hashChild);
                }

                std::set<uint256> parentSiblings = g_dagManager.GetDAGSiblingBlocks(hashParent);
                siblings.insert(parentSiblings.begin(), parentSiblings.end());
            }

            BOOST_FOREACH(const uint256& hashSib, siblings)
            {
                std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashSib);
                if (mi == mapBlockIndex.end())
                    continue;
                CBlock sibBlock;
                if (!sibBlock.ReadFromDisk(mi->second))
                    continue;
                for (const CTransaction& sibTx : sibBlock.vtx)
                {
                    if (sibTx.IsCoinBase() || sibTx.IsCoinStake())
                        continue;
                    setDAGSiblingTxids.insert(sibTx.GetHash());
                    BOOST_FOREACH(const CTxIn& txin, sibTx.vin)
                        setDAGSiblingSpentOutpoints.insert(txin.prevout);
                    AppendPrivacyVNextConflictTags(sibTx, setDAGSiblingSpentTags);
                }
            }
        }

        // The height this block would occupy. Both selection passes gate on it.
        const int nCandidateHeight = pindexPrev->nHeight + 1;

        // This vector will be sorted into a priority queue:
        vector<TxPriority> vecPriority;
        vecPriority.reserve(mempool.mapTx.size());
        for (map<uint256, CTransaction>::iterator mi = mempool.mapTx.begin(); mi != mempool.mapTx.end(); ++mi)
        {
            CTransaction& tx = (*mi).second;
            if (tx.IsCoinBase() || tx.IsCoinStake() || !tx.IsFinal())
                continue;

            if ((tx.nVersion == ANON_TXN_VERSION &&
                 (IsLegacyPrivacyPolicyDisabled() ||
                  nCandidateHeight >= FORK_HEIGHT_RINGSIG_DEPRECATION)) ||
                (IsLegacyShieldedTransactionVersion(tx.nVersion) &&
                 (IsLegacyPrivacyPolicyDisabled() ||
                  IsBoundaryAActiveAtHeight(nCandidateHeight))) ||
                (tx.nVersion == SHIELDED_TX_VERSION_DSP &&
                 (!IsBoundaryBActiveAtHeight(nCandidateHeight) ||
                  !IsShieldedVNextConsensusReady())))
                continue;

            // IDAG: Skip transactions already in DAG sibling blocks
            if (!setDAGSiblingTxids.empty() && setDAGSiblingTxids.count(tx.GetHash()))
                continue;
            if (TransactionSpendsAnyOutpoint(tx, setDAGSiblingSpentOutpoints))
                continue;
            // A note already spent by a sibling makes this transaction inactive at
            // connect time; including it only wastes the space.
            if (!setDAGSiblingSpentTags.empty())
            {
                std::set<uint256> setTags;
                AppendPrivacyVNextConflictTags(tx, setTags);
                bool fSpentBySibling = false;
                for (std::set<uint256>::const_iterator it = setTags.begin();
                     !fSpentBySibling && it != setTags.end(); ++it)
                    fSpentBySibling = setDAGSiblingSpentTags.count(*it) > 0;
                if (fSpentBySibling)
                    continue;
            }

            // Transparent finality votes use existing UTXOs as stake proofs.
            // Consensus rejects blocks that both commit such a vote and spend
            // the proof UTXO, so reserve those outpoints while building the
            // candidate block.
            if (TransactionSpendsAnyOutpoint(tx, setFinalityStakeProofOutpoints))
                continue;

            // The term bound moves with height, so a name tx the mempool took
            // at an earlier height can be one connect would skip by the time it
            // would be mined. Re-ask at the candidate height and leave it out.
            if (tx.nVersion == NAMECOIN_TX_VERSION)
            {
                std::string strNameReason;
                if (!hooks->CheckNameTxShape(tx, nCandidateHeight, strNameReason))
                {
                    printf("CreateNewBlock: excluding name transaction %s: %s\n",
                           tx.GetHash().ToString().substr(0,10).c_str(),
                           strNameReason.c_str());
                    continue;
                }
            }

            COrphan* porphan = NULL;
            double dPriority = 0;
            int64_t nTotalIn = 0;
            bool fMissingInputs = false;
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
            {
                if (tx.nVersion == ANON_TXN_VERSION
                    && txin.IsAnonInput()) // anon inputs are verified later in CheckAnonInputs()
                    continue;
                // Read prev transaction
                CTransaction txPrev;
                CTxIndex txindex;
                if (!txPrev.ReadFromDisk(txdb, txin.prevout, txindex))
                {
                    // This should never happen; all transactions in the memory
                    // pool should connect to either transactions in the chain
                    // or other transactions in the memory pool.
                    if (!mempool.mapTx.count(txin.prevout.hash))
                    {
                        printf("ERROR: mempool transaction missing input\n");
                        fMissingInputs = true;
                        if (porphan)
                            vOrphan.pop_back();
                        break;
                    }

                    // Has to wait for dependencies
                    if (!porphan)
                    {
                        // Use list for automatic deletion
                        vOrphan.push_back(COrphan(&tx));
                        porphan = &vOrphan.back();
                    }
                    mapDependers[txin.prevout.hash].push_back(porphan);
                    porphan->setDependsOn.insert(txin.prevout.hash);
                    nTotalIn += mempool.mapTx[txin.prevout.hash].vout[txin.prevout.n].nValue;
                    continue;
                }
                int64_t nValueIn = txPrev.vout[txin.prevout.n].nValue;
                nTotalIn += nValueIn;

                int nConf = txindex.GetDepthInMainChain();
                dPriority += (double)nValueIn * nConf;
            };

            if (tx.nVersion == ANON_TXN_VERSION)
            {
                int64_t nSumAnon;
                bool fInvalid;
                if (!tx.CheckAnonInputs(txdb, nSumAnon, fInvalid, false))
                {
                    if (fInvalid)
                        printf("CreateNewBlock() : CheckAnonInputs found invalid tx %s\n", tx.GetHash().ToString().substr(0,10).c_str());
                    fMissingInputs = true;
                    continue;
                };

                nTotalIn += nSumAnon;
            };

            if (fMissingInputs)
                continue;

            // Priority is sum(valuein * age) / txsize
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            dPriority /= nTxSize;

            // This is a more accurate fee-per-kilobyte than is used by the client code, because the
            // client code rounds up the size to the nearest 1K. That's good, because it gives an
            // incentive to create smaller transactions.
            int64_t nFee = nTotalIn-tx.GetValueOut();
            if (tx.IsShielded() && tx.nValueBalance != 0)
            {
                if ((tx.nValueBalance > 0 && nFee > std::numeric_limits<int64_t>::max() - tx.nValueBalance) ||
                    (tx.nValueBalance < 0 && nFee < std::numeric_limits<int64_t>::min() - tx.nValueBalance))
                {
                    printf("CreateNewBlock: fee overflow with shielded value balance, skipping tx\n");
                    continue;
                }
                nFee += tx.nValueBalance;
            }
            if (tx.IsPrivacyVNext())
            {
                // The anchor window is finite and the tip has moved since this
                // transaction was accepted. Selecting one that has aged out builds a
                // block this node's own ConnectBlock rejects, every round.
                std::string strAnchorError;
                if (!CheckPrivacyVNextFinalizedAnchor(txdb, nCandidateHeight, tx,
                                                      strAnchorError))
                {
                    printf("CreateNewBlock: IV5 anchor no longer valid at height %d, "
                           "skipping tx %s: %s\n", nCandidateHeight,
                           tx.GetHash().ToString().substr(0,10).c_str(),
                           strAnchorError.c_str());
                    continue;
                }

                int64_t nAbsorbed = 0;
                int64_t nReleased = 0;
                int64_t nDeclaredBalance = 0;
                bool fFlowLocalFailure = false;
                std::string strFlowError;
                if (!GetPrivacyVNextTransparentFlow(tx, nAbsorbed, nReleased,
                                                    fFlowLocalFailure, strFlowError,
                                                    NULL, &nDeclaredBalance))
                {
                    printf("CreateNewBlock: IV5 pool flow unavailable, skipping tx: %s\n",
                           strFlowError.c_str());
                    continue;
                }
                // A transaction accepted before the fork may still be sitting in the
                // mempool; selecting it now builds a block this node's own
                // ConnectBlock rejects.
                std::string strRetiredError;
                if (!CheckPrivacyVNextUnshieldRetired(nDeclaredBalance,
                                                      nCandidateHeight,
                                                      strRetiredError))
                {
                    printf("CreateNewBlock: skipping tx %s: %s\n",
                           tx.GetHash().ToString().substr(0,10).c_str(),
                           strRetiredError.c_str());
                    continue;
                }
                nFee += nReleased;
                nFee -= nAbsorbed;
            }
            double dFeePerKb =  double(nFee) / (double(nTxSize)/1000.0);

            if (porphan)
            {
                porphan->dPriority = dPriority;
                porphan->dFeePerKb = dFeePerKb;
            }
            else
                vecPriority.push_back(TxPriority(dPriority, dFeePerKb, nFee, &(*mi).second));
        }

        // Collect transactions into block
        map<uint256, CTxIndex> mapTestPool;
        // Key images already consumed by a transaction in this block. ConnectBlock reads
        // the spent-key index as it goes, so an attestation ordered after a spend of the
        // note it names is rejected and takes the whole block with it.
        std::set<uint256> setBlockPrivacyVNextSpent;
        uint64_t nBlockSize = 1000;
        uint64_t nBlockTx = 0;
        int nBlockSigOps = 100;
        bool fSortedByFee = (nBlockPrioritySize <= 0);

        TxPriorityCompare comparer(fSortedByFee);
        std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

        while (!vecPriority.empty())
        {
            // Take highest priority transaction off the priority queue:
            double dPriority = vecPriority.front().get<0>();
            double dFeePerKb = vecPriority.front().get<1>();
            int64_t nFee = vecPriority.front().get<2>();
            CTransaction& tx = *(vecPriority.front().get<3>());

            std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
            vecPriority.pop_back();

            // Size limits
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            if (nBlockSize + nTxSize >= nBlockMaxSize)
                continue;

            // Legacy limits on sigOps:
            unsigned int nTxSigOps = tx.GetLegacySigOpCount();
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

            // Timestamp limit
            if (tx.nTime > GetAdjustedTime() || (fProofOfStake && tx.nTime > pblock->vtx[0].nTime))
                continue;

            // Transaction fee
            int64_t nMinFee = tx.GetMinFee(nBlockSize, GMF_BLOCK); // will get GMF_ANON if tx.nVersion == ANON_TXN_VERSION

            // An IV5 attestation carries no value to pay a fee from, so the size-based
            // floor and the free-transaction skip below would leave it unmineable for
            // good. Relay makes the same exemption.
            const bool fFeeExempt = IsPrivacyVNextFeeExemptShape(tx);

            // Skip free transactions if we're past the minimum block size:
            if (fSortedByFee && (dFeePerKb < nMinTxFee) &&
                (nBlockSize + nTxSize >= nBlockMinSize) && !fFeeExempt)
                continue;

            // Prioritize by fee once past the priority size or we run out of high-priority
            // transactions:
            if (!fSortedByFee &&
                ((nBlockSize + nTxSize >= nBlockPrioritySize) || (dPriority < COIN * 144 / 250)))
            {
                fSortedByFee = true;
                comparer = TxPriorityCompare(fSortedByFee);
                std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
            }

            // Connecting shouldn't fail due to dependency on other memory pool transactions
            // because we're already processing them in order of dependency
            map<uint256, CTxIndex> mapTestPoolTmp(mapTestPool);
            MapPrevTx mapInputs;
            bool fInvalid;
            if (!tx.FetchInputs(txdb, mapTestPoolTmp, false, true, mapInputs, fInvalid))
                continue;

            // -- Avoid calling CheckAnonInputs twice, use nFee from vecPriority
            //int64_t nTxFees = tx.GetValueIn(mapInputs)-tx.GetValueOut();
            if (nFee == 0) // tx came from COrphan
            {
                int64_t nTxFees = tx.GetValueIn(mapInputs)-tx.GetValueOut();

                if (tx.nVersion == ANON_TXN_VERSION)
                {
                    int64_t nSumAnon;
                    bool fInvalid;
                    if (!tx.CheckAnonInputs(txdb, nSumAnon, fInvalid, false))
                    {
                        if (fInvalid)
                            printf("CreateNewBlock() : CheckAnonInputs found invalid tx %s\n", tx.GetHash().ToString().substr(0,10).c_str());
                        continue;
                    };

                    nTxFees += nSumAnon;
                };
                if (tx.IsShielded() && tx.nValueBalance != 0)
                    nTxFees += tx.nValueBalance;
                if (tx.IsPrivacyVNext())
                {
                    int64_t nAbsorbed = 0;
                    int64_t nReleased = 0;
                    bool fFlowLocalFailure = false;
                    std::string strFlowError;
                    if (!GetPrivacyVNextTransparentFlow(tx, nAbsorbed, nReleased,
                                                        fFlowLocalFailure, strFlowError))
                    {
                        printf("CreateNewBlock() : IV5 pool flow unavailable for %s: %s\n",
                               tx.GetHash().ToString().substr(0,10).c_str(),
                               strFlowError.c_str());
                        continue;
                    }
                    nTxFees += nReleased;
                    nTxFees -= nAbsorbed;
                }
                nFee = nTxFees;
            };
            // TODO: must this be done twice!?
            // Need to look at COrphan
            if (nFee < nMinFee && !(nFee == 0 && fFeeExempt))
                continue;

            nTxSigOps += tx.GetP2SHSigOpCount(mapInputs);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

            // Orphan-queue transactions skipped selection, and nothing else checks the
            // anchor; an aged-out anchor would make ConnectBlock reject the block.
            int64_t nDeclaredPayloadFee = 0;
            std::vector<uint256> vTxPrivacyVNextSpent;
            if (tx.IsPrivacyVNext())
            {
                std::vector<uint256> vTxPrivacyVNextAttested;
                if (!ReadPrivacyVNextTxKeyImages(tx, vTxPrivacyVNextSpent,
                                                 vTxPrivacyVNextAttested))
                {
                    printf("CreateNewBlock: IV5 payload effects unavailable, skipping tx %s\n",
                           tx.GetHash().ToString().substr(0,10).c_str());
                    continue;
                }
                bool fCollateralAlreadySpent = false;
                for (size_t i = 0; i < vTxPrivacyVNextAttested.size(); ++i)
                {
                    if (!setBlockPrivacyVNextSpent.count(vTxPrivacyVNextAttested[i]))
                        continue;
                    printf("CreateNewBlock: dropping IV5 attestation %s; this block "
                           "already spends the collateral it names\n",
                           tx.GetHash().ToString().substr(0,10).c_str());
                    fCollateralAlreadySpent = true;
                    break;
                }
                if (fCollateralAlreadySpent)
                    continue;

                std::string strAnchorError;
                if (!CheckPrivacyVNextFinalizedAnchor(txdb, nCandidateHeight, tx,
                                                      strAnchorError))
                {
                    printf("CreateNewBlock: IV5 anchor no longer valid at height %d, "
                           "skipping tx %s: %s\n", nCandidateHeight,
                           tx.GetHash().ToString().substr(0,10).c_str(),
                           strAnchorError.c_str());
                    continue;
                }

                int64_t nAbsorbed = 0;
                int64_t nReleased = 0;
                int64_t nDeclaredBalance = 0;
                bool fFlowLocalFailure = false;
                std::string strFlowError;
                if (!GetPrivacyVNextTransparentFlow(tx, nAbsorbed, nReleased,
                                                    fFlowLocalFailure, strFlowError,
                                                    &nDeclaredPayloadFee,
                                                    &nDeclaredBalance))
                {
                    printf("CreateNewBlock: IV5 pool flow unavailable for %s: %s\n",
                           tx.GetHash().ToString().substr(0,10).c_str(),
                           strFlowError.c_str());
                    continue;
                }
                std::string strRetiredError;
                if (!CheckPrivacyVNextUnshieldRetired(nDeclaredBalance,
                                                      nCandidateHeight,
                                                      strRetiredError))
                {
                    printf("CreateNewBlock: skipping tx %s: %s\n",
                           tx.GetHash().ToString().substr(0,10).c_str(),
                           strRetiredError.c_str());
                    continue;
                }
            }

            if (!tx.ConnectInputs(txdb, mapInputs, mapTestPoolTmp, CDiskTxPos(1,1,1), pindexPrev, false, true, MANDATORY_SCRIPT_VERIFY_FLAGS))
                continue;
            mapTestPoolTmp[tx.GetHash()] = CTxIndex(CDiskTxPos(1,1,1), tx.vout.size());
            swap(mapTestPool, mapTestPoolTmp);

            // Added
            pblock->vtx.push_back(tx);
            for (size_t i = 0; i < vTxPrivacyVNextSpent.size(); ++i)
                setBlockPrivacyVNextSpent.insert(vTxPrivacyVNextSpent[i]);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            //nFees += nTxFees;
            nFees += nFee;
            // One derivation of the sum the coinbase allowance drops and the coinbase
            // note credits back, over exactly the transactions this block carries.
            nIV5FeeSum += nDeclaredPayloadFee;

            if (fDebug && GetBoolArg("-printpriority"))
            {
                printf("priority %.1f feeperkb %.1f txid %s\n",
                       dPriority, dFeePerKb, tx.GetHash().ToString().c_str());
            }

            // Add transactions that depend on this one to the priority queue
            uint256 hash = tx.GetHash();
            if (mapDependers.count(hash))
            {
                BOOST_FOREACH(COrphan* porphan, mapDependers[hash])
                {
                    if (!porphan->setDependsOn.empty())
                    {
                        porphan->setDependsOn.erase(hash);
                        if (porphan->setDependsOn.empty())
                        {
                            vecPriority.push_back(TxPriority(porphan->dPriority, porphan->dFeePerKb, porphan->nFee, porphan->ptx));
                            std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                        }
                    }
                }
            }
        }

        int64_t nFinalityRewardTotal = 0;
        if (!fProofOfStake && nHeight >= FORK_HEIGHT_DAG)
        {
            std::vector<CFinalityVote> vVotesEmbedded;
            vVotesEmbedded.reserve(vFinalityVotesForBlock.size());
            for (const CFinalityVote& vote : vFinalityVotesForBlock)
            {
                // No reward accumulation here: carrying a vote mints nothing, so there is
                // no per-vote total to overflow-check. The epoch total is settled below.
                CScript voteScript;
                if (!BuildFinalityVoteScriptForHeight(vote, nHeight, voteScript))
                    continue;
                unsigned int nVoteCommitSize = ::GetSerializeSize(voteScript, SER_NETWORK, PROTOCOL_VERSION);
                if (nBlockSize + nVoteCommitSize + 64 >= nBlockMaxSize)
                    break;

                // Commitment only. Carrying a vote mints nothing -- the voter is paid
                // once for the whole epoch at the settlement height, below.
                CTxOut voteOut;
                voteOut.nValue = 0;
                voteOut.scriptPubKey = voteScript;
                pblock->vtx[0].vout.push_back(voteOut);
                vVotesEmbedded.push_back(vote);

                nBlockSize += nVoteCommitSize + 64;
            }

            // Epoch settlement leg (space already reserved above).
            for (const CTxOut& settleOut : vFinalitySettlementOutputs)
            {
                pblock->vtx[0].vout.push_back(settleOut);
                nBlockSize += ::GetSerializeSize(settleOut, SER_NETWORK, PROTOCOL_VERSION);
            }
            nFinalityRewardTotal = nFinalitySettlementTotal;
            if (nFinalityRewardTotal > 0)
                printf("CreateNewBlock: finality settlement at height %d pays %u voter(s), total %s\n",
                       nHeight, (unsigned int)vFinalitySettlementOutputs.size(),
                       FormatMoney(nFinalityRewardTotal).c_str());

            // Note votes ride their own coinbase outputs and mint nothing: a vote is not a
            // pool operation, so the coinbase IV5 payload is deliberately untouched here.
            if (IsIV5NoteVoteActiveAtHeight(nHeight))
            {
                std::vector<CNoteFinalityVote> vNoteVotes =
                    g_finalityTracker.GetPendingNoteVotesForBlock(nHeight);
                for (const CNoteFinalityVote& vote : vNoteVotes)
                {
                    // Relay accepted this vote without a chain to test it against.
                    // Connect judges it against THIS block's ancestors, so a vote naming
                    // a boundary block off our own chain would make the whole template
                    // invalid. Drop it here instead. Ancestry only: the proofs were
                    // verified once at relay and re-running them per template is far too
                    // expensive at 1s spacing.
                    const CBlockIndex* pNamed = GetFinalityAncestorOnChain(
                        pindexPrev, vote.nHeight, FINALITY_ANCESTOR_MAX_WALK);
                    if (!pNamed || pNamed->GetBlockHash() != vote.hashBlock)
                    {
                        printf("CreateNewBlock: excluding note vote for off-chain epoch block %s\n",
                               vote.hashBlock.ToString().substr(0,20).c_str());
                        continue;
                    }
                    CScript voteScript;
                    if (!BuildNoteFinalityVoteScript(vote, voteScript))
                        continue;
                    unsigned int nVoteCommitSize =
                        ::GetSerializeSize(voteScript, SER_NETWORK, PROTOCOL_VERSION);
                    if (nBlockSize + nVoteCommitSize + 16 >= nBlockMaxSize)
                        break;

                    CTxOut voteOut;
                    voteOut.nValue = 0;
                    voteOut.scriptPubKey = voteScript;
                    pblock->vtx[0].vout.push_back(voteOut);
                    nBlockSize += nVoteCommitSize + 16;
                }
            }

            std::vector<CFinalityTallyShare> vFinalityShares;
            if (!IsLegacyPrivacyPolicyDisabled() &&
                !IsBoundaryAActiveAtHeight(nHeight))
                vFinalityShares = g_finalityTracker.GetPendingTallySharesForBlock(
                    nHeight, 16, &vVotesEmbedded);
            for (const CFinalityTallyShare& share : vFinalityShares)
            {
                CScript shareScript = BuildFinalityTallyShareScript(share);
                unsigned int nShareCommitSize = ::GetSerializeSize(shareScript, SER_NETWORK, PROTOCOL_VERSION);
                if (nBlockSize + nShareCommitSize + 16 >= nBlockMaxSize)
                    break;

                CTxOut shareOut;
                shareOut.nValue = 0;
                shareOut.scriptPubKey = shareScript;
                pblock->vtx[0].vout.push_back(shareOut);
                nBlockSize += nShareCommitSize + 16;
            }

            std::vector<CFinalityTallyCertificate> vFinalityCerts = g_finalityTracker.GetPendingTallyCertificatesForBlock(nHeight);
            for (const CFinalityTallyCertificate& cert : vFinalityCerts)
            {
                if (cert.HasPrivateWeight() &&
                    (IsLegacyPrivacyPolicyDisabled() ||
                     IsBoundaryAActiveAtHeight(nHeight)))
                    continue;
                // Only embed certificates every node can validate: votes must
                // be connected or embedded in this same block. Certificates
                // depending on local pending relay state would make the block
                // invalid on nodes that have not seen those votes.
                std::string strCertError;
                if (!g_finalityTracker.CheckTallyCertificate(cert, txdb, &strCertError, &vVotesEmbedded, false, nHeight))
                {
                    printf("CreateNewBlock: excluding finality tally certificate %s: %s\n",
                           cert.GetHash().ToString().substr(0,20).c_str(), strCertError.c_str());
                    continue;
                }

                CScript certScript;
                if (!BuildFinalityTallyCertificateScriptForHeight(
                        cert, nHeight, certScript))
                    continue;
                unsigned int nCertCommitSize = ::GetSerializeSize(certScript, SER_NETWORK, PROTOCOL_VERSION);
                if (nBlockSize + nCertCommitSize + 16 >= nBlockMaxSize)
                    break;

                CTxOut certOut;
                certOut.nValue = 0;
                certOut.scriptPubKey = certScript;
                pblock->vtx[0].vout.push_back(certOut);
                nBlockSize += nCertCommitSize + 16;
            }

        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;

        // Post-fork the block's IV5 fees go to the pool, not the transparent coinbase;
        // nFees already includes them, so they are removed from the claim.
        const bool fIV5FeeNoteFork = IsIV5FeeNoteActiveAtHeight(nHeight);
        int64_t nAllowedFees = nFees;
        if (fIV5FeeNoteFork)
            nAllowedFees -= nIV5FeeSum;

        // Placed before the reward is computed (the size penalty reads the serialized
        // block); dropped if the final payload size differs, since a larger claimed block
        // could overpay.
        bool fFeeNote = false;
        size_t nFeeNoteBytes = 0;
        if (!fProofOfStake && fIV5FeeNoteFork && nIV5FeeSum > 0 && pwallet)
        {
            std::vector<unsigned char> vchProvisional;
            std::string strNoteError;
            if (!pwallet->BuildPrivacyVNextFeeNote(nIV5FeeSum, pblock->vtx[0],
                                                   vchProvisional, strNoteError))
            {
                printf("CreateNewBlock: not collecting %" PRId64 " of IV5 fees "
                       "(they are burned): %s\n", nIV5FeeSum, strNoteError.c_str());
            }
            else if (nBlockSize + vchProvisional.size() + 64 >= nBlockMaxSize)
            {
                printf("CreateNewBlock: no room for the IV5 fee note; %" PRId64
                       " of IV5 fees are burned\n", nIV5FeeSum);
            }
            else
            {
                nFeeNoteBytes = vchProvisional.size();
                pblock->vtx[0].nVersion = SHIELDED_TX_VERSION_DSP;
                pblock->vtx[0].privacyVNext.vchPayload.swap(vchProvisional);
                fFeeNote = true;
            }
        }

        int nRewardHeight = nHeight;
        if (nHeight < FORK_HEIGHT_TIGHTER_DRIFT && nHeight > 0)
            nRewardHeight = nHeight - 1;
        // ONE subsidy, split at payment, from the same function every validator
        // calls. The settlement this block owes is netted off the issuance
        // headroom before the subsidy is computed, exactly as ConnectBlock does.
        int64_t nSubsidy = GetProofOfWorkReward(nRewardHeight, 0, pindexPrev, nFinalitySettlementTotal);
        int64_t blockValue = nSubsidy + nAllowedFees;
        int64_t nIssuance = nSubsidy;
        if (!fProofOfStake)
        {
            blockValue = ApplyBlockSizePenalty(blockValue, *pblock, pindexPrev);
            nIssuance = ApplyBlockSizePenalty(nIssuance, *pblock, pindexPrev);
        }
        if (nIssuance > blockValue)
            nIssuance = blockValue;
        if (!MoneyRange(blockValue))
        {
            printf("CreateNewBlock: ERROR: blockValue %" PRId64 " out of MoneyRange (nHeight=%d, nFees=%" PRId64 ")\n", blockValue, nHeight, nAllowedFees);
            return NULL;
        }
        const CBlockSubsidySplit subsidySplit =
            CBlockSubsidySplit::ForBlock(nHeight, nIssuance, blockValue - nIssuance,
                                         CollateralnodeShare::Paid);
        // The finality reserve stays unminted here; it settles to the epoch's
        // voters at H_E + K. What this block may pay out is the rest.
        blockValue = subsidySplit.PaidToBlock();
        int64_t collateralnodePayment = subsidySplit.Collateralnode();

        //create collateralnode payment
        if(payments > 1){
            if (collateralnodePayment > blockValue)
            {
                printf("CreateNewBlock: WARNING: collateralnodePayment %" PRId64 " > blockValue %" PRId64 ", clamping\n",
                       collateralnodePayment, blockValue);
                collateralnodePayment = blockValue;
            }
            pblock->vtx[0].vout[payments-1].nValue = collateralnodePayment;
            blockValue -= collateralnodePayment;
        }

        if (fDebug && GetBoolArg("-printpriority"))
            printf("CreateNewBlock(): total size %" PRIu64"\n", nBlockSize);

        if (!fProofOfStake){
            pblock->vtx[0].vout[0].nValue = blockValue;
        }

        if (pFees)
            *pFees = nFees;

        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        pblock->nTime          = max(pindexPrev->GetPastTimeLimit()+1, pblock->GetMaxTransactionTime());
        pblock->nTime          = max(pblock->GetBlockTime(), PastDrift(pindexPrev->GetBlockTime(), pindexPrev->nHeight + 1));
        if (!fProofOfStake)
            pblock->UpdateTime(pindexPrev);
        pblock->nNonce         = 0;
        // Rewrites a coinbase output, so it has to run before the note below binds
        // the output vector. Stamping afterwards leaves the producer's own block
        // failing its own binding check on every node that receives it.
        StampMsTimestampCommitment(pblock.get(), nHeight);

        // The payload binds the output vector, which only settles above. Rebuild it
        // against the final coinbase; anything that changes its size invalidates the
        // penalty already applied, so drop the note rather than publish a claim
        // computed over a block that no longer exists.
        //
        // Last thing here that may touch vout. IncrementExtraNonce runs after this
        // and edits vin[0].scriptSig only, which the binding excludes.
        if (fFeeNote)
        {
            std::string strDrop;
            std::vector<unsigned char> vchFinal;
            std::string strNoteError;
            if (!pwallet->BuildPrivacyVNextFeeNote(nIV5FeeSum, pblock->vtx[0],
                                                   vchFinal, strNoteError) ||
                vchFinal.size() != nFeeNoteBytes)
            {
                strDrop = strNoteError.empty() ? "payload size is not stable"
                                               : strNoteError;
            }
            else
            {
                pblock->vtx[0].privacyVNext.vchPayload.swap(vchFinal);
            }
            if (!strDrop.empty())
            {
                printf("CreateNewBlock: dropping the IV5 fee note; %" PRId64
                       " of IV5 fees are burned: %s\n", nIV5FeeSum, strDrop.c_str());
                pblock->vtx[0].privacyVNext.SetNull();
                pblock->vtx[0].nVersion = CTransaction::CURRENT_VERSION;
                fFeeNote = false;
            }
        }
    }

    // ConnectBlock's two checks, after everything that may write to the coinbase.
    // A rewrite between the note's build and here ships a block this node refuses
    // itself; dropping the note burns the fees and leaves the block valid.
    if (!pblock->vtx.empty() && pblock->vtx[0].IsPrivacyVNext())
    {
        PrivacyVNextStateEffects effects;
        const PrivacyVNextPayloadValidation validation =
            ExtractPrivacyVNextPayloadEffects(
                static_cast<uint32_t>(pblock->vtx[0].nVersion),
                pblock->vtx[0].privacyVNext.vchPayload, effects);
        std::string strDrop;
        if (!validation.IsValid())
        {
            strDrop = validation.strError;
        }
        else
        {
            std::string strBindingError;
            if (!CheckPrivacyVNextTransparentBinding(pblock->vtx[0], effects,
                                                     strBindingError))
                strDrop = strBindingError;
        }
        if (!strDrop.empty())
        {
            printf("CreateNewBlock: dropping the IV5 fee note, its fees are burned: "
                   "%s\n", strDrop.c_str());
            pblock->vtx[0].privacyVNext.SetNull();
            pblock->vtx[0].nVersion = CTransaction::CURRENT_VERSION;
        }
    }

    return pblock.release();
}


void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static CCriticalSection cs_extraNonce;
    static unsigned int nGlobalExtraNonce = 0;
    {
        LOCK(cs_extraNonce);
        nExtraNonce = ++nGlobalExtraNonce;
    }

    int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    CScript scriptSig = CoinbaseHeightScript(nHeight);
    scriptSig << CBigNum(nExtraNonce);
    pblock->vtx[0].vin[0].scriptSig = scriptSig + COINBASE_FLAGS;
    if (pblock->vtx[0].vin[0].scriptSig.size() > 100)
    {
        printf("IncrementExtraNonce() : coinbase scriptSig too large (%d bytes)\n", (int)pblock->vtx[0].vin[0].scriptSig.size());
        return;
    }

    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
}


void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata, char* phash1)
{
    //
    // Pre-build hash buffers
    //
    struct
    {
        struct unnamed2
        {
            int nVersion;
            uint256 hashPrevBlock;
            uint256 hashMerkleRoot;
            unsigned int nTime;
            unsigned int nBits;
            unsigned int nNonce;
        }
        block;
        unsigned char pchPadding0[64];
        uint256 hash1;
        unsigned char pchPadding1[64];
    }
    tmp;
    memset(&tmp, 0, sizeof(tmp));

    tmp.block.nVersion       = pblock->nVersion;
    tmp.block.hashPrevBlock  = pblock->hashPrevBlock;
    tmp.block.hashMerkleRoot = pblock->hashMerkleRoot;
    tmp.block.nTime          = pblock->nTime;
    tmp.block.nBits          = pblock->nBits;
    tmp.block.nNonce         = pblock->nNonce;

    FormatHashBlocks(&tmp.block, sizeof(tmp.block));
    FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));

    // Byte swap all the input buffer
    for (unsigned int i = 0; i < sizeof(tmp)/4; i++)
        ((unsigned int*)&tmp)[i] = ByteReverse(((unsigned int*)&tmp)[i]);

    // Precalc the first half of the first hash, which stays constant
    SHA256Transform(pmidstate, &tmp.block, pSHA256InitState);

    memcpy(pdata, &tmp.block, 128);
    memcpy(phash1, &tmp.hash1, 64);
}


bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey)
{
    uint256 hashBlock = pblock->GetHash();
    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

    if(!pblock->IsProofOfWork())
        return error("CheckWork() : %s is not a proof-of-work block", hashBlock.GetHex().c_str());

    if (hashBlock > hashTarget)
        return error("CheckWork() : proof-of-work not meeting target");

    //// debug print
    printf("CheckWork() : new proof-of-work block found  \n  hash: %s  \ntarget: %s\n", hashBlock.GetHex().c_str(), hashTarget.GetHex().c_str());
    pblock->print();
    printf("generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue).c_str());

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != hashBestChain)
            return error("CheckWork() : generated block is stale");

        // Remove key from key pool
        reservekey.KeepKey();

        // Track how many getdata requests this block gets
        {
            LOCK(wallet.cs_wallet);
            wallet.mapRequestCount[hashBlock] = 0;
        }

        // Process this block the same as if we had received it from another node
        if (!ProcessBlock(NULL, pblock))
            return error("CheckWork() : ProcessBlock, block not accepted");
    }

    return true;
}

bool CheckStake(CBlock* pblock, CWallet& wallet)
{
    uint256 proofHash = 0, hashTarget = 0;
    uint256 hashBlock = pblock->GetHash();

    if(!pblock->IsProofOfStake())
        return error("CheckStake() : %s is not a proof-of-stake block", hashBlock.GetHex().c_str());
    {
        LOCK(cs_main);
        if (pindexBest && pindexBest->nHeight + 1 >= FORK_HEIGHT_DAG)
            return error("CheckStake() : proof-of-stake block production disabled after DAG fork");
    }

   // verify hash target and signature of coinstake tx -
    //if (!CheckProofOfStake(mapBlockIndex[pblock->hashPrevBlock], pblock->vtx[1], pblock->nBits, proofHash, hashTarget))
	if (!CheckProofOfStake(pblock->vtx[1], pblock->nBits, proofHash, hashTarget, nBestHeight + 1))
        return error("CheckStake() : proof-of-stake checking failed");

    //// debug print
    printf("CheckStake() : new proof-of-stake block found  \n  hash: %s \nproofhash: %s  \ntarget: %s\n", hashBlock.GetHex().c_str(), proofHash.GetHex().c_str(), hashTarget.GetHex().c_str());
    pblock->print();
    printf("out %s\n", FormatMoney(pblock->vtx[1].GetValueOut()).c_str());

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != hashBestChain)
            return error("CheckStake() : generated block is stale");

        // Track how many getdata requests this block gets
        {
            LOCK(wallet.cs_wallet);
            wallet.mapRequestCount[hashBlock] = 0;
        }

        // Process this block the same as if we had received it from another node
        if (!ProcessBlock(NULL, pblock))
            return error("CheckStake() : ProcessBlock, block not accepted");
    }

    return true;
}

void StakeMiner(CWallet *pwallet)
{
    SetThreadPriority(THREAD_PRIORITY_LOWEST);

    // Make this thread recognisable as the mining thread
    RenameThread("innova-miner");

    bool fTryToSync = true;
    int64_t nTimeLastStake = 0;
    int64_t nLastTallyPassMs = 0;

    while (true)
    {
        if (fShutdown)
            return;

        while (pwallet->IsLocked())
        {
            nLastCoinStakeSearchInterval = 0;
            MilliSleep(2000);
            if (fShutdown)
                return;
        }

        bool fWaitForSync;
        {
            LOCK(cs_vNodes);
            fWaitForSync = (!fRegTest && vNodes.empty()) || (!fRegTest && IsInitialBlockDownload() && !fHybridSPV);
        }
        while (fWaitForSync)
        {
            nLastCoinStakeSearchInterval = 0;
            fTryToSync = true;
            if (fDebug  && GetBoolArg("-printcoinstake"))
                printf("StakeMiner() IsInitialBlockDownload\n");
            MilliSleep(2000);
            if (fShutdown)
                return;
            {
                LOCK(cs_vNodes);
                fWaitForSync = vNodes.empty() || (IsInitialBlockDownload() && !fHybridSPV);
            }
        }

        if (fTryToSync)
        {
            fTryToSync = false;
            bool fTooFewNodes;
            {
                LOCK(cs_vNodes);
                fTooFewNodes = vNodes.size() < 3;
            }
            if (fTooFewNodes || nBestHeight < GetNumBlocksOfPeers())
            {
                if (fDebug  && GetBoolArg("-printcoinstake"))
                    printf("StakeMiner() vNodes.size() < 3 || nBestHeight < GetNumBlocksOfPeers()\n");
                vnThreadsRunning[THREAD_STAKE_MINER]--;
                MilliSleep(5000);
                vnThreadsRunning[THREAD_STAKE_MINER]++;
				if (fShutdown)
                    return;
            }
        }

        if (!fRegTest && !fHybridSPV && nBestHeight < GetNumBlocksOfPeers()-1)
        {
            if (fDebug  && GetBoolArg("-printcoinstake"))
                printf("StakeMiner() nBestHeight < GetNumBlocksOfPeers()\n");
            MilliSleep(nMinerSleep * 4);
            continue;
        };

        // Pause staking while chain is stale to yield cs_main for sync.
        // Staking during active sync causes cs_main contention that starves
        // ThreadMessageHandler, preventing block/inv processing.
        bool fChainStale = false;
        {
            LOCK(cs_main);
            fChainStale = !fRegTest && !fTestNet && pindexBest &&
                          pindexBest->GetBlockTime() < GetTime() - 300;
        }
        if (fChainStale)
        {
            if (fDebug && GetBoolArg("-printcoinstake"))
                printf("StakeMiner() chain stale, pausing for sync\n");
            MilliSleep(5000);
            continue;
        }

        // IDAG: after the DAG fork, stakers no longer create blocks. The
        // staking thread only produces transparent finality votes.
        bool fPostDAGFinalityMode = false;
        int nFinalityTipHeight = -1;
        {
            LOCK(cs_main);
            if (pindexBest && pindexBest->nHeight >= FORK_HEIGHT_DAG)
            {
                fPostDAGFinalityMode = true;
                nFinalityTipHeight = pindexBest->nHeight;
            }
        }
        if (fPostDAGFinalityMode)
        {
            // Own rhythm: the vote wake below must not multiply this work.
            if (GetTimeMillis() - nLastTallyPassMs >= FINALITY_VOTER_POLL_MS_PRE_DAG)
            {
                nLastTallyPassMs = GetTimeMillis();
                ProcessFinalityTallyCommittee();
            }
            // Shares one schedule with ThreadFinalityVoter: the epoch is claimed,
            // so whichever loop gets there first votes and the other does not
            // duplicate it.
            NotifyFinalityTipChanged(nFinalityTipHeight);
            int nClaimedEpoch = -1;
            if (ClaimFinalityVote(nFinalityTipHeight, nClaimedEpoch) == FINALITY_VOTE_CLAIM_OK)
            {
                bool fProduced = ProduceFinalityVote();
                ReleaseFinalityVote(nClaimedEpoch, fProduced);
            }
            WaitForFinalityVoteWork(FINALITY_VOTER_POLL_MS_POST_DAG);
            if (FinalityVoterShouldStop())
                return;
            continue;
        }

        // Post-DAG: reduce stake interval to match nMaxStakeSearchInterval (2s)
        // This ensures no timestamp slots are skipped between staking attempts
        int64_t nEffectiveStakeInterval = nMinStakeInterval;
        {
            LOCK(cs_main);
            if (pindexBest && pindexBest->nHeight >= FORK_HEIGHT_DAG)
                nEffectiveStakeInterval = std::min(nEffectiveStakeInterval, (int64_t)2);
        }
        if (nEffectiveStakeInterval > 0 && nTimeLastStake + nEffectiveStakeInterval > GetTime())
        {
            if (fDebug && GetBoolArg("-printcoinstake"))
                printf("StakeMiner() Rate limited to 1 / %d seconds.\n", (int)nEffectiveStakeInterval);
            MilliSleep(nEffectiveStakeInterval * 1000);
            continue;
        };

        if (vecCollateralnodes.size() == 0 && !fTestNet && !fRegTest)
        {
            if (fDebug && GetBoolArg("-printcoinstake")) printf("StakeMiner() waiting for CN list.");
            vnThreadsRunning[THREAD_STAKE_MINER]--;
            MilliSleep(10000);
            vnThreadsRunning[THREAD_STAKE_MINER]++;
            continue;
        }

        //
        // Create new block
        //
        int64_t nFees;
        if (fDebug && GetBoolArg("-printcoinstake")) printf ("creating block. ");
        unique_ptr<CBlock> pblock(CreateNewBlock(pwallet, true, &nFees));
        if (!pblock.get())
        {
            printf("StakeMiner: CreateNewBlock failed, retrying...\n");
            MilliSleep(5000);
            continue;
        }

        if (fDebug && GetBoolArg("-printcoinstake")) printf ("signing block. ");
        // Trying to sign a block
        if (pblock->SignBlock(*pwallet, nFees))
        {
            if (fDebug && GetBoolArg("-printcoinstake")) printf ("checking stake. ");
            bool staked;
            SetThreadPriority(THREAD_PRIORITY_NORMAL);
            staked = CheckStake(pblock.get(), *pwallet);
            if (staked && fDebug && GetBoolArg("-printcoinstake")) printf ("stake is good. \n");
            SetThreadPriority(THREAD_PRIORITY_LOWEST);
			if (fShutdown)
                return;
            MilliSleep(nMinerSleep);
            if (staked) {
                nTimeLastStake = GetAdjustedTime();
                MilliSleep(nMinerSleep*3); // sleep for a while after successfully staking
            }
            else if (fDebug && GetBoolArg("-printcoinstake")) printf ("stake is bad. \n");
        }
        else
        {
            if (fDebug && GetBoolArg("-printcoinstake")) printf ("failed to sign.\n");
			if (fShutdown)
                return;
            MilliSleep(nMinerSleep);
        }
    }
}

bool fCPUMining = false;
int nCPUMinerThreads = 1;
int nCPUMineTarget = 0;
static CCriticalSection cs_cpuminer;

static bool CPUMinerShouldRun()
{
    LOCK(cs_cpuminer);
    return fCPUMining && !fShutdown;
}

static void CPUMinerConsumeAcceptedBlock()
{
    LOCK(cs_cpuminer);
    if (nCPUMineTarget > 0)
    {
        nCPUMineTarget--;
        if (nCPUMineTarget <= 0)
            fCPUMining = false;
    }
}

void CPUMiner(CWallet* pwallet)
{
    printf("CPUMiner started with %d thread(s)\n", nCPUMinerThreads);
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("innova-cpuminer");

    unsigned int nExtraNonce = 0;
    CReserveKey reservekey(pwallet);
    CBlock* pblock = NULL;

    while (CPUMinerShouldRun())
    {
        if (fShutdown)
            return;

        if (pblock) { delete pblock; pblock = NULL; }

        {
            bool fNoNodes;
            {
                LOCK(cs_vNodes);
                fNoNodes = vNodes.empty();
            }
            // Regtest may mine an isolated branch at any height, testnet only at low
            // height; mainnet never bypasses the peer/IBD guard.
            bool fSkipBootstrap = fRegTest || (fTestNet && nBestHeight <= 10);
            if (!fSkipBootstrap && (fNoNodes || IsInitialBlockDownload()))
            {
                MilliSleep(1000);
                continue;
            }
        }

        bool fChainStale = false;
        {
            LOCK(cs_main);
            fChainStale = !fRegTest && !fTestNet && pindexBest && pindexBest->nHeight > 10 &&
                          pindexBest->GetBlockTime() < GetTime() - 300;
        }
        if (fChainStale)
        {
            MilliSleep(5000);
            continue;
        }

        int nHeight;
        uint256 hashTarget;

        CBlock* ptmp = CreateNewBlock(pwallet);
        if (!ptmp)
        {
            printf("CPUMiner: CreateNewBlock failed, retrying...\n");
            MilliSleep(5000);
            continue;
        }
        if (pblock)
            delete pblock;
        pblock = new CBlock(*ptmp);
        delete ptmp;

        {
            LOCK(cs_main);
            std::map<uint256, CBlockIndex*>::iterator miPrev = mapBlockIndex.find(pblock->hashPrevBlock);
            if (miPrev == mapBlockIndex.end() || !miPrev->second)
            {
                std::string strParent = pblock->hashPrevBlock.ToString().substr(0, 20);
                delete pblock;
                pblock = NULL;
                printf("CPUMiner: previous block index missing for template parent %s, retrying...\n",
                       strParent.c_str());
                MilliSleep(1000);
                continue;
            }
            CBlockIndex* pindexBlockPrev = miPrev->second;

            IncrementExtraNonce(pblock, pindexBlockPrev, nExtraNonce);
            nHeight = pindexBlockPrev->nHeight + 1;
            if (!CoinbaseStartsWithHeight(pblock, nHeight))
            {
                printf("CPUMiner: coinbase height prefix mismatch before hashing at height %d, retrying...\n",
                       nHeight);
                delete pblock;
                pblock = NULL;
                MilliSleep(100);
                continue;
            }

            CBigNum bnTarget;
            bnTarget.SetCompact(pblock->nBits);
            hashTarget = bnTarget.getuint256();
        }

        printf("CPUMiner: Mining block at height %d, target bits=0x%08x\n",
               nHeight, pblock->nBits);

        int64_t nStart = GetTime();
        uint64_t nHashesDone = 0;
        bool fBlockFound = false;

        while (!fShutdown)
        {
            if ((nHashesDone % 4096) == 0 && !CPUMinerShouldRun())
                break;

            uint256 hash = pblock->GetPoWHash();
            if (hash <= hashTarget)
            {
                fBlockFound = true;
                break;
            }

            nHashesDone++;
            ++pblock->nNonce;

            if (pblock->nNonce == 0)
                ++pblock->nTime;

            if ((nHashesDone % 500000) == 0)
            {
                int64_t nElapsed = GetTime() - nStart;
                if (nElapsed > 0)
                    printf("CPUMiner: %.0f H/s (height %d, %llu hashes)\n",
                           (double)nHashesDone / nElapsed, nHeight, (unsigned long long)nHashesDone);
            }

            if ((nHashesDone % 100000) == 0)
            {
                bool fStale = false;
                {
                    LOCK(cs_main);
                    fStale = (mapBlockIndex.count(pblock->hashPrevBlock) == 0);
                }
                if (fStale)
                    break;
            }
        }

        if (fBlockFound)
        {
            printf("CPUMiner: Found block! height=%d nonce=%u\n",
                   nHeight, pblock->nNonce);

            bool fAcceptedAsBest = false;
            {
                LOCK(cs_main);
                std::map<uint256, CBlockIndex*>::iterator miPrev = mapBlockIndex.find(pblock->hashPrevBlock);
                if (miPrev == mapBlockIndex.end() || !miPrev->second)
                {
                    printf("CPUMiner: Skipping found block at height %d because parent is missing\n", nHeight);
                }
                else
                {
                    int nSubmitHeight = miPrev->second->nHeight + 1;
                    if (!CoinbaseStartsWithHeight(pblock, nSubmitHeight))
                    {
                        printf("CPUMiner: refusing found block with coinbase height mismatch at height %d\n",
                               nSubmitHeight);
                        continue;
                    }
                    unique_ptr<CBlock> psubmit(new CBlock(*pblock));
                    uint256 hashSubmit = psubmit->GetHash();
                    if (!ProcessBlock(NULL, psubmit.get()))
                    {
                        printf("CPUMiner: ProcessBlock failed\n");
                    }
                    else if (hashBestChain == hashSubmit)
                    {
                        fAcceptedAsBest = true;
                        printf("CPUMiner: Block accepted at height %d\n", pindexBest->nHeight);
                    }
                    else
                    {
                        printf("CPUMiner: Block accepted but did not become best tip\n");
                    }
                }
            }

            if (fAcceptedAsBest)
            {
                CPUMinerConsumeAcceptedBlock();
            }
            else
            {
                if (!CPUMinerShouldRun())
                    break;
            }

            MilliSleep(500);
        }

        MilliSleep(100);
    }

    if (pblock) delete pblock;

    printf("CPUMiner stopped\n");
}

void ThreadCPUMiner(void* parg)
{
    printf("ThreadCPUMiner started\n");
    CWallet* pwallet = (CWallet*)parg;
    try
    {
        vnThreadsRunning[THREAD_STAKE_MINER]++;  // Reuse stake miner slot for counting
        CPUMiner(pwallet);
        vnThreadsRunning[THREAD_STAKE_MINER]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[THREAD_STAKE_MINER]--;
        PrintException(&e, "ThreadCPUMiner()");
    } catch (...) {
        vnThreadsRunning[THREAD_STAKE_MINER]--;
        PrintException(NULL, "ThreadCPUMiner()");
    }
    printf("ThreadCPUMiner exiting\n");
}
