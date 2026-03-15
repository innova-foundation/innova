// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "finality.h"
#include "main.h"
#include "init.h"
#include "wallet.h"
#include "net.h"
#include "util.h"
#include "dag.h"
#include "txdb.h"
#include "base58.h"

#include <openssl/sha.h>

CFinalityTracker g_finalityTracker;


// ---------------------------------------------------------------------------
// POEM Entropy
// ---------------------------------------------------------------------------

uint256 GetBlockEntropy(const uint256& hashValue)
{
    uint256 comp = ~hashValue;
    if (comp == 0)
        return 0;

    CBigNum bnComp(comp);
    unsigned int nBitSize = bnComp.bitSize();

    uint256 result = 0;
    result = (uint64_t)nBitSize << 32;

    if (nBitSize > 33)
    {
        uint256 shifted = comp >> (nBitSize - 33);
        uint32_t nFracBits = (uint32_t)(shifted.Get64(0) & 0xFFFFFFFF);
        result += nFracBits;
    }

    return result;
}


// ---------------------------------------------------------------------------
// CFinalityVote
// ---------------------------------------------------------------------------

uint256 CFinalityVote::GetHash() const
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << nEpoch;
    ss << hashBlock;
    ss << nHeight;
    ss << nTime;
    ss << nVoteWeight;
    ss << nullifier;
    ss << vchPubKey;
    return ss.GetHash();
}

uint256 CFinalityVote::GetSignatureHash() const
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("Innova/FinalityVote/v1");
    ss << nEpoch;
    ss << hashBlock;
    ss << nHeight;
    ss << nTime;
    ss << nVoteWeight;
    ss << nullifier;
    return ss.GetHash();
}

bool CFinalityVote::Sign(CKey& key)
{
    uint256 hash = GetSignatureHash();

    CPubKey pubkey = key.GetPubKey();
    vchPubKey = std::vector<unsigned char>(pubkey.begin(), pubkey.end());

    if (!key.Sign(hash, vchSig))
        return false;

    return true;
}

bool CFinalityVote::CheckSignature() const
{
    if (vchPubKey.empty() || vchSig.empty())
        return false;

    CPubKey pubkey(vchPubKey);
    if (!pubkey.IsValid())
        return false;

    uint256 hash = GetSignatureHash();
    if (!pubkey.Verify(hash, vchSig))
        return false;

    return true;
}

bool CFinalityVote::IsValid() const
{
    if (nEpoch < 0)
        return false;
    if (nHeight < 0)
        return false;
    if (nVoteWeight <= 0)
        return false;
    if (hashBlock == 0)
        return false;
    if (nullifier == 0)
        return false;
    if (vchPubKey.empty())
        return false;
    if (!CheckSignature())
        return false;
    return true;
}

bool CFinalityVote::IsExpired(int64_t nNow) const
{
    return (nNow - nTime) > FINALITY_VOTE_MAX_AGE;
}


// ---------------------------------------------------------------------------
// CFinalityTracker
// ---------------------------------------------------------------------------

bool CFinalityTracker::AddVote(const CFinalityVote& vote)
{
    LOCK(cs_finality);

    if (setVoteNullifiers.count(vote.nullifier))
        return false;

    // Verify nullifier matches H(pubkey || epoch) — prevents same key voting multiple times
    {
        CHashWriter expectedNullifier(SER_GETHASH, 0);
        expectedNullifier << vote.vchPubKey;
        expectedNullifier << vote.nEpoch;
        if (vote.nullifier != expectedNullifier.GetHash())
            return false;
    }

    // Reject duplicate keyIDs within an epoch (prevents spend-then-re-vote under new key)
    {
        CPubKey checkPubKey(vote.vchPubKey);
        if (checkPubKey.IsValid())
        {
            CKeyID voterKeyID = checkPubKey.GetID();
            if (mapEpochVoters.count(vote.nEpoch) && mapEpochVoters[vote.nEpoch].count(voterKeyID))
                return false;
        }
    }

    // Reject votes for epochs far beyond current chain tip (DoS protection)
    {
        int nCurrentEpoch = 0;
        CBlockIndex* pBest = pindexBest;
        if (pBest)
            nCurrentEpoch = GetEpochForHeight(pBest->nHeight);
        if (vote.nEpoch > nCurrentEpoch + 2)
            return false;
    }

    // Validate vote weight: verify pubkey controls UTXOs worth at least nVoteWeight
    {
        CPubKey votePubKey(vote.vchPubKey);
        if (!votePubKey.IsValid())
            return false;

        if (vote.nVoteWeight > MAX_MONEY)
            return false;

        CKeyID keyID = votePubKey.GetID();
        int64_t nVerifiedBalance = 0;
        bool fHasAddrIndex = false;

        // Verify on-chain balance via address index + tx index
        {
            CTxDB txdb("r");
            std::vector<uint256> vTxHashes;
            if (txdb.ReadAddrIndex(keyID, vTxHashes))
            {
                fHasAddrIndex = true;
                for (const uint256& txHash : vTxHashes)
                {
                    CTransaction tx;
                    CTxIndex txindex;
                    if (!txdb.ReadDiskTx(txHash, tx, txindex))
                        continue;

                    for (unsigned int i = 0; i < tx.vout.size(); i++)
                    {
                        // Check if output pays to this key
                        CTxDestination dest;
                        if (!ExtractDestination(tx.vout[i].scriptPubKey, dest))
                            continue;
                        CKeyID outKeyID;
                        if (!CBitcoinAddress(dest).GetKeyID(outKeyID))
                            continue;
                        if (outKeyID != keyID)
                            continue;

                        // Check if output is unspent
                        if (i < txindex.vSpent.size() && !txindex.vSpent[i].IsNull())
                            continue; // spent

                        int64_t nValue = tx.vout[i].nValue;
                        if (nValue > 0 && nVerifiedBalance <= MAX_MONEY - nValue)
                            nVerifiedBalance += nValue;
                    }

                    // Early exit if we've verified enough
                    if (nVerifiedBalance >= vote.nVoteWeight)
                        break;
                }
            }
        }

        // Reject if claimed weight exceeds verified on-chain balance
        if (fHasAddrIndex && vote.nVoteWeight > nVerifiedBalance)
        {
            if (fDebug)
                printf("AddVote: rejected vote with weight %s > verified balance %s\n",
                       FormatMoney(vote.nVoteWeight).c_str(),
                       FormatMoney(nVerifiedBalance).c_str());
            return false;
        }

        // If address index unavailable, reject ALL votes — cannot verify weight
        // Nodes without -reindexaddr cannot participate in finality voting
        if (!fHasAddrIndex)
        {
            if (fDebug)
                printf("AddVote: rejected (no address index, cannot verify weight)\n");
            return false;
        }
    }

    if (mapEpochVotes.count(vote.nEpoch) &&
        (int)mapEpochVotes[vote.nEpoch].size() >= FINALITY_MAX_VOTES)
        return false;

    setVoteNullifiers.insert(vote.nullifier);
    mapEpochVotes[vote.nEpoch].push_back(vote);

    // Track voter keyID to prevent same key voting under different nullifiers
    {
        CPubKey regPubKey(vote.vchPubKey);
        if (regPubKey.IsValid())
            mapEpochVoters[vote.nEpoch].insert(regPubKey.GetID());
    }

    int64_t nPrevWeight = mapEpochVoteWeight.count(vote.nEpoch)
                              ? mapEpochVoteWeight[vote.nEpoch]
                              : 0;
    if (vote.nVoteWeight > 0 && nPrevWeight <= MAX_MONEY - vote.nVoteWeight)
        mapEpochVoteWeight[vote.nEpoch] = nPrevWeight + vote.nVoteWeight;
    else
        mapEpochVoteWeight[vote.nEpoch] = MAX_MONEY;

    CheckFinalityThreshold(vote.nEpoch);

    return true;
}

bool CFinalityTracker::IsFinalized(int nHeight) const
{
    LOCK(cs_finality);
    return nHeight <= nLastFinalizedHeight;
}

bool CFinalityTracker::CheckFinalityThreshold(int nEpoch)
{
    if (!mapEpochVoteWeight.count(nEpoch))
        return false;

    int64_t nEpochVoteWeight = mapEpochVoteWeight[nEpoch];

    // Participation-relative finality: threshold is based on THIS EPOCH's
    // total vote weight, not total money supply. This ensures finality works
    // even with low staking participation.

    // Check minimum absolute stake floor (configurable via -minfinalitystake)
    int64_t nMinStakeCoins = GetArg("-minfinalitystake", FINALITY_MIN_STAKE_DEFAULT / COIN);
    if (nMinStakeCoins < 0) nMinStakeCoins = 0;
    if (nMinStakeCoins > MAX_MONEY / COIN) nMinStakeCoins = MAX_MONEY / COIN;
    int64_t nMinStake = nMinStakeCoins * COIN;
    if (nEpochVoteWeight < nMinStake)
    {
        nLastFinalityTier = FINALITY_NONE;
        return false; // not enough total stake for finality to be meaningful
    }

    // Check minimum unique voter count
    int nVoterCount = mapEpochVoters.count(nEpoch) ? (int)mapEpochVoters[nEpoch].size() : 0;
    if (nVoterCount < FINALITY_MIN_VOTERS)
    {
        nLastFinalityTier = FINALITY_NONE;
        return false; // need at least 2 unique voters
    }

    if (!mapEpochVotes.count(nEpoch) || mapEpochVotes[nEpoch].empty())
        return false;

    // Select block with highest cumulative vote weight (deterministic tiebreaker by hash)
    std::map<uint256, int64_t> mapBlockVoteWeight;
    std::map<uint256, int> mapBlockHeight;
    for (const CFinalityVote& v : mapEpochVotes[nEpoch])
    {
        if (v.nVoteWeight > 0 && mapBlockVoteWeight[v.hashBlock] <= MAX_MONEY - v.nVoteWeight)
            mapBlockVoteWeight[v.hashBlock] += v.nVoteWeight;
        mapBlockHeight[v.hashBlock] = v.nHeight;
    }

    uint256 hashFinal = 0;
    int64_t nBestBlockWeight = 0;
    for (const auto& p : mapBlockVoteWeight)
    {
        if (p.second > nBestBlockWeight ||
            (p.second == nBestBlockWeight && (hashFinal == 0 || p.first < hashFinal)))
        {
            nBestBlockWeight = p.second;
            hashFinal = p.first;
        }
    }

    if (hashFinal == 0)
        return false;

    // Determine finality tier based on the winning block's weight vs total epoch weight
    // Thresholds are relative to nEpochVoteWeight (participation-relative)
    FinalityTier tier = FINALITY_NONE;
    if (nBestBlockWeight * 3 >= nEpochVoteWeight * 2)      // >= 2/3
        tier = FINALITY_HARD;
    else if (nBestBlockWeight * 2 >= nEpochVoteWeight)       // >= 1/2
        tier = FINALITY_SOFT;
    else if (nBestBlockWeight * 3 >= nEpochVoteWeight)       // >= 1/3
        tier = FINALITY_TENTATIVE;

    nLastFinalityTier = tier;

    int nFinalHeight = mapBlockHeight.count(hashFinal) ? mapBlockHeight[hashFinal] : 0;

    if (tier >= FINALITY_HARD)
    {
        // Track consecutive HARD epochs for confirmation delay
        // This prevents chain splits from P2P vote propagation differences:
        // finality only becomes binding after N consecutive HARD epochs agree
        nConsecutiveHardEpochs++;

        if (nFinalHeight > nPendingFinalizedHeight)
        {
            nPendingFinalizedHeight = nFinalHeight;
            hashPendingFinalized = hashFinal;
        }

        if (nConsecutiveHardEpochs >= FINALITY_CONFIRMATION_EPOCHS &&
            nPendingFinalizedHeight > nLastFinalizedHeight)
        {
            nLastFinalizedHeight = nPendingFinalizedHeight;
            hashLastFinalized = hashPendingFinalized;
            printf("FINALITY: CONFIRMED at height %d after %d consecutive HARD epochs (hash=%s, voters=%d)\n",
                   nLastFinalizedHeight, nConsecutiveHardEpochs,
                   hashLastFinalized.ToString().substr(0, 20).c_str(),
                   nVoterCount);
        }
        else
        {
            printf("FINALITY: Epoch %d HARD (%d/%d confirmations) at height %d (block_weight=%s, epoch_weight=%s, voters=%d)\n",
                   nEpoch, nConsecutiveHardEpochs, FINALITY_CONFIRMATION_EPOCHS,
                   nFinalHeight,
                   FormatMoney(nBestBlockWeight).c_str(),
                   FormatMoney(nEpochVoteWeight).c_str(),
                   nVoterCount);
        }
        return nConsecutiveHardEpochs >= FINALITY_CONFIRMATION_EPOCHS;
    }
    else
    {
        // Non-HARD epoch breaks the consecutive streak
        nConsecutiveHardEpochs = 0;

        if (tier >= FINALITY_SOFT)
        {
            printf("FINALITY: Epoch %d SOFT at height %d (block_weight=%s, epoch_weight=%s, voters=%d)\n",
                   nEpoch, nFinalHeight,
                   FormatMoney(nBestBlockWeight).c_str(),
                   FormatMoney(nEpochVoteWeight).c_str(),
                   nVoterCount);
        }
        else if (tier >= FINALITY_TENTATIVE && fDebug)
        {
            printf("FINALITY: Epoch %d tentative at height %d (voters=%d)\n",
                   nEpoch, nFinalHeight, nVoterCount);
        }
    }

    return false;
}

std::vector<CFinalityVote> CFinalityTracker::GetEpochVotes(int nEpoch) const
{
    LOCK(cs_finality);
    auto it = mapEpochVotes.find(nEpoch);
    if (it != mapEpochVotes.end())
        return it->second;
    return std::vector<CFinalityVote>();
}

int64_t CFinalityTracker::GetEpochVoteWeight(int nEpoch) const
{
    LOCK(cs_finality);
    auto it = mapEpochVoteWeight.find(nEpoch);
    if (it != mapEpochVoteWeight.end())
        return it->second;
    return 0;
}

int CFinalityTracker::GetEpochVoteCount(int nEpoch) const
{
    LOCK(cs_finality);
    auto it = mapEpochVotes.find(nEpoch);
    if (it != mapEpochVotes.end())
        return (int)it->second.size();
    return 0;
}

int CFinalityTracker::GetEpochVoterCount(int nEpoch) const
{
    LOCK(cs_finality);
    auto it = mapEpochVoters.find(nEpoch);
    if (it != mapEpochVoters.end())
        return (int)it->second.size();
    return 0;
}

void CFinalityTracker::PruneOldEpochs(int nCurrentEpoch)
{
    LOCK(cs_finality);
    int nMinEpoch = nCurrentEpoch - 10;
    if (nMinEpoch < 0)
        nMinEpoch = 0;

    for (auto it = mapEpochVotes.begin(); it != mapEpochVotes.end(); )
    {
        if (it->first < nMinEpoch)
        {
            for (const CFinalityVote& vote : it->second)
                setVoteNullifiers.erase(vote.nullifier);
            mapEpochVoteWeight.erase(it->first);
            mapEpochVoters.erase(it->first);
            it = mapEpochVotes.erase(it);
        }
        else
        {
            ++it;
        }
    }
}


// ---------------------------------------------------------------------------
// P2P Message Processing
// ---------------------------------------------------------------------------

bool ProcessMessageFinality(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv)
{
    if (strCommand == "fvote")
    {
        CFinalityVote vote;
        vRecv >> vote;

        // Cheap checks first (before expensive ECDSA signature verification)
        if (vote.nEpoch < 0 || vote.nHeight < 0 || vote.nVoteWeight <= 0)
            return false;
        if (vote.hashBlock == 0 || vote.nullifier == 0 || vote.vchPubKey.empty())
            return false;
        // Reject future-timestamped votes (prevents permanent nullifier squatting)
        if (vote.nTime > GetAdjustedTime() + 300)
            return false;
        if (vote.IsExpired(GetAdjustedTime()))
            return false;

        // Epoch range check (cheap — avoids ECDSA on far-future votes)
        {
            int nCurrentEpoch = 0;
            CBlockIndex* pBest = pindexBest;
            if (pBest)
                nCurrentEpoch = GetEpochForHeight(pBest->nHeight);
            if (vote.nEpoch > nCurrentEpoch + 2)
                return false;
        }

        // Now do expensive ECDSA signature verification
        if (!vote.IsValid())
        {
            printf("ProcessMessageFinality: invalid vote from peer %s\n",
                   pfrom->addr.ToString().c_str());
            return false;
        }

        if (g_finalityTracker.AddVote(vote))
        {
            LOCK(cs_vNodes);
            for (CNode* pnode : vNodes)
            {
                if (pnode == pfrom)
                    continue;
                pnode->PushMessage("fvote", vote);
            }
        }

        return true;
    }
    else if (strCommand == "fvreq")
    {
        int nEpoch;
        vRecv >> nEpoch;

        // Validate epoch range (prevent amplification from arbitrary epoch requests)
        int nCurrentEpoch = 0;
        {
            CBlockIndex* pBest = pindexBest;
            if (pBest)
                nCurrentEpoch = GetEpochForHeight(pBest->nHeight);
        }
        if (nEpoch < 0 || nEpoch > nCurrentEpoch + 1)
            return false;

        // Rate limit: max 1 fvreq per 5 seconds per peer
        static std::map<CAddress, int64_t> mapLastFvreq;
        int64_t nNow = GetTimeMillis();
        if (mapLastFvreq.count(pfrom->addr) && nNow - mapLastFvreq[pfrom->addr] < 5000)
            return false;
        mapLastFvreq[pfrom->addr] = nNow;

        // Bound map size to prevent memory growth from many peers
        if (mapLastFvreq.size() > 1000)
            mapLastFvreq.clear();

        std::vector<CFinalityVote> votes = g_finalityTracker.GetEpochVotes(nEpoch);
        for (const CFinalityVote& vote : votes)
        {
            pfrom->PushMessage("fvote", vote);
        }

        return true;
    }

    return false;
}


// ---------------------------------------------------------------------------
// Finality Voter Thread
// ---------------------------------------------------------------------------

void ThreadFinalityVoter(void* parg)
{
    printf("ThreadFinalityVoter started\n");

    if (GetBoolArg("-nofinalityvoting", false))
    {
        printf("ThreadFinalityVoter: voting disabled\n");
        return;
    }

    int nLastEpochVoted = -1;

    while (!fShutdown)
    {
        MilliSleep(5000);

        if (fShutdown)
            break;

        if (IsInitialBlockDownload())
            continue;

        int nCurrentHeight = 0;
        {
            LOCK(cs_main);
            if (!pindexBest)
                continue;
            nCurrentHeight = pindexBest->nHeight;
        }

        if (nCurrentHeight < FORK_HEIGHT_FINALITY)
            continue;

        int nCurrentEpoch = GetEpochForHeight(nCurrentHeight);
        int nEpochProgress = nCurrentHeight % GetEpochInterval(nCurrentHeight);

        if (nEpochProgress >= FINALITY_VOTE_WINDOW)
            continue;

        if (nCurrentEpoch == nLastEpochVoted)
            continue;

        if (ProduceFinalityVote())
        {
            nLastEpochVoted = nCurrentEpoch;
            g_finalityTracker.PruneOldEpochs(nCurrentEpoch);
        }
    }

    printf("ThreadFinalityVoter stopped\n");
}


bool ProduceFinalityVote()
{
    if (!pwalletMain)
        return false;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (!pindexBest)
        return false;

    int nCurrentHeight = pindexBest->nHeight;
    int nCurrentEpoch = GetEpochForHeight(nCurrentHeight);

    // IDAG Phase 2: If DAG is active, vote for DAG-selected best tip
    int nEpochHeight = GetEpochBoundaryHeight(nCurrentEpoch, nCurrentHeight);
    CBlockIndex* pEpochBlock = NULL;
    if (nCurrentHeight >= FORK_HEIGHT_DAG)
    {
        CBlockIndex* pDAGTip = g_dagManager.SelectBestDAGTip();
        if (pDAGTip)
        {
            // Walk back to epoch boundary from DAG tip
            CBlockIndex* pWalk = pDAGTip;
            while (pWalk && pWalk->nHeight > nEpochHeight)
                pWalk = pWalk->pprev;
            if (pWalk && pWalk->nHeight == nEpochHeight)
                pEpochBlock = pWalk;
        }
    }
    if (!pEpochBlock)
        pEpochBlock = FindBlockByHeight(nEpochHeight);
    if (!pEpochBlock)
        return false;

    int64_t nTotalWeight = 0;
    CKey votingKey;
    bool fFoundKey = false;

    std::vector<COutput> vCoins;
    pwalletMain->AvailableCoins(vCoins);

    for (const COutput& out : vCoins)
    {
        const CWalletTx* wtx = out.tx;
        unsigned int nOut = out.i;

        if (nOut >= wtx->vout.size())
            continue;

        int64_t nValue = wtx->vout[nOut].nValue;
        if (nValue <= 0 || nValue > MAX_MONEY)
            continue;

        if (nTotalWeight > MAX_MONEY - nValue)
        {
            nTotalWeight = MAX_MONEY;
            break;
        }
        nTotalWeight += nValue;

        if (!fFoundKey)
        {
            CTxDestination dest;
            if (ExtractDestination(wtx->vout[nOut].scriptPubKey, dest))
            {
                CKeyID keyID;
                if (CBitcoinAddress(dest).GetKeyID(keyID))
                {
                    if (pwalletMain->GetKey(keyID, votingKey))
                        fFoundKey = true;
                }
            }
        }
    }

    if (!fFoundKey || nTotalWeight <= 0)
        return false;

    CHashWriter nullifierHash(SER_GETHASH, 0);
    CPubKey pubkey = votingKey.GetPubKey();
    nullifierHash << std::vector<unsigned char>(pubkey.begin(), pubkey.end());
    nullifierHash << nCurrentEpoch;
    uint256 nullifier = nullifierHash.GetHash();

    CFinalityVote vote;
    vote.nEpoch = nCurrentEpoch;
    vote.hashBlock = pEpochBlock->GetBlockHash();
    vote.nHeight = nEpochHeight;
    vote.nTime = GetAdjustedTime();
    vote.nVoteWeight = nTotalWeight;
    vote.nullifier = nullifier;

    if (!vote.Sign(votingKey))
        return false;

    if (!g_finalityTracker.AddVote(vote))
        return false;

    printf("ProduceFinalityVote: epoch=%d height=%d weight=%s\n",
           nCurrentEpoch, nEpochHeight, FormatMoney(nTotalWeight).c_str());

    {
        LOCK(cs_vNodes);
        for (CNode* pnode : vNodes)
        {
            pnode->PushMessage("fvote", vote);
        }
    }

    return true;
}
