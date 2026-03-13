// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "finality.h"
#include "main.h"
#include "init.h"
#include "wallet.h"
#include "net.h"
#include "util.h"

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

    if (mapEpochVotes.count(vote.nEpoch) &&
        (int)mapEpochVotes[vote.nEpoch].size() >= FINALITY_MAX_VOTES)
        return false;

    setVoteNullifiers.insert(vote.nullifier);
    mapEpochVotes[vote.nEpoch].push_back(vote);

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

    int64_t nVoteWeight = mapEpochVoteWeight[nEpoch];

    int64_t nSupply = 0;
    {
        CBlockIndex* pBest = pindexBest;
        if (pBest)
            nSupply = pBest->nMoneySupply;
    }

    if (nSupply <= 0)
        return false;

    // nVoteWeight * 3 >= nSupply * 2 (overflow-safe: both <= MAX_MONEY, *3 fits int64_t)
    if (nVoteWeight * FINALITY_THRESHOLD_DEN >= nSupply * FINALITY_THRESHOLD_NUM)
    {
        if (!mapEpochVotes.count(nEpoch) || mapEpochVotes[nEpoch].empty())
            return false;

        int nFinalHeight = mapEpochVotes[nEpoch][0].nHeight;
        uint256 hashFinal = mapEpochVotes[nEpoch][0].hashBlock;

        if (nFinalHeight > nLastFinalizedHeight)
        {
            nLastFinalizedHeight = nFinalHeight;
            hashLastFinalized = hashFinal;
            printf("FINALITY: Epoch %d finalized at height %d (hash=%s, weight=%s/%s)\n",
                   nEpoch, nFinalHeight,
                   hashFinal.ToString().substr(0, 20).c_str(),
                   FormatMoney(nVoteWeight).c_str(),
                   FormatMoney(nSupply).c_str());
        }
        return true;
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

        if (!vote.IsValid())
        {
            printf("ProcessMessageFinality: invalid vote from peer %s\n",
                   pfrom->addr.ToString().c_str());
            return false;
        }

        if (vote.IsExpired(GetAdjustedTime()))
            return false;

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

        int nCurrentEpoch = nCurrentHeight / FINALITY_EPOCH_INTERVAL;
        int nEpochProgress = nCurrentHeight % FINALITY_EPOCH_INTERVAL;

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
    int nCurrentEpoch = nCurrentHeight / FINALITY_EPOCH_INTERVAL;

    int nEpochHeight = nCurrentEpoch * FINALITY_EPOCH_INTERVAL;
    CBlockIndex* pEpochBlock = FindBlockByHeight(nEpochHeight);
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
