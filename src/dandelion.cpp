// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "dandelion.h"
#include "hash.h"
#include "util.h"

#include <openssl/rand.h>
#include <algorithm>

CDandelionRouter dandelionRouter;
CDandelionState dandelionState;


void CDandelionRouter::UpdateEpoch(int64_t nNow, const std::vector<int>& vPeerIds)
{
    LOCK(cs_router);

    if (nEpochStartTime > 0 && (nNow - nEpochStartTime) < DANDELION_EPOCH_DURATION)
        return;

    nCurrentEpoch++;
    nEpochStartTime = nNow;
    vStemPeers.clear();

    if (vPeerIds.empty())
        return;

    std::vector<int> candidates = vPeerIds;

    for (int i = (int)candidates.size() - 1; i > 0; i--)
    {
        unsigned int rnd;
        if (RAND_bytes((unsigned char*)&rnd, sizeof(rnd)) != 1)
            return;
        int j = rnd % (i + 1);
        std::swap(candidates[i], candidates[j]);
    }

    int nToSelect = std::min(DANDELION_STEM_PEERS, (int)candidates.size());
    for (int i = 0; i < nToSelect; i++)
        vStemPeers.push_back(candidates[i]);
}

int CDandelionRouter::GetStemPeer(const uint256& txHash) const
{
    LOCK(cs_router);
    if (vStemPeers.empty())
        return -1;

    // PRIV-AUDIT-9: Use CSPRNG instead of deterministic per-txhash selection
    // to prevent an observer from correlating transactions to the same stem peer
    unsigned int idx = GetRand((uint32_t)vStemPeers.size());
    return vStemPeers[idx];
}

bool CDandelionRouter::IsStemPeer(int nPeerId) const
{
    LOCK(cs_router);
    for (size_t i = 0; i < vStemPeers.size(); i++)
    {
        if (vStemPeers[i] == nPeerId)
            return true;
    }
    return false;
}

bool CDandelionRouter::ShouldFluff(const CDandelionTxState& state) const
{
    LOCK(cs_router);

    if (state.nStemHops >= DANDELION_MAX_STEM_HOPS)
        return true;

    unsigned int rnd;
    if (RAND_bytes((unsigned char*)&rnd, sizeof(rnd)) != 1)
        return true;
    double prob = (double)(rnd % 10000) / 10000.0;
    return prob < DANDELION_FLUFF_PROBABILITY;
}

void CDandelionRouter::OnStemPeerDisconnect(int nPeerId)
{
    LOCK(cs_router);

    for (auto it = vStemPeers.begin(); it != vStemPeers.end(); )
    {
        if (*it == nPeerId)
            it = vStemPeers.erase(it);
        else
            ++it;
    }

}


bool CDandelionState::AddTransaction(const uint256& txHash, bool fShielded, bool fFromStemPeer)
{
    LOCK(cs_state);
    if (!fEnabled)
        return false;

    if (mapTxState.count(txHash))
        return mapTxState[txHash].phase == DANDELION_STEM;

    if (mapTxState.size() >= 10000)
        return false;

    CDandelionTxState state;
    state.txHash = txHash;
    state.phase = DANDELION_STEM;
    state.nStemStartTime = GetTime();
    state.nLastRelayTime = GetTime();
    state.nStemHops = 0;
    state.fFromStemPeer = fFromStemPeer;
    state.fShielded = fShielded;

    mapTxState[txHash] = state;
    return true;
}

EDandelionPhase CDandelionState::GetPhase(const uint256& txHash) const
{
    LOCK(cs_state);
    auto it = mapTxState.find(txHash);
    if (it != mapTxState.end())
        return it->second.phase;

    return DANDELION_FLUFF;
}

bool CDandelionState::GetTxState(const uint256& txHash, CDandelionTxState& stateOut) const
{
    LOCK(cs_state);
    auto it = mapTxState.find(txHash);
    if (it != mapTxState.end())
    {
        stateOut = it->second;
        return true;
    }
    return false;
}

void CDandelionState::TransitionToFluff(const uint256& txHash)
{
    LOCK(cs_state);
    auto it = mapTxState.find(txHash);
    if (it != mapTxState.end())
        it->second.phase = DANDELION_FLUFF;
}

void CDandelionState::RemoveTransaction(const uint256& txHash)
{
    LOCK(cs_state);
    mapTxState.erase(txHash);
}

std::vector<uint256> CDandelionState::CheckStemTimeouts(int64_t nNow)
{
    LOCK(cs_state);
    std::vector<uint256> vFluff;

    static const int64_t DANDELION_CLEANUP_AGE = 3600;
    std::vector<uint256> vStale;
    for (auto& pair : mapTxState)
    {
        if (pair.second.phase == DANDELION_STEM &&
            pair.second.IsStemTimedOut(nNow))
        {
            pair.second.phase = DANDELION_FLUFF;
            vFluff.push_back(pair.first);

            if (fDebug)
                printf("Dandelion: stem timeout for %s, transitioning to fluff\n",
                       pair.first.ToString().substr(0,10).c_str());
        }
        else if (pair.second.phase == DANDELION_FLUFF &&
                 (nNow - pair.second.nStemStartTime) > DANDELION_CLEANUP_AGE)
        {
            vStale.push_back(pair.first);
        }
    }

    for (const uint256& hash : vStale)
        mapTxState.erase(hash);

    return vFluff;
}

int CDandelionState::GetStemCount() const
{
    LOCK(cs_state);
    int nCount = 0;
    for (auto& pair : mapTxState)
    {
        if (pair.second.phase == DANDELION_STEM)
            nCount++;
    }
    return nCount;
}
