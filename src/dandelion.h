// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_DANDELION_H
#define INN_DANDELION_H

#include "uint256.h"
#include "serialize.h"
#include "sync.h"

#include <openssl/rand.h>

#include <vector>
#include <map>
#include <set>
#include <stdint.h>

static const int DANDELION_STEM_TIMEOUT_BASE = 30;
static const int DANDELION_STEM_TIMEOUT_JITTER = 15;
static const int DANDELION_EPOCH_DURATION = 600;
static const int DANDELION_STEM_PEERS = 2;
static const double DANDELION_FLUFF_PROBABILITY = 0.1;
static const int DANDELION_MAX_STEM_HOPS = 10;

enum EDandelionPhase
{
    DANDELION_STEM  = 0,
    DANDELION_FLUFF = 1
};

class CDandelionTxState
{
public:
    uint256 txHash;
    EDandelionPhase phase;
    int64_t nStemStartTime;
    int64_t nLastRelayTime;
    int nStemHops;
    bool fFromStemPeer;
    bool fShielded;
    int nStemTimeout;

    CDandelionTxState()
    {
        phase = DANDELION_STEM;
        nStemStartTime = 0;
        nLastRelayTime = 0;
        nStemHops = 0;
        fFromStemPeer = false;
        fShielded = false;
        unsigned char rndByte[1];
        if (RAND_bytes(rndByte, 1) != 1)
            rndByte[0] = 0;
        nStemTimeout = DANDELION_STEM_TIMEOUT_BASE +
                       (rndByte[0] % (2 * DANDELION_STEM_TIMEOUT_JITTER + 1)) -
                       DANDELION_STEM_TIMEOUT_JITTER;
    }

    bool IsStemTimedOut(int64_t nNow) const
    {
        return (nNow - nStemStartTime) >= nStemTimeout;
    }
};


class CDandelionRouter
{
public:
    void UpdateEpoch(int64_t nNow, const std::vector<int>& vPeerIds);

    int GetStemPeer(const uint256& txHash) const;

    bool IsStemPeer(int nPeerId) const;

    bool ShouldFluff(const CDandelionTxState& state) const;

    void OnStemPeerDisconnect(int nPeerId);

    int64_t GetCurrentEpoch() const { return nCurrentEpoch; }

    CDandelionRouter()
    {
        nCurrentEpoch = 0;
        nEpochStartTime = 0;
    }

    mutable CCriticalSection cs_router;

private:
    int64_t nCurrentEpoch;
    int64_t nEpochStartTime;
    std::vector<int> vStemPeers;
};


class CDandelionState
{
public:
    bool AddTransaction(const uint256& txHash, bool fShielded, bool fFromStemPeer);

    EDandelionPhase GetPhase(const uint256& txHash) const;

    bool GetTxState(const uint256& txHash, CDandelionTxState& stateOut) const;

    void TransitionToFluff(const uint256& txHash);

    void RemoveTransaction(const uint256& txHash);

    std::vector<uint256> CheckStemTimeouts(int64_t nNow);

    bool IsEnabled() const { LOCK(cs_state); return fEnabled; }
    void SetEnabled(bool fEnable) { LOCK(cs_state); fEnabled = fEnable; }

    int GetStemCount() const;

    CDandelionState()
    {
        fEnabled = true;
    }

    mutable CCriticalSection cs_state;

private:
    bool fEnabled;
    std::map<uint256, CDandelionTxState> mapTxState;
};


extern CDandelionRouter dandelionRouter;
extern CDandelionState dandelionState;


#endif // INN_DANDELION_H
