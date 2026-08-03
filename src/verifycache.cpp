// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "verifycache.h"

#include "hash.h"
#include "sync.h"
#include "util.h"

#include <list>
#include <map>

// Bounded so the cache can never grow without limit. The working set is one
// epoch of finality votes (FINALITY_MAX_VOTES = 10000) plus in-flight shielded
// spends, comfortably under this cap; eviction is least-recently-used.
static const size_t VERIFY_CACHE_MAX_ENTRIES = 65536;

namespace {
CCriticalSection cs_verifyCache;
std::list<uint256> lruOrder;                                  // front = most recently used
std::map<uint256, std::list<uint256>::iterator> mapCache;     // key -> its node in lruOrder
}

uint256 VerifyProofCacheKey(int nDomain, int nHeight, const uint256& hashArgs)
{
    extern bool fTestNet;
    extern bool fRegTest;
    // Network is bound explicitly rather than relying on the argument bytes
    // differing: fork heights differ per network, so the same proof at the same
    // height can be judged under different rules on regtest vs mainnet.
    const unsigned char nNetwork = fRegTest ? 2 : (fTestNet ? 1 : 0);
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("Innova/VerifyProofCache/v1");
    ss << (uint32_t)VERIFYCACHE_SEMANTICS_VERSION;
    ss << (unsigned char)nNetwork;
    ss << (int32_t)nDomain;
    ss << (int32_t)nHeight;
    ss << hashArgs;
    return ss.GetHash();
}

bool VerifyProofCacheEnabled()
{
    // Magic-static init is thread-safe; the arg is read once after parameters
    // have been parsed (verifiers only run well after node startup).
    static bool fEnabled = GetBoolArg("-verifycache", true);
    return fEnabled;
}

bool VerifyProofCacheCheck(const uint256& key)
{
    LOCK(cs_verifyCache);
    std::map<uint256, std::list<uint256>::iterator>::iterator it = mapCache.find(key);
    if (it == mapCache.end())
        return false;
    // Promote to most-recently-used.
    lruOrder.splice(lruOrder.begin(), lruOrder, it->second);
    return true;
}

void VerifyProofCacheStore(const uint256& key)
{
    LOCK(cs_verifyCache);
    std::map<uint256, std::list<uint256>::iterator>::iterator it = mapCache.find(key);
    if (it != mapCache.end())
    {
        lruOrder.splice(lruOrder.begin(), lruOrder, it->second);
        return;
    }
    lruOrder.push_front(key);
    mapCache[key] = lruOrder.begin();
    if (mapCache.size() > VERIFY_CACHE_MAX_ENTRIES)
    {
        const uint256& evict = lruOrder.back();
        mapCache.erase(evict);
        lruOrder.pop_back();
    }
}

void VerifyProofCacheClear()
{
    LOCK(cs_verifyCache);
    mapCache.clear();
    lruOrder.clear();
}
