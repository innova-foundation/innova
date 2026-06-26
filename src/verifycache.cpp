// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "verifycache.h"

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
