#define BOOST_TEST_DYN_LINK

#include <boost/test/unit_test.hpp>

#include "checkpoints.h"
#include "main.h"
#include "util.h"

#include <cstdint>

BOOST_AUTO_TEST_SUITE(orphan_stake_marker_tests)

// A proof-of-stake orphan block whose kernel identity is exactly (prevout,
// nTime), with a distinct block hash per seed.
static CBlock* MakePosOrphanBlock(
    const std::pair<COutPoint, unsigned int>& stake,
    unsigned int nSeed,
    const uint256& hashPrev = uint256())
{
    CBlock* pblock = new CBlock();
    pblock->nTime = 1000 + nSeed;
    pblock->hashPrevBlock = (hashPrev == uint256()) ? uint256((uint64_t)nSeed) : hashPrev;

    CTransaction coinstake;
    coinstake.nTime = stake.second;
    coinstake.vin.push_back(CTxIn(stake.first));
    CTxOut emptyOut;
    emptyOut.SetEmpty();
    coinstake.vout.push_back(emptyOut);
    CTxOut valueOut;
    valueOut.nValue = 1;
    coinstake.vout.push_back(valueOut);

    pblock->vtx.push_back(CTransaction());
    pblock->vtx.push_back(coinstake);
    return pblock;
}

// Mirrors the receive-path orphan-store bookkeeping: block table, by-prev
// index, per-peer counts, and the proof-of-stake marker set.
static void RegisterPosOrphan(CBlock* pblock, NodeId peer = -1)
{
    const uint256 hash = pblock->GetHash();
    mapOrphanBlocks[hash] = pblock;
    mapOrphanBlocksByPrev.insert(std::make_pair(pblock->hashPrevBlock, pblock));
    if (pblock->IsProofOfStake())
        setStakeSeenOrphan.insert(pblock->GetProofOfStake());
    if (peer >= 0)
    {
        mapOrphanBlocksByNode[hash] = peer;
        mapOrphanCountByNode[peer]++;
    }
}

// Mirrors the parent-connect / orphan-replay removal body exactly as the fix
// performs it: remove block bookkeeping, then release the marker only when no
// retained orphan still references it.
static void RemoveOrphanAsParentConnect(const uint256& hash)
{
    std::map<uint256, CBlock*>::iterator it = mapOrphanBlocks.find(hash);
    if (it == mapOrphanBlocks.end())
        return;
    CBlock* pblockOrphan = it->second;
    const bool fIsProofOfStake = pblockOrphan->IsProofOfStake();
    const std::pair<COutPoint, unsigned int> stake = pblockOrphan->GetProofOfStake();

    mapOrphanBlocks.erase(hash);
    if (fIsProofOfStake)
        EraseStakeSeenOrphanIfUnreferenced(stake);

    std::map<uint256, NodeId>::iterator nodeIt = mapOrphanBlocksByNode.find(hash);
    if (nodeIt != mapOrphanBlocksByNode.end()) {
        mapOrphanCountByNode[nodeIt->second]--;
        mapOrphanBlocksByNode.erase(nodeIt);
    }

    delete pblockOrphan;
}

// Mirrors the receive-path duplicate-stake-orphan reject gate.
static bool WouldRejectDuplicateStakeOrphan(const CBlock* pblock)
{
    return pblock->IsProofOfStake() &&
           setStakeSeenOrphan.count(pblock->GetProofOfStake()) != 0 &&
           mapOrphanBlocksByPrev.count(pblock->GetHash()) == 0 &&
           !Checkpoints::WantedByPendingSyncCheckpoint(pblock->GetHash());
}

typedef std::pair<COutPoint, unsigned int> Stake;

static Stake MakeStake(unsigned int nHash, unsigned int nTime)
{
    return Stake(COutPoint(uint256((uint64_t)nHash), 1), nTime);
}

// Full orphan-storage snapshot restored on scope exit, so tests do not leak
// orphan blocks or markers into later cases.
class CScopedOrphanStorage
{
private:
    std::map<uint256, CBlock*> savedBlocks;
    std::multimap<uint256, CBlock*> savedByPrev;
    std::map<uint256, NodeId> savedByNode;
    std::map<NodeId, int> savedCount;
    std::set<Stake> savedStakeSeen;

public:
    CScopedOrphanStorage()
    {
        LOCK(cs_main);
        savedBlocks = mapOrphanBlocks;
        savedByPrev = mapOrphanBlocksByPrev;
        savedByNode = mapOrphanBlocksByNode;
        savedCount = mapOrphanCountByNode;
        savedStakeSeen = setStakeSeenOrphan;
        mapOrphanBlocks.clear();
        mapOrphanBlocksByPrev.clear();
        mapOrphanBlocksByNode.clear();
        mapOrphanCountByNode.clear();
        setStakeSeenOrphan.clear();
    }
    ~CScopedOrphanStorage()
    {
        LOCK(cs_main);
        for (std::map<uint256, CBlock*>::iterator it = mapOrphanBlocks.begin();
             it != mapOrphanBlocks.end(); ++it)
            delete it->second;
        mapOrphanBlocks = savedBlocks;
        mapOrphanBlocksByPrev = savedByPrev;
        mapOrphanBlocksByNode = savedByNode;
        mapOrphanCountByNode = savedCount;
        setStakeSeenOrphan = savedStakeSeen;
    }
};

// Overrides -maxorphanblocks for the duration of the scope so prune eviction
// can be exercised with a tiny table.
class CScopedMaxOrphanBlocks
{
private:
    std::string strSaved;
    bool fHad;

public:
    explicit CScopedMaxOrphanBlocks(const std::string& strValue)
    {
        fHad = mapArgs.count("-maxorphanblocks") != 0;
        if (fHad)
            strSaved = mapArgs["-maxorphanblocks"];
        mapArgs["-maxorphanblocks"] = strValue;
    }
    ~CScopedMaxOrphanBlocks()
    {
        if (fHad)
            mapArgs["-maxorphanblocks"] = strSaved;
        else
            mapArgs.erase("-maxorphanblocks");
    }
};

BOOST_AUTO_TEST_CASE(prune_eviction_releases_unreferenced_marker)
{
    CScopedOrphanStorage scope;
    CScopedMaxOrphanBlocks max0("0");
    Stake K1 = MakeStake(1, 100);
    RegisterPosOrphan(MakePosOrphanBlock(K1, 1));
    BOOST_CHECK_EQUAL(setStakeSeenOrphan.count(K1), 1U);

    // Single removable orphan is deterministically evicted.
    PruneOrphanBlocks();

    BOOST_CHECK(mapOrphanBlocks.empty());
    BOOST_CHECK_EQUAL(setStakeSeenOrphan.count(K1), 0U);
}

BOOST_AUTO_TEST_CASE(parent_connect_removal_releases_unreferenced_marker)
{
    CScopedOrphanStorage scope;
    Stake K1 = MakeStake(2, 100);
    CBlock* orphan = MakePosOrphanBlock(K1, 1);
    RegisterPosOrphan(orphan, 3);
    const uint256 hash = orphan->GetHash();

    RemoveOrphanAsParentConnect(hash);

    BOOST_CHECK(mapOrphanBlocks.empty());
    BOOST_CHECK_EQUAL(setStakeSeenOrphan.count(K1), 0U);
    BOOST_CHECK_EQUAL(mapOrphanBlocksByNode.count(hash), 0U);
}

BOOST_AUTO_TEST_CASE(shared_marker_retention_after_first_orphan_removal)
{
    CScopedOrphanStorage scope;
    Stake K = MakeStake(3, 100);
    CBlock* orphanA = MakePosOrphanBlock(K, 1);
    // orphanB shares the same kernel K but has its own block hash.
    CBlock* orphanB = MakePosOrphanBlock(K, 2);
    RegisterPosOrphan(orphanA);
    RegisterPosOrphan(orphanB);
    BOOST_CHECK_EQUAL(setStakeSeenOrphan.count(K), 1U);

    RemoveOrphanAsParentConnect(orphanA->GetHash());

    // K must survive while orphanB still references it.
    BOOST_CHECK_EQUAL(setStakeSeenOrphan.count(K), 1U);
    BOOST_CHECK_EQUAL(mapOrphanBlocks.count(orphanB->GetHash()), 1U);
}

BOOST_AUTO_TEST_CASE(final_reference_marker_release)
{
    CScopedOrphanStorage scope;
    Stake K = MakeStake(4, 100);
    CBlock* orphanA = MakePosOrphanBlock(K, 1);
    CBlock* orphanB = MakePosOrphanBlock(K, 2);
    RegisterPosOrphan(orphanA);
    RegisterPosOrphan(orphanB);

    RemoveOrphanAsParentConnect(orphanA->GetHash());
    BOOST_CHECK_EQUAL(setStakeSeenOrphan.count(K), 1U);

    RemoveOrphanAsParentConnect(orphanB->GetHash());
    BOOST_CHECK(mapOrphanBlocks.empty());
    BOOST_CHECK_EQUAL(setStakeSeenOrphan.count(K), 0U);
}

BOOST_AUTO_TEST_CASE(legitimate_redelivery_after_final_marker_release)
{
    CScopedOrphanStorage scope;
    CScopedMaxOrphanBlocks max0("0");
    Stake K = MakeStake(5, 100);
    CBlock* orphan = MakePosOrphanBlock(K, 1);
    RegisterPosOrphan(orphan);

    PruneOrphanBlocks();
    BOOST_CHECK_EQUAL(setStakeSeenOrphan.count(K), 0U);

    // With the marker released, a fresh same-stake orphan is no longer
    // rejected solely because of stale orphan state.
    CBlock* re = MakePosOrphanBlock(K, 3);
    BOOST_CHECK(!WouldRejectDuplicateStakeOrphan(re));

    // And a subsequent legitimate re-delivery re-registers cleanly.
    RegisterPosOrphan(re);
    BOOST_CHECK_EQUAL(setStakeSeenOrphan.count(K), 1U);
}

BOOST_AUTO_TEST_CASE(orphan_bookkeeping_consistent_after_marker_cleanup)
{
    CScopedOrphanStorage scope;
    Stake K1 = MakeStake(6, 100);
    Stake K2 = MakeStake(7, 100);
    CBlock* orphanA = MakePosOrphanBlock(K1, 1);
    CBlock* orphanB = MakePosOrphanBlock(K2, 2);
    RegisterPosOrphan(orphanA, 7);
    RegisterPosOrphan(orphanB, 7);
    BOOST_CHECK_EQUAL(mapOrphanCountByNode[7], 2);

    RemoveOrphanAsParentConnect(orphanA->GetHash());

    BOOST_CHECK_EQUAL(mapOrphanCountByNode[7], 1);
    BOOST_CHECK_EQUAL(mapOrphanBlocksByNode.count(orphanA->GetHash()), 0U);
    BOOST_CHECK_EQUAL(setStakeSeenOrphan.count(K1), 0U);
    BOOST_CHECK_EQUAL(setStakeSeenOrphan.count(K2), 1U);
}

BOOST_AUTO_TEST_SUITE_END()