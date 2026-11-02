// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include "../main.h"
#include "../script.h"
#include "../util.h"

BOOST_AUTO_TEST_SUITE(consensus_determinism_tests)

namespace {

struct MergesetHeightGuard
{
    int nSaved;
    MergesetHeightGuard() : nSaved(nRegtestMergesetHeight) {}
    ~MergesetHeightGuard() { nRegtestMergesetHeight = nSaved; }
};

CBlock MakeBlock(const uint256& hashPrev, int64_t nTime)
{
    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock = hashPrev;
    block.nTime = (unsigned int)nTime;
    block.nBits = 0;
    block.nNonce = 0;
    CTransaction tx;
    tx.nTime = (unsigned int)nTime;
    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vin[0].scriptSig = CScript() << 1 << 2;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    block.vtx.push_back(tx);
    block.hashMerkleRoot = block.BuildMerkleTree();
    return block;
}

bool TimestampOK(const CBlock& block)
{
    return block.CheckBlock(false, false, false);
}

} // namespace

BOOST_AUTO_TEST_CASE(pow_reward_height_is_a_pure_function_of_height)
{
    const int nFork = FORK_HEIGHT_TIGHTER_DRIFT;
    BOOST_CHECK_EQUAL(PoWRewardHeight(0), 0);
    if (nFork > 2)
    {
        BOOST_CHECK_EQUAL(PoWRewardHeight(1), 0);
        BOOST_CHECK_EQUAL(PoWRewardHeight(nFork - 1), nFork - 2);
    }
    BOOST_CHECK_EQUAL(PoWRewardHeight(nFork), nFork);
    BOOST_CHECK_EQUAL(PoWRewardHeight(nFork + 1), nFork + 1);
}

// Mainnet pins: the fork height and the reward height on both sides of it.
BOOST_AUTO_TEST_CASE(pow_reward_height_mainnet_pins)
{
    const bool fSavedReg = fRegTest, fSavedTest = fTestNet;
    fRegTest = false;
    fTestNet = false;
    const int nFork = FORK_HEIGHT_TIGHTER_DRIFT;
    BOOST_CHECK(nFork > 1);
    BOOST_CHECK_EQUAL(PoWRewardHeight(1), 0);
    BOOST_CHECK_EQUAL(PoWRewardHeight(nFork - 1), nFork - 2);
    BOOST_CHECK_EQUAL(PoWRewardHeight(nFork), nFork);
    BOOST_CHECK_EQUAL(PoWRewardHeight(8150040), 8150040);
    fRegTest = fSavedReg;
    fTestNet = fSavedTest;
}

// The mergeset drift limit holds whether the parent arrives before or after the child.
BOOST_AUTO_TEST_CASE(mergeset_future_drift_holds_in_any_delivery_order)
{
    BOOST_REQUIRE(pindexBest != NULL);
    MergesetHeightGuard guard;
    nRegtestMergesetHeight = 1;
    BOOST_REQUIRE(IsMergesetActiveAtHeight(nBestHeight + 1));

    const int64_t nNow = GetAdjustedTime();
    const int64_t nFar = nNow + MERGESET_MAX_FUTURE_DRIFT + 120;
    BOOST_REQUIRE(nFar < FutureDrift(nNow));
    const int64_t nNear = nNow + 30;

    uint256 hashUnknown;
    hashUnknown.SetHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    BOOST_REQUIRE(!mapBlockIndex.count(hashUnknown));
    const uint256 hashKnown = pindexBest->GetBlockHash();

    BOOST_CHECK(TimestampOK(MakeBlock(hashKnown, nNear)));
    BOOST_CHECK(TimestampOK(MakeBlock(hashUnknown, nNear)));
    CBlock farKnown = MakeBlock(hashKnown, nFar);
    CBlock farUnknown = MakeBlock(hashUnknown, nFar);
    BOOST_CHECK(!TimestampOK(farKnown));
    BOOST_CHECK(!TimestampOK(farUnknown));
    // A clock refusal is never scored.
    BOOST_CHECK_EQUAL(farKnown.nDoS, 0);
    BOOST_CHECK_EQUAL(farUnknown.nDoS, 0);

    // Inactive mergeset: the legacy limit applies to both orders.
    nRegtestMergesetHeight = PRIVACY_VNEXT_HEIGHT_UNSET;
    BOOST_CHECK(TimestampOK(MakeBlock(hashKnown, nFar)));
    BOOST_CHECK(TimestampOK(MakeBlock(hashUnknown, nFar)));
}

// A recorded block skips the plain-tx re-run, but changed bytes still fail on the merkle root.
BOOST_AUTO_TEST_CASE(checked_tx_cache_is_bound_by_the_merkle_root)
{
    BOOST_REQUIRE(pindexBest != NULL);
    const int64_t nNow = GetAdjustedTime();
    CBlock block = MakeBlock(pindexBest->GetBlockHash(), nNow);
    BOOST_REQUIRE(block.CheckBlock(false, true, false));
    BOOST_CHECK(CheckedTxBlockSeen(block.GetHash()));
    BOOST_CHECK(block.CheckBlock(false, true, false));

    CBlock tampered = block;
    tampered.vtx[0].vout[0].nValue = -1;
    BOOST_REQUIRE(tampered.GetHash() == block.GetHash());
    BOOST_CHECK(!tampered.CheckBlock(false, true, false));
    BOOST_CHECK(tampered.nDoS > 0);
    // Without the merkle check the cache is not consulted.
    BOOST_CHECK(!tampered.CheckBlock(false, false, false));
}

BOOST_AUTO_TEST_SUITE_END()
