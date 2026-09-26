//
// Unit tests for block-chain checkpoints
//
#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/test/unit_test.hpp>
#include <boost/foreach.hpp>

#include "../checkpoints.h"
#include "../main.h"
#include "../util.h"

using namespace std;

namespace {

// Each case sets the network flags it needs and restores them.
struct ScopedNetwork
{
    bool fWasRegTest;
    bool fWasTestNet;
    ScopedNetwork(bool fRegTestIn, bool fTestNetIn)
        : fWasRegTest(fRegTest), fWasTestNet(fTestNet)
    {
        fRegTest = fRegTestIn;
        fTestNet = fTestNetIn;
    }
    ~ScopedNetwork()
    {
        fRegTest = fWasRegTest;
        fTestNet = fWasTestNet;
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(Checkpoints_tests)

BOOST_AUTO_TEST_CASE(sanity)
{
    ScopedNetwork mainnet(false, false);

    BOOST_REQUIRE(Checkpoints::mapCheckpoints.size() >= 2);
    const Checkpoints::MapCheckpoints::const_iterator first = Checkpoints::mapCheckpoints.begin();
    const Checkpoints::MapCheckpoints::const_reverse_iterator last = Checkpoints::mapCheckpoints.rbegin();

    BOOST_CHECK(Checkpoints::CheckHardened(first->first, first->second));
    BOOST_CHECK(Checkpoints::CheckHardened(last->first, last->second));


    // Wrong hashes at checkpoints should fail:
    BOOST_CHECK(!Checkpoints::CheckHardened(first->first, last->second));
    BOOST_CHECK(!Checkpoints::CheckHardened(last->first, first->second));

    // ... but any hash not at a checkpoint should succeed:
    BOOST_CHECK(Checkpoints::CheckHardened(first->first + 1, last->second));
    BOOST_CHECK(Checkpoints::CheckHardened(last->first + 1, first->second));

    BOOST_CHECK_EQUAL(Checkpoints::GetTotalBlocksEstimate(), last->first);
}

// The estimate gates script verification (skipped below it) and mempool resurrection on
// reorg (above it only); regtest must not read the mainnet height.
BOOST_AUTO_TEST_CASE(the_block_estimate_is_the_active_networks_own)
{
    {
        ScopedNetwork regtest(true, false);
        BOOST_CHECK_EQUAL(Checkpoints::GetTotalBlocksEstimate(), 0);
    }
    {
        ScopedNetwork testnet(false, true);
        BOOST_REQUIRE(!Checkpoints::mapCheckpointsTestnet.empty());
        BOOST_CHECK_EQUAL(Checkpoints::GetTotalBlocksEstimate(),
                          Checkpoints::mapCheckpointsTestnet.rbegin()->first);
    }
    {
        ScopedNetwork mainnet(false, false);
        BOOST_CHECK_EQUAL(Checkpoints::GetTotalBlocksEstimate(),
                          Checkpoints::mapCheckpoints.rbegin()->first);
    }
}

// Regtest chains are fresh per run, so regtest must not use the mainnet checkpoint map
// (it would refuse a regtest block at mainnet checkpoint heights, e.g. 2000).
BOOST_AUTO_TEST_CASE(regtest_is_not_bound_by_mainnet_checkpoints)
{
    BOOST_REQUIRE(Checkpoints::mapCheckpoints.count(2000) == 1);
    const uint256 hashMainnet2000 = Checkpoints::mapCheckpoints.find(2000)->second;
    const uint256 hashSomethingElse("0x00000000000000000000000000000000000000000000000000000000deadbeef");
    BOOST_REQUIRE(hashSomethingElse != hashMainnet2000);

    {
        ScopedNetwork mainnet(false, false);
        BOOST_CHECK(!Checkpoints::CheckHardened(2000, hashSomethingElse));
    }
    {
        ScopedNetwork regtest(true, false);
        BOOST_CHECK(Checkpoints::CheckHardened(2000, hashSomethingElse));
        // Genesis is still pinned: it is the one block regtest does fix.
        BOOST_CHECK(Checkpoints::CheckHardened(0, hashGenesisBlockRegTest));
        BOOST_CHECK(!Checkpoints::CheckHardened(0, hashSomethingElse));
    }
}

// Testnet keeps its own map; the regtest map must not be reachable from it.
BOOST_AUTO_TEST_CASE(each_network_reads_its_own_checkpoints)
{
    const uint256 hashSomethingElse("0x00000000000000000000000000000000000000000000000000000000deadbeef");
    ScopedNetwork testnet(false, true);
    BOOST_CHECK(Checkpoints::CheckHardened(0, hashGenesisBlockTestNet));
    BOOST_CHECK(!Checkpoints::CheckHardened(0, hashSomethingElse));
    // A mainnet-only checkpoint height is not testnet's business.
    BOOST_CHECK(Checkpoints::CheckHardened(2000, hashSomethingElse));
}

BOOST_AUTO_TEST_SUITE_END()
