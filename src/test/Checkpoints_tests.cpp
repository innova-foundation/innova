//
// Unit tests for block-chain checkpoints
//
#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/test/unit_test.hpp>
#include <boost/foreach.hpp>

#include "../checkpoints.h"
#include "../util.h"

using namespace std;

BOOST_AUTO_TEST_SUITE(Checkpoints_tests)

BOOST_AUTO_TEST_CASE(sanity)
{
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

BOOST_AUTO_TEST_SUITE_END()
