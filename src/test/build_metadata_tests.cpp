#define BOOST_TEST_DYN_LINK

#include <boost/test/unit_test.hpp>

#include "../version.h"

BOOST_AUTO_TEST_SUITE(build_metadata_tests)

BOOST_AUTO_TEST_CASE(embedded_build_metadata_is_consistent)
{
    BOOST_CHECK(!CLIENT_BUILD_COMMIT.empty());
    BOOST_CHECK(CLIENT_BUILD_COMMIT == "unknown" ||
                CLIENT_BUILD_COMMIT.size() <= 12);
    BOOST_CHECK(!CLIENT_BUILD_DIRTY || CLIENT_BUILD_COMMIT != "unknown");
}

BOOST_AUTO_TEST_SUITE_END()
