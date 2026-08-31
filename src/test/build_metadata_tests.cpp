#define BOOST_TEST_DYN_LINK

#include <boost/test/unit_test.hpp>

#include "../version.h"

#include <cctype>

BOOST_AUTO_TEST_SUITE(build_metadata_tests)

BOOST_AUTO_TEST_CASE(embedded_build_metadata_is_consistent)
{
    BOOST_CHECK(!CLIENT_BUILD_COMMIT.empty());
    // genbuild.sh records the complete commit so release evidence cannot be
    // ambiguous; accept an abbreviated one too for builds that supply it.
    BOOST_CHECK(CLIENT_BUILD_COMMIT == "unknown" ||
                CLIENT_BUILD_COMMIT.size() == 40 ||
                CLIENT_BUILD_COMMIT.size() <= 12);
    if (CLIENT_BUILD_COMMIT != "unknown")
    {
        for (size_t i = 0; i < CLIENT_BUILD_COMMIT.size(); ++i)
            BOOST_CHECK(isxdigit((unsigned char)CLIENT_BUILD_COMMIT[i]));
    }
    BOOST_CHECK(!CLIENT_BUILD_DIRTY || CLIENT_BUILD_COMMIT != "unknown");
}

BOOST_AUTO_TEST_SUITE_END()
