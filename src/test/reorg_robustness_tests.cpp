#include <boost/test/unit_test.hpp>

#include "txdb.h"

BOOST_AUTO_TEST_SUITE(reorg_robustness_tests)

BOOST_AUTO_TEST_CASE(startup_check_level_clamped_to_one)
{
    BOOST_CHECK_EQUAL(DEFAULT_CHECKBLOCKS, 288);
    for (int nIn = -3; nIn <= 7; nIn++)
    {
        int nLevel = nIn, nDepth = 288;
        ClampStartupCheck(nLevel, nDepth, 10000);
        BOOST_CHECK_EQUAL(nLevel, nIn < 0 ? 0 : (nIn > 1 ? 1 : nIn));
        BOOST_CHECK_EQUAL(nDepth, 288);
    }
}

BOOST_AUTO_TEST_CASE(startup_check_depth_bounds)
{
    int nLevel = 1, nDepth = 0;
    ClampStartupCheck(nLevel, nDepth, 500);
    BOOST_CHECK_EQUAL(nDepth, 500);
    nDepth = 2500;
    ClampStartupCheck(nLevel, nDepth, 100);
    BOOST_CHECK_EQUAL(nDepth, 100);
}

BOOST_AUTO_TEST_CASE(startup_check_failure_names_height_and_resync)
{
    std::string str = StartupCheckFailureMessage(7883137);
    BOOST_CHECK(str.find("7883137") != std::string::npos);
    BOOST_CHECK(str.find("resync") != std::string::npos);
    BOOST_CHECK(str.find("txleveldb") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
