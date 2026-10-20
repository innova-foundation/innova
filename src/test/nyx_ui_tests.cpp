#include <boost/test/unit_test.hpp>

#include "nyxui.h"

BOOST_AUTO_TEST_SUITE(nyx_ui_tests)

static const std::string A = "i4wsTwN5i1nbXXXXXXXXXXXXXXXXh5hc9U";

BOOST_AUTO_TEST_CASE(avatar_hue_stable)
{
    BOOST_CHECK_EQUAL(NyxAvatarHue(A), NyxAvatarHue(A));
    BOOST_CHECK(NyxAvatarHue(A) >= 0 && NyxAvatarHue(A) < 360);
    BOOST_CHECK(NyxAvatarHue("iD33N6urpMYm") != NyxAvatarHue("iD33N6urpMYn"));
    BOOST_CHECK_EQUAL(NyxAvatarHue(""), (int)(2166136261u % 360));
}

BOOST_AUTO_TEST_CASE(initials)
{
    BOOST_CHECK_EQUAL(NyxInitials("alice bob carol", A), "AB");
    BOOST_CHECK_EQUAL(NyxInitials("  zed", A), "Z");
    BOOST_CHECK_EQUAL(NyxInitials("", A), "4W");
    BOOST_CHECK_EQUAL(NyxInitials(NyxShortAddress(A), A), "4W");
    BOOST_CHECK_EQUAL(NyxInitials(A, A), "4W");
    BOOST_CHECK_EQUAL(NyxInitials("\xC3\xA9mile x", A), "\xC3\xA9");
    BOOST_CHECK_EQUAL(NyxInitials("", "i"), "?");
}

BOOST_AUTO_TEST_CASE(display_name)
{
    BOOST_CHECK_EQUAL(NyxShortAddress(A), "i4wsTwN5i1nb\xE2\x80\xA6h5hc9U");
    BOOST_CHECK_EQUAL(NyxShortAddress("short"), "short");
    BOOST_CHECK_EQUAL(NyxDisplayName(A, "Nick", "Label"), "Nick");
    BOOST_CHECK_EQUAL(NyxDisplayName(A, "", "Label"), "Label");
    BOOST_CHECK_EQUAL(NyxDisplayName(A, "", ""), NyxShortAddress(A));
}

BOOST_AUTO_TEST_CASE(grouping)
{
    BOOST_CHECK(NyxGroupsWith("a", 1000, 1, "a", 1000, 1));
    BOOST_CHECK(NyxGroupsWith("a", 1000, 1, "a", 1300, 1));
    BOOST_CHECK(!NyxGroupsWith("a", 1000, 1, "a", 1301, 1));
    BOOST_CHECK(!NyxGroupsWith("a", 1000, 1, "b", 1001, 1));
    BOOST_CHECK(!NyxGroupsWith("a", 1000, 1, "a", 1001, 2));
    BOOST_CHECK(!NyxGroupsWith("a", 1000, 1, "a", 999, 1));
    BOOST_CHECK(!NyxGroupsWith("", 1000, 1, "", 1000, 1));
}

BOOST_AUTO_TEST_SUITE_END()
