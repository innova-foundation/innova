#include <boost/test/unit_test.hpp>

#include "base58.h"
#include "nyxsafety.h"

#include <boost/filesystem.hpp>

BOOST_AUTO_TEST_SUITE(nyx_safety_tests)

BOOST_AUTO_TEST_CASE(detects_recovery_phrases)
{
    BOOST_CHECK_EQUAL(NyxDetectSecret("abandon abandon abandon abandon abandon abandon abandon "
                                      "abandon abandon abandon abandon about"), NYX_SECRET_PHRASE);
    BOOST_CHECK_EQUAL(NyxDetectSecret("here: 1. Legal 2. winner 3. thank 4. year 5. wave 6. sausage "
                                      "7. worth 8. useful 9. legal 10. winner 11. thank 12. yellow"),
                      NYX_SECRET_PHRASE);
    // One typo or non-list word in twelve still counts.
    BOOST_CHECK_EQUAL(NyxDetectSecret("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrongg"), NYX_SECRET_PHRASE);
    BOOST_CHECK_EQUAL(NyxDetectSecret("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrongg wrongg"), NYX_SECRET_NONE);
    BOOST_CHECK_EQUAL(NyxDetectSecret("Hey, are we still meeting at the station later today? "
                                      "I can bring the documents and we can go over the plan for the release."),
                      NYX_SECRET_NONE);
    BOOST_CHECK_EQUAL(NyxDetectSecret("abandon abandon abandon"), NYX_SECRET_NONE);
}

BOOST_AUTO_TEST_CASE(detects_key_material)
{
    std::vector<unsigned char> v(1, 0x80);
    v.insert(v.end(), 32, 0x11);
    v.push_back(0x01);
    BOOST_CHECK_EQUAL(NyxDetectSecret("my key " + EncodeBase58Check(v)), NYX_SECRET_PRIVKEY);
    v.pop_back();
    BOOST_CHECK_EQUAL(NyxDetectSecret(EncodeBase58Check(v)), NYX_SECRET_PRIVKEY);

    // An address (21-byte payload) is not key material.
    std::vector<unsigned char> a(21, 0x22);
    BOOST_CHECK_EQUAL(NyxDetectSecret("pay " + EncodeBase58Check(a)), NYX_SECRET_NONE);

    BOOST_CHECK_EQUAL(NyxDetectSecret("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"),
                      NYX_SECRET_XPRV);
    BOOST_CHECK_EQUAL(NyxDetectSecret("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"),
                      NYX_SECRET_NONE);

    const std::string hex(64, 'a');
    BOOST_CHECK_EQUAL(NyxDetectSecret("{\"seed\": \"" + hex + "\", \"generation\": 1}"), NYX_SECRET_HEXSEED);
    // A bare txid is not flagged.
    BOOST_CHECK_EQUAL(NyxDetectSecret("tx " + hex + " confirmed"), NYX_SECRET_NONE);
    BOOST_CHECK(!std::string(NYX_SECRET_WARNING).empty());
}

BOOST_AUTO_TEST_CASE(scam_heuristic)
{
    BOOST_CHECK(NyxLooksLikeScam("Hello from support. Please send your recovery phrase so we can fix the issue."));
    BOOST_CHECK(NyxLooksLikeScam("Your wallet needs validation: VERIFY YOUR   WALLET at the link"));
    BOOST_CHECK(NyxLooksLikeScam("run dumpprivkey and paste the output"));
    BOOST_CHECK(NyxLooksLikeScam("Enter your 24 words to claim the airdrop"));
    BOOST_CHECK(!NyxLooksLikeScam("Never share your recovery phrase."));
    BOOST_CHECK(!NyxLooksLikeScam("lunch at noon?"));
}

BOOST_AUTO_TEST_CASE(request_gating_rules)
{
    BOOST_CHECK_EQUAL(NyxClassifySender("iA", false, false, false, false), NYX_SENDER_REQUEST);
    BOOST_CHECK_EQUAL(NyxClassifySender("iA", true, false, false, false), NYX_SENDER_KNOWN);
    BOOST_CHECK_EQUAL(NyxClassifySender("iA", false, true, false, false), NYX_SENDER_KNOWN);
    BOOST_CHECK_EQUAL(NyxClassifySender("iA", false, false, true, false), NYX_SENDER_KNOWN);
    BOOST_CHECK_EQUAL(NyxClassifySender("iA", true, true, true, true), NYX_SENDER_BLOCKED);
    BOOST_CHECK_EQUAL(NyxClassifySender("anon", true, true, true, false), NYX_SENDER_REQUEST);
    BOOST_CHECK_EQUAL(NyxClassifySender("", false, false, false, false), NYX_SENDER_REQUEST);
}

BOOST_AUTO_TEST_CASE(contact_lists_persist)
{
    NyxContactLists l;
    l.Parse("accept iAAA\nblock iBBB\r\naccept iBBB\nbogus\naccept bad addr\nblock \n");
    BOOST_CHECK_EQUAL(l.setAccepted.size(), 1U);
    BOOST_CHECK(l.setAccepted.count("iAAA"));
    BOOST_CHECK(l.setBlocked.count("iBBB"));
    BOOST_CHECK(!l.setAccepted.count("iBBB"));

    boost::filesystem::path p = boost::filesystem::temp_directory_path()
                                / boost::filesystem::unique_path("nyxc-%%%%%%%%.dat");
    BOOST_REQUIRE(l.Save(p.string()));
    NyxContactLists r;
    BOOST_REQUIRE(r.Load(p.string()));
    BOOST_CHECK(r.setAccepted == l.setAccepted);
    BOOST_CHECK(r.setBlocked == l.setBlocked);
    boost::filesystem::remove(p);
    BOOST_CHECK(!r.Load(p.string()));
}

BOOST_AUTO_TEST_CASE(tracking_strip)
{
    BOOST_CHECK_EQUAL(NyxStripTracking("https://a.com/p?utm_source=x&id=7&fbclid=Z#top"), "https://a.com/p?id=7#top");
    BOOST_CHECK_EQUAL(NyxStripTracking("https://a.com/p?UTM_Medium=x&gclid=1"), "https://a.com/p");
    BOOST_CHECK_EQUAL(NyxStripTracking("https://a.com/p?mc_eid=1&igshid=2&q=a%20b"), "https://a.com/p?q=a%20b");
    BOOST_CHECK_EQUAL(NyxStripTracking("https://a.com/p?q=1"), "https://a.com/p?q=1");
    BOOST_CHECK_EQUAL(NyxStripTracking("https://a.com/"), "https://a.com/");
    BOOST_CHECK_EQUAL(NyxStripTracking("https://a.com/?utm_x#f?utm_y=1"), "https://a.com/#f?utm_y=1");
    BOOST_CHECK_EQUAL(NyxStripTrackingInText("see https://a.com/?utm_source=t, and http://b.org/x?fbclid=1&k=v."),
                      "see https://a.com/, and http://b.org/x?k=v.");
    BOOST_CHECK_EQUAL(NyxStripTrackingInText("no links"), "no links");
}

BOOST_AUTO_TEST_CASE(registrable_domain)
{
    BOOST_CHECK_EQUAL(NyxRegistrableDomain("www.example.com"), "example.com");
    BOOST_CHECK_EQUAL(NyxRegistrableDomain("example.com"), "example.com");
    BOOST_CHECK_EQUAL(NyxRegistrableDomain("a.b.bbc.co.uk"), "bbc.co.uk");
    BOOST_CHECK_EQUAL(NyxRegistrableDomain("innova.example.com.au"), "example.com.au");
    BOOST_CHECK_EQUAL(NyxRegistrableDomain("paypal.com.evil.io"), "evil.io");
}

BOOST_AUTO_TEST_CASE(idn_and_hidden_chars)
{
    std::u32string cps;
    BOOST_REQUIRE(NyxPunycodeDecode("mnchen-3ya", cps));
    BOOST_CHECK(cps == std::u32string(U"münchen"));
    BOOST_REQUIRE(NyxPunycodeDecode("80ak6aa92e", cps));  // Cyrillic "apple" lookalike
    BOOST_CHECK_EQUAL(cps.size(), 5U);
    BOOST_CHECK(!NyxPunycodeDecode("99999999999", cps));

    BOOST_CHECK_EQUAL(NyxUrlRiskFlags("https://example.com/a"), 0);
    // Latin-only IDN is flagged as IDN but not as a lookalike.
    BOOST_CHECK_EQUAL(NyxUrlRiskFlags("https://xn--mnchen-3ya.de/"), NYX_URL_IDN);
    BOOST_CHECK_EQUAL(NyxUrlRiskFlags("https://xn--80ak6aa92e.com/"), NYX_URL_IDN | NYX_URL_LOOKALIKE);
    // "pаypal" with a Cyrillic a: mixed script.
    BOOST_CHECK_EQUAL(NyxUrlRiskFlags("https://xn--pypal-4ve.com/"), NYX_URL_IDN | NYX_URL_LOOKALIKE);
    BOOST_CHECK(NyxUrlRiskFlags("https://xn--zz.com/") & NYX_URL_LOOKALIKE);
    BOOST_CHECK(NyxUrlRiskFlags("https://example.com/%E2%80%AEfdp.exe") & NYX_URL_HIDDEN_CHARS);
    BOOST_CHECK(NyxUrlRiskFlags("https://example.com/a%E2%80%8Bb") & NYX_URL_HIDDEN_CHARS);
    BOOST_CHECK(NyxUrlRiskFlags("https://example.com/\xE2\x81\xA6x") & NYX_URL_HIDDEN_CHARS);
    BOOST_CHECK_EQUAL(NyxUrlRiskFlags("https://example.com/%C3%BC"), 0);
}

BOOST_AUTO_TEST_SUITE_END()
