#include <boost/test/unit_test.hpp>

#include "nyxembed.h"
#include "smessage.h"

BOOST_AUTO_TEST_SUITE(nyx_embed_tests)

static NyxEmbed Sample()
{
    NyxEmbed e;
    e.id = "0123456789abcdef";
    e.url = "https://priscus.ai/";
    e.title = "Priscus";
    e.desc = "A description";
    e.site = "priscus.ai";
    e.thumb = std::string("\xFF\xD8\xFF\xE0", 4) + std::string(200, 'x');
    return e;
}

BOOST_AUTO_TEST_CASE(embed_roundtrip_and_legacy_view)
{
    NyxEmbed e = Sample(), d;
    std::string full = NyxComposePlain("see https://priscus.ai/", NyxEncodeEmbed(e));
    // v5.0 clients read the plaintext as a C string.
    BOOST_CHECK_EQUAL(std::string(full.c_str()), "see https://priscus.ai/");
    std::string text, ext;
    NyxSplitPlain(full, text, ext);
    BOOST_CHECK_EQUAL(text, "see https://priscus.ai/");
    BOOST_CHECK(NyxDecodeEmbed(ext, d));
    BOOST_CHECK_EQUAL(d.id, e.id);
    BOOST_CHECK_EQUAL(d.url, e.url);
    BOOST_CHECK_EQUAL(d.title, e.title);
    BOOST_CHECK(d.thumb == e.thumb);

    NyxSplitPlain("plain", text, ext);
    BOOST_CHECK_EQUAL(text, "plain");
    BOOST_CHECK(ext.empty());
    BOOST_CHECK(!NyxDecodeEmbed(ext, d));
}

BOOST_AUTO_TEST_CASE(embed_decode_rejects_hostile)
{
    NyxEmbed e = Sample(), d;
    e.url = "javascript:alert(1)";
    BOOST_CHECK(!NyxDecodeEmbed(NyxEncodeEmbed(e), d));
    e.url = "http://priscus.ai/";
    BOOST_CHECK(!NyxDecodeEmbed(NyxEncodeEmbed(e), d));
    e.url = "https://user@evil.example/";
    BOOST_CHECK(!NyxDecodeEmbed(NyxEncodeEmbed(e), d));
    e = Sample();
    e.thumb = "GIF89a....";
    BOOST_CHECK(!NyxDecodeEmbed(NyxEncodeEmbed(e), d));
    e = Sample();
    e.thumb = std::string("\xFF\xD8\xFF", 3) + std::string(NYX_EMBED_MAX_THUMB, 'x');
    BOOST_CHECK(!NyxDecodeEmbed(NyxEncodeEmbed(e), d));
    e = Sample();
    e.id = "XYZ";
    BOOST_CHECK(!NyxDecodeEmbed(NyxEncodeEmbed(e), d));
    BOOST_CHECK(!NyxDecodeEmbed("nyx-embed:1:0123456789abcdef:!!!:a:b:c:d", d));
    BOOST_CHECK(!NyxDecodeEmbed("nyx-embed:2:" + NyxEncodeEmbed(Sample()).substr(12), d));

    // Control characters, bidi overrides and oversize fields are cleaned.
    e = Sample();
    e.title = std::string("a\x01" "b\xE2\x80\xAE" "c") + std::string(500, 'z');
    BOOST_CHECK(NyxDecodeEmbed(NyxEncodeEmbed(e), d));
    BOOST_CHECK(d.title.compare(0, 3, "abc") == 0);
    BOOST_CHECK(d.title.size() <= NYX_EMBED_MAX_TITLE);
}

BOOST_AUTO_TEST_CASE(embed_fits_message_cap)
{
    NyxEmbed e = Sample();
    e.thumb = std::string("\xFF\xD8\xFF", 3) + std::string(NYX_EMBED_MAX_THUMB - 3, 'x');
    std::string ext = NyxFitEmbed("hi", e, SMSG_MAX_MSG_BYTES);
    BOOST_CHECK(!ext.empty());
    BOOST_CHECK(2 + 1 + ext.size() <= SMSG_MAX_MSG_BYTES);

    // Long text: thumbnail is dropped first.
    std::string big(3500, 'a');
    ext = NyxFitEmbed(big, e, SMSG_MAX_MSG_BYTES);
    NyxEmbed d;
    BOOST_CHECK(!ext.empty());
    BOOST_CHECK(big.size() + 1 + ext.size() <= SMSG_MAX_MSG_BYTES);
    BOOST_CHECK(NyxDecodeEmbed(ext, d));
    BOOST_CHECK(d.thumb.empty());

    // No room at all.
    BOOST_CHECK(NyxFitEmbed(std::string(4090, 'a'), e, SMSG_MAX_MSG_BYTES).empty());
}

BOOST_AUTO_TEST_CASE(removal_authenticated_by_sender)
{
    std::string id;
    std::string full = NyxRemovalPlain("0123456789abcdef");
    BOOST_CHECK_EQUAL(std::string(full.c_str()), NYX_CTL_VISIBLE);
    std::string text, ext;
    NyxSplitPlain(full, text, ext);
    BOOST_CHECK(NyxDecodeRemoval(ext, id));
    BOOST_CHECK_EQUAL(id, "0123456789abcdef");
    BOOST_CHECK(!NyxDecodeRemoval(ext + "0", id));
    BOOST_CHECK(!NyxDecodeRemoval("nyx-ctl:1:rmembed:0123456789ABCDEF", id));

    std::vector<std::pair<std::string, std::string> > rm;
    rm.push_back(std::make_pair(std::string("iMallory"), std::string("0123456789abcdef")));
    BOOST_CHECK(!NyxEmbedHidden("iAlice", "0123456789abcdef", rm));
    rm.push_back(std::make_pair(std::string("iAlice"), std::string("0123456789abcdef")));
    BOOST_CHECK(NyxEmbedHidden("iAlice", "0123456789abcdef", rm));
    BOOST_CHECK(!NyxEmbedHidden("iAlice", "fedcba9876543210", rm));
    rm.push_back(std::make_pair(std::string("anon"), std::string("1111111111111111")));
    BOOST_CHECK(!NyxEmbedHidden("anon", "1111111111111111", rm));
}

BOOST_AUTO_TEST_CASE(linkify_escapes_first)
{
    BOOST_CHECK_EQUAL(NyxLinkify("<b>hi</b> & \"x\""), "&lt;b&gt;hi&lt;/b&gt; &amp; &quot;x&quot;");
    BOOST_CHECK_EQUAL(NyxLinkify("go https://priscus.ai."),
                      "go <a href=\"https://priscus.ai\">https://priscus.ai</a>.");
    BOOST_CHECK_EQUAL(NyxLinkify("a\nb"), "a<br>b");
    BOOST_CHECK_EQUAL(NyxLinkify("https://x.io/?a=1&b=2"),
                      "<a href=\"https://x.io/?a=1&amp;b=2\">https://x.io/?a=1&amp;b=2</a>");
    // Attribute breakout attempts stop at the quote.
    BOOST_CHECK_EQUAL(NyxLinkify("https://x.io/\"onmouseover=\"a"),
                      "<a href=\"https://x.io/\">https://x.io/</a>&quot;onmouseover=&quot;a");
    BOOST_CHECK_EQUAL(NyxLinkify("javascript:alert(1)"), "javascript:alert(1)");
    BOOST_CHECK_EQUAL(NyxLinkify("data:text/html,<x>"), "data:text/html,&lt;x&gt;");
    BOOST_CHECK_EQUAL(NyxLinkify("xhttps://a.io"), "xhttps://a.io");
    BOOST_CHECK_EQUAL(NyxLinkify("https://user@evil.io"), "https://user@evil.io");
    BOOST_CHECK_EQUAL(NyxLinkify("(https://a.io)"), "(<a href=\"https://a.io\">https://a.io</a>)");
    BOOST_CHECK_EQUAL(NyxFirstHttpsUrl("http://a.io then https://b.io/x, ok"), "https://b.io/x");
    BOOST_CHECK(NyxFirstHttpsUrl("none here").empty());
}

BOOST_AUTO_TEST_CASE(fetchable_host_rules)
{
    BOOST_CHECK(NyxIsFetchableHost("priscus.ai", false));
    BOOST_CHECK(!NyxIsFetchableHost("127.0.0.1", false));
    BOOST_CHECK(!NyxIsFetchableHost("localhost", false));
    BOOST_CHECK(!NyxIsFetchableHost("router.local", false));
    BOOST_CHECK(!NyxIsFetchableHost("abc.onion", false));
    BOOST_CHECK(NyxIsFetchableHost("abc.onion", true));
    BOOST_CHECK(!NyxIsFetchableHost("0x7f.1", false));
    BOOST_CHECK(!NyxIsFetchableHost("intranet", false));
    BOOST_CHECK(NyxUrlHost("https://a.io:8443/x").size() == 4);
    BOOST_CHECK(NyxUrlHost("https://a.io:/x").empty());

    unsigned char v4[4] = {192, 168, 1, 5};
    BOOST_CHECK(!NyxIsPublicAddress(v4, 4));
    unsigned char v4b[4] = {93, 184, 216, 34};
    BOOST_CHECK(NyxIsPublicAddress(v4b, 4));
    unsigned char v6[16] = {0};
    v6[15] = 1;
    BOOST_CHECK(!NyxIsPublicAddress(v6, 16));
    unsigned char mapped[16] = {0,0,0,0,0,0,0,0,0,0,0xFF,0xFF,10,0,0,1};
    BOOST_CHECK(!NyxIsPublicAddress(mapped, 16));
    unsigned char v6pub[16] = {0x26,0x06,0x47,0x00,0,0,0,0,0,0,0,0,0,0,0,1};
    BOOST_CHECK(NyxIsPublicAddress(v6pub, 16));
}

BOOST_AUTO_TEST_CASE(head_parser_hostile_html)
{
    std::string html =
        "<html><head><!-- <meta property=\"og:title\" content=\"COMMENT\"> -->"
        "<script>var s='<meta property=\"og:title\" content=\"SCRIPT\">';</script>"
        "<title>Fallback &amp; Title</title>"
        "<meta property='og:title' content='Priscus &#x26; Co &lt;b&gt;\x01'>"
        "<meta name=description content=Unquoted>"
        "<meta property=\"og:image\" content=\"/img/a.png\">"
        "</head><body><meta property=\"og:site_name\" content=\"BODY\"></body></html>";
    NyxPageMeta m = NyxParseHead(html, "https://priscus.ai/page");
    BOOST_CHECK_EQUAL(m.title, "Priscus & Co <b>");
    BOOST_CHECK_EQUAL(m.desc, "Unquoted");
    BOOST_CHECK_EQUAL(m.site, "priscus.ai");
    BOOST_CHECK_EQUAL(m.image, "https://priscus.ai/img/a.png");

    m = NyxParseHead("<head><title>Only</title><meta property=og:image content=\"javascript:x\">", "https://a.io/");
    BOOST_CHECK_EQUAL(m.title, "Only");
    BOOST_CHECK(m.image.empty());

    m = NyxParseHead("<head><meta property=\"og:image\" content=\"http://a.io/x.png\">", "https://a.io/");
    BOOST_CHECK(m.image.empty());

    // Truncated and garbage input does not crash or loop.
    NyxParseHead("<", "https://a.io/");
    NyxParseHead("<meta content=\"", "https://a.io/");
    NyxParseHead(std::string(100000, '<'), "https://a.io/");
    NyxParseHead("<title>unterminated", "https://a.io/");
    m = NyxParseHead("<title>&#0;&#xD800;&#99999999;ok</title>", "https://a.io/");
    BOOST_CHECK_EQUAL(m.title, "ok");
}

BOOST_AUTO_TEST_SUITE_END()
