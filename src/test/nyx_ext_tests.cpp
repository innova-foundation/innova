#include <boost/test/unit_test.hpp>

#include "nyxembed.h"
#include "nyxext.h"

BOOST_AUTO_TEST_SUITE(nyx_ext_tests)

static const std::string A = "iAliceAddressxxxxxxxxxxxxxxxxxxxxx";
static const std::string B = "iBobAddressxxxxxxxxxxxxxxxxxxxxxxx";
static const std::string THUMB = "\xF0\x9F\x91\x8D";   // thumbs up
static const std::string HEART = "\xE2\x9D\xA4\xEF\xB8\x8F";

static NyxThreadMsg Msg(const std::string& from, int64_t ts, const std::string& full)
{
    NyxThreadMsg m;
    m.sender = from;
    m.ts = ts;
    m.mid = NyxMessageId(from, ts, full);
    NyxSplitPlain(full, m.text, m.ext);
    return m;
}

static bool AllowAll(const std::string&) { return true; }

BOOST_AUTO_TEST_CASE(message_id_is_stable_and_bound)
{
    std::string id = NyxMessageId(A, 1000, "hi");
    BOOST_CHECK(NyxIsHexId(id));
    BOOST_CHECK_EQUAL(id, NyxMessageId(A, 1000, "hi"));
    BOOST_CHECK(id != NyxMessageId(B, 1000, "hi"));
    BOOST_CHECK(id != NyxMessageId(A, 1001, "hi"));
    BOOST_CHECK(id != NyxMessageId(A, 1000, "hi!"));
}

BOOST_AUTO_TEST_CASE(codecs_roundtrip_and_old_client_view)
{
    const std::string mid = NyxMessageId(A, 1, "x");
    NyxReply r; r.mid = mid; r.quote = "original text";
    std::string full = NyxReplyPlain("my reply", r, std::string(), 4096);
    BOOST_CHECK_EQUAL(std::string(full.c_str()), "my reply");
    std::string text, ext;
    NyxSplitPlain(full, text, ext);
    BOOST_CHECK(ext.find('\0') == std::string::npos);
    NyxRecords rec = NyxParseRecords(ext);
    BOOST_CHECK(rec.fReply && rec.reply.mid == mid && rec.reply.quote == "original text");
    BOOST_CHECK(!rec.IsControl());

    NyxReact k; k.mid = mid; k.emoji = THUMB;
    full = NyxReactPlain(k);
    BOOST_CHECK_EQUAL(std::string(full.c_str()), "[reacted " + THUMB + "]");
    NyxSplitPlain(full, text, ext);
    rec = NyxParseRecords(ext);
    BOOST_CHECK(rec.fReact && rec.react.fAdd && rec.react.emoji == THUMB && rec.IsControl());

    NyxEdit e; e.mid = mid; e.seq = 1;
    full = NyxEditPlain("fixed", e, 4096);
    BOOST_CHECK_EQUAL(std::string(full.c_str()), "[edited] fixed");
    NyxSplitPlain(full, text, ext);
    rec = NyxParseRecords(ext);
    BOOST_CHECK(rec.fEdit && rec.edit.seq == 1);

    full = NyxDeletePlain(mid);
    BOOST_CHECK_EQUAL(std::string(full.c_str()), "[message deleted]");
    NyxSplitPlain(full, text, ext);
    rec = NyxParseRecords(ext);
    BOOST_CHECK(rec.fDelete && rec.delMid == mid);

    // Reply alongside an embed record.
    NyxEmbed em; em.id = "0123456789abcdef"; em.url = "https://priscus.ai/"; em.title = "t";
    full = NyxReplyPlain("see https://priscus.ai/", r, NyxEncodeEmbed(em), 4096);
    NyxSplitPlain(full, text, ext);
    rec = NyxParseRecords(ext);
    NyxEmbed d;
    BOOST_CHECK(rec.fReply && NyxDecodeEmbed(rec.embedRec, d) && d.id == em.id);
}

BOOST_AUTO_TEST_CASE(strict_decoding)
{
    const std::string mid = NyxMessageId(A, 1, "x");
    NyxReact k;
    BOOST_CHECK(!NyxDecodeReact("K\x01" + mid.substr(0, 15) + "G\x01" "04" + THUMB, k));
    BOOST_CHECK(!NyxDecodeReact("K\x01" + mid + "\x03" "04" + THUMB, k));
    BOOST_CHECK(!NyxDecodeReact("K\x01" + mid + "\x01" "05" + THUMB, k));
    BOOST_CHECK(!NyxDecodeReact("K\x02" + mid + "\x01" "04" + THUMB, k));
    k.mid = mid; k.emoji = "abc";
    BOOST_CHECK(NyxEncodeReact(k).empty());
    BOOST_CHECK(!NyxIsReactionEmoji(std::string(5, '\xF0')));
    BOOST_CHECK(!NyxIsReactionEmoji(THUMB + " "));
    BOOST_CHECK(NyxIsReactionEmoji(HEART));
    NyxEdit e;
    BOOST_CHECK(!NyxDecodeEdit("E\x01" + mid + "00", e));
    BOOST_CHECK(!NyxDecodeEdit("E\x01" + mid + "1", e));
    std::string m;
    BOOST_CHECK(!NyxDecodeDelete("D\x01" + mid + "x", m));
    std::vector<std::string> v;
    BOOST_CHECK(!NyxSplitRecords("M\x01" "0005abc", v));
    BOOST_CHECK(!NyxSplitRecords("M\x01" "0003abc", v));  // one record must not use the wrapper
    // Unknown tag is not a control.
    BOOST_CHECK(!NyxParseRecords("Z\x01" + mid).IsControl());
}

BOOST_AUTO_TEST_CASE(only_original_sender_edits_and_deletes)
{
    std::vector<NyxThreadMsg> rows;
    rows.push_back(Msg(A, 100, "hello"));
    const std::string mid = rows[0].mid;
    NyxEdit e; e.mid = mid; e.seq = 1;
    rows.push_back(Msg(B, 110, NyxEditPlain("forged", e, 4096)));
    rows.push_back(Msg("anon", 111, NyxEditPlain("anon forged", e, 4096)));
    std::vector<NyxMsgView> v = NyxBuildThread(rows, AllowAll);
    BOOST_CHECK(!v[0].fEdited && v[0].text == "hello");
    BOOST_CHECK(v[1].fControl);
    BOOST_CHECK(!v[2].fControl);   // anon carries no authority: plain text row

    rows.push_back(Msg(A, 120, NyxEditPlain("hello v2", e, 4096)));
    e.seq = 2;
    rows.push_back(Msg(A, 119, NyxEditPlain("hello v3", e, 4096)));  // higher seq wins regardless of time
    v = NyxBuildThread(rows, AllowAll);
    BOOST_CHECK(v[0].fEdited && v[0].text == "hello v3" && v[0].seq == 2);

    // Edit after the window is ignored.
    e.seq = 3;
    rows.push_back(Msg(A, 100 + NYX_EDIT_WINDOW + 1, NyxEditPlain("late", e, 4096)));
    v = NyxBuildThread(rows, AllowAll);
    BOOST_CHECK_EQUAL(v[0].text, "hello v3");

    // Forged delete is ignored, the owner's delete wins over edits.
    rows.push_back(Msg(B, 130, NyxDeletePlain(mid)));
    v = NyxBuildThread(rows, AllowAll);
    BOOST_CHECK(!v[0].fTombstone);
    rows.push_back(Msg(A, 131, NyxDeletePlain(mid)));
    v = NyxBuildThread(rows, AllowAll);
    BOOST_CHECK(v[0].fTombstone && !v[0].fEdited && v[0].text == NYX_DELETED_TEXT);

    // Original wiped: the delete row itself renders as the tombstone.
    std::vector<NyxThreadMsg> wiped(1, Msg(A, 131, NyxDeletePlain(mid)));
    v = NyxBuildThread(wiped, AllowAll);
    BOOST_CHECK(v[0].fTombstone && !v[0].fControl);
}

BOOST_AUTO_TEST_CASE(reactions_dedup_toggle_and_gate)
{
    std::vector<NyxThreadMsg> rows;
    rows.push_back(Msg(A, 100, "hello"));
    NyxReact k; k.mid = rows[0].mid; k.emoji = THUMB;
    rows.push_back(Msg(B, 101, NyxReactPlain(k)));
    rows.push_back(Msg(B, 102, NyxReactPlain(k)));   // duplicate add
    rows.push_back(Msg(A, 103, NyxReactPlain(k)));
    std::vector<NyxMsgView> v = NyxBuildThread(rows, AllowAll);
    BOOST_REQUIRE_EQUAL(v[0].reactions.size(), 1u);
    BOOST_CHECK_EQUAL(v[0].reactions[0].second.size(), 2u);

    k.fAdd = false;
    rows.push_back(Msg(B, 104, NyxReactPlain(k)));
    rows.push_back(Msg(B, 104, NyxReactPlain(k)));   // remove is idempotent
    v = NyxBuildThread(rows, AllowAll);
    BOOST_REQUIRE_EQUAL(v[0].reactions.size(), 1u);
    BOOST_CHECK(v[0].reactions[0].second == std::vector<std::string>(1, A));

    // Gate: B is not an accepted contact; anon never counts.
    k.fAdd = true;
    rows.push_back(Msg(B, 105, NyxReactPlain(k)));
    rows.push_back(Msg("anon", 106, NyxReactPlain(k)));
    v = NyxBuildThread(rows, [](const std::string& s) { return s == A; });
    BOOST_CHECK_EQUAL(v[0].reactions[0].second.size(), 1u);
    BOOST_CHECK(!v[7].fControl);
}

BOOST_AUTO_TEST_CASE(reaction_spam_caps)
{
    static const char* emoji[] = {"\xF0\x9F\x98\x80", "\xF0\x9F\x98\x81", "\xF0\x9F\x98\x82", "\xF0\x9F\x98\x83",
                                  "\xF0\x9F\x98\x84", "\xF0\x9F\x98\x85", "\xF0\x9F\x98\x86", "\xF0\x9F\x98\x87",
                                  "\xF0\x9F\x98\x88", "\xF0\x9F\x98\x89"};
    std::vector<NyxThreadMsg> rows;
    rows.push_back(Msg(A, 100, "hello"));
    NyxReact k; k.mid = rows[0].mid;
    for (int i = 0; i < 10; i++)
    {
        k.emoji = emoji[i];
        rows.push_back(Msg(B, 101 + i, NyxReactPlain(k)));
    }
    std::vector<NyxMsgView> v = NyxBuildThread(rows, AllowAll);
    BOOST_CHECK_EQUAL(v[0].reactions.size(), NYX_REACT_MAX_EMOJI);

    // Rate: ops beyond 20 per 10 minutes are dropped; the window then reopens.
    rows.resize(1);
    for (int i = 0; i < 30; i++)
    {
        k.emoji = emoji[0];
        k.fAdd = (i % 2) == 0;
        rows.push_back(Msg(B, 200 + i, NyxReactPlain(k)));
    }
    v = NyxBuildThread(rows, AllowAll);
    BOOST_CHECK(v[0].reactions.empty());   // op 20 (a remove) was the last one honoured
    k.fAdd = true;
    rows.push_back(Msg(B, 200 + 25, NyxReactPlain(k)));
    v = NyxBuildThread(rows, AllowAll);
    BOOST_CHECK(v[0].reactions.empty());
    rows.push_back(Msg(B, 200 + NYX_REACT_WINDOW + 1, NyxReactPlain(k)));
    v = NyxBuildThread(rows, AllowAll);
    BOOST_CHECK_EQUAL(v[0].reactions.size(), 1u);
}

BOOST_AUTO_TEST_CASE(reply_resolution)
{
    std::vector<NyxThreadMsg> rows;
    rows.push_back(Msg(A, 100, "question"));
    NyxReply r; r.mid = rows[0].mid; r.quote = "misquoted";
    rows.push_back(Msg(B, 101, NyxReplyPlain("answer", r, std::string(), 4096)));
    r.mid = NyxMessageId(A, 1, "gone");
    rows.push_back(Msg(B, 102, NyxReplyPlain("to a pruned one", r, std::string(), 4096)));
    std::vector<NyxMsgView> v = NyxBuildThread(rows, AllowAll);
    BOOST_CHECK(v[1].fReply && v[1].replyIndex == 0 && v[1].text == "answer");
    BOOST_CHECK(v[2].fReply && v[2].replyIndex == -1 && v[2].reply.quote == "misquoted");
}

BOOST_AUTO_TEST_SUITE_END()
