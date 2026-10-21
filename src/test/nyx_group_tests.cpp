#include <boost/test/unit_test.hpp>

#include "nyxembed.h"
#include "nyxext.h"
#include "nyxgroup.h"

BOOST_AUTO_TEST_SUITE(nyx_group_tests)

static std::string Addr(char c)
{
    return std::string("i") + std::string(33, c);
}

static const std::string O = Addr('o');
static const std::string A = Addr('a');
static const std::string B = Addr('b');
static const std::string X = Addr('x');
static const unsigned char RND[16] = {7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
static const std::string RNDHEX = "070102030405060708090a0b0c0d0e0f";
static const std::string GID = NyxNewGroupId(O, 1000, RND);

static NyxGroupRec Roster(int epoch, const std::vector<std::string>& m, const std::string& name = "team")
{
    NyxGroupRec g;
    g.gid = GID;
    g.creator = O;
    g.createTime = 1000;
    g.rnd = RNDHEX;
    g.epoch = epoch;
    g.op = NYX_GOP_ROSTER;
    g.name = name;
    g.members = m;
    return g;
}

static NyxGroupRec Op(int epoch, int op, const std::string& addr = std::string())
{
    NyxGroupRec g;
    g.gid = GID;
    g.epoch = epoch;
    g.op = op;
    g.addr = addr;
    if (op == NYX_GOP_RENAME)
        g.name = addr;
    return g;
}

BOOST_AUTO_TEST_CASE(group_codec_roundtrip)
{
    std::vector<NyxGroupRec> recs;
    recs.push_back(Roster(0, {O, A, B}));
    recs.push_back(Op(3, NYX_GOP_ADD, X));
    recs.push_back(Op(4, NYX_GOP_REMOVE, A));
    recs.push_back(Op(5, NYX_GOP_LEAVE));
    recs.push_back(Op(6, NYX_GOP_RENAME, "new name"));
    recs.push_back(Op(7, NYX_GOP_OWNER, B));
    recs.push_back(Op(65535, NYX_GOP_MSG));
    for (const NyxGroupRec& g : recs)
    {
        std::string s = NyxEncodeGroup(g);
        BOOST_REQUIRE(!s.empty());
        BOOST_CHECK(s.find('\0') == std::string::npos);
        NyxGroupRec d;
        BOOST_REQUIRE(NyxDecodeGroup(s, d));
        BOOST_CHECK_EQUAL(d.gid, g.gid);
        BOOST_CHECK_EQUAL(d.epoch, g.epoch);
        BOOST_CHECK_EQUAL(d.op, g.op);
        BOOST_CHECK_EQUAL(d.addr, g.op == NYX_GOP_RENAME ? std::string() : g.addr);
        BOOST_CHECK_EQUAL(d.name, g.name);
        BOOST_CHECK(d.members == g.members);
        BOOST_CHECK_EQUAL(d.creator, g.creator);
        BOOST_CHECK_EQUAL(d.createTime, g.createTime);
        BOOST_CHECK_EQUAL(d.rnd, g.rnd);
    }
}

BOOST_AUTO_TEST_CASE(group_codec_strict)
{
    std::string s = NyxEncodeGroup(Roster(0, {O, A}));
    NyxGroupRec d;
    BOOST_CHECK(!NyxDecodeGroup(s + "x", d));             // trailing bytes
    BOOST_CHECK(!NyxDecodeGroup(s.substr(0, s.size() - 1), d));
    std::string bad = s;
    bad[1] = '\x02';
    BOOST_CHECK(!NyxDecodeGroup(bad, d));                 // version
    bad = s;
    bad[3] = 'G';
    BOOST_CHECK(!NyxDecodeGroup(bad, d));                 // gid hex
    std::string op = NyxEncodeGroup(Op(1, NYX_GOP_LEAVE));
    op[23] = '9';
    BOOST_CHECK(!NyxDecodeGroup(op, d));                  // unknown op
    BOOST_CHECK(NyxEncodeGroup(Roster(0, {O, O})).empty()); // duplicate member
    BOOST_CHECK(NyxEncodeGroup(Roster(0, {O, "anon"})).empty());
    BOOST_CHECK(NyxEncodeGroup(Roster(0, {O}, std::string(49, 'n'))).empty());
    BOOST_CHECK(NyxEncodeGroup(Op(70000, NYX_GOP_MSG)).empty());
}

BOOST_AUTO_TEST_CASE(group_max_ten_members)
{
    std::vector<std::string> m;
    for (int i = 0; i < 10; i++)
        m.push_back(Addr('a' + i));
    BOOST_CHECK(!NyxEncodeGroup(Roster(0, m)).empty());
    m.push_back(Addr('z'));
    BOOST_CHECK(NyxEncodeGroup(Roster(0, m)).empty());

    // Hand-built 11-member roster is refused on decode.
    m.pop_back();
    std::string s = NyxEncodeGroup(Roster(0, m));
    size_t countPos = 24 + 2 + 4;   // header, name length, "team"
    BOOST_REQUIRE_EQUAL(s.substr(countPos, 2), "0a");
    s.replace(countPos, 2, "0b");
    s += "22" + Addr('z');
    NyxGroupRec d;
    BOOST_CHECK(!NyxDecodeGroup(s, d));

    // An add past ten is not honoured.
    NyxGroupState st;
    m[0] = O;
    BOOST_REQUIRE(NyxGroupApply(st, O, 1, Roster(0, m)));
    BOOST_CHECK(!NyxGroupApply(st, O, 2, Op(1, NYX_GOP_ADD, Addr('z'))));
    BOOST_CHECK_EQUAL(st.members.size(), 10u);
}

BOOST_AUTO_TEST_CASE(group_membership_rules)
{
    NyxGroupState s;
    BOOST_CHECK(!NyxGroupApply(s, O, 1, Op(1, NYX_GOP_ADD, X)));    // no state yet
    BOOST_CHECK(!NyxGroupApply(s, X, 1, Roster(0, {O, A})));        // signer not in roster
    BOOST_REQUIRE(NyxGroupApply(s, O, 1, Roster(0, {A, O})));
    BOOST_CHECK_EQUAL(s.owner, O);
    BOOST_CHECK_EQUAL(s.members[0], O);                             // owner first

    BOOST_CHECK(!NyxGroupApply(s, A, 2, Op(1, NYX_GOP_ADD, X)));     // only the owner adds
    BOOST_CHECK(!NyxGroupApply(s, O, 2, Op(2, NYX_GOP_ADD, X)));     // epoch gap
    BOOST_CHECK(!NyxGroupApply(s, O, 2, Op(0, NYX_GOP_ADD, X)));     // replayed epoch
    BOOST_REQUIRE(NyxGroupApply(s, O, 2, Op(1, NYX_GOP_ADD, X)));
    BOOST_CHECK(!NyxGroupApply(s, O, 3, Op(2, NYX_GOP_ADD, X)));     // already a member
    BOOST_CHECK(!NyxGroupApply(s, A, 3, Op(2, NYX_GOP_REMOVE, X)));  // only the owner removes
    BOOST_CHECK(!NyxGroupApply(s, O, 3, Op(2, NYX_GOP_REMOVE, O)));  // owner cannot be removed
    BOOST_CHECK(!NyxGroupApply(s, O, 3, Op(2, NYX_GOP_LEAVE)));      // owner must hand over first
    BOOST_REQUIRE(NyxGroupApply(s, X, 3, Op(2, NYX_GOP_LEAVE)));     // any member leaves
    BOOST_CHECK(!s.IsMember(X));
    BOOST_CHECK(!NyxGroupApply(s, A, 4, Op(3, NYX_GOP_RENAME, "x"))); // only the owner renames
    BOOST_REQUIRE(NyxGroupApply(s, O, 4, Op(3, NYX_GOP_RENAME, "renamed")));
    BOOST_CHECK_EQUAL(s.name, "renamed");
    BOOST_CHECK(!NyxGroupApply(s, O, 5, Op(4, NYX_GOP_OWNER, X)));   // new owner must be a member
    BOOST_REQUIRE(NyxGroupApply(s, O, 5, Op(4, NYX_GOP_OWNER, A)));
    BOOST_CHECK_EQUAL(s.owner, A);
    BOOST_CHECK(!NyxGroupApply(s, O, 6, Op(5, NYX_GOP_REMOVE, A)));  // old owner lost authority
    BOOST_REQUIRE(NyxGroupApply(s, A, 6, Op(5, NYX_GOP_REMOVE, O)));
    BOOST_CHECK_EQUAL(s.members.size(), 1u);
    BOOST_CHECK_EQUAL(s.epoch, 5);
}

BOOST_AUTO_TEST_CASE(group_message_authentication)
{
    NyxGroupState s;
    BOOST_REQUIRE(NyxGroupApply(s, O, 100, Roster(0, {O, A, B})));
    BOOST_CHECK(NyxGroupMsgAllowed(s, A, 110, 0));
    BOOST_CHECK(!NyxGroupMsgAllowed(s, X, 110, 0));        // outside the roster
    BOOST_CHECK(!NyxGroupMsgAllowed(s, "anon", 110, 0));
    BOOST_CHECK(!NyxGroupMsgAllowed(s, A, 110, 1));        // epoch not seen yet: held back
    BOOST_REQUIRE(NyxGroupApply(s, O, 200, Op(1, NYX_GOP_REMOVE, B)));
    BOOST_CHECK(NyxGroupMsgAllowed(s, B, 150, 0));         // before removal
    BOOST_CHECK(!NyxGroupMsgAllowed(s, B, 250, 0));        // after removal, stale epoch
    BOOST_CHECK(!NyxGroupMsgAllowed(s, B, 250, 1));
    BOOST_REQUIRE(NyxGroupApply(s, O, 300, Op(2, NYX_GOP_ADD, X)));
    BOOST_CHECK(!NyxGroupMsgAllowed(s, X, 310, 1));        // not a member at epoch 1
    BOOST_CHECK(NyxGroupMsgAllowed(s, X, 310, 2));
}

BOOST_AUTO_TEST_CASE(group_build_replays_in_epoch_order)
{
    std::vector<NyxGroupEvent> ev;
    NyxGroupEvent e;
    e.sender = O; e.ts = 300; e.mid = "m3"; e.rec = Op(2, NYX_GOP_RENAME, "late");
    ev.push_back(e);
    e.sender = O; e.ts = 200; e.mid = "m2"; e.rec = Op(1, NYX_GOP_ADD, X);
    ev.push_back(e);
    ev.push_back(e);                                       // outbox duplicate
    e.sender = A; e.ts = 250; e.mid = "m9"; e.rec = Op(2, NYX_GOP_RENAME, "forged");
    ev.push_back(e);                                       // non-owner, same epoch
    e.sender = O; e.ts = 100; e.mid = "m1"; e.rec = Roster(0, {O, A});
    ev.push_back(e);
    e.sender = "anon"; e.ts = 50; e.mid = "m0"; e.rec = Roster(0, {A});
    ev.push_back(e);
    std::map<std::string, NyxGroupState> g = NyxBuildGroups(ev);
    BOOST_REQUIRE_EQUAL(g.size(), 1u);
    const NyxGroupState& s = g[GID];
    BOOST_CHECK_EQUAL(s.owner, O);
    BOOST_CHECK_EQUAL(s.name, "late");
    BOOST_CHECK_EQUAL(s.epoch, 2);
    BOOST_CHECK_EQUAL(s.members.size(), 3u);
}

BOOST_AUTO_TEST_CASE(group_plain_and_records)
{
    NyxGroupRec g = Op(0, NYX_GOP_MSG);
    NyxReply r;
    r.mid = "fedcba9876543210";
    r.quote = "original";
    std::string full = NyxGroupPlain("team", "hello", g, {NyxEncodeReply(r)}, 4096);
    BOOST_REQUIRE(!full.empty());
    std::string text, ext;
    NyxSplitPlain(full, text, ext);
    BOOST_CHECK_EQUAL(text, "[group: team] hello");
    BOOST_CHECK_EQUAL(NyxStripGroupFallback(text), "hello");
    NyxRecords recs = NyxParseRecords(ext);
    BOOST_CHECK(recs.fGroup);
    BOOST_CHECK_EQUAL(recs.group.gid, GID);
    BOOST_CHECK(recs.fReply);
    BOOST_CHECK(recs.embedRec.empty());
    BOOST_CHECK(NyxGroupPlain("team", std::string(5000, 'x'), g, {}, 4096).empty());
    BOOST_CHECK_EQUAL(NyxStripGroupFallback("[group: x no close"), "[group: x no close");
}

BOOST_AUTO_TEST_CASE(group_hijack_earlier_timestamp_rejected)
{
    // A member replays the gid with an earlier timestamp and a lower mid to claim ownership.
    std::vector<NyxGroupEvent> ev;
    NyxGroupEvent e;
    e.sender = O; e.ts = 1000; e.mid = "m5"; e.rec = Roster(0, {O, A, B});
    ev.push_back(e);
    NyxGroupRec forged = Roster(0, {A, O, B}, "mine");
    forged.creator = A;
    e.sender = A; e.ts = 1; e.mid = "m0"; e.rec = forged;
    ev.push_back(e);
    NyxGroupRec claim = Roster(0, {A, O, B}, "mine");   // claims O as creator, signed by A
    e.sender = A; e.ts = 2; e.mid = "m1"; e.rec = claim;
    ev.push_back(e);
    std::map<std::string, NyxGroupState> g = NyxBuildGroups(ev);
    BOOST_REQUIRE_EQUAL(g.size(), 1u);
    BOOST_CHECK_EQUAL(g[GID].owner, O);
    BOOST_CHECK_EQUAL(g[GID].name, "team");

    // Without the genesis, the member's rosters alone open nothing.
    ev.erase(ev.begin());
    BOOST_CHECK(NyxBuildGroups(ev).empty());

    // A member cannot push a later roster either.
    NyxGroupState s;
    BOOST_REQUIRE(NyxGroupApply(s, O, 1000, Roster(0, {O, A})));
    BOOST_CHECK(!NyxGroupApply(s, A, 1, Roster(1, {A, O})));
    BOOST_CHECK_EQUAL(s.owner, O);
}

BOOST_AUTO_TEST_CASE(group_forged_genesis_rejected)
{
    NyxGroupState s;
    NyxGroupRec r = Roster(0, {O, A});
    r.gid = "0123456789abcdef";                           // not bound to O
    BOOST_CHECK(!NyxGroupApply(s, O, 1, r));
    r = Roster(0, {O, A});
    r.createTime = 999;
    BOOST_CHECK(!NyxGroupApply(s, O, 1, r));
    r = Roster(0, {O, A});
    r.rnd[1] = '8';
    BOOST_CHECK(!NyxGroupApply(s, O, 1, r));
    r = Roster(0, {A, X});                                // creator outside the roster
    BOOST_CHECK(!NyxGroupApply(s, O, 1, r));
    BOOST_CHECK(!s.fValid);
    BOOST_CHECK(NyxGroupIdBinds(GID, O, 1000, RNDHEX));
    BOOST_CHECK(!NyxGroupIdBinds(GID, A, 1000, RNDHEX));
    BOOST_CHECK(!NyxGroupIdBinds(GID, O, 1000, "07"));
}

BOOST_AUTO_TEST_CASE(group_legit_flow_and_handover)
{
    std::vector<NyxGroupEvent> ev;
    NyxGroupEvent e;
    e.sender = O; e.ts = 1000; e.mid = "z1"; e.rec = Roster(0, {O, A});
    ev.push_back(e);
    e.sender = O; e.ts = 900; e.mid = "a2"; e.rec = Op(1, NYX_GOP_ADD, B);  // skewed clock
    ev.push_back(e);
    e.sender = O; e.ts = 1100; e.mid = "a3"; e.rec = Op(2, NYX_GOP_OWNER, A);
    ev.push_back(e);
    e.sender = A; e.ts = 1200; e.mid = "a4"; e.rec = Op(3, NYX_GOP_RENAME, "by A");
    ev.push_back(e);
    e.sender = O; e.ts = 1300; e.mid = "a5"; e.rec = Op(4, NYX_GOP_RENAME, "by O");
    ev.push_back(e);                                     // old owner, no authority
    std::map<std::string, NyxGroupState> g = NyxBuildGroups(ev);
    BOOST_REQUIRE_EQUAL(g.size(), 1u);
    const NyxGroupState& s = g[GID];
    BOOST_CHECK_EQUAL(s.owner, A);
    BOOST_CHECK_EQUAL(s.creator, O);
    BOOST_CHECK_EQUAL(s.name, "by A");
    BOOST_CHECK_EQUAL(s.epoch, 3);
    BOOST_CHECK_EQUAL(s.members.size(), 3u);

    // A new member opens the group from the creator's later snapshot.
    NyxGroupState j;
    BOOST_CHECK(!NyxGroupApply(j, A, 1, Roster(4, {O, A, B, X})));
    BOOST_REQUIRE(NyxGroupApply(j, O, 1, Roster(4, {O, A, B, X})));
    BOOST_CHECK_EQUAL(j.epoch, 4);
}

BOOST_AUTO_TEST_CASE(group_id_and_typing)
{
    unsigned char r1[16] = {1}, r2[16] = {2};
    std::string a = NyxNewGroupId(O, 1000, r1);
    BOOST_CHECK(NyxIsHexId(a));
    BOOST_CHECK(a != NyxNewGroupId(O, 1000, r2));
    BOOST_CHECK(a != NyxNewGroupId(A, 1000, r1));
    bool on = false;
    BOOST_CHECK(NyxDecodeTyping(NyxEncodeTyping(true), on) && on);
    BOOST_CHECK(NyxDecodeTyping(NyxEncodeTyping(false), on) && !on);
    BOOST_CHECK(!NyxDecodeTyping(std::string("T\x01\x03", 3), on));
    BOOST_CHECK(NyxParseRecords(NyxEncodeTyping(true)).fTyping);
}

BOOST_AUTO_TEST_SUITE_END()
