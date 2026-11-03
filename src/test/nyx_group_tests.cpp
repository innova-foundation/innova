#include <boost/test/unit_test.hpp>

#include "nyxembed.h"
#include "nyxext.h"
#include "nyxgroup.h"

#include <algorithm>
#include <map>
#include <stdio.h>

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

// Fake signatures: (digest, sig) -> signer.
static std::map<std::string, std::string> g_sigs;
static std::string DigestHex(const unsigned char d[32])
{
    static const char* x = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < 32; i++)
    {
        s.push_back(x[d[i] >> 4]);
        s.push_back(x[d[i] & 15]);
    }
    return s;
}
static size_t g_recovers = 0;
static std::string FakeRecover(const unsigned char d[32], const std::string& sig)
{
    g_recovers++;
    std::map<std::string, std::string>::const_iterator it = g_sigs.find(DigestHex(d) + sig);
    return it == g_sigs.end() ? std::string() : it->second;
}
struct FakeSigs
{
    FakeSigs() { NyxGroupSetRecover(FakeRecover); }
    ~FakeSigs() { NyxGroupSetRecover(0); }
};
static void Sign(NyxGroupRec& g, const std::string& who)
{
    static int n = 0;
    char buf[16];
    snprintf(buf, sizeof(buf), "%08x", ++n);
    g.sig = std::string(122, '0') + buf;
    unsigned char d[32];
    NyxGroupDigest(g, d);
    g_sigs[DigestHex(d) + g.sig] = who;
}

static NyxGroupRec Roster(int epoch, const std::vector<std::string>& m, const std::string& name = "team",
                          const std::string& creator = O)
{
    NyxGroupRec g;
    g.creator = creator;
    g.createTime = 1000;
    g.rnd = RNDHEX;
    g.epoch = epoch;
    g.op = NYX_GOP_ROSTER;
    g.name = name;
    g.members = m;
    g.gid = NyxNewGroupId(creator, 1000, RND, name, m);
    return g;
}

static const NyxGroupRec G0 = Roster(0, {O, A});
static const std::string GID = G0.gid;

// Chained op on top of a state, signed by who.
static NyxGroupRec Next(const NyxGroupState& s, int op, const std::string& arg, const std::string& who)
{
    NyxGroupRec g;
    g.gid = s.gid;
    g.epoch = s.epoch + 1;
    g.op = op;
    g.prev = s.head;
    if (op == NYX_GOP_RENAME)
        g.name = arg;
    else
        g.addr = arg;
    Sign(g, who);
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
    if (op == NYX_GOP_MSG || op == NYX_GOP_SYNC)
        g.prev = std::string(32, 'a');
    if (NyxGroupOpSigned(op))
    {
        g.prev = std::string(32, 'a');
        Sign(g, O);
    }
    return g;
}

// Leave signed by who, pinned to the state's head.
static NyxGroupRec Leave(const NyxGroupState& s, const std::string& who)
{
    NyxGroupRec g;
    g.gid = s.gid;
    g.epoch = s.epoch;
    g.op = NYX_GOP_LEAVE;
    g.prev = s.head;
    Sign(g, who);
    return g;
}

static NyxGroupEvent Ev(const std::string& sender, int64_t ts, const std::string& mid, const NyxGroupRec& r)
{
    NyxGroupEvent e;
    e.sender = sender;
    e.ts = ts;
    e.mid = mid;
    e.rec = r;
    return e;
}

BOOST_GLOBAL_FIXTURE(FakeSigs);

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
    recs.push_back(Op(3, NYX_GOP_SYNC));
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
        BOOST_CHECK_EQUAL(d.prev, g.prev);
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
    op[2 + NYX_GID_HEX + 4 + 1] = '9';
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
    size_t countPos = 8 + NYX_GID_HEX + 2 + 4;   // header, name length, "team"
    BOOST_REQUIRE_EQUAL(s.substr(countPos, 2), "0a");
    s.replace(countPos, 2, "0b");
    s += "22" + Addr('z');
    NyxGroupRec d;
    BOOST_CHECK(!NyxDecodeGroup(s, d));

    // An 11th member via add is not honoured.
    m[0] = O;
    NyxGroupState st;
    BOOST_REQUIRE(NyxGroupApply(st, O, 1, Roster(0, m)));
    BOOST_CHECK(!NyxGroupApply(st, O, 2, Next(st, NYX_GOP_ADD, Addr('z'), O)));
    BOOST_CHECK_EQUAL(st.members.size(), 10u);
}

BOOST_AUTO_TEST_CASE(group_membership_rules)
{
    NyxGroupState s;
    BOOST_CHECK(!NyxGroupApply(s, O, 1, Op(1, NYX_GOP_ADD, X)));    // no state yet
    BOOST_REQUIRE(NyxGroupApply(s, O, 1, Roster(0, {A, O})));
    BOOST_CHECK_EQUAL(s.owner, O);
    BOOST_CHECK_EQUAL(s.members[0], O);                             // owner first

    BOOST_CHECK(!NyxGroupApply(s, A, 2, Next(s, NYX_GOP_ADD, X, A)));   // non-owner op
    NyxGroupRec gap = Next(s, NYX_GOP_ADD, X, O);
    gap.epoch = 2;
    Sign(gap, O);
    BOOST_CHECK(!NyxGroupApply(s, O, 2, gap));                          // epoch gap
    NyxGroupRec badPrev = Next(s, NYX_GOP_ADD, X, O);
    badPrev.prev = std::string(32, 'b');
    Sign(badPrev, O);
    BOOST_CHECK(!NyxGroupApply(s, O, 2, badPrev));                      // does not extend the head
    NyxGroupRec unsigned_ = Next(s, NYX_GOP_ADD, X, O);
    unsigned_.sig = std::string(130, 'f');
    BOOST_CHECK(!NyxGroupApply(s, O, 2, unsigned_));                    // bad signature
    BOOST_REQUIRE(NyxGroupApply(s, O, 2, Next(s, NYX_GOP_ADD, X, O)));
    BOOST_CHECK(!NyxGroupApply(s, O, 3, Next(s, NYX_GOP_ADD, X, O)));   // already a member
    BOOST_CHECK(!NyxGroupApply(s, O, 3, Next(s, NYX_GOP_REMOVE, O, O)));// owner cannot be removed
    BOOST_CHECK(!NyxGroupApply(s, O, 3, Leave(s, O)));   // owner must hand over first
    NyxGroupRec stale = Leave(s, X);
    stale.prev = std::string(32, 'c');
    Sign(stale, X);
    BOOST_CHECK(!NyxGroupApply(s, X, 3, stale));         // not pinned to the head
    BOOST_CHECK(!NyxGroupApply(s, X, 3, Leave(s, Addr('q'))));  // not a member
    BOOST_REQUIRE(NyxGroupApply(s, X, 3, Leave(s, X)));  // any member leaves
    BOOST_CHECK(!s.IsMember(X));
    BOOST_REQUIRE(NyxGroupApply(s, O, 4, Next(s, NYX_GOP_RENAME, "renamed", O)));
    BOOST_CHECK_EQUAL(s.name, "renamed");
    BOOST_CHECK(!NyxGroupApply(s, O, 5, Next(s, NYX_GOP_OWNER, Addr('q'), O)));
    BOOST_REQUIRE(NyxGroupApply(s, O, 5, Next(s, NYX_GOP_OWNER, A, O)));
    BOOST_CHECK_EQUAL(s.owner, A);
    BOOST_CHECK(!NyxGroupApply(s, O, 6, Next(s, NYX_GOP_REMOVE, A, O)));   // old owner lost authority
    BOOST_REQUIRE(NyxGroupApply(s, A, 6, Next(s, NYX_GOP_REMOVE, O, A)));
    BOOST_CHECK_EQUAL(s.members.size(), 1u);
}

BOOST_AUTO_TEST_CASE(group_message_authentication)
{
    NyxGroupState s;
    BOOST_REQUIRE(NyxGroupApply(s, O, 100, Roster(0, {O, A, B})));
    BOOST_CHECK(NyxGroupMsgAllowed(s, A, 110, 0, s.head));
    BOOST_CHECK(!NyxGroupMsgAllowed(s, X, 110, 0, s.head));
    BOOST_CHECK(!NyxGroupMsgAllowed(s, "anon", 110, 0, s.head));
    BOOST_CHECK(!NyxGroupMsgAllowed(s, A, 110, 1, s.head));        // epoch not seen yet: held back
    BOOST_REQUIRE(NyxGroupApply(s, O, 200, Next(s, NYX_GOP_REMOVE, B, O)));
    BOOST_CHECK(!NyxGroupMsgAllowed(s, B, 150, 0, s.head));        // former member, any epoch
    BOOST_CHECK(!NyxGroupMsgAllowed(s, B, 250, 1, s.head));
    BOOST_REQUIRE(NyxGroupApply(s, O, 300, Next(s, NYX_GOP_ADD, X, O)));
    BOOST_CHECK(!NyxGroupMsgAllowed(s, X, 310, 1, s.head));
    BOOST_CHECK(NyxGroupMsgAllowed(s, X, 310, 2, s.head));
}

BOOST_AUTO_TEST_CASE(group_out_of_order_converges)
{
    NyxGroupState s;
    NyxGroupRec g = Roster(0, {O, A});
    BOOST_REQUIRE(NyxGroupApply(s, O, 1, g));
    NyxGroupRec o1 = Next(s, NYX_GOP_ADD, X, O);
    BOOST_REQUIRE(NyxGroupApply(s, O, 2, o1));
    NyxGroupRec o2 = Next(s, NYX_GOP_RENAME, "late", O);
    BOOST_REQUIRE(NyxGroupApply(s, O, 3, o2));
    NyxGroupRec forged = Next(s, NYX_GOP_RENAME, "forged", A);   // non-owner at the head
    std::vector<NyxGroupEvent> ev = {Ev(O, 3, "m3", o2), Ev(A, 4, "m9", forged), Ev(O, 2, "m2", o1),
                                     Ev(O, 2, "m2", o1), Ev(O, 1, "m1", g), Ev("anon", 0, "m0", Roster(0, {A}))};
    std::map<std::string, NyxGroupState> r1 = NyxBuildGroups(ev);
    std::reverse(ev.begin(), ev.end());
    std::map<std::string, NyxGroupState> r2 = NyxBuildGroups(ev);
    for (std::map<std::string, NyxGroupState>* r : {&r1, &r2})
    {
        const NyxGroupState& t = (*r)[g.gid];
        BOOST_CHECK(!t.fFrozen);
        BOOST_CHECK_EQUAL(t.name, "late");
        BOOST_CHECK_EQUAL(t.epoch, 2);
        BOOST_CHECK_EQUAL(t.members.size(), 3u);
        BOOST_CHECK_EQUAL(t.head, s.head);
    }
}

BOOST_AUTO_TEST_CASE(group_leave_then_owner_ops_rebuild)
{
    // Full group: B leaves, owner fills the seat, then re-adds nobody else; rebuild matches the signer.
    std::vector<std::string> m = {O, B};
    for (int i = 0; i < 8; i++)
        m.push_back(Addr('c' + i));
    NyxGroupState s;
    NyxGroupRec g = Roster(0, m);
    BOOST_REQUIRE(NyxGroupApply(s, O, 1, g));
    NyxGroupRec leave = Leave(s, B);
    BOOST_REQUIRE(NyxGroupApply(s, B, 2, leave));
    NyxGroupRec fill = Next(s, NYX_GOP_ADD, X, O);
    BOOST_REQUIRE(NyxGroupApply(s, O, 3, fill));
    NyxGroupRec rm = Next(s, NYX_GOP_REMOVE, X, O);
    BOOST_REQUIRE(NyxGroupApply(s, O, 4, rm));
    NyxGroupRec back = Next(s, NYX_GOP_ADD, B, O);
    BOOST_REQUIRE(NyxGroupApply(s, O, 5, back));
    NyxGroupRec ren = Next(s, NYX_GOP_RENAME, "after", O);
    BOOST_REQUIRE(NyxGroupApply(s, O, 6, ren));
    std::vector<NyxGroupEvent> ev = {Ev(O, 1, "g", g), Ev(B, 2, "l", leave), Ev(O, 3, "f", fill),
                                     Ev(O, 4, "r", rm), Ev(O, 5, "b", back), Ev(O, 6, "n", ren)};
    for (int k = 0; k < 2; k++)
    {
        NyxGroupState t = NyxBuildGroups(ev)[g.gid];
        BOOST_CHECK(!t.fFrozen);
        BOOST_CHECK_EQUAL(t.epoch, 4);
        BOOST_CHECK_EQUAL(t.head, s.head);
        BOOST_CHECK(t.IsMember(B));
        BOOST_CHECK(!t.IsMember(X));
        BOOST_CHECK_EQUAL(t.members.size(), 10u);
        std::reverse(ev.begin(), ev.end());
    }
    // Owner removes a member who already left unseen: the chain still advances.
    NyxGroupRec l2 = Leave(s, Addr('c'));
    BOOST_REQUIRE(NyxGroupApply(s, Addr('c'), 7, l2));
    NyxGroupRec rm2 = Next(s, NYX_GOP_REMOVE, Addr('c'), O);
    ev.push_back(Ev(Addr('c'), 7, "l2", l2));
    ev.push_back(Ev(O, 8, "r2", rm2));
    NyxGroupState t = NyxBuildGroups(ev)[g.gid];
    BOOST_CHECK_EQUAL(t.epoch, 5);
    BOOST_CHECK(!t.fFrozen);
}

BOOST_AUTO_TEST_CASE(group_removed_member_backdated_msg_rejected)
{
    NyxGroupState s;
    BOOST_REQUIRE(NyxGroupApply(s, O, 100, Roster(0, {O, A, B})));
    BOOST_REQUIRE(NyxGroupApply(s, O, 200, Next(s, NYX_GOP_RENAME, "r", O)));
    BOOST_REQUIRE(NyxGroupApply(s, O, 300, Next(s, NYX_GOP_REMOVE, B, O)));
    // The sender picks the epoch, so a removed member stamping one before its removal is still refused.
    BOOST_CHECK(!NyxGroupMsgAllowed(s, B, 50, 1, s.head));
    BOOST_CHECK(!NyxGroupMsgAllowed(s, B, 50, 0, s.head));
    BOOST_CHECK(!NyxGroupMsgAllowed(s, B, 50, 2, s.head));
    BOOST_CHECK(!NyxGroupMsgAllowed(s, A, 50, 1, s.head));
    BOOST_REQUIRE(NyxGroupApply(s, A, 400, Leave(s, A)));
    BOOST_CHECK(!NyxGroupMsgAllowed(s, A, 50, 1, s.head));
    BOOST_CHECK(!NyxGroupMsgAllowed(s, A, 50, 0, s.head));
}

BOOST_AUTO_TEST_CASE(group_leave_reaches_concurrent_new_member)
{
    // Full group. B leaves (fanned only to its view); the owner adds Y concurrently without seeing the leave,
    // then sees it and fills the seat with Z. Y must converge on the owner's roster.
    const std::string Y = Addr('y'), Z = Addr('z');
    std::vector<std::string> m = {O, B};
    for (int i = 0; i < 7; i++)
        m.push_back(Addr('c' + i));
    NyxGroupState s;
    NyxGroupRec g = Roster(0, m);
    BOOST_REQUIRE(NyxGroupApply(s, O, 1, g));
    NyxGroupRec rn = Next(s, NYX_GOP_RENAME, "r", O);
    BOOST_REQUIRE(NyxGroupApply(s, O, 2, rn));
    NyxGroupRec leave = Leave(s, B);
    NyxGroupRec addY = Next(s, NYX_GOP_ADD, Y, O);
    BOOST_REQUIRE(NyxGroupApply(s, O, 3, leave));
    BOOST_REQUIRE(NyxGroupApply(s, O, 4, addY));
    BOOST_REQUIRE_EQUAL(s.members.size(), 9u);
    NyxGroupRec addZ = Next(s, NYX_GOP_ADD, Z, O);
    BOOST_REQUIRE(NyxGroupApply(s, O, 5, addZ));
    BOOST_REQUIRE_EQUAL(s.members.size(), 10u);
    // Y's chain bundle was cut before the owner saw the leave; the add of Z travels with the known leaves.
    NyxGroupRec yChain;
    yChain.gid = s.gid;
    yChain.op = NYX_GOP_CHAIN;
    yChain.chain = {NyxEncodeGroup(g), NyxEncodeGroup(rn), NyxEncodeGroup(addY)};
    std::vector<std::string> recs = s.leaves;
    recs.push_back(NyxEncodeGroup(addZ));
    std::vector<NyxGroupRec> zb = NyxGroupChainBundles(s.gid, recs, 4000);
    BOOST_REQUIRE_EQUAL(zb.size(), 1u);
    NyxGroupRec zd;
    BOOST_REQUIRE(NyxDecodeGroup(NyxEncodeGroup(zb[0]), zd));
    std::vector<NyxGroupEvent> ev = {Ev(O, 4, "y", yChain), Ev(O, 5, "z", zd)};
    for (int k = 0; k < 2; k++)
    {
        NyxGroupState t = NyxBuildGroups(ev)[s.gid];
        BOOST_CHECK(!t.fFrozen);
        BOOST_CHECK_EQUAL(t.epoch, 3);
        BOOST_CHECK_EQUAL(t.head, s.head);
        BOOST_CHECK(!t.IsMember(B));
        BOOST_CHECK(t.IsMember(Z));
        std::reverse(ev.begin(), ev.end());
    }
    // Without the leave the add of Z cannot apply: the leave is what makes it converge.
    NyxGroupRec bare;
    BOOST_REQUIRE(NyxDecodeGroup(NyxEncodeGroup(addZ), bare));
    BOOST_CHECK_EQUAL(NyxBuildGroups({Ev(O, 4, "y", yChain), Ev(O, 5, "z", bare)})[s.gid].epoch, 2);
    // A new member's chain bundle carries the leaves.
    std::vector<std::string> full = s.chain;
    full.insert(full.end(), s.leaves.begin(), s.leaves.end());
    std::vector<NyxGroupRec> nb = NyxGroupChainBundles(s.gid, full, 4000);
    std::vector<NyxGroupEvent> ne;
    for (size_t i = 0; i < nb.size(); i++)
        ne.push_back(Ev(O, 6, "n" + std::to_string(i), nb[i]));
    NyxGroupState n = NyxBuildGroups(ne)[s.gid];
    BOOST_CHECK_EQUAL(n.head, s.head);
    BOOST_CHECK(!n.IsMember(B));
    // A leave is a signed record: an unsigned or forged one changes nothing.
    NyxGroupRec forged = Leave(s, Addr('c'));
    forged.sig = std::string(130, 'f');
    NyxGroupState f = s;
    BOOST_CHECK(!NyxGroupApply(f, Addr('c'), 7, forged));
}

BOOST_AUTO_TEST_CASE(group_id_full_hash)
{
    // The gid is the full 256-bit hash; a 64-bit prefix neither decodes nor binds.
    NyxGroupRec g = Roster(0, {O, A});
    BOOST_CHECK(NyxIsGroupId(g.gid));
    BOOST_CHECK_EQUAL(g.gid.size(), 64u);
    BOOST_CHECK(NyxGroupIdBinds(g));
    NyxGroupRec shortId = g;
    shortId.gid = g.gid.substr(0, 16);
    BOOST_CHECK(!NyxGroupIdBinds(shortId));
    BOOST_CHECK(NyxEncodeGroup(shortId).empty());
    std::string enc = NyxEncodeGroup(g);
    NyxGroupRec d;
    BOOST_CHECK(!NyxDecodeGroup(enc.substr(0, 2) + g.gid.substr(0, 16) + enc.substr(2 + NYX_GID_HEX), d));
    // A genesis differing only past the old 64-bit prefix gets a different gid.
    NyxGroupRec other = Roster(0, {O, B});
    BOOST_CHECK(other.gid != g.gid);
    other.gid = g.gid.substr(0, 16) + other.gid.substr(16);
    BOOST_CHECK(!NyxGroupIdBinds(other));
    std::map<std::string, NyxGroupState> r = NyxBuildGroups({Ev(O, 1, "a", g), Ev(O, 2, "b", other)});
    BOOST_CHECK_EQUAL(r.size(), 1u);
    BOOST_CHECK(!r[g.gid].fFrozen);
    BOOST_CHECK(r[g.gid].IsMember(A));
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

BOOST_AUTO_TEST_CASE(group_forged_second_genesis_rejected)
{
    // Same creator, time and rnd, different members: the gid binds content, so only one genesis matches.
    NyxGroupRec real = Roster(0, {O, A, B});
    NyxGroupRec forged = Roster(0, {O, A, X});
    forged.gid = real.gid;
    BOOST_CHECK(NyxGroupIdBinds(real));
    BOOST_CHECK(!NyxGroupIdBinds(forged));
    NyxGroupRec renamed = real;
    renamed.name = "mine";
    BOOST_CHECK(!NyxGroupIdBinds(renamed));
    NyxGroupState s;
    BOOST_CHECK(!NyxGroupApply(s, O, 1, forged));
    std::vector<NyxGroupEvent> ev = {Ev(O, 1, "a0", forged), Ev(O, 2, "z9", real), Ev(A, 0, "00", renamed)};
    std::map<std::string, NyxGroupState> g = NyxBuildGroups(ev);
    BOOST_REQUIRE_EQUAL(g.size(), 1u);
    BOOST_CHECK(g[real.gid].IsMember(B));
    BOOST_CHECK(!g[real.gid].IsMember(X));
    BOOST_CHECK_EQUAL(g[real.gid].name, "team");
    // A later-epoch roster is no longer an op.
    NyxGroupRec late = real;
    late.epoch = 3;
    BOOST_CHECK(NyxEncodeGroup(late).empty());
    BOOST_CHECK(!NyxGroupApply(s, O, 1, late));
}

BOOST_AUTO_TEST_CASE(group_ex_owner_cannot_rewrite)
{
    NyxGroupState s;
    NyxGroupRec g = Roster(0, {O, A, B});
    BOOST_REQUIRE(NyxGroupApply(s, O, 1, g));
    NyxGroupRec h = Next(s, NYX_GOP_OWNER, A, O);
    NyxGroupState before = s;
    BOOST_REQUIRE(NyxGroupApply(s, O, 2, h));
    // The creator signs an alternative at the handover's position and on the new head.
    NyxGroupRec alt = Next(before, NYX_GOP_REMOVE, A, O);
    NyxGroupRec onHead = Next(s, NYX_GOP_REMOVE, A, O);
    NyxGroupRec legit = Next(s, NYX_GOP_RENAME, "by A", A);
    BOOST_CHECK(!NyxGroupApply(s, O, 3, onHead));
    std::vector<NyxGroupEvent> ev = {Ev(O, 1, "1", g), Ev(O, 2, "2", h), Ev(O, 3, "3", onHead), Ev(A, 4, "4", legit)};
    std::map<std::string, NyxGroupState> r = NyxBuildGroups(ev);
    BOOST_CHECK_EQUAL(r[g.gid].owner, A);
    BOOST_CHECK_EQUAL(r[g.gid].name, "by A");
    BOOST_CHECK(r[g.gid].IsMember(A));
    BOOST_CHECK(!r[g.gid].fFrozen);
    // An alternative at the handover's position, signed later by the creator, loses to the side A built on.
    ev.push_back(Ev(O, 5, "5", alt));
    r = NyxBuildGroups(ev);
    BOOST_CHECK(!r[g.gid].fFrozen);
    BOOST_CHECK_EQUAL(r[g.gid].owner, A);
    BOOST_CHECK_EQUAL(r[g.gid].name, "by A");
}

BOOST_AUTO_TEST_CASE(group_former_owner_cannot_freeze_or_split)
{
    NyxGroupState s;
    NyxGroupRec g = Roster(0, {O, A, B});
    BOOST_REQUIRE(NyxGroupApply(s, O, 1, g));
    NyxGroupState before = s;
    NyxGroupRec h = Next(s, NYX_GOP_OWNER, A, O);
    BOOST_REQUIRE(NyxGroupApply(s, O, 2, h));
    NyxGroupRec add = Next(s, NYX_GOP_ADD, X, A);
    BOOST_REQUIRE(NyxGroupApply(s, A, 3, add));
    // The old owner extends its own conflicting branch, so both sides have a successor.
    NyxGroupState fork = before;
    NyxGroupRec alt = Next(fork, NYX_GOP_RENAME, "mine", O);
    BOOST_REQUIRE(NyxGroupApply(fork, O, 4, alt));
    NyxGroupRec alt2 = Next(fork, NYX_GOP_REMOVE, B, O);
    std::vector<NyxGroupEvent> full = {Ev(O, 1, "1", g), Ev(O, 2, "2", h), Ev(A, 3, "3", add),
                                       Ev(O, 4, "4", alt), Ev(O, 5, "5", alt2)};
    std::vector<NyxGroupEvent> plain = {Ev(O, 1, "1", g), Ev(O, 2, "2", h), Ev(A, 3, "3", add)};
    NyxGroupState rf = NyxBuildGroups(full)[g.gid], rp = NyxBuildGroups(plain)[g.gid];
    BOOST_CHECK(!rf.fFrozen);
    BOOST_CHECK_EQUAL(rf.head, rp.head);
    BOOST_CHECK_EQUAL(rf.owner, A);
    BOOST_CHECK(rf.IsMember(X) && rf.IsMember(B));
    // The current owner equivocating at the head still freezes.
    full.push_back(Ev(A, 6, "6", Next(s, NYX_GOP_RENAME, "a1", A)));
    full.push_back(Ev(A, 7, "7", Next(s, NYX_GOP_RENAME, "a2", A)));
    BOOST_CHECK(NyxBuildGroups(full)[g.gid].fFrozen);
}

BOOST_AUTO_TEST_CASE(group_junk_leaves_bounded)
{
    NyxGroupState s;
    NyxGroupRec g = Roster(0, {O, A, B});
    BOOST_REQUIRE(NyxGroupApply(s, O, 1, g));
    std::vector<NyxGroupEvent> ev = {Ev(O, 1, "1", g)};
    for (int i = 0; i < 20; i++)
    {
        NyxGroupRec op = Next(s, NYX_GOP_RENAME, "n" + std::to_string(i), O);
        BOOST_REQUIRE(NyxGroupApply(s, O, 2 + i, op));
        ev.push_back(Ev(O, 2 + i, "o" + std::to_string(i), op));
    }
    // Junk leaves off the chain cost no recovery; a flood at one position cannot crowd out a member's leave.
    for (int i = 0; i < 2000; i++)
    {
        NyxGroupRec j;
        j.gid = g.gid;
        j.epoch = i % 20;
        j.op = NYX_GOP_LEAVE;
        j.prev = std::string(32, 'a' + (i % 6));
        j.sig = std::string(122, '0') + "ffffffff";
        ev.push_back(Ev(X, 100, "j" + std::to_string(i), j));
    }
    NyxGroupState ref = s;
    for (int i = 0; i < 500; i++)
    {
        NyxGroupRec j = Leave(ref, X);
        char buf[16];
        snprintf(buf, sizeof(buf), "f%07x", i);
        j.sig = std::string(122, '1') + buf;
        ev.push_back(Ev(X, 100, "k" + std::to_string(i), j));
    }
    ev.push_back(Ev(B, 200, "lb", Leave(ref, B)));
    g_recovers = 0;
    NyxGroupState r = NyxBuildGroups(ev)[g.gid];
    BOOST_CHECK_EQUAL(r.epoch, 20);
    BOOST_CHECK(g_recovers < 600);
    BOOST_CHECK(r.IsMember(A));
    BOOST_CHECK(!r.IsMember(B));
}

BOOST_AUTO_TEST_CASE(group_owner_equivocation_freezes)
{
    NyxGroupState s;
    NyxGroupRec g = Roster(0, {O, A, B});
    BOOST_REQUIRE(NyxGroupApply(s, O, 1, g));
    NyxGroupRec r1 = Next(s, NYX_GOP_RENAME, "one", O);
    NyxGroupRec r2 = Next(s, NYX_GOP_REMOVE, B, O);
    NyxGroupRec nonOwner = Next(s, NYX_GOP_RENAME, "two", A);
    std::vector<NyxGroupEvent> ev = {Ev(O, 1, "1", g), Ev(O, 2, "2", r1), Ev(A, 2, "3", nonOwner)};
    BOOST_CHECK(!NyxBuildGroups(ev)[g.gid].fFrozen);           // non-owner ops never fork
    BOOST_CHECK_EQUAL(NyxBuildGroups(ev)[g.gid].name, "one");
    ev.push_back(Ev(O, 3, "4", r2));
    std::map<std::string, NyxGroupState> r = NyxBuildGroups(ev);
    BOOST_CHECK(r[g.gid].fFrozen);
    BOOST_CHECK_EQUAL(r[g.gid].epoch, 0);
    NyxGroupState f = r[g.gid];
    BOOST_CHECK(!NyxGroupApply(f, O, 4, r1));
}

BOOST_AUTO_TEST_CASE(group_new_owner_adds_member_with_full_chain)
{
    NyxGroupState s;
    NyxGroupRec g = Roster(0, {O, A});
    BOOST_REQUIRE(NyxGroupApply(s, O, 1, g));
    BOOST_REQUIRE(NyxGroupApply(s, O, 2, Next(s, NYX_GOP_RENAME, "first", O)));
    BOOST_REQUIRE(NyxGroupApply(s, O, 3, Next(s, NYX_GOP_OWNER, A, O)));
    BOOST_REQUIRE(NyxGroupApply(s, A, 4, Next(s, NYX_GOP_ADD, B, A)));
    BOOST_REQUIRE(NyxGroupApply(s, A, 5, Next(s, NYX_GOP_ADD, X, A)));
    BOOST_REQUIRE_EQUAL(s.chain.size(), 5u);
    // Tight budget forces several bundles; each fits.
    std::vector<NyxGroupRec> bundles = NyxGroupChainBundles(s.gid, s.chain, 400);
    BOOST_CHECK(bundles.size() > 1);
    std::vector<NyxGroupEvent> ev;
    for (size_t i = 0; i < bundles.size(); i++)
    {
        std::string enc = NyxEncodeGroup(bundles[i]);
        BOOST_REQUIRE(!enc.empty());
        BOOST_CHECK(enc.size() <= 400);
        NyxGroupRec d;
        BOOST_REQUIRE(NyxDecodeGroup(enc, d));
        ev.insert(ev.begin(), Ev(A, 10, "b" + std::to_string(i), d));   // reversed delivery
    }
    std::map<std::string, NyxGroupState> r = NyxBuildGroups(ev);
    const NyxGroupState& j = r[s.gid];
    BOOST_CHECK_EQUAL(j.owner, A);
    BOOST_CHECK_EQUAL(j.name, "first");
    BOOST_CHECK_EQUAL(j.epoch, 4);
    BOOST_CHECK(j.IsMember(X) && j.IsMember(B) && j.IsMember(O));
    BOOST_CHECK_EQUAL(j.head, s.head);
    // A tampered bundle entry breaks the chain at that op.
    NyxGroupRec bad = bundles[0];
    NyxGroupRec op1;
    BOOST_REQUIRE(NyxDecodeGroup(s.chain[1], op1));
    op1.name = "other";
    bad.chain = {s.chain[0], NyxEncodeGroup(op1)};
    BOOST_CHECK_EQUAL(NyxBuildGroups({Ev(A, 1, "x", bad)})[s.gid].epoch, 0);
}

BOOST_AUTO_TEST_CASE(group_id_and_typing)
{
    unsigned char r1[16] = {1}, r2[16] = {2};
    std::string a = NyxNewGroupId(O, 1000, r1, "t", {O, A});
    BOOST_CHECK(NyxIsGroupId(a));
    BOOST_CHECK(a != NyxNewGroupId(O, 1000, r2, "t", {O, A}));
    BOOST_CHECK(a != NyxNewGroupId(O, 1000, r1, "t", {O, B}));
    BOOST_CHECK(a != NyxNewGroupId(A, 1000, r1, "t", {O, A}));
    bool on = false;
    BOOST_CHECK(NyxDecodeTyping(NyxEncodeTyping(true), on) && on);
    BOOST_CHECK(NyxDecodeTyping(NyxEncodeTyping(false), on) && !on);
    BOOST_CHECK(!NyxDecodeTyping(std::string("T\x01\x03", 3), on));
    BOOST_CHECK(NyxParseRecords(NyxEncodeTyping(true)).fTyping);
}

BOOST_AUTO_TEST_CASE(v2_group_text_binds_gid)
{
    unsigned char gid[32];
    for (int i = 0; i < 32; i++)
        gid[i] = (unsigned char)strtol(GID.substr(2 * i, 2).c_str(), NULL, 16);
    NyxGroupRec m;
    m.gid = GID;
    m.op = NYX_GOP_MSG;
    m.prev = std::string(32, 'a');
    const std::string text = NyxGroupPlain("team", "hello", m, std::vector<std::string>(), 4000);
    NyxGroupRec got;
    std::string body;
    BOOST_REQUIRE(NyxGroupFromText(text, gid, got, body));
    BOOST_CHECK_EQUAL(body, "hello");
    BOOST_CHECK_EQUAL(got.gid, GID);
    gid[31] ^= 1;
    BOOST_CHECK(!NyxGroupFromText(text, gid, got, body));                 // envelope gid must match the record
    gid[31] ^= 1;
    BOOST_CHECK(!NyxGroupFromText("hello", gid, got, body));              // no record
    BOOST_CHECK(!NyxGroupFromText(NyxComposePlain("x", NyxEncodeTyping(true)), gid, got, body));
}

BOOST_AUTO_TEST_CASE(v2_group_removed_member_gets_no_later_copy)
{
    NyxGroupState s;
    BOOST_REQUIRE(NyxGroupApply(s, O, 1, Roster(0, {O, A, B})));
    BOOST_CHECK(NyxGroupOthers(s.members, O) == std::vector<std::string>({A, B}));
    const NyxGroupState before = s;
    BOOST_REQUIRE(NyxGroupApply(s, O, 2, Next(s, NYX_GOP_REMOVE, B, O)));
    // The removal itself reaches B; every later send goes to the remaining members only.
    BOOST_CHECK(NyxGroupOthers(before.members, O) == std::vector<std::string>({A, B}));
    BOOST_CHECK(NyxGroupOthers(s.members, O) == std::vector<std::string>({A}));
    BOOST_CHECK(NyxGroupOthers(s.members, A) == std::vector<std::string>({O}));
    BOOST_CHECK(!NyxGroupMsgAllowed(s, B, 3, 1, s.head));
    BOOST_CHECK(!NyxGroupMsgAllowed(s, B, 3, 0, s.head));                        // an older epoch does not help
    BOOST_CHECK(NyxGroupMsgAllowed(s, A, 3, 1, s.head));
    BOOST_REQUIRE(NyxGroupApply(s, O, 4, Next(s, NYX_GOP_ADD, X, O)));
    BOOST_CHECK(NyxGroupOthers(s.members, O) == std::vector<std::string>({A, X}));
    BOOST_CHECK(NyxGroupMsgAllowed(s, X, 5, 2, s.head));
    BOOST_CHECK(!NyxGroupMsgAllowed(s, X, 5, 1, s.head));                        // no voice before the add
    BOOST_CHECK(!NyxGroupMsgAllowed(s, A, 5, 3, s.head));                        // epoch ahead of the chain
}

BOOST_AUTO_TEST_CASE(bad_signature_copy_does_not_shadow_the_owner_op)
{
    NyxGroupState s;
    const NyxGroupRec g = Roster(0, {O, A, B});
    BOOST_REQUIRE(NyxGroupApply(s, O, 1, g));
    const NyxGroupRec rm = Next(s, NYX_GOP_REMOVE, B, O);
    NyxGroupRec forged = rm;
    forged.sig = std::string(130, 'e');
    BOOST_REQUIRE_EQUAL(NyxGroupOpHash(forged), NyxGroupOpHash(rm));
    std::vector<NyxGroupEvent> ev;
    ev.push_back(Ev(O, 1, "g", g));
    ev.push_back(Ev(B, 2, "f", forged));        // arrives first
    ev.push_back(Ev(O, 3, "r", rm));
    ev.push_back(Ev(O, 4, "r2", rm));
    const NyxGroupState r = NyxBuildGroups(ev)[g.gid];
    BOOST_CHECK(!r.fFrozen);
    BOOST_CHECK_EQUAL(r.epoch, 1);
    BOOST_CHECK(!r.IsMember(B));
}

BOOST_AUTO_TEST_CASE(v2_genesis_counts_only_from_its_creator)
{
    const NyxGroupRec g = Roster(0, {O, A, X});
    NyxGroupEvent e = Ev(X, 1, "g", g);         // X forges a group naming O as creator
    BOOST_CHECK(!NyxGroupFromCreator(e));
    e.sender = O;
    BOOST_CHECK(NyxGroupFromCreator(e));
    NyxGroupState s;
    BOOST_REQUIRE(NyxGroupApply(s, O, 1, g));
    const NyxGroupRec add = Next(s, NYX_GOP_ADD, B, O);
    const std::vector<NyxGroupRec> b = NyxGroupChainBundles(g.gid, {NyxEncodeGroup(g), NyxEncodeGroup(add)}, 4000);
    BOOST_REQUIRE_EQUAL(b.size(), 1U);
    NyxGroupEvent c = Ev(X, 2, "c", b[0]);
    BOOST_CHECK(NyxGroupFromCreator(c));        // the signed add stays
    BOOST_CHECK_EQUAL(c.rec.chain.size(), 1U);
    std::vector<NyxGroupEvent> ev(1, c);
    BOOST_CHECK(NyxBuildGroups(ev).empty());    // no genesis left to start from
    NyxGroupEvent c2 = Ev(O, 2, "c", b[0]);
    BOOST_CHECK(NyxGroupFromCreator(c2));
    BOOST_CHECK_EQUAL(c2.rec.chain.size(), 2U);
    std::vector<NyxGroupEvent> ev2(1, c2);
    BOOST_CHECK(NyxBuildGroups(ev2)[g.gid].IsMember(B));
    NyxGroupEvent only = Ev(X, 3, "o", NyxGroupChainBundles(g.gid, {NyxEncodeGroup(g)}, 4000)[0]);
    BOOST_CHECK(!NyxGroupFromCreator(only));
}



BOOST_AUTO_TEST_CASE(v2_group_missed_removal_epoch_catchup)
{
    NyxGroupState owner;
    const NyxGroupRec genesis = Roster(0, {O, A, B});
    BOOST_REQUIRE(NyxGroupApply(owner, O, 1, genesis));
    NyxGroupState stale = owner;
    const NyxGroupRec removal = Next(owner, NYX_GOP_REMOVE, B, O);
    BOOST_REQUIRE(NyxGroupApply(owner, O, 2, removal));
    BOOST_CHECK(!NyxGroupMsgAllowed(owner, A, 3, stale.epoch, stale.head));
    BOOST_CHECK(NyxGroupMsgAllowed(owner, A, 1, stale.epoch, stale.head, false));
    BOOST_CHECK(!NyxGroupMsgAllowed(owner, B, 1, stale.epoch, stale.head, false));
    BOOST_CHECK(!NyxGroupMsgAllowed(stale, O, 3, owner.epoch, owner.head));
    BOOST_CHECK(!NyxGroupMsgAllowed(owner, A, 3, owner.epoch, stale.head));
    NyxGroupRec msg = Op(owner.epoch, NYX_GOP_MSG);
    msg.gid = owner.gid;
    msg.prev = owner.head;
    NyxGroupRec decoded;
    const std::string wire = NyxEncodeGroup(msg);
    BOOST_REQUIRE(NyxDecodeGroup(wire, decoded));
    BOOST_CHECK_EQUAL(decoded.prev, owner.head);
    BOOST_CHECK(!NyxDecodeGroup(wire.substr(0, wire.size() - 32), decoded));
    msg.prev.clear();
    BOOST_CHECK(NyxEncodeGroup(msg).empty());
    msg.prev = owner.head;
    BOOST_CHECK(NyxGroupRosterPending(stale, O, msg));
    BOOST_CHECK(!NyxGroupRosterPending(stale, X, msg));
    BOOST_CHECK(!NyxGroupRosterPending(owner, O, msg));
    const NyxGroupRec rename = Next(owner, NYX_GOP_RENAME, "renamed", O);
    BOOST_CHECK(NyxGroupRosterPending(stale, O, rename));
    NyxGroupRec partial;
    partial.gid = owner.gid;
    partial.op = NYX_GOP_CHAIN;
    partial.chain.push_back(NyxEncodeGroup(rename));
    BOOST_CHECK(NyxGroupRosterPending(stale, O, partial));
    const auto request = NyxGroupCatchUpRecords(stale, owner.epoch, owner.head, 4000);
    BOOST_REQUIRE_EQUAL(request.size(), 1u);
    BOOST_REQUIRE(NyxDecodeGroup(NyxEncodeGroup(request[0]), decoded));
    BOOST_CHECK_EQUAL(decoded.op, NYX_GOP_SYNC);
    BOOST_CHECK_EQUAL(decoded.epoch, stale.epoch);
    BOOST_CHECK_EQUAL(decoded.prev, stale.head);
    const auto bundles = NyxGroupCatchUpRecords(owner, decoded.epoch, decoded.prev, 4000);
    BOOST_REQUIRE_EQUAL(bundles.size(), 1u);
    BOOST_REQUIRE(NyxDecodeGroup(NyxEncodeGroup(bundles[0]), decoded));
    for (const auto& raw : decoded.chain)
    {
        NyxGroupRec op;
        BOOST_REQUIRE(NyxDecodeGroup(raw, op));
        BOOST_REQUIRE(NyxGroupApply(stale, O, 4, op));
    }
    BOOST_CHECK_EQUAL(stale.head, owner.head);
    BOOST_CHECK(!NyxGroupRosterPending(stale, O, msg));
    BOOST_CHECK(NyxGroupCatchUpRecords(owner, stale.epoch, stale.head, 4000).empty());
    BOOST_CHECK(NyxGroupMsgAllowed(owner, A, 5, stale.epoch, stale.head));
    BOOST_CHECK(NyxGroupOthers(stale.members, A) == std::vector<std::string>({O}));
    BOOST_CHECK(!NyxGroupMsgAllowed(owner, B, 5, stale.epoch, stale.head));
}

BOOST_AUTO_TEST_SUITE_END()
