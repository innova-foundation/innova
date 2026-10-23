// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "nyxgroup.h"
#include "nyxembed.h"
#include "nyxext.h"
#include "nyxsafety.h"

#include "base58.h"
#include "key.h"

#include <openssl/sha.h>
#include <string.h>

#include <algorithm>

static const char NYX_GRP_VER = '\x01';
static const char* const HEXD = "0123456789abcdef";

static std::string Hex(uint64_t v, int digits)
{
    std::string s(digits, '0');
    for (int i = digits - 1; i >= 0; i--, v >>= 4)
        s[i] = HEXD[v & 15];
    return s;
}

static bool ReadHex(const std::string& s, size_t& pos, int digits, uint64_t& v)
{
    if (pos + digits > s.size())
        return false;
    v = 0;
    for (int i = 0; i < digits; i++)
    {
        char c = s[pos + i];
        int d = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
        if (d < 0)
            return false;
        v = (v << 4) | (size_t)d;
    }
    pos += digits;
    return true;
}

static bool ReadStr(const std::string& s, size_t& pos, size_t cap, std::string& out)
{
    uint64_t n;
    if (!ReadHex(s, pos, 2, n) || n > cap || pos + n > s.size())
        return false;
    out = s.substr(pos, n);
    pos += n;
    return true;
}

static bool ValidAddr(const std::string& a)
{
    return !a.empty() && a.size() <= NYX_GROUP_ADDR_MAX && a != "anon" && NyxIsValidContactAddress(a);
}

static bool ValidName(const std::string& n)
{
    return !n.empty() && n.size() <= NYX_GROUP_NAME_MAX && NyxCleanText(n, NYX_GROUP_NAME_MAX) == n;
}

static bool ValidRoster(const std::vector<std::string>& m)
{
    if (m.empty() || m.size() > NYX_GROUP_MAX)
        return false;
    std::set<std::string> seen;
    for (const std::string& a : m)
        if (!ValidAddr(a) || !seen.insert(a).second)
            return false;
    return true;
}

static std::string RosterBytes(const std::string& name, const std::vector<std::string>& members)
{
    std::string s = Hex(name.size(), 2) + name + Hex(members.size(), 2);
    for (const std::string& a : members)
        s += Hex(a.size(), 2) + a;
    return s;
}

static std::string BytesHex(const unsigned char* p, size_t n)
{
    std::string out;
    for (size_t i = 0; i < n; i++)
    {
        out.push_back(HEXD[p[i] >> 4]);
        out.push_back(HEXD[p[i] & 15]);
    }
    return out;
}

std::string NyxNewGroupId(const std::string& creator, int64_t createTime, const unsigned char rnd[16],
                          const std::string& name, const std::vector<std::string>& members)
{
    std::string rb = RosterBytes(name, members);
    unsigned char rh[32];
    SHA256((const unsigned char*)rb.data(), rb.size(), rh);
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, creator.data(), creator.size());
    unsigned char ts[8];
    for (int i = 0; i < 8; i++)
        ts[i] = (unsigned char)(((uint64_t)createTime >> (8 * i)) & 0xFF);
    SHA256_Update(&ctx, ts, 8);
    SHA256_Update(&ctx, rnd, 16);
    SHA256_Update(&ctx, rh, 32);
    unsigned char h[32];
    SHA256_Final(h, &ctx);
    return BytesHex(h, 32);
}

bool NyxIsGroupId(const std::string& id)
{
    if (id.size() != NYX_GID_HEX)
        return false;
    for (char c : id)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    return true;
}

static bool HexToBytes(const std::string& h, unsigned char* out, size_t n)
{
    if (h.size() != 2 * n)
        return false;
    size_t pos = 0;
    uint64_t v;
    for (size_t i = 0; i < n; i++)
    {
        if (!ReadHex(h, pos, 2, v))
            return false;
        out[i] = (unsigned char)v;
    }
    return true;
}

bool NyxGroupIdBinds(const NyxGroupRec& g)
{
    unsigned char rnd[16];
    return g.op == NYX_GOP_ROSTER && g.epoch == 0 && ValidAddr(g.creator) && HexToBytes(g.rnd, rnd, 16)
           && NyxNewGroupId(g.creator, g.createTime, rnd, g.name, g.members) == g.gid;
}

static bool ValidRnd(const std::string& r)
{
    unsigned char b[16];
    return HexToBytes(r, b, 16);
}

static bool IsHexN(const std::string& h, size_t n)
{
    size_t pos = 0;
    uint64_t v;
    if (h.size() != n)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!ReadHex(h, pos, 1, v))
            return false;
    return true;
}

bool NyxGroupOpChained(int op)
{
    return op == NYX_GOP_ADD || op == NYX_GOP_REMOVE || op == NYX_GOP_RENAME || op == NYX_GOP_OWNER;
}

bool NyxGroupOpSigned(int op)
{
    return NyxGroupOpChained(op) || op == NYX_GOP_LEAVE;
}

static bool ChainInner(int op)
{
    return op == NYX_GOP_ROSTER || NyxGroupOpSigned(op);
}

static const size_t NYX_SIG_HEX = 130;
static const size_t NYX_CHAIN_RECS_MAX = NYX_GROUP_OPS_MAX + 1;

static std::string EncodeBody(const NyxGroupRec& g)
{
    if (!NyxIsGroupId(g.gid) || g.epoch < 0 || g.epoch > 0xFFFF)
        return std::string();
    const bool fChained = NyxGroupOpSigned(g.op);
    if (fChained && ((NyxGroupOpChained(g.op) && g.epoch < 1) || !IsHexN(g.prev, 32)))
        return std::string();
    std::string s(1, 'G');
    s.push_back(NYX_GRP_VER);
    s += g.gid + Hex(g.epoch, 4) + Hex(g.op, 2);
    if (fChained)
        s += g.prev;
    switch (g.op)
    {
    case NYX_GOP_MSG:
    case NYX_GOP_LEAVE:
        break;
    case NYX_GOP_ROSTER:
        if (g.epoch != 0 || !ValidName(g.name) || !ValidRoster(g.members) || !ValidAddr(g.creator) || !ValidRnd(g.rnd))
            return std::string();
        s += RosterBytes(g.name, g.members);
        s += Hex(g.creator.size(), 2) + g.creator + Hex((uint64_t)g.createTime, 16) + g.rnd;
        break;
    case NYX_GOP_ADD:
    case NYX_GOP_REMOVE:
    case NYX_GOP_OWNER:
        if (!ValidAddr(g.addr))
            return std::string();
        s += Hex(g.addr.size(), 2) + g.addr;
        break;
    case NYX_GOP_RENAME:
        if (!ValidName(g.name))
            return std::string();
        s += Hex(g.name.size(), 2) + g.name;
        break;
    case NYX_GOP_CHAIN:
        if (g.chain.empty() || g.chain.size() > NYX_CHAIN_RECS_MAX)
            return std::string();
        s += Hex(g.chain.size(), 2);
        for (const std::string& r : g.chain)
        {
            NyxGroupRec n;
            if (!NyxDecodeGroup(r, n) || n.gid != g.gid || !ChainInner(n.op))
                return std::string();
            s += Hex(r.size(), 4) + r;
        }
        break;
    default:
        return std::string();
    }
    return s;
}

std::string NyxGroupSigningBytes(const NyxGroupRec& g)
{
    return EncodeBody(g);
}

std::string NyxEncodeGroup(const NyxGroupRec& g)
{
    std::string s = EncodeBody(g);
    if (s.empty() || !NyxGroupOpSigned(g.op))
        return s;
    return IsHexN(g.sig, NYX_SIG_HEX) ? s + g.sig : std::string();
}

void NyxGroupDigest(const NyxGroupRec& g, unsigned char out[32])
{
    std::string b = EncodeBody(g);
    SHA256((const unsigned char*)b.data(), b.size(), out);
}

std::string NyxGroupOpHash(const NyxGroupRec& g)
{
    unsigned char h[32];
    NyxGroupDigest(g, h);
    return BytesHex(h, 16);
}

static std::string DefaultRecover(const unsigned char digest[32], const std::string& sigHex)
{
    std::vector<unsigned char> sig(65);
    if (!HexToBytes(sigHex, sig.data(), 65))
        return std::string();
    uint256 h;
    memcpy(h.begin(), digest, 32);
    CPubKey pk;
    if (!pk.RecoverCompact(h, sig))
        return std::string();
    return CBitcoinAddress(pk.GetID()).ToString();
}

static NyxGroupRecoverFn fnRecover = DefaultRecover;

void NyxGroupSetRecover(NyxGroupRecoverFn fn)
{
    fnRecover = fn ? fn : DefaultRecover;
}

std::string NyxGroupRecover(const NyxGroupRec& g)
{
    if (!NyxGroupOpSigned(g.op) || !IsHexN(g.sig, NYX_SIG_HEX))
        return std::string();
    unsigned char h[32];
    NyxGroupDigest(g, h);
    return fnRecover(h, g.sig);
}

std::vector<NyxGroupRec> NyxGroupChainBundles(const std::string& gid, const std::vector<std::string>& chain, size_t maxBytes)
{
    std::vector<NyxGroupRec> out;
    NyxGroupRec cur;
    size_t sz = 0;
    for (const std::string& r : chain)
    {
        if (!cur.chain.empty() && (sz + r.size() + 4 > maxBytes || cur.chain.size() >= NYX_CHAIN_RECS_MAX))
        {
            out.push_back(cur);
            cur.chain.clear();
            sz = 0;
        }
        if (cur.chain.empty())
        {
            cur.gid = gid;
            cur.op = NYX_GOP_CHAIN;
            sz = 10 + NYX_GID_HEX;
        }
        cur.chain.push_back(r);
        sz += r.size() + 4;
    }
    if (!cur.chain.empty())
        out.push_back(cur);
    return out;
}

bool NyxDecodeGroup(const std::string& rec, NyxGroupRec& g)
{
    g = NyxGroupRec();
    if (rec.size() < 8 + NYX_GID_HEX || rec[0] != 'G' || rec[1] != NYX_GRP_VER)
        return false;
    g.gid = rec.substr(2, NYX_GID_HEX);
    if (!NyxIsGroupId(g.gid))
        return false;
    size_t pos = 2 + NYX_GID_HEX;
    uint64_t v;
    if (!ReadHex(rec, pos, 4, v))
        return false;
    g.epoch = (int)v;
    if (!ReadHex(rec, pos, 2, v))
        return false;
    g.op = (int)v;
    if (NyxGroupOpSigned(g.op))
    {
        if ((NyxGroupOpChained(g.op) && g.epoch < 1) || pos + 32 > rec.size())
            return false;
        g.prev = rec.substr(pos, 32);
        pos += 32;
        if (!IsHexN(g.prev, 32))
            return false;
    }
    switch (g.op)
    {
    case NYX_GOP_MSG:
    case NYX_GOP_LEAVE:
        break;
    case NYX_GOP_ROSTER:
    {
        uint64_t n;
        if (g.epoch != 0 || !ReadStr(rec, pos, NYX_GROUP_NAME_MAX, g.name) || !ValidName(g.name)
            || !ReadHex(rec, pos, 2, n) || n == 0 || n > NYX_GROUP_MAX)
            return false;
        for (size_t i = 0; i < n; i++)
        {
            std::string a;
            if (!ReadStr(rec, pos, NYX_GROUP_ADDR_MAX, a))
                return false;
            g.members.push_back(a);
        }
        if (!ValidRoster(g.members) || !ReadStr(rec, pos, NYX_GROUP_ADDR_MAX, g.creator) || !ValidAddr(g.creator)
            || !ReadHex(rec, pos, 16, v) || pos + 32 > rec.size())
            return false;
        g.createTime = (int64_t)(uint64_t)v;
        g.rnd = rec.substr(pos, 32);
        pos += 32;
        if (!ValidRnd(g.rnd))
            return false;
        break;
    }
    case NYX_GOP_ADD:
    case NYX_GOP_REMOVE:
    case NYX_GOP_OWNER:
        if (!ReadStr(rec, pos, NYX_GROUP_ADDR_MAX, g.addr) || !ValidAddr(g.addr))
            return false;
        break;
    case NYX_GOP_RENAME:
        if (!ReadStr(rec, pos, NYX_GROUP_NAME_MAX, g.name) || !ValidName(g.name))
            return false;
        break;
    case NYX_GOP_CHAIN:
    {
        uint64_t n, len;
        if (!ReadHex(rec, pos, 2, n) || n == 0 || n > NYX_CHAIN_RECS_MAX)
            return false;
        for (size_t i = 0; i < n; i++)
        {
            if (!ReadHex(rec, pos, 4, len) || pos + len > rec.size())
                return false;
            std::string r = rec.substr(pos, len);
            pos += len;
            NyxGroupRec inner;
            if (!NyxDecodeGroup(r, inner) || inner.gid != g.gid || !ChainInner(inner.op))
                return false;
            g.chain.push_back(r);
        }
        break;
    }
    default:
        return false;
    }
    if (NyxGroupOpSigned(g.op))
    {
        if (pos + NYX_SIG_HEX != rec.size())
            return false;
        g.sig = rec.substr(pos, NYX_SIG_HEX);
        pos += NYX_SIG_HEX;
        if (!IsHexN(g.sig, NYX_SIG_HEX))
            return false;
    }
    return pos == rec.size();
}

std::string NyxGroupFallback(const std::string& name)
{
    return "[group: " + name + "] ";
}

std::string NyxStripGroupFallback(const std::string& text)
{
    static const std::string pre = "[group: ";
    if (text.compare(0, pre.size(), pre) != 0)
        return text;
    size_t e = text.find("] ", pre.size());
    if (e == std::string::npos || e > pre.size() + NYX_GROUP_NAME_MAX)
        return text;
    return text.substr(e + 2);
}

std::string NyxGroupPlain(const std::string& name, const std::string& body, const NyxGroupRec& g,
                          const std::vector<std::string>& extraRecs, size_t maxBytes)
{
    std::vector<std::string> recs;
    recs.push_back(NyxEncodeGroup(g));
    if (recs[0].empty())
        return std::string();
    for (const std::string& r : extraRecs)
        if (!r.empty())
            recs.push_back(r);
    std::string ext = NyxJoinRecords(recs);
    if (ext.empty())
        return std::string();
    std::string full = NyxComposePlain(NyxGroupFallback(name) + body, ext);
    return full.size() <= maxBytes ? full : std::string();
}

bool NyxGroupState::IsMember(const std::string& a) const
{
    return std::find(members.begin(), members.end(), a) != members.end();
}

static void Snapshot(NyxGroupState& s)
{
    s.history[s.epoch] = std::set<std::string>(s.members.begin(), s.members.end());
}

static bool ApplyGenesis(NyxGroupState& s, int64_t ts, const NyxGroupRec& r)
{
    if (!NyxGroupIdBinds(r) || std::find(r.members.begin(), r.members.end(), r.creator) == r.members.end())
        return false;
    s = NyxGroupState();
    s.fValid = true;
    s.gid = r.gid;
    s.creator = r.creator;
    s.createTime = r.createTime;
    s.rnd = r.rnd;
    s.owner = r.creator;
    s.name = r.name;
    s.epoch = 0;
    s.members.push_back(r.creator);
    for (const std::string& a : r.members)
        if (a != r.creator)
            s.members.push_back(a);
    s.lastTs = ts;
    s.head = NyxGroupOpHash(r);
    s.chain.push_back(NyxEncodeGroup(r));
    Snapshot(s);
    return true;
}

// Semantics of a chained op already known to extend the head and carry the owner's signature.
static bool ApplyChained(NyxGroupState& s, int64_t ts, const NyxGroupRec& r)
{
    switch (r.op)
    {
    case NYX_GOP_ADD:
        if (s.IsMember(r.addr) || s.members.size() >= NYX_GROUP_MAX)
            return false;
        s.members.push_back(r.addr);
        s.removedAt.erase(r.addr);
        break;
    case NYX_GOP_REMOVE:
        if (r.addr == s.owner)
            return false;
        if (!s.IsMember(r.addr))
        {
            // Target already left: the op still advances the chain.
            if (!s.removedAt.count(r.addr))
                return false;
            break;
        }
        s.members.erase(std::find(s.members.begin(), s.members.end(), r.addr));
        s.removedAt[r.addr] = r.epoch;
        break;
    case NYX_GOP_RENAME:
        s.name = r.name;
        break;
    case NYX_GOP_OWNER:
        if (r.addr == s.owner)
            return false;
        if (!s.IsMember(r.addr))
        {
            if (!s.removedAt.count(r.addr))
                return false;
            break;      // target left before the handover: no-op
        }
        s.owner = r.addr;
        s.members.erase(std::find(s.members.begin(), s.members.end(), r.addr));
        s.members.insert(s.members.begin(), r.addr);
        break;
    default:
        return false;
    }
    s.epoch = r.epoch;
    s.head = NyxGroupOpHash(r);
    s.chain.push_back(NyxEncodeGroup(r));
    s.lastTs = std::max(s.lastTs, ts);
    Snapshot(s);
    return true;
}

static bool Extends(const NyxGroupState& s, const NyxGroupRec& r)
{
    return s.fValid && NyxGroupOpChained(r.op) && r.gid == s.gid && r.epoch == s.epoch + 1
           && r.epoch <= NYX_GROUP_OPS_MAX && r.prev == s.head && NyxGroupRecover(r) == s.owner;
}

// A leave is signed by the leaver and pinned to one chain position (epoch, prev = head there).
static bool ApplyLeaveAs(NyxGroupState& s, const NyxGroupRec& r, const std::string& signer)
{
    if (r.op != NYX_GOP_LEAVE || r.gid != s.gid || r.epoch != s.epoch || r.prev != s.head)
        return false;
    // The owner hands over first; a sole owner may close the group.
    if (signer.empty() || !s.IsMember(signer) || (signer == s.owner && s.members.size() > 1))
        return false;
    s.members.erase(std::find(s.members.begin(), s.members.end(), signer));
    s.removedAt[signer] = r.epoch;
    s.leaves.push_back(NyxEncodeGroup(r));
    Snapshot(s);
    return true;
}

static bool ApplyLeave(NyxGroupState& s, const NyxGroupRec& r)
{
    if (r.op != NYX_GOP_LEAVE || r.gid != s.gid || r.epoch != s.epoch || r.prev != s.head)
        return false;
    return ApplyLeaveAs(s, r, NyxGroupRecover(r));
}

bool NyxGroupApply(NyxGroupState& s, const std::string& signer, int64_t ts, const NyxGroupRec& r)
{
    if (r.op == NYX_GOP_MSG || r.op == NYX_GOP_CHAIN || s.fFrozen)
        return false;
    if (!s.fValid)
        return r.op == NYX_GOP_ROSTER && ApplyGenesis(s, ts, r);
    if (r.op == NYX_GOP_LEAVE)
        return ApplyLeave(s, r);
    if (!Extends(s, r))
        return false;
    NyxGroupState t = s;
    if (!ApplyChained(t, ts, r))
        return false;
    s = t;
    return true;
}

bool NyxGroupMsgAllowed(const NyxGroupState& s, const std::string& signer, int64_t ts, int epoch)
{
    if (!s.fValid || signer.empty() || signer == "anon" || epoch > s.epoch)
        return false;
    // Roster at the message's epoch: the latest snapshot at or below it.
    std::map<int, std::set<std::string> >::const_iterator it = s.history.upper_bound(epoch);
    if (it == s.history.begin())
        return false;
    --it;
    // The message epoch is sender-chosen, so a former member is refused outright.
    return it->second.count(signer) && s.IsMember(signer);
}

std::map<std::string, NyxGroupState> NyxBuildGroups(const std::vector<NyxGroupEvent>& events)
{
    struct Op { NyxGroupRec rec; int64_t ts; };
    std::map<std::string, std::map<std::string, NyxGroupRec> > genesis; // gid -> hash -> binding genesis
    std::map<std::string, std::map<std::string, Op> > ops;               // gid -> op hash -> op
    typedef std::pair<int, std::string> Pos;                             // (epoch, prev)
    std::map<std::string, std::map<Pos, std::map<std::string, NyxGroupRec> > > leaves; // gid -> pos -> encoding -> leave
    std::vector<std::pair<NyxGroupRec, int64_t> > flat;
    for (const NyxGroupEvent& e : events)
    {
        if (e.rec.op == NYX_GOP_MSG)
            continue;
        if (e.rec.op == NYX_GOP_CHAIN)
        {
            for (const std::string& raw : e.rec.chain)
            {
                NyxGroupRec n;
                if (NyxDecodeGroup(raw, n) && n.gid == e.rec.gid)
                    flat.push_back(std::make_pair(n, e.ts));
            }
            continue;
        }
        flat.push_back(std::make_pair(e.rec, e.ts));
    }
    for (const auto& p : flat)
    {
        const NyxGroupRec& r = p.first;
        if (r.op == NYX_GOP_ROSTER)
        {
            if (NyxGroupIdBinds(r))
                genesis[r.gid].insert(std::make_pair(NyxGroupOpHash(r), r));
        }
        else if (r.op == NYX_GOP_LEAVE)
        {
            // Uncapped: a cap lets junk crowd out a member's leave. Recovered only at chain positions.
            // Keyed by encoding: the digest omits the signer, so every leave at one position shares a hash.
            leaves[r.gid][Pos(r.epoch, r.prev)].insert(std::make_pair(NyxEncodeGroup(r), r));
        }
        else if (NyxGroupOpChained(r.op))
        {
            Op& o = ops[r.gid].insert(std::make_pair(NyxGroupOpHash(r), Op{r, p.second})).first->second;
            o.ts = std::min(o.ts, p.second);
        }
    }
    std::map<std::string, NyxGroupState> out;
    for (const auto& g : genesis)
    {
        NyxGroupState s;
        if (!ApplyGenesis(s, 0, g.second.begin()->second))
            continue;
        if (g.second.size() > 1)
        {
            s.fFrozen = true;               // two binding geneses for one gid
            out[g.first] = s;
            continue;
        }
        std::map<std::string, Op>& pool = ops[g.first];
        const std::map<Pos, std::map<std::string, NyxGroupRec> >& lv = leaves[g.first];
        for (;;)
        {
            // Leaves pinned to this position, each recovered once; members first so a sole owner's leave can follow.
            std::map<Pos, std::map<std::string, NyxGroupRec> >::const_iterator b = lv.find(Pos(s.epoch, s.head));
            if (b != lv.end())
            {
                std::vector<std::pair<const NyxGroupRec*, std::string> > here;
                for (const auto& l : b->second)
                    here.push_back(std::make_pair(&l.second, NyxGroupRecover(l.second)));
                for (int pass = 0; pass < 2; pass++)
                    for (const auto& l : here)
                        if ((l.second == s.owner) == (pass == 1))
                            ApplyLeaveAs(s, *l.first, l.second);
            }
            std::vector<const Op*> next;
            for (const auto& o : pool)
                if (Extends(s, o.second.rec))
                    next.push_back(&o.second);
            if (next.empty())
                break;
            if (next.size() > 1)
            {
                // A fork is settled by a member other than the forking signer building on one side:
                // after a handover the old owner can still sign at its last position.
                std::vector<const Op*> confirmed;
                for (const Op* c : next)
                {
                    NyxGroupState t = s;
                    if (!ApplyChained(t, c->ts, c->rec) || t.owner == s.owner || !s.IsMember(t.owner))
                        continue;
                    for (const auto& o : pool)
                        if (Extends(t, o.second.rec))
                        {
                            confirmed.push_back(c);
                            break;
                        }
                }
                if (confirmed.size() != 1)
                {
                    s.fFrozen = true;
                    break;
                }
                next = confirmed;
            }
            if (!ApplyChained(s, next[0]->ts, next[0]->rec))
                break;
        }
        out[g.first] = s;
    }
    return out;
}

std::string NyxEncodeTyping(bool fTyping)
{
    std::string s(1, 'T');
    s.push_back(NYX_GRP_VER);
    s.push_back(fTyping ? '\x01' : '\x02');
    return s;
}

bool NyxDecodeTyping(const std::string& rec, bool& fTyping)
{
    if (rec.size() != 3 || rec[0] != 'T' || rec[1] != NYX_GRP_VER || (rec[2] != '\x01' && rec[2] != '\x02'))
        return false;
    fTyping = rec[2] == '\x01';
    return true;
}
