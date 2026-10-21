// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "nyxgroup.h"
#include "nyxembed.h"
#include "nyxext.h"
#include "nyxsafety.h"

#include <openssl/sha.h>

#include <algorithm>

static const char NYX_GRP_VER = '\x01';
static const char* const HEXD = "0123456789abcdef";

static std::string Hex(size_t v, int digits)
{
    std::string s(digits, '0');
    for (int i = digits - 1; i >= 0; i--, v >>= 4)
        s[i] = HEXD[v & 15];
    return s;
}

static bool ReadHex(const std::string& s, size_t& pos, int digits, size_t& v)
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
    size_t n;
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

std::string NyxNewGroupId(const std::string& creator, int64_t createTime, const unsigned char rnd[16])
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, creator.data(), creator.size());
    unsigned char ts[8];
    for (int i = 0; i < 8; i++)
        ts[i] = (unsigned char)(((uint64_t)createTime >> (8 * i)) & 0xFF);
    SHA256_Update(&ctx, ts, 8);
    SHA256_Update(&ctx, rnd, 16);
    unsigned char h[32];
    SHA256_Final(h, &ctx);
    std::string out;
    for (int i = 0; i < 8; i++)
    {
        out.push_back(HEXD[h[i] >> 4]);
        out.push_back(HEXD[h[i] & 15]);
    }
    return out;
}

std::string NyxEncodeGroup(const NyxGroupRec& g)
{
    if (!NyxIsHexId(g.gid) || g.epoch < 0 || g.epoch > 0xFFFF)
        return std::string();
    std::string s(1, 'G');
    s.push_back(NYX_GRP_VER);
    s += g.gid + Hex(g.epoch, 4) + Hex(g.op, 2);
    switch (g.op)
    {
    case NYX_GOP_MSG:
    case NYX_GOP_LEAVE:
        break;
    case NYX_GOP_ROSTER:
        if (!ValidName(g.name) || !ValidRoster(g.members))
            return std::string();
        s += Hex(g.name.size(), 2) + g.name + Hex(g.members.size(), 2);
        for (const std::string& a : g.members)
            s += Hex(a.size(), 2) + a;
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
    default:
        return std::string();
    }
    return s;
}

bool NyxDecodeGroup(const std::string& rec, NyxGroupRec& g)
{
    g = NyxGroupRec();
    if (rec.size() < 24 || rec[0] != 'G' || rec[1] != NYX_GRP_VER)
        return false;
    g.gid = rec.substr(2, 16);
    if (!NyxIsHexId(g.gid))
        return false;
    size_t pos = 18, v;
    if (!ReadHex(rec, pos, 4, v))
        return false;
    g.epoch = (int)v;
    if (!ReadHex(rec, pos, 2, v))
        return false;
    g.op = (int)v;
    switch (g.op)
    {
    case NYX_GOP_MSG:
    case NYX_GOP_LEAVE:
        break;
    case NYX_GOP_ROSTER:
    {
        size_t n;
        if (!ReadStr(rec, pos, NYX_GROUP_NAME_MAX, g.name) || !ValidName(g.name)
            || !ReadHex(rec, pos, 2, n) || n == 0 || n > NYX_GROUP_MAX)
            return false;
        for (size_t i = 0; i < n; i++)
        {
            std::string a;
            if (!ReadStr(rec, pos, NYX_GROUP_ADDR_MAX, a))
                return false;
            g.members.push_back(a);
        }
        if (!ValidRoster(g.members))
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
    default:
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

bool NyxGroupApply(NyxGroupState& s, const std::string& signer, int64_t ts, const NyxGroupRec& r)
{
    if (signer.empty() || signer == "anon" || r.op == NYX_GOP_MSG)
        return false;
    if (!s.fValid)
    {
        // First sight: a roster snapshot from a member who becomes the owner.
        if (r.op != NYX_GOP_ROSTER || !ValidRoster(r.members)
            || std::find(r.members.begin(), r.members.end(), signer) == r.members.end())
            return false;
        s.fValid = true;
        s.gid = r.gid;
        s.owner = signer;
        s.name = r.name;
        s.epoch = r.epoch;
        s.members.clear();
        s.members.push_back(signer);
        for (const std::string& a : r.members)
            if (a != signer)
                s.members.push_back(a);
        s.lastTs = ts;
        Snapshot(s);
        return true;
    }
    if (r.gid != s.gid || r.epoch != s.epoch + 1)
        return false;
    const bool fOwner = signer == s.owner;
    switch (r.op)
    {
    case NYX_GOP_ROSTER:
    {
        if (!fOwner || !ValidRoster(r.members)
            || std::find(r.members.begin(), r.members.end(), s.owner) == r.members.end())
            return false;
        for (const std::string& a : s.members)
            if (std::find(r.members.begin(), r.members.end(), a) == r.members.end())
                s.removedAt[a] = ts;
        s.members.clear();
        s.members.push_back(s.owner);
        for (const std::string& a : r.members)
            if (a != s.owner)
                s.members.push_back(a);
        s.name = r.name;
        break;
    }
    case NYX_GOP_ADD:
        if (!fOwner || s.IsMember(r.addr) || s.members.size() >= NYX_GROUP_MAX)
            return false;
        s.members.push_back(r.addr);
        s.removedAt.erase(r.addr);
        break;
    case NYX_GOP_REMOVE:
        if (!fOwner || r.addr == s.owner || !s.IsMember(r.addr))
            return false;
        s.members.erase(std::find(s.members.begin(), s.members.end(), r.addr));
        s.removedAt[r.addr] = ts;
        break;
    case NYX_GOP_LEAVE:
        // The owner hands over first; a sole owner may close the group.
        if (!s.IsMember(signer) || (fOwner && s.members.size() > 1))
            return false;
        s.members.erase(std::find(s.members.begin(), s.members.end(), signer));
        s.removedAt[signer] = ts;
        break;
    case NYX_GOP_RENAME:
        if (!fOwner)
            return false;
        s.name = r.name;
        break;
    case NYX_GOP_OWNER:
        if (!fOwner || !s.IsMember(r.addr) || r.addr == s.owner)
            return false;
        s.owner = r.addr;
        s.members.erase(std::find(s.members.begin(), s.members.end(), r.addr));
        s.members.insert(s.members.begin(), r.addr);
        break;
    default:
        return false;
    }
    s.epoch = r.epoch;
    s.lastTs = std::max(s.lastTs, ts);
    Snapshot(s);
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
    if (!it->second.count(signer))
        return false;
    if (s.IsMember(signer))
        return true;
    // A former member's old-epoch messages count only up to its removal.
    std::map<std::string, int64_t>::const_iterator r = s.removedAt.find(signer);
    return r != s.removedAt.end() && ts <= r->second;
}

std::map<std::string, NyxGroupState> NyxBuildGroups(const std::vector<NyxGroupEvent>& events)
{
    std::vector<const NyxGroupEvent*> v;
    std::set<std::string> seen;
    for (const NyxGroupEvent& e : events)
    {
        if (e.rec.op == NYX_GOP_MSG || e.sender.empty() || e.sender == "anon")
            continue;
        if (!e.mid.empty() && !seen.insert(e.mid).second)
            continue;
        v.push_back(&e);
    }
    std::stable_sort(v.begin(), v.end(), [](const NyxGroupEvent* a, const NyxGroupEvent* b) {
        if (a->rec.epoch != b->rec.epoch)
            return a->rec.epoch < b->rec.epoch;
        if (a->ts != b->ts)
            return a->ts < b->ts;
        return a->mid < b->mid;
    });
    std::map<std::string, NyxGroupState> out;
    for (const NyxGroupEvent* e : v)
        NyxGroupApply(out[e->rec.gid], e->sender, e->ts, e->rec);
    for (std::map<std::string, NyxGroupState>::iterator it = out.begin(); it != out.end();)
        if (!it->second.fValid)
            out.erase(it++);
        else
            ++it;
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
