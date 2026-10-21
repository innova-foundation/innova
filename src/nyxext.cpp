// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "nyxext.h"
#include "nyxembed.h"

#include <openssl/sha.h>

#include <algorithm>
#include <deque>
#include <map>
#include <set>

static const char NYX_EXT_VER = '\x01';

std::string NyxMessageId(const std::string& sender, int64_t timestamp, const std::string& fullPlain)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, sender.data(), sender.size());
    unsigned char ts[8];
    for (int i = 0; i < 8; i++)
        ts[i] = (unsigned char)(((uint64_t)timestamp >> (8 * i)) & 0xFF);
    SHA256_Update(&ctx, ts, 8);
    SHA256_Update(&ctx, fullPlain.data(), fullPlain.size());
    unsigned char h[32];
    SHA256_Final(h, &ctx);
    static const char* hex = "0123456789abcdef";
    std::string out;
    for (int i = 0; i < 8; i++)
    {
        out.push_back(hex[h[i] >> 4]);
        out.push_back(hex[h[i] & 15]);
    }
    return out;
}

static std::string Hex(size_t v, int digits)
{
    static const char* hex = "0123456789abcdef";
    std::string s(digits, '0');
    for (int i = digits - 1; i >= 0; i--, v >>= 4)
        s[i] = hex[v & 15];
    return s;
}

static bool ReadHex(const std::string& s, size_t pos, int digits, size_t& v)
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
    return true;
}

static bool Head(const std::string& rec, char tag, std::string& mid)
{
    if (rec.size() < 18 || rec[0] != tag || rec[1] != NYX_EXT_VER)
        return false;
    mid = rec.substr(2, 16);
    return NyxIsHexId(mid);
}

static std::string EncodeLenStr(const std::string& s)
{
    return Hex(s.size(), 2) + s;
}

static bool DecodeLenStr(const std::string& rec, size_t pos, std::string& s)
{
    size_t n;
    if (!ReadHex(rec, pos, 2, n) || pos + 2 + n != rec.size())
        return false;
    s = rec.substr(pos + 2);
    return true;
}

std::string NyxEncodeReply(const NyxReply& r)
{
    if (!NyxIsHexId(r.mid))
        return std::string();
    return std::string(1, 'R') + NYX_EXT_VER + r.mid + EncodeLenStr(NyxCleanText(r.quote, NYX_QUOTE_MAX));
}

bool NyxDecodeReply(const std::string& rec, NyxReply& r)
{
    std::string q;
    if (!Head(rec, 'R', r.mid) || !DecodeLenStr(rec, 18, q) || q.size() > NYX_QUOTE_MAX)
        return false;
    r.quote = NyxCleanText(q, NYX_QUOTE_MAX);
    return true;
}

std::string NyxEncodeReact(const NyxReact& k)
{
    if (!NyxIsHexId(k.mid) || !NyxIsReactionEmoji(k.emoji))
        return std::string();
    return std::string(1, 'K') + NYX_EXT_VER + k.mid + (k.fAdd ? '\x01' : '\x02') + EncodeLenStr(k.emoji);
}

bool NyxDecodeReact(const std::string& rec, NyxReact& k)
{
    if (!Head(rec, 'K', k.mid) || rec.size() < 19 || (rec[18] != '\x01' && rec[18] != '\x02'))
        return false;
    k.fAdd = rec[18] == '\x01';
    return DecodeLenStr(rec, 19, k.emoji) && NyxIsReactionEmoji(k.emoji);
}

std::string NyxEncodeEdit(const NyxEdit& e)
{
    if (!NyxIsHexId(e.mid) || e.seq < 1 || e.seq > 255)
        return std::string();
    return std::string(1, 'E') + NYX_EXT_VER + e.mid + Hex(e.seq, 2);
}

bool NyxDecodeEdit(const std::string& rec, NyxEdit& e)
{
    size_t seq;
    if (!Head(rec, 'E', e.mid) || rec.size() != 20 || !ReadHex(rec, 18, 2, seq) || seq < 1)
        return false;
    e.seq = (int)seq;
    return true;
}

std::string NyxEncodeDelete(const std::string& mid)
{
    if (!NyxIsHexId(mid))
        return std::string();
    return std::string(1, 'D') + NYX_EXT_VER + mid;
}

bool NyxDecodeDelete(const std::string& rec, std::string& mid)
{
    return rec.size() == 18 && Head(rec, 'D', mid);
}

std::string NyxJoinRecords(const std::vector<std::string>& recs)
{
    std::vector<std::string> v;
    for (const std::string& r : recs)
        if (!r.empty())
            v.push_back(r);
    if (v.empty())
        return std::string();
    if (v.size() == 1)
        return v[0];
    std::string s(1, 'M');
    s.push_back(NYX_EXT_VER);
    for (const std::string& r : v)
    {
        if (r.size() > 0xFFFF)
            return std::string();
        s += Hex(r.size(), 4) + r;
    }
    return s;
}

bool NyxSplitRecords(const std::string& ext, std::vector<std::string>& out)
{
    out.clear();
    if (ext.empty())
        return true;
    if (ext.size() < 2 || ext[0] != 'M' || ext[1] != NYX_EXT_VER)
    {
        out.push_back(ext);
        return true;
    }
    size_t pos = 2;
    while (pos < ext.size())
    {
        size_t n;
        if (!ReadHex(ext, pos, 4, n) || n == 0 || pos + 4 + n > ext.size() || out.size() >= 8)
        {
            out.clear();
            return false;
        }
        out.push_back(ext.substr(pos + 4, n));
        pos += 4 + n;
    }
    return out.size() >= 2 || (out.clear(), false);
}

bool NyxIsReactionEmoji(const std::string& e)
{
    if (e.empty() || e.size() > NYX_EMOJI_MAX || NyxCleanText(e, NYX_EMOJI_MAX) != e)
        return false;
    bool fHigh = false;
    for (unsigned char c : e)
    {
        if (c >= 0x80)
            fHigh = true;
        else if (!((c >= '0' && c <= '9') || c == '#' || c == '*'))
            return false;
    }
    return fHigh;
}

std::string NyxReplyPlain(const std::string& body, const NyxReply& r, const std::string& extraRec, size_t maxBytes)
{
    std::vector<std::string> recs;
    recs.push_back(NyxEncodeReply(r));
    if (recs[0].empty())
        return std::string();
    if (!extraRec.empty())
        recs.push_back(extraRec);
    std::string full = NyxComposePlain(body, NyxJoinRecords(recs));
    return full.size() <= maxBytes ? full : std::string();
}

std::string NyxReactPlain(const NyxReact& k)
{
    std::string rec = NyxEncodeReact(k);
    if (rec.empty())
        return std::string();
    return NyxComposePlain((k.fAdd ? "[reacted " : "[unreacted ") + k.emoji + "]", rec);
}

std::string NyxEditPlain(const std::string& body, const NyxEdit& e, size_t maxBytes)
{
    std::string rec = NyxEncodeEdit(e);
    if (rec.empty() || body.empty())
        return std::string();
    std::string full = NyxComposePlain(NYX_EDITED_PREFIX + body, rec);
    return full.size() <= maxBytes ? full : std::string();
}

std::string NyxDeletePlain(const std::string& mid)
{
    std::string rec = NyxEncodeDelete(mid);
    return rec.empty() ? std::string() : NyxComposePlain(NYX_DELETED_TEXT, rec);
}

NyxRecords NyxParseRecords(const std::string& ext)
{
    NyxRecords r;
    std::vector<std::string> recs;
    if (!NyxSplitRecords(ext, recs))
        return r;
    for (const std::string& rec : recs)
    {
        if (rec.empty())
            continue;
        switch (rec[0])
        {
        case 'R': if (!r.fReply) r.fReply = NyxDecodeReply(rec, r.reply); break;
        case 'K': if (!r.fReact) r.fReact = NyxDecodeReact(rec, r.react); break;
        case 'E': if (!r.fEdit) r.fEdit = NyxDecodeEdit(rec, r.edit); break;
        case 'D': if (!r.fDelete) r.fDelete = NyxDecodeDelete(rec, r.delMid); break;
        case 'G': if (!r.fGroup) r.fGroup = NyxDecodeGroup(rec, r.group); break;
        case 'T': if (!r.fTyping) r.fTyping = NyxDecodeTyping(rec, r.typingOn); break;
        default: if (r.embedRec.empty()) r.embedRec = rec; break;
        }
    }
    // One control kind per message; a mix is malformed.
    if ((int)r.fReact + (int)r.fEdit + (int)r.fDelete > 1)
        r.fReact = r.fEdit = r.fDelete = false;
    return r;
}

std::vector<NyxMsgView> NyxBuildThread(const std::vector<NyxThreadMsg>& rows,
                                       const std::function<bool(const std::string&)>& fReactAllowed)
{
    const size_t n = rows.size();
    std::vector<NyxMsgView> v(n);
    std::vector<NyxRecords> recs(n);
    std::map<std::string, size_t> base;
    std::vector<size_t> controls;

    for (size_t i = 0; i < n; i++)
    {
        v[i].text = rows[i].text;
        if (rows[i].sender == "anon" || rows[i].sender.empty())
        {
            if (!base.count(rows[i].mid))
                base[rows[i].mid] = i;
            continue;
        }
        recs[i] = NyxParseRecords(rows[i].ext);
        if (recs[i].IsControl())
        {
            v[i].fControl = true;
            controls.push_back(i);
        }
        else if (!base.count(rows[i].mid))
            base[rows[i].mid] = i;
    }

    std::stable_sort(controls.begin(), controls.end(), [&](size_t a, size_t b) {
        if (rows[a].ts != rows[b].ts)
            return rows[a].ts < rows[b].ts;
        return rows[a].mid < rows[b].mid;
    });

    // reactions[target][emoji] = reactors; emoji order by first add
    std::map<size_t, std::vector<std::pair<std::string, std::set<std::string> > > > reacts;
    std::map<std::string, std::deque<int64_t> > rate;

    for (size_t i : controls)
    {
        const NyxRecords& r = recs[i];
        const std::string& from = rows[i].sender;
        const std::string target = r.fDelete ? r.delMid : r.fEdit ? r.edit.mid : r.react.mid;
        auto it = base.find(target);
        if (r.fDelete)
        {
            if (it == base.end())
            {
                v[i].fControl = false;   // original already wiped: show the tombstone here
                v[i].fTombstone = true;
                v[i].text = NYX_DELETED_TEXT;
            }
            else if (rows[it->second].sender == from)
            {
                NyxMsgView& t = v[it->second];
                t.fTombstone = true;
                t.fEdited = false;
                t.text = NYX_DELETED_TEXT;
                reacts.erase(it->second);
            }
            continue;
        }
        if (it == base.end() || v[it->second].fTombstone)
            continue;
        const size_t ti = it->second;
        if (r.fEdit)
        {
            if (rows[ti].sender != from || rows[i].ts > rows[ti].ts + NYX_EDIT_WINDOW || r.edit.seq <= v[ti].seq)
                continue;
            std::string body = rows[i].text;
            const std::string pre = NYX_EDITED_PREFIX;
            if (body.compare(0, pre.size(), pre) == 0)
                body = body.substr(pre.size());
            v[ti].text = body;
            v[ti].seq = r.edit.seq;
            v[ti].fEdited = true;
            continue;
        }
        // reaction
        if (!fReactAllowed || !fReactAllowed(from))
            continue;
        std::deque<int64_t>& q = rate[from];
        while (!q.empty() && q.front() <= rows[i].ts - NYX_REACT_WINDOW)
            q.pop_front();
        if (q.size() >= NYX_REACT_MAX_OPS)
            continue;
        q.push_back(rows[i].ts);
        auto& lst = reacts[ti];
        size_t mine = 0;
        for (const auto& e : lst)
            mine += e.second.count(from);
        auto e = std::find_if(lst.begin(), lst.end(), [&](const std::pair<std::string, std::set<std::string> >& p) {
            return p.first == r.react.emoji;
        });
        if (r.react.fAdd)
        {
            if (e != lst.end() && e->second.count(from))
                continue;
            if (mine >= NYX_REACT_MAX_EMOJI)
                continue;
            if (e == lst.end())
            {
                lst.push_back(std::make_pair(r.react.emoji, std::set<std::string>()));
                e = lst.end() - 1;
            }
            e->second.insert(from);
        }
        else if (e != lst.end())
            e->second.erase(from);
    }

    for (const auto& p : reacts)
        for (const auto& e : p.second)
            if (!e.second.empty())
                v[p.first].reactions.push_back(std::make_pair(e.first,
                    std::vector<std::string>(e.second.begin(), e.second.end())));

    for (size_t i = 0; i < n; i++)
    {
        if (v[i].fControl || v[i].fTombstone || !recs[i].fReply)
            continue;
        v[i].fReply = true;
        v[i].reply = recs[i].reply;
        auto it = base.find(recs[i].reply.mid);
        if (it != base.end() && it->second != i)
            v[i].replyIndex = (int)it->second;
    }
    return v;
}
