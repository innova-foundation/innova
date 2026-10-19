// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "nyxembed.h"
#include "util.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <strings.h>

static const char* const EMBED_TAG = "nyx-embed:1:";
static const char* const CTL_TAG = "nyx-ctl:1:rmembed:";

void NyxSplitPlain(const std::string& full, std::string& text, std::string& ext)
{
    size_t z = full.find('\0');
    if (z == std::string::npos)
    {
        text = full;
        ext.clear();
        return;
    }
    text = full.substr(0, z);
    ext = full.substr(z + 1);
    size_t z2 = ext.find('\0');
    if (z2 != std::string::npos)
        ext.resize(z2);
}

std::string NyxComposePlain(const std::string& text, const std::string& ext)
{
    if (ext.empty())
        return text;
    std::string s = text;
    s.push_back('\0');
    s += ext;
    return s;
}

bool NyxIsHexId(const std::string& id)
{
    if (id.size() != 16)
        return false;
    for (char c : id)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    return true;
}

// Cut to at most n bytes without splitting a UTF-8 sequence.
static std::string Utf8Cap(const std::string& s, size_t n)
{
    if (s.size() <= n)
        return s;
    size_t k = n;
    while (k > 0 && ((unsigned char)s[k] & 0xC0) == 0x80)
        k--;
    return s.substr(0, k);
}

// Drop control characters and invalid UTF-8, collapse whitespace runs.
static std::string CleanText(const std::string& in, size_t cap)
{
    std::string out;
    bool fSpace = false;
    size_t i = 0;
    while (i < in.size())
    {
        unsigned char c = in[i];
        size_t len = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
        if (len == 0 || i + len > in.size())
        {
            i++;
            continue;
        }
        bool ok = true;
        for (size_t k = 1; k < len; k++)
            if (((unsigned char)in[i + k] & 0xC0) != 0x80)
                ok = false;
        if (!ok)
        {
            i++;
            continue;
        }
        if (len == 1)
        {
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
            {
                fSpace = true;
                i++;
                continue;
            }
            if (c < 0x20 || c == 0x7F)
            {
                i++;
                continue;
            }
        }
        else if (len == 2 && c == 0xC2 && (unsigned char)in[i + 1] < 0xA0)
        {
            i += 2; // C1 controls
            continue;
        }
        else if (len == 3 && c == 0xE2 && (unsigned char)in[i + 1] == 0x80
                 && ((unsigned char)in[i + 2] >= 0xAA && (unsigned char)in[i + 2] <= 0xAE))
        {
            i += 3; // bidi embedding/override
            continue;
        }
        else if (len == 3 && c == 0xE2 && (unsigned char)in[i + 1] == 0x81
                 && ((unsigned char)in[i + 2] >= 0xA6 && (unsigned char)in[i + 2] <= 0xA9))
        {
            i += 3; // bidi isolates
            continue;
        }
        if (fSpace && !out.empty())
            out.push_back(' ');
        fSpace = false;
        out.append(in, i, len);
        i += len;
    }
    return Utf8Cap(out, cap);
}

static bool StrictB64(const std::string& s, std::string& out)
{
    if (s.size() % 4 != 0)
        return false;
    for (char c : s)
        if (!(isalnum((unsigned char)c) || c == '+' || c == '/' || c == '='))
            return false;
    bool fInvalid = false;
    std::vector<unsigned char> v = DecodeBase64(s.c_str(), &fInvalid);
    if (fInvalid)
        return false;
    out.assign(v.begin(), v.end());
    return true;
}

static std::vector<std::string> SplitColon(const std::string& s)
{
    std::vector<std::string> parts;
    size_t start = 0;
    for (;;)
    {
        size_t p = s.find(':', start);
        if (p == std::string::npos)
        {
            parts.push_back(s.substr(start));
            break;
        }
        parts.push_back(s.substr(start, p - start));
        start = p + 1;
    }
    return parts;
}

std::string NyxEncodeEmbed(const NyxEmbed& e)
{
    return std::string(EMBED_TAG) + e.id
        + ":" + EncodeBase64(e.url) + ":" + EncodeBase64(e.title)
        + ":" + EncodeBase64(e.desc) + ":" + EncodeBase64(e.site)
        + ":" + EncodeBase64(e.thumb);
}

bool NyxDecodeEmbed(const std::string& ext, NyxEmbed& e)
{
    const size_t tagLen = strlen(EMBED_TAG);
    if (ext.compare(0, tagLen, EMBED_TAG) != 0)
        return false;
    std::vector<std::string> f = SplitColon(ext.substr(tagLen));
    if (f.size() != 6 || !NyxIsHexId(f[0]))
        return false;
    std::string url, title, desc, site, thumb;
    if (!StrictB64(f[1], url) || !StrictB64(f[2], title) || !StrictB64(f[3], desc)
        || !StrictB64(f[4], site) || !StrictB64(f[5], thumb))
        return false;
    if (url.size() > NYX_EMBED_MAX_URL || url.compare(0, 8, "https://") != 0 || !NyxIsLinkableUrl(url))
        return false;
    if (thumb.size() > NYX_EMBED_MAX_THUMB)
        return false;
    if (!thumb.empty() && (thumb.size() < 4 || (unsigned char)thumb[0] != 0xFF
                           || (unsigned char)thumb[1] != 0xD8 || (unsigned char)thumb[2] != 0xFF))
        return false;
    e.id = f[0];
    e.url = url;
    e.title = CleanText(title, NYX_EMBED_MAX_TITLE);
    e.desc = CleanText(desc, NYX_EMBED_MAX_DESC);
    e.site = CleanText(site, NYX_EMBED_MAX_SITE);
    e.thumb = thumb;
    if (e.site.empty())
        e.site = NyxUrlHost(url);
    return true;
}

std::string NyxEncodeRemoval(const std::string& id)
{
    return std::string(CTL_TAG) + id;
}

bool NyxDecodeRemoval(const std::string& ext, std::string& id)
{
    const size_t tagLen = strlen(CTL_TAG);
    if (ext.size() != tagLen + 16 || ext.compare(0, tagLen, CTL_TAG) != 0)
        return false;
    id = ext.substr(tagLen);
    return NyxIsHexId(id);
}

std::string NyxRemovalPlain(const std::string& id)
{
    return NyxComposePlain(NYX_CTL_VISIBLE, NyxEncodeRemoval(id));
}

bool NyxEmbedHidden(const std::string& owner, const std::string& id,
                    const std::vector<std::pair<std::string, std::string> >& removals)
{
    if (owner.empty() || owner == "anon")
        return false;
    for (const auto& r : removals)
        if (r.first == owner && r.second == id)
            return true;
    return false;
}

std::string NyxFitEmbed(const std::string& text, NyxEmbed e, size_t maxBytes)
{
    e.title = Utf8Cap(e.title, NYX_EMBED_MAX_TITLE);
    e.desc = Utf8Cap(e.desc, NYX_EMBED_MAX_DESC);
    e.site = Utf8Cap(e.site, NYX_EMBED_MAX_SITE);
    if (e.thumb.size() > NYX_EMBED_MAX_THUMB)
        e.thumb.clear();
    if (!NyxIsHexId(e.id) || e.url.size() > NYX_EMBED_MAX_URL)
        return std::string();
    for (int step = 0; step < 4; step++)
    {
        if (step == 1) e.thumb.clear();
        if (step == 2) e.desc.clear();
        if (step == 3) e.title = Utf8Cap(e.title, 40);
        std::string ext = NyxEncodeEmbed(e);
        if (text.size() + 1 + ext.size() <= maxBytes)
            return ext;
    }
    return std::string();
}

static bool IsUrlChar(unsigned char c)
{
    return c > 0x20 && c < 0x7F && c != '<' && c != '>' && c != '"' && c != '\'' && c != '`'
        && c != '\\' && c != '{' && c != '}' && c != '|' && c != '^';
}

std::string NyxUrlHost(const std::string& url)
{
    size_t p;
    if (url.size() > 8 && strncasecmp(url.c_str(), "https://", 8) == 0)
        p = 8;
    else if (url.size() > 7 && strncasecmp(url.c_str(), "http://", 7) == 0)
        p = 7;
    else
        return std::string();
    size_t end = url.find_first_of("/?#", p);
    std::string auth = url.substr(p, end == std::string::npos ? std::string::npos : end - p);
    if (auth.empty() || auth.find('@') != std::string::npos)
        return std::string();
    std::string host = auth;
    size_t colon = host.find(':');
    if (colon != std::string::npos)
    {
        std::string port = host.substr(colon + 1);
        host.resize(colon);
        if (port.empty() || port.size() > 5)
            return std::string();
        for (char c : port)
            if (!isdigit((unsigned char)c))
                return std::string();
    }
    if (host.empty() || host.size() > 253 || host[0] == '.' || host[0] == '-')
        return std::string();
    for (char& c : host)
    {
        if (!(isalnum((unsigned char)c) || c == '.' || c == '-'))
            return std::string();
        c = tolower((unsigned char)c);
    }
    return host;
}

bool NyxIsLinkableUrl(const std::string& url)
{
    if (url.empty() || url.size() > 2048)
        return false;
    for (char c : url)
        if (!IsUrlChar((unsigned char)c))
            return false;
    return !NyxUrlHost(url).empty();
}

std::string NyxHtmlEscape(const std::string& s)
{
    std::string o;
    o.reserve(s.size() + 16);
    for (char c : s)
    {
        switch (c)
        {
            case '&': o += "&amp;"; break;
            case '<': o += "&lt;"; break;
            case '>': o += "&gt;"; break;
            case '"': o += "&quot;"; break;
            case '\'': o += "&#39;"; break;
            default: o.push_back(c);
        }
    }
    return o;
}

// Find the next URL candidate at or after pos; returns start or npos, sets len.
static size_t NextUrl(const std::string& t, size_t pos, size_t& len)
{
    while (pos < t.size())
    {
        size_t a = std::string::npos;
        for (size_t i = pos; i + 7 <= t.size(); i++)
        {
            if ((t[i] == 'h' || t[i] == 'H')
                && (strncasecmp(&t[i], "http://", 7) == 0
                    || (i + 8 <= t.size() && strncasecmp(&t[i], "https://", 8) == 0))
                && (i == 0 || !isalnum((unsigned char)t[i - 1])))
            {
                a = i;
                break;
            }
        }
        if (a == std::string::npos)
            return std::string::npos;
        size_t b = a;
        while (b < t.size() && IsUrlChar((unsigned char)t[b]))
            b++;
        while (b > a && strchr(".,;:!?)]*", t[b - 1]))
            b--;
        if (NyxIsLinkableUrl(t.substr(a, b - a)))
        {
            len = b - a;
            return a;
        }
        pos = a + 4;
    }
    return std::string::npos;
}

static std::string EscapeWithBreaks(const std::string& s)
{
    std::string e = NyxHtmlEscape(s), o;
    for (char c : e)
    {
        if (c == '\n') o += "<br>";
        else if (c != '\r') o.push_back(c);
    }
    return o;
}

std::string NyxLinkify(const std::string& text)
{
    std::string out;
    size_t pos = 0, len = 0;
    for (;;)
    {
        size_t a = NextUrl(text, pos, len);
        if (a == std::string::npos)
        {
            out += EscapeWithBreaks(text.substr(pos));
            break;
        }
        out += EscapeWithBreaks(text.substr(pos, a - pos));
        std::string u = NyxHtmlEscape(text.substr(a, len));
        out += "<a href=\"" + u + "\">" + u + "</a>";
        pos = a + len;
    }
    return out;
}

std::string NyxFirstHttpsUrl(const std::string& text)
{
    size_t pos = 0, len = 0;
    for (;;)
    {
        size_t a = NextUrl(text, pos, len);
        if (a == std::string::npos)
            return std::string();
        std::string u = text.substr(a, len);
        if (strncasecmp(u.c_str(), "https://", 8) == 0)
            return u;
        pos = a + len;
    }
}

static bool EndsWith(const std::string& s, const std::string& suf)
{
    return s.size() >= suf.size() && s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

bool NyxIsFetchableHost(const std::string& host, bool fAllowOnion)
{
    if (host.empty() || host.find('.') == std::string::npos)
        return false;
    bool fAllNumeric = true;
    for (char c : host)
        if (!(isdigit((unsigned char)c) || c == '.'))
            fAllNumeric = false;
    if (fAllNumeric)
        return false;
    // Hex/octal-ish dotted forms like 0x7f.1 are IP literals to some resolvers.
    if (host.compare(0, 2, "0x") == 0)
        return false;
    if (host == "localhost" || EndsWith(host, ".localhost") || EndsWith(host, ".local")
        || EndsWith(host, ".internal") || EndsWith(host, ".lan") || EndsWith(host, ".home")
        || EndsWith(host, ".arpa") || EndsWith(host, ".i2p"))
        return false;
    if (EndsWith(host, ".onion") && !fAllowOnion)
        return false;
    return true;
}

bool NyxIsPublicAddress(const unsigned char* a, size_t len)
{
    if (len == 4)
    {
        if (a[0] == 0 || a[0] == 10 || a[0] == 127 || a[0] >= 224) return false;
        if (a[0] == 100 && (a[1] & 0xC0) == 64) return false;   // 100.64/10
        if (a[0] == 169 && a[1] == 254) return false;
        if (a[0] == 172 && (a[1] & 0xF0) == 16) return false;
        if (a[0] == 192 && a[1] == 168) return false;
        if (a[0] == 192 && a[1] == 0 && (a[2] == 0 || a[2] == 2)) return false;
        if (a[0] == 198 && (a[1] == 18 || a[1] == 19)) return false;
        if (a[0] == 198 && a[1] == 51 && a[2] == 100) return false;
        if (a[0] == 203 && a[1] == 0 && a[2] == 113) return false;
        return true;
    }
    if (len == 16)
    {
        static const unsigned char v4mapped[12] = {0,0,0,0,0,0,0,0,0,0,0xFF,0xFF};
        if (memcmp(a, v4mapped, 12) == 0)
            return NyxIsPublicAddress(a + 12, 4);
        bool fZeroPrefix = true;
        for (int i = 0; i < 15; i++)
            if (a[i]) fZeroPrefix = false;
        if (fZeroPrefix) return false;                          // :: and ::1
        if ((a[0] & 0xFE) == 0xFC) return false;                // fc00::/7
        if (a[0] == 0xFE && (a[1] & 0xC0) == 0x80) return false; // fe80::/10
        if (a[0] == 0xFF) return false;                          // multicast
        if (a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x0D && a[3] == 0xB8) return false;
        if (a[0] == 0x00 && a[1] == 0x64 && a[2] == 0xFF && a[3] == 0x9B) return false; // NAT64
        if (a[0] == 0x20 && a[1] == 0x02) return false;          // 6to4 can embed private v4
        return true;
    }
    return false;
}

// ---- strict head tokenizer ----

static void AppendUtf8(std::string& o, unsigned long cp)
{
    if (cp < 0x20 || (cp >= 0x7F && cp < 0xA0) || (cp >= 0xD800 && cp <= 0xDFFF) || cp > 0x10FFFF)
        return;
    if (cp < 0x80) o.push_back((char)cp);
    else if (cp < 0x800) { o.push_back(0xC0 | (cp >> 6)); o.push_back(0x80 | (cp & 0x3F)); }
    else if (cp < 0x10000) { o.push_back(0xE0 | (cp >> 12)); o.push_back(0x80 | ((cp >> 6) & 0x3F)); o.push_back(0x80 | (cp & 0x3F)); }
    else { o.push_back(0xF0 | (cp >> 18)); o.push_back(0x80 | ((cp >> 12) & 0x3F)); o.push_back(0x80 | ((cp >> 6) & 0x3F)); o.push_back(0x80 | (cp & 0x3F)); }
}

static std::string DecodeEntities(const std::string& s)
{
    std::string o;
    for (size_t i = 0; i < s.size(); i++)
    {
        if (s[i] != '&')
        {
            o.push_back(s[i]);
            continue;
        }
        size_t semi = s.find(';', i);
        if (semi == std::string::npos || semi - i > 10)
        {
            o.push_back('&');
            continue;
        }
        std::string ent = s.substr(i + 1, semi - i - 1);
        if (ent == "amp") o.push_back('&');
        else if (ent == "lt") o.push_back('<');
        else if (ent == "gt") o.push_back('>');
        else if (ent == "quot") o.push_back('"');
        else if (ent == "apos") o.push_back('\'');
        else if (ent == "nbsp") o.push_back(' ');
        else if (ent.size() > 1 && ent[0] == '#')
        {
            unsigned long cp = 0;
            bool fHex = (ent[1] == 'x' || ent[1] == 'X');
            size_t k = fHex ? 2 : 1;
            if (k >= ent.size()) { o.push_back('&'); continue; }
            bool ok = true;
            for (; k < ent.size() && ok; k++)
            {
                char c = ent[k];
                int d = fHex ? (isdigit((unsigned char)c) ? c - '0' : (isxdigit((unsigned char)c) ? (tolower(c) - 'a' + 10) : -1))
                             : (isdigit((unsigned char)c) ? c - '0' : -1);
                if (d < 0 || cp > 0x10FFFF) ok = false;
                else cp = cp * (fHex ? 16 : 10) + d;
            }
            if (!ok) { i = semi; continue; }
            AppendUtf8(o, cp);
        }
        else
        {
            o.push_back('&');
            continue;
        }
        i = semi;
    }
    return o;
}

static std::string Lower(std::string s)
{
    for (char& c : s) c = tolower((unsigned char)c);
    return s;
}

static size_t FindCI(const std::string& h, const std::string& needle, size_t from)
{
    for (size_t i = from; i + needle.size() <= h.size(); i++)
        if (strncasecmp(&h[i], needle.c_str(), needle.size()) == 0)
            return i;
    return std::string::npos;
}

static std::string ResolveImage(const std::string& img, const std::string& pageUrl)
{
    std::string u = img;
    if (u.compare(0, 2, "//") == 0)
        u = "https:" + u;
    else if (!u.empty() && u[0] == '/')
    {
        std::string host = NyxUrlHost(pageUrl);
        if (host.empty()) return std::string();
        u = "https://" + host + u;
    }
    if (u.size() > NYX_EMBED_MAX_URL || strncasecmp(u.c_str(), "https://", 8) != 0 || !NyxIsLinkableUrl(u))
        return std::string();
    return u;
}

NyxPageMeta NyxParseHead(const std::string& htmlIn, const std::string& pageUrl)
{
    NyxPageMeta m;
    std::string ogTitle, ogDesc, ogSite, ogImage, title, desc;
    const std::string html = htmlIn.substr(0, 512 * 1024);
    size_t i = 0;
    int nTags = 0;
    while (i < html.size() && nTags++ < 4000)
    {
        size_t lt = html.find('<', i);
        if (lt == std::string::npos)
            break;
        if (html.compare(lt, 4, "<!--") == 0)
        {
            size_t e = html.find("-->", lt + 4);
            if (e == std::string::npos) break;
            i = e + 3;
            continue;
        }
        size_t gt = html.find('>', lt);
        if (gt == std::string::npos)
            break;
        std::string tag = html.substr(lt + 1, gt - lt - 1);
        size_t n = 0;
        while (n < tag.size() && (isalnum((unsigned char)tag[n]) || tag[n] == '/' || tag[n] == '!'))
            n++;
        std::string name = Lower(tag.substr(0, n));
        i = gt + 1;
        if (name == "/head" || name == "body")
            break;
        if (name == "script" || name == "style" || name == "noscript" || name == "template")
        {
            size_t e = FindCI(html, "</" + name, i);
            if (e == std::string::npos) break;
            i = e;
            continue;
        }
        if (name == "title" && title.empty())
        {
            size_t e = FindCI(html, "</title", i);
            if (e == std::string::npos) break;
            title = html.substr(i, std::min<size_t>(e - i, 2048));
            i = e;
            continue;
        }
        if (name != "meta")
            continue;
        // attributes
        std::string key, val, prop, content;
        size_t p = n;
        int nAttr = 0;
        while (p < tag.size() && nAttr++ < 32)
        {
            while (p < tag.size() && (isspace((unsigned char)tag[p]) || tag[p] == '/')) p++;
            size_t ks = p;
            while (p < tag.size() && !isspace((unsigned char)tag[p]) && tag[p] != '=' && tag[p] != '/') p++;
            key = Lower(tag.substr(ks, p - ks));
            while (p < tag.size() && isspace((unsigned char)tag[p])) p++;
            val.clear();
            if (p < tag.size() && tag[p] == '=')
            {
                p++;
                while (p < tag.size() && isspace((unsigned char)tag[p])) p++;
                if (p < tag.size() && (tag[p] == '"' || tag[p] == '\''))
                {
                    char q = tag[p++];
                    size_t e = tag.find(q, p);
                    if (e == std::string::npos) e = tag.size();
                    val = tag.substr(p, e - p);
                    p = e + 1;
                }
                else
                {
                    size_t vs = p;
                    while (p < tag.size() && !isspace((unsigned char)tag[p])) p++;
                    val = tag.substr(vs, p - vs);
                }
            }
            if (key.empty()) { p++; continue; }
            if (val.size() > 4096) val.resize(4096);
            if (key == "property" || key == "name") prop = Lower(val);
            else if (key == "content") content = val;
        }
        if (prop == "og:title" && ogTitle.empty()) ogTitle = content;
        else if (prop == "og:description" && ogDesc.empty()) ogDesc = content;
        else if (prop == "og:site_name" && ogSite.empty()) ogSite = content;
        else if ((prop == "og:image" || prop == "og:image:secure_url") && ogImage.empty()) ogImage = content;
        else if ((prop == "description" || prop == "twitter:description") && desc.empty()) desc = content;
        else if (prop == "twitter:title" && ogTitle.empty()) ogTitle = content;
    }
    m.title = CleanText(DecodeEntities(ogTitle.empty() ? title : ogTitle), NYX_EMBED_MAX_TITLE);
    m.desc = CleanText(DecodeEntities(ogDesc.empty() ? desc : ogDesc), NYX_EMBED_MAX_DESC);
    m.site = CleanText(DecodeEntities(ogSite), NYX_EMBED_MAX_SITE);
    if (m.site.empty())
        m.site = NyxUrlHost(pageUrl);
    m.image = ResolveImage(DecodeEntities(ogImage), pageUrl);
    return m;
}
