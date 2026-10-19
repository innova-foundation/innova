// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "nyxsafety.h"

#include "base58.h"
#include "bip39.h"
#include "nyxembed.h"
#include "sync.h"
#include "util.h"

#include <cctype>
#include <cstring>
#include <fstream>
#include <sstream>
#include <vector>

static std::string Lower(std::string s)
{
    for (char& c : s)
        c = tolower((unsigned char)c);
    return s;
}

static bool IsB58(char c)
{
    return isalnum((unsigned char)c) && c != '0' && c != 'O' && c != 'I' && c != 'l';
}

static bool PhraseRun(const std::string& lower)
{
    std::vector<bool> v;
    std::string w;
    for (size_t i = 0; i <= lower.size(); i++)
    {
        char c = i < lower.size() ? lower[i] : ' ';
        if (c >= 'a' && c <= 'z')
        {
            w.push_back(c);
            continue;
        }
        if (!w.empty())
        {
            v.push_back(BIP39IsWord(w));
            w.clear();
        }
    }
    // 12-word window with at most one miss; numbering between words is ignored.
    static const size_t WIN = 12;
    if (v.size() < WIN)
        return false;
    size_t hits = 0;
    for (size_t i = 0; i < v.size(); i++)
    {
        hits += v[i];
        if (i >= WIN)
            hits -= v[i - WIN];
        if (i + 1 >= WIN && hits + 1 >= WIN)
            return true;
    }
    return false;
}

NyxSecretKind NyxDetectSecret(const std::string& text)
{
    const std::string lower = Lower(text);
    if (PhraseRun(lower))
        return NYX_SECRET_PHRASE;

    bool fKeyWords = lower.find("seed") != std::string::npos || lower.find("priv") != std::string::npos
                  || lower.find("secret") != std::string::npos || lower.find("key") != std::string::npos;
    for (size_t i = 0; i < text.size();)
    {
        if (isxdigit((unsigned char)text[i]) && (i == 0 || !isalnum((unsigned char)text[i - 1])))
        {
            size_t j = i;
            while (j < text.size() && isxdigit((unsigned char)text[j]))
                j++;
            if (j - i >= 64 && (j == text.size() || !isalnum((unsigned char)text[j])) && fKeyWords)
                return NYX_SECRET_HEXSEED;
        }
        if (!IsB58(text[i]))
        {
            i++;
            continue;
        }
        size_t j = i;
        while (j < text.size() && IsB58(text[j]))
            j++;
        std::string tok = text.substr(i, j - i);
        i = j;
        if (tok.size() < 50 || tok.size() > 200)
            continue;
        std::string pre = tok.substr(0, 4);
        if (pre == "xprv" || pre == "tprv")
            return NYX_SECRET_XPRV;
        if (pre == "xpub" || pre == "tpub")
            continue;
        std::vector<unsigned char> v;
        if (DecodeBase58Check(tok, v) && v.size() >= 33)
            return NYX_SECRET_PRIVKEY;
    }
    return NYX_SECRET_NONE;
}

std::string NyxSecretKindName(NyxSecretKind k)
{
    switch (k)
    {
        case NYX_SECRET_PHRASE:  return "recovery phrase";
        case NYX_SECRET_PRIVKEY: return "private key";
        case NYX_SECRET_XPRV:    return "extended private key";
        case NYX_SECRET_HEXSEED: return "wallet seed";
        default:                 return "";
    }
}

static bool Contains(const std::string& h, const char* const* list)
{
    for (; *list; list++)
        if (h.find(*list) != std::string::npos)
            return true;
    return false;
}

bool NyxLooksLikeScam(const std::string& text)
{
    std::string s;
    bool fSpace = false;
    for (char c : Lower(text))
    {
        bool sp = isspace((unsigned char)c);
        if (sp && fSpace)
            continue;
        s.push_back(sp ? ' ' : c);
        fSpace = sp;
    }
    static const char* const direct[] = {
        "verify your wallet", "validate your wallet", "wallet validation", "wallet verification",
        "validate wallet", "verify wallet", "sync your wallet", "synchronize your wallet",
        "rectify your wallet", "revalidate", "dumpprivkey", "z_exportphrase", "z_exportkey",
        "z_exportiv5seed", 0};
    static const char* const secrets[] = {
        "recovery phrase", "seed phrase", "seed words", "secret phrase", "backup phrase",
        "recovery words", "mnemonic", "private key", "privkey", "secret key", "12 words",
        "24 words", "12-word", "24-word", "wallet.dat", "passphrase", "your seed", 0};
    static const char* const asks[] = {
        "send", "share", "give", "provide", "enter", "type", "paste", "submit", "tell",
        "need", "require", "verify", "validate", "confirm", "import", "upload", "what is",
        "what's", "dm ", 0};
    static const char* const warnings[] = {
        "never share", "never send", "never give", "never enter", "never ask", "do not share",
        "don't share", "dont share", 0};
    if (Contains(s, direct))
        return true;
    return Contains(s, secrets) && Contains(s, asks) && !Contains(s, warnings);
}

NyxSenderState NyxClassifySender(const std::string& from, bool fSentTo, bool fInAddressBook,
                                 bool fAccepted, bool fBlocked)
{
    if (fBlocked)
        return NYX_SENDER_BLOCKED;
    if (from.empty() || from == "anon")
        return NYX_SENDER_REQUEST;
    return (fSentTo || fInAddressBook || fAccepted) ? NYX_SENDER_KNOWN : NYX_SENDER_REQUEST;
}

bool NyxIsValidContactAddress(const std::string& addr)
{
    if (addr.empty() || addr.size() > 128)
        return false;
    for (char c : addr)
        if (!isalnum((unsigned char)c))
            return false;
    return true;
}

void NyxContactLists::Parse(const std::string& data)
{
    setAccepted.clear();
    setBlocked.clear();
    std::istringstream in(data);
    std::string line;
    while (std::getline(in, line))
    {
        if (!line.empty() && line[line.size() - 1] == '\r')
            line.resize(line.size() - 1);
        size_t sp = line.find(' ');
        if (sp == std::string::npos)
            continue;
        std::string op = line.substr(0, sp), addr = line.substr(sp + 1);
        if (!NyxIsValidContactAddress(addr))
            continue;
        if (op == "accept")
            setAccepted.insert(addr);
        else if (op == "block")
            setBlocked.insert(addr);
    }
    for (const std::string& a : setBlocked)
        setAccepted.erase(a);
}

std::string NyxContactLists::Serialize() const
{
    std::string o;
    for (const std::string& a : setAccepted)
        o += "accept " + a + "\n";
    for (const std::string& a : setBlocked)
        o += "block " + a + "\n";
    return o;
}

bool NyxContactLists::Load(const std::string& path)
{
    std::ifstream f(path.c_str(), std::ios::binary);
    if (!f)
        return false;
    std::stringstream ss;
    ss << f.rdbuf();
    Parse(ss.str());
    return true;
}

bool NyxContactLists::Save(const std::string& path) const
{
    std::string tmp = path + ".new";
    {
        std::ofstream f(tmp.c_str(), std::ios::binary | std::ios::trunc);
        if (!f)
            return false;
        f << Serialize();
        if (!f.good())
            return false;
    }
    return rename(tmp.c_str(), path.c_str()) == 0;
}

static CCriticalSection cs_nyxContacts;
static NyxContactLists g_nyxContacts;
static bool g_fNyxContactsLoaded = false;

static std::string ContactsPath()
{
    return (GetDataDir() / "nyxcontacts.dat").string();
}

static NyxContactLists& Contacts()
{
    if (!g_fNyxContactsLoaded)
    {
        g_nyxContacts.Load(ContactsPath());
        g_fNyxContactsLoaded = true;
    }
    return g_nyxContacts;
}

bool NyxIsAccepted(const std::string& addr)
{
    LOCK(cs_nyxContacts);
    return Contacts().setAccepted.count(addr) != 0;
}

bool NyxIsBlocked(const std::string& addr)
{
    LOCK(cs_nyxContacts);
    return Contacts().setBlocked.count(addr) != 0;
}

bool NyxHasBlocked()
{
    LOCK(cs_nyxContacts);
    return !Contacts().setBlocked.empty();
}

bool NyxAccept(const std::string& addr)
{
    if (!NyxIsValidContactAddress(addr) || addr == "anon")
        return false;
    LOCK(cs_nyxContacts);
    Contacts().setBlocked.erase(addr);
    Contacts().setAccepted.insert(addr);
    return Contacts().Save(ContactsPath());
}

bool NyxBlock(const std::string& addr)
{
    if (!NyxIsValidContactAddress(addr) || addr == "anon")
        return false;
    LOCK(cs_nyxContacts);
    Contacts().setAccepted.erase(addr);
    Contacts().setBlocked.insert(addr);
    return Contacts().Save(ContactsPath());
}

bool NyxUnblock(const std::string& addr)
{
    LOCK(cs_nyxContacts);
    Contacts().setBlocked.erase(addr);
    return Contacts().Save(ContactsPath());
}

static bool IsTrackingParam(const std::string& keyIn)
{
    std::string key = Lower(keyIn);
    if (key.compare(0, 4, "utm_") == 0)
        return true;
    static const char* const names[] = {"fbclid", "gclid", "gclsrc", "dclid", "gbraid", "wbraid",
                                        "msclkid", "mc_eid", "mc_cid", "igshid", "yclid", "_hsenc",
                                        "_hsmi", 0};
    for (const char* const* p = names; *p; p++)
        if (key == *p)
            return true;
    return false;
}

std::string NyxStripTracking(const std::string& url)
{
    size_t q = url.find('?');
    if (q == std::string::npos)
        return url;
    size_t h = url.find('#', q);
    std::string query = url.substr(q + 1, h == std::string::npos ? std::string::npos : h - q - 1);
    std::string frag = h == std::string::npos ? std::string() : url.substr(h);
    std::string kept;
    size_t a = 0;
    while (a <= query.size())
    {
        size_t b = query.find('&', a);
        if (b == std::string::npos)
            b = query.size();
        std::string part = query.substr(a, b - a);
        if (!part.empty() && !IsTrackingParam(part.substr(0, part.find('='))))
            kept += (kept.empty() ? "" : "&") + part;
        a = b + 1;
    }
    return url.substr(0, q) + (kept.empty() ? std::string() : "?" + kept) + frag;
}

std::string NyxStripTrackingInText(const std::string& text)
{
    std::string out;
    size_t pos = 0, len = 0;
    for (;;)
    {
        size_t a = NyxNextUrl(text, pos, len);
        if (a == std::string::npos)
        {
            out += text.substr(pos);
            return out;
        }
        out += text.substr(pos, a - pos);
        out += NyxStripTracking(text.substr(a, len));
        pos = a + len;
    }
}

std::string NyxRegistrableDomain(const std::string& host)
{
    std::vector<std::string> labels;
    size_t a = 0;
    for (;;)
    {
        size_t b = host.find('.', a);
        labels.push_back(host.substr(a, b == std::string::npos ? std::string::npos : b - a));
        if (b == std::string::npos)
            break;
        a = b + 1;
    }
    if (labels.size() <= 2)
        return host;
    static const char* const second[] = {"co", "com", "net", "org", "gov", "edu", "ac", "or",
                                         "ne", "go", "gob", "nic", "ltd", "plc", "me", 0};
    const std::string& sld = labels[labels.size() - 2];
    size_t keep = 2;
    if (labels.back().size() == 2)
        for (const char* const* p = second; *p; p++)
            if (sld == *p)
                keep = 3;
    std::string o;
    for (size_t i = labels.size() - keep; i < labels.size(); i++)
        o += (o.empty() ? "" : ".") + labels[i];
    return o;
}

bool NyxPunycodeDecode(const std::string& in, std::u32string& out)
{
    const unsigned long base = 36, tmin = 1, tmax = 26, skew = 38, damp = 700;
    out.clear();
    size_t b = in.rfind('-');
    if (b == std::string::npos)
        b = 0;
    for (size_t i = 0; i < b; i++)
    {
        if ((unsigned char)in[i] >= 0x80)
            return false;
        out.push_back((char32_t)(unsigned char)in[i]);
    }
    unsigned long n = 128, i = 0, bias = 72;
    for (size_t p = b > 0 ? b + 1 : 0; p < in.size();)
    {
        unsigned long oldi = i, w = 1;
        for (unsigned long k = base;; k += base)
        {
            if (p >= in.size())
                return false;
            char c = in[p++];
            unsigned long d;
            if (c >= '0' && c <= '9') d = c - '0' + 26;
            else if (c >= 'a' && c <= 'z') d = c - 'a';
            else if (c >= 'A' && c <= 'Z') d = c - 'A';
            else return false;
            if (d > (0x10FFFF - i) / w)
                return false;
            i += d * w;
            unsigned long t = k <= bias ? tmin : (k >= bias + tmax ? tmax : k - bias);
            if (d < t)
                break;
            if (w > 0x10FFFF / (base - t))
                return false;
            w *= base - t;
        }
        unsigned long len = out.size() + 1;
        unsigned long delta = oldi == 0 ? i / damp : (i - oldi) / 2;
        delta += delta / len;
        unsigned long k = 0;
        while (delta > ((base - tmin) * tmax) / 2)
        {
            delta /= base - tmin;
            k += base;
        }
        bias = k + (base - tmin + 1) * delta / (delta + skew);
        n += i / len;
        i %= len;
        if (n > 0x10FFFF || out.size() > 63)
            return false;
        out.insert(out.begin() + i, (char32_t)n);
        i++;
    }
    return true;
}

enum Script { SC_NONE, SC_LATIN, SC_GREEK, SC_CYRILLIC, SC_ARMENIAN, SC_OTHER };

static Script ScriptOf(char32_t c)
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= 0xC0 && c <= 0x24F && c != 0xD7 && c != 0xF7))
        return SC_LATIN;
    if (c < 0x80)
        return SC_NONE;
    if (c >= 0x370 && c <= 0x3FF) return SC_GREEK;
    if (c >= 0x400 && c <= 0x52F) return SC_CYRILLIC;
    if (c >= 0x530 && c <= 0x58F) return SC_ARMENIAN;
    return SC_OTHER;
}

static bool LatinConfusable(char32_t c)
{
    static const char32_t set[] = {0x430, 0x435, 0x43E, 0x440, 0x441, 0x443, 0x445, 0x456, 0x458,
                                   0x455, 0x501, 0x4BB, 0x4CF, 0x51B, 0x51D, 0x3BF, 0x3B1, 0x3BD,
                                   0x3C1, 0x3B9, 0x3BA, 0x3C5, 0x585, 0x570, 0x578, 0x57D, 0};
    for (const char32_t* p = set; *p; p++)
        if (*p == c)
            return true;
    return false;
}

static bool HiddenCodepoint(unsigned long c)
{
    return c == 0xAD || c == 0x61C || c == 0x180E || (c >= 0x200B && c <= 0x200F)
        || (c >= 0x202A && c <= 0x202E) || (c >= 0x2060 && c <= 0x2064)
        || (c >= 0x2066 && c <= 0x2069) || c == 0xFEFF;
}

static bool HasHiddenUtf8(const std::string& s)
{
    for (size_t i = 0; i < s.size(); i++)
    {
        unsigned char c = s[i];
        unsigned long cp;
        size_t n;
        if (c < 0x80) continue;
        else if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; n = 1; }
        else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; n = 2; }
        else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; n = 3; }
        else continue;
        bool ok = true;
        for (size_t k = 1; k <= n; k++)
        {
            if (i + k >= s.size() || ((unsigned char)s[i + k] & 0xC0) != 0x80) { ok = false; break; }
            cp = (cp << 6) | ((unsigned char)s[i + k] & 0x3F);
        }
        if (!ok) continue;
        if (HiddenCodepoint(cp))
            return true;
        i += n;
    }
    return false;
}

static std::string PercentDecode(const std::string& s)
{
    std::string o;
    for (size_t i = 0; i < s.size(); i++)
    {
        if (s[i] == '%' && i + 2 < s.size() && isxdigit((unsigned char)s[i + 1]) && isxdigit((unsigned char)s[i + 2]))
        {
            o.push_back((char)strtol(s.substr(i + 1, 2).c_str(), NULL, 16));
            i += 2;
        }
        else
            o.push_back(s[i]);
    }
    return o;
}

int NyxUrlRiskFlags(const std::string& url)
{
    int flags = 0;
    if (HasHiddenUtf8(url) || HasHiddenUtf8(PercentDecode(url)) || HasHiddenUtf8(PercentDecode(PercentDecode(url))))
        flags |= NYX_URL_HIDDEN_CHARS;
    std::string host = NyxUrlHost(url);
    size_t a = 0;
    while (!host.empty() && a <= host.size())
    {
        size_t b = host.find('.', a);
        if (b == std::string::npos)
            b = host.size();
        std::string label = host.substr(a, b - a);
        a = b + 1;
        if (label.compare(0, 4, "xn--") != 0)
            continue;
        flags |= NYX_URL_IDN;
        std::u32string cps;
        if (!NyxPunycodeDecode(label.substr(4), cps) || cps.empty())
        {
            flags |= NYX_URL_LOOKALIKE;
            continue;
        }
        std::set<int> scripts;
        bool fAllConfusable = true, fAnyNonLatin = false;
        for (char32_t c : cps)
        {
            if (HiddenCodepoint(c))
                flags |= NYX_URL_HIDDEN_CHARS;
            Script sc = ScriptOf(c);
            if (sc == SC_NONE)
                continue;
            scripts.insert(sc);
            if (sc != SC_LATIN)
            {
                fAnyNonLatin = true;
                if (!LatinConfusable(c))
                    fAllConfusable = false;
            }
        }
        bool fMixed = scripts.count(SC_LATIN) && (scripts.count(SC_GREEK) || scripts.count(SC_CYRILLIC) || scripts.count(SC_ARMENIAN));
        if (fMixed || (scripts.size() > 1 && !scripts.count(SC_OTHER)) || (fAnyNonLatin && fAllConfusable))
            flags |= NYX_URL_LOOKALIKE;
    }
    return flags;
}
