// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "nyxpo.h"
#include "nyxparts.h"

#include <string.h>

bool NyxPoIsPublicType(uint8_t t)
{
    return t == NYX_PO_BUNDLE || t == NYX_PO_CERT || t == NYX_PO_KEYRING;
}

static uint32_t LE32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t LE64(const uint8_t* p)
{
    return (uint64_t)LE32(p) | ((uint64_t)LE32(p + 4) << 32);
}

static bool IsZero(const uint8_t* p, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        if (p[i])
            return false;
    return true;
}

static int ParseCert(const uint8_t* p, size_t n, NyxPoInfo& out)
{
    const size_t nFixed = 1 + 1 + 1 + 20 + 16 + 8 + 8 + 4 + 32;
    if (n < nFixed)
        return 2;
    if (p[1] != 1)
        return 3;
    const uint8_t mode = p[2];
    if (mode > 1)
        return 4;
    memcpy(out.addrHash, p + 3, 20);
    memcpy(out.deviceId, p + 23, 16);
    const uint64_t created = LE64(p + 39), expiry = LE64(p + 47);
    if (expiry <= created || expiry - created > (uint64_t)NYX_CERT_MAX_LIFE)
        return 5;
    out.seq = LE32(p + 55);
    out.ts = created;
    out.expiry = expiry;
    size_t off = nFixed + (mode == 1 ? NYX_MLDSA_PK : 0) + NYX_ECDSA_SIG;
    if (n < off + 16)
        return 2;
    const bool fFirst = IsZero(p + off, 16);
    off += 16;
    if (mode == 1 && !fFirst)
        off += NYX_MLDSA_SIG;
    return n == off ? 0 : 6;
}

static int ParseBundle(const uint8_t* p, size_t n, NyxPoInfo& out)
{
    const size_t nHead = 1 + 20 + 16 + 8 + 4 + 4 + 32;
    if (n < nHead + 1)
        return 2;
    memcpy(out.addrHash, p + 1, 20);
    memcpy(out.deviceId, p + 21, 16);
    out.ts = LE64(p + 37);
    out.seq = LE32(p + 45);
    const size_t nPqMin = nHead + 4 + NYX_MLKEM_EK + 1 + NYX_MLDSA_SIG;
    const bool fPq = n >= nPqMin;
    const size_t offOpk = nHead + (fPq ? 4 + NYX_MLKEM_EK : 0);
    if (n < offOpk + 1)
        return 2;
    const uint8_t nOpk = p[offOpk];
    if (nOpk > 8)
        return 4;
    const size_t nWant = offOpk + 1 + (size_t)nOpk * 36 + (fPq ? NYX_MLDSA_SIG : NYX_ECDSA_SIG);
    return n == nWant ? 0 : 6;
}

static int ParseKeyring(const uint8_t* p, size_t n, NyxPoInfo& out)
{
    const size_t nHead = 1 + 1 + 20 + 4 + 4 + 32 + 8 + 1 + 1;
    if (n < nHead)
        return 2;
    if (p[1] != 2)
        return 3;
    memcpy(out.addrHash, p + 2, 20);
    out.epoch = LE32(p + 22);
    out.seq = LE32(p + 26);
    if (out.epoch == 0 || out.seq == 0)
        return 5;
    out.ts = LE64(p + 62);
    const uint8_t mode = p[70];
    if (mode > 1)
        return 4;
    const uint8_t nLive = p[71];
    if (nLive < 1 || nLive > 16)
        return 4;
    size_t off = nHead + (size_t)nLive * 48;
    if (n < off + 1)
        return 2;
    const uint8_t nRev = p[off++];
    if (nRev > 16)
        return 4;
    off += (size_t)nRev * 16 + NYX_ECDSA_SIG;
    if (n < off + 16)
        return 2;
    const bool fZeroSigner = IsZero(p + off, 16);
    if (fZeroSigner != (out.seq == 1))
        return 5;
    off += 16;
    if (mode == 1 && out.seq > 1)
        off += NYX_MLDSA_SIG;
    return n == off ? 0 : 6;
}

int NyxPoParse(const uint8_t* p, size_t n, NyxPoInfo& out)
{
    memset(&out, 0, sizeof(out));
    if (!p || n < 1)
        return 1;
    out.type = p[0];
    switch (p[0])
    {
    case NYX_PO_BUNDLE:  return ParseBundle(p, n, out);
    case NYX_PO_CERT:    return ParseCert(p, n, out);
    case NYX_PO_KEYRING: return ParseKeyring(p, n, out);
    }
    return 1;
}

static int NyxPoVerifyStub(const std::vector<uint8_t>&)
{
    return NYX_PO_UNVERIFIED;
}

static NyxPoVerifyFn pfnVerify = NyxPoVerifyStub;
static std::list<std::pair<std::string, int> > lruVerify;
static std::map<std::string, std::list<std::pair<std::string, int> >::iterator> mapVerify;

void NyxPoSetVerifyHook(NyxPoVerifyFn fn)
{
    pfnVerify = fn ? fn : NyxPoVerifyStub;
    NyxPoClearCache();
}

void NyxPoClearCache()
{
    lruVerify.clear();
    mapVerify.clear();
}

size_t NyxPoCacheSize()
{
    return mapVerify.size();
}

int NyxPoVerify(const std::vector<uint8_t>& body)
{
    uint8_t h[32];
    NyxSha256(body.empty() ? NULL : &body[0], body.size(), h);
    const std::string k((const char*)h, 32);
    std::map<std::string, std::list<std::pair<std::string, int> >::iterator>::iterator it = mapVerify.find(k);
    if (it != mapVerify.end())
    {
        lruVerify.splice(lruVerify.begin(), lruVerify, it->second);
        return it->second->second;
    }
    const int r = pfnVerify(body);
    lruVerify.push_front(std::make_pair(k, r));
    mapVerify[k] = lruVerify.begin();
    if (lruVerify.size() > NYX_PO_CACHE_SIZE)
    {
        mapVerify.erase(lruVerify.back().first);
        lruVerify.pop_back();
    }
    return r;
}

std::string NyxPoStore::Key(const NyxPoInfo& info)
{
    std::string k("po");
    k.append((const char*)info.addrHash, 20);
    k.push_back((char)info.type);
    k.append((const char*)info.deviceId, 16);
    return k;
}

uint64_t NyxPoStore::Record::Bytes() const
{
    uint64_t n = 0;
    for (size_t i = 0; i < vParts.size(); ++i)
        n += vParts[i].size();
    return n;
}

static bool Newer(const NyxPoInfo& a, const NyxPoInfo& b)
{
    if (a.epoch != b.epoch)
        return a.epoch > b.epoch;
    if (a.seq != b.seq)
        return a.seq > b.seq;
    return a.ts > b.ts;
}

void NyxPoStore::Account(const Record& r, bool fAdd)
{
    const uint64_t n = r.Bytes();
    if (fAdd)
        nBytes += n;
    else
        nBytes -= n;
    if (!r.fVerified)
    {
        if (fAdd)
            nUnvBytes += n;
        else
            nUnvBytes -= n;
    }
}

void NyxPoStore::Erase(std::map<std::string, Record>::iterator it)
{
    Account(it->second, false);
    vErased.push_back(it->first);
    records.erase(it);
}

void NyxPoStore::Enforce()
{
    while (!records.empty() && (nBytes > nCap || nUnvBytes > nCap / 8))
    {
        // Unverified records go first.
        const bool fUnv = nUnvBytes > 0;
        std::map<std::string, Record>::iterator oldest = records.end();
        for (std::map<std::string, Record>::iterator it = records.begin(); it != records.end(); ++it)
            if ((!fUnv || !it->second.fVerified)
                && (oldest == records.end() || it->second.nLastSeen < oldest->second.nLastSeen))
                oldest = it;
        Erase(oldest);
    }
}

bool NyxPoStore::Put(const NyxPoInfo& info, const std::vector<std::vector<uint8_t> >& vParts, int64_t nNow, bool fVerified)
{
    const std::string k = Key(info);
    std::map<std::string, Record>::iterator it = records.find(k);
    if (it != records.end())
    {
        const bool fOldVerified = it->second.fVerified;
        if ((fOldVerified && !fVerified) || (fOldVerified == fVerified && !Newer(info, it->second.info)))
        {
            if (it->second.vParts == vParts)
                it->second.nLastSeen = nNow;
            return false;
        }
        Account(it->second, false);
        records.erase(it);
    }
    Record r;
    r.info = info;
    r.nLastSeen = nNow;
    r.vParts = vParts;
    r.fVerified = fVerified;
    Account(r, true);
    records[k] = r;
    Enforce();
    return records.count(k) > 0;
}

void NyxPoStore::Load(const std::string& key, const Record& rec)
{
    std::map<std::string, Record>::iterator it = records.find(key);
    if (it != records.end())
        Account(it->second, false);
    records[key] = rec;
    Account(rec, true);
    Enforce();
}

void NyxPoStore::Get(const uint8_t addrHash[20], std::vector<const Record*>& out) const
{
    out.clear();
    std::string prefix("po");
    prefix.append((const char*)addrHash, 20);
    for (std::map<std::string, Record>::const_iterator it = records.lower_bound(prefix);
         it != records.end() && it->first.compare(0, prefix.size(), prefix) == 0; ++it)
        out.push_back(&it->second);
}

void NyxPoStore::All(std::vector<std::pair<std::string, const Record*> >& out) const
{
    out.clear();
    for (std::map<std::string, Record>::const_iterator it = records.begin(); it != records.end(); ++it)
        out.push_back(std::make_pair(it->first, &it->second));
}

void NyxPoStore::Expire(int64_t nNow)
{
    for (std::map<std::string, Record>::iterator it = records.begin(); it != records.end();)
    {
        std::map<std::string, Record>::iterator cur = it++;
        if (nNow - cur->second.nLastSeen >= nKeep)
            Erase(cur);
    }
}

std::vector<std::string> NyxPoStore::TakeErased()
{
    std::vector<std::string> v;
    v.swap(vErased);
    return v;
}
