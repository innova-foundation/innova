// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "nyxsession.h"
#include "privacy_vnext/rust/include/nyx_pq.h"

#include "key.h"

#include <algorithm>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <set>
#include <string.h>

static const char INFO_PQXDH[] = "NyxPQXDH_CURVE25519_SHA-256_ML-KEM-768";
static const char INFO_X3DH[] = "NyxX3DH_CURVE25519_SHA-256";
static const char INFO_RK[] = "NyxRatchetRK";
static const char INFO_MK[] = "NyxMsgKey";
static const char TAG_TRANSCRIPT[] = "NYX-TRANSCRIPT-v1";

namespace {

// Wipes a fixed buffer on scope exit.
template <size_t N>
struct Secret
{
    uint8_t b[N];
    Secret() { memset(b, 0, N); }
    ~Secret() { OPENSSL_cleanse(b, N); }
};

void Put32(NyxBytes& v, uint32_t x)
{
    for (int i = 0; i < 4; ++i)
        v.push_back((uint8_t)(x >> (8 * i)));
}

uint32_t Rd32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

void WrRaw(std::string& s, const void* p, size_t n)
{
    const uint32_t len = n;
    s.append((const char*)&len, 4);
    s.append((const char*)p, n);
}

bool RdRaw(const std::string& s, size_t& off, void* p, size_t n)
{
    uint32_t len = 0;
    if (s.size() - off < 4)
        return false;
    memcpy(&len, s.data() + off, 4);
    if (len != n || s.size() - off - 4 < n)
        return false;
    memcpy(p, s.data() + off + 4, n);
    off += 4 + n;
    return true;
}

bool RdBytes(const std::string& s, size_t& off, NyxBytes& v, size_t nMax)
{
    uint32_t len = 0;
    if (s.size() - off < 4)
        return false;
    memcpy(&len, s.data() + off, 4);
    if (len > nMax || s.size() - off - 4 < len)
        return false;
    v.assign(s.begin() + off + 4, s.begin() + off + 4 + len);
    off += 4 + len;
    return true;
}

const uint8_t BASE[32] = {9};

bool Dh(const uint8_t sk[32], const uint8_t pk[32], uint8_t out[32])
{
    return nyx_x25519(sk, pk, out) == 0;
}

} // namespace

// ---------------------------------------------------------------- KDFs

bool NyxPqxdhKdf(const uint8_t* dh, size_t nDh, const uint8_t* ss, uint8_t out[96])
{
    if (nDh < 3 || nDh > 4)
        return false;
    std::vector<uint8_t> ikm(32, 0xFF);
    ikm.reserve(32 + 32 * 5);
    ikm.insert(ikm.end(), dh, dh + 32 * nDh);
    if (ss)
        ikm.insert(ikm.end(), ss, ss + 32);
    const uint8_t salt[32] = {0};
    const char* info = ss ? INFO_PQXDH : INFO_X3DH;
    const bool fOk = nyx_hkdf_sha256(salt, 32, &ikm[0], ikm.size(), (const uint8_t*)info, strlen(info), out, 96) == 0;
    OPENSSL_cleanse(&ikm[0], ikm.size());
    return fOk;
}

bool NyxKdfRk(const uint8_t rk[32], const uint8_t dhOut[32], uint8_t out[96])
{
    return nyx_hkdf_sha256(rk, 32, dhOut, 32, (const uint8_t*)INFO_RK, strlen(INFO_RK), out, 96) == 0;
}

bool NyxKdfCk(const uint8_t ck[32], uint8_t ckNext[32], uint8_t mk[32])
{
    static const uint8_t one = 0x01, two = 0x02;
    unsigned int n = 32;
    Secret<32> m;
    const uint8_t salt[32] = {0};
    if (!HMAC(EVP_sha256(), ck, 32, &one, 1, m.b, &n) || n != 32 || !HMAC(EVP_sha256(), ck, 32, &two, 1, ckNext, &n)
        || n != 32 || nyx_hkdf_sha256(salt, 32, m.b, 32, (const uint8_t*)INFO_MK, strlen(INFO_MK), mk, 32) != 0)
    {
        OPENSSL_cleanse(ckNext, 32);
        OPENSSL_cleanse(mk, 32);
        return false;
    }
    return true;
}

void NyxTranscript(const NyxHandshake& hs, const uint8_t ikB[32], uint8_t out[32])
{
    NyxBytes v((const uint8_t*)TAG_TRANSCRIPT, (const uint8_t*)TAG_TRANSCRIPT + strlen(TAG_TRANSCRIPT));
    v.push_back(hs.mode);
    v.insert(v.end(), hs.addrA, hs.addrA + 20);
    v.insert(v.end(), hs.addrB, hs.addrB + 20);
    v.insert(v.end(), hs.devA, hs.devA + 16);
    v.insert(v.end(), hs.devB, hs.devB + 16);
    v.insert(v.end(), hs.ikA, hs.ikA + 32);
    v.insert(v.end(), ikB, ikB + 32);
    v.insert(v.end(), hs.certHashA, hs.certHashA + 32);
    v.insert(v.end(), hs.certHashB, hs.certHashB + 32);
    Put32(v, hs.epochA);
    Put32(v, hs.seqA);
    Put32(v, hs.epochB);
    Put32(v, hs.seqB);
    NyxHash(v, out);
}

void NyxHsId(const NyxHandshake& hs, uint8_t out[32])
{
    NyxBytes v(hs.ekA, hs.ekA + 32);
    v.insert(v.end(), hs.devA, hs.devA + 16);
    NyxHash(v, out);
}

// ---------------------------------------------------------------- ratchet state

NyxRatchet::NyxRatchet()
{
    memset(this->T, 0, 32);
    mode = NYX_MODE_PQ;
    memset(hsId, 0, 32);
    memset(remoteAddr, 0, 20);
    memset(remoteDev, 0, 16);
    memset(localDev, 0, 16);
    memset(localCert, 0, 32);
    memset(remoteCert, 0, 32);
    localEpoch = remoteEpoch = 0;
    fInitiator = fAcked = fOpk = false;
    created = lastUsed = 0;
    memset(RK, 0, 32);
    memset(CKs, 0, 32);
    memset(CKr, 0, 32);
    fCKs = fCKr = false;
    memset(DHsSk, 0, 32);
    memset(DHsPk, 0, 32);
    memset(DHr, 0, 32);
    fDHr = false;
    memset(HKs, 0, 32);
    memset(HKr, 0, 32);
    memset(NHKs, 0, 32);
    memset(NHKr, 0, 32);
    fHKs = fHKr = false;
    Ns = Nr = PN = 0;
}

NyxRatchet::NyxRatchet(const NyxRatchet& o)
{
    *this = o;
}

NyxRatchet& NyxRatchet::operator=(const NyxRatchet& o)
{
    if (this == &o)
        return *this;
    Wipe();
    mode = o.mode;
    memcpy(T, o.T, 32);
    memcpy(hsId, o.hsId, 32);
    memcpy(remoteAddr, o.remoteAddr, 20);
    memcpy(remoteDev, o.remoteDev, 16);
    memcpy(localDev, o.localDev, 16);
    memcpy(localCert, o.localCert, 32);
    memcpy(remoteCert, o.remoteCert, 32);
    localEpoch = o.localEpoch;
    remoteEpoch = o.remoteEpoch;
    fInitiator = o.fInitiator;
    fAcked = o.fAcked;
    fOpk = o.fOpk;
    hsFixed = o.hsFixed;
    created = o.created;
    lastUsed = o.lastUsed;
    memcpy(RK, o.RK, 32);
    memcpy(CKs, o.CKs, 32);
    memcpy(CKr, o.CKr, 32);
    fCKs = o.fCKs;
    fCKr = o.fCKr;
    memcpy(DHsSk, o.DHsSk, 32);
    memcpy(DHsPk, o.DHsPk, 32);
    memcpy(DHr, o.DHr, 32);
    fDHr = o.fDHr;
    memcpy(HKs, o.HKs, 32);
    memcpy(HKr, o.HKr, 32);
    memcpy(NHKs, o.NHKs, 32);
    memcpy(NHKr, o.NHKr, 32);
    fHKs = o.fHKs;
    fHKr = o.fHKr;
    Ns = o.Ns;
    Nr = o.Nr;
    PN = o.PN;
    skipped.reserve(o.skipped.size());
    skipped = o.skipped;
    return *this;
}

NyxRatchet::~NyxRatchet()
{
    Wipe();
}

void NyxRatchet::Wipe()
{
    OPENSSL_cleanse(RK, 32);
    OPENSSL_cleanse(CKs, 32);
    OPENSSL_cleanse(CKr, 32);
    OPENSSL_cleanse(DHsSk, 32);
    OPENSSL_cleanse(HKs, 32);
    OPENSSL_cleanse(HKr, 32);
    OPENSSL_cleanse(NHKs, 32);
    OPENSSL_cleanse(NHKr, 32);
    if (skipped.capacity())
        OPENSSL_cleanse(skipped.data(), skipped.capacity() * sizeof(NyxSkippedKey));
    skipped.clear();
}

void NyxRatchet::Serialize(std::string& s) const
{
    const uint8_t flags = (fInitiator ? 1 : 0) | (fAcked ? 2 : 0) | (fOpk ? 4 : 0) | (fCKs ? 8 : 0) | (fCKr ? 16 : 0)
                        | (fDHr ? 32 : 0) | (fHKs ? 64 : 0) | (fHKr ? 128 : 0);
    WrRaw(s, &mode, 1);
    WrRaw(s, &flags, 1);
    WrRaw(s, T, 32);
    WrRaw(s, hsId, 32);
    WrRaw(s, remoteAddr, 20);
    WrRaw(s, remoteDev, 16);
    WrRaw(s, localDev, 16);
    WrRaw(s, localCert, 32);
    WrRaw(s, remoteCert, 32);
    WrRaw(s, &localEpoch, 4);
    WrRaw(s, &remoteEpoch, 4);
    WrRaw(s, hsFixed.empty() ? NULL : &hsFixed[0], hsFixed.size());
    WrRaw(s, &created, 8);
    WrRaw(s, &lastUsed, 8);
    WrRaw(s, RK, 32);
    WrRaw(s, CKs, 32);
    WrRaw(s, CKr, 32);
    WrRaw(s, DHsSk, 32);
    WrRaw(s, DHr, 32);
    WrRaw(s, HKs, 32);
    WrRaw(s, HKr, 32);
    WrRaw(s, NHKs, 32);
    WrRaw(s, NHKr, 32);
    WrRaw(s, &Ns, 4);
    WrRaw(s, &Nr, 4);
    WrRaw(s, &PN, 4);
    const uint32_t n = skipped.size();
    WrRaw(s, &n, 4);
    for (size_t i = 0; i < skipped.size(); ++i)
        WrRaw(s, &skipped[i], sizeof(NyxSkippedKey));
}

bool NyxRatchet::Deserialize(const std::string& s, size_t& off)
{
    uint8_t flags = 0;
    uint32_t n = 0;
    if (!RdRaw(s, off, &mode, 1) || mode > NYX_MODE_PQ || !RdRaw(s, off, &flags, 1) || !RdRaw(s, off, T, 32)
        || !RdRaw(s, off, hsId, 32) || !RdRaw(s, off, remoteAddr, 20) || !RdRaw(s, off, remoteDev, 16)
        || !RdRaw(s, off, localDev, 16) || !RdRaw(s, off, localCert, 32) || !RdRaw(s, off, remoteCert, 32)
        || !RdRaw(s, off, &localEpoch, 4) || !RdRaw(s, off, &remoteEpoch, 4) || !RdBytes(s, off, hsFixed, NYX_HS_FIXED_PQ)
        || !RdRaw(s, off, &created, 8) || !RdRaw(s, off, &lastUsed, 8) || !RdRaw(s, off, RK, 32)
        || !RdRaw(s, off, CKs, 32) || !RdRaw(s, off, CKr, 32) || !RdRaw(s, off, DHsSk, 32) || !RdRaw(s, off, DHr, 32)
        || !RdRaw(s, off, HKs, 32) || !RdRaw(s, off, HKr, 32) || !RdRaw(s, off, NHKs, 32) || !RdRaw(s, off, NHKr, 32)
        || !RdRaw(s, off, &Ns, 4) || !RdRaw(s, off, &Nr, 4) || !RdRaw(s, off, &PN, 4) || !RdRaw(s, off, &n, 4)
        || n > NYX_MAX_SKIPPED)
        return false;
    fInitiator = flags & 1;
    fAcked = flags & 2;
    fOpk = flags & 4;
    fCKs = flags & 8;
    fCKr = flags & 16;
    fDHr = flags & 32;
    fHKs = flags & 64;
    fHKr = flags & 128;
    skipped.reserve(n);
    skipped.resize(n);
    for (uint32_t i = 0; i < n; ++i)
        if (!RdRaw(s, off, &skipped[i], sizeof(NyxSkippedKey)))
            return false;
    return nyx_x25519(DHsSk, BASE, DHsPk) == 0;
}

// ---------------------------------------------------------------- ratchet

static bool SealHeader(const uint8_t hk[32], const uint8_t T[32], const uint8_t hdr[NYX_HDR_LEN], uint8_t* out)
{
    if (nyx_random(out, 12) != 0)
        return false;
    return nyx_aead_seal(hk, out, T, 32, hdr, NYX_HDR_LEN, out + 12) == 0;
}

static bool OpenHeader(const uint8_t hk[32], const uint8_t T[32], const uint8_t* in, uint8_t hdr[NYX_HDR_LEN])
{
    return nyx_aead_open(hk, in, T, 32, in + 12, NYX_ENC_HDR_LEN, hdr) == 0;
}

static NyxBytes BodyAd(const uint8_t T[32], const uint8_t* encHdr, const uint8_t* mnonce)
{
    NyxBytes ad(T, T + 32);
    ad.insert(ad.end(), encHdr, encHdr + 12 + NYX_ENC_HDR_LEN);
    ad.insert(ad.end(), mnonce, mnonce + 12);
    return ad;
}

bool NyxRatchetEncrypt(NyxRatchet& s, const NyxBytes& pt, int64_t now, NyxBytes& tail)
{
    if (!s.fCKs || !s.fHKs || s.Ns == 0xFFFFFFFFu)
        return false;
    Secret<32> mk, ck;
    if (!NyxKdfCk(s.CKs, ck.b, mk.b))
        return false;
    uint8_t hdr[NYX_HDR_LEN];
    memcpy(hdr, s.DHsPk, 32);
    for (int i = 0; i < 4; ++i)
    {
        hdr[32 + i] = (uint8_t)(s.PN >> (8 * i));
        hdr[36 + i] = (uint8_t)(s.Ns >> (8 * i));
    }
    tail.assign(12 + NYX_ENC_HDR_LEN + 12 + pt.size() + 16, 0);
    uint8_t* mnonce = &tail[12 + NYX_ENC_HDR_LEN];
    if (!SealHeader(s.HKs, s.T, hdr, &tail[0]) || nyx_random(mnonce, 12) != 0)
        return false;
    const NyxBytes ad = BodyAd(s.T, &tail[0], mnonce);
    if (nyx_aead_seal(mk.b, mnonce, &ad[0], ad.size(), pt.empty() ? NULL : &pt[0], pt.size(), mnonce + 12) != 0)
        return false;
    memcpy(s.CKs, ck.b, 32);
    s.Ns++;
    s.lastUsed = now;
    return true;
}

static bool OpenBody(const NyxRatchet& s, const uint8_t mk[32], const NyxBytes& tail, NyxBytes& pt)
{
    const uint8_t* mnonce = &tail[12 + NYX_ENC_HDR_LEN];
    const size_t nCt = tail.size() - 12 - NYX_ENC_HDR_LEN - 12;
    const NyxBytes ad = BodyAd(s.T, &tail[0], mnonce);
    pt.assign(nCt - 16, 0);
    if (nyx_aead_open(mk, mnonce, &ad[0], ad.size(), mnonce + 12, nCt, pt.empty() ? NULL : &pt[0]) != 0)
    {
        if (!pt.empty())
            OPENSSL_cleanse(&pt[0], pt.size());
        pt.clear();
        return false;
    }
    return true;
}

// push_back without leaving a freed copy of the keys behind on reallocation.
static void PushSkipped(std::vector<NyxSkippedKey>& v, const NyxSkippedKey& k)
{
    if (v.size() == v.capacity())
    {
        std::vector<NyxSkippedKey> w;
        w.reserve(std::max<size_t>(16, v.capacity() * 2));
        w = v;
        if (!v.empty())
            OPENSSL_cleanse(&v[0], v.size() * sizeof(NyxSkippedKey));
        v.swap(w);
    }
    v.push_back(k);
}

static void EraseSkipped(std::vector<NyxSkippedKey>& v, size_t i)
{
    OPENSSL_cleanse(&v[i], sizeof(NyxSkippedKey));
    v.erase(v.begin() + i);
    OPENSSL_cleanse(v.data() + v.size(), sizeof(NyxSkippedKey));
}

static int SkipKeys(NyxRatchet& s, uint32_t until, int64_t now)
{
    if (until < s.Nr)
        return NYX_DR_OK;
    if (until - s.Nr > NYX_MAX_SKIP)
        return NYX_DR_SKIP_LIMIT;
    if (!s.fCKr)
        return NYX_DR_OK;
    while (s.Nr < until)
    {
        NyxSkippedKey k;
        uint8_t ck[32];
        memcpy(k.hk, s.HKr, 32);
        k.n = s.Nr;
        k.ts = now;
        if (!NyxKdfCk(s.CKr, ck, k.mk))
        {
            OPENSSL_cleanse(&k, sizeof(k));
            return NYX_DR_MALFORMED;
        }
        memcpy(s.CKr, ck, 32);
        OPENSSL_cleanse(ck, 32);
        if (s.skipped.size() >= NYX_MAX_SKIPPED)
        {
            EraseSkipped(s.skipped, 0);
        }
        PushSkipped(s.skipped, k);
        OPENSSL_cleanse(&k, sizeof(k));
        s.Nr++;
    }
    return NYX_DR_OK;
}

static bool DhRatchet(NyxRatchet& s, const uint8_t dhr[32])
{
    Secret<32> dh;
    Secret<96> o;
    s.PN = s.Ns;
    s.Ns = 0;
    s.Nr = 0;
    memcpy(s.HKs, s.NHKs, 32);
    memcpy(s.HKr, s.NHKr, 32);
    s.fHKs = s.fHKr = true;
    memcpy(s.DHr, dhr, 32);
    s.fDHr = true;
    if (!Dh(s.DHsSk, s.DHr, dh.b) || !NyxKdfRk(s.RK, dh.b, o.b))
        return false;
    memcpy(s.RK, o.b, 32);
    memcpy(s.CKr, o.b + 32, 32);
    memcpy(s.NHKr, o.b + 64, 32);
    s.fCKr = true;
    if (nyx_x25519_keygen(s.DHsSk, s.DHsPk) != 0 || !Dh(s.DHsSk, s.DHr, dh.b) || !NyxKdfRk(s.RK, dh.b, o.b))
        return false;
    memcpy(s.RK, o.b, 32);
    memcpy(s.CKs, o.b + 32, 32);
    memcpy(s.NHKs, o.b + 64, 32);
    s.fCKs = true;
    return true;
}

void NyxRatchetExpire(NyxRatchet& s, int64_t now)
{
    for (size_t i = 0; i < s.skipped.size();)
        if (now - s.skipped[i].ts > NYX_SKIPPED_TTL)
        {
            EraseSkipped(s.skipped, i);
        }
        else
            ++i;
}

int NyxRatchetDecrypt(NyxRatchet& st, const NyxBytes& tail, int64_t now, NyxBytes& pt)
{
    pt.clear();
    if (tail.size() < NYX_TAIL_MIN)
        return NYX_DR_MALFORMED;
    NyxRatchet s(st);
    NyxRatchetExpire(s, now);
    uint8_t hdr[NYX_HDR_LEN];

    const uint8_t* lastHk = NULL;
    bool fLastOpen = false;
    for (size_t i = 0; i < s.skipped.size(); ++i)
    {
        if (!lastHk || memcmp(lastHk, s.skipped[i].hk, 32) != 0)
        {
            lastHk = s.skipped[i].hk;
            fLastOpen = OpenHeader(lastHk, s.T, &tail[0], hdr);
        }
        if (!fLastOpen || Rd32(hdr + 36) != s.skipped[i].n)
            continue;
        if (!OpenBody(s, s.skipped[i].mk, tail, pt))
            return NYX_DR_AUTH;
        EraseSkipped(s.skipped, i);
        if (s.fInitiator)
            s.fAcked = true;
        s.lastUsed = now;
        st = s;
        return NYX_DR_OK;
    }

    bool fRatchet;
    if (s.fHKr && OpenHeader(s.HKr, s.T, &tail[0], hdr))
        fRatchet = false;
    else if (OpenHeader(s.NHKr, s.T, &tail[0], hdr))
        fRatchet = true;
    else
        return NYX_DR_NO_HEADER;
    const uint32_t pn = Rd32(hdr + 32), n = Rd32(hdr + 36);
    if (!fRatchet && n < s.Nr)
        return NYX_DR_REPLAY;
    if (fRatchet)
    {
        int r = SkipKeys(s, pn, now);
        if (r != NYX_DR_OK)
            return r;
        if (!DhRatchet(s, hdr))
            return NYX_DR_AUTH;
    }
    int r = SkipKeys(s, n, now);
    if (r != NYX_DR_OK)
        return r;
    Secret<32> mk, ck;
    if (!NyxKdfCk(s.CKr, ck.b, mk.b))
        return NYX_DR_MALFORMED;
    if (!OpenBody(s, mk.b, tail, pt))
        return NYX_DR_AUTH;
    memcpy(s.CKr, ck.b, 32);
    s.Nr++;
    if (s.fInitiator)
        s.fAcked = true;
    s.lastUsed = now;
    st = s;
    return NYX_DR_OK;
}

// ---------------------------------------------------------------- session

std::string NyxSession::Serialize() const
{
    std::string s;
    size_t n = 64;
    for (size_t i = 0; i < states.size(); ++i)
        n += 1024 + states[i].hsFixed.size() + states[i].skipped.size() * (sizeof(NyxSkippedKey) + 4);
    s.reserve(n);
    const uint8_t ver = 2, cnt = states.size();
    s.push_back((char)ver);
    s.push_back((char)cnt);
    for (size_t i = 0; i < states.size(); ++i)
        states[i].Serialize(s);
    return s;
}

bool NyxSession::Deserialize(const std::string& s)
{
    states.clear();
    if (s.size() < 2 || s[0] != 2 || (uint8_t)s[1] > NYX_SESSION_STATES)
        return false;
    size_t off = 2;
    states.resize((uint8_t)s[1]);
    for (size_t i = 0; i < states.size(); ++i)
        if (!states[i].Deserialize(s, off))
        {
            states.clear();
            return false;
        }
    return off == s.size();
}

bool NyxSessBind::Matches(const NyxRatchet& r) const
{
    return memcmp(r.localDev, localDev, 16) == 0 && memcmp(r.localCert, localCert, 32) == 0
        && r.localEpoch == localEpoch && memcmp(r.remoteAddr, remoteAddr, 20) == 0
        && memcmp(r.remoteDev, remoteDev, 16) == 0 && memcmp(r.remoteCert, remoteCert, 32) == 0
        && r.remoteEpoch == remoteEpoch;
}

int NyxSession::Decrypt(const NyxBytes& tail, int64_t now, NyxBytes& pt, const NyxSessBind* bind, size_t* idx)
{
    int best = NYX_DR_NO_HEADER;
    for (size_t i = 0; i < states.size(); ++i)
    {
        if (bind && !bind->Matches(states[i]))
            continue;
        if (i > 0 && now - states[0].created > NYX_SKIPPED_TTL)
            continue;
        // Simultaneous initiation: opposite directions, made within NYX_HS_RETRY, the initiator side unacked.
        bool fSimul = false;
        if (i != 0)
        {
            const NyxRatchet& c = states[0];
            const NyxRatchet& o = states[i];
            const int64_t dt = c.created > o.created ? c.created - o.created : o.created - c.created;
            fSimul = c.fInitiator != o.fInitiator && dt < NYX_HS_RETRY && !(c.fInitiator ? c.fAcked : o.fAcked);
        }
        const int r = NyxRatchetDecrypt(states[i], tail, now, pt);
        if (r == NYX_DR_OK)
        {
            if (fSimul && memcmp(states[i].hsId, states[0].hsId, 32) < 0)
            {
                std::swap(states[0], states[i]);
                i = 0;
            }
            if (idx)
                *idx = i;
            return r;
        }
        if (r != NYX_DR_NO_HEADER)
            best = r;
    }
    return best;
}

void NyxSession::Push(const NyxRatchet& r)
{
    states.insert(states.begin(), r);
    while (states.size() > NYX_SESSION_STATES)
        states.pop_back();
}

int NyxSession::FindHs(const uint8_t hsId[32]) const
{
    for (size_t i = 0; i < states.size(); ++i)
        if (memcmp(states[i].hsId, hsId, 32) == 0)
            return (int)i;
    return -1;
}

bool NyxSession::BoundTo(const uint8_t remoteAddr[20]) const
{
    for (size_t i = 0; i < states.size(); ++i)
        if (memcmp(states[i].remoteAddr, remoteAddr, 20) != 0)
            return false;
    return true;
}

int NyxSession::SentCheck(const NyxBytes& tail, const uint8_t* remoteAddr) const
{
    if (tail.size() < NYX_TAIL_MIN)
        return NYX_SENT_NONE;
    for (size_t i = 0; i < states.size(); ++i)
    {
        const NyxRatchet& r = states[i];
        if (remoteAddr && memcmp(r.remoteAddr, remoteAddr, 20) != 0)
            continue;
        uint8_t hdr[NYX_HDR_LEN];
        const bool fCur = r.fHKs && OpenHeader(r.HKs, r.T, &tail[0], hdr);
        if (!fCur && !OpenHeader(r.NHKs, r.T, &tail[0], hdr))
            continue;
        const bool fOurs = fCur && memcmp(hdr, r.DHsPk, 32) == 0 && Rd32(hdr + 36) < r.Ns;
        const bool fOld = fCur && memcmp(hdr, r.DHsPk, 32) != 0;
        OPENSSL_cleanse(hdr, sizeof(hdr));
        if (fOurs)
            return NYX_SENT_OURS;
        // An earlier sending chain cannot be told apart from our own past messages.
        return fOld ? NYX_SENT_NONE : NYX_SENT_COPY;
    }
    return NYX_SENT_NONE;
}

std::vector<NyxFanoutTarget> NyxFanout(const NyxKeyring& peerKr, const std::vector<std::string>& peerUsable,
                                       const NyxKeyring* ownKr, const std::vector<std::string>& ownUsable,
                                       const uint8_t selfDev[16])
{
    std::vector<NyxFanoutTarget> v;
    std::set<std::string> done;
    const std::string self((const char*)selfDev, 16);
    for (int k = 0; k < 2; ++k)
    {
        const NyxKeyring* kr = k == 0 ? &peerKr : ownKr;
        const std::vector<std::string>& usable = k == 0 ? peerUsable : ownUsable;
        if (!kr)
            continue;
        for (size_t i = 0; i < usable.size() && v.size() < NYX_FANOUT_MAX; ++i)
        {
            const std::string& id = usable[i];
            if (id.size() != 16 || id == self || !kr->IsLive((const uint8_t*)id.data())
                || std::find(kr->revoked.begin(), kr->revoked.end(), id) != kr->revoked.end()
                || !done.insert(std::string(1, (char)k) + id).second)
                continue;
            NyxFanoutTarget t;
            t.fOwn = k == 1;
            t.dev = id;
            v.push_back(t);
        }
    }
    return v;
}

int NyxRouteEnvelope(const NyxEnvelope& env, const uint8_t local[20], const uint8_t remote[20])
{
    static const uint8_t zero[32] = {0};
    const bool fSelf = memcmp(local, remote, 20) == 0;
    const bool fGroup = memcmp(env.groupId, zero, 32) != 0;
    if (env.ctype == NYX_CTYPE_MSG && !fSelf && memcmp(env.convAddr, remote, 20) == 0)
        return fGroup ? NYX_ROUTE_GROUP_IN : NYX_ROUTE_IN;
    if (env.ctype == NYX_CTYPE_SENT && fSelf && !fGroup && memcmp(env.convAddr, local, 20) != 0)
        return NYX_ROUTE_SENT;
    if (env.ctype == NYX_CTYPE_SENT && fSelf && fGroup && memcmp(env.convAddr, zero, 20) == 0)
        return NYX_ROUTE_GROUP_SENT;
    return NYX_ROUTE_DROP;
}

bool NyxSession::NeedsHandshake(const uint8_t localCert[32], uint32_t localEpoch, const uint8_t remoteCert[32],
                                uint32_t remoteEpoch, int64_t now) const
{
    if (states.empty())
        return true;
    const NyxRatchet& r = states[0];
    return !r.fCKs || memcmp(r.localCert, localCert, 32) != 0 || memcmp(r.remoteCert, remoteCert, 32) != 0
        || r.localEpoch != localEpoch || r.remoteEpoch != remoteEpoch || r.Ns >= NYX_RESYNC_SENDS
        || (r.fInitiator && !r.fAcked && now - r.created > NYX_HS_RETRY);
}

bool NyxSeenPrune(std::map<std::string, int64_t>& seen, int64_t now)
{
    for (std::map<std::string, int64_t>::iterator it = seen.begin(); it != seen.end();)
        if (now - it->second > NYX_HS_WINDOW)
            seen.erase(it++);
        else
            ++it;
    return seen.size() < NYX_SEEN_MAX;
}

size_t NyxHeldEvict(const std::vector<NyxHeldTag>& q, const NyxHeldTag& t)
{
    size_t nSender = 0, nUnpinned = 0, firstSender = q.size(), firstUnpinned = q.size();
    for (size_t i = 0; i < q.size(); ++i)
    {
        if (q[i].sender == t.sender && nSender++ == 0)
            firstSender = i;
        if (q[i].fUnpinned && nUnpinned++ == 0)
            firstUnpinned = i;
    }
    if (nSender >= NYX_HELD_PER_SENDER)
        return firstSender;
    if (t.fUnpinned && nUnpinned >= NYX_HELD_UNPINNED_MAX)
        return firstUnpinned;
    if (q.size() >= NYX_HELD_MAX)
        return firstUnpinned < q.size() ? firstUnpinned : 0;
    return q.size();
}

// ---------------------------------------------------------------- handshake

static bool SignHs(const NyxLocalSide& me, const NyxHandshake& hs, const uint8_t T[32], NyxBytes& sig)
{
    NyxBytes m(T, T + 32);
    const NyxBytes f = hs.Fields();
    m.insert(m.end(), f.begin(), f.end());
    if (hs.mode == NYX_MODE_PQ)
        return NyxDsaSign(me.dev->dsaSeed, NyxTagged(NYX_TAG_HS, m), sig);
    if (!me.addrKey)
        return false;
    sig.assign(65, 0);
    return NyxAddrSign(*me.addrKey, NYX_TAG_HS, m, &sig[0]);
}

static bool VerifyHs(const NyxCert& certA, const NyxHandshake& hs, const uint8_t T[32])
{
    NyxBytes m(T, T + 32);
    const NyxBytes f = hs.Fields();
    m.insert(m.end(), f.begin(), f.end());
    if (hs.mode == NYX_MODE_PQ)
        return NyxDsaVerify(certA.dsaPk, NyxTagged(NYX_TAG_HS, m), hs.sig);
    return hs.sig.size() == 65 && NyxAddrVerify(hs.addrA, NYX_TAG_HS, m, &hs.sig[0]);
}

bool NyxIsOwnCopy(const NyxSession& s, const uint8_t local[20], const NyxBytes& body, const NyxCert& ownCert)
{
    if (body.empty() || !s.BoundTo(local))
        return false;
    if (body[0] == NYX_BODY_RATCHET)
    {
        NyxRatchetMsg m;
        return NyxParseRatchetMsg(&body[0], body.size(), m) == 0 && memcmp(m.devA, ownCert.deviceId, 16) == 0
            && s.SentCheck(m.tail, local) == NYX_SENT_COPY;
    }
    NyxHandshake hs;
    if (NyxParseHandshake(&body[0], body.size(), hs) != 0 || memcmp(hs.devA, ownCert.deviceId, 16) != 0
        || memcmp(hs.addrA, local, 20) != 0 || memcmp(hs.addrB, local, 20) != 0)
        return false;
    uint8_t hsId[32];
    NyxHsId(hs, hsId);
    // An unacked initiator wraps every new tail in its handshake: the tail shows whether this state sent it.
    return s.FindHs(hsId) >= 0 && s.SentCheck(hs.tail, local) == NYX_SENT_COPY;
}

bool NyxHsInitiate(const NyxLocalSide& me, const NyxPeerSide& peer, const NyxBundle& b, int64_t now,
                   NyxRatchet& out, std::string& sError)
{
    const NyxOwnDevice& d = *me.dev;
    const NyxCert& cB = *peer.cert;
    if (d.mode != cB.mode)
    {
        sError = d.mode == NYX_MODE_PQ ? "peer device is classical-only; refusing to downgrade"
                                       : "peer device is PQ; this device is classical";
        return false;
    }
    if (!NyxBundleValid(b, cB))
    {
        sError = "bundle does not verify under the pinned cert";
        return false;
    }
    NyxHandshake hs;
    hs.mode = d.mode;
    memcpy(hs.addrA, d.addrHash, 20);
    memcpy(hs.addrB, cB.addrHash, 20);
    memcpy(hs.devB, cB.deviceId, 16);
    memcpy(hs.devA, d.deviceId, 16);
    memcpy(hs.certHashA, me.certHash, 32);
    memcpy(hs.certHashB, peer.certHash, 32);
    memcpy(hs.ikA, d.ik, 32);
    hs.epochA = me.epoch;
    hs.seqA = me.seq;
    hs.epochB = peer.epoch;
    hs.seqB = peer.seq;
    hs.spkId = b.spkId;
    hs.kemId = b.fPq ? b.kemId : 0;
    hs.ts = now;

    Secret<32> ekSk;
    Secret<32 * 4> dh;
    Secret<32> ss;
    Secret<96> keys;
    if (nyx_x25519_keygen(ekSk.b, hs.ekA) != 0)
        return false;
    size_t nDh = 3;
    if (!Dh(d.ikSk, b.spk, dh.b) || !Dh(ekSk.b, cB.ik, dh.b + 32) || !Dh(ekSk.b, b.spk, dh.b + 64))
    {
        sError = "bad bundle key";
        return false;
    }
    if (!b.opks.empty())
    {
        // Random pick: initiators working from one bundle rarely collide on a single-use key.
        uint32_t pick = 0;
        if (nyx_random((uint8_t*)&pick, 4) != 0)
            return false;
        const std::pair<uint32_t, NyxBytes>& opk = b.opks[pick % b.opks.size()];
        hs.opkId = opk.first;
        if (opk.second.size() != 32 || !Dh(ekSk.b, &opk.second[0], dh.b + 96))
        {
            sError = "bad one-time prekey";
            return false;
        }
        nDh = 4;
    }
    if (hs.mode == NYX_MODE_PQ)
    {
        hs.ct.assign(NYX_MLKEM768_CT, 0);
        if (b.ek.size() != NYX_MLKEM768_EK || nyx_mlkem768_encaps(&b.ek[0], &hs.ct[0], ss.b) != 0)
        {
            sError = "ML-KEM encapsulation failed";
            return false;
        }
    }
    if (!NyxPqxdhKdf(dh.b, nDh, hs.mode == NYX_MODE_PQ ? ss.b : NULL, keys.b))
        return false;

    out = NyxRatchet();
    NyxTranscript(hs, cB.ik, out.T);
    if (!SignHs(me, hs, out.T, hs.sig))
    {
        sError = "could not sign the handshake";
        return false;
    }
    out.mode = hs.mode;
    NyxHsId(hs, out.hsId);
    memcpy(out.remoteAddr, cB.addrHash, 20);
    memcpy(out.remoteDev, cB.deviceId, 16);
    memcpy(out.localDev, d.deviceId, 16);
    memcpy(out.localCert, me.certHash, 32);
    memcpy(out.remoteCert, peer.certHash, 32);
    out.localEpoch = me.epoch;
    out.remoteEpoch = peer.epoch;
    out.fInitiator = true;
    out.fOpk = nDh == 4;
    out.hsFixed = hs.Fixed();
    out.created = out.lastUsed = now;

    // Alice: DHr = SPK_B, first DH ratchet step now.
    Secret<32> dhOut;
    Secret<96> o;
    memcpy(out.DHr, b.spk, 32);
    out.fDHr = true;
    if (nyx_x25519_keygen(out.DHsSk, out.DHsPk) != 0 || !Dh(out.DHsSk, out.DHr, dhOut.b)
        || !NyxKdfRk(keys.b, dhOut.b, o.b))
        return false;
    memcpy(out.RK, o.b, 32);
    memcpy(out.CKs, o.b + 32, 32);
    memcpy(out.NHKs, o.b + 64, 32);
    out.fCKs = true;
    memcpy(out.HKs, keys.b + 32, 32);
    out.fHKs = true;
    memcpy(out.NHKr, keys.b + 64, 32);
    return true;
}

bool NyxHsRespond(const NyxLocalSide& me, const NyxPeerSide& peer, const NyxHandshake& hs, int64_t now,
                  NyxRatchet& out, uint32_t& opkUsed, std::string& sError)
{
    opkUsed = NYX_OPK_NONE;
    const NyxOwnDevice& d = *me.dev;
    const NyxCert& cA = *peer.cert;
    if (memcmp(hs.devB, d.deviceId, 16) != 0 || memcmp(hs.addrB, d.addrHash, 20) != 0)
    {
        sError = "handshake is for another device";
        return false;
    }
    if (hs.mode != d.mode || cA.mode != d.mode)
    {
        sError = "mode mismatch (downgrade refused)";
        return false;
    }
    if (memcmp(hs.devA, cA.deviceId, 16) != 0 || memcmp(hs.addrA, cA.addrHash, 20) != 0
        || memcmp(hs.certHashA, peer.certHash, 32) != 0 || memcmp(hs.ikA, cA.ik, 32) != 0)
    {
        sError = "initiator does not match its pinned cert";
        return false;
    }
    if (memcmp(hs.certHashB, me.certHash, 32) != 0 || hs.epochB != me.epoch || hs.seqB > me.seq)
    {
        sError = "handshake names another cert or keyring of this device";
        return false;
    }
    if (hs.epochA != peer.epoch || hs.seqA > peer.seq)
    {
        sError = "handshake names a keyring of the initiator that is not pinned";
        return false;
    }
    if ((int64_t)hs.ts < now - NYX_HS_WINDOW || (int64_t)hs.ts > now + NYX_HS_FUTURE)
    {
        sError = "handshake time outside the window";
        return false;
    }
    out = NyxRatchet();
    NyxTranscript(hs, d.ik, out.T);
    if (!VerifyHs(cA, hs, out.T))
    {
        sError = "handshake signature does not verify";
        return false;
    }
    Secret<32> spkSk;
    const uint8_t* kemSeed = NULL;
    if (!NyxDeviceSpk(d, hs.spkId, now, spkSk.b, &kemSeed) || (hs.mode == NYX_MODE_PQ && hs.kemId != hs.spkId))
    {
        sError = "unknown or expired signed prekey";
        return false;
    }
    Secret<32 * 4> dh;
    Secret<32> ss;
    Secret<96> keys;
    size_t nDh = 3;
    if (!Dh(spkSk.b, hs.ikA, dh.b) || !Dh(d.ikSk, hs.ekA, dh.b + 32) || !Dh(spkSk.b, hs.ekA, dh.b + 64))
    {
        sError = "bad handshake key";
        return false;
    }
    if (hs.opkId != NYX_OPK_NONE)
    {
        const NyxOpk* o = NyxDeviceOpk(d, hs.opkId);
        if (!o || !Dh(o->sk, hs.ekA, dh.b + 96))
        {
            sError = "unknown or used one-time prekey";
            return false;
        }
        nDh = 4;
        opkUsed = hs.opkId;
    }
    if (hs.mode == NYX_MODE_PQ && (hs.ct.size() != NYX_MLKEM768_CT || nyx_mlkem768_decaps(kemSeed, &hs.ct[0], ss.b) != 0))
    {
        sError = "ML-KEM decapsulation failed";
        return false;
    }
    if (!NyxPqxdhKdf(dh.b, nDh, hs.mode == NYX_MODE_PQ ? ss.b : NULL, keys.b))
        return false;

    out.mode = hs.mode;
    NyxHsId(hs, out.hsId);
    memcpy(out.remoteAddr, hs.addrA, 20);
    memcpy(out.remoteDev, hs.devA, 16);
    memcpy(out.localDev, d.deviceId, 16);
    memcpy(out.localCert, me.certHash, 32);
    memcpy(out.remoteCert, peer.certHash, 32);
    out.localEpoch = me.epoch;
    out.remoteEpoch = peer.epoch;
    out.fInitiator = false;
    out.fAcked = true;
    out.fOpk = nDh == 4;
    out.created = out.lastUsed = now;
    // Bob: DHs = SPK until the first DH ratchet step.
    memcpy(out.DHsSk, spkSk.b, 32);
    if (nyx_x25519(out.DHsSk, BASE, out.DHsPk) != 0)
        return false;
    memcpy(out.RK, keys.b, 32);
    memcpy(out.NHKs, keys.b + 64, 32);
    memcpy(out.NHKr, keys.b + 32, 32);
    return true;
}

bool NyxSessionSeal(NyxRatchet& r, const NyxBytes& pt, int64_t now, NyxBytes& body)
{
    NyxBytes tail;
    if (!NyxRatchetEncrypt(r, pt, now, tail))
        return false;
    body.clear();
    if (r.fInitiator && !r.fAcked)
    {
        if (r.hsFixed.empty())
            return false;
        body.reserve(r.hsFixed.size() + tail.size());
        body = r.hsFixed;
    }
    else
    {
        body.reserve(33 + tail.size());
        body.push_back(NYX_BODY_RATCHET);
        body.insert(body.end(), r.remoteDev, r.remoteDev + 16);
        body.insert(body.end(), r.localDev, r.localDev + 16);
    }
    body.insert(body.end(), tail.begin(), tail.end());
    return true;
}
