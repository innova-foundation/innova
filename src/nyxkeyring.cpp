// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "nyxkeyring.h"
#include "nyxpo.h"
#include "privacy_vnext/rust/include/nyx_pq.h"

#include "key.h"
#include "uint256.h"

#include <algorithm>
#include <string.h>

static_assert(NYX_MLDSA_PK == NYX_MLDSA65_PK, "ML-DSA-65 public key size");
static_assert(NYX_MLDSA_SIG == NYX_MLDSA65_SIG, "ML-DSA-65 signature size");
static_assert(NYX_MLKEM_EK == NYX_MLKEM768_EK, "ML-KEM-768 encapsulation key size");
static_assert(NYX_X25519_LEN == NYX_X25519, "X25519 size");
static_assert(NYX_MLDSA_SEED_LEN == NYX_MLDSA65_SEED, "ML-DSA seed size");
static_assert(NYX_MLKEM_SEED_LEN == NYX_MLKEM768_SEED, "ML-KEM seed size");

static uint256 TaggedHash(const char* tag, const NyxBytes& fields)
{
    const NyxBytes m = NyxTagged(tag, fields);
    uint8_t h[32];
    NyxHash(m, h);
    uint256 r;
    memcpy(r.begin(), h, 32);
    return r;
}

static const uint8_t SECP_N[32] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
                                   0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41};
static const uint8_t SECP_HALF_N[32] = {0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                                        0x5d,0x57,0x6e,0x73,0x57,0xa4,0x50,0x1d,0xdf,0xe9,0x2f,0x46,0x68,0x1b,0x20,0xa0};

// One encoding per signature: header 27..34 and s in [1, n/2].
static bool CompactCanonical(const uint8_t sig[65])
{
    return sig[0] >= 27 && sig[0] <= 34 && !NyxIsZero(sig + 33, 32) && memcmp(sig + 33, SECP_HALF_N, 32) <= 0;
}

bool NyxAddrSign(const CKey& key, const char* tag, const NyxBytes& fields, uint8_t sig[65])
{
    std::vector<unsigned char> v;
    if (!key.SignCompact(TaggedHash(tag, fields), v) || v.size() != 65)
        return false;
    if (memcmp(&v[33], SECP_HALF_N, 32) > 0)
    {
        int borrow = 0;
        for (int i = 31; i >= 0; --i)
        {
            const int d = (int)SECP_N[i] - (int)v[33 + i] - borrow;
            v[33 + i] = (unsigned char)(d & 0xff);
            borrow = d < 0;
        }
        v[0] ^= 1;
    }
    memcpy(sig, &v[0], 65);
    return CompactCanonical(sig);
}

bool NyxAddrVerify(const uint8_t addrHash[20], const char* tag, const NyxBytes& fields, const uint8_t sig[65])
{
    if (!CompactCanonical(sig))
        return false;
    CPubKey pk;
    if (!pk.RecoverCompact(TaggedHash(tag, fields), std::vector<unsigned char>(sig, sig + 65)))
        return false;
    const CKeyID id = pk.GetID();
    return memcmp(id.begin(), addrHash, 20) == 0;
}

bool NyxDsaSign(const uint8_t seed[32], const NyxBytes& msg, NyxBytes& sig)
{
    sig.assign(NYX_MLDSA65_SIG, 0);
    return nyx_mldsa65_sign(seed, msg.empty() ? NULL : &msg[0], msg.size(), &sig[0]) == 0;
}

bool NyxDsaVerify(const NyxBytes& pk, const NyxBytes& msg, const NyxBytes& sig)
{
    if (pk.size() != NYX_MLDSA65_PK || sig.size() != NYX_MLDSA65_SIG)
        return false;
    return nyx_mldsa65_verify(&pk[0], msg.empty() ? NULL : &msg[0], msg.size(), &sig[0]) == 0;
}

NyxBytes NyxCertSignerMsg(const NyxCert& c)
{
    NyxBytes m = NyxTagged(NYX_TAG_CERT, c.Signed());
    m.insert(m.end(), c.addrSig, c.addrSig + 65);
    return m;
}

NyxBytes NyxKeyringSignerMsg(const NyxKeyring& k)
{
    NyxBytes m = NyxTagged(NYX_TAG_KEYRING, k.Signed());
    m.insert(m.end(), k.addrSig, k.addrSig + 65);
    return m;
}

bool NyxCertAddrValid(const NyxCert& c)
{
    return NyxAddrVerify(c.addrHash, NYX_TAG_CERT, c.Signed(), c.addrSig);
}

bool NyxCertSignerValid(const NyxCert& c, const NyxBytes& signerPk)
{
    return c.mode == NYX_MODE_PQ && c.HasSigner() && NyxDsaVerify(signerPk, NyxCertSignerMsg(c), c.signerSig);
}

bool NyxKeyringAddrValid(const NyxKeyring& k)
{
    return NyxAddrVerify(k.addrHash, NYX_TAG_KEYRING, k.Signed(), k.addrSig);
}

bool NyxKeyringSignerValid(const NyxKeyring& k, const NyxBytes& signerPk)
{
    return k.mode == NYX_MODE_PQ && k.seq > 1 && NyxDsaVerify(signerPk, NyxKeyringSignerMsg(k), k.signerSig);
}

bool NyxBundleValid(const NyxBundle& b, const NyxCert& cert)
{
    if (memcmp(b.addrHash, cert.addrHash, 20) != 0 || memcmp(b.deviceId, cert.deviceId, 16) != 0)
        return false;
    if (b.fPq != (cert.mode == NYX_MODE_PQ))
        return false;
    const NyxBytes fields = b.Fields();
    if (b.fPq)
        return NyxDsaVerify(cert.dsaPk, NyxTagged(NYX_TAG_BUNDLE, fields), b.sig);
    return b.sig.size() == 65 && NyxAddrVerify(b.addrHash, NYX_TAG_BUNDLE, fields, &b.sig[0]);
}

// ---------------------------------------------------------------- relay

static bool HashEq(const NyxBytes& a, const uint8_t* b)
{
    return a.size() == 32 && memcmp(&a[0], b, 32) == 0;
}

static uint32_t MaxEpoch(const NyxRelayHeld& held)
{
    uint32_t e = 0;
    for (size_t i = 0; i < held.keyrings.size(); ++i)
        e = std::max(e, held.keyrings[i].epoch);
    return e;
}

// A signer cert held by the relay that is live in kr (by id) with a matching cert hash, or renewed.
static const NyxCert* RelaySignerCert(const NyxRelayHeld& held, const NyxKeyring& pred, const uint8_t id[16],
                                      const NyxKeyring* pNext)
{
    const NyxKeyringEntry* e = pred.Find(id);
    if (!e)
        return NULL;
    std::map<std::string, NyxCert>::const_iterator it = held.certs.find(NyxId(id));
    if (it == held.certs.end())
        return NULL;
    const NyxBytes& h = held.certHashes.find(NyxId(id))->second;
    if (HashEq(h, e->certHash))
        return &it->second;
    const NyxKeyringEntry* n = pNext ? pNext->Find(id) : NULL;
    if (n && HashEq(h, n->certHash))
        return &it->second;
    return NULL;
}

static int RelayKeyring(const NyxRelayHeld& held, const NyxKeyring& kr, const uint8_t hash[32])
{
    if (!NyxKeyringAddrValid(kr))
        return NYX_PO_BAD;
    for (size_t i = 0; i < kr.live.size(); ++i)
        if (held.revoked.count(NyxId(kr.live[i].deviceId)) && kr.epoch == MaxEpoch(held))
            return NYX_PO_BAD;
    if (held.keyrings.empty())
    {
        if (kr.seq == 1 || kr.mode != NYX_MODE_PQ)
            return NYX_PO_OK;
        std::map<std::string, NyxCert>::const_iterator it = held.certs.find(NyxId(kr.signerId));
        if (it == held.certs.end())
            return NYX_PO_UNVERIFIED;
        return NyxKeyringSignerValid(kr, it->second.dsaPk) ? NYX_PO_OK : NYX_PO_BAD;
    }
    const uint32_t maxEpoch = MaxEpoch(held);
    if (kr.epoch > maxEpoch)
        return kr.seq == 1 && kr.epoch - maxEpoch <= NYX_KR_MAX_SEQ_JUMP ? NYX_PO_OK : NYX_PO_BAD;

    uint32_t lo = 0xffffffff, hi = 0;
    const NyxKeyring* pred = NULL;
    for (size_t i = 0; i < held.keyrings.size(); ++i)
    {
        const NyxKeyring& k = held.keyrings[i];
        if (k.epoch != kr.epoch)
            continue;
        lo = std::min(lo, k.seq);
        hi = std::max(hi, k.seq);
        if (HashEq(held.keyringHashes[i], hash))
            return NYX_PO_OK;
        if (HashEq(held.keyringHashes[i], kr.prevHash))
            pred = &k;
    }
    if (!pred)
    {
        if (hi == 0)
            return kr.epoch < maxEpoch ? NYX_PO_BAD : (kr.seq == 1 ? NYX_PO_OK : NYX_PO_UNVERIFIED);
        if (kr.epoch < maxEpoch || kr.seq <= lo || kr.seq > hi + NYX_KR_MAX_SEQ_JUMP)
            return NYX_PO_BAD;
        if (kr.seq == 1)
            return NYX_PO_OK;   // same-epoch seq=1 fork; contacts resolve it
        return NYX_PO_UNVERIFIED;
    }
    if (kr.seq <= pred->seq || kr.seq > pred->seq + NYX_KR_MAX_SEQ_JUMP)
        return NYX_PO_BAD;
    if (pred->mode == NYX_MODE_PQ && kr.mode != NYX_MODE_PQ)
        return NYX_PO_BAD;
    if (kr.mode != NYX_MODE_PQ)
        return NYX_PO_OK;
    if (!pred->IsLive(kr.signerId))
        return NYX_PO_BAD;
    const NyxCert* pc = RelaySignerCert(held, *pred, kr.signerId, &kr);
    if (!pc)
        return NYX_PO_UNVERIFIED;
    return NyxKeyringSignerValid(kr, pc->dsaPk) ? NYX_PO_OK : NYX_PO_BAD;
}

static int RelayCert(const NyxRelayHeld& held, const NyxCert& c, const uint8_t hash[32])
{
    if (!NyxCertAddrValid(c))
        return NYX_PO_BAD;
    const std::string id = NyxId(c.deviceId);
    if (held.revoked.count(id))
        return NYX_PO_BAD;
    const uint32_t maxEpoch = MaxEpoch(held);
    bool fPq = false;
    for (size_t i = 0; i < held.keyrings.size(); ++i)
    {
        const NyxKeyring& k = held.keyrings[i];
        if (k.epoch != maxEpoch)
            continue;
        if (k.mode == NYX_MODE_PQ)
            fPq = true;
        const NyxKeyringEntry* e = k.Find(c.deviceId);
        if (e && memcmp(e->certHash, hash, 32) == 0 && !c.HasSigner())
            return NYX_PO_OK;
    }
    if (!c.HasSigner())
        return fPq ? NYX_PO_UNVERIFIED : NYX_PO_OK;
    if (c.mode != NYX_MODE_PQ)
        return NYX_PO_OK;
    std::map<std::string, NyxCert>::const_iterator it = held.certs.find(NyxId(c.signerId));
    if (it == held.certs.end() || it->second.mode != NYX_MODE_PQ)
        return NYX_PO_UNVERIFIED;
    if (!NyxCertSignerValid(c, it->second.dsaPk))
        return NYX_PO_BAD;
    if (held.keyrings.empty())
        return NYX_PO_OK;
    for (size_t i = 0; i < held.keyrings.size(); ++i)
        if (held.keyrings[i].epoch == maxEpoch && held.keyrings[i].IsLive(c.signerId))
            return NYX_PO_OK;
    return NYX_PO_UNVERIFIED;
}

static int RelayBundle(const NyxRelayHeld& held, const NyxBundle& b)
{
    const std::string id = NyxId(b.deviceId);
    if (held.revoked.count(id))
        return NYX_PO_BAD;
    std::map<std::string, NyxCert>::const_iterator it = held.certs.find(id);
    if (it == held.certs.end())
        return NYX_PO_UNVERIFIED;
    return NyxBundleValid(b, it->second) ? NYX_PO_OK : NYX_PO_BAD;
}

int NyxRelayVerify(const NyxRelayHeld& held, const NyxBytes& body)
{
    if (body.empty())
        return NYX_PO_BAD;
    uint8_t h[32];
    NyxHash(body, h);
    switch (body[0])
    {
    case NYX_PO_KEYRING:
    {
        NyxKeyring k;
        return NyxParseKeyring(&body[0], body.size(), k) == 0 ? RelayKeyring(held, k, h) : NYX_PO_BAD;
    }
    case NYX_PO_CERT:
    {
        NyxCert c;
        return NyxParseCert(&body[0], body.size(), c) == 0 ? RelayCert(held, c, h) : NYX_PO_BAD;
    }
    case NYX_PO_BUNDLE:
    {
        NyxBundle b;
        return NyxParseBundle(&body[0], body.size(), b) == 0 ? RelayBundle(held, b) : NYX_PO_BAD;
    }
    }
    return NYX_PO_BAD;
}

// ---------------------------------------------------------------- serialization helpers

static void WrStr(std::string& s, const std::string& v)
{
    const uint32_t n = v.size();
    s.append((const char*)&n, 4);
    s.append(v);
}

static void WrBytes(std::string& s, const NyxBytes& v)
{
    WrStr(s, std::string(v.begin(), v.end()));
}

static void WrRaw(std::string& s, const void* p, size_t n)
{
    WrStr(s, std::string((const char*)p, n));
}

struct NyxReader
{
    const std::string& s;
    size_t off;
    bool fOk;
    explicit NyxReader(const std::string& s) : s(s), off(0), fOk(true) {}
    std::string Str()
    {
        uint32_t n = 0;
        if (!fOk || s.size() - off < 4)
        {
            fOk = false;
            return std::string();
        }
        memcpy(&n, s.data() + off, 4);
        off += 4;
        if (s.size() - off < n)
        {
            fOk = false;
            return std::string();
        }
        std::string r = s.substr(off, n);
        off += n;
        return r;
    }
    NyxBytes Bytes()
    {
        const std::string r = Str();
        return NyxBytes(r.begin(), r.end());
    }
    void Raw(void* p, size_t n)
    {
        const std::string r = Str();
        if (r.size() != n)
        {
            fOk = false;
            return;
        }
        memcpy(p, r.data(), n);
    }
};

// ---------------------------------------------------------------- contact pin

NyxPin::NyxPin() : fPinned(false), fPqSeen(false), fFrozen(false), fResetPending(false)
{
    memset(addrHash, 0, sizeof(addrHash));
    memset(krHash, 0, sizeof(krHash));
}

static void WrDevices(std::string& s, const NyxDeviceMap& m)
{
    WrStr(s, std::string(1, (char)m.size()));
    for (NyxDeviceMap::const_iterator it = m.begin(); it != m.end(); ++it)
        WrBytes(s, it->second.body);
}

static bool RdDevices(NyxReader& r, NyxDeviceMap& m)
{
    m.clear();
    const std::string n = r.Str();
    if (n.size() != 1)
        return false;
    for (unsigned int i = 0; i < (unsigned char)n[0]; ++i)
    {
        NyxPinDevice d;
        d.body = r.Bytes();
        if (!r.fOk || d.body.empty() || NyxParseCert(&d.body[0], d.body.size(), d.cert) != 0)
            return false;
        NyxHash(d.body, d.certHash);
        m[NyxId(d.cert.deviceId)] = d;
    }
    return true;
}

static void WrSet(std::string& s, const std::set<std::string>& v)
{
    std::string all;
    for (std::set<std::string>::const_iterator it = v.begin(); it != v.end(); ++it)
        all += *it;
    WrStr(s, all);
}

static bool RdSet(NyxReader& r, std::set<std::string>& v)
{
    v.clear();
    const std::string all = r.Str();
    if (all.size() % 16)
        return false;
    for (size_t i = 0; i < all.size(); i += 16)
        v.insert(all.substr(i, 16));
    return true;
}

std::string NyxPin::Serialize() const
{
    std::string s;
    WrStr(s, std::string(1, (char)1));
    WrRaw(s, addrHash, 20);
    WrStr(s, std::string(1, (char)((fPinned ? 1 : 0) | (fPqSeen ? 2 : 0) | (fFrozen ? 4 : 0) | (fResetPending ? 8 : 0))));
    WrBytes(s, krBody);
    WrDevices(s, devices);
    WrDevices(s, prevDevices);
    WrSet(s, revoked);
    WrSet(s, prevRevoked);
    WrBytes(s, conflictBody);
    WrDevices(s, conflictDevices);
    WrBytes(s, resetBody);
    WrStr(s, std::string(1, (char)resetCerts.size()));
    for (size_t i = 0; i < resetCerts.size(); ++i)
        WrBytes(s, resetCerts[i]);
    return s;
}

bool NyxPin::Deserialize(const std::string& s)
{
    *this = NyxPin();
    NyxReader r(s);
    if (r.Str() != std::string(1, (char)1))
        return false;
    r.Raw(addrHash, 20);
    const std::string f = r.Str();
    if (f.size() != 1)
        return false;
    fPinned = f[0] & 1;
    fPqSeen = f[0] & 2;
    fFrozen = f[0] & 4;
    fResetPending = f[0] & 8;
    krBody = r.Bytes();
    if (!RdDevices(r, devices) || !RdDevices(r, prevDevices) || !RdSet(r, revoked) || !RdSet(r, prevRevoked))
        return false;
    conflictBody = r.Bytes();
    if (!RdDevices(r, conflictDevices))
        return false;
    resetBody = r.Bytes();
    const std::string n = r.Str();
    if (n.size() != 1)
        return false;
    for (unsigned int i = 0; i < (unsigned char)n[0]; ++i)
        resetCerts.push_back(r.Bytes());
    if (!r.fOk)
        return false;
    if (fPinned)
    {
        if (krBody.empty() || NyxParseKeyring(&krBody[0], krBody.size(), kr) != 0)
            return false;
        NyxHash(krBody, krHash);
    }
    return true;
}

struct ParsedKeyring
{
    NyxKeyring kr;
    NyxBytes body;
    uint8_t hash[32];
};

static bool KrLess(const ParsedKeyring& a, const ParsedKeyring& b)
{
    if (a.kr.epoch != b.kr.epoch)
        return a.kr.epoch < b.kr.epoch;
    if (a.kr.seq != b.kr.seq)
        return a.kr.seq < b.kr.seq;
    return memcmp(a.hash, b.hash, 32) < 0;
}

// Finds a cert body with this hash, parsed and address-signed for the address.
static bool FindCert(const NyxPinInput& in, const uint8_t addrHash[20], const uint8_t id[16], const uint8_t hash[32],
                     NyxPinDevice& out)
{
    for (size_t i = 0; i < in.certs.size(); ++i)
    {
        const NyxBytes& b = in.certs[i];
        uint8_t h[32];
        NyxHash(b, h);
        if (memcmp(h, hash, 32) != 0 || b.empty())
            continue;
        NyxCert c;
        if (NyxParseCert(&b[0], b.size(), c) != 0 || memcmp(c.addrHash, addrHash, 20) != 0
            || memcmp(c.deviceId, id, 16) != 0 || !NyxCertAddrValid(c))
            return false;
        out.cert = c;
        out.body = b;
        memcpy(out.certHash, h, 32);
        return true;
    }
    return false;
}

// Builds the device set of kr from the previous trusted set; flags explain any refusal.
static bool StepDevices(const NyxPinInput& in, const NyxKeyring& kr, const NyxDeviceMap& prev,
                        const std::set<std::string>& revoked, bool fPq, uint32_t prevSeq, bool fFirst,
                        int64_t now, NyxDeviceMap& out, int& flags)
{
    out.clear();
    for (size_t i = 0; i < kr.live.size(); ++i)
    {
        const NyxKeyringEntry& e = kr.live[i];
        const std::string id = NyxId(e.deviceId);
        if (revoked.count(id))
        {
            flags |= NYX_PIN_REVOKED;
            return false;
        }
        NyxDeviceMap::const_iterator itPrev = prev.find(id);
        if (itPrev != prev.end() && memcmp(itPrev->second.certHash, e.certHash, 32) == 0)
        {
            out[id] = itPrev->second;
            continue;
        }
        NyxPinDevice d;
        if (!FindCert(in, kr.addrHash, e.deviceId, e.certHash, d))
        {
            flags |= NYX_PIN_INCOMPLETE;
            return false;
        }
        if (d.cert.mode != kr.mode || d.cert.expiry <= (uint64_t)now
            || d.cert.expiry - d.cert.created > (uint64_t)NYX_CERT_LIFE)
        {
            flags |= NYX_PIN_FORGERY;
            return false;
        }
        if (!fFirst && d.cert.keyringSeq > prevSeq + NYX_KR_MAX_SEQ_JUMP)
        {
            flags |= NYX_PIN_SEQ_JUMP;
            return false;
        }
        if (fFirst)
        {
            out[id] = d;
            continue;
        }
        if (!d.cert.HasSigner())
        {
            if (fPq)
            {
                // Address key alone cannot add or renew a device once ML-DSA keys are pinned.
                flags |= NYX_PIN_FORGERY;
                return false;
            }
            out[id] = d;
            continue;
        }
        if (fPq)
        {
            NyxDeviceMap::const_iterator itS = prev.find(NyxId(d.cert.signerId));
            if (itS == prev.end() || itS->second.cert.expiry <= (uint64_t)now
                || !NyxCertSignerValid(d.cert, itS->second.cert.dsaPk))
            {
                flags |= NYX_PIN_FORGERY;
                return false;
            }
        }
        out[id] = d;
    }
    return true;
}

// Signer checks for a first pin: every co-signed cert chains to a cert in the same set.
static bool FirstPinSigners(const NyxKeyring& kr, const NyxDeviceMap& devs, const NyxPinInput& in)
{
    if (kr.mode != NYX_MODE_PQ)
        return true;
    std::map<std::string, NyxBytes> pks;
    for (NyxDeviceMap::const_iterator it = devs.begin(); it != devs.end(); ++it)
        pks[it->first] = it->second.cert.dsaPk;
    for (size_t i = 0; i < in.certs.size(); ++i)
    {
        NyxCert c;
        const NyxBytes& b = in.certs[i];
        if (!b.empty() && NyxParseCert(&b[0], b.size(), c) == 0 && memcmp(c.addrHash, kr.addrHash, 20) == 0
            && c.mode == NYX_MODE_PQ && !pks.count(NyxId(c.deviceId)) && NyxCertAddrValid(c))
            pks[NyxId(c.deviceId)] = c.dsaPk;
    }
    if (kr.seq > 1)
    {
        std::map<std::string, NyxBytes>::const_iterator it = pks.find(NyxId(kr.signerId));
        if (it == pks.end() || !NyxKeyringSignerValid(kr, it->second))
            return false;
    }
    for (NyxDeviceMap::const_iterator it = devs.begin(); it != devs.end(); ++it)
    {
        const NyxCert& c = it->second.cert;
        if (!c.HasSigner())
            continue;
        std::map<std::string, NyxBytes>::const_iterator s = pks.find(NyxId(c.signerId));
        if (s == pks.end() || !NyxCertSignerValid(c, s->second))
            return false;
    }
    return true;
}

static void Adopt(NyxPin& pin, const ParsedKeyring& p, const NyxDeviceMap& devs, bool fNewEpoch)
{
    if (fNewEpoch)
    {
        pin.prevDevices.clear();
        pin.prevRevoked.clear();
        pin.revoked.clear();
    }
    else
    {
        pin.prevDevices = pin.devices;
        pin.prevRevoked = pin.revoked;
    }
    for (size_t i = 0; i < p.kr.revoked.size(); ++i)
        pin.revoked.insert(p.kr.revoked[i]);
    pin.kr = p.kr;
    pin.krBody = p.body;
    memcpy(pin.krHash, p.hash, 32);
    pin.devices = devs;
    pin.fPinned = true;
    if (p.kr.mode == NYX_MODE_PQ)
        pin.fPqSeen = true;
}

// One step from the pinned keyring (or its frozen sibling) to a successor.
static bool TryStep(const NyxPin& pin, const NyxPinInput& in, const ParsedKeyring& p, const NyxDeviceMap& prev,
                    const std::set<std::string>& revoked, uint32_t prevSeq, int64_t now, NyxDeviceMap& devs, int& flags)
{
    if (pin.fPqSeen && p.kr.mode != NYX_MODE_PQ)
    {
        flags |= NYX_PIN_DOWNGRADE;
        return false;
    }
    if (p.kr.mode == NYX_MODE_PQ)
    {
        NyxDeviceMap::const_iterator itS = prev.find(NyxId(p.kr.signerId));
        if (itS == prev.end() || itS->second.cert.mode != NYX_MODE_PQ || itS->second.cert.expiry <= (uint64_t)now
            || !NyxKeyringSignerValid(p.kr, itS->second.cert.dsaPk))
        {
            flags |= NYX_PIN_FORGERY;
            return false;
        }
    }
    std::set<std::string> rev = revoked;
    for (size_t i = 0; i < p.kr.revoked.size(); ++i)
        rev.insert(p.kr.revoked[i]);
    return StepDevices(in, p.kr, prev, rev, pin.fPqSeen || p.kr.mode == NYX_MODE_PQ, prevSeq, false, now, devs, flags);
}

// Makes the frozen sibling the pinned keyring; its revocations stack on the shared predecessor's.
static void SwitchToConflict(NyxPin& pin)
{
    ParsedKeyring c;
    c.body = pin.conflictBody;
    if (c.body.empty() || NyxParseKeyring(&c.body[0], c.body.size(), c.kr) != 0)
        return;
    NyxHash(c.body, c.hash);
    std::set<std::string> rev = pin.prevRevoked;
    rev.insert(c.kr.revoked.begin(), c.kr.revoked.end());
    const NyxBytes oldBody = pin.krBody;
    const NyxDeviceMap oldDevs = pin.devices;
    pin.kr = c.kr;
    pin.krBody = c.body;
    memcpy(pin.krHash, c.hash, 32);
    pin.devices = pin.conflictDevices;
    pin.revoked = rev;
    pin.conflictBody = oldBody;
    pin.conflictDevices = oldDevs;
}

int NyxPinApply(NyxPin& pin, const NyxPinInput& in, int64_t now)
{
    int flags = 0;
    std::vector<ParsedKeyring> v;
    for (size_t i = 0; i < in.keyrings.size(); ++i)
    {
        ParsedKeyring p;
        p.body = in.keyrings[i];
        if (p.body.empty() || NyxParseKeyring(&p.body[0], p.body.size(), p.kr) != 0
            || memcmp(p.kr.addrHash, pin.addrHash, 20) != 0 || !NyxKeyringAddrValid(p.kr))
            continue;
        NyxHash(p.body, p.hash);
        bool fDup = false;
        for (size_t j = 0; j < v.size(); ++j)
            fDup |= memcmp(v[j].hash, p.hash, 32) == 0;
        if (!fDup)
            v.push_back(p);
    }
    std::sort(v.begin(), v.end(), KrLess);
    if (v.empty())
        return NYX_PIN_INCOMPLETE;

    if (!pin.fPinned)
    {
        const ParsedKeyring& top = v.back();
        size_t nTop = 0;
        for (size_t i = 0; i < v.size(); ++i)
            nTop += v[i].kr.epoch == top.kr.epoch && v[i].kr.seq == top.kr.seq;
        if (nTop > 1)
            return NYX_PIN_FROZEN | NYX_PIN_INCOMPLETE;
        if (top.kr.ts + NYX_FIRST_PIN_MAX_AGE < (uint64_t)now)
            return NYX_PIN_STALE;
        NyxDeviceMap devs;
        std::set<std::string> rev(top.kr.revoked.begin(), top.kr.revoked.end());
        if (!StepDevices(in, top.kr, NyxDeviceMap(), rev, top.kr.mode == NYX_MODE_PQ, 0, true, now, devs, flags))
            return flags;
        if (!FirstPinSigners(top.kr, devs, in))
            return flags | NYX_PIN_FORGERY;
        Adopt(pin, top, devs, true);
        return flags | NYX_PIN_PINNED | NYX_PIN_UPDATED;
    }

    // Everything served is older than the pin: a stale or withheld view.
    const ParsedKeyring& newest = v.back();
    if (newest.kr.epoch < pin.kr.epoch || (newest.kr.epoch == pin.kr.epoch && newest.kr.seq < pin.kr.seq))
        flags |= NYX_PIN_ROLLBACK;

    bool fProgress = true;
    while (fProgress)
    {
        fProgress = false;
        // Same-seq sibling of the pinned keyring: freeze.
        if (!pin.fFrozen)
        {
            for (size_t i = 0; i < v.size(); ++i)
            {
                const ParsedKeyring& p = v[i];
                if (p.kr.epoch != pin.kr.epoch || p.kr.seq != pin.kr.seq || memcmp(p.hash, pin.krHash, 32) == 0)
                    continue;
                NyxDeviceMap devs;
                int f = 0;
                bool fValid;
                if (p.kr.seq == 1)
                    fValid = memcmp(p.kr.prevHash, pin.kr.prevHash, 32) == 0
                          && StepDevices(in, p.kr, NyxDeviceMap(), std::set<std::string>(), p.kr.mode == NYX_MODE_PQ,
                                         0, true, now, devs, f);
                else
                    fValid = memcmp(p.kr.prevHash, pin.kr.prevHash, 32) == 0
                          && TryStep(pin, in, p, pin.prevDevices, pin.prevRevoked, pin.kr.seq - 1, now, devs, f);
                if (fValid)
                {
                    pin.fFrozen = true;
                    pin.conflictBody = p.body;
                    pin.conflictDevices = devs;
                    flags |= NYX_PIN_FROZEN;
                    break;
                }
            }
        }

        std::vector<size_t> vNext;
        for (size_t i = 0; i < v.size(); ++i)
        {
            const ParsedKeyring& p = v[i];
            if (p.kr.epoch != pin.kr.epoch || p.kr.seq <= pin.kr.seq)
                continue;
            if (p.kr.seq > pin.kr.seq + NYX_KR_MAX_SEQ_JUMP)
            {
                flags |= NYX_PIN_SEQ_JUMP;
                continue;
            }
            uint8_t conflictHash[32];
            if (pin.fFrozen)
                NyxHash(pin.conflictBody, conflictHash);
            if (memcmp(p.kr.prevHash, pin.krHash, 32) == 0
                || (pin.fFrozen && memcmp(p.kr.prevHash, conflictHash, 32) == 0))
                vNext.push_back(i);
        }

        // Successors that validate; two of them fork the chain.
        std::vector<std::pair<size_t, NyxDeviceMap> > vOk, vSide;
        for (size_t j = 0; j < vNext.size(); ++j)
        {
            const ParsedKeyring& p = v[vNext[j]];
            const bool fFromConflict = memcmp(p.kr.prevHash, pin.krHash, 32) != 0;
            NyxDeviceMap devs;
            if (fFromConflict)
            {
                // A seq 1 sibling is address-signed only: it freezes, never becomes a base.
                NyxPin side = pin;
                SwitchToConflict(side);
                if (side.kr.seq > 1 && TryStep(side, in, p, side.devices, side.revoked, side.kr.seq, now, devs, flags))
                    vSide.push_back(std::make_pair(vNext[j], devs));
                continue;
            }
            if (TryStep(pin, in, p, pin.devices, pin.revoked, pin.kr.seq, now, devs, flags))
                vOk.push_back(std::make_pair(vNext[j], devs));
        }
        if (!vSide.empty())
        {
            // Both sides advanced: stay frozen.
            if (!vOk.empty())
                break;
            // The owner confirmed the other side of the fork: continue from it.
            SwitchToConflict(pin);
            vOk.swap(vSide);
            vOk.resize(1);
        }
        if (vOk.size() > 1 && !pin.fFrozen)
        {
            // Two different continuations of the pinned keyring.
            if (v[vOk[0].first].kr.seq == v[vOk[1].first].kr.seq)
            {
                pin.fFrozen = true;
                pin.conflictBody = v[vOk[1].first].body;
                pin.conflictDevices = vOk[1].second;
                flags |= NYX_PIN_FROZEN;
            }
            Adopt(pin, v[vOk[0].first], vOk[0].second, false);
            if (pin.fFrozen)
                flags |= NYX_PIN_FROZEN;
            flags |= NYX_PIN_UPDATED;
            fProgress = !pin.fFrozen;
            continue;
        }
        if (!vOk.empty())
        {
            const bool fWasFrozen = pin.fFrozen;
            Adopt(pin, v[vOk[0].first], vOk[0].second, false);
            if (fWasFrozen)
            {
                pin.fFrozen = false;
                pin.conflictBody.clear();
                pin.conflictDevices.clear();
                flags |= NYX_PIN_UNFROZEN;
            }
            flags |= NYX_PIN_UPDATED;
            fProgress = true;
        }
    }
    if (pin.fFrozen)
        flags |= NYX_PIN_FROZEN;

    // Identity reset: a later epoch at seq 1, address-signed only.
    const ParsedKeyring& top = v.back();
    if (top.kr.epoch > pin.kr.epoch && top.kr.seq == 1 && top.kr.ts + NYX_FIRST_PIN_MAX_AGE >= (uint64_t)now
        && !(pin.fResetPending && top.body == pin.resetBody))
    {
        NyxDeviceMap devs;
        int f = 0;
        std::set<std::string> rev(top.kr.revoked.begin(), top.kr.revoked.end());
        if (StepDevices(in, top.kr, NyxDeviceMap(), rev, top.kr.mode == NYX_MODE_PQ, 0, true, now, devs, f)
            && FirstPinSigners(top.kr, devs, in))
        {
            pin.fResetPending = true;
            pin.resetBody = top.body;
            pin.resetCerts.clear();
            for (NyxDeviceMap::const_iterator it = devs.begin(); it != devs.end(); ++it)
                pin.resetCerts.push_back(it->second.body);
        }
        else
            flags |= f | NYX_PIN_INCOMPLETE;
    }
    if (pin.fResetPending)
        flags |= NYX_PIN_RESET;
    return flags;
}

bool NyxPinAcceptReset(NyxPin& pin, bool fAllowDowngrade, int64_t now, std::string& sError)
{
    if (!pin.fResetPending)
    {
        sError = "No identity reset is pending.";
        return false;
    }
    ParsedKeyring p;
    p.body = pin.resetBody;
    if (p.body.empty() || NyxParseKeyring(&p.body[0], p.body.size(), p.kr) != 0)
    {
        sError = "Stored reset keyring is unreadable.";
        return false;
    }
    if (pin.fPqSeen && p.kr.mode != NYX_MODE_PQ && !fAllowDowngrade)
    {
        sError = "The reset keyring is classical; accepting it is a downgrade from PQ.";
        return false;
    }
    NyxHash(p.body, p.hash);
    NyxPinInput in;
    in.certs = pin.resetCerts;
    NyxDeviceMap devs;
    int f = 0;
    if (!StepDevices(in, p.kr, NyxDeviceMap(), std::set<std::string>(), p.kr.mode == NYX_MODE_PQ, 0, true,
                     now, devs, f))
    {
        sError = "Reset keyring certs are missing or expired.";
        return false;
    }
    const bool fPq = pin.fPqSeen && p.kr.mode == NYX_MODE_PQ;
    Adopt(pin, p, devs, true);
    pin.fPqSeen = fPq || p.kr.mode == NYX_MODE_PQ;
    pin.fFrozen = false;
    pin.conflictBody.clear();
    pin.conflictDevices.clear();
    pin.fResetPending = false;
    pin.resetBody.clear();
    pin.resetCerts.clear();
    return true;
}

std::vector<std::string> NyxPinUsable(const NyxPin& pin, int64_t now)
{
    std::vector<std::string> v;
    for (NyxDeviceMap::const_iterator it = pin.devices.begin(); it != pin.devices.end(); ++it)
        if (it->second.cert.expiry > (uint64_t)now && !pin.revoked.count(it->first))
            v.push_back(it->first);
    return v;
}

bool NyxPinCanSend(const NyxPin& pin)
{
    return pin.fPinned && !pin.fFrozen && !pin.fResetPending;
}

std::string NyxPinFlagsText(int flags)
{
    static const char* names[] = {"updated", "frozen", "reset_pending", "downgrade_refused", "rollback_ignored",
                                  "seq_jump_refused", "forgery_refused", "stale", "revoked_refused", "incomplete",
                                  "unfrozen", "pinned"};
    std::string s;
    for (int i = 0; i < 12; ++i)
        if (flags & (1 << i))
            s += (s.empty() ? "" : ",") + std::string(names[i]);
    return s;
}

std::string NyxSafetyNumber(const uint8_t addrHash[20], uint32_t epoch, const NyxDeviceMap& devices)
{
    NyxBytes m((const uint8_t*)"NYX-SAFETY-v2", (const uint8_t*)"NYX-SAFETY-v2" + 13);
    m.insert(m.end(), addrHash, addrHash + 20);
    for (int i = 0; i < 4; ++i)
        m.push_back((uint8_t)(epoch >> (8 * i)));
    for (NyxDeviceMap::const_iterator it = devices.begin(); it != devices.end(); ++it)
    {
        m.insert(m.end(), it->first.begin(), it->first.end());
        m.insert(m.end(), it->second.cert.ik, it->second.cert.ik + 32);
        m.insert(m.end(), it->second.cert.dsaPk.begin(), it->second.cert.dsaPk.end());
    }
    uint8_t h[64];
    NyxHash(m, h);
    NyxBytes m2(h, h + 32);
    m2.push_back(1);
    NyxHash(m2, h + 32);
    std::string s;
    for (int g = 0; g < 12; ++g)
    {
        uint64_t x = 0;
        for (int i = 0; i < 5; ++i)
            x = (x << 8) | h[g * 5 + i];
        char buf[8];
        snprintf(buf, sizeof(buf), "%05u", (unsigned)(x % 100000));
        if (g)
            s += ' ';
        s += buf;
    }
    return s;
}

// ---------------------------------------------------------------- own device

NyxOwnDevice::NyxOwnDevice()
{
    memset(addrHash, 0, sizeof(addrHash));
    mode = NYX_MODE_PQ;
    memset(deviceId, 0, sizeof(deviceId));
    memset(installNonce, 0, sizeof(installNonce));
    memset(hostFp, 0, sizeof(hostFp));
    memset(ikSk, 0, sizeof(ikSk));
    memset(ik, 0, sizeof(ik));
    memset(dsaSeed, 0, sizeof(dsaSeed));
    memset(kemSeed, 0, sizeof(kemSeed));
    memset(spkSk, 0, sizeof(spkSk));
    memset(spk, 0, sizeof(spk));
    spkId = 0;
    bundleSeq = 0;
    fCloneAlarm = false;
}

void NyxOwnDevice::Wipe()
{
    OPENSSL_cleanse(ikSk, sizeof(ikSk));
    OPENSSL_cleanse(dsaSeed, sizeof(dsaSeed));
    OPENSSL_cleanse(kemSeed, sizeof(kemSeed));
    OPENSSL_cleanse(spkSk, sizeof(spkSk));
}

NyxOwnDevice::~NyxOwnDevice()
{
    Wipe();
}

std::string NyxOwnDevice::Serialize() const
{
    std::string s;
    s.reserve(512 + certBody.size() + lastBundle.size() + keyringBody.size() + cloneReason.size());   // no secret-bearing reallocations
    WrStr(s, std::string(1, (char)1));
    WrRaw(s, addrHash, 20);
    WrStr(s, std::string(1, (char)mode));
    WrRaw(s, deviceId, 16);
    WrRaw(s, installNonce, 16);
    WrRaw(s, hostFp, 32);
    WrRaw(s, ikSk, 32);
    WrRaw(s, dsaSeed, 32);
    WrRaw(s, kemSeed, 64);
    WrRaw(s, spkSk, 32);
    WrRaw(s, &spkId, 4);
    WrRaw(s, &bundleSeq, 4);
    WrBytes(s, certBody);
    WrBytes(s, lastBundle);
    WrBytes(s, keyringBody);
    WrStr(s, std::string(1, (char)fCloneAlarm));
    WrStr(s, cloneReason);
    return s;
}

static bool DerivePublic(NyxOwnDevice& d)
{
    static const uint8_t base[32] = {9};
    if (nyx_x25519(d.ikSk, base, d.ik) != 0 || nyx_x25519(d.spkSk, base, d.spk) != 0)
        return false;
    if (d.mode == NYX_MODE_PQ)
    {
        d.dsaPk.assign(NYX_MLDSA65_PK, 0);
        d.ek.assign(NYX_MLKEM768_EK, 0);
        return nyx_mldsa65_pk_from_seed(d.dsaSeed, &d.dsaPk[0]) == 0
            && nyx_mlkem768_ek_from_seed(d.kemSeed, &d.ek[0]) == 0;
    }
    d.dsaPk.clear();
    d.ek.clear();
    return true;
}

bool NyxOwnDevice::Deserialize(const std::string& s)
{
    NyxReader r(s);
    if (r.Str() != std::string(1, (char)1))
        return false;
    r.Raw(addrHash, 20);
    const std::string m = r.Str();
    if (m.size() != 1 || (uint8_t)m[0] > NYX_MODE_PQ)
        return false;
    mode = m[0];
    r.Raw(deviceId, 16);
    r.Raw(installNonce, 16);
    r.Raw(hostFp, 32);
    r.Raw(ikSk, 32);
    r.Raw(dsaSeed, 32);
    r.Raw(kemSeed, 64);
    r.Raw(spkSk, 32);
    r.Raw(&spkId, 4);
    r.Raw(&bundleSeq, 4);
    certBody = r.Bytes();
    lastBundle = r.Bytes();
    keyringBody = r.Bytes();
    const std::string a = r.Str();
    cloneReason = r.Str();
    if (!r.fOk || a.size() != 1)
        return false;
    fCloneAlarm = a[0] != 0;
    return DerivePublic(*this);
}

bool NyxDeviceCreate(NyxOwnDevice& dev, const uint8_t addrHash[20], uint8_t mode, const uint8_t hostFp[32])
{
    dev = NyxOwnDevice();
    memcpy(dev.addrHash, addrHash, 20);
    dev.mode = mode;
    memcpy(dev.hostFp, hostFp, 32);
    uint8_t pk[32];
    if (nyx_random(dev.deviceId, 16) != 0 || nyx_random(dev.installNonce, 16) != 0
        || nyx_x25519_keygen(dev.ikSk, pk) != 0 || nyx_x25519_keygen(dev.spkSk, pk) != 0
        || nyx_random((uint8_t*)&dev.spkId, 4) != 0)
        return false;
    if (mode == NYX_MODE_PQ)
    {
        NyxBytes tmp(NYX_MLKEM768_EK > NYX_MLDSA65_PK ? NYX_MLKEM768_EK : NYX_MLDSA65_PK);
        if (nyx_mldsa65_keygen(dev.dsaSeed, &tmp[0]) != 0 || nyx_mlkem768_keygen(dev.kemSeed, &tmp[0]) != 0)
            return false;
    }
    return !NyxIsZero(dev.deviceId, 16) && DerivePublic(dev);
}

bool NyxBuildCertFor(uint8_t mode, const uint8_t addrHash[20], const uint8_t deviceId[16], const uint8_t ik[32],
                     const NyxBytes& dsaPk, const CKey& addrKey, int64_t created, uint32_t keyringSeq,
                     const NyxOwnDevice* signer, NyxCert& out)
{
    out = NyxCert();
    out.mode = mode;
    memcpy(out.addrHash, addrHash, 20);
    memcpy(out.deviceId, deviceId, 16);
    out.created = created;
    out.expiry = created + NYX_CERT_LIFE;
    out.keyringSeq = keyringSeq;
    memcpy(out.ik, ik, 32);
    if (mode == NYX_MODE_PQ)
    {
        if (dsaPk.size() != NYX_MLDSA65_PK)
            return false;
        out.dsaPk = dsaPk;
    }
    if (signer)
        memcpy(out.signerId, signer->deviceId, 16);
    if (!NyxAddrSign(addrKey, NYX_TAG_CERT, out.Signed(), out.addrSig))
        return false;
    if (signer && mode == NYX_MODE_PQ)
    {
        if (signer->mode != NYX_MODE_PQ)
            return false;
        if (!NyxDsaSign(signer->dsaSeed, NyxCertSignerMsg(out), out.signerSig))
            return false;
    }
    return true;
}

bool NyxBuildCert(const NyxOwnDevice& dev, const CKey& addrKey, int64_t created, uint32_t keyringSeq,
                  const NyxOwnDevice* signer, NyxCert& out)
{
    return NyxBuildCertFor(dev.mode, dev.addrHash, dev.deviceId, dev.ik, dev.dsaPk, addrKey, created, keyringSeq,
                           signer, out);
}

bool NyxBuildKeyring(NyxKeyring& kr, const CKey& addrKey, const NyxOwnDevice* signer)
{
    if (kr.seq == 1)
        memset(kr.signerId, 0, 16);
    else if (!signer)
        return false;
    else
        memcpy(kr.signerId, signer->deviceId, 16);
    if (!NyxAddrSign(addrKey, NYX_TAG_KEYRING, kr.Signed(), kr.addrSig))
        return false;
    kr.signerSig.clear();
    if (kr.mode == NYX_MODE_PQ && kr.seq > 1)
    {
        if (signer->mode != NYX_MODE_PQ)
            return false;
        return NyxDsaSign(signer->dsaSeed, NyxKeyringSignerMsg(kr), kr.signerSig);
    }
    return true;
}

bool NyxBuildBundle(NyxOwnDevice& dev, const CKey& addrKey, int64_t ts, NyxBundle& out)
{
    out = NyxBundle();
    memcpy(out.addrHash, dev.addrHash, 20);
    memcpy(out.deviceId, dev.deviceId, 16);
    out.ts = ts;
    out.seq = dev.bundleSeq + 1;
    out.spkId = dev.spkId;
    memcpy(out.spk, dev.spk, 32);
    out.fPq = dev.mode == NYX_MODE_PQ;
    if (out.fPq)
    {
        out.kemId = dev.spkId;
        out.ek = dev.ek;
        if (!NyxDsaSign(dev.dsaSeed, NyxTagged(NYX_TAG_BUNDLE, out.Fields()), out.sig))
            return false;
    }
    else
    {
        out.sig.assign(65, 0);
        if (!NyxAddrSign(addrKey, NYX_TAG_BUNDLE, out.Fields(), &out.sig[0]))
            return false;
    }
    dev.bundleSeq = out.seq;
    dev.lastBundle = out.Serialize();
    return true;
}

std::string NyxCloneCheck(const NyxOwnDevice& dev, const uint8_t hostFpNow[32], const NyxBytes* pSeenBundle)
{
    if (memcmp(dev.hostFp, hostFpNow, 32) != 0)
        return "host fingerprint changed";
    if (!pSeenBundle || pSeenBundle->empty())
        return std::string();
    NyxBundle b;
    if (NyxParseBundle(&(*pSeenBundle)[0], pSeenBundle->size(), b) != 0
        || memcmp(b.deviceId, dev.deviceId, 16) != 0 || memcmp(b.addrHash, dev.addrHash, 20) != 0)
        return std::string();
    if (b.seq > dev.bundleSeq)
        return "a bundle for this device id with a higher seq was published elsewhere";
    if (b.seq == dev.bundleSeq && *pSeenBundle != dev.lastBundle)
        return "a different bundle for this device id at the same seq was published elsewhere";
    return std::string();
}

// ---------------------------------------------------------------- storage

bool NyxStoreSeal(const uint8_t sk[32], const std::string& dbkey, const std::string& plain, std::string& out)
{
    uint8_t nonce[NYX_AEAD_NONCE];
    if (nyx_random(nonce, sizeof(nonce)) != 0)
        return false;
    out.assign((const char*)nonce, sizeof(nonce));
    out.resize(sizeof(nonce) + plain.size() + NYX_AEAD_TAG);
    return nyx_aead_seal(sk, nonce, (const uint8_t*)dbkey.data(), dbkey.size(), (const uint8_t*)plain.data(),
                         plain.size(), (uint8_t*)&out[sizeof(nonce)]) == 0;
}

bool NyxStoreOpen(const uint8_t sk[32], const std::string& dbkey, const std::string& sealed, std::string& out)
{
    out.clear();
    if (sealed.size() < NYX_AEAD_NONCE + NYX_AEAD_TAG)
        return false;
    const size_t n = sealed.size() - NYX_AEAD_NONCE - NYX_AEAD_TAG;
    std::string pt(n, '\0');
    if (nyx_aead_open(sk, (const uint8_t*)sealed.data(), (const uint8_t*)dbkey.data(), dbkey.size(),
                      (const uint8_t*)sealed.data() + NYX_AEAD_NONCE, n + NYX_AEAD_TAG,
                      n ? (uint8_t*)&pt[0] : NULL) != 0)
    {
        if (n)
            OPENSSL_cleanse(&pt[0], n);
        return false;
    }
    out.swap(pt);
    return true;
}
