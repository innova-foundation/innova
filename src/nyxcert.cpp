// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "nyxcert.h"
#include "nyxparts.h"
#include "nyxpo.h"

#include <string.h>

const char NYX_TAG_CERT[] = "NYX-CERT-v1";
const char NYX_TAG_KEYRING[] = "NYX-KEYRING-v2";
const char NYX_TAG_BUNDLE[] = "NYX-BUNDLE-v1";

static uint32_t RdLE32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t RdLE64(const uint8_t* p)
{
    return (uint64_t)RdLE32(p) | ((uint64_t)RdLE32(p + 4) << 32);
}

static void Put(NyxBytes& v, const uint8_t* p, size_t n)
{
    v.insert(v.end(), p, p + n);
}

static void Put32(NyxBytes& v, uint32_t x)
{
    for (int i = 0; i < 4; ++i)
        v.push_back((uint8_t)(x >> (8 * i)));
}

static void Put64(NyxBytes& v, uint64_t x)
{
    for (int i = 0; i < 8; ++i)
        v.push_back((uint8_t)(x >> (8 * i)));
}

bool NyxIsZero(const uint8_t* p, size_t n)
{
    uint8_t a = 0;
    for (size_t i = 0; i < n; ++i)
        a |= p[i];
    return a == 0;
}

std::string NyxId(const uint8_t id[16])
{
    return std::string((const char*)id, 16);
}

NyxBytes NyxTagged(const char* tag, const NyxBytes& fields)
{
    NyxBytes v((const uint8_t*)tag, (const uint8_t*)tag + strlen(tag));
    v.insert(v.end(), fields.begin(), fields.end());
    return v;
}

void NyxHash(const NyxBytes& v, uint8_t out[32])
{
    NyxSha256(v.empty() ? NULL : &v[0], v.size(), out);
}

NyxCert::NyxCert() : mode(NYX_MODE_PQ), created(0), expiry(0), keyringSeq(0)
{
    memset(addrHash, 0, sizeof(addrHash));
    memset(deviceId, 0, sizeof(deviceId));
    memset(ik, 0, sizeof(ik));
    memset(addrSig, 0, sizeof(addrSig));
    memset(signerId, 0, sizeof(signerId));
}

bool NyxCert::HasSigner() const
{
    return !NyxIsZero(signerId, 16);
}

NyxBytes NyxCert::Fields() const
{
    NyxBytes v;
    v.push_back(NYX_PO_CERT);
    v.push_back(1);
    v.push_back(mode);
    Put(v, addrHash, 20);
    Put(v, deviceId, 16);
    Put64(v, created);
    Put64(v, expiry);
    Put32(v, keyringSeq);
    Put(v, ik, 32);
    if (mode == NYX_MODE_PQ)
        v.insert(v.end(), dsaPk.begin(), dsaPk.end());
    return v;
}

NyxBytes NyxCert::Serialize() const
{
    NyxBytes v = Fields();
    Put(v, addrSig, 65);
    Put(v, signerId, 16);
    if (mode == NYX_MODE_PQ && HasSigner())
        v.insert(v.end(), signerSig.begin(), signerSig.end());
    return v;
}

int NyxParseCert(const uint8_t* p, size_t n, NyxCert& out)
{
    out = NyxCert();
    NyxPoInfo info;
    if (!p || n < 1 || p[0] != NYX_PO_CERT)
        return 1;
    const int r = NyxPoParse(p, n, info);
    if (r != 0)
        return r;
    out.mode = p[2];
    memcpy(out.addrHash, p + 3, 20);
    memcpy(out.deviceId, p + 23, 16);
    out.created = RdLE64(p + 39);
    out.expiry = RdLE64(p + 47);
    out.keyringSeq = RdLE32(p + 55);
    memcpy(out.ik, p + 59, 32);
    size_t off = 91;
    if (out.mode == NYX_MODE_PQ)
    {
        out.dsaPk.assign(p + off, p + off + NYX_MLDSA_PK);
        off += NYX_MLDSA_PK;
    }
    memcpy(out.addrSig, p + off, 65);
    off += 65;
    memcpy(out.signerId, p + off, 16);
    off += 16;
    if (out.mode == NYX_MODE_PQ && out.HasSigner())
        out.signerSig.assign(p + off, p + off + NYX_MLDSA_SIG);
    if (NyxIsZero(out.deviceId, 16))
        return 7;
    return 0;
}

NyxKeyring::NyxKeyring() : epoch(1), seq(1), ts(0), mode(NYX_MODE_PQ)
{
    memset(addrHash, 0, sizeof(addrHash));
    memset(prevHash, 0, sizeof(prevHash));
    memset(addrSig, 0, sizeof(addrSig));
    memset(signerId, 0, sizeof(signerId));
}

const NyxKeyringEntry* NyxKeyring::Find(const uint8_t id[16]) const
{
    for (size_t i = 0; i < live.size(); ++i)
        if (memcmp(live[i].deviceId, id, 16) == 0)
            return &live[i];
    return NULL;
}

bool NyxKeyring::IsLive(const uint8_t id[16]) const
{
    return Find(id) != NULL;
}

NyxBytes NyxKeyring::Fields() const
{
    NyxBytes v;
    v.push_back(NYX_PO_KEYRING);
    v.push_back(2);
    Put(v, addrHash, 20);
    Put32(v, epoch);
    Put32(v, seq);
    Put(v, prevHash, 32);
    Put64(v, ts);
    v.push_back(mode);
    v.push_back((uint8_t)live.size());
    for (size_t i = 0; i < live.size(); ++i)
    {
        Put(v, live[i].deviceId, 16);
        Put(v, live[i].certHash, 32);
    }
    v.push_back((uint8_t)revoked.size());
    for (size_t i = 0; i < revoked.size(); ++i)
        v.insert(v.end(), revoked[i].begin(), revoked[i].end());
    return v;
}

NyxBytes NyxKeyring::Serialize() const
{
    NyxBytes v = Fields();
    Put(v, addrSig, 65);
    Put(v, signerId, 16);
    if (mode == NYX_MODE_PQ && seq > 1)
        v.insert(v.end(), signerSig.begin(), signerSig.end());
    return v;
}

int NyxParseKeyring(const uint8_t* p, size_t n, NyxKeyring& out)
{
    out = NyxKeyring();
    NyxPoInfo info;
    if (!p || n < 1 || p[0] != NYX_PO_KEYRING)
        return 1;
    const int r = NyxPoParse(p, n, info);
    if (r != 0)
        return r;
    memcpy(out.addrHash, p + 2, 20);
    out.epoch = RdLE32(p + 22);
    out.seq = RdLE32(p + 26);
    memcpy(out.prevHash, p + 30, 32);
    out.ts = RdLE64(p + 62);
    out.mode = p[70];
    const unsigned int nLive = p[71];
    size_t off = 72;
    for (unsigned int i = 0; i < nLive; ++i, off += 48)
    {
        NyxKeyringEntry e;
        memcpy(e.deviceId, p + off, 16);
        memcpy(e.certHash, p + off + 16, 32);
        if (NyxIsZero(e.deviceId, 16) || out.IsLive(e.deviceId))
            return 8;
        out.live.push_back(e);
    }
    const unsigned int nRev = p[off++];
    for (unsigned int i = 0; i < nRev; ++i, off += 16)
    {
        const std::string id((const char*)p + off, 16);
        if (out.IsLive(p + off))
            return 9;
        out.revoked.push_back(id);
    }
    memcpy(out.addrSig, p + off, 65);
    off += 65;
    memcpy(out.signerId, p + off, 16);
    off += 16;
    if (out.mode == NYX_MODE_PQ && out.seq > 1)
        out.signerSig.assign(p + off, p + off + NYX_MLDSA_SIG);
    if (out.seq == 1 && out.epoch == 1 && !NyxIsZero(out.prevHash, 32))
        return 10;
    return 0;
}

NyxBundle::NyxBundle() : ts(0), seq(0), spkId(0), fPq(true), kemId(0)
{
    memset(addrHash, 0, sizeof(addrHash));
    memset(deviceId, 0, sizeof(deviceId));
    memset(spk, 0, sizeof(spk));
}

NyxBytes NyxBundle::Fields() const
{
    NyxBytes v;
    v.push_back(NYX_PO_BUNDLE);
    Put(v, addrHash, 20);
    Put(v, deviceId, 16);
    Put64(v, ts);
    Put32(v, seq);
    Put32(v, spkId);
    Put(v, spk, 32);
    if (fPq)
    {
        Put32(v, kemId);
        v.insert(v.end(), ek.begin(), ek.end());
    }
    v.push_back((uint8_t)opks.size());
    for (size_t i = 0; i < opks.size(); ++i)
    {
        Put32(v, opks[i].first);
        v.insert(v.end(), opks[i].second.begin(), opks[i].second.end());
    }
    return v;
}

NyxBytes NyxBundle::Serialize() const
{
    NyxBytes v = Fields();
    v.insert(v.end(), sig.begin(), sig.end());
    return v;
}

int NyxParseBundle(const uint8_t* p, size_t n, NyxBundle& out)
{
    out = NyxBundle();
    NyxPoInfo info;
    if (!p || n < 1 || p[0] != NYX_PO_BUNDLE)
        return 1;
    const int r = NyxPoParse(p, n, info);
    if (r != 0)
        return r;
    memcpy(out.addrHash, p + 1, 20);
    memcpy(out.deviceId, p + 21, 16);
    out.ts = RdLE64(p + 37);
    out.seq = RdLE32(p + 45);
    out.spkId = RdLE32(p + 49);
    memcpy(out.spk, p + 53, 32);
    size_t off = 85;
    out.fPq = n >= off + 4 + NYX_MLKEM_EK + 1 + NYX_MLDSA_SIG;
    if (out.fPq)
    {
        out.kemId = RdLE32(p + off);
        out.ek.assign(p + off + 4, p + off + 4 + NYX_MLKEM_EK);
        off += 4 + NYX_MLKEM_EK;
    }
    const unsigned int nOpk = p[off++];
    for (unsigned int i = 0; i < nOpk; ++i, off += 36)
        out.opks.push_back(std::make_pair(RdLE32(p + off), NyxBytes(p + off + 4, p + off + 36)));
    out.sig.assign(p + off, p + n);
    if (NyxIsZero(out.deviceId, 16))
        return 7;
    return 0;
}
