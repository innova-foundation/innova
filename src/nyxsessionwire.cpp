// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "nyxsession.h"

#include <string.h>

const char NYX_TAG_HS[] = "NYX-HS-v1";

static uint32_t RdLE32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
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

NyxHandshake::NyxHandshake()
    : mode(NYX_MODE_PQ), epochA(0), seqA(0), epochB(0), seqB(0), spkId(0), opkId(NYX_OPK_NONE), kemId(0), ts(0)
{
    memset(addrA, 0, sizeof(addrA));
    memset(addrB, 0, sizeof(addrB));
    memset(devB, 0, sizeof(devB));
    memset(devA, 0, sizeof(devA));
    memset(certHashA, 0, sizeof(certHashA));
    memset(certHashB, 0, sizeof(certHashB));
    memset(ikA, 0, sizeof(ikA));
    memset(ekA, 0, sizeof(ekA));
}

NyxBytes NyxHandshake::Fields() const
{
    NyxBytes v;
    v.push_back(NYX_BODY_HANDSHAKE);
    v.push_back(mode);
    Put(v, addrA, 20);
    Put(v, addrB, 20);
    Put(v, devB, 16);
    Put(v, devA, 16);
    Put(v, certHashA, 32);
    Put(v, certHashB, 32);
    Put(v, ikA, 32);
    Put(v, ekA, 32);
    Put32(v, epochA);
    Put32(v, seqA);
    Put32(v, epochB);
    Put32(v, seqB);
    Put32(v, spkId);
    Put32(v, opkId);
    Put32(v, kemId);
    if (mode == NYX_MODE_PQ)
        v.insert(v.end(), ct.begin(), ct.end());
    Put32(v, (uint32_t)ts);
    Put32(v, (uint32_t)(ts >> 32));
    return v;
}

NyxBytes NyxHandshake::Fixed() const
{
    NyxBytes v = Fields();
    v.insert(v.end(), sig.begin(), sig.end());
    return v;
}

int NyxParseHandshake(const uint8_t* p, size_t n, NyxHandshake& out)
{
    out = NyxHandshake();
    if (!p || n < 2 || p[0] != NYX_BODY_HANDSHAKE)
        return 1;
    if (p[1] > NYX_MODE_PQ)
        return 2;
    out.mode = p[1];
    const bool fPq = out.mode == NYX_MODE_PQ;
    const size_t fixed = fPq ? NYX_HS_FIXED_PQ : NYX_HS_FIXED_CLASSICAL;
    if (n < fixed + NYX_TAIL_MIN)
        return 3;
    memcpy(out.addrA, p + 2, 20);
    memcpy(out.addrB, p + 22, 20);
    memcpy(out.devB, p + 42, 16);
    memcpy(out.devA, p + 58, 16);
    memcpy(out.certHashA, p + 74, 32);
    memcpy(out.certHashB, p + 106, 32);
    memcpy(out.ikA, p + 138, 32);
    memcpy(out.ekA, p + 170, 32);
    out.epochA = RdLE32(p + 202);
    out.seqA = RdLE32(p + 206);
    out.epochB = RdLE32(p + 210);
    out.seqB = RdLE32(p + 214);
    out.spkId = RdLE32(p + 218);
    out.opkId = RdLE32(p + 222);
    out.kemId = RdLE32(p + 226);
    size_t off = 230;
    if (fPq)
    {
        out.ct.assign(p + off, p + off + 1088);
        off += 1088;
    }
    out.ts = (uint64_t)RdLE32(p + off) | ((uint64_t)RdLE32(p + off + 4) << 32);
    off += 8;
    const size_t nSig = fPq ? 3309 : 65;
    out.sig.assign(p + off, p + off + nSig);
    off += nSig;
    out.tail.assign(p + off, p + n);
    if (NyxIsZero(out.devA, 16) || NyxIsZero(out.devB, 16) || !memcmp(out.devA, out.devB, 16))
        return 4;
    if (out.epochA == 0 || out.seqA == 0 || out.epochB == 0 || out.seqB == 0)
        return 5;
    if (!fPq && out.kemId != 0)
        return 6;
    return 0;
}

int NyxParseRatchetMsg(const uint8_t* p, size_t n, NyxRatchetMsg& out)
{
    if (!p || n < 1 || p[0] != NYX_BODY_RATCHET)
        return 1;
    if (n < 33 + NYX_TAIL_MIN)
        return 3;
    memcpy(out.devB, p + 1, 16);
    memcpy(out.devA, p + 17, 16);
    out.tail.assign(p + 33, p + n);
    if (NyxIsZero(out.devA, 16) || NyxIsZero(out.devB, 16))
        return 4;
    return 0;
}

NyxEnvelope::NyxEnvelope() : ctype(0), flags(0)
{
    memset(logicalId, 0, sizeof(logicalId));
    memset(convAddr, 0, sizeof(convAddr));
    memset(groupId, 0, sizeof(groupId));
}

NyxBytes NyxEnvelope::Serialize() const
{
    NyxBytes v;
    v.reserve(NYX_ENV_LEN + text.size());
    v.push_back(ctype);
    Put(v, logicalId, 16);
    Put(v, convAddr, 20);
    Put(v, groupId, 32);
    v.push_back(flags);
    v.insert(v.end(), text.begin(), text.end());
    return v;
}

bool NyxEnvelope::Parse(const NyxBytes& v)
{
    if (v.size() < NYX_ENV_LEN)
        return false;
    ctype = v[0];
    memcpy(logicalId, &v[1], 16);
    memcpy(convAddr, &v[17], 20);
    memcpy(groupId, &v[37], 32);
    flags = v[69];
    text.assign(v.begin() + NYX_ENV_LEN, v.end());
    return true;
}
