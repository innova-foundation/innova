// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "nyxparts.h"

#include <openssl/sha.h>

#include <string.h>

void NyxSha256(const uint8_t* p, size_t n, uint8_t out[32])
{
    static const uint8_t empty = 0;
    SHA256(n ? p : &empty, n, out);
}

static void PutLE32(uint8_t* p, uint32_t v)
{
    p[0] = v & 0xff; p[1] = (v >> 8) & 0xff; p[2] = (v >> 16) & 0xff; p[3] = (v >> 24) & 0xff;
}

static uint32_t GetLE32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

const char NYX_MESSAGE_AUTH_TAG_BASE_DOMAIN[] = "Innova/Nyx/MessageAuth/TagBase/v1";

void NyxMessageAuthTagBase(uint64_t epoch, uint8_t out[32])
{
    // Opaque PQ base; never reuse the IV5 vote's curve base.
    std::vector<uint8_t> input(NYX_MESSAGE_AUTH_TAG_BASE_DOMAIN,
        NYX_MESSAGE_AUTH_TAG_BASE_DOMAIN + sizeof(NYX_MESSAGE_AUTH_TAG_BASE_DOMAIN) - 1);
    for (int i = 0; i < 8; ++i)
        input.push_back((uint8_t)(epoch >> (8 * i)));
    NyxSha256(&input[0], input.size(), out);
}

const NyxSenderAuthProofType* NyxFindSenderAuthProofType(uint16_t)
{
    return NULL;
}

bool NyxVerifySenderAuth(const NyxSenderAuth& auth, const NyxSenderAuthContext& context,
                         const NyxSenderAuthPolicy& policy)
{
    if (auth.version != NYX_SENDER_AUTH_VERSION || auth.proof.empty()
        || auth.proof.size() > NYX_SENDER_AUTH_MAX || policy.minNoteValue < 0
        || !policy.perEpochLimit || context.useIndex >= policy.perEpochLimit)
        return false;
    const NyxSenderAuthProofType* type = NyxFindSenderAuthProofType(auth.proofType);
    return type && type->postQuantum && type->provesUnspent && type->verify
        && type->verify(auth, context, policy);
}

bool NyxWrapSenderAuth(const std::vector<uint8_t>& body, const NyxSenderAuth& auth,
                       std::vector<uint8_t>& out)
{
    if (body.empty() || body[0] == NYX_BODY_SENDER_AUTH || auth.proof.size() > NYX_SENDER_AUTH_MAX
        || body.size() > NYX_MAX_BODY - 8 - auth.proof.size())
    {
        out.clear();
        return false;
    }
    std::vector<uint8_t> v(8);
    v[0] = NYX_BODY_SENDER_AUTH;
    v[1] = auth.version;
    v[2] = (uint8_t)auth.proofType;
    v[3] = (uint8_t)(auth.proofType >> 8);
    PutLE32(&v[4], (uint32_t)auth.proof.size());
    v.insert(v.end(), auth.proof.begin(), auth.proof.end());
    v.insert(v.end(), body.begin(), body.end());
    out.swap(v);
    return true;
}

bool NyxUnwrapSenderAuth(std::vector<uint8_t>& body, NyxSenderAuth& auth)
{
    auth = NyxSenderAuth();
    if (body.empty())
        return false;
    if (body[0] != NYX_BODY_SENDER_AUTH)
        return true;
    if (body.size() < 9)
        return false;
    const uint32_t n = GetLE32(&body[4]);
    if (n > NYX_SENDER_AUTH_MAX || n >= body.size() - 8
        || body[8 + n] == NYX_BODY_SENDER_AUTH)
        return false;
    auth.version = body[1];
    auth.proofType = (uint16_t)body[2] | ((uint16_t)body[3] << 8);
    auth.proof.assign(body.begin() + 8, body.begin() + 8 + n);
    body.erase(body.begin(), body.begin() + 8 + n);
    return true;
}

uint32_t NyxPartLen(uint32_t totalLen, uint8_t count, uint8_t idx)
{
    if (count == 0 || idx >= count)
        return 0;
    if (idx + 1 < count)
        return NYX_PART_BODY_MAX;
    return totalLen - (uint32_t)(count - 1) * NYX_PART_BODY_MAX;
}

bool NyxSplit(const std::vector<uint8_t>& body, std::vector<std::vector<uint8_t> >& frames, const uint8_t msgid[16],
              unsigned int nMaxParts)
{
    frames.clear();
    if (body.empty() || body.size() > NYX_MAX_BODY)
        return false;
    const uint32_t totalLen = (uint32_t)body.size();
    const uint32_t nCount = (totalLen + NYX_PART_BODY_MAX - 1) / NYX_PART_BODY_MAX;
    if (nCount > nMaxParts || nCount > NYX_MAX_PARTS)
        return false;

    uint8_t hash[32];
    NyxSha256(&body[0], body.size(), hash);

    frames.resize(nCount);
    for (uint32_t i = 0; i < nCount; ++i)
    {
        const uint32_t nLen = NyxPartLen(totalLen, (uint8_t)nCount, (uint8_t)i);
        std::vector<uint8_t>& f = frames[i];
        f.resize(NYX_FRAME_PREFIX + nLen);
        f[0] = NYX_V2TYPE_PART;
        memcpy(&f[1], msgid, 16);
        f[17] = (uint8_t)i;
        f[18] = (uint8_t)nCount;
        PutLE32(&f[19], totalLen);
        memcpy(&f[23], hash, 32);
        memcpy(&f[NYX_FRAME_PREFIX], &body[(size_t)i * NYX_PART_BODY_MAX], nLen);
    }
    return true;
}

int NyxParseFrame(const uint8_t* p, size_t n, NyxFrame& out)
{
    if (!p || n < NYX_FRAME_PREFIX + 1)
        return NYX_FRAME_SHORT;
    if (p[0] != NYX_V2TYPE_PART)
        return NYX_FRAME_TYPE;
    const uint8_t idx = p[17], count = p[18];
    if (count == 0 || count > NYX_MAX_PARTS)
        return NYX_FRAME_COUNT;
    if (idx >= count)
        return NYX_FRAME_INDEX;
    const uint32_t totalLen = GetLE32(p + 19);
    if (totalLen == 0 || totalLen > NYX_MAX_BODY
        || totalLen <= (uint32_t)(count - 1) * NYX_PART_BODY_MAX
        || totalLen > (uint32_t)count * NYX_PART_BODY_MAX)
        return NYX_FRAME_TOTAL;
    if (n - NYX_FRAME_PREFIX != NyxPartLen(totalLen, count, idx))
        return NYX_FRAME_LENGTH;

    memcpy(out.msgid, p + 1, 16);
    out.partIdx = idx;
    out.partCount = count;
    out.totalLen = totalLen;
    memcpy(out.totalHash, p + 23, 32);
    out.pBody = p + NYX_FRAME_PREFIX;
    out.nBody = (uint32_t)(n - NYX_FRAME_PREFIX);
    return NYX_FRAME_OK;
}

NyxReassemblyLimits NyxReassemblyLimits::For(NyxPoolKind kind)
{
    NyxReassemblyLimits l;
    if (kind == NYX_POOL_PUBLIC)
    {
        l.nOwnerBytes = NYX_PUB_BUF_PEER;
        l.nNodeBytes = NYX_PUB_BUF_NODE;
        l.nOwnerSets = NYX_PUB_SETS_PEER;
        l.nTimeout = NYX_PUB_SET_TIMEOUT;
    } else
    {
        l.nOwnerBytes = NYX_PRIV_BUF_ADDR;
        l.nNodeBytes = NYX_PRIV_BUF_NODE;
        l.nOwnerSets = NYX_PRIV_SETS_ADDR;
        l.nTimeout = NYX_PRIV_SET_TIMEOUT;
    }
    return l;
}

void NyxReassembler::Drop(std::map<Key, Set>::iterator it)
{
    const std::string& owner = it->first.first;
    std::map<std::string, uint64_t>::iterator ob = ownerBytes.find(owner);
    if (ob != ownerBytes.end())
    {
        ob->second -= it->second.nBytes;
        if (ob->second == 0)
            ownerBytes.erase(ob);
    }
    std::map<std::string, uint32_t>::iterator os = ownerSets.find(owner);
    if (os != ownerSets.end() && --os->second == 0)
        ownerSets.erase(os);
    nNodeBytes -= it->second.nBytes;
    sets.erase(it);
}

bool NyxReassembler::EvictWeakest(const std::string* pOwner, const Key& keep)
{
    std::map<Key, Set>::iterator best = sets.end();
    for (std::map<Key, Set>::iterator it = sets.begin(); it != sets.end(); ++it)
    {
        if (it->first == keep || (pOwner && it->first.first != *pOwner))
            continue;
        if (best == sets.end())
        {
            best = it;
            continue;
        }
        // Least complete first, then oldest.
        const uint64_t a = (uint64_t)it->second.parts.size() * best->second.nCount;
        const uint64_t b = (uint64_t)best->second.parts.size() * it->second.nCount;
        if (a < b || (a == b && (it->second.nFirstSeen < best->second.nFirstSeen
            || (it->second.nFirstSeen == best->second.nFirstSeen && it->second.nSeq < best->second.nSeq))))
            best = it;
    }
    if (best == sets.end())
        return false;
    Drop(best);
    return true;
}

NyxAddResult NyxReassembler::Add(const std::string& owner, const NyxFrame& f, int64_t nNow,
                                 std::vector<uint8_t>& bodyOut, const std::vector<uint8_t>* pRaw,
                                 std::vector<std::vector<uint8_t> >* vRawOut, NyxSenderAuth* authOut)
{
    bodyOut.clear();
    if (authOut)
        *authOut = NyxSenderAuth();
    if (vRawOut)
        vRawOut->clear();

    const Key k(owner, std::string((const char*)f.msgid, 16));
    std::map<Key, Set>::iterator it = sets.find(k);
    if (it == sets.end())
    {
        if (limits.nOwnerSets == 0)
            return NYX_RA_REFUSED;
        while (OwnerSetCount(owner) >= limits.nOwnerSets)
            if (!EvictWeakest(&owner, k))
                return NYX_RA_REFUSED;
        Set s;
        s.nCount = f.partCount;
        s.totalLen = f.totalLen;
        memcpy(s.totalHash, f.totalHash, 32);
        s.nFirstSeen = nNow;
        s.nSeq = ++nSeq;
        s.nBytes = 0;
        it = sets.insert(std::make_pair(k, s)).first;
        ownerSets[owner]++;
    } else
    {
        const Set& s = it->second;
        if (s.nCount != f.partCount || s.totalLen != f.totalLen || memcmp(s.totalHash, f.totalHash, 32) != 0)
        {
            Drop(it);
            return NYX_RA_MISMATCH;
        }
        if (s.parts.count(f.partIdx))
            return NYX_RA_DUPLICATE;
    }

    Set& s = it->second;
    s.parts[f.partIdx].assign(f.pBody, f.pBody + f.nBody);
    uint64_t nAdd = f.nBody;
    if (pRaw)
    {
        s.raws[f.partIdx] = *pRaw;
        nAdd += pRaw->size();
    }
    s.nBytes += nAdd;
    ownerBytes[owner] += nAdd;
    nNodeBytes += nAdd;

    while (OwnerBytes(owner) > limits.nOwnerBytes)
        if (!EvictWeakest(&owner, k))
        {
            Drop(sets.find(k));
            return NYX_RA_REFUSED;
        }
    while (nNodeBytes > limits.nNodeBytes)
        if (!EvictWeakest(NULL, k))
        {
            Drop(sets.find(k));
            return NYX_RA_REFUSED;
        }

    if (s.parts.size() < s.nCount)
        return NYX_RA_STORED;

    bodyOut.reserve(s.totalLen);
    for (std::map<uint8_t, std::vector<uint8_t> >::const_iterator p = s.parts.begin(); p != s.parts.end(); ++p)
        bodyOut.insert(bodyOut.end(), p->second.begin(), p->second.end());
    uint8_t hash[32];
    NyxSha256(bodyOut.empty() ? NULL : &bodyOut[0], bodyOut.size(), hash);
    const bool fOk = bodyOut.size() == s.totalLen && memcmp(hash, s.totalHash, 32) == 0;
    if (fOk && vRawOut)
        for (std::map<uint8_t, std::vector<uint8_t> >::const_iterator r = s.raws.begin(); r != s.raws.end(); ++r)
            vRawOut->push_back(r->second);
    Drop(it);
    if (!fOk)
    {
        bodyOut.clear();
        return NYX_RA_BADHASH;
    }
    NyxSenderAuth auth;
    if (!NyxUnwrapSenderAuth(bodyOut, auth))
    {
        bodyOut.clear();
        if (vRawOut)
            vRawOut->clear();
        return NYX_RA_BADAUTH;
    }
    if (authOut)
        *authOut = auth;
    return NYX_RA_COMPLETE;
}

void NyxReassembler::Expire(int64_t nNow)
{
    for (std::map<Key, Set>::iterator it = sets.begin(); it != sets.end();)
    {
        std::map<Key, Set>::iterator cur = it++;
        if (nNow - cur->second.nFirstSeen >= limits.nTimeout)
            Drop(cur);
    }
}

void NyxReassembler::FreeOwner(const std::string& owner)
{
    for (std::map<Key, Set>::iterator it = sets.begin(); it != sets.end();)
    {
        std::map<Key, Set>::iterator cur = it++;
        if (cur->first.first == owner)
            Drop(cur);
    }
}

void NyxReassembler::Clear()
{
    sets.clear();
    ownerBytes.clear();
    ownerSets.clear();
    nNodeBytes = 0;
}

uint64_t NyxReassembler::OwnerBytes(const std::string& owner) const
{
    std::map<std::string, uint64_t>::const_iterator it = ownerBytes.find(owner);
    return it == ownerBytes.end() ? 0 : it->second;
}

size_t NyxReassembler::OwnerSetCount(const std::string& owner) const
{
    std::map<std::string, uint32_t>::const_iterator it = ownerSets.find(owner);
    return it == ownerSets.end() ? 0 : it->second;
}

void NyxReassembler::List(std::vector<NyxSetProgress>& out) const
{
    out.clear();
    for (std::map<Key, Set>::const_iterator it = sets.begin(); it != sets.end(); ++it)
    {
        NyxSetProgress p;
        p.owner = it->first.first;
        p.msgid = it->first.second;
        p.nHave = (unsigned int)it->second.parts.size();
        p.nCount = it->second.nCount;
        p.nFirstSeen = it->second.nFirstSeen;
        out.push_back(p);
    }
}
