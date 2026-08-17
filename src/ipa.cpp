// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "curvetree.h"
#include "ipa.h"
#include "ed25519_zk.h"
#include "hash.h"
#include "util.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <string.h>
#include <algorithm>
#include <map>
#include <mutex>


// Per-thread secp256k1 group and BN_CTX. EC_GROUP_new_by_curve_name rebuilds the
// entire curve, and was previously constructed once per scalar/point op -- tens
// of thousands of times per proof verify (e.g. IPAScalarMulScalar built a whole
// group just to read the curve order). BN_CTX was likewise reallocated each op.
// Reusing them per thread is behaviourally identical (the group is read-only
// during compute ops; OpenSSL self-balances BN_CTX scratch, and no caller uses
// BN_CTX_start/get) -- it only removes the allocation churn and lets OpenSSL
// reuse per-thread generator precomputation. They are never shared across
// threads (EC_GROUP precompute state and BN_CTX are not thread-safe), and are
// intentionally leaked at thread exit (one small fixed object per thread).
static EC_GROUP* IPAThreadGroup()
{
    static thread_local EC_GROUP* tl = NULL;
    if (!tl) tl = EC_GROUP_new_by_curve_name(NID_secp256k1);
    return tl;
}
static BN_CTX* IPAThreadCtx()
{
    static thread_local BN_CTX* tl = NULL;
    if (!tl) tl = BN_CTX_new();
    return tl;
}

class CIPABNCtxGuard
{
public:
    BN_CTX* ctx;
    CIPABNCtxGuard() { ctx = IPAThreadCtx(); }
    ~CIPABNCtxGuard() { }   // thread-local, not owned
    operator BN_CTX*() { return ctx; }
};

class CIPAECGroupGuard
{
public:
    EC_GROUP* group;
    CIPAECGroupGuard() { group = IPAThreadGroup(); }
    ~CIPAECGroupGuard() { } // thread-local, not owned
    operator EC_GROUP*() { return group; }
    operator const EC_GROUP*() const { return group; }
};

class CIPAECPointGuard
{
public:
    EC_POINT* point;
    const EC_GROUP* group;
    CIPAECPointGuard(const EC_GROUP* g) : group(g) { point = EC_POINT_new(group); }
    ~CIPAECPointGuard() { if (point) EC_POINT_free(point); }
    operator EC_POINT*() { return point; }
    operator const EC_POINT*() const { return point; }
};

class CIPABNGuard
{
public:
    BIGNUM* bn;
    CIPABNGuard() { bn = BN_new(); }
    ~CIPABNGuard() { if (bn) BN_clear_free(bn); }
    operator BIGNUM*() { return bn; }
    operator const BIGNUM*() const { return bn; }
};

bool IsCanonicalIPAScalar(const std::vector<unsigned char>& scalar,
                          EIPACurveType curveType)
{
    if (scalar.size() != IPA_SCALAR_SIZE)
        return false;

    CIPABNGuard value, order;
    if (!value.bn || !order.bn ||
        !BN_bin2bn(scalar.data(), scalar.size(), value))
        return false;

    if (curveType == IPA_CURVE_SECP256K1)
    {
        CIPAECGroupGuard group;
        CIPABNCtxGuard ctx;
        if (!group.group || !ctx.ctx || !EC_GROUP_get_order(group, order, ctx))
            return false;
    }
    else if (curveType == IPA_CURVE_ED25519)
    {
        // Ed25519's group order is conventionally written little-endian.  IPA
        // scalar byte strings are big-endian, so reverse it before comparing.
        static const unsigned char ed25519OrderLE[32] = {
            0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58,
            0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
        };
        unsigned char orderBE[32];
        for (size_t i = 0; i < sizeof(orderBE); ++i)
            orderBE[i] = ed25519OrderLE[sizeof(orderBE) - 1 - i];
        if (!BN_bin2bn(orderBE, sizeof(orderBE), order))
            return false;
    }
    else
    {
        return false;
    }

    return BN_cmp(value, order) < 0;
}



void CIPATranscript::AppendScalar(const std::vector<unsigned char>& scalar)
{
    vchData.insert(vchData.end(), scalar.begin(), scalar.end());
}

void CIPATranscript::AppendPoint(const std::vector<unsigned char>& point)
{
    vchData.insert(vchData.end(), point.begin(), point.end());
}

void CIPATranscript::AppendBytes(const unsigned char* data, size_t len)
{
    vchData.insert(vchData.end(), data, data + len);
}

bool CIPATranscript::GetChallenge(std::vector<unsigned char>& challengeOut,
                                   EIPACurveType curveType) const
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(vchData.data(), vchData.size(), hash);

    CIPABNCtxGuard ctx;
    if (!ctx.ctx) return false;

    CIPABNGuard bnHash, bnReduced;
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, bnHash);

    if (curveType == IPA_CURVE_SECP256K1)
    {
        CIPAECGroupGuard group;
        if (!group.group) return false;

        CIPABNGuard order;
        EC_GROUP_get_order(group, order, ctx);
        BN_mod(bnReduced, bnHash, order, ctx);
    }
    else
    {
        static const unsigned char ed25519_order[32] = {
            0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58,
            0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
        };
        CIPABNGuard order;
        unsigned char orderBE[32];
        for (int i = 0; i < 32; i++)
            orderBE[i] = ed25519_order[31 - i];
        BN_bin2bn(orderBE, 32, order);
        BN_mod(bnReduced, bnHash, order, ctx);
    }

    if (BN_is_zero(bnReduced))
    {
        unsigned char extended[SHA256_DIGEST_LENGTH + 4];
        memcpy(extended, hash, SHA256_DIGEST_LENGTH);
        uint32_t ctr = 1;
        memcpy(extended + SHA256_DIGEST_LENGTH, &ctr, 4);
        SHA256(extended, sizeof(extended), hash);
        BN_bin2bn(hash, SHA256_DIGEST_LENGTH, bnHash);

        if (curveType == IPA_CURVE_SECP256K1)
        {
            CIPAECGroupGuard group;
            CIPABNGuard order;
            EC_GROUP_get_order(group, order, ctx);
            BN_mod(bnReduced, bnHash, order, ctx);
        }
    }

    challengeOut.resize(IPA_SCALAR_SIZE);
    memset(challengeOut.data(), 0, IPA_SCALAR_SIZE);
    int nBytes = BN_num_bytes(bnReduced);
    if (nBytes > 0)
        BN_bn2bin(bnReduced, challengeOut.data() + (IPA_SCALAR_SIZE - nBytes));

    return true;
}

bool CIPATranscript::GetChallengeAndUpdate(std::vector<unsigned char>& challengeOut,
                                            EIPACurveType curveType)
{
    if (!GetChallenge(challengeOut, curveType))
        return false;
    AppendScalar(challengeOut);
    return true;
}



bool IPAScalarAdd(const std::vector<unsigned char>& a,
                  const std::vector<unsigned char>& b,
                  std::vector<unsigned char>& resultOut,
                  EIPACurveType curveType)
{
    if (a.size() != IPA_SCALAR_SIZE || b.size() != IPA_SCALAR_SIZE)
        return false;

    CIPABNCtxGuard ctx;
    if (!ctx.ctx) return false;

    CIPABNGuard bnA, bnB, bnResult, order;
    BN_bin2bn(a.data(), IPA_SCALAR_SIZE, bnA);
    BN_bin2bn(b.data(), IPA_SCALAR_SIZE, bnB);

    if (curveType == IPA_CURVE_SECP256K1)
    {
        CIPAECGroupGuard group;
        if (!group.group) return false;
        EC_GROUP_get_order(group, order, ctx);
    }
    else
    {
        static const unsigned char ed25519_order[32] = {
            0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58,
            0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
        };
        unsigned char orderBE[32];
        for (int i = 0; i < 32; i++)
            orderBE[i] = ed25519_order[31 - i];
        BN_bin2bn(orderBE, 32, order);
    }

    BN_mod_add(bnResult, bnA, bnB, order, ctx);

    resultOut.resize(IPA_SCALAR_SIZE);
    memset(resultOut.data(), 0, IPA_SCALAR_SIZE);
    int nBytes = BN_num_bytes(bnResult);
    if (nBytes > 0)
        BN_bn2bin(bnResult, resultOut.data() + (IPA_SCALAR_SIZE - nBytes));

    return true;
}

bool IPAScalarMulScalar(const std::vector<unsigned char>& a,
                        const std::vector<unsigned char>& b,
                        std::vector<unsigned char>& resultOut,
                        EIPACurveType curveType)
{
    if (a.size() != IPA_SCALAR_SIZE || b.size() != IPA_SCALAR_SIZE)
        return false;

    CIPABNCtxGuard ctx;
    if (!ctx.ctx) return false;

    CIPABNGuard bnA, bnB, bnResult, order;
    BN_bin2bn(a.data(), IPA_SCALAR_SIZE, bnA);
    BN_bin2bn(b.data(), IPA_SCALAR_SIZE, bnB);

    if (curveType == IPA_CURVE_SECP256K1)
    {
        CIPAECGroupGuard group;
        if (!group.group) return false;
        EC_GROUP_get_order(group, order, ctx);
    }
    else
    {
        static const unsigned char ed25519_order[32] = {
            0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58,
            0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
        };
        unsigned char orderBE[32];
        for (int i = 0; i < 32; i++)
            orderBE[i] = ed25519_order[31 - i];
        BN_bin2bn(orderBE, 32, order);
    }

    BN_mod_mul(bnResult, bnA, bnB, order, ctx);

    resultOut.resize(IPA_SCALAR_SIZE);
    memset(resultOut.data(), 0, IPA_SCALAR_SIZE);
    int nBytes = BN_num_bytes(bnResult);
    if (nBytes > 0)
        BN_bn2bin(bnResult, resultOut.data() + (IPA_SCALAR_SIZE - nBytes));

    return true;
}

bool IPAScalarInv(const std::vector<unsigned char>& a,
                  std::vector<unsigned char>& resultOut,
                  EIPACurveType curveType)
{
    if (a.size() != IPA_SCALAR_SIZE)
        return false;

    CIPABNCtxGuard ctx;
    if (!ctx.ctx) return false;

    CIPABNGuard bnA, bnResult, order;
    BN_bin2bn(a.data(), IPA_SCALAR_SIZE, bnA);

    if (BN_is_zero(bnA))
        return false;

    if (curveType == IPA_CURVE_SECP256K1)
    {
        CIPAECGroupGuard group;
        if (!group.group) return false;
        EC_GROUP_get_order(group, order, ctx);
    }
    else
    {
        static const unsigned char ed25519_order[32] = {
            0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58,
            0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
        };
        unsigned char orderBE[32];
        for (int i = 0; i < 32; i++)
            orderBE[i] = ed25519_order[31 - i];
        BN_bin2bn(orderBE, 32, order);
    }

    if (!BN_mod_inverse(bnResult, bnA, order, ctx))
        return false;

    resultOut.resize(IPA_SCALAR_SIZE);
    memset(resultOut.data(), 0, IPA_SCALAR_SIZE);
    int nBytes = BN_num_bytes(bnResult);
    if (nBytes > 0)
        BN_bn2bin(bnResult, resultOut.data() + (IPA_SCALAR_SIZE - nBytes));

    return true;
}



bool IPAScalarMul(const std::vector<unsigned char>& scalar,
                  const std::vector<unsigned char>& point,
                  std::vector<unsigned char>& resultOut,
                  EIPACurveType curveType)
{
    if (scalar.size() != IPA_SCALAR_SIZE)
        return false;

    if (curveType == IPA_CURVE_SECP256K1)
    {
        if (point.size() != IPA_SECP256K1_POINT)
            return false;

        CIPAECGroupGuard group;
        CIPABNCtxGuard ctx;
        if (!group.group || !ctx.ctx) return false;

        CIPAECPointGuard pt(group), result(group);
        CIPABNGuard bnScalar;

        if (EC_POINT_oct2point(group, pt, point.data(), point.size(), ctx) != 1)
            return false;

        if (EC_POINT_is_on_curve(group, pt, ctx) != 1)
            return false;
        if (EC_POINT_is_at_infinity(group, pt))
            return false;

        BN_bin2bn(scalar.data(), IPA_SCALAR_SIZE, bnScalar);
        EC_POINT_mul(group, result, NULL, pt, bnScalar, ctx);

        resultOut.resize(IPA_SECP256K1_POINT);
        EC_POINT_point2oct(group, result, POINT_CONVERSION_COMPRESSED,
                          resultOut.data(), IPA_SECP256K1_POINT, ctx);
        return true;
    }
    else
    {
        if (point.size() != IPA_ED25519_POINT)
            return false;

        return Ed25519ScalarMult(scalar, point, resultOut);
    }
}

bool IPAPointAdd(const std::vector<unsigned char>& a,
                 const std::vector<unsigned char>& b,
                 std::vector<unsigned char>& resultOut,
                 EIPACurveType curveType)
{
    if (curveType == IPA_CURVE_SECP256K1)
    {
        if (a.size() != IPA_SECP256K1_POINT || b.size() != IPA_SECP256K1_POINT)
            return false;

        CIPAECGroupGuard group;
        CIPABNCtxGuard ctx;
        if (!group.group || !ctx.ctx) return false;

        CIPAECPointGuard ptA(group), ptB(group), result(group);

        if (EC_POINT_oct2point(group, ptA, a.data(), a.size(), ctx) != 1)
            return false;
        if (EC_POINT_oct2point(group, ptB, b.data(), b.size(), ctx) != 1)
            return false;

        EC_POINT_add(group, result, ptA, ptB, ctx);

        resultOut.resize(IPA_SECP256K1_POINT);
        EC_POINT_point2oct(group, result, POINT_CONVERSION_COMPRESSED,
                          resultOut.data(), IPA_SECP256K1_POINT, ctx);
        return true;
    }
    else
    {
        if (a.size() != IPA_ED25519_POINT || b.size() != IPA_ED25519_POINT)
            return false;

        return Ed25519PointAdd(a, b, resultOut);
    }
}



bool IPAInnerProduct(const std::vector<std::vector<unsigned char>>& a,
                     const std::vector<std::vector<unsigned char>>& b,
                     std::vector<unsigned char>& resultOut,
                     EIPACurveType curveType)
{
    if (a.size() != b.size() || a.empty())
        return false;

    resultOut.resize(IPA_SCALAR_SIZE);
    memset(resultOut.data(), 0, IPA_SCALAR_SIZE);

    for (size_t i = 0; i < a.size(); i++)
    {
        std::vector<unsigned char> product;
        if (!IPAScalarMulScalar(a[i], b[i], product, curveType))
            return false;

        std::vector<unsigned char> newResult;
        if (!IPAScalarAdd(resultOut, product, newResult, curveType))
            return false;

        resultOut = newResult;
    }

    return true;
}



static bool HashToPointSecp256k1(const std::string& label,
                                  std::vector<unsigned char>& pointOut)
{
    CIPAECGroupGuard group;
    CIPABNCtxGuard ctx;
    if (!group.group || !ctx.ctx) return false;

    for (uint32_t counter = 0; counter < 256; counter++)
    {
        SHA256_CTX sha;
        SHA256_Init(&sha);
        SHA256_Update(&sha, label.data(), label.size());
        SHA256_Update(&sha, &counter, sizeof(counter));

        unsigned char hash[32];
        SHA256_Final(hash, &sha);

        unsigned char compressed[33];
        compressed[0] = 0x02;
        memcpy(compressed + 1, hash, 32);

        CIPAECPointGuard pt(group);
        if (EC_POINT_oct2point(group, pt, compressed, 33, ctx) == 1 &&
            EC_POINT_is_on_curve(group, pt, ctx) == 1)
        {
            pointOut.resize(IPA_SECP256K1_POINT);
            EC_POINT_point2oct(group, pt, POINT_CONVERSION_COMPRESSED,
                              pointOut.data(), IPA_SECP256K1_POINT, ctx);
            return true;
        }
    }

    return false;
}

namespace {
std::mutex g_ipaGenCacheMutex;
std::map<std::string, CIPAGenerators> g_ipaGenCache;
}

static bool GenerateIPAGeneratorsUncached(const std::string& domain,
                                          int n,
                                          EIPACurveType curveType,
                                          CIPAGenerators& gensOut);

bool GenerateIPAGenerators(const std::string& domain,
                           int n,
                           EIPACurveType curveType,
                           CIPAGenerators& gensOut)
{
    // Generators are a deterministic function of (domain, n, curveType), so a
    // process-wide memo removes the 2n+1 hash-to-curve derivations (4097 at
    // n=2048) that previously ran on every verify. Only a handful of distinct
    // tuples are ever used, so the map stays tiny and needs no eviction.
    std::string key = domain;
    key += '|';
    key += std::to_string(n);
    key += '|';
    key += std::to_string((int)curveType);
    {
        std::lock_guard<std::mutex> lock(g_ipaGenCacheMutex);
        std::map<std::string, CIPAGenerators>::iterator it = g_ipaGenCache.find(key);
        if (it != g_ipaGenCache.end())
        {
            gensOut = it->second;
            return true;
        }
    }
    CIPAGenerators gens;
    if (!GenerateIPAGeneratorsUncached(domain, n, curveType, gens))
        return false;
    {
        std::lock_guard<std::mutex> lock(g_ipaGenCacheMutex);
        g_ipaGenCache[key] = gens;
    }
    gensOut = gens;
    return true;
}

static bool GenerateIPAGeneratorsUncached(const std::string& domain,
                                          int n,
                                          EIPACurveType curveType,
                                          CIPAGenerators& gensOut)
{
    if (n <= 0 || n > (int)IPA_MAX_VECTOR_LEN)
        return false;

    if ((n & (n - 1)) != 0)
        return false;

    gensOut.curveType = curveType;
    gensOut.nLength = n;
    gensOut.vG.resize(n);
    gensOut.vH.resize(n);

    if (curveType == IPA_CURVE_SECP256K1)
    {
        for (int i = 0; i < n; i++)
        {
            std::string label = domain + "_G_" + std::to_string(i);
            if (!HashToPointSecp256k1(label, gensOut.vG[i]))
                return false;
        }

        for (int i = 0; i < n; i++)
        {
            std::string label = domain + "_H_" + std::to_string(i);
            if (!HashToPointSecp256k1(label, gensOut.vH[i]))
                return false;
        }

        std::string labelU = domain + "_U";
        if (!HashToPointSecp256k1(labelU, gensOut.vchU))
            return false;

        std::set<std::vector<unsigned char>> setPoints;
        for (int i = 0; i < n; i++)
        {
            if (!setPoints.insert(gensOut.vG[i]).second)
                return false;
            if (!setPoints.insert(gensOut.vH[i]).second)
                return false;
        }
        if (!setPoints.insert(gensOut.vchU).second)
            return false;
    }
    else if (curveType == IPA_CURVE_ED25519)
    {
        for (int i = 0; i < n; i++)
        {
            std::string label = domain + "_Ed25519_G_" + std::to_string(i);
            if (!Ed25519HashToPoint(label, gensOut.vG[i]))
                return false;
        }

        for (int i = 0; i < n; i++)
        {
            std::string label = domain + "_Ed25519_H_" + std::to_string(i);
            if (!Ed25519HashToPoint(label, gensOut.vH[i]))
                return false;
        }

        std::string labelU = domain + "_Ed25519_U";
        if (!Ed25519HashToPoint(labelU, gensOut.vchU))
            return false;

        std::set<std::vector<unsigned char>> setPoints;
        for (int i = 0; i < n; i++)
        {
            if (!setPoints.insert(gensOut.vG[i]).second)
                return false;
            if (!setPoints.insert(gensOut.vH[i]).second)
                return false;
        }
        if (!setPoints.insert(gensOut.vchU).second)
            return false;
    }
    else
    {
        return false;
    }

    return true;
}



bool CreateIPAProof(const std::vector<std::vector<unsigned char>>& a,
                    const std::vector<std::vector<unsigned char>>& b,
                    const std::vector<unsigned char>& z,
                    const CIPAGenerators& gens,
                    CIPATranscript& transcript,
                    CIPAProof& proofOut)
{
    size_t n = a.size();

    if (n != b.size() || n != (size_t)gens.nLength)
        return false;
    if (n == 0 || (n & (n - 1)) != 0)
        return false;
    if (n > IPA_MAX_VECTOR_LEN)
        return false;

    proofOut.curveType = gens.curveType;
    proofOut.vL.clear();
    proofOut.vR.clear();

    std::vector<std::vector<unsigned char>> aVec = a;
    std::vector<std::vector<unsigned char>> bVec = b;
    std::vector<std::vector<unsigned char>> gVec = gens.vG;
    std::vector<std::vector<unsigned char>> hVec = gens.vH;

    int curN = (int)n;
    int logN = 0;
    while ((1 << logN) < curN) logN++;

    for (int round = 0; round < logN; round++)
    {
        int half = curN / 2;

        std::vector<unsigned char> L, R;

        CIPAECGroupGuard group;
        CIPABNCtxGuard ctx;
        if (!group.group || !ctx.ctx) return false;

        CIPAECPointGuard ptL(group), ptR(group);
        EC_POINT_set_to_infinity(group, ptL);
        EC_POINT_set_to_infinity(group, ptR);

        std::vector<unsigned char> cL, cR;
        cL.resize(IPA_SCALAR_SIZE, 0);
        cR.resize(IPA_SCALAR_SIZE, 0);

        for (int i = 0; i < half; i++)
        {
            std::vector<unsigned char> term;
            if (!IPAScalarMul(aVec[i], gVec[half + i], term, gens.curveType))
                return false;

            CIPAECPointGuard tmpPt(group);
            EC_POINT_oct2point(group, tmpPt, term.data(), term.size(), ctx);
            EC_POINT_add(group, ptL, ptL, tmpPt, ctx);

            if (!IPAScalarMul(bVec[half + i], hVec[i], term, gens.curveType))
                return false;
            EC_POINT_oct2point(group, tmpPt, term.data(), term.size(), ctx);
            EC_POINT_add(group, ptL, ptL, tmpPt, ctx);

            std::vector<unsigned char> prod, newCL;
            if (!IPAScalarMulScalar(aVec[i], bVec[half + i], prod, gens.curveType))
                return false;
            if (!IPAScalarAdd(cL, prod, newCL, gens.curveType))
                return false;
            cL = newCL;

            if (!IPAScalarMul(aVec[half + i], gVec[i], term, gens.curveType))
                return false;
            EC_POINT_oct2point(group, tmpPt, term.data(), term.size(), ctx);
            EC_POINT_add(group, ptR, ptR, tmpPt, ctx);

            if (!IPAScalarMul(bVec[i], hVec[half + i], term, gens.curveType))
                return false;
            EC_POINT_oct2point(group, tmpPt, term.data(), term.size(), ctx);
            EC_POINT_add(group, ptR, ptR, tmpPt, ctx);

            if (!IPAScalarMulScalar(aVec[half + i], bVec[i], prod, gens.curveType))
                return false;
            if (!IPAScalarAdd(cR, prod, newCL, gens.curveType))
                return false;
            cR = newCL;
        }

        {
            std::vector<unsigned char> cLU, cRU;
            if (!IPAScalarMul(cL, gens.vchU, cLU, gens.curveType))
                return false;
            if (!IPAScalarMul(cR, gens.vchU, cRU, gens.curveType))
                return false;

            CIPAECPointGuard tmpPt(group);
            EC_POINT_oct2point(group, tmpPt, cLU.data(), cLU.size(), ctx);
            EC_POINT_add(group, ptL, ptL, tmpPt, ctx);

            EC_POINT_oct2point(group, tmpPt, cRU.data(), cRU.size(), ctx);
            EC_POINT_add(group, ptR, ptR, tmpPt, ctx);
        }

        L.resize(IPA_SECP256K1_POINT);
        R.resize(IPA_SECP256K1_POINT);
        EC_POINT_point2oct(group, ptL, POINT_CONVERSION_COMPRESSED,
                          L.data(), IPA_SECP256K1_POINT, ctx);
        EC_POINT_point2oct(group, ptR, POINT_CONVERSION_COMPRESSED,
                          R.data(), IPA_SECP256K1_POINT, ctx);

        proofOut.vL.push_back(L);
        proofOut.vR.push_back(R);

        transcript.AppendPoint(L);
        transcript.AppendPoint(R);

        std::vector<unsigned char> u;
        if (!transcript.GetChallengeAndUpdate(u, gens.curveType))
            return false;

        std::vector<unsigned char> uInv;
        if (!IPAScalarInv(u, uInv, gens.curveType))
            return false;

        std::vector<std::vector<unsigned char>> newA(half), newB(half);
        std::vector<std::vector<unsigned char>> newG(half), newH(half);

        for (int i = 0; i < half; i++)
        {
            std::vector<unsigned char> term1, term2;
            if (!IPAScalarMulScalar(aVec[i], u, term1, gens.curveType))
                return false;
            if (!IPAScalarMulScalar(aVec[half + i], uInv, term2, gens.curveType))
                return false;
            if (!IPAScalarAdd(term1, term2, newA[i], gens.curveType))
                return false;

            if (!IPAScalarMulScalar(bVec[i], uInv, term1, gens.curveType))
                return false;
            if (!IPAScalarMulScalar(bVec[half + i], u, term2, gens.curveType))
                return false;
            if (!IPAScalarAdd(term1, term2, newB[i], gens.curveType))
                return false;

            std::vector<unsigned char> pt1, pt2;
            if (!IPAScalarMul(uInv, gVec[i], pt1, gens.curveType))
                return false;
            if (!IPAScalarMul(u, gVec[half + i], pt2, gens.curveType))
                return false;
            if (!IPAPointAdd(pt1, pt2, newG[i], gens.curveType))
                return false;

            if (!IPAScalarMul(u, hVec[i], pt1, gens.curveType))
                return false;
            if (!IPAScalarMul(uInv, hVec[half + i], pt2, gens.curveType))
                return false;
            if (!IPAPointAdd(pt1, pt2, newH[i], gens.curveType))
                return false;
        }

        aVec = newA;
        bVec = newB;
        gVec = newG;
        hVec = newH;
        curN = half;
    }

    proofOut.vchAFinal = aVec[0];
    proofOut.vchBFinal = bVec[0];

    return true;
}



bool VerifyIPAProof(const std::vector<unsigned char>& P,
                    const std::vector<unsigned char>& z,
                    const CIPAGenerators& gens,
                    CIPATranscript& transcript,
                    const CIPAProof& proof)
{
    if (proof.IsNull())
        return false;

    if (proof.curveType != gens.curveType ||
        (proof.curveType != IPA_CURVE_SECP256K1 && proof.curveType != IPA_CURVE_ED25519))
        return false;

    const int logN = proof.GetNumRounds();
    if (logN < 0 || logN > (int)IPA_MAX_ROUNDS ||
        proof.vR.size() != proof.vL.size())
        return false;

    const int n = 1 << logN;

    if (n <= 0 || n > (int)IPA_MAX_VECTOR_LEN || n != gens.nLength ||
        gens.vG.size() != (size_t)n || gens.vH.size() != (size_t)n)
        return false;

    const size_t nPointSize = proof.curveType == IPA_CURVE_SECP256K1
        ? IPA_SECP256K1_POINT : IPA_ED25519_POINT;
    const bool fPSizeValid = proof.curveType == IPA_CURVE_SECP256K1
        ? (P.size() == IPA_SECP256K1_POINT ||
           P.size() == IPA_SECP256K1_POINT_UNCOMPRESSED)
        : P.size() == nPointSize;
    if (!fPSizeValid || z.size() != IPA_SCALAR_SIZE ||
        proof.vchAFinal.size() != IPA_SCALAR_SIZE ||
        proof.vchBFinal.size() != IPA_SCALAR_SIZE ||
        gens.vchU.size() != nPointSize)
        return false;
    if (!IsCanonicalIPAScalar(z, proof.curveType) ||
        !IsCanonicalIPAScalar(proof.vchAFinal, proof.curveType) ||
        !IsCanonicalIPAScalar(proof.vchBFinal, proof.curveType))
        return false;
    for (int i = 0; i < logN; ++i)
        if (proof.vL[i].size() != nPointSize || proof.vR[i].size() != nPointSize)
            return false;

    if (gens.curveType == IPA_CURVE_ED25519)
    {
        for (size_t i = 0; i < proof.vL.size(); i++)
        {
            std::vector<unsigned char> validatedL, validatedR;
            if (!Ed25519PointFromBytes(proof.vL[i], validatedL, true))
                return false;
            if (!Ed25519PointFromBytes(proof.vR[i], validatedR, true))
                return false;
        }
    }

    std::vector<std::vector<unsigned char>> challenges(logN);
    std::vector<std::vector<unsigned char>> challengeInvs(logN);

    for (int round = 0; round < logN; round++)
    {
        transcript.AppendPoint(proof.vL[round]);
        transcript.AppendPoint(proof.vR[round]);

        if (!transcript.GetChallengeAndUpdate(challenges[round], gens.curveType))
            return false;

        if (!IPAScalarInv(challenges[round], challengeInvs[round], gens.curveType))
            return false;
    }

    CIPAECGroupGuard group;
    CIPABNCtxGuard ctx;
    if (!group.group || !ctx.ctx) return false;

    CIPAECPointGuard pPrime(group);
    if (EC_POINT_oct2point(group, pPrime, P.data(), P.size(), ctx) != 1)
        return false;

    for (int i = 0; i < logN; i++)
    {
        std::vector<unsigned char> uSq, uInvSq;
        if (!IPAScalarMulScalar(challenges[i], challenges[i], uSq, gens.curveType))
            return false;
        if (!IPAScalarMulScalar(challengeInvs[i], challengeInvs[i], uInvSq, gens.curveType))
            return false;

        std::vector<unsigned char> lTerm, rTerm;
        if (!IPAScalarMul(uSq, proof.vL[i], lTerm, gens.curveType))
            return false;
        if (!IPAScalarMul(uInvSq, proof.vR[i], rTerm, gens.curveType))
            return false;

        CIPAECPointGuard tmpL(group), tmpR(group);
        EC_POINT_oct2point(group, tmpL, lTerm.data(), lTerm.size(), ctx);
        EC_POINT_oct2point(group, tmpR, rTerm.data(), rTerm.size(), ctx);

        EC_POINT_add(group, pPrime, pPrime, tmpL, ctx);
        EC_POINT_add(group, pPrime, pPrime, tmpR, ctx);
    }

    std::vector<unsigned char> g0Scalar, h0Scalar;
    g0Scalar.resize(IPA_SCALAR_SIZE);
    h0Scalar.resize(IPA_SCALAR_SIZE);
    memset(g0Scalar.data(), 0, IPA_SCALAR_SIZE);
    memset(h0Scalar.data(), 0, IPA_SCALAR_SIZE);
    g0Scalar[IPA_SCALAR_SIZE - 1] = 1;  // Start with 1
    h0Scalar[IPA_SCALAR_SIZE - 1] = 1;

    for (int round = 0; round < logN; round++)
    {
        std::vector<unsigned char> newG0, newH0;
        if (!IPAScalarMulScalar(g0Scalar, challengeInvs[round], newG0, gens.curveType))
            return false;
        if (!IPAScalarMulScalar(h0Scalar, challenges[round], newH0, gens.curveType))
            return false;
        g0Scalar = newG0;
        h0Scalar = newH0;
    }

    std::vector<unsigned char> gFinal, hFinal;
    if (!IPAScalarMul(g0Scalar, gens.vG[0], gFinal, gens.curveType))
        return false;
    if (!IPAScalarMul(h0Scalar, gens.vH[0], hFinal, gens.curveType))
        return false;

    for (int i = 1; i < n; i++)
    {
        std::vector<unsigned char> gScalar, hScalar;
        gScalar.resize(IPA_SCALAR_SIZE);
        hScalar.resize(IPA_SCALAR_SIZE);
        memset(gScalar.data(), 0, IPA_SCALAR_SIZE);
        memset(hScalar.data(), 0, IPA_SCALAR_SIZE);
        gScalar[IPA_SCALAR_SIZE - 1] = 1;  // Start with 1
        hScalar[IPA_SCALAR_SIZE - 1] = 1;

        int idx = i;
        for (int round = logN - 1; round >= 0; round--)
        {
            int bit = idx & 1;
            idx >>= 1;

            std::vector<unsigned char> newGScalar, newHScalar;
            if (bit == 0)
            {
                if (!IPAScalarMulScalar(gScalar, challengeInvs[round], newGScalar, gens.curveType))
                    return false;
                if (!IPAScalarMulScalar(hScalar, challenges[round], newHScalar, gens.curveType))
                    return false;
            }
            else
            {
                if (!IPAScalarMulScalar(gScalar, challenges[round], newGScalar, gens.curveType))
                    return false;
                if (!IPAScalarMulScalar(hScalar, challengeInvs[round], newHScalar, gens.curveType))
                    return false;
            }
            gScalar = newGScalar;
            hScalar = newHScalar;
        }

        std::vector<unsigned char> gTerm, hTerm, newGFinal, newHFinal;
        if (!IPAScalarMul(gScalar, gens.vG[i], gTerm, gens.curveType))
            return false;
        if (!IPAScalarMul(hScalar, gens.vH[i], hTerm, gens.curveType))
            return false;

        if (!IPAPointAdd(gFinal, gTerm, newGFinal, gens.curveType))
            return false;
        if (!IPAPointAdd(hFinal, hTerm, newHFinal, gens.curveType))
            return false;

        gFinal = newGFinal;
        hFinal = newHFinal;
    }

    std::vector<unsigned char> aG, bH, ab, abU;
    if (!IPAScalarMul(proof.vchAFinal, gFinal, aG, gens.curveType))
        return false;
    if (!IPAScalarMul(proof.vchBFinal, hFinal, bH, gens.curveType))
        return false;
    if (!IPAScalarMulScalar(proof.vchAFinal, proof.vchBFinal, ab, gens.curveType))
        return false;
    if (!IPAScalarMul(ab, gens.vchU, abU, gens.curveType))
        return false;

    std::vector<unsigned char> expected1, expected2;
    if (!IPAPointAdd(aG, bH, expected1, gens.curveType))
        return false;
    if (!IPAPointAdd(expected1, abU, expected2, gens.curveType))
        return false;

    std::vector<unsigned char> pPrimeBytes(IPA_SECP256K1_POINT);
    EC_POINT_point2oct(group, pPrime, POINT_CONVERSION_COMPRESSED,
                      pPrimeBytes.data(), IPA_SECP256K1_POINT, ctx);

    if (pPrimeBytes != expected2)
        return false;

    return true;
}
