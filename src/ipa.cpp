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


class CIPABNCtxGuard
{
public:
    BN_CTX* ctx;
    CIPABNCtxGuard() { ctx = BN_CTX_new(); }
    ~CIPABNCtxGuard() { if (ctx) BN_CTX_free(ctx); }
    operator BN_CTX*() { return ctx; }
};

class CIPAECGroupGuard
{
public:
    EC_GROUP* group;
    CIPAECGroupGuard() { group = EC_GROUP_new_by_curve_name(NID_secp256k1); }
    ~CIPAECGroupGuard() { if (group) EC_GROUP_free(group); }
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

bool GenerateIPAGenerators(const std::string& domain,
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

    int logN = proof.GetNumRounds();
    int n = 1 << logN;

    if (n != gens.nLength)
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



static const char* PATH_IPA_DOMAIN = "Innova_FCMP_PathIPA_v5";

static bool CommitToPositionBits(uint64_t nPosition,
                                  int nDepth,
                                  const std::vector<unsigned char>& vchBlindR,
                                  const CIPAGenerators& gens,
                                  std::vector<unsigned char>& commitOut)
{
    if (nDepth > (int)gens.vG.size())
        return false;

    CIPAECGroupGuard group;
    CIPABNCtxGuard ctx;
    if (!group.group || !ctx.ctx) return false;

    CIPAECPointGuard result(group);
    EC_POINT_set_to_infinity(group, result);

    for (int i = 0; i < nDepth; i++)
    {
        int bit = (nPosition >> i) & 1;
        if (bit == 1)
        {
            CIPAECPointGuard gi(group);
            if (EC_POINT_oct2point(group, gi, gens.vG[i].data(), gens.vG[i].size(), ctx) != 1)
                return false;
            EC_POINT_add(group, result, result, gi, ctx);
        }
    }

    std::vector<unsigned char> rH;
    if (!IPAScalarMul(vchBlindR, gens.vH[0], rH, IPA_CURVE_SECP256K1))
        return false;

    CIPAECPointGuard rHPt(group);
    if (EC_POINT_oct2point(group, rHPt, rH.data(), rH.size(), ctx) != 1)
        return false;
    EC_POINT_add(group, result, result, rHPt, ctx);

    commitOut.resize(IPA_SECP256K1_POINT);
    EC_POINT_point2oct(group, result, POINT_CONVERSION_COMPRESSED,
                      commitOut.data(), IPA_SECP256K1_POINT, ctx);

    return true;
}

static bool EncodePathPolynomial(const std::vector<std::vector<unsigned char>>& vSiblings,
                                  uint64_t nPosition,
                                  int nDepth,
                                  std::vector<std::vector<unsigned char>>& coeffsOut)
{
    coeffsOut.resize(nDepth);

    for (int i = 0; i < nDepth; i++)
    {
        SHA256_CTX sha;
        SHA256_Init(&sha);

        const char* domain = "PathPoly_Coeff_v5";
        SHA256_Update(&sha, domain, strlen(domain));
        SHA256_Update(&sha, vSiblings[i].data(), vSiblings[i].size());

        uint32_t level = (uint32_t)i;
        SHA256_Update(&sha, &level, sizeof(level));

        coeffsOut[i].resize(IPA_SCALAR_SIZE);
        SHA256_Final(coeffsOut[i].data(), &sha);
    }

    return true;
}

bool CreatePathIPAProof(const std::vector<std::vector<unsigned char>>& vSiblings,
                        uint64_t nPosition,
                        int nDepth,
                        const std::vector<unsigned char>& vchBlind,
                        CPathIPAProof& proofOut)
{
    if (vSiblings.size() != (size_t)nDepth || nDepth <= 0)
        return false;
    if (vchBlind.size() != IPA_SCALAR_SIZE)
        return false;

    proofOut.nVersion = PATH_IPA_VERSION;
    proofOut.nDepth = nDepth;

    int n = 1;
    while (n < nDepth) n *= 2;

    CIPAGenerators gens;
    if (!GenerateIPAGenerators(PATH_IPA_DOMAIN, n, IPA_CURVE_SECP256K1, gens))
        return false;

    std::vector<unsigned char> blindR(IPA_SCALAR_SIZE);
    std::vector<unsigned char> blindPath(IPA_SCALAR_SIZE);
    {
        SHA256_CTX sha;

        SHA256_Init(&sha);
        SHA256_Update(&sha, "PathIPA_BlindR_v5", 17);
        SHA256_Update(&sha, vchBlind.data(), vchBlind.size());
        SHA256_Final(blindR.data(), &sha);

        SHA256_Init(&sha);
        SHA256_Update(&sha, "PathIPA_BlindPath_v5", 20);
        SHA256_Update(&sha, vchBlind.data(), vchBlind.size());
        SHA256_Final(blindPath.data(), &sha);
    }

    if (!CommitToPositionBits(nPosition, nDepth, blindR, gens, proofOut.vchPositionCommit))
        return false;

    std::vector<std::vector<unsigned char>> pathCoeffs;
    if (!EncodePathPolynomial(vSiblings, nPosition, nDepth, pathCoeffs))
        return false;

    while (pathCoeffs.size() < (size_t)n)
    {
        std::vector<unsigned char> zero(IPA_SCALAR_SIZE, 0);
        pathCoeffs.push_back(zero);
    }

    std::vector<std::vector<unsigned char>> aVec = pathCoeffs;
    std::vector<std::vector<unsigned char>> bVec(n);

    for (int i = 0; i < n; i++)
    {
        bVec[i].resize(IPA_SCALAR_SIZE);
        memset(bVec[i].data(), 0, IPA_SCALAR_SIZE);

        if (i < nDepth)
        {
            int bit = (nPosition >> i) & 1;

            SHA256_CTX sha;
            SHA256_Init(&sha);
            SHA256_Update(&sha, "PathIPA_B_v5", 12);
            SHA256_Update(&sha, vchBlind.data(), vchBlind.size());
            uint32_t idx = (uint32_t)i;
            SHA256_Update(&sha, &idx, sizeof(idx));
            SHA256_Update(&sha, &bit, sizeof(bit));
            SHA256_Final(bVec[i].data(), &sha);
        }
        else
        {
            bVec[i][IPA_SCALAR_SIZE - 1] = 1;  // Non-zero padding
        }
    }

    std::vector<unsigned char> z;
    if (!IPAInnerProduct(aVec, bVec, z, IPA_CURVE_SECP256K1))
        return false;

    {
        CIPAECGroupGuard group;
        CIPABNCtxGuard ctx;
        if (!group.group || !ctx.ctx) return false;

        CIPAECPointGuard result(group);
        EC_POINT_set_to_infinity(group, result);

        for (int i = 0; i < n; i++)
        {
            std::vector<unsigned char> aG;
            if (!IPAScalarMul(aVec[i], gens.vG[i], aG, IPA_CURVE_SECP256K1))
                return false;
            CIPAECPointGuard ptAG(group);
            if (EC_POINT_oct2point(group, ptAG, aG.data(), aG.size(), ctx) != 1)
                return false;
            EC_POINT_add(group, result, result, ptAG, ctx);

            std::vector<unsigned char> bH;
            if (!IPAScalarMul(bVec[i], gens.vH[i], bH, IPA_CURVE_SECP256K1))
                return false;
            CIPAECPointGuard ptBH(group);
            if (EC_POINT_oct2point(group, ptBH, bH.data(), bH.size(), ctx) != 1)
                return false;
            EC_POINT_add(group, result, result, ptBH, ctx);
        }

        std::vector<unsigned char> zU;
        if (!IPAScalarMul(z, gens.vchU, zU, IPA_CURVE_SECP256K1))
            return false;
        CIPAECPointGuard ptZU(group);
        if (EC_POINT_oct2point(group, ptZU, zU.data(), zU.size(), ctx) != 1)
            return false;
        EC_POINT_add(group, result, result, ptZU, ctx);

        proofOut.vchPathCommit.resize(IPA_SECP256K1_POINT);
        EC_POINT_point2oct(group, result, POINT_CONVERSION_COMPRESSED,
                          proofOut.vchPathCommit.data(), IPA_SECP256K1_POINT, ctx);
    }

    CIPATranscript transcript;
    transcript.AppendBytes((const unsigned char*)"PathIPAProof_v5", 15);
    transcript.AppendPoint(proofOut.vchPositionCommit);
    transcript.AppendPoint(proofOut.vchPathCommit);

    if (!CreateIPAProof(aVec, bVec, z, gens, transcript, proofOut.ipaProof))
        return false;

    proofOut.vchInnerProduct = z;

    {
        std::vector<unsigned char> currentHash = vSiblings[0];

        SHA256_CTX sha;
        SHA256_Init(&sha);
        SHA256_Update(&sha, "PathIPA_SibCommit_v5", 20);
        for (int i = 0; i < nDepth; i++)
        {
            SHA256_Update(&sha, vSiblings[i].data(), vSiblings[i].size());
        }
        proofOut.vchSiblingCommit.resize(32);
        SHA256_Final(proofOut.vchSiblingCommit.data(), &sha);
    }

    return true;
}

bool VerifyPathIPAProof(const std::vector<unsigned char>& vchRoot,
                        const std::vector<unsigned char>& vchLeafCommit,
                        const CPathIPAProof& proof)
{
    if (proof.nVersion != PATH_IPA_VERSION)
        return false;
    if (proof.nDepth <= 0 || proof.nDepth > 64)
        return false;
    if (proof.ipaProof.IsNull())
        return false;

    int n = 1;
    while (n < proof.nDepth) n *= 2;

    CIPAGenerators gens;
    if (!GenerateIPAGenerators(PATH_IPA_DOMAIN, n, IPA_CURVE_SECP256K1, gens))
        return false;

    CIPATranscript transcript;
    transcript.AppendBytes((const unsigned char*)"PathIPAProof_v5", 15);
    transcript.AppendPoint(proof.vchPositionCommit);
    transcript.AppendPoint(proof.vchPathCommit);

    if (!VerifyIPAProof(proof.vchPathCommit, proof.vchInnerProduct, gens, transcript, proof.ipaProof))
        return false;

    if (!vchRoot.empty())
    {
        SHA256_CTX sha;
        SHA256_Init(&sha);
        SHA256_Update(&sha, "PathIPA_RootBind_v5", 19);
        SHA256_Update(&sha, vchRoot.data(), vchRoot.size());
        SHA256_Update(&sha, proof.vchPositionCommit.data(), proof.vchPositionCommit.size());
        SHA256_Update(&sha, proof.vchPathCommit.data(), proof.vchPathCommit.size());

    }

    if (!vchLeafCommit.empty())
    {
    }

    return true;
}

bool CreateFCMPProofV5(const std::vector<std::vector<unsigned char>>& vSiblings,
                        uint64_t nLeafIndex,
                        int nDepth,
                        const std::vector<unsigned char>& vchBlind,
                        const std::vector<unsigned char>& vchLeafCommit,
                        std::vector<unsigned char>& proofOut)
{
    CPathIPAProof pathProof;
    if (!CreatePathIPAProof(vSiblings, nLeafIndex, nDepth, vchBlind, pathProof))
        return false;

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);

    uint32_t version = FCMP_PROOF_VERSION_IPA;
    ss << version;

    ss << pathProof.nVersion;
    ss << pathProof.nDepth;
    ss << pathProof.vchPositionCommit;
    ss << pathProof.vchPathCommit;
    ss << pathProof.vchInnerProduct;
    ss << pathProof.vchSiblingCommit;

    ss << pathProof.ipaProof;

    ss << vchLeafCommit;

    proofOut.assign(ss.begin(), ss.end());
    return true;
}

bool VerifyFCMPProofV5(const std::vector<unsigned char>& vchRoot,
                        const std::vector<unsigned char>& vchLeafCommit,
                        const std::vector<unsigned char>& proof)
{
    if (proof.size() < 4)
        return false;

    CDataStream ss(proof, SER_NETWORK, PROTOCOL_VERSION);

    uint32_t version;
    ss >> version;
    if (version != FCMP_PROOF_VERSION_IPA)
        return false;

    CPathIPAProof pathProof;
    ss >> pathProof.nVersion;
    ss >> pathProof.nDepth;
    ss >> pathProof.vchPositionCommit;
    ss >> pathProof.vchPathCommit;
    ss >> pathProof.vchInnerProduct;
    ss >> pathProof.vchSiblingCommit;
    ss >> pathProof.ipaProof;

    std::vector<unsigned char> leafCommit;
    ss >> leafCommit;

    if (!vchLeafCommit.empty() && leafCommit != vchLeafCommit)
        return false;

    return VerifyPathIPAProof(vchRoot, leafCommit, pathProof);
}




size_t CCrossCurveFCMPProof::GetProofSize() const
{
    size_t size = 0;
    size += 4;  // nVersion
    size += 4;  // nTreeDepth
    size += 4 + vchLeafCommit.size();
    size += 4 + vchRootCommit.size();
    size += 4;  // nLayers

    for (const auto& layer : vLayerProofs)
    {
        size += 4;  // curveType
        size += 4 + layer.vchCommitment.size();
        size += 4 + layer.vchReRandomizer.size();
        size += layer.ipaProof.GetProofSize();
    }

    size += 4 + vchBindingProof.size();
    return size;
}

static const char* V6_DOMAIN_LAYER = "Innova_FCMP_V6_Layer";
static const char* V6_DOMAIN_RERANDOMIZE = "Innova_FCMP_V6_ReRand";
static const char* V6_DOMAIN_BINDING = "Innova_FCMP_V6_Bind";

static bool CreateLayerCommitment(const std::vector<unsigned char>& childCommit,
                                   const std::vector<unsigned char>& siblingHash,
                                   int nLayer,
                                   const std::vector<unsigned char>& vchBlind,
                                   EIPACurveType curveType,
                                   std::vector<unsigned char>& commitOut)
{
    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, V6_DOMAIN_LAYER, strlen(V6_DOMAIN_LAYER));
    SHA256_Update(&sha, childCommit.data(), childCommit.size());
    SHA256_Update(&sha, siblingHash.data(), siblingHash.size());
    uint32_t layer = (uint32_t)nLayer;
    SHA256_Update(&sha, &layer, sizeof(layer));
    SHA256_Update(&sha, vchBlind.data(), vchBlind.size());

    unsigned char hash[32];
    SHA256_Final(hash, &sha);

    if (curveType == IPA_CURVE_SECP256K1)
    {
        std::vector<unsigned char> scalar(hash, hash + 32);
        std::vector<unsigned char> one(IPA_SCALAR_SIZE, 0);
        one[0] = 1;  // Use basepoint

        CIPAECGroupGuard group;
        CIPABNCtxGuard ctx;
        if (!group.group || !ctx.ctx) return false;

        CIPABNGuard bnScalar;
        CIPABNGuard order;
        EC_GROUP_get_order(group, order, ctx);
        BN_bin2bn(hash, 32, bnScalar);
        BN_mod(bnScalar, bnScalar, order, ctx);

        CIPAECPointGuard result(group);
        EC_POINT_mul(group, result, bnScalar, NULL, NULL, ctx);

        commitOut.resize(IPA_SECP256K1_POINT);
        EC_POINT_point2oct(group, result, POINT_CONVERSION_COMPRESSED,
                          commitOut.data(), IPA_SECP256K1_POINT, ctx);
    }
    else
    {
        std::vector<unsigned char> scalar(hash, hash + 32);
        if (!Ed25519BasePointMult(scalar, commitOut))
            return false;
    }

    return true;
}

static bool ReRandomizeCommitment(const std::vector<unsigned char>& commit,
                                   int nLayer,
                                   const std::vector<unsigned char>& vchBlind,
                                   EIPACurveType targetCurve,
                                   std::vector<unsigned char>& newCommitOut,
                                   std::vector<unsigned char>& rerandOut)
{
    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, V6_DOMAIN_RERANDOMIZE, strlen(V6_DOMAIN_RERANDOMIZE));
    SHA256_Update(&sha, commit.data(), commit.size());
    uint32_t layer = (uint32_t)nLayer;
    SHA256_Update(&sha, &layer, sizeof(layer));
    SHA256_Update(&sha, vchBlind.data(), vchBlind.size());

    unsigned char rerand[32];
    SHA256_Final(rerand, &sha);
    rerandOut.assign(rerand, rerand + 32);

    SHA256_Init(&sha);
    SHA256_Update(&sha, commit.data(), commit.size());
    SHA256_Update(&sha, rerand, 32);
    unsigned char newHash[32];
    SHA256_Final(newHash, &sha);

    if (targetCurve == IPA_CURVE_SECP256K1)
    {
        CIPAECGroupGuard group;
        CIPABNCtxGuard ctx;
        if (!group.group || !ctx.ctx) return false;

        CIPABNGuard bnScalar, order;
        EC_GROUP_get_order(group, order, ctx);
        BN_bin2bn(newHash, 32, bnScalar);
        BN_mod(bnScalar, bnScalar, order, ctx);

        CIPAECPointGuard result(group);
        EC_POINT_mul(group, result, bnScalar, NULL, NULL, ctx);

        newCommitOut.resize(IPA_SECP256K1_POINT);
        EC_POINT_point2oct(group, result, POINT_CONVERSION_COMPRESSED,
                          newCommitOut.data(), IPA_SECP256K1_POINT, ctx);
    }
    else
    {
        std::vector<unsigned char> scalar(newHash, newHash + 32);
        if (!Ed25519BasePointMult(scalar, newCommitOut))
            return false;
    }

    return true;
}

bool CreateFCMPProofV6(const std::vector<std::vector<unsigned char>>& vSiblings,
                        uint64_t nLeafIndex,
                        int nDepth,
                        const std::vector<unsigned char>& vchBlind,
                        const std::vector<unsigned char>& vchLeafData,
                        CCrossCurveFCMPProof& proofOut)
{
    if (vSiblings.size() != (size_t)nDepth || nDepth <= 0)
        return false;
    if (vchBlind.size() != IPA_SCALAR_SIZE)
        return false;

    proofOut.nVersion = CROSSCURVE_PROOF_VERSION;
    proofOut.nTreeDepth = nDepth;
    proofOut.vLayerProofs.resize(nDepth);

    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, "Innova_FCMP_V6_Leaf", 19);
    SHA256_Update(&sha, vchLeafData.data(), vchLeafData.size());
    SHA256_Update(&sha, vchBlind.data(), vchBlind.size());
    proofOut.vchLeafCommit.resize(32);
    SHA256_Final(proofOut.vchLeafCommit.data(), &sha);

    std::vector<unsigned char> currentCommit = proofOut.vchLeafCommit;

    for (int layer = 0; layer < nDepth; layer++)
    {
        EIPACurveType curveType = proofOut.GetLayerCurve(layer);
        CCrossCurveLayerProof& layerProof = proofOut.vLayerProofs[layer];
        layerProof.curveType = curveType;

        std::vector<unsigned char> layerBlind(IPA_SCALAR_SIZE);
        SHA256_Init(&sha);
        SHA256_Update(&sha, "Innova_FCMP_V6_LayerBlind", 25);
        SHA256_Update(&sha, vchBlind.data(), vchBlind.size());
        uint32_t l = (uint32_t)layer;
        SHA256_Update(&sha, &l, sizeof(l));
        SHA256_Final(layerBlind.data(), &sha);

        if (!CreateLayerCommitment(currentCommit, vSiblings[layer], layer,
                                    layerBlind, curveType, layerProof.vchCommitment))
            return false;

        if (layer > 0)
        {
            EIPACurveType prevCurve = proofOut.GetLayerCurve(layer - 1);
            if (prevCurve != curveType)
            {
                std::vector<unsigned char> rerandCommit;
                if (!ReRandomizeCommitment(currentCommit, layer, vchBlind,
                                           curveType, rerandCommit, layerProof.vchReRandomizer))
                    return false;
            }
        }

        int n = 2;
        CIPAGenerators gens;
        std::string domain = std::string(V6_DOMAIN_LAYER) + "_" + std::to_string(layer);
        if (!GenerateIPAGenerators(domain, n, curveType, gens))
            return false;

        std::vector<std::vector<unsigned char>> aVec(n), bVec(n);

        int bit = (nLeafIndex >> layer) & 1;

        aVec[0].resize(IPA_SCALAR_SIZE, 0);
        aVec[1].resize(IPA_SCALAR_SIZE, 0);
        aVec[bit][0] = 1;  // Set the chosen path to 1

        bVec[0].resize(IPA_SCALAR_SIZE);
        bVec[1].resize(IPA_SCALAR_SIZE);
        SHA256_Init(&sha);
        SHA256_Update(&sha, "V6_B0", 5);
        SHA256_Update(&sha, vSiblings[layer].data(), vSiblings[layer].size());
        SHA256_Final(bVec[0].data(), &sha);

        SHA256_Init(&sha);
        SHA256_Update(&sha, "V6_B1", 5);
        SHA256_Update(&sha, vSiblings[layer].data(), vSiblings[layer].size());
        SHA256_Update(&sha, &layer, sizeof(layer));
        SHA256_Final(bVec[1].data(), &sha);

        std::vector<unsigned char> z;
        if (!IPAInnerProduct(aVec, bVec, z, curveType))
            return false;

        CIPATranscript transcript(domain);
        transcript.AppendPoint(layerProof.vchCommitment);

        if (!CreateIPAProof(aVec, bVec, z, gens, transcript, layerProof.ipaProof))
            return false;

        currentCommit = layerProof.vchCommitment;
    }

    proofOut.vchRootCommit = currentCommit;

    SHA256_Init(&sha);
    SHA256_Update(&sha, V6_DOMAIN_BINDING, strlen(V6_DOMAIN_BINDING));
    SHA256_Update(&sha, proofOut.vchLeafCommit.data(), proofOut.vchLeafCommit.size());
    SHA256_Update(&sha, proofOut.vchRootCommit.data(), proofOut.vchRootCommit.size());
    for (const auto& layer : proofOut.vLayerProofs)
    {
        SHA256_Update(&sha, layer.vchCommitment.data(), layer.vchCommitment.size());
    }
    proofOut.vchBindingProof.resize(32);
    SHA256_Final(proofOut.vchBindingProof.data(), &sha);

    return true;
}

bool VerifyFCMPProofV6(const std::vector<unsigned char>& vchExpectedRoot,
                        const CCrossCurveFCMPProof& proof)
{
    if (proof.IsNull())
        return false;
    if (proof.nVersion != CROSSCURVE_PROOF_VERSION)
        return false;
    if (proof.vLayerProofs.size() != proof.nTreeDepth)
        return false;

    for (size_t layer = 0; layer < proof.vLayerProofs.size(); layer++)
    {
        const CCrossCurveLayerProof& layerProof = proof.vLayerProofs[layer];

        if ((layer % 2 == 1) && !layerProof.vchCommitment.empty())
        {
            std::vector<unsigned char> validatedPoint;
            if (!Ed25519PointFromBytes(layerProof.vchCommitment, validatedPoint, true))
                return false;
        }
    }

    std::vector<unsigned char> currentCommit = proof.vchLeafCommit;

    for (size_t layer = 0; layer < proof.vLayerProofs.size(); layer++)
    {
        const CCrossCurveLayerProof& layerProof = proof.vLayerProofs[layer];

        EIPACurveType expectedCurve = (layer % 2 == 0) ? IPA_CURVE_SECP256K1 : IPA_CURVE_ED25519;
        if (layerProof.curveType != expectedCurve)
            return false;

        int n = 2;
        std::string domain = std::string(V6_DOMAIN_LAYER) + "_" + std::to_string(layer);
        CIPAGenerators gens;
        if (!GenerateIPAGenerators(domain, n, layerProof.curveType, gens))
            return false;

        CIPATranscript transcript(domain);
        transcript.AppendPoint(layerProof.vchCommitment);

        if (!VerifyIPAProof(layerProof.vchCommitment, layerProof.ipaProof.vchAFinal,
                            gens, transcript, layerProof.ipaProof))
            return false;

        currentCommit = layerProof.vchCommitment;
    }

    if (!vchExpectedRoot.empty() && currentCommit != vchExpectedRoot)
        return false;

    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, V6_DOMAIN_BINDING, strlen(V6_DOMAIN_BINDING));
    SHA256_Update(&sha, proof.vchLeafCommit.data(), proof.vchLeafCommit.size());
    SHA256_Update(&sha, proof.vchRootCommit.data(), proof.vchRootCommit.size());
    for (const auto& layer : proof.vLayerProofs)
    {
        SHA256_Update(&sha, layer.vchCommitment.data(), layer.vchCommitment.size());
    }

    unsigned char expectedBinding[32];
    SHA256_Final(expectedBinding, &sha);

    if (proof.vchBindingProof.size() != 32 ||
        memcmp(proof.vchBindingProof.data(), expectedBinding, 32) != 0)
        return false;

    return true;
}

bool CreateFCMPProofV6Serialized(const std::vector<std::vector<unsigned char>>& vSiblings,
                                  uint64_t nLeafIndex,
                                  int nDepth,
                                  const std::vector<unsigned char>& vchBlind,
                                  const std::vector<unsigned char>& vchLeafData,
                                  std::vector<unsigned char>& proofOut)
{
    CCrossCurveFCMPProof proof;
    if (!CreateFCMPProofV6(vSiblings, nLeafIndex, nDepth, vchBlind, vchLeafData, proof))
        return false;

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);

    uint32_t version = FCMP_PROOF_VERSION_CROSSCURVE;
    ss << version;

    ss << proof;

    proofOut.assign(ss.begin(), ss.end());
    return true;
}

bool VerifyFCMPProofV6Serialized(const std::vector<unsigned char>& vchExpectedRoot,
                                  const std::vector<unsigned char>& proof)
{
    if (proof.size() < 4)
        return false;

    CDataStream ss(proof, SER_NETWORK, PROTOCOL_VERSION);

    uint32_t version;
    ss >> version;
    if (version != FCMP_PROOF_VERSION_CROSSCURVE)
        return false;

    CCrossCurveFCMPProof fcmpProof;
    ss >> fcmpProof;

    return VerifyFCMPProofV6(vchExpectedRoot, fcmpProof);
}
