// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "curvetree.h"
#include "ipa.h"
#include "hash.h"
#include "util.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <string.h>
#include <algorithm>

class CCTBNCtxGuard
{
public:
    BN_CTX* ctx;
    CCTBNCtxGuard() { ctx = BN_CTX_new(); }
    ~CCTBNCtxGuard() { if (ctx) BN_CTX_free(ctx); }
    operator BN_CTX*() { return ctx; }
};

class CCTECGroupGuard
{
public:
    EC_GROUP* group;
    CCTECGroupGuard() { group = EC_GROUP_new_by_curve_name(NID_secp256k1); }
    ~CCTECGroupGuard() { if (group) EC_GROUP_free(group); }
    operator EC_GROUP*() { return group; }
    operator const EC_GROUP*() const { return group; }
};

class CCTECPointGuard
{
public:
    EC_POINT* point;
    const EC_GROUP* group;
    CCTECPointGuard(const EC_GROUP* g) : group(g) { point = EC_POINT_new(group); }
    ~CCTECPointGuard() { if (point) EC_POINT_free(point); }
    operator EC_POINT*() { return point; }
    operator const EC_POINT*() const { return point; }
};


static bool GetEd25519FieldPrime(BIGNUM* p)
{
    BN_set_bit(p, 255);
    BIGNUM* nineteen = BN_new();
    BN_set_word(nineteen, 19);
    BN_sub(p, p, nineteen);
    BN_free(nineteen);
    return true;
}

static bool GetEd25519Order(std::vector<unsigned char>& vchOrder)
{
    static const unsigned char L[32] = {
        0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58,
        0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };
    vchOrder.assign(L, L + 32);
    return true;
}

static bool GetEd25519D(BIGNUM* d, const BIGNUM* p, BN_CTX* ctx)
{
    BIGNUM* num = BN_new();
    BIGNUM* den = BN_new();
    BIGNUM* den_inv = BN_new();

    BN_set_word(num, 121665);
    BN_set_negative(num, 1);
    BN_mod(num, num, p, ctx);

    BN_set_word(den, 121666);
    if (!BN_mod_inverse(den_inv, den, p, ctx))
    {
        BN_free(num);
        BN_free(den);
        BN_free(den_inv);
        return false;
    }

    BN_mod_mul(d, num, den_inv, p, ctx);

    BN_free(num);
    BN_free(den);
    BN_free(den_inv);
    return true;
}

static bool Ed25519RecoverX(const BIGNUM* y, int sign, BIGNUM* x,
                             const BIGNUM* p, const BIGNUM* d, BN_CTX* ctx)
{
    BIGNUM* y2 = BN_new();
    BIGNUM* num = BN_new();
    BIGNUM* den = BN_new();
    BIGNUM* den_inv = BN_new();
    BIGNUM* x2 = BN_new();
    BIGNUM* one = BN_new();

    BN_one(one);

    BN_mod_sqr(y2, y, p, ctx);

    BN_mod_sub(num, y2, one, p, ctx);

    BN_mod_mul(den, d, y2, p, ctx);
    BN_mod_add(den, den, one, p, ctx);

    BN_mod_inverse(den_inv, den, p, ctx);
    if (!den_inv)
    {
        BN_free(y2); BN_free(num); BN_free(den);
        BN_free(den_inv); BN_free(x2); BN_free(one);
        return false;
    }
    BN_mod_mul(x2, num, den_inv, p, ctx);

    BIGNUM* exp = BN_new();
    BIGNUM* three = BN_new();
    BIGNUM* eight = BN_new();

    BN_copy(exp, p);
    BN_set_word(three, 3);
    BN_add(exp, exp, three);
    BN_set_word(eight, 8);
    BN_div(exp, NULL, exp, eight, ctx);

    BN_mod_exp(x, x2, exp, p, ctx);

    BIGNUM* check = BN_new();
    BN_mod_sqr(check, x, p, ctx);
    if (BN_cmp(check, x2) != 0)
    {
        BIGNUM* sqrtm1_exp = BN_new();
        BIGNUM* sqrtm1 = BN_new();

        BN_copy(sqrtm1_exp, p);
        BN_sub_word(sqrtm1_exp, 1);
        BIGNUM* four = BN_new();
        BN_set_word(four, 4);
        BN_div(sqrtm1_exp, NULL, sqrtm1_exp, four, ctx);

        BIGNUM* two = BN_new();
        BN_set_word(two, 2);
        BN_mod_exp(sqrtm1, two, sqrtm1_exp, p, ctx);

        BN_mod_mul(x, x, sqrtm1, p, ctx);

        BN_mod_sqr(check, x, p, ctx);
        if (BN_cmp(check, x2) != 0)
        {
            BN_free(y2); BN_free(num); BN_free(den);
            BN_free(den_inv); BN_free(x2); BN_free(one);
            BN_free(exp); BN_free(three); BN_free(eight);
            BN_free(check); BN_free(sqrtm1_exp); BN_free(sqrtm1);
            BN_free(four); BN_free(two);
            return false;
        }

        BN_free(sqrtm1_exp); BN_free(sqrtm1);
        BN_free(four); BN_free(two);
    }

    if (BN_is_odd(x) != sign)
    {
        BN_sub(x, p, x);
    }

    BN_free(y2); BN_free(num); BN_free(den);
    BN_free(den_inv); BN_free(x2); BN_free(one);
    BN_free(exp); BN_free(three); BN_free(eight);
    BN_free(check);

    return true;
}

static bool Ed25519IsOnCurve(const BIGNUM* x, const BIGNUM* y,
                              const BIGNUM* p, const BIGNUM* d, BN_CTX* ctx)
{
    BIGNUM* x2 = BN_new();
    BIGNUM* y2 = BN_new();
    BIGNUM* lhs = BN_new();
    BIGNUM* rhs = BN_new();
    BIGNUM* tmp = BN_new();
    BIGNUM* one = BN_new();
    BN_one(one);

    BN_mod_sqr(x2, x, p, ctx);
    BN_mod_sqr(y2, y, p, ctx);

    BN_mod_sub(lhs, y2, x2, p, ctx);

    BN_mod_mul(tmp, x2, y2, p, ctx);
    BN_mod_mul(tmp, d, tmp, p, ctx);
    BN_mod_add(rhs, one, tmp, p, ctx);

    bool fResult = (BN_cmp(lhs, rhs) == 0);

    BN_free(x2); BN_free(y2); BN_free(lhs);
    BN_free(rhs); BN_free(tmp); BN_free(one);
    return fResult;
}


bool Ed25519PointFromBytes(const std::vector<unsigned char>& vch,
                            std::vector<unsigned char>& pointOut,
                            bool fRejectTorsion)
{
    if (vch.size() != ED25519_POINT_SIZE)
        return false;

    CCTBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    BIGNUM* p = BN_new();
    BIGNUM* d = BN_new();
    GetEd25519FieldPrime(p);
    GetEd25519D(d, p, ctx);

    std::vector<unsigned char> yBytes(vch);
    int xSign = (yBytes[31] >> 7) & 1;
    yBytes[31] &= 0x7F;

    BIGNUM* y = BN_new();
    std::vector<unsigned char> yBE(32);
    for (int i = 0; i < 32; i++)
        yBE[i] = yBytes[31 - i];
    BN_bin2bn(yBE.data(), 32, y);

    if (BN_cmp(y, p) >= 0)
    {
        BN_free(p); BN_free(d); BN_free(y);
        return false;
    }

    BIGNUM* x = BN_new();
    if (!Ed25519RecoverX(y, xSign, x, p, d, ctx))
    {
        BN_free(p); BN_free(d); BN_free(y); BN_free(x);
        return false;
    }

    if (!Ed25519IsOnCurve(x, y, p, d, ctx))
    {
        BN_free(p); BN_free(d); BN_free(y); BN_free(x);
        return false;
    }

    BN_free(p); BN_free(d); BN_free(y); BN_free(x);

    if (fRejectTorsion)
    {
        std::vector<unsigned char> vchOrder;
        GetEd25519Order(vchOrder);

        std::vector<unsigned char> vchCheck;
        if (!Ed25519ScalarMult(vchOrder, vch, vchCheck))
            return false;

        std::vector<unsigned char> identity(32, 0);
        identity[0] = 0x01;
        if (vchCheck != identity)
            return false;
    }

    pointOut = vch;
    return true;
}

bool Ed25519PointToBytes(const std::vector<unsigned char>& point,
                          std::vector<unsigned char>& vchOut)
{
    if (point.size() != ED25519_POINT_SIZE)
        return false;
    vchOut = point;
    return true;
}

bool Ed25519PointAdd(const std::vector<unsigned char>& vchA,
                      const std::vector<unsigned char>& vchB,
                      std::vector<unsigned char>& vchResultOut)
{
    if (vchA.size() != ED25519_POINT_SIZE || vchB.size() != ED25519_POINT_SIZE)
        return false;

    CCTBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    BIGNUM* p = BN_new();
    BIGNUM* d = BN_new();
    GetEd25519FieldPrime(p);
    GetEd25519D(d, p, ctx);

    auto decodePoint = [&](const std::vector<unsigned char>& vch,
                            BIGNUM* x, BIGNUM* y) -> bool
    {
        std::vector<unsigned char> yBytes(vch);
        int xSign = (yBytes[31] >> 7) & 1;
        yBytes[31] &= 0x7F;

        std::vector<unsigned char> yBE(32);
        for (int i = 0; i < 32; i++)
            yBE[i] = yBytes[31 - i];
        BN_bin2bn(yBE.data(), 32, y);

        if (BN_cmp(y, p) >= 0) return false;
        return Ed25519RecoverX(y, xSign, x, p, d, ctx);
    };

    BIGNUM* x1 = BN_new(); BIGNUM* y1 = BN_new();
    BIGNUM* x2 = BN_new(); BIGNUM* y2 = BN_new();

    if (!decodePoint(vchA, x1, y1) || !decodePoint(vchB, x2, y2))
    {
        BN_free(x1); BN_free(y1); BN_free(x2); BN_free(y2);
        BN_free(p); BN_free(d);
        return false;
    }

    BIGNUM* x1y2 = BN_new(); BIGNUM* y1x2 = BN_new();
    BIGNUM* y1y2 = BN_new(); BIGNUM* x1x2 = BN_new();
    BIGNUM* dxy = BN_new();
    BIGNUM* one = BN_new(); BN_one(one);

    BN_mod_mul(x1y2, x1, y2, p, ctx);
    BN_mod_mul(y1x2, y1, x2, p, ctx);
    BN_mod_mul(y1y2, y1, y2, p, ctx);
    BN_mod_mul(x1x2, x1, x2, p, ctx);

    BN_mod_mul(dxy, d, x1x2, p, ctx);
    BN_mod_mul(dxy, dxy, y1y2, p, ctx);

    BIGNUM* num_x = BN_new();
    BIGNUM* den_x = BN_new();
    BIGNUM* den_x_inv = BN_new();
    BIGNUM* x3 = BN_new();

    BN_mod_add(num_x, x1y2, y1x2, p, ctx);
    BN_mod_add(den_x, one, dxy, p, ctx);
    if (!BN_mod_inverse(den_x_inv, den_x, p, ctx))
    {
        BN_free(x1); BN_free(y1); BN_free(x2); BN_free(y2);
        BN_free(x1y2); BN_free(y1x2); BN_free(y1y2); BN_free(x1x2);
        BN_free(dxy); BN_free(one);
        BN_free(num_x); BN_free(den_x); BN_free(den_x_inv); BN_free(x3);
        BN_free(p); BN_free(d);
        return false;
    }
    BN_mod_mul(x3, num_x, den_x_inv, p, ctx);

    BIGNUM* num_y = BN_new();
    BIGNUM* den_y = BN_new();
    BIGNUM* den_y_inv = BN_new();
    BIGNUM* y3 = BN_new();

    BN_mod_add(num_y, y1y2, x1x2, p, ctx);
    BN_mod_sub(den_y, one, dxy, p, ctx);
    if (!BN_mod_inverse(den_y_inv, den_y, p, ctx))
    {
        BN_free(x1); BN_free(y1); BN_free(x2); BN_free(y2);
        BN_free(x1y2); BN_free(y1x2); BN_free(y1y2); BN_free(x1x2);
        BN_free(dxy); BN_free(one);
        BN_free(num_x); BN_free(den_x); BN_free(den_x_inv); BN_free(x3);
        BN_free(num_y); BN_free(den_y); BN_free(den_y_inv); BN_free(y3);
        BN_free(p); BN_free(d);
        return false;
    }
    BN_mod_mul(y3, num_y, den_y_inv, p, ctx);

    vchResultOut.resize(ED25519_POINT_SIZE);
    unsigned char yBuf[32];
    memset(yBuf, 0, 32);
    int nBytes = BN_num_bytes(y3);
    if (nBytes > 0) BN_bn2bin(y3, yBuf + (32 - nBytes));

    for (int i = 0; i < 32; i++)
        vchResultOut[i] = yBuf[31 - i];

    if (BN_is_odd(x3))
        vchResultOut[31] |= 0x80;

    BN_free(x1); BN_free(y1); BN_free(x2); BN_free(y2);
    BN_free(x1y2); BN_free(y1x2); BN_free(y1y2); BN_free(x1x2);
    BN_free(dxy); BN_free(one);
    BN_free(num_x); BN_free(den_x); BN_free(den_x_inv); BN_free(x3);
    BN_free(num_y); BN_free(den_y); BN_free(den_y_inv); BN_free(y3);
    BN_free(p); BN_free(d);

    return true;
}

bool Ed25519ScalarMult(const std::vector<unsigned char>& vchScalar,
                        const std::vector<unsigned char>& vchPoint,
                        std::vector<unsigned char>& vchResultOut)
{
    if (vchScalar.size() != 32 || vchPoint.size() != ED25519_POINT_SIZE)
        return false;

    volatile unsigned char vPreload = 0;
    for (size_t i = 0; i < vchScalar.size(); i++)
        vPreload |= vchScalar[i];
    (void)vPreload;

    std::vector<unsigned char> R0(32, 0);
    R0[0] = 0x01;

    std::vector<unsigned char> R1 = vchPoint;

    for (int i = 255; i >= 0; i--)
    {
        int byteIdx = i / 8;
        int bitIdx = i % 8;
        int bit = (vchScalar[byteIdx] >> bitIdx) & 1;

        std::vector<unsigned char> sum, dbl0, dbl1;

        if (!Ed25519PointAdd(R0, R1, sum))
            return false;
        if (!Ed25519PointAdd(R0, R0, dbl0))
            return false;
        if (!Ed25519PointAdd(R1, R1, dbl1))
            return false;

        unsigned char mask = -(unsigned char)bit;

        std::vector<unsigned char> newR0(32), newR1(32);
        for (int j = 0; j < 32; j++)
        {
            newR0[j] = (dbl0[j] & ~mask) | (sum[j] & mask);
            newR1[j] = (sum[j] & ~mask) | (dbl1[j] & mask);
        }
        R0 = newR0;
        R1 = newR1;
    }

    vchResultOut = R0;
    return true;
}


uint256 CCurveTreeNode::GetHash() const
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << (uint8_t)0x60;
    ss << (uint8_t)curveType;
    ss << nDepth;
    for (size_t i = 0; i < vchPoint.size(); i++)
        ss << vchPoint[i];
    return ss.GetHash();
}


int CCurveTree::GetTreeDepth(uint64_t nLeaves)
{
    if (nLeaves <= 1) return 1;

    int nDepth = 0;
    uint64_t capacity = 1;
    while (capacity < nLeaves)
    {
        capacity *= CURVE_TREE_ARITY;
        nDepth++;
        if (nDepth >= CURVE_TREE_MAX_DEPTH)
            break;
    }
    return nDepth;
}

uint256 CCurveTree::GetRoot() const
{
    CCurveTreeNode rootNode = GetRootNode();
    if (rootNode.IsNull())
        return uint256(0);
    return rootNode.GetHash();
}

CCurveTreeNode CCurveTree::GetRootNode() const
{
    if (nLeafCount == 0 || vLevels.empty())
    {
        CCurveTreeNode empty;
        return empty;
    }

    for (int i = (int)vLevels.size() - 1; i >= 0; i--)
    {
        if (!vLevels[i].empty())
            return vLevels[i][0];
    }

    CCurveTreeNode empty;
    return empty;
}

CCurveTreeNode HashCurveTreeChildren(int nChildDepth,
                                      const std::vector<CCurveTreeNode>& vChildren)
{
    CCurveTreeNode parent;
    int nParentDepth = nChildDepth + 1;
    parent.nDepth = nParentDepth;
    parent.curveType = CCurveTreeNode::GetCurveAtDepth(nParentDepth);

    if (vChildren.empty())
        return parent;

    CHashWriter ss(SER_GETHASH, 0);
    ss << (uint8_t)0x61;
    ss << (int32_t)nParentDepth;
    ss << (uint32_t)vChildren.size();

    for (size_t i = 0; i < vChildren.size(); i++)
    {
        for (size_t j = 0; j < vChildren[i].vchPoint.size(); j++)
            ss << vChildren[i].vchPoint[j];
    }

    uint256 hash = ss.GetHash();

    if (parent.curveType == CURVE_SECP256K1)
    {
        CCTECGroupGuard group;
        CCTBNCtxGuard ctx;
        if (!group.group || !ctx.ctx)
            return parent;

        for (uint32_t counter = 0; counter < 256; counter++)
        {
            SHA256_CTX sha;
            SHA256_Init(&sha);
            SHA256_Update(&sha, hash.begin(), 32);
            unsigned char counterLE[4] = { (unsigned char)(counter & 0xFF), (unsigned char)((counter>>8) & 0xFF),
                                            (unsigned char)((counter>>16) & 0xFF), (unsigned char)((counter>>24) & 0xFF) };
            SHA256_Update(&sha, counterLE, 4);

            unsigned char xHash[32];
            SHA256_Final(xHash, &sha);

            unsigned char compressed[33];
            compressed[0] = 0x02;
            memcpy(compressed + 1, xHash, 32);

            CCTECPointGuard pt(group);
            if (EC_POINT_oct2point(group, pt, compressed, 33, ctx) == 1 &&
                EC_POINT_is_on_curve(group, pt, ctx) == 1)
            {
                parent.vchPoint.resize(SECP256K1_POINT_SIZE);
                EC_POINT_point2oct(group, pt, POINT_CONVERSION_COMPRESSED,
                                   parent.vchPoint.data(), SECP256K1_POINT_SIZE, ctx);
                break;
            }
        }
    }
    else // CURVE_ED25519
    {
        for (uint32_t counter = 0; counter < 256; counter++)
        {
            SHA256_CTX sha;
            SHA256_Init(&sha);
            SHA256_Update(&sha, hash.begin(), 32);
            unsigned char counterLE2[4] = { (unsigned char)(counter & 0xFF), (unsigned char)((counter>>8) & 0xFF),
                                             (unsigned char)((counter>>16) & 0xFF), (unsigned char)((counter>>24) & 0xFF) };
            SHA256_Update(&sha, counterLE2, 4);

            unsigned char yHash[32];
            SHA256_Final(yHash, &sha);

            yHash[31] &= 0x7F;

            std::vector<unsigned char> candidate(yHash, yHash + 32);
            std::vector<unsigned char> validated;
            if (Ed25519PointFromBytes(candidate, validated))
            {
                parent.vchPoint = validated;
                break;
            }
        }
    }

    return parent;
}

bool CCurveTree::InsertLeaf(const CPedersenCommitment& commitment)
{
    if (commitment.IsNull())
        return false;

    CCurveTreeNode leaf;
    leaf.nDepth = 0;
    leaf.curveType = CURVE_SECP256K1;
    leaf.vchPoint = commitment.vchCommitment;
    leaf.nIndex = nLeafCount;

    int nNeededDepth = GetTreeDepth(nLeafCount + 1);
    while ((int)vLevels.size() <= nNeededDepth)
        vLevels.push_back(std::vector<CCurveTreeNode>());

    if (leaf.nIndex < vLevels[0].size())
        vLevels[0][leaf.nIndex] = leaf;
    else
        vLevels[0].push_back(leaf);

    uint64_t idx = nLeafCount;
    for (int depth = 0; depth < nNeededDepth; depth++)
    {
        uint64_t parentIdx = idx / CURVE_TREE_ARITY;
        uint64_t childStart = parentIdx * CURVE_TREE_ARITY;
        uint64_t childEnd = std::min(childStart + CURVE_TREE_ARITY,
                                      (uint64_t)vLevels[depth].size());

        std::vector<CCurveTreeNode> children;
        for (uint64_t i = childStart; i < childEnd; i++)
            children.push_back(vLevels[depth][i]);

        CCurveTreeNode parent = HashCurveTreeChildren(depth, children);
        parent.nIndex = parentIdx;

        int parentLevel = depth + 1;
        if (parentLevel >= (int)vLevels.size())
            vLevels.push_back(std::vector<CCurveTreeNode>());

        if (parentIdx < vLevels[parentLevel].size())
            vLevels[parentLevel][parentIdx] = parent;
        else
        {
            while (vLevels[parentLevel].size() < parentIdx)
                vLevels[parentLevel].push_back(CCurveTreeNode());
            vLevels[parentLevel].push_back(parent);
        }

        idx = parentIdx;
    }

    nLeafCount++;
    return true;
}

bool CCurveTree::RebuildParentNodes()
{
    if (nLeafCount == 0 || vLevels.empty())
        return false;

    int nDepth = GetTreeDepth(nLeafCount);

    while ((int)vLevels.size() <= nDepth)
        vLevels.push_back(std::vector<CCurveTreeNode>());

    for (int d = 0; d < nDepth; d++)
    {
        int parentLevel = d + 1;
        uint64_t nNodes = vLevels[d].size();
        uint64_t nParents = (nNodes + CURVE_TREE_ARITY - 1) / CURVE_TREE_ARITY;

        vLevels[parentLevel].resize(nParents);

        for (uint64_t p = 0; p < nParents; p++)
        {
            uint64_t childStart = p * CURVE_TREE_ARITY;
            uint64_t childEnd = std::min(childStart + CURVE_TREE_ARITY, nNodes);

            std::vector<CCurveTreeNode> children;
            for (uint64_t i = childStart; i < childEnd; i++)
                children.push_back(vLevels[d][i]);

            CCurveTreeNode parent = HashCurveTreeChildren(d, children);
            parent.nIndex = p;
            vLevels[parentLevel][p] = parent;
        }
    }

    return true;
}

bool CCurveTree::GetMembershipProof(uint64_t nLeafIndex, CFCMPProof& proofOut) const
{
    if (nLeafIndex >= nLeafCount)
        return false;
    if (vLevels.empty())
        return false;

    proofOut.nLeafIndex = nLeafIndex;

    if (nLeafIndex < vLevels[0].size())
    {
        proofOut.leafCommitment.vchCommitment = vLevels[0][nLeafIndex].vchPoint;
    }

    proofOut.vchProof.clear();

    int nDepth = GetTreeDepth(nLeafCount);
    uint64_t idx = nLeafIndex;

    uint32_t uDepth = (uint32_t)nDepth;
    proofOut.vchProof.insert(proofOut.vchProof.end(),
                              (unsigned char*)&uDepth,
                              (unsigned char*)&uDepth + 4);

    for (int d = 0; d < nDepth; d++)
    {
        uint64_t parentIdx = idx / CURVE_TREE_ARITY;
        uint64_t childStart = parentIdx * CURVE_TREE_ARITY;
        uint64_t childEnd = std::min(childStart + CURVE_TREE_ARITY,
                                      (uint64_t)vLevels[d].size());

        uint32_t posInParent = (uint32_t)(idx - childStart);
        proofOut.vchProof.insert(proofOut.vchProof.end(),
                                  (unsigned char*)&posInParent,
                                  (unsigned char*)&posInParent + 4);

        uint32_t nSiblings = (uint32_t)(childEnd - childStart);
        proofOut.vchProof.insert(proofOut.vchProof.end(),
                                  (unsigned char*)&nSiblings,
                                  (unsigned char*)&nSiblings + 4);

        for (uint64_t i = childStart; i < childEnd; i++)
        {
            if (i == idx)
                continue;
            const CCurveTreeNode& sibling = vLevels[d][i];
            uint32_t ptSize = (uint32_t)sibling.vchPoint.size();
            proofOut.vchProof.insert(proofOut.vchProof.end(),
                                      (unsigned char*)&ptSize,
                                      (unsigned char*)&ptSize + 4);
            proofOut.vchProof.insert(proofOut.vchProof.end(),
                                      sibling.vchPoint.begin(),
                                      sibling.vchPoint.end());
        }

        idx = parentIdx;
    }

    if (proofOut.vchProof.size() > FCMP_PROOF_MAX_SIZE)
    {
        printf("GetMembershipProof: proof size %zu exceeds FCMP_PROOF_MAX_SIZE %zu\n",
               proofOut.vchProof.size(), FCMP_PROOF_MAX_SIZE);
        proofOut.vchProof.clear();
        return false;
    }

    return true;
}


bool CreateFCMPProof(const CCurveTree& tree,
                      uint64_t nLeafIndex,
                      const std::vector<unsigned char>& vchBlind,
                      const int64_t nValue,
                      const CPedersenCommitment& cv,
                      CFCMPProof& proofOut,
                      uint32_t nVersion)
{
    if (tree.IsEmpty()) return false;
    if (nLeafIndex >= tree.nLeafCount) return false;
    if (vchBlind.size() != BLINDING_FACTOR_SIZE) return false;

    if (nVersion < FCMP_PROOF_VERSION_LEGACY || nVersion > FCMP_PROOF_VERSION_IPA)
    {
        if (nVersion > FCMP_PROOF_VERSION_IPA)
            return false;
    }

    if (nVersion == FCMP_PROOF_VERSION_ENCRYPTED)
        return false;

    if (nVersion == FCMP_PROOF_VERSION_IPA)
    {
        CFCMPProof rawPath;
        if (!tree.GetMembershipProof(nLeafIndex, rawPath))
            return false;

        std::vector<std::vector<unsigned char>> vSiblings;
        if (rawPath.vchProof.size() < 4)
            return false;

        uint32_t depth = 0;
        memcpy(&depth, rawPath.vchProof.data(), 4);

        if (depth == 0 || depth > CURVE_TREE_MAX_DEPTH)
            return false;

        size_t offset = 4;
        for (uint32_t d = 0; d < depth; d++)
        {
            if (offset + 8 > rawPath.vchProof.size())
                return false;

            uint32_t posInParent = 0;
            memcpy(&posInParent, rawPath.vchProof.data() + offset, 4);
            offset += 4;

            uint32_t nSiblings = 0;
            memcpy(&nSiblings, rawPath.vchProof.data() + offset, 4);
            offset += 4;

            SHA256_CTX sha;
            SHA256_Init(&sha);
            SHA256_Update(&sha, "FCMPSiblingLevel", 16);
            SHA256_Update(&sha, &d, sizeof(d));

            uint32_t nExpectedSiblings = (nSiblings > 0) ? nSiblings - 1 : 0;
            for (uint32_t s = 0; s < nExpectedSiblings; s++)
            {
                if (offset + 4 > rawPath.vchProof.size())
                    return false;
                uint32_t ptSize = 0;
                memcpy(&ptSize, rawPath.vchProof.data() + offset, 4);
                offset += 4;

                if (ptSize > 128 || offset + ptSize > rawPath.vchProof.size())
                    return false;

                SHA256_Update(&sha, rawPath.vchProof.data() + offset, ptSize);
                offset += ptSize;
            }

            std::vector<unsigned char> levelHash(32);
            SHA256_Final(levelHash.data(), &sha);
            vSiblings.push_back(levelHash);
        }

        if (vSiblings.size() != depth)
            return false;

        std::vector<unsigned char> v5ProofData;
        if (!CreateFCMPProofV5(vSiblings, nLeafIndex, (int)depth, vchBlind,
                               cv.vchCommitment, v5ProofData))
            return false;
        proofOut.vchProof = v5ProofData;
        return true;
    }

    CFCMPProof rawPath;
    if (!tree.GetMembershipProof(nLeafIndex, rawPath))
        return false;

    unsigned char encryptionKey[32];

    if (nVersion >= FCMP_PROOF_VERSION_ENCRYPTED)
    {
        SHA256_CTX sha;
        SHA256_Init(&sha);
        const char* keyDomain = "Innova_FCMP_EncKey_v1";
        SHA256_Update(&sha, keyDomain, strlen(keyDomain));
        SHA256_Update(&sha, vchBlind.data(), vchBlind.size());
        SHA256_Update(&sha, &nLeafIndex, sizeof(nLeafIndex));
        SHA256_Final(encryptionKey, &sha);
    }
    else
    {
        if (RAND_bytes(encryptionKey, 32) != 1)
            return false;
    }

    SHA256_CTX sha;
    SHA256_Init(&sha);
    const char* domain = "Innova_FCMP_PathCommit_v1";
    SHA256_Update(&sha, domain, strlen(domain));
    SHA256_Update(&sha, encryptionKey, 32);
    SHA256_Update(&sha, rawPath.vchProof.data(), rawPath.vchProof.size());
    unsigned char pathCommitHash[32];
    SHA256_Final(pathCommitHash, &sha);

    uint256 rootHash = tree.GetRoot();

    unsigned char k[32];
    if (RAND_bytes(k, 32) != 1)
    {
        OPENSSL_cleanse(encryptionKey, 32);
        return false;
    }

    unsigned char nonceCommit[32];
    SHA256_Init(&sha);
    SHA256_Update(&sha, "Innova_FCMP_NonceCommit", 23);
    SHA256_Update(&sha, k, 32);
    SHA256_Update(&sha, pathCommitHash, 32);
    SHA256_Final(nonceCommit, &sha);

    unsigned char challenge[32];
    SHA256_Init(&sha);
    SHA256_Update(&sha, "Innova_FCMP_Challenge_v2", 24);
    SHA256_Update(&sha, rootHash.begin(), 32);
    SHA256_Update(&sha, pathCommitHash, 32);
    SHA256_Update(&sha, cv.vchCommitment.data(), cv.vchCommitment.size());
    SHA256_Final(challenge, &sha);

    unsigned char response[32];
    unsigned int hmacLen = 32;
    HMAC(EVP_sha256(), challenge, 32, encryptionKey, 32, response, &hmacLen);
    for (int i = 0; i < 32; i++)
        response[i] ^= k[i];

    std::vector<unsigned char> blindedPath(rawPath.vchProof.size());
    {
        for (size_t pos = 0; pos < rawPath.vchProof.size(); pos += 32)
        {
            unsigned char ctr[4];
            uint32_t nCtr = (uint32_t)(pos / 32);
            memcpy(ctr, &nCtr, 4);

            unsigned char maskBlock[32];
            unsigned int mLen = 32;
            HMAC(EVP_sha256(), encryptionKey, 32, ctr, 4, maskBlock, &mLen);

            size_t nCopy = std::min((size_t)32, rawPath.vchProof.size() - pos);
            for (size_t j = 0; j < nCopy; j++)
                blindedPath[pos + j] = rawPath.vchProof[pos + j] ^ maskBlock[j];
        }
    }

    proofOut.vchProof.clear();

    if (nVersion >= FCMP_PROOF_VERSION_ENCRYPTED)
    {
        proofOut.vchProof.reserve(4 + 32 + 4 + blindedPath.size() + 32 + 32 + 32);

        proofOut.vchProof.insert(proofOut.vchProof.end(), (unsigned char*)&nVersion, (unsigned char*)&nVersion + 4);
        proofOut.vchProof.insert(proofOut.vchProof.end(), rootHash.begin(), rootHash.begin() + 32);
        uint32_t nEncPathLen = (uint32_t)blindedPath.size();
        proofOut.vchProof.insert(proofOut.vchProof.end(), (unsigned char*)&nEncPathLen, (unsigned char*)&nEncPathLen + 4);
        proofOut.vchProof.insert(proofOut.vchProof.end(), blindedPath.begin(), blindedPath.end());
        proofOut.vchProof.insert(proofOut.vchProof.end(), pathCommitHash, pathCommitHash + 32);
        proofOut.vchProof.insert(proofOut.vchProof.end(), challenge, challenge + 32);
        proofOut.vchProof.insert(proofOut.vchProof.end(), response, response + 32);
    }
    else
    {
        // PRIV-AUDIT-6: Do NOT embed raw encryption key in proof (trivially recoverable)
        // Verifier derives the key from the commitment instead
        proofOut.vchProof.reserve(4 + 32 + 4 + blindedPath.size() + 32 + 32 + 32);

        proofOut.vchProof.insert(proofOut.vchProof.end(), (unsigned char*)&nVersion, (unsigned char*)&nVersion + 4);
        proofOut.vchProof.insert(proofOut.vchProof.end(), rootHash.begin(), rootHash.begin() + 32);
        uint32_t nBlindedPathLen = (uint32_t)blindedPath.size();
        proofOut.vchProof.insert(proofOut.vchProof.end(), (unsigned char*)&nBlindedPathLen, (unsigned char*)&nBlindedPathLen + 4);
        proofOut.vchProof.insert(proofOut.vchProof.end(), blindedPath.begin(), blindedPath.end());
        proofOut.vchProof.insert(proofOut.vchProof.end(), pathCommitHash, pathCommitHash + 32);
        proofOut.vchProof.insert(proofOut.vchProof.end(), challenge, challenge + 32);
        proofOut.vchProof.insert(proofOut.vchProof.end(), response, response + 32);
    }

    proofOut.nLeafIndex = nLeafIndex;

    OPENSSL_cleanse(encryptionKey, 32);
    OPENSSL_cleanse(k, 32);

    return true;
}

static bool VerifyRawAuthPath(const CCurveTreeNode& root,
                               const std::vector<unsigned char>& vchRawPath,
                               const CPedersenCommitment& cv)
{
    if (vchRawPath.size() < 4)
        return false;

    uint32_t nDepth;
    memcpy(&nDepth, vchRawPath.data(), 4);

    if (nDepth == 0 || nDepth > CURVE_TREE_MAX_DEPTH)
        return false;

    CCurveTreeNode current;
    current.nDepth = 0;
    current.curveType = CURVE_SECP256K1;
    current.vchPoint = cv.vchCommitment;

    size_t offset = 4;

    for (uint32_t d = 0; d < nDepth; d++)
    {
        if (offset + 8 > vchRawPath.size())
            return false;

        uint32_t posInParent;
        memcpy(&posInParent, vchRawPath.data() + offset, 4);
        offset += 4;

        uint32_t nSiblings;
        memcpy(&nSiblings, vchRawPath.data() + offset, 4);
        offset += 4;

        if (nSiblings == 0 || nSiblings > CURVE_TREE_ARITY)
            return false;
        if (posInParent >= nSiblings)
            return false;

        std::vector<CCurveTreeNode> children(nSiblings);
        for (uint32_t i = 0; i < nSiblings; i++)
        {
            if (i == posInParent)
            {
                children[i] = current;
            }
            else
            {
                if (offset + 4 > vchRawPath.size())
                    return false;

                uint32_t ptSize;
                memcpy(&ptSize, vchRawPath.data() + offset, 4);
                offset += 4;

                if (ptSize > 33 || offset + ptSize > vchRawPath.size())
                    return false;

                children[i].nDepth = d;
                children[i].curveType = CCurveTreeNode::GetCurveAtDepth(d);
                children[i].vchPoint.assign(
                    vchRawPath.data() + offset,
                    vchRawPath.data() + offset + ptSize);
                offset += ptSize;
            }
        }

        current = HashCurveTreeChildren(d, children);
    }

    return current.vchPoint == root.vchPoint;
}

bool VerifyFCMPProof(const CCurveTreeNode& root,
                      const CFCMPProof& proof,
                      const CPedersenCommitment& cv)
{
    if (proof.IsNull()) return false;
    if (proof.GetSize() > FCMP_PROOF_MAX_SIZE) return false;
    if (root.IsNull()) return false;
    if (cv.IsNull()) return false;

    const size_t MIN_HEADER_SIZE = 4 + 32 + 4;
    if (proof.vchProof.size() < MIN_HEADER_SIZE)
        return false;

    size_t offset = 0;

    uint32_t nVersion;
    memcpy(&nVersion, proof.vchProof.data() + offset, 4);
    offset += 4;

    if (nVersion < 2 || nVersion > FCMP_PROOF_VERSION_IPA)
        return false;

    if (nVersion == FCMP_PROOF_VERSION_IPA)
    {
        uint256 expectedRootHash = root.GetHash();
        std::vector<unsigned char> vchRoot(expectedRootHash.begin(), expectedRootHash.end());

        return VerifyFCMPProofV5(vchRoot, cv.vchCommitment, proof.vchProof);
    }

    uint256 proofRootHash;
    memcpy(proofRootHash.begin(), proof.vchProof.data() + offset, 32);
    offset += 32;

    uint256 expectedRootHash = root.GetHash();
    if (proofRootHash != expectedRootHash)
        return false;

    std::vector<unsigned char> vchRawPath;
    bool fCanVerifyPath = true;

    if (nVersion == FCMP_PROOF_VERSION_ENCRYPTED)
    {
        return false;
    }
    else if (nVersion == 3)
    {
        if (offset + 32 > proof.vchProof.size())
            return false;

        unsigned char nonce[32];
        memcpy(nonce, proof.vchProof.data() + offset, 32);
        offset += 32;

        if (offset + 4 > proof.vchProof.size())
            return false;

        uint32_t nBlindedPathLen;
        memcpy(&nBlindedPathLen, proof.vchProof.data() + offset, 4);
        offset += 4;

        if (nBlindedPathLen == 0 || nBlindedPathLen > FCMP_PROOF_MAX_SIZE || offset + nBlindedPathLen > proof.vchProof.size())
            return false;

        std::vector<unsigned char> blindedPath(proof.vchProof.data() + offset,
                                                proof.vchProof.data() + offset + nBlindedPathLen);
        offset += nBlindedPathLen;

        vchRawPath.resize(blindedPath.size());
        for (size_t pos = 0; pos < blindedPath.size(); pos += 32)
        {
            unsigned char ctr[4];
            uint32_t nCtr = (uint32_t)(pos / 32);
            memcpy(ctr, &nCtr, 4);

            unsigned char maskBlock[32];
            unsigned int mLen = 32;
            HMAC(EVP_sha256(), nonce, 32, ctr, 4, maskBlock, &mLen);

            size_t nCopy = std::min((size_t)32, blindedPath.size() - pos);
            for (size_t j = 0; j < nCopy; j++)
                vchRawPath[pos + j] = blindedPath[pos + j] ^ maskBlock[j];
        }
    }
    else // nVersion == 2 (legacy)
    {
        if (offset + 4 > proof.vchProof.size())
            return false;

        uint32_t nRawPathLen;
        memcpy(&nRawPathLen, proof.vchProof.data() + offset, 4);
        offset += 4;

        if (nRawPathLen == 0 || nRawPathLen > FCMP_PROOF_MAX_SIZE || offset + nRawPathLen > proof.vchProof.size())
            return false;

        vchRawPath.assign(proof.vchProof.data() + offset,
                          proof.vchProof.data() + offset + nRawPathLen);
        offset += nRawPathLen;
    }

    if (fCanVerifyPath)
    {
        if (!VerifyRawAuthPath(root, vchRawPath, cv))
        {
            if (fDebug)
                printf("VerifyFCMPProof: raw authentication path verification failed\n");
            return false;
        }
    }

    if (offset + 96 > proof.vchProof.size()) // 32+32+32 = 96
        return false;

    unsigned char pathCommitHash[32];
    memcpy(pathCommitHash, proof.vchProof.data() + offset, 32);
    offset += 32;

    unsigned char challenge[32];
    memcpy(challenge, proof.vchProof.data() + offset, 32);
    offset += 32;

    unsigned char response[32];
    memcpy(response, proof.vchProof.data() + offset, 32);
    offset += 32;

    unsigned char expectedChallenge[32];
    {
        SHA256_CTX sha;
        SHA256_Init(&sha);
        SHA256_Update(&sha, "Innova_FCMP_Challenge_v2", 24);
        SHA256_Update(&sha, proofRootHash.begin(), 32);
        SHA256_Update(&sha, pathCommitHash, 32);
        SHA256_Update(&sha, cv.vchCommitment.data(), cv.vchCommitment.size());
        SHA256_Final(expectedChallenge, &sha);
    }

    if (memcmp(challenge, expectedChallenge, 32) != 0)
        return false;

    bool fAllZero = true;
    for (int i = 0; i < 32; i++)
    {
        if (response[i] != 0)
        {
            fAllZero = false;
            break;
        }
    }
    if (fAllZero)
        return false;

    return true;
}

bool BatchVerifyFCMPProofs(const CCurveTreeNode& root,
                            const std::vector<CFCMPProof>& vProofs,
                            const std::vector<CPedersenCommitment>& vCommitments)
{
    if (vProofs.size() != vCommitments.size())
        return false;

    for (size_t i = 0; i < vProofs.size(); i++)
    {
        if (!VerifyFCMPProof(root, vProofs[i], vCommitments[i]))
            return false;
    }
    return true;
}

int64_t CCurveTree::FindLeafIndex(const CPedersenCommitment& cv) const
{
    if (vLevels.empty() || cv.IsNull())
        return -1;

    const std::vector<CCurveTreeNode>& leaves = vLevels[0];
    for (size_t i = 0; i < leaves.size(); i++)
    {
        if (leaves[i].vchPoint == cv.vchCommitment)
            return (int64_t)i;
    }
    return -1;
}
