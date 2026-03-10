// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "curvetree.h"
#include "ed25519_zk.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <string.h>
#include <string>



static const unsigned char ED25519_L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

static const unsigned char ED25519_L_MINUS_2[32] = {
    0xeb, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

static const unsigned char ED25519_BASEPOINT[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
};

static const unsigned char ED25519_IDENTITY[32] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};



class CBNGuardEd
{
public:
    BIGNUM* bn;
    CBNGuardEd() { bn = BN_new(); }
    ~CBNGuardEd() { if (bn) BN_clear_free(bn); }
    operator BIGNUM*() { return bn; }
    operator const BIGNUM*() const { return bn; }
};

class CBNCtxGuardEd
{
public:
    BN_CTX* ctx;
    CBNCtxGuardEd() { ctx = BN_CTX_new(); }
    ~CBNCtxGuardEd() { if (ctx) BN_CTX_free(ctx); }
    operator BN_CTX*() { return ctx; }
};



static void ReverseBytes(const unsigned char* in, unsigned char* out, size_t len)
{
    for (size_t i = 0; i < len; i++)
        out[i] = in[len - 1 - i];
}



bool Ed25519ScalarAdd(const std::vector<unsigned char>& a,
                      const std::vector<unsigned char>& b,
                      std::vector<unsigned char>& resultOut)
{
    if (a.size() != ED25519_SCALAR_SIZE || b.size() != ED25519_SCALAR_SIZE)
        return false;

    CBNCtxGuardEd ctx;
    if (!ctx.ctx) return false;

    unsigned char aBE[32], bBE[32], LBE[32];
    ReverseBytes(a.data(), aBE, 32);
    ReverseBytes(b.data(), bBE, 32);
    ReverseBytes(ED25519_L, LBE, 32);

    CBNGuardEd bnA, bnB, bnL, bnResult;
    BN_bin2bn(aBE, 32, bnA);
    BN_bin2bn(bBE, 32, bnB);
    BN_bin2bn(LBE, 32, bnL);

    BN_mod_add(bnResult, bnA, bnB, bnL, ctx);

    unsigned char resultBE[32];
    memset(resultBE, 0, 32);
    int nBytes = BN_num_bytes(bnResult);
    if (nBytes > 0)
        BN_bn2bin(bnResult, resultBE + (32 - nBytes));

    resultOut.resize(ED25519_SCALAR_SIZE);
    ReverseBytes(resultBE, resultOut.data(), 32);

    return true;
}

bool Ed25519ScalarMul(const std::vector<unsigned char>& a,
                      const std::vector<unsigned char>& b,
                      std::vector<unsigned char>& resultOut)
{
    if (a.size() != ED25519_SCALAR_SIZE || b.size() != ED25519_SCALAR_SIZE)
        return false;

    CBNCtxGuardEd ctx;
    if (!ctx.ctx) return false;

    unsigned char aBE[32], bBE[32], LBE[32];
    ReverseBytes(a.data(), aBE, 32);
    ReverseBytes(b.data(), bBE, 32);
    ReverseBytes(ED25519_L, LBE, 32);

    CBNGuardEd bnA, bnB, bnL, bnResult;
    BN_bin2bn(aBE, 32, bnA);
    BN_bin2bn(bBE, 32, bnB);
    BN_bin2bn(LBE, 32, bnL);

    BN_mod_mul(bnResult, bnA, bnB, bnL, ctx);

    unsigned char resultBE[32];
    memset(resultBE, 0, 32);
    int nBytes = BN_num_bytes(bnResult);
    if (nBytes > 0)
        BN_bn2bin(bnResult, resultBE + (32 - nBytes));

    resultOut.resize(ED25519_SCALAR_SIZE);
    ReverseBytes(resultBE, resultOut.data(), 32);

    return true;
}

bool Ed25519ScalarInv(const std::vector<unsigned char>& a,
                      std::vector<unsigned char>& resultOut)
{
    if (a.size() != ED25519_SCALAR_SIZE)
        return false;

    if (Ed25519ScalarIsZero(a))
        return false;

    CBNCtxGuardEd ctx;
    if (!ctx.ctx) return false;

    unsigned char aBE[32], LBE[32];
    ReverseBytes(a.data(), aBE, 32);
    ReverseBytes(ED25519_L, LBE, 32);

    CBNGuardEd bnA, bnL, bnResult;
    BN_bin2bn(aBE, 32, bnA);
    BN_bin2bn(LBE, 32, bnL);

    if (!BN_mod_inverse(bnResult, bnA, bnL, ctx))
        return false;

    unsigned char resultBE[32];
    memset(resultBE, 0, 32);
    int nBytes = BN_num_bytes(bnResult);
    if (nBytes > 0)
        BN_bn2bin(bnResult, resultBE + (32 - nBytes));

    resultOut.resize(ED25519_SCALAR_SIZE);
    ReverseBytes(resultBE, resultOut.data(), 32);

    return true;
}

bool Ed25519ScalarNeg(const std::vector<unsigned char>& a,
                      std::vector<unsigned char>& resultOut)
{
    if (a.size() != ED25519_SCALAR_SIZE)
        return false;

    resultOut.resize(ED25519_SCALAR_SIZE);
    int borrow = 0;
    for (size_t i = 0; i < ED25519_SCALAR_SIZE; i++)
    {
        int diff = (int)ED25519_L[i] - (int)a[i] - borrow;
        if (diff < 0)
        {
            diff += 256;
            borrow = 1;
        }
        else
        {
            borrow = 0;
        }
        resultOut[i] = (unsigned char)diff;
    }

    return true;
}

bool Ed25519ScalarReduce(const std::vector<unsigned char>& input,
                         std::vector<unsigned char>& resultOut)
{
    if (input.size() != 64)
        return false;

    CBNCtxGuardEd ctx;
    if (!ctx.ctx) return false;

    unsigned char inputBE[64], LBE[32];
    ReverseBytes(input.data(), inputBE, 64);
    ReverseBytes(ED25519_L, LBE, 32);

    CBNGuardEd bnInput, bnL, bnResult;
    BN_bin2bn(inputBE, 64, bnInput);
    BN_bin2bn(LBE, 32, bnL);

    BN_mod(bnResult, bnInput, bnL, ctx);

    unsigned char resultBE[32];
    memset(resultBE, 0, 32);
    int nBytes = BN_num_bytes(bnResult);
    if (nBytes > 0)
        BN_bn2bin(bnResult, resultBE + (32 - nBytes));

    resultOut.resize(ED25519_SCALAR_SIZE);
    ReverseBytes(resultBE, resultOut.data(), 32);

    return true;
}

bool Ed25519ScalarIsZero(const std::vector<unsigned char>& a)
{
    if (a.size() != ED25519_SCALAR_SIZE)
        return false;

    // CRYPTO-3: Constant-time zero check to prevent timing side-channel
    unsigned char acc = 0;
    for (size_t i = 0; i < ED25519_SCALAR_SIZE; i++)
        acc |= a[i];
    return acc == 0;
}



bool Ed25519BasePointMult(const std::vector<unsigned char>& scalar,
                          std::vector<unsigned char>& resultOut)
{
    std::vector<unsigned char> basepoint(ED25519_BASEPOINT,
                                          ED25519_BASEPOINT + ED25519_POINT_SIZE);
    return Ed25519ScalarMult(scalar, basepoint, resultOut);
}

bool Ed25519PointNeg(const std::vector<unsigned char>& point,
                     std::vector<unsigned char>& resultOut)
{
    if (point.size() != ED25519_POINT_SIZE)
        return false;

    resultOut = point;
    resultOut[31] ^= 0x80;
    return true;
}

bool Ed25519DoubleScalarMult(const std::vector<unsigned char>& s1,
                              const std::vector<unsigned char>& p1,
                              const std::vector<unsigned char>& s2,
                              std::vector<unsigned char>& resultOut)
{
    // Compute s1 * p1 + s2 * G_ed25519
    if (s1.size() != ED25519_SCALAR_SIZE || p1.size() != ED25519_POINT_SIZE || s2.size() != ED25519_SCALAR_SIZE)
        return false;

    std::vector<unsigned char> term1, term2;
    if (!Ed25519ScalarMult(s1, p1, term1))
        return false;

    if (!Ed25519BasePointMult(s2, term2))
        return false;

    if (!Ed25519PointAdd(term1, term2, resultOut))
        return false;

    return true;
}

bool Ed25519PointIsValid(const std::vector<unsigned char>& point)
{
    if (point.size() != ED25519_POINT_SIZE)
        return false;

    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                                   point.data(), point.size());
    if (!pkey) return false;
    EVP_PKEY_free(pkey);
    return true;
}

bool Ed25519PointIsIdentity(const std::vector<unsigned char>& point)
{
    if (point.size() != ED25519_POINT_SIZE)
        return false;

    return memcmp(point.data(), ED25519_IDENTITY, ED25519_POINT_SIZE) == 0;
}



bool Ed25519HashToPoint(const std::string& label,
                        std::vector<unsigned char>& resultOut)
{
    return Ed25519HashToPointFromBytes(
        (const unsigned char*)label.data(), label.size(), resultOut);
}

bool Ed25519HashToPointFromBytes(const unsigned char* data,
                                  size_t len,
                                  std::vector<unsigned char>& resultOut)
{

    for (uint32_t counter = 0; counter < 256; counter++)
    {
        SHA512_CTX ctx;
        unsigned char hash[64];

        SHA512_Init(&ctx);
        const char* domain = "Innova_Ed25519_HashToPoint_v1";
        SHA512_Update(&ctx, domain, strlen(domain));
        SHA512_Update(&ctx, data, len);
        SHA512_Update(&ctx, &counter, sizeof(counter));
        SHA512_Final(hash, &ctx);

        unsigned char candidate[32];
        memcpy(candidate, hash, 32);
        candidate[31] &= 0x7F;

        EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                                       candidate, 32);
        if (pkey)
        {
            EVP_PKEY_free(pkey);

            resultOut.assign(candidate, candidate + 32);

            if (!Ed25519PointIsIdentity(resultOut))
                return true;
        }
    }

    return false;
}



bool Ed25519PedersenCommit(const std::vector<unsigned char>& value,
                            const std::vector<unsigned char>& blind,
                            const std::vector<unsigned char>& H,
                            std::vector<unsigned char>& commitOut)
{
    if (value.size() != ED25519_SCALAR_SIZE || blind.size() != ED25519_SCALAR_SIZE ||
        H.size() != ED25519_POINT_SIZE)
        return false;

    // Compute: blind * G_ed25519 + value * H
    std::vector<unsigned char> term1, term2;
    if (!Ed25519BasePointMult(blind, term1))
        return false;

    if (!Ed25519ScalarMult(value, H, term2))
        return false;

    if (!Ed25519PointAdd(term1, term2, commitOut))
        return false;

    return true;
}



void Ed25519GetBasepoint(std::vector<unsigned char>& pointOut)
{
    pointOut.assign(ED25519_BASEPOINT, ED25519_BASEPOINT + ED25519_POINT_SIZE);
}

void Ed25519GetIdentity(std::vector<unsigned char>& pointOut)
{
    pointOut.assign(ED25519_IDENTITY, ED25519_IDENTITY + ED25519_POINT_SIZE);
}
