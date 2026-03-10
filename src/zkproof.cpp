// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "zkproof.h"
#include "hash.h"
#include "util.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>
#include <string.h>

boost::once_flag CZKContext::initOnceFlag = BOOST_ONCE_INIT;
bool CZKContext::fInitialized = false;
bool CZKContext::fInitFailed = false;
CCriticalSection CZKContext::cs_zkcontext;
std::vector<unsigned char> CZKContext::vchGeneratorG;
std::vector<unsigned char> CZKContext::vchGeneratorH;

class CBNCtxGuard
{
public:
    BN_CTX* ctx;
    CBNCtxGuard() { ctx = BN_CTX_new(); }
    ~CBNCtxGuard() { if (ctx) BN_CTX_free(ctx); }
    operator BN_CTX*() { return ctx; }
};

class CECGroupGuard
{
public:
    EC_GROUP* group;
    CECGroupGuard() { group = EC_GROUP_new_by_curve_name(NID_secp256k1); }
    ~CECGroupGuard() { if (group) EC_GROUP_free(group); }
    operator EC_GROUP*() { return group; }
    operator const EC_GROUP*() const { return group; }
};

class CECPointGuard
{
public:
    EC_POINT* point;
    const EC_GROUP* group;
    CECPointGuard(const EC_GROUP* g) : group(g) { point = EC_POINT_new(group); }
    ~CECPointGuard() { if (point) EC_POINT_free(point); }
    operator EC_POINT*() { return point; }
    operator const EC_POINT*() const { return point; }
};

class CBNGuard
{
public:
    BIGNUM* bn;
    CBNGuard() { bn = BN_new(); }
    CBNGuard(int64_t val) { bn = BN_new(); BN_set_word(bn, (unsigned long)(val < 0 ? -val : val)); if (val < 0) BN_set_negative(bn, 1); }
    ~CBNGuard() { if (bn) BN_clear_free(bn); }
    operator BIGNUM*() { return bn; }
    operator const BIGNUM*() const { return bn; }
};

static inline void BN_set_consttime(BIGNUM* bn)
{
    if (bn) BN_set_flags(bn, BN_FLG_CONSTTIME);
}

static BIGNUM* BN_dup_consttime(const BIGNUM* src)
{
    BIGNUM* dst = BN_dup(src);
    if (dst) BN_set_flags(dst, BN_FLG_CONSTTIME);
    return dst;
}

static bool PointToBytes(const EC_GROUP* group, const EC_POINT* point,
                          std::vector<unsigned char>& vchOut, BN_CTX* ctx)
{
    size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED,
                                     NULL, 0, ctx);
    if (len == 0) return false;

    vchOut.resize(len);
    size_t written = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED,
                                         vchOut.data(), len, ctx);
    return written == len;
}

static bool BytesToPoint(const EC_GROUP* group, const std::vector<unsigned char>& vch,
                          EC_POINT* point, BN_CTX* ctx)
{
    if (vch.size() < 33) return false;
    if (EC_POINT_oct2point(group, point, vch.data(), vch.size(), ctx) != 1)
        return false;
    if (EC_POINT_is_at_infinity(group, point))
        return false;
    return true;
}

static bool HashToPoint(const EC_GROUP* group, const char* tag,
                         EC_POINT* point, BN_CTX* ctx)
{
    for (uint32_t counter = 0; counter < 256; counter++)
    {
        SHA256_CTX sha;
        SHA256_Init(&sha);
        SHA256_Update(&sha, tag, strlen(tag));
        // CRYPTO-10: Use little-endian encoding for cross-platform consensus
        unsigned char counterLE[4];
        counterLE[0] = (counter >>  0) & 0xFF;
        counterLE[1] = (counter >>  8) & 0xFF;
        counterLE[2] = (counter >> 16) & 0xFF;
        counterLE[3] = (counter >> 24) & 0xFF;
        SHA256_Update(&sha, counterLE, 4);

        unsigned char hash[32];
        SHA256_Final(hash, &sha);

        BIGNUM* x = BN_bin2bn(hash, 32, NULL);
        if (!x) continue;

        BIGNUM* field_p = BN_new();
        EC_GROUP_get_curve(group, field_p, NULL, NULL, ctx);

        if (BN_cmp(x, field_p) >= 0)
        {
            BN_free(x);
            BN_free(field_p);
            continue;
        }
        BN_free(field_p);

        unsigned char compressed[33];
        compressed[0] = 0x02;
        BN_bn2bin(x, compressed + 1 + (32 - BN_num_bytes(x)));
        if (BN_num_bytes(x) < 32)
            memset(compressed + 1, 0, 32 - BN_num_bytes(x));

        BN_free(x);

        if (EC_POINT_oct2point(group, point, compressed, 33, ctx) == 1)
        {
            if (EC_POINT_is_on_curve(group, point, ctx) == 1)
            {
                OPENSSL_cleanse(hash, 32);
                return true;
            }
        }
    }

    return false;
}

void CZKContext::DoInitialize()
{
    CECGroupGuard group;
    if (!group.group) { fInitFailed = true; return; }

    CBNCtxGuard ctx;
    if (!ctx.ctx) { fInitFailed = true; return; }

    const EC_POINT* G = EC_GROUP_get0_generator(group);
    if (!G) { fInitFailed = true; return; }
    if (!PointToBytes(group, G, vchGeneratorG, ctx)) { fInitFailed = true; return; }

    CECPointGuard H(group);
    if (!HashToPoint(group, "Innova_Pedersen_Generator_H_v1", H, ctx))
    {
        fInitFailed = true;
        return;
    }
    if (!PointToBytes(group, H, vchGeneratorH, ctx)) { fInitFailed = true; return; }

    fInitialized = true;
    printf("ZK proof context initialized (secp256k1, Pedersen + Bulletproofs)\n");
}

bool CZKContext::Initialize()
{
    boost::call_once(initOnceFlag, &CZKContext::DoInitialize);

    LOCK(cs_zkcontext);
    return fInitialized && !fInitFailed;
}

void CZKContext::Shutdown()
{
    LOCK(cs_zkcontext);
    vchGeneratorG.clear();
    vchGeneratorH.clear();
    fInitialized = false;
}

bool CZKContext::IsInitialized()
{
    LOCK(cs_zkcontext);
    return fInitialized;
}

const std::vector<unsigned char>& CZKContext::GetGeneratorG()
{
    return vchGeneratorG;
}

const std::vector<unsigned char>& CZKContext::GetGeneratorH()
{
    return vchGeneratorH;
}


bool CPedersenCommitment::IsNull() const
{
    for (size_t i = 0; i < vchCommitment.size(); i++)
        if (vchCommitment[i] != 0) return false;
    return true;
}

uint256 CPedersenCommitment::GetHash() const
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << (uint8_t)0x30;
    for (size_t i = 0; i < vchCommitment.size(); i++)
        ss << vchCommitment[i];
    return ss.GetHash();
}

bool CreatePedersenCommitment(int64_t nValue,
                               const std::vector<unsigned char>& vchBlind,
                               CPedersenCommitment& commitOut)
{
    if (!CZKContext::IsInitialized()) return false;
    if (vchBlind.size() != BLINDING_FACTOR_SIZE) return false;
    if (nValue < 0) return false;
    static const int64_t ZK_MAX_VALUE = 1800000000000000LL;
    if (nValue > ZK_MAX_VALUE) return false;

    CECGroupGuard group;
    if (!group.group) return false;

    CBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    CECPointGuard G(group), H(group);
    if (!BytesToPoint(group, CZKContext::GetGeneratorG(), G, ctx)) return false;
    if (!BytesToPoint(group, CZKContext::GetGeneratorH(), H, ctx)) return false;

    unsigned char valBytes[8];
    for (int i = 7; i >= 0; i--) { valBytes[7-i] = (unsigned char)((uint64_t)nValue >> (i*8)); }
    BIGNUM* bnValue = BN_bin2bn(valBytes, 8, NULL);
    if (!bnValue) return false;

    BIGNUM* bnBlind = BN_bin2bn(vchBlind.data(), vchBlind.size(), NULL);
    if (!bnBlind) return false;

    BN_set_consttime(bnValue);
    BN_set_consttime(bnBlind);

    const BIGNUM* order = EC_GROUP_get0_order(group);
    BN_mod(bnBlind, bnBlind, order, ctx);

    if (BN_is_zero(bnBlind))
    {
        BN_free(bnValue); BN_clear_free(bnBlind);
        return false;
    }

    CECPointGuard vH(group), rG(group), C(group);

    if (EC_POINT_mul(group, vH, NULL, H, bnValue, ctx) != 1)
    {
        BN_free(bnValue); BN_clear_free(bnBlind);
        return false;
    }

    if (EC_POINT_mul(group, rG, NULL, G, bnBlind, ctx) != 1)
    {
        BN_free(bnValue); BN_clear_free(bnBlind);
        return false;
    }

    if (EC_POINT_add(group, C, vH, rG, ctx) != 1)
    {
        BN_free(bnValue); BN_clear_free(bnBlind);
        return false;
    }

    BN_free(bnValue);
    BN_clear_free(bnBlind);

    return PointToBytes(group, C, commitOut.vchCommitment, ctx);
}

bool VerifyPedersenCommitment(const CPedersenCommitment& commit,
                               int64_t nValue,
                               const std::vector<unsigned char>& vchBlind)
{
    if (vchBlind.size() == BLINDING_FACTOR_SIZE)
    {
        bool fAllZero = true;
        for (size_t i = 0; i < vchBlind.size(); i++)
        {
            if (vchBlind[i] != 0) { fAllZero = false; break; }
        }
        if (fAllZero) return false;
    }

    CPedersenCommitment expected;
    if (!CreatePedersenCommitment(nValue, vchBlind, expected))
        return false;
    return commit.vchCommitment == expected.vchCommitment;
}

bool CreateBlindCommitment(const std::vector<unsigned char>& vchBlind,
                            CPedersenCommitment& commitOut)
{
    return CreatePedersenCommitment(0, vchBlind, commitOut);
}

bool GenerateBlindingFactor(std::vector<unsigned char>& vchBlindOut)
{
    vchBlindOut.resize(BLINDING_FACTOR_SIZE);
    if (RAND_bytes(vchBlindOut.data(), BLINDING_FACTOR_SIZE) != 1)
        return false;

    CECGroupGuard group;
    if (!group.group) return false;

    const BIGNUM* order = EC_GROUP_get0_order(group);
    BIGNUM* bn = BN_bin2bn(vchBlindOut.data(), BLINDING_FACTOR_SIZE, NULL);
    if (!bn) return false;

    CBNCtxGuard ctx;
    BN_mod(bn, bn, order, ctx);

    if (BN_is_zero(bn))
    {
        BN_clear_free(bn);
        return false;
    }

    memset(vchBlindOut.data(), 0, BLINDING_FACTOR_SIZE);
    int nBytes = BN_num_bytes(bn);
    BN_bn2bin(bn, vchBlindOut.data() + (BLINDING_FACTOR_SIZE - nBytes));
    BN_clear_free(bn);

    return true;
}

bool AddCommitments(const CPedersenCommitment& a,
                     const CPedersenCommitment& b,
                     CPedersenCommitment& resultOut)
{
    if (!CZKContext::IsInitialized()) return false;

    CECGroupGuard group;
    if (!group.group) return false;

    CBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    CECPointGuard pA(group), pB(group), pResult(group);
    if (!BytesToPoint(group, a.vchCommitment, pA, ctx)) return false;
    if (!BytesToPoint(group, b.vchCommitment, pB, ctx)) return false;

    if (EC_POINT_add(group, pResult, pA, pB, ctx) != 1) return false;

    return PointToBytes(group, pResult, resultOut.vchCommitment, ctx);
}

bool SubtractCommitments(const CPedersenCommitment& a,
                          const CPedersenCommitment& b,
                          CPedersenCommitment& resultOut)
{
    if (!CZKContext::IsInitialized()) return false;

    CECGroupGuard group;
    if (!group.group) return false;

    CBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    CECPointGuard pA(group), pB(group), pNegB(group), pResult(group);
    if (!BytesToPoint(group, a.vchCommitment, pA, ctx)) return false;
    if (!BytesToPoint(group, b.vchCommitment, pB, ctx)) return false;

    EC_POINT_copy(pNegB, pB);
    if (EC_POINT_invert(group, pNegB, ctx) != 1) return false;

    if (EC_POINT_add(group, pResult, pA, pNegB, ctx) != 1) return false;

    return PointToBytes(group, pResult, resultOut.vchCommitment, ctx);
}

bool VerifyCommitmentBalance(const std::vector<CPedersenCommitment>& vInputCommits,
                              const std::vector<CPedersenCommitment>& vOutputCommits,
                              int64_t nFee)
{
    if (!CZKContext::IsInitialized()) return false;
    if (nFee < 0) return false;

    CECGroupGuard group;
    if (!group.group) return false;

    CBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    CECPointGuard sumIn(group);
    EC_POINT_set_to_infinity(group, sumIn);

    for (size_t i = 0; i < vInputCommits.size(); i++)
    {
        CECPointGuard p(group);
        if (!BytesToPoint(group, vInputCommits[i].vchCommitment, p, ctx)) return false;
        if (EC_POINT_add(group, sumIn, sumIn, p, ctx) != 1) return false;
    }

    CECPointGuard sumOut(group);
    EC_POINT_set_to_infinity(group, sumOut);

    for (size_t i = 0; i < vOutputCommits.size(); i++)
    {
        CECPointGuard p(group);
        if (!BytesToPoint(group, vOutputCommits[i].vchCommitment, p, ctx)) return false;
        if (EC_POINT_add(group, sumOut, sumOut, p, ctx) != 1) return false;
    }

    if (nFee > 0)
    {
        CECPointGuard H(group), feeH(group);
        if (!BytesToPoint(group, CZKContext::GetGeneratorH(), H, ctx)) return false;

        CBNGuard bnFee;
        { unsigned char fb[8]; for(int i=7;i>=0;i--) fb[7-i]=(unsigned char)((uint64_t)nFee>>(i*8)); BN_bin2bn(fb,8,bnFee); }

        if (EC_POINT_mul(group, feeH, NULL, H, bnFee, ctx) != 1) return false;
        if (EC_POINT_add(group, sumOut, sumOut, feeH, ctx) != 1) return false;
    }

    return EC_POINT_cmp(group, sumIn, sumOut, ctx) == 0;
}


static bool ScalarPowers(const BIGNUM* base, int n, const BIGNUM* order,
                          std::vector<BIGNUM*>& powersOut, BN_CTX* ctx)
{
    powersOut.resize(n);
    for (int i = 0; i < n; i++)
    {
        powersOut[i] = BN_new();
        if (i == 0)
            BN_one(powersOut[i]);
        else if (i == 1)
            BN_copy(powersOut[i], base);
        else
            BN_mod_mul(powersOut[i], powersOut[i-1], base, order, ctx);
    }
    return true;
}

static void FreeScalars(std::vector<BIGNUM*>& v)
{
    for (size_t i = 0; i < v.size(); i++)
        if (v[i]) BN_clear_free(v[i]);
    v.clear();
}

static bool GenerateBPGenerators(const EC_GROUP* group, int n,
                                   std::vector<EC_POINT*>& vG,
                                   std::vector<EC_POINT*>& vH,
                                   BN_CTX* ctx)
{
    vG.resize(n);
    vH.resize(n);

    for (int i = 0; i < n; i++)
    {
        vG[i] = EC_POINT_new(group);
        vH[i] = EC_POINT_new(group);

        char tagG[64], tagH[64];
        snprintf(tagG, sizeof(tagG), "Innova_BP_G_%d", i);
        snprintf(tagH, sizeof(tagH), "Innova_BP_H_%d", i);

        if (!HashToPoint(group, tagG, vG[i], ctx) ||
            !HashToPoint(group, tagH, vH[i], ctx))
        {
            for (int j = 0; j <= i; j++)
            {
                EC_POINT_free(vG[j]);
                EC_POINT_free(vH[j]);
            }
            return false;
        }
    }

    return true;
}

static void FreeBPGenerators(std::vector<EC_POINT*>& vG, std::vector<EC_POINT*>& vH)
{
    for (size_t i = 0; i < vG.size(); i++) if (vG[i]) EC_POINT_free(vG[i]);
    for (size_t i = 0; i < vH.size(); i++) if (vH[i]) EC_POINT_free(vH[i]);
    vG.clear();
    vH.clear();
}

static bool FiatShamirChallenge(const std::vector<unsigned char>& transcript,
                                 BIGNUM* challenge, const BIGNUM* order, BN_CTX* ctx)
{
    unsigned char hash[32];
    SHA256(transcript.data(), transcript.size(), hash);
    BN_bin2bn(hash, 32, challenge);
    BN_mod(challenge, challenge, order, ctx);
    OPENSSL_cleanse(hash, 32);

    if (BN_is_zero(challenge))
        return false;

    return true;
}

static void AppendToTranscript(std::vector<unsigned char>& transcript,
                                const EC_GROUP* group, const EC_POINT* point, BN_CTX* ctx)
{
    unsigned char buf[33];
    EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, buf, 33, ctx);
    transcript.insert(transcript.end(), buf, buf + 33);
}

static void AppendScalarToTranscript(std::vector<unsigned char>& transcript,
                                      const BIGNUM* scalar)
{
    unsigned char buf[32];
    memset(buf, 0, 32);
    int nBytes = BN_num_bytes(scalar);
    if (nBytes > 0 && nBytes <= 32)
        BN_bn2bin(scalar, buf + (32 - nBytes));
    transcript.insert(transcript.end(), buf, buf + 32);
}

bool CreateBulletproofRangeProof(int64_t nValue,
                                  const std::vector<unsigned char>& vchBlind,
                                  const CPedersenCommitment& commit,
                                  CBulletproofRangeProof& proofOut)
{
    if (!CZKContext::IsInitialized()) return false;
    if (nValue < 0) return false;
    if (vchBlind.size() != BLINDING_FACTOR_SIZE) return false;

    const int N = 64;

    CECGroupGuard group;
    if (!group.group) return false;

    CBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    const BIGNUM* order = EC_GROUP_get0_order(group);

    CECPointGuard G(group), H(group);
    if (!BytesToPoint(group, CZKContext::GetGeneratorG(), G, ctx)) return false;
    if (!BytesToPoint(group, CZKContext::GetGeneratorH(), H, ctx)) return false;

    std::vector<EC_POINT*> vGi, vHi;
    if (!GenerateBPGenerators(group, N, vGi, vHi, ctx))
        return false;

    std::vector<BIGNUM*> aL(N), aR(N);
    uint64_t uValue = (uint64_t)nValue;
    for (int i = 0; i < N; i++)
    {
        aL[i] = BN_new();
        aR[i] = BN_new();
        if ((uValue >> i) & 1)
        {
            BN_one(aL[i]);
            BN_zero(aR[i]);
        }
        else
        {
            BN_zero(aL[i]);
            BN_one(aR[i]);
            BN_set_negative(aR[i], 1);
            BN_mod(aR[i], aR[i], order, ctx);
        }
    }

    std::vector<BIGNUM*> sL(N), sR(N);
    for (int i = 0; i < N; i++)
    {
        unsigned char rnd[32];
        sL[i] = BN_new();
        sR[i] = BN_new();

        if (RAND_bytes(rnd, 32) != 1)
            return false;
        BN_bin2bn(rnd, 32, sL[i]);
        BN_mod(sL[i], sL[i], order, ctx);

        if (RAND_bytes(rnd, 32) != 1)
            return false;
        BN_bin2bn(rnd, 32, sR[i]);
        BN_mod(sR[i], sR[i], order, ctx);

        OPENSSL_cleanse(rnd, 32);
    }

    unsigned char rndAlpha[32], rndRho[32];
    if (RAND_bytes(rndAlpha, 32) != 1 || RAND_bytes(rndRho, 32) != 1)
        return false;

    BIGNUM* alpha = BN_bin2bn(rndAlpha, 32, NULL);
    BN_mod(alpha, alpha, order, ctx);
    BIGNUM* rho = BN_bin2bn(rndRho, 32, NULL);
    BN_mod(rho, rho, order, ctx);

    OPENSSL_cleanse(rndAlpha, 32);
    OPENSSL_cleanse(rndRho, 32);

    CECPointGuard A(group);
    EC_POINT_mul(group, A, NULL, G, alpha, ctx);

    for (int i = 0; i < N; i++)
    {
        CECPointGuard tmp(group);
        EC_POINT_mul(group, tmp, NULL, vGi[i], aL[i], ctx);
        EC_POINT_add(group, A, A, tmp, ctx);

        EC_POINT_mul(group, tmp, NULL, vHi[i], aR[i], ctx);
        EC_POINT_add(group, A, A, tmp, ctx);
    }

    CECPointGuard S(group);
    EC_POINT_mul(group, S, NULL, G, rho, ctx);

    for (int i = 0; i < N; i++)
    {
        CECPointGuard tmp(group);
        EC_POINT_mul(group, tmp, NULL, vGi[i], sL[i], ctx);
        EC_POINT_add(group, S, S, tmp, ctx);

        EC_POINT_mul(group, tmp, NULL, vHi[i], sR[i], ctx);
        EC_POINT_add(group, S, S, tmp, ctx);
    }

    std::vector<unsigned char> transcript;
    const char* bpDomain = "Innova_Bulletproof_v1";
    transcript.insert(transcript.end(), bpDomain, bpDomain + strlen(bpDomain));
    unsigned char nBuf[4] = {(unsigned char)(N>>24),(unsigned char)(N>>16),(unsigned char)(N>>8),(unsigned char)N};
    transcript.insert(transcript.end(), nBuf, nBuf + 4);
    transcript.insert(transcript.end(), CZKContext::GetGeneratorG().begin(), CZKContext::GetGeneratorG().end());
    transcript.insert(transcript.end(), CZKContext::GetGeneratorH().begin(), CZKContext::GetGeneratorH().end());
    transcript.insert(transcript.end(), commit.vchCommitment.begin(), commit.vchCommitment.end());
    AppendToTranscript(transcript, group, A, ctx);
    AppendToTranscript(transcript, group, S, ctx);

    BIGNUM* y = BN_new();
    FiatShamirChallenge(transcript, y, order, ctx);

    unsigned char yBytes[32];
    memset(yBytes, 0, 32);
    int yLen = BN_num_bytes(y);
    if (yLen > 0) BN_bn2bin(y, yBytes + (32 - yLen));
    transcript.insert(transcript.end(), yBytes, yBytes + 32);

    BIGNUM* z = BN_new();
    FiatShamirChallenge(transcript, z, order, ctx);

    std::vector<BIGNUM*> yn;
    ScalarPowers(y, N, order, yn, ctx);

    std::vector<BIGNUM*> twon;
    BIGNUM* two = BN_new();
    BN_set_word(two, 2);
    ScalarPowers(two, N, order, twon, ctx);
    BN_free(two);

    BIGNUM* z2 = BN_new();
    BN_mod_sqr(z2, z, order, ctx);

    BIGNUM* t1 = BN_new(); BN_zero(t1);
    BIGNUM* t2 = BN_new(); BN_zero(t2);
    BIGNUM* tmp = BN_new();

    for (int i = 0; i < N; i++)
    {
        BIGNUM* aLz = BN_new();
        BN_mod_sub(aLz, aL[i], z, order, ctx);

        BIGNUM* aRz = BN_new();
        BN_mod_add(aRz, aR[i], z, order, ctx);

        BIGNUM* ynSR = BN_new();
        BN_mod_mul(ynSR, yn[i], sR[i], order, ctx);

        BIGNUM* ynARz = BN_new();
        BN_mod_mul(ynARz, yn[i], aRz, order, ctx);
        BN_mod_mul(tmp, z2, twon[i], order, ctx);
        BN_mod_add(ynARz, ynARz, tmp, order, ctx);

        BN_mod_mul(tmp, aLz, ynSR, order, ctx);
        BN_mod_add(t1, t1, tmp, order, ctx);

        BN_mod_mul(tmp, sL[i], ynARz, order, ctx);
        BN_mod_add(t1, t1, tmp, order, ctx);

        BN_mod_mul(tmp, sL[i], ynSR, order, ctx);
        BN_mod_add(t2, t2, tmp, order, ctx);

        BN_free(aLz);
        BN_free(aRz);
        BN_free(ynSR);
        BN_free(ynARz);
    }

    unsigned char rndTau1[32], rndTau2[32];
    if (RAND_bytes(rndTau1, 32) != 1 || RAND_bytes(rndTau2, 32) != 1)
        return false;

    BIGNUM* tau1 = BN_bin2bn(rndTau1, 32, NULL);
    BN_mod(tau1, tau1, order, ctx);
    BIGNUM* tau2 = BN_bin2bn(rndTau2, 32, NULL);
    BN_mod(tau2, tau2, order, ctx);

    OPENSSL_cleanse(rndTau1, 32);
    OPENSSL_cleanse(rndTau2, 32);

    CECPointGuard T1(group), T2(group);
    {
        CECPointGuard tmp1(group), tmp2(group);
        EC_POINT_mul(group, tmp1, NULL, H, t1, ctx);
        EC_POINT_mul(group, tmp2, NULL, G, tau1, ctx);
        EC_POINT_add(group, T1, tmp1, tmp2, ctx);

        EC_POINT_mul(group, tmp1, NULL, H, t2, ctx);
        EC_POINT_mul(group, tmp2, NULL, G, tau2, ctx);
        EC_POINT_add(group, T2, tmp1, tmp2, ctx);
    }

    AppendToTranscript(transcript, group, T1, ctx);
    AppendToTranscript(transcript, group, T2, ctx);

    BIGNUM* x = BN_new();
    FiatShamirChallenge(transcript, x, order, ctx);

    BIGNUM* x2 = BN_new();
    BN_mod_sqr(x2, x, order, ctx);

    BIGNUM* taux = BN_new();
    BN_mod_mul(taux, tau2, x2, order, ctx);
    BN_mod_mul(tmp, tau1, x, order, ctx);
    BN_mod_add(taux, taux, tmp, order, ctx);

    BIGNUM* bnBlind = BN_bin2bn(vchBlind.data(), vchBlind.size(), NULL);
    BN_mod(bnBlind, bnBlind, order, ctx);
    BN_mod_mul(tmp, z2, bnBlind, order, ctx);
    BN_mod_add(taux, taux, tmp, order, ctx);
    BN_clear_free(bnBlind);

    BIGNUM* mu = BN_new();
    BN_mod_mul(mu, rho, x, order, ctx);
    BN_mod_add(mu, mu, alpha, order, ctx);

    BIGNUM* sumYn = BN_new(); BN_zero(sumYn);
    BIGNUM* sum2n = BN_new(); BN_zero(sum2n);
    for (int i = 0; i < N; i++)
    {
        BN_mod_add(sumYn, sumYn, yn[i], order, ctx);
        BN_mod_add(sum2n, sum2n, twon[i], order, ctx);
    }

    BIGNUM* z3 = BN_new();
    BN_mod_mul(z3, z2, z, order, ctx);

    BIGNUM* delta = BN_new();
    BN_mod_sub(tmp, z, z2, order, ctx);
    BN_mod_mul(delta, tmp, sumYn, order, ctx);
    BN_mod_mul(tmp, z3, sum2n, order, ctx);
    BN_mod_sub(delta, delta, tmp, order, ctx);

    BIGNUM* t_hat = BN_new();
    BIGNUM* bnValue2 = BN_new();
    { unsigned char vb[8]; for(int k=7;k>=0;k--) vb[7-k]=(unsigned char)((uint64_t)nValue>>(k*8)); BN_bin2bn(vb,8,bnValue2); }
    BN_mod_mul(t_hat, bnValue2, z2, order, ctx);
    BN_mod_add(t_hat, t_hat, delta, order, ctx);
    BN_mod_mul(tmp, t1, x, order, ctx);
    BN_mod_add(t_hat, t_hat, tmp, order, ctx);
    BN_mod_mul(tmp, t2, x2, order, ctx);
    BN_mod_add(t_hat, t_hat, tmp, order, ctx);

    proofOut.vchProof.clear();

    unsigned char ptBuf[33];
    EC_POINT_point2oct(group, A, POINT_CONVERSION_COMPRESSED, ptBuf, 33, ctx);
    proofOut.vchProof.insert(proofOut.vchProof.end(), ptBuf, ptBuf + 33);

    EC_POINT_point2oct(group, S, POINT_CONVERSION_COMPRESSED, ptBuf, 33, ctx);
    proofOut.vchProof.insert(proofOut.vchProof.end(), ptBuf, ptBuf + 33);

    EC_POINT_point2oct(group, T1, POINT_CONVERSION_COMPRESSED, ptBuf, 33, ctx);
    proofOut.vchProof.insert(proofOut.vchProof.end(), ptBuf, ptBuf + 33);

    EC_POINT_point2oct(group, T2, POINT_CONVERSION_COMPRESSED, ptBuf, 33, ctx);
    proofOut.vchProof.insert(proofOut.vchProof.end(), ptBuf, ptBuf + 33);

    unsigned char scBuf[32];
    memset(scBuf, 0, 32);
    int nB = BN_num_bytes(taux);
    if (nB > 0) BN_bn2bin(taux, scBuf + (32 - nB));
    proofOut.vchProof.insert(proofOut.vchProof.end(), scBuf, scBuf + 32);

    memset(scBuf, 0, 32);
    nB = BN_num_bytes(mu);
    if (nB > 0) BN_bn2bin(mu, scBuf + (32 - nB));
    proofOut.vchProof.insert(proofOut.vchProof.end(), scBuf, scBuf + 32);

    memset(scBuf, 0, 32);
    nB = BN_num_bytes(t_hat);
    if (nB > 0) BN_bn2bin(t_hat, scBuf + (32 - nB));
    proofOut.vchProof.insert(proofOut.vchProof.end(), scBuf, scBuf + 32);

    int logN = 6;

    std::vector<BIGNUM*> lVec(N), rVec(N);
    for (int i = 0; i < N; i++)
    {
        lVec[i] = BN_new();
        rVec[i] = BN_new();

        BN_mod_sub(lVec[i], aL[i], z, order, ctx);
        BN_mod_mul(tmp, sL[i], x, order, ctx);
        BN_mod_add(lVec[i], lVec[i], tmp, order, ctx);

        BIGNUM* inner = BN_new();
        BN_mod_add(inner, aR[i], z, order, ctx);
        BN_mod_mul(tmp, sR[i], x, order, ctx);
        BN_mod_add(inner, inner, tmp, order, ctx);
        BN_mod_mul(rVec[i], yn[i], inner, order, ctx);
        BN_mod_mul(tmp, z2, twon[i], order, ctx);
        BN_mod_add(rVec[i], rVec[i], tmp, order, ctx);

        BN_free(inner);
    }

    BIGNUM* y_inv = BN_new();
    BN_mod_inverse(y_inv, y, order, ctx);
    std::vector<BIGNUM*> y_inv_n;
    ScalarPowers(y_inv, N, order, y_inv_n, ctx);
    BN_free(y_inv);

    std::vector<EC_POINT*> vHiPrime(N);
    for (int i = 0; i < N; i++)
    {
        vHiPrime[i] = EC_POINT_new(group);
        EC_POINT_mul(group, vHiPrime[i], NULL, vHi[i], y_inv_n[i], ctx);
    }
    FreeScalars(y_inv_n);

    int curN = N;
    std::vector<EC_POINT*> curGi(vGi), curHi(vHiPrime);

    for (int round = 0; round < logN; round++)
    {
        int half = curN / 2;

        CECPointGuard L(group), R(group);
        EC_POINT_set_to_infinity(group, L);
        EC_POINT_set_to_infinity(group, R);

        BIGNUM* cL = BN_new(); BN_zero(cL);
        BIGNUM* cR = BN_new(); BN_zero(cR);

        for (int i = 0; i < half; i++)
        {
            CECPointGuard tmpPt(group);
            EC_POINT_mul(group, tmpPt, NULL, curGi[half + i], lVec[i], ctx);
            EC_POINT_add(group, L, L, tmpPt, ctx);

            EC_POINT_mul(group, tmpPt, NULL, curHi[i], rVec[half + i], ctx);
            EC_POINT_add(group, L, L, tmpPt, ctx);

            BN_mod_mul(tmp, lVec[i], rVec[half + i], order, ctx);
            BN_mod_add(cL, cL, tmp, order, ctx);

            EC_POINT_mul(group, tmpPt, NULL, curGi[i], lVec[half + i], ctx);
            EC_POINT_add(group, R, R, tmpPt, ctx);

            EC_POINT_mul(group, tmpPt, NULL, curHi[half + i], rVec[i], ctx);
            EC_POINT_add(group, R, R, tmpPt, ctx);

            BN_mod_mul(tmp, lVec[half + i], rVec[i], order, ctx);
            BN_mod_add(cR, cR, tmp, order, ctx);
        }

        {
            CECPointGuard tmpPt(group);
            EC_POINT_mul(group, tmpPt, NULL, H, cL, ctx);
            EC_POINT_add(group, L, L, tmpPt, ctx);

            EC_POINT_mul(group, tmpPt, NULL, H, cR, ctx);
            EC_POINT_add(group, R, R, tmpPt, ctx);
        }

        EC_POINT_point2oct(group, L, POINT_CONVERSION_COMPRESSED, ptBuf, 33, ctx);
        proofOut.vchProof.insert(proofOut.vchProof.end(), ptBuf, ptBuf + 33);

        EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED, ptBuf, 33, ctx);
        proofOut.vchProof.insert(proofOut.vchProof.end(), ptBuf, ptBuf + 33);

        AppendToTranscript(transcript, group, L, ctx);
        AppendToTranscript(transcript, group, R, ctx);

        BIGNUM* u_round = BN_new();
        FiatShamirChallenge(transcript, u_round, order, ctx);

        BIGNUM* u_inv = BN_new();
        BN_mod_inverse(u_inv, u_round, order, ctx);

        std::vector<BIGNUM*> newL(half), newR(half);
        std::vector<EC_POINT*> newGi(half), newHi(half);

        for (int i = 0; i < half; i++)
        {
            newL[i] = BN_new();
            BN_mod_mul(newL[i], lVec[i], u_round, order, ctx);
            BN_mod_mul(tmp, lVec[half + i], u_inv, order, ctx);
            BN_mod_add(newL[i], newL[i], tmp, order, ctx);

            newR[i] = BN_new();
            BN_mod_mul(newR[i], rVec[i], u_inv, order, ctx);
            BN_mod_mul(tmp, rVec[half + i], u_round, order, ctx);
            BN_mod_add(newR[i], newR[i], tmp, order, ctx);

            newGi[i] = EC_POINT_new(group);
            {
                CECPointGuard p1(group), p2(group);
                EC_POINT_mul(group, p1, NULL, curGi[i], u_inv, ctx);
                EC_POINT_mul(group, p2, NULL, curGi[half + i], u_round, ctx);
                EC_POINT_add(group, newGi[i], p1, p2, ctx);
            }

            newHi[i] = EC_POINT_new(group);
            {
                CECPointGuard p1(group), p2(group);
                EC_POINT_mul(group, p1, NULL, curHi[i], u_round, ctx);
                EC_POINT_mul(group, p2, NULL, curHi[half + i], u_inv, ctx);
                EC_POINT_add(group, newHi[i], p1, p2, ctx);
            }
        }

        for (int i = 0; i < curN; i++)
        {
            BN_clear_free(lVec[i]);
            BN_clear_free(rVec[i]);
        }
        if (round > 0)
        {
            for (int i = 0; i < curN; i++)
                EC_POINT_free(curGi[i]);
        }
        for (int i = 0; i < curN; i++)
            EC_POINT_free(curHi[i]);

        lVec = newL;
        rVec = newR;
        curGi = newGi;
        curHi = newHi;
        curN = half;

        BN_free(cL);
        BN_free(cR);
        BN_free(u_round);
        BN_free(u_inv);
    }

    memset(scBuf, 0, 32);
    nB = BN_num_bytes(lVec[0]);
    if (nB > 0) BN_bn2bin(lVec[0], scBuf + (32 - nB));
    proofOut.vchProof.insert(proofOut.vchProof.end(), scBuf, scBuf + 32);

    memset(scBuf, 0, 32);
    nB = BN_num_bytes(rVec[0]);
    if (nB > 0) BN_bn2bin(rVec[0], scBuf + (32 - nB));
    proofOut.vchProof.insert(proofOut.vchProof.end(), scBuf, scBuf + 32);

    BN_clear_free(lVec[0]);
    BN_clear_free(rVec[0]);
    if (logN > 0)
    {
        EC_POINT_free(curGi[0]);
        EC_POINT_free(curHi[0]);
    }

    FreeScalars(aL); FreeScalars(aR);
    FreeScalars(sL); FreeScalars(sR);
    FreeScalars(yn); FreeScalars(twon);
    FreeBPGenerators(vGi, vHi);

    BN_clear_free(alpha); BN_clear_free(rho);
    BN_free(y); BN_free(z); BN_free(z2); BN_free(z3);
    BN_free(x); BN_free(x2);
    BN_clear_free(tau1); BN_clear_free(tau2);
    BN_free(t1); BN_free(t2);
    BN_free(taux); BN_free(mu); BN_free(t_hat);
    BN_free(delta); BN_free(sumYn); BN_free(sum2n);
    BN_free(bnValue2); BN_free(tmp);

    OPENSSL_cleanse(scBuf, 32);

    return true;
}

bool VerifyBulletproofRangeProof(const CPedersenCommitment& commit,
                                  const CBulletproofRangeProof& proof)
{
    if (!CZKContext::IsInitialized()) return false;

    const int N = 64;
    const int logN = 6;

    if (proof.vchProof.size() > MAX_BULLETPROOF_PROOF_SIZE)
        return false;

    size_t minSize = 4 * 33 + 3 * 32 + logN * 2 * 33 + 2 * 32;
    if (proof.vchProof.size() < minSize)
        return false;

    CECGroupGuard group;
    if (!group.group) return false;

    CBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    const BIGNUM* order = EC_GROUP_get0_order(group);

    CECPointGuard G(group), H(group);
    if (!BytesToPoint(group, CZKContext::GetGeneratorG(), G, ctx)) return false;
    if (!BytesToPoint(group, CZKContext::GetGeneratorH(), H, ctx)) return false;

    size_t offset = 0;

    CECPointGuard A(group), S(group), T1(group), T2(group);
    if (EC_POINT_oct2point(group, A, proof.vchProof.data() + offset, 33, ctx) != 1) return false;
    if (EC_POINT_is_on_curve(group, A, ctx) != 1) return false;
    offset += 33;
    if (EC_POINT_oct2point(group, S, proof.vchProof.data() + offset, 33, ctx) != 1) return false;
    if (EC_POINT_is_on_curve(group, S, ctx) != 1) return false;
    offset += 33;
    if (EC_POINT_oct2point(group, T1, proof.vchProof.data() + offset, 33, ctx) != 1) return false;
    if (EC_POINT_is_on_curve(group, T1, ctx) != 1) return false;
    offset += 33;
    if (EC_POINT_oct2point(group, T2, proof.vchProof.data() + offset, 33, ctx) != 1) return false;
    if (EC_POINT_is_on_curve(group, T2, ctx) != 1) return false;
    offset += 33;

    BIGNUM* taux = BN_bin2bn(proof.vchProof.data() + offset, 32, NULL); offset += 32;
    if (!taux || BN_cmp(taux, order) >= 0) { if (taux) BN_free(taux); return false; }
    BIGNUM* mu = BN_bin2bn(proof.vchProof.data() + offset, 32, NULL); offset += 32;
    if (!mu || BN_cmp(mu, order) >= 0) { BN_free(taux); if (mu) BN_free(mu); return false; }
    BIGNUM* t_hat = BN_bin2bn(proof.vchProof.data() + offset, 32, NULL); offset += 32;
    if (!t_hat || BN_cmp(t_hat, order) >= 0) { BN_free(taux); BN_free(mu); if (t_hat) BN_free(t_hat); return false; }

    std::vector<unsigned char> transcript;
    const char* bpDomain = "Innova_Bulletproof_v1";
    transcript.insert(transcript.end(), bpDomain, bpDomain + strlen(bpDomain));
    unsigned char nBuf[4] = {(unsigned char)(N>>24),(unsigned char)(N>>16),(unsigned char)(N>>8),(unsigned char)N};
    transcript.insert(transcript.end(), nBuf, nBuf + 4);
    transcript.insert(transcript.end(), CZKContext::GetGeneratorG().begin(), CZKContext::GetGeneratorG().end());
    transcript.insert(transcript.end(), CZKContext::GetGeneratorH().begin(), CZKContext::GetGeneratorH().end());
    transcript.insert(transcript.end(), commit.vchCommitment.begin(), commit.vchCommitment.end());
    AppendToTranscript(transcript, group, A, ctx);
    AppendToTranscript(transcript, group, S, ctx);

    BIGNUM* y = BN_new();
    FiatShamirChallenge(transcript, y, order, ctx);

    unsigned char yBytes[32];
    memset(yBytes, 0, 32);
    int yLen = BN_num_bytes(y);
    if (yLen > 0) BN_bn2bin(y, yBytes + (32 - yLen));
    transcript.insert(transcript.end(), yBytes, yBytes + 32);

    BIGNUM* z = BN_new();
    FiatShamirChallenge(transcript, z, order, ctx);

    AppendToTranscript(transcript, group, T1, ctx);
    AppendToTranscript(transcript, group, T2, ctx);

    BIGNUM* x = BN_new();
    FiatShamirChallenge(transcript, x, order, ctx);

    BIGNUM* x2 = BN_new();
    BN_mod_sqr(x2, x, order, ctx);
    BIGNUM* z2 = BN_new();
    BN_mod_sqr(z2, z, order, ctx);
    BIGNUM* z3 = BN_new();
    BN_mod_mul(z3, z2, z, order, ctx);

    std::vector<BIGNUM*> yn;
    ScalarPowers(y, N, order, yn, ctx);

    BIGNUM* y_inv_v = BN_new();
    BN_mod_inverse(y_inv_v, y, order, ctx);
    std::vector<BIGNUM*> y_inv_n;
    ScalarPowers(y_inv_v, N, order, y_inv_n, ctx);
    BN_free(y_inv_v);

    std::vector<BIGNUM*> twon;
    BIGNUM* two = BN_new();
    BN_set_word(two, 2);
    ScalarPowers(two, N, order, twon, ctx);
    BN_free(two);

    BIGNUM* sumYn = BN_new(); BN_zero(sumYn);
    BIGNUM* sum2n = BN_new(); BN_zero(sum2n);
    BIGNUM* tmp = BN_new();

    for (int i = 0; i < N; i++)
    {
        BN_mod_add(sumYn, sumYn, yn[i], order, ctx);
        BN_mod_add(sum2n, sum2n, twon[i], order, ctx);
    }

    BIGNUM* delta = BN_new();
    BN_mod_sub(tmp, z, z2, order, ctx);
    BN_mod_mul(delta, tmp, sumYn, order, ctx);
    BN_mod_mul(tmp, z3, sum2n, order, ctx);
    BN_mod_sub(delta, delta, tmp, order, ctx);

    CECPointGuard LHS(group);
    {
        CECPointGuard p1(group), p2(group);
        EC_POINT_mul(group, p1, NULL, H, t_hat, ctx);
        EC_POINT_mul(group, p2, NULL, G, taux, ctx);
        EC_POINT_add(group, LHS, p1, p2, ctx);
    }

    CECPointGuard RHS(group);
    {
        CECPointGuard V(group);
        BytesToPoint(group, commit.vchCommitment, V, ctx);

        CECPointGuard p1(group), p2(group), p3(group), p4(group);
        EC_POINT_mul(group, p1, NULL, V, z2, ctx);
        EC_POINT_mul(group, p2, NULL, H, delta, ctx);
        EC_POINT_mul(group, p3, NULL, T1, x, ctx);
        EC_POINT_mul(group, p4, NULL, T2, x2, ctx);

        EC_POINT_add(group, RHS, p1, p2, ctx);
        EC_POINT_add(group, RHS, RHS, p3, ctx);
        EC_POINT_add(group, RHS, RHS, p4, ctx);
    }

    bool fValid = (EC_POINT_cmp(group, LHS, RHS, ctx) == 0);

    if (fValid)
    {
        std::vector<EC_POINT*> vL(logN), vR(logN);
        std::vector<BIGNUM*> vChallenge(logN);

        for (int round = 0; round < logN; round++)
        {
            vL[round] = EC_POINT_new(group);
            vR[round] = EC_POINT_new(group);

            if (EC_POINT_oct2point(group, vL[round], proof.vchProof.data() + offset, 33, ctx) != 1 ||
                EC_POINT_is_on_curve(group, vL[round], ctx) != 1)
            {
                fValid = false;
                break;
            }
            offset += 33;
            if (EC_POINT_oct2point(group, vR[round], proof.vchProof.data() + offset, 33, ctx) != 1 ||
                EC_POINT_is_on_curve(group, vR[round], ctx) != 1)
            {
                fValid = false;
                break;
            }
            offset += 33;

            AppendToTranscript(transcript, group, vL[round], ctx);
            AppendToTranscript(transcript, group, vR[round], ctx);

            vChallenge[round] = BN_new();
            FiatShamirChallenge(transcript, vChallenge[round], order, ctx);
        }

        BIGNUM* a_final = BN_bin2bn(proof.vchProof.data() + offset, 32, NULL); offset += 32;
        BIGNUM* b_final = BN_bin2bn(proof.vchProof.data() + offset, 32, NULL); offset += 32;

        if (!a_final || !b_final || BN_cmp(a_final, order) >= 0 || BN_cmp(b_final, order) >= 0)
        {
            if (a_final) BN_free(a_final);
            if (b_final) BN_free(b_final);
            return false;
        }

        BIGNUM* ab = BN_new();
        BN_mod_mul(ab, a_final, b_final, order, ctx);

        std::vector<EC_POINT*> vGi, vHi;
        GenerateBPGenerators(group, N, vGi, vHi, ctx);

        CECPointGuard P(group);
        {
            CECPointGuard xS(group);
            EC_POINT_mul(group, xS, NULL, S, x, ctx);
            EC_POINT_add(group, P, A, xS, ctx);
        }

        for (int i = 0; i < N; i++)
        {
            CECPointGuard tmp2(group);
            EC_POINT_mul(group, tmp2, NULL, vGi[i], z, ctx);
            EC_POINT_invert(group, tmp2, ctx);
            EC_POINT_add(group, P, P, tmp2, ctx);
        }

        for (int i = 0; i < N; i++)
        {
            BIGNUM* coeff = BN_new();
            BN_mod_mul(coeff, z2, twon[i], order, ctx);
            BN_mod_mul(coeff, coeff, y_inv_n[i], order, ctx);
            BN_mod_add(coeff, coeff, z, order, ctx);

            CECPointGuard tmp2(group);
            EC_POINT_mul(group, tmp2, NULL, vHi[i], coeff, ctx);
            EC_POINT_add(group, P, P, tmp2, ctx);

            BN_free(coeff);
        }

        {
            CECPointGuard muG(group);
            EC_POINT_mul(group, muG, NULL, G, mu, ctx);
            EC_POINT_invert(group, muG, ctx);
            EC_POINT_add(group, P, P, muG, ctx);
        }

        {
            CECPointGuard tH(group);
            EC_POINT_mul(group, tH, NULL, H, t_hat, ctx);
            EC_POINT_add(group, P, P, tH, ctx);
        }

        CECPointGuard Plhs(group);
        EC_POINT_copy(Plhs, P);

        for (int round = 0; round < logN; round++)
        {
            BIGNUM* u2 = BN_new();
            BN_mod_sqr(u2, vChallenge[round], order, ctx);

            BIGNUM* u_inv = BN_new();
            BN_mod_inverse(u_inv, vChallenge[round], order, ctx);
            BIGNUM* u_inv2 = BN_new();
            BN_mod_sqr(u_inv2, u_inv, order, ctx);

            CECPointGuard tmpL(group), tmpR(group);
            EC_POINT_mul(group, tmpL, NULL, vL[round], u2, ctx);
            EC_POINT_mul(group, tmpR, NULL, vR[round], u_inv2, ctx);

            EC_POINT_add(group, Plhs, Plhs, tmpL, ctx);
            EC_POINT_add(group, Plhs, Plhs, tmpR, ctx);

            BN_free(u2);
            BN_free(u_inv);
            BN_free(u_inv2);
        }

        CECPointGuard Pcheck(group);
        EC_POINT_set_to_infinity(group, Pcheck);

        for (int i = 0; i < N; i++)
        {
            BIGNUM* sG = BN_new(); BN_one(sG);
            BIGNUM* sH = BN_new(); BN_one(sH);

            for (int j = 0; j < logN; j++)
            {
                int bit = (i >> (logN - 1 - j)) & 1;
                if (bit)
                {
                    BN_mod_mul(sG, sG, vChallenge[j], order, ctx);
                    BIGNUM* u_inv = BN_new();
                    BN_mod_inverse(u_inv, vChallenge[j], order, ctx);
                    BN_mod_mul(sH, sH, u_inv, order, ctx);
                    BN_free(u_inv);
                }
                else
                {
                    BIGNUM* u_inv = BN_new();
                    BN_mod_inverse(u_inv, vChallenge[j], order, ctx);
                    BN_mod_mul(sG, sG, u_inv, order, ctx);
                    BN_free(u_inv);
                    BN_mod_mul(sH, sH, vChallenge[j], order, ctx);
                }
            }

            BIGNUM* asG = BN_new();
            BN_mod_mul(asG, a_final, sG, order, ctx);
            CECPointGuard tmpPt(group);
            EC_POINT_mul(group, tmpPt, NULL, vGi[i], asG, ctx);
            EC_POINT_add(group, Pcheck, Pcheck, tmpPt, ctx);

            BIGNUM* bsH = BN_new();
            BN_mod_mul(bsH, b_final, sH, order, ctx);
            BN_mod_mul(bsH, bsH, y_inv_n[i], order, ctx);
            EC_POINT_mul(group, tmpPt, NULL, vHi[i], bsH, ctx);
            EC_POINT_add(group, Pcheck, Pcheck, tmpPt, ctx);

            BN_free(sG); BN_free(sH);
            BN_free(asG); BN_free(bsH);
        }

        {
            CECPointGuard abH(group);
            EC_POINT_mul(group, abH, NULL, H, ab, ctx);
            EC_POINT_add(group, Pcheck, Pcheck, abH, ctx);
        }

        if (EC_POINT_cmp(group, Plhs, Pcheck, ctx) != 0)
            fValid = false;

        BN_free(ab);
        BN_clear_free(a_final);
        BN_clear_free(b_final);
        FreeBPGenerators(vGi, vHi);

        for (int i = 0; i < logN; i++)
        {
            EC_POINT_free(vL[i]);
            EC_POINT_free(vR[i]);
            BN_free(vChallenge[i]);
        }
    }

    BN_clear_free(taux);
    BN_clear_free(mu);
    BN_free(t_hat);
    BN_free(y); BN_free(z);
    BN_free(x); BN_free(x2);
    BN_free(z2); BN_free(z3);
    BN_free(delta); BN_free(sumYn); BN_free(sum2n);
    BN_free(tmp);
    FreeScalars(yn); FreeScalars(twon);
    FreeScalars(y_inv_n);

    return fValid;
}

bool BatchVerifyBulletproofRangeProofs(const std::vector<CPedersenCommitment>& vCommits,
                                        const std::vector<CBulletproofRangeProof>& vProofs)
{
    if (vCommits.size() != vProofs.size()) return false;

    for (size_t i = 0; i < vCommits.size(); i++)
    {
        if (!VerifyBulletproofRangeProof(vCommits[i], vProofs[i]))
            return false;
    }

    return true;
}


bool CreateBindingSignature(const std::vector<std::vector<unsigned char>>& vInputBlinds,
                             const std::vector<std::vector<unsigned char>>& vOutputBlinds,
                             const uint256& sighash,
                             CBindingSignature& sigOut)
{
    if (!CZKContext::IsInitialized()) return false;

    CECGroupGuard group;
    if (!group.group) return false;

    CBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    const BIGNUM* order = EC_GROUP_get0_order(group);

    BIGNUM* bsk = BN_new(); BN_zero(bsk);
    BIGNUM* tmp = BN_new();

    for (size_t i = 0; i < vInputBlinds.size(); i++)
    {
        if (vInputBlinds[i].size() != BLINDING_FACTOR_SIZE) { BN_free(bsk); BN_free(tmp); return false; }
        BIGNUM* b = BN_bin2bn(vInputBlinds[i].data(), BLINDING_FACTOR_SIZE, NULL);
        BN_mod_add(bsk, bsk, b, order, ctx);
        BN_free(b);
    }

    for (size_t i = 0; i < vOutputBlinds.size(); i++)
    {
        if (vOutputBlinds[i].size() != BLINDING_FACTOR_SIZE) { BN_free(bsk); BN_free(tmp); return false; }
        BIGNUM* b = BN_bin2bn(vOutputBlinds[i].data(), BLINDING_FACTOR_SIZE, NULL);
        BN_mod_sub(bsk, bsk, b, order, ctx);
        BN_free(b);
    }

    BN_set_consttime(bsk);

    const EC_POINT* G = EC_GROUP_get0_generator(group);

    unsigned char rndK[32];
    if (RAND_bytes(rndK, 32) != 1)
    {
        BN_clear_free(bsk); BN_free(tmp);
        return false;
    }

    unsigned char bskBytes[32];
    memset(bskBytes, 0, 32);
    int bskLen = BN_num_bytes(bsk);
    if (bskLen > 0 && bskLen <= 32)
        BN_bn2bin(bsk, bskBytes + (32 - bskLen));

    unsigned char nonceInput[96];
    memcpy(nonceInput, bskBytes, 32);
    memcpy(nonceInput + 32, sighash.begin(), 32);
    memcpy(nonceInput + 64, rndK, 32);
    OPENSSL_cleanse(bskBytes, 32);
    OPENSSL_cleanse(rndK, 32);

    unsigned char hedgedNonce[32];
    unsigned int hmacLen = 32;
    HMAC(EVP_sha256(), "Innova_BindingSig_nonce", 22,
         nonceInput, 96, hedgedNonce, &hmacLen);
    OPENSSL_cleanse(nonceInput, 96);

    BIGNUM* k = BN_bin2bn(hedgedNonce, 32, NULL);
    BN_mod(k, k, order, ctx);
    OPENSSL_cleanse(hedgedNonce, 32);

    BN_set_consttime(k);

    if (BN_is_zero(k))
    {
        BN_clear_free(bsk); BN_clear_free(k); BN_free(tmp);
        return false;
    }

    CECPointGuard R(group);
    if (EC_POINT_mul(group, R, NULL, G, k, ctx) != 1)
    {
        BN_clear_free(bsk); BN_clear_free(k); BN_free(tmp);
        return false;
    }

    CECPointGuard bvk(group);
    if (EC_POINT_mul(group, bvk, NULL, G, bsk, ctx) != 1)
    {
        BN_clear_free(bsk); BN_clear_free(k); BN_free(tmp);
        return false;
    }

    unsigned char rBuf[33], bvkBuf[33];
    EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED, rBuf, 33, ctx);
    EC_POINT_point2oct(group, bvk, POINT_CONVERSION_COMPRESSED, bvkBuf, 33, ctx);

    SHA256_CTX sha;
    SHA256_Init(&sha);
    const char* domain = "Innova_BindingSig_v2";
    SHA256_Update(&sha, domain, strlen(domain));
    SHA256_Update(&sha, rBuf, 33);
    SHA256_Update(&sha, bvkBuf, 33);
    SHA256_Update(&sha, sighash.begin(), 32);

    unsigned char eHash[32];
    SHA256_Final(eHash, &sha);

    BIGNUM* e = BN_bin2bn(eHash, 32, NULL);
    BN_mod(e, e, order, ctx);

    BIGNUM* s = BN_new();
    BN_mod_mul(tmp, e, bsk, order, ctx);
    BN_mod_sub(s, k, tmp, order, ctx);

    sigOut.vchSignature.resize(BINDING_SIGNATURE_SIZE);

    memcpy(sigOut.vchSignature.data(), rBuf, 33);

    unsigned char sBuf[32];
    memset(sBuf, 0, 32);
    int nBytes = BN_num_bytes(s);
    if (nBytes > 0) BN_bn2bin(s, sBuf + (32 - nBytes));
    memcpy(sigOut.vchSignature.data() + 33, sBuf, 32);

    BN_clear_free(bsk);
    BN_clear_free(k);
    BN_free(e);
    BN_clear_free(s);
    BN_free(tmp);
    OPENSSL_cleanse(sBuf, 32);
    OPENSSL_cleanse(eHash, 32);

    return true;
}

bool VerifyBindingSignature(const std::vector<CPedersenCommitment>& vInputCommits,
                             const std::vector<CPedersenCommitment>& vOutputCommits,
                             int64_t nValueBalance,
                             const uint256& sighash,
                             const CBindingSignature& sig)
{
    if (!CZKContext::IsInitialized()) return false;
    if (sig.vchSignature.size() != BINDING_SIGNATURE_SIZE) return false;

    CECGroupGuard group;
    if (!group.group) return false;

    CBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    const BIGNUM* order = EC_GROUP_get0_order(group);
    const EC_POINT* G = EC_GROUP_get0_generator(group);

    CECPointGuard bvk(group);
    EC_POINT_set_to_infinity(group, bvk);

    for (size_t i = 0; i < vInputCommits.size(); i++)
    {
        CECPointGuard p(group);
        if (!BytesToPoint(group, vInputCommits[i].vchCommitment, p, ctx)) return false;
        EC_POINT_add(group, bvk, bvk, p, ctx);
    }

    for (size_t i = 0; i < vOutputCommits.size(); i++)
    {
        CECPointGuard p(group);
        if (!BytesToPoint(group, vOutputCommits[i].vchCommitment, p, ctx)) return false;
        EC_POINT_invert(group, p, ctx);
        EC_POINT_add(group, bvk, bvk, p, ctx);
    }

    if (nValueBalance != 0)
    {
        CECPointGuard Hpt(group), vbH(group);
        if (!BytesToPoint(group, CZKContext::GetGeneratorH(), Hpt, ctx)) return false;

        int64_t absVal = (nValueBalance < 0) ? -nValueBalance : nValueBalance;
        CBNGuard bnVal;
        { unsigned char fb[8]; for(int i=7;i>=0;i--) fb[7-i]=(unsigned char)((uint64_t)absVal>>(i*8)); BN_bin2bn(fb,8,bnVal); }
        EC_POINT_mul(group, vbH, NULL, Hpt, bnVal, ctx);
        if (nValueBalance > 0)
            EC_POINT_invert(group, vbH, ctx);
        EC_POINT_add(group, bvk, bvk, vbH, ctx);
    }

    CECPointGuard R(group);
    if (EC_POINT_oct2point(group, R, sig.vchSignature.data(), 33, ctx) != 1) return false;
    if (EC_POINT_is_at_infinity(group, R)) return false;
    if (EC_POINT_is_on_curve(group, R, ctx) != 1) return false;

    BIGNUM* s = BN_bin2bn(sig.vchSignature.data() + 33, 32, NULL);
    if (!s) return false;

    if (BN_is_negative(s) || BN_cmp(s, order) >= 0)
    {
        BN_free(s);
        return false;
    }

    unsigned char rBuf[33], bvkBuf[33];
    EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED, rBuf, 33, ctx);
    EC_POINT_point2oct(group, bvk, POINT_CONVERSION_COMPRESSED, bvkBuf, 33, ctx);

    SHA256_CTX sha;
    SHA256_Init(&sha);
    const char* domain = "Innova_BindingSig_v2";
    SHA256_Update(&sha, domain, strlen(domain));
    SHA256_Update(&sha, rBuf, 33);
    SHA256_Update(&sha, bvkBuf, 33);
    SHA256_Update(&sha, sighash.begin(), 32);

    unsigned char eHash[32];
    SHA256_Final(eHash, &sha);

    BIGNUM* e = BN_bin2bn(eHash, 32, NULL);
    BN_mod(e, e, order, ctx);

    CECPointGuard sG(group), eBvk(group), check(group);
    EC_POINT_mul(group, sG, NULL, G, s, ctx);
    EC_POINT_mul(group, eBvk, NULL, bvk, e, ctx);
    EC_POINT_add(group, check, sG, eBvk, ctx);

    bool fValid = (EC_POINT_cmp(group, R, check, ctx) == 0);

    BN_free(s);
    BN_free(e);
    OPENSSL_cleanse(eHash, 32);

    return fValid;
}


bool VerifySpendAuthSignature(const std::vector<unsigned char>& vchRk,
                               const uint256& sighash,
                               const std::vector<unsigned char>& vchSig)
{
    if (!CZKContext::IsInitialized()) return false;
    if (vchRk.size() != 33) return false;
    if (vchSig.size() != 65) return false;

    CECGroupGuard group;
    if (!group.group) return false;

    CBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    const BIGNUM* order = EC_GROUP_get0_order(group);
    const EC_POINT* G = EC_GROUP_get0_generator(group);

    CECPointGuard rk(group);
    if (EC_POINT_oct2point(group, rk, vchRk.data(), vchRk.size(), ctx) != 1)
        return false;

    if (EC_POINT_is_on_curve(group, rk, ctx) != 1)
        return false;

    CECPointGuard R(group);
    if (EC_POINT_oct2point(group, R, vchSig.data(), 33, ctx) != 1)
        return false;
    if (EC_POINT_is_at_infinity(group, R)) return false;
    if (EC_POINT_is_on_curve(group, R, ctx) != 1) return false;

    BIGNUM* s = BN_bin2bn(vchSig.data() + 33, 32, NULL);
    if (!s) return false;

    if (BN_is_negative(s) || BN_cmp(s, order) >= 0)
    {
        BN_free(s);
        return false;
    }

    unsigned char rBuf[33], rkBuf[33];
    EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED, rBuf, 33, ctx);
    memcpy(rkBuf, vchRk.data(), 33);

    SHA256_CTX sha;
    SHA256_Init(&sha);
    const char* domain = "Innova_SpendAuth_v1";
    SHA256_Update(&sha, domain, strlen(domain));
    SHA256_Update(&sha, rBuf, 33);
    SHA256_Update(&sha, rkBuf, 33);
    SHA256_Update(&sha, sighash.begin(), 32);

    unsigned char eHash[32];
    SHA256_Final(eHash, &sha);

    BIGNUM* e = BN_bin2bn(eHash, 32, NULL);
    BN_mod(e, e, order, ctx);

    CECPointGuard sG(group), eRk(group), check(group);
    EC_POINT_mul(group, sG, NULL, G, s, ctx);
    EC_POINT_mul(group, eRk, NULL, rk, e, ctx);
    EC_POINT_add(group, check, sG, eRk, ctx);

    bool fValid = (EC_POINT_cmp(group, R, check, ctx) == 0);

    BN_free(s);
    BN_free(e);
    OPENSSL_cleanse(eHash, 32);

    return fValid;
}

bool CreateSpendAuthSignature(const uint256& skSpend,
                               const uint256& sighash,
                               std::vector<unsigned char>& vchRk,
                               std::vector<unsigned char>& vchSig)
{
    if (!CZKContext::IsInitialized()) return false;

    CECGroupGuard group;
    if (!group.group) return false;

    CBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    const BIGNUM* order = EC_GROUP_get0_order(group);
    const EC_POINT* G = EC_GROUP_get0_generator(group);

    BIGNUM* sk = BN_bin2bn(skSpend.begin(), 32, NULL);
    if (!sk) return false;
    BN_mod(sk, sk, order, ctx);

    BN_set_consttime(sk);

    CECPointGuard rkPoint(group);
    EC_POINT_mul(group, rkPoint, NULL, G, sk, ctx);

    vchRk.resize(33);
    EC_POINT_point2oct(group, rkPoint, POINT_CONVERSION_COMPRESSED, vchRk.data(), 33, ctx);

    unsigned char rndK[32];
    if (RAND_bytes(rndK, 32) != 1) { BN_clear_free(sk); return false; }

    unsigned char skBytes[32];
    memset(skBytes, 0, 32);
    int skLen = BN_num_bytes(sk);
    if (skLen > 0 && skLen <= 32)
        BN_bn2bin(sk, skBytes + (32 - skLen));

    unsigned char nonceInput[96];
    memcpy(nonceInput, skBytes, 32);
    memcpy(nonceInput + 32, sighash.begin(), 32);
    memcpy(nonceInput + 64, rndK, 32);
    OPENSSL_cleanse(skBytes, 32);
    OPENSSL_cleanse(rndK, 32);

    unsigned char hedgedNonce[32];
    unsigned int hmacLen = 32;
    HMAC(EVP_sha256(), "Innova_SpendAuth_nonce", 22,
         nonceInput, 96, hedgedNonce, &hmacLen);
    OPENSSL_cleanse(nonceInput, 96);

    BIGNUM* k = BN_bin2bn(hedgedNonce, 32, NULL);
    BN_mod(k, k, order, ctx);
    OPENSSL_cleanse(hedgedNonce, 32);

    BN_set_consttime(k);

    if (BN_is_zero(k))
    {
        BN_clear_free(sk); BN_clear_free(k);
        return false;
    }

    CECPointGuard R(group);
    EC_POINT_mul(group, R, NULL, G, k, ctx);

    unsigned char rBuf[33];
    EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED, rBuf, 33, ctx);

    SHA256_CTX sha;
    SHA256_Init(&sha);
    const char* domain = "Innova_SpendAuth_v1";
    SHA256_Update(&sha, domain, strlen(domain));
    SHA256_Update(&sha, rBuf, 33);
    SHA256_Update(&sha, vchRk.data(), 33);
    SHA256_Update(&sha, sighash.begin(), 32);

    unsigned char eHash[32];
    SHA256_Final(eHash, &sha);

    BIGNUM* e = BN_bin2bn(eHash, 32, NULL);
    BN_mod(e, e, order, ctx);
    OPENSSL_cleanse(eHash, 32);

    BIGNUM* eSk = BN_new();
    BN_mod_mul(eSk, e, sk, order, ctx);
    BIGNUM* s = BN_new();
    BN_mod_sub(s, k, eSk, order, ctx);

    vchSig.resize(65);
    memcpy(vchSig.data(), rBuf, 33);
    unsigned char sBuf[32];
    memset(sBuf, 0, 32);
    int sLen = BN_num_bytes(s);
    if (sLen > 32) sLen = 32;
    BN_bn2bin(s, sBuf + (32 - sLen));
    memcpy(vchSig.data() + 33, sBuf, 32);

    BN_clear_free(sk);
    BN_clear_free(k);
    BN_free(e);
    BN_clear_free(eSk);
    BN_clear_free(s);
    OPENSSL_cleanse(sBuf, 32);

    return true;
}


uint256 HMAC_SHA256_Compute(const uint256& key, const uint256& data)
{
    unsigned char result[32];
    unsigned int len = 32;

    HMAC(EVP_sha256(), key.begin(), 32, data.begin(), 32, result, &len);

    uint256 hash;
    memcpy(hash.begin(), result, 32);
    OPENSSL_cleanse(result, 32);
    return hash;
}

uint256 PRF_nf(const uint256& nk, const uint256& rho)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << (uint8_t)0x02;
    ss << nk;
    uint256 domainKey = ss.GetHash();

    return HMAC_SHA256_Compute(domainKey, rho);
}


bool ChaCha20Poly1305Encrypt(const std::vector<unsigned char>& vchKey,
                              const std::vector<unsigned char>& vchPlaintext,
                              const std::vector<unsigned char>& vchAad,
                              std::vector<unsigned char>& vchCiphertextOut)
{
    if (vchKey.size() != 32) return false;

    const EVP_CIPHER* cipher = EVP_chacha20_poly1305();
    if (!cipher) return false;

    unsigned char nonce[12];
    if (RAND_bytes(nonce, 12) != 1) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, vchKey.data(), nonce) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int outLen = 0;
    if (!vchAad.empty())
    {
        if (EVP_EncryptUpdate(ctx, NULL, &outLen, vchAad.data(), vchAad.size()) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    std::vector<unsigned char> ciphertext(vchPlaintext.size() + 16);
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outLen, vchPlaintext.data(), vchPlaintext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int totalLen = outLen;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outLen, &outLen) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    totalLen += outLen;

    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);

    vchCiphertextOut.clear();
    vchCiphertextOut.reserve(12 + totalLen + 16);
    vchCiphertextOut.insert(vchCiphertextOut.end(), nonce, nonce + 12);
    vchCiphertextOut.insert(vchCiphertextOut.end(), ciphertext.begin(), ciphertext.begin() + totalLen);
    vchCiphertextOut.insert(vchCiphertextOut.end(), tag, tag + 16);

    return true;
}

bool ChaCha20Poly1305Decrypt(const std::vector<unsigned char>& vchCiphertext,
                              const std::vector<unsigned char>& vchKey,
                              const std::vector<unsigned char>& vchAad,
                              std::vector<unsigned char>& vchPlaintextOut)
{
    if (vchKey.size() != 32) return false;
    if (vchCiphertext.size() < 12 + 16) return false;

    const EVP_CIPHER* cipher = EVP_chacha20_poly1305();
    if (!cipher) return false;

    const unsigned char* nonce = vchCiphertext.data();
    size_t ctLen = vchCiphertext.size() - 12 - 16;
    const unsigned char* ct = vchCiphertext.data() + 12;
    const unsigned char* tag = vchCiphertext.data() + 12 + ctLen;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, vchKey.data(), nonce) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int outLen = 0;
    if (!vchAad.empty())
    {
        if (EVP_DecryptUpdate(ctx, NULL, &outLen, vchAad.data(), vchAad.size()) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    vchPlaintextOut.resize(ctLen);
    if (EVP_DecryptUpdate(ctx, vchPlaintextOut.data(), &outLen, ct, ctLen) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int totalLen = outLen;

    if (EVP_DecryptFinal_ex(ctx, vchPlaintextOut.data() + outLen, &outLen) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        vchPlaintextOut.clear();
        return false;
    }
    totalLen += outLen;

    EVP_CIPHER_CTX_free(ctx);
    vchPlaintextOut.resize(totalLen);

    return true;
}


bool GenerateMuSigNonce(std::vector<unsigned char>& vchNonceOut,
                        std::vector<unsigned char>& vchNoncePointOut)
{
    if (!CZKContext::IsInitialized()) return false;

    CECGroupGuard group;
    if (!group.group) return false;

    CBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    const BIGNUM* order = EC_GROUP_get0_order(group);
    const EC_POINT* G = EC_GROUP_get0_generator(group);

    unsigned char rnd[32];
    if (RAND_bytes(rnd, 32) != 1)
        return false;

    CBNGuard k;
    if (!BN_bin2bn(rnd, 32, k)) { OPENSSL_cleanse(rnd, 32); return false; }
    BN_mod(k, k, order, ctx);
    OPENSSL_cleanse(rnd, 32);

    if (BN_is_zero(k))
        return false;

    vchNonceOut.resize(32);
    memset(vchNonceOut.data(), 0, 32);
    int nBytes = BN_num_bytes(k);
    if (nBytes > 0 && nBytes <= 32)
        BN_bn2bin(k, vchNonceOut.data() + (32 - nBytes));

    CECPointGuard R(group);
    if (EC_POINT_mul(group, R, NULL, G, k, ctx) != 1)
    {
        OPENSSL_cleanse(vchNonceOut.data(), 32);
        vchNonceOut.clear();
        return false;
    }

    return PointToBytes(group, R, vchNoncePointOut, ctx);
}

uint256 ComputeNonceCommitment(const std::vector<unsigned char>& vchNoncePoint)
{
    SHA256_CTX sha;
    SHA256_Init(&sha);
    const char* domain = "Innova_NullSendNonce";
    SHA256_Update(&sha, domain, strlen(domain));
    SHA256_Update(&sha, vchNoncePoint.data(), vchNoncePoint.size());

    uint256 result;
    SHA256_Final((unsigned char*)&result, &sha);
    return result;
}

bool AggregateNoncePoints(const std::vector<std::vector<unsigned char>>& vNoncePoints,
                          std::vector<unsigned char>& vchAggregateOut)
{
    if (vNoncePoints.empty()) return false;
    if (!CZKContext::IsInitialized()) return false;

    CECGroupGuard group;
    if (!group.group) return false;

    CBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    CECPointGuard R(group);
    EC_POINT_set_to_infinity(group, R);

    for (size_t i = 0; i < vNoncePoints.size(); i++)
    {
        CECPointGuard Ri(group);
        if (!BytesToPoint(group, vNoncePoints[i], Ri, ctx))
            return false;
        EC_POINT_add(group, R, R, Ri, ctx);
    }

    if (EC_POINT_is_at_infinity(group, R))
        return false;

    return PointToBytes(group, R, vchAggregateOut, ctx);
}

bool ComputeMuSigChallenge(const std::vector<unsigned char>& vchAggNonce,
                           const std::vector<CPedersenCommitment>& vInputCommits,
                           const std::vector<CPedersenCommitment>& vOutputCommits,
                           int64_t nValueBalance,
                           const uint256& sighash,
                           std::vector<unsigned char>& vchChallengeOut)
{
    if (!CZKContext::IsInitialized()) return false;

    CECGroupGuard group;
    if (!group.group) return false;

    CBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    const BIGNUM* order = EC_GROUP_get0_order(group);

    CECPointGuard bvk(group);
    EC_POINT_set_to_infinity(group, bvk);

    for (size_t i = 0; i < vInputCommits.size(); i++)
    {
        CECPointGuard p(group);
        if (!BytesToPoint(group, vInputCommits[i].vchCommitment, p, ctx)) return false;
        EC_POINT_add(group, bvk, bvk, p, ctx);
    }

    for (size_t i = 0; i < vOutputCommits.size(); i++)
    {
        CECPointGuard p(group);
        if (!BytesToPoint(group, vOutputCommits[i].vchCommitment, p, ctx)) return false;
        EC_POINT_invert(group, p, ctx);
        EC_POINT_add(group, bvk, bvk, p, ctx);
    }

    if (nValueBalance != 0)
    {
        CECPointGuard Hpt(group), vbH(group);
        if (!BytesToPoint(group, CZKContext::GetGeneratorH(), Hpt, ctx)) return false;

        int64_t absVal = (nValueBalance < 0) ? -nValueBalance : nValueBalance;
        CBNGuard bnVal;
        { unsigned char fb[8]; for(int i=7;i>=0;i--) fb[7-i]=(unsigned char)((uint64_t)absVal>>(i*8)); BN_bin2bn(fb,8,bnVal); }
        EC_POINT_mul(group, vbH, NULL, Hpt, bnVal, ctx);
        if (nValueBalance > 0)
            EC_POINT_invert(group, vbH, ctx);
        EC_POINT_add(group, bvk, bvk, vbH, ctx);
    }

    unsigned char rBuf[33], bvkBuf[33];
    if (vchAggNonce.size() != 33) return false;
    memcpy(rBuf, vchAggNonce.data(), 33);
    EC_POINT_point2oct(group, bvk, POINT_CONVERSION_COMPRESSED, bvkBuf, 33, ctx);

    SHA256_CTX sha;
    SHA256_Init(&sha);
    const char* domain = "Innova_BindingSig_v2";
    SHA256_Update(&sha, domain, strlen(domain));
    SHA256_Update(&sha, rBuf, 33);
    SHA256_Update(&sha, bvkBuf, 33);
    SHA256_Update(&sha, sighash.begin(), 32);

    unsigned char eHash[32];
    SHA256_Final(eHash, &sha);

    CBNGuard e;
    BN_bin2bn(eHash, 32, e);
    BN_mod(e, e, order, ctx);

    vchChallengeOut.resize(32);
    memset(vchChallengeOut.data(), 0, 32);
    int nBytes = BN_num_bytes(e);
    if (nBytes > 0 && nBytes <= 32)
        BN_bn2bin(e, vchChallengeOut.data() + (32 - nBytes));

    OPENSSL_cleanse(eHash, 32);
    return true;
}

bool CreatePartialBindingSig(const std::vector<unsigned char>& vchNonce,
                              const std::vector<std::vector<unsigned char>>& vMyInputBlinds,
                              const std::vector<std::vector<unsigned char>>& vMyOutputBlinds,
                              const std::vector<unsigned char>& vchChallenge,
                              std::vector<unsigned char>& vchPartialSigOut)
{
    if (vchNonce.size() != 32 || vchChallenge.size() != 32) return false;
    if (!CZKContext::IsInitialized()) return false;

    CECGroupGuard group;
    if (!group.group) return false;

    CBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    const BIGNUM* order = EC_GROUP_get0_order(group);

    CBNGuard k;
    if (!BN_bin2bn(vchNonce.data(), 32, k)) return false;

    CBNGuard e;
    if (!BN_bin2bn(vchChallenge.data(), 32, e)) return false;

    CBNGuard bsk;
    BN_zero(bsk);

    for (size_t i = 0; i < vMyInputBlinds.size(); i++)
    {
        if (vMyInputBlinds[i].size() != BLINDING_FACTOR_SIZE) return false;
        CBNGuard b;
        if (!BN_bin2bn(vMyInputBlinds[i].data(), BLINDING_FACTOR_SIZE, b)) return false;
        BN_mod_add(bsk, bsk, b, order, ctx);
    }

    for (size_t i = 0; i < vMyOutputBlinds.size(); i++)
    {
        if (vMyOutputBlinds[i].size() != BLINDING_FACTOR_SIZE) return false;
        CBNGuard b;
        if (!BN_bin2bn(vMyOutputBlinds[i].data(), BLINDING_FACTOR_SIZE, b)) return false;
        BN_mod_sub(bsk, bsk, b, order, ctx);
    }

    CBNGuard tmp, s;
    BN_mod_mul(tmp, e, bsk, order, ctx);
    BN_mod_sub(s, k, tmp, order, ctx);

    vchPartialSigOut.resize(32);
    memset(vchPartialSigOut.data(), 0, 32);
    int nBytes = BN_num_bytes(s);
    if (nBytes > 0 && nBytes <= 32)
        BN_bn2bin(s, vchPartialSigOut.data() + (32 - nBytes));

    return true;
}

bool AggregatePartialSigs(const std::vector<std::vector<unsigned char>>& vPartialSigs,
                           std::vector<unsigned char>& vchAggSigOut)
{
    if (vPartialSigs.empty()) return false;
    if (!CZKContext::IsInitialized()) return false;

    CECGroupGuard group;
    if (!group.group) return false;

    CBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    const BIGNUM* order = EC_GROUP_get0_order(group);

    CBNGuard s;
    BN_zero(s);

    for (size_t i = 0; i < vPartialSigs.size(); i++)
    {
        if (vPartialSigs[i].size() != 32) return false;
        CBNGuard si;
        if (!BN_bin2bn(vPartialSigs[i].data(), 32, si)) return false;
        BN_mod_add(s, s, si, order, ctx);
    }

    vchAggSigOut.resize(32);
    memset(vchAggSigOut.data(), 0, 32);
    int nBytes = BN_num_bytes(s);
    if (nBytes > 0 && nBytes <= 32)
        BN_bn2bin(s, vchAggSigOut.data() + (32 - nBytes));

    return true;
}

bool AssembleBindingSignature(const std::vector<unsigned char>& vchAggNonce,
                               const std::vector<unsigned char>& vchAggSig,
                               CBindingSignature& sigOut)
{
    if (vchAggNonce.size() != 33 || vchAggSig.size() != 32) return false;

    sigOut.vchSignature.resize(BINDING_SIGNATURE_SIZE);
    memcpy(sigOut.vchSignature.data(), vchAggNonce.data(), 33);
    memcpy(sigOut.vchSignature.data() + 33, vchAggSig.data(), 32);

    return true;
}
