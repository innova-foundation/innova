// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "nullstake.h"
#include "poseidon2.h"
#include "bulletproof_ac.h"
#include "hash.h"
#include "util.h"
#include "verifycache.h"
#include "bignum.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>
#include <string.h>
#include <algorithm>
#include <utility>

class CZarcBNCtxGuard
{
public:
    BN_CTX* ctx;
    CZarcBNCtxGuard() { ctx = BN_CTX_new(); }
    ~CZarcBNCtxGuard() { if (ctx) BN_CTX_free(ctx); }
    operator BN_CTX*() { return ctx; }
};

class CNullStakeBNGuard
{
public:
    BIGNUM* bn;
    CNullStakeBNGuard() { bn = BN_new(); }
    ~CNullStakeBNGuard() { if (bn) BN_free(bn); }
    operator BIGNUM*() { return bn; }
    BIGNUM* get() { return bn; }
};

class CZarcECGroupGuard
{
public:
    EC_GROUP* group;
    CZarcECGroupGuard() { group = EC_GROUP_new_by_curve_name(NID_secp256k1); }
    ~CZarcECGroupGuard() { if (group) EC_GROUP_free(group); }
    operator const EC_GROUP*() { return group; }
};

class CZarcECPointGuard
{
public:
    EC_POINT* point;
    const EC_GROUP* group;
    CZarcECPointGuard(const EC_GROUP* g) : group(g) { point = EC_POINT_new(g); }
    ~CZarcECPointGuard() { if (point) EC_POINT_free(point); }
    operator EC_POINT*() { return point; }
};

static const char* NULLSTAKE_KERNEL_DOMAIN = "Innova_NullStakeKernel";
static const char* NULLSTAKE_SIGMA_DOMAIN = "Innova_NullStakeSigma";


uint256 PedersenKernelHash(uint64_t nStakeModifier,
                            unsigned int nBlockTimeFrom,
                            unsigned int nTxPrevOffset,
                            unsigned int nTxTimePrev,
                            unsigned int nVoutN,
                            unsigned int nTimeTx)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << std::string(NULLSTAKE_KERNEL_DOMAIN);
    ss << nStakeModifier;
    ss << nBlockTimeFrom;
    ss << nTxPrevOffset;
    ss << nTxTimePrev;
    ss << nVoutN;
    ss << nTimeTx;

    return Hash(ss.begin(), ss.end());
}


bool CheckShieldedStakeKernelHash(unsigned int nBits,
                                   uint64_t nStakeModifier,
                                   unsigned int nBlockTimeFrom,
                                   unsigned int nTxPrevOffset,
                                   unsigned int nTxTimePrev,
                                   unsigned int nVoutN,
                                   unsigned int nTimeTx,
                                   int64_t nValue,
                                   int64_t nWeight)
{
    if (nValue <= 0 || nWeight <= 0)
        return false;

    CBigNum bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);
    if (bnTargetPerCoinDay <= 0)
        return false;

    // regtest: easier target
    {
        extern bool fRegTest;
        if (fRegTest)
            bnTargetPerCoinDay *= 1000;
    }

    uint256 hashKernel = PedersenKernelHash(nStakeModifier, nBlockTimeFrom,
                                             nTxPrevOffset, nTxTimePrev,
                                             nVoutN, nTimeTx);

    CBigNum bnCoinDayWeight = CBigNum(nValue) * nWeight / (int64_t)100000000 / (int64_t)86400;
    CBigNum bnTarget = bnCoinDayWeight * bnTargetPerCoinDay;

    if (fDebug)
    {
        CBigNum bnHash(hashKernel);
        printf("CheckShieldedStakeKernelHash() : hash=%s\n  target=%s\n  coinDayWeight=%s\n",
               bnHash.ToString().c_str(), bnTarget.ToString().c_str(), bnCoinDayWeight.ToString().c_str());
    }
    if (CBigNum(hashKernel) > bnTarget)
        return false;

    return true;
}


bool CreateNullStakeKernelProof(int64_t nValue,
                                const std::vector<unsigned char>& vchBlind,
                                const CPedersenCommitment& cv,
                                unsigned int nBits,
                                int64_t nWeight,
                                uint64_t nStakeModifier,
                                unsigned int nBlockTimeFrom,
                                unsigned int nTxPrevOffset,
                                unsigned int nTxTimePrev,
                                unsigned int nVoutN,
                                unsigned int nTimeTx,
                                CNullStakeKernelProof& proofOut)
{
    if (nValue <= 0 || nWeight <= 0 || vchBlind.size() != 32 || cv.IsNull())
        return false;

    CZarcECGroupGuard group;
    CZarcBNCtxGuard ctx;
    if (!group.group || !ctx.ctx)
        return false;

    CNullStakeBNGuard bnOrder;
    if (!EC_GROUP_get_order(group, bnOrder, ctx))
        return false;

    CZarcECPointGuard H(group);
    {
        const std::vector<unsigned char>& vchH = CZKContext::GetGeneratorH();
        if (vchH.empty() || !EC_POINT_oct2point(group, H, vchH.data(), vchH.size(), ctx))
            return false;
    }

    uint256 hashKernel = PedersenKernelHash(nStakeModifier, nBlockTimeFrom,
                                             nTxPrevOffset, nTxTimePrev,
                                             nVoutN, nTimeTx);

    CBigNum bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);

    CNullStakeBNGuard bnValue, bnWeightScalar, bnVW;
    {
        unsigned char valBytes[8];
        for (int i = 7; i >= 0; i--) valBytes[7-i] = (unsigned char)((uint64_t)nValue >> (i*8));
        BN_bin2bn(valBytes, 8, bnValue);
    }
    {
        unsigned char wBytes[8];
        for (int i = 7; i >= 0; i--) wBytes[7-i] = (unsigned char)((uint64_t)nWeight >> (i*8));
        BN_bin2bn(wBytes, 8, bnWeightScalar);
    }
    BN_mod_mul(bnVW, bnValue, bnWeightScalar, bnOrder, ctx);

    CNullStakeBNGuard bnBlind, bnRW;
    BN_bin2bn(vchBlind.data(), 32, bnBlind);
    BN_mod_mul(bnRW, bnBlind, bnWeightScalar, bnOrder, ctx);

    CZarcECPointGuard CW(group);
    {
        CZarcECPointGuard tmp1(group), tmp2(group);
        EC_POINT_mul(group, tmp1, NULL, H, bnVW, ctx);
        EC_POINT_mul(group, tmp2, bnRW, NULL, NULL, ctx);
        EC_POINT_add(group, CW, tmp1, tmp2, ctx);
    }

    size_t cwLen = EC_POINT_point2oct(group, CW, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    std::vector<unsigned char> vchCW(cwLen);
    EC_POINT_point2oct(group, CW, POINT_CONVERSION_COMPRESSED, vchCW.data(), cwLen, ctx);
    proofOut.weightedCommitment.vchCommitment = vchCW;

    CNullStakeBNGuard bnKV, bnKR;
    BN_rand_range(bnKV, bnOrder);
    if (BN_is_zero(bnKV))
        return false;
    BN_rand_range(bnKR, bnOrder);
    if (BN_is_zero(bnKR))
        return false;

    CZarcECPointGuard A(group);
    {
        CZarcECPointGuard tmp1(group), tmp2(group);
        EC_POINT_mul(group, tmp1, NULL, H, bnKV, ctx);
        EC_POINT_mul(group, tmp2, bnKR, NULL, NULL, ctx);
        EC_POINT_add(group, A, tmp1, tmp2, ctx);
    }

    size_t aLen = EC_POINT_point2oct(group, A, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    std::vector<unsigned char> vchA(aLen);
    EC_POINT_point2oct(group, A, POINT_CONVERSION_COMPRESSED, vchA.data(), aLen, ctx);

    CDataStream ss(SER_GETHASH, 0);
    ss << std::string(NULLSTAKE_SIGMA_DOMAIN);
    ss << cv.vchCommitment;
    ss << vchCW;
    ss << vchA;
    ss << hashKernel;
    ss << nBits;
    uint256 hashChallenge = Hash(ss.begin(), ss.end());

    CNullStakeBNGuard bnE;
    BN_bin2bn(hashChallenge.begin(), 32, bnE);
    BN_mod(bnE, bnE, bnOrder, ctx);

    if (BN_is_zero(bnE))
        return false;

    CNullStakeBNGuard bnSV, bnSR, bnTmp;
    BN_mod_mul(bnTmp, bnE, bnValue, bnOrder, ctx);
    BN_mod_add(bnSV, bnKV, bnTmp, bnOrder, ctx);

    BN_mod_mul(bnTmp, bnE, bnBlind, bnOrder, ctx);
    BN_mod_add(bnSR, bnKR, bnTmp, bnOrder, ctx);

    if (nValue < 0 || nWeight < 0)
        return false;
    CBigNum bnCoinDayWeight = CBigNum(nValue) * nWeight / (int64_t)100000000 / (int64_t)86400;
    if (bnCoinDayWeight < CBigNum(0))
        return false;
    CBigNum bnTargetThreshold = bnCoinDayWeight * bnTargetPerCoinDay;
    CBigNum bnHashKernel(hashKernel);

    if (bnHashKernel > bnTargetThreshold)
        return false;

    CBigNum bnExcess = bnTargetThreshold - bnHashKernel;

    static const int64_t nMaxExcess = (int64_t)9223372036854775807LL;
    int64_t nExcessValue = 0;
    if (bnExcess > CBigNum(nMaxExcess))
        return false;
    if (bnExcess > CBigNum(0))
        nExcessValue = bnExcess.getuint64();

    std::vector<unsigned char> vchExcessBlind(32);
    if (RAND_bytes(vchExcessBlind.data(), 32) != 1)
        return false;

    CPedersenCommitment excessCv;
    if (!CreatePedersenCommitment(nExcessValue, vchExcessBlind, excessCv))
        return false;

    CBulletproofRangeProof excessRangeProof;
    if (!CreateBulletproofRangeProof(nExcessValue, vchExcessBlind, excessCv, excessRangeProof))
        return false;

    CNullStakeBNGuard bnK, bnCOIN, bn86400;
    BN_set_word(bnCOIN, 100000000);  // COIN = 10^8
    BN_set_word(bn86400, 86400);

    CNullStakeBNGuard bnTarget, bnDivisor;
    {
        std::vector<unsigned char> targetBytes = bnTargetPerCoinDay.getvch();
        BN_bin2bn(targetBytes.data(), targetBytes.size(), bnTarget);
    }
    BN_mul(bnDivisor, bnCOIN, bn86400, ctx);  // COIN * 86400

    CNullStakeBNGuard bnKNum, bnDenomInv;
    BN_mul(bnKNum, bnTarget, bnWeightScalar, ctx);

    BN_mod_inverse(bnDenomInv, bnDivisor, bnOrder, ctx);

    BN_mod_mul(bnK, bnKNum, bnDenomInv, bnOrder, ctx);

    CNullStakeBNGuard bnRExcess, bnKRW, bnRDiff;
    BN_bin2bn(vchExcessBlind.data(), 32, bnRExcess);
    BN_mod_mul(bnKRW, bnK, bnRW, bnOrder, ctx);
    BN_mod_sub(bnRDiff, bnRExcess, bnKRW, bnOrder, ctx);

    CNullStakeBNGuard bnKD;
    BN_rand_range(bnKD, bnOrder);

    CZarcECPointGuard RD(group);
    EC_POINT_mul(group, RD, bnKD, NULL, NULL, ctx);

    size_t rdLen = EC_POINT_point2oct(group, RD, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    std::vector<unsigned char> vchRD(rdLen);
    EC_POINT_point2oct(group, RD, POINT_CONVERSION_COMPRESSED, vchRD.data(), rdLen, ctx);

    CDataStream ssBinding(SER_GETHASH, 0);
    ssBinding << std::string("Innova_NullStakeBinding");
    ssBinding << excessCv.vchCommitment;
    ssBinding << hashKernel;
    ssBinding << vchCW;
    ssBinding << vchRD;
    uint256 hashBindingChallenge = Hash(ssBinding.begin(), ssBinding.end());

    CNullStakeBNGuard bnED;
    BN_bin2bn(hashBindingChallenge.begin(), 32, bnED);
    BN_mod(bnED, bnED, bnOrder, ctx);

    if (BN_is_zero(bnED))
        return false;

    CNullStakeBNGuard bnSD, bnTmpD;
    BN_mod_mul(bnTmpD, bnED, bnRDiff, bnOrder, ctx);
    BN_mod_add(bnSD, bnKD, bnTmpD, bnOrder, ctx);

    proofOut.vchProof.clear();
    uint32_t nALen = (uint32_t)vchA.size();
    proofOut.vchProof.insert(proofOut.vchProof.end(), (unsigned char*)&nALen, (unsigned char*)&nALen + 4);
    proofOut.vchProof.insert(proofOut.vchProof.end(), vchA.begin(), vchA.end());

    unsigned char eBytes[32];
    memset(eBytes, 0, 32);
    BN_bn2bin(bnE, eBytes + 32 - BN_num_bytes(bnE));
    proofOut.vchProof.insert(proofOut.vchProof.end(), eBytes, eBytes + 32);

    unsigned char svBytes[32];
    memset(svBytes, 0, 32);
    BN_bn2bin(bnSV, svBytes + 32 - BN_num_bytes(bnSV));
    proofOut.vchProof.insert(proofOut.vchProof.end(), svBytes, svBytes + 32);

    unsigned char srBytes[32];
    memset(srBytes, 0, 32);
    BN_bn2bin(bnSR, srBytes + 32 - BN_num_bytes(bnSR));
    proofOut.vchProof.insert(proofOut.vchProof.end(), srBytes, srBytes + 32);

    uint32_t nExCvLen = (uint32_t)excessCv.vchCommitment.size();
    proofOut.vchProof.insert(proofOut.vchProof.end(), (unsigned char*)&nExCvLen, (unsigned char*)&nExCvLen + 4);
    proofOut.vchProof.insert(proofOut.vchProof.end(), excessCv.vchCommitment.begin(), excessCv.vchCommitment.end());

    uint32_t nExProofLen = (uint32_t)excessRangeProof.vchProof.size();
    proofOut.vchProof.insert(proofOut.vchProof.end(), (unsigned char*)&nExProofLen, (unsigned char*)&nExProofLen + 4);
    proofOut.vchProof.insert(proofOut.vchProof.end(), excessRangeProof.vchProof.begin(), excessRangeProof.vchProof.end());

    uint32_t nRDLen = (uint32_t)vchRD.size();
    proofOut.vchProof.insert(proofOut.vchProof.end(), (unsigned char*)&nRDLen, (unsigned char*)&nRDLen + 4);
    proofOut.vchProof.insert(proofOut.vchProof.end(), vchRD.begin(), vchRD.end());

    unsigned char sdBytes[32];
    memset(sdBytes, 0, 32);
    BN_bn2bin(bnSD, sdBytes + 32 - BN_num_bytes(bnSD));
    proofOut.vchProof.insert(proofOut.vchProof.end(), sdBytes, sdBytes + 32);

    OPENSSL_cleanse(vchExcessBlind.data(), 32);

    proofOut.nStakeModifier = nStakeModifier;
    proofOut.nBlockTimeFrom = nBlockTimeFrom;
    proofOut.nTxPrevOffset = nTxPrevOffset;
    proofOut.nTxTimePrev = nTxTimePrev;
    proofOut.nVoutN = nVoutN;
    proofOut.nTimeTx = nTimeTx;

    return true;
}


bool VerifyNullStakeKernelProof(const CNullStakeKernelProof& proof,
                                const CPedersenCommitment& cv,
                                unsigned int nBits,
                                int64_t nWeight)
{
    if (proof.IsNull() || proof.GetSize() > NULLSTAKE_PROOF_MAX_SIZE)
        return false;
    if (cv.IsNull() || nWeight <= 0)
        return false;

    CZarcECGroupGuard group;
    CZarcBNCtxGuard ctx;
    if (!group.group || !ctx.ctx)
        return false;

    CNullStakeBNGuard bnOrder;
    if (!EC_GROUP_get_order(group, bnOrder, ctx))
        return false;

    CZarcECPointGuard H(group);
    {
        const std::vector<unsigned char>& vchH = CZKContext::GetGeneratorH();
        if (vchH.empty() || !EC_POINT_oct2point(group, H, vchH.data(), vchH.size(), ctx))
            return false;
    }

    if (proof.vchProof.size() < 4)
        return false;

    uint32_t nALen;
    memcpy(&nALen, proof.vchProof.data(), 4);
    if (nALen > 33 || 4 + nALen + 96 > proof.vchProof.size())
        return false;

    CZarcECPointGuard A(group);
    if (!EC_POINT_oct2point(group, A, proof.vchProof.data() + 4, nALen, ctx))
        return false;

    size_t offset = 4 + nALen;

    CNullStakeBNGuard bnE, bnSV, bnSR;
    BN_bin2bn(proof.vchProof.data() + offset, 32, bnE);
    offset += 32;
    BN_bin2bn(proof.vchProof.data() + offset, 32, bnSV);
    offset += 32;
    BN_bin2bn(proof.vchProof.data() + offset, 32, bnSR);

    uint256 hashKernel = PedersenKernelHash(proof.nStakeModifier, proof.nBlockTimeFrom,
                                             proof.nTxPrevOffset, proof.nTxTimePrev,
                                             proof.nVoutN, proof.nTimeTx);

    size_t aSerLen = EC_POINT_point2oct(group, A, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    std::vector<unsigned char> vchA(aSerLen);
    EC_POINT_point2oct(group, A, POINT_CONVERSION_COMPRESSED, vchA.data(), aSerLen, ctx);

    std::vector<unsigned char> vchCW = proof.weightedCommitment.vchCommitment;

    CDataStream ss(SER_GETHASH, 0);
    ss << std::string(NULLSTAKE_SIGMA_DOMAIN);
    ss << cv.vchCommitment;
    ss << vchCW;
    ss << vchA;
    ss << hashKernel;
    ss << nBits;
    uint256 hashChallengeExpected = Hash(ss.begin(), ss.end());

    CNullStakeBNGuard bnEExpected;
    BN_bin2bn(hashChallengeExpected.begin(), 32, bnEExpected);
    BN_mod(bnEExpected, bnEExpected, bnOrder, ctx);

    if (BN_is_zero(bnEExpected))
        return false;

    if (BN_cmp(bnE, bnEExpected) != 0)
        return false;

    CZarcECPointGuard lhs(group);
    {
        CZarcECPointGuard tmp1(group), tmp2(group);
        EC_POINT_mul(group, tmp1, NULL, H, bnSV, ctx);
        EC_POINT_mul(group, tmp2, bnSR, NULL, NULL, ctx);
        EC_POINT_add(group, lhs, tmp1, tmp2, ctx);
    }

    CZarcECPointGuard rhs(group);
    {
        CZarcECPointGuard cvPoint(group);
        if (!EC_POINT_oct2point(group, cvPoint, cv.vchCommitment.data(), cv.vchCommitment.size(), ctx))
            return false;

        CZarcECPointGuard eCv(group);
        EC_POINT_mul(group, eCv, NULL, cvPoint, bnE, ctx);
        EC_POINT_add(group, rhs, A, eCv, ctx);
    }

    if (EC_POINT_cmp(group, lhs, rhs, ctx) != 0)
        return false;

    CNullStakeBNGuard bnWeightScalar;
    {
        unsigned char wBytes[8];
        for (int i = 7; i >= 0; i--) wBytes[7-i] = (unsigned char)((uint64_t)nWeight >> (i*8));
        BN_bin2bn(wBytes, 8, bnWeightScalar);
    }

    CZarcECPointGuard expectedCW(group);
    {
        CZarcECPointGuard cvPoint(group);
        EC_POINT_oct2point(group, cvPoint, cv.vchCommitment.data(), cv.vchCommitment.size(), ctx);
        EC_POINT_mul(group, expectedCW, NULL, cvPoint, bnWeightScalar, ctx);
    }

    CZarcECPointGuard actualCW(group);
    if (!EC_POINT_oct2point(group, actualCW, vchCW.data(), vchCW.size(), ctx))
        return false;

    if (EC_POINT_cmp(group, actualCW, expectedCW, ctx) != 0)
        return false;

    if (offset + 4 > proof.vchProof.size())
        return false;

    uint32_t nExCvLen;
    memcpy(&nExCvLen, proof.vchProof.data() + offset, 4);
    offset += 4;

    if (nExCvLen == 0 || nExCvLen > 33 || offset + nExCvLen > proof.vchProof.size())
        return false;

    CPedersenCommitment excessCv;
    excessCv.vchCommitment.assign(proof.vchProof.data() + offset,
                                   proof.vchProof.data() + offset + nExCvLen);
    offset += nExCvLen;

    if (offset + 4 > proof.vchProof.size())
        return false;

    uint32_t nExProofLen;
    memcpy(&nExProofLen, proof.vchProof.data() + offset, 4);
    offset += 4;

    if (nExProofLen == 0 || nExProofLen > MAX_BULLETPROOF_PROOF_SIZE || offset + nExProofLen > proof.vchProof.size())
        return false;

    CBulletproofRangeProof excessRangeProof;
    excessRangeProof.vchProof.assign(proof.vchProof.data() + offset,
                                      proof.vchProof.data() + offset + nExProofLen);
    offset += nExProofLen;

    if (!VerifyBulletproofRangeProof(excessCv, excessRangeProof))
    {
        if (fDebug)
            printf("VerifyNullStakeKernelProof: excess range proof failed\n");
        return false;
    }

    if (offset + 4 > proof.vchProof.size())
        return false;

    uint32_t nRDLen;
    memcpy(&nRDLen, proof.vchProof.data() + offset, 4);
    offset += 4;

    if (nRDLen == 0 || nRDLen > 33 || offset + nRDLen > proof.vchProof.size())
        return false;

    CZarcECPointGuard RD(group);
    if (!EC_POINT_oct2point(group, RD, proof.vchProof.data() + offset, nRDLen, ctx))
        return false;
    offset += nRDLen;

    if (offset + 32 > proof.vchProof.size())
        return false;

    CNullStakeBNGuard bnSD;
    BN_bin2bn(proof.vchProof.data() + offset, 32, bnSD);
    offset += 32;

    size_t rdSerLen = EC_POINT_point2oct(group, RD, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    std::vector<unsigned char> vchRD(rdSerLen);
    EC_POINT_point2oct(group, RD, POINT_CONVERSION_COMPRESSED, vchRD.data(), rdSerLen, ctx);

    CDataStream ssBinding(SER_GETHASH, 0);
    ssBinding << std::string("Innova_NullStakeBinding");
    ssBinding << excessCv.vchCommitment;
    ssBinding << hashKernel;
    ssBinding << vchCW;
    ssBinding << vchRD;
    uint256 hashBindingChallenge = Hash(ssBinding.begin(), ssBinding.end());

    CNullStakeBNGuard bnED;
    BN_bin2bn(hashBindingChallenge.begin(), 32, bnED);
    BN_mod(bnED, bnED, bnOrder, ctx);

    if (BN_is_zero(bnED))
        return false;

    CBigNum bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);
    std::vector<unsigned char> targetBytes = bnTargetPerCoinDay.getvch();

    CNullStakeBNGuard bnTarget, bnCOIN, bn86400, bnDivisor, bnKNum, bnDenomInv, bnK;
    BN_bin2bn(targetBytes.data(), targetBytes.size(), bnTarget);
    BN_set_word(bnCOIN, 100000000);
    BN_set_word(bn86400, 86400);
    BN_mul(bnDivisor, bnCOIN, bn86400, ctx);

    BN_mul(bnKNum, bnTarget, bnWeightScalar, ctx);
    BN_mod_inverse(bnDenomInv, bnDivisor, bnOrder, ctx);
    BN_mod_mul(bnK, bnKNum, bnDenomInv, bnOrder, ctx);

    CZarcECPointGuard D(group);
    {
        CZarcECPointGuard excessPoint(group);
        if (!EC_POINT_oct2point(group, excessPoint, excessCv.vchCommitment.data(), excessCv.vchCommitment.size(), ctx))
            return false;

        CNullStakeBNGuard bnHashKernel;
        BN_bin2bn(hashKernel.begin(), 32, bnHashKernel);
        BN_mod(bnHashKernel, bnHashKernel, bnOrder, ctx);

        CZarcECPointGuard hashH(group);
        EC_POINT_mul(group, hashH, NULL, H, bnHashKernel, ctx);

        CZarcECPointGuard kCW(group);
        EC_POINT_mul(group, kCW, NULL, actualCW, bnK, ctx);

        EC_POINT_add(group, D, excessPoint, hashH, ctx);
        CZarcECPointGuard negKCW(group);
        EC_POINT_copy(negKCW, kCW);
        EC_POINT_invert(group, negKCW, ctx);
        EC_POINT_add(group, D, D, negKCW, ctx);
    }

    CZarcECPointGuard lhsBinding(group);
    EC_POINT_mul(group, lhsBinding, bnSD, NULL, NULL, ctx);

    CZarcECPointGuard rhsBinding(group);
    {
        CZarcECPointGuard eD(group);
        EC_POINT_mul(group, eD, NULL, D, bnED, ctx);
        EC_POINT_add(group, rhsBinding, RD, eD, ctx);
    }

    if (EC_POINT_cmp(group, lhsBinding, rhsBinding, ctx) != 0)
    {
        if (fDebug)
            printf("VerifyNullStakeKernelProof: algebraic binding proof failed\n");
        return false;
    }

    return true;
}


static const char* NULLSTAKE_V2_LINK_DOMAIN = "Innova_NullStakeV2Linking";


bool CheckShieldedStakeKernelHashV2(unsigned int nBits,
                                     uint64_t nStakeModifier,
                                     unsigned int nBlockTimeFrom,
                                     unsigned int nTxPrevOffset,
                                     unsigned int nTxTimePrev,
                                     unsigned int nVoutN,
                                     unsigned int nTimeTx,
                                     int64_t nValue,
                                     int64_t nWeight)
{
    if (nValue <= 0 || nWeight <= 0)
        return false;

    CBigNum bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);
    if (bnTargetPerCoinDay <= 0)
        return false;

    // regtest: easier target
    {
        extern bool fRegTest;
        if (fRegTest)
            bnTargetPerCoinDay *= 1000;
    }

    uint256 hashKernel = Poseidon2KernelHash(nStakeModifier, nBlockTimeFrom,
                                               nTxPrevOffset, nTxTimePrev,
                                               nVoutN, nTimeTx);

    CBigNum bnCoinDayWeight = CBigNum(nValue) * nWeight / (int64_t)100000000 / (int64_t)86400;
    CBigNum bnTarget = bnCoinDayWeight * bnTargetPerCoinDay;

    if (fDebug)
    {
        CBigNum bnHash(hashKernel);
        printf("CheckShieldedStakeKernelHashV2() : hash=%s\n  target=%s\n  coinDayWeight=%s\n",
               bnHash.ToString().c_str(), bnTarget.ToString().c_str(), bnCoinDayWeight.ToString().c_str());
    }
    if (CBigNum(hashKernel) > bnTarget)
        return false;

    return true;
}


bool CreateNullStakeKernelProofV2(int64_t nValue,
                                  const std::vector<unsigned char>& vchBlind,
                                  const CPedersenCommitment& cv,
                                  unsigned int nBits,
                                  uint64_t nStakeModifier,
                                  unsigned int nBlockTimeFrom,
                                  unsigned int nTxPrevOffset,
                                  unsigned int nTxTimePrev,
                                  unsigned int nVoutN,
                                  unsigned int nTimeTx,
                                  CNullStakeKernelProofV2& proofOut)
{
    if (nValue <= 0 || vchBlind.size() != 32 || cv.IsNull())
        return false;

    if (!CPoseidon2Params::IsInitialized())
        CPoseidon2Params::Initialize();

    CZarcECGroupGuard group;
    CZarcBNCtxGuard ctx;
    if (!group.group || !ctx.ctx)
        return false;

    CNullStakeBNGuard bnOrder;
    if (!EC_GROUP_get_order(group, bnOrder, ctx))
        return false;

    CZarcECPointGuard H(group);
    {
        const std::vector<unsigned char>& vchH = CZKContext::GetGeneratorH();
        if (vchH.empty() || !EC_POINT_oct2point(group, H, vchH.data(), vchH.size(), ctx))
            return false;
    }

    CR1CSCircuit circuit = BuildNullStakeV2Circuit(nStakeModifier, nBlockTimeFrom,
                                                    nTxPrevOffset, nTxTimePrev,
                                                    nVoutN, nTimeTx, nBits);

    CR1CSWitness witness;
    if (!AssignNullStakeV2Witness(circuit, nStakeModifier, nBlockTimeFrom,
                                  nTxPrevOffset, nTxTimePrev, nVoutN,
                                  nTimeTx, nValue, vchBlind, nBits, witness))
    {
        if (fDebug) printf("CreateNullStakeKernelProofV2: witness assignment failed\n");
        return false;
    }

    std::vector<unsigned char> vchValueBlindCircuit(32);
    if (RAND_bytes(vchValueBlindCircuit.data(), 32) != 1)
        return false;

    uint256 blindCircuit;
    for (int i = 0; i < 32; i++)
        blindCircuit.begin()[i] = vchValueBlindCircuit[31 - i];
    witness.vBlinds[0] = blindCircuit;

    CPedersenCommitment valueCommitCircuit;
    if (!CreatePedersenCommitment(nValue, vchValueBlindCircuit, valueCommitCircuit))
    {
        if (fDebug) printf("CreateNullStakeKernelProofV2: circuit commitment failed\n");
        return false;
    }

    proofOut.valueCommitment = valueCommitCircuit;

    std::vector<std::vector<unsigned char>> vCommitments;
    vCommitments.push_back(valueCommitCircuit.vchCommitment);

    if (!CreateBulletproofACProof(circuit, witness, vCommitments, proofOut.acProof))
    {
        if (fDebug) printf("CreateNullStakeKernelProofV2: AC proof creation failed\n");
        return false;
    }

    CNullStakeBNGuard bnRV, bnR, bnS;
    BN_bin2bn(vchValueBlindCircuit.data(), 32, bnRV);
    BN_bin2bn(vchBlind.data(), 32, bnR);
    BN_mod_sub(bnS, bnRV, bnR, bnOrder, ctx);

    CNullStakeBNGuard bnK;
    BN_rand_range(bnK, bnOrder);

    CZarcECPointGuard RLink(group);
    if (EC_POINT_mul(group, RLink, bnK, NULL, NULL, ctx) != 1)
    {
        if (fDebug) printf("CreateNullStakeKernelProofV2: link nonce point failed\n");
        return false;
    }

    size_t rlLen = EC_POINT_point2oct(group, RLink, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    std::vector<unsigned char> vchRL(rlLen);
    EC_POINT_point2oct(group, RLink, POINT_CONVERSION_COMPRESSED, vchRL.data(), rlLen, ctx);

    CDataStream ssLink(SER_GETHASH, 0);
    ssLink << std::string(NULLSTAKE_V2_LINK_DOMAIN);
    ssLink << valueCommitCircuit.vchCommitment;
    ssLink << cv.vchCommitment;
    ssLink << vchRL;
    uint256 hashLinkChallenge = Hash(ssLink.begin(), ssLink.end());

    CNullStakeBNGuard bnELink;
    BN_bin2bn(hashLinkChallenge.begin(), 32, bnELink);
    BN_mod(bnELink, bnELink, bnOrder, ctx);

    if (BN_is_zero(bnELink))
    {
        if (fDebug) printf("CreateNullStakeKernelProofV2: zero link challenge\n");
        return false;
    }

    CNullStakeBNGuard bnSLink, bnTmp;
    BN_mod_mul(bnTmp, bnELink, bnS, bnOrder, ctx);
    BN_mod_add(bnSLink, bnK, bnTmp, bnOrder, ctx);

    proofOut.vchLinkProof.clear();
    proofOut.vchLinkProof.insert(proofOut.vchLinkProof.end(), vchRL.begin(), vchRL.end());

    unsigned char slBytes[32];
    memset(slBytes, 0, 32);
    BN_bn2bin(bnSLink, slBytes + 32 - BN_num_bytes(bnSLink));
    proofOut.vchLinkProof.insert(proofOut.vchLinkProof.end(), slBytes, slBytes + 32);

    proofOut.nStakeModifier = nStakeModifier;
    proofOut.nBlockTimeFrom = nBlockTimeFrom;
    proofOut.nTxPrevOffset = nTxPrevOffset;
    proofOut.nTxTimePrev = nTxTimePrev;
    proofOut.nVoutN = nVoutN;
    proofOut.nTimeTx = nTimeTx;

    OPENSSL_cleanse(vchValueBlindCircuit.data(), 32);

    return true;
}


static bool VerifyNullStakeKernelProofV2Uncached(const CNullStakeKernelProofV2& proof,
                                                 const CPedersenCommitment& cv,
                                                 unsigned int nBits);

bool VerifyNullStakeKernelProofV2(const CNullStakeKernelProofV2& proof,
                                  const CPedersenCommitment& cv,
                                  unsigned int nBits)
{
    if (!VerifyProofCacheEnabled())
        return VerifyNullStakeKernelProofV2Uncached(proof, cv, nBits);

    CHashWriter ss(SER_GETHASH, 0);
    ss << (unsigned char)VERIFYCACHE_NULLSTAKE_V2 << proof << cv << nBits;
    uint256 key = ss.GetHash();
    if (VerifyProofCacheCheck(key))
        return true;
    if (!VerifyNullStakeKernelProofV2Uncached(proof, cv, nBits))
        return false;
    VerifyProofCacheStore(key);
    return true;
}

static bool VerifyNullStakeKernelProofV2Uncached(const CNullStakeKernelProofV2& proof,
                                                 const CPedersenCommitment& cv,
                                                 unsigned int nBits)
{
    if (proof.IsNull() || cv.IsNull())
        return false;

    if (proof.vchLinkProof.size() != 65)
        return false;

    CZarcECGroupGuard group;
    CZarcBNCtxGuard ctx;
    if (!group.group || !ctx.ctx)
        return false;

    CNullStakeBNGuard bnOrder;
    if (!EC_GROUP_get_order(group, bnOrder, ctx))
        return false;

    CR1CSCircuit circuit = BuildNullStakeV2Circuit(proof.nStakeModifier,
                                                    proof.nBlockTimeFrom,
                                                    proof.nTxPrevOffset,
                                                    proof.nTxTimePrev,
                                                    proof.nVoutN,
                                                    proof.nTimeTx, nBits);

    std::vector<std::vector<unsigned char>> vCommitments;
    vCommitments.push_back(proof.valueCommitment.vchCommitment);

    if (!VerifyBulletproofACProof(circuit, vCommitments, proof.acProof))
    {
        if (fDebug)
            printf("VerifyNullStakeKernelProofV2: AC proof verification failed\n");
        return false;
    }

    CZarcECPointGuard RLink(group);
    if (!EC_POINT_oct2point(group, RLink, proof.vchLinkProof.data(), 33, ctx))
        return false;

    CNullStakeBNGuard bnSLink;
    BN_bin2bn(proof.vchLinkProof.data() + 33, 32, bnSLink);

    std::vector<unsigned char> vchRL(proof.vchLinkProof.begin(), proof.vchLinkProof.begin() + 33);

    CDataStream ssLink(SER_GETHASH, 0);
    ssLink << std::string(NULLSTAKE_V2_LINK_DOMAIN);
    ssLink << proof.valueCommitment.vchCommitment;
    ssLink << cv.vchCommitment;
    ssLink << vchRL;
    uint256 hashLinkChallenge = Hash(ssLink.begin(), ssLink.end());

    CNullStakeBNGuard bnELink;
    BN_bin2bn(hashLinkChallenge.begin(), 32, bnELink);
    BN_mod(bnELink, bnELink, bnOrder, ctx);

    if (BN_is_zero(bnELink))
        return false;

    CZarcECPointGuard D(group);
    {
        CZarcECPointGuard VvPoint(group), cvPoint(group);
        if (!EC_POINT_oct2point(group, VvPoint, proof.valueCommitment.vchCommitment.data(),
                                proof.valueCommitment.vchCommitment.size(), ctx))
            return false;
        if (!EC_POINT_oct2point(group, cvPoint, cv.vchCommitment.data(),
                                cv.vchCommitment.size(), ctx))
            return false;

        CZarcECPointGuard negCv(group);
        EC_POINT_copy(negCv, cvPoint);
        EC_POINT_invert(group, negCv, ctx);
        EC_POINT_add(group, D, VvPoint, negCv, ctx);
    }

    CZarcECPointGuard lhsLink(group);
    EC_POINT_mul(group, lhsLink, bnSLink, NULL, NULL, ctx);

    CZarcECPointGuard rhsLink(group);
    {
        CZarcECPointGuard eD(group);
        EC_POINT_mul(group, eD, NULL, D, bnELink, ctx);
        EC_POINT_add(group, rhsLink, RLink, eD, ctx);
    }

    if (EC_POINT_cmp(group, lhsLink, rhsLink, ctx) != 0)
    {
        if (fDebug)
            printf("VerifyNullStakeKernelProofV2: linking proof failed\n");
        return false;
    }

    return true;
}


static const char* NULLSTAKE_V3_LINK_DOMAIN = "Innova_NullStakeV3ColdStakeLinking";


bool CheckShieldedStakeKernelHashV3(unsigned int nBits,
                                     uint64_t nStakeModifier,
                                     unsigned int nBlockTimeFrom,
                                     unsigned int nTxPrevOffset,
                                     unsigned int nTxTimePrev,
                                     unsigned int nVoutN,
                                     unsigned int nTimeTx,
                                     int64_t nValue,
                                     int64_t nWeight)
{
    return CheckShieldedStakeKernelHashV2(nBits, nStakeModifier,
                                           nBlockTimeFrom, nTxPrevOffset,
                                           nTxTimePrev, nVoutN,
                                           nTimeTx, nValue, nWeight);
}


bool CreateNullStakeKernelProofV3(int64_t nValue,
                                  const std::vector<unsigned char>& vchBlind,
                                  const CPedersenCommitment& cv,
                                  unsigned int nBits,
                                  uint64_t nStakeModifier,
                                  unsigned int nBlockTimeFrom,
                                  unsigned int nTxPrevOffset,
                                  unsigned int nTxTimePrev,
                                  unsigned int nVoutN,
                                  unsigned int nTimeTx,
                                  const uint256& skStake,
                                  const std::vector<unsigned char>& vchPkOwner,
                                  const uint256& delegationHash,
                                  CNullStakeKernelProofV3& proofOut)
{
    if (nValue <= 0 || vchBlind.size() != 32 || cv.IsNull())
        return false;
    if (vchPkOwner.size() != 33)
        return false;

    if (!CPoseidon2Params::IsInitialized())
        CPoseidon2Params::Initialize();

    CZarcECGroupGuard group;
    CZarcBNCtxGuard ctx;
    if (!group.group || !ctx.ctx)
        return false;

    CNullStakeBNGuard bnOrder;
    if (!EC_GROUP_get_order(group, bnOrder, ctx))
        return false;

    {
        unsigned char skBE[32];
        const unsigned char* skLE = skStake.begin();
        for (int i = 0; i < 32; i++)
            skBE[i] = skLE[31 - i];

        CNullStakeBNGuard bnSK;
        BN_bin2bn(skBE, 32, bnSK);
        OPENSSL_cleanse(skBE, 32);
        BN_mod(bnSK, bnSK, bnOrder, ctx);

        if (BN_is_zero(bnSK))
            return false;

        CZarcECPointGuard pkOwner(group);
        if (EC_POINT_oct2point(group, pkOwner, vchPkOwner.data(),
                               vchPkOwner.size(), ctx) != 1 ||
            EC_POINT_is_on_curve(group, pkOwner, ctx) != 1 ||
            EC_POINT_is_at_infinity(group, pkOwner))
            return false;

        CZarcECPointGuard pkStake(group);
        if (EC_POINT_mul(group, pkStake, bnSK, NULL, NULL, ctx) != 1)
            return false;

        size_t pkLen = EC_POINT_point2oct(group, pkStake, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        proofOut.vchPkStake.resize(pkLen);
        if (pkLen != 33 ||
            EC_POINT_point2oct(group, pkStake, POINT_CONVERSION_COMPRESSED,
                               proofOut.vchPkStake.data(), pkLen, ctx) != pkLen)
            return false;
    }

    uint256 expectedDelegationHash;
    if (!ComputeNullStakeV3DelegationHash(nValue, proofOut.vchPkStake,
                                          vchPkOwner, expectedDelegationHash) ||
        expectedDelegationHash != delegationHash)
        return false;
    proofOut.vchPkOwner = vchPkOwner;

    CZarcECPointGuard H(group);
    {
        const std::vector<unsigned char>& vchH = CZKContext::GetGeneratorH();
        if (vchH.empty() || !EC_POINT_oct2point(group, H, vchH.data(), vchH.size(), ctx))
            return false;
    }

    CR1CSCircuit circuit = BuildNullStakeV3Circuit(nStakeModifier, nBlockTimeFrom,
                                                    nTxPrevOffset, nTxTimePrev,
                                                    nVoutN, nTimeTx, nBits,
                                                    delegationHash,
                                                    proofOut.vchPkStake,
                                                    proofOut.vchPkOwner);

    CR1CSWitness witness;
    if (!AssignNullStakeV3Witness(circuit, nStakeModifier, nBlockTimeFrom,
                                  nTxPrevOffset, nTxTimePrev, nVoutN,
                                  nTimeTx, nValue, vchBlind, nBits,
                                  skStake, proofOut.vchPkStake, vchPkOwner,
                                  delegationHash, witness))
    {
        if (fDebug) printf("CreateNullStakeKernelProofV3: witness assignment failed\n");
        return false;
    }

    std::vector<unsigned char> vchValueBlindCircuit(32);
    if (RAND_bytes(vchValueBlindCircuit.data(), 32) != 1)
        return false;

    uint256 blindCircuit;
    for (int i = 0; i < 32; i++)
        blindCircuit.begin()[i] = vchValueBlindCircuit[31 - i];
    witness.vBlinds[0] = blindCircuit;

    CPedersenCommitment valueCommitCircuit;
    if (!CreatePedersenCommitment(nValue, vchValueBlindCircuit, valueCommitCircuit))
        return false;

    proofOut.valueCommitment = valueCommitCircuit;

    std::vector<std::vector<unsigned char>> vCommitments;
    vCommitments.push_back(valueCommitCircuit.vchCommitment);

    if (!CreateBulletproofACProof(circuit, witness, vCommitments, proofOut.acProof))
    {
        if (fDebug) printf("CreateNullStakeKernelProofV3: AC proof creation failed\n");
        return false;
    }

    CNullStakeBNGuard bnRV, bnR, bnS;
    BN_bin2bn(vchValueBlindCircuit.data(), 32, bnRV);
    BN_bin2bn(vchBlind.data(), 32, bnR);
    BN_mod_sub(bnS, bnRV, bnR, bnOrder, ctx);

    CNullStakeBNGuard bnK;
    BN_rand_range(bnK, bnOrder);

    CZarcECPointGuard RLink(group);
    if (EC_POINT_mul(group, RLink, bnK, NULL, NULL, ctx) != 1)
        return false;

    size_t rlLen = EC_POINT_point2oct(group, RLink, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    std::vector<unsigned char> vchRL(rlLen);
    if (rlLen != 33 ||
        EC_POINT_point2oct(group, RLink, POINT_CONVERSION_COMPRESSED, vchRL.data(), rlLen, ctx) != rlLen)
        return false;

    CDataStream ssLink(SER_GETHASH, 0);
    ssLink << std::string(NULLSTAKE_V3_LINK_DOMAIN);
    ssLink << valueCommitCircuit.vchCommitment;
    ssLink << cv.vchCommitment;
    ssLink << delegationHash;
    ssLink << proofOut.vchPkStake;
    ssLink << proofOut.vchPkOwner;
    ssLink << vchRL;
    uint256 hashLinkChallenge = Hash(ssLink.begin(), ssLink.end());

    CNullStakeBNGuard bnELink;
    BN_bin2bn(hashLinkChallenge.begin(), 32, bnELink);
    BN_mod(bnELink, bnELink, bnOrder, ctx);

    if (BN_is_zero(bnELink))
        return false;

    CNullStakeBNGuard bnSLink, bnTmp;
    BN_mod_mul(bnTmp, bnELink, bnS, bnOrder, ctx);
    BN_mod_add(bnSLink, bnK, bnTmp, bnOrder, ctx);

    proofOut.vchLinkProof.clear();
    proofOut.vchLinkProof.insert(proofOut.vchLinkProof.end(), vchRL.begin(), vchRL.end());

    unsigned char slBytes[32];
    memset(slBytes, 0, 32);
    BN_bn2bin(bnSLink, slBytes + 32 - BN_num_bytes(bnSLink));
    proofOut.vchLinkProof.insert(proofOut.vchLinkProof.end(), slBytes, slBytes + 32);

    proofOut.nStakeModifier = nStakeModifier;
    proofOut.nBlockTimeFrom = nBlockTimeFrom;
    proofOut.nTxPrevOffset = nTxPrevOffset;
    proofOut.nTxTimePrev = nTxTimePrev;
    proofOut.nVoutN = nVoutN;
    proofOut.nTimeTx = nTimeTx;
    proofOut.delegationHash = delegationHash;
    proofOut.vchPkOwner = vchPkOwner;

    OPENSSL_cleanse(vchValueBlindCircuit.data(), 32);

    return true;
}

// ============================================================================
// B2-e: M-of-N (half-aggregated Schnorr) cold-stake kernel proof (value-decoupled,
// public-signer tier). The note leaf is the 3-generator commitment
//   cv3 = value*H + blind*G + delegationHash*J.
// The kernel proof proves range+weight over the J-free commitment
//   cv_plain = cv3 - delegationHash*J
// with the V2 (range+weight only) circuit, links the circuit's value commitment to
// cv_plain, and requires an M-of-N half-aggregated signature -- the only check that
// needs the member secret keys -- over a stake digest bound to the leaf + kernel params.
// ============================================================================

static const char* NULLSTAKE_V3_MOFN_LINK_DOMAIN = "Innova_NullStakeV3MofNLinking";

// Shared Fiat-Shamir challenge for the M-of-N value-commitment link, so create and verify
// build the IDENTICAL transcript. Binds the circuit commitment Vv, the J-free leaf
// commitment cv_plain, the delegation, and the stake digest (which itself binds cv3 +
// kernel params). The set is bound through delegationHash (the set hash) and re-checked by
// the authorization gate.
static uint256 NullStakeMofNLinkChallenge(const std::vector<unsigned char>& vchVv,
                                          const std::vector<unsigned char>& vchCvPlain,
                                          const uint256& delegationHash,
                                          const uint256& stakeDigest,
                                          const std::vector<unsigned char>& vchRL)
{
    CDataStream ssLink(SER_GETHASH, 0);
    ssLink << std::string(NULLSTAKE_V3_MOFN_LINK_DOMAIN);
    ssLink << vchVv;
    ssLink << vchCvPlain;
    ssLink << delegationHash;
    ssLink << stakeDigest;
    ssLink << vchRL;
    return Hash(ssLink.begin(), ssLink.end());
}

bool CreateNullStakeMofNKernelProofV3(int64_t nValue,
                                      const std::vector<unsigned char>& vchBlind,
                                      const CPedersenCommitment& cv3,
                                      unsigned int nBits,
                                      uint64_t nStakeModifier,
                                      unsigned int nBlockTimeFrom,
                                      unsigned int nTxPrevOffset,
                                      unsigned int nTxTimePrev,
                                      unsigned int nVoutN,
                                      unsigned int nTimeTx,
                                      const std::vector<std::vector<unsigned char> >& vStakerSet,
                                      unsigned int nThresholdM,
                                      const std::vector<unsigned char>& vchPkOwner,
                                      const uint256& delegationHash,
                                      const std::vector<uint256>& vSignerSecrets,
                                      CNullStakeKernelProofV3& proofOut)
{
    if (nValue <= 0 || vchBlind.size() != 32 || cv3.IsNull())
        return false;
    if (vchPkOwner.size() != 33)
        return false;
    if (vStakerSet.empty() || vStakerSet.size() > MAX_NULLSTAKE_MOFN_MEMBERS)
        return false;
    if (nThresholdM < 1 || nThresholdM > vStakerSet.size())
        return false;
    if (vSignerSecrets.size() < nThresholdM || vSignerSecrets.size() > vStakerSet.size())
        return false;

    // The set must hash to the supplied delegationHash, and the leaf must be the 3-generator
    // commitment to (nValue, vchBlind, delegationHash).
    uint256 expectedDeleg;
    if (!ComputeNullStakeV3DelegationSetHash(vStakerSet, nThresholdM, vchPkOwner, expectedDeleg) ||
        expectedDeleg != delegationHash)
        return false;
    if (!VerifyNullStakeMofNCommitment(cv3, nValue, vchBlind, delegationHash))
        return false;

    // cv_plain = value*H + blind*G (J-free), the commitment the circuit + link operate on.
    CPedersenCommitment cvPlain;
    if (!CreatePedersenCommitment(nValue, vchBlind, cvPlain))
        return false;

    if (!CPoseidon2Params::IsInitialized())
        CPoseidon2Params::Initialize();
    CZarcECGroupGuard group;
    CZarcBNCtxGuard ctx;
    if (!group.group || !ctx.ctx)
        return false;
    CNullStakeBNGuard bnOrder;
    if (!EC_GROUP_get_order(group, bnOrder, ctx))
        return false;

    // V2 range+weight circuit over a freshly-blinded circuit commitment Vv.
    CR1CSCircuit circuit = BuildNullStakeV2Circuit(nStakeModifier, nBlockTimeFrom,
                                                    nTxPrevOffset, nTxTimePrev,
                                                    nVoutN, nTimeTx, nBits);
    CR1CSWitness witness;
    if (!AssignNullStakeV2Witness(circuit, nStakeModifier, nBlockTimeFrom,
                                  nTxPrevOffset, nTxTimePrev, nVoutN,
                                  nTimeTx, nValue, vchBlind, nBits, witness))
        return false;

    std::vector<unsigned char> vchRv(32);
    if (RAND_bytes(vchRv.data(), 32) != 1)
        return false;
    uint256 blindCircuit;
    for (int i = 0; i < 32; i++)
        blindCircuit.begin()[i] = vchRv[31 - i];
    witness.vBlinds[0] = blindCircuit;

    CPedersenCommitment Vv;
    if (!CreatePedersenCommitment(nValue, vchRv, Vv))
    {
        OPENSSL_cleanse(vchRv.data(), 32);
        return false;
    }
    proofOut.valueCommitment = Vv;

    std::vector<std::vector<unsigned char> > vCommitments;
    vCommitments.push_back(Vv.vchCommitment);
    if (!CreateBulletproofACProof(circuit, witness, vCommitments, proofOut.acProof))
    {
        OPENSSL_cleanse(vchRv.data(), 32);
        return false;
    }

    // Stake digest binds the leaf cv3 + delegation + chain-pinned kernel params.
    uint256 stakeDigest = ComputeNullStakeMofNStakeDigest(delegationHash, nStakeModifier,
                                                          nBlockTimeFrom, nTxPrevOffset,
                                                          nTxTimePrev, nVoutN, nTimeTx,
                                                          cv3.vchCommitment);

    // Half-aggregated signature: each signer signs the digest; sort by pubkey (canonical),
    // keeping (pk, R, s) paired. Aggregation sums the s-scalars.
    typedef std::pair<std::vector<unsigned char>,
                      std::pair<std::vector<unsigned char>, std::vector<unsigned char> > > SignerTrip;
    std::vector<SignerTrip> trips;
    for (size_t i = 0; i < vSignerSecrets.size(); i++)
    {
        std::vector<unsigned char> pk, R, s;
        if (!HalfAggStakeDerivePubKey(vSignerSecrets[i], pk) ||
            !SignHalfAggStakeShare(vSignerSecrets[i], stakeDigest, R, s))
        {
            OPENSSL_cleanse(vchRv.data(), 32);
            return false;
        }
        trips.push_back(std::make_pair(pk, std::make_pair(R, s)));
    }
    std::sort(trips.begin(), trips.end());
    proofOut.vSignerPubKeys.clear();
    proofOut.vSignerRPoints.clear();
    std::vector<std::vector<unsigned char> > vS;
    for (size_t i = 0; i < trips.size(); i++)
    {
        proofOut.vSignerPubKeys.push_back(trips[i].first);
        proofOut.vSignerRPoints.push_back(trips[i].second.first);
        vS.push_back(trips[i].second.second);
    }
    if (!AggregatePartialSigs(vS, proofOut.vchAggregatedSScalar))
    {
        OPENSSL_cleanse(vchRv.data(), 32);
        return false;
    }

    // Value-commitment link: D = Vv - cv_plain = (rv - r)*G; prove knowledge of (rv - r).
    CNullStakeBNGuard bnRV, bnR, bnS;
    BN_bin2bn(vchRv.data(), 32, bnRV);
    BN_bin2bn(vchBlind.data(), 32, bnR);
    BN_mod_sub(bnS, bnRV, bnR, bnOrder, ctx);

    CNullStakeBNGuard bnK;
    BN_rand_range(bnK, bnOrder);
    CZarcECPointGuard RLink(group);
    if (EC_POINT_mul(group, RLink, bnK, NULL, NULL, ctx) != 1)
    {
        OPENSSL_cleanse(vchRv.data(), 32);
        return false;
    }
    std::vector<unsigned char> vchRL(33);
    if (EC_POINT_point2oct(group, RLink, POINT_CONVERSION_COMPRESSED, vchRL.data(), 33, ctx) != 33)
    {
        OPENSSL_cleanse(vchRv.data(), 32);
        return false;
    }

    uint256 hashLinkChallenge = NullStakeMofNLinkChallenge(Vv.vchCommitment, cvPlain.vchCommitment,
                                                           delegationHash, stakeDigest, vchRL);
    CNullStakeBNGuard bnELink;
    BN_bin2bn(hashLinkChallenge.begin(), 32, bnELink);
    BN_mod(bnELink, bnELink, bnOrder, ctx);
    if (BN_is_zero(bnELink))
    {
        OPENSSL_cleanse(vchRv.data(), 32);
        return false;
    }

    CNullStakeBNGuard bnSLink, bnTmp;
    BN_mod_mul(bnTmp, bnELink, bnS, bnOrder, ctx);
    BN_mod_add(bnSLink, bnK, bnTmp, bnOrder, ctx);

    proofOut.vchLinkProof.clear();
    proofOut.vchLinkProof.insert(proofOut.vchLinkProof.end(), vchRL.begin(), vchRL.end());
    unsigned char slBytes[32];
    memset(slBytes, 0, 32);
    BN_bn2bin(bnSLink, slBytes + 32 - BN_num_bytes(bnSLink));
    proofOut.vchLinkProof.insert(proofOut.vchLinkProof.end(), slBytes, slBytes + 32);

    proofOut.nThresholdM = nThresholdM;
    proofOut.vStakerSet = vStakerSet;       // canonicalize so the wire form is non-malleable
    std::sort(proofOut.vStakerSet.begin(), proofOut.vStakerSet.end());
    proofOut.delegationHash = delegationHash;
    proofOut.vchPkOwner = vchPkOwner;
    proofOut.vchPkStake.clear();            // M-of-N: no single staking key
    proofOut.nStakeModifier = nStakeModifier;
    proofOut.nBlockTimeFrom = nBlockTimeFrom;
    proofOut.nTxPrevOffset = nTxPrevOffset;
    proofOut.nTxTimePrev = nTxTimePrev;
    proofOut.nVoutN = nVoutN;
    proofOut.nTimeTx = nTimeTx;

    OPENSSL_cleanse(vchRv.data(), 32);
    return true;
}

// Dedicated verifier for an M-of-N (nThresholdM > 0) V3 cold-stake kernel proof. Called from
// VerifyNullStakeKernelProofV3Uncached so the verify cache (keyed on the full serialized proof)
// covers every input. cv3 is the FCMP-membership-verified leaf (3-generator commitment).
static bool VerifyNullStakeMofNKernelProofV3(const CNullStakeKernelProofV3& proof,
                                             const CPedersenCommitment& cv3,
                                             unsigned int nBits)
{
    // Structural + DoS caps (bound before any heavy work).
    // Tier tag: the B2-c hidden mode is dispatched away before this function; every other value must be
    // the public half-agg tier exactly (rejects an out-of-range nAuthMode that would otherwise slip in).
    if (proof.nAuthMode != NULLSTAKE_AUTHMODE_HALFAGG)
        return false;
    if (proof.nThresholdM < 1 || proof.nThresholdM > MAX_NULLSTAKE_MOFN_MEMBERS)
        return false;
    if (proof.vStakerSet.empty() || proof.vStakerSet.size() > MAX_NULLSTAKE_MOFN_MEMBERS)
        return false;
    if (proof.nThresholdM > proof.vStakerSet.size())
        return false;
    if (proof.vSignerPubKeys.size() < proof.nThresholdM ||
        proof.vSignerPubKeys.size() > MAX_NULLSTAKE_MOFN_SIGNERS)
        return false;
    if (proof.vSignerRPoints.size() != proof.vSignerPubKeys.size())   // R-points paired 1:1 with signers
        return false;
    if (proof.valueCommitment.vchCommitment.size() != 33)             // circuit commitment must be a point
        return false;
    if (!proof.vchPkStake.empty())            // M-of-N proofs carry a SET, never a single pkStake
        return false;
    if (proof.vchPkOwner.size() != 33)
        return false;
    if (cv3.vchCommitment.size() != 33)
        return false;
    if (proof.vchLinkProof.size() != 65)
        return false;
    {
        uint256 zero; memset(zero.begin(), 0, 32);
        if (proof.delegationHash == zero)
            return false;
    }
    // Canonical-range guard: reject delegationHash >= n (the authorization recompute, which
    // produces a value < n, also enforces this via the equality check).
    if (FieldReduce(proof.delegationHash) != proof.delegationHash)
        return false;

    if (!CPoseidon2Params::IsInitialized())
        CPoseidon2Params::Initialize();
    CZarcECGroupGuard group;
    CZarcBNCtxGuard ctx;
    if (!group.group || !ctx.ctx)
        return false;
    CNullStakeBNGuard bnOrder;
    if (!EC_GROUP_get_order(group, bnOrder, ctx))
        return false;

    // Recover the J-free commitment from the FCMP-verified leaf cv3 (a wrong delegationHash
    // leaves a J residual that the J-free range/link proofs below reject).
    CPedersenCommitment cvPlain;
    if (!NullStakeMofNDeriveValueCommitment(cv3, proof.delegationHash, cvPlain))
        return false;

    // V2 range+weight proof over proof.valueCommitment (J-free 2-generator basis).
    CR1CSCircuit circuit = BuildNullStakeV2Circuit(proof.nStakeModifier, proof.nBlockTimeFrom,
                                                    proof.nTxPrevOffset, proof.nTxTimePrev,
                                                    proof.nVoutN, proof.nTimeTx, nBits);
    std::vector<std::vector<unsigned char> > vCommitments;
    vCommitments.push_back(proof.valueCommitment.vchCommitment);
    if (!VerifyBulletproofACProof(circuit, vCommitments, proof.acProof))
    {
        if (fDebug) printf("VerifyNullStakeMofNKernelProofV3: AC proof failed\n");
        return false;
    }

    // Stake digest over the leaf cv3 + delegation + kernel params.
    uint256 stakeDigest = ComputeNullStakeMofNStakeDigest(proof.delegationHash, proof.nStakeModifier,
                                                          proof.nBlockTimeFrom, proof.nTxPrevOffset,
                                                          proof.nTxTimePrev, proof.nVoutN, proof.nTimeTx,
                                                          cv3.vchCommitment);

    // Value-commitment link to cv_plain (NOT cv3): proves Vv and cv_plain share the same
    // value*H, so the range/weight proven over Vv applies to the staked note's value.
    std::vector<unsigned char> vchRL(proof.vchLinkProof.begin(), proof.vchLinkProof.begin() + 33);
    CZarcECPointGuard RLink(group);
    if (!EC_POINT_oct2point(group, RLink, vchRL.data(), 33, ctx))
        return false;
    CNullStakeBNGuard bnSLink;
    BN_bin2bn(proof.vchLinkProof.data() + 33, 32, bnSLink);
    // Canonical link s-scalar (s < n): reject non-canonical encodings so the link proof bytes
    // are not malleable (matches the half-agg s-scalar range check).
    if (BN_is_negative(bnSLink) || BN_cmp(bnSLink, bnOrder) >= 0)
        return false;

    uint256 hashLinkChallenge = NullStakeMofNLinkChallenge(proof.valueCommitment.vchCommitment,
                                                           cvPlain.vchCommitment, proof.delegationHash,
                                                           stakeDigest, vchRL);
    CNullStakeBNGuard bnELink;
    BN_bin2bn(hashLinkChallenge.begin(), 32, bnELink);
    BN_mod(bnELink, bnELink, bnOrder, ctx);
    if (BN_is_zero(bnELink))
        return false;

    CZarcECPointGuard D(group);
    {
        CZarcECPointGuard VvPoint(group), cvpPoint(group);
        if (!EC_POINT_oct2point(group, VvPoint, proof.valueCommitment.vchCommitment.data(),
                                proof.valueCommitment.vchCommitment.size(), ctx))
            return false;
        if (!EC_POINT_oct2point(group, cvpPoint, cvPlain.vchCommitment.data(),
                                cvPlain.vchCommitment.size(), ctx))
            return false;
        CZarcECPointGuard negCvp(group);
        EC_POINT_copy(negCvp, cvpPoint);
        EC_POINT_invert(group, negCvp, ctx);
        EC_POINT_add(group, D, VvPoint, negCvp, ctx);
    }
    CZarcECPointGuard lhsLink(group);
    EC_POINT_mul(group, lhsLink, bnSLink, NULL, NULL, ctx);
    CZarcECPointGuard rhsLink(group);
    {
        CZarcECPointGuard eD(group);
        EC_POINT_mul(group, eD, NULL, D, bnELink, ctx);
        EC_POINT_add(group, rhsLink, RLink, eD, ctx);
    }
    if (EC_POINT_cmp(group, lhsLink, rhsLink, ctx) != 0)
    {
        if (fDebug) printf("VerifyNullStakeMofNKernelProofV3: link proof failed\n");
        return false;
    }

    // MANDATORY M-of-N authorization: the ONLY gate requiring the member secret keys. Recompute
    // SetHash(set,M,owner) == proof.delegationHash, require distinct member signers (count >= M)
    // in canonical order, and verify the half-aggregated signature over the leaf-bound digest.
    std::string err;
    if (!VerifyNullStakeMofNAuthorization(proof.vStakerSet, proof.nThresholdM, proof.vchPkOwner,
                                          proof.delegationHash, proof.vSignerPubKeys,
                                          proof.vSignerRPoints, proof.vchAggregatedSScalar,
                                          stakeDigest, err))
    {
        if (fDebug) printf("VerifyNullStakeMofNKernelProofV3: authorization failed: %s\n", err.c_str());
        return false;
    }

    return true;
}


// B2-c (Increment 4): hidden-signer M-of-N kernel verifier. IDENTICAL value spine to the B2-e verifier
// (derive cv_plain from the FCMP-verified cv3, AC range/weight over Vv, recompute the stake digest, value-
// link Vv<->cv_plain); it swaps ONLY the authorization predicate -- the revealed half-agg signers become a
// ring-DLEQ hidden-auth proof. Every statement input is recomputed here from consensus data (cv3 + kernel
// params); nothing is trusted from proof-carried statement fields. Height-independent (the B2C fork gate
// lives at the height-aware call sites) so the verify cache stays deterministic.
static bool VerifyNullStakeB2CHiddenKernelProofV3(const CNullStakeKernelProofV3& proof,
                                                  const CPedersenCommitment& cv3,
                                                  unsigned int nBits)
{
    // Tier tag + structural/DoS caps.
    if (proof.nAuthMode != NULLSTAKE_AUTHMODE_B2C_HIDDEN)
        return false;
    if (proof.nThresholdM < 1 || proof.nThresholdM > MAX_NULLSTAKE_MOFN_MEMBERS)
        return false;
    if (proof.vStakerSet.empty() || proof.vStakerSet.size() > MAX_NULLSTAKE_MOFN_MEMBERS)
        return false;
    if (proof.nThresholdM > proof.vStakerSet.size())
        return false;
    // The B2-e public half-agg triple MUST be empty for a hidden proof (the empty-vchPkStake analogue:
    // a hidden proof never carries revealed signers).
    if (!proof.vSignerPubKeys.empty() || !proof.vSignerRPoints.empty() || !proof.vchAggregatedSScalar.empty())
        return false;
    if (proof.hiddenAuth.IsNull())
        return false;
    if (proof.hiddenAuth.GetProofSize() > NULLSTAKE_B2C_MAX_AUTH_SIZE)
        return false;
    if (proof.valueCommitment.vchCommitment.size() != 33)
        return false;
    if (!proof.vchPkStake.empty())            // M-of-N proofs carry a SET, never a single pkStake
        return false;
    if (proof.vchPkOwner.size() != 33)
        return false;
    if (cv3.vchCommitment.size() != 33)
        return false;
    if (proof.vchLinkProof.size() != 65)
        return false;
    {
        uint256 zero; memset(zero.begin(), 0, 32);
        if (proof.delegationHash == zero)
            return false;
    }
    if (FieldReduce(proof.delegationHash) != proof.delegationHash)
        return false;

    if (!CPoseidon2Params::IsInitialized())
        CPoseidon2Params::Initialize();
    CZarcECGroupGuard group;
    CZarcBNCtxGuard ctx;
    if (!group.group || !ctx.ctx)
        return false;
    CNullStakeBNGuard bnOrder;
    if (!EC_GROUP_get_order(group, bnOrder, ctx))
        return false;

    // Recover the J-free commitment from the FCMP-verified leaf cv3 (identical to the B2-e spine).
    CPedersenCommitment cvPlain;
    if (!NullStakeMofNDeriveValueCommitment(cv3, proof.delegationHash, cvPlain))
        return false;

    CR1CSCircuit circuit = BuildNullStakeV2Circuit(proof.nStakeModifier, proof.nBlockTimeFrom,
                                                    proof.nTxPrevOffset, proof.nTxTimePrev,
                                                    proof.nVoutN, proof.nTimeTx, nBits);
    std::vector<std::vector<unsigned char> > vCommitments;
    vCommitments.push_back(proof.valueCommitment.vchCommitment);
    if (!VerifyBulletproofACProof(circuit, vCommitments, proof.acProof))
    {
        if (fDebug) printf("VerifyNullStakeB2CHiddenKernelProofV3: AC proof failed\n");
        return false;
    }

    uint256 stakeDigest = ComputeNullStakeMofNStakeDigest(proof.delegationHash, proof.nStakeModifier,
                                                          proof.nBlockTimeFrom, proof.nTxPrevOffset,
                                                          proof.nTxTimePrev, proof.nVoutN, proof.nTimeTx,
                                                          cv3.vchCommitment);

    // Value-commitment link Vv <-> cv_plain (identical to the B2-e spine).
    std::vector<unsigned char> vchRL(proof.vchLinkProof.begin(), proof.vchLinkProof.begin() + 33);
    CZarcECPointGuard RLink(group);
    if (!EC_POINT_oct2point(group, RLink, vchRL.data(), 33, ctx))
        return false;
    CNullStakeBNGuard bnSLink;
    BN_bin2bn(proof.vchLinkProof.data() + 33, 32, bnSLink);
    if (BN_is_negative(bnSLink) || BN_cmp(bnSLink, bnOrder) >= 0)
        return false;
    uint256 hashLinkChallenge = NullStakeMofNLinkChallenge(proof.valueCommitment.vchCommitment,
                                                           cvPlain.vchCommitment, proof.delegationHash,
                                                           stakeDigest, vchRL);
    CNullStakeBNGuard bnELink;
    BN_bin2bn(hashLinkChallenge.begin(), 32, bnELink);
    BN_mod(bnELink, bnELink, bnOrder, ctx);
    if (BN_is_zero(bnELink))
        return false;
    CZarcECPointGuard Dpt(group);
    {
        CZarcECPointGuard VvPoint(group), cvpPoint(group);
        if (!EC_POINT_oct2point(group, VvPoint, proof.valueCommitment.vchCommitment.data(),
                                proof.valueCommitment.vchCommitment.size(), ctx))
            return false;
        if (!EC_POINT_oct2point(group, cvpPoint, cvPlain.vchCommitment.data(),
                                cvPlain.vchCommitment.size(), ctx))
            return false;
        CZarcECPointGuard negCvp(group);
        EC_POINT_copy(negCvp, cvpPoint);
        EC_POINT_invert(group, negCvp, ctx);
        EC_POINT_add(group, Dpt, VvPoint, negCvp, ctx);
    }
    CZarcECPointGuard lhsLink(group);
    EC_POINT_mul(group, lhsLink, bnSLink, NULL, NULL, ctx);
    CZarcECPointGuard rhsLink(group);
    {
        CZarcECPointGuard eD(group);
        EC_POINT_mul(group, eD, NULL, Dpt, bnELink, ctx);
        EC_POINT_add(group, rhsLink, RLink, eD, ctx);
    }
    if (EC_POINT_cmp(group, lhsLink, rhsLink, ctx) != 0)
    {
        if (fDebug) printf("VerifyNullStakeB2CHiddenKernelProofV3: link proof failed\n");
        return false;
    }

    // MANDATORY hidden authorization: prove >= M distinct committed members authorized the RECOMPUTED
    // stake digest without revealing which. Statement inputs (stakeDigest, kernelValueCommitment := cv3)
    // are the consensus-recomputed values; the hidden verifier rebuilds the statement hash internally.
    std::string err;
    if (!VerifyNullStakeMofNHiddenAuthProof(proof.vStakerSet, proof.nThresholdM, proof.vchPkOwner,
                                            proof.delegationHash, stakeDigest, cv3,
                                            proof.hiddenAuth, err))
    {
        if (fDebug) printf("VerifyNullStakeB2CHiddenKernelProofV3: hidden authorization failed: %s\n", err.c_str());
        return false;
    }

    return true;
}


static bool VerifyNullStakeKernelProofV3Uncached(const CNullStakeKernelProofV3& proof,
                                                 const CPedersenCommitment& cv,
                                                 unsigned int nBits);

bool VerifyNullStakeKernelProofV3(const CNullStakeKernelProofV3& proof,
                                  const CPedersenCommitment& cv,
                                  unsigned int nBits)
{
    if (!VerifyProofCacheEnabled())
        return VerifyNullStakeKernelProofV3Uncached(proof, cv, nBits);

    CHashWriter ss(SER_GETHASH, 0);
    ss << (unsigned char)VERIFYCACHE_NULLSTAKE_V3 << proof << cv << nBits;
    uint256 key = ss.GetHash();
    if (VerifyProofCacheCheck(key))
        return true;
    if (!VerifyNullStakeKernelProofV3Uncached(proof, cv, nBits))
        return false;
    VerifyProofCacheStore(key);
    return true;
}

static bool VerifyNullStakeKernelProofV3Uncached(const CNullStakeKernelProofV3& proof,
                                                 const CPedersenCommitment& cv,
                                                 unsigned int nBits)
{
    if (proof.IsNull() || cv.IsNull())
        return false;

    // B2-e: route M-of-N (nThresholdM > 0) proofs to the value-decoupled verifier. This verify
    // is height-independent (so it can be verify-cached deterministically); the fork-height gate
    // rejecting nThresholdM > 0 before FORK_HEIGHT_NULLSTAKE_DELEGSET is enforced by the
    // height-aware consensus call sites: ConnectBlock (main.cpp, on pindex->nHeight) and the
    // finality vote path (finality.cpp, on pEpochBlock->nHeight). The legacy 1-of-1
    // (nThresholdM == 0) path below is unchanged; a 3-generator M-of-N leaf submitted as
    // nThresholdM == 0 fails the 1-of-1 link (which targets the raw leaf with its J term).
    // B2-c hidden tier (nAuthMode == B2C_HIDDEN) routes to the ring-DLEQ verifier; the B2C height gate
    // is enforced at the call sites (like DELEGSET). Any other M-of-N nAuthMode is the B2-e public tier.
    if (proof.nThresholdM > 0 && proof.nAuthMode == NULLSTAKE_AUTHMODE_B2C_HIDDEN)
        return VerifyNullStakeB2CHiddenKernelProofV3(proof, cv, nBits);
    if (proof.nThresholdM > 0)
        return VerifyNullStakeMofNKernelProofV3(proof, cv, nBits);

    if (proof.vchLinkProof.size() != 65)
        return false;

    {
        uint256 zero;
        memset(zero.begin(), 0, 32);
        if (proof.delegationHash == zero)
            return false;
    }

    if (proof.vchPkStake.size() != 33)  // Only accept compressed pubkeys
        return false;
    if (proof.vchPkOwner.size() != 33)
        return false;

    if (!CPoseidon2Params::IsInitialized())
        CPoseidon2Params::Initialize();

    CZarcECGroupGuard group;
    CZarcBNCtxGuard ctx;
    if (!group.group || !ctx.ctx)
        return false;

    CZarcECPointGuard pkStake(group);
    if (EC_POINT_oct2point(group, pkStake, proof.vchPkStake.data(),
                           proof.vchPkStake.size(), ctx) != 1 ||
        EC_POINT_is_on_curve(group, pkStake, ctx) != 1 ||
        EC_POINT_is_at_infinity(group, pkStake))
        return false;

    CZarcECPointGuard pkOwner(group);
    if (EC_POINT_oct2point(group, pkOwner, proof.vchPkOwner.data(),
                           proof.vchPkOwner.size(), ctx) != 1 ||
        EC_POINT_is_on_curve(group, pkOwner, ctx) != 1 ||
        EC_POINT_is_at_infinity(group, pkOwner))
        return false;

    CNullStakeBNGuard bnOrder;
    if (!EC_GROUP_get_order(group, bnOrder, ctx))
        return false;

    CR1CSCircuit circuit = BuildNullStakeV3Circuit(proof.nStakeModifier,
                                                    proof.nBlockTimeFrom,
                                                    proof.nTxPrevOffset,
                                                    proof.nTxTimePrev,
                                                    proof.nVoutN,
                                                    proof.nTimeTx,
                                                    nBits, proof.delegationHash,
                                                    proof.vchPkStake,
                                                    proof.vchPkOwner);

    std::vector<std::vector<unsigned char>> vCommitments;
    vCommitments.push_back(proof.valueCommitment.vchCommitment);

    if (!VerifyBulletproofACProof(circuit, vCommitments, proof.acProof))
    {
        if (fDebug)
            printf("VerifyNullStakeKernelProofV3: AC proof verification failed\n");
        return false;
    }

    std::vector<unsigned char> vchRL(proof.vchLinkProof.begin(), proof.vchLinkProof.begin() + 33);
    std::vector<unsigned char> vchSL(proof.vchLinkProof.begin() + 33, proof.vchLinkProof.end());

    CZarcECPointGuard RLink(group);
    if (!EC_POINT_oct2point(group, RLink, vchRL.data(), vchRL.size(), ctx))
        return false;

    CNullStakeBNGuard bnSLink;
    BN_bin2bn(vchSL.data(), 32, bnSLink);

    CDataStream ssLink(SER_GETHASH, 0);
    ssLink << std::string(NULLSTAKE_V3_LINK_DOMAIN);
    ssLink << proof.valueCommitment.vchCommitment;
    ssLink << cv.vchCommitment;
    ssLink << proof.delegationHash;
    ssLink << proof.vchPkStake;
    ssLink << proof.vchPkOwner;
    ssLink << vchRL;
    uint256 hashLinkChallenge = Hash(ssLink.begin(), ssLink.end());

    CNullStakeBNGuard bnELink;
    BN_bin2bn(hashLinkChallenge.begin(), 32, bnELink);
    BN_mod(bnELink, bnELink, bnOrder, ctx);

    if (BN_is_zero(bnELink))
        return false;

    CZarcECPointGuard D(group);
    {
        CZarcECPointGuard VvPoint(group), cvPoint(group);
        if (!EC_POINT_oct2point(group, VvPoint, proof.valueCommitment.vchCommitment.data(),
                                proof.valueCommitment.vchCommitment.size(), ctx))
            return false;
        if (!EC_POINT_oct2point(group, cvPoint, cv.vchCommitment.data(),
                                cv.vchCommitment.size(), ctx))
            return false;

        CZarcECPointGuard negCv(group);
        EC_POINT_copy(negCv, cvPoint);
        EC_POINT_invert(group, negCv, ctx);
        EC_POINT_add(group, D, VvPoint, negCv, ctx);
    }

    CZarcECPointGuard lhsLink(group);
    EC_POINT_mul(group, lhsLink, bnSLink, NULL, NULL, ctx);

    CZarcECPointGuard rhsLink(group);
    {
        CZarcECPointGuard eD(group);
        EC_POINT_mul(group, eD, NULL, D, bnELink, ctx);
        EC_POINT_add(group, rhsLink, RLink, eD, ctx);
    }

    if (EC_POINT_cmp(group, lhsLink, rhsLink, ctx) != 0)
    {
        if (fDebug)
            printf("VerifyNullStakeKernelProofV3: linking proof failed\n");
        return false;
    }

    return true;
}


// ============================================================================
// B2-c research prototype: hidden M-of-N authorization, off-consensus.
//
// The BPAC track is explicitly gated below. Under the current cap, full secp256k1
// membership+authorization inside BPAC is estimated too large, so Create... uses a
// threshold-ring xM fallback: M independent one-out-of-N DLEQ ring proofs. Each slot proves
// knowledge of x for some public member P_i=xG and a per-proof duplicate tag T=xH_tag.
// Tags are checked distinct within one proof, but H_tag includes a random proof nonce, so
// tags do not provide a stable cross-proof signer handle.
// ============================================================================

size_t CNullStakeMofNHiddenAuthProof::GetProofSize() const
{
    CDataStream ss(SER_DISK, 0);
    ss << *this;
    return ss.size();
}

bool EstimateNullStakeB2CHiddenAuthBPACBudget(unsigned int nMembers,
                                              unsigned int nThresholdM,
                                              bool fIncludeECAuth,
                                              CNullStakeB2CBPACBudget& budgetOut)
{
    budgetOut = CNullStakeB2CBPACBudget();
    budgetOut.nMembers = nMembers;
    budgetOut.nThresholdM = nThresholdM;
    budgetOut.fECAuthIncluded = fIncludeECAuth;

    if (nMembers == 0 || nMembers > MAX_NULLSTAKE_MOFN_MEMBERS ||
        nThresholdM == 0 || nThresholdM > nMembers)
    {
        budgetOut.strFallbackReason = "invalid B2-c M-of-N budget parameters";
        return false;
    }

    // Constraint spike for selector bits, threshold count, distinctness, and transcript binding.
    // These are conservative planning numbers, not a consensus circuit commitment.
    budgetOut.nSelectorConstraints = nMembers * nThresholdM;                  // boolean selector matrix
    budgetOut.nThresholdConstraints = nThresholdM + nMembers + 8;             // row sums + M counter
    budgetOut.nDistinctnessConstraints = (nThresholdM * (nThresholdM - 1) / 2) * nMembers;
    budgetOut.nTranscriptConstraints = 512 + 8 * nMembers + 64 * nThresholdM; // statement/hash binding

    // A complete secp256k1 Schnorr/public-key relation inside this BPAC system needs field
    // arithmetic, point decompression, scalar multiplication, and challenge binding per hidden
    // signer. This dominates the selector budget and exceeds the current B2-c cap even at M=1.
    budgetOut.nECAuthConstraints = fIncludeECAuth ? (32000 * nThresholdM) : 0;
    budgetOut.nTotalConstraints = budgetOut.nSelectorConstraints +
                                  budgetOut.nThresholdConstraints +
                                  budgetOut.nDistinctnessConstraints +
                                  budgetOut.nTranscriptConstraints +
                                  budgetOut.nECAuthConstraints;

    const unsigned int nPadded = 1u << 13; // cap target for the research gate
    budgetOut.nEstimatedProofSize = 512 + (size_t)nPadded / 2 +
                                    (size_t)budgetOut.nTotalConstraints / 4;
    budgetOut.fWithinConstraintCap =
        budgetOut.nTotalConstraints <= NULLSTAKE_B2C_BPAC_AUTH_CONSTRAINT_CAP;
    budgetOut.fWithinProofCap =
        budgetOut.nEstimatedProofSize <= NULLSTAKE_B2C_BPAC_AUTH_PROOF_MAX_SIZE;
    budgetOut.fBPACFeasible = fIncludeECAuth &&
                              budgetOut.fWithinConstraintCap &&
                              budgetOut.fWithinProofCap;

    if (!budgetOut.fBPACFeasible)
    {
        if (!fIncludeECAuth)
            budgetOut.strFallbackReason = "BPAC selector/threshold spike only; EC authorization not included";
        else if (!budgetOut.fWithinConstraintCap)
            budgetOut.strFallbackReason = "BPAC secp256k1 authorization estimate exceeds B2-c constraint cap";
        else
            budgetOut.strFallbackReason = "BPAC secp256k1 authorization estimate exceeds B2-c proof-size cap";
    }
    return true;
}

static bool NullStakeB2CPointToBytes(const EC_GROUP* group, const EC_POINT* point,
                                     BN_CTX* ctx, std::vector<unsigned char>& out)
{
    size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    if (len != 33)
        return false;
    out.resize(33);
    return EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED,
                              out.data(), out.size(), ctx) == out.size();
}

static bool NullStakeB2CBytesToPoint(const EC_GROUP* group,
                                     const std::vector<unsigned char>& in,
                                     EC_POINT* point,
                                     BN_CTX* ctx)
{
    if (in.size() != 33)
        return false;
    if (EC_POINT_oct2point(group, point, in.data(), in.size(), ctx) != 1)
        return false;
    if (EC_POINT_is_at_infinity(group, point) ||
        EC_POINT_is_on_curve(group, point, ctx) != 1)
        return false;
    std::vector<unsigned char> canonical;
    if (!NullStakeB2CPointToBytes(group, point, ctx, canonical))
        return false;
    return canonical == in;
}

static bool NullStakeB2CBNToScalar(const BIGNUM* bn, uint256& out)
{
    if (!bn || BN_is_negative(bn) || BN_num_bytes(bn) > 32)
        return false;
    memset(out.begin(), 0, 32);
    int nBytes = BN_num_bytes(bn);
    if (nBytes > 0)
        BN_bn2bin(bn, out.begin() + (32 - nBytes));
    return true;
}

static bool NullStakeB2CScalarToBN(const uint256& scalar,
                                   const BIGNUM* order,
                                   BIGNUM* out)
{
    if (!BN_bin2bn(scalar.begin(), 32, out))
        return false;
    return !BN_is_negative(out) && BN_cmp(out, order) < 0;
}

static bool NullStakeB2CRandomScalar(const BIGNUM* order, BIGNUM* out, bool fNonZero)
{
    for (unsigned int i = 0; i < 64; i++)
    {
        if (BN_rand_range(out, order) != 1)
            return false;
        if (!fNonZero || !BN_is_zero(out))
            return true;
    }
    return false;
}

// Hedged ring-proof nonce (parity with SignHalfAggStakeShare's HMAC-hedged nonce, zkproof.cpp): the scalar
// is derived from H(domain || slotSecret || statementHash || per-proof-nonce || slot || label || idx ||
// counter || fresh-random). Binding it to the signing secret means a weak or failed RNG cannot by itself
// leak the witness (an attacker who does not know the secret still cannot predict the Schnorr nonce), while
// the fresh random + per-proof nonce keep the alphas/simulated scalars independent across proofs of the
// same statement -- which the signer-set unlinkability property requires.
static bool NullStakeB2CHedgedScalar(const uint256& slotSecret,
                                     const uint256& statementHash,
                                     const std::vector<unsigned char>& nonce,
                                     uint32_t nSlot,
                                     uint32_t nLabel,
                                     uint32_t nIdx,
                                     const BIGNUM* order,
                                     BN_CTX* ctx,
                                     BIGNUM* out,
                                     bool fNonZero)
{
    for (uint32_t counter = 0; counter < 256; counter++)
    {
        unsigned char rnd[32];
        if (RAND_bytes(rnd, 32) != 1)
            return false;
        CDataStream ss(SER_GETHASH, 0);
        ss << std::string("Innova_NullStakeB2C_HedgedNonce_v1");
        ss << slotSecret;
        ss << statementHash;
        ss << nonce;
        ss << nSlot;
        ss << nLabel;
        ss << nIdx;
        ss << counter;
        ss.write((const char*)rnd, 32);
        uint256 h = Hash(ss.begin(), ss.end());
        OPENSSL_cleanse(rnd, 32);
        if (!BN_bin2bn(h.begin(), 32, out))
            return false;
        BN_mod(out, out, order, ctx);
        if (!fNonZero || !BN_is_zero(out))
            return true;
    }
    return false;
}

static bool NullStakeB2CSecretToBN(const uint256& sk,
                                   const BIGNUM* order,
                                   BN_CTX* ctx,
                                   BIGNUM* out)
{
    if (!BN_bin2bn(sk.begin(), 32, out))
        return false;
    BN_mod(out, out, order, ctx);
    return !BN_is_zero(out);
}

static bool NullStakeB2CHashToTagBase(const uint256& statementHash,
                                      const std::vector<unsigned char>& nonce,
                                      const EC_GROUP* group,
                                      BN_CTX* ctx,
                                      EC_POINT* out)
{
    if (nonce.size() != 32)
        return false;

    for (uint32_t counter = 0; counter < 512; counter++)
    {
        CDataStream ss(SER_GETHASH, 0);
        ss << std::string("Innova_NullStakeB2C_TagBase_v1");
        ss << statementHash;
        ss << nonce;
        ss << counter;
        uint256 h = Hash(ss.begin(), ss.end());

        unsigned char compressed[33];
        compressed[0] = 0x02;
        memcpy(compressed + 1, h.begin(), 32);
        if (EC_POINT_oct2point(group, out, compressed, 33, ctx) == 1 &&
            !EC_POINT_is_at_infinity(group, out) &&
            EC_POINT_is_on_curve(group, out, ctx) == 1)
            return true;
    }
    return false;
}

uint256 ComputeNullStakeMofNHiddenAuthStatementHash(const std::vector<std::vector<unsigned char> >& vStakerSet,
                                                    unsigned int nThresholdM,
                                                    const std::vector<unsigned char>& vchPkOwner,
                                                    const uint256& delegationHash,
                                                    const uint256& stakeDigest,
                                                    const CPedersenCommitment& kernelValueCommitment,
                                                    unsigned int nAuthMode)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << std::string("Innova_NullStakeB2C_HiddenAuthStatement_v1");
    ss << delegationHash;
    // Bind the authorization-tier tag so a proof valid under one tier's statement is not a witness under
    // another's -- closes the cross-tier reinterpretation gap the wiring audit flagged.
    ss << (uint32_t)nAuthMode;
    ss << (uint32_t)nThresholdM;
    ss << (uint32_t)vStakerSet.size();
    ss << vchPkOwner;
    ss << stakeDigest;
    ss << kernelValueCommitment.vchCommitment;
    for (size_t i = 0; i < vStakerSet.size(); i++)
        ss << vStakerSet[i];
    return Hash(ss.begin(), ss.end());
}

static bool NullStakeB2CValidateStatement(const std::vector<std::vector<unsigned char> >& vStakerSet,
                                          unsigned int nThresholdM,
                                          const std::vector<unsigned char>& vchPkOwner,
                                          const uint256& delegationHash,
                                          const uint256& stakeDigest,
                                          const CPedersenCommitment& kernelValueCommitment,
                                          std::string& strError)
{
    strError.clear();
    if (vStakerSet.empty() || vStakerSet.size() > MAX_NULLSTAKE_MOFN_MEMBERS)
    {
        strError = "staker set size out of range";
        return false;
    }
    if (nThresholdM < 1 || nThresholdM > vStakerSet.size())
    {
        strError = "threshold M out of range";
        return false;
    }
    if (vchPkOwner.size() != 33)
    {
        strError = "owner pubkey must be 33 bytes";
        return false;
    }
    if (kernelValueCommitment.vchCommitment.size() != 33 || kernelValueCommitment.IsNull())
    {
        strError = "kernel value commitment is invalid";
        return false;
    }
    if (delegationHash == uint256(0) || FieldReduce(delegationHash) != delegationHash)
    {
        strError = "delegation hash is zero or non-canonical";
        return false;
    }
    if (stakeDigest == uint256(0))
    {
        strError = "stake digest must be nonzero";
        return false;
    }
    for (size_t i = 0; i < vStakerSet.size(); i++)
    {
        if (vStakerSet[i].size() != 33)
        {
            strError = "staker pubkey must be 33 bytes";
            return false;
        }
        if (i > 0 && !(vStakerSet[i - 1] < vStakerSet[i]))
        {
            strError = "staker set not strictly ascending";
            return false;
        }
    }

    uint256 recomputed;
    if (!ComputeNullStakeV3DelegationSetHash(vStakerSet, nThresholdM, vchPkOwner, recomputed) ||
        recomputed != delegationHash)
    {
        strError = "staker set does not match delegation hash";
        return false;
    }

    CZarcECGroupGuard group;
    CZarcBNCtxGuard ctx;
    if (!group.group || !ctx.ctx)
    {
        strError = "EC context allocation failed";
        return false;
    }
    CZarcECPointGuard point(group);
    if (!NullStakeB2CBytesToPoint(group, vchPkOwner, point, ctx))
    {
        strError = "owner pubkey is not a valid compressed secp256k1 point";
        return false;
    }
    if (!NullStakeB2CBytesToPoint(group, kernelValueCommitment.vchCommitment, point, ctx))
    {
        strError = "kernel value commitment is not a valid compressed secp256k1 point";
        return false;
    }
    for (size_t i = 0; i < vStakerSet.size(); i++)
    {
        if (!NullStakeB2CBytesToPoint(group, vStakerSet[i], point, ctx))
        {
            strError = "staker pubkey is not a valid compressed secp256k1 point";
            return false;
        }
    }
    return true;
}

static bool NullStakeB2CComputeSlotChallenge(const uint256& statementHash,
                                             const std::vector<unsigned char>& nonce,
                                             unsigned int nSlot,
                                             const std::vector<unsigned char>& vchTag,
                                             const std::vector<std::vector<unsigned char> >& vA,
                                             const std::vector<std::vector<unsigned char> >& vB,
                                             const BIGNUM* order,
                                             BN_CTX* ctx,
                                             BIGNUM* challengeOut)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << std::string("Innova_NullStakeB2C_RingDLEQ_v1");
    ss << statementHash;
    ss << nonce;
    ss << (uint32_t)nSlot;
    ss << vchTag;
    ss << (uint32_t)vA.size();
    for (size_t i = 0; i < vA.size(); i++)
    {
        ss << vA[i];
        ss << vB[i];
    }
    uint256 h = Hash(ss.begin(), ss.end());
    if (!BN_bin2bn(h.begin(), 32, challengeOut))
        return false;
    BN_mod(challengeOut, challengeOut, order, ctx);
    return true;
}

static bool NullStakeB2CComputeProofCommitments(const std::vector<std::vector<unsigned char> >& vStakerSet,
                                                const EC_POINT* tag,
                                                const EC_POINT* tagBase,
                                                const std::vector<uint256>& vChallenges,
                                                const std::vector<uint256>& vResponses,
                                                const EC_GROUP* group,
                                                const BIGNUM* order,
                                                BN_CTX* ctx,
                                                std::vector<std::vector<unsigned char> >& vAOut,
                                                std::vector<std::vector<unsigned char> >& vBOut)
{
    if (vChallenges.size() != vStakerSet.size() || vResponses.size() != vStakerSet.size())
        return false;

    vAOut.clear();
    vBOut.clear();
    for (size_t i = 0; i < vStakerSet.size(); i++)
    {
        CNullStakeBNGuard c, z;
        if (!NullStakeB2CScalarToBN(vChallenges[i], order, c) ||
            !NullStakeB2CScalarToBN(vResponses[i], order, z))
            return false;

        CZarcECPointGuard member(group);
        if (!NullStakeB2CBytesToPoint(group, vStakerSet[i], member, ctx))
            return false;

        CZarcECPointGuard zG(group), cP(group), A(group);
        if (EC_POINT_mul(group, zG, z, NULL, NULL, ctx) != 1)
            return false;
        if (EC_POINT_mul(group, cP, NULL, member, c, ctx) != 1)
            return false;
        if (EC_POINT_invert(group, cP, ctx) != 1)
            return false;
        if (EC_POINT_add(group, A, zG, cP, ctx) != 1)
            return false;

        CZarcECPointGuard zH(group), cT(group), B(group);
        if (EC_POINT_mul(group, zH, NULL, tagBase, z, ctx) != 1)
            return false;
        if (EC_POINT_mul(group, cT, NULL, tag, c, ctx) != 1)
            return false;
        if (EC_POINT_invert(group, cT, ctx) != 1)
            return false;
        if (EC_POINT_add(group, B, zH, cT, ctx) != 1)
            return false;

        std::vector<unsigned char> aBytes, bBytes;
        if (!NullStakeB2CPointToBytes(group, A, ctx, aBytes) ||
            !NullStakeB2CPointToBytes(group, B, ctx, bBytes))
            return false;
        vAOut.push_back(aBytes);
        vBOut.push_back(bBytes);
    }
    return true;
}

bool CreateNullStakeMofNHiddenAuthProof(const std::vector<std::vector<unsigned char> >& vStakerSet,
                                        unsigned int nThresholdM,
                                        const std::vector<unsigned char>& vchPkOwner,
                                        const uint256& delegationHash,
                                        const uint256& stakeDigest,
                                        const CPedersenCommitment& kernelValueCommitment,
                                        const std::vector<uint256>& vSignerSecrets,
                                        CNullStakeMofNHiddenAuthProof& proofOut,
                                        std::string& strError)
{
    proofOut = CNullStakeMofNHiddenAuthProof();
    strError.clear();
    if (!CZKContext::Initialize())
    {
        strError = "zk context initialization failed";
        return false;
    }
    if (!NullStakeB2CValidateStatement(vStakerSet, nThresholdM, vchPkOwner, delegationHash,
                                       stakeDigest, kernelValueCommitment, strError))
        return false;
    if (vSignerSecrets.size() != nThresholdM)
    {
        strError = "prototype requires exactly M signer secrets";
        return false;
    }

    // NOTE: this construction is the ring xM DLEQ path unconditionally. A single-shot BPAC circuit for the
    // full secp256k1 M-of-N authorization is estimated over the research cap even at M=1 (see
    // EstimateNullStakeB2CHiddenAuthBPACBudget, kept as an ADVISORY sizing estimate for future work, not an
    // operative feasibility branch), so there is no BPAC prover to select. Parameter validity is already
    // enforced by NullStakeB2CValidateStatement above and the exactly-M signer-secret check.

    proofOut.nVersion = NULLSTAKE_B2C_HIDDEN_AUTH_VERSION;
    proofOut.nAuthType = NULLSTAKE_B2C_AUTH_TYPE_RINGXM_DLEQ;
    proofOut.vchTagBaseNonce.resize(32);
    if (RAND_bytes(proofOut.vchTagBaseNonce.data(), 32) != 1 ||
        proofOut.vchTagBaseNonce == std::vector<unsigned char>(32, 0))
    {
        strError = "failed to create B2-c proof nonce";
        return false;
    }

    const uint256 statementHash = ComputeNullStakeMofNHiddenAuthStatementHash(
        vStakerSet, nThresholdM, vchPkOwner, delegationHash, stakeDigest, kernelValueCommitment);

    CZarcECGroupGuard group;
    CZarcBNCtxGuard ctx;
    if (!group.group || !ctx.ctx)
    {
        strError = "EC context allocation failed";
        return false;
    }
    CNullStakeBNGuard order;
    if (!EC_GROUP_get_order(group, order, ctx))
    {
        strError = "EC order lookup failed";
        return false;
    }

    CZarcECPointGuard tagBase(group);
    if (!NullStakeB2CHashToTagBase(statementHash, proofOut.vchTagBaseNonce, group, ctx, tagBase))
    {
        strError = "failed to derive B2-c tag base";
        return false;
    }

    std::vector<std::vector<unsigned char> > vUsedSignerPks;
    for (size_t slot = 0; slot < vSignerSecrets.size(); slot++)
    {
        std::vector<unsigned char> signerPk;
        if (!HalfAggStakeDerivePubKey(vSignerSecrets[slot], signerPk))
        {
            strError = "failed to derive signer pubkey";
            return false;
        }
        std::vector<std::vector<unsigned char> >::const_iterator it =
            std::find(vStakerSet.begin(), vStakerSet.end(), signerPk);
        if (it == vStakerSet.end())
        {
            strError = "signer secret is not a member of the delegated set";
            return false;
        }
        if (std::find(vUsedSignerPks.begin(), vUsedSignerPks.end(), signerPk) != vUsedSignerPks.end())
        {
            strError = "duplicate signer secret";
            return false;
        }
        vUsedSignerPks.push_back(signerPk);
        const size_t realIndex = (size_t)(it - vStakerSet.begin());

        CNullStakeBNGuard sk;
        if (!NullStakeB2CSecretToBN(vSignerSecrets[slot], order, ctx, sk))
        {
            strError = "invalid signer secret scalar";
            return false;
        }
        CNullStakeBNGuard alpha;
        if (!NullStakeB2CHedgedScalar(vSignerSecrets[slot], statementHash, proofOut.vchTagBaseNonce,
                                      (uint32_t)slot, /*label=alpha*/ 0, 0, order, ctx, alpha, true))
        {
            strError = "failed to generate ring proof nonce";
            return false;
        }

        CZarcECPointGuard tag(group);
        if (EC_POINT_mul(group, tag, NULL, tagBase, sk, ctx) != 1)
        {
            strError = "failed to compute hidden duplicate tag";
            return false;
        }
        CNullStakeMofNHiddenAuthRingSlotProof slotProof;
        if (!NullStakeB2CPointToBytes(group, tag, ctx, slotProof.vchTag))
        {
            strError = "failed to encode hidden duplicate tag";
            return false;
        }

        slotProof.vChallenges.assign(vStakerSet.size(), uint256(0));
        slotProof.vResponses.assign(vStakerSet.size(), uint256(0));
        std::vector<std::vector<unsigned char> > vA(vStakerSet.size());
        std::vector<std::vector<unsigned char> > vB(vStakerSet.size());
        CNullStakeBNGuard sumC;
        BN_zero(sumC);

        for (size_t i = 0; i < vStakerSet.size(); i++)
        {
            if (i == realIndex)
            {
                CZarcECPointGuard A(group), B(group);
                if (EC_POINT_mul(group, A, alpha, NULL, NULL, ctx) != 1 ||
                    EC_POINT_mul(group, B, NULL, tagBase, alpha, ctx) != 1 ||
                    !NullStakeB2CPointToBytes(group, A, ctx, vA[i]) ||
                    !NullStakeB2CPointToBytes(group, B, ctx, vB[i]))
                {
                    strError = "failed to create real ring commitment";
                    return false;
                }
                continue;
            }

            CNullStakeBNGuard c, z;
            if (!NullStakeB2CHedgedScalar(vSignerSecrets[slot], statementHash, proofOut.vchTagBaseNonce,
                                          (uint32_t)slot, /*label=simC*/ 1, (uint32_t)i, order, ctx, c, false) ||
                !NullStakeB2CHedgedScalar(vSignerSecrets[slot], statementHash, proofOut.vchTagBaseNonce,
                                          (uint32_t)slot, /*label=simZ*/ 2, (uint32_t)i, order, ctx, z, false))
            {
                strError = "failed to generate simulated ring scalars";
                return false;
            }
            BN_mod_add(sumC, sumC, c, order, ctx);
            if (!NullStakeB2CBNToScalar(c, slotProof.vChallenges[i]) ||
                !NullStakeB2CBNToScalar(z, slotProof.vResponses[i]))
            {
                strError = "failed to encode simulated ring scalars";
                return false;
            }

            CZarcECPointGuard member(group);
            if (!NullStakeB2CBytesToPoint(group, vStakerSet[i], member, ctx))
            {
                strError = "invalid member pubkey";
                return false;
            }
            CZarcECPointGuard zG(group), cP(group), A(group);
            if (EC_POINT_mul(group, zG, z, NULL, NULL, ctx) != 1 ||
                EC_POINT_mul(group, cP, NULL, member, c, ctx) != 1 ||
                EC_POINT_invert(group, cP, ctx) != 1 ||
                EC_POINT_add(group, A, zG, cP, ctx) != 1)
            {
                strError = "failed to create simulated public-key commitment";
                return false;
            }
            CZarcECPointGuard zH(group), cT(group), B(group);
            if (EC_POINT_mul(group, zH, NULL, tagBase, z, ctx) != 1 ||
                EC_POINT_mul(group, cT, NULL, tag, c, ctx) != 1 ||
                EC_POINT_invert(group, cT, ctx) != 1 ||
                EC_POINT_add(group, B, zH, cT, ctx) != 1)
            {
                strError = "failed to create simulated tag commitment";
                return false;
            }
            if (!NullStakeB2CPointToBytes(group, A, ctx, vA[i]) ||
                !NullStakeB2CPointToBytes(group, B, ctx, vB[i]))
            {
                strError = "failed to encode simulated ring commitments";
                return false;
            }
        }

        CNullStakeBNGuard totalC, realC, realZ, tmp;
        if (!NullStakeB2CComputeSlotChallenge(statementHash, proofOut.vchTagBaseNonce,
                                              (unsigned int)slot, slotProof.vchTag,
                                              vA, vB, order, ctx, totalC))
        {
            strError = "failed to compute ring challenge";
            return false;
        }
        BN_mod_sub(realC, totalC, sumC, order, ctx);
        BN_mod_mul(tmp, realC, sk, order, ctx);
        BN_mod_add(realZ, alpha, tmp, order, ctx);

        if (!NullStakeB2CBNToScalar(realC, slotProof.vChallenges[realIndex]) ||
            !NullStakeB2CBNToScalar(realZ, slotProof.vResponses[realIndex]))
        {
            strError = "failed to encode real ring scalars";
            return false;
        }
        proofOut.vRingSlotProofs.push_back(slotProof);
    }

    if (proofOut.GetProofSize() > NULLSTAKE_B2C_RINGXM_AUTH_PROOF_MAX_SIZE)
    {
        strError = "B2-c ring xM proof exceeds research cap";
        proofOut = CNullStakeMofNHiddenAuthProof();
        return false;
    }
    if (!VerifyNullStakeMofNHiddenAuthProof(vStakerSet, nThresholdM, vchPkOwner,
                                            delegationHash, stakeDigest, kernelValueCommitment,
                                            proofOut, strError))
    {
        proofOut = CNullStakeMofNHiddenAuthProof();
        return false;
    }
    return true;
}

bool VerifyNullStakeMofNHiddenAuthProof(const std::vector<std::vector<unsigned char> >& vStakerSet,
                                        unsigned int nThresholdM,
                                        const std::vector<unsigned char>& vchPkOwner,
                                        const uint256& delegationHash,
                                        const uint256& stakeDigest,
                                        const CPedersenCommitment& kernelValueCommitment,
                                        const CNullStakeMofNHiddenAuthProof& proof,
                                        std::string& strError)
{
    strError.clear();
    if (!CZKContext::Initialize())
    {
        strError = "zk context initialization failed";
        return false;
    }
    if (!NullStakeB2CValidateStatement(vStakerSet, nThresholdM, vchPkOwner, delegationHash,
                                       stakeDigest, kernelValueCommitment, strError))
        return false;
    if (proof.nVersion != NULLSTAKE_B2C_HIDDEN_AUTH_VERSION)
    {
        strError = "unsupported B2-c hidden auth proof version";
        return false;
    }
    if (proof.nAuthType != NULLSTAKE_B2C_AUTH_TYPE_RINGXM_DLEQ)
    {
        strError = "unsupported B2-c hidden auth proof type";
        return false;
    }
    if (!proof.vchResearchProof.empty())
    {
        strError = "unexpected BPAC research proof bytes in ring xM proof";
        return false;
    }
    if (proof.vchTagBaseNonce.size() != 32 ||
        proof.vchTagBaseNonce == std::vector<unsigned char>(32, 0))
    {
        strError = "invalid B2-c proof nonce";
        return false;
    }
    if (proof.vRingSlotProofs.size() != nThresholdM)
    {
        strError = "ring slot count must equal threshold M";
        return false;
    }
    if (proof.GetProofSize() > NULLSTAKE_B2C_RINGXM_AUTH_PROOF_MAX_SIZE)
    {
        strError = "B2-c hidden auth proof exceeds research cap";
        return false;
    }

    const uint256 statementHash = ComputeNullStakeMofNHiddenAuthStatementHash(
        vStakerSet, nThresholdM, vchPkOwner, delegationHash, stakeDigest, kernelValueCommitment);

    CZarcECGroupGuard group;
    CZarcBNCtxGuard ctx;
    if (!group.group || !ctx.ctx)
    {
        strError = "EC context allocation failed";
        return false;
    }
    CNullStakeBNGuard order;
    if (!EC_GROUP_get_order(group, order, ctx))
    {
        strError = "EC order lookup failed";
        return false;
    }
    CZarcECPointGuard tagBase(group);
    if (!NullStakeB2CHashToTagBase(statementHash, proof.vchTagBaseNonce, group, ctx, tagBase))
    {
        strError = "failed to derive B2-c tag base";
        return false;
    }

    std::vector<std::vector<unsigned char> > vTagsSeen;
    for (size_t slot = 0; slot < proof.vRingSlotProofs.size(); slot++)
    {
        const CNullStakeMofNHiddenAuthRingSlotProof& slotProof = proof.vRingSlotProofs[slot];
        if (slotProof.vChallenges.size() != vStakerSet.size() ||
            slotProof.vResponses.size() != vStakerSet.size())
        {
            strError = "ring scalar vector size mismatch";
            return false;
        }

        CZarcECPointGuard tag(group);
        if (!NullStakeB2CBytesToPoint(group, slotProof.vchTag, tag, ctx))
        {
            strError = "invalid hidden duplicate tag";
            return false;
        }
        if (std::find(vTagsSeen.begin(), vTagsSeen.end(), slotProof.vchTag) != vTagsSeen.end())
        {
            strError = "duplicate hidden signer tag";
            return false;
        }
        vTagsSeen.push_back(slotProof.vchTag);

        std::vector<std::vector<unsigned char> > vA, vB;
        if (!NullStakeB2CComputeProofCommitments(vStakerSet, tag, tagBase,
                                                 slotProof.vChallenges,
                                                 slotProof.vResponses,
                                                 group, order, ctx, vA, vB))
        {
            strError = "failed to reconstruct ring commitments";
            return false;
        }

        CNullStakeBNGuard expectedC, sumC;
        BN_zero(sumC);
        for (size_t i = 0; i < slotProof.vChallenges.size(); i++)
        {
            CNullStakeBNGuard c;
            if (!NullStakeB2CScalarToBN(slotProof.vChallenges[i], order, c))
            {
                strError = "non-canonical ring challenge scalar";
                return false;
            }
            BN_mod_add(sumC, sumC, c, order, ctx);
        }
        if (!NullStakeB2CComputeSlotChallenge(statementHash, proof.vchTagBaseNonce,
                                              (unsigned int)slot, slotProof.vchTag,
                                              vA, vB, order, ctx, expectedC))
        {
            strError = "failed to compute expected ring challenge";
            return false;
        }
        if (BN_cmp(sumC, expectedC) != 0)
        {
            strError = "ring DLEQ challenge sum mismatch";
            return false;
        }
    }
    return true;
}
