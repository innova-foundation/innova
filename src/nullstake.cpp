// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "nullstake.h"
#include "poseidon2.h"
#include "bulletproof_ac.h"
#include "hash.h"
#include "util.h"
#include "bignum.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>
#include <string.h>

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

    CR1CSCircuit circuit = BuildNullStakeV2Circuit(nStakeModifier, nTimeTx, nBits);

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
    memcpy(blindCircuit.begin(), vchValueBlindCircuit.data(), 32);
    blindCircuit = FieldReduce(blindCircuit);
    witness.vBlinds[0] = blindCircuit;

    CPedersenCommitment valueCommitCircuit;
    if (!CreatePedersenCommitment(nValue, vchValueBlindCircuit, valueCommitCircuit))
        return false;

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
    EC_POINT_mul(group, RLink, bnK, NULL, NULL, ctx);

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
    proofOut.nTimeTx = nTimeTx;

    OPENSSL_cleanse(vchValueBlindCircuit.data(), 32);

    return true;
}


bool VerifyNullStakeKernelProofV2(const CNullStakeKernelProofV2& proof,
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

    CR1CSCircuit circuit = BuildNullStakeV3Circuit(nStakeModifier, nTimeTx, nBits, delegationHash);

    CR1CSWitness witness;
    if (!AssignNullStakeV3Witness(circuit, nStakeModifier, nBlockTimeFrom,
                                  nTxPrevOffset, nTxTimePrev, nVoutN,
                                  nTimeTx, nValue, vchBlind, nBits,
                                  skStake, vchPkOwner, delegationHash, witness))
    {
        if (fDebug) printf("CreateNullStakeKernelProofV3: witness assignment failed\n");
        return false;
    }

    std::vector<unsigned char> vchValueBlindCircuit(32);
    if (RAND_bytes(vchValueBlindCircuit.data(), 32) != 1)
        return false;

    uint256 blindCircuit;
    memcpy(blindCircuit.begin(), vchValueBlindCircuit.data(), 32);
    blindCircuit = FieldReduce(blindCircuit);
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
    EC_POINT_mul(group, RLink, bnK, NULL, NULL, ctx);

    size_t rlLen = EC_POINT_point2oct(group, RLink, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    std::vector<unsigned char> vchRL(rlLen);
    EC_POINT_point2oct(group, RLink, POINT_CONVERSION_COMPRESSED, vchRL.data(), rlLen, ctx);

    CDataStream ssLink(SER_GETHASH, 0);
    ssLink << std::string(NULLSTAKE_V3_LINK_DOMAIN);
    ssLink << valueCommitCircuit.vchCommitment;
    ssLink << cv.vchCommitment;
    ssLink << delegationHash;
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
    proofOut.nTimeTx = nTimeTx;
    proofOut.delegationHash = delegationHash;

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

        CZarcECPointGuard pkStake(group);
        EC_POINT_mul(group, pkStake, bnSK, NULL, NULL, ctx);

        size_t pkLen = EC_POINT_point2oct(group, pkStake, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        proofOut.vchPkStake.resize(pkLen);
        EC_POINT_point2oct(group, pkStake, POINT_CONVERSION_COMPRESSED, proofOut.vchPkStake.data(), pkLen, ctx);
    }

    OPENSSL_cleanse(vchValueBlindCircuit.data(), 32);

    return true;
}


bool VerifyNullStakeKernelProofV3(const CNullStakeKernelProofV3& proof,
                                  const CPedersenCommitment& cv,
                                  unsigned int nBits)
{
    if (proof.IsNull() || cv.IsNull())
        return false;

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

    if (!CPoseidon2Params::IsInitialized())
        CPoseidon2Params::Initialize();

    CZarcECGroupGuard group;
    CZarcBNCtxGuard ctx;
    if (!group.group || !ctx.ctx)
        return false;

    CNullStakeBNGuard bnOrder;
    if (!EC_GROUP_get_order(group, bnOrder, ctx))
        return false;

    CR1CSCircuit circuit = BuildNullStakeV3Circuit(proof.nStakeModifier, proof.nTimeTx,
                                                    nBits, proof.delegationHash);

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
