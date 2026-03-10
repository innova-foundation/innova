// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "lelantus.h"
#include "hash.h"
#include "util.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>
#include <string.h>
#include <algorithm>

int CAnonymitySet::FindIndex(const CPedersenCommitment& commit) const
{
    for (size_t i = 0; i < vCommitments.size(); i++)
    {
        if (vCommitments[i] == commit)
            return (int)i;
    }
    return -1;
}

bool BuildAnonymitySet(const CPedersenCommitment& realCommit,
                        const std::vector<CPedersenCommitment>& vAllCommitments,
                        const uint256& blockHashSeed,
                        int nBlockHeight,
                        CAnonymitySet& setOut)
{
    if (vAllCommitments.empty())
        return false;

    setOut.blockHashSeed = blockHashSeed;
    setOut.nBlockHeight = nBlockHeight;
    setOut.vCommitments.clear();

    int nSetSize = LELANTUS_SET_SIZE;

    if ((int)vAllCommitments.size() < nSetSize)
    {
        if ((int)vAllCommitments.size() < LELANTUS_MIN_SET_SIZE)
        {
            printf("BuildAnonymitySet: not enough commitments (%d < %d)\n",
                   (int)vAllCommitments.size(), LELANTUS_MIN_SET_SIZE);
            return false;
        }
        nSetSize = (int)vAllCommitments.size();
    }

    {
        int pow2 = 1;
        while (pow2 * 2 <= nSetSize)
            pow2 *= 2;
        nSetSize = pow2;
    }

    int nRealPoolIdx = -1;
    for (int i = 0; i < (int)vAllCommitments.size(); i++)
    {
        if (vAllCommitments[i] == realCommit)
        {
            nRealPoolIdx = i;
            break;
        }
    }

    if (fDebug)
        printf("BuildAnonymitySet: nSetSize=%d (from pool=%d), selecting %d decoys\n",
               nSetSize, (int)vAllCommitments.size(), nSetSize - 1);

    std::vector<int> vDecoyIndices;
    if (!SelectDecoys(vAllCommitments, nSetSize - 1, blockHashSeed, vDecoyIndices, nRealPoolIdx))
    {
        printf("BuildAnonymitySet: SelectDecoys FAILED\n");
        return false;
    }
    if (fDebug)
        printf("BuildAnonymitySet: got %d decoy indices\n", (int)vDecoyIndices.size());

    unsigned char rndPos[4];
    if (RAND_bytes(rndPos, 4) != 1)
        return false;
    unsigned int rndVal;
    memcpy(&rndVal, rndPos, sizeof(rndVal));
    int nRealPos = rndVal % nSetSize;

    int decoyIdx = 0;
    for (int i = 0; i < nSetSize; i++)
    {
        if (i == nRealPos)
        {
            setOut.vCommitments.push_back(realCommit);
        }
        else if (decoyIdx < (int)vDecoyIndices.size())
        {
            setOut.vCommitments.push_back(vAllCommitments[vDecoyIndices[decoyIdx]]);
            decoyIdx++;
        }
    }

    if (fDebug)
        printf("BuildAnonymitySet: final set size = %d\n", (int)setOut.vCommitments.size());
    return setOut.vCommitments.size() >= LELANTUS_MIN_SET_SIZE;
}

bool SelectDecoys(const std::vector<CPedersenCommitment>& vPool,
                   int nCount,
                   const uint256& seed,
                   std::vector<int>& vIndicesOut,
                   int nExcludeIdx)
{
    if (vPool.empty() || nCount <= 0)
        return false;

    vIndicesOut.clear();
    vIndicesOut.reserve(nCount);

    CHashWriter seedMixer(SER_GETHASH, 0);
    seedMixer << seed;
    unsigned char vchRand[32];
    if (RAND_bytes(vchRand, 32) != 1)
    {
        vIndicesOut.clear();
        return false;
    }
    seedMixer.write((const char*)vchRand, 32);
    uint256 current = seedMixer.GetHash();
    std::vector<bool> vUsed(vPool.size(), false);

    if (nExcludeIdx >= 0 && nExcludeIdx < (int)vPool.size())
        vUsed[nExcludeIdx] = true;

    int nSelected = 0;

    for (int attempt = 0; attempt < nCount * 10 && nSelected < nCount; attempt++)
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << (uint8_t)0x41;
        ss << current;
        ss << (uint32_t)attempt;
        current = ss.GetHash();

        unsigned int idxVal;
        memcpy(&idxVal, current.begin(), sizeof(idxVal));
        int idx = idxVal % (int)vPool.size();

        if (!vUsed[idx])
        {
            vUsed[idx] = true;
            vIndicesOut.push_back(idx);
            nSelected++;
        }
    }

    return nSelected == nCount;
}


uint256 ComputeLelantusSerial(const uint256& skSpend,
                               const uint256& rho,
                               const CPedersenCommitment& commitment,
                               int64_t nOutputIndex)
{
    CHashWriter ss(SER_GETHASH, 0);

    if (nOutputIndex >= 0)
    {
        ss << (uint8_t)0x51;
        ss << skSpend;
        ss << rho;
        for (size_t i = 0; i < commitment.vchCommitment.size(); i++)
            ss << commitment.vchCommitment[i];
        ss << nOutputIndex;
    }
    else
    {
        ss << (uint8_t)0x50;
        ss << skSpend;
        ss << rho;
        for (size_t i = 0; i < commitment.vchCommitment.size(); i++)
            ss << commitment.vchCommitment[i];
    }

    return ss.GetHash();
}


class CLelBNCtxGuard
{
public:
    BN_CTX* ctx;
    CLelBNCtxGuard() { ctx = BN_CTX_new(); }
    ~CLelBNCtxGuard() { if (ctx) BN_CTX_free(ctx); }
    operator BN_CTX*() { return ctx; }
};

class CLelECGroupGuard
{
public:
    EC_GROUP* group;
    CLelECGroupGuard() { group = EC_GROUP_new_by_curve_name(NID_secp256k1); }
    ~CLelECGroupGuard() { if (group) EC_GROUP_free(group); }
    operator EC_GROUP*() { return group; }
    operator const EC_GROUP*() const { return group; }
};

class CLelECPointGuard
{
public:
    EC_POINT* point;
    const EC_GROUP* group;
    CLelECPointGuard(const EC_GROUP* g) : group(g) { point = EC_POINT_new(group); }
    ~CLelECPointGuard() { if (point) EC_POINT_free(point); }
    operator EC_POINT*() { return point; }
    operator const EC_POINT*() const { return point; }
};

static bool LelPointToBytes(const EC_GROUP* group, const EC_POINT* point,
                              std::vector<unsigned char>& vchOut, BN_CTX* ctx)
{
    size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    if (len == 0) return false;
    vchOut.resize(len);
    return EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, vchOut.data(), len, ctx) == len;
}

static bool LelBytesToPoint(const EC_GROUP* group, const std::vector<unsigned char>& vch,
                              EC_POINT* point, BN_CTX* ctx)
{
    if (vch.size() < 33) return false;
    return EC_POINT_oct2point(group, point, vch.data(), vch.size(), ctx) == 1;
}

static bool LelFiatShamir(const std::vector<unsigned char>& transcript,
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

static void LelAppendPoint(std::vector<unsigned char>& transcript,
                             const EC_GROUP* group, const EC_POINT* point, BN_CTX* ctx)
{
    unsigned char buf[33];
    EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, buf, 33, ctx);
    transcript.insert(transcript.end(), buf, buf + 33);
}

static bool ComputePolyCoeffs(int i, int n, const std::vector<int>& bits,
                               const std::vector<BIGNUM*>& vA,
                               const BIGNUM* order, BN_CTX* ctx,
                               std::vector<BIGNUM*>& polyOut)
{
    polyOut.resize(n + 1);
    for (int m = 0; m <= n; m++)
    {
        polyOut[m] = BN_new();
        BN_zero(polyOut[m]);
    }
    BN_one(polyOut[0]);

    int curDeg = 0;
    for (int j = 0; j < n; j++)
    {
        bool bMatch = (((i >> j) & 1) == bits[j]);
        bool bAlpha = bMatch;
        bool bBetaPositive = (bMatch == (bits[j] == 1));

        std::vector<BIGNUM*> newPoly(n + 1);
        for (int m = 0; m <= n; m++)
        {
            newPoly[m] = BN_new();
            BN_zero(newPoly[m]);
        }

        for (int m = 0; m <= curDeg + 1; m++)
        {
            if (bAlpha && m > 0)
            {
                BN_mod_add(newPoly[m], newPoly[m], polyOut[m - 1], order, ctx);
            }
            if (m <= curDeg)
            {
                BIGNUM* tmp = BN_new();
                BN_mod_mul(tmp, vA[j], polyOut[m], order, ctx);
                if (bBetaPositive)
                    BN_mod_add(newPoly[m], newPoly[m], tmp, order, ctx);
                else
                    BN_mod_sub(newPoly[m], newPoly[m], tmp, order, ctx);
                BN_free(tmp);
            }
        }

        for (int m = 0; m <= n; m++)
            BN_free(polyOut[m]);
        polyOut = newPoly;
        if (bAlpha) curDeg++;
    }
    return true;
}

bool CreateLelantusProof(const CAnonymitySet& anonSet,
                          int nRealIndex,
                          int64_t nValue,
                          const std::vector<unsigned char>& vchBlind,
                          const uint256& serialNumber,
                          CLelantusProof& proofOut)
{
    if (!CZKContext::IsInitialized()) return false;

    int N = anonSet.Size();
    if (N < LELANTUS_MIN_SET_SIZE) return false;
    if (nRealIndex < 0 || nRealIndex >= N) return false;
    if (vchBlind.size() != BLINDING_FACTOR_SIZE) return false;

    {
        CPedersenCommitment expectedCv;
        if (!CreatePedersenCommitment(nValue, vchBlind, expectedCv))
            return false;
        if (expectedCv.vchCommitment != anonSet.vCommitments[nRealIndex].vchCommitment)
        {
            printf("CreateLelantusProof: commitment at nRealIndex %d does not match prover's commitment\n", nRealIndex);
            return false;
        }
    }

    int n = 0;
    int temp = N - 1;
    while (temp > 0) { temp >>= 1; n++; }
    if (n == 0) return false;

    CLelECGroupGuard group;
    if (!group.group) return false;

    CLelBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    const BIGNUM* order = EC_GROUP_get0_order(group);

    CLelECPointGuard G(group), H(group);
    if (!LelBytesToPoint(group, CZKContext::GetGeneratorG(), G, ctx)) return false;
    if (!LelBytesToPoint(group, CZKContext::GetGeneratorH(), H, ctx)) return false;

    std::vector<int> bits(n, 0);
    for (int j = 0; j < n; j++)
        bits[j] = (nRealIndex >> j) & 1;

    std::vector<BIGNUM*> vR(n);
    std::vector<BIGNUM*> vA(n);
    std::vector<EC_POINT*> vCb(n);
    std::vector<EC_POINT*> vCa(n);

    for (int j = 0; j < n; j++)
    {
        unsigned char rnd[32];

        vR[j] = BN_new();
        if (RAND_bytes(rnd, 32) != 1)
            return false;
        BN_bin2bn(rnd, 32, vR[j]);
        BN_mod(vR[j], vR[j], order, ctx);

        vA[j] = BN_new();
        if (RAND_bytes(rnd, 32) != 1)
            return false;
        BN_bin2bn(rnd, 32, vA[j]);
        BN_mod(vA[j], vA[j], order, ctx);

        OPENSSL_cleanse(rnd, 32);

        vCb[j] = EC_POINT_new(group);
        {
            BIGNUM* bnBit = BN_new();
            BN_set_word(bnBit, bits[j]);

            CLelECPointGuard tmpH(group), tmpG(group);
            EC_POINT_mul(group, tmpH, NULL, H, bnBit, ctx);
            EC_POINT_mul(group, tmpG, NULL, G, vR[j], ctx);
            EC_POINT_add(group, vCb[j], tmpH, tmpG, ctx);

            BN_free(bnBit);
        }

        vCa[j] = EC_POINT_new(group);
        {
            CLelECPointGuard tmpH(group), tmpG(group);
            EC_POINT_mul(group, tmpH, NULL, H, vA[j], ctx);

            unsigned char aBuf[32];
            memset(aBuf, 0, 32);
            int nB = BN_num_bytes(vA[j]);
            if (nB > 0) BN_bn2bin(vA[j], aBuf + (32 - nB));

            CHashWriter ssS(SER_GETHASH, 0);
            ssS << (uint8_t)0x51;
            for (int k = 0; k < 32; k++) ssS << aBuf[k];
            uint256 sHash = ssS.GetHash();
            BIGNUM* bnS = BN_bin2bn(sHash.begin(), 32, NULL);
            BN_mod(bnS, bnS, order, ctx);

            EC_POINT_mul(group, tmpG, NULL, G, bnS, ctx);
            EC_POINT_add(group, vCa[j], tmpH, tmpG, ctx);

            BN_clear_free(bnS);
            OPENSSL_cleanse(aBuf, 32);
        }
    }

    std::vector<BIGNUM*> vRho(n);
    for (int k = 0; k < n; k++)
    {
        vRho[k] = BN_new();
        unsigned char rnd[32];
        if (RAND_bytes(rnd, 32) != 1)
            return false;
        BN_bin2bn(rnd, 32, vRho[k]);
        BN_mod(vRho[k], vRho[k], order, ctx);
        OPENSSL_cleanse(rnd, 32);
    }

    std::vector<EC_POINT*> vCi(N);
    for (int i = 0; i < N; i++)
    {
        vCi[i] = EC_POINT_new(group);
        if (!LelBytesToPoint(group, anonSet.At(i).vchCommitment, vCi[i], ctx))
        {
            for (int ii = 0; ii <= i; ii++) EC_POINT_free(vCi[ii]);
            for (int k = 0; k < n; k++) BN_clear_free(vRho[k]);
            return false;
        }
    }

    std::vector<EC_POINT*> vD(n);
    for (int k = 0; k < n; k++)
    {
        vD[k] = EC_POINT_new(group);
        EC_POINT_set_to_infinity(group, vD[k]);

        for (int i = 0; i < N; i++)
        {
            std::vector<BIGNUM*> poly;
            ComputePolyCoeffs(i, n, bits, vA, order, ctx, poly);

            if (!BN_is_zero(poly[k]))
            {
                CLelECPointGuard scaled(group);
                EC_POINT_mul(group, scaled, NULL, vCi[i], poly[k], ctx);
                EC_POINT_add(group, vD[k], vD[k], scaled, ctx);
            }

            for (int m = 0; m <= n; m++) BN_free(poly[m]);
        }

        CLelECPointGuard rhoG(group);
        EC_POINT_mul(group, rhoG, NULL, G, vRho[k], ctx);
        EC_POINT_add(group, vD[k], vD[k], rhoG, ctx);
    }

    std::vector<unsigned char> transcript;

    const std::string domain = "Innova/Lelantus/Proof/v1";
    transcript.insert(transcript.end(), domain.begin(), domain.end());

    for (int i = 0; i < N; i++)
    {
        const CPedersenCommitment& c = anonSet.At(i);
        transcript.insert(transcript.end(), c.vchCommitment.begin(), c.vchCommitment.end());
    }

    transcript.insert(transcript.end(), serialNumber.begin(), serialNumber.begin() + 32);

    for (int j = 0; j < n; j++)
    {
        LelAppendPoint(transcript, group, vCb[j], ctx);
        LelAppendPoint(transcript, group, vCa[j], ctx);
    }

    for (int k = 0; k < n; k++)
        LelAppendPoint(transcript, group, vD[k], ctx);

    BIGNUM* x = BN_new();
    if (!LelFiatShamir(transcript, x, order, ctx))
    {
        BN_free(x);
        for (int i = 0; i < N; i++) EC_POINT_free(vCi[i]);
        for (int k = 0; k < n; k++) { EC_POINT_free(vD[k]); BN_clear_free(vRho[k]); }
        return false;
    }

    std::vector<BIGNUM*> vF(n), vZ(n);

    for (int j = 0; j < n; j++)
    {
        vF[j] = BN_new();
        BN_set_word(vF[j], bits[j]);
        BN_mod_mul(vF[j], vF[j], x, order, ctx);
        BN_mod_add(vF[j], vF[j], vA[j], order, ctx);

        unsigned char aBuf[32];
        memset(aBuf, 0, 32);
        int nB = BN_num_bytes(vA[j]);
        if (nB > 0) BN_bn2bin(vA[j], aBuf + (32 - nB));

        CHashWriter ssS(SER_GETHASH, 0);
        ssS << (uint8_t)0x51;
        for (int k = 0; k < 32; k++) ssS << aBuf[k];
        uint256 sHash = ssS.GetHash();
        BIGNUM* bnS = BN_bin2bn(sHash.begin(), 32, NULL);
        BN_mod(bnS, bnS, order, ctx);

        vZ[j] = BN_new();
        BN_mod_mul(vZ[j], vR[j], x, order, ctx);
        BN_mod_add(vZ[j], vZ[j], bnS, order, ctx);

        BN_clear_free(bnS);
        OPENSSL_cleanse(aBuf, 32);
    }

    BIGNUM* zV = BN_new();
    BN_zero(zV);
    BIGNUM* xPow = BN_new();
    BN_one(xPow);
    for (int k = 0; k < n; k++)
    {
        BIGNUM* term = BN_new();
        BN_mod_mul(term, vRho[k], xPow, order, ctx);
        BN_mod_add(zV, zV, term, order, ctx);
        BN_free(term);
        BN_mod_mul(xPow, xPow, x, order, ctx);
    }

    proofOut.vchProof.clear();
    proofOut.serialNumber = serialNumber;

    uint32_t un = (uint32_t)n;
    uint32_t uN = (uint32_t)N;
    proofOut.vchProof.insert(proofOut.vchProof.end(), (unsigned char*)&un, (unsigned char*)&un + 4);
    proofOut.vchProof.insert(proofOut.vchProof.end(), (unsigned char*)&uN, (unsigned char*)&uN + 4);

    unsigned char ptBuf[33], scBuf[32];

    for (int j = 0; j < n; j++)
    {
        EC_POINT_point2oct(group, vCb[j], POINT_CONVERSION_COMPRESSED, ptBuf, 33, ctx);
        proofOut.vchProof.insert(proofOut.vchProof.end(), ptBuf, ptBuf + 33);

        EC_POINT_point2oct(group, vCa[j], POINT_CONVERSION_COMPRESSED, ptBuf, 33, ctx);
        proofOut.vchProof.insert(proofOut.vchProof.end(), ptBuf, ptBuf + 33);

        memset(scBuf, 0, 32);
        int nB = BN_num_bytes(vF[j]);
        if (nB > 0) BN_bn2bin(vF[j], scBuf + (32 - nB));
        proofOut.vchProof.insert(proofOut.vchProof.end(), scBuf, scBuf + 32);

        memset(scBuf, 0, 32);
        nB = BN_num_bytes(vZ[j]);
        if (nB > 0) BN_bn2bin(vZ[j], scBuf + (32 - nB));
        proofOut.vchProof.insert(proofOut.vchProof.end(), scBuf, scBuf + 32);
    }

    for (int k = 0; k < n; k++)
    {
        EC_POINT_point2oct(group, vD[k], POINT_CONVERSION_COMPRESSED, ptBuf, 33, ctx);
        proofOut.vchProof.insert(proofOut.vchProof.end(), ptBuf, ptBuf + 33);
    }

    memset(scBuf, 0, 32);
    int nB = BN_num_bytes(zV);
    if (nB > 0) BN_bn2bin(zV, scBuf + (32 - nB));
    proofOut.vchProof.insert(proofOut.vchProof.end(), scBuf, scBuf + 32);

    for (int j = 0; j < n; j++)
    {
        BN_clear_free(vR[j]);
        BN_clear_free(vA[j]);
        BN_clear_free(vF[j]);
        BN_clear_free(vZ[j]);
        EC_POINT_free(vCb[j]);
        EC_POINT_free(vCa[j]);
    }
    for (int k = 0; k < n; k++)
    {
        BN_clear_free(vRho[k]);
        EC_POINT_free(vD[k]);
    }
    for (int i = 0; i < N; i++)
        EC_POINT_free(vCi[i]);
    BN_free(x);
    BN_free(xPow);
    BN_clear_free(zV);

    OPENSSL_cleanse(scBuf, 32);

    return true;
}


bool VerifyLelantusProof(const CAnonymitySet& anonSet,
                          const CLelantusProof& proof,
                          const CPedersenCommitment& spendCv)
{
    if (!CZKContext::IsInitialized()) { printf("VerifyLelantus: ZK not init\n"); return false; }
    if (proof.IsNull()) { printf("VerifyLelantus: proof null\n"); return false; }

    if (proof.vchProof.size() < 8) { printf("VerifyLelantus: proof too small (%d)\n", (int)proof.vchProof.size()); return false; }

    uint32_t n, N;
    memcpy(&n, proof.vchProof.data(), 4);
    memcpy(&N, proof.vchProof.data() + 4, 4);

    if (fDebug)
        printf("VerifyLelantus: proof n=%u N=%u, anonSet.Size()=%d, proofSize=%d\n",
               n, N, anonSet.Size(), (int)proof.vchProof.size());

    if ((int)N != anonSet.Size()) { printf("VerifyLelantus: N mismatch\n"); return false; }
    if (n == 0 || n > 32) { printf("VerifyLelantus: n out of range\n"); return false; }
    if (N < LELANTUS_MIN_SET_SIZE || N > 1024) { printf("VerifyLelantus: N out of range\n"); return false; }
    if ((N & (N - 1)) != 0) { printf("VerifyLelantus: N not power of 2\n"); return false; }

    size_t expectedSize = 8 + n * (33 + 33 + 32 + 32) + n * 33 + 32;
    if (proof.vchProof.size() < expectedSize) return false;

    CLelECGroupGuard group;
    if (!group.group) return false;

    CLelBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    const BIGNUM* order = EC_GROUP_get0_order(group);

    CLelECPointGuard G(group), H(group);
    if (!LelBytesToPoint(group, CZKContext::GetGeneratorG(), G, ctx)) return false;
    if (!LelBytesToPoint(group, CZKContext::GetGeneratorH(), H, ctx)) return false;

    for (int i = 0; i < (int)N; i++)
    {
        CLelECPointGuard testPt(group);
        if (!LelBytesToPoint(group, anonSet.At(i).vchCommitment, testPt, ctx))
            return false;
        if (EC_POINT_is_on_curve(group, testPt, ctx) != 1)
            return false;
    }

    size_t offset = 8;
    std::vector<EC_POINT*> vCb(n, NULL), vCa(n, NULL), vD(n, NULL);
    std::vector<BIGNUM*> vF(n, NULL), vZ(n, NULL);
    BIGNUM* zV = NULL;

    auto cleanupProof = [&]() {
        for (uint32_t j = 0; j < n; j++) {
            if (vCb[j]) EC_POINT_free(vCb[j]);
            if (vCa[j]) EC_POINT_free(vCa[j]);
            if (vD[j]) EC_POINT_free(vD[j]);
            if (vF[j]) BN_free(vF[j]);
            if (vZ[j]) BN_free(vZ[j]);
        }
        if (zV) BN_free(zV);
    };

    for (uint32_t j = 0; j < n; j++)
    {
        vCb[j] = EC_POINT_new(group);
        if (EC_POINT_oct2point(group, vCb[j], proof.vchProof.data() + offset, 33, ctx) != 1)
        { cleanupProof(); return false; }
        if (EC_POINT_is_on_curve(group, vCb[j], ctx) != 1)
        { cleanupProof(); return false; }
        if (EC_POINT_is_at_infinity(group, vCb[j]))
        { cleanupProof(); return false; }
        offset += 33;

        vCa[j] = EC_POINT_new(group);
        if (EC_POINT_oct2point(group, vCa[j], proof.vchProof.data() + offset, 33, ctx) != 1)
        { cleanupProof(); return false; }
        if (EC_POINT_is_on_curve(group, vCa[j], ctx) != 1)
        { cleanupProof(); return false; }
        if (EC_POINT_is_at_infinity(group, vCa[j]))
        { cleanupProof(); return false; }
        offset += 33;

        vF[j] = BN_bin2bn(proof.vchProof.data() + offset, 32, NULL);
        if (!vF[j]) { cleanupProof(); return false; }
        if (BN_cmp(vF[j], order) >= 0) { cleanupProof(); return false; }
        offset += 32;

        vZ[j] = BN_bin2bn(proof.vchProof.data() + offset, 32, NULL);
        if (!vZ[j]) { cleanupProof(); return false; }
        if (BN_cmp(vZ[j], order) >= 0) { cleanupProof(); return false; }
        offset += 32;
    }

    for (uint32_t k = 0; k < n; k++)
    {
        vD[k] = EC_POINT_new(group);
        if (EC_POINT_oct2point(group, vD[k], proof.vchProof.data() + offset, 33, ctx) != 1)
        { cleanupProof(); return false; }
        if (EC_POINT_is_on_curve(group, vD[k], ctx) != 1)
        { cleanupProof(); return false; }
        offset += 33;
    }

    zV = BN_bin2bn(proof.vchProof.data() + offset, 32, NULL);
    if (!zV) { cleanupProof(); return false; }

    std::vector<unsigned char> transcript;

    const std::string domain = "Innova/Lelantus/Proof/v1";
    transcript.insert(transcript.end(), domain.begin(), domain.end());

    for (int i = 0; i < (int)N; i++)
    {
        const CPedersenCommitment& c = anonSet.At(i);
        transcript.insert(transcript.end(), c.vchCommitment.begin(), c.vchCommitment.end());
    }

    transcript.insert(transcript.end(), proof.serialNumber.begin(), proof.serialNumber.begin() + 32);

    for (uint32_t j = 0; j < n; j++)
    {
        LelAppendPoint(transcript, group, vCb[j], ctx);
        LelAppendPoint(transcript, group, vCa[j], ctx);
    }

    for (uint32_t k = 0; k < n; k++)
        LelAppendPoint(transcript, group, vD[k], ctx);

    BIGNUM* x = BN_new();
    if (!LelFiatShamir(transcript, x, order, ctx))
    {
        BN_free(x);
        cleanupProof();
        return false;
    }

    bool fValid = true;
    if (fDebug)
        printf("VerifyLelantus: starting bit commitment checks (n=%u)\n", n);

    for (uint32_t j = 0; j < n && fValid; j++)
    {
        CLelECPointGuard lhs(group);
        {
            CLelECPointGuard tmpH(group), tmpG(group);
            EC_POINT_mul(group, tmpH, NULL, H, vF[j], ctx);
            EC_POINT_mul(group, tmpG, NULL, G, vZ[j], ctx);
            EC_POINT_add(group, lhs, tmpH, tmpG, ctx);
        }

        CLelECPointGuard rhs(group);
        {
            CLelECPointGuard tmpC(group);
            EC_POINT_mul(group, tmpC, NULL, vCb[j], x, ctx);
            EC_POINT_add(group, rhs, tmpC, vCa[j], ctx);
        }

        if (EC_POINT_cmp(group, lhs, rhs, ctx) != 0)
        {
            printf("VerifyLelantus: bit commitment check FAILED at j=%u\n", j);
            fValid = false;
        }
    }

    if (fValid)
    {
        CLelECPointGuard sumPC(group);
        EC_POINT_set_to_infinity(group, sumPC);

        for (int i = 0; i < (int)N; i++)
        {
            BIGNUM* pi = BN_new();
            BN_one(pi);

            for (uint32_t j = 0; j < n; j++)
            {
                BIGNUM* factor = BN_new();
                if ((i >> j) & 1)
                    BN_copy(factor, vF[j]);
                else
                    BN_mod_sub(factor, x, vF[j], order, ctx);
                BN_mod_mul(pi, pi, factor, order, ctx);
                BN_free(factor);
            }

            if (!BN_is_zero(pi))
            {
                CLelECPointGuard Ci(group), piCi(group);
                if (LelBytesToPoint(group, anonSet.At(i).vchCommitment, Ci, ctx))
                {
                    EC_POINT_mul(group, piCi, NULL, Ci, pi, ctx);
                    EC_POINT_add(group, sumPC, sumPC, piCi, ctx);
                }
            }

            BN_free(pi);
        }

        CLelECPointGuard lhs(group);
        {
            CLelECPointGuard zVG(group);
            EC_POINT_mul(group, zVG, NULL, G, zV, ctx);
            EC_POINT_add(group, lhs, sumPC, zVG, ctx);
        }

        CLelECPointGuard rhs(group);
        EC_POINT_set_to_infinity(group, rhs);

        {
            BIGNUM* xn = BN_new();
            BN_one(xn);
            for (uint32_t j = 0; j < n; j++)
                BN_mod_mul(xn, xn, x, order, ctx);

            CLelECPointGuard cvPt(group);
            if (!LelBytesToPoint(group, spendCv.vchCommitment, cvPt, ctx))
            {
                BN_free(xn);
                fValid = false;
            }
            else
            {
                CLelECPointGuard xnCv(group);
                EC_POINT_mul(group, xnCv, NULL, cvPt, xn, ctx);
                EC_POINT_add(group, rhs, rhs, xnCv, ctx);
                BN_free(xn);
            }
        }

        if (fValid)
        {
            BIGNUM* xPow = BN_new();
            BN_one(xPow);
            for (uint32_t k = 0; k < n; k++)
            {
                CLelECPointGuard xkDk(group);
                EC_POINT_mul(group, xkDk, NULL, vD[k], xPow, ctx);
                EC_POINT_add(group, rhs, rhs, xkDk, ctx);
                BN_mod_mul(xPow, xPow, x, order, ctx);
            }
            BN_free(xPow);

            if (EC_POINT_cmp(group, lhs, rhs, ctx) != 0)
            {
                printf("VerifyLelantus: product commitment check FAILED\n");
                fValid = false;
            }
            else
            {
                if (fDebug)
                    printf("VerifyLelantus: product commitment check PASSED\n");
            }
        }
    }

    cleanupProof();
    BN_free(x);

    if (fDebug)
        printf("VerifyLelantus: final result = %s\n", fValid ? "PASS" : "FAIL");
    return fValid;
}

bool BatchVerifyLelantusProofs(const CAnonymitySet& anonSet,
                                const std::vector<CLelantusProof>& vProofs,
                                const std::vector<CPedersenCommitment>& vSpendCvs)
{
    if (vProofs.size() != vSpendCvs.size())
        return false;

    for (size_t i = 0; i < vProofs.size(); i++)
    {
        if (!VerifyLelantusProof(anonSet, vProofs[i], vSpendCvs[i]))
            return false;
    }
    return true;
}
