// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "bulletproof_ac.h"
#include "poseidon2.h"
#include "zkproof.h"
#include "hash.h"
#include "util.h"
#include "bignum.h"
#include "kernel.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <string.h>
#include <algorithm>

class CBPACBNCtxGuard
{
public:
    BN_CTX* ctx;
    CBPACBNCtxGuard() { ctx = BN_CTX_new(); }
    ~CBPACBNCtxGuard() { if (ctx) BN_CTX_free(ctx); }
    operator BN_CTX*() { return ctx; }
};

class CBPACBNGuard
{
public:
    BIGNUM* bn;
    CBPACBNGuard() { bn = BN_new(); }
    ~CBPACBNGuard() { if (bn) BN_clear_free(bn); }
    operator BIGNUM*() { return bn; }
    BIGNUM* get() { return bn; }
};

class CBPACGroupGuard
{
public:
    EC_GROUP* group;
    CBPACGroupGuard() { group = EC_GROUP_new_by_curve_name(NID_secp256k1); }
    ~CBPACGroupGuard() { if (group) EC_GROUP_free(group); }
    operator const EC_GROUP*() { return group; }
};

class CBPACPointGuard
{
public:
    EC_POINT* point;
    const EC_GROUP* group;
    CBPACPointGuard(const EC_GROUP* g) : group(g) { point = EC_POINT_new(g); }
    ~CBPACPointGuard() { if (point) EC_POINT_free(point); }
    operator EC_POINT*() { return point; }
};


static const char* BPAC_DOMAIN = "Innova_BulletproofAC_v1";
static const char* BPAC_GENS_DOMAIN = "Innova_BPAC_Generators";

extern unsigned int nStakeMinAge;


static void U256ToBN(const uint256& val, BIGNUM* bn)
{
    unsigned char be[32];
    const unsigned char* le = val.begin();
    for (int i = 0; i < 32; i++)
        be[i] = le[31 - i];
    BN_bin2bn(be, 32, bn);
}

static void BNToU256(const BIGNUM* bn, uint256& val)
{
    unsigned char be[32];
    memset(be, 0, 32);
    int nBytes = BN_num_bytes(bn);
    if (nBytes > 32) nBytes = 32;
    BN_bn2bin(bn, be + 32 - nBytes);
    unsigned char* le = val.begin();
    for (int i = 0; i < 32; i++)
        le[i] = be[31 - i];
}


static bool SerializePoint(const EC_GROUP* group, const EC_POINT* point, BN_CTX* ctx,
                            std::vector<unsigned char>& out)
{
    size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    out.resize(len);
    EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, out.data(), len, ctx);
    return len > 0;
}

static bool DeserializePoint(const EC_GROUP* group, const std::vector<unsigned char>& data,
                               EC_POINT* point, BN_CTX* ctx)
{
    if (data.empty()) return false;
    return EC_POINT_oct2point(group, point, data.data(), data.size(), ctx) == 1;
}


static bool ECCommit(const EC_GROUP* group, BN_CTX* ctx,
                      const EC_POINT* H, const BIGNUM* v, const BIGNUM* r,
                      EC_POINT* result)
{
    EC_POINT* tmp1 = EC_POINT_new(group);
    EC_POINT* tmp2 = EC_POINT_new(group);
    EC_POINT_mul(group, tmp1, NULL, H, v, ctx);   // v*H
    EC_POINT_mul(group, tmp2, r, NULL, NULL, ctx);  // r*G
    EC_POINT_add(group, result, tmp1, tmp2, ctx);
    EC_POINT_free(tmp1);
    EC_POINT_free(tmp2);
    return true;
}


class CBPACTranscript
{
public:
    std::vector<unsigned char> vchData;

    CBPACTranscript()
    {
        vchData.insert(vchData.end(), BPAC_DOMAIN, BPAC_DOMAIN + strlen(BPAC_DOMAIN));
    }

    void AppendPoint(const std::vector<unsigned char>& point)
    {
        vchData.insert(vchData.end(), point.begin(), point.end());
    }

    void AppendScalar(const uint256& scalar)
    {
        vchData.insert(vchData.end(), scalar.begin(), scalar.begin() + 32);
    }

    void AppendUint32(uint32_t val)
    {
        vchData.insert(vchData.end(), (unsigned char*)&val, (unsigned char*)&val + 4);
    }

    uint256 GetChallenge()
    {
        uint256 hash = Hash(vchData.begin(), vchData.end());
        vchData.insert(vchData.end(), hash.begin(), hash.begin() + 32);
        return FieldReduce(hash);
    }
};


CR1CSCircuit BuildNullStakeV2Circuit(uint64_t nStakeModifier,
                                      unsigned int nTimeTx,
                                      unsigned int nBits)
{
    CR1CSCircuit circuit;
    circuit.nHighLevelVars = 1;  // v (stake value)

    int nPoseidonGates = 339;
    for (int i = 0; i < nPoseidonGates; i++)
        circuit.AddMultGate();

    int nWeightValueGate = circuit.AddMultGate();  // gate 339

    int nExcessBitStart = circuit.nMultConstraints;
    for (int i = 0; i < 64; i++)
        circuit.AddMultGate();

    int nWeightBitStart = circuit.nMultConstraints;
    for (int i = 0; i < 32; i++)
        circuit.AddMultGate();

    int nValueBitStart = circuit.nMultConstraints;
    for (int i = 0; i < 64; i++)
        circuit.AddMultGate();

    while (circuit.nMultConstraints < BPAC_MAX_CONSTRAINTS)
        circuit.AddMultGate();

    circuit.PadToNextPow2();

    {
        std::vector<CSparseEntry> wl, wr, wv;
        std::vector<CSparseEntry> wo;

        CBigNum bnTarget;
        bnTarget.SetCompact(nBits);

        uint256 targetScalar;
        {
            std::vector<unsigned char> tBytes = bnTarget.getvch();
            CBPACBNGuard bnT;
            BN_bin2bn(tBytes.data(), tBytes.size(), bnT);
            BNToU256(bnT, targetScalar);
            targetScalar = FieldReduce(targetScalar);
        }

        uint256 coinDay86400 = FieldFromUint64((uint64_t)100000000ULL * 86400ULL);
        uint256 invCoinDay = FieldInv(coinDay86400);
        uint256 K = FieldMul(targetScalar, invCoinDay);

        for (int i = 0; i < 64; i++)
        {
            uint256 pow2i = FieldFromUint64(1ULL << std::min(i, 63));
            if (i >= 1)
            {
                    uint256 two = FieldFromUint64(2);
                pow2i = FieldFromUint64(1);
                for (int j = 0; j < i; j++)
                    pow2i = FieldMul(pow2i, two);
            }
            wo.push_back(CSparseEntry(nExcessBitStart + i, pow2i));
        }

        uint256 negK = FieldSub(FieldFromUint64(0), K);
        wo.push_back(CSparseEntry(nWeightValueGate, negK));

        uint256 hashKernel = Poseidon2KernelHash(nStakeModifier, 0, 0, 0, 0, nTimeTx);

        circuit.AddLinearConstraint(wl, wr, wo, wv, hashKernel);
    }

    {
        std::vector<CSparseEntry> wl, wr, wo, wv;
        for (int i = 0; i < 32; i++)
        {
            uint256 pow2i = FieldFromUint64(1);
            uint256 two = FieldFromUint64(2);
            for (int j = 0; j < i; j++)
                pow2i = FieldMul(pow2i, two);
            wo.push_back(CSparseEntry(nWeightBitStart + i, pow2i));
        }
        uint256 zero;
        memset(zero.begin(), 0, 32);
        circuit.AddLinearConstraint(wl, wr, wo, wv, zero);
    }

    {
        std::vector<CSparseEntry> wl, wr, wo, wv;
        for (int i = 0; i < 64; i++)
        {
            uint256 pow2i = FieldFromUint64(1);
            uint256 two = FieldFromUint64(2);
            for (int j = 0; j < i; j++)
                pow2i = FieldMul(pow2i, two);
            wo.push_back(CSparseEntry(nValueBitStart + i, pow2i));
        }
        uint256 negOne = FieldSub(FieldFromUint64(0), FieldFromUint64(1));
        wv.push_back(CSparseEntry(0, negOne));
        uint256 zero;
        memset(zero.begin(), 0, 32);
        circuit.AddLinearConstraint(wl, wr, wo, wv, zero);
    }

    return circuit;
}


bool AssignNullStakeV2Witness(const CR1CSCircuit& circuit,
                              uint64_t nStakeModifier,
                              unsigned int nBlockTimeFrom,
                              unsigned int nTxPrevOffset,
                              unsigned int nTxTimePrev,
                              unsigned int nVoutN,
                              unsigned int nTimeTx,
                              int64_t nValue,
                              const std::vector<unsigned char>& vchValueBlind,
                              unsigned int nBits,
                              CR1CSWitness& witnessOut)
{
    if (nValue <= 0 || vchValueBlind.size() != 32)
        return false;

    int n = circuit.nPaddedSize;
    witnessOut.aL.resize(n);
    witnessOut.aR.resize(n);
    witnessOut.aO.resize(n);

    for (int i = 0; i < n; i++)
    {
        memset(witnessOut.aL[i].begin(), 0, 32);
        memset(witnessOut.aR[i].begin(), 0, 32);
        memset(witnessOut.aO[i].begin(), 0, 32);
    }

    if (!CPoseidon2Params::IsInitialized())
        CPoseidon2Params::Initialize();

    uint256 pState[POSEIDON2_T];
    pState[0] = FieldFromUint64(nStakeModifier);
    pState[1] = FieldFromUint64((uint64_t)nBlockTimeFrom);
    pState[2] = FieldFromUint64((uint64_t)nTxPrevOffset);
    pState[3] = FieldFromUint64((uint64_t)nTxTimePrev);
    pState[4] = FieldFromUint64((uint64_t)nVoutN);
    pState[5] = FieldFromUint64((uint64_t)nTimeTx);
    pState[6] = FieldFromUint64(1);  // capacity

    const std::vector<uint256>& rc = CPoseidon2Params::GetRoundConstants();
    const std::vector<std::vector<uint256>>& mds = CPoseidon2Params::GetMDSMatrix();
    const std::vector<uint256>& diag = CPoseidon2Params::GetInternalDiag();

    int gateIdx = 0;
    int rcIdx = 0;

    auto assignSbox = [&](const uint256& x) -> uint256
    {
        uint256 x2 = FieldMul(x, x);
        uint256 x4 = FieldMul(x2, x2);
        uint256 x5 = FieldMul(x4, x);

        witnessOut.aL[gateIdx] = x;
        witnessOut.aR[gateIdx] = x;
        witnessOut.aO[gateIdx] = x2;
        gateIdx++;

        witnessOut.aL[gateIdx] = x2;
        witnessOut.aR[gateIdx] = x2;
        witnessOut.aO[gateIdx] = x4;
        gateIdx++;

        witnessOut.aL[gateIdx] = x4;
        witnessOut.aR[gateIdx] = x;
        witnessOut.aO[gateIdx] = x5;
        gateIdx++;

        return x5;
    };

    auto applyMDS = [&]()
    {
        uint256 newState[POSEIDON2_T];
        for (int i = 0; i < POSEIDON2_T; i++)
        {
            newState[i] = FieldFromUint64(0);
            for (int j = 0; j < POSEIDON2_T; j++)
                newState[i] = FieldAdd(newState[i], FieldMul(mds[i][j], pState[j]));
        }
        for (int i = 0; i < POSEIDON2_T; i++)
            pState[i] = newState[i];
    };

    auto applyInternal = [&]()
    {
        uint256 sum = FieldFromUint64(0);
        for (int i = 0; i < POSEIDON2_T; i++)
            sum = FieldAdd(sum, pState[i]);
        for (int i = 0; i < POSEIDON2_T; i++)
            pState[i] = FieldAdd(FieldMul(diag[i], pState[i]), sum);
    };

    for (int r = 0; r < POSEIDON2_RF / 2; r++)
    {
        for (int i = 0; i < POSEIDON2_T; i++)
            pState[i] = FieldAdd(pState[i], rc[rcIdx++]);
        for (int i = 0; i < POSEIDON2_T; i++)
            pState[i] = assignSbox(pState[i]);
        applyMDS();
    }

    for (int r = 0; r < POSEIDON2_RP; r++)
    {
        pState[0] = FieldAdd(pState[0], rc[rcIdx++]);
        pState[0] = assignSbox(pState[0]);
        applyInternal();
    }

    for (int r = 0; r < POSEIDON2_RF / 2; r++)
    {
        for (int i = 0; i < POSEIDON2_T; i++)
            pState[i] = FieldAdd(pState[i], rc[rcIdx++]);
        for (int i = 0; i < POSEIDON2_T; i++)
            pState[i] = assignSbox(pState[i]);
        applyMDS();
    }

    uint256 kernelHash = pState[0];

    int64_t nWeight = (int64_t)nTimeTx - (int64_t)nBlockTimeFrom - (int64_t)nStakeMinAge;
    if (nWeight < 0) nWeight = 0;

    uint256 weightScalar = FieldFromUint64((uint64_t)nWeight);
    uint256 valueScalar = FieldFromUint64((uint64_t)nValue);
    uint256 weightedValue = FieldMul(weightScalar, valueScalar);

    witnessOut.aL[gateIdx] = weightScalar;
    witnessOut.aR[gateIdx] = valueScalar;
    witnessOut.aO[gateIdx] = weightedValue;
    gateIdx++;

    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    uint256 targetScalar;
    {
        std::vector<unsigned char> tBytes = bnTarget.getvch();
        CBPACBNGuard bnT;
        BN_bin2bn(tBytes.data(), tBytes.size(), bnT);
        BNToU256(bnT, targetScalar);
        targetScalar = FieldReduce(targetScalar);
    }

    uint256 coinDay86400 = FieldFromUint64((uint64_t)100000000ULL * 86400ULL);
    uint256 invCoinDay = FieldInv(coinDay86400);
    uint256 K = FieldMul(targetScalar, invCoinDay);

    uint256 excess = FieldSub(FieldMul(K, weightedValue), kernelHash);

    {
        CBPACBNGuard bnExcess;
        U256ToBN(excess, bnExcess);
        uint64_t nExcess = 0;
        if (BN_num_bits(bnExcess) <= 64)
        {
            unsigned char exBytes[8];
            memset(exBytes, 0, 8);
            int nb = BN_num_bytes(bnExcess);
            if (nb > 8) nb = 8;
            BN_bn2bin(bnExcess, exBytes + 8 - nb);
            for (int i = 0; i < 8; i++)
                nExcess |= ((uint64_t)exBytes[7 - i]) << (i * 8);
        }

        for (int i = 0; i < 64; i++)
        {
            uint256 bit = FieldFromUint64((nExcess >> i) & 1);
            witnessOut.aL[gateIdx] = bit;
            witnessOut.aR[gateIdx] = bit;
            witnessOut.aO[gateIdx] = bit;  // b*b = b for b in {0,1}
            gateIdx++;
        }
    }

    {
        uint64_t nW = (uint64_t)nWeight;
        for (int i = 0; i < 32; i++)
        {
            uint256 bit = FieldFromUint64((nW >> i) & 1);
            witnessOut.aL[gateIdx] = bit;
            witnessOut.aR[gateIdx] = bit;
            witnessOut.aO[gateIdx] = bit;
            gateIdx++;
        }
    }

    {
        uint64_t nV = (uint64_t)nValue;
        for (int i = 0; i < 64; i++)
        {
            uint256 bit = FieldFromUint64((nV >> i) & 1);
            witnessOut.aL[gateIdx] = bit;
            witnessOut.aR[gateIdx] = bit;
            witnessOut.aO[gateIdx] = bit;
            gateIdx++;
        }
    }

    witnessOut.v.resize(1);
    witnessOut.v[0] = valueScalar;
    witnessOut.vBlinds.resize(1);
    uint256 blind;
    memcpy(blind.begin(), vchValueBlind.data(), 32);
    witnessOut.vBlinds[0] = blind;

    return true;
}


bool CreateBulletproofACProof(const CR1CSCircuit& circuit,
                                const CR1CSWitness& witness,
                                const std::vector<std::vector<unsigned char>>& vCommitments,
                                CBulletproofACProof& proofOut)
{
    int n = circuit.nPaddedSize;
    if (n == 0 || n > BPAC_MAX_CONSTRAINTS)
        return false;
    if ((int)witness.aL.size() != n || (int)witness.aR.size() != n || (int)witness.aO.size() != n)
        return false;

    CBPACGroupGuard group;
    CBPACBNCtxGuard ctx;
    if (!group.group || !ctx.ctx)
        return false;

    CBPACBNGuard bnOrder;
    if (!EC_GROUP_get_order(group, bnOrder, ctx))
        return false;

    CBPACPointGuard genH(group);
    {
        const std::vector<unsigned char>& vchH = CZKContext::GetGeneratorH();
        if (vchH.empty() || !EC_POINT_oct2point(group, genH, vchH.data(), vchH.size(), ctx))
            return false;
    }

    CIPAGenerators bpacGens;
    if (!GenerateIPAGenerators(BPAC_GENS_DOMAIN, n, IPA_CURVE_SECP256K1, bpacGens))
        return false;

    unsigned char alphaBytes[32], betaBytes[32], rhoBytes[32];
    if (RAND_bytes(alphaBytes, 32) != 1) return false;
    if (RAND_bytes(betaBytes, 32) != 1) return false;
    if (RAND_bytes(rhoBytes, 32) != 1) return false;

    std::vector<uint256> sL(n), sR(n);
    for (int i = 0; i < n; i++)
    {
        unsigned char buf[32];
        if (RAND_bytes(buf, 32) != 1) return false;
        memcpy(sL[i].begin(), buf, 32);
        sL[i] = FieldReduce(sL[i]);
        if (RAND_bytes(buf, 32) != 1) return false;
        memcpy(sR[i].begin(), buf, 32);
        sR[i] = FieldReduce(sR[i]);
    }

    CBPACPointGuard AI(group);
    {
        CBPACBNGuard bnAlpha;
        BN_bin2bn(alphaBytes, 32, bnAlpha);
        BN_nnmod(bnAlpha, bnAlpha, bnOrder, ctx);
        EC_POINT_mul(group, AI, bnAlpha, NULL, NULL, ctx);  // alpha*G

        for (int i = 0; i < n; i++)
        {
            CBPACBNGuard bnAL, bnAR;
            U256ToBN(witness.aL[i], bnAL);
            U256ToBN(witness.aR[i], bnAR);

            CBPACPointGuard tmpG(group), tmpH(group);
            EC_POINT_oct2point(group, tmpG, bpacGens.vG[i].data(), bpacGens.vG[i].size(), ctx);
            EC_POINT_oct2point(group, tmpH, bpacGens.vH[i].data(), bpacGens.vH[i].size(), ctx);

            CBPACPointGuard term1(group), term2(group);
            EC_POINT_mul(group, term1, NULL, tmpG, bnAL, ctx);
            EC_POINT_mul(group, term2, NULL, tmpH, bnAR, ctx);

            EC_POINT_add(group, AI, AI, term1, ctx);
            EC_POINT_add(group, AI, AI, term2, ctx);
        }
    }
    SerializePoint(group, AI, ctx, proofOut.vchAI);

    CBPACPointGuard AO(group);
    {
        CBPACBNGuard bnBeta;
        BN_bin2bn(betaBytes, 32, bnBeta);
        BN_nnmod(bnBeta, bnBeta, bnOrder, ctx);
        EC_POINT_mul(group, AO, bnBeta, NULL, NULL, ctx);

        for (int i = 0; i < n; i++)
        {
            CBPACBNGuard bnAO;
            U256ToBN(witness.aO[i], bnAO);
            CBPACPointGuard tmpG(group);
            EC_POINT_oct2point(group, tmpG, bpacGens.vG[i].data(), bpacGens.vG[i].size(), ctx);
            CBPACPointGuard term(group);
            EC_POINT_mul(group, term, NULL, tmpG, bnAO, ctx);
            EC_POINT_add(group, AO, AO, term, ctx);
        }
    }
    SerializePoint(group, AO, ctx, proofOut.vchAO);

    CBPACPointGuard S(group);
    {
        CBPACBNGuard bnRho;
        BN_bin2bn(rhoBytes, 32, bnRho);
        BN_nnmod(bnRho, bnRho, bnOrder, ctx);
        EC_POINT_mul(group, S, bnRho, NULL, NULL, ctx);

        for (int i = 0; i < n; i++)
        {
            CBPACBNGuard bnSL, bnSR;
            U256ToBN(sL[i], bnSL);
            U256ToBN(sR[i], bnSR);

            CBPACPointGuard tmpG(group), tmpH(group);
            EC_POINT_oct2point(group, tmpG, bpacGens.vG[i].data(), bpacGens.vG[i].size(), ctx);
            EC_POINT_oct2point(group, tmpH, bpacGens.vH[i].data(), bpacGens.vH[i].size(), ctx);

            CBPACPointGuard term1(group), term2(group);
            EC_POINT_mul(group, term1, NULL, tmpG, bnSL, ctx);
            EC_POINT_mul(group, term2, NULL, tmpH, bnSR, ctx);

            EC_POINT_add(group, S, S, term1, ctx);
            EC_POINT_add(group, S, S, term2, ctx);
        }
    }
    SerializePoint(group, S, ctx, proofOut.vchS);

    CBPACTranscript transcript;
    for (size_t i = 0; i < vCommitments.size(); i++)
        transcript.AppendPoint(vCommitments[i]);
    transcript.AppendPoint(proofOut.vchAI);
    transcript.AppendPoint(proofOut.vchAO);
    transcript.AppendPoint(proofOut.vchS);

    uint256 y = transcript.GetChallenge();
    uint256 z = transcript.GetChallenge();

    unsigned char tau1[32], tau3[32], tau4[32], tau5[32], tau6[32];
    if (RAND_bytes(tau1, 32) != 1) return false;
    if (RAND_bytes(tau3, 32) != 1) return false;
    if (RAND_bytes(tau4, 32) != 1) return false;
    if (RAND_bytes(tau5, 32) != 1) return false;
    if (RAND_bytes(tau6, 32) != 1) return false;

    uint256 t1Val, t3Val, t4Val, t5Val, t6Val;

    for (int i = 0; i < 32; i++)
    {
        t1Val.begin()[i] = 0;
        t3Val.begin()[i] = 0;
        t4Val.begin()[i] = 0;
        t5Val.begin()[i] = 0;
        t6Val.begin()[i] = 0;
    }

    auto commitT = [&](const uint256& tVal, const unsigned char* tau, std::vector<unsigned char>& out)
    {
        CBPACBNGuard bnT, bnTau;
        U256ToBN(tVal, bnT);
        BN_bin2bn(tau, 32, bnTau);
        BN_nnmod(bnTau, bnTau, bnOrder, ctx);

        CBPACPointGuard T(group);
        ECCommit(group, ctx, genH, bnT, bnTau, T);
        SerializePoint(group, T, ctx, out);
    };

    commitT(t1Val, tau1, proofOut.vchT1);
    commitT(t3Val, tau3, proofOut.vchT3);
    commitT(t4Val, tau4, proofOut.vchT4);
    commitT(t5Val, tau5, proofOut.vchT5);
    commitT(t6Val, tau6, proofOut.vchT6);

    transcript.AppendPoint(proofOut.vchT1);
    transcript.AppendPoint(proofOut.vchT3);
    transcript.AppendPoint(proofOut.vchT4);
    transcript.AppendPoint(proofOut.vchT5);
    transcript.AppendPoint(proofOut.vchT6);

    uint256 x = transcript.GetChallenge();

    std::vector<uint256> lVec(n), rVec(n);
    for (int i = 0; i < n; i++)
    {
        lVec[i] = FieldAdd(witness.aL[i], FieldMul(sL[i], x));
        rVec[i] = FieldAdd(witness.aR[i], FieldMul(sR[i], x));
    }

    uint256 tHat;
    memset(tHat.begin(), 0, 32);
    for (int i = 0; i < n; i++)
        tHat = FieldAdd(tHat, FieldMul(lVec[i], rVec[i]));
    proofOut.tHat = tHat;

    {
        uint256 x2 = FieldMul(x, x);
        uint256 x3 = FieldMul(x2, x);
        uint256 x4 = FieldMul(x3, x);
        uint256 x5 = FieldMul(x4, x);
        uint256 x6 = FieldMul(x5, x);

        uint256 tau1U, tau3U, tau4U, tau5U, tau6U;
        memcpy(tau1U.begin(), tau1, 32);
        memcpy(tau3U.begin(), tau3, 32);
        memcpy(tau4U.begin(), tau4, 32);
        memcpy(tau5U.begin(), tau5, 32);
        memcpy(tau6U.begin(), tau6, 32);

        tau1U = FieldReduce(tau1U);
        tau3U = FieldReduce(tau3U);
        tau4U = FieldReduce(tau4U);
        tau5U = FieldReduce(tau5U);
        tau6U = FieldReduce(tau6U);

        proofOut.tauX = FieldMul(tau1U, x);
        proofOut.tauX = FieldAdd(proofOut.tauX, FieldMul(tau3U, x3));
        proofOut.tauX = FieldAdd(proofOut.tauX, FieldMul(tau4U, x4));
        proofOut.tauX = FieldAdd(proofOut.tauX, FieldMul(tau5U, x5));
        proofOut.tauX = FieldAdd(proofOut.tauX, FieldMul(tau6U, x6));

        uint256 z2 = FieldMul(z, z);
        for (int j = 0; j < (int)witness.vBlinds.size(); j++)
        {
            uint256 zPow = z2;
            for (int k = 0; k < j; k++)
                zPow = FieldMul(zPow, z);
            proofOut.tauX = FieldAdd(proofOut.tauX, FieldMul(zPow, witness.vBlinds[j]));
        }
    }

    {
        uint256 alphaU, betaU, rhoU;
        memcpy(alphaU.begin(), alphaBytes, 32);
        memcpy(betaU.begin(), betaBytes, 32);
        memcpy(rhoU.begin(), rhoBytes, 32);
        alphaU = FieldReduce(alphaU);
        betaU = FieldReduce(betaU);
        rhoU = FieldReduce(rhoU);

        uint256 x2 = FieldMul(x, x);
        proofOut.mu = FieldAdd(alphaU, FieldAdd(FieldMul(betaU, x), FieldMul(rhoU, x2)));
    }

    std::vector<std::vector<unsigned char>> aVec(n), bVec(n);
    for (int i = 0; i < n; i++)
    {
        aVec[i].resize(32);
        memcpy(aVec[i].data(), lVec[i].begin(), 32);
        bVec[i].resize(32);
        memcpy(bVec[i].data(), rVec[i].begin(), 32);
    }

    std::vector<unsigned char> zIPA(32);
    memcpy(zIPA.data(), tHat.begin(), 32);

    CIPATranscript ipaTranscript(BPAC_DOMAIN);
    ipaTranscript.AppendScalar(std::vector<unsigned char>(proofOut.tauX.begin(), proofOut.tauX.begin() + 32));
    ipaTranscript.AppendScalar(std::vector<unsigned char>(proofOut.mu.begin(), proofOut.mu.begin() + 32));
    ipaTranscript.AppendScalar(std::vector<unsigned char>(proofOut.tHat.begin(), proofOut.tHat.begin() + 32));

    if (!CreateIPAProof(aVec, bVec, zIPA, bpacGens, ipaTranscript, proofOut.ipaProof))
        return false;

    OPENSSL_cleanse(alphaBytes, 32);
    OPENSSL_cleanse(betaBytes, 32);
    OPENSSL_cleanse(rhoBytes, 32);
    OPENSSL_cleanse(tau1, 32);
    OPENSSL_cleanse(tau3, 32);
    OPENSSL_cleanse(tau4, 32);
    OPENSSL_cleanse(tau5, 32);
    OPENSSL_cleanse(tau6, 32);

    return true;
}


bool VerifyBulletproofACProof(const CR1CSCircuit& circuit,
                                const std::vector<std::vector<unsigned char>>& vCommitments,
                                const CBulletproofACProof& proof)
{
    if (proof.IsNull() || proof.GetProofSize() > BPAC_MAX_PROOF_SIZE)
        return false;

    int n = circuit.nPaddedSize;
    if (n == 0 || n > BPAC_MAX_CONSTRAINTS)
        return false;

    CBPACGroupGuard group;
    CBPACBNCtxGuard ctx;
    if (!group.group || !ctx.ctx)
        return false;

    CBPACBNGuard bnOrder;
    if (!EC_GROUP_get_order(group, bnOrder, ctx))
        return false;

    CBPACPointGuard genH(group);
    {
        const std::vector<unsigned char>& vchH = CZKContext::GetGeneratorH();
        if (vchH.empty() || !EC_POINT_oct2point(group, genH, vchH.data(), vchH.size(), ctx))
            return false;
    }

    CIPAGenerators bpacGens;
    if (!GenerateIPAGenerators(BPAC_GENS_DOMAIN, n, IPA_CURVE_SECP256K1, bpacGens))
        return false;

    CBPACPointGuard AI(group), AO(group), S(group);
    if (!DeserializePoint(group, proof.vchAI, AI, ctx)) return false;
    if (!DeserializePoint(group, proof.vchAO, AO, ctx)) return false;
    if (!DeserializePoint(group, proof.vchS, S, ctx)) return false;

    CBPACPointGuard T1(group), T3(group), T4(group), T5(group), T6(group);
    if (!DeserializePoint(group, proof.vchT1, T1, ctx)) return false;
    if (!DeserializePoint(group, proof.vchT3, T3, ctx)) return false;
    if (!DeserializePoint(group, proof.vchT4, T4, ctx)) return false;
    if (!DeserializePoint(group, proof.vchT5, T5, ctx)) return false;
    if (!DeserializePoint(group, proof.vchT6, T6, ctx)) return false;

    CBPACTranscript transcript;
    for (size_t i = 0; i < vCommitments.size(); i++)
        transcript.AppendPoint(vCommitments[i]);
    transcript.AppendPoint(proof.vchAI);
    transcript.AppendPoint(proof.vchAO);
    transcript.AppendPoint(proof.vchS);

    uint256 y = transcript.GetChallenge();
    uint256 z = transcript.GetChallenge();

    transcript.AppendPoint(proof.vchT1);
    transcript.AppendPoint(proof.vchT3);
    transcript.AppendPoint(proof.vchT4);
    transcript.AppendPoint(proof.vchT5);
    transcript.AppendPoint(proof.vchT6);

    uint256 x = transcript.GetChallenge();

    uint256 zero;
    memset(zero.begin(), 0, 32);
    if (x == zero || y == zero || z == zero)
        return false;

    CBPACPointGuard lhsCheck(group);
    {
        CBPACBNGuard bnTauX, bnTHat;
        U256ToBN(proof.tauX, bnTauX);
        U256ToBN(proof.tHat, bnTHat);
        ECCommit(group, ctx, genH, bnTHat, bnTauX, lhsCheck);
    }

    CBPACPointGuard rhsCheck(group);
    EC_POINT_set_to_infinity(group, rhsCheck);
    {
        uint256 zPow = z;
        for (size_t j = 0; j < vCommitments.size(); j++)
        {
            zPow = FieldMul(zPow, z);  // z^(j+2)
            CBPACBNGuard bnZPow;
            U256ToBN(zPow, bnZPow);

            CBPACPointGuard Vj(group);
            if (!DeserializePoint(group, vCommitments[j], Vj, ctx))
                return false;

            CBPACPointGuard term(group);
            EC_POINT_mul(group, term, NULL, Vj, bnZPow, ctx);
            EC_POINT_add(group, rhsCheck, rhsCheck, term, ctx);
        }

        uint256 x2 = FieldMul(x, x);
        uint256 x3 = FieldMul(x2, x);
        uint256 x4 = FieldMul(x3, x);
        uint256 x5 = FieldMul(x4, x);
        uint256 x6 = FieldMul(x5, x);

        auto addTerm = [&](const EC_POINT* T, const uint256& xPow)
        {
            CBPACBNGuard bnXP;
            U256ToBN(xPow, bnXP);
            CBPACPointGuard term(group);
            EC_POINT_mul(group, term, NULL, T, bnXP, ctx);
            EC_POINT_add(group, rhsCheck, rhsCheck, term, ctx);
        };

        addTerm(T1, x);
        addTerm(T3, x3);
        addTerm(T4, x4);
        addTerm(T5, x5);
        addTerm(T6, x6);
    }

    CBPACPointGuard P(group);
    {
        CBPACBNGuard bnX, bnX2, bnMu;
        U256ToBN(x, bnX);
        uint256 x2 = FieldMul(x, x);
        U256ToBN(x2, bnX2);
        U256ToBN(proof.mu, bnMu);

        EC_POINT_copy(P, AI);

        CBPACPointGuard xAO(group);
        EC_POINT_mul(group, xAO, NULL, AO, bnX, ctx);
        EC_POINT_add(group, P, P, xAO, ctx);

        CBPACPointGuard x2S(group);
        EC_POINT_mul(group, x2S, NULL, S, bnX2, ctx);
        EC_POINT_add(group, P, P, x2S, ctx);

        CBPACPointGuard muG(group);
        EC_POINT_mul(group, muG, bnMu, NULL, NULL, ctx);
        EC_POINT_invert(group, muG, ctx);
        EC_POINT_add(group, P, P, muG, ctx);
    }

    std::vector<unsigned char> vchP;
    SerializePoint(group, P, ctx, vchP);

    std::vector<unsigned char> zIPA(32);
    memcpy(zIPA.data(), proof.tHat.begin(), 32);

    CIPATranscript ipaTranscript(BPAC_DOMAIN);
    ipaTranscript.AppendScalar(std::vector<unsigned char>(proof.tauX.begin(), proof.tauX.begin() + 32));
    ipaTranscript.AppendScalar(std::vector<unsigned char>(proof.mu.begin(), proof.mu.begin() + 32));
    ipaTranscript.AppendScalar(std::vector<unsigned char>(proof.tHat.begin(), proof.tHat.begin() + 32));

    if (!VerifyIPAProof(vchP, zIPA, bpacGens, ipaTranscript, proof.ipaProof))
    {
        if (fDebug)
            printf("VerifyBulletproofACProof: IPA verification failed\n");
        return false;
    }

    return true;
}


CR1CSCircuit BuildNullStakeV3Circuit(uint64_t nStakeModifier,
                                      unsigned int nTimeTx,
                                      unsigned int nBits,
                                      const uint256& delegationHash)
{
    CR1CSCircuit circuit;
    circuit.nHighLevelVars = 1;

    int nPoseidonGates = 339;
    for (int i = 0; i < nPoseidonGates; i++)
        circuit.AddMultGate();

    int nWeightValueGate = circuit.AddMultGate();

    int nExcessBitStart = circuit.nMultConstraints;
    for (int i = 0; i < 64; i++)
        circuit.AddMultGate();

    int nWeightBitStart = circuit.nMultConstraints;
    for (int i = 0; i < 32; i++)
        circuit.AddMultGate();

    int nValueBitStart = circuit.nMultConstraints;
    for (int i = 0; i < 64; i++)
        circuit.AddMultGate();

    int nDelegHashStart = circuit.nMultConstraints;
    int nDelegHashGates = 12;
    for (int i = 0; i < nDelegHashGates; i++)
        circuit.AddMultGate();

    int nStakeAuthStart = circuit.nMultConstraints;
    int nStakeAuthGates = 32;
    for (int i = 0; i < nStakeAuthGates; i++)
        circuit.AddMultGate();

    int nOwnerBindStart = circuit.nMultConstraints;
    int nOwnerBindGates = 32;
    for (int i = 0; i < nOwnerBindGates; i++)
        circuit.AddMultGate();

    while (circuit.nMultConstraints < BPAC_V3_MAX_CONSTRAINTS)
        circuit.AddMultGate();

    circuit.PadToNextPow2();

    {
        std::vector<CSparseEntry> wl, wr, wv;
        std::vector<CSparseEntry> wo;

        CBigNum bnTarget;
        bnTarget.SetCompact(nBits);
        uint256 targetScalar;
        {
            std::vector<unsigned char> tBytes = bnTarget.getvch();
            CBPACBNGuard bnT;
            BN_bin2bn(tBytes.data(), tBytes.size(), bnT);
            BNToU256(bnT, targetScalar);
            targetScalar = FieldReduce(targetScalar);
        }

        uint256 coinDay86400 = FieldFromUint64((uint64_t)100000000ULL * 86400ULL);
        uint256 invCoinDay = FieldInv(coinDay86400);
        uint256 K = FieldMul(targetScalar, invCoinDay);

        for (int i = 0; i < 64; i++)
        {
            uint256 pow2i = FieldFromUint64(1);
            uint256 two = FieldFromUint64(2);
            for (int j = 0; j < i; j++)
                pow2i = FieldMul(pow2i, two);
            wo.push_back(CSparseEntry(nExcessBitStart + i, pow2i));
        }

        uint256 negK = FieldSub(FieldFromUint64(0), K);
        wo.push_back(CSparseEntry(nWeightValueGate, negK));

        uint256 hashKernel = Poseidon2KernelHash(nStakeModifier, 0, 0, 0, 0, nTimeTx);
        circuit.AddLinearConstraint(wl, wr, wo, wv, hashKernel);
    }

    {
        std::vector<CSparseEntry> wl, wr, wo, wv;
        for (int i = 0; i < 32; i++)
        {
            uint256 pow2i = FieldFromUint64(1);
            uint256 two = FieldFromUint64(2);
            for (int j = 0; j < i; j++)
                pow2i = FieldMul(pow2i, two);
            wo.push_back(CSparseEntry(nWeightBitStart + i, pow2i));
        }
        uint256 zero;
        memset(zero.begin(), 0, 32);
        circuit.AddLinearConstraint(wl, wr, wo, wv, zero);
    }

    {
        std::vector<CSparseEntry> wl, wr, wo, wv;
        for (int i = 0; i < 64; i++)
        {
            uint256 pow2i = FieldFromUint64(1);
            uint256 two = FieldFromUint64(2);
            for (int j = 0; j < i; j++)
                pow2i = FieldMul(pow2i, two);
            wo.push_back(CSparseEntry(nValueBitStart + i, pow2i));
        }
        uint256 negOne = FieldSub(FieldFromUint64(0), FieldFromUint64(1));
        wv.push_back(CSparseEntry(0, negOne));
        uint256 zero;
        memset(zero.begin(), 0, 32);
        circuit.AddLinearConstraint(wl, wr, wo, wv, zero);
    }

    {
        std::vector<CSparseEntry> wl, wr, wo, wv;
        int nDelegLastGate = nDelegHashStart + nDelegHashGates - 1;
        uint256 one = FieldFromUint64(1);
        wo.push_back(CSparseEntry(nDelegLastGate, one));
        uint256 negDelegHash = FieldSub(FieldFromUint64(0), FieldReduce(delegationHash));
        circuit.AddLinearConstraint(wl, wr, wo, wv, negDelegHash);
    }

    {
        std::vector<CSparseEntry> wl, wr, wo, wv;
        int nStakeAuthLastGate = nStakeAuthStart + nStakeAuthGates - 1;
        uint256 one = FieldFromUint64(1);
        wo.push_back(CSparseEntry(nStakeAuthLastGate, one));
        uint256 zero;
        memset(zero.begin(), 0, 32);
        circuit.AddLinearConstraint(wl, wr, wo, wv, zero);
    }

    {
        std::vector<CSparseEntry> wl, wr, wo, wv;
        int nOwnerBindLastGate = nOwnerBindStart + nOwnerBindGates - 1;
        uint256 one = FieldFromUint64(1);
        wo.push_back(CSparseEntry(nOwnerBindLastGate, one));
        uint256 zero;
        memset(zero.begin(), 0, 32);
        circuit.AddLinearConstraint(wl, wr, wo, wv, zero);
    }

    return circuit;
}


bool AssignNullStakeV3Witness(const CR1CSCircuit& circuit,
                              uint64_t nStakeModifier,
                              unsigned int nBlockTimeFrom,
                              unsigned int nTxPrevOffset,
                              unsigned int nTxTimePrev,
                              unsigned int nVoutN,
                              unsigned int nTimeTx,
                              int64_t nValue,
                              const std::vector<unsigned char>& vchValueBlind,
                              unsigned int nBits,
                              const uint256& skStake,
                              const std::vector<unsigned char>& vchPkOwner,
                              const uint256& delegationHash,
                              CR1CSWitness& witnessOut)
{
    if (nValue <= 0 || vchValueBlind.size() != 32)
        return false;

    int n = circuit.nPaddedSize;
    witnessOut.aL.resize(n);
    witnessOut.aR.resize(n);
    witnessOut.aO.resize(n);

    for (int i = 0; i < n; i++)
    {
        memset(witnessOut.aL[i].begin(), 0, 32);
        memset(witnessOut.aR[i].begin(), 0, 32);
        memset(witnessOut.aO[i].begin(), 0, 32);
    }

    if (!CPoseidon2Params::IsInitialized())
        CPoseidon2Params::Initialize();

    uint256 pState[POSEIDON2_T];
    pState[0] = FieldFromUint64(nStakeModifier);
    pState[1] = FieldFromUint64((uint64_t)nBlockTimeFrom);
    pState[2] = FieldFromUint64((uint64_t)nTxPrevOffset);
    pState[3] = FieldFromUint64((uint64_t)nTxTimePrev);
    pState[4] = FieldFromUint64((uint64_t)nVoutN);
    pState[5] = FieldFromUint64((uint64_t)nTimeTx);
    pState[6] = FieldFromUint64(1);  // capacity

    const std::vector<uint256>& rc = CPoseidon2Params::GetRoundConstants();
    const std::vector<std::vector<uint256>>& mds = CPoseidon2Params::GetMDSMatrix();
    const std::vector<uint256>& diag = CPoseidon2Params::GetInternalDiag();

    int gateIdx = 0;
    int rcIdx = 0;

    auto assignSbox = [&](const uint256& x) -> uint256
    {
        uint256 x2 = FieldMul(x, x);
        uint256 x4 = FieldMul(x2, x2);
        uint256 x5 = FieldMul(x4, x);

        witnessOut.aL[gateIdx] = x;
        witnessOut.aR[gateIdx] = x;
        witnessOut.aO[gateIdx] = x2;
        gateIdx++;

        witnessOut.aL[gateIdx] = x2;
        witnessOut.aR[gateIdx] = x2;
        witnessOut.aO[gateIdx] = x4;
        gateIdx++;

        witnessOut.aL[gateIdx] = x4;
        witnessOut.aR[gateIdx] = x;
        witnessOut.aO[gateIdx] = x5;
        gateIdx++;

        return x5;
    };

    auto applyMDS = [&]()
    {
        uint256 newState[POSEIDON2_T];
        for (int i = 0; i < POSEIDON2_T; i++)
        {
            newState[i] = FieldFromUint64(0);
            for (int j = 0; j < POSEIDON2_T; j++)
                newState[i] = FieldAdd(newState[i], FieldMul(mds[i][j], pState[j]));
        }
        for (int i = 0; i < POSEIDON2_T; i++)
            pState[i] = newState[i];
    };

    auto applyInternal = [&]()
    {
        uint256 sum = FieldFromUint64(0);
        for (int i = 0; i < POSEIDON2_T; i++)
            sum = FieldAdd(sum, pState[i]);
        for (int i = 0; i < POSEIDON2_T; i++)
            pState[i] = FieldAdd(FieldMul(diag[i], pState[i]), sum);
    };

    for (int r = 0; r < POSEIDON2_RF / 2; r++)
    {
        for (int i = 0; i < POSEIDON2_T; i++)
            pState[i] = FieldAdd(pState[i], rc[rcIdx++]);
        for (int i = 0; i < POSEIDON2_T; i++)
            pState[i] = assignSbox(pState[i]);
        applyMDS();
    }

    for (int r = 0; r < POSEIDON2_RP; r++)
    {
        pState[0] = FieldAdd(pState[0], rc[rcIdx++]);
        pState[0] = assignSbox(pState[0]);
        applyInternal();
    }

    for (int r = 0; r < POSEIDON2_RF / 2; r++)
    {
        for (int i = 0; i < POSEIDON2_T; i++)
            pState[i] = FieldAdd(pState[i], rc[rcIdx++]);
        for (int i = 0; i < POSEIDON2_T; i++)
            pState[i] = assignSbox(pState[i]);
        applyMDS();
    }

    uint256 kernelHash = pState[0];

    int64_t nWeight = (int64_t)nTimeTx - (int64_t)nBlockTimeFrom - (int64_t)nStakeMinAge;
    if (nWeight < 0) nWeight = 0;

    uint256 weightScalar = FieldFromUint64((uint64_t)nWeight);
    uint256 valueScalar = FieldFromUint64((uint64_t)nValue);
    uint256 weightedValue = FieldMul(weightScalar, valueScalar);

    witnessOut.aL[gateIdx] = weightScalar;
    witnessOut.aR[gateIdx] = valueScalar;
    witnessOut.aO[gateIdx] = weightedValue;
    gateIdx++;

    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);
    uint256 targetScalar;
    {
        std::vector<unsigned char> tBytes = bnTarget.getvch();
        CBPACBNGuard bnT;
        BN_bin2bn(tBytes.data(), tBytes.size(), bnT);
        BNToU256(bnT, targetScalar);
        targetScalar = FieldReduce(targetScalar);
    }

    uint256 coinDay86400 = FieldFromUint64((uint64_t)100000000ULL * 86400ULL);
    uint256 invCoinDay = FieldInv(coinDay86400);
    uint256 K = FieldMul(targetScalar, invCoinDay);
    uint256 excess = FieldSub(FieldMul(K, weightedValue), kernelHash);

    {
        CBPACBNGuard bnExcess;
        U256ToBN(excess, bnExcess);
        uint64_t nExcess = 0;
        if (BN_num_bits(bnExcess) <= 64)
        {
            unsigned char exBytes[8];
            memset(exBytes, 0, 8);
            int nb = BN_num_bytes(bnExcess);
            if (nb > 8) nb = 8;
            BN_bn2bin(bnExcess, exBytes + 8 - nb);
            for (int i = 0; i < 8; i++)
                nExcess |= ((uint64_t)exBytes[7 - i]) << (i * 8);
        }

        for (int i = 0; i < 64; i++)
        {
            uint256 bit = FieldFromUint64((nExcess >> i) & 1);
            witnessOut.aL[gateIdx] = bit;
            witnessOut.aR[gateIdx] = bit;
            witnessOut.aO[gateIdx] = bit;
            gateIdx++;
        }
    }

    {
        uint64_t nW = (uint64_t)nWeight;
        for (int i = 0; i < 32; i++)
        {
            uint256 bit = FieldFromUint64((nW >> i) & 1);
            witnessOut.aL[gateIdx] = bit;
            witnessOut.aR[gateIdx] = bit;
            witnessOut.aO[gateIdx] = bit;
            gateIdx++;
        }
    }

    {
        uint64_t nV = (uint64_t)nValue;
        for (int i = 0; i < 64; i++)
        {
            uint256 bit = FieldFromUint64((nV >> i) & 1);
            witnessOut.aL[gateIdx] = bit;
            witnessOut.aR[gateIdx] = bit;
            witnessOut.aO[gateIdx] = bit;
            gateIdx++;
        }
    }

    {
        uint256 delegInput1 = FieldReduce(skStake);
        uint256 delegInput2;
        if (vchPkOwner.size() == 33)
        {
            uint256 pkHash = Hash(vchPkOwner.begin(), vchPkOwner.end());
            delegInput2 = FieldReduce(pkHash);
        }
        else if (vchPkOwner.size() >= 32)
            memcpy(delegInput2.begin(), vchPkOwner.data(), 32);
        delegInput2 = FieldReduce(delegInput2);

        uint256 dState = FieldAdd(delegInput1, delegInput2);
        for (int s = 0; s < 4; s++)
        {
            uint256 x = dState;
            uint256 x2 = FieldMul(x, x);
            uint256 x4 = FieldMul(x2, x2);
            uint256 x5 = FieldMul(x4, x);

            witnessOut.aL[gateIdx] = x;
            witnessOut.aR[gateIdx] = x;
            witnessOut.aO[gateIdx] = x2;
            gateIdx++;

            witnessOut.aL[gateIdx] = x2;
            witnessOut.aR[gateIdx] = x2;
            witnessOut.aO[gateIdx] = x4;
            gateIdx++;

            witnessOut.aL[gateIdx] = x4;
            witnessOut.aR[gateIdx] = x;
            witnessOut.aO[gateIdx] = x5;
            gateIdx++;

            dState = FieldAdd(x5, delegInput1);
        }
    }

    {
        uint256 authHash = Hash(skStake.begin(), skStake.begin() + 32);
        authHash = FieldReduce(authHash);

        const unsigned char* authBytes = authHash.begin();
        for (int i = 0; i < 32; i++)
        {
            uint256 bit = FieldFromUint64((authBytes[i / 8] >> (i % 8)) & 1);
            witnessOut.aL[gateIdx] = bit;
            witnessOut.aR[gateIdx] = bit;
            witnessOut.aO[gateIdx] = bit;
            gateIdx++;
        }
    }

    {
        CHashWriter ss(SER_GETHASH, 0);
        ss.write((const char*)vchPkOwner.data(), vchPkOwner.size());
        ss << nValue;
        uint256 ownerBind = ss.GetHash();
        ownerBind = FieldReduce(ownerBind);

        const unsigned char* ownerBytes = ownerBind.begin();
        for (int i = 0; i < 32; i++)
        {
            uint256 bit = FieldFromUint64((ownerBytes[i / 8] >> (i % 8)) & 1);
            witnessOut.aL[gateIdx] = bit;
            witnessOut.aR[gateIdx] = bit;
            witnessOut.aO[gateIdx] = bit;
            gateIdx++;
        }
    }

    witnessOut.v.resize(1);
    witnessOut.v[0] = valueScalar;
    witnessOut.vBlinds.resize(1);
    uint256 blind;
    memcpy(blind.begin(), vchValueBlind.data(), 32);
    witnessOut.vBlinds[0] = blind;

    return true;
}
