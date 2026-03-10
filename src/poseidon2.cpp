// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "poseidon2.h"
#include "hash.h"
#include "util.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string.h>
#include <algorithm>
#include <mutex>

class CPoseBNCtxGuard
{
public:
    BN_CTX* ctx;
    CPoseBNCtxGuard() { ctx = BN_CTX_new(); }
    ~CPoseBNCtxGuard() { if (ctx) BN_CTX_free(ctx); }
    operator BN_CTX*() { return ctx; }
};

class CPoseBNGuard
{
public:
    BIGNUM* bn;
    CPoseBNGuard() { bn = BN_new(); }
    ~CPoseBNGuard() { if (bn) BN_clear_free(bn); }
    operator BIGNUM*() { return bn; }
    BIGNUM* get() { return bn; }
};


bool CPoseidon2Params::fInitialized = false;
std::vector<uint256> CPoseidon2Params::vRoundConstants;
std::vector<std::vector<uint256>> CPoseidon2Params::vMDSMatrix;
std::vector<uint256> CPoseidon2Params::vInternalDiag;
uint256 CPoseidon2Params::fieldOrder;

static const unsigned char SECP256K1_ORDER_BE[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
};


static void Uint256ToBN(const uint256& val, BIGNUM* bn)
{
    unsigned char be[32];
    const unsigned char* le = val.begin();
    for (int i = 0; i < 32; i++)
        be[i] = le[31 - i];
    BN_bin2bn(be, 32, bn);
}

static void BNToUint256(const BIGNUM* bn, uint256& val)
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



static BIGNUM* GetOrderBN()
{
    static BIGNUM* bnOrder = NULL;
    static std::once_flag flag;
    std::call_once(flag, []() {
        bnOrder = BN_new();
        BN_bin2bn(SECP256K1_ORDER_BE, 32, bnOrder);
    });
    return bnOrder;
}

uint256 FieldAdd(const uint256& a, const uint256& b)
{
    CPoseBNCtxGuard ctx;
    CPoseBNGuard bnA, bnB, bnR;
    Uint256ToBN(a, bnA);
    Uint256ToBN(b, bnB);
    BN_mod_add(bnR, bnA, bnB, GetOrderBN(), ctx);
    uint256 result;
    BNToUint256(bnR, result);
    return result;
}

uint256 FieldSub(const uint256& a, const uint256& b)
{
    CPoseBNCtxGuard ctx;
    CPoseBNGuard bnA, bnB, bnR;
    Uint256ToBN(a, bnA);
    Uint256ToBN(b, bnB);
    BN_mod_sub(bnR, bnA, bnB, GetOrderBN(), ctx);
    uint256 result;
    BNToUint256(bnR, result);
    return result;
}

uint256 FieldMul(const uint256& a, const uint256& b)
{
    CPoseBNCtxGuard ctx;
    CPoseBNGuard bnA, bnB, bnR;
    Uint256ToBN(a, bnA);
    Uint256ToBN(b, bnB);
    BN_mod_mul(bnR, bnA, bnB, GetOrderBN(), ctx);
    uint256 result;
    BNToUint256(bnR, result);
    return result;
}

uint256 FieldPow5(const uint256& a)
{
    uint256 x2 = FieldMul(a, a);
    uint256 x4 = FieldMul(x2, x2);
    return FieldMul(x4, a);
}

uint256 FieldFromUint64(uint64_t val)
{
    uint256 result;
    memset(result.begin(), 0, 32);
    memcpy(result.begin(), &val, sizeof(val));
    return result;
}

uint256 FieldInv(const uint256& a)
{
    CPoseBNCtxGuard ctx;
    CPoseBNGuard bnA, bnR;
    Uint256ToBN(a, bnA);
    BN_mod_inverse(bnR, bnA, GetOrderBN(), ctx);
    uint256 result;
    BNToUint256(bnR, result);
    return result;
}

bool FieldIsValid(const uint256& a)
{
    CPoseBNGuard bnA;
    Uint256ToBN(a, bnA);
    return BN_cmp(bnA, GetOrderBN()) < 0;
}

uint256 FieldReduce(const uint256& a)
{
    CPoseBNCtxGuard ctx;
    CPoseBNGuard bnA, bnR;
    Uint256ToBN(a, bnA);
    BN_nnmod(bnR, bnA, GetOrderBN(), ctx);
    uint256 result;
    BNToUint256(bnR, result);
    return result;
}


static bool SHAKE256_XOF(const unsigned char* seed, size_t seedLen,
                          unsigned char* output, size_t outputLen)
{
    const EVP_MD* md = EVP_shake256();
    if (md)
    {
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (!mdctx) return false;

        bool ok = true;
        if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) ok = false;
        if (ok && EVP_DigestUpdate(mdctx, seed, seedLen) != 1) ok = false;
        if (ok && EVP_DigestFinalXOF(mdctx, output, outputLen) != 1) ok = false;

        EVP_MD_CTX_free(mdctx);
        return ok;
    }

    size_t offset = 0;
    uint32_t counter = 0;
    while (offset < outputLen)
    {
        unsigned char block[32];
        SHA256_CTX sha;
        SHA256_Init(&sha);
        SHA256_Update(&sha, seed, seedLen);
        SHA256_Update(&sha, (unsigned char*)&counter, 4);
        SHA256_Final(block, &sha);

        size_t toCopy = std::min((size_t)32, outputLen - offset);
        memcpy(output + offset, block, toCopy);
        offset += toCopy;
        counter++;
    }
    return true;
}


void CPoseidon2Params::GenerateRoundConstants()
{
    const char* domain = "Innova_Poseidon2_RC_secp256k1_t7_RF8_RP57";
    size_t domainLen = strlen(domain);

    size_t xofLen = POSEIDON2_NUM_RC * 64;
    std::vector<unsigned char> xofOutput(xofLen);
    SHAKE256_XOF((const unsigned char*)domain, domainLen, xofOutput.data(), xofLen);

    CPoseBNCtxGuard ctx;
    vRoundConstants.resize(POSEIDON2_NUM_RC);

    for (int i = 0; i < POSEIDON2_NUM_RC; i++)
    {
        CPoseBNGuard bnVal, bnReduced;
        BN_bin2bn(xofOutput.data() + i * 64, 64, bnVal);
        BN_nnmod(bnReduced, bnVal, GetOrderBN(), ctx);
        BNToUint256(bnReduced, vRoundConstants[i]);
    }
}


void CPoseidon2Params::GenerateMDSMatrix()
{
    const char* domain = "Innova_Poseidon2_MDS_t7";
    size_t domainLen = strlen(domain);

    size_t xofLen = 2 * POSEIDON2_T * 64;
    std::vector<unsigned char> xofOutput(xofLen);
    SHAKE256_XOF((const unsigned char*)domain, domainLen, xofOutput.data(), xofLen);

    CPoseBNCtxGuard ctx;
    std::vector<uint256> x(POSEIDON2_T), y(POSEIDON2_T);

    for (int i = 0; i < POSEIDON2_T; i++)
    {
        CPoseBNGuard bnVal, bnReduced;
        BN_bin2bn(xofOutput.data() + i * 64, 64, bnVal);
        BN_nnmod(bnReduced, bnVal, GetOrderBN(), ctx);
        BNToUint256(bnReduced, x[i]);

        BN_bin2bn(xofOutput.data() + (POSEIDON2_T + i) * 64, 64, bnVal);
        BN_nnmod(bnReduced, bnVal, GetOrderBN(), ctx);
        BNToUint256(bnReduced, y[i]);
    }

    vMDSMatrix.resize(POSEIDON2_T, std::vector<uint256>(POSEIDON2_T));
    for (int i = 0; i < POSEIDON2_T; i++)
    {
        for (int j = 0; j < POSEIDON2_T; j++)
        {
            uint256 sum = FieldAdd(x[i], y[j]);
            vMDSMatrix[i][j] = FieldInv(sum);
        }
    }
}


void CPoseidon2Params::GenerateInternalDiag()
{
    const char* domain = "Innova_Poseidon2_DIAG_t7";
    size_t domainLen = strlen(domain);

    size_t xofLen = POSEIDON2_T * 64;
    std::vector<unsigned char> xofOutput(xofLen);
    SHAKE256_XOF((const unsigned char*)domain, domainLen, xofOutput.data(), xofLen);

    CPoseBNCtxGuard ctx;
    vInternalDiag.resize(POSEIDON2_T);

    for (int i = 0; i < POSEIDON2_T; i++)
    {
        CPoseBNGuard bnVal, bnReduced;
        BN_bin2bn(xofOutput.data() + i * 64, 64, bnVal);
        BN_nnmod(bnReduced, bnVal, GetOrderBN(), ctx);
        BNToUint256(bnReduced, vInternalDiag[i]);
    }
}


bool CPoseidon2Params::Initialize()
{
    static std::once_flag initFlag;
    std::call_once(initFlag, []() {
        memset(fieldOrder.begin(), 0, 32);
        for (int i = 0; i < 32; i++)
            fieldOrder.begin()[i] = SECP256K1_ORDER_BE[31 - i];

        GenerateRoundConstants();
        GenerateMDSMatrix();
        GenerateInternalDiag();

        fInitialized = true;
    });
    return true;
}

bool CPoseidon2Params::IsInitialized()
{
    return fInitialized;
}

const std::vector<uint256>& CPoseidon2Params::GetRoundConstants()
{
    return vRoundConstants;
}

const std::vector<std::vector<uint256>>& CPoseidon2Params::GetMDSMatrix()
{
    return vMDSMatrix;
}

const std::vector<uint256>& CPoseidon2Params::GetInternalDiag()
{
    return vInternalDiag;
}

const uint256& CPoseidon2Params::GetFieldOrder()
{
    return fieldOrder;
}



static void ApplyMDS(CPoseidon2State& state)
{
    const std::vector<std::vector<uint256>>& M = CPoseidon2Params::GetMDSMatrix();
    uint256 newState[POSEIDON2_T];

    for (int i = 0; i < POSEIDON2_T; i++)
    {
        newState[i] = 0;
        for (int j = 0; j < POSEIDON2_T; j++)
        {
            uint256 prod = FieldMul(M[i][j], state.GetElement(j));
            newState[i] = FieldAdd(newState[i], prod);
        }
    }

    for (int i = 0; i < POSEIDON2_T; i++)
        state.SetElement(i, newState[i]);
}

static void ApplyInternalLinear(CPoseidon2State& state)
{
    const std::vector<uint256>& diag = CPoseidon2Params::GetInternalDiag();

    uint256 stateSum = 0;
    for (int i = 0; i < POSEIDON2_T; i++)
        stateSum = FieldAdd(stateSum, state.GetElement(i));

    for (int i = 0; i < POSEIDON2_T; i++)
    {
        uint256 diagProduct = FieldMul(diag[i], state.GetElement(i));
        state.SetElement(i, FieldAdd(diagProduct, stateSum));
    }
}

void Poseidon2Permute(CPoseidon2State& state)
{
    if (!CPoseidon2Params::IsInitialized())
        CPoseidon2Params::Initialize();

    const std::vector<uint256>& rc = CPoseidon2Params::GetRoundConstants();
    int rcIdx = 0;

    for (int r = 0; r < POSEIDON2_RF / 2; r++)
    {
        for (int i = 0; i < POSEIDON2_T; i++)
        {
            state.SetElement(i, FieldAdd(state.GetElement(i), rc[rcIdx++]));
        }

        for (int i = 0; i < POSEIDON2_T; i++)
        {
            state.SetElement(i, FieldPow5(state.GetElement(i)));
        }

        ApplyMDS(state);
    }

    for (int r = 0; r < POSEIDON2_RP; r++)
    {
        state.SetElement(0, FieldAdd(state.GetElement(0), rc[rcIdx++]));

        state.SetElement(0, FieldPow5(state.GetElement(0)));

        ApplyInternalLinear(state);
    }

    for (int r = 0; r < POSEIDON2_RF / 2; r++)
    {
        for (int i = 0; i < POSEIDON2_T; i++)
        {
            state.SetElement(i, FieldAdd(state.GetElement(i), rc[rcIdx++]));
        }

        for (int i = 0; i < POSEIDON2_T; i++)
        {
            state.SetElement(i, FieldPow5(state.GetElement(i)));
        }

        ApplyMDS(state);
    }
}


void Poseidon2Hash(const uint256 inputs[6], uint256& output)
{
    CPoseidon2State state;

    for (int i = 0; i < POSEIDON2_RATE; i++)
    {
        state.SetElement(i, FieldReduce(inputs[i]));
    }

    state.SetElement(POSEIDON2_T - 1, FieldFromUint64(1));

    Poseidon2Permute(state);

    output = state.GetElement(0);
}


uint256 Poseidon2KernelHash(uint64_t nStakeModifier,
                             unsigned int nBlockTimeFrom,
                             unsigned int nTxPrevOffset,
                             unsigned int nTxTimePrev,
                             unsigned int nVoutN,
                             unsigned int nTimeTx)
{
    uint256 inputs[6];
    inputs[0] = FieldFromUint64(nStakeModifier);
    inputs[1] = FieldFromUint64((uint64_t)nBlockTimeFrom);
    inputs[2] = FieldFromUint64((uint64_t)nTxPrevOffset);
    inputs[3] = FieldFromUint64((uint64_t)nTxTimePrev);
    inputs[4] = FieldFromUint64((uint64_t)nVoutN);
    inputs[5] = FieldFromUint64((uint64_t)nTimeTx);

    uint256 output;
    Poseidon2Hash(inputs, output);
    return output;
}
