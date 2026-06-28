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

static void U256ToScalarBytes(const uint256& val, std::vector<unsigned char>& out)
{
    out.resize(32);
    const unsigned char* le = val.begin();
    for (int i = 0; i < 32; i++)
        out[i] = le[31 - i];
}

static void ScalarBytesToU256Raw(const unsigned char* bytes, uint256& out)
{
    unsigned char* le = out.begin();
    for (int i = 0; i < 32; i++)
        le[i] = bytes[31 - i];
}

static bool ScalarBytesToU256(const unsigned char* bytes, const BIGNUM* bnOrder,
                              BN_CTX* ctx, uint256& out)
{
    CBPACBNGuard bn;
    BN_bin2bn(bytes, 32, bn);
    if (!BN_nnmod(bn, bn, bnOrder, ctx))
        return false;
    BNToU256(bn, out);
    return true;
}

static bool U256ToUint64(const uint256& val, uint64_t& out)
{
    const unsigned char* le = val.begin();
    for (int i = 8; i < 32; i++)
    {
        if (le[i] != 0)
            return false;
    }

    out = 0;
    for (int i = 0; i < 8; i++)
        out |= ((uint64_t)le[i]) << (8 * i);
    return true;
}

static uint256 CircuitFingerprint(const CR1CSCircuit& circuit)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("Innova/BPAC/Circuit/v1");
    ss << circuit.nMultConstraints;
    ss << circuit.nPaddedSize;
    ss << circuit.nHighLevelVars;
    ss << circuit.nLinearConstraints;
    ss << circuit.WL;
    ss << circuit.WR;
    ss << circuit.WO;
    ss << circuit.WV;
    ss << circuit.c;
    return ss.GetHash();
}

static bool CheckCircuitShape(const CR1CSCircuit& circuit)
{
    int n = circuit.nPaddedSize;
    if (circuit.nMultConstraints <= 0 || n <= 0 || n > BPAC_MAX_CONSTRAINTS)
        return false;
    if (circuit.nMultConstraints > n || (n & (n - 1)) != 0)
        return false;
    if (circuit.nHighLevelVars < 0 || circuit.nHighLevelVars > BPAC_MAX_HIGH_VARS)
        return false;
    if (circuit.nLinearConstraints < 0 ||
        circuit.nLinearConstraints != (int)circuit.WL.size() ||
        circuit.nLinearConstraints != (int)circuit.WR.size() ||
        circuit.nLinearConstraints != (int)circuit.WO.size() ||
        circuit.nLinearConstraints != (int)circuit.WV.size() ||
        circuit.nLinearConstraints != (int)circuit.c.size())
        return false;

    auto checkEntries = [](const std::vector<CSparseEntry>& entries, int nCols) -> bool {
        for (const CSparseEntry& entry : entries)
        {
            if (entry.nCol < 0 || entry.nCol >= nCols)
                return false;
        }
        return true;
    };

    for (int j = 0; j < circuit.nLinearConstraints; j++)
    {
        if (!checkEntries(circuit.WL[j], n) ||
            !checkEntries(circuit.WR[j], n) ||
            !checkEntries(circuit.WO[j], n) ||
            !checkEntries(circuit.WV[j], circuit.nHighLevelVars))
            return false;
    }
    return true;
}

static uint256 SparseEval(const std::vector<CSparseEntry>& entries,
                          const std::vector<uint256>& values)
{
    uint256 acc = FieldFromUint64(0);
    for (const CSparseEntry& entry : entries)
        acc = FieldAdd(acc, FieldMul(entry.value, values[entry.nCol]));
    return acc;
}

static uint256 InnerProduct(const std::vector<uint256>& a,
                            const std::vector<uint256>& b)
{
    uint256 acc = FieldFromUint64(0);
    for (size_t i = 0; i < a.size(); i++)
        acc = FieldAdd(acc, FieldMul(a[i], b[i]));
    return acc;
}

static bool DeserializePoint(const EC_GROUP* group, const std::vector<unsigned char>& data,
                               EC_POINT* point, BN_CTX* ctx);
static bool SerializePoint(const EC_GROUP* group, const EC_POINT* point, BN_CTX* ctx,
                           std::vector<unsigned char>& out);

static uint256 FieldNeg(const uint256& a)
{
    return FieldSub(FieldFromUint64(0), a);
}

static bool ComputePowers(const uint256& base, int n, std::vector<uint256>& powersOut)
{
    if (n <= 0)
        return false;
    powersOut.resize(n);
    powersOut[0] = FieldFromUint64(1);
    for (int i = 1; i < n; i++)
        powersOut[i] = FieldMul(powersOut[i - 1], base);
    return true;
}

static bool CheckWitnessShape(const CR1CSCircuit& circuit,
                              const CR1CSWitness& witness,
                              const std::vector<std::vector<unsigned char>>& vCommitments)
{
    if (!CheckCircuitShape(circuit))
        return false;

    int n = circuit.nPaddedSize;
    if ((int)witness.aL.size() != n ||
        (int)witness.aR.size() != n ||
        (int)witness.aO.size() != n)
        return false;
    if ((int)witness.v.size() != circuit.nHighLevelVars ||
        (int)witness.vBlinds.size() != circuit.nHighLevelVars ||
        (int)vCommitments.size() != circuit.nHighLevelVars)
        return false;
    return true;
}

static bool CheckR1CSWitness(const CR1CSCircuit& circuit,
                             const CR1CSWitness& witness,
                             const std::vector<std::vector<unsigned char>>& vCommitments)
{
    if (!CheckWitnessShape(circuit, witness, vCommitments))
        return false;

    for (int i = 0; i < circuit.nMultConstraints; i++)
    {
        if (FieldMul(witness.aL[i], witness.aR[i]) != witness.aO[i])
        {
            if (fDebug) fprintf(stderr, "CheckR1CSWitness: multiplication gate %d failed\n", i);
            return false;
        }
    }

    for (int j = 0; j < circuit.nLinearConstraints; j++)
    {
        uint256 lhs = FieldFromUint64(0);
        lhs = FieldAdd(lhs, SparseEval(circuit.WL[j], witness.aL));
        lhs = FieldAdd(lhs, SparseEval(circuit.WR[j], witness.aR));
        lhs = FieldAdd(lhs, SparseEval(circuit.WO[j], witness.aO));
        lhs = FieldAdd(lhs, SparseEval(circuit.WV[j], witness.v));
        lhs = FieldAdd(lhs, circuit.c[j]);
        if (lhs != FieldFromUint64(0))
        {
            if (fDebug) fprintf(stderr, "CheckR1CSWitness: linear constraint %d failed\n", j);
            return false;
        }
    }

    for (int j = 0; j < circuit.nHighLevelVars; j++)
    {
        uint64_t nValue = 0;
        if (!U256ToUint64(witness.v[j], nValue))
        {
            if (fDebug) fprintf(stderr, "CheckR1CSWitness: committed value %d not uint64\n", j);
            return false;
        }
        std::vector<unsigned char> vchBlind;
        U256ToScalarBytes(witness.vBlinds[j], vchBlind);

        CPedersenCommitment commit;
        commit.vchCommitment = vCommitments[j];
        if (!VerifyPedersenCommitment(commit, (int64_t)nValue, vchBlind))
        {
            if (fDebug) fprintf(stderr, "CheckR1CSWitness: commitment %d failed\n", j);
            return false;
        }
    }

    return true;
}

static bool AddSparseFold(const std::vector<CSparseEntry>& entries,
                          const uint256& rowWeight,
                          std::vector<uint256>& out)
{
    for (const CSparseEntry& entry : entries)
    {
        if (entry.nCol < 0 || entry.nCol >= (int)out.size())
            return false;
        out[entry.nCol] = FieldAdd(out[entry.nCol], FieldMul(rowWeight, entry.value));
    }
    return true;
}

static bool FlattenCircuitWeights(const CR1CSCircuit& circuit,
                                  const uint256& z,
                                  std::vector<uint256>& wL,
                                  std::vector<uint256>& wR,
                                  std::vector<uint256>& wO,
                                  std::vector<uint256>& wV,
                                  uint256& wC)
{
    int n = circuit.nPaddedSize;
    wL.assign(n, FieldFromUint64(0));
    wR.assign(n, FieldFromUint64(0));
    wO.assign(n, FieldFromUint64(0));
    wV.assign(circuit.nHighLevelVars, FieldFromUint64(0));
    wC = FieldFromUint64(0);

    uint256 rowWeight = z;
    for (int j = 0; j < circuit.nLinearConstraints; j++)
    {
        if (!AddSparseFold(circuit.WL[j], rowWeight, wL) ||
            !AddSparseFold(circuit.WR[j], rowWeight, wR) ||
            !AddSparseFold(circuit.WO[j], rowWeight, wO) ||
            !AddSparseFold(circuit.WV[j], rowWeight, wV))
            return false;
        wC = FieldAdd(wC, FieldMul(rowWeight, circuit.c[j]));
        rowWeight = FieldMul(rowWeight, z);
    }
    return true;
}

static bool DeriveR1CSIPAGenerators(const CIPAGenerators& baseGens,
                                    const std::vector<uint256>& yInvPowers,
                                    CIPAGenerators& gensOut)
{
    if ((int)yInvPowers.size() != baseGens.nLength)
        return false;

    gensOut = baseGens;
    for (int i = 0; i < baseGens.nLength; i++)
    {
        std::vector<unsigned char> scalar;
        U256ToScalarBytes(yInvPowers[i], scalar);
        if (!IPAScalarMul(scalar, baseGens.vH[i], gensOut.vH[i], baseGens.curveType))
            return false;
    }
    return true;
}

static bool DeserializeNonInfinityPoint(const EC_GROUP* group,
                                        const std::vector<unsigned char>& data,
                                        EC_POINT* point,
                                        BN_CTX* ctx)
{
    if (!DeserializePoint(group, data, point, ctx))
        return false;
    if (EC_POINT_is_on_curve(group, point, ctx) != 1)
        return false;
    if (EC_POINT_is_at_infinity(group, point))
        return false;
    return true;
}

static bool AddPointTimesScalar(const EC_GROUP* group,
                                BN_CTX* ctx,
                                EC_POINT* accumulator,
                                const std::vector<unsigned char>& pointBytes,
                                const uint256& scalar)
{
    uint256 zero = FieldFromUint64(0);
    if (scalar == zero)
        return true;

    CBPACBNGuard bnScalar;
    U256ToBN(scalar, bnScalar);

    CBPACPointGuard point(group), term(group);
    if (!DeserializeNonInfinityPoint(group, pointBytes, point, ctx))
        return false;
    if (EC_POINT_mul(group, term, NULL, point, bnScalar, ctx) != 1)
        return false;
    if (EC_POINT_add(group, accumulator, accumulator, term, ctx) != 1)
        return false;
    return true;
}

// Pippenger bucket-method multi-scalar multiplication over secp256k1:
//   result = sum_i scalars[i] * points[i]
// The returned group element is IDENTICAL to the naive accumulation, so this is a
// drop-in replacement for the per-point EC_POINT_mul+add loops in the proof
// verifier (the AC verify's dominant cost). It is validated bit-for-bit against the
// naive method over random inputs by a differential unit test. Verification-only,
// not constant time; scalars are reduced mod the group order, points may be the
// identity. External linkage so the test can reach it.
bool BPACMultiScalarMul(const EC_GROUP* group, BN_CTX* ctx,
                        const std::vector<EC_POINT*>& points,
                        const std::vector<BIGNUM*>& scalars,
                        EC_POINT* result)
{
    if (points.size() != scalars.size())
        return false;
    if (EC_POINT_set_to_infinity(group, result) != 1)
        return false;
    const size_t n = points.size();
    if (n == 0)
        return true;

    // Window size, tuned for n up to ~2n+5 with n<=2048 in the AC verifier.
    int c;
    if (n >= 1024)     c = 11;
    else if (n >= 256) c = 9;
    else if (n >= 32)  c = 7;
    else               c = 4;

    CBPACBNGuard order;
    if (EC_GROUP_get_order(group, order, ctx) != 1)
        return false;
    const int nbits = BN_num_bits(order);
    const int numWindows = (nbits + c - 1) / c;
    const int numBuckets = (1 << c) - 1;

    bool ok = true;
    std::vector<EC_POINT*> buckets(numBuckets, (EC_POINT*)NULL);
    for (int b = 0; b < numBuckets && ok; b++)
    {
        buckets[b] = EC_POINT_new(group);
        ok = (buckets[b] != NULL);
    }
    EC_POINT* running = EC_POINT_new(group);
    EC_POINT* windowSum = EC_POINT_new(group);
    ok = ok && running && windowSum;

    for (int w = numWindows - 1; w >= 0 && ok; w--)
    {
        // result <<= c (skip on the most-significant window)
        if (w != numWindows - 1)
            for (int b = 0; b < c && ok; b++)
                ok = (EC_POINT_dbl(group, result, result, ctx) == 1);

        for (int b = 0; b < numBuckets && ok; b++)
            ok = (EC_POINT_set_to_infinity(group, buckets[b]) == 1);

        const int base = w * c;
        for (size_t i = 0; i < n && ok; i++)
        {
            int digit = 0;
            for (int b = 0; b < c; b++)
                if (BN_is_bit_set(scalars[i], base + b))
                    digit |= (1 << b);
            if (digit != 0)
                ok = (EC_POINT_add(group, buckets[digit - 1], buckets[digit - 1], points[i], ctx) == 1);
        }

        // windowSum = sum_{d=1..numBuckets} d * buckets[d-1] via the running-sum trick.
        ok = ok && (EC_POINT_set_to_infinity(group, running) == 1)
                && (EC_POINT_set_to_infinity(group, windowSum) == 1);
        for (int d = numBuckets; d >= 1 && ok; d--)
        {
            ok = (EC_POINT_add(group, running, running, buckets[d - 1], ctx) == 1)
              && (EC_POINT_add(group, windowSum, windowSum, running, ctx) == 1);
        }

        ok = ok && (EC_POINT_add(group, result, result, windowSum, ctx) == 1);
    }

    for (int b = 0; b < numBuckets; b++)
        if (buckets[b]) EC_POINT_free(buckets[b]);
    if (running) EC_POINT_free(running);
    if (windowSum) EC_POINT_free(windowSum);
    return ok;
}

static void AppendIPAScalar(CIPATranscript& transcript, const uint256& scalar)
{
    std::vector<unsigned char> scalarBytes;
    U256ToScalarBytes(scalar, scalarBytes);
    transcript.AppendScalar(scalarBytes);
}

static void AppendBPACIPAStatement(CIPATranscript& transcript,
                                   const CR1CSCircuit& circuit,
                                   const std::vector<std::vector<unsigned char>>& vCommitments,
                                   const CBulletproofACProof& proof,
                                   const std::vector<unsigned char>& vchP)
{
    AppendIPAScalar(transcript, CircuitFingerprint(circuit));
    for (size_t i = 0; i < vCommitments.size(); i++)
        transcript.AppendPoint(vCommitments[i]);
    transcript.AppendPoint(proof.vchAI);
    transcript.AppendPoint(proof.vchAO);
    transcript.AppendPoint(proof.vchS);
    transcript.AppendPoint(proof.vchT1);
    transcript.AppendPoint(proof.vchT3);
    transcript.AppendPoint(proof.vchT4);
    transcript.AppendPoint(proof.vchT5);
    transcript.AppendPoint(proof.vchT6);
    transcript.AppendPoint(vchP);
    AppendIPAScalar(transcript, proof.tauX);
    AppendIPAScalar(transcript, proof.mu);
    AppendIPAScalar(transcript, proof.tHat);
}

// Append (deserialize(pointBytes), scalar) to the multiexp arrays, skipping zero
// scalars (matching AddPointTimesScalar's early-out) and rejecting infinity points.
static bool BPACAppendTermBytes(const EC_GROUP* group, BN_CTX* ctx,
                                const std::vector<unsigned char>& pointBytes,
                                const BIGNUM* scalar,
                                std::vector<EC_POINT*>& vPts,
                                std::vector<BIGNUM*>& vScs)
{
    if (BN_is_zero(scalar))
        return true;
    EC_POINT* p = EC_POINT_new(group);
    BIGNUM* s = BN_dup(scalar);
    if (!p || !s || !DeserializeNonInfinityPoint(group, pointBytes, p, ctx))
    {
        if (p) EC_POINT_free(p);
        if (s) BN_free(s);
        return false;
    }
    vPts.push_back(p);
    vScs.push_back(s);
    return true;
}

// Append (copy(point), scalar) to the multiexp arrays, skipping zero scalars.
static bool BPACAppendTermPoint(const EC_GROUP* group,
                                const EC_POINT* point,
                                const BIGNUM* scalar,
                                std::vector<EC_POINT*>& vPts,
                                std::vector<BIGNUM*>& vScs)
{
    if (BN_is_zero(scalar))
        return true;
    EC_POINT* p = EC_POINT_dup(point, group);
    BIGNUM* s = BN_dup(scalar);
    if (!p || !s)
    {
        if (p) EC_POINT_free(p);
        if (s) BN_free(s);
        return false;
    }
    vPts.push_back(p);
    vScs.push_back(s);
    return true;
}

static bool ComputeBPACIPAStatementPoint(const EC_GROUP* group,
                                         BN_CTX* ctx,
                                         const CIPAGenerators& proofGens,
                                         const std::vector<uint256>& yPowers,
                                         const std::vector<uint256>& yInvPowers,
                                         const std::vector<uint256>& wL,
                                         const std::vector<uint256>& wR,
                                         const std::vector<uint256>& wO,
                                         const uint256& x,
                                         const CBulletproofACProof& proof,
                                         std::vector<unsigned char>& vchPOut)
{
    int n = proofGens.nLength;
    if ((int)yPowers.size() != n ||
        (int)yInvPowers.size() != n ||
        (int)wL.size() != n ||
        (int)wR.size() != n ||
        (int)wO.size() != n)
        return false;

    CBPACPointGuard AI(group), AO(group), S(group);
    if (!DeserializeNonInfinityPoint(group, proof.vchAI, AI, ctx)) return false;
    if (!DeserializeNonInfinityPoint(group, proof.vchAO, AO, ctx)) return false;
    if (!DeserializeNonInfinityPoint(group, proof.vchS, S, ctx)) return false;

    CBPACBNGuard bnX, bnX2, bnX3, bnMu;
    U256ToBN(x, bnX);
    uint256 x2 = FieldMul(x, x);
    uint256 x3 = FieldMul(x2, x);
    U256ToBN(x2, bnX2);
    U256ToBN(x3, bnX3);
    U256ToBN(proof.mu, bnMu);

    CBPACPointGuard P(group);

    // Evaluate the IPA statement point as ONE Pippenger multiexp over all ~2n+5
    // (point, scalar) terms instead of a per-term EC_POINT_mul+add. The result is
    // identical to the naive accumulation (multiscalarmul_matches_naive test):
    //   P = x*AI + x^2*AO + x^3*S - mu*G + tHat*U
    //       + sum_i coeffG_i*vG[i] + coeffH_i*vH[i]
    std::vector<EC_POINT*> vPts;
    std::vector<BIGNUM*> vScs;
    bool ok = true;

    ok = ok && BPACAppendTermPoint(group, AI, bnX, vPts, vScs);
    ok = ok && BPACAppendTermPoint(group, AO, bnX2, vPts, vScs);
    ok = ok && BPACAppendTermPoint(group, S, bnX3, vPts, vScs);

    // -mu*G  (scalar = order - mu)
    CBPACBNGuard order, negMu;
    if (!ok || EC_GROUP_get_order(group, order, ctx) != 1 || !BN_sub(negMu, order, bnMu))
        ok = false;
    else
        ok = BPACAppendTermPoint(group, EC_GROUP_get0_generator(group), negMu, vPts, vScs);

    for (int i = 0; i < n && ok; i++)
    {
        uint256 coeffG = FieldMul(x, FieldMul(yInvPowers[i], wR[i]));
        CBPACBNGuard bnCoeffG;
        U256ToBN(coeffG, bnCoeffG);
        if (!BPACAppendTermBytes(group, ctx, proofGens.vG[i], bnCoeffG, vPts, vScs)) { ok = false; break; }

        uint256 coeffH = FieldSub(wO[i], yPowers[i]);
        coeffH = FieldAdd(coeffH, FieldMul(x, wL[i]));
        CBPACBNGuard bnCoeffH;
        U256ToBN(coeffH, bnCoeffH);
        if (!BPACAppendTermBytes(group, ctx, proofGens.vH[i], bnCoeffH, vPts, vScs)) { ok = false; break; }
    }

    if (ok)
    {
        CBPACBNGuard bnTHat;
        U256ToBN(proof.tHat, bnTHat);
        ok = BPACAppendTermBytes(group, ctx, proofGens.vchU, bnTHat, vPts, vScs);
    }

    if (ok)
        ok = BPACMultiScalarMul(group, ctx, vPts, vScs, P);

    for (size_t i = 0; i < vPts.size(); i++) EC_POINT_free(vPts[i]);
    for (size_t i = 0; i < vScs.size(); i++) BN_free(vScs[i]);

    if (!ok)
        return false;

    return SerializePoint(group, P, ctx, vchPOut);
}

static void AddWireValueConstraint(CR1CSCircuit& circuit,
                                   int nGate,
                                   char wire,
                                   const uint256& value);
static void AddBitSumTerms(std::vector<CSparseEntry>& entries,
                           int nStart,
                           int nCount,
                           const uint256& nSign);

static const int BPAC_KERNEL_COINDAY_BITS = 64;
static const int BPAC_KERNEL_REMAINDER_BITS = 43;
static const int BPAC_KERNEL_PRODUCT_BITS = 96;
static const int BPAC_KERNEL_COMPARE_BITS = 352;
static const uint64_t BPAC_KERNEL_DENOMINATOR = (uint64_t)100000000ULL * 86400ULL;
static const int BPAC_V3_DELEGATION_BITS = 256;

static const BIGNUM* BigNumConst(const CBigNum& bn)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return bn.pbn;
#else
    return bn.getc();
#endif
}

static bool CompactTargetMantissaAndShift(unsigned int nBits,
                                          uint64_t& nMantissaOut,
                                          int& nShiftBitsOut)
{
    if (nBits & 0x00800000)
        return false;

    unsigned int nSize = nBits >> 24;
    uint64_t nWord = nBits & 0x007fffff;
    if (nWord == 0)
        return false;

    if (nSize <= 3)
    {
        nMantissaOut = nWord >> (8 * (3 - nSize));
        nShiftBitsOut = 0;
    }
    else
    {
        nMantissaOut = nWord;
        nShiftBitsOut = 8 * (nSize - 3);
    }

    return nMantissaOut != 0 &&
           nShiftBitsOut >= 0 &&
           nShiftBitsOut + BPAC_KERNEL_PRODUCT_BITS <= BPAC_KERNEL_COMPARE_BITS;
}

static void SetBitVectorBigNum(const CBigNum& value,
                               int nBits,
                               std::vector<uint256>& out,
                               int nStart)
{
    const BIGNUM* bn = BigNumConst(value);
    for (int i = 0; i < nBits; i++)
        out[nStart + i] = FieldFromUint64(BN_is_bit_set(bn, i) ? 1 : 0);
}

static void SetKernelCompareBorrowBits(const CBigNum& threshold,
                                       const uint256& hashKernel,
                                       std::vector<uint256>& out,
                                       int nStart)
{
    const BIGNUM* bnThreshold = BigNumConst(threshold);
    const unsigned char* hashLE = hashKernel.begin();
    int nBorrow = 0;
    for (int i = 0; i < BPAC_KERNEL_COMPARE_BITS; i++)
    {
        int nThresholdBit = BN_is_bit_set(bnThreshold, i) ? 1 : 0;
        int nHashBit = 0;
        if (i < 256)
            nHashBit = (hashLE[i / 8] >> (i % 8)) & 1;
        int nBorrowOut = (nThresholdBit - nBorrow < nHashBit) ? 1 : 0;
        out[nStart + i] = FieldFromUint64((uint64_t)nBorrowOut);
        nBorrow = nBorrowOut;
    }
}

static void AddKernelIntegerTargetConstraints(CR1CSCircuit& circuit,
                                              int nWeightValueGate,
                                              int nCoinDayBitStart,
                                              int nRemainderBitStart,
                                              int nProductBitStart,
                                              int nDifferenceBitStart,
                                              int nBorrowBitStart,
                                              const uint256& hashKernel,
                                              unsigned int nBits)
{
    uint64_t nTargetMantissa = 0;
    int nTargetShiftBits = 0;
    if (!CompactTargetMantissaAndShift(nBits, nTargetMantissa, nTargetShiftBits))
    {
        std::vector<CSparseEntry> wl, wr, wo, wv;
        circuit.AddLinearConstraint(wl, wr, wo, wv, FieldFromUint64(1));
        return;
    }

    {
        std::vector<CSparseEntry> wl, wr, wo, wv;
        wo.push_back(CSparseEntry(nWeightValueGate, FieldFromUint64(1)));

        uint256 denom = FieldFromUint64(BPAC_KERNEL_DENOMINATOR);
        uint256 pow2 = FieldFromUint64(1);
        uint256 two = FieldFromUint64(2);
        for (int i = 0; i < BPAC_KERNEL_COINDAY_BITS; i++)
        {
            wo.push_back(CSparseEntry(nCoinDayBitStart + i,
                                      FieldNeg(FieldMul(denom, pow2))));
            pow2 = FieldMul(pow2, two);
        }

        AddBitSumTerms(wo, nRemainderBitStart, BPAC_KERNEL_REMAINDER_BITS,
                       FieldNeg(FieldFromUint64(1)));
        circuit.AddLinearConstraint(wl, wr, wo, wv, FieldFromUint64(0));
    }

    {
        std::vector<CSparseEntry> wl, wr, wo, wv;
        AddBitSumTerms(wo, nProductBitStart, BPAC_KERNEL_PRODUCT_BITS,
                       FieldFromUint64(1));

        uint256 mantissa = FieldFromUint64(nTargetMantissa);
        uint256 pow2 = FieldFromUint64(1);
        uint256 two = FieldFromUint64(2);
        for (int i = 0; i < BPAC_KERNEL_COINDAY_BITS; i++)
        {
            wo.push_back(CSparseEntry(nCoinDayBitStart + i,
                                      FieldNeg(FieldMul(mantissa, pow2))));
            pow2 = FieldMul(pow2, two);
        }

        circuit.AddLinearConstraint(wl, wr, wo, wv, FieldFromUint64(0));
    }

    const unsigned char* hashLE = hashKernel.begin();
    for (int i = 0; i < BPAC_KERNEL_COMPARE_BITS; i++)
    {
        std::vector<CSparseEntry> wl, wr, wo, wv;
        int nProductBit = i - nTargetShiftBits;
        if (nProductBit >= 0 && nProductBit < BPAC_KERNEL_PRODUCT_BITS)
            wo.push_back(CSparseEntry(nProductBitStart + nProductBit, FieldFromUint64(1)));
        wo.push_back(CSparseEntry(nDifferenceBitStart + i, FieldNeg(FieldFromUint64(1))));
        if (i > 0)
            wo.push_back(CSparseEntry(nBorrowBitStart + i - 1, FieldNeg(FieldFromUint64(1))));
        wo.push_back(CSparseEntry(nBorrowBitStart + i, FieldFromUint64(2)));

        uint256 hashBit = FieldFromUint64(0);
        if (i < 256)
            hashBit = FieldFromUint64((hashLE[i / 8] >> (i % 8)) & 1);
        circuit.AddLinearConstraint(wl, wr, wo, wv, FieldNeg(hashBit));
    }

    AddWireValueConstraint(circuit, nBorrowBitStart + BPAC_KERNEL_COMPARE_BITS - 1,
                           'O', FieldFromUint64(0));
}

static uint256 LowBitsToScalar(const uint256& value, int nBits)
{
    uint256 acc = FieldFromUint64(0);
    uint256 pow2 = FieldFromUint64(1);
    uint256 two = FieldFromUint64(2);
    const unsigned char* le = value.begin();
    for (int i = 0; i < nBits; i++)
    {
        if ((le[i / 8] >> (i % 8)) & 1)
            acc = FieldAdd(acc, pow2);
        pow2 = FieldMul(pow2, two);
    }
    return acc;
}

static uint256 NullStakeV3StakeAuthHash(const std::vector<unsigned char>& vchPkStake)
{
    uint256 authHash = Hash(vchPkStake.begin(), vchPkStake.end());
    return FieldReduce(authHash);
}

static uint256 NullStakeV3OwnerAuthHash(const std::vector<unsigned char>& vchPkOwner)
{
    uint256 authHash = Hash(vchPkOwner.begin(), vchPkOwner.end());
    return FieldReduce(authHash);
}

static uint256 NullStakeV3OwnerBindHash(int64_t nValue,
                                        const std::vector<unsigned char>& vchPkOwner)
{
    return FieldAdd(NullStakeV3OwnerAuthHash(vchPkOwner),
                    FieldFromUint64((uint64_t)nValue));
}

static uint256 NullStakeV3DelegationChain(const uint256& authHash,
                                          const uint256& ownerBind)
{
    uint256 authScalar = LowBitsToScalar(authHash, BPAC_V3_DELEGATION_BITS);
    uint256 ownerScalar = LowBitsToScalar(ownerBind, BPAC_V3_DELEGATION_BITS);
    uint256 dState = FieldAdd(authScalar, ownerScalar);
    for (int s = 0; s < 4; s++)
    {
        uint256 x2 = FieldMul(dState, dState);
        uint256 x4 = FieldMul(x2, x2);
        uint256 x5 = FieldMul(x4, dState);
        dState = FieldAdd(x5, authScalar);
    }
    return dState;
}

bool ComputeNullStakeV3DelegationHash(int64_t nValue,
                                      const std::vector<unsigned char>& vchPkStake,
                                      const std::vector<unsigned char>& vchPkOwner,
                                      uint256& delegationHashOut)
{
    if (nValue <= 0 || vchPkStake.size() != 33 || vchPkOwner.size() != 33)
        return false;

    uint256 authHash = NullStakeV3StakeAuthHash(vchPkStake);
    uint256 ownerBind = NullStakeV3OwnerBindHash(nValue, vchPkOwner);
    delegationHashOut = NullStakeV3DelegationChain(authHash, ownerBind);
    return delegationHashOut != uint256(0);
}

bool ComputeNullStakeV3DelegationSetHash(std::vector<std::vector<unsigned char> > vStakerPubKeys,
                                         unsigned int nThresholdM,
                                         const std::vector<unsigned char>& vchPkOwner,
                                         uint256& delegationHashOut)
{
    size_t nMembers = vStakerPubKeys.size();
    if (nMembers == 0 || nThresholdM < 1 || nThresholdM > nMembers ||
        vchPkOwner.size() != 33)
        return false;
    for (size_t i = 0; i < nMembers; i++)
        if (vStakerPubKeys[i].size() != 33)
            return false;

    // Canonical order so the set commitment is independent of member ordering;
    // reject duplicate members (a set, not a multiset).
    std::sort(vStakerPubKeys.begin(), vStakerPubKeys.end());
    for (size_t i = 1; i < nMembers; i++)
        if (vStakerPubKeys[i] == vStakerPubKeys[i - 1])
            return false;

    // Fold the per-member auth hashes into a set hash, chaining x^5 for collision
    // resistance, seeded by the threshold M and member count N so both are bound.
    uint256 setHash = FieldFromUint64(((uint64_t)nThresholdM << 20) | (uint64_t)nMembers);
    for (size_t i = 0; i < nMembers; i++)
    {
        uint256 keyAuth = LowBitsToScalar(NullStakeV3StakeAuthHash(vStakerPubKeys[i]),
                                          BPAC_V3_DELEGATION_BITS);
        uint256 x = FieldAdd(setHash, keyAuth);
        uint256 x2 = FieldMul(x, x);
        uint256 x4 = FieldMul(x2, x2);
        uint256 x5 = FieldMul(x4, x);
        setHash = FieldAdd(x5, keyAuth);
    }

    // Value-decoupled (B2-e per-set authority): the delegation commits to the set,
    // threshold, and owner only. The staked value is bound separately by the note
    // commitment / kernel proof and by the half-agg signature over the stake digest.
    uint256 ownerBind = NullStakeV3OwnerAuthHash(vchPkOwner);
    delegationHashOut = NullStakeV3DelegationChain(setHash, ownerBind);
    return delegationHashOut != uint256(0);
}

// B2-e: verify that M-of-N members of the set committed in delegationHash authorized the
// stake digest. This is the AUTHORIZATION component only: it proves (set <-> delegationHash)
// consistency, distinct M-of-N membership, and a valid half-aggregated signature over the
// stake digest. It does NOT by itself bind delegationHash to the staked note -- that binding
// (the note's spend-authority == this set) is enforced by the shielded spend path; callers
// MUST take delegationHash from the committed note, not from attacker-supplied data.
bool VerifyNullStakeMofNAuthorization(const std::vector<std::vector<unsigned char> >& vStakerSet,
                                      unsigned int nThresholdM,
                                      const std::vector<unsigned char>& vchPkOwner,
                                      const uint256& delegationHash,
                                      const std::vector<std::vector<unsigned char> >& vSignerPubKeys,
                                      const std::vector<std::vector<unsigned char> >& vSignerRPoints,
                                      const std::vector<unsigned char>& vchAggregatedSScalar,
                                      const uint256& stakeDigest,
                                      std::string& strError)
{
    strError.clear();

    // 1. The provided staker set must hash to the committed delegationHash. Combined with
    //    the note->delegationHash binding enforced by the spend path, this pins the exact
    //    set: substituting attacker keys would change the recompute and be rejected here.
    uint256 recomputed;
    if (!ComputeNullStakeV3DelegationSetHash(vStakerSet, nThresholdM, vchPkOwner, recomputed))
    {
        strError = "delegation set hash recompute failed (bad set/threshold/owner)";
        return false;
    }
    if (recomputed != delegationHash)
    {
        strError = "staker set does not match the committed delegation hash";
        return false;
    }

    // 2. At least M signers, paired 1:1 with R-points.
    size_t nSigners = vSignerPubKeys.size();
    if (nSigners < (size_t)nThresholdM)
    {
        strError = "fewer signers than the threshold M";
        return false;
    }
    if (vSignerRPoints.size() != nSigners)
    {
        strError = "R-point count does not match signer count";
        return false;
    }

    // 3. Every signer must be a DISTINCT member of the committed set: rejects non-member
    //    key-stapling and counting one member more than once toward the threshold.
    for (size_t i = 0; i < nSigners; i++)
    {
        if (vSignerPubKeys[i].size() != 33)
        {
            strError = "signer pubkey must be 33 bytes";
            return false;
        }
        bool fMember = false;
        for (size_t j = 0; j < vStakerSet.size(); j++)
            if (vSignerPubKeys[i] == vStakerSet[j]) { fMember = true; break; }
        if (!fMember)
        {
            strError = "signer is not a member of the delegated set";
            return false;
        }
        for (size_t k = 0; k < i; k++)
            if (vSignerPubKeys[i] == vSignerPubKeys[k])
            {
                strError = "duplicate signer";
                return false;
            }
    }

    // 4. The half-aggregated signature must verify over the stake digest: M distinct members
    //    actually signed THIS stake (the digest binds the kernel params + value commitment).
    if (!VerifyHalfAggStakeSignature(vSignerPubKeys, vSignerRPoints,
                                     vchAggregatedSScalar, stakeDigest, strError))
        return false;

    return true;
}

uint256 ComputeNullStakeMofNStakeDigest(const uint256& delegationHash,
                                        uint64_t nStakeModifier,
                                        unsigned int nBlockTimeFrom,
                                        unsigned int nTxPrevOffset,
                                        unsigned int nTxTimePrev,
                                        unsigned int nVoutN,
                                        unsigned int nTimeTx,
                                        const std::vector<unsigned char>& vchValueCommitment)
{
    // Deterministic (CHashWriter serializes little-endian) so the digest is identical on
    // every node. Binds the delegation, the full stake kernel parameters, and the value
    // commitment, so an M-of-N signature over it authorizes exactly one stake -- it cannot
    // be replayed for a different stake or a different note.
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("Innova_NullStakeMofN_StakeDigest_v1");
    ss << delegationHash;
    ss << nStakeModifier;
    ss << nBlockTimeFrom;
    ss << nTxPrevOffset;
    ss << nTxTimePrev;
    ss << nVoutN;
    ss << nTimeTx;
    ss << vchValueCommitment;
    return ss.GetHash();
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

static std::vector<CSparseEntry>* SelectWire(std::vector<CSparseEntry>& wl,
                                             std::vector<CSparseEntry>& wr,
                                             std::vector<CSparseEntry>& wo,
                                             char wire)
{
    if (wire == 'L') return &wl;
    if (wire == 'R') return &wr;
    if (wire == 'O') return &wo;
    return NULL;
}

static void AddWireEqualityConstraint(CR1CSCircuit& circuit,
                                      int lhsGate,
                                      char lhsWire,
                                      int rhsGate,
                                      char rhsWire)
{
    std::vector<CSparseEntry> wl, wr, wo, wv;
    std::vector<CSparseEntry>* pLhs = SelectWire(wl, wr, wo, lhsWire);
    std::vector<CSparseEntry>* pRhs = SelectWire(wl, wr, wo, rhsWire);
    if (!pLhs || !pRhs)
        return;

    pLhs->push_back(CSparseEntry(lhsGate, FieldFromUint64(1)));
    pRhs->push_back(CSparseEntry(rhsGate, FieldNeg(FieldFromUint64(1))));
    circuit.AddLinearConstraint(wl, wr, wo, wv, FieldFromUint64(0));
}

static void AddGateEqualityConstraint(CR1CSCircuit& circuit,
                                      int nGate,
                                      char lhsWire,
                                      char rhsWire)
{
    AddWireEqualityConstraint(circuit, nGate, lhsWire, nGate, rhsWire);
}

static void AddWireValueConstraint(CR1CSCircuit& circuit,
                                   int nGate,
                                   char wire,
                                   const uint256& value)
{
    std::vector<CSparseEntry> wl, wr, wo, wv;
    std::vector<CSparseEntry>* pWire = SelectWire(wl, wr, wo, wire);
    if (!pWire)
        return;

    pWire->push_back(CSparseEntry(nGate, FieldFromUint64(1)));
    circuit.AddLinearConstraint(wl, wr, wo, wv, FieldNeg(value));
}

static void AddBooleanGateConstraints(CR1CSCircuit& circuit, int nGate)
{
    // Together with the multiplication gate aL*aR=aO, these equalities force
    // the gate value to be 0 or 1 and bind the bit used by linear sums to it.
    AddGateEqualityConstraint(circuit, nGate, 'L', 'O');
    AddGateEqualityConstraint(circuit, nGate, 'R', 'O');
}

static void AddBooleanRangeConstraints(CR1CSCircuit& circuit, int nStart, int nCount)
{
    for (int i = 0; i < nCount; i++)
        AddBooleanGateConstraints(circuit, nStart + i);
}

static void AddBitSumTerms(std::vector<CSparseEntry>& entries,
                           int nStart,
                           int nCount,
                           const uint256& nSign)
{
    uint256 pow2 = FieldFromUint64(1);
    uint256 two = FieldFromUint64(2);
    for (int i = 0; i < nCount; i++)
    {
        entries.push_back(CSparseEntry(nStart + i, FieldMul(nSign, pow2)));
        pow2 = FieldMul(pow2, two);
    }
}

static void AddPow5SboxConstraints(CR1CSCircuit& circuit, int nGateStart)
{
    // Three multiplication gates encode x^2, x^4, x^5. These linear links
    // prevent the prover from using independent witnesses for each gate.
    AddGateEqualityConstraint(circuit, nGateStart, 'L', 'R');
    AddWireEqualityConstraint(circuit, nGateStart, 'O', nGateStart + 1, 'L');
    AddWireEqualityConstraint(circuit, nGateStart, 'O', nGateStart + 1, 'R');
    AddGateEqualityConstraint(circuit, nGateStart + 1, 'L', 'R');
    AddWireEqualityConstraint(circuit, nGateStart + 1, 'O', nGateStart + 2, 'L');
    AddWireEqualityConstraint(circuit, nGateStart, 'L', nGateStart + 2, 'R');
}

static void AddNegBitScalarTerms(std::vector<CSparseEntry>& wo, int nStart, int nBits)
{
    uint256 pow2 = FieldFromUint64(1);
    uint256 two = FieldFromUint64(2);
    for (int i = 0; i < nBits; i++)
    {
        wo.push_back(CSparseEntry(nStart + i, FieldNeg(pow2)));
        pow2 = FieldMul(pow2, two);
    }
}

static void AddDelegationSeedConstraint(CR1CSCircuit& circuit,
                                        int nDelegGate,
                                        int nStakeAuthStart,
                                        int nOwnerBindStart,
                                        int nBits)
{
    std::vector<CSparseEntry> wl, wr, wo, wv;
    wl.push_back(CSparseEntry(nDelegGate, FieldFromUint64(1)));
    AddNegBitScalarTerms(wo, nStakeAuthStart, nBits);
    AddNegBitScalarTerms(wo, nOwnerBindStart, nBits);
    circuit.AddLinearConstraint(wl, wr, wo, wv, FieldFromUint64(0));
}

static void AddDelegationRoundLinkConstraint(CR1CSCircuit& circuit,
                                             int nNextDelegGate,
                                             int nPrevDelegGate,
                                             int nStakeAuthStart,
                                             int nBits)
{
    std::vector<CSparseEntry> wl, wr, wo, wv;
    wl.push_back(CSparseEntry(nNextDelegGate, FieldFromUint64(1)));
    wo.push_back(CSparseEntry(nPrevDelegGate + 2, FieldNeg(FieldFromUint64(1))));
    AddNegBitScalarTerms(wo, nStakeAuthStart, nBits);
    circuit.AddLinearConstraint(wl, wr, wo, wv, FieldFromUint64(0));
}

static void AddPublicBitValueConstraints(CR1CSCircuit& circuit,
                                         int nStart,
                                         int nBits,
                                         const uint256& value)
{
    const unsigned char* le = value.begin();
    for (int i = 0; i < nBits; i++)
    {
        uint256 bit = FieldFromUint64((le[i / 8] >> (i % 8)) & 1);
        AddWireValueConstraint(circuit, nStart + i, 'O', bit);
    }
}

static void AddWireCommittedVarEqualityConstraint(CR1CSCircuit& circuit,
                                                  int nGate,
                                                  char wire,
                                                  int nVar)
{
    std::vector<CSparseEntry> wl, wr, wo, wv;
    std::vector<CSparseEntry>* pWire = SelectWire(wl, wr, wo, wire);
    if (!pWire)
        return;

    pWire->push_back(CSparseEntry(nGate, FieldFromUint64(1)));
    wv.push_back(CSparseEntry(nVar, FieldNeg(FieldFromUint64(1))));
    circuit.AddLinearConstraint(wl, wr, wo, wv, FieldFromUint64(0));
}

static void AddOwnerBindValueConstraint(CR1CSCircuit& circuit,
                                        int nOwnerBindStart,
                                        int nBits,
                                        const std::vector<unsigned char>& vchPkOwner)
{
    std::vector<CSparseEntry> wl, wr, wo, wv;
    AddBitSumTerms(wo, nOwnerBindStart, nBits, FieldFromUint64(1));
    wv.push_back(CSparseEntry(0, FieldNeg(FieldFromUint64(1))));
    circuit.AddLinearConstraint(wl, wr, wo, wv,
                                FieldNeg(NullStakeV3OwnerAuthHash(vchPkOwner)));
}

static void AddDelegationFinalConstraint(CR1CSCircuit& circuit,
                                         int nPublicDelegGate,
                                         int nFinalDelegGate,
                                         int nStakeAuthStart,
                                         int nBits)
{
    std::vector<CSparseEntry> wl, wr, wo, wv;
    wo.push_back(CSparseEntry(nPublicDelegGate, FieldFromUint64(1)));
    wo.push_back(CSparseEntry(nFinalDelegGate + 2, FieldNeg(FieldFromUint64(1))));
    AddNegBitScalarTerms(wo, nStakeAuthStart, nBits);
    circuit.AddLinearConstraint(wl, wr, wo, wv, FieldFromUint64(0));
}


CR1CSCircuit BuildNullStakeV2Circuit(uint64_t nStakeModifier,
                                      unsigned int nBlockTimeFrom,
                                      unsigned int nTxPrevOffset,
                                      unsigned int nTxTimePrev,
                                      unsigned int nVoutN,
                                      unsigned int nTimeTx,
                                      unsigned int nBits)
{
    CR1CSCircuit circuit;
    circuit.nHighLevelVars = 1;  // v (stake value)

    int nPoseidonGates = 339;
    for (int i = 0; i < nPoseidonGates; i++)
        circuit.AddMultGate();

    int nWeightValueGate = circuit.AddMultGate();  // gate 339

    int nCoinDayBitStart = circuit.nMultConstraints;
    for (int i = 0; i < BPAC_KERNEL_COINDAY_BITS; i++)
        circuit.AddMultGate();

    int nRemainderBitStart = circuit.nMultConstraints;
    for (int i = 0; i < BPAC_KERNEL_REMAINDER_BITS; i++)
        circuit.AddMultGate();

    int nProductBitStart = circuit.nMultConstraints;
    for (int i = 0; i < BPAC_KERNEL_PRODUCT_BITS; i++)
        circuit.AddMultGate();

    int nDifferenceBitStart = circuit.nMultConstraints;
    for (int i = 0; i < BPAC_KERNEL_COMPARE_BITS; i++)
        circuit.AddMultGate();

    int nBorrowBitStart = circuit.nMultConstraints;
    for (int i = 0; i < BPAC_KERNEL_COMPARE_BITS; i++)
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

    uint256 hashKernel = Poseidon2KernelHash(nStakeModifier, nBlockTimeFrom,
                                              nTxPrevOffset, nTxTimePrev,
                                              nVoutN, nTimeTx);
    AddKernelIntegerTargetConstraints(circuit, nWeightValueGate,
                                      nCoinDayBitStart,
                                      nRemainderBitStart,
                                      nProductBitStart,
                                      nDifferenceBitStart,
                                      nBorrowBitStart,
                                      hashKernel, nBits);

    int64_t nWeight = (int64_t)nTimeTx - (int64_t)nBlockTimeFrom - (int64_t)nStakeMinAge;
    if (nWeight < 0)
        nWeight = 0;
    AddWireValueConstraint(circuit, nWeightValueGate, 'L',
                           FieldFromUint64((uint64_t)nWeight));
    AddWireCommittedVarEqualityConstraint(circuit, nWeightValueGate, 'R', 0);

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
        uint256 negOne = FieldSub(FieldFromUint64(0), FieldFromUint64(1));
        wl.push_back(CSparseEntry(nWeightValueGate, negOne));
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

    AddBooleanRangeConstraints(circuit, nCoinDayBitStart, BPAC_KERNEL_COINDAY_BITS);
    AddBooleanRangeConstraints(circuit, nRemainderBitStart, BPAC_KERNEL_REMAINDER_BITS);
    AddBooleanRangeConstraints(circuit, nProductBitStart, BPAC_KERNEL_PRODUCT_BITS);
    AddBooleanRangeConstraints(circuit, nDifferenceBitStart, BPAC_KERNEL_COMPARE_BITS);
    AddBooleanRangeConstraints(circuit, nBorrowBitStart, BPAC_KERNEL_COMPARE_BITS);
    AddBooleanRangeConstraints(circuit, nWeightBitStart, 32);
    AddBooleanRangeConstraints(circuit, nValueBitStart, 64);

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
    if (nWeight <= 0)
        return false;

    uint256 weightScalar = FieldFromUint64((uint64_t)nWeight);
    uint256 valueScalar = FieldFromUint64((uint64_t)nValue);
    uint256 weightedValue = FieldMul(weightScalar, valueScalar);

    witnessOut.aL[gateIdx] = weightScalar;
    witnessOut.aR[gateIdx] = valueScalar;
    witnessOut.aO[gateIdx] = weightedValue;
    gateIdx++;

    uint64_t nTargetMantissa = 0;
    int nTargetShiftBits = 0;
    if (!CompactTargetMantissaAndShift(nBits, nTargetMantissa, nTargetShiftBits))
    {
        if (fDebug) printf("AssignNullStakeV2Witness: invalid compact target\n");
        return false;
    }

    CBigNum bnWeightedValue = CBigNum((uint64_t)nValue) * CBigNum((uint64_t)nWeight);
    CBigNum bnDenominator(BPAC_KERNEL_DENOMINATOR);
    CBigNum bnCoinDayWeight = bnWeightedValue / bnDenominator;
    CBigNum bnRemainder = bnWeightedValue % bnDenominator;
    CBigNum bnTargetProduct = bnCoinDayWeight * CBigNum(nTargetMantissa);
    CBigNum bnThreshold = bnTargetProduct << nTargetShiftBits;
    CBigNum bnHash(kernelHash);
    if (bnHash > bnThreshold)
    {
        if (fDebug)
            printf("AssignNullStakeV2Witness: kernel target failed hash=%s threshold=%s coinDay=%s\n",
                   bnHash.ToString().c_str(), bnThreshold.ToString().c_str(),
                   bnCoinDayWeight.ToString().c_str());
        return false;
    }
    CBigNum bnDifference = bnThreshold - bnHash;

    SetBitVectorBigNum(bnCoinDayWeight, BPAC_KERNEL_COINDAY_BITS, witnessOut.aL, gateIdx);
    SetBitVectorBigNum(bnCoinDayWeight, BPAC_KERNEL_COINDAY_BITS, witnessOut.aR, gateIdx);
    SetBitVectorBigNum(bnCoinDayWeight, BPAC_KERNEL_COINDAY_BITS, witnessOut.aO, gateIdx);
    gateIdx += BPAC_KERNEL_COINDAY_BITS;

    SetBitVectorBigNum(bnRemainder, BPAC_KERNEL_REMAINDER_BITS, witnessOut.aL, gateIdx);
    SetBitVectorBigNum(bnRemainder, BPAC_KERNEL_REMAINDER_BITS, witnessOut.aR, gateIdx);
    SetBitVectorBigNum(bnRemainder, BPAC_KERNEL_REMAINDER_BITS, witnessOut.aO, gateIdx);
    gateIdx += BPAC_KERNEL_REMAINDER_BITS;

    SetBitVectorBigNum(bnTargetProduct, BPAC_KERNEL_PRODUCT_BITS, witnessOut.aL, gateIdx);
    SetBitVectorBigNum(bnTargetProduct, BPAC_KERNEL_PRODUCT_BITS, witnessOut.aR, gateIdx);
    SetBitVectorBigNum(bnTargetProduct, BPAC_KERNEL_PRODUCT_BITS, witnessOut.aO, gateIdx);
    gateIdx += BPAC_KERNEL_PRODUCT_BITS;

    SetBitVectorBigNum(bnDifference, BPAC_KERNEL_COMPARE_BITS, witnessOut.aL, gateIdx);
    SetBitVectorBigNum(bnDifference, BPAC_KERNEL_COMPARE_BITS, witnessOut.aR, gateIdx);
    SetBitVectorBigNum(bnDifference, BPAC_KERNEL_COMPARE_BITS, witnessOut.aO, gateIdx);
    gateIdx += BPAC_KERNEL_COMPARE_BITS;

    SetKernelCompareBorrowBits(bnThreshold, kernelHash, witnessOut.aL, gateIdx);
    SetKernelCompareBorrowBits(bnThreshold, kernelHash, witnessOut.aR, gateIdx);
    SetKernelCompareBorrowBits(bnThreshold, kernelHash, witnessOut.aO, gateIdx);
    gateIdx += BPAC_KERNEL_COMPARE_BITS;

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
    ScalarBytesToU256Raw(vchValueBlind.data(), blind);
    witnessOut.vBlinds[0] = blind;

    return true;
}


static bool CreateBulletproofACProofInternal(const CR1CSCircuit& circuit,
                                             const CR1CSWitness& witness,
                                             const std::vector<std::vector<unsigned char>>& vCommitments,
                                             CBulletproofACProof& proofOut,
                                             bool fCheckWitness)
{
    proofOut.nVersion = BPAC_PROOF_VERSION;

    int n = circuit.nPaddedSize;
    if (fCheckWitness)
    {
        if (!CheckR1CSWitness(circuit, witness, vCommitments))
            return false;
    }
    else if (!CheckWitnessShape(circuit, witness, vCommitments))
    {
        return false;
    }

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
    transcript.AppendScalar(CircuitFingerprint(circuit));
    for (size_t i = 0; i < vCommitments.size(); i++)
        transcript.AppendPoint(vCommitments[i]);
    transcript.AppendPoint(proofOut.vchAI);
    transcript.AppendPoint(proofOut.vchAO);
    transcript.AppendPoint(proofOut.vchS);

    uint256 y = transcript.GetChallenge();
    uint256 z = transcript.GetChallenge();
    uint256 zero = FieldFromUint64(0);
    if (y == zero || z == zero)
        return false;

    std::vector<uint256> yPowers, yInvPowers;
    uint256 yInv = FieldInv(y);
    if (!ComputePowers(y, n, yPowers) ||
        !ComputePowers(yInv, n, yInvPowers))
        return false;

    std::vector<uint256> wL, wR, wO, wV;
    uint256 wC;
    if (!FlattenCircuitWeights(circuit, z, wL, wR, wO, wV, wC))
        return false;

    CIPAGenerators proofGens;
    if (!DeriveR1CSIPAGenerators(bpacGens, yInvPowers, proofGens))
        return false;

    unsigned char tau1[32], tau3[32], tau4[32], tau5[32], tau6[32];
    if (RAND_bytes(tau1, 32) != 1) return false;
    if (RAND_bytes(tau3, 32) != 1) return false;
    if (RAND_bytes(tau4, 32) != 1) return false;
    if (RAND_bytes(tau5, 32) != 1) return false;
    if (RAND_bytes(tau6, 32) != 1) return false;

    std::vector<uint256> l1(n), l2(n), l3(n), r0(n), r1(n), r3(n);
    for (int i = 0; i < n; i++)
    {
        l1[i] = FieldAdd(witness.aL[i], FieldMul(yInvPowers[i], wR[i]));
        l2[i] = witness.aO[i];
        l3[i] = sL[i];
        r0[i] = FieldSub(wO[i], yPowers[i]);
        r1[i] = FieldAdd(FieldMul(yPowers[i], witness.aR[i]), wL[i]);
        r3[i] = FieldMul(yPowers[i], sR[i]);
    }

    uint256 t1Val = InnerProduct(l1, r0);
    uint256 t3Val = FieldAdd(InnerProduct(l3, r0), InnerProduct(l2, r1));
    uint256 t4Val = FieldAdd(InnerProduct(l1, r3), InnerProduct(l3, r1));
    uint256 t5Val = InnerProduct(l2, r3);
    uint256 t6Val = InnerProduct(l3, r3);

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
    if (x == zero)
        return false;

    std::vector<uint256> lVec(n), rVec(n);
    uint256 x2 = FieldMul(x, x);
    uint256 x3 = FieldMul(x2, x);
    for (int i = 0; i < n; i++)
    {
        lVec[i] = FieldMul(l1[i], x);
        lVec[i] = FieldAdd(lVec[i], FieldMul(l2[i], x2));
        lVec[i] = FieldAdd(lVec[i], FieldMul(l3[i], x3));

        rVec[i] = r0[i];
        rVec[i] = FieldAdd(rVec[i], FieldMul(r1[i], x));
        rVec[i] = FieldAdd(rVec[i], FieldMul(r3[i], x3));
    }

    proofOut.tHat = InnerProduct(lVec, rVec);

    {
        uint256 x4 = FieldMul(x3, x);
        uint256 x5 = FieldMul(x4, x);
        uint256 x6 = FieldMul(x5, x);

        uint256 tau1U, tau3U, tau4U, tau5U, tau6U;
        if (!ScalarBytesToU256(tau1, bnOrder, ctx, tau1U) ||
            !ScalarBytesToU256(tau3, bnOrder, ctx, tau3U) ||
            !ScalarBytesToU256(tau4, bnOrder, ctx, tau4U) ||
            !ScalarBytesToU256(tau5, bnOrder, ctx, tau5U) ||
            !ScalarBytesToU256(tau6, bnOrder, ctx, tau6U))
            return false;

        uint256 t2Blind = FieldFromUint64(0);
        for (int j = 0; j < circuit.nHighLevelVars; j++)
            t2Blind = FieldSub(t2Blind, FieldMul(wV[j], witness.vBlinds[j]));

        proofOut.tauX = FieldMul(tau1U, x);
        proofOut.tauX = FieldAdd(proofOut.tauX, FieldMul(t2Blind, x2));
        proofOut.tauX = FieldAdd(proofOut.tauX, FieldMul(tau3U, x3));
        proofOut.tauX = FieldAdd(proofOut.tauX, FieldMul(tau4U, x4));
        proofOut.tauX = FieldAdd(proofOut.tauX, FieldMul(tau5U, x5));
        proofOut.tauX = FieldAdd(proofOut.tauX, FieldMul(tau6U, x6));
    }

    {
        uint256 alphaU, betaU, rhoU;
        if (!ScalarBytesToU256(alphaBytes, bnOrder, ctx, alphaU) ||
            !ScalarBytesToU256(betaBytes, bnOrder, ctx, betaU) ||
            !ScalarBytesToU256(rhoBytes, bnOrder, ctx, rhoU))
            return false;

        proofOut.mu = FieldMul(alphaU, x);
        proofOut.mu = FieldAdd(proofOut.mu, FieldMul(betaU, x2));
        proofOut.mu = FieldAdd(proofOut.mu, FieldMul(rhoU, x3));
    }

    std::vector<std::vector<unsigned char>> aVec(n), bVec(n);
    for (int i = 0; i < n; i++)
    {
        U256ToScalarBytes(lVec[i], aVec[i]);
        U256ToScalarBytes(rVec[i], bVec[i]);
    }

    std::vector<unsigned char> zIPA(32);
    U256ToScalarBytes(proofOut.tHat, zIPA);

    std::vector<unsigned char> vchP;
    if (!ComputeBPACIPAStatementPoint(group, ctx, proofGens, yPowers,
                                      yInvPowers, wL, wR, wO, x,
                                      proofOut, vchP))
        return false;

    CIPATranscript ipaTranscript(BPAC_DOMAIN);
    AppendBPACIPAStatement(ipaTranscript, circuit, vCommitments, proofOut, vchP);

    if (!CreateIPAProof(aVec, bVec, zIPA, proofGens, ipaTranscript, proofOut.ipaProof))
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

bool CreateBulletproofACProof(const CR1CSCircuit& circuit,
                                const CR1CSWitness& witness,
                                const std::vector<std::vector<unsigned char>>& vCommitments,
                                CBulletproofACProof& proofOut)
{
    return CreateBulletproofACProofInternal(circuit, witness, vCommitments, proofOut, true);
}

bool CreateBulletproofACProofUncheckedForTests(const CR1CSCircuit& circuit,
                                               const CR1CSWitness& witness,
                                               const std::vector<std::vector<unsigned char>>& vCommitments,
                                               CBulletproofACProof& proofOut)
{
    return CreateBulletproofACProofInternal(circuit, witness, vCommitments, proofOut, false);
}


bool VerifyBulletproofACProof(const CR1CSCircuit& circuit,
                                const std::vector<std::vector<unsigned char>>& vCommitments,
                                const CBulletproofACProof& proof)
{
    if (proof.IsNull() || proof.GetProofSize() > BPAC_MAX_PROOF_SIZE)
        return false;
    if (proof.nVersion != BPAC_PROOF_VERSION)
        return false;

    if (!CheckCircuitShape(circuit))
        return false;
    if ((int)vCommitments.size() != circuit.nHighLevelVars)
        return false;

    int n = circuit.nPaddedSize;

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
    if (!DeserializeNonInfinityPoint(group, proof.vchAI, AI, ctx)) return false;
    if (!DeserializeNonInfinityPoint(group, proof.vchAO, AO, ctx)) return false;
    if (!DeserializeNonInfinityPoint(group, proof.vchS, S, ctx)) return false;

    CBPACPointGuard T1(group), T3(group), T4(group), T5(group), T6(group);
    if (!DeserializeNonInfinityPoint(group, proof.vchT1, T1, ctx)) return false;
    if (!DeserializeNonInfinityPoint(group, proof.vchT3, T3, ctx)) return false;
    if (!DeserializeNonInfinityPoint(group, proof.vchT4, T4, ctx)) return false;
    if (!DeserializeNonInfinityPoint(group, proof.vchT5, T5, ctx)) return false;
    if (!DeserializeNonInfinityPoint(group, proof.vchT6, T6, ctx)) return false;

    for (const std::vector<unsigned char>& vchCommitment : vCommitments)
    {
        CBPACPointGuard commitment(group);
        if (!DeserializeNonInfinityPoint(group, vchCommitment, commitment, ctx))
            return false;
    }

    CBPACTranscript transcript;
    transcript.AppendScalar(CircuitFingerprint(circuit));
    for (size_t i = 0; i < vCommitments.size(); i++)
        transcript.AppendPoint(vCommitments[i]);
    transcript.AppendPoint(proof.vchAI);
    transcript.AppendPoint(proof.vchAO);
    transcript.AppendPoint(proof.vchS);

    uint256 y = transcript.GetChallenge();
    uint256 z = transcript.GetChallenge();
    uint256 zero = FieldFromUint64(0);
    if (y == zero || z == zero)
        return false;

    std::vector<uint256> yPowers, yInvPowers;
    uint256 yInv = FieldInv(y);
    if (!ComputePowers(y, n, yPowers) ||
        !ComputePowers(yInv, n, yInvPowers))
        return false;

    std::vector<uint256> wL, wR, wO, wV;
    uint256 wC;
    if (!FlattenCircuitWeights(circuit, z, wL, wR, wO, wV, wC))
        return false;

    CIPAGenerators proofGens;
    if (!DeriveR1CSIPAGenerators(bpacGens, yInvPowers, proofGens))
        return false;

    transcript.AppendPoint(proof.vchT1);
    transcript.AppendPoint(proof.vchT3);
    transcript.AppendPoint(proof.vchT4);
    transcript.AppendPoint(proof.vchT5);
    transcript.AppendPoint(proof.vchT6);

    uint256 x = transcript.GetChallenge();

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

        CBPACPointGuard T2(group);
        EC_POINT_set_to_infinity(group, T2);
        {
            uint256 delta = FieldFromUint64(0);
            for (int i = 0; i < n; i++)
                delta = FieldAdd(delta, FieldMul(FieldMul(yInvPowers[i], wR[i]), wL[i]));

            uint256 t2Constant = FieldSub(delta, wC);
            CBPACBNGuard bnT2Value, bnZero;
            U256ToBN(t2Constant, bnT2Value);
            BN_zero(bnZero);
            if (!ECCommit(group, ctx, genH, bnT2Value, bnZero, T2))
                return false;

            for (int j = 0; j < circuit.nHighLevelVars; j++)
            {
                if (!AddPointTimesScalar(group, ctx, T2, vCommitments[j], FieldNeg(wV[j])))
                    return false;
            }
        }

        addTerm(T2, x2);
        addTerm(T3, x3);
        addTerm(T4, x4);
        addTerm(T5, x5);
        addTerm(T6, x6);
    }

    if (EC_POINT_cmp(group, lhsCheck, rhsCheck, ctx) != 0)
    {
        if (fDebug)
            printf("VerifyBulletproofACProof: polynomial commitment check failed\n");
        return false;
    }

    CBPACPointGuard P(group);
    {
        CBPACBNGuard bnX, bnX2, bnX3, bnMu;
        U256ToBN(x, bnX);
        uint256 x2 = FieldMul(x, x);
        uint256 x3 = FieldMul(x2, x);
        U256ToBN(x2, bnX2);
        U256ToBN(x3, bnX3);
        U256ToBN(proof.mu, bnMu);

        EC_POINT_set_to_infinity(group, P);

        CBPACPointGuard xAI(group);
        EC_POINT_mul(group, xAI, NULL, AI, bnX, ctx);
        EC_POINT_add(group, P, P, xAI, ctx);

        CBPACPointGuard xAO(group);
        EC_POINT_mul(group, xAO, NULL, AO, bnX2, ctx);
        EC_POINT_add(group, P, P, xAO, ctx);

        CBPACPointGuard x3S(group);
        EC_POINT_mul(group, x3S, NULL, S, bnX3, ctx);
        EC_POINT_add(group, P, P, x3S, ctx);

        for (int i = 0; i < n; i++)
        {
            uint256 coeffG = FieldMul(x, FieldMul(yInvPowers[i], wR[i]));
            if (!AddPointTimesScalar(group, ctx, P, proofGens.vG[i], coeffG))
                return false;

            uint256 coeffH = FieldSub(wO[i], yPowers[i]);
            coeffH = FieldAdd(coeffH, FieldMul(x, wL[i]));
            if (!AddPointTimesScalar(group, ctx, P, proofGens.vH[i], coeffH))
                return false;
        }

        CBPACPointGuard muG(group);
        EC_POINT_mul(group, muG, bnMu, NULL, NULL, ctx);
        EC_POINT_invert(group, muG, ctx);
        EC_POINT_add(group, P, P, muG, ctx);

        std::vector<unsigned char> tHatScalar;
        U256ToScalarBytes(proof.tHat, tHatScalar);
        std::vector<unsigned char> tHatU;
        if (!IPAScalarMul(tHatScalar, proofGens.vchU, tHatU, IPA_CURVE_SECP256K1))
            return false;

        CBPACPointGuard tHatUPoint(group);
        if (!DeserializeNonInfinityPoint(group, tHatU, tHatUPoint, ctx))
            return false;
        EC_POINT_add(group, P, P, tHatUPoint, ctx);
    }

    std::vector<unsigned char> vchP;
    SerializePoint(group, P, ctx, vchP);

    std::vector<unsigned char> zIPA(32);
    U256ToScalarBytes(proof.tHat, zIPA);

    CIPATranscript ipaTranscript(BPAC_DOMAIN);
    AppendBPACIPAStatement(ipaTranscript, circuit, vCommitments, proof, vchP);

    if (!VerifyIPAProof(vchP, zIPA, proofGens, ipaTranscript, proof.ipaProof))
    {
        if (fDebug)
            printf("VerifyBulletproofACProof: IPA verification failed\n");
        return false;
    }

    return true;
}


CR1CSCircuit BuildNullStakeV3Circuit(uint64_t nStakeModifier,
                                      unsigned int nBlockTimeFrom,
                                      unsigned int nTxPrevOffset,
                                      unsigned int nTxTimePrev,
                                      unsigned int nVoutN,
                                      unsigned int nTimeTx,
                                      unsigned int nBits,
                                      const uint256& delegationHash,
                                      const std::vector<unsigned char>& vchPkStake,
                                      const std::vector<unsigned char>& vchPkOwner)
{
    CR1CSCircuit circuit;
    circuit.nHighLevelVars = 1;

    int nPoseidonGates = 339;
    for (int i = 0; i < nPoseidonGates; i++)
        circuit.AddMultGate();

    int nWeightValueGate = circuit.AddMultGate();

    int nCoinDayBitStart = circuit.nMultConstraints;
    for (int i = 0; i < BPAC_KERNEL_COINDAY_BITS; i++)
        circuit.AddMultGate();

    int nRemainderBitStart = circuit.nMultConstraints;
    for (int i = 0; i < BPAC_KERNEL_REMAINDER_BITS; i++)
        circuit.AddMultGate();

    int nProductBitStart = circuit.nMultConstraints;
    for (int i = 0; i < BPAC_KERNEL_PRODUCT_BITS; i++)
        circuit.AddMultGate();

    int nDifferenceBitStart = circuit.nMultConstraints;
    for (int i = 0; i < BPAC_KERNEL_COMPARE_BITS; i++)
        circuit.AddMultGate();

    int nBorrowBitStart = circuit.nMultConstraints;
    for (int i = 0; i < BPAC_KERNEL_COMPARE_BITS; i++)
        circuit.AddMultGate();

    int nWeightBitStart = circuit.nMultConstraints;
    for (int i = 0; i < 32; i++)
        circuit.AddMultGate();

    int nValueBitStart = circuit.nMultConstraints;
    for (int i = 0; i < 64; i++)
        circuit.AddMultGate();

    int nDelegHashStart = circuit.nMultConstraints;
    int nDelegHashGates = 13;
    for (int i = 0; i < nDelegHashGates; i++)
        circuit.AddMultGate();

    int nStakeAuthStart = circuit.nMultConstraints;
    int nStakeAuthGates = BPAC_V3_DELEGATION_BITS;
    for (int i = 0; i < nStakeAuthGates; i++)
        circuit.AddMultGate();

    int nOwnerBindStart = circuit.nMultConstraints;
    int nOwnerBindGates = BPAC_V3_DELEGATION_BITS;
    for (int i = 0; i < nOwnerBindGates; i++)
        circuit.AddMultGate();

    while (circuit.nMultConstraints < BPAC_V3_MAX_CONSTRAINTS)
        circuit.AddMultGate();

    circuit.PadToNextPow2();

    uint256 hashKernel = Poseidon2KernelHash(nStakeModifier, nBlockTimeFrom,
                                              nTxPrevOffset, nTxTimePrev,
                                              nVoutN, nTimeTx);
    AddKernelIntegerTargetConstraints(circuit, nWeightValueGate,
                                      nCoinDayBitStart,
                                      nRemainderBitStart,
                                      nProductBitStart,
                                      nDifferenceBitStart,
                                      nBorrowBitStart,
                                      hashKernel, nBits);

    int64_t nWeight = (int64_t)nTimeTx - (int64_t)nBlockTimeFrom - (int64_t)nStakeMinAge;
    if (nWeight < 0)
        nWeight = 0;
    AddWireValueConstraint(circuit, nWeightValueGate, 'L',
                           FieldFromUint64((uint64_t)nWeight));
    AddWireCommittedVarEqualityConstraint(circuit, nWeightValueGate, 'R', 0);

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
        uint256 negOne = FieldSub(FieldFromUint64(0), FieldFromUint64(1));
        wl.push_back(CSparseEntry(nWeightValueGate, negOne));
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

    AddBooleanRangeConstraints(circuit, nCoinDayBitStart, BPAC_KERNEL_COINDAY_BITS);
    AddBooleanRangeConstraints(circuit, nRemainderBitStart, BPAC_KERNEL_REMAINDER_BITS);
    AddBooleanRangeConstraints(circuit, nProductBitStart, BPAC_KERNEL_PRODUCT_BITS);
    AddBooleanRangeConstraints(circuit, nDifferenceBitStart, BPAC_KERNEL_COMPARE_BITS);
    AddBooleanRangeConstraints(circuit, nBorrowBitStart, BPAC_KERNEL_COMPARE_BITS);
    AddBooleanRangeConstraints(circuit, nWeightBitStart, 32);
    AddBooleanRangeConstraints(circuit, nValueBitStart, 64);

    AddWireValueConstraint(circuit, nDelegHashStart, 'R', FieldFromUint64(1));
    AddGateEqualityConstraint(circuit, nDelegHashStart, 'L', 'O');
    AddWireValueConstraint(circuit, nDelegHashStart, 'O', FieldReduce(delegationHash));

    AddDelegationSeedConstraint(circuit, nDelegHashStart + 1,
                                nStakeAuthStart, nOwnerBindStart,
                                BPAC_V3_DELEGATION_BITS);
    for (int s = 0; s < 4; s++)
        AddPow5SboxConstraints(circuit, nDelegHashStart + 1 + s * 3);
    for (int s = 0; s < 3; s++)
        AddDelegationRoundLinkConstraint(circuit,
                                         nDelegHashStart + 1 + (s + 1) * 3,
                                         nDelegHashStart + 1 + s * 3,
                                         nStakeAuthStart,
                                         BPAC_V3_DELEGATION_BITS);
    AddDelegationFinalConstraint(circuit, nDelegHashStart,
                                 nDelegHashStart + 1 + 3 * 3,
                                 nStakeAuthStart,
                                 BPAC_V3_DELEGATION_BITS);

    AddBooleanRangeConstraints(circuit, nStakeAuthStart, nStakeAuthGates);
    AddBooleanRangeConstraints(circuit, nOwnerBindStart, nOwnerBindGates);
    AddPublicBitValueConstraints(circuit, nStakeAuthStart, nStakeAuthGates,
                                 NullStakeV3StakeAuthHash(vchPkStake));
    AddOwnerBindValueConstraint(circuit, nOwnerBindStart, nOwnerBindGates,
                                vchPkOwner);

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
                              const std::vector<unsigned char>& vchPkStake,
                              const std::vector<unsigned char>& vchPkOwner,
                              const uint256& delegationHash,
                              CR1CSWitness& witnessOut)
{
    if (nValue <= 0 || vchValueBlind.size() != 32 ||
        vchPkStake.size() != 33 || vchPkOwner.size() != 33)
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
    if (nWeight <= 0)
        return false;

    uint256 weightScalar = FieldFromUint64((uint64_t)nWeight);
    uint256 valueScalar = FieldFromUint64((uint64_t)nValue);
    uint256 weightedValue = FieldMul(weightScalar, valueScalar);

    witnessOut.aL[gateIdx] = weightScalar;
    witnessOut.aR[gateIdx] = valueScalar;
    witnessOut.aO[gateIdx] = weightedValue;
    gateIdx++;

    uint64_t nTargetMantissa = 0;
    int nTargetShiftBits = 0;
    if (!CompactTargetMantissaAndShift(nBits, nTargetMantissa, nTargetShiftBits))
        return false;

    CBigNum bnWeightedValue = CBigNum((uint64_t)nValue) * CBigNum((uint64_t)nWeight);
    CBigNum bnDenominator(BPAC_KERNEL_DENOMINATOR);
    CBigNum bnCoinDayWeight = bnWeightedValue / bnDenominator;
    CBigNum bnRemainder = bnWeightedValue % bnDenominator;
    CBigNum bnTargetProduct = bnCoinDayWeight * CBigNum(nTargetMantissa);
    CBigNum bnThreshold = bnTargetProduct << nTargetShiftBits;
    CBigNum bnHash(kernelHash);
    if (bnHash > bnThreshold)
        return false;
    CBigNum bnDifference = bnThreshold - bnHash;

    SetBitVectorBigNum(bnCoinDayWeight, BPAC_KERNEL_COINDAY_BITS, witnessOut.aL, gateIdx);
    SetBitVectorBigNum(bnCoinDayWeight, BPAC_KERNEL_COINDAY_BITS, witnessOut.aR, gateIdx);
    SetBitVectorBigNum(bnCoinDayWeight, BPAC_KERNEL_COINDAY_BITS, witnessOut.aO, gateIdx);
    gateIdx += BPAC_KERNEL_COINDAY_BITS;

    SetBitVectorBigNum(bnRemainder, BPAC_KERNEL_REMAINDER_BITS, witnessOut.aL, gateIdx);
    SetBitVectorBigNum(bnRemainder, BPAC_KERNEL_REMAINDER_BITS, witnessOut.aR, gateIdx);
    SetBitVectorBigNum(bnRemainder, BPAC_KERNEL_REMAINDER_BITS, witnessOut.aO, gateIdx);
    gateIdx += BPAC_KERNEL_REMAINDER_BITS;

    SetBitVectorBigNum(bnTargetProduct, BPAC_KERNEL_PRODUCT_BITS, witnessOut.aL, gateIdx);
    SetBitVectorBigNum(bnTargetProduct, BPAC_KERNEL_PRODUCT_BITS, witnessOut.aR, gateIdx);
    SetBitVectorBigNum(bnTargetProduct, BPAC_KERNEL_PRODUCT_BITS, witnessOut.aO, gateIdx);
    gateIdx += BPAC_KERNEL_PRODUCT_BITS;

    SetBitVectorBigNum(bnDifference, BPAC_KERNEL_COMPARE_BITS, witnessOut.aL, gateIdx);
    SetBitVectorBigNum(bnDifference, BPAC_KERNEL_COMPARE_BITS, witnessOut.aR, gateIdx);
    SetBitVectorBigNum(bnDifference, BPAC_KERNEL_COMPARE_BITS, witnessOut.aO, gateIdx);
    gateIdx += BPAC_KERNEL_COMPARE_BITS;

    SetKernelCompareBorrowBits(bnThreshold, kernelHash, witnessOut.aL, gateIdx);
    SetKernelCompareBorrowBits(bnThreshold, kernelHash, witnessOut.aR, gateIdx);
    SetKernelCompareBorrowBits(bnThreshold, kernelHash, witnessOut.aO, gateIdx);
    gateIdx += BPAC_KERNEL_COMPARE_BITS;

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

    (void)skStake;
    uint256 authHash = NullStakeV3StakeAuthHash(vchPkStake);
    uint256 ownerBind = NullStakeV3OwnerBindHash(nValue, vchPkOwner);

    uint256 expectedDelegationHash = NullStakeV3DelegationChain(authHash, ownerBind);
    if (FieldReduce(delegationHash) != expectedDelegationHash)
        return false;

    uint256 authScalar = LowBitsToScalar(authHash, BPAC_V3_DELEGATION_BITS);
    uint256 ownerScalar = LowBitsToScalar(ownerBind, BPAC_V3_DELEGATION_BITS);

    {
        uint256 delegScalar = FieldReduce(delegationHash);
        witnessOut.aL[gateIdx] = delegScalar;
        witnessOut.aR[gateIdx] = FieldFromUint64(1);
        witnessOut.aO[gateIdx] = delegScalar;
        gateIdx++;
    }

    {
        uint256 dState = FieldAdd(authScalar, ownerScalar);
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

            dState = FieldAdd(x5, authScalar);
        }
    }

    {
        const unsigned char* authBytes = authHash.begin();
        for (int i = 0; i < BPAC_V3_DELEGATION_BITS; i++)
        {
            uint256 bit = FieldFromUint64((authBytes[i / 8] >> (i % 8)) & 1);
            witnessOut.aL[gateIdx] = bit;
            witnessOut.aR[gateIdx] = bit;
            witnessOut.aO[gateIdx] = bit;
            gateIdx++;
        }
    }

    {
        const unsigned char* ownerBytes = ownerBind.begin();
        for (int i = 0; i < BPAC_V3_DELEGATION_BITS; i++)
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
    ScalarBytesToU256Raw(vchValueBlind.data(), blind);
    witnessOut.vBlinds[0] = blind;

    return true;
}
