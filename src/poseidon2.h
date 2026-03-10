// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_POSEIDON2_H
#define INN_POSEIDON2_H

#include "uint256.h"

#include <vector>
#include <stdint.h>


static const int POSEIDON2_T = 7;       // State width
static const int POSEIDON2_RATE = 6;    // Absorption rate
static const int POSEIDON2_RF = 8;      // Full rounds (4 + 4)
static const int POSEIDON2_RP = 57;     // Partial rounds
static const int POSEIDON2_SBOX = 5;    // S-box exponent

static const int POSEIDON2_NUM_RC = POSEIDON2_RF * POSEIDON2_T + POSEIDON2_RP;


class CPoseidon2State
{
public:
    uint256 elements[POSEIDON2_T];

    CPoseidon2State()
    {
        for (int i = 0; i < POSEIDON2_T; i++)
            elements[i] = 0;
    }

    void SetElement(int idx, const uint256& val)
    {
        if (idx >= 0 && idx < POSEIDON2_T)
            elements[idx] = val;
    }

    const uint256& GetElement(int idx) const
    {
        return elements[idx];
    }
};


class CPoseidon2Params
{
public:
    static bool Initialize();
    static bool IsInitialized();
    static const std::vector<uint256>& GetRoundConstants();
    static const std::vector<std::vector<uint256>>& GetMDSMatrix();
    static const std::vector<uint256>& GetInternalDiag();
    static const uint256& GetFieldOrder();

private:
    static bool fInitialized;
    static std::vector<uint256> vRoundConstants;
    static std::vector<std::vector<uint256>> vMDSMatrix;
    static std::vector<uint256> vInternalDiag;
    static uint256 fieldOrder;

    static void GenerateRoundConstants();
    static void GenerateMDSMatrix();
    static void GenerateInternalDiag();
};


void Poseidon2Permute(CPoseidon2State& state);

void Poseidon2Hash(const uint256 inputs[6], uint256& output);

uint256 Poseidon2KernelHash(uint64_t nStakeModifier,
                             unsigned int nBlockTimeFrom,
                             unsigned int nTxPrevOffset,
                             unsigned int nTxTimePrev,
                             unsigned int nVoutN,
                             unsigned int nTimeTx);


uint256 FieldAdd(const uint256& a, const uint256& b);
uint256 FieldSub(const uint256& a, const uint256& b);
uint256 FieldMul(const uint256& a, const uint256& b);
uint256 FieldPow5(const uint256& a);
uint256 FieldFromUint64(uint64_t val);
uint256 FieldInv(const uint256& a);
bool FieldIsValid(const uint256& a);
uint256 FieldReduce(const uint256& a);


#endif // INN_POSEIDON2_H
