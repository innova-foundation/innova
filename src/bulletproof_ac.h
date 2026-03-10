// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_BULLETPROOF_AC_H
#define INN_BULLETPROOF_AC_H

#include "uint256.h"
#include "serialize.h"
#include "ipa.h"
#include "poseidon2.h"

#include <vector>
#include <stdint.h>

static const int BPAC_MAX_CONSTRAINTS = 1024;   // 2^10 (supports V3 cold staking 576-gate circuit)
static const int BPAC_LOG_CONSTRAINTS = 10;

static const int BPAC_V3_MAX_CONSTRAINTS = 1024;  // 2^10
static const int BPAC_V3_LOG_CONSTRAINTS = 10;

static const int BPAC_MAX_HIGH_VARS = 8;

static const size_t BPAC_MAX_PROOF_SIZE = 2048;     // DoS protection
static const size_t BPAC_V3_MAX_PROOF_SIZE = 4096;  // DoS protection


struct CSparseEntry
{
    int nCol;       // Column index
    uint256 value;  // Field element value

    CSparseEntry() : nCol(0) {}
    CSparseEntry(int col, const uint256& val) : nCol(col), value(val) {}
};


class CR1CSCircuit
{
public:
    int nMultConstraints;   // Number of multiplication gates (n)
    int nPaddedSize;        // Padded to power of 2 for IPA
    int nHighLevelVars;     // Number of committed variables (m)
    int nLinearConstraints; // Number of linear constraints (q)

    std::vector<std::vector<CSparseEntry>> WL;
    std::vector<std::vector<CSparseEntry>> WR;
    std::vector<std::vector<CSparseEntry>> WO;
    std::vector<std::vector<CSparseEntry>> WV;

    std::vector<uint256> c;  // one per linear constraint

    CR1CSCircuit()
    {
        nMultConstraints = 0;
        nPaddedSize = 0;
        nHighLevelVars = 0;
        nLinearConstraints = 0;
    }

    int AddMultGate()
    {
        return nMultConstraints++;
    }

    void AddLinearConstraint(const std::vector<CSparseEntry>& wl,
                              const std::vector<CSparseEntry>& wr,
                              const std::vector<CSparseEntry>& wo,
                              const std::vector<CSparseEntry>& wv,
                              const uint256& constant)
    {
        WL.push_back(wl);
        WR.push_back(wr);
        WO.push_back(wo);
        WV.push_back(wv);
        c.push_back(constant);
        nLinearConstraints++;
    }

    void PadToNextPow2()
    {
        nPaddedSize = 1;
        while (nPaddedSize < nMultConstraints)
            nPaddedSize <<= 1;
    }
};


class CBulletproofACProof
{
public:
    std::vector<unsigned char> vchAI;   // 33 bytes - commitment to aL, aR
    std::vector<unsigned char> vchAO;   // 33 bytes - commitment to aO
    std::vector<unsigned char> vchS;    // 33 bytes - blinding vector commitment

    std::vector<unsigned char> vchT1;   // 33 bytes
    std::vector<unsigned char> vchT3;   // 33 bytes
    std::vector<unsigned char> vchT4;   // 33 bytes
    std::vector<unsigned char> vchT5;   // 33 bytes
    std::vector<unsigned char> vchT6;   // 33 bytes

    uint256 tauX;       // Blinding evaluation at challenge x
    uint256 mu;         // Aggregate blinding for inner product
    uint256 tHat;       // Polynomial evaluation t(x)

    CIPAProof ipaProof;

    CBulletproofACProof() {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchAI);
        READWRITE(vchAO);
        READWRITE(vchS);
        READWRITE(vchT1);
        READWRITE(vchT3);
        READWRITE(vchT4);
        READWRITE(vchT5);
        READWRITE(vchT6);
        READWRITE(tauX);
        READWRITE(mu);
        READWRITE(tHat);
        READWRITE(ipaProof);
    )

    bool IsNull() const
    {
        return vchAI.empty() || ipaProof.IsNull();
    }

    size_t GetProofSize() const
    {
        return 8 * 33 + 3 * 32 + ipaProof.GetProofSize();
    }
};


CR1CSCircuit BuildNullStakeV2Circuit(uint64_t nStakeModifier,
                                      unsigned int nTimeTx,
                                      unsigned int nBits);


struct CR1CSWitness
{
    std::vector<uint256> aL;    // Left multiplication inputs
    std::vector<uint256> aR;    // Right multiplication inputs
    std::vector<uint256> aO;    // Multiplication outputs

    std::vector<uint256> v;         // Committed values
    std::vector<uint256> vBlinds;   // Blinding factors
};

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
                              CR1CSWitness& witnessOut);


bool CreateBulletproofACProof(const CR1CSCircuit& circuit,
                                const CR1CSWitness& witness,
                                const std::vector<std::vector<unsigned char>>& vCommitments,
                                CBulletproofACProof& proofOut);

bool VerifyBulletproofACProof(const CR1CSCircuit& circuit,
                                const std::vector<std::vector<unsigned char>>& vCommitments,
                                const CBulletproofACProof& proof);


CR1CSCircuit BuildNullStakeV3Circuit(uint64_t nStakeModifier,
                                      unsigned int nTimeTx,
                                      unsigned int nBits,
                                      const uint256& delegationHash);

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
                              CR1CSWitness& witnessOut);


#endif // INN_BULLETPROOF_AC_H
