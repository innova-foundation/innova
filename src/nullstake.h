// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_NULLSTAKE_H
#define INN_NULLSTAKE_H

#include "uint256.h"
#include "serialize.h"
#include "zkproof.h"
#include "curvetree.h"
#include "shielded.h"
#include "bulletproof_ac.h"

#include <vector>
#include <stdint.h>

static const size_t NULLSTAKE_PROOF_MAX_SIZE = 8192;  // DoS protection


class CNullStakeKernelProof
{
public:
    std::vector<unsigned char> vchProof;    // ZK proof blob (Sigma protocol)

    uint64_t nStakeModifier;                // Stake modifier from chain
    unsigned int nBlockTimeFrom;            // Block time of stake input's block
    unsigned int nTxPrevOffset;             // Offset of stake input tx in its block
    unsigned int nTxTimePrev;               // Time of stake input tx
    unsigned int nVoutN;                    // Output index in stake input tx
    unsigned int nTimeTx;                   // Staking timestamp

    CPedersenCommitment weightedCommitment;

    CNullStakeKernelProof()
    {
        nStakeModifier = 0;
        nBlockTimeFrom = 0;
        nTxPrevOffset = 0;
        nTxTimePrev = 0;
        nVoutN = 0;
        nTimeTx = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchProof);
        READWRITE(nStakeModifier);
        READWRITE(nBlockTimeFrom);
        READWRITE(nTxPrevOffset);
        READWRITE(nTxTimePrev);
        READWRITE(nVoutN);
        READWRITE(nTimeTx);
        READWRITE(weightedCommitment);
    )

    bool IsNull() const { return vchProof.empty(); }
    size_t GetSize() const { return vchProof.size(); }
};


class CShieldedCoinstake
{
public:
    CShieldedSpendDescription stakeInput;      // Shielded spend of stake UTXO (with FCMP proof)
    CShieldedOutputDescription stakeReturn;    // Return stake to self (shielded)
    CShieldedOutputDescription stakeReward;    // Stake reward output (shielded)
    CNullStakeKernelProof kernelProof;          // ZK proof of kernel satisfaction
    uint256 curveTreeRoot;                     // FCMP root at proof creation time

    IMPLEMENT_SERIALIZE
    (
        READWRITE(stakeInput);
        READWRITE(stakeReturn);
        READWRITE(stakeReward);
        READWRITE(kernelProof);
        READWRITE(curveTreeRoot);
    )

    bool IsNull() const { return kernelProof.IsNull(); }
};


uint256 PedersenKernelHash(uint64_t nStakeModifier,
                            unsigned int nBlockTimeFrom,
                            unsigned int nTxPrevOffset,
                            unsigned int nTxTimePrev,
                            unsigned int nVoutN,
                            unsigned int nTimeTx);


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
                                CNullStakeKernelProof& proofOut);

bool VerifyNullStakeKernelProof(const CNullStakeKernelProof& proof,
                                const CPedersenCommitment& cv,
                                unsigned int nBits,
                                int64_t nWeight);

bool CheckShieldedStakeKernelHash(unsigned int nBits,
                                   uint64_t nStakeModifier,
                                   unsigned int nBlockTimeFrom,
                                   unsigned int nTxPrevOffset,
                                   unsigned int nTxTimePrev,
                                   unsigned int nVoutN,
                                   unsigned int nTimeTx,
                                   int64_t nValue,
                                   int64_t nWeight);


static const size_t NULLSTAKE_V2_PROOF_MAX_SIZE = 4096;  // DoS protection

class CNullStakeKernelProofV2
{
public:
    CBulletproofACProof acProof;

    CPedersenCommitment valueCommitment;

    std::vector<unsigned char> vchLinkProof;

    uint64_t nStakeModifier;
    unsigned int nTimeTx;

    CNullStakeKernelProofV2()
    {
        nStakeModifier = 0;
        nTimeTx = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(acProof);
        READWRITE(valueCommitment);
        READWRITE(vchLinkProof);
        READWRITE(nStakeModifier);
        READWRITE(nTimeTx);
    )

    bool IsNull() const { return acProof.IsNull(); }
};


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
                                  CNullStakeKernelProofV2& proofOut);

bool VerifyNullStakeKernelProofV2(const CNullStakeKernelProofV2& proof,
                                  const CPedersenCommitment& cv,
                                  unsigned int nBits);

bool CheckShieldedStakeKernelHashV2(unsigned int nBits,
                                     uint64_t nStakeModifier,
                                     unsigned int nBlockTimeFrom,
                                     unsigned int nTxPrevOffset,
                                     unsigned int nTxTimePrev,
                                     unsigned int nVoutN,
                                     unsigned int nTimeTx,
                                     int64_t nValue,
                                     int64_t nWeight);


static const size_t NULLSTAKE_V3_PROOF_MAX_SIZE = 4096;  // DoS protection

class CNullStakeKernelProofV3
{
public:
    CBulletproofACProof acProof;

    CPedersenCommitment valueCommitment;

    std::vector<unsigned char> vchLinkProof;

    uint64_t nStakeModifier;
    unsigned int nTimeTx;

    uint256 delegationHash;

    std::vector<unsigned char> vchPkStake;  // 33 bytes compressed

    CNullStakeKernelProofV3()
    {
        nStakeModifier = 0;
        nTimeTx = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(acProof);
        READWRITE(valueCommitment);
        READWRITE(vchLinkProof);
        READWRITE(nStakeModifier);
        READWRITE(nTimeTx);
        READWRITE(delegationHash);
        READWRITE(vchPkStake);
    )

    bool IsNull() const { return acProof.IsNull(); }
};


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
                                  CNullStakeKernelProofV3& proofOut);

bool VerifyNullStakeKernelProofV3(const CNullStakeKernelProofV3& proof,
                                  const CPedersenCommitment& cv,
                                  unsigned int nBits);

bool CheckShieldedStakeKernelHashV3(unsigned int nBits,
                                     uint64_t nStakeModifier,
                                     unsigned int nBlockTimeFrom,
                                     unsigned int nTxPrevOffset,
                                     unsigned int nTxTimePrev,
                                     unsigned int nVoutN,
                                     unsigned int nTimeTx,
                                     int64_t nValue,
                                     int64_t nWeight);


#endif // INN_NULLSTAKE_H
