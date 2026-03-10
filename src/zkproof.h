// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_ZKPROOF_H
#define INN_ZKPROOF_H

#include "uint256.h"
#include "serialize.h"
#include "sync.h"

#include <vector>
#include <stdint.h>
#include <boost/thread/once.hpp>

static const size_t PEDERSEN_COMMITMENT_SIZE = 33;
static const size_t BULLETPROOF_PROOF_SIZE = 688;
static const size_t MAX_BULLETPROOF_PROOF_SIZE = 1024;
static const size_t BINDING_SIGNATURE_SIZE = 65;
static const size_t BLINDING_FACTOR_SIZE = 32;

class CZKContext
{
public:
    static bool Initialize();

    static void Shutdown();

    static bool IsInitialized();

    static const std::vector<unsigned char>& GetGeneratorG();

    static const std::vector<unsigned char>& GetGeneratorH();

private:
    static boost::once_flag initOnceFlag;
    static void DoInitialize();
    static bool fInitialized;
    static bool fInitFailed;
    static CCriticalSection cs_zkcontext;
    static std::vector<unsigned char> vchGeneratorG;
    static std::vector<unsigned char> vchGeneratorH;
};


class CPedersenCommitment
{
public:
    std::vector<unsigned char> vchCommitment;

    CPedersenCommitment()
    {
        vchCommitment.resize(PEDERSEN_COMMITMENT_SIZE, 0);
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchCommitment);
    )

    bool IsNull() const;

    uint256 GetHash() const;

    bool operator==(const CPedersenCommitment& other) const
    {
        return vchCommitment == other.vchCommitment;
    }
};

bool CreatePedersenCommitment(int64_t nValue,
                               const std::vector<unsigned char>& vchBlind,
                               CPedersenCommitment& commitOut);

bool VerifyPedersenCommitment(const CPedersenCommitment& commit,
                               int64_t nValue,
                               const std::vector<unsigned char>& vchBlind);

bool CreateBlindCommitment(const std::vector<unsigned char>& vchBlind,
                            CPedersenCommitment& commitOut);

bool GenerateBlindingFactor(std::vector<unsigned char>& vchBlindOut);

bool AddCommitments(const CPedersenCommitment& a,
                     const CPedersenCommitment& b,
                     CPedersenCommitment& resultOut);

bool SubtractCommitments(const CPedersenCommitment& a,
                          const CPedersenCommitment& b,
                          CPedersenCommitment& resultOut);

bool VerifyCommitmentBalance(const std::vector<CPedersenCommitment>& vInputCommits,
                              const std::vector<CPedersenCommitment>& vOutputCommits,
                              int64_t nFee);


class CBulletproofRangeProof
{
public:
    std::vector<unsigned char> vchProof;

    CBulletproofRangeProof()
    {
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchProof);
    )

    bool IsNull() const { return vchProof.empty(); }
    size_t GetSize() const { return vchProof.size(); }
};

bool CreateBulletproofRangeProof(int64_t nValue,
                                  const std::vector<unsigned char>& vchBlind,
                                  const CPedersenCommitment& commit,
                                  CBulletproofRangeProof& proofOut);

bool VerifyBulletproofRangeProof(const CPedersenCommitment& commit,
                                  const CBulletproofRangeProof& proof);

bool BatchVerifyBulletproofRangeProofs(const std::vector<CPedersenCommitment>& vCommits,
                                        const std::vector<CBulletproofRangeProof>& vProofs);


class CBindingSignature
{
public:
    std::vector<unsigned char> vchSignature;

    CBindingSignature()
    {
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchSignature);
    )

    bool IsNull() const { return vchSignature.empty(); }
};

bool CreateBindingSignature(const std::vector<std::vector<unsigned char>>& vInputBlinds,
                             const std::vector<std::vector<unsigned char>>& vOutputBlinds,
                             const uint256& sighash,
                             CBindingSignature& sigOut);

bool VerifyBindingSignature(const std::vector<CPedersenCommitment>& vInputCommits,
                             const std::vector<CPedersenCommitment>& vOutputCommits,
                             int64_t nValueBalance,
                             const uint256& sighash,
                             const CBindingSignature& sig);


bool VerifySpendAuthSignature(const std::vector<unsigned char>& vchRk,
                               const uint256& sighash,
                               const std::vector<unsigned char>& vchSig);

bool CreateSpendAuthSignature(const uint256& skSpend,
                               const uint256& sighash,
                               std::vector<unsigned char>& vchRk,
                               std::vector<unsigned char>& vchSig);

uint256 HMAC_SHA256_Compute(const uint256& key, const uint256& data);

uint256 PRF_nf(const uint256& nk, const uint256& rho);


bool ChaCha20Poly1305Encrypt(const std::vector<unsigned char>& vchKey,
                              const std::vector<unsigned char>& vchPlaintext,
                              const std::vector<unsigned char>& vchAad,
                              std::vector<unsigned char>& vchCiphertextOut);

bool ChaCha20Poly1305Decrypt(const std::vector<unsigned char>& vchCiphertext,
                              const std::vector<unsigned char>& vchKey,
                              const std::vector<unsigned char>& vchAad,
                              std::vector<unsigned char>& vchPlaintextOut);


bool GenerateMuSigNonce(std::vector<unsigned char>& vchNonceOut,
                        std::vector<unsigned char>& vchNoncePointOut);

uint256 ComputeNonceCommitment(const std::vector<unsigned char>& vchNoncePoint);

bool AggregateNoncePoints(const std::vector<std::vector<unsigned char>>& vNoncePoints,
                          std::vector<unsigned char>& vchAggregateOut);

bool ComputeMuSigChallenge(const std::vector<unsigned char>& vchAggNonce,
                           const std::vector<CPedersenCommitment>& vInputCommits,
                           const std::vector<CPedersenCommitment>& vOutputCommits,
                           int64_t nValueBalance,
                           const uint256& sighash,
                           std::vector<unsigned char>& vchChallengeOut);

bool CreatePartialBindingSig(const std::vector<unsigned char>& vchNonce,        // k_i
                              const std::vector<std::vector<unsigned char>>& vMyInputBlinds,
                              const std::vector<std::vector<unsigned char>>& vMyOutputBlinds,
                              const std::vector<unsigned char>& vchChallenge,
                              std::vector<unsigned char>& vchPartialSigOut);

bool AggregatePartialSigs(const std::vector<std::vector<unsigned char>>& vPartialSigs,
                           std::vector<unsigned char>& vchAggSigOut);

bool AssembleBindingSignature(const std::vector<unsigned char>& vchAggNonce,
                               const std::vector<unsigned char>& vchAggSig,
                               CBindingSignature& sigOut);


#endif // INN_ZKPROOF_H
