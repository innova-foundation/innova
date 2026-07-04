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

#include <string>
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
    unsigned int nBlockTimeFrom;
    unsigned int nTxPrevOffset;
    unsigned int nTxTimePrev;
    unsigned int nVoutN;
    unsigned int nTimeTx;

    CNullStakeKernelProofV2()
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
        READWRITE(acProof);
        READWRITE(valueCommitment);
        READWRITE(vchLinkProof);
        READWRITE(nStakeModifier);
        READWRITE(nBlockTimeFrom);
        READWRITE(nTxPrevOffset);
        READWRITE(nTxTimePrev);
        READWRITE(nVoutN);
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
static const size_t NULLSTAKE_B2C_BPAC_AUTH_PROOF_MAX_SIZE = 16384;       // research cap, not consensus
static const size_t NULLSTAKE_B2C_RINGXM_AUTH_PROOF_MAX_SIZE = 96 * 1024; // off-consensus prototype cap
static const unsigned int NULLSTAKE_B2C_HIDDEN_AUTH_VERSION = 1;
static const unsigned int NULLSTAKE_B2C_AUTH_TYPE_BPAC = 1;
static const unsigned int NULLSTAKE_B2C_AUTH_TYPE_RINGXM_DLEQ = 2;
static const unsigned int NULLSTAKE_B2C_BPAC_AUTH_CONSTRAINT_CAP = 8192;

// M-of-N authorization tier tag on CNullStakeKernelProofV3 (nThresholdM > 0 only). HALFAGG = B2-e public
// half-aggregated signers; B2C_HIDDEN = B2-c ring-DLEQ hidden signers. 1-of-1 (nThresholdM == 0) carries no
// nAuthMode. Each tier requires the OTHER tier's authorization material empty (the empty-vchPkStake analogue).
static const unsigned int NULLSTAKE_AUTHMODE_HALFAGG    = 0;
static const unsigned int NULLSTAKE_AUTHMODE_B2C_HIDDEN = 1;
// Consensus wire cap for a B2-c hidden-auth blob (headroom over the 32-of-32 worst case ~66.7 KiB), enforced
// structurally before any expensive EC work at every call site.
static const size_t NULLSTAKE_B2C_MAX_AUTH_SIZE = 96 * 1024;

struct CNullStakeB2CBPACBudget
{
    unsigned int nMembers;
    unsigned int nThresholdM;
    unsigned int nSelectorConstraints;
    unsigned int nThresholdConstraints;
    unsigned int nDistinctnessConstraints;
    unsigned int nTranscriptConstraints;
    unsigned int nECAuthConstraints;
    unsigned int nTotalConstraints;
    size_t nEstimatedProofSize;
    bool fECAuthIncluded;
    bool fWithinConstraintCap;
    bool fWithinProofCap;
    bool fBPACFeasible;
    std::string strFallbackReason;

    CNullStakeB2CBPACBudget()
    {
        nMembers = 0;
        nThresholdM = 0;
        nSelectorConstraints = 0;
        nThresholdConstraints = 0;
        nDistinctnessConstraints = 0;
        nTranscriptConstraints = 0;
        nECAuthConstraints = 0;
        nTotalConstraints = 0;
        nEstimatedProofSize = 0;
        fECAuthIncluded = false;
        fWithinConstraintCap = false;
        fWithinProofCap = false;
        fBPACFeasible = false;
    }
};

class CNullStakeMofNHiddenAuthRingSlotProof
{
public:
    std::vector<unsigned char> vchTag;  // per-proof duplicate tag, not stable across proofs
    std::vector<uint256> vChallenges;
    std::vector<uint256> vResponses;

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchTag);
        READWRITE(vChallenges);
        READWRITE(vResponses);
    )
};

// B2-c off-consensus hidden M-of-N authorization proof envelope. This object is deliberately
// separate from CNullStakeKernelProofV3 so the B2-e wire format remains byte-compatible while
// the hidden-signer construction is researched and benchmarked.
class CNullStakeMofNHiddenAuthProof
{
public:
    unsigned int nVersion;
    unsigned int nAuthType;
    std::vector<unsigned char> vchTagBaseNonce;
    std::vector<CNullStakeMofNHiddenAuthRingSlotProof> vRingSlotProofs;
    std::vector<unsigned char> vchResearchProof;

    CNullStakeMofNHiddenAuthProof()
    {
        nVersion = NULLSTAKE_B2C_HIDDEN_AUTH_VERSION;
        nAuthType = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nVersion);
        READWRITE(nAuthType);
        READWRITE(vchTagBaseNonce);
        READWRITE(vRingSlotProofs);
        READWRITE(vchResearchProof);
    )

    bool IsNull() const { return vRingSlotProofs.empty() && vchResearchProof.empty(); }
    size_t GetProofSize() const;
};

bool EstimateNullStakeB2CHiddenAuthBPACBudget(unsigned int nMembers,
                                              unsigned int nThresholdM,
                                              bool fIncludeECAuth,
                                              CNullStakeB2CBPACBudget& budgetOut);

uint256 ComputeNullStakeMofNHiddenAuthStatementHash(const std::vector<std::vector<unsigned char> >& vStakerSet,
                                                    unsigned int nThresholdM,
                                                    const std::vector<unsigned char>& vchPkOwner,
                                                    const uint256& delegationHash,
                                                    const uint256& stakeDigest,
                                                    const CPedersenCommitment& kernelValueCommitment,
                                                    unsigned int nAuthMode = NULLSTAKE_AUTHMODE_B2C_HIDDEN);

bool CreateNullStakeMofNHiddenAuthProof(const std::vector<std::vector<unsigned char> >& vStakerSet,
                                        unsigned int nThresholdM,
                                        const std::vector<unsigned char>& vchPkOwner,
                                        const uint256& delegationHash,
                                        const uint256& stakeDigest,
                                        const CPedersenCommitment& kernelValueCommitment,
                                        const std::vector<uint256>& vSignerSecrets,
                                        CNullStakeMofNHiddenAuthProof& proofOut,
                                        std::string& strError);

bool VerifyNullStakeMofNHiddenAuthProof(const std::vector<std::vector<unsigned char> >& vStakerSet,
                                        unsigned int nThresholdM,
                                        const std::vector<unsigned char>& vchPkOwner,
                                        const uint256& delegationHash,
                                        const uint256& stakeDigest,
                                        const CPedersenCommitment& kernelValueCommitment,
                                        const CNullStakeMofNHiddenAuthProof& proof,
                                        std::string& strError);

class CNullStakeKernelProofV3
{
public:
    CBulletproofACProof acProof;

    CPedersenCommitment valueCommitment;

    std::vector<unsigned char> vchLinkProof;

    uint64_t nStakeModifier;
    unsigned int nBlockTimeFrom;
    unsigned int nTxPrevOffset;
    unsigned int nTxTimePrev;
    unsigned int nVoutN;
    unsigned int nTimeTx;

    uint256 delegationHash;

    std::vector<unsigned char> vchPkStake;  // 33 bytes compressed
    std::vector<unsigned char> vchPkOwner;  // 33 bytes compressed

    // B2-e: half-aggregated Schnorr M-of-N staking authorization (public-signer tier).
    // nThresholdM == 0 selects the legacy single-key path (vchPkStake, value-coupled in-circuit
    // delegation chain). nThresholdM >= 1 selects M-of-N: vStakerSet is the full ordered
    // (strictly-ascending, duplicate-free) N-member staker set that hashes to delegationHash;
    // vSignerPubKeys are the M signing members (a strictly-ascending subset of vStakerSet);
    // vSignerRPoints their per-signer R-points; vchAggregatedSScalar the summed s-scalar.
    // The full set is carried in the proof so the verifier can recompute the set hash for a
    // real threshold (M < N) and so the set is covered by the txid and the verify cache.
    unsigned int nThresholdM;
    std::vector<std::vector<unsigned char> > vStakerSet;
    std::vector<std::vector<unsigned char> > vSignerPubKeys;
    std::vector<std::vector<unsigned char> > vSignerRPoints;
    std::vector<unsigned char> vchAggregatedSScalar;

    CNullStakeKernelProofV3()
    {
        nStakeModifier = 0;
        nBlockTimeFrom = 0;
        nTxPrevOffset = 0;
        nTxTimePrev = 0;
        nVoutN = 0;
        nTimeTx = 0;
        nThresholdM = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(acProof);
        READWRITE(valueCommitment);
        READWRITE(vchLinkProof);
        READWRITE(nStakeModifier);
        READWRITE(nBlockTimeFrom);
        READWRITE(nTxPrevOffset);
        READWRITE(nTxTimePrev);
        READWRITE(nVoutN);
        READWRITE(nTimeTx);
        READWRITE(delegationHash);
        READWRITE(vchPkStake);
        READWRITE(vchPkOwner);
        READWRITE(nThresholdM);
        // B2-e: the M-of-N fields exist only for nThresholdM > 0. A legacy 1-of-1 proof
        // serializes nThresholdM == 0 and nothing further, keeping the legacy wire form
        // compact and self-describing. A pre-fork consensus guard separately rejects any
        // proof with nThresholdM != 0 below FORK_HEIGHT_NULLSTAKE_DELEGSET.
        if (nThresholdM > 0)
        {
            READWRITE(vStakerSet);
            READWRITE(vSignerPubKeys);
            READWRITE(vSignerRPoints);
            READWRITE(vchAggregatedSScalar);
        }
    )

    bool IsNull() const { return acProof.IsNull(); }
};


// B2-e Phase 3c.4: owner-override reclaim authorization (carried on a SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM
// tx). The owner reveals the full staker set + threshold + owner pubkey; consensus recomputes
// SetHash(set, M, owner) and requires it to equal delegationHash (the spent note's J-coefficient), so a
// substituted set/owner leaves a J residual the cv_plain checks reject. The owner authorization itself is
// the tx's mandatory spend-auth signature with rk == vchPkOwner (no extra signature field).
class CNullStakeReclaimAuth
{
public:
    uint256 delegationHash;
    std::vector<std::vector<unsigned char> > vStakerSet;   // full N-member set (sorted, dedup)
    unsigned int nThresholdM;
    std::vector<unsigned char> vchPkOwner;                 // 33 bytes; rk of the reclaim spend must equal this

    CNullStakeReclaimAuth() { nThresholdM = 0; }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(delegationHash);
        READWRITE(vStakerSet);
        READWRITE(nThresholdM);
        READWRITE(vchPkOwner);
    )

    bool IsNull() const { return vchPkOwner.empty() && vStakerSet.empty(); }
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

// B2-e: build an M-of-N (half-aggregated Schnorr) cold-stake kernel proof. The leaf cv3 is the
// 3-generator commitment to (nValue, vchBlind, delegationHash); vStakerSet is the ordered
// N-member set (hashing to delegationHash); vSignerSecrets are the >= M member secret scalars
// that sign the stake digest. Routed through VerifyNullStakeKernelProofV3 (nThresholdM > 0).
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
