// Copyright (c) 2026 The Innova developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef INNOVA_PRIVACY_VNEXT_BUILDER_H
#define INNOVA_PRIVACY_VNEXT_BUILDER_H

#include <string>
#include <vector>

#include "privacy_vnext/iv5_protocol.h"
#include "privacy_vnext_ffi.h"

// Assembles a canonical IV5 payload from a wallet's notes. Proofs bind to the prefix hash,
// so the prefix is fully serialized before proving; the result is checked with the
// consensus decoder before it is returned.

// One note being spent, with the material needed to prove and re-open it.
struct PrivacyVNextSpendNote
{
    PrivacyVNextDigest spendSecret;      // x, the note's derived spend authority
    PrivacyVNextDigest y;                // the note's commitment scalar
    PrivacyVNextDigest mask;             // the note's commitment mask
    uint64_t nAmount;
    PrivacyVNextOutputLeaf leaf;
    std::vector<unsigned char> vchWitnessRecord;

    PrivacyVNextSpendNote() : nAmount(0)
    {
        spendSecret.fill(0);
        y.fill(0);
        mask.fill(0);
    }

    void Clear();
    ~PrivacyVNextSpendNote() { Clear(); }
};

// One note being created.
struct PrivacyVNextNewOutput
{
    PrivacyVNextAddressComponents recipient;
    uint64_t nAmount;

    PrivacyVNextNewOutput() : nAmount(0) {}
};

// The fields of a spend-shaped payload prefix that are not per input or per output.
struct PrivacyVNextPrefixHeader
{
    uint8_t nOperation;
    uint8_t nDisclosureMask;
    uint8_t nNetwork;
    PrivacyVNextDigest genesis;
    PrivacyVNextDigest parameterDigest;
    PrivacyVNextDigest finalizedRoot;
    uint64_t nFinalizedTreeSize;
    int64_t nTransparentValueBalance;
    uint64_t nFee;
    PrivacyVNextDigest transparentBinding;
    // A note finality vote's boundary; NULL for every other operation.
    const PrivacyVNextDigest* pVoteBoundaryHash;
    uint32_t nVoteBoundaryHeight;

    PrivacyVNextPrefixHeader()
        : nOperation(0), nDisclosureMask(0), nNetwork(0), nFinalizedTreeSize(0),
          nTransparentValueBalance(0), nFee(0), pVoteBoundaryHash(NULL),
          nVoteBoundaryHeight(0)
    {
        genesis.fill(0);
        parameterDigest.fill(0);
        finalizedRoot.fill(0);
        transparentBinding.fill(0);
    }
};

// One input as the prefix names it. The sender authority is written only when the mask
// discloses senders.
struct PrivacyVNextPrefixInput
{
    PrivacyVNextDigest pseudoOut;
    PrivacyVNextDigest keyImage;
    PrivacyVNextDigest senderAuthority;
};

// One output as the prefix names it. The recipient keys are written only when the mask
// discloses receivers, and the amount and mask only when it discloses amounts.
struct PrivacyVNextPrefixOutput
{
    PrivacyVNextDigest owner;
    PrivacyVNextDigest commitment;
    PrivacyVNextDigest noteEphemeral;
    PrivacyVNextDigest tweakEphemeral;
    std::vector<unsigned char> vchRecipientCiphertext;
    std::vector<unsigned char> vchOutgoingCiphertext;
    PrivacyVNextDigest recipientSpend;
    PrivacyVNextDigest recipientView;
    uint64_t nAmount;
    PrivacyVNextDigest mask;

    PrivacyVNextPrefixOutput() : nAmount(0) {}
};

/** A uniformly random canonical scalar; the single source for every IV5 secret. */
bool RandomScalar(PrivacyVNextDigest& out, std::string& strErrorOut);

// Serializes a spend-shaped prefix in decoder order (the signing-hash preimage). Shared by
// the builder and the mix coordinator.
bool AssemblePrivacyVNextPayloadPrefix(const PrivacyVNextPrefixHeader& header,
                                       const std::vector<PrivacyVNextPrefixInput>& vInputs,
                                       const std::vector<PrivacyVNextPrefixOutput>& vOutputs,
                                       std::vector<unsigned char>& vchPrefixOut,
                                       std::string& strErrorOut);

// Disclosure mask: a set bit hides that field (7 = nothing disclosed, 0 = senders,
// recipients and amounts disclosed). Disclosed fields are proved against the commitments;
// disclosed amounts replace the range proof.

// `pvchChainParameterDigest` must come from the same finalized epoch state as the anchor
// root. NULL only below the chain's first IV5 epoch (bootstrap seed).

// Build a transfer payload. `transparentBinding` is GetPrivacyVNextTransparentBinding of
// the carrying transaction; it is part of the proved prefix.
bool BuildPrivacyVNextTransferPayload(
    uint8_t nNetwork,
    uint8_t nDisclosureMask,
    const PrivacyVNextDigest& genesis,
    const PrivacyVNextDigest& outgoingViewSecret,
    const PrivacyVNextDigest& finalizedRoot,
    uint64_t nFinalizedTreeSize,
    const PrivacyVNextDigest& transparentBinding,
    uint64_t nFee,
    const std::vector<PrivacyVNextSpendNote>& spends,
    const std::vector<PrivacyVNextNewOutput>& outputs,
    std::vector<unsigned char>& vchPayloadOut,
    std::string& strErrorOut,
    const std::vector<unsigned char>* pvchChainParameterDigest = NULL);

// Build an unshield payload. Spent notes must cover `nTransparentValueOut` + fee + change;
// `outputs` are the change notes only.
bool BuildPrivacyVNextUnshieldPayload(
    uint8_t nNetwork,
    uint8_t nDisclosureMask,
    const PrivacyVNextDigest& genesis,
    const PrivacyVNextDigest& outgoingViewSecret,
    const PrivacyVNextDigest& finalizedRoot,
    uint64_t nFinalizedTreeSize,
    const PrivacyVNextDigest& transparentBinding,
    uint64_t nTransparentValueOut,
    uint64_t nFee,
    const std::vector<PrivacyVNextSpendNote>& spends,
    const std::vector<PrivacyVNextNewOutput>& outputs,
    std::vector<unsigned char>& vchPayloadOut,
    std::string& strErrorOut,
    const std::vector<unsigned char>* pvchChainParameterDigest = NULL);

// Build a shield payload (no membership proof). `nTransparentValueIn` must equal outputs
// plus fee.
bool BuildPrivacyVNextShieldPayload(
    uint8_t nNetwork,
    uint8_t nDisclosureMask,
    const PrivacyVNextDigest& genesis,
    const PrivacyVNextDigest& outgoingViewSecret,
    const PrivacyVNextDigest& finalizedRoot,
    uint64_t nFinalizedTreeSize,
    const PrivacyVNextDigest& transparentBinding,
    uint64_t nTransparentValueIn,
    uint64_t nFee,
    const std::vector<PrivacyVNextNewOutput>& outputs,
    std::vector<unsigned char>& vchPayloadOut,
    std::string& strErrorOut,
    const std::vector<unsigned char>* pvchChainParameterDigest = NULL);

// Build a note finality vote payload (op 10): spends the note and reissues value + `nVoteReward`
// (fee 0, mask 7). `nVoteReward` must equal GetFinalityNoteVoteReward at `nVoteBoundaryHeight`.
bool BuildPrivacyVNextNoteVotePayload(
    uint8_t nNetwork,
    const PrivacyVNextDigest& genesis,
    const PrivacyVNextDigest& outgoingViewSecret,
    const PrivacyVNextDigest& finalizedRoot,
    uint64_t nFinalizedTreeSize,
    const PrivacyVNextDigest& transparentBinding,
    const PrivacyVNextDigest& voteBoundaryHash,
    uint32_t nVoteBoundaryHeight,
    int64_t nVoteReward,
    const PrivacyVNextSpendNote& note,
    const PrivacyVNextAddressComponents& reissueTo,
    std::vector<unsigned char>& vchPayloadOut,
    PrivacyVNextDigest& keyImageOut,
    std::string& strErrorOut,
    const std::vector<unsigned char>* pvchChainParameterDigest = NULL);

// Build a collateralnode attestation payload. The note is named, not spent; its key image
// goes to the collateral watch set. `registrationContext` (node identity, endpoint, payout)
// is in the signing hash.
bool BuildPrivacyVNextCollateralAttestationPayload(
    uint8_t nNetwork,
    const PrivacyVNextDigest& genesis,
    const PrivacyVNextDigest& finalizedRoot,
    uint64_t nFinalizedTreeSize,
    const PrivacyVNextDigest& transparentBinding,
    const PrivacyVNextDigest& registrationContext,
    const PrivacyVNextSpendNote& collateral,
    std::vector<unsigned char>& vchPayloadOut,
    PrivacyVNextDigest& keyImageOut,
    std::string& strErrorOut,
    const std::vector<unsigned char>* pvchChainParameterDigest = NULL);

// Build a finality-committee member registration payload: the attestation plus
// `vchMemberKey`, a 33-byte compressed secp256k1 key covered by the signing hash.
bool BuildPrivacyVNextFinalityMemberRegistrationPayload(
    uint8_t nNetwork,
    const PrivacyVNextDigest& genesis,
    const PrivacyVNextDigest& finalizedRoot,
    uint64_t nFinalizedTreeSize,
    const PrivacyVNextDigest& transparentBinding,
    const PrivacyVNextDigest& registrationContext,
    const std::vector<unsigned char>& vchMemberKey,
    const PrivacyVNextSpendNote& collateral,
    std::vector<unsigned char>& vchPayloadOut,
    PrivacyVNextDigest& keyImageOut,
    std::string& strErrorOut,
    const std::vector<unsigned char>* pvchChainParameterDigest = NULL);

#endif // INNOVA_PRIVACY_VNEXT_BUILDER_H
