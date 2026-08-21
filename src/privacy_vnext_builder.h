// Copyright (c) 2026 The Innova developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef INNOVA_PRIVACY_VNEXT_BUILDER_H
#define INNOVA_PRIVACY_VNEXT_BUILDER_H

#include <string>
#include <vector>

#include "privacy_vnext/iv5_protocol.h"
#include "privacy_vnext_ffi.h"

// Assembles a canonical IV5 payload from a wallet's notes.
//
// The payload's proofs bind to a hash of everything serialized before them, so the order
// here is fixed: encrypt the outputs, learn the inputs' pseudo-outputs, serialize the
// prefix, hash it, then prove against that hash. The result is validated with the same
// decoder consensus uses before it is returned, so a payload that would be rejected never
// leaves the builder.

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
