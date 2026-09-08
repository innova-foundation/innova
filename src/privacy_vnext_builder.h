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

// Build a note finality vote payload (operation 10).
//
// The vote spends its note and reissues the same value to one fresh note, so unspent-ness
// is the spent-key index the spend path already keeps and a second vote of the same note
// is a double spend. Everything the decoder pins is fixed here rather than taken from the
// caller -- one input, one output, fee zero, transparent balance zero, mask 7 -- so the
// only choices are which note votes, which epoch boundary it names, and where the value
// is reissued.
//
// `voteBoundaryHash` and `nVoteBoundaryHeight` name the epoch boundary block H_E. Both sit
// inside the signing hash, so a vote cannot be replayed into another epoch and a
// transfer's proof cannot be repackaged as one.
//
// `reissueTo` should be an address of the voting wallet: the reissue is what votes in the
// next epoch. Its one-time key derives under input_context(10, transparent_binding,
// [key image]), which is unique per note, so the reissue's key cannot recur.
//
// `keyImageOut` is the key image the proof publishes -- the value the caller watches, and
// the value the reissue's self-pay index is drawn from.
bool BuildPrivacyVNextNoteVotePayload(
    uint8_t nNetwork,
    const PrivacyVNextDigest& genesis,
    const PrivacyVNextDigest& outgoingViewSecret,
    const PrivacyVNextDigest& finalizedRoot,
    uint64_t nFinalizedTreeSize,
    const PrivacyVNextDigest& transparentBinding,
    const PrivacyVNextDigest& voteBoundaryHash,
    uint32_t nVoteBoundaryHeight,
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
