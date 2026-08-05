// Copyright (c) 2026 The Innova developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef INNOVA_PRIVACY_VNEXT_BUILDER_H
#define INNOVA_PRIVACY_VNEXT_BUILDER_H

#include <string>
#include <vector>

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

// Build a fully private transfer payload.
//
// Every disclosure bit is set, so nothing about the sender, the recipient or the amounts is
// revealed and the outputs carry a range proof. Payloads that disclose any of those are a
// separate shape and are not built here.
bool BuildPrivacyVNextTransferPayload(
    uint8_t nNetwork,
    const PrivacyVNextDigest& genesis,
    const PrivacyVNextDigest& outgoingViewSecret,
    const PrivacyVNextDigest& finalizedRoot,
    uint64_t nFinalizedTreeSize,
    uint64_t nFee,
    const std::vector<PrivacyVNextSpendNote>& spends,
    const std::vector<PrivacyVNextNewOutput>& outputs,
    std::vector<unsigned char>& vchPayloadOut,
    std::string& strErrorOut);

#endif // INNOVA_PRIVACY_VNEXT_BUILDER_H
