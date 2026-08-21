// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license.

#ifndef INN_IV5_PROTOCOL_H
#define INN_IV5_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace iv5
{
static const char PROTOCOL_CONTRACT_SHA256[] =
    "a07c1273435135dcd3d9c79d5abb2f89a70343d1af3d960b6b5947bab41b84e7";
// Contract texts this build's lineage has published, besides the current one.
//
// Provenance only. No consensus rule may branch on this list: a payload is judged against
// the digest the chain carries, so that two builds whose lists differ still reach the same
// verdict on the same block. Reused here only to hold the two halves of one build to the
// same list -- LoadPrivacyVNextAbiInfo refuses a build whose C++ and Rust lists disagree.
//
// e65eaaa6: operation 8 was written into the contract text and operation 9 was added.
// f0259ccc: the parameter-digest acceptance rule was written down as the chain's own.
static const char* const PROTOCOL_CONTRACT_SHA256_PRIOR[] = {
    "e65eaaa660c07e806f5b7e7c9550709929b9c2e9ba4cfd1e4fe56dcd384c9d5f",
    "f0259cccfe96b0665a26b1774e2794222ceb8093d800d886cb1646f760f3710b"
};
static const size_t PROTOCOL_CONTRACT_SHA256_PRIOR_COUNT =
    sizeof(PROTOCOL_CONTRACT_SHA256_PRIOR) /
    sizeof(PROTOCOL_CONTRACT_SHA256_PRIOR[0]);
// SHA-256 of privacy_vnext/rust/provenance.json as compiled into the crate.
// LoadPrivacyVNextAbiInfo refuses a mismatch; update together with the manifest
// (verify_provenance.py checks).
static const char PROVENANCE_SHA256[] =
    "fbbaeb819a9fe4e799e8316673a17a8d74217ef7d46b466febfe094a51a5072e";
// The parameter digest a chain's first IV5 epoch is stamped with, and the digest a
// payload is judged against below that epoch.
//
// Consensus, not provenance. Nothing earlier exists to inherit from there, so something
// must choose; taking the linked contract text's hash would make the choice a property
// of the binary and Boundary B a flag day. Not equal to any contract text's hash --
// sha256("Innova/IV5/GenesisParameterDigest/v1" || the contract digest at pin time) --
// so the chain's value and a build's own are never confusable.
//
// Boundary B is unset on mainnet and testnet, so no chain has stamped a first IV5 epoch
// yet. Once one has, editing this line is a fork.
static const char GENESIS_PARAMETER_DIGEST_SHA256[] =
    "e34a1abae989c66e6d06906a83e419adac4ba04dc0a5dd7804a52fdad9df0387";
static const uint16_t PROTOCOL_SCHEMA = 1;
static const unsigned char ENVELOPE_MARKER[5] = {
    0xff, 0x49, 0x56, 0x35, 0x50
};
static const uint32_t MAX_PAYLOAD_BYTES = 262144;
static const uint8_t TREE_LAYERS = 8;
static const uint8_t PRE_BENCHMARK_MAX_INPUTS = 16;
static const uint8_t PRE_BENCHMARK_MAX_OUTPUTS = 16;
static const uint8_t NULLSEND_MIN_PARTICIPANTS = 2;
static const uint8_t NULLSEND_MAX_PARTICIPANTS = 16;

enum NoteOperation
{
    NOTE_SHIELD = 0,
    NOTE_UNSHIELD = 1,
    NOTE_TRANSFER = 2,
    NOTE_NULLSEND = 3,
    NOTE_DELEGATION_CREATE = 4,
    NOTE_M_OF_N_MINT = 5,
    NOTE_RECLAIM = 6,
    NOTE_CONDITIONAL_MIGRATION = 7,
    NOTE_COLLATERAL_REGISTER = 8,
    // Collateral attestation plus the key other voters seal tally shares to. A separate
    // operation because an operation code fixes its own layout.
    NOTE_FINALITY_MEMBER_REGISTER = 9,
    NOTE_OPERATION_NONE = 255
};

// Compressed secp256k1 encoding length of a committee member's tally-encryption key.
static const size_t FINALITY_MEMBER_KEY_BYTES = 33;

// Operations that name a hidden note without consuming it.
inline bool IsAttestationOperation(uint8_t operation)
{
    return operation == NOTE_COLLATERAL_REGISTER ||
           operation == NOTE_FINALITY_MEMBER_REGISTER;
}

enum FinalityProfile
{
    FINALITY_NONE = 0,
    FINALITY_NULLSTAKE_V1 = 1,
    FINALITY_NULLSTAKE_V2 = 2,
    FINALITY_NULLSTAKE_V3 = 3
};

enum AuthorizationMode
{
    AUTH_OWNER = 0,
    AUTH_COLD_STAKER = 1,
    AUTH_M_OF_N_PUBLIC_SIGNERS = 2,
    AUTH_M_OF_N_HIDDEN_SIGNERS = 3
};

enum FinalityObject
{
    FINALITY_OBJECT_NONE = 0,
    FINALITY_OBJECT_VOTE = 1,
    FINALITY_OBJECT_TALLY_SHARE = 2,
    FINALITY_OBJECT_CERTIFICATE = 3,
    FINALITY_OBJECT_COMMITTEE_ROTATION = 4
};

static const uint8_t DISCLOSURE_HIDE_SENDER = 1;
static const uint8_t DISCLOSURE_HIDE_RECEIVER = 2;
static const uint8_t DISCLOSURE_HIDE_AMOUNT = 4;
static const uint8_t DISCLOSURE_MASK = 7;
static const uint8_t WALLET_DEFAULT_DISCLOSURE_MASK = 7;

inline bool IsKnownNoteOperation(uint8_t operation)
{
    return operation <= NOTE_FINALITY_MEMBER_REGISTER ||
           operation == NOTE_OPERATION_NONE;
}

// Read the declared operation and mask from the fixed header. Not a decoder; consensus
// acts only on the Rust decoder's output.
inline bool ReadDeclaredEnvelope(const unsigned char* payload, size_t nSize,
                                 uint8_t& operationOut, uint8_t& disclosureMaskOut)
{
    static const size_t HEADER_BYTES = 9;
    if (payload == 0 || nSize < HEADER_BYTES)
        return false;
    const uint16_t schema =
        (uint16_t)payload[0] | ((uint16_t)payload[1] << 8);
    if (schema != PROTOCOL_SCHEMA || payload[5] > DISCLOSURE_MASK ||
        !IsKnownNoteOperation(payload[2]))
        return false;
    operationOut = payload[2];
    disclosureMaskOut = payload[5];
    return true;
}

inline bool IsKnownTypedContract(uint8_t operation, uint8_t profile,
                                 uint8_t authorization,
                                 uint8_t finalityObject,
                                 uint8_t disclosureMask)
{
    if (!IsKnownNoteOperation(operation) ||
        profile > FINALITY_NULLSTAKE_V3 ||
        authorization > AUTH_M_OF_N_HIDDEN_SIGNERS ||
        finalityObject > FINALITY_OBJECT_COMMITTEE_ROTATION ||
        disclosureMask > DISCLOSURE_MASK)
        return false;
    const bool fFinality = finalityObject != FINALITY_OBJECT_NONE;
    if (fFinality)
        return operation == NOTE_OPERATION_NONE && profile != FINALITY_NONE;
    return operation != NOTE_OPERATION_NONE && profile == FINALITY_NONE;
}

inline bool EnvelopeAllows(int wireVersion, uint8_t operation,
                           uint8_t profile, uint8_t authorization,
                           uint8_t finalityObject,
                           uint8_t disclosureMask)
{
    if (!IsKnownTypedContract(operation, profile, authorization,
                              finalityObject, disclosureMask))
        return false;
    switch (wireVersion)
    {
    case 2000:
        return (operation == NOTE_SHIELD || operation == NOTE_UNSHIELD ||
                operation == NOTE_TRANSFER) &&
               disclosureMask == 7 && authorization == AUTH_OWNER;
    case 2001:
        return (operation == NOTE_SHIELD || operation == NOTE_UNSHIELD ||
                operation == NOTE_TRANSFER) && authorization == AUTH_OWNER;
    case 2002:
        return (operation == NOTE_TRANSFER || operation == NOTE_NULLSEND) &&
               authorization == AUTH_OWNER;
    case 2003:
        return profile == FINALITY_NULLSTAKE_V1 &&
               authorization == AUTH_OWNER;
    case 2004:
        return profile == FINALITY_NULLSTAKE_V2 &&
               authorization == AUTH_OWNER;
    case 2005:
        return (profile == FINALITY_NULLSTAKE_V3 ||
                operation == NOTE_DELEGATION_CREATE);
    case 2006:
        return operation == NOTE_M_OF_N_MINT &&
               (authorization == AUTH_M_OF_N_PUBLIC_SIGNERS ||
                authorization == AUTH_M_OF_N_HIDDEN_SIGNERS);
    case 2007:
        return operation == NOTE_RECLAIM && authorization == AUTH_OWNER;
    case 2008:
        // An attestation publishes a persistent per-node pseudonym by design; the rest of
        // the note must stay hidden, so the fully private mask is the only one allowed and
        // the sender authority a lower mask would publish never exists.
        return !IsAttestationOperation(operation) ||
               (disclosureMask == DISCLOSURE_MASK && authorization == AUTH_OWNER);
    default:
        return false;
    }
}

// Whether a hex digest names a contract text this build's lineage published.
//
// Provenance reporting only -- never a validity test. See PROTOCOL_CONTRACT_SHA256_PRIOR.
inline bool IsAcceptedContractDigestHex(const char* pszDigest)
{
    if (pszDigest == 0)
        return false;
    if (strcmp(pszDigest, PROTOCOL_CONTRACT_SHA256) == 0)
        return true;
    for (size_t i = 0; i < PROTOCOL_CONTRACT_SHA256_PRIOR_COUNT; ++i)
        if (strcmp(pszDigest, PROTOCOL_CONTRACT_SHA256_PRIOR[i]) == 0)
            return true;
    return false;
}

// Decode a 64-character lowercase hex digest into 32 bytes. False on anything else.
inline bool DecodeDigestHex(const char* pszHex, unsigned char* pOut)
{
    if (pszHex == 0 || pOut == 0 || strlen(pszHex) != 64)
        return false;
    for (size_t i = 0; i < 32; ++i)
    {
        unsigned int nByte = 0;
        for (size_t nNibble = 0; nNibble < 2; ++nNibble)
        {
            const char c = pszHex[i * 2 + nNibble];
            unsigned int nValue;
            if (c >= '0' && c <= '9')
                nValue = (unsigned int)(c - '0');
            else if (c >= 'a' && c <= 'f')
                nValue = (unsigned int)(c - 'a') + 10;
            else
                return false;
            nByte = (nByte << 4) | nValue;
        }
        pOut[i] = (unsigned char)nByte;
    }
    return true;
}
} // namespace iv5

#endif // INN_IV5_PROTOCOL_H
