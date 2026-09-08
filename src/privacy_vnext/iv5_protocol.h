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
    "1424a38b5e4351e0ae9fb103b779d3b5b245aaf02d02525d79ad8bb9b3e970d5";
// Contract texts this build's lineage has published, besides the current one.
//
// Provenance only. No consensus rule may branch on this list: a payload is judged against
// the digest the chain carries, so that two builds whose lists differ still reach the same
// verdict on the same block. Reused here only to hold the two halves of one build to the
// same list -- LoadPrivacyVNextAbiInfo refuses a build whose C++ and Rust lists disagree.
//
// e65eaaa6: operation 8 was written into the contract text and operation 9 was added.
// 4313419b: the vote membership prover began reporting r_i and r_r_i, widening its FFI
// response record. That record is prover-side construction material, never a consensus
// payload, so no rule moved and no payload's verdict changes.
// f0259ccc: the parameter-digest acceptance rule was written down as the chain's own, and
// the text still declared all four authorization modes on 2005 and 2008 after the decoders
// were narrowed to owner. The digest selects no rule, so a payload carrying it is judged by
// the narrowed table like any other.
// 07c5f16b: the effects trailer began reporting the boundary a note finality vote names. The
// trailer is the decoder's answer to this binary, never a consensus payload, so no rule
// moved and no payload's verdict changes.
// b796ba76: a note finality vote gained its stake-floor rule and the floor itself. This one
// DOES move a rule: a vote that proves no floor, or proves it against an unshifted point, is
// refused from the same height the lane activates, and the lane has never been active.
static const char* const PROTOCOL_CONTRACT_SHA256_PRIOR[] = {
    "e65eaaa660c07e806f5b7e7c9550709929b9c2e9ba4cfd1e4fe56dcd384c9d5f",
    "f0259cccfe96b0665a26b1774e2794222ceb8093d800d886cb1646f760f3710b",
    "4313419b351b5c9ba6a25bb94c5bf2b317843d238d2376b5cc181dfb6146a280",
    "07c5f16b0da26d5f201a24039dc7eb0c00b4ff57d161ed6c7896586cc50163f1",
    "b796ba76b3a95bd96e36c7e1255c6deae410675692de7e7eaaff1b4d1f70a2a7"
};
static const size_t PROTOCOL_CONTRACT_SHA256_PRIOR_COUNT =
    sizeof(PROTOCOL_CONTRACT_SHA256_PRIOR) /
    sizeof(PROTOCOL_CONTRACT_SHA256_PRIOR[0]);
// SHA-256 of privacy_vnext/rust/provenance.json as compiled into the crate.
// LoadPrivacyVNextAbiInfo refuses a mismatch; update together with the manifest
// (verify_provenance.py checks).
static const char PROVENANCE_SHA256[] =
    "7a1548f58ef09da64be0515201d55793a6f5049bea690e5a934087e5ef772558";
// The parameter digest a chain's first IV5 epoch is stamped with, and the digest a
// payload is judged against below that epoch.
//
// Consensus, not provenance. Nothing earlier exists to inherit from there, so something
// must choose; taking the linked contract text's hash would make the choice a property
// of the binary and Boundary B a flag day.
//
// FROZEN. It was derived once, as sha256("Innova/IV5/GenesisParameterDigest/v1" || a
// contract digest), only to land on a value provably unequal to any contract text's hash.
// The derivation is spent: it is now an opaque constant and must NOT be re-derived when
// the contract text changes. Re-deriving it forks every chain that has stamped an epoch.
// genesis_parameter_digest_is_frozen pins the literal so an edit fails rather than forks.
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
    // Spends one note as a finality vote for an epoch boundary and reissues its value to
    // one fresh output. The key image goes to the spent-key index, never the watch set.
    NOTE_FINALITY_VOTE = 10,
    NOTE_OPERATION_NONE = 255
};

// Minimum note value for a finality vote. Mirrors NOTE_VOTE_MIN_WEIGHT in the Rust
// crate; a new rung moves both under a new wire version.
static const int64_t NOTE_VOTE_MIN_WEIGHT = 500LL * 100000000LL;

// Compressed secp256k1 encoding length of a committee member's tally-encryption key.
static const size_t FINALITY_MEMBER_KEY_BYTES = 33;
// The two fields a note finality vote carries after its outputs: boundary block hash (32)
// and boundary height (u32 LE).
static const size_t FINALITY_VOTE_CONTEXT_BYTES = 32 + 4;

// Operations that name a hidden note without consuming it.
inline bool IsAttestationOperation(uint8_t operation)
{
    return operation == NOTE_COLLATERAL_REGISTER ||
           operation == NOTE_FINALITY_MEMBER_REGISTER;
}

// The one operation that spends a note as a finality vote. Not an attestation: it
// consumes the note it names.
inline bool IsNoteFinalityVoteOperation(uint8_t operation)
{
    return operation == NOTE_FINALITY_VOTE;
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

// The only mask a coinbase fee note may carry: amount disclosed (it equals the block's
// published IV5 fee sum), producer address hidden. Fixed by consensus so the shape is
// not a per-producer fingerprint.
static const uint8_t COINBASE_FEE_NOTE_DISCLOSURE_MASK =
    (uint8_t)(DISCLOSURE_HIDE_SENDER | DISCLOSURE_HIDE_RECEIVER);

inline bool IsKnownNoteOperation(uint8_t operation)
{
    return operation <= NOTE_FINALITY_VOTE ||
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

// Whether a coinbase IV5 payload declares the fee-note envelope. Checked before proofs
// so the error names the header field.
inline bool CoinbaseFeeNoteEnvelopeAllows(const unsigned char* payload, size_t nSize,
                                          uint8_t& disclosureMaskOut)
{
    uint8_t operation = 0;
    disclosureMaskOut = 0;
    return ReadDeclaredEnvelope(payload, nSize, operation, disclosureMaskOut) &&
           disclosureMaskOut == COINBASE_FEE_NOTE_DISCLOSURE_MASK;
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
                operation == NOTE_DELEGATION_CREATE) &&
               authorization == AUTH_OWNER;
    case 2006:
        return operation == NOTE_M_OF_N_MINT &&
               (authorization == AUTH_M_OF_N_PUBLIC_SIGNERS ||
                authorization == AUTH_M_OF_N_HIDDEN_SIGNERS);
    case 2007:
        return operation == NOTE_RECLAIM && authorization == AUTH_OWNER;
    case 2008:
        // Only owner authorization is enforced by any proof. Attestations and note votes must
        // be fully private: any disclosure would link a node or voter across epochs.
        return authorization == AUTH_OWNER &&
               (!(IsAttestationOperation(operation) ||
                  IsNoteFinalityVoteOperation(operation)) ||
                disclosureMask == DISCLOSURE_MASK);
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
