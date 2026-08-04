// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license.

#ifndef INN_IV5_PROTOCOL_H
#define INN_IV5_PROTOCOL_H

#include <stdint.h>

namespace iv5
{
static const char PROTOCOL_CONTRACT_SHA256[] =
    "5d8a31e5bb98a76ca894234558a8449ca9161dfa895854c2a8aabd2ea30cd1c1";
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
    NOTE_OPERATION_NONE = 255
};

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
    return operation <= NOTE_CONDITIONAL_MIGRATION || operation == NOTE_OPERATION_NONE;
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
        return true;
    default:
        return false;
    }
}
} // namespace iv5

#endif // INN_IV5_PROTOCOL_H
