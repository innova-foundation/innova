// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see COPYING.
#ifndef INNOVA_NYXAUTH_H
#define INNOVA_NYXAUTH_H

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

static const uint8_t NYX_BODY_SENDER_AUTH = 0x08;
static const uint8_t NYX_SENDER_AUTH_VERSION = 1;
static const size_t NYX_SENDER_AUTH_MAX = 16384;
extern const char NYX_MESSAGE_AUTH_TAG_BASE_DOMAIN[];

struct NyxSenderAuth
{
    uint8_t version;
    uint16_t proofType;
    std::vector<uint8_t> proof;
    NyxSenderAuth() : version(NYX_SENDER_AUTH_VERSION), proofType(0) {}
};

enum NyxAuthTopic { NYX_AUTH_PUBLIC_BUNDLE, NYX_AUTH_OPEN_POSTING };
struct NyxSenderAuthPolicy
{
    int64_t minNoteValue; // atomic units
    uint32_t perEpochLimit; // per note, across required topics
    bool requirePublicBundles;
    bool requireOpenPosting;
    NyxSenderAuthPolicy() : minNoteValue(100000000), perEpochLimit(100),
        requirePublicBundles(true), requireOpenPosting(false) {}
    bool Requires(NyxAuthTopic topic) const
    {
        return topic == NYX_AUTH_PUBLIC_BUNDLE ? requirePublicBundles : requireOpenPosting;
    }
};

// Future verifiers must prove PQ ownership of an UNSPENT note at the bound state,
// minimum value, message binding and an epoch tag with a bounded use index.
struct NyxSenderAuthContext
{
    uint64_t epoch;
    uint32_t useIndex;
    NyxAuthTopic topic;
    uint8_t stateRoot[32];
    uint8_t messageHash[32]; // hash of the unwrapped body
    NyxSenderAuthContext() : epoch(0), useIndex(0), topic(NYX_AUTH_PUBLIC_BUNDLE),
        stateRoot(), messageHash() {}
};
struct NyxSenderAuthProofType
{
    uint16_t type;
    bool postQuantum;
    bool provesUnspent;
    bool (*verify)(const NyxSenderAuth&, const NyxSenderAuthContext&, const NyxSenderAuthPolicy&);
};
// Empty registry in 5.2.0.4. Only PQ, unspent-note proof types may be added here.
const NyxSenderAuthProofType* NyxFindSenderAuthProofType(uint16_t type);
bool NyxVerifySenderAuth(const NyxSenderAuth& auth, const NyxSenderAuthContext& context,
                         const NyxSenderAuthPolicy& policy);
void NyxMessageAuthTagBase(uint64_t epoch, uint8_t out[32]);

// Optional outer body: kind || version || proofType LE16 || proofLen LE32 || proof || body.
// No nesting. Legacy bodies remain byte-identical. Unknown versions carry no authority.
bool NyxWrapSenderAuth(const std::vector<uint8_t>& body, const NyxSenderAuth& auth,
                       std::vector<uint8_t>& out);
bool NyxUnwrapSenderAuth(std::vector<uint8_t>& body, NyxSenderAuth& auth);

extern NyxSenderAuthPolicy nyxSenderAuthPolicy;
bool NyxLoadSenderAuthPolicy(std::string& error);
#endif
