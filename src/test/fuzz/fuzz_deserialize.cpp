// Copyright (c) 2019-2026 The Innova developers
// Fuzz target: network/consensus envelope deserialization.
// The first byte selects an object type; the remainder is its wire payload.

#include "bulletproof_ac.h"
#include "curvetree.h"
#include "finality.h"
#include "main.h"
#include "nullstake.h"
#include "serialize.h"
#include "zkproof.h"

#include <cstdint>
#include <cstddef>
#include <vector>

#ifdef INNOVA_FUZZ_STANDALONE
// CTransaction's legacy default constructor samples adjusted network time.
// Deserialization immediately overwrites nTime, so the standalone fuzz binary
// can use a deterministic stub instead of linking the node's runtime globals.
int64_t GetAdjustedTime()
{
    return 0;
}
#endif

namespace
{

// Large enough for a certificate carrying FINALITY_MAX_VOTES in both bounded
// vectors, while still preventing the fuzzer from turning one input into an
// unbounded allocation request.
static const size_t FUZZ_DESERIALIZE_MAX_INPUT_SIZE = 1024 * 1024;

template <typename T>
bool TryDeserializeEnvelope(const uint8_t* data, size_t size)
{
    try
    {
        const std::vector<unsigned char> bytes(data, data + size);
        CDataStream ss(bytes, SER_NETWORK, PROTOCOL_VERSION);
        T value;
        ss >> value;

        // Deliberately do not require exact stream consumption. Several active
        // v5 envelopes historically accept bounded trailing bytes.
        return true;
    }
    catch (const std::exception&)
    {
        return false;
    }
    catch (...)
    {
        return false;
    }
}

enum DeserializeTarget
{
    DESERIALIZE_TRANSACTION = 0,
    DESERIALIZE_BLOCK,
    DESERIALIZE_FINALITY_VOTE,
    DESERIALIZE_CANONICAL_FINALITY_VOTE,
    DESERIALIZE_FINALITY_TALLY_SHARE,
    DESERIALIZE_FINALITY_AGGREGATE_PARTIAL,
    DESERIALIZE_FINALITY_CERTIFICATE,
    DESERIALIZE_CANONICAL_FINALITY_CERTIFICATE,
    DESERIALIZE_PRIVATE_FINALITY_PROOF,
    DESERIALIZE_FCMP_PROOF,
    DESERIALIZE_BULLETPROOF_RANGE,
    DESERIALIZE_BULLETPROOF_AC,
    DESERIALIZE_NULLSTAKE_V1,
    DESERIALIZE_NULLSTAKE_V2,
    DESERIALIZE_NULLSTAKE_V3,
    DESERIALIZE_NULLSTAKE_RECLAIM,
    DESERIALIZE_NULLSTAKE_HIDDEN_AUTH,
    DESERIALIZE_TARGET_COUNT
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > FUZZ_DESERIALIZE_MAX_INPUT_SIZE)
        return 0;

    const unsigned int target = data[0] % DESERIALIZE_TARGET_COUNT;
    const uint8_t* payload = data + 1;
    const size_t payloadSize = size - 1;

    switch (target)
    {
    case DESERIALIZE_TRANSACTION:
        (void)TryDeserializeEnvelope<CTransaction>(payload, payloadSize);
        break;
    case DESERIALIZE_BLOCK:
        (void)TryDeserializeEnvelope<CBlock>(payload, payloadSize);
        break;
    case DESERIALIZE_FINALITY_VOTE:
        (void)TryDeserializeEnvelope<CFinalityVote>(payload, payloadSize);
        break;
    case DESERIALIZE_CANONICAL_FINALITY_VOTE:
        (void)TryDeserializeEnvelope<CCanonicalFinalityVoteEnvelope>(payload, payloadSize);
        break;
    case DESERIALIZE_FINALITY_TALLY_SHARE:
        (void)TryDeserializeEnvelope<CFinalityTallyShare>(payload, payloadSize);
        break;
    case DESERIALIZE_FINALITY_AGGREGATE_PARTIAL:
        (void)TryDeserializeEnvelope<CFinalityTallyAggregatePartial>(payload, payloadSize);
        break;
    case DESERIALIZE_FINALITY_CERTIFICATE:
        (void)TryDeserializeEnvelope<CFinalityTallyCertificate>(payload, payloadSize);
        break;
    case DESERIALIZE_CANONICAL_FINALITY_CERTIFICATE:
        (void)TryDeserializeEnvelope<CCanonicalFinalityTallyCertificateEnvelope>(payload, payloadSize);
        break;
    case DESERIALIZE_PRIVATE_FINALITY_PROOF:
        (void)TryDeserializeEnvelope<CPrivateFinalityVoteProof>(payload, payloadSize);
        break;
    case DESERIALIZE_FCMP_PROOF:
        (void)TryDeserializeEnvelope<CFCMPProof>(payload, payloadSize);
        break;
    case DESERIALIZE_BULLETPROOF_RANGE:
        (void)TryDeserializeEnvelope<CBulletproofRangeProof>(payload, payloadSize);
        break;
    case DESERIALIZE_BULLETPROOF_AC:
        (void)TryDeserializeEnvelope<CBulletproofACProof>(payload, payloadSize);
        break;
    case DESERIALIZE_NULLSTAKE_V1:
        (void)TryDeserializeEnvelope<CNullStakeKernelProof>(payload, payloadSize);
        break;
    case DESERIALIZE_NULLSTAKE_V2:
        (void)TryDeserializeEnvelope<CNullStakeKernelProofV2>(payload, payloadSize);
        break;
    case DESERIALIZE_NULLSTAKE_V3:
        (void)TryDeserializeEnvelope<CNullStakeKernelProofV3>(payload, payloadSize);
        break;
    case DESERIALIZE_NULLSTAKE_RECLAIM:
        (void)TryDeserializeEnvelope<CNullStakeReclaimAuth>(payload, payloadSize);
        break;
    case DESERIALIZE_NULLSTAKE_HIDDEN_AUTH:
        (void)TryDeserializeEnvelope<CNullStakeMofNHiddenAuthProof>(payload, payloadSize);
        break;
    }

    return 0;
}
