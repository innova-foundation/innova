// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license.

#ifndef INN_PRIVACY_VNEXT_FFI_H
#define INN_PRIVACY_VNEXT_FFI_H

#include <stdint.h>
#include <array>
#include <string>
#include <vector>

struct PrivacyVNextAbiInfo
{
    bool fLinked;
    uint32_t nAbiVersion;
    uint32_t nTransactionVersion;
    uint32_t nConsensusActive;
    uint32_t nTreeLayers;
    uint32_t nMaxInputs;
    uint32_t nMaxOutputs;
    uint32_t nMaxPayloadBytes;
    uint32_t nPayloadSchema;
    uint32_t nImplementedCapabilities;
    uint32_t nConsensusCapabilities;
    std::string strAbiSha256;
    std::string strParameterDigest;
    std::string strProvenanceDigest;
    std::string strUpstreamRevision;
    std::string strError;

    PrivacyVNextAbiInfo();
};

// Reads and cross-checks the statically linked Rust ABI. A false result is a
// local fail-closed condition and must never be attributed to peer input.
bool LoadPrivacyVNextAbiInfo(PrivacyVNextAbiInfo& info);

struct PrivacyVNextEpochSeed
{
    std::vector<unsigned char> vchTreeState;
    std::vector<unsigned char> vchRoot;
    std::vector<unsigned char> vchNullifierState;
    std::vector<unsigned char> vchNullifierRoot;
    std::vector<unsigned char> vchParameterDigest;
    uint64_t nTreeSize;
    uint64_t nNullifierCount;

    PrivacyVNextEpochSeed() : nTreeSize(0), nNullifierCount(0) {}
};

// Builds the canonical empty eight-layer accumulator and reads its parameter
// digest from the linked Rust implementation. Failure is local and fail closed.
bool LoadPrivacyVNextEpochSeed(PrivacyVNextEpochSeed& seed,
                               std::string& error);

// Recomputes root and size from one persisted Rust frontier. This is used by
// restart and write-time checks so corrupted local state is never peer blame.
bool DecodePrivacyVNextTreeState(
    const std::vector<unsigned char>& state,
    std::vector<unsigned char>& root,
    uint64_t& treeSize,
    std::string& error);

bool DecodePrivacyVNextNullifierState(
    const std::vector<unsigned char>& state,
    std::vector<unsigned char>& root,
    uint64_t& nullifierCount,
    std::string& error);

struct PrivacyVNextPayloadValidation
{
    int32_t nResult;
    bool fLocalFailure;
    std::string strError;

    PrivacyVNextPayloadValidation()
        : nResult(6), fLocalFailure(true) {}
    bool IsValid() const { return nResult == 0; }
};

// Validates outer-version binding and canonical payload shape. Proof
// verification remains a separate contextual ABI operation.
PrivacyVNextPayloadValidation ValidatePrivacyVNextPayload(
    uint32_t wireVersion,
    const std::vector<unsigned char>& payload);

typedef std::array<unsigned char, 32> PrivacyVNextDigest;

struct PrivacyVNextOutputLeaf
{
    PrivacyVNextDigest owner;
    PrivacyVNextDigest nullifierBase;
    PrivacyVNextDigest commitment;
};

struct PrivacyVNextStateEffects
{
    PrivacyVNextDigest finalizedRoot;
    uint64_t nFinalizedTreeSize;
    PrivacyVNextDigest parameterDigest;
    std::vector<PrivacyVNextDigest> keyImages;
    std::vector<PrivacyVNextOutputLeaf> outputLeaves;

    PrivacyVNextStateEffects() : nFinalizedTreeSize(0)
    {
        finalizedRoot.fill(0);
        parameterDigest.fill(0);
    }
};

bool ApplyPrivacyVNextOutputLeaves(
    const std::vector<unsigned char>& currentState,
    const std::vector<PrivacyVNextOutputLeaf>& leaves,
    std::vector<unsigned char>& nextState,
    std::vector<unsigned char>& nextRoot,
    uint64_t& nextSize,
    std::string& error);

bool ApplyPrivacyVNextNullifiers(
    const std::vector<unsigned char>& currentState,
    const std::vector<PrivacyVNextDigest>& keyImages,
    std::vector<unsigned char>& nextState,
    std::vector<unsigned char>& nextRoot,
    uint64_t& nextCount,
    std::string& error);

// Rust performs complete payload/proof validation before returning this frame.
// A malformed frame after successful validation is local state failure.
PrivacyVNextPayloadValidation ExtractPrivacyVNextPayloadEffects(
    uint32_t wireVersion,
    const std::vector<unsigned char>& payload,
    PrivacyVNextStateEffects& effects);

struct PrivacyVNextDerivedKeys
{
    uint8_t nNetwork;
    uint8_t nAddressType;
    uint32_t nIndex;
    PrivacyVNextDigest spendSecret;
    PrivacyVNextDigest viewSecret;
    PrivacyVNextDigest outgoingViewSecret;
    PrivacyVNextDigest nullifierSecret;
    PrivacyVNextDigest stakingSecret;
    PrivacyVNextDigest spendPublic;
    PrivacyVNextDigest viewPublic;

    PrivacyVNextDerivedKeys();
    ~PrivacyVNextDerivedKeys();
    void Clear();

private:
    PrivacyVNextDerivedKeys(const PrivacyVNextDerivedKeys&) = delete;
    PrivacyVNextDerivedKeys& operator=(const PrivacyVNextDerivedKeys&) = delete;
};

struct PrivacyVNextAddressComponents
{
    uint8_t nNetwork;
    uint8_t nAddressType;
    PrivacyVNextDigest spendPublic;
    PrivacyVNextDigest viewPublic;

    PrivacyVNextAddressComponents()
        : nNetwork(0), nAddressType(0)
    {
        spendPublic.fill(0);
        viewPublic.fill(0);
    }
};

// These helpers expose the strict Rust-owned IV5 derivation and address codec
// to C++ wallet code. They do not persist secrets or activate consensus.
bool DerivePrivacyVNextKeys(
    const PrivacyVNextDigest& seed,
    const PrivacyVNextDigest& genesis,
    uint32_t index,
    uint8_t network,
    uint8_t addressType,
    PrivacyVNextDerivedKeys& keys,
    std::string& error);

bool EncodePrivacyVNextAddress(
    const PrivacyVNextAddressComponents& components,
    std::string& address,
    std::string& error);

bool DecodePrivacyVNextAddress(
    const std::string& address,
    uint8_t expectedNetwork,
    PrivacyVNextAddressComponents& components,
    std::string& error);

#endif // INN_PRIVACY_VNEXT_FFI_H
