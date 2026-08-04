// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license.

#include "privacy_vnext_ffi.h"

#include "privacy_vnext/iv5_protocol.h"
#include "privacy_vnext/rust/include/innova_privacy_vnext.h"

#include <openssl/crypto.h>

#include <cstring>
#include <stdexcept>   // std::runtime_error; not transitively included by libstdc++

namespace
{
std::string HexDigest(const uint8_t* bytes, size_t size)
{
    static const char hex[] = "0123456789abcdef";
    std::string result(size * 2, '0');
    for (size_t i = 0; i < size; ++i)
    {
        result[2 * i] = hex[bytes[i] >> 4];
        result[2 * i + 1] = hex[bytes[i] & 0x0f];
    }
    return result;
}

bool ReadDigest(int32_t (*reader)(uint8_t*, size_t),
                std::string& digest, std::string& error,
                const char* field)
{
    uint8_t bytes[INNOVA_PRIVACY_VNEXT_DIGEST_SIZE] = {0};
    const int32_t result = reader(bytes, sizeof(bytes));
    if (result != INNOVA_PRIVACY_VNEXT_VALID)
    {
        error = std::string(field) + " returned result " +
                std::to_string(result);
        return false;
    }
    digest = HexDigest(bytes, sizeof(bytes));
    return true;
}

bool Fail(PrivacyVNextAbiInfo& info, const std::string& error)
{
    info.fLinked = false;
    info.strError = error;
    return false;
}

uint32_t ReadLE32(const uint8_t* bytes)
{
    uint32_t value = 0;
    for (size_t i = 0; i < 4; ++i)
        value |= static_cast<uint32_t>(bytes[i]) << (8 * i);
    return value;
}

void PutLE32(uint8_t* bytes, uint32_t value)
{
    for (size_t i = 0; i < 4; ++i)
        bytes[i] = static_cast<uint8_t>(value >> (8 * i));
}

uint64_t ReadLE64(const uint8_t* bytes)
{
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i)
        value |= static_cast<uint64_t>(bytes[i]) << (8 * i);
    return value;
}

void PutLE64(uint8_t* bytes, uint64_t value)
{
    for (size_t i = 0; i < 8; ++i)
        bytes[i] = static_cast<uint8_t>(value >> (8 * i));
}

std::string ResultError(const char* operation, int32_t result)
{
    return std::string(operation) + " returned result " +
           std::to_string(result);
}
} // namespace

PrivacyVNextDerivedKeys::PrivacyVNextDerivedKeys()
    : nNetwork(0), nAddressType(0), nIndex(0)
{
    spendSecret.fill(0);
    viewSecret.fill(0);
    outgoingViewSecret.fill(0);
    nullifierSecret.fill(0);
    stakingSecret.fill(0);
    spendPublic.fill(0);
    viewPublic.fill(0);
}

PrivacyVNextDerivedKeys::~PrivacyVNextDerivedKeys()
{
    Clear();
}

void PrivacyVNextDerivedKeys::Clear()
{
    OPENSSL_cleanse(spendSecret.data(), spendSecret.size());
    OPENSSL_cleanse(viewSecret.data(), viewSecret.size());
    OPENSSL_cleanse(outgoingViewSecret.data(), outgoingViewSecret.size());
    OPENSSL_cleanse(nullifierSecret.data(), nullifierSecret.size());
    OPENSSL_cleanse(stakingSecret.data(), stakingSecret.size());
    spendPublic.fill(0);
    viewPublic.fill(0);
    nNetwork = 0;
    nAddressType = 0;
    nIndex = 0;
}

bool DerivePrivacyVNextKeys(
    const PrivacyVNextDigest& seed,
    const PrivacyVNextDigest& genesis,
    uint32_t index,
    uint8_t network,
    uint8_t addressType,
    PrivacyVNextDerivedKeys& keys,
    std::string& error)
{
    keys.Clear();
    error.clear();

    std::array<uint8_t, INNOVA_PRIVACY_VNEXT_KEY_DERIVATION_REQUEST_SIZE>
        request = {};
    request[0] = static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA);
    request[1] = 0;
    request[2] = network;
    request[3] = addressType;
    PutLE32(request.data() + 4, index);
    std::memcpy(request.data() + 8, seed.data(), seed.size());
    std::memcpy(request.data() + 40, genesis.data(), genesis.size());

    std::array<uint8_t, INNOVA_PRIVACY_VNEXT_KEY_DERIVATION_OUTPUT_SIZE>
        response = {};
    size_t written = 0;
    const int32_t result = innova_privacy_vnext_key_derive(
        request.data(), request.size(), response.data(), response.size(),
        &written);
    OPENSSL_cleanse(request.data(), request.size());
    if (result != INNOVA_PRIVACY_VNEXT_VALID)
    {
        OPENSSL_cleanse(response.data(), response.size());
        error = ResultError("IV5 key derivation", result);
        return false;
    }
    if (written != response.size() ||
        response[0] != static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA) ||
        response[1] != 0 || response[2] != network ||
        response[3] != addressType || ReadLE32(response.data() + 4) != index)
    {
        OPENSSL_cleanse(response.data(), response.size());
        error = "non-canonical IV5 key-derivation response";
        return false;
    }

    keys.nNetwork = network;
    keys.nAddressType = addressType;
    keys.nIndex = index;
    std::memcpy(keys.spendSecret.data(), response.data() + 8, 32);
    std::memcpy(keys.viewSecret.data(), response.data() + 40, 32);
    std::memcpy(keys.outgoingViewSecret.data(), response.data() + 72, 32);
    std::memcpy(keys.nullifierSecret.data(), response.data() + 104, 32);
    std::memcpy(keys.stakingSecret.data(), response.data() + 136, 32);
    std::memcpy(keys.spendPublic.data(), response.data() + 168, 32);
    std::memcpy(keys.viewPublic.data(), response.data() + 200, 32);
    OPENSSL_cleanse(response.data(), response.size());
    return true;
}

bool EncodePrivacyVNextAddress(
    const PrivacyVNextAddressComponents& components,
    std::string& address,
    std::string& error)
{
    address.clear();
    error.clear();

    std::array<uint8_t, INNOVA_PRIVACY_VNEXT_ADDRESS_COMPONENT_SIZE> request = {};
    request[0] = static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA);
    request[1] = 0;
    request[2] = components.nNetwork;
    request[3] = INNOVA_PRIVACY_VNEXT_ADDRESS_FORMAT;
    request[4] = components.nAddressType;
    request[5] = 0;
    std::memcpy(request.data() + 6, components.spendPublic.data(), 32);
    std::memcpy(request.data() + 38, components.viewPublic.data(), 32);

    std::array<uint8_t, 128> encoded = {};
    size_t written = 0;
    const int32_t result = innova_privacy_vnext_address_encode(
        request.data(), request.size(), encoded.data(), encoded.size(),
        &written);
    if (result != INNOVA_PRIVACY_VNEXT_VALID)
    {
        error = ResultError("IV5 address encoding", result);
        return false;
    }
    if (written == 0 || written > encoded.size())
    {
        error = "non-canonical IV5 address-encoding response";
        return false;
    }
    address.assign(reinterpret_cast<const char*>(encoded.data()), written);
    return true;
}

bool DecodePrivacyVNextAddress(
    const std::string& address,
    uint8_t expectedNetwork,
    PrivacyVNextAddressComponents& components,
    std::string& error)
{
    components = PrivacyVNextAddressComponents();
    error.clear();
    if (address.empty() || address.size() > 128)
    {
        error = "invalid IV5 address length";
        return false;
    }

    std::vector<uint8_t> request;
    request.reserve(4 + address.size());
    request.push_back(static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA));
    request.push_back(0);
    request.push_back(expectedNetwork);
    request.push_back(0);
    request.insert(request.end(), address.begin(), address.end());

    std::array<uint8_t, INNOVA_PRIVACY_VNEXT_ADDRESS_COMPONENT_SIZE> decoded = {};
    size_t written = 0;
    const int32_t result = innova_privacy_vnext_address_decode(
        request.data(), request.size(), decoded.data(), decoded.size(),
        &written);
    if (result != INNOVA_PRIVACY_VNEXT_VALID)
    {
        error = ResultError("IV5 address decoding", result);
        return false;
    }
    if (written != decoded.size() ||
        decoded[0] != static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA) ||
        decoded[1] != 0 || decoded[2] != expectedNetwork ||
        decoded[3] != INNOVA_PRIVACY_VNEXT_ADDRESS_FORMAT || decoded[5] != 0)
    {
        error = "non-canonical IV5 address-decoding response";
        return false;
    }

    components.nNetwork = decoded[2];
    components.nAddressType = decoded[4];
    std::memcpy(components.spendPublic.data(), decoded.data() + 6, 32);
    std::memcpy(components.viewPublic.data(), decoded.data() + 38, 32);
    return true;
}

PrivacyVNextAbiInfo::PrivacyVNextAbiInfo()
    : fLinked(false),
      nAbiVersion(0),
      nTransactionVersion(0),
      nConsensusActive(0),
      nTreeLayers(0),
      nMaxInputs(0),
      nMaxOutputs(0),
      nMaxPayloadBytes(0),
      nPayloadSchema(0),
      nImplementedCapabilities(0),
      nConsensusCapabilities(0)
{
}

bool LoadPrivacyVNextAbiInfo(PrivacyVNextAbiInfo& info)
{
    info = PrivacyVNextAbiInfo();

    uint32_t abiVersion = 0;
    int32_t result = innova_privacy_vnext_abi_version(&abiVersion);
    if (result != INNOVA_PRIVACY_VNEXT_VALID)
        return Fail(info, "ABI version query returned result " +
                          std::to_string(result));
    if (abiVersion != INNOVA_PRIVACY_VNEXT_ABI_VERSION)
        return Fail(info, "Rust/C ABI version mismatch");

    innova_privacy_vnext_contract contract;
    std::memset(&contract, 0, sizeof(contract));
    result = innova_privacy_vnext_contract_metadata(&contract,
                                                     sizeof(contract));
    if (result != INNOVA_PRIVACY_VNEXT_VALID)
        return Fail(info, "contract metadata returned result " +
                          std::to_string(result));
    if (contract.struct_size != sizeof(contract) ||
        contract.abi_version != INNOVA_PRIVACY_VNEXT_ABI_VERSION ||
        contract.transaction_version != 2008 ||
        contract.tree_layers != iv5::TREE_LAYERS ||
        contract.max_payload_bytes != iv5::MAX_PAYLOAD_BYTES ||
        contract.payload_schema != iv5::PROTOCOL_SCHEMA)
        return Fail(info, "Rust/C canonical contract mismatch");
    if ((contract.consensus_capabilities &
         ~contract.implemented_capabilities) != 0)
        return Fail(info, "consensus capability is not implemented");
    if ((contract.consensus_active == 0) !=
        (contract.consensus_capabilities == 0))
        return Fail(info, "consensus activation/capability mismatch");

    std::string error;
    if (!ReadDigest(innova_privacy_vnext_abi_hash, info.strAbiSha256,
                    error, "ABI hash"))
        return Fail(info, error);
    if (!ReadDigest(innova_privacy_vnext_parameter_digest,
                    info.strParameterDigest, error, "parameter digest"))
        return Fail(info, error);
    if (!ReadDigest(innova_privacy_vnext_provenance_digest,
                    info.strProvenanceDigest, error, "provenance digest"))
        return Fail(info, error);
    if (info.strParameterDigest != iv5::PROTOCOL_CONTRACT_SHA256)
        return Fail(info, "Rust/C protocol contract digest mismatch");

    size_t protocolContractSize = 0;
    result = innova_privacy_vnext_protocol_contract(NULL, 0,
                                                     &protocolContractSize);
    if (result != INNOVA_PRIVACY_VNEXT_VALID || protocolContractSize == 0 ||
        protocolContractSize > iv5::MAX_PAYLOAD_BYTES)
        return Fail(info, "normative protocol contract query failed");

    info.nAbiVersion = abiVersion;
    info.nTransactionVersion = contract.transaction_version;
    info.nConsensusActive = contract.consensus_active;
    info.nTreeLayers = contract.tree_layers;
    info.nMaxInputs = contract.max_inputs;
    info.nMaxOutputs = contract.max_outputs;
    info.nMaxPayloadBytes = contract.max_payload_bytes;
    info.nPayloadSchema = contract.payload_schema;
    info.nImplementedCapabilities = contract.implemented_capabilities;
    info.nConsensusCapabilities = contract.consensus_capabilities;
    info.strUpstreamRevision.assign(
        reinterpret_cast<const char*>(contract.upstream_revision),
        INNOVA_PRIVACY_VNEXT_UPSTREAM_REVISION_SIZE);
    info.fLinked = true;
    return true;
}

bool DecodePrivacyVNextTreeState(
    const std::vector<unsigned char>& state,
    std::vector<unsigned char>& root,
    uint64_t& treeSize,
    std::string& error)
{
    root.clear();
    treeSize = 0;
    error.clear();
    if (state.size() != INNOVA_PRIVACY_VNEXT_TREE_STATE_SIZE)
    {
        error = "invalid IV5 tree-state length";
        return false;
    }

    uint8_t encodedRoot[INNOVA_PRIVACY_VNEXT_TREE_ROOT_SIZE] = {0};
    size_t written = 0;
    const int32_t result = innova_privacy_vnext_tree_root(
        &state[0], state.size(), encodedRoot, sizeof(encodedRoot), &written);
    if (result != INNOVA_PRIVACY_VNEXT_VALID || written != sizeof(encodedRoot))
    {
        error = "Rust IV5 tree-root query returned result " +
                std::to_string(result);
        return false;
    }
    if (encodedRoot[0] != 1 || encodedRoot[1] != 0 ||
        encodedRoot[2] != INNOVA_PRIVACY_VNEXT_TREE_LAYERS ||
        encodedRoot[3] != 2)
    {
        error = "non-canonical Rust IV5 tree-root envelope";
        return false;
    }

    for (size_t i = 0; i < sizeof(treeSize); ++i)
        treeSize |= static_cast<uint64_t>(encodedRoot[4 + i]) << (8 * i);
    root.assign(encodedRoot + 12, encodedRoot + sizeof(encodedRoot));
    return true;
}

bool ApplyPrivacyVNextOutputLeaves(
    const std::vector<unsigned char>& currentState,
    const std::vector<PrivacyVNextOutputLeaf>& leaves,
    std::vector<unsigned char>& nextState,
    std::vector<unsigned char>& nextRoot,
    uint64_t& nextSize,
    std::string& error)
{
    nextState.clear();
    nextRoot.clear();
    nextSize = 0;
    error.clear();
    if (currentState.size() != INNOVA_PRIVACY_VNEXT_TREE_STATE_SIZE)
    {
        error = "invalid IV5 current tree-state length";
        return false;
    }
    if (leaves.size() > INNOVA_PRIVACY_VNEXT_MAX_OUTPUTS)
    {
        error = "IV5 output update exceeds ABI limit";
        return false;
    }

    std::vector<uint8_t> request;
    request.reserve(8 + currentState.size() + leaves.size() * 96);
    request.push_back(1);
    request.push_back(0);
    request.push_back(0);
    request.push_back(0);
    request.insert(request.end(), currentState.begin(), currentState.end());
    const uint32_t count = static_cast<uint32_t>(leaves.size());
    for (size_t i = 0; i < 4; ++i)
        request.push_back(static_cast<uint8_t>(count >> (8 * i)));
    for (size_t i = 0; i < leaves.size(); ++i)
    {
        request.insert(request.end(), leaves[i].owner.begin(),
                       leaves[i].owner.end());
        request.insert(request.end(), leaves[i].nullifierBase.begin(),
                       leaves[i].nullifierBase.end());
        request.insert(request.end(), leaves[i].commitment.begin(),
                       leaves[i].commitment.end());
    }

    uint8_t encoded[INNOVA_PRIVACY_VNEXT_TREE_STATE_SIZE] = {0};
    size_t written = 0;
    const int32_t result = innova_privacy_vnext_tree_update(
        &request[0], request.size(), encoded, sizeof(encoded), &written);
    if (result != INNOVA_PRIVACY_VNEXT_VALID || written != sizeof(encoded))
    {
        error = "Rust IV5 tree update returned result " +
                std::to_string(result);
        return false;
    }
    nextState.assign(encoded, encoded + sizeof(encoded));
    return DecodePrivacyVNextTreeState(nextState, nextRoot, nextSize, error);
}

bool DecodePrivacyVNextNullifierState(
    const std::vector<unsigned char>& state,
    std::vector<unsigned char>& root,
    uint64_t& nullifierCount,
    std::string& error)
{
    root.clear();
    nullifierCount = 0;
    error.clear();
    if (state.size() != INNOVA_PRIVACY_VNEXT_NULLIFIER_STATE_SIZE)
    {
        error = "invalid IV5 nullifier-state length";
        return false;
    }

    uint8_t encoded[INNOVA_PRIVACY_VNEXT_NULLIFIER_ROOT_SIZE] = {0};
    size_t written = 0;
    const int32_t result = innova_privacy_vnext_nullifier_root(
        &state[0], state.size(), encoded, sizeof(encoded), &written);
    if (result != INNOVA_PRIVACY_VNEXT_VALID || written != sizeof(encoded))
    {
        error = "Rust IV5 nullifier-root query returned result " +
                std::to_string(result);
        return false;
    }
    if (encoded[0] != 1 || encoded[1] != 0 || encoded[2] != 1 ||
        encoded[3] != 0)
    {
        error = "non-canonical Rust IV5 nullifier-root envelope";
        return false;
    }
    for (size_t i = 0; i < sizeof(nullifierCount); ++i)
        nullifierCount |= static_cast<uint64_t>(encoded[4 + i]) << (8 * i);
    root.assign(encoded + 12, encoded + sizeof(encoded));
    return true;
}

bool ApplyPrivacyVNextNullifiers(
    const std::vector<unsigned char>& currentState,
    const std::vector<PrivacyVNextDigest>& keyImages,
    std::vector<unsigned char>& nextState,
    std::vector<unsigned char>& nextRoot,
    uint64_t& nextCount,
    std::string& error)
{
    nextState.clear();
    nextRoot.clear();
    nextCount = 0;
    error.clear();
    if (currentState.size() != INNOVA_PRIVACY_VNEXT_NULLIFIER_STATE_SIZE)
    {
        error = "invalid IV5 current nullifier-state length";
        return false;
    }
    if (keyImages.size() > INNOVA_PRIVACY_VNEXT_MAX_INPUTS)
    {
        error = "IV5 nullifier update exceeds ABI limit";
        return false;
    }

    std::vector<uint8_t> request;
    request.reserve(8 + currentState.size() + keyImages.size() * 32);
    request.push_back(1);
    request.push_back(0);
    request.push_back(0);
    request.push_back(0);
    request.insert(request.end(), currentState.begin(), currentState.end());
    const uint32_t count = static_cast<uint32_t>(keyImages.size());
    for (size_t i = 0; i < 4; ++i)
        request.push_back(static_cast<uint8_t>(count >> (8 * i)));
    for (size_t i = 0; i < keyImages.size(); ++i)
        request.insert(request.end(), keyImages[i].begin(), keyImages[i].end());

    uint8_t encoded[INNOVA_PRIVACY_VNEXT_NULLIFIER_STATE_SIZE] = {0};
    size_t written = 0;
    const int32_t result = innova_privacy_vnext_nullifier_update(
        &request[0], request.size(), encoded, sizeof(encoded), &written);
    if (result != INNOVA_PRIVACY_VNEXT_VALID || written != sizeof(encoded))
    {
        error = "Rust IV5 nullifier update returned result " +
                std::to_string(result);
        return false;
    }
    nextState.assign(encoded, encoded + sizeof(encoded));
    return DecodePrivacyVNextNullifierState(nextState, nextRoot,
                                             nextCount, error);
}

bool LoadPrivacyVNextEpochSeed(PrivacyVNextEpochSeed& seed,
                               std::string& error)
{
    seed = PrivacyVNextEpochSeed();
    error.clear();

    PrivacyVNextAbiInfo info;
    if (!LoadPrivacyVNextAbiInfo(info))
    {
        error = info.strError;
        return false;
    }
    if ((info.nImplementedCapabilities &
         (INNOVA_PRIVACY_VNEXT_CAP_TREE_UPDATE |
          INNOVA_PRIVACY_VNEXT_CAP_TREE_ROOT |
          INNOVA_PRIVACY_VNEXT_CAP_NULLIFIER_ACCUMULATOR)) !=
        (INNOVA_PRIVACY_VNEXT_CAP_TREE_UPDATE |
         INNOVA_PRIVACY_VNEXT_CAP_TREE_ROOT |
         INNOVA_PRIVACY_VNEXT_CAP_NULLIFIER_ACCUMULATOR))
    {
        error = "linked Rust ABI lacks IV5 tree capabilities";
        return false;
    }

    const uint8_t emptyUpdate[8] = {1, 0, 1, 0, 0, 0, 0, 0};
    uint8_t state[INNOVA_PRIVACY_VNEXT_TREE_STATE_SIZE] = {0};
    size_t stateWritten = 0;
    int32_t result = innova_privacy_vnext_tree_update(
        emptyUpdate, sizeof(emptyUpdate), state, sizeof(state), &stateWritten);
    if (result != INNOVA_PRIVACY_VNEXT_VALID || stateWritten != sizeof(state))
    {
        error = "Rust IV5 empty-tree update returned result " +
                std::to_string(result);
        return false;
    }
    seed.vchTreeState.assign(state, state + sizeof(state));
    if (!DecodePrivacyVNextTreeState(seed.vchTreeState, seed.vchRoot,
                                     seed.nTreeSize, error) ||
        seed.nTreeSize != 0 ||
        seed.vchRoot.size() != INNOVA_PRIVACY_VNEXT_DIGEST_SIZE)
    {
        if (error.empty())
            error = "Rust IV5 empty-tree seed is non-canonical";
        return false;
    }

    const uint8_t emptyNullifierUpdate[8] = {1, 0, 1, 0, 0, 0, 0, 0};
    uint8_t nullifierState[INNOVA_PRIVACY_VNEXT_NULLIFIER_STATE_SIZE] = {0};
    size_t nullifierWritten = 0;
    result = innova_privacy_vnext_nullifier_update(
        emptyNullifierUpdate, sizeof(emptyNullifierUpdate),
        nullifierState, sizeof(nullifierState), &nullifierWritten);
    if (result != INNOVA_PRIVACY_VNEXT_VALID ||
        nullifierWritten != sizeof(nullifierState))
    {
        error = "Rust IV5 empty-nullifier update returned result " +
                std::to_string(result);
        return false;
    }
    seed.vchNullifierState.assign(
        nullifierState, nullifierState + sizeof(nullifierState));
    if (!DecodePrivacyVNextNullifierState(
            seed.vchNullifierState, seed.vchNullifierRoot,
            seed.nNullifierCount, error) ||
        seed.nNullifierCount != 0 ||
        seed.vchNullifierRoot.size() != INNOVA_PRIVACY_VNEXT_DIGEST_SIZE)
    {
        if (error.empty())
            error = "Rust IV5 empty-nullifier seed is non-canonical";
        return false;
    }

    uint8_t parameterDigest[INNOVA_PRIVACY_VNEXT_DIGEST_SIZE] = {0};
    result = innova_privacy_vnext_parameter_digest(
        parameterDigest, sizeof(parameterDigest));
    if (result != INNOVA_PRIVACY_VNEXT_VALID)
    {
        error = "Rust IV5 parameter digest returned result " +
                std::to_string(result);
        return false;
    }
    seed.vchParameterDigest.assign(
        parameterDigest, parameterDigest + sizeof(parameterDigest));
    return true;
}

PrivacyVNextPayloadValidation ValidatePrivacyVNextPayload(
    uint32_t wireVersion,
    const std::vector<unsigned char>& payload)
{
    PrivacyVNextPayloadValidation validation;
    try
    {
        if (payload.size() > INNOVA_PRIVACY_VNEXT_MAX_PAYLOAD_BYTES)
        {
            validation.nResult = INNOVA_PRIVACY_VNEXT_RESOURCE_LIMIT;
            validation.fLocalFailure = false;
            validation.strError = "IV5 payload exceeds consensus limit";
            return validation;
        }

        std::vector<uint8_t> request;
        request.reserve(4 + payload.size());
        request.push_back(static_cast<uint8_t>(wireVersion));
        request.push_back(static_cast<uint8_t>(wireVersion >> 8));
        request.push_back(static_cast<uint8_t>(wireVersion >> 16));
        request.push_back(static_cast<uint8_t>(wireVersion >> 24));
        request.insert(request.end(), payload.begin(), payload.end());
        validation.nResult = innova_privacy_vnext_payload_validate(
            &request[0], request.size());
        validation.fLocalFailure =
            validation.nResult == INNOVA_PRIVACY_VNEXT_CONTAINED_PANIC ||
            validation.nResult ==
                INNOVA_PRIVACY_VNEXT_INTERNAL_LOCAL_STATE_FAILURE;
        switch (validation.nResult)
        {
        case INNOVA_PRIVACY_VNEXT_VALID:
            validation.strError.clear();
            break;
        case INNOVA_PRIVACY_VNEXT_CONSENSUS_INVALID:
            validation.strError = "consensus-invalid IV5 payload";
            break;
        case INNOVA_PRIVACY_VNEXT_BAD_LENGTH:
            validation.strError = "invalid IV5 payload length";
            break;
        case INNOVA_PRIVACY_VNEXT_UNSUPPORTED_FORMAT:
            validation.strError = "unsupported IV5 payload format";
            break;
        case INNOVA_PRIVACY_VNEXT_RESOURCE_LIMIT:
            validation.strError = "IV5 payload resource limit";
            break;
        case INNOVA_PRIVACY_VNEXT_CONTAINED_PANIC:
            validation.strError = "contained Rust IV5 panic";
            break;
        case INNOVA_PRIVACY_VNEXT_INTERNAL_LOCAL_STATE_FAILURE:
            validation.strError = "Rust IV5 internal/local-state failure";
            break;
        default:
            validation.nResult =
                INNOVA_PRIVACY_VNEXT_INTERNAL_LOCAL_STATE_FAILURE;
            validation.fLocalFailure = true;
            validation.strError = "unknown Rust IV5 result class";
            break;
        }
    }
    catch (const std::exception& e)
    {
        validation.nResult =
            INNOVA_PRIVACY_VNEXT_INTERNAL_LOCAL_STATE_FAILURE;
        validation.fLocalFailure = true;
        validation.strError = std::string("local IV5 validation failure: ") +
                              e.what();
    }
    catch (...)
    {
        validation.nResult =
            INNOVA_PRIVACY_VNEXT_INTERNAL_LOCAL_STATE_FAILURE;
        validation.fLocalFailure = true;
        validation.strError = "unknown local IV5 validation failure";
    }
    return validation;
}

PrivacyVNextPayloadValidation ExtractPrivacyVNextPayloadEffects(
    uint32_t wireVersion,
    const std::vector<unsigned char>& payload,
    PrivacyVNextStateEffects& effects)
{
    effects = PrivacyVNextStateEffects();
    PrivacyVNextPayloadValidation validation =
        ValidatePrivacyVNextPayload(wireVersion, payload);
    if (!validation.IsValid())
        return validation;

    try
    {
        std::vector<uint8_t> request(4 + payload.size());
        request[0] = static_cast<uint8_t>(wireVersion);
        request[1] = static_cast<uint8_t>(wireVersion >> 8);
        request[2] = static_cast<uint8_t>(wireVersion >> 16);
        request[3] = static_cast<uint8_t>(wireVersion >> 24);
        if (!payload.empty())
            std::memcpy(&request[4], &payload[0], payload.size());

        size_t required = 0;
        int32_t result = innova_privacy_vnext_payload_effects(
            &request[0], request.size(), NULL, 0, &required);
        if (result != INNOVA_PRIVACY_VNEXT_VALID ||
            required < INNOVA_PRIVACY_VNEXT_PAYLOAD_EFFECTS_HEADER_SIZE ||
            required > INNOVA_PRIVACY_VNEXT_MAX_PAYLOAD_BYTES)
        {
            validation.nResult =
                INNOVA_PRIVACY_VNEXT_INTERNAL_LOCAL_STATE_FAILURE;
            validation.fLocalFailure = true;
            validation.strError = "Rust IV5 effects-size query failed after validation";
            return validation;
        }

        std::vector<uint8_t> encoded(required);
        size_t written = 0;
        result = innova_privacy_vnext_payload_effects(
            &request[0], request.size(), &encoded[0], encoded.size(), &written);
        if (result != INNOVA_PRIVACY_VNEXT_VALID || written != required)
        {
            validation.nResult =
                INNOVA_PRIVACY_VNEXT_INTERNAL_LOCAL_STATE_FAILURE;
            validation.fLocalFailure = true;
            validation.strError = "Rust IV5 effects extraction changed after validation";
            return validation;
        }

        if (encoded[0] != 1 || encoded[1] != 0)
            throw std::runtime_error("unsupported IV5 effects schema");
        const size_t inputCount = encoded[2];
        const size_t outputCount = encoded[3];
        if (inputCount > INNOVA_PRIVACY_VNEXT_MAX_INPUTS ||
            outputCount > INNOVA_PRIVACY_VNEXT_MAX_OUTPUTS)
            throw std::runtime_error("IV5 effects count exceeds ABI limits");
        const size_t exactSize =
            INNOVA_PRIVACY_VNEXT_PAYLOAD_EFFECTS_HEADER_SIZE +
            inputCount * INNOVA_PRIVACY_VNEXT_DIGEST_SIZE +
            outputCount * 3 * INNOVA_PRIVACY_VNEXT_DIGEST_SIZE;
        if (encoded.size() != exactSize)
            throw std::runtime_error("non-canonical IV5 effects length");

        std::copy(encoded.begin() + 4, encoded.begin() + 36,
                  effects.finalizedRoot.begin());
        effects.nFinalizedTreeSize = 0;
        for (size_t i = 0; i < 8; ++i)
            effects.nFinalizedTreeSize |=
                static_cast<uint64_t>(encoded[36 + i]) << (8 * i);
        std::copy(encoded.begin() + 44, encoded.begin() + 76,
                  effects.parameterDigest.begin());

        size_t offset = INNOVA_PRIVACY_VNEXT_PAYLOAD_EFFECTS_HEADER_SIZE;
        effects.keyImages.resize(inputCount);
        for (size_t i = 0; i < inputCount; ++i)
        {
            std::copy(encoded.begin() + offset,
                      encoded.begin() + offset + INNOVA_PRIVACY_VNEXT_DIGEST_SIZE,
                      effects.keyImages[i].begin());
            offset += INNOVA_PRIVACY_VNEXT_DIGEST_SIZE;
        }
        effects.outputLeaves.resize(outputCount);
        for (size_t i = 0; i < outputCount; ++i)
        {
            std::copy(encoded.begin() + offset, encoded.begin() + offset + 32,
                      effects.outputLeaves[i].owner.begin());
            offset += 32;
            std::copy(encoded.begin() + offset, encoded.begin() + offset + 32,
                      effects.outputLeaves[i].nullifierBase.begin());
            offset += 32;
            std::copy(encoded.begin() + offset, encoded.begin() + offset + 32,
                      effects.outputLeaves[i].commitment.begin());
            offset += 32;
        }
        if (offset != encoded.size())
            throw std::runtime_error("trailing IV5 effects bytes");
        validation.strError.clear();
        return validation;
    }
    catch (const std::exception& e)
    {
        effects = PrivacyVNextStateEffects();
        validation.nResult = INNOVA_PRIVACY_VNEXT_INTERNAL_LOCAL_STATE_FAILURE;
        validation.fLocalFailure = true;
        validation.strError = std::string("local IV5 effects failure: ") + e.what();
        return validation;
    }
    catch (...)
    {
        effects = PrivacyVNextStateEffects();
        validation.nResult = INNOVA_PRIVACY_VNEXT_INTERNAL_LOCAL_STATE_FAILURE;
        validation.fLocalFailure = true;
        validation.strError = "unknown local IV5 effects failure";
        return validation;
    }
}

PrivacyVNextScannedNote::PrivacyVNextScannedNote()
{
    Clear();
}

PrivacyVNextScannedNote::~PrivacyVNextScannedNote()
{
    Clear();
}

void PrivacyVNextScannedNote::Clear()
{
    OPENSSL_cleanse(spendSecret.data(), spendSecret.size());
    OPENSSL_cleanse(y.data(), y.size());
    OPENSSL_cleanse(mask.data(), mask.size());
    recipientSpend.fill(0);
    recipientView.fill(0);
    keyImage.fill(0);
    nScanKind = 0;
    nNetwork = 0;
    nAddressType = 0;
    nOutputIndex = 0;
    nAmount = 0;
}

PrivacyVNextValueProof::PrivacyVNextValueProof()
{
    Clear();
}

void PrivacyVNextValueProof::Clear()
{
    vOutputCommitments.clear();
    vchRangeProof.clear();
    balanceProof.fill(0);
    bindingSignature.fill(0);
}

bool ScanPrivacyVNextNote(
    uint8_t scanKind,
    uint8_t network,
    uint8_t addressType,
    const PrivacyVNextEncryptedNote& note,
    const PrivacyVNextDigest& scanSecret,
    const PrivacyVNextDigest& spendMaterial,
    PrivacyVNextScannedNote& scanned,
    std::string& error)
{
    scanned.Clear();
    error.clear();

    size_t nExpectedCiphertext = 0;
    switch (scanKind)
    {
    case PRIVACY_VNEXT_SCAN_FULL:
    case PRIVACY_VNEXT_SCAN_VIEW_ONLY:
        nExpectedCiphertext = INNOVA_PRIVACY_VNEXT_RECIPIENT_CIPHERTEXT_SIZE;
        break;
    case PRIVACY_VNEXT_SCAN_OUTGOING:
        nExpectedCiphertext = INNOVA_PRIVACY_VNEXT_OUTGOING_CIPHERTEXT_SIZE;
        break;
    default:
        error = "unknown IV5 note scan kind";
        return false;
    }
    if (note.vchCiphertext.size() != nExpectedCiphertext)
    {
        error = "IV5 note ciphertext has the wrong length for this scan kind";
        return false;
    }

    std::vector<uint8_t> request(
        INNOVA_PRIVACY_VNEXT_NOTE_SCAN_PREFIX_SIZE + nExpectedCiphertext, 0);
    request[0] = static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA);
    request[1] = 0;
    request[2] = scanKind;
    request[3] = network;
    request[4] = addressType;
    PutLE32(&request[8], note.nOutputIndex);
    std::memcpy(&request[12], note.genesis.data(), 32);
    std::memcpy(&request[44], scanSecret.data(), 32);
    std::memcpy(&request[76], spendMaterial.data(), 32);
    std::memcpy(&request[108], note.leafO.data(), 32);
    std::memcpy(&request[140], note.leafI.data(), 32);
    std::memcpy(&request[172], note.leafC.data(), 32);
    std::memcpy(&request[204], note.ephemeral.data(), 32);
    std::memcpy(&request[INNOVA_PRIVACY_VNEXT_NOTE_SCAN_PREFIX_SIZE],
                &note.vchCiphertext[0], nExpectedCiphertext);

    std::array<uint8_t, INNOVA_PRIVACY_VNEXT_NOTE_SCAN_RESULT_SIZE> response = {};
    size_t written = 0;
    const int32_t result = innova_privacy_vnext_note_scan(
        &request[0], request.size(), response.data(), response.size(), &written);
    OPENSSL_cleanse(&request[0], request.size());
    if (result != INNOVA_PRIVACY_VNEXT_VALID)
    {
        OPENSSL_cleanse(response.data(), response.size());
        error = ResultError("IV5 note scan", result);
        return false;
    }
    if (written != response.size() ||
        response[0] != static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA) ||
        response[1] != 0 || response[2] != scanKind ||
        response[3] != network || response[4] != addressType ||
        ReadLE32(response.data() + 8) != note.nOutputIndex)
    {
        OPENSSL_cleanse(response.data(), response.size());
        error = "non-canonical IV5 note-scan response";
        return false;
    }

    scanned.nScanKind = scanKind;
    scanned.nNetwork = network;
    scanned.nAddressType = addressType;
    scanned.nOutputIndex = note.nOutputIndex;
    scanned.nAmount = ReadLE64(response.data() + 12);
    std::memcpy(scanned.recipientSpend.data(), response.data() + 20, 32);
    std::memcpy(scanned.recipientView.data(), response.data() + 52, 32);
    std::memcpy(scanned.spendSecret.data(), response.data() + 84, 32);
    std::memcpy(scanned.y.data(), response.data() + 116, 32);
    std::memcpy(scanned.mask.data(), response.data() + 148, 32);
    std::memcpy(scanned.keyImage.data(), response.data() + 180, 32);
    OPENSSL_cleanse(response.data(), response.size());
    return true;
}

PrivacyVNextScanMatch::PrivacyVNextScanMatch()
{
    Clear();
}

PrivacyVNextScanMatch::PrivacyVNextScanMatch(PrivacyVNextScanMatch&& other) noexcept
{
    nOutputIndex = other.nOutputIndex;
    leaf = other.leaf;
    nAmount = other.nAmount;
    recipientSpend = other.recipientSpend;
    recipientView = other.recipientView;
    spendSecret = other.spendSecret;
    y = other.y;
    mask = other.mask;
    keyImage = other.keyImage;
    other.Clear();
}

PrivacyVNextScanMatch& PrivacyVNextScanMatch::operator=(
    PrivacyVNextScanMatch&& other) noexcept
{
    if (this != &other)
    {
        Clear();
        nOutputIndex = other.nOutputIndex;
        leaf = other.leaf;
        nAmount = other.nAmount;
        recipientSpend = other.recipientSpend;
        recipientView = other.recipientView;
        spendSecret = other.spendSecret;
        y = other.y;
        mask = other.mask;
        keyImage = other.keyImage;
        other.Clear();
    }
    return *this;
}

PrivacyVNextScanMatch::~PrivacyVNextScanMatch()
{
    Clear();
}

void PrivacyVNextScanMatch::Clear()
{
    OPENSSL_cleanse(spendSecret.data(), spendSecret.size());
    OPENSSL_cleanse(y.data(), y.size());
    OPENSSL_cleanse(mask.data(), mask.size());
    leaf.owner.fill(0);
    leaf.nullifierBase.fill(0);
    leaf.commitment.fill(0);
    recipientSpend.fill(0);
    recipientView.fill(0);
    keyImage.fill(0);
    nOutputIndex = 0;
    nAmount = 0;
}

bool ScanPrivacyVNextPayload(
    uint8_t scanKind,
    uint8_t network,
    uint8_t addressType,
    uint32_t wireVersion,
    const std::vector<unsigned char>& payload,
    const PrivacyVNextDigest& scanSecret,
    const PrivacyVNextDigest& spendMaterial,
    const PrivacyVNextStateEffects& effects,
    std::vector<PrivacyVNextScanMatch>& matches,
    std::string& error)
{
    matches.clear();
    error.clear();

    if (payload.empty())
    {
        error = "empty IV5 payload";
        return false;
    }

    static const size_t nRequestPrefix = 76;
    static const size_t nRecordSize = 4 + 96 + INNOVA_PRIVACY_VNEXT_NOTE_SCAN_RESULT_SIZE;

    std::vector<uint8_t> request(nRequestPrefix + payload.size(), 0);
    request[0] = static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA);
    request[1] = 0;
    request[2] = scanKind;
    request[3] = network;
    request[4] = addressType;
    PutLE32(&request[8], wireVersion);
    std::memcpy(&request[12], scanSecret.data(), 32);
    std::memcpy(&request[44], spendMaterial.data(), 32);
    std::memcpy(&request[nRequestPrefix], &payload[0], payload.size());

    size_t required = 0;
    int32_t result = innova_privacy_vnext_payload_scan(
        &request[0], request.size(), NULL, 0, &required);
    if (result != INNOVA_PRIVACY_VNEXT_VALID || required < 4 ||
        required > INNOVA_PRIVACY_VNEXT_MAX_PAYLOAD_BYTES)
    {
        OPENSSL_cleanse(&request[0], request.size());
        error = ResultError("IV5 payload scan size query", result);
        return false;
    }

    std::vector<uint8_t> response(required, 0);
    size_t written = 0;
    result = innova_privacy_vnext_payload_scan(
        &request[0], request.size(), &response[0], response.size(), &written);
    OPENSSL_cleanse(&request[0], request.size());
    if (result != INNOVA_PRIVACY_VNEXT_VALID)
    {
        error = ResultError("IV5 payload scan", result);
        return false;
    }

    const size_t nMatches = response[2];
    if (written != response.size() ||
        response[0] != static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA) ||
        response[1] != 0 || response[3] != 0 ||
        written != 4 + (nMatches * nRecordSize))
    {
        OPENSSL_cleanse(&response[0], response.size());
        error = "non-canonical IV5 payload-scan response";
        return false;
    }

    matches.reserve(nMatches);
    for (size_t i = 0; i < nMatches; ++i)
    {
        const uint8_t* record = &response[4 + (i * nRecordSize)];
        PrivacyVNextScanMatch match;
        match.nOutputIndex = ReadLE32(record);
        std::memcpy(match.leaf.owner.data(), record + 4, 32);
        std::memcpy(match.leaf.nullifierBase.data(), record + 36, 32);
        std::memcpy(match.leaf.commitment.data(), record + 68, 32);

        const uint8_t* scanned = record + 100;
        if (scanned[0] != static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA) ||
            scanned[1] != 0 || scanned[2] != scanKind ||
            scanned[3] != network || scanned[4] != addressType ||
            ReadLE32(scanned + 8) != match.nOutputIndex)
        {
            OPENSSL_cleanse(&response[0], response.size());
            error = "non-canonical IV5 note-scan record";
            return false;
        }
        match.nAmount = ReadLE64(scanned + 12);
        std::memcpy(match.recipientSpend.data(), scanned + 20, 32);
        std::memcpy(match.recipientView.data(), scanned + 52, 32);
        std::memcpy(match.spendSecret.data(), scanned + 84, 32);
        std::memcpy(match.y.data(), scanned + 116, 32);
        std::memcpy(match.mask.data(), scanned + 148, 32);
        std::memcpy(match.keyImage.data(), scanned + 180, 32);

        // The scan reads the payload separately from the validating decoder. Requiring
        // the matched leaf to equal the validated one keeps a divergence between the
        // two from assigning a note to the wrong tree position.
        if (match.nOutputIndex >= effects.outputLeaves.size())
        {
            OPENSSL_cleanse(&response[0], response.size());
            error = "IV5 scan matched an output the validated effects do not carry";
            return false;
        }
        const PrivacyVNextOutputLeaf& expected =
            effects.outputLeaves[match.nOutputIndex];
        if (match.leaf.owner != expected.owner ||
            match.leaf.nullifierBase != expected.nullifierBase ||
            match.leaf.commitment != expected.commitment)
        {
            OPENSSL_cleanse(&response[0], response.size());
            error = "IV5 scan leaf disagrees with the validated payload effects";
            return false;
        }

        for (size_t seen = 0; seen < matches.size(); ++seen)
        {
            if (matches[seen].nOutputIndex == match.nOutputIndex)
            {
                OPENSSL_cleanse(&response[0], response.size());
                error = "IV5 payload scan repeated an output index";
                return false;
            }
        }
        matches.push_back(std::move(match));
    }

    OPENSSL_cleanse(&response[0], response.size());
    return true;
}

bool ProvePrivacyVNextValue(
    const std::vector<PrivacyVNextDigest>& vPseudoOuts,
    const std::vector<PrivacyVNextValueOutput>& vOutputs,
    int64_t nTransparentValueBalance,
    uint64_t nFee,
    const PrivacyVNextDigest& signableHash,
    const PrivacyVNextDigest& entropy,
    const PrivacyVNextDigest& excessMask,
    PrivacyVNextValueProof& proof,
    std::string& error)
{
    proof.Clear();
    error.clear();

    if (vPseudoOuts.size() > INNOVA_PRIVACY_VNEXT_MAX_INPUTS ||
        vOutputs.size() > INNOVA_PRIVACY_VNEXT_MAX_OUTPUTS)
    {
        error = "IV5 value proof exceeds the input or output limit";
        return false;
    }

    std::vector<uint8_t> request(
        INNOVA_PRIVACY_VNEXT_VALUE_PROVE_HEADER_SIZE +
            (vPseudoOuts.size() * 32) + (vOutputs.size() * 40),
        0);
    request[0] = static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA);
    request[1] = 0;
    request[2] = static_cast<uint8_t>(vOutputs.size());
    request[3] = static_cast<uint8_t>(vPseudoOuts.size());
    PutLE64(&request[4], static_cast<uint64_t>(nTransparentValueBalance));
    PutLE64(&request[12], nFee);
    std::memcpy(&request[20], signableHash.data(), 32);
    std::memcpy(&request[52], entropy.data(), 32);
    std::memcpy(&request[84], excessMask.data(), 32);

    size_t offset = INNOVA_PRIVACY_VNEXT_VALUE_PROVE_HEADER_SIZE;
    for (size_t i = 0; i < vPseudoOuts.size(); ++i)
    {
        std::memcpy(&request[offset], vPseudoOuts[i].data(), 32);
        offset += 32;
    }
    for (size_t i = 0; i < vOutputs.size(); ++i)
    {
        PutLE64(&request[offset], vOutputs[i].nAmount);
        std::memcpy(&request[offset + 8], vOutputs[i].mask.data(), 32);
        offset += 40;
    }

    size_t required = 0;
    int32_t result = innova_privacy_vnext_value_prove(
        &request[0], request.size(), NULL, 0, &required);
    if (result != INNOVA_PRIVACY_VNEXT_VALID ||
        required == 0 || required > INNOVA_PRIVACY_VNEXT_MAX_PAYLOAD_BYTES)
    {
        OPENSSL_cleanse(&request[0], request.size());
        error = ResultError("IV5 value proof size query", result);
        return false;
    }

    std::vector<uint8_t> response(required, 0);
    size_t written = 0;
    result = innova_privacy_vnext_value_prove(
        &request[0], request.size(), &response[0], response.size(), &written);
    OPENSSL_cleanse(&request[0], request.size());
    if (result != INNOVA_PRIVACY_VNEXT_VALID)
    {
        error = ResultError("IV5 value proof", result);
        return false;
    }

    const size_t nFixed = 4 + (vOutputs.size() * 32) + 4 + 128;
    if (written != response.size() || written < nFixed ||
        response[0] != static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA) ||
        response[1] != 0 ||
        response[2] != static_cast<uint8_t>(vOutputs.size()) ||
        response[3] != static_cast<uint8_t>(vPseudoOuts.size()))
    {
        error = "non-canonical IV5 value-proof response";
        return false;
    }

    offset = 4;
    proof.vOutputCommitments.resize(vOutputs.size());
    for (size_t i = 0; i < vOutputs.size(); ++i)
    {
        std::memcpy(proof.vOutputCommitments[i].data(), &response[offset], 32);
        offset += 32;
    }
    const uint32_t nRangeProof = ReadLE32(&response[offset]);
    offset += 4;
    if (nRangeProof != written - nFixed)
    {
        proof.Clear();
        error = "IV5 value-proof range section does not fill the response";
        return false;
    }
    proof.vchRangeProof.assign(response.begin() + offset,
                               response.begin() + offset + nRangeProof);
    offset += nRangeProof;
    std::memcpy(proof.balanceProof.data(), &response[offset], 64);
    std::memcpy(proof.bindingSignature.data(), &response[offset + 64], 64);
    return true;
}
