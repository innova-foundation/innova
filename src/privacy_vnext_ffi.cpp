// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license.

#include "privacy_vnext_ffi.h"
#include <atomic>
#include <deque>
#include <thread>
#include <utility>
#include <map>

#include "hash.h"
#include "sync.h"
#include "util.h"
#include "uint256.h"
#include "verifycache.h"
#include "blockprofile.h"

namespace {
// Defined with the effects cache below; the payload-verdict cache above uses the
// identical key derivation so one payload has one cache identity.
uint256 VNextEffectsCacheKey(uint32_t wireVersion,
                             const std::vector<unsigned char>& payload);
}

#include "privacy_vnext/iv5_protocol.h"
#include "privacy_vnext/rust/include/innova_privacy_vnext.h"

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

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

// [wire version u32][network u8][reserved 3][genesis 32]
const size_t kValidationPrefixSize = 40;

void PutValidationPrefix(uint8_t* bytes, uint32_t wireVersion)
{
    PutLE32(bytes, wireVersion);
    bytes[4] = PrivacyVNextLocalNetworkId();
    bytes[5] = 0;
    bytes[6] = 0;
    bytes[7] = 0;
    PrivacyVNextLocalGenesis(bytes + 8);
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

namespace
{
// Read the linked library's published contract digests as lowercase hex, current first.
bool ReadAcceptedParameterDigests(std::vector<std::string>& vHexOut,
                                  std::string& error)
{
    vHexOut.clear();
    error.clear();

    size_t required = 0;
    int32_t result = innova_privacy_vnext_accepted_parameter_digests(
        NULL, 0, &required);
    if (result != INNOVA_PRIVACY_VNEXT_VALID || required < 1 ||
        required > iv5::MAX_PAYLOAD_BYTES ||
        (required - 1) % INNOVA_PRIVACY_VNEXT_DIGEST_SIZE != 0)
    {
        error = "accepted parameter digest size query failed";
        return false;
    }
    std::vector<uint8_t> encoded(required);
    size_t written = 0;
    result = innova_privacy_vnext_accepted_parameter_digests(
        &encoded[0], encoded.size(), &written);
    if (result != INNOVA_PRIVACY_VNEXT_VALID || written != required)
    {
        error = "accepted parameter digest read failed";
        return false;
    }
    const size_t nCount = encoded[0];
    if (nCount == 0 ||
        required != 1 + nCount * INNOVA_PRIVACY_VNEXT_DIGEST_SIZE)
    {
        error = "accepted parameter digest list is not canonical";
        return false;
    }
    for (size_t i = 0; i < nCount; ++i)
        vHexOut.push_back(HexDigest(&encoded[1 + i * INNOVA_PRIVACY_VNEXT_DIGEST_SIZE],
                                    INNOVA_PRIVACY_VNEXT_DIGEST_SIZE));
    return true;
}
} // namespace

bool IsAcceptedPrivacyVNextParameterDigest(const unsigned char* pDigest,
                                           size_t nSize)
{
    if (pDigest == NULL || nSize != INNOVA_PRIVACY_VNEXT_DIGEST_SIZE)
        return false;
    std::vector<std::string> vAccepted;
    std::string error;
    if (!ReadAcceptedParameterDigests(vAccepted, error))
        return false;
    const std::string strDigest = HexDigest(pDigest, nSize);
    for (size_t i = 0; i < vAccepted.size(); ++i)
        if (vAccepted[i] == strDigest)
            return true;
    return false;
}

bool IsPrivacyVNextMemberKeyOnCurve(const unsigned char* pKey, size_t nSize)
{
    if (pKey == NULL || nSize != iv5::FINALITY_MEMBER_KEY_BYTES)
        return false;
    // The Rust decoder already refused a non-canonical encoding; what is left is whether
    // the x it names has a y at all, which is the algebraic test below and nothing about
    // this node.
    if (pKey[0] != 2 && pKey[0] != 3)
        return false;
    EC_KEY* pECKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (pECKey == NULL)
        return false;
    const unsigned char* pIn = pKey;
    const bool fValid = o2i_ECPublicKey(&pECKey, &pIn, (long)nSize) != NULL &&
                        pIn == pKey + nSize;
    EC_KEY_free(pECKey);
    return fValid;
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

    // A stale archive answers with the manifest it was compiled against, so this is the
    // one check that catches a decoder the build system failed to relink. Refuse the
    // build rather than validate consensus payloads with an unknown decoder.
    if (info.strProvenanceDigest != iv5::PROVENANCE_SHA256)
        return Fail(info,
                    "linked IV5 decoder was built from provenance " +
                    info.strProvenanceDigest + " but this build expects " +
                    std::string(iv5::PROVENANCE_SHA256) +
                    "; rebuild the Rust library (make -f makefile.unix "
                    "check-privacy-vnext-freshness)");

    // The two published-contract lists must be the same list. Nothing branches on it,
    // but the halves disagreeing means the C++ side and the decoder were not built from
    // the same tree, which is the interesting failure here.
    std::vector<std::string> vAccepted;
    if (!ReadAcceptedParameterDigests(vAccepted, error))
        return Fail(info, error);
    if (vAccepted.size() != iv5::PROTOCOL_CONTRACT_SHA256_PRIOR_COUNT + 1 ||
        vAccepted[0] != iv5::PROTOCOL_CONTRACT_SHA256)
        return Fail(info, "Rust/C accepted parameter digest list mismatch");
    for (size_t i = 0; i < iv5::PROTOCOL_CONTRACT_SHA256_PRIOR_COUNT; ++i)
        if (vAccepted[i + 1] != iv5::PROTOCOL_CONTRACT_SHA256_PRIOR[i])
            return Fail(info, "Rust/C accepted parameter digest list mismatch");

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

bool ExtendPrivacyVNextOutputLeaves(
    const std::vector<unsigned char>& currentState,
    const std::vector<PrivacyVNextOutputLeaf>& leaves,
    std::vector<unsigned char>& nextState,
    std::vector<unsigned char>& nextRoot,
    uint64_t& nextSize,
    std::vector<PrivacyVNextTreeNode>& nodes,
    std::string& error)
{
    nextState.clear();
    nextRoot.clear();
    nextSize = 0;
    nodes.clear();
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

    size_t required = 0;
    int32_t result = innova_privacy_vnext_tree_extend(
        &request[0], request.size(), NULL, 0, &required);
    if (result != INNOVA_PRIVACY_VNEXT_VALID ||
        required < INNOVA_PRIVACY_VNEXT_TREE_STATE_SIZE + 4 ||
        required > INNOVA_PRIVACY_VNEXT_MAX_PAYLOAD_BYTES)
    {
        error = ResultError("IV5 tree extension size query", result);
        return false;
    }
    std::vector<uint8_t> response(required, 0);
    size_t written = 0;
    result = innova_privacy_vnext_tree_extend(
        &request[0], request.size(), &response[0], response.size(), &written);
    if (result != INNOVA_PRIVACY_VNEXT_VALID || written != required)
    {
        error = ResultError("IV5 tree extension", result);
        return false;
    }

    nextState.assign(response.begin(),
                     response.begin() + INNOVA_PRIVACY_VNEXT_TREE_STATE_SIZE);
    const size_t nCountOffset = INNOVA_PRIVACY_VNEXT_TREE_STATE_SIZE;
    const size_t nNodeCount =
        static_cast<size_t>(response[nCountOffset]) |
        (static_cast<size_t>(response[nCountOffset + 1]) << 8);
    if (response[nCountOffset + 2] != 0 || response[nCountOffset + 3] != 0)
    {
        error = "IV5 tree extension header is not canonical";
        return false;
    }
    if (written != nCountOffset + 4 + (nNodeCount * 44))
    {
        error = "IV5 tree extension length does not match its node count";
        return false;
    }
    nodes.resize(nNodeCount);
    for (size_t i = 0; i < nNodeCount; ++i)
    {
        const size_t at = nCountOffset + 4 + (i * 44);
        if (response[at + 1] != 0 || response[at + 2] != 0 ||
            response[at + 3] != 0)
        {
            error = "IV5 tree extension node record is not canonical";
            return false;
        }
        nodes[i].nLevel = response[at];
        uint64_t nIndex = 0;
        for (size_t b = 0; b < 8; ++b)
            nIndex |= static_cast<uint64_t>(response[at + 4 + b]) << (8 * b);
        nodes[i].nIndex = nIndex;
        std::memcpy(nodes[i].point.data(), &response[at + 12], 32);
    }
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

    // The pinned constant, never the linked library's own digest: first-epoch stamping and
    // pre-epoch validity must not depend on what each node was compiled from.
    unsigned char parameterDigest[INNOVA_PRIVACY_VNEXT_DIGEST_SIZE] = {0};
    if (!iv5::DecodeDigestHex(iv5::GENESIS_PARAMETER_DIGEST_SHA256,
                              parameterDigest))
    {
        error = "IV5 genesis parameter digest is malformed";
        return false;
    }
    seed.vchParameterDigest.assign(
        parameterDigest, parameterDigest + sizeof(parameterDigest));
    return true;
}

static PrivacyVNextPayloadValidation ValidatePrivacyVNextPayloadUncached(
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

        std::vector<uint8_t> request(kValidationPrefixSize + payload.size(), 0);
        PutValidationPrefix(&request[0], wireVersion);
        if (!payload.empty())
            std::memcpy(&request[kValidationPrefixSize], &payload[0],
                        payload.size());
        validation.nResult = innova_privacy_vnext_payload_validate(
            &request[0], request.size());
        // The Rust entry point reads only (wireVersion, payload), so every result it
        // returns, including a contained panic, is deterministic across nodes and is a
        // consensus verdict; only the C++-side conditions below stay node-local.
        validation.fLocalFailure = false;
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
            validation.strError = "Rust IV5 internal-state failure";
            break;
        default:
            // Left non-zero so IsValid() stays false; the raw code is kept for the log
            // rather than folded into a class it does not belong to.
            validation.strError = "unknown Rust IV5 result class " +
                                  std::to_string(validation.nResult);
            break;
        }
    }
    catch (const std::exception& e)
    {
        // Reached only by allocation or stream failure on this side of the FFI, which
        // is genuinely node-local: another node may have the memory this one lacks.
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

// A payload's verdict is a pure function of its bytes and outer version, so successes are
// cached under VerifyProofCacheKey with height fixed at 0.
PrivacyVNextPayloadValidation ValidatePrivacyVNextPayload(
    uint32_t wireVersion,
    const std::vector<unsigned char>& payload)
{
    if (!VerifyProofCacheEnabled())
        return ValidatePrivacyVNextPayloadUncached(wireVersion, payload);

    const uint256 key = VerifyProofCacheKey(VERIFYCACHE_IV5_PAYLOAD, 0,
                                            VNextEffectsCacheKey(wireVersion, payload));
    if (VerifyProofCacheCheck(key))
    {
        BlockProfileCount("vnext_verdict_hit", 1);
        PrivacyVNextPayloadValidation hit;
        hit.nResult = INNOVA_PRIVACY_VNEXT_VALID;
        hit.fLocalFailure = false;
        return hit;
    }

    BlockProfileCount("vnext_verdict_miss", 1);
    const PrivacyVNextPayloadValidation validation =
        ValidatePrivacyVNextPayloadUncached(wireVersion, payload);
    if (validation.IsValid())
        VerifyProofCacheStore(key);
    return validation;
}

static PrivacyVNextPayloadValidation& DeterministicVNextEffectsReject(
    PrivacyVNextStateEffects& effects,
    PrivacyVNextPayloadValidation& validation,
    const char* pszError)
{
    effects = PrivacyVNextStateEffects();
    validation.nResult = INNOVA_PRIVACY_VNEXT_CONSENSUS_INVALID;
    validation.fLocalFailure = false;
    validation.strError = pszError;
    return validation;
}

// Which decoder entry an extraction uses. ASSUME_VALID skips the proof verdicts and
// nothing else; it is only ever reached through the ancestry gate in main.cpp.
enum VNextEffectsMode
{
    VNEXT_EFFECTS_VERIFY = 0,
    VNEXT_EFFECTS_ASSUME_VALID = 1
};

static PrivacyVNextPayloadValidation ExtractPrivacyVNextPayloadEffectsUncached(
    uint32_t wireVersion,
    const std::vector<unsigned char>& payload,
    PrivacyVNextStateEffects& effects,
    VNextEffectsMode mode = VNEXT_EFFECTS_VERIFY)
{
    effects = PrivacyVNextStateEffects();
    PrivacyVNextPayloadValidation validation;
    if (mode == VNEXT_EFFECTS_VERIFY)
    {
        // The verifying path validates first and extracts second; under assume-valid
        // that first pass is exactly the cost being skipped, so it is not run.
        validation = ValidatePrivacyVNextPayload(wireVersion, payload);
        if (!validation.IsValid())
            return validation;
    }
    else
    {
        validation.nResult = INNOVA_PRIVACY_VNEXT_VALID;
        validation.fLocalFailure = false;
    }

    try
    {
        std::vector<uint8_t> request(kValidationPrefixSize + payload.size(), 0);
        PutValidationPrefix(&request[0], wireVersion);
        if (!payload.empty())
            std::memcpy(&request[kValidationPrefixSize], &payload[0],
                        payload.size());

        size_t required = 0;
        int32_t result =
            (mode == VNEXT_EFFECTS_ASSUME_VALID)
                ? innova_privacy_vnext_payload_effects_assume_valid(
                      &request[0], request.size(), NULL, 0, &required)
                : innova_privacy_vnext_payload_effects(
                      &request[0], request.size(), NULL, 0, &required);
        if (result != INNOVA_PRIVACY_VNEXT_VALID ||
            required < INNOVA_PRIVACY_VNEXT_PAYLOAD_EFFECTS_HEADER_SIZE ||
            required > INNOVA_PRIVACY_VNEXT_MAX_PAYLOAD_BYTES)
        {
            // Same pure inputs as the validate call that just succeeded, so a
            // disagreement here is a property of the payload and this binary, not of
            // this node.
            validation.nResult = INNOVA_PRIVACY_VNEXT_CONSENSUS_INVALID;
            validation.fLocalFailure = false;
            validation.strError = "Rust IV5 effects-size query failed after validation";
            return validation;
        }

        std::vector<uint8_t> encoded(required);
        size_t written = 0;
        result = (mode == VNEXT_EFFECTS_ASSUME_VALID)
                     ? innova_privacy_vnext_payload_effects_assume_valid(
                           &request[0], request.size(), &encoded[0], encoded.size(),
                           &written)
                     : innova_privacy_vnext_payload_effects(
                           &request[0], request.size(), &encoded[0], encoded.size(),
                           &written);
        if (result != INNOVA_PRIVACY_VNEXT_VALID || written != required)
        {
            validation.nResult = INNOVA_PRIVACY_VNEXT_CONSENSUS_INVALID;
            validation.fLocalFailure = false;
            validation.strError = "Rust IV5 effects extraction changed after validation";
            return validation;
        }

        // The encoded effects are a function of the payload alone, so a shape this
        // side refuses is refused identically everywhere: reject rather than stop.
        if (encoded[0] != 1 || encoded[1] != 0)
            return DeterministicVNextEffectsReject(
                effects, validation, "unsupported IV5 effects schema");
        const size_t inputCount = encoded[2];
        const size_t outputCount = encoded[3];
        if (inputCount > INNOVA_PRIVACY_VNEXT_MAX_INPUTS ||
            outputCount > INNOVA_PRIVACY_VNEXT_MAX_OUTPUTS)
            return DeterministicVNextEffectsReject(
                effects, validation, "IV5 effects count exceeds ABI limits");
        const size_t trailerAt =
            INNOVA_PRIVACY_VNEXT_PAYLOAD_EFFECTS_HEADER_SIZE +
            inputCount * INNOVA_PRIVACY_VNEXT_DIGEST_SIZE +
            outputCount * 3 * INNOVA_PRIVACY_VNEXT_DIGEST_SIZE;
        if (encoded.size() <
            trailerAt + INNOVA_PRIVACY_VNEXT_PAYLOAD_EFFECTS_TRAILER_SIZE)
            return DeterministicVNextEffectsReject(
                effects, validation, "truncated IV5 effects trailer");
        const size_t attestationCount = encoded[trailerAt];
        if (attestationCount > INNOVA_PRIVACY_VNEXT_MAX_INPUTS)
            return DeterministicVNextEffectsReject(
                effects, validation, "IV5 effects count exceeds ABI limits");
        const size_t exactSize =
            trailerAt + INNOVA_PRIVACY_VNEXT_PAYLOAD_EFFECTS_TRAILER_SIZE +
            attestationCount * INNOVA_PRIVACY_VNEXT_DIGEST_SIZE;
        if (encoded.size() != exactSize)
            return DeterministicVNextEffectsReject(
                effects, validation, "non-canonical IV5 effects length");

        std::copy(encoded.begin() + 4, encoded.begin() + 36,
                  effects.finalizedRoot.begin());
        effects.nFinalizedTreeSize = 0;
        for (size_t i = 0; i < 8; ++i)
            effects.nFinalizedTreeSize |=
                static_cast<uint64_t>(encoded[36 + i]) << (8 * i);
        std::copy(encoded.begin() + 44, encoded.begin() + 76,
                  effects.parameterDigest.begin());
        uint64_t nRawBalance = 0;
        for (size_t i = 0; i < 8; ++i)
            nRawBalance |= static_cast<uint64_t>(encoded[76 + i]) << (8 * i);
        effects.nTransparentValueBalance = static_cast<int64_t>(nRawBalance);
        effects.nFee = 0;
        for (size_t i = 0; i < 8; ++i)
            effects.nFee |= static_cast<uint64_t>(encoded[84 + i]) << (8 * i);
        std::copy(encoded.begin() + 92, encoded.begin() + 124,
                  effects.transparentBinding.begin());

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
        ++offset;  // attestation count, already read
        std::copy(encoded.begin() + offset, encoded.begin() + offset + 32,
                  effects.registrationContext.begin());
        offset += 32;
        std::copy(encoded.begin() + offset,
                  encoded.begin() + offset +
                      INNOVA_PRIVACY_VNEXT_FINALITY_MEMBER_KEY_SIZE,
                  effects.memberKey.begin());
        offset += INNOVA_PRIVACY_VNEXT_FINALITY_MEMBER_KEY_SIZE;
        std::copy(encoded.begin() + offset, encoded.begin() + offset + 32,
                  effects.voteBoundaryHash.begin());
        offset += 32;
        effects.nVoteBoundaryHeight = 0;
        for (size_t i = 0; i < 4; ++i)
            effects.nVoteBoundaryHeight |=
                static_cast<uint32_t>(encoded[offset + i]) << (8 * i);
        offset += 4;
        effects.attestationKeyImages.resize(attestationCount);
        for (size_t i = 0; i < attestationCount; ++i)
        {
            std::copy(encoded.begin() + offset,
                      encoded.begin() + offset + INNOVA_PRIVACY_VNEXT_DIGEST_SIZE,
                      effects.attestationKeyImages[i].begin());
            offset += INNOVA_PRIVACY_VNEXT_DIGEST_SIZE;
        }
        if (offset != encoded.size())
            return DeterministicVNextEffectsReject(
                effects, validation, "trailing IV5 effects bytes");
        validation.strError.clear();
        return validation;
    }
    catch (const std::exception& e)
    {
        // Only allocation and container failures remain; those are node-local.
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

namespace
{
// Memoized effects for payloads already validated in full (proofs dominate connect cost;
// the same payload is validated at mempool entry, connect and replay). Only successes are
// recorded, keyed on the outer wire version and the whole payload.
CCriticalSection cs_vnextEffects;
std::map<uint256, PrivacyVNextStateEffects> mapVNextEffects;
std::deque<uint256> dequeVNextEffects;
const size_t VNEXT_EFFECTS_CACHE_MAX = 65536;

uint256 VNextEffectsCacheKey(uint32_t wireVersion,
                             const std::vector<unsigned char>& payload)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << (uint32_t)wireVersion;
    ss << payload;
    // Height is fixed: a payload's validity is a pure function of its bytes and its outer
    // version, so no verdict here can straddle a fork gate.
    return VerifyProofCacheKey(VERIFYCACHE_IV5_PAYLOAD, 0, ss.GetHash());
}
} // namespace

void ClearPrivacyVNextEffectsCache()
{
    LOCK(cs_vnextEffects);
    mapVNextEffects.clear();
    dequeVNextEffects.clear();
}

size_t PrivacyVNextEffectsCacheSize()
{
    LOCK(cs_vnextEffects);
    return mapVNextEffects.size();
}

void WarmPrivacyVNextEffectsCache(
    const std::vector<std::pair<uint32_t, const std::vector<unsigned char>*> >& vPayloads,
    int nThreads)
{
    // With the cache off there is nothing to fill, and a single payload gains nothing from
    // a thread it would have to wait for anyway.
    if (!VerifyProofCacheEnabled() || vPayloads.size() < 2)
        return;

    unsigned int nWorkers = nThreads > 0 ? (unsigned int)nThreads
                                         : std::thread::hardware_concurrency();
    if (nWorkers == 0)
        nWorkers = 1;
    if (nWorkers > vPayloads.size())
        nWorkers = (unsigned int)vPayloads.size();
    if (nWorkers > 64)
        nWorkers = 64;
    if (nWorkers < 2)
        return;

    std::atomic<size_t> next(0);
    std::vector<std::thread> vWorkers;
    vWorkers.reserve(nWorkers);
    for (unsigned int i = 0; i < nWorkers; ++i)
    {
        vWorkers.push_back(std::thread([&vPayloads, &next]() {
            for (;;)
            {
                const size_t index = next.fetch_add(1);
                if (index >= vPayloads.size())
                    return;
                if (!vPayloads[index].second)
                    continue;
                PrivacyVNextStateEffects discarded;
                // The verdict is deliberately dropped: this call exists for the entry it
                // leaves behind, and a rejection is the sequential validator's to report.
                ExtractPrivacyVNextPayloadEffects(vPayloads[index].first,
                                                  *vPayloads[index].second,
                                                  discarded);
            }
        }));
    }
    for (size_t i = 0; i < vWorkers.size(); ++i)
        vWorkers[i].join();
}

// Effects with the proof verdicts skipped, for a block the caller has already established
// is an ancestor of a hash compiled into this binary.
//
// DELIBERATELY UNCACHED. The effects cache is keyed on the payload alone, so a result
// produced here would be indistinguishable from a verified one and could be served later to
// a caller that must verify. Assume-valid costs about 2 ms, so the cache saves little and
// conflating the two would cost correctness.
PrivacyVNextPayloadValidation ExtractPrivacyVNextPayloadEffectsAssumeValid(
    uint32_t wireVersion,
    const std::vector<unsigned char>& payload,
    PrivacyVNextStateEffects& effects)
{
    return ExtractPrivacyVNextPayloadEffectsUncached(wireVersion, payload, effects,
                                                     VNEXT_EFFECTS_ASSUME_VALID);
}

PrivacyVNextPayloadValidation ExtractPrivacyVNextPayloadEffects(
    uint32_t wireVersion,
    const std::vector<unsigned char>& payload,
    PrivacyVNextStateEffects& effects)
{
    if (!VerifyProofCacheEnabled())
        return ExtractPrivacyVNextPayloadEffectsUncached(wireVersion, payload,
                                                         effects);

    const uint256 key = VNextEffectsCacheKey(wireVersion, payload);
    {
        LOCK(cs_vnextEffects);
        std::map<uint256, PrivacyVNextStateEffects>::const_iterator it =
            mapVNextEffects.find(key);
        if (it != mapVNextEffects.end())
        {
            effects = it->second;
            PrivacyVNextPayloadValidation hit;
            hit.nResult = INNOVA_PRIVACY_VNEXT_VALID;
            hit.fLocalFailure = false;
            return hit;
        }
    }

    const PrivacyVNextPayloadValidation validation =
        ExtractPrivacyVNextPayloadEffectsUncached(wireVersion, payload, effects);
    if (!validation.IsValid())
        return validation;

    LOCK(cs_vnextEffects);
    if (mapVNextEffects.insert(std::make_pair(key, effects)).second)
    {
        dequeVNextEffects.push_back(key);
        while (dequeVNextEffects.size() > VNEXT_EFFECTS_CACHE_MAX)
        {
            mapVNextEffects.erase(dequeVNextEffects.front());
            dequeVNextEffects.pop_front();
        }
    }
    return validation;
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
}

// The hand-framed requests below end at the size the ABI header declares. A request the
// archive widens without a matching change here stops compiling, instead of going out
// with a zero tail the archive reads as a field.
static_assert(PRIVACY_VNEXT_NOTE_SCAN_INPUT_CONTEXT_OFFSET +
                      INNOVA_PRIVACY_VNEXT_INPUT_CONTEXT_SIZE ==
                  INNOVA_PRIVACY_VNEXT_NOTE_SCAN_PREFIX_SIZE,
              "IV5 note-scan framing does not end where the ABI prefix does");
static_assert(PRIVACY_VNEXT_NOTE_SCAN_CIPHERTEXT_OFFSET ==
                  INNOVA_PRIVACY_VNEXT_NOTE_SCAN_PREFIX_SIZE,
              "IV5 note-scan ciphertext does not start where the ABI prefix ends");
static_assert(PRIVACY_VNEXT_NOTE_ENCRYPT_INPUT_CONTEXT_OFFSET +
                      INNOVA_PRIVACY_VNEXT_INPUT_CONTEXT_SIZE ==
                  INNOVA_PRIVACY_VNEXT_NOTE_ENCRYPT_REQUEST_SIZE,
              "IV5 note-encrypt framing does not fill the ABI request");
static_assert(PRIVACY_VNEXT_RECEIVER_DISCLOSURE_INPUT_CONTEXT_OFFSET +
                      INNOVA_PRIVACY_VNEXT_INPUT_CONTEXT_SIZE ==
                  INNOVA_PRIVACY_VNEXT_RECEIVER_DISCLOSURE_REQUEST_SIZE,
              "IV5 receiver-disclosure framing does not fill the ABI request");
static_assert(INNOVA_PRIVACY_VNEXT_INPUT_CONTEXT_SIZE ==
                  INNOVA_PRIVACY_VNEXT_DIGEST_SIZE,
              "IV5 input context is carried as a PrivacyVNextDigest");
static_assert(2 + 1 + 1 + INNOVA_PRIVACY_VNEXT_DIGEST_SIZE ==
                  INNOVA_PRIVACY_VNEXT_INPUT_CONTEXT_REQUEST_HEADER_SIZE,
              "IV5 input-context request header framing disagrees with the ABI");

bool DerivePrivacyVNextInputContext(
    uint8_t nOperation,
    const PrivacyVNextDigest& transparentBinding,
    const std::vector<PrivacyVNextDigest>& vKeyImages,
    PrivacyVNextDigest& contextOut,
    std::string& error)
{
    contextOut.fill(0);
    error.clear();
    if (vKeyImages.size() > INNOVA_PRIVACY_VNEXT_MAX_INPUTS)
    {
        error = "an IV5 input context covers at most sixteen key images";
        return false;
    }

    std::vector<uint8_t> request(
        INNOVA_PRIVACY_VNEXT_INPUT_CONTEXT_REQUEST_HEADER_SIZE +
            (vKeyImages.size() * 32), 0);
    request[0] = static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA);
    request[1] = 0;
    request[2] = nOperation;
    request[3] = static_cast<uint8_t>(vKeyImages.size());
    std::memcpy(&request[4], transparentBinding.data(), 32);
    for (size_t i = 0; i < vKeyImages.size(); ++i)
        std::memcpy(&request[INNOVA_PRIVACY_VNEXT_INPUT_CONTEXT_REQUEST_HEADER_SIZE +
                             (i * 32)],
                    vKeyImages[i].data(), 32);

    const int32_t rc = innova_privacy_vnext_input_context(
        &request[0], request.size(), contextOut.data(), contextOut.size());
    if (rc != INNOVA_PRIVACY_VNEXT_VALID)
    {
        contextOut.fill(0);
        error = ResultError("IV5 input context", rc);
        return false;
    }
    return true;
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
    std::memcpy(&request[140], note.leafC.data(), 32);
    std::memcpy(&request[172], note.noteEphemeral.data(), 32);
    std::memcpy(&request[204], note.tweakEphemeral.data(), 32);
    std::memcpy(&request[PRIVACY_VNEXT_NOTE_SCAN_INPUT_CONTEXT_OFFSET],
                note.inputContext.data(), 32);
    std::memcpy(&request[PRIVACY_VNEXT_NOTE_SCAN_CIPHERTEXT_OFFSET],
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
    nKeyIndex = other.nKeyIndex;
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
        nKeyIndex = other.nKeyIndex;
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
    nKeyIndex = 0;
    nOutputIndex = 0;
    nAmount = 0;
}

bool ScanPrivacyVNextPayload(
    uint8_t scanKind,
    uint8_t network,
    uint8_t addressType,
    uint32_t wireVersion,
    const std::vector<unsigned char>& payload,
    const std::vector<PrivacyVNextScanKey>& keys,
    std::vector<PrivacyVNextScanMatch>& matches,
    std::vector<PrivacyVNextDigest>& keyImages,
    uint8_t& nOutputCount,
    std::string& error)
{
    matches.clear();
    keyImages.clear();
    nOutputCount = 0;
    error.clear();

    if (payload.empty())
    {
        error = "empty IV5 payload";
        return false;
    }

    if (keys.empty() || keys.size() > 1024)
    {
        error = "IV5 scan needs between one and 1024 derivation keys";
        return false;
    }

    static const size_t nHeader = 16;
    static const size_t nRecordSize =
        2 + 4 + 96 + INNOVA_PRIVACY_VNEXT_NOTE_SCAN_RESULT_SIZE;
    const size_t nKeysBytes = keys.size() * 64;

    std::vector<uint8_t> request(nHeader + nKeysBytes + payload.size(), 0);
    request[0] = static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA);
    request[1] = 0;
    request[2] = scanKind;
    request[3] = network;
    request[4] = addressType;
    PutLE32(&request[8], wireVersion);
    request[12] = static_cast<uint8_t>(keys.size() & 0xff);
    request[13] = static_cast<uint8_t>((keys.size() >> 8) & 0xff);
    for (size_t i = 0; i < keys.size(); ++i)
    {
        std::memcpy(&request[nHeader + (i * 64)], keys[i].scanSecret.data(), 32);
        std::memcpy(&request[nHeader + (i * 64) + 32],
                    keys[i].spendMaterial.data(), 32);
    }
    std::memcpy(&request[nHeader + nKeysBytes], &payload[0], payload.size());

    size_t required = 0;
    int32_t result = innova_privacy_vnext_payload_scan(
        &request[0], request.size(), NULL, 0, &required);
    if (result != INNOVA_PRIVACY_VNEXT_VALID || required < 6 ||
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

    static const size_t nResponseHeader = 6;
    const size_t nMatches = response[2];
    const size_t nKeyImages = response[3];
    if (written != response.size() ||
        response[0] != static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA) ||
        response[1] != 0 || response[5] != 0 ||
        written != nResponseHeader + (nKeyImages * 32) + (nMatches * nRecordSize))
    {
        OPENSSL_cleanse(&response[0], response.size());
        error = "non-canonical IV5 payload-scan response";
        return false;
    }

    nOutputCount = response[4];
    if (nMatches > nOutputCount)
    {
        OPENSSL_cleanse(&response[0], response.size());
        error = "IV5 payload scan reported more matches than outputs";
        return false;
    }
    keyImages.resize(nKeyImages);
    for (size_t i = 0; i < nKeyImages; ++i)
        std::memcpy(keyImages[i].data(), &response[nResponseHeader + (i * 32)], 32);

    const size_t nRecordBase = nResponseHeader + (nKeyImages * 32);
    matches.reserve(nMatches);
    for (size_t i = 0; i < nMatches; ++i)
    {
        const uint8_t* record = &response[nRecordBase + (i * nRecordSize)];
        PrivacyVNextScanMatch match;
        match.nKeyIndex = (uint16_t)(record[0] | ((uint16_t)record[1] << 8));
        match.nOutputIndex = ReadLE32(record + 2);
        if (match.nKeyIndex >= keys.size())
        {
            OPENSSL_cleanse(&response[0], response.size());
            error = "IV5 payload scan named a key the caller did not supply";
            return false;
        }
        std::memcpy(match.leaf.owner.data(), record + 6, 32);
        std::memcpy(match.leaf.nullifierBase.data(), record + 38, 32);
        std::memcpy(match.leaf.commitment.data(), record + 70, 32);

        const uint8_t* scanned = record + 102;
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

void PrivacyVNextSpendConstruction::Clear()
{
    OPENSSL_cleanse(pseudoOutMaskDelta.data(), pseudoOutMaskDelta.size());
    pseudoOut.fill(0);
    keyImage.fill(0);
    senderAuthority.fill(0);
    if (!vchSenderDisclosureProof.empty())
        OPENSSL_cleanse(&vchSenderDisclosureProof[0],
                        vchSenderDisclosureProof.size());
    vchSenderDisclosureProof.clear();
}

void PrivacyVNextSpendInput::Clear()
{
    OPENSSL_cleanse(spendScalar.data(), spendScalar.size());
    OPENSSL_cleanse(commitmentScalar.data(), commitmentScalar.size());
    if (!vchWitnessRecord.empty())
        OPENSSL_cleanse(&vchWitnessRecord[0], vchWitnessRecord.size());
    vchWitnessRecord.clear();
}

bool EncryptPrivacyVNextNote(
    uint8_t nNetwork,
    uint8_t nAddressType,
    uint32_t nOutputIndex,
    const PrivacyVNextDigest& genesis,
    const PrivacyVNextDigest& recipientSpend,
    const PrivacyVNextDigest& recipientView,
    const PrivacyVNextDigest& outgoingSecret,
    const PrivacyVNextDigest& noteEphemeralSecret,
    const PrivacyVNextDigest& tweakEphemeralSecret,
    uint64_t nAmount,
    const PrivacyVNextDigest& y,
    const PrivacyVNextDigest& mask,
    const PrivacyVNextDigest& inputContext,
    PrivacyVNextEncryptedOutput& noteOut,
    std::string& error)
{
    noteOut = PrivacyVNextEncryptedOutput();
    error.clear();

    uint8_t request[INNOVA_PRIVACY_VNEXT_NOTE_ENCRYPT_REQUEST_SIZE] = {0};
    request[0] = static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA);
    request[1] = 0;
    request[2] = nNetwork;
    request[3] = nAddressType;
    PutLE32(request + 4, nOutputIndex);
    std::memcpy(request + 8, genesis.data(), 32);
    std::memcpy(request + 40, recipientSpend.data(), 32);
    std::memcpy(request + 72, recipientView.data(), 32);
    std::memcpy(request + 104, outgoingSecret.data(), 32);
    std::memcpy(request + 136, noteEphemeralSecret.data(), 32);
    std::memcpy(request + 168, tweakEphemeralSecret.data(), 32);
    PutLE64(request + 200, nAmount);
    std::memcpy(request + 208, y.data(), 32);
    std::memcpy(request + 240, mask.data(), 32);
    std::memcpy(request + PRIVACY_VNEXT_NOTE_ENCRYPT_INPUT_CONTEXT_OFFSET,
                inputContext.data(), 32);

    uint8_t result[INNOVA_PRIVACY_VNEXT_NOTE_ENCRYPT_RESULT_SIZE] = {0};
    size_t written = 0;
    const int32_t rc = innova_privacy_vnext_note_encrypt(
        request, sizeof(request), result, sizeof(result), &written);
    OPENSSL_cleanse(request, sizeof(request));
    if (rc != INNOVA_PRIVACY_VNEXT_VALID || written != sizeof(result))
    {
        OPENSSL_cleanse(result, sizeof(result));
        error = ResultError("IV5 note encryption", rc);
        return false;
    }

    noteOut.nOutputIndex = nOutputIndex;
    std::memcpy(noteOut.leaf.owner.data(), result + 8, 32);
    std::memcpy(noteOut.leaf.nullifierBase.data(), result + 40, 32);
    std::memcpy(noteOut.leaf.commitment.data(), result + 72, 32);
    std::memcpy(noteOut.noteEphemeral.data(), result + 104, 32);
    std::memcpy(noteOut.tweakEphemeral.data(), result + 136, 32);
    noteOut.vchRecipientCiphertext.assign(
        result + 168,
        result + 168 + INNOVA_PRIVACY_VNEXT_RECIPIENT_CIPHERTEXT_SIZE);
    noteOut.vchOutgoingCiphertext.assign(
        result + 168 + INNOVA_PRIVACY_VNEXT_RECIPIENT_CIPHERTEXT_SIZE,
        result + 168 + INNOVA_PRIVACY_VNEXT_RECIPIENT_CIPHERTEXT_SIZE +
            INNOVA_PRIVACY_VNEXT_OUTGOING_CIPHERTEXT_SIZE);
    OPENSSL_cleanse(result, sizeof(result));
    return true;
}

bool HashPrivacyVNextPayloadPrefix(
    uint32_t nWireVersion,
    const std::vector<unsigned char>& vchPrefix,
    PrivacyVNextDigest& hashOut,
    std::string& error)
{
    hashOut.fill(0);
    error.clear();
    if (vchPrefix.empty())
    {
        error = "IV5 signing hash needs a payload prefix";
        return false;
    }

    std::vector<uint8_t> request;
    request.reserve(8 + vchPrefix.size());
    request.push_back(static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA));
    request.push_back(0);
    request.push_back(0);
    request.push_back(0);
    for (size_t i = 0; i < 4; ++i)
        request.push_back(static_cast<uint8_t>(nWireVersion >> (8 * i)));
    request.insert(request.end(), vchPrefix.begin(), vchPrefix.end());
    if (request.size() > INNOVA_PRIVACY_VNEXT_MAX_PAYLOAD_BYTES)
    {
        error = "IV5 signing hash request exceeds the payload bound";
        return false;
    }

    const int32_t rc = innova_privacy_vnext_payload_signing_hash(
        &request[0], request.size(), hashOut.data(), hashOut.size());
    if (rc != INNOVA_PRIVACY_VNEXT_VALID)
    {
        hashOut.fill(0);
        error = ResultError("IV5 payload signing hash", rc);
        return false;
    }
    return true;
}

bool GetPrivacyVNextProofSize(uint32_t nInputs, size_t& nSizeOut,
                              std::string& error)
{
    nSizeOut = 0;
    error.clear();
    size_t nSize = 0;
    const int32_t rc = innova_privacy_vnext_fcmp_proof_size(
        nInputs, INNOVA_PRIVACY_VNEXT_TREE_LAYERS, &nSize);
    if (rc != INNOVA_PRIVACY_VNEXT_VALID || nSize == 0)
    {
        error = ResultError("IV5 proof size", rc);
        return false;
    }
    nSizeOut = nSize;
    return true;
}

// One membership proof per input, concatenated in input order, so each mix participant
// proves only its own input (the aggregated prover needs every spend scalar). Each input
// draws its own entropy.
bool ProvePrivacyVNextMembershipPerInput(
    const PrivacyVNextDigest& finalizedRoot,
    const PrivacyVNextDigest& signableHash,
    const PrivacyVNextDigest& entropy,
    const std::vector<PrivacyVNextSpendInput>& inputs,
    std::vector<PrivacyVNextSpendConstruction>& constructions,
    std::vector<unsigned char>& vchProof,
    std::string& error)
{
    constructions.clear();
    vchProof.clear();
    error.clear();
    if (inputs.empty())
    {
        error = "a mix proves at least one input";
        return false;
    }

    for (size_t i = 0; i < inputs.size(); ++i)
    {
        // Per-input entropy, derived so the assembly is reproducible while no two inputs
        // share a stream. A real participant supplies its own and this never runs.
        PrivacyVNextDigest inputEntropy;
        {
            CHashWriter ss(SER_GETHASH, 0);
            ss.write((const char*)entropy.data(), entropy.size());
            ss << (unsigned int)i;
            const uint256 draw = ss.GetHash();
            std::memcpy(inputEntropy.data(), draw.begin(), inputEntropy.size());
        }

        const std::vector<PrivacyVNextSpendInput> one(1, inputs[i]);
        std::vector<PrivacyVNextSpendConstruction> oneConstruction;
        std::vector<unsigned char> vchOne;
        if (!ProvePrivacyVNextMembership(finalizedRoot, signableHash, inputEntropy, one,
                                         oneConstruction, vchOne, error))
            return false;
        if (oneConstruction.size() != 1)
        {
            error = "a single-input membership proof returned the wrong construction count";
            return false;
        }
        constructions.push_back(oneConstruction[0]);
        vchProof.insert(vchProof.end(), vchOne.begin(), vchOne.end());
    }
    return true;
}

bool VerifyPrivacyVNextInputMembership(
    const PrivacyVNextDigest& finalizedRoot,
    const PrivacyVNextDigest& signableHash,
    const PrivacyVNextDigest& pseudoOut,
    const PrivacyVNextDigest& keyImage,
    const std::vector<unsigned char>& vchProof,
    std::string& error)
{
    error.clear();
    size_t nProofSize = 0;
    if (!GetPrivacyVNextProofSize(1, nProofSize, error))
        return false;
    if (vchProof.size() != nProofSize)
    {
        error = "IV5 input membership proof is not the one-input size";
        return false;
    }
    std::vector<uint8_t> request;
    request.reserve(8 + 64 + 64 + 4 + vchProof.size());
    request.push_back(static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA));
    request.push_back(0);
    request.push_back(INNOVA_PRIVACY_VNEXT_TREE_LAYERS);
    request.push_back(2);   // Helios root curve
    request.push_back(1);   // one input
    request.push_back(0);
    request.push_back(0);
    request.push_back(0);
    request.insert(request.end(), finalizedRoot.begin(), finalizedRoot.end());
    request.insert(request.end(), signableHash.begin(), signableHash.end());
    request.insert(request.end(), pseudoOut.begin(), pseudoOut.end());
    request.insert(request.end(), keyImage.begin(), keyImage.end());
    for (size_t i = 0; i < 4; ++i)
        request.push_back(static_cast<uint8_t>(vchProof.size() >> (8 * i)));
    request.insert(request.end(), vchProof.begin(), vchProof.end());
    const int32_t rc = innova_privacy_vnext_fcmp_verify(&request[0], request.size());
    if (rc != INNOVA_PRIVACY_VNEXT_VALID)
    {
        error = ResultError("IV5 input membership proof", rc);
        return false;
    }
    return true;
}

bool ProvePrivacyVNextMembership(
    const PrivacyVNextDigest& finalizedRoot,
    const PrivacyVNextDigest& signableHash,
    const PrivacyVNextDigest& entropy,
    const std::vector<PrivacyVNextSpendInput>& inputs,
    std::vector<PrivacyVNextSpendConstruction>& constructions,
    std::vector<unsigned char>& vchProof,
    std::string& error)
{
    constructions.clear();
    vchProof.clear();
    error.clear();

    if (inputs.empty() || inputs.size() > INNOVA_PRIVACY_VNEXT_MAX_INPUTS)
    {
        error = "IV5 membership proof needs between one and sixteen inputs";
        return false;
    }
    PrivacyVNextDigest zero;
    zero.fill(0);
    if (entropy == zero)
    {
        error = "IV5 membership proof needs nonzero caller entropy";
        return false;
    }

    static const size_t nHeader = 8;
    std::vector<uint8_t> request;
    request.resize(nHeader + 96, 0);
    request[0] = static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA);
    request[1] = 0;
    request[2] = INNOVA_PRIVACY_VNEXT_TREE_LAYERS;
    request[3] = 2;   // Helios root curve
    request[4] = static_cast<uint8_t>(inputs.size());
    std::memcpy(&request[nHeader], finalizedRoot.data(), 32);
    std::memcpy(&request[nHeader + 32], signableHash.data(), 32);
    std::memcpy(&request[nHeader + 64], entropy.data(), 32);

    for (size_t i = 0; i < inputs.size(); ++i)
    {
        if (inputs[i].vchWitnessRecord.empty())
        {
            OPENSSL_cleanse(&request[0], request.size());
            error = "IV5 membership proof input is missing its witness record";
            return false;
        }
        request.insert(request.end(), inputs[i].spendScalar.begin(),
                       inputs[i].spendScalar.end());
        request.insert(request.end(), inputs[i].commitmentScalar.begin(),
                       inputs[i].commitmentScalar.end());
        // The witness record already opens with the target's own O-I-C leaf and carries
        // the branches in proving order, so it splices in verbatim.
        request.insert(request.end(), inputs[i].vchWitnessRecord.begin(),
                       inputs[i].vchWitnessRecord.end());
    }
    if (request.size() > INNOVA_PRIVACY_VNEXT_MAX_PAYLOAD_BYTES)
    {
        OPENSSL_cleanse(&request[0], request.size());
        error = "IV5 membership proof request exceeds the payload bound";
        return false;
    }

    size_t required = 0;
    int32_t rc = innova_privacy_vnext_fcmp_prove(&request[0], request.size(),
                                                 NULL, 0, &required);
    if (rc != INNOVA_PRIVACY_VNEXT_VALID || required == 0 ||
        required > INNOVA_PRIVACY_VNEXT_MAX_PAYLOAD_BYTES)
    {
        OPENSSL_cleanse(&request[0], request.size());
        error = ResultError("IV5 membership proof size query", rc);
        return false;
    }
    std::vector<uint8_t> response(required, 0);
    size_t written = 0;
    rc = innova_privacy_vnext_fcmp_prove(&request[0], request.size(),
                                         &response[0], response.size(),
                                         &written);
    OPENSSL_cleanse(&request[0], request.size());
    if (rc != INNOVA_PRIVACY_VNEXT_VALID || written != required)
    {
        OPENSSL_cleanse(&response[0], response.size());
        error = ResultError("IV5 membership proof", rc);
        return false;
    }

    static const size_t nRespHeader =
        INNOVA_PRIVACY_VNEXT_FCMP_PROVE_RESPONSE_HEADER_SIZE;
    static const size_t nRecord =
        INNOVA_PRIVACY_VNEXT_FCMP_PROVE_RESPONSE_RECORD_SIZE;
    if (written < nRespHeader + (inputs.size() * nRecord) + 4 ||
        response[0] != static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA) ||
        response[1] != 0 ||
        response[2] != INNOVA_PRIVACY_VNEXT_TREE_LAYERS ||
        response[3] != static_cast<uint8_t>(inputs.size()))
    {
        OPENSSL_cleanse(&response[0], response.size());
        error = "non-canonical IV5 membership proof response";
        return false;
    }

    constructions.resize(inputs.size());
    for (size_t i = 0; i < inputs.size(); ++i)
    {
        const size_t at = nRespHeader + (i * nRecord);
        std::memcpy(constructions[i].pseudoOut.data(), &response[at], 32);
        std::memcpy(constructions[i].keyImage.data(), &response[at + 32], 32);
        std::memcpy(constructions[i].pseudoOutMaskDelta.data(),
                    &response[at + INNOVA_PRIVACY_VNEXT_FCMP_PROVE_MASK_DELTA_OFFSET],
                    32);
        std::memcpy(constructions[i].senderAuthority.data(),
                    &response[at + INNOVA_PRIVACY_VNEXT_FCMP_PROVE_SENDER_AUTHORITY_OFFSET],
                    32);
        constructions[i].vchSenderDisclosureProof.assign(
            response.begin() + at + INNOVA_PRIVACY_VNEXT_FCMP_PROVE_SENDER_PROOF_OFFSET,
            response.begin() + at + INNOVA_PRIVACY_VNEXT_FCMP_PROVE_SENDER_PROOF_OFFSET +
                INNOVA_PRIVACY_VNEXT_SENDER_DISCLOSURE_PROOF_SIZE);
    }

    const size_t nLenAt = nRespHeader + (inputs.size() * nRecord);
    uint32_t nProofLen = 0;
    for (size_t b = 0; b < 4; ++b)
        nProofLen |= static_cast<uint32_t>(response[nLenAt + b]) << (8 * b);
    if (written != nLenAt + 4 + nProofLen)
    {
        constructions.clear();
        OPENSSL_cleanse(&response[0], response.size());
        error = "IV5 membership proof length does not match its response";
        return false;
    }
    // The proof must be exactly the size upstream fixes for this input count, or the
    // payload it goes into cannot be the canonical one a verifier expects.
    size_t nExpected = 0;
    if (!GetPrivacyVNextProofSize(static_cast<uint32_t>(inputs.size()),
                                  nExpected, error) ||
        nExpected != nProofLen)
    {
        constructions.clear();
        OPENSSL_cleanse(&response[0], response.size());
        if (error.empty())
            error = "IV5 membership proof is not the exact upstream size";
        return false;
    }
    vchProof.assign(response.begin() + nLenAt + 4, response.end());
    OPENSSL_cleanse(&response[0], response.size());
    return true;
}

static bool RunPrivacyVNextWitnessRequest(
    const std::vector<uint8_t>& request,
    const std::vector<uint64_t>& vTargetLeafIndexes,
    std::vector<PrivacyVNextMembershipWitness>& witnesses,
    PrivacyVNextDigest& treeRoot,
    std::string& error);

bool BuildPrivacyVNextWitnesses(
    const std::vector<unsigned char>& treeState,
    const std::vector<PrivacyVNextOutputLeaf>& leaves,
    const std::vector<uint64_t>& vTargetLeafIndexes,
    std::vector<PrivacyVNextMembershipWitness>& witnesses,
    PrivacyVNextDigest& treeRoot,
    std::string& error)
{
    witnesses.clear();
    treeRoot.fill(0);
    error.clear();

    if (treeState.size() != INNOVA_PRIVACY_VNEXT_TREE_STATE_SIZE)
    {
        error = "IV5 witness needs the exact canonical tree state";
        return false;
    }
    if (vTargetLeafIndexes.empty() ||
        vTargetLeafIndexes.size() > INNOVA_PRIVACY_VNEXT_MAX_INPUTS)
    {
        error = "IV5 witness needs between one and sixteen targets";
        return false;
    }
    if (leaves.empty())
    {
        error = "IV5 witness needs the tree's leaf set";
        return false;
    }
    for (size_t i = 0; i < vTargetLeafIndexes.size(); ++i)
    {
        if (vTargetLeafIndexes[i] >= leaves.size())
        {
            error = "IV5 witness target is outside the supplied leaf set";
            return false;
        }
        for (size_t j = 0; j < i; ++j)
        {
            if (vTargetLeafIndexes[j] == vTargetLeafIndexes[i])
            {
                error = "IV5 witness targets repeat a leaf index";
                return false;
            }
        }
    }

    static const size_t nHeader = 4;
    static const size_t nLeafSize = 96;
    const size_t nRequest = nHeader + INNOVA_PRIVACY_VNEXT_TREE_STATE_SIZE +
                            (vTargetLeafIndexes.size() * 8) + 4 +
                            (leaves.size() * nLeafSize);
    if (nRequest > INNOVA_PRIVACY_VNEXT_MAX_PAYLOAD_BYTES)
    {
        error = "IV5 witness request needs " + std::to_string(nRequest) +
                " bytes for " + std::to_string(leaves.size()) +
                " leaves, over the " +
                std::to_string((size_t)INNOVA_PRIVACY_VNEXT_MAX_PAYLOAD_BYTES) + " bound";
        return false;
    }

    std::vector<uint8_t> request(nRequest, 0);
    request[0] = static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA);
    request[1] = 0;
    request[2] = static_cast<uint8_t>(vTargetLeafIndexes.size());
    std::memcpy(&request[nHeader], &treeState[0], treeState.size());
    size_t offset = nHeader + treeState.size();
    for (size_t i = 0; i < vTargetLeafIndexes.size(); ++i)
    {
        PutLE64(&request[offset], vTargetLeafIndexes[i]);
        offset += 8;
    }
    PutLE32(&request[offset], static_cast<uint32_t>(leaves.size()));
    offset += 4;
    for (size_t i = 0; i < leaves.size(); ++i)
    {
        std::memcpy(&request[offset], leaves[i].owner.data(), 32);
        std::memcpy(&request[offset + 32], leaves[i].nullifierBase.data(), 32);
        std::memcpy(&request[offset + 64], leaves[i].commitment.data(), 32);
        offset += nLeafSize;
    }

    return RunPrivacyVNextWitnessRequest(request, vTargetLeafIndexes, witnesses,
                                         treeRoot, error);
}

// Issue one witness request and decode its response. Both request modes answer in the
// same format, so the decode belongs in one place.
static bool RunPrivacyVNextWitnessRequest(
    const std::vector<uint8_t>& request,
    const std::vector<uint64_t>& vTargetLeafIndexes,
    std::vector<PrivacyVNextMembershipWitness>& witnesses,
    PrivacyVNextDigest& treeRoot,
    std::string& error)
{
    static const size_t nLeafSize = 96;
    size_t required = 0;
    int32_t result = innova_privacy_vnext_tree_witness(
        &request[0], request.size(), NULL, 0, &required);
    if (result != INNOVA_PRIVACY_VNEXT_VALID || required == 0 ||
        required > INNOVA_PRIVACY_VNEXT_MAX_PAYLOAD_BYTES)
    {
        error = ResultError("IV5 witness size query", result);
        return false;
    }

    std::vector<uint8_t> response(required, 0);
    size_t written = 0;
    result = innova_privacy_vnext_tree_witness(
        &request[0], request.size(), &response[0], response.size(), &written);
    if (result != INNOVA_PRIVACY_VNEXT_VALID)
    {
        error = ResultError("IV5 witness", result);
        return false;
    }

    static const size_t nRootSize = INNOVA_PRIVACY_VNEXT_TREE_ROOT_SIZE;
    if (written != response.size() || written < nRootSize + 4 ||
        response[0] != static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA) ||
        response[1] != 0 ||
        response[nRootSize] != vTargetLeafIndexes.size() ||
        response[nRootSize + 1] != 0 || response[nRootSize + 2] != 0 ||
        response[nRootSize + 3] != 0)
    {
        error = "non-canonical IV5 witness response";
        return false;
    }
    std::memcpy(treeRoot.data(), &response[12], 32);

    // Records are positional and variable width: each carries its own leaf-branch
    // count, so the next record only starts after this one is measured.
    static const size_t nBranchBytes = (4 * 18 * 32) + (3 * 38 * 32);
    size_t nPos = nRootSize + 4;
    witnesses.resize(vTargetLeafIndexes.size());
    for (size_t i = 0; i < vTargetLeafIndexes.size(); ++i)
    {
        if (nPos + 100 > written)
        {
            witnesses.clear();
            error = "IV5 witness response is truncated";
            return false;
        }
        const size_t nBranchLeaves = response[nPos + 96];
        if (nBranchLeaves == 0 || nBranchLeaves > 38 ||
            response[nPos + 97] != 0 || response[nPos + 98] != 0 ||
            response[nPos + 99] != 0)
        {
            witnesses.clear();
            error = "IV5 witness record has a malformed leaf branch";
            return false;
        }
        const size_t nRecord = 100 + (nBranchLeaves * nLeafSize) + nBranchBytes;
        if (nPos + nRecord > written)
        {
            witnesses.clear();
            error = "IV5 witness response is truncated";
            return false;
        }
        witnesses[i].nLeafIndex = vTargetLeafIndexes[i];
        witnesses[i].vchRecord.assign(response.begin() + nPos,
                                      response.begin() + nPos + nRecord);
        nPos += nRecord;
    }
    if (nPos != written)
    {
        witnesses.clear();
        error = "IV5 witness response has trailing bytes";
        return false;
    }
    return true;
}

bool BuildPrivacyVNextWitnessesFromPaths(
    const std::vector<unsigned char>& treeState,
    const std::vector<uint64_t>& vTargetLeafIndexes,
    const std::vector<unsigned char>& vchPaths,
    std::vector<PrivacyVNextMembershipWitness>& witnesses,
    PrivacyVNextDigest& treeRoot,
    std::string& error)
{
    witnesses.clear();
    treeRoot.fill(0);
    error.clear();

    if (treeState.size() != INNOVA_PRIVACY_VNEXT_TREE_STATE_SIZE)
    {
        error = "IV5 witness needs the exact canonical tree state";
        return false;
    }
    if (vTargetLeafIndexes.empty() ||
        vTargetLeafIndexes.size() > INNOVA_PRIVACY_VNEXT_MAX_INPUTS)
    {
        error = "IV5 witness needs between one and sixteen targets";
        return false;
    }
    if (vchPaths.empty())
    {
        error = "IV5 path-mode witness needs the targets' sibling paths";
        return false;
    }
    for (size_t i = 0; i < vTargetLeafIndexes.size(); ++i)
    {
        for (size_t j = 0; j < i; ++j)
        {
            if (vTargetLeafIndexes[j] == vTargetLeafIndexes[i])
            {
                error = "IV5 witness targets repeat a leaf index";
                return false;
            }
        }
    }

    static const size_t nHeader = 4;
    const size_t nRequest = nHeader + INNOVA_PRIVACY_VNEXT_TREE_STATE_SIZE +
                            (vTargetLeafIndexes.size() * 8) + vchPaths.size();
    if (nRequest > INNOVA_PRIVACY_VNEXT_MAX_PAYLOAD_BYTES)
    {
        error = "IV5 path-mode witness request needs " +
                std::to_string(nRequest) + " bytes, over the " +
                std::to_string((size_t)INNOVA_PRIVACY_VNEXT_MAX_PAYLOAD_BYTES) +
                " bound";
        return false;
    }

    std::vector<uint8_t> request(nRequest, 0);
    request[0] = static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA);
    request[1] = 0;
    request[2] = static_cast<uint8_t>(vTargetLeafIndexes.size());
    request[3] = 1;
    std::memcpy(&request[nHeader], &treeState[0], treeState.size());
    size_t offset = nHeader + treeState.size();
    for (size_t i = 0; i < vTargetLeafIndexes.size(); ++i)
    {
        PutLE64(&request[offset], vTargetLeafIndexes[i]);
        offset += 8;
    }
    std::memcpy(&request[offset], &vchPaths[0], vchPaths.size());

    return RunPrivacyVNextWitnessRequest(request, vTargetLeafIndexes, witnesses,
                                         treeRoot, error);
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

    const size_t nFixed = 4 + (vOutputs.size() * 32) + 4 + 64;
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
    return true;
}

bool ProvePrivacyVNextReceiverDisclosure(
    uint32_t nOutputIndex,
    const PrivacyVNextDigest& recipientSpend,
    const PrivacyVNextDigest& recipientView,
    const PrivacyVNextDigest& outputOwner,
    const PrivacyVNextDigest& tweakEphemeralPublic,
    const PrivacyVNextDigest& tweakEphemeralSecret,
    const PrivacyVNextDigest& outputY,
    const PrivacyVNextDigest& signableHash,
    const PrivacyVNextDigest& entropy,
    const PrivacyVNextDigest& inputContext,
    std::vector<unsigned char>& vchProofOut,
    std::string& error)
{
    vchProofOut.clear();
    error.clear();

    std::vector<uint8_t> request(
        INNOVA_PRIVACY_VNEXT_RECEIVER_DISCLOSURE_REQUEST_SIZE, 0);
    request[0] = static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA);
    request[1] = 0;
    PutLE32(&request[4], nOutputIndex);
    std::memcpy(&request[8], recipientSpend.data(), 32);
    std::memcpy(&request[40], recipientView.data(), 32);
    std::memcpy(&request[72], outputOwner.data(), 32);
    std::memcpy(&request[104], tweakEphemeralPublic.data(), 32);
    std::memcpy(&request[136], tweakEphemeralSecret.data(), 32);
    std::memcpy(&request[168], outputY.data(), 32);
    std::memcpy(&request[200], signableHash.data(), 32);
    std::memcpy(&request[232], entropy.data(), 32);
    std::memcpy(&request[PRIVACY_VNEXT_RECEIVER_DISCLOSURE_INPUT_CONTEXT_OFFSET],
                inputContext.data(), 32);

    std::vector<uint8_t> response(
        INNOVA_PRIVACY_VNEXT_RECEIVER_DISCLOSURE_PROOF_SIZE, 0);
    size_t written = 0;
    const int32_t result = innova_privacy_vnext_receiver_disclosure_prove(
        &request[0], request.size(), &response[0], response.size(), &written);
    OPENSSL_cleanse(&request[0], request.size());
    if (result != INNOVA_PRIVACY_VNEXT_VALID || written != response.size())
    {
        error = ResultError("IV5 receiver disclosure proof", result);
        return false;
    }
    vchProofOut.assign(response.begin(), response.end());
    return true;
}

// Prove one commitment opens to a fixed amount. The commitment must be the re-randomized
// one the payload names: a proof against a leaf would identify the note.
bool ProvePrivacyVNextAmountEquality(
    const PrivacyVNextDigest& commitment,
    uint64_t nAmount,
    const PrivacyVNextDigest& mask,
    const PrivacyVNextDigest& signableHash,
    const PrivacyVNextDigest& entropy,
    std::vector<unsigned char>& vchProofOut,
    std::string& error)
{
    vchProofOut.clear();
    error.clear();

    std::vector<uint8_t> request(
        INNOVA_PRIVACY_VNEXT_AMOUNT_EQUALITY_REQUEST_SIZE, 0);
    request[0] = static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA);
    request[1] = 0;
    PutLE64(&request[4], nAmount);
    std::memcpy(&request[12], commitment.data(), 32);
    std::memcpy(&request[44], mask.data(), 32);
    std::memcpy(&request[76], signableHash.data(), 32);
    std::memcpy(&request[108], entropy.data(), 32);

    std::vector<uint8_t> response(
        INNOVA_PRIVACY_VNEXT_AMOUNT_EQUALITY_PROOF_SIZE, 0);
    size_t written = 0;
    const int32_t result = innova_privacy_vnext_amount_equality_prove(
        &request[0], request.size(), &response[0], response.size(), &written);
    OPENSSL_cleanse(&request[0], request.size());
    if (result != INNOVA_PRIVACY_VNEXT_VALID || written != response.size())
    {
        error = ResultError("IV5 amount equality proof", result);
        return false;
    }
    vchProofOut.assign(response.begin(), response.end());
    return true;
}

PrivacyVNextMixBalanceFacts::PrivacyVNextMixBalanceFacts()
{
    nOutputCount = 0;
    nInputCount = 0;
    nTransparentValueBalance = 0;
    nFee = 0;
    signableHash.fill(0);
}

PrivacyVNextMixBalanceShare::PrivacyVNextMixBalanceShare()
{
    nInputIndex = 0;
    nOutputIndex = 0;
    nFeeShare = 0;
    mask.fill(0);
    outputMask.fill(0);
    entropy.fill(0);
}

namespace
{

const size_t MIX_BALANCE_FACTS_HEADER = 52;
const size_t MIX_BALANCE_SHARE_BYTES = 108;
const size_t MIX_BALANCE_PROOF_BYTES = 64;

bool EncodeMixBalanceFacts(const PrivacyVNextMixBalanceFacts& facts,
                           std::vector<uint8_t>& vchOut, std::string& error)
{
    vchOut.clear();
    if (facts.nInputCount == 0 || facts.nOutputCount == 0)
    {
        error = "IV5 mix balance: a mix declares at least one input and one output";
        return false;
    }
    if (facts.vPseudoOuts.size() != facts.nInputCount ||
        facts.vOutputs.size() != facts.nOutputCount)
    {
        error = "IV5 mix balance: the declared counts do not match the commitments given";
        return false;
    }
    vchOut.assign(MIX_BALANCE_FACTS_HEADER +
                      32 * (facts.vPseudoOuts.size() + facts.vOutputs.size()),
                  0);
    vchOut[0] = static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA);
    vchOut[1] = 0;
    vchOut[2] = facts.nOutputCount;
    vchOut[3] = facts.nInputCount;
    PutLE64(&vchOut[4], static_cast<uint64_t>(facts.nTransparentValueBalance));
    PutLE64(&vchOut[12], facts.nFee);
    std::memcpy(&vchOut[20], facts.signableHash.data(), 32);
    size_t nCursor = MIX_BALANCE_FACTS_HEADER;
    for (size_t i = 0; i < facts.vPseudoOuts.size(); i++, nCursor += 32)
        std::memcpy(&vchOut[nCursor], facts.vPseudoOuts[i].data(), 32);
    for (size_t i = 0; i < facts.vOutputs.size(); i++, nCursor += 32)
        std::memcpy(&vchOut[nCursor], facts.vOutputs[i].data(), 32);
    return true;
}

void AppendMixBalanceShare(const PrivacyVNextMixBalanceShare& share,
                           std::vector<uint8_t>& vchOut)
{
    const size_t nAt = vchOut.size();
    vchOut.resize(nAt + MIX_BALANCE_SHARE_BYTES, 0);
    vchOut[nAt] = share.nInputIndex;
    vchOut[nAt + 1] = share.nOutputIndex;
    PutLE64(&vchOut[nAt + 4], share.nFeeShare);
    std::memcpy(&vchOut[nAt + 12], share.mask.data(), 32);
    std::memcpy(&vchOut[nAt + 44], share.outputMask.data(), 32);
    std::memcpy(&vchOut[nAt + 76], share.entropy.data(), 32);
}

bool AppendMixBalanceDigests(const std::vector<PrivacyVNextDigest>& vDigests,
                             size_t nExpected, const char* pszWhat,
                             std::vector<uint8_t>& vchOut, std::string& error)
{
    if (vDigests.size() != nExpected)
    {
        error = strprintf("IV5 mix balance: %zu %s for %zu seats",
                          vDigests.size(), pszWhat, nExpected);
        return false;
    }
    for (size_t i = 0; i < vDigests.size(); i++)
    {
        const size_t nAt = vchOut.size();
        vchOut.resize(nAt + 32, 0);
        std::memcpy(&vchOut[nAt], vDigests[i].data(), 32);
    }
    return true;
}

bool CallMixBalance(int32_t (*pfn)(const uint8_t*, size_t, uint8_t*, size_t, size_t*),
                    std::vector<uint8_t>& request, size_t nOutBytes,
                    const char* pszWhat, std::vector<unsigned char>& vchOut,
                    std::string& error)
{
    std::vector<uint8_t> response(nOutBytes, 0);
    size_t written = 0;
    const int32_t result =
        pfn(&request[0], request.size(), &response[0], response.size(), &written);
    OPENSSL_cleanse(&request[0], request.size());
    if (result != INNOVA_PRIVACY_VNEXT_VALID || written != response.size())
    {
        error = ResultError(pszWhat, result);
        return false;
    }
    vchOut.assign(response.begin(), response.end());
    return true;
}

} // namespace

bool PrivacyVNextMixBalanceNonce(
    const PrivacyVNextMixBalanceFacts& facts,
    const PrivacyVNextMixBalanceShare& share,
    PrivacyVNextDigest& nonceOut,
    std::string& error)
{
    nonceOut.fill(0);
    error.clear();
    std::vector<uint8_t> request;
    if (!EncodeMixBalanceFacts(facts, request, error))
        return false;
    AppendMixBalanceShare(share, request);
    std::vector<unsigned char> vchOut;
    if (!CallMixBalance(&innova_privacy_vnext_mix_balance_nonce, request, 32,
                        "IV5 mix balance nonce", vchOut, error))
        return false;
    std::memcpy(nonceOut.data(), &vchOut[0], 32);
    return true;
}

bool PrivacyVNextMixBalanceSign(
    const PrivacyVNextMixBalanceFacts& facts,
    const PrivacyVNextMixBalanceShare& share,
    const std::vector<PrivacyVNextDigest>& vNonces,
    PrivacyVNextDigest& responseOut,
    std::string& error)
{
    responseOut.fill(0);
    error.clear();
    std::vector<uint8_t> request;
    if (!EncodeMixBalanceFacts(facts, request, error))
        return false;
    AppendMixBalanceShare(share, request);
    if (!AppendMixBalanceDigests(vNonces, facts.nInputCount, "nonce points", request, error))
        return false;
    std::vector<unsigned char> vchOut;
    if (!CallMixBalance(&innova_privacy_vnext_mix_balance_sign, request, 32,
                        "IV5 mix balance signature share", vchOut, error))
        return false;
    std::memcpy(responseOut.data(), &vchOut[0], 32);
    return true;
}

bool PrivacyVNextMixBalanceCombine(
    const PrivacyVNextMixBalanceFacts& facts,
    const std::vector<PrivacyVNextDigest>& vNonces,
    const std::vector<PrivacyVNextDigest>& vResponses,
    const std::vector<PrivacyVNextDigest>& vOutputMasks,
    std::vector<unsigned char>& vchProofOut,
    std::string& error)
{
    vchProofOut.clear();
    error.clear();
    std::vector<uint8_t> request;
    if (!EncodeMixBalanceFacts(facts, request, error))
        return false;
    if (!AppendMixBalanceDigests(vNonces, facts.nInputCount, "nonce points", request, error))
        return false;
    if (!AppendMixBalanceDigests(vResponses, facts.nInputCount, "responses", request, error))
        return false;
    if (!AppendMixBalanceDigests(vOutputMasks, facts.nOutputCount, "output openings",
                                 request, error))
        return false;
    return CallMixBalance(&innova_privacy_vnext_mix_balance_combine, request,
                          MIX_BALANCE_PROOF_BYTES, "IV5 mix balance proof",
                          vchProofOut, error);
}

PrivacyVNextCombineTerm::PrivacyVNextCombineTerm()
{
    nSource = PRIVACY_VNEXT_TERM_SUPPLIED;
    scalar.fill(0);
    point.fill(0);
}

namespace
{

} // namespace

bool CombinePrivacyVNextPoints(
    const std::vector<PrivacyVNextCombineTerm>& vTerms,
    PrivacyVNextDigest& pointOut,
    std::string& error)
{
    error.clear();
    pointOut.fill(0);

    PrivacyVNextDigest zero;
    zero.fill(0);

    // The ABI bounds one call at 1024 terms; a longer sum chains by feeding the running
    // total back as a supplied point, so callers never have to know the bound.
    const size_t nChunk = 1024;
    bool fHaveRunning = false;
    PrivacyVNextDigest running;
    running.fill(0);

    size_t nOffset = 0;
    do
    {
        std::vector<PrivacyVNextCombineTerm> vChunk;
        if (fHaveRunning)
        {
            PrivacyVNextCombineTerm carry;
            carry.nSource = PRIVACY_VNEXT_TERM_SUPPLIED;
            carry.scalar[0] = 1;
            carry.point = running;
            vChunk.push_back(carry);
        }
        while (nOffset < vTerms.size() && vChunk.size() < nChunk)
            vChunk.push_back(vTerms[nOffset++]);

        std::vector<uint8_t> request(8, 0);
        request[0] = static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA);
        request[1] = 0;
        request[4] = static_cast<uint8_t>(vChunk.size() & 0xff);
        request[5] = static_cast<uint8_t>((vChunk.size() >> 8) & 0xff);
        for (size_t i = 0; i < vChunk.size(); ++i)
        {
            if (vChunk[i].nSource != PRIVACY_VNEXT_TERM_SUPPLIED &&
                vChunk[i].point != zero)
            {
                error = "IV5 point combination generator term carries a point";
                return false;
            }
            request.push_back(vChunk[i].nSource);
            request.insert(request.end(), 3, 0);
            request.insert(request.end(), vChunk[i].scalar.begin(), vChunk[i].scalar.end());
            request.insert(request.end(), vChunk[i].point.begin(), vChunk[i].point.end());
        }

        std::vector<uint8_t> response(32, 0);
        size_t written = 0;
        const int32_t rc = innova_privacy_vnext_ed25519_combine(
            &request[0], request.size(), &response[0], response.size(), &written);
        if (rc != INNOVA_PRIVACY_VNEXT_VALID || written != response.size())
        {
            error = ResultError("IV5 point combination", rc);
            return false;
        }
        std::memcpy(running.data(), &response[0], 32);
        fHaveRunning = true;
    } while (nOffset < vTerms.size());

    pointOut = running;
    return true;
}

bool ProvePrivacyVNextRange(
    uint64_t nAmount,
    const PrivacyVNextDigest& mask,
    const PrivacyVNextDigest& entropy,
    PrivacyVNextDigest& commitmentOut,
    std::vector<unsigned char>& vchProofOut,
    std::string& error)
{
    commitmentOut.fill(0);
    vchProofOut.clear();
    error.clear();

    std::vector<uint8_t> request(12, 0);
    request[0] = static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA);
    request[1] = 0;
    PutLE64(&request[4], nAmount);
    request.insert(request.end(), mask.begin(), mask.end());
    request.insert(request.end(), entropy.begin(), entropy.end());

    size_t required = 0;
    int32_t rc = innova_privacy_vnext_range_prove(&request[0], request.size(),
                                                  NULL, 0, &required);
    if (rc != INNOVA_PRIVACY_VNEXT_VALID || required <= 36 ||
        required > INNOVA_PRIVACY_VNEXT_MAX_PAYLOAD_BYTES)
    {
        OPENSSL_cleanse(&request[0], request.size());
        error = ResultError("IV5 range proof size query", rc);
        return false;
    }
    std::vector<uint8_t> response(required, 0);
    size_t written = 0;
    rc = innova_privacy_vnext_range_prove(&request[0], request.size(),
                                          &response[0], response.size(), &written);
    OPENSSL_cleanse(&request[0], request.size());
    if (rc != INNOVA_PRIVACY_VNEXT_VALID || written != required)
    {
        error = ResultError("IV5 range proof", rc);
        return false;
    }
    const uint32_t nProofLen = ReadLE32(&response[32]);
    if (nProofLen == 0 || response.size() != 36 + nProofLen)
    {
        error = "IV5 range proof returned a truncated response";
        return false;
    }
    std::memcpy(commitmentOut.data(), &response[0], 32);
    vchProofOut.assign(response.begin() + 36, response.end());
    return true;
}

bool VerifyPrivacyVNextRange(
    const PrivacyVNextDigest& commitment,
    const PrivacyVNextDigest& signableHash,
    const std::vector<unsigned char>& vchProof,
    std::string& error)
{
    error.clear();
    if (vchProof.empty() ||
        vchProof.size() > INNOVA_PRIVACY_VNEXT_MAX_PAYLOAD_BYTES)
    {
        error = "IV5 range proof has an unusable length";
        return false;
    }
    std::vector<uint8_t> request(4, 0);
    request[0] = static_cast<uint8_t>(iv5::PROTOCOL_SCHEMA);
    request[1] = 0;
    request.insert(request.end(), commitment.begin(), commitment.end());
    request.insert(request.end(), signableHash.begin(), signableHash.end());
    request.insert(request.end(), vchProof.begin(), vchProof.end());

    const int32_t rc = innova_privacy_vnext_range_verify(&request[0], request.size());
    if (rc != INNOVA_PRIVACY_VNEXT_VALID)
    {
        error = ResultError("IV5 range proof verification", rc);
        return false;
    }
    return true;
}
