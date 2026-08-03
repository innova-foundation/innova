// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license.

#include <boost/test/unit_test.hpp>

#include "privacy_vnext_ffi.h"
#include "privacy_vnext/iv5_protocol.h"
#include "privacy_vnext/rust/include/innova_privacy_vnext.h"

#include <cstring>
#include <vector>

namespace
{
void PutLE64(uint8_t* out, uint64_t value)
{
    for (size_t i = 0; i < 8; ++i)
        out[i] = static_cast<uint8_t>(value >> (8 * i));
}

uint64_t ReadLE64(const uint8_t* in)
{
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i)
        value |= static_cast<uint64_t>(in[i]) << (8 * i);
    return value;
}

uint32_t ReadLE32(const uint8_t* in)
{
    uint32_t value = 0;
    for (size_t i = 0; i < 4; ++i)
        value |= static_cast<uint32_t>(in[i]) << (8 * i);
    return value;
}
}

BOOST_AUTO_TEST_SUITE(privacy_vnext_abi_tests)

BOOST_AUTO_TEST_CASE(linked_contract_is_exact_and_consensus_disabled)
{
    PrivacyVNextAbiInfo info;
    BOOST_REQUIRE_MESSAGE(LoadPrivacyVNextAbiInfo(info), info.strError);
    BOOST_CHECK(info.fLinked);
    BOOST_CHECK_EQUAL(info.nAbiVersion, 2U);
    BOOST_CHECK_EQUAL(info.nTransactionVersion, 2008U);
    BOOST_CHECK_EQUAL(info.nTreeLayers, 8U);
    BOOST_CHECK_EQUAL(info.nPayloadSchema, 1U);
    BOOST_CHECK_EQUAL(info.nImplementedCapabilities,
                      INNOVA_PRIVACY_VNEXT_IMPLEMENTED_CAPABILITIES);
    BOOST_CHECK_EQUAL(info.nConsensusCapabilities, 0U);
    BOOST_CHECK_EQUAL(info.nConsensusActive, 0U);
    BOOST_CHECK_EQUAL(info.strParameterDigest,
                      iv5::PROTOCOL_CONTRACT_SHA256);
    BOOST_CHECK_EQUAL(info.strAbiSha256.size(), 64U);
    BOOST_CHECK_EQUAL(info.strProvenanceDigest.size(), 64U);
    BOOST_CHECK_EQUAL(info.strUpstreamRevision,
                      "76399e58bfc7e652d900936f84b3785ea59ab4cd");
}

BOOST_AUTO_TEST_CASE(malformed_verification_is_fail_closed_and_differential)
{
    const uint8_t request[] = {1};
    const int32_t single =
        innova_privacy_vnext_fcmp_verify(request, sizeof(request));
    const int32_t batch =
        innova_privacy_vnext_fcmp_batch_verify(request, sizeof(request), 1);
    BOOST_CHECK_EQUAL(single, INNOVA_PRIVACY_VNEXT_BAD_LENGTH);
    BOOST_CHECK_EQUAL(batch, single);
    BOOST_CHECK_EQUAL(
        innova_privacy_vnext_payload_validate(request, sizeof(request)),
        INNOVA_PRIVACY_VNEXT_BAD_LENGTH);
    size_t effectsWritten = 99;
    uint8_t effects[INNOVA_PRIVACY_VNEXT_PAYLOAD_EFFECTS_HEADER_SIZE];
    std::memset(effects, 0xa5, sizeof(effects));
    BOOST_CHECK_EQUAL(
        innova_privacy_vnext_payload_effects(
            request, sizeof(request), effects, sizeof(effects),
            &effectsWritten),
        INNOVA_PRIVACY_VNEXT_BAD_LENGTH);
    BOOST_CHECK_EQUAL(effectsWritten, 99U);
    for (size_t i = 0; i < sizeof(effects); ++i)
        BOOST_CHECK_EQUAL(effects[i], 0xa5U);
}

BOOST_AUTO_TEST_CASE(cpp_payload_validation_preserves_result_class)
{
    const std::vector<unsigned char> emptyPayload;
    const PrivacyVNextPayloadValidation badLength =
        ValidatePrivacyVNextPayload(2008, emptyPayload);
    BOOST_CHECK_EQUAL(badLength.nResult,
                      INNOVA_PRIVACY_VNEXT_BAD_LENGTH);
    BOOST_CHECK(!badLength.fLocalFailure);
    BOOST_CHECK(!badLength.IsValid());

    const std::vector<unsigned char> oversized(
        INNOVA_PRIVACY_VNEXT_MAX_PAYLOAD_BYTES + 1, 0);
    const PrivacyVNextPayloadValidation resourceLimit =
        ValidatePrivacyVNextPayload(2008, oversized);
    BOOST_CHECK_EQUAL(resourceLimit.nResult,
                      INNOVA_PRIVACY_VNEXT_RESOURCE_LIMIT);
    BOOST_CHECK(!resourceLimit.fLocalFailure);
}

BOOST_AUTO_TEST_CASE(key_and_address_round_trip_crosses_the_c_abi)
{
    uint8_t keyRequest[INNOVA_PRIVACY_VNEXT_KEY_DERIVATION_REQUEST_SIZE] = {0};
    keyRequest[0] = 1;
    keyRequest[2] = 1;
    keyRequest[4] = 7;
    for (size_t i = 0; i < 32; ++i)
    {
        keyRequest[8 + i] = static_cast<uint8_t>(i + 1);
        keyRequest[40 + i] = static_cast<uint8_t>(0xa0 + i);
    }
    uint8_t keys[INNOVA_PRIVACY_VNEXT_KEY_DERIVATION_OUTPUT_SIZE] = {0};
    size_t keysWritten = 0;
    BOOST_REQUIRE_EQUAL(
        innova_privacy_vnext_key_derive(
            keyRequest, sizeof(keyRequest), keys, sizeof(keys), &keysWritten),
        INNOVA_PRIVACY_VNEXT_VALID);
    BOOST_REQUIRE_EQUAL(keysWritten, sizeof(keys));

    uint8_t components[INNOVA_PRIVACY_VNEXT_ADDRESS_COMPONENT_SIZE] = {0};
    components[0] = 1;
    components[2] = 1;
    components[3] = INNOVA_PRIVACY_VNEXT_ADDRESS_FORMAT;
    std::memcpy(components + 6, keys + 168, 64);
    uint8_t address[128] = {0};
    size_t addressWritten = 0;
    BOOST_REQUIRE_EQUAL(
        innova_privacy_vnext_address_encode(
            components, sizeof(components), address, sizeof(address),
            &addressWritten),
        INNOVA_PRIVACY_VNEXT_VALID);
    BOOST_REQUIRE(addressWritten > 90 && addressWritten < sizeof(address));

    std::vector<uint8_t> decodeRequest;
    decodeRequest.push_back(1);
    decodeRequest.push_back(0);
    decodeRequest.push_back(1);
    decodeRequest.push_back(0);
    decodeRequest.insert(decodeRequest.end(), address,
                         address + addressWritten);
    uint8_t decoded[INNOVA_PRIVACY_VNEXT_ADDRESS_COMPONENT_SIZE] = {0};
    size_t decodedWritten = 0;
    BOOST_REQUIRE_EQUAL(
        innova_privacy_vnext_address_decode(
            &decodeRequest[0], decodeRequest.size(), decoded, sizeof(decoded),
            &decodedWritten),
        INNOVA_PRIVACY_VNEXT_VALID);
    BOOST_CHECK_EQUAL(decodedWritten, sizeof(components));
    BOOST_CHECK_EQUAL_COLLECTIONS(decoded, decoded + sizeof(decoded),
                                  components,
                                  components + sizeof(components));
}

BOOST_AUTO_TEST_CASE(cpp_key_and_address_bridge_is_strict_and_deterministic)
{
    PrivacyVNextDigest seed;
    PrivacyVNextDigest genesis;
    for (size_t i = 0; i < seed.size(); ++i)
    {
        seed[i] = static_cast<unsigned char>(i + 1);
        genesis[i] = static_cast<unsigned char>(0x80 + i);
    }

    std::string error;
    PrivacyVNextDerivedKeys first;
    PrivacyVNextDerivedKeys second;
    BOOST_REQUIRE_MESSAGE(DerivePrivacyVNextKeys(
                              seed, genesis, 17, 1, 0, first, error), error);
    BOOST_REQUIRE_MESSAGE(DerivePrivacyVNextKeys(
                              seed, genesis, 17, 1, 0, second, error), error);
    BOOST_CHECK_EQUAL(first.nNetwork, 1U);
    BOOST_CHECK_EQUAL(first.nAddressType, 0U);
    BOOST_CHECK_EQUAL(first.nIndex, 17U);
    BOOST_CHECK(first.spendSecret == second.spendSecret);
    BOOST_CHECK(first.viewSecret == second.viewSecret);
    BOOST_CHECK(first.outgoingViewSecret == second.outgoingViewSecret);
    BOOST_CHECK(first.nullifierSecret == second.nullifierSecret);
    BOOST_CHECK(first.stakingSecret == second.stakingSecret);
    BOOST_CHECK(first.spendPublic == second.spendPublic);
    BOOST_CHECK(first.viewPublic == second.viewPublic);

    PrivacyVNextAddressComponents source;
    source.nNetwork = first.nNetwork;
    source.nAddressType = first.nAddressType;
    source.spendPublic = first.spendPublic;
    source.viewPublic = first.viewPublic;
    std::string address;
    BOOST_REQUIRE_MESSAGE(EncodePrivacyVNextAddress(
                              source, address, error), error);

    PrivacyVNextAddressComponents decoded;
    BOOST_REQUIRE_MESSAGE(DecodePrivacyVNextAddress(
                              address, 1, decoded, error), error);
    BOOST_CHECK_EQUAL(decoded.nNetwork, source.nNetwork);
    BOOST_CHECK_EQUAL(decoded.nAddressType, source.nAddressType);
    BOOST_CHECK(decoded.spendPublic == source.spendPublic);
    BOOST_CHECK(decoded.viewPublic == source.viewPublic);

    PrivacyVNextAddressComponents rejected;
    BOOST_CHECK(!DecodePrivacyVNextAddress(address, 2, rejected, error));
    BOOST_CHECK(!error.empty());
    BOOST_CHECK(!DecodePrivacyVNextAddress(address + "1", 1, rejected, error));
    BOOST_CHECK(!error.empty());

    PrivacyVNextDigest zeroSeed;
    zeroSeed.fill(0);
    PrivacyVNextDerivedKeys invalid;
    BOOST_CHECK(!DerivePrivacyVNextKeys(
        zeroSeed, genesis, 17, 1, 0, invalid, error));
    BOOST_CHECK(!error.empty());
    PrivacyVNextDigest zero;
    zero.fill(0);
    BOOST_CHECK(invalid.spendSecret == zero);
    BOOST_CHECK(invalid.viewPublic == zero);
}

BOOST_AUTO_TEST_CASE(eight_layer_tree_round_trip_crosses_the_c_abi)
{
    uint8_t keyRequest[INNOVA_PRIVACY_VNEXT_KEY_DERIVATION_REQUEST_SIZE] = {0};
    keyRequest[0] = 1;
    keyRequest[2] = 1;
    keyRequest[4] = 9;
    for (size_t i = 0; i < 32; ++i)
    {
        keyRequest[8 + i] = static_cast<uint8_t>(i + 3);
        keyRequest[40 + i] = static_cast<uint8_t>(0xc0 + i);
    }
    uint8_t keys[INNOVA_PRIVACY_VNEXT_KEY_DERIVATION_OUTPUT_SIZE] = {0};
    size_t keysWritten = 0;
    BOOST_REQUIRE_EQUAL(
        innova_privacy_vnext_key_derive(
            keyRequest, sizeof(keyRequest), keys, sizeof(keys), &keysWritten),
        INNOVA_PRIVACY_VNEXT_VALID);
    BOOST_REQUIRE_EQUAL(keysWritten, sizeof(keys));

    std::vector<uint8_t> updateRequest(8, 0);
    updateRequest[0] = 1;
    updateRequest[2] = 1;
    updateRequest[4] = 1;
    updateRequest.insert(updateRequest.end(), keys + 168, keys + 200);
    updateRequest.insert(updateRequest.end(), keys + 200, keys + 232);
    updateRequest.insert(updateRequest.end(), keys + 168, keys + 200);

    uint8_t state[INNOVA_PRIVACY_VNEXT_TREE_STATE_SIZE] = {0};
    size_t stateWritten = 0;
    BOOST_REQUIRE_EQUAL(
        innova_privacy_vnext_tree_update(
            &updateRequest[0], updateRequest.size(), state, sizeof(state),
            &stateWritten),
        INNOVA_PRIVACY_VNEXT_VALID);
    BOOST_REQUIRE_EQUAL(stateWritten, sizeof(state));

    uint8_t repeatedState[INNOVA_PRIVACY_VNEXT_TREE_STATE_SIZE] = {0};
    size_t repeatedStateWritten = 0;
    BOOST_REQUIRE_EQUAL(
        innova_privacy_vnext_tree_update(
            &updateRequest[0], updateRequest.size(), repeatedState,
            sizeof(repeatedState), &repeatedStateWritten),
        INNOVA_PRIVACY_VNEXT_VALID);
    BOOST_REQUIRE_EQUAL(repeatedStateWritten, sizeof(repeatedState));
    BOOST_CHECK_EQUAL_COLLECTIONS(state, state + sizeof(state), repeatedState,
                                  repeatedState + sizeof(repeatedState));

    uint8_t root[INNOVA_PRIVACY_VNEXT_TREE_ROOT_SIZE] = {0};
    size_t rootWritten = 0;
    BOOST_REQUIRE_EQUAL(
        innova_privacy_vnext_tree_root(
            state, sizeof(state), root, sizeof(root), &rootWritten),
        INNOVA_PRIVACY_VNEXT_VALID);
    BOOST_REQUIRE_EQUAL(rootWritten, sizeof(root));
    BOOST_CHECK_EQUAL(root[0], 1U);
    BOOST_CHECK_EQUAL(root[1], 0U);
    BOOST_CHECK_EQUAL(root[2], INNOVA_PRIVACY_VNEXT_TREE_LAYERS);
    BOOST_CHECK_EQUAL(root[3], 2U);
    BOOST_CHECK_EQUAL(root[4], 1U);
    for (size_t i = 5; i < 12; ++i)
        BOOST_CHECK_EQUAL(root[i], 0U);
}

BOOST_AUTO_TEST_CASE(boundary_b_empty_epoch_seed_is_canonical)
{
    PrivacyVNextEpochSeed seed;
    std::string error;
    BOOST_REQUIRE_MESSAGE(LoadPrivacyVNextEpochSeed(seed, error), error);
    BOOST_CHECK_EQUAL(seed.vchTreeState.size(),
                      INNOVA_PRIVACY_VNEXT_TREE_STATE_SIZE);
    BOOST_CHECK_EQUAL(seed.vchRoot.size(),
                      INNOVA_PRIVACY_VNEXT_DIGEST_SIZE);
    BOOST_CHECK_EQUAL(seed.vchParameterDigest.size(),
                      INNOVA_PRIVACY_VNEXT_DIGEST_SIZE);
    BOOST_CHECK_EQUAL(seed.nTreeSize, 0U);

    std::vector<unsigned char> root;
    uint64_t size = 1;
    BOOST_REQUIRE_MESSAGE(DecodePrivacyVNextTreeState(
                              seed.vchTreeState, root, size, error), error);
    BOOST_CHECK(root == seed.vchRoot);
    BOOST_CHECK_EQUAL(size, seed.nTreeSize);
}

BOOST_AUTO_TEST_CASE(note_and_value_construction_cross_the_c_abi)
{
    uint8_t keyRequest[INNOVA_PRIVACY_VNEXT_KEY_DERIVATION_REQUEST_SIZE] = {0};
    keyRequest[0] = 1;
    keyRequest[2] = 1;
    keyRequest[4] = 11;
    for (size_t i = 0; i < 32; ++i)
    {
        keyRequest[8 + i] = static_cast<uint8_t>(i + 1);
        keyRequest[40 + i] = static_cast<uint8_t>(0x80 + i);
    }
    uint8_t keys[INNOVA_PRIVACY_VNEXT_KEY_DERIVATION_OUTPUT_SIZE] = {0};
    size_t keysWritten = 0;
    BOOST_REQUIRE_EQUAL(
        innova_privacy_vnext_key_derive(
            keyRequest, sizeof(keyRequest), keys, sizeof(keys), &keysWritten),
        INNOVA_PRIVACY_VNEXT_VALID);
    BOOST_REQUIRE_EQUAL(keysWritten, sizeof(keys));

    uint8_t encryptRequest[INNOVA_PRIVACY_VNEXT_NOTE_ENCRYPT_REQUEST_SIZE] = {0};
    encryptRequest[0] = 1;
    encryptRequest[2] = 1;
    encryptRequest[4] = 11;
    std::memcpy(encryptRequest + 8, keyRequest + 40, 32);
    std::memcpy(encryptRequest + 40, keys + 168, 32);
    std::memcpy(encryptRequest + 72, keys + 200, 32);
    std::memcpy(encryptRequest + 104, keys + 72, 32);
    encryptRequest[136] = 7;
    PutLE64(encryptRequest + 168, 9);
    encryptRequest[176] = 5;
    encryptRequest[208] = 3;
    std::memcpy(encryptRequest + 240, keys + 168, 32);

    uint8_t encrypted[INNOVA_PRIVACY_VNEXT_NOTE_ENCRYPT_RESULT_SIZE] = {0};
    size_t encryptedWritten = 0;
    BOOST_REQUIRE_EQUAL(
        innova_privacy_vnext_note_encrypt(
            encryptRequest, sizeof(encryptRequest), encrypted,
            sizeof(encrypted), &encryptedWritten),
        INNOVA_PRIVACY_VNEXT_VALID);
    BOOST_REQUIRE_EQUAL(encryptedWritten, sizeof(encrypted));
    BOOST_CHECK_EQUAL(encrypted[0], 1U);
    BOOST_CHECK_EQUAL(encrypted[2], 1U);
    BOOST_CHECK_EQUAL(encrypted[4], 11U);

    std::vector<uint8_t> scanRequest(
        INNOVA_PRIVACY_VNEXT_NOTE_SCAN_PREFIX_SIZE +
        INNOVA_PRIVACY_VNEXT_RECIPIENT_CIPHERTEXT_SIZE, 0);
    scanRequest[0] = 1;
    scanRequest[2] = 0;
    scanRequest[3] = 1;
    scanRequest[8] = 11;
    std::memcpy(&scanRequest[12], keyRequest + 40, 32);
    std::memcpy(&scanRequest[44], keys + 40, 32);
    std::memcpy(&scanRequest[76], keys + 8, 32);
    std::memcpy(&scanRequest[108], encrypted + 8, 128);
    std::memcpy(&scanRequest[236], encrypted + 136,
                INNOVA_PRIVACY_VNEXT_RECIPIENT_CIPHERTEXT_SIZE);

    uint8_t fullScan[INNOVA_PRIVACY_VNEXT_NOTE_SCAN_RESULT_SIZE] = {0};
    size_t fullScanWritten = 0;
    BOOST_REQUIRE_EQUAL(
        innova_privacy_vnext_note_scan(
            &scanRequest[0], scanRequest.size(), fullScan, sizeof(fullScan),
            &fullScanWritten),
        INNOVA_PRIVACY_VNEXT_VALID);
    BOOST_REQUIRE_EQUAL(fullScanWritten, sizeof(fullScan));
    BOOST_CHECK_EQUAL(ReadLE64(fullScan + 12), 9U);
    BOOST_CHECK_EQUAL_COLLECTIONS(fullScan + 20, fullScan + 84,
                                  keys + 168, keys + 232);
    BOOST_CHECK_EQUAL(fullScan[116], 5U);
    BOOST_CHECK_EQUAL(fullScan[148], 3U);

    scanRequest[2] = 1;
    std::memset(&scanRequest[76], 0, 32);
    uint8_t viewScan[INNOVA_PRIVACY_VNEXT_NOTE_SCAN_RESULT_SIZE] = {0};
    size_t viewScanWritten = 0;
    BOOST_REQUIRE_EQUAL(
        innova_privacy_vnext_note_scan(
            &scanRequest[0], scanRequest.size(), viewScan, sizeof(viewScan),
            &viewScanWritten),
        INNOVA_PRIVACY_VNEXT_VALID);
    BOOST_REQUIRE_EQUAL(viewScanWritten, sizeof(viewScan));
    BOOST_CHECK_EQUAL(ReadLE64(viewScan + 12), 9U);
    for (size_t i = 84; i < 116; ++i)
        BOOST_CHECK_EQUAL(viewScan[i], 0U);
    for (size_t i = 180; i < 212; ++i)
        BOOST_CHECK_EQUAL(viewScan[i], 0U);

    scanRequest.resize(INNOVA_PRIVACY_VNEXT_NOTE_SCAN_PREFIX_SIZE +
                       INNOVA_PRIVACY_VNEXT_OUTGOING_CIPHERTEXT_SIZE);
    scanRequest[2] = 2;
    std::memcpy(&scanRequest[44], keys + 72, 32);
    std::memcpy(&scanRequest[236], encrypted + 313,
                INNOVA_PRIVACY_VNEXT_OUTGOING_CIPHERTEXT_SIZE);
    uint8_t outgoingScan[INNOVA_PRIVACY_VNEXT_NOTE_SCAN_RESULT_SIZE] = {0};
    size_t outgoingScanWritten = 0;
    BOOST_REQUIRE_EQUAL(
        innova_privacy_vnext_note_scan(
            &scanRequest[0], scanRequest.size(), outgoingScan,
            sizeof(outgoingScan), &outgoingScanWritten),
        INNOVA_PRIVACY_VNEXT_VALID);
    BOOST_REQUIRE_EQUAL(outgoingScanWritten, sizeof(outgoingScan));
    BOOST_CHECK_EQUAL(ReadLE64(outgoingScan + 12), 9U);
    BOOST_CHECK_EQUAL_COLLECTIONS(outgoingScan + 20, outgoingScan + 84,
                                  fullScan + 20, fullScan + 84);

    scanRequest.back() ^= 1;
    uint8_t rejected[INNOVA_PRIVACY_VNEXT_NOTE_SCAN_RESULT_SIZE];
    std::memset(rejected, 0xa5, sizeof(rejected));
    size_t rejectedWritten = 123;
    BOOST_CHECK_EQUAL(
        innova_privacy_vnext_note_scan(
            &scanRequest[0], scanRequest.size(), rejected, sizeof(rejected),
            &rejectedWritten),
        INNOVA_PRIVACY_VNEXT_CONSENSUS_INVALID);
    BOOST_CHECK_EQUAL(rejectedWritten, 123U);
    for (size_t i = 0; i < sizeof(rejected); ++i)
        BOOST_CHECK_EQUAL(rejected[i], 0xa5U);

    std::vector<uint8_t> valueRequest(
        INNOVA_PRIVACY_VNEXT_VALUE_PROVE_HEADER_SIZE + 8 + 32, 0);
    valueRequest[0] = 1;
    valueRequest[2] = 1;
    PutLE64(&valueRequest[4], 10);
    PutLE64(&valueRequest[12], 1);
    std::memset(&valueRequest[20], 0x44, 32);
    std::memset(&valueRequest[52], 0x45, 32);
    const uint8_t minusThree[32] = {
        0xea, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };
    std::memcpy(&valueRequest[84], minusThree, sizeof(minusThree));
    PutLE64(&valueRequest[116], 9);
    valueRequest[124] = 3;

    std::vector<uint8_t> valueResult(INNOVA_PRIVACY_VNEXT_MAX_PAYLOAD_BYTES, 0);
    size_t valueWritten = 0;
    BOOST_REQUIRE_EQUAL(
        innova_privacy_vnext_value_prove(
            &valueRequest[0], valueRequest.size(), &valueResult[0],
            valueResult.size(), &valueWritten),
        INNOVA_PRIVACY_VNEXT_VALID);
    valueResult.resize(valueWritten);
    BOOST_REQUIRE(valueResult.size() >= 40 + 128);
    BOOST_CHECK_EQUAL(valueResult[0], 1U);
    BOOST_CHECK_EQUAL(valueResult[2], 1U);
    BOOST_CHECK_EQUAL(valueResult[3], 0U);
    BOOST_CHECK_EQUAL_COLLECTIONS(valueResult.begin() + 4,
                                  valueResult.begin() + 36,
                                  encrypted + 72, encrypted + 104);
    const uint32_t rangeSize = ReadLE32(&valueResult[36]);
    BOOST_CHECK_GT(rangeSize, 0U);
    BOOST_CHECK_EQUAL(valueResult.size(),
                      static_cast<size_t>(40 + rangeSize + 128));
}

BOOST_AUTO_TEST_CASE(nullifier_accumulator_is_canonical_and_bounded)
{
    PrivacyVNextEpochSeed seed;
    std::string error;
    BOOST_REQUIRE_MESSAGE(LoadPrivacyVNextEpochSeed(seed, error), error);
    BOOST_CHECK_EQUAL(seed.vchNullifierState.size(),
                      INNOVA_PRIVACY_VNEXT_NULLIFIER_STATE_SIZE);
    BOOST_CHECK_EQUAL(seed.vchNullifierRoot.size(),
                      INNOVA_PRIVACY_VNEXT_DIGEST_SIZE);
    BOOST_CHECK_EQUAL(seed.nNullifierCount, 0U);

    PrivacyVNextDigest keyImage;
    keyImage.fill(0x66);
    keyImage[0] = 0x58;
    std::vector<PrivacyVNextDigest> keyImages(1, keyImage);
    std::vector<unsigned char> nextState;
    std::vector<unsigned char> nextRoot;
    uint64_t nextCount = 0;
    BOOST_REQUIRE_MESSAGE(ApplyPrivacyVNextNullifiers(
                              seed.vchNullifierState, keyImages,
                              nextState, nextRoot, nextCount, error),
                          error);
    BOOST_CHECK_EQUAL(nextCount, 1U);
    BOOST_CHECK(nextRoot != seed.vchNullifierRoot);

    keyImages.push_back(keyImage);
    BOOST_CHECK(!ApplyPrivacyVNextNullifiers(
        seed.vchNullifierState, keyImages,
        nextState, nextRoot, nextCount, error));
}

BOOST_AUTO_TEST_SUITE_END()
