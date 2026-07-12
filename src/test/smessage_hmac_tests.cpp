// Deterministic secure-message HMAC vectors.  These pin the v1 transcripts
// independently of the OpenSSL API branch used by the build.

#include <boost/test/unit_test.hpp>

#include "../smessage.h"
#include "../util.h"

#include <cstring>
#include <vector>

namespace
{
    class SecureMsgEnabledGuard
    {
    public:
        SecureMsgEnabledGuard()
            : fWasEnabled(fSecMsgEnabled)
        {
            fSecMsgEnabled = true;
        }

        ~SecureMsgEnabledGuard()
        {
            fSecMsgEnabled = fWasEnabled;
        }

    private:
        bool fWasEnabled;
    };

    std::vector<unsigned char> TestPayload()
    {
        return ParseHex(
            "00017f80ff63726f73732d6f70656e73736c2d7365637572652d6d6573736167"
            "652d766563746f72");
    }

    void InitializeHeader(SecureMessage& smsg,
                          const unsigned char nonse[4])
    {
        memset(smsg.hash, 0, sizeof(smsg.hash));
        smsg.version[0] = 1;
        smsg.version[1] = 0;
        smsg.flags = 0xa5;

        const unsigned char timestamp[8] = {
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
        };
        memcpy(&smsg.timestamp, timestamp, sizeof(timestamp));

        for (size_t i = 0; i < sizeof(smsg.iv); ++i)
            smsg.iv[i] = static_cast<unsigned char>(i);
        smsg.cpkR[0] = 0x02;
        for (size_t i = 1; i < sizeof(smsg.cpkR); ++i)
            smsg.cpkR[i] = static_cast<unsigned char>(i);
        for (size_t i = 0; i < sizeof(smsg.mac); ++i)
            smsg.mac[i] = static_cast<unsigned char>(0x80 + i);

        memcpy(smsg.nonse, nonse, sizeof(smsg.nonse));
        const unsigned char payloadSizeWire[4] = {0x28, 0x00, 0x00, 0x00};
        memcpy(&smsg.nPayload, payloadSizeWire, sizeof(payloadSizeWire));
    }

    void CheckBytes(const unsigned char* actual, const char* expectedHex)
    {
        const std::vector<unsigned char> expected = ParseHex(expectedHex);
        BOOST_REQUIRE_EQUAL(expected.size(), 32U);
        BOOST_CHECK_EQUAL_COLLECTIONS(actual, actual + 32,
                                      expected.begin(), expected.end());
    }
}

BOOST_AUTO_TEST_SUITE(smessage_hmac_tests)

BOOST_AUTO_TEST_CASE(canonical_proof_vector_and_tamper_rejection)
{
    std::vector<unsigned char> payload = TestPayload();
    BOOST_REQUIRE_EQUAL(payload.size(), 40U);

    // Little-endian nonce 133597.  This vector meets the existing v1 target.
    const unsigned char nonse[4] = {0xdd, 0x09, 0x02, 0x00};
    SecureMessage smsg;
    InitializeHeader(smsg, nonse);

    unsigned char proofHash[32];
    BOOST_REQUIRE(SecureMsgComputeProofHash(
        smsg, &payload[0], payload.size(), proofHash));
    CheckBytes(proofHash,
        "6a0199a8e4067f75147c0b7249b1b4df"
        "8b082b7c31649fb457e8361d336e0000");

    // Production generation stores these four bytes; production validation
    // must recompute the identical canonical transcript.
    memcpy(smsg.hash, proofHash, sizeof(smsg.hash));
    BOOST_CHECK_EQUAL(SecureMsgValidate(
        smsg.hash, &payload[0], payload.size()), 0);

    // Exercise the production nonce search too: its first matching nonce and
    // checksum must be the fixed canonical vector above.
    const unsigned char zeroNonse[4] = {0x00, 0x00, 0x00, 0x00};
    SecureMessage generated;
    InitializeHeader(generated, zeroNonse);
    {
        SecureMsgEnabledGuard enabled;
        BOOST_REQUIRE_EQUAL(SecureMsgSetHash(
            generated.hash, &payload[0], payload.size()), 0);
    }
    BOOST_CHECK_EQUAL_COLLECTIONS(generated.nonse, generated.nonse + 4,
                                  nonse, nonse + 4);
    BOOST_CHECK_EQUAL_COLLECTIONS(generated.hash, generated.hash + 4,
                                  proofHash, proofHash + 4);
    BOOST_CHECK_EQUAL(SecureMsgValidate(
        generated.hash, &payload[0], payload.size()), 0);

    payload[5] ^= 0x01;
    BOOST_CHECK_NE(SecureMsgValidate(
        smsg.hash, &payload[0], payload.size()), 0);
    payload[5] ^= 0x01;

    smsg.flags ^= 0x01;
    BOOST_CHECK_NE(SecureMsgValidate(
        smsg.hash, &payload[0], payload.size()), 0);
}

BOOST_AUTO_TEST_CASE(legacy_single_payload_receive_compatibility)
{
    std::vector<unsigned char> payload = TestPayload();

    // Historical pre-1.1 receive transcript: header[4..103] || payload.
    // Full digest: 20379c35130a314ab50d7b4c3fe1bde6
    //              46442ff9c47cdaeb470c4ccdb94c0000
    const unsigned char nonse[4] = {0x71, 0x52, 0x00, 0x00};
    const unsigned char legacyChecksum[4] = {0x20, 0x37, 0x9c, 0x35};
    SecureMessage smsg;
    InitializeHeader(smsg, nonse);
    memcpy(smsg.hash, legacyChecksum, sizeof(smsg.hash));

    // The canonical digest is deliberately different, proving acceptance
    // comes from the receive-only compatibility path.
    unsigned char canonicalHash[32];
    BOOST_REQUIRE(SecureMsgComputeProofHash(
        smsg, &payload[0], payload.size(), canonicalHash));
    BOOST_CHECK_NE(memcmp(canonicalHash, legacyChecksum,
                          sizeof(legacyChecksum)), 0);
    BOOST_CHECK_EQUAL(SecureMsgValidate(
        smsg.hash, &payload[0], payload.size()), 0);

    payload.back() ^= 0x80;
    BOOST_CHECK_NE(SecureMsgValidate(
        smsg.hash, &payload[0], payload.size()), 0);
}

BOOST_AUTO_TEST_CASE(message_mac_vector_and_tamper_rejection)
{
    std::vector<unsigned char> payload = TestPayload();
    const unsigned char nonse[4] = {0xdd, 0x09, 0x02, 0x00};
    SecureMessage smsg;
    InitializeHeader(smsg, nonse);

    unsigned char key[32];
    for (size_t i = 0; i < sizeof(key); ++i)
        key[i] = static_cast<unsigned char>(i);

    unsigned char mac[32];
    BOOST_REQUIRE(SecureMsgComputeMessageMAC(
        key, smsg, &payload[0], payload.size(), mac));
    CheckBytes(mac,
        "dbf66aa248e10c3e4c325b39d970df6b"
        "8d7182dd54acd54cc11b85a99241fcf5");

    memcpy(smsg.mac, mac, sizeof(smsg.mac));
    BOOST_CHECK(SecureMsgVerifyMessageMAC(
        key, smsg, &payload[0], payload.size()));

    payload[0] ^= 0x01;
    BOOST_CHECK(!SecureMsgVerifyMessageMAC(
        key, smsg, &payload[0], payload.size()));
    payload[0] ^= 0x01;

    reinterpret_cast<unsigned char*>(&smsg.timestamp)[0] ^= 0x01;
    BOOST_CHECK(!SecureMsgVerifyMessageMAC(
        key, smsg, &payload[0], payload.size()));
    reinterpret_cast<unsigned char*>(&smsg.timestamp)[0] ^= 0x01;

    smsg.mac[31] ^= 0x01;
    BOOST_CHECK(!SecureMsgVerifyMessageMAC(
        key, smsg, &payload[0], payload.size()));
}

BOOST_AUTO_TEST_SUITE_END()
