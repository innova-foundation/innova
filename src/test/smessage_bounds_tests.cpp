// Length bounds on secure-message decode: the header length must be checked before it
// is subtracted from the record or payload size.

#include <boost/test/unit_test.hpp>

#include "../smessage.h"
#include "../util.h"

#include <cstring>
#include <new>
#include <string>
#include <vector>

namespace
{
    // A record shaped like the ones SecureMsgSend writes: SMSG_HDR_LEN of
    // header followed by the AES-CBC ciphertext.
    std::vector<unsigned char> StoredRecord(size_t nTotal)
    {
        std::vector<unsigned char> vch(nTotal, 0);
        if (nTotal > 4)
            vch[4] = 1;         // version[0]
        return vch;
    }
}

BOOST_AUTO_TEST_SUITE(smessage_bounds_tests)

// The five RPC read paths computed vchMessage.size() - SMSG_HDR_LEN with no minimum-length
// check; a short message wrapped it to ~4 GB with the pointer past the buffer end.
BOOST_AUTO_TEST_CASE(split_stored_rejects_short_records)
{
    unsigned char* pHeader = NULL;
    unsigned char* pPayload = NULL;
    uint32_t nPayload = 0;

    const size_t nShort[] = {0, 1, 8, 103, SMSG_HDR_LEN,
                             SMSG_HDR_LEN + 1,
                             SMSG_HDR_LEN + SMSG_MIN_PAYLOAD_LEN - 1};

    for (size_t i = 0; i < sizeof(nShort) / sizeof(nShort[0]); ++i)
    {
        std::vector<unsigned char> vch = StoredRecord(nShort[i]);

        pHeader = reinterpret_cast<unsigned char*>(0x1);
        pPayload = reinterpret_cast<unsigned char*>(0x1);
        nPayload = 0xffffffffU;

        BOOST_CHECK_MESSAGE(
            !SecureMsgSplitStored(vch, pHeader, pPayload, nPayload),
            "record of " << nShort[i] << " bytes must be refused");

        // The out-parameters must be cleared, not left holding the wrapped
        // length a caller would otherwise pass straight to the decoder.
        BOOST_CHECK(pHeader == NULL);
        BOOST_CHECK(pPayload == NULL);
        BOOST_CHECK_EQUAL(nPayload, 0U);
    }
}

BOOST_AUTO_TEST_CASE(split_stored_accepts_and_locates_a_whole_record)
{
    const size_t nPayloadBytes = 64;
    std::vector<unsigned char> vch = StoredRecord(SMSG_HDR_LEN + nPayloadBytes);
    for (size_t i = 0; i < nPayloadBytes; ++i)
        vch[SMSG_HDR_LEN + i] = static_cast<unsigned char>(i);

    unsigned char* pHeader = NULL;
    unsigned char* pPayload = NULL;
    uint32_t nPayload = 0;

    BOOST_REQUIRE(SecureMsgSplitStored(vch, pHeader, pPayload, nPayload));
    BOOST_CHECK(pHeader == &vch[0]);
    BOOST_CHECK(pPayload == &vch[SMSG_HDR_LEN]);
    BOOST_CHECK_EQUAL(nPayload, (uint32_t)nPayloadBytes);

    // The smallest record the encrypt path can produce is one whole block.
    std::vector<unsigned char> vchMin =
        StoredRecord(SMSG_HDR_LEN + SMSG_MIN_PAYLOAD_LEN);
    BOOST_CHECK(SecureMsgSplitStored(vchMin, pHeader, pPayload, nPayload));
    BOOST_CHECK_EQUAL(nPayload, SMSG_MIN_PAYLOAD_LEN);
}

// SecureMsgDecrypt null-checked its pointers and the version byte but never the
// length it was handed, so a caller that computed a wrapped length reached the
// decoder. The guard runs before any wallet or address lookup.
BOOST_AUTO_TEST_CASE(decrypt_rejects_a_payload_shorter_than_one_block)
{
    std::vector<unsigned char> vch = StoredRecord(SMSG_HDR_LEN + 64);
    std::string address = "not-a-valid-innova-address";
    MessageData msg;

    for (uint32_t nPayload = 0; nPayload < SMSG_MIN_PAYLOAD_LEN; ++nPayload)
    {
        BOOST_CHECK_MESSAGE(
            SecureMsgDecrypt(true, address, &vch[0], &vch[SMSG_HDR_LEN],
                             nPayload, msg) == 1,
            "payload of " << nPayload << " bytes must be refused as too short");
    }

    // Past the minimum the length guard no longer fires, and the function
    // proceeds to the checks that follow it. Distinguishing 3 (address) from 1
    // (too short) is what proves the rejection above came from the new guard.
    BOOST_CHECK_EQUAL(
        SecureMsgDecrypt(true, address, &vch[0], &vch[SMSG_HDR_LEN],
                         SMSG_MIN_PAYLOAD_LEN, msg), 3);
}

// The plaintext header lengths the decoder subtracts must agree with the
// constants the encrypt path builds against, or the guards are checking the
// wrong boundary.
BOOST_AUTO_TEST_CASE(plaintext_header_lengths_are_pinned)
{
    BOOST_CHECK_EQUAL(SMSG_PL_HDR_LEN, 1U + 20U + 65U + 4U);
    BOOST_CHECK_EQUAL(SMSG_PL_HDR_LEN_ANON, 1U + 4U + 4U);
    BOOST_CHECK_EQUAL(SMSG_HDR_LEN, 104U);

    // One AES block; a shorter ciphertext cannot decrypt to either header.
    BOOST_CHECK_EQUAL(SMSG_MIN_PAYLOAD_LEN, 16U);
    BOOST_CHECK(SMSG_PL_HDR_LEN_ANON < SMSG_MIN_PAYLOAD_LEN);
}

// The flags byte is broadcast with every message and was never assigned, so a
// stack byte left over from whatever ran before went out on the wire.
BOOST_AUTO_TEST_CASE(header_is_fully_initialised)
{
    // Poison the storage, then construct in place: anything the constructor
    // fails to set keeps the poison.
    alignas(8) unsigned char storage[sizeof(SecureMessage)];
    memset(storage, 0xa5, sizeof(storage));

    SecureMessage* psmsg = new (storage) SecureMessage();

    BOOST_CHECK_EQUAL((unsigned)psmsg->flags, 0U);
    // Through the accessor: the field is bytes because a direct int64_t at offset 7 in a packed
    // struct is a misaligned reference (UBSan finding, same access as smessage.cpp).
    BOOST_CHECK_EQUAL(psmsg->GetTimestamp(), 0);
    BOOST_CHECK_EQUAL(psmsg->nPayload, 0U);
    BOOST_CHECK(psmsg->pPayload == NULL);

    for (size_t i = 0; i < sizeof(psmsg->hash); ++i)
        BOOST_CHECK_EQUAL((unsigned)psmsg->hash[i], 0U);
    for (size_t i = 0; i < sizeof(psmsg->version); ++i)
        BOOST_CHECK_EQUAL((unsigned)psmsg->version[i], 0U);
    for (size_t i = 0; i < sizeof(psmsg->iv); ++i)
        BOOST_CHECK_EQUAL((unsigned)psmsg->iv[i], 0U);
    for (size_t i = 0; i < sizeof(psmsg->cpkR); ++i)
        BOOST_CHECK_EQUAL((unsigned)psmsg->cpkR[i], 0U);
    for (size_t i = 0; i < sizeof(psmsg->mac); ++i)
        BOOST_CHECK_EQUAL((unsigned)psmsg->mac[i], 0U);
    for (size_t i = 0; i < sizeof(psmsg->nonse); ++i)
        BOOST_CHECK_EQUAL((unsigned)psmsg->nonse[i], 0U);

    psmsg->~SecureMessage();
}

// SecureMsgSend must refuse rather than encrypt, queue and report success while
// no proof-of-work thread is running to transmit what it queued.
BOOST_AUTO_TEST_CASE(send_refuses_while_messaging_is_disabled)
{
    const bool fWasEnabled = fSecMsgEnabled;
    fSecMsgEnabled = false;

    std::string addressFrom = "iFromAddressPlaceholder";
    std::string addressTo   = "iToAddressPlaceholder";
    std::string message     = "queued but never sent";
    std::string sError;

    const int rv = SecureMsgSend(addressFrom, addressTo, message, sError);

    fSecMsgEnabled = fWasEnabled;

    BOOST_CHECK(rv != 0);
    BOOST_CHECK(!sError.empty());
    // The caller must be told how to turn it on, not just that it failed.
    BOOST_CHECK(sError.find("disabled") != std::string::npos);
    BOOST_CHECK(sError.find("smsg=1") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
