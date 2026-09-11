// RFC 4231 vectors for HMAC-SHA-512, which phrase stretching and BIP-0032 derivation use.
// Cases 1, 2, 3, 4, 6 and 7; case 5 is truncation and does not apply.

#include <boost/test/unit_test.hpp>

#include "../hash.h"
#include "../util.h"

#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(hmac_sha512_tests)

namespace {

std::string HmacHex(const std::vector<unsigned char>& vKey,
                    const std::vector<unsigned char>& vData)
{
    HMAC_SHA512_CTX ctx;
    HMAC_SHA512_Init(&ctx, vKey.empty() ? NULL : &vKey[0], vKey.size());
    if (!vData.empty())
        HMAC_SHA512_Update(&ctx, &vData[0], vData.size());
    unsigned char md[64];
    HMAC_SHA512_Final(md, &ctx);
    return HexStr(md, md + sizeof(md));
}

std::vector<unsigned char> Repeat(unsigned char c, size_t n)
{
    return std::vector<unsigned char>(n, c);
}

std::vector<unsigned char> Bytes(const std::string& str)
{
    return std::vector<unsigned char>(str.begin(), str.end());
}

} // namespace

BOOST_AUTO_TEST_CASE(the_rfc_4231_vectors_hold)
{
    // Case 1: a short key.
    BOOST_CHECK_EQUAL(
        HmacHex(Repeat(0x0b, 20), Bytes("Hi There")),
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
        "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");

    // Case 2: a key shorter than the digest.
    BOOST_CHECK_EQUAL(
        HmacHex(Bytes("Jefe"), Bytes("what do ya want for nothing?")),
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
        "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");

    // Case 3: data longer than the digest.
    BOOST_CHECK_EQUAL(
        HmacHex(Repeat(0xaa, 20), Repeat(0xdd, 50)),
        "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39"
        "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb");

    // Case 4: a key of arbitrary bytes rather than a repeated one.
    std::vector<unsigned char> vKey4;
    for (unsigned char c = 0x01; c <= 0x19; ++c)
        vKey4.push_back(c);
    BOOST_CHECK_EQUAL(
        HmacHex(vKey4, Repeat(0xcd, 50)),
        "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db"
        "a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd");

    // Cases 6 and 7: a 131-byte key, longer than SHA-512's 128-byte block, so the key is
    // hashed before use. This is the branch an implementation is most likely to get wrong
    // and the least likely to exercise by accident.
    BOOST_CHECK_EQUAL(
        HmacHex(Repeat(0xaa, 131),
                Bytes("Test Using Larger Than Block-Size Key - Hash Key First")),
        "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
        "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598");

    BOOST_CHECK_EQUAL(
        HmacHex(Repeat(0xaa, 131),
                Bytes("This is a test using a larger than block-size key and a larger "
                      "than block-size data. The key needs to be hashed before being "
                      "used by the HMAC algorithm.")),
        "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944"
        "b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58");
}

// Streaming has to reach the same digest as one shot, because the callers that matter
// feed the key and the data in pieces.
BOOST_AUTO_TEST_CASE(an_update_split_anywhere_reaches_the_same_digest)
{
    const std::vector<unsigned char> vKey = Repeat(0x5c, 40);
    std::vector<unsigned char> vData;
    for (size_t i = 0; i < 200; ++i)
        vData.push_back((unsigned char)(i * 7 + 3));

    const std::string strWhole = HmacHex(vKey, vData);
    for (size_t nSplit = 0; nSplit <= vData.size(); nSplit += 17)
    {
        HMAC_SHA512_CTX ctx;
        HMAC_SHA512_Init(&ctx, &vKey[0], vKey.size());
        if (nSplit > 0)
            HMAC_SHA512_Update(&ctx, &vData[0], nSplit);
        if (nSplit < vData.size())
            HMAC_SHA512_Update(&ctx, &vData[nSplit], vData.size() - nSplit);
        unsigned char md[64];
        HMAC_SHA512_Final(md, &ctx);
        BOOST_CHECK_MESSAGE(HexStr(md, md + sizeof(md)) == strWhole,
                            "a split at " << nSplit << " changed the digest");
    }
}

BOOST_AUTO_TEST_SUITE_END()
