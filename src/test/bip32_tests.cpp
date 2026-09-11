// BIP-0032 test vectors 1 to 4. Vectors 3 and 4 cover keys and chain codes with leading
// zero bytes. Expected values are the 74-byte serializations without the 4-byte network
// version, which the caller adds for base58.

#include <boost/test/unit_test.hpp>

#include "../key.h"
#include "../util.h"

#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(bip32_tests)

namespace {

struct Step { unsigned int nChild; const char* prv; const char* pub; };
struct Vector { const char* seed; const Step* steps; size_t nSteps; };

const Step steps1[] = {
    { 0u,         "000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
      "000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2" },
    { 0x80000000u, "013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614100edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
      "013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56" },
    { 0x00000001u, "025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19003c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
      "025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c1903501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c" },
    { 0x80000002u, "03bef5a2f98000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f00cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
      "03bef5a2f98000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2" },
    { 0x00000002u, "04ee7ab90c00000002cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd000f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
      "04ee7ab90c00000002cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29" },
    { 0x3b9aca00u, "05d880d7d83b9aca00c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e00471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
      "05d880d7d83b9aca00c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011" },
};

const Step steps2[] = {
    { 0u,         "00000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689004b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
      "00000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd968903cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7" },
    { 0x00000000u, "01bd16bee500000000f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c00abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
      "01bd16bee500000000f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea" },
    { 0xffffffffu, "025a61ff8effffffffbe17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d900877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
      "025a61ff8effffffffbe17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d903c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b" },
    { 0x00000001u, "03d8ab493700000001f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb00704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
      "03d8ab493700000001f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9" },
    { 0xfffffffeu, "0478412e3afffffffe637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e2900f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
      "0478412e3afffffffe637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e2902d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0" },
    { 0x00000002u, "0531a507b8000000029452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed27100bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
      "0531a507b8000000029452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c" },
};

const Step steps3[] = {
    { 0u,         "00000000000000000001d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f0000ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae32",
      "00000000000000000001d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f03683af1ba5743bdfc798cf814efeeab2735ec52d95eced528e692b8e34c4e5669" },
    { 0x80000000u, "0141d63b5080000000e5fea12a97b927fc9dc3d2cb0d1ea1cf50aa5a1fdc1f933e8906bb38df3377bd00491f7a2eebc7b57028e0d3faa0acda02e75c33b03c48fb288c41e2ea44e1daef",
      "0141d63b5080000000e5fea12a97b927fc9dc3d2cb0d1ea1cf50aa5a1fdc1f933e8906bb38df3377bd026557fdda1d5d43d79611f784780471f086d58e8126b8c40acb82272a7712e7f2" },
};

const Step steps4[] = {
    { 0u,         "000000000000000000d0c8a1f6edf2500798c3e0b54f1b56e45f6d03e6076abd36e5e2f54101e44ce60012c0d59c7aa3a10973dbd3f478b65f2516627e3fe61e00c345be9a477ad2e215",
      "000000000000000000d0c8a1f6edf2500798c3e0b54f1b56e45f6d03e6076abd36e5e2f54101e44ce6026f6fedc9240f61daa9c7144b682a430a3a1366576f840bf2d070101fcbc9a02d" },
    { 0x80000000u, "01ad85d95580000000cdc0f06456a14876c898790e0b3b1a41c531170aec69da44ff7b7265bfe7743b0000d948e9261e41362a688b916f297121ba6bfb2274a3575ac0e456551dfd7f7e",
      "01ad85d95580000000cdc0f06456a14876c898790e0b3b1a41c531170aec69da44ff7b7265bfe7743b039382d2b6003446792d2917f7ac4b3edf079a1a94dd4eb010dc25109dda680a9d" },
    { 0x80000001u, "02cfa6128180000001a48ee6674c5264a237703fd383bccd9fad4d9378ac98ab05e6e7029b06360c0d003a2086edd7d9df86c3487a5905a1712a9aa664bce8cc268141e07549eaa8661d",
      "02cfa6128180000001a48ee6674c5264a237703fd383bccd9fad4d9378ac98ab05e6e7029b06360c0d032edaf9e591ee27f3c69c36221e3c54c38088ef34e93fbb9bb2d4d9b92364cbbd" },
};

const Vector vectors[] = {
    { "000102030405060708090a0b0c0d0e0f",
      steps1, sizeof(steps1) / sizeof(steps1[0]) },
    { "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
      steps2, sizeof(steps2) / sizeof(steps2[0]) },
    { "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
      steps3, sizeof(steps3) / sizeof(steps3[0]) },
    { "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
      steps4, sizeof(steps4) / sizeof(steps4[0]) },
};

std::string EncodedPrv(const CExtKey& key)
{
    unsigned char code[74];
    key.Encode(code);
    return HexStr(code, code + sizeof(code));
}

std::string EncodedPub(const CExtPubKey& key)
{
    unsigned char code[74];
    key.Encode(code);
    return HexStr(code, code + sizeof(code));
}

} // namespace
// Master from seed, then each child; private and neutered serializations checked each step.
BOOST_AUTO_TEST_CASE(the_official_vectors_derive_step_by_step)
{
    for (size_t v = 0; v < sizeof(vectors) / sizeof(vectors[0]); ++v)
    {
        const std::vector<unsigned char> vSeed = ParseHex(vectors[v].seed);
        BOOST_REQUIRE(!vSeed.empty());

        CExtKey key;
        key.SetMaster(&vSeed[0], (unsigned int)vSeed.size());

        for (size_t s = 0; s < vectors[v].nSteps; ++s)
        {
            const Step& step = vectors[v].steps[s];
            if (s != 0)
            {
                CExtKey child;
                BOOST_REQUIRE_MESSAGE(
                    key.Derive(child, step.nChild),
                    "vector " << (v + 1) << " step " << s << " failed to derive");
                key = child;
            }

            BOOST_CHECK_MESSAGE(EncodedPrv(key) == std::string(step.prv),
                                "vector " << (v + 1) << " step " << s
                                          << " private serialization differs");
            BOOST_CHECK_MESSAGE(EncodedPub(key.Neuter()) == std::string(step.pub),
                                "vector " << (v + 1) << " step " << s
                                          << " public serialization differs");
        }
    }
}

// A neutered parent reaches the same child as the private one for a non-hardened index.
BOOST_AUTO_TEST_CASE(a_public_parent_reaches_the_same_non_hardened_child)
{
    const std::vector<unsigned char> vSeed = ParseHex(vectors[0].seed);
    CExtKey master;
    master.SetMaster(&vSeed[0], (unsigned int)vSeed.size());

    const unsigned int vChildren[] = { 0u, 1u, 2u, 1000000000u, 0x7fffffffu };
    for (size_t i = 0; i < sizeof(vChildren) / sizeof(vChildren[0]); ++i)
    {
        CExtKey privChild;
        BOOST_REQUIRE(master.Derive(privChild, vChildren[i]));
        CExtPubKey pubChild;
        BOOST_REQUIRE(master.Neuter().Derive(pubChild, vChildren[i]));
        BOOST_CHECK_MESSAGE(privChild.Neuter() == pubChild,
                            "child " << vChildren[i] << " differs by path");
    }
}

// A neutered parent refuses (does not assert on) a hardened index.
BOOST_AUTO_TEST_CASE(a_public_parent_cannot_reach_a_hardened_child)
{
    const std::vector<unsigned char> vSeed = ParseHex(vectors[0].seed);
    CExtKey master;
    master.SetMaster(&vSeed[0], (unsigned int)vSeed.size());
    const CExtPubKey pub = master.Neuter();

    CExtPubKey out;
    BOOST_CHECK(!pub.Derive(out, 0x80000000u));
    BOOST_CHECK(!pub.Derive(out, 0x80000001u));
    BOOST_CHECK(!pub.Derive(out, 0xffffffffu));

    // The private parent can derive hardened children.
    CExtKey hardened;
    BOOST_CHECK(master.Derive(hardened, 0x80000000u));
}

// Encode and Decode are exact inverses, including depth, parent fingerprint and child number.
BOOST_AUTO_TEST_CASE(a_serialized_key_round_trips)
{
    const std::vector<unsigned char> vSeed = ParseHex(vectors[0].seed);
    CExtKey master;
    master.SetMaster(&vSeed[0], (unsigned int)vSeed.size());

    CExtKey deep;
    BOOST_REQUIRE(master.Derive(deep, 0x80000000u));
    CExtKey deeper;
    BOOST_REQUIRE(deep.Derive(deeper, 1u));

    unsigned char code[74];
    deeper.Encode(code);
    CExtKey decoded;
    decoded.Decode(code);
    BOOST_CHECK(decoded == deeper);
    BOOST_CHECK_EQUAL(decoded.nDepth, deeper.nDepth);
    BOOST_CHECK_EQUAL(decoded.nChild, deeper.nChild);

    CExtPubKey pub = deeper.Neuter();
    unsigned char pubCode[74];
    pub.Encode(pubCode);
    CExtPubKey decodedPub;
    decodedPub.Decode(pubCode);
    BOOST_CHECK(decodedPub == pub);

    // Private and public serializations differ only at byte 41 (zero pad vs parity header);
    // decoding one as the other must fail.
    BOOST_CHECK_EQUAL((int)code[41], 0);
    BOOST_CHECK(pubCode[41] == 0x02 || pubCode[41] == 0x03);
    CExtKey misread;
    misread.Decode(pubCode);
    BOOST_CHECK(!misread.key.IsValid());
}

BOOST_AUTO_TEST_SUITE_END()
