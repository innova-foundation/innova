// BIP-0039 conformance against the official vectors, with the wordlist pinned by hash,
// so phrases restore in other wallets.

#include <boost/test/unit_test.hpp>

#include "../bip39.h"
#include "../bip39_wordlist.h"
#include "../hash.h"
#include "../util.h"

#include <openssl/sha.h>

#include <set>
#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(bip39_tests)

namespace {

std::vector<unsigned char> FromHex(const std::string& strHex)
{
    return ParseHex(strHex);
}

std::string ToHexString(const std::vector<unsigned char>& v)
{
    return HexStr(v.begin(), v.end());
}

} // namespace

// The list itself is data, and the index of a word IS its value, so a reordered or
// misspelled entry changes every phrase it appears in. Pinning the hash makes any edit to
// the file fail here rather than in a user's restore.
BOOST_AUTO_TEST_CASE(the_wordlist_is_the_published_one)
{
    BOOST_REQUIRE_EQUAL(BIP39_WORDLIST_SIZE, 2048u);

    // Reconstruct the file exactly as published: one word per line, trailing newline.
    std::string strFile;
    for (unsigned int i = 0; i < BIP39_WORDLIST_SIZE; ++i)
    {
        strFile += BIP39_ENGLISH_WORDLIST[i];
        strFile += '\n';
    }
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)strFile.data(), strFile.size(), hash);
    BOOST_CHECK_EQUAL(
        HexStr(hash, hash + SHA256_DIGEST_LENGTH),
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda");

    // The properties the standard relies on: sorted, unique, and identified by the first
    // four letters, which is what lets a wallet accept a truncated word.
    std::set<std::string> setWords;
    std::set<std::string> setPrefixes;
    for (unsigned int i = 0; i < BIP39_WORDLIST_SIZE; ++i)
    {
        const std::string strWord = BIP39_ENGLISH_WORDLIST[i];
        BOOST_REQUIRE(strWord.size() >= 3);
        if (i > 0)
            BOOST_CHECK_MESSAGE(
                std::string(BIP39_ENGLISH_WORDLIST[i - 1]) < strWord,
                "wordlist is not sorted at index " << i);
        setWords.insert(strWord);
        setPrefixes.insert(strWord.substr(0, 4));
    }
    BOOST_CHECK_EQUAL(setWords.size(), (size_t)BIP39_WORDLIST_SIZE);
    BOOST_CHECK_EQUAL(setPrefixes.size(), (size_t)BIP39_WORDLIST_SIZE);
}

// The official 24-word vectors, entropy -> words -> seed, passphrase "TREZOR".
BOOST_AUTO_TEST_CASE(the_official_twenty_four_word_vectors_round_trip)
{
    struct Vector { const char* entropy; const char* mnemonic; const char* seed; };
    static const Vector vectors[] = {
        { "0000000000000000000000000000000000000000000000000000000000000000",
          "abandon abandon abandon abandon abandon abandon abandon abandon "
          "abandon abandon abandon abandon abandon abandon abandon abandon "
          "abandon abandon abandon abandon abandon abandon abandon art",
          "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8" },
        { "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
          "legal winner thank year wave sausage worth useful legal winner "
          "thank year wave sausage worth useful legal winner thank year wave "
          "sausage worth title",
          "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87" },
        { "8080808080808080808080808080808080808080808080808080808080808080",
          "letter advice cage absurd amount doctor acoustic avoid letter "
          "advice cage absurd amount doctor acoustic avoid letter advice "
          "cage absurd amount doctor acoustic bless",
          "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f" },
        { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
          "zoo zoo zoo zoo zoo zoo zoo vote",
          "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad" },
        { "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
          "hamster diagram private dutch cause delay private meat slide "
          "toddler razor book happy fancy gospel tennis maple dilemma loan "
          "word shrug inflict delay length",
          "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440" },
        { "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
          "panda eyebrow bullet gorilla call smoke muffin taste mesh "
          "discover soft ostrich alcohol speed nation flash devote level "
          "hobby quick inner drive ghost inside",
          "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d" },
        { "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
          "all hour make first leader extend hole alien behind guard gospel "
          "lava path output census museum junior mass reopen famous sing "
          "advance salt reform",
          "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d" },
        { "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
          "void come effort suffer camp survey warrior heavy shoot primary "
          "clutch crush open amazing screen patrol group space point ten "
          "exist slush involve unfold",
          "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998" },
    };

    for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i)
    {
        const std::vector<unsigned char> vEntropy = FromHex(vectors[i].entropy);
        BOOST_REQUIRE_EQUAL(vEntropy.size(), (size_t)BIP39_ENTROPY_BYTES);

        std::string strMnemonic, strError;
        BOOST_REQUIRE_MESSAGE(
            BIP39EntropyToMnemonic(vEntropy, strMnemonic, strError), strError);
        BOOST_CHECK_MESSAGE(strMnemonic == vectors[i].mnemonic,
                            "vector " << i << ": got \"" << strMnemonic << "\"");

        // And back, which is the direction a restore takes.
        std::vector<unsigned char> vBack;
        BOOST_REQUIRE_MESSAGE(
            BIP39MnemonicToEntropy(vectors[i].mnemonic, vBack, strError), strError);
        BOOST_CHECK_EQUAL(ToHexString(vBack), ToHexString(vEntropy));

        // The stretched seed, under the standard's own passphrase. This is the value a
        // BIP32 master is built from, so agreeing here is what makes a phrase portable.
        std::vector<unsigned char> vSeed;
        BOOST_REQUIRE_MESSAGE(
            BIP39MnemonicToSeed(vectors[i].mnemonic, "TREZOR", vSeed, strError),
            strError);
        BOOST_CHECK_EQUAL(ToHexString(vSeed), std::string(vectors[i].seed));
    }
}

// A wrong word usually lands on another valid word, so only the checksum catches it.
BOOST_AUTO_TEST_CASE(a_phrase_with_a_wrong_word_is_refused)
{
    const std::vector<unsigned char> vEntropy(BIP39_ENTROPY_BYTES, 0x5a);
    std::string strMnemonic, strError;
    BOOST_REQUIRE(BIP39EntropyToMnemonic(vEntropy, strMnemonic, strError));
    BOOST_REQUIRE(BIP39CheckMnemonic(strMnemonic, strError));

    std::vector<std::string> vWords = BIP39SplitWords(strMnemonic);
    BOOST_REQUIRE_EQUAL(vWords.size(), (size_t)BIP39_WORD_COUNT);

    // Swap one word for a different valid word: the list lookup still succeeds, so only
    // the checksum can catch it.
    const std::string strOriginal = vWords[7];
    vWords[7] = (strOriginal == "abandon") ? "ability" : "abandon";
    std::string strTampered;
    for (size_t i = 0; i < vWords.size(); ++i)
    {
        if (i) strTampered += ' ';
        strTampered += vWords[i];
    }
    BOOST_CHECK(!BIP39CheckMnemonic(strTampered, strError));
    BOOST_CHECK(!strError.empty());

    // Two words transposed is the other common transcription error.
    std::vector<std::string> vSwapped = BIP39SplitWords(strMnemonic);
    if (vSwapped[3] != vSwapped[11])
    {
        std::swap(vSwapped[3], vSwapped[11]);
        std::string strSwapped;
        for (size_t i = 0; i < vSwapped.size(); ++i)
        {
            if (i) strSwapped += ' ';
            strSwapped += vSwapped[i];
        }
        BOOST_CHECK(!BIP39CheckMnemonic(strSwapped, strError));
    }

    // A word that is not in the list at all names its position, so a user can fix it.
    std::string strUnknown = strMnemonic;
    const size_t nSpace = strUnknown.find(' ');
    strUnknown = "notaword" + strUnknown.substr(nSpace);
    BOOST_CHECK(!BIP39CheckMnemonic(strUnknown, strError));
    BOOST_CHECK(strError.find("wordlist") != std::string::npos);
}

// Only the 24-word form carries 256 bits, which is the size of the seed this wallet
// holds. The shorter forms are valid BIP39 and still cannot represent it.
BOOST_AUTO_TEST_CASE(only_the_twenty_four_word_form_is_accepted)
{
    std::string strError;
    BOOST_CHECK(!BIP39CheckMnemonic("abandon abandon about", strError));
    BOOST_CHECK(!strError.empty());

    // The official 12-word vector: valid BIP39, but not 256 bits.
    BOOST_CHECK(!BIP39CheckMnemonic(
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        strError));

    std::vector<unsigned char> vShort(16, 0);
    std::string strMnemonic;
    BOOST_CHECK(!BIP39EntropyToMnemonic(vShort, strMnemonic, strError));
    BOOST_CHECK(strMnemonic.empty());
}

// What a user actually types: extra spaces, capitals, a trailing newline.
BOOST_AUTO_TEST_CASE(a_phrase_is_read_the_way_a_user_types_it)
{
    const std::vector<unsigned char> vEntropy(BIP39_ENTROPY_BYTES, 0x11);
    std::string strMnemonic, strError;
    BOOST_REQUIRE(BIP39EntropyToMnemonic(vEntropy, strMnemonic, strError));

    std::vector<unsigned char> vBack;
    BOOST_REQUIRE(BIP39MnemonicToEntropy("  " + strMnemonic + "  \n", vBack, strError));
    BOOST_CHECK_EQUAL(ToHexString(vBack), ToHexString(vEntropy));

    std::string strShouty = strMnemonic;
    for (size_t i = 0; i < strShouty.size(); ++i)
        strShouty[i] = (char)toupper((unsigned char)strShouty[i]);
    vBack.clear();
    BOOST_REQUIRE(BIP39MnemonicToEntropy(strShouty, vBack, strError));
    BOOST_CHECK_EQUAL(ToHexString(vBack), ToHexString(vEntropy));
}

// Every 32-byte value is a phrase and every phrase is a 32-byte value: that bijection is
// what lets an IV5 seed that already exists be shown as words with no migration.
BOOST_AUTO_TEST_CASE(entropy_and_phrases_are_one_to_one)
{
    for (unsigned int nSeed = 0; nSeed < 64; ++nSeed)
    {
        std::vector<unsigned char> vEntropy(BIP39_ENTROPY_BYTES);
        for (size_t i = 0; i < vEntropy.size(); ++i)
            vEntropy[i] = (unsigned char)((nSeed * 7 + i * 31 + (i & 3)) & 0xff);

        std::string strMnemonic, strError;
        BOOST_REQUIRE_MESSAGE(
            BIP39EntropyToMnemonic(vEntropy, strMnemonic, strError), strError);
        BOOST_CHECK_EQUAL(BIP39SplitWords(strMnemonic).size(), (size_t)BIP39_WORD_COUNT);

        std::vector<unsigned char> vBack;
        BOOST_REQUIRE_MESSAGE(
            BIP39MnemonicToEntropy(strMnemonic, vBack, strError), strError);
        BOOST_CHECK_EQUAL(ToHexString(vBack), ToHexString(vEntropy));
    }
}

BOOST_AUTO_TEST_SUITE_END()
