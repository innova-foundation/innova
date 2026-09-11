#include "bip39.h"
#include "bip39_wordlist.h"
#include "hash.h"
#include "util.h"

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <map>
#include <sstream>

namespace
{

// Word -> index, built once. The list is sorted, so a binary search would also do; the map
// costs one small allocation and keeps the lookup obviously correct.
const std::map<std::string, uint16_t>& WordIndex()
{
    static std::map<std::string, uint16_t> mapIndex;
    if (mapIndex.empty())
        for (uint16_t i = 0; i < BIP39_WORDLIST_SIZE; ++i)
            mapIndex[BIP39_ENGLISH_WORDLIST[i]] = i;
    return mapIndex;
}

bool Fail(std::string& strErrorOut, const std::string& strError)
{
    strErrorOut = strError;
    return false;
}

} // namespace

std::vector<std::string> BIP39SplitWords(const std::string& strMnemonic)
{
    std::string strLower;
    strLower.reserve(strMnemonic.size());
    for (size_t i = 0; i < strMnemonic.size(); ++i)
        strLower += (char)std::tolower((unsigned char)strMnemonic[i]);

    std::vector<std::string> vWords;
    std::istringstream stream(strLower);
    std::string strWord;
    while (stream >> strWord)
        vWords.push_back(strWord);
    return vWords;
}

bool BIP39EntropyToMnemonic(const std::vector<unsigned char>& vEntropy,
                            std::string& strMnemonicOut,
                            std::string& strErrorOut)
{
    strMnemonicOut.clear();
    strErrorOut.clear();
    if (vEntropy.size() != BIP39_ENTROPY_BYTES)
        return Fail(strErrorOut, strprintf(
            "a recovery phrase carries exactly %u bytes of entropy, not %u",
            (unsigned int)BIP39_ENTROPY_BYTES, (unsigned int)vEntropy.size()));

    // The checksum is the first ENT/32 bits of SHA-256 over the entropy: 8 bits here.
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(&vEntropy[0], vEntropy.size(), hash);

    std::vector<unsigned char> vBits = vEntropy;
    vBits.push_back(hash[0]);

    // 264 bits, read 11 at a time, most significant first.
    for (size_t i = 0; i < BIP39_WORD_COUNT; ++i)
    {
        uint16_t nIndex = 0;
        for (size_t b = 0; b < 11; ++b)
        {
            const size_t nBit = i * 11 + b;
            const unsigned char nByte = vBits[nBit / 8];
            const unsigned char nMask = (unsigned char)(1u << (7 - (nBit % 8)));
            nIndex = (uint16_t)((nIndex << 1) | ((nByte & nMask) ? 1u : 0u));
        }
        if (nIndex >= BIP39_WORDLIST_SIZE)
            return Fail(strErrorOut, "internal: word index outside the list");
        if (!strMnemonicOut.empty())
            strMnemonicOut += ' ';
        strMnemonicOut += BIP39_ENGLISH_WORDLIST[nIndex];
    }
    return true;
}

bool BIP39MnemonicToEntropy(const std::string& strMnemonic,
                            std::vector<unsigned char>& vEntropyOut,
                            std::string& strErrorOut)
{
    vEntropyOut.clear();
    strErrorOut.clear();

    const std::vector<std::string> vWords = BIP39SplitWords(strMnemonic);
    if (vWords.size() != BIP39_WORD_COUNT)
        return Fail(strErrorOut, strprintf(
            "a recovery phrase is %u words; this one is %u",
            (unsigned int)BIP39_WORD_COUNT, (unsigned int)vWords.size()));

    const std::map<std::string, uint16_t>& mapIndex = WordIndex();
    std::vector<unsigned char> vBits((BIP39_WORD_COUNT * 11 + 7) / 8, 0);
    for (size_t i = 0; i < vWords.size(); ++i)
    {
        std::map<std::string, uint16_t>::const_iterator it = mapIndex.find(vWords[i]);
        if (it == mapIndex.end())
            return Fail(strErrorOut, strprintf(
                "word %u (\"%s\") is not in the recovery wordlist",
                (unsigned int)(i + 1), vWords[i].c_str()));
        const uint16_t nIndex = it->second;
        for (size_t b = 0; b < 11; ++b)
        {
            if (!(nIndex & (1u << (10 - b))))
                continue;
            const size_t nBit = i * 11 + b;
            vBits[nBit / 8] |= (unsigned char)(1u << (7 - (nBit % 8)));
        }
    }

    std::vector<unsigned char> vEntropy(vBits.begin(), vBits.begin() + BIP39_ENTROPY_BYTES);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(&vEntropy[0], vEntropy.size(), hash);

    // A mistyped word usually lands on another valid word, so the checksum is the only
    // thing between a typo and a different, empty wallet.
    if (vBits[BIP39_ENTROPY_BYTES] != hash[0])
        return Fail(strErrorOut,
                    "the recovery phrase checksum does not match; a word is wrong or out "
                    "of order");

    vEntropyOut.swap(vEntropy);
    return true;
}

bool BIP39CheckMnemonic(const std::string& strMnemonic, std::string& strErrorOut)
{
    std::vector<unsigned char> vEntropy;
    return BIP39MnemonicToEntropy(strMnemonic, vEntropy, strErrorOut);
}

bool BIP39MnemonicToSeed(const std::string& strMnemonic,
                         const std::string& strPassphrase,
                         std::vector<unsigned char>& vSeedOut,
                         std::string& strErrorOut)
{
    vSeedOut.clear();
    strErrorOut.clear();

    // The phrase is stretched as the user's words, normalised the way this wallet accepts
    // them, so what is stretched is what a restore will parse.
    const std::vector<std::string> vWords = BIP39SplitWords(strMnemonic);
    if (vWords.size() != BIP39_WORD_COUNT)
        return Fail(strErrorOut, strprintf(
            "a recovery phrase is %u words; this one is %u",
            (unsigned int)BIP39_WORD_COUNT, (unsigned int)vWords.size()));
    std::string strNormalised;
    for (size_t i = 0; i < vWords.size(); ++i)
    {
        if (i != 0)
            strNormalised += ' ';
        strNormalised += vWords[i];
    }

    const std::string strSalt = std::string("mnemonic") + strPassphrase;
    vSeedOut.resize(BIP39_SEED_BYTES);
    if (PKCS5_PBKDF2_HMAC(strNormalised.c_str(), (int)strNormalised.size(),
                          (const unsigned char*)strSalt.data(), (int)strSalt.size(),
                          2048, EVP_sha512(),
                          (int)vSeedOut.size(), &vSeedOut[0]) != 1)
    {
        vSeedOut.clear();
        return Fail(strErrorOut, "recovery phrase key stretching failed");
    }
    return true;
}
