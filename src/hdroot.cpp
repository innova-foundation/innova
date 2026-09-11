#include "hdroot.h"
#include "bip39.h"
#include "util.h"

namespace
{

bool Fail(std::string& strErrorOut, const std::string& strError)
{
    strErrorOut = strError;
    return false;
}

} // namespace

unsigned int HDCoinType()
{
    extern bool fTestNet;
    extern bool fRegTest;
    // Test networks use SLIP-44 slot 1. The shielded derivation already folds in the
    // network byte and genesis hash.
    return (fTestNet || fRegTest) ? HD_COIN_TYPE_TESTNET : HD_COIN_TYPE_MAINNET;
}

bool HDShieldedSeedFromEntropy(const std::vector<unsigned char>& vEntropy,
                               std::vector<unsigned char>& vSeedOut,
                               std::string& strErrorOut)
{
    vSeedOut.clear();
    strErrorOut.clear();
    if (vEntropy.size() != BIP39_ENTROPY_BYTES)
        return Fail(strErrorOut, "a recovery phrase's entropy is not a shielded seed");

    // The all-zero seed is a valid BIP39 phrase -- abandon x23 art -- and is refused as a
    // seed at both ends of the FFI, so refuse it here where the message can say why.
    bool fAllZero = true;
    for (size_t i = 0; i < vEntropy.size(); ++i)
        if (vEntropy[i] != 0)
        {
            fAllZero = false;
            break;
        }
    if (fAllZero)
        return Fail(strErrorOut,
                    "that phrase encodes an all-zero seed, which no wallet may use");

    vSeedOut = vEntropy;
    return true;
}

bool HDAccountKeyFromEntropy(const std::vector<unsigned char>& vEntropy,
                             CExtKey& accountKeyOut,
                             std::string& strErrorOut)
{
    strErrorOut.clear();
    if (vEntropy.size() != BIP39_ENTROPY_BYTES)
        return Fail(strErrorOut, "a recovery phrase carries 32 bytes of entropy");

    // The words are what BIP39 stretches, not the entropy, so the phrase is rendered and
    // re-parsed here rather than the seed being fed in directly. Any other input would
    // produce a tree no standard wallet reaches from the same words.
    std::string strMnemonic;
    if (!BIP39EntropyToMnemonic(vEntropy, strMnemonic, strErrorOut))
        return false;

    std::vector<unsigned char> vSeed;
    if (!BIP39MnemonicToSeed(strMnemonic, std::string(), vSeed, strErrorOut))
        return false;
    if (vSeed.size() != BIP39_SEED_BYTES)
        return Fail(strErrorOut, "recovery phrase stretching produced the wrong length");

    CExtKey master;
    master.SetMaster(&vSeed[0], (unsigned int)vSeed.size());
    OPENSSL_cleanse(&vSeed[0], vSeed.size());
    if (!master.key.IsValid())
        return Fail(strErrorOut, "recovery phrase does not produce a usable master key");

    CExtKey purpose;
    CExtKey coin;
    if (!master.Derive(purpose, BIP44_PURPOSE | BIP32_HARDENED) ||
        !purpose.Derive(coin, HDCoinType() | BIP32_HARDENED) ||
        !coin.Derive(accountKeyOut, HD_ACCOUNT | BIP32_HARDENED))
        return Fail(strErrorOut, "transparent account derivation failed");
    return true;
}

bool HDDeriveTransparentKey(const CExtKey& accountKey,
                            unsigned int nChain,
                            unsigned int nIndex,
                            CKey& keyOut,
                            std::string& strErrorOut)
{
    strErrorOut.clear();
    if (nChain != HD_CHAIN_EXTERNAL && nChain != HD_CHAIN_INTERNAL)
        return Fail(strErrorOut, "a BIP44 chain is either receive or change");
    // BIP44 pins the address level non-hardened, which is what lets an account's extended
    // public key follow the same chain without its private key.
    if ((nIndex & BIP32_HARDENED) != 0)
        return Fail(strErrorOut, "a transparent address index is not hardened");
    if (!accountKey.key.IsValid())
        return Fail(strErrorOut, "the account key is not usable");

    CExtKey chainKey;
    CExtKey childKey;
    if (!accountKey.Derive(chainKey, nChain) || !chainKey.Derive(childKey, nIndex))
        return Fail(strErrorOut, "transparent key derivation failed");
    if (!childKey.key.IsValid())
        return Fail(strErrorOut, "derived transparent key is not usable");

    keyOut = childKey.key;
    return true;
}

std::string HDKeyPath(unsigned int nChain, unsigned int nIndex)
{
    return strprintf("m/%u'/%u'/%u'/%u/%u", BIP44_PURPOSE, HDCoinType(), HD_ACCOUNT,
                     nChain, nIndex);
}
