// One phrase reaching both key systems. Expected transparent keys come from a separate
// BIP-0039/BIP-0032 implementation.

#include <boost/test/unit_test.hpp>

#include "../bip39.h"
#include "../hdroot.h"
#include "../key.h"
#include "../util.h"
#include "../privacy_vnext_wallet.h"
#include "../wallet.h"

#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(hdroot_tests)

namespace {

// Entropy 00 01 02 .. 1f, and the phrase BIP-0039 says it is.
const char* kEntropyHex =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

std::vector<unsigned char> Entropy()
{
    return ParseHex(kEntropyHex);
}

std::string PrivHex(const CKey& key)
{
    BOOST_REQUIRE(key.IsValid());
    return HexStr(key.begin(), key.end());
}

PrivacyVNextDigest BuilderSeedForHD()
{
    PrivacyVNextDigest out;
    for (size_t i = 0; i < out.size(); ++i)
        out[i] = (unsigned char)(i + 1);
    return out;
}

PrivacyVNextDigest LocalGenesisForHD()
{
    PrivacyVNextDigest out;
    for (size_t i = 0; i < out.size(); ++i)
        out[i] = (unsigned char)(0x80 + i);
    return out;
}

} // namespace

// The shielded half: the phrase's entropy IS the seed. This is the identity the whole
// design rests on -- it is why a wallet that already holds a seed can be shown a phrase
// for it without migrating anything or re-scanning a single block.
BOOST_AUTO_TEST_CASE(the_shielded_seed_is_the_phrases_own_entropy)
{
    const std::vector<unsigned char> vEntropy = Entropy();
    BOOST_REQUIRE_EQUAL(vEntropy.size(), (size_t)BIP39_ENTROPY_BYTES);

    std::vector<unsigned char> vSeed;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(
        HDShieldedSeedFromEntropy(vEntropy, vSeed, strError), strError);
    BOOST_CHECK_EQUAL(HexStr(vSeed.begin(), vSeed.end()), std::string(kEntropyHex));

    // And the round trip a restore actually performs: seed -> words -> seed.
    std::string strMnemonic;
    BOOST_REQUIRE(BIP39EntropyToMnemonic(vSeed, strMnemonic, strError));
    std::vector<unsigned char> vBack;
    BOOST_REQUIRE(BIP39MnemonicToEntropy(strMnemonic, vBack, strError));
    BOOST_CHECK(vBack == vSeed);
}

// The all-zero phrase is valid BIP-0039 and is refused as a seed at both ends of the FFI,
// so it is refused here where the message can explain itself rather than deep in a
// derivation failure.
BOOST_AUTO_TEST_CASE(the_all_zero_phrase_is_refused_as_a_seed)
{
    const std::vector<unsigned char> vZero(BIP39_ENTROPY_BYTES, 0);
    std::string strMnemonic, strError;
    BOOST_REQUIRE(BIP39EntropyToMnemonic(vZero, strMnemonic, strError));
    BOOST_CHECK(strMnemonic.find("abandon abandon") == 0);

    std::vector<unsigned char> vSeed;
    BOOST_CHECK(!HDShieldedSeedFromEntropy(vZero, vSeed, strError));
    BOOST_CHECK(vSeed.empty());
    BOOST_CHECK(!strError.empty());
}

// The transparent half, against values derived elsewhere from the same phrase.
BOOST_AUTO_TEST_CASE(the_transparent_path_matches_an_independent_derivation)
{
    // The path is only this one on a test network; the coin type differs on mainnet and
    // the pinned keys below are the test-network ones, so state the assumption.
    BOOST_REQUIRE_EQUAL(HDCoinType(), HD_COIN_TYPE_TESTNET);

    CExtKey account;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(
        HDAccountKeyFromEntropy(Entropy(), account, strError), strError);
    BOOST_CHECK_EQUAL(account.nDepth, 3);

    struct Expect { unsigned int nChain; unsigned int nIndex; const char* priv; };
    static const Expect expected[] = {
        { HD_CHAIN_EXTERNAL, 0u, "0590e9f459806876b37828c2a01a22e6934de784bbdf08203b6dcba478a11aae" },
        { HD_CHAIN_EXTERNAL, 1u, "b4225405e4a097651c48dfcf9208827f80801b93350701b0264dcfe907ed52b1" },
        { HD_CHAIN_EXTERNAL, 5u, "e56338b51c4032756234bff3b37296f649d141efcf2ca0efba538c8126cc749e" },
        { HD_CHAIN_INTERNAL, 0u, "07fa79db5931b9355ae3d8eea336104901cccc1b58e2f3138d8fda076b6951f2" },
        { HD_CHAIN_INTERNAL, 1u, "f6f374dea593a165753b77bc85752751f948cd1fde3d11514636e0dbe214f151" },
        { HD_CHAIN_INTERNAL, 5u, "77edef087d884f49f58a0fb4d1e62953c9f5bb76af408aedb45efb361d8968d8" },
    };

    for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); ++i)
    {
        CKey key;
        BOOST_REQUIRE_MESSAGE(
            HDDeriveTransparentKey(account, expected[i].nChain, expected[i].nIndex,
                                   key, strError),
            strError);
        BOOST_CHECK_MESSAGE(
            PrivHex(key) == std::string(expected[i].priv),
            HDKeyPath(expected[i].nChain, expected[i].nIndex)
                << " derived " << PrivHex(key));
        // BIP-0044 addresses are compressed; an uncompressed one is a different address
        // for the same key, so a restore would not find the funds.
        BOOST_CHECK(key.IsCompressed());
    }
}

// Mainnet uses a different coin type and so a different tree; its keys are pinned here
// because the suite runs on regtest.
BOOST_AUTO_TEST_CASE(the_mainnet_coin_type_is_a_different_tree)
{
    BOOST_CHECK_EQUAL(HD_COIN_TYPE_MAINNET, 116u);
    BOOST_CHECK_EQUAL(HD_COIN_TYPE_TESTNET, 1u);
    BOOST_CHECK(HD_COIN_TYPE_MAINNET != HD_COIN_TYPE_TESTNET);

    struct Expect { unsigned int nChain; unsigned int nIndex; const char* priv; };
    static const Expect mainnet[] = {
        { HD_CHAIN_EXTERNAL, 0u, "b92c9d2c7adc9cb05867ba4beb70398ac298f08bebab19831f0c980a03df89f0" },
        { HD_CHAIN_EXTERNAL, 1u, "a0fb2ca8e92bc45e985972e22ea7c41b6e39cdb68aa3b93bb778dfaecce26d11" },
        { HD_CHAIN_EXTERNAL, 5u, "dc75979b4e54021f53847b7b7ed6747709fe675c6f7e1efc0e7ac8aa26fa87d9" },
        { HD_CHAIN_INTERNAL, 0u, "ad85157d91d172b2d3deed67d22085fd1a1730181acda52966b7d666d3a4326d" },
        { HD_CHAIN_INTERNAL, 1u, "e1e3f59e203f8fabc05117edf0a7a99a41157f89e7583d610c2fa6f7256f33ec" },
        { HD_CHAIN_INTERNAL, 5u, "bb08acb50ad322feb5f04679db9db816f8846b8f9c2c8be8c8192a1a7c66d951" },
    };

    // Every mainnet key differs from the test-network key at the same position.
    CExtKey account;
    std::string strError;
    BOOST_REQUIRE(HDAccountKeyFromEntropy(Entropy(), account, strError));
    for (size_t i = 0; i < sizeof(mainnet) / sizeof(mainnet[0]); ++i)
    {
        CKey key;
        BOOST_REQUIRE(HDDeriveTransparentKey(account, mainnet[i].nChain,
                                             mainnet[i].nIndex, key, strError));
        BOOST_CHECK_MESSAGE(PrivHex(key) != std::string(mainnet[i].priv),
                            "the test network reached a mainnet key at "
                                << HDKeyPath(mainnet[i].nChain, mainnet[i].nIndex));
    }
}

// BIP-0044 pins the address level non-hardened, which is what lets an account's extended
// public key follow the same chain without holding its private key. A hardened index here
// would silently produce a chain no watch-only wallet could track.
BOOST_AUTO_TEST_CASE(the_address_level_refuses_a_hardened_index)
{
    CExtKey account;
    std::string strError;
    BOOST_REQUIRE(HDAccountKeyFromEntropy(Entropy(), account, strError));

    CKey key;
    BOOST_CHECK(!HDDeriveTransparentKey(account, HD_CHAIN_EXTERNAL, BIP32_HARDENED,
                                        key, strError));
    BOOST_CHECK(!strError.empty());
    BOOST_CHECK(!HDDeriveTransparentKey(account, HD_CHAIN_EXTERNAL, 0xffffffffu,
                                        key, strError));

    // And only the two chains BIP-0044 defines.
    BOOST_CHECK(!HDDeriveTransparentKey(account, 2u, 0u, key, strError));
    BOOST_CHECK(!HDDeriveTransparentKey(account, BIP32_HARDENED, 0u, key, strError));
}

// Receive and change must never collide, and the same index on each chain must be a
// different key -- a wallet that paid change to a receive address would hand its own
// change out as an invoice.
BOOST_AUTO_TEST_CASE(receive_and_change_are_separate_chains)
{
    CExtKey account;
    std::string strError;
    BOOST_REQUIRE(HDAccountKeyFromEntropy(Entropy(), account, strError));

    for (unsigned int nIndex = 0; nIndex < 4; ++nIndex)
    {
        CKey external, internal;
        BOOST_REQUIRE(HDDeriveTransparentKey(account, HD_CHAIN_EXTERNAL, nIndex,
                                             external, strError));
        BOOST_REQUIRE(HDDeriveTransparentKey(account, HD_CHAIN_INTERNAL, nIndex,
                                             internal, strError));
        BOOST_CHECK_MESSAGE(PrivHex(external) != PrivHex(internal),
                            "chains collide at index " << nIndex);
    }

    // Derivation is a pure function of the phrase: the same entropy must reach the same
    // keys in a fresh wallet, which is the whole promise of a recovery phrase.
    CExtKey again;
    BOOST_REQUIRE(HDAccountKeyFromEntropy(Entropy(), again, strError));
    BOOST_CHECK(again == account);
}

// The path string the key metadata records, so a user can re-derive by hand.
BOOST_AUTO_TEST_CASE(the_recorded_path_names_the_key)
{
    BOOST_CHECK_EQUAL(HDKeyPath(HD_CHAIN_EXTERNAL, 0u), "m/44'/1'/0'/0/0");
    BOOST_CHECK_EQUAL(HDKeyPath(HD_CHAIN_INTERNAL, 7u), "m/44'/1'/0'/1/7");
}

// The chain record is bookkeeping, so its job is to survive a restart: a wallet that
// forgot how far it had issued would hand out an address it had already given someone.
BOOST_AUTO_TEST_CASE(the_chain_record_round_trips_and_refuses_a_future_version)
{
    CHDChainRecord record;
    BOOST_CHECK(!record.IsPresent());          // a null record is not an adopted one
    record.nCoinType = HDCoinType();
    record.nAccount = HD_ACCOUNT;
    record.nExternalCount = 9;
    record.nInternalCount = 4;
    record.nCreateTime = 1757000000;
    BOOST_CHECK(record.IsPresent());

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << record;
    CHDChainRecord reloaded;
    ss >> reloaded;
    BOOST_CHECK_EQUAL(reloaded.nVersion, (int)CHDChainRecord::CURRENT_VERSION);
    BOOST_CHECK_EQUAL(reloaded.nCoinType, record.nCoinType);
    BOOST_CHECK_EQUAL(reloaded.nExternalCount, 9u);
    BOOST_CHECK_EQUAL(reloaded.nInternalCount, 4u);
    BOOST_CHECK_EQUAL(reloaded.nCreateTime, record.nCreateTime);
    BOOST_CHECK(ss.empty());

    // A record this build cannot read must be fatal rather than ignored: keys were
    // issued under rules it does not know, and carrying on would issue more under
    // different ones, so the phrase would cover part of the wallet and not the rest.
    CWallet wallet;
    CHDChainRecord future = record;
    future.nVersion = (int)CHDChainRecord::CURRENT_VERSION + 1;
    std::string strError;
    BOOST_CHECK(!wallet.LoadHDChainRecord(future, strError));
    BOOST_CHECK(!strError.empty());
    BOOST_CHECK(!wallet.HaveHDChain());

    // A record with no adoption time is not a chain either.
    CHDChainRecord empty;
    empty.nCoinType = HDCoinType();
    BOOST_CHECK(!wallet.LoadHDChainRecord(empty, strError));

    // The real one loads, and only once.
    BOOST_REQUIRE_MESSAGE(wallet.LoadHDChainRecord(record, strError), strError);
    BOOST_CHECK(wallet.HaveHDChain());
    BOOST_CHECK(!wallet.LoadHDChainRecord(record, strError));
}

// Adopting a phrase is a claim that the phrase reaches this wallet's keys, so it must be
// refused wherever that claim cannot be checked.
BOOST_AUTO_TEST_CASE(adopting_a_phrase_needs_a_seed_and_an_unlocked_wallet)
{
    CWallet wallet;
    std::string strError;

    // No seed: there is nothing for a phrase to be a rendering of.
    BOOST_CHECK(!wallet.AdoptHDChainFromSeed(strError));
    BOOST_CHECK(!strError.empty());
    BOOST_CHECK(!wallet.HaveHDChain());

    // And not twice, which would overwrite the counts a live chain is issuing from.
    CHDChainRecord record;
    record.nCoinType = HDCoinType();
    record.nCreateTime = 1757000000;
    BOOST_REQUIRE(wallet.LoadHDChainRecord(record, strError));
    BOOST_CHECK(!wallet.AdoptHDChainFromSeed(strError));
}

// The scan count is a pure function of the seed record's issued-address counter.
BOOST_AUTO_TEST_CASE(the_issued_count_has_exactly_one_source)
{
    CWallet wallet;
    // A wallet with no seed still reports at least one index, so a scan always derives
    // the first address rather than an empty key list.
    BOOST_CHECK_GE(wallet.GetPrivacyVNextScanIndexCount(), 1u);

    // And the scan list is that count plus the lookahead plus the self-pay key, with no
    // second counter able to raise or lower it.
    const PrivacyVNextDigest seed = BuilderSeedForHD();
    const PrivacyVNextDigest genesis = LocalGenesisForHD();
    std::vector<PrivacyVNextScanKey> vKeys;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(
        wallet.BuildPrivacyVNextScanKeys(seed, genesis, 0, vKeys, strError), strError);
    BOOST_CHECK_EQUAL(vKeys.size(),
                      (size_t)wallet.GetPrivacyVNextScanIndexCount() +
                          (size_t)PRIVACY_VNEXT_SCAN_LOOKAHEAD + 1);
}

BOOST_AUTO_TEST_SUITE_END()
