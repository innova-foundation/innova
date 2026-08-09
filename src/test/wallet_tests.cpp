#include <boost/test/unit_test.hpp>

#include <cstring>

#include "main.h"
#include "privacy_vnext_ffi.h"
#include "wallet.h"
#include "walletdb.h"

// how many times to run all the tests to have a chance to catch errors that only show up with particular random shuffles
#define RUN_TESTS 100

// some tests fail 1% of the time due to bad luck.
// we repeat those tests this many times and only complain if all iterations of the test fail
#define RANDOM_REPEATS 5

using namespace std;

typedef set<pair<const CWalletTx*,unsigned int> > CoinSet;

BOOST_AUTO_TEST_SUITE(wallet_tests)

BOOST_AUTO_TEST_CASE(privacy_vnext_seed_record_is_encrypted_and_checked)
{
    CKeyingMaterial masterKey(32, 0x31);
    CSecret seed(32, 0);
    for (size_t i = 0; i < seed.size(); ++i)
        seed[i] = static_cast<unsigned char>(i + 1);

    CPrivacyVNextSeedRecord record;
    record.nGeneration = PRIVACY_VNEXT_WALLET_SEED_GENERATION;
    record.hashSeedCommitment = Hash(seed.begin(), seed.end());
    record.nNextAddressIndex = 0;
    BOOST_REQUIRE(EncryptSecret(masterKey, seed, uint256(1),
                                record.vchCryptedSeed));
    BOOST_REQUIRE_EQUAL(record.vchCryptedSeed.size(),
                        PRIVACY_VNEXT_WALLET_SEED_CIPHERTEXT_SIZE);
    BOOST_CHECK(!std::equal(seed.begin(), seed.end(),
                           record.vchCryptedSeed.begin()));

    const std::string walletFile("iv5-seed-wallet-test.dat");
    {
        CWalletDB walletdb(walletFile);
        BOOST_REQUIRE(walletdb.WritePrivacyVNextSeed(record));
    }

    CWallet localWallet(walletFile);
    std::string error;
    BOOST_REQUIRE_MESSAGE(localWallet.LoadPrivacyVNextSeedRecord(
                              record, error), error);
    BOOST_CHECK(localWallet.HasPrivacyVNextSeed());
    BOOST_CHECK(!localWallet.IsPrivacyVNextSeedUnlocked());
    BOOST_REQUIRE_MESSAGE(localWallet.UnlockPrivacyVNextSeed(
                              masterKey, error), error);
    BOOST_CHECK(localWallet.IsPrivacyVNextSeedUnlocked());
    CKeyingMaterial recovered;
    BOOST_REQUIRE(localWallet.GetPrivacyVNextSeed(recovered));
    BOOST_CHECK_EQUAL_COLLECTIONS(seed.begin(), seed.end(),
                                  recovered.begin(), recovered.end());

    std::string address;
    uint32_t addressIndex = 99;
    BOOST_REQUIRE_MESSAGE(localWallet.GenerateNewPrivacyVNextAddress(
                              0, address, addressIndex, error), error);
    BOOST_CHECK_EQUAL(addressIndex, 0U);
    PrivacyVNextAddressComponents decodedAddress;
    BOOST_REQUIRE_MESSAGE(DecodePrivacyVNextAddress(
                              address, 2, decodedAddress, error), error);
    BOOST_CHECK_EQUAL(decodedAddress.nNetwork, 2U);
    BOOST_CHECK_EQUAL(decodedAddress.nAddressType, 0U);
    CPrivacyVNextSeedRecord advanced;
    {
        CWalletDB walletdb(walletFile);
        BOOST_REQUIRE(walletdb.ReadPrivacyVNextSeed(advanced));
    }
    BOOST_CHECK_EQUAL(advanced.nNextAddressIndex, 1U);
    BOOST_CHECK_EQUAL(localWallet.privacyVNextSeedRecord.nNextAddressIndex, 1U);

    CPrivacyVNextSeedRecord corrupt = record;
    corrupt.hashSeedCommitment.begin()[0] ^= 1;
    CWallet corruptWallet;
    BOOST_REQUIRE_MESSAGE(corruptWallet.LoadPrivacyVNextSeedRecord(
                              corrupt, error), error);
    BOOST_CHECK(!corruptWallet.UnlockPrivacyVNextSeed(masterKey, error));
    BOOST_CHECK(!error.empty());
    BOOST_CHECK(!corruptWallet.IsPrivacyVNextSeedUnlocked());

    CPrivacyVNextSeedRecord wrongGeneration = record;
    wrongGeneration.nGeneration++;
    CWallet rejectedWallet;
    BOOST_CHECK(!rejectedWallet.LoadPrivacyVNextSeedRecord(
        wrongGeneration, error));
    BOOST_CHECK(!error.empty());
}

// Issuance must stop exactly where scanning stops. A scan covers indices below
// PRIVACY_VNEXT_MAX_SCAN_KEYS, so an address issued at or above the bound is
// receivable and permanently invisible, and unshield is retired, so value paid to it
// has no recovery path. Starting one index below the bound reaches both the last
// issuable address and the first refused one without 1024 round trips.
BOOST_AUTO_TEST_CASE(privacy_vnext_address_issuance_stops_at_the_scan_bound)
{
    // All wallet files share one mock database and the seed record cannot be
    // overwritten, so adopt an existing seed or write one (order-independent).
    const std::string walletFile("iv5-seed-wallet-test.dat");
    CKeyingMaterial masterKey(32, 0x31);
    CPrivacyVNextSeedRecord record;
    {
        CWalletDB walletdb(walletFile);
        if (!walletdb.ReadPrivacyVNextSeed(record))
        {
            CSecret seed(32, 0);
            for (size_t i = 0; i < seed.size(); ++i)
                seed[i] = static_cast<unsigned char>(i + 1);
            record.nGeneration = PRIVACY_VNEXT_WALLET_SEED_GENERATION;
            record.hashSeedCommitment = Hash(seed.begin(), seed.end());
            record.nNextAddressIndex = 0;
            BOOST_REQUIRE(EncryptSecret(masterKey, seed, uint256(1),
                                        record.vchCryptedSeed));
            BOOST_REQUIRE(walletdb.WritePrivacyVNextSeed(record));
        }
    // Advance the persisted counter through the same durable step issuance uses,
    // without deriving a thousand keys.
        BOOST_REQUIRE(record.nNextAddressIndex < PRIVACY_VNEXT_MAX_SCAN_KEYS);
        while (record.nNextAddressIndex + 1 < PRIVACY_VNEXT_MAX_SCAN_KEYS)
        {
            BOOST_REQUIRE(walletdb.AdvancePrivacyVNextSeedIndex(
                record, record.nNextAddressIndex + 1));
            record.nNextAddressIndex += 1;
        }
    }
    BOOST_REQUIRE_EQUAL(record.nNextAddressIndex,
                        PRIVACY_VNEXT_MAX_SCAN_KEYS - 1);

    CWallet localWallet(walletFile);
    std::string error;
    BOOST_REQUIRE_MESSAGE(localWallet.LoadPrivacyVNextSeedRecord(record, error),
                          error);
    BOOST_REQUIRE_MESSAGE(localWallet.UnlockPrivacyVNextSeed(masterKey, error),
                          error);

    // The last index a scan reaches is still issuable. This is also the control for
    // the refusal below: it shows the wallet can issue here at all.
    std::string address;
    uint32_t addressIndex = 0xffffffffU;
    BOOST_REQUIRE_MESSAGE(localWallet.GenerateNewPrivacyVNextAddress(
                              0, address, addressIndex, error), error);
    BOOST_CHECK_EQUAL(addressIndex, PRIVACY_VNEXT_MAX_SCAN_KEYS - 1);
    BOOST_CHECK(!address.empty());
    // What makes the address safe to hand out is that a scan covers its index.
    BOOST_CHECK_LT(addressIndex, localWallet.GetPrivacyVNextScanIndexCount());
    BOOST_CHECK_EQUAL(localWallet.privacyVNextSeedRecord.nNextAddressIndex,
                      PRIVACY_VNEXT_MAX_SCAN_KEYS);

    // The next index is outside every scan, so issuance must refuse it.
    std::string beyond;
    uint32_t beyondIndex = 0xffffffffU;
    error.clear();
    BOOST_CHECK(!localWallet.GenerateNewPrivacyVNextAddress(
        0, beyond, beyondIndex, error));
    BOOST_CHECK(!error.empty());
    BOOST_CHECK(beyond.empty());

    // A refusal that still advanced the counter would leave the persisted record
    // ahead of what a scan covers, which is the same failure one step later.
    BOOST_CHECK_EQUAL(localWallet.privacyVNextSeedRecord.nNextAddressIndex,
                      PRIVACY_VNEXT_MAX_SCAN_KEYS);
    CPrivacyVNextSeedRecord persisted;
    {
        CWalletDB walletdb(walletFile);
        BOOST_REQUIRE(walletdb.ReadPrivacyVNextSeed(persisted));
    }
    BOOST_CHECK_EQUAL(persisted.nNextAddressIndex, PRIVACY_VNEXT_MAX_SCAN_KEYS);
}

class CSelectionTestWallet : public CWallet
{
public:
    using CWallet::SelectCoinsMinConf;

    bool SelectCoinsMinConf(int64_t nTargetValue,
                            int nConfMine,
                            int nConfTheirs,
                            std::vector<COutput> vCoins,
                            CoinSet& setCoinsRet,
                            int64_t& nValueRet) const
    {
        // Synthetic test transactions have no meaningful wall-clock time.
        return CWallet::SelectCoinsMinConf(nTargetValue,
                                           std::numeric_limits<unsigned int>::max(),
                                           nConfMine,
                                           nConfTheirs,
                                           vCoins,
                                           setCoinsRet,
                                           nValueRet);
    }
};

static CSelectionTestWallet wallet;
static vector<COutput> vCoins;

static void add_coin(int64_t nValue, int nAge = 6*24, bool fIsFromMe = false, int nInput=0)
{
    static int i;
    CTransaction* tx = new CTransaction;
    tx->nLockTime = i++;        // so all transactions get different hashes
    tx->vout.resize(nInput+1);
    tx->vout[nInput].nValue = nValue;
    CWalletTx* wtx = new CWalletTx(&wallet, *tx);
    delete tx;
    if (fIsFromMe)
    {
        // IsFromMe() returns (GetDebit() > 0), and GetDebit() is 0 if vin.empty(),
        // so stop vin being empty, and cache a non-zero Debit to fake out IsFromMe()
        wtx->vin.resize(1);
        wtx->fDebitCached = true;
        wtx->nDebitCached = 1;
    }
    COutput output(wtx, nInput, nAge, true);
    vCoins.push_back(output);
}

static void empty_wallet(void)
{
    BOOST_FOREACH(COutput output, vCoins)
        delete output.tx;
    vCoins.clear();
}

static bool equal_sets(CoinSet a, CoinSet b)
{
    pair<CoinSet::iterator, CoinSet::iterator> ret = mismatch(a.begin(), a.end(), b.begin());
    return ret.first == a.end() && ret.second == b.end();
}

BOOST_AUTO_TEST_CASE(coin_selection_tests)
{
    CoinSet setCoinsRet, setCoinsRet2;
    int64_t nValueRet;

    // test multiple times to allow for differences in the shuffle order
    for (int i = 0; i < RUN_TESTS; i++)
    {
        empty_wallet();

        // with an empty wallet we can't even pay one cent
        BOOST_CHECK(!wallet.SelectCoinsMinConf( 1 * CENT, 1, 6, vCoins, setCoinsRet, nValueRet));

        add_coin(1*CENT, 4);        // add a new 1 cent coin

        // with a new 1 cent coin, we still can't find a mature 1 cent
        BOOST_CHECK(!wallet.SelectCoinsMinConf( 1 * CENT, 1, 6, vCoins, setCoinsRet, nValueRet));

        // but we can find a new 1 cent
        BOOST_CHECK( wallet.SelectCoinsMinConf( 1 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 1 * CENT);

        add_coin(2*CENT);           // add a mature 2 cent coin

        // we can't make 3 cents of mature coins
        BOOST_CHECK(!wallet.SelectCoinsMinConf( 3 * CENT, 1, 6, vCoins, setCoinsRet, nValueRet));

        // we can make 3 cents of new  coins
        BOOST_CHECK( wallet.SelectCoinsMinConf( 3 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 3 * CENT);

        add_coin(5*CENT);           // add a mature 5 cent coin,
        add_coin(10*CENT, 3, true); // a new 10 cent coin sent from one of our own addresses
        add_coin(20*CENT);          // and a mature 20 cent coin

        // now we have new: 1+10=11 (of which 10 was self-sent), and mature: 2+5+20=27.  total = 38

        // we can't make 38 cents only if we disallow new coins:
        BOOST_CHECK(!wallet.SelectCoinsMinConf(38 * CENT, 1, 6, vCoins, setCoinsRet, nValueRet));
        // we can't even make 37 cents if we don't allow new coins even if they're from us
        BOOST_CHECK(!wallet.SelectCoinsMinConf(38 * CENT, 6, 6, vCoins, setCoinsRet, nValueRet));
        // but we can make 37 cents if we accept new coins from ourself
        BOOST_CHECK( wallet.SelectCoinsMinConf(37 * CENT, 1, 6, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 37 * CENT);
        // and we can make 38 cents if we accept all new coins
        BOOST_CHECK( wallet.SelectCoinsMinConf(38 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 38 * CENT);

        // try making 34 cents from 1,2,5,10,20 - we can't do it exactly
        BOOST_CHECK( wallet.SelectCoinsMinConf(34 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_GT(nValueRet, 34 * CENT);         // but should get more than 34 cents
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 3);     // the best should be 20+10+5.  it's incredibly unlikely the 1 or 2 got included (but possible)

        // when we try making 7 cents, the smaller coins (1,2,5) are enough.  We should see just 2+5
        BOOST_CHECK( wallet.SelectCoinsMinConf( 7 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 7 * CENT);
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 2);

        // when we try making 8 cents, the smaller coins (1,2,5) are exactly enough.
        BOOST_CHECK( wallet.SelectCoinsMinConf( 8 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK(nValueRet == 8 * CENT);
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 3);

        // when we try making 9 cents, no subset of smaller coins is enough, and we get the next bigger coin (10)
        BOOST_CHECK( wallet.SelectCoinsMinConf( 9 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 10 * CENT);
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1);

        // now clear out the wallet and start again to test choosing between subsets of smaller coins and the next biggest coin
        empty_wallet();

        add_coin( 6*CENT);
        add_coin( 7*CENT);
        add_coin( 8*CENT);
        add_coin(20*CENT);
        add_coin(30*CENT); // now we have 6+7+8+20+30 = 71 cents total

        // check that we have 71 and not 72
        BOOST_CHECK( wallet.SelectCoinsMinConf(71 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK(!wallet.SelectCoinsMinConf(72 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));

        // now try making 16 cents.  the best smaller coins can do is 6+7+8 = 21; not as good at the next biggest coin, 20
        BOOST_CHECK( wallet.SelectCoinsMinConf(16 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 20 * CENT); // we should get 20 in one coin
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1);

        add_coin( 5*CENT); // now we have 5+6+7+8+20+30 = 75 cents total

        // now if we try making 16 cents again, the smaller coins can make 5+6+7 = 18 cents, better than the next biggest coin, 20
        BOOST_CHECK( wallet.SelectCoinsMinConf(16 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 18 * CENT); // we should get 18 in 3 coins
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 3);

        add_coin( 18*CENT); // now we have 5+6+7+8+18+20+30

        // and now if we try making 16 cents again, the smaller coins can make 5+6+7 = 18 cents, the same as the next biggest coin, 18
        BOOST_CHECK( wallet.SelectCoinsMinConf(16 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 18 * CENT);  // we should get 18 in 1 coin
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1); // because in the event of a tie, the biggest coin wins

        // now try making 11 cents.  we should get 5+6
        BOOST_CHECK( wallet.SelectCoinsMinConf(11 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 11 * CENT);
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 2);

        // check that the smallest bigger coin is used
        add_coin( 1*COIN);
        add_coin( 2*COIN);
        add_coin( 3*COIN);
        add_coin( 4*COIN); // now we have 5+6+7+8+18+20+30+100+200+300+400 = 1094 cents
        BOOST_CHECK( wallet.SelectCoinsMinConf(95 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 1 * COIN);  // we should get 1 BTC in 1 coin
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1);

        BOOST_CHECK( wallet.SelectCoinsMinConf(195 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 2 * COIN);  // we should get 2 BTC in 1 coin
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1);

        // empty the wallet and start again, now with fractions of a cent, to test sub-cent change avoidance
        empty_wallet();
        add_coin(0.1*CENT);
        add_coin(0.2*CENT);
        add_coin(0.3*CENT);
        add_coin(0.4*CENT);
        add_coin(0.5*CENT);

        // try making 1 cent from 0.1 + 0.2 + 0.3 + 0.4 + 0.5 = 1.5 cents
        // we'll get sub-cent change whatever happens, so can expect 1.0 exactly
        BOOST_CHECK( wallet.SelectCoinsMinConf(1 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 1 * CENT);

        // but if we add a bigger coin, making it possible to avoid sub-cent change, things change:
        add_coin(1111*CENT);

        // try making 1 cent from 0.1 + 0.2 + 0.3 + 0.4 + 0.5 + 1111 = 1112.5 cents
        BOOST_CHECK( wallet.SelectCoinsMinConf(1 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 1 * CENT); // we should get the exact amount

        // if we add more sub-cent coins:
        add_coin(0.6*CENT);
        add_coin(0.7*CENT);

        // and try again to make 1.0 cents, we can still make 1.0 cents
        BOOST_CHECK( wallet.SelectCoinsMinConf(1 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 1 * CENT); // we should get the exact amount

        // run the 'mtgox' test (see http://blockexplorer.com/tx/29a3efd3ef04f9153d47a990bd7b048a4b2d213daaa5fb8ed670fb85f13bdbcf)
        // they tried to consolidate 10 50k coins into one 500k coin, and ended up with 50k in change
        empty_wallet();
        for (int i = 0; i < 20; i++)
            add_coin(50000 * COIN);

        BOOST_CHECK( wallet.SelectCoinsMinConf(500000 * COIN, 1, 1, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 500000 * COIN); // we should get the exact amount
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 10); // in ten coins

        // if there's not enough in the smaller coins to make at least 1 cent change (0.5+0.6+0.7 < 1.0+1.0),
        // we need to try finding an exact subset anyway

        // sometimes it will fail, and so we use the next biggest coin:
        empty_wallet();
        add_coin(0.5 * CENT);
        add_coin(0.6 * CENT);
        add_coin(0.7 * CENT);
        add_coin(1111 * CENT);
        BOOST_CHECK( wallet.SelectCoinsMinConf(1 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 1111 * CENT); // we get the bigger coin
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 1);

        // but sometimes it's possible, and we use an exact subset (0.4 + 0.6 = 1.0)
        empty_wallet();
        add_coin(0.4 * CENT);
        add_coin(0.6 * CENT);
        add_coin(0.8 * CENT);
        add_coin(1111 * CENT);
        BOOST_CHECK( wallet.SelectCoinsMinConf(1 * CENT, 1, 1, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 1 * CENT);   // we should get the exact amount
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 2); // in two coins 0.4+0.6

        // test avoiding sub-cent change
        empty_wallet();
        add_coin(0.0005 * COIN);
        add_coin(0.01 * COIN);
        add_coin(1 * COIN);

        // trying to make 1.0001 from these three coins
        BOOST_CHECK( wallet.SelectCoinsMinConf(1.0001 * COIN, 1, 1, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 1.0105 * COIN);   // we should get all coins
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 3);

        // but if we try to make 0.999, we should take the bigger of the two small coins to avoid sub-cent change
        BOOST_CHECK( wallet.SelectCoinsMinConf(0.999 * COIN, 1, 1, vCoins, setCoinsRet, nValueRet));
        BOOST_CHECK_EQUAL(nValueRet, 1.01 * COIN);   // we should get 1 + 0.01
        BOOST_CHECK_EQUAL(setCoinsRet.size(), 2);

        // test randomness
        {
            empty_wallet();
            for (int i2 = 0; i2 < 100; i2++)
                add_coin(COIN);

            // picking 50 from 100 coins doesn't depend on the shuffle,
            // but does depend on randomness in the stochastic approximation code
            BOOST_CHECK(wallet.SelectCoinsMinConf(50 * COIN, 1, 6, vCoins, setCoinsRet , nValueRet));
            BOOST_CHECK(wallet.SelectCoinsMinConf(50 * COIN, 1, 6, vCoins, setCoinsRet2, nValueRet));
            BOOST_CHECK(!equal_sets(setCoinsRet, setCoinsRet2));

            int fails = 0;
            for (int i = 0; i < RANDOM_REPEATS; i++)
            {
                // selecting 1 from 100 identical coins depends on the shuffle; this test will fail 1% of the time
                // run the test RANDOM_REPEATS times and only complain if all of them fail
                BOOST_CHECK(wallet.SelectCoinsMinConf(COIN, 1, 6, vCoins, setCoinsRet , nValueRet));
                BOOST_CHECK(wallet.SelectCoinsMinConf(COIN, 1, 6, vCoins, setCoinsRet2, nValueRet));
                if (equal_sets(setCoinsRet, setCoinsRet2))
                    fails++;
            }
            BOOST_CHECK_NE(fails, RANDOM_REPEATS);

            // add 75 cents in small change.  not enough to make 90 cents,
            // then try making 90 cents.  there are multiple competing "smallest bigger" coins,
            // one of which should be picked at random
            add_coin( 5*CENT); add_coin(10*CENT); add_coin(15*CENT); add_coin(20*CENT); add_coin(25*CENT);

            fails = 0;
            for (int i = 0; i < RANDOM_REPEATS; i++)
            {
                // selecting 1 from 100 identical coins depends on the shuffle; this test will fail 1% of the time
                // run the test RANDOM_REPEATS times and only complain if all of them fail
                BOOST_CHECK(wallet.SelectCoinsMinConf(90*CENT, 1, 6, vCoins, setCoinsRet , nValueRet));
                BOOST_CHECK(wallet.SelectCoinsMinConf(90*CENT, 1, 6, vCoins, setCoinsRet2, nValueRet));
                if (equal_sets(setCoinsRet, setCoinsRet2))
                    fails++;
            }
            BOOST_CHECK_NE(fails, RANDOM_REPEATS);
        }
    }

    setCoinsRet.clear();
    setCoinsRet2.clear();
    empty_wallet();
}

static CPrivacyVNextWalletNote MakeVNextNote(uint64_t nAmount, int nHeight,
                                             bool fLeafKnown, unsigned char tag)
{
    CPrivacyVNextWalletNote note;
    note.txhash = uint256(tag);
    note.nOutputIndex = tag;
    note.nHeight = nHeight;
    note.fSpent = false;
    note.fLeafIndexKnown = fLeafKnown;
    note.nAmount = nAmount;
    note.nLeafIndex = tag;
    note.vchOwner.assign(32, tag);
    note.vchNullifierBase.assign(32, tag);
    note.vchCommitment.assign(32, tag);
    note.vchSpendSecret.assign(32, tag);
    note.vchY.assign(32, tag);
    note.vchMask.assign(32, tag);
    note.vchKeyImage.assign(32, tag);
    return note;
}

// A note is only spendable once it is deep enough and its epoch has given it a
// tree position. Selection must respect both, and never exceed the input bound.
BOOST_AUTO_TEST_CASE(privacy_vnext_selection_honours_depth_position_and_bound)
{
    CWallet wallet;
    const int nSpendHeight = 1000;
    const int nDeep = nSpendHeight - MIN_SHIELDED_SPEND_DEPTH;

    wallet.vPrivacyVNextNotes.push_back(MakeVNextNote(50, nDeep, true, 1));
    wallet.vPrivacyVNextNotes.push_back(MakeVNextNote(30, nDeep, true, 2));
    wallet.vPrivacyVNextNotes.push_back(MakeVNextNote(90, nSpendHeight, true, 3));
    wallet.vPrivacyVNextNotes.push_back(MakeVNextNote(80, nDeep, false, 4));
    CPrivacyVNextWalletNote spent = MakeVNextNote(70, nDeep, true, 5);
    spent.fSpent = true;
    wallet.vPrivacyVNextNotes.push_back(spent);

    std::vector<CPrivacyVNextWalletNote> vSelected;
    int64_t nValue = 0;

    // Largest spendable first: 50 alone covers 40.
    BOOST_REQUIRE(wallet.SelectPrivacyVNextNotes(40, nSpendHeight, vSelected, nValue));
    BOOST_CHECK_EQUAL(vSelected.size(), 1U);
    BOOST_CHECK_EQUAL(vSelected[0].nAmount, 50U);
    BOOST_CHECK_EQUAL(nValue, 50);

    // 80 is spendable but has no tree position, 90 is too shallow, 70 is spent,
    // so only 50 + 30 are available and 100 cannot be reached.
    BOOST_CHECK(wallet.SelectPrivacyVNextNotes(80, nSpendHeight, vSelected, nValue));
    BOOST_CHECK_EQUAL(vSelected.size(), 2U);
    BOOST_CHECK_EQUAL(nValue, 80);
    BOOST_CHECK(!wallet.SelectPrivacyVNextNotes(100, nSpendHeight, vSelected, nValue));
    BOOST_CHECK(vSelected.empty());
    BOOST_CHECK_EQUAL(nValue, 0);

    BOOST_CHECK(!wallet.SelectPrivacyVNextNotes(0, nSpendHeight, vSelected, nValue));
    BOOST_CHECK(!wallet.SelectPrivacyVNextNotes(-1, nSpendHeight, vSelected, nValue));

    // A spend cannot carry more inputs than one proof admits.
    CWallet many;
    for (unsigned char i = 0; i < 20; ++i)
        many.vPrivacyVNextNotes.push_back(MakeVNextNote(1, nDeep, true, i + 1));
    BOOST_CHECK(!many.SelectPrivacyVNextNotes(20, nSpendHeight, vSelected, nValue));
    BOOST_REQUIRE(many.SelectPrivacyVNextNotes(16, nSpendHeight, vSelected, nValue));
    BOOST_CHECK_EQUAL(vSelected.size(), PRIVACY_VNEXT_MAX_SPEND_INPUTS);
    BOOST_CHECK_EQUAL(nValue, 16);
}

namespace
{

CPrivacyVNextCollateralRegistration MakeCollateralRecord(
    const CPrivacyVNextWalletNote& note)
{
    CPrivacyVNextCollateralRegistration record;
    std::memcpy(record.keyImage.begin(), &note.vchKeyImage[0], 32);
    record.fundingTxHash = note.txhash;
    record.nFundingOutputIndex = note.nOutputIndex;
    record.hashContext = uint256(0x5c);
    record.vchCollateralPubKey.assign(33, 0x02);
    record.announceKeyId = uint160(0x11);
    record.strAddr = "127.0.0.1:14539";
    record.strPoolPayout = "iv5payoutaddress";
    record.nTimeCreated = 1;
    return record;
}

// nBestHeight drives the balance views, and the harness leaves it at genesis.
struct BestHeightOverride
{
    int nSaved;
    explicit BestHeightOverride(int nHeight) : nSaved(nBestHeight)
    {
        nBestHeight = nHeight;
    }
    ~BestHeightOverride() { nBestHeight = nSaved; }
};

} // namespace

// Largest-first selection would pick a 25,000 collateral note first, and spending it
// deregisters the collateralnode permanently. The exclusion must survive a wallet
// reload; only release lifts it.
BOOST_AUTO_TEST_CASE(privacy_vnext_collateral_lock_excludes_a_note_across_reload)
{
    const std::string walletFile("iv5-collateral-lock-test.dat");
    const int nSpendHeight = 1000;
    const int nDeep = nSpendHeight - MIN_SHIELDED_SPEND_DEPTH;
    const CPrivacyVNextWalletNote collateral = MakeVNextNote(2500000000000ULL,
                                                             nDeep, true, 7);
    const CPrivacyVNextWalletNote ordinary = MakeVNextNote(500, nDeep, true, 8);
    const CPrivacyVNextCollateralRegistration record =
        MakeCollateralRecord(collateral);

    {
        CWalletDB walletdb(walletFile);
        BOOST_REQUIRE(walletdb.WritePrivacyVNextNote(collateral.txhash,
                                                     collateral.nOutputIndex,
                                                     collateral));
        BOOST_REQUIRE(walletdb.WritePrivacyVNextNote(ordinary.txhash,
                                                     ordinary.nOutputIndex,
                                                     ordinary));
    }

    std::vector<CPrivacyVNextWalletNote> vSelected;
    int64_t nValue = 0;

    // Unlocked, the collateral note is what an ordinary spend reaches for first.
    {
        CWallet before(walletFile);
        BOOST_REQUIRE_EQUAL(CWalletDB(walletFile).LoadWallet(&before), DB_LOAD_OK);
        BOOST_REQUIRE_EQUAL(before.vPrivacyVNextNotes.size(), 2U);
        BOOST_REQUIRE(before.SelectPrivacyVNextNotes(100, nSpendHeight, vSelected,
                                                     nValue));
        BOOST_CHECK_EQUAL(vSelected.size(), 1U);
        BOOST_CHECK_EQUAL(vSelected[0].nAmount, collateral.nAmount);
    }

    {
        CWallet locked(walletFile);
        BOOST_REQUIRE_EQUAL(CWalletDB(walletFile).LoadWallet(&locked), DB_LOAD_OK);
        std::string error;
        BOOST_REQUIRE_MESSAGE(
            locked.AddPrivacyVNextCollateralRegistration(record, error), error);
        BOOST_CHECK(locked.IsPrivacyVNextCollateralLocked(record.keyImage));

        // A small spend now takes the ordinary note, and the collateral note is
        // unreachable at any target.
        BOOST_REQUIRE(locked.SelectPrivacyVNextNotes(100, nSpendHeight, vSelected,
                                                     nValue));
        BOOST_CHECK_EQUAL(vSelected.size(), 1U);
        BOOST_CHECK_EQUAL(vSelected[0].nAmount, ordinary.nAmount);
        BOOST_CHECK(!locked.SelectPrivacyVNextNotes(1000, nSpendHeight, vSelected,
                                                    nValue));

        BestHeightOverride height(nSpendHeight);
        BOOST_CHECK_EQUAL(locked.GetPrivacyVNextBalance(),
                          (int64_t)ordinary.nAmount);
        BOOST_CHECK_EQUAL(locked.GetPrivacyVNextCollateralBalance(),
                          (int64_t)collateral.nAmount);
        BOOST_CHECK_EQUAL(locked.GetPrivacyVNextUnconfirmedBalance(), 0);
    }

    // A fresh wallet over the same file: the lock is a record, not process state.
    {
        CWallet reloaded(walletFile);
        BOOST_REQUIRE_EQUAL(CWalletDB(walletFile).LoadWallet(&reloaded), DB_LOAD_OK);
        BOOST_CHECK(reloaded.IsPrivacyVNextCollateralLocked(record.keyImage));
        CPrivacyVNextCollateralRegistration loaded;
        BOOST_REQUIRE(reloaded.GetPrivacyVNextCollateralRegistration(
            record.keyImage, loaded));
        BOOST_CHECK_EQUAL(loaded.strAddr, record.strAddr);
        BOOST_CHECK_EQUAL(loaded.strPoolPayout, record.strPoolPayout);
        BOOST_CHECK(loaded.hashContext == record.hashContext);
        BOOST_CHECK(loaded.fundingTxHash == collateral.txhash);

        BOOST_REQUIRE(reloaded.SelectPrivacyVNextNotes(100, nSpendHeight, vSelected,
                                                       nValue));
        BOOST_CHECK_EQUAL(vSelected.size(), 1U);
        BOOST_CHECK_EQUAL(vSelected[0].nAmount, ordinary.nAmount);

        // Release is the deliberate deregistration path and the only way back.
        std::string error;
        BOOST_REQUIRE_MESSAGE(
            reloaded.ReleasePrivacyVNextCollateralRegistration(record.keyImage,
                                                               error), error);
        BOOST_CHECK(!reloaded.IsPrivacyVNextCollateralLocked(record.keyImage));
        BOOST_REQUIRE(reloaded.SelectPrivacyVNextNotes(100, nSpendHeight, vSelected,
                                                       nValue));
        BOOST_CHECK_EQUAL(vSelected[0].nAmount, collateral.nAmount);
    }

    // The release is persisted too, or the next restart would re-lock a note the
    // operator deliberately freed.
    {
        CWallet released(walletFile);
        BOOST_REQUIRE_EQUAL(CWalletDB(walletFile).LoadWallet(&released), DB_LOAD_OK);
        BOOST_CHECK(!released.IsPrivacyVNextCollateralLocked(record.keyImage));
    }
}

BOOST_AUTO_TEST_SUITE_END()
