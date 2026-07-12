#include <map>
#include <string>
#include <boost/test/unit_test.hpp>
#include "main.h"
#include "wallet.h"

using namespace std;
extern bool AreInputsStandard(const CTransaction& tx, const MapPrevTx& mapInputs);

BOOST_AUTO_TEST_SUITE(transaction_tests)

static const char* const NATIVE_TRANSACTION_GOLDEN =
    "010000000403020101"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "ffffffff025151ffffffff"
    "01"
    "0100000000000000"
    "0151"
    "00000000";

static CTransaction NativeGoldenTransaction()
{
    CTransaction tx;
    tx.nVersion = CTransaction::CURRENT_VERSION;
    tx.nTime = 0x01020304;
    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vin[0].scriptSig << OP_1 << OP_1;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1;
    tx.vout[0].scriptPubKey << OP_1;
    tx.nLockTime = 0;
    return tx;
}

BOOST_AUTO_TEST_CASE(tx_valid)
{
    const CTransaction expected = NativeGoldenTransaction();
    CDataStream stream(ParseHex(NATIVE_TRANSACTION_GOLDEN),
                       SER_NETWORK, PROTOCOL_VERSION);
    CTransaction decoded;
    stream >> decoded;

    BOOST_CHECK(stream.empty());
    BOOST_CHECK(decoded == expected);
    BOOST_CHECK(decoded.CheckTransaction());
    BOOST_CHECK_EQUAL(decoded.GetHash().GetHex(),
                      "a768cd9db25be9a90f37b291aeb44b27c76da870cd2fac4d90bc2b7ed644bc85");
}

BOOST_AUTO_TEST_CASE(tx_invalid)
{
    CTransaction empty;
    empty.nTime = 0x01020304;
    BOOST_CHECK(!empty.CheckTransaction());

    CTransaction noOutputs = NativeGoldenTransaction();
    noOutputs.vout.clear();
    BOOST_CHECK(!noOutputs.CheckTransaction());

    CTransaction negativeOutput = NativeGoldenTransaction();
    negativeOutput.vout[0].nValue = -1;
    BOOST_CHECK(!negativeOutput.CheckTransaction());

    CTransaction excessiveOutput = NativeGoldenTransaction();
    excessiveOutput.vout[0].nValue = MAX_MONEY + 1;
    BOOST_CHECK(!excessiveOutput.CheckTransaction());

    CTransaction excessiveTotal = NativeGoldenTransaction();
    excessiveTotal.vout.resize(2, excessiveTotal.vout[0]);
    excessiveTotal.vout[0].nValue = MAX_MONEY;
    excessiveTotal.vout[1].nValue = 1;
    BOOST_CHECK(!excessiveTotal.CheckTransaction());

    CTransaction duplicateInputs;
    duplicateInputs.nTime = 0x01020304;
    duplicateInputs.vin.resize(2);
    duplicateInputs.vin[0].prevout = COutPoint(uint256(1), 0);
    duplicateInputs.vin[1].prevout = duplicateInputs.vin[0].prevout;
    duplicateInputs.vin[0].scriptSig << OP_1;
    duplicateInputs.vin[1].scriptSig << OP_1;
    duplicateInputs.vout.resize(1);
    duplicateInputs.vout[0].nValue = 1;
    duplicateInputs.vout[0].scriptPubKey << OP_1;
    BOOST_CHECK(!duplicateInputs.CheckTransaction());
}

BOOST_AUTO_TEST_CASE(basic_transaction_tests)
{
    const CTransaction expected = NativeGoldenTransaction();
    CDataStream encoded(SER_NETWORK, PROTOCOL_VERSION);
    encoded << expected;
    BOOST_CHECK_EQUAL(HexStr(encoded.begin(), encoded.end()),
                      NATIVE_TRANSACTION_GOLDEN);

    std::vector<unsigned char> truncated(encoded.begin(), encoded.end() - 1);
    CDataStream truncatedStream(truncated, SER_NETWORK, PROTOCOL_VERSION);
    CTransaction truncatedTx;
    BOOST_CHECK_THROW(truncatedStream >> truncatedTx, std::ios_base::failure);

    // Check that duplicate txins fail
    CTransaction tx = expected;
    tx.vin.push_back(tx.vin[0]);
    BOOST_CHECK_MESSAGE(!tx.CheckTransaction(), "Transaction with duplicate txins should be invalid.");
}

//
// Helper: create two dummy transactions, each with
// two outputs.  The first has 11 and 50 CENT outputs
// paid to a TX_PUBKEY, the second 21 and 22 CENT outputs
// paid to a TX_PUBKEYHASH.
//
static std::vector<CTransaction>
SetupDummyInputs(CBasicKeyStore& keystoreRet, MapPrevTx& inputsRet)
{
    std::vector<CTransaction> dummyTransactions;
    dummyTransactions.resize(2);

    // Add some keys to the keystore:
    CKey key[4];
    for (int i = 0; i < 4; i++)
    {
        key[i].MakeNewKey(i % 2);
        keystoreRet.AddKey(key[i]);
    }

    // Create some dummy input transactions
    dummyTransactions[0].vout.resize(2);
    dummyTransactions[0].vout[0].nValue = 11*CENT;
    dummyTransactions[0].vout[0].scriptPubKey << key[0].GetPubKey() << OP_CHECKSIG;
    dummyTransactions[0].vout[1].nValue = 50*CENT;
    dummyTransactions[0].vout[1].scriptPubKey << key[1].GetPubKey() << OP_CHECKSIG;
    inputsRet[dummyTransactions[0].GetHash()] = make_pair(CTxIndex(), dummyTransactions[0]);

    dummyTransactions[1].vout.resize(2);
    dummyTransactions[1].vout[0].nValue = 21*CENT;
    dummyTransactions[1].vout[0].scriptPubKey.SetDestination(key[2].GetPubKey().GetID());
    dummyTransactions[1].vout[1].nValue = 22*CENT;
    dummyTransactions[1].vout[1].scriptPubKey.SetDestination(key[3].GetPubKey().GetID());
    inputsRet[dummyTransactions[1].GetHash()] = make_pair(CTxIndex(), dummyTransactions[1]);

    return dummyTransactions;
}

BOOST_AUTO_TEST_CASE(test_Get)
{
    CBasicKeyStore keystore;
    MapPrevTx dummyInputs;
    std::vector<CTransaction> dummyTransactions = SetupDummyInputs(keystore, dummyInputs);

    CTransaction t1;
    t1.vin.resize(3);
    t1.vin[0].prevout.hash = dummyTransactions[0].GetHash();
    t1.vin[0].prevout.n = 1;
    t1.vin[0].scriptSig << std::vector<unsigned char>(65, 0);
    t1.vin[1].prevout.hash = dummyTransactions[1].GetHash();
    t1.vin[1].prevout.n = 0;
    t1.vin[1].scriptSig << std::vector<unsigned char>(65, 0) << std::vector<unsigned char>(33, 4);
    t1.vin[2].prevout.hash = dummyTransactions[1].GetHash();
    t1.vin[2].prevout.n = 1;
    t1.vin[2].scriptSig << std::vector<unsigned char>(65, 0) << std::vector<unsigned char>(33, 4);
    t1.vout.resize(2);
    t1.vout[0].nValue = 90*CENT;
    t1.vout[0].scriptPubKey << OP_1;

    BOOST_CHECK(::AreInputsStandard(t1, dummyInputs));
    BOOST_CHECK_EQUAL(t1.GetValueIn(dummyInputs), (50+21+22)*CENT);

    // Adding extra junk to the scriptSig should make it non-standard:
    t1.vin[0].scriptSig << OP_11;
    BOOST_CHECK(!::AreInputsStandard(t1, dummyInputs));

    // ... as should not having enough:
    t1.vin[0].scriptSig = CScript();
    BOOST_CHECK(!::AreInputsStandard(t1, dummyInputs));
}

BOOST_AUTO_TEST_CASE(test_GetThrow)
{
    CBasicKeyStore keystore;
    MapPrevTx dummyInputs;
    std::vector<CTransaction> dummyTransactions = SetupDummyInputs(keystore, dummyInputs);

    MapPrevTx missingInputs;

    CTransaction t1;
    t1.vin.resize(3);
    t1.vin[0].prevout.hash = dummyTransactions[0].GetHash();
    t1.vin[0].prevout.n = 0;
    t1.vin[1].prevout.hash = dummyTransactions[1].GetHash();;
    t1.vin[1].prevout.n = 0;
    t1.vin[2].prevout.hash = dummyTransactions[1].GetHash();;
    t1.vin[2].prevout.n = 1;
    t1.vout.resize(2);
    t1.vout[0].nValue = 90*CENT;
    t1.vout[0].scriptPubKey << OP_1;

    BOOST_CHECK_THROW(::AreInputsStandard(t1, missingInputs), runtime_error);
    BOOST_CHECK_THROW(t1.GetValueIn(missingInputs), runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()
