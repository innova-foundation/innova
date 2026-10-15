#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

#include "key.h"
#include "base58.h"
#include "uint256.h"
#include "util.h"

using namespace std;

static const string strSecret1     ("8iESvaTAX6WvJE6NX1cgDoppZN3Q2q5mYs7jT1Sj4bwGrFZ74wY");
static const string strSecret2     ("8jTzePdUfJzAmvYsrAS1mvAhS1MrP9hyhZCtu4SQQKwnHfsFHX5");
static const string strSecret1C    ("b2zMRUeV1qM4F2nhyTiU7Xg4uqsaf5E3deCiMnxYeuCYxEyqWTvC");
static const string strSecret2C    ("b8S9S2t166PL9HMhRzdQRFfoTNb2xmRsG19W4nB8HxcntJDevPnU");
static const CBitcoinAddress addr1 ("iSjNGRsbVUprTbX4oMs5mzdeyBcfaEqMjL");
static const CBitcoinAddress addr2 ("iHZVWJUdn1LvQqXifwfr3GQJEiWAmFbrRn");
static const CBitcoinAddress addr1C("iRGqHtHGNnSh5QWjoKRZkNPZ3yhScH7gkk");
static const CBitcoinAddress addr2C("iEuFTNNjRbntQVPMqCsDj8jvspjN44waEp");


static const string strAddressBad("1HV9Lc3sNHZxwj4Zk6fB38tEmBryq2cBiF");


#ifdef KEY_TESTS_DUMPINFO
void dumpKeyInfo(uint256 privkey)
{
    CSecret secret;
    secret.resize(32);
    memcpy(&secret[0], &privkey, 32);
    vector<unsigned char> sec;
    sec.resize(32);
    memcpy(&sec[0], &secret[0], 32);
    printf("  * secret (hex): %s\n", HexStr(sec).c_str());

    for (int nCompressed=0; nCompressed<2; nCompressed++)
    {
        bool fCompressed = nCompressed == 1;
        printf("  * %s:\n", fCompressed ? "compressed" : "uncompressed");
        CBitcoinSecret bsecret;
        bsecret.SetSecret(secret, fCompressed);
        printf("    * secret (base58): %s\n", bsecret.ToString().c_str());
        CKey key;
        key.SetSecret(secret, fCompressed);
        vector<unsigned char> vchPubKey = key.GetPubKey();
        printf("    * pubkey (hex): %s\n", HexStr(vchPubKey).c_str());
        printf("    * address (base58): %s\n", CBitcoinAddress(vchPubKey).ToString().c_str());
    }
}
#endif


BOOST_AUTO_TEST_SUITE(key_tests)

BOOST_AUTO_TEST_CASE(key_test1)
{
    CBitcoinSecret bsecret1, bsecret2, bsecret1C, bsecret2C, baddress1;
    BOOST_CHECK( bsecret1.SetString (strSecret1));
    BOOST_CHECK( bsecret2.SetString (strSecret2));
    BOOST_CHECK( bsecret1C.SetString(strSecret1C));
    BOOST_CHECK( bsecret2C.SetString(strSecret2C));
    BOOST_CHECK(!baddress1.SetString(strAddressBad));

    bool fCompressed;
    CSecret secret1  = bsecret1.GetSecret (fCompressed);
    BOOST_CHECK(fCompressed == false);
    CSecret secret2  = bsecret2.GetSecret (fCompressed);
    BOOST_CHECK(fCompressed == false);
    CSecret secret1C = bsecret1C.GetSecret(fCompressed);
    BOOST_CHECK(fCompressed == true);
    CSecret secret2C = bsecret2C.GetSecret(fCompressed);
    BOOST_CHECK(fCompressed == true);

    BOOST_CHECK(secret1 == secret1C);
    BOOST_CHECK(secret2 == secret2C);

    CKey key1, key2, key1C, key2C;
    key1.SetSecret(secret1, false);
    key2.SetSecret(secret2, false);
    key1C.SetSecret(secret1, true);
    key2C.SetSecret(secret2, true);

    CKeyID addr1KeyID, addr2KeyID, addr1CKeyID, addr2CKeyID;
    BOOST_CHECK(addr1.GetKeyID(addr1KeyID) && addr1KeyID == key1.GetPubKey().GetID());
    BOOST_CHECK(addr2.GetKeyID(addr2KeyID) && addr2KeyID == key2.GetPubKey().GetID());
    BOOST_CHECK(addr1C.GetKeyID(addr1CKeyID) && addr1CKeyID == key1C.GetPubKey().GetID());
    BOOST_CHECK(addr2C.GetKeyID(addr2CKeyID) && addr2CKeyID == key2C.GetPubKey().GetID());

    for (int n=0; n<16; n++)
    {
        string strMsg = strprintf("Very secret message %i: 11", n);
        uint256 hashMsg = Hash(strMsg.begin(), strMsg.end());

        // normal signatures

        vector<unsigned char> sign1, sign2, sign1C, sign2C;

        BOOST_CHECK(key1.Sign (hashMsg, sign1));
        BOOST_CHECK(key2.Sign (hashMsg, sign2));
        BOOST_CHECK(key1C.Sign(hashMsg, sign1C));
        BOOST_CHECK(key2C.Sign(hashMsg, sign2C));

        BOOST_CHECK( key1.GetPubKey().Verify(hashMsg, sign1));
        BOOST_CHECK(!key1.GetPubKey().Verify(hashMsg, sign2));
        BOOST_CHECK( key1.GetPubKey().Verify(hashMsg, sign1C));
        BOOST_CHECK(!key1.GetPubKey().Verify(hashMsg, sign2C));

        BOOST_CHECK(!key2.GetPubKey().Verify(hashMsg, sign1));
        BOOST_CHECK( key2.GetPubKey().Verify(hashMsg, sign2));
        BOOST_CHECK(!key2.GetPubKey().Verify(hashMsg, sign1C));
        BOOST_CHECK( key2.GetPubKey().Verify(hashMsg, sign2C));

        BOOST_CHECK( key1C.GetPubKey().Verify(hashMsg, sign1));
        BOOST_CHECK(!key1C.GetPubKey().Verify(hashMsg, sign2));
        BOOST_CHECK( key1C.GetPubKey().Verify(hashMsg, sign1C));
        BOOST_CHECK(!key1C.GetPubKey().Verify(hashMsg, sign2C));

        BOOST_CHECK(!key2C.GetPubKey().Verify(hashMsg, sign1));
        BOOST_CHECK( key2C.GetPubKey().Verify(hashMsg, sign2));
        BOOST_CHECK(!key2C.GetPubKey().Verify(hashMsg, sign1C));
        BOOST_CHECK( key2C.GetPubKey().Verify(hashMsg, sign2C));

        // compact signatures (with key recovery)

        vector<unsigned char> csign1, csign2, csign1C, csign2C;

        BOOST_CHECK(key1.SignCompact (hashMsg, csign1));
        BOOST_CHECK(key2.SignCompact (hashMsg, csign2));
        BOOST_CHECK(key1C.SignCompact(hashMsg, csign1C));
        BOOST_CHECK(key2C.SignCompact(hashMsg, csign2C));

        CPubKey rkey1, rkey2, rkey1C, rkey2C;

        BOOST_CHECK(rkey1.RecoverCompact (hashMsg, csign1));
        BOOST_CHECK(rkey2.RecoverCompact (hashMsg, csign2));
        BOOST_CHECK(rkey1C.RecoverCompact(hashMsg, csign1C));
        BOOST_CHECK(rkey2C.RecoverCompact(hashMsg, csign2C));


        BOOST_CHECK(rkey1  == key1.GetPubKey());
        BOOST_CHECK(rkey2  == key2.GetPubKey());
        BOOST_CHECK(rkey1C == key1C.GetPubKey());
        BOOST_CHECK(rkey2C == key2C.GetPubKey());
    }
}

// RFC 6979 deterministic ECDSA nonces. Vectors derived with an independent
// python-ecdsa-style RFC 6979 reference (HMAC-SHA256 DRBG over secp256k1),
// whose DRBG was first confirmed against the published RFC 6979 A.2.5
// P-256/SHA-256 vector.
BOOST_AUTO_TEST_CASE(rfc6979_deterministic)
{
    vector<unsigned char> vchPriv = ParseHex("ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f");
    CSecret secret(vchPriv.begin(), vchPriv.end());
    CKey key;
    BOOST_CHECK(key.SetSecret(secret, true));

    // Raw 32-byte message hash, signed exactly as laid out in memory.
    vector<unsigned char> rawhash = ParseHex("6ed697fbebf7ba9075a8d15a44db2747dedeeec57625970d75e238d48f851fd2");
    uint256 hashMsg;
    memcpy(&hashMsg, &rawhash[0], 32);

    // 1. reproduces the RFC 6979 secp256k1+SHA256 (r,s) vector (low-S DER).
    vector<unsigned char> sig1;
    BOOST_CHECK(key.Sign(hashMsg, sig1));
    BOOST_CHECK_EQUAL(HexStr(sig1),
        "3045022100a94f137b2463098e36091ee1e1221c8411708583fde933bfc86ec9e51eff945f"
        "022011e1c55e2fde67c31eb42d788ff84ce3eeafb6d9176d7271a5eb2e637b1eb487");

    // 2. sign-twice is byte-identical, for both the DER and compact forms.
    vector<unsigned char> sig2;
    BOOST_CHECK(key.Sign(hashMsg, sig2));
    BOOST_CHECK(sig1 == sig2);
    vector<unsigned char> csig1, csig2;
    BOOST_CHECK(key.SignCompact(hashMsg, csig1));
    BOOST_CHECK(key.SignCompact(hashMsg, csig2));
    BOOST_CHECK(csig1 == csig2);

    // 3. the deterministic signature verifies.
    BOOST_CHECK(key.GetPubKey().Verify(hashMsg, sig1));
    CPubKey rec;
    BOOST_CHECK(rec.RecoverCompact(hashMsg, csig1));
    BOOST_CHECK(rec == key.GetPubKey());

    // 4. an old-style arbitrary-nonce (non-RFC6979, high-S) signature still
    // verifies: verification is nonce-agnostic, so pre-existing on-chain sigs hold.
    vector<unsigned char> oldsig = ParseHex(
        "3045022100d6ff7cc449455b7526a53e8af54930dcd02d71aa0e82a4e8cc24b3ac03589d55"
        "02207ba40248297825a058649ee8043e64610a4155ec25b6e2c0ab3f83117788a958");
    BOOST_CHECK(key.GetPubKey().Verify(hashMsg, oldsig));
}

BOOST_AUTO_TEST_SUITE_END()
