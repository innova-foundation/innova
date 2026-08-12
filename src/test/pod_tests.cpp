// Copyright (c) 2019-2026 The Innova Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>
#include <boost/filesystem.hpp>

#include <fstream>
#include <string>
#include <vector>

#include "main.h"
#include "pod.h"
#include "script.h"
#include "util.h"

using namespace std;

BOOST_AUTO_TEST_SUITE(pod_tests)

static vector<unsigned char> Digest(unsigned char fill)
{
    return vector<unsigned char>(POD_DIGEST_SIZE, fill);
}

static string WriteTempFile(const string& strContents)
{
    boost::filesystem::path p = boost::filesystem::temp_directory_path()
        / boost::filesystem::unique_path("innova-pod-%%%%%%%%.bin");
    ofstream out(p.string().c_str(), ios::binary);
    out.write(strContents.data(), (streamsize)strContents.size());
    out.close();
    return p.string();
}

// A stamp output is exactly OP_RETURN <"IPOD" version type digest32>, so a third
// party can read the digest straight out of a raw transaction.
BOOST_AUTO_TEST_CASE(pod_payload_layout)
{
    vector<unsigned char> vDigest = Digest(0xAB);
    CScript script = PodStampScript(POD_TYPE_PLAIN, vDigest, vector<unsigned char>());

    BOOST_CHECK_EQUAL(script.size(), (size_t)(1 + 1 + POD_PAYLOAD_SIZE));
    BOOST_CHECK_EQUAL((int)script[0], (int)OP_RETURN);
    BOOST_CHECK_EQUAL((int)script[1], (int)POD_PAYLOAD_SIZE); // direct push, not PUSHDATA1

    BOOST_CHECK_EQUAL(script[2], 'I');
    BOOST_CHECK_EQUAL(script[3], 'P');
    BOOST_CHECK_EQUAL(script[4], 'O');
    BOOST_CHECK_EQUAL(script[5], 'D');
    BOOST_CHECK_EQUAL((unsigned int)script[6], POD_STAMP_VERSION);
    BOOST_CHECK_EQUAL((int)script[7], (int)POD_TYPE_PLAIN);
    for (unsigned int i = 0; i < POD_DIGEST_SIZE; i++)
        BOOST_CHECK_EQUAL((int)script[8 + i], 0xAB);

    BOOST_CHECK(script.HasCanonicalPushes());
}

BOOST_AUTO_TEST_CASE(pod_pushes_fit_the_relay_limit)
{
    BOOST_CHECK(POD_PAYLOAD_SIZE <= MAX_OP_RETURN_RELAY);
    BOOST_CHECK(POD_LOCATOR_SIZE <= MAX_OP_RETURN_RELAY);
}

BOOST_AUTO_TEST_CASE(pod_roundtrip_all_types)
{
    const int types[3] = { POD_TYPE_PLAIN, POD_TYPE_BLINDED, POD_TYPE_HYPERFILE };
    for (int i = 0; i < 3; i++)
    {
        vector<unsigned char> vDigest = Digest((unsigned char)(0x10 + i));
        CScript script = PodStampScript(types[i], vDigest, vector<unsigned char>());
        CPodStamp stamp;
        BOOST_CHECK(PodParseStampScript(script, stamp));
        BOOST_CHECK_EQUAL(stamp.nStampVersion, (int)POD_STAMP_VERSION);
        BOOST_CHECK_EQUAL(stamp.nType, types[i]);
        BOOST_CHECK(stamp.vDigest == vDigest);
        BOOST_CHECK(stamp.vLocator.empty());
    }
}

BOOST_AUTO_TEST_CASE(pod_locator_only_on_hyperfile)
{
    vector<unsigned char> vDigest = Digest(0x22);
    vector<unsigned char> vLocator;
    BOOST_CHECK(PodCidToLocator("QmYKi7A9PyqywRA4aBWmqgSCYrXgRzri2QF25JKzBMjCxT", vLocator));
    BOOST_CHECK_EQUAL(vLocator.size(), (size_t)POD_LOCATOR_SIZE);
    BOOST_CHECK_EQUAL((int)vLocator[0], 0x12);
    BOOST_CHECK_EQUAL((int)vLocator[1], 0x20);
    BOOST_CHECK_EQUAL(PodLocatorToCid(vLocator),
                      "QmYKi7A9PyqywRA4aBWmqgSCYrXgRzri2QF25JKzBMjCxT");

    CScript scriptHyper = PodStampScript(POD_TYPE_HYPERFILE, vDigest, vLocator);
    CPodStamp stamp;
    BOOST_CHECK(PodParseStampScript(scriptHyper, stamp));
    BOOST_CHECK(stamp.vLocator == vLocator);

    // A locator handed to a non-hyperfile type is dropped, not smuggled in.
    CScript scriptPlain = PodStampScript(POD_TYPE_PLAIN, vDigest, vLocator);
    CPodStamp stampPlain;
    BOOST_CHECK(PodParseStampScript(scriptPlain, stampPlain));
    BOOST_CHECK(stampPlain.vLocator.empty());
}

BOOST_AUTO_TEST_CASE(pod_rejects_non_cidv0)
{
    vector<unsigned char> vLocator;
    BOOST_CHECK(!PodCidToLocator("", vLocator));
    BOOST_CHECK(!PodCidToLocator("not base58 !!!", vLocator));
    // CIDv1 base32 is not a base58 multihash.
    BOOST_CHECK(!PodCidToLocator("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
                                 vLocator));
}

// Both emitted shapes must match a TX_NULL_DATA template or they never relay.
BOOST_AUTO_TEST_CASE(pod_shapes_are_standard_nulldata)
{
    vector<unsigned char> vDigest = Digest(0x33);
    vector<unsigned char> vLocator;
    BOOST_CHECK(PodCidToLocator("QmYKi7A9PyqywRA4aBWmqgSCYrXgRzri2QF25JKzBMjCxT", vLocator));

    txnouttype whichType;
    vector<vector<unsigned char> > vSolutions;

    CScript scriptOne = PodStampScript(POD_TYPE_PLAIN, vDigest, vector<unsigned char>());
    BOOST_CHECK(Solver(scriptOne, whichType, vSolutions));
    BOOST_CHECK_EQUAL(whichType, TX_NULL_DATA);

    vSolutions.clear();
    CScript scriptTwo = PodStampScript(POD_TYPE_HYPERFILE, vDigest, vLocator);
    BOOST_CHECK(Solver(scriptTwo, whichType, vSolutions));
    BOOST_CHECK_EQUAL(whichType, TX_NULL_DATA);
    BOOST_CHECK(scriptTwo.HasCanonicalPushes());

    // Control: one OP_RETURN with two pushes matches no template.
    CScript scriptBad;
    scriptBad << OP_RETURN << vDigest << vLocator;
    vSolutions.clear();
    BOOST_CHECK(!Solver(scriptBad, whichType, vSolutions));
}

// A stamp push must not be read as a stealth ephemeral pubkey (exactly 33 bytes)
// nor as an 'np' plaintext narration (first push starting 'n','p').
BOOST_AUTO_TEST_CASE(pod_does_not_collide_with_stealth_or_narration)
{
    vector<unsigned char> vDigest = Digest(0x44);
    vector<unsigned char> vLocator;
    BOOST_CHECK(PodCidToLocator("QmYKi7A9PyqywRA4aBWmqgSCYrXgRzri2QF25JKzBMjCxT", vLocator));

    CTransaction tx;
    tx.vout.push_back(CTxOut(0, PodStampScript(POD_TYPE_PLAIN, vDigest, vector<unsigned char>())));
    tx.vout.push_back(CTxOut(0, PodStampScript(POD_TYPE_HYPERFILE, vDigest, vLocator)));
    BOOST_CHECK(!tx.HasStealthOutput());

    CScript script = PodStampScript(POD_TYPE_PLAIN, vDigest, vector<unsigned char>());
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    vector<unsigned char> vch;
    BOOST_CHECK(script.GetOp(pc, opcode, vch));
    BOOST_CHECK(script.GetOp(pc, opcode, vch));
    BOOST_CHECK(vch.size() != 33);
    BOOST_CHECK(!(vch.size() > 1 && vch[0] == 'n' && vch[1] == 'p'));

    // IsAnonOutput keys on OP_RETURN followed by OP_ANON_MARKER. The stamp's
    // second byte is the push length, so it must not land on that marker.
    BOOST_CHECK(!tx.vout[0].IsAnonOutput());
    BOOST_CHECK(!tx.vout[1].IsAnonOutput());
    BOOST_CHECK((int)POD_PAYLOAD_SIZE != (int)OP_ANON_MARKER);
    BOOST_CHECK((int)POD_LOCATOR_SIZE != (int)OP_ANON_MARKER);

    // The narration output the old POD relied on is not mistaken for a stamp.
    CScript scriptNarr;
    vector<unsigned char> vNp;
    vNp.push_back('n'); vNp.push_back('p');
    vector<unsigned char> vNarr;
    vNarr.push_back('P'); vNarr.push_back('O'); vNarr.push_back('D');
    scriptNarr << OP_RETURN << vNp << OP_RETURN << vNarr;
    CPodStamp stamp;
    BOOST_CHECK(!PodParseStampScript(scriptNarr, stamp));
}

BOOST_AUTO_TEST_CASE(pod_parser_rejects_near_misses)
{
    vector<unsigned char> vDigest = Digest(0x55);
    CPodStamp stamp;

    BOOST_CHECK(!PodParseStampScript(CScript(), stamp));
    BOOST_CHECK(!PodParseStampScript(CScript() << OP_RETURN, stamp));

    // Wrong magic.
    vector<unsigned char> vBad(POD_PAYLOAD_SIZE, 0);
    vBad[0] = 'X'; vBad[1] = 'P'; vBad[2] = 'O'; vBad[3] = 'D';
    BOOST_CHECK(!PodParseStampScript(CScript() << OP_RETURN << vBad, stamp));

    // Right magic, wrong length.
    vector<unsigned char> vShort(POD_PAYLOAD_SIZE - 1, 0);
    vShort[0] = 'I'; vShort[1] = 'P'; vShort[2] = 'O'; vShort[3] = 'D';
    BOOST_CHECK(!PodParseStampScript(CScript() << OP_RETURN << vShort, stamp));

    // Not an OP_RETURN at all.
    CScript scriptP2PKH;
    scriptP2PKH << OP_DUP << OP_HASH160 << vector<unsigned char>(20, 1)
                << OP_EQUALVERIFY << OP_CHECKSIG;
    BOOST_CHECK(!PodParseStampScript(scriptP2PKH, stamp));
}

BOOST_AUTO_TEST_CASE(pod_find_stamp_scans_all_outputs)
{
    vector<unsigned char> vDigest = Digest(0x66);

    CTransaction tx;
    CScript scriptP2PKH;
    scriptP2PKH << OP_DUP << OP_HASH160 << vector<unsigned char>(20, 1)
                << OP_EQUALVERIFY << OP_CHECKSIG;
    tx.vout.push_back(CTxOut(POD_STAMP_SELFPAY, scriptP2PKH));
    tx.vout.push_back(CTxOut(0, PodStampScript(POD_TYPE_BLINDED, vDigest, vector<unsigned char>())));

    CPodStamp stamp;
    BOOST_CHECK(PodFindStamp(tx, stamp));
    BOOST_CHECK_EQUAL(stamp.nOut, 1);
    BOOST_CHECK_EQUAL(stamp.nType, (int)POD_TYPE_BLINDED);
    BOOST_CHECK(stamp.vDigest == vDigest);

    CTransaction txNone;
    txNone.vout.push_back(CTxOut(POD_STAMP_SELFPAY, scriptP2PKH));
    CPodStamp stampNone;
    BOOST_CHECK(!PodFindStamp(txNone, stampNone));
}

// IsStandardTx rejects nDataOut > nTxnOut, so a stamp tx must carry a value
// output. This is why the builder always pays itself.
BOOST_AUTO_TEST_CASE(pod_stamp_needs_a_value_output_to_relay)
{
    LOCK(cs_main);

    vector<unsigned char> vDigest = Digest(0x77);
    CScript scriptStamp = PodStampScript(POD_TYPE_PLAIN, vDigest, vector<unsigned char>());

    CScript scriptP2PKH;
    scriptP2PKH << OP_DUP << OP_HASH160 << vector<unsigned char>(20, 1)
                << OP_EQUALVERIFY << OP_CHECKSIG;

    CTransaction txStampOnly;
    txStampOnly.nTime = GetAdjustedTime();
    txStampOnly.vin.push_back(CTxIn());
    txStampOnly.vout.push_back(CTxOut(0, scriptStamp));
    string reason;
    BOOST_CHECK(!IsStandardTx(txStampOnly, reason));
    BOOST_CHECK_EQUAL(reason, "multi-op-return");

    CTransaction txWithValue;
    txWithValue.nTime = GetAdjustedTime();
    txWithValue.vin.push_back(CTxIn());
    txWithValue.vout.push_back(CTxOut(POD_STAMP_SELFPAY, scriptP2PKH));
    txWithValue.vout.push_back(CTxOut(0, scriptStamp));
    reason.clear();
    BOOST_CHECK(IsStandardTx(txWithValue, reason));

    // The two-push hyperfile shape is one output, so one value output still covers it.
    vector<unsigned char> vLocator;
    BOOST_CHECK(PodCidToLocator("QmYKi7A9PyqywRA4aBWmqgSCYrXgRzri2QF25JKzBMjCxT", vLocator));
    CTransaction txHyper;
    txHyper.nTime = GetAdjustedTime();
    txHyper.vin.push_back(CTxIn());
    txHyper.vout.push_back(CTxOut(POD_STAMP_SELFPAY, scriptP2PKH));
    txHyper.vout.push_back(CTxOut(0, PodStampScript(POD_TYPE_HYPERFILE, vDigest, vLocator)));
    reason.clear();
    BOOST_CHECK(IsStandardTx(txHyper, reason));
}

// A plain stamp must be exactly what sha256sum prints, or the whole
// verify-with-coreutils claim is false.
BOOST_AUTO_TEST_CASE(pod_hash_file_matches_sha256sum)
{
    string strEmpty = WriteTempFile("");
    vector<unsigned char> vDigest;
    string strError;
    BOOST_CHECK(PodHashFile(strEmpty, vDigest, strError));
    BOOST_CHECK_EQUAL(HexStr(vDigest.begin(), vDigest.end()),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    boost::filesystem::remove(strEmpty);

    string strAbc = WriteTempFile("abc");
    BOOST_CHECK(PodHashFile(strAbc, vDigest, strError));
    BOOST_CHECK_EQUAL(HexStr(vDigest.begin(), vDigest.end()),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    boost::filesystem::remove(strAbc);

    // Larger than one read chunk, to exercise the streaming loop.
    string strBig(200000, 'x');
    string strBigPath = WriteTempFile(strBig);
    BOOST_CHECK(PodHashFile(strBigPath, vDigest, strError));
    vector<unsigned char> vExpect(POD_DIGEST_SIZE);
    SHA256((const unsigned char*)strBig.data(), strBig.size(), &vExpect[0]);
    BOOST_CHECK(vDigest == vExpect);
    boost::filesystem::remove(strBigPath);
}

// A missing file must be an error, not the digest of nothing. The old POD path
// hashed an unopened stream and stamped the hash of an empty file.
BOOST_AUTO_TEST_CASE(pod_hash_file_reports_missing_file)
{
    vector<unsigned char> vDigest;
    string strError;
    BOOST_CHECK(!PodHashFile("/nonexistent/innova/pod/test/file", vDigest, strError));
    BOOST_CHECK(!strError.empty());
    BOOST_CHECK(vDigest.empty());

    uint256 hashLegacy;
    strError.clear();
    BOOST_CHECK(!PodLegacyHashFile("/nonexistent/innova/pod/test/file", hashLegacy, strError));
    BOOST_CHECK(!strError.empty());
}

// The legacy digest podverify recomputes must equal what the old code produced.
BOOST_AUTO_TEST_CASE(pod_legacy_hash_matches_serializehash)
{
    const char* cases[3] = { "", "abc", "the quick brown fox" };
    for (int i = 0; i < 3; i++)
    {
        string strContents(cases[i]);
        string strPath = WriteTempFile(strContents);

        uint256 hashStreamed;
        string strError;
        BOOST_CHECK(PodLegacyHashFile(strPath, hashStreamed, strError));

        vector<char> vContents(strContents.begin(), strContents.end());
        BOOST_CHECK(hashStreamed == SerializeHash(vContents));

        boost::filesystem::remove(strPath);
    }

    // Past the 1-byte compact-size boundary, where the prefix widens to 3 bytes.
    string strLong(300, 'q');
    string strPath = WriteTempFile(strLong);
    uint256 hashStreamed;
    string strError;
    BOOST_CHECK(PodLegacyHashFile(strPath, hashStreamed, strError));
    vector<char> vContents(strLong.begin(), strLong.end());
    BOOST_CHECK(hashStreamed == SerializeHash(vContents));
    boost::filesystem::remove(strPath);
}

BOOST_AUTO_TEST_CASE(pod_blinding)
{
    vector<unsigned char> vDigest = Digest(0x88);
    vector<unsigned char> vSaltA(POD_SALT_SIZE, 0x01);
    vector<unsigned char> vSaltB(POD_SALT_SIZE, 0x02);

    vector<unsigned char> vA = PodBlindDigest(vDigest, vSaltA);
    BOOST_CHECK_EQUAL(vA.size(), (size_t)POD_DIGEST_SIZE);
    BOOST_CHECK(vA == PodBlindDigest(vDigest, vSaltA));   // deterministic
    BOOST_CHECK(vA != PodBlindDigest(vDigest, vSaltB));   // salt matters
    BOOST_CHECK(vA != vDigest);                           // hides the file digest

    // SHA-256(digest || salt), verified against a direct one-shot hash.
    vector<unsigned char> vCat;
    vCat.insert(vCat.end(), vDigest.begin(), vDigest.end());
    vCat.insert(vCat.end(), vSaltA.begin(), vSaltA.end());
    vector<unsigned char> vExpect(POD_DIGEST_SIZE);
    SHA256(&vCat[0], vCat.size(), &vExpect[0]);
    BOOST_CHECK(vA == vExpect);

    // Wrong-length inputs yield nothing rather than a silently truncated digest.
    BOOST_CHECK(PodBlindDigest(vector<unsigned char>(31, 0), vSaltA).empty());
    BOOST_CHECK(PodBlindDigest(vDigest, vector<unsigned char>(31, 0)).empty());

    vector<unsigned char> vSalt = PodNewSalt();
    BOOST_CHECK_EQUAL(vSalt.size(), (size_t)POD_SALT_SIZE);
    BOOST_CHECK(vSalt != PodNewSalt());
}

BOOST_AUTO_TEST_CASE(pod_builder_rejects_bad_input)
{
    BOOST_CHECK(PodStampScript(POD_TYPE_PLAIN, vector<unsigned char>(31, 0),
                               vector<unsigned char>()).empty());
    BOOST_CHECK(PodStampScript(POD_TYPE_PLAIN, vector<unsigned char>(33, 0),
                               vector<unsigned char>()).empty());
    BOOST_CHECK(PodStampScript(0, Digest(1), vector<unsigned char>()).empty());
}

BOOST_AUTO_TEST_SUITE_END()
