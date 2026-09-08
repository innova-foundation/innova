// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// A coinbase's IV5 transparent binding folds in its scriptSig height push; every other
// binding is the v2 digest. Both preimages are restated independently and pinned to vectors.

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <string>
#include <vector>

#include "../bignum.h"
#include "../main.h"
#include "../privacy_vnext_ffi.h"
#include "../script.h"
#include "../util.h"

namespace {

std::string Hex(const uint256& h)
{
    return HexStr(h.begin(), h.end());
}

std::vector<unsigned char> Bytes(const CScript& script)
{
    return std::vector<unsigned char>(script.begin(), script.end());
}

// The v2 digest: domain, input count, prevouts, outputs, lock time.
uint256 LegacyBinding(const CTransaction& tx)
{
    static const char* pszDomain = "Innova/IV5/TransparentBinding/v2";
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss.write(pszDomain, strlen(pszDomain));
    ss << (unsigned int)tx.vin.size();
    for (unsigned int i = 0; i < tx.vin.size(); i++)
        ss << tx.vin[i].prevout;
    ss << tx.vout;
    ss << tx.nLockTime;
    return ss.GetHash();
}

// The v2 digest followed by one length-prefixed byte string.
uint256 FoldedBinding(const CTransaction& tx, const std::vector<unsigned char>& vchPush)
{
    static const char* pszDomain = "Innova/IV5/TransparentBinding/v2";
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss.write(pszDomain, strlen(pszDomain));
    ss << (unsigned int)tx.vin.size();
    for (unsigned int i = 0; i < tx.vin.size(); i++)
        ss << tx.vin[i].prevout;
    ss << tx.vout;
    ss << tx.nLockTime;
    ss << vchPush;
    return ss.GetHash();
}

CTxOut SampleOut()
{
    std::vector<unsigned char> vchData;
    vchData.push_back(0xaa);
    vchData.push_back(0xbb);
    vchData.push_back(0xcc);
    CScript script;
    script << OP_RETURN << vchData;
    return CTxOut(123456789, script);
}

CTransaction Coinbase(const CScript& scriptSig)
{
    CTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vin[0].scriptSig = scriptSig;
    tx.vout.push_back(SampleOut());
    tx.nLockTime = 0;
    BOOST_REQUIRE(tx.IsCoinBase());
    return tx;
}

CTransaction NonCoinbase()
{
    CTransaction tx;
    tx.vin.resize(1);
    unsigned char* p = tx.vin[0].prevout.hash.begin();
    for (int i = 0; i < 32; i++)
        p[i] = (unsigned char)(0x10 + i);
    tx.vin[0].prevout.n = 3;
    tx.vout.push_back(SampleOut());
    tx.nLockTime = 7;
    BOOST_REQUIRE(!tx.IsCoinBase());
    return tx;
}

PrivacyVNextStateEffects EffectsBinding(const CTransaction& tx)
{
    PrivacyVNextStateEffects effects;
    const uint256 binding = GetPrivacyVNextTransparentBinding(tx);
    std::memcpy(effects.transparentBinding.data(), binding.begin(), 32);
    return effects;
}

// SHA256d over: "Innova/IV5/TransparentBinding/v2" || 00000000 || 00 || 00000000.
const char* const EMPTY_TX_BINDING =
    "4b81b8feeeddb5e71b32ef4948125615cb1678c6c732de6ab65100c6665c1170";

// SHA256d over the v2 preimage of NonCoinbase(): prevout 10..2f/3, one output of
// 123456789 to OP_RETURN aabbcc, lock time 7.
const char* const NON_COINBASE_BINDING =
    "07c45b4838197b7e1378688fc4da24d5fcb39667e2af072bbf36f67e236ceee8";

// Coinbase(CScript() << 8100000) with the same output: the v2 preimage over a null
// prevout, then 04 || 03 a0 98 7b.
const char* const COINBASE_8100000_BINDING =
    "8618f48c403a6f74effae1054b1e6cceb4ed1c7b235da3f01a19d39a309a5ce1";
const char* const COINBASE_8100001_BINDING =
    "04699c19b730bf081cfa0cc01b45e3b86ddcc6f42b6cb397b9f9a4259a4bbe82";

} // namespace

BOOST_AUTO_TEST_SUITE(coinbase_binding_height_tests)

BOOST_AUTO_TEST_CASE(non_coinbase_bindings_are_the_v2_digest_byte_for_byte)
{
    // The empty transaction is the fixed binding several suites build payloads over.
    {
        CTransaction tx;
        BOOST_CHECK(!tx.IsCoinBase());
        BOOST_CHECK_EQUAL(Hex(GetPrivacyVNextTransparentBinding(tx)),
                          Hex(LegacyBinding(tx)));
        BOOST_CHECK_EQUAL(Hex(GetPrivacyVNextTransparentBinding(tx)), EMPTY_TX_BINDING);
    }

    // One transparent input: a shield.
    {
        const CTransaction tx = NonCoinbase();
        BOOST_CHECK_EQUAL(Hex(GetPrivacyVNextTransparentBinding(tx)),
                          Hex(LegacyBinding(tx)));
        BOOST_CHECK_EQUAL(Hex(GetPrivacyVNextTransparentBinding(tx)),
                          NON_COINBASE_BINDING);
    }

    // The scriptSig of a transparent input is not in the digest, height-shaped or not.
    {
        CTransaction tx = NonCoinbase();
        tx.vin[0].scriptSig = CScript() << 8100000;
        BOOST_CHECK_EQUAL(Hex(GetPrivacyVNextTransparentBinding(tx)),
                          NON_COINBASE_BINDING);
    }

    // Two inputs, and a lock time.
    {
        CTransaction tx = NonCoinbase();
        tx.vin.push_back(tx.vin[0]);
        tx.vin[1].prevout.n = 4;
        tx.nLockTime = 9000;
        BOOST_CHECK_EQUAL(Hex(GetPrivacyVNextTransparentBinding(tx)),
                          Hex(LegacyBinding(tx)));
    }

    // No inputs, two outputs: a spend's shape.
    {
        CTransaction tx;
        tx.vout.push_back(SampleOut());
        tx.vout.push_back(SampleOut());
        BOOST_CHECK(!tx.IsCoinBase());
        BOOST_CHECK_EQUAL(Hex(GetPrivacyVNextTransparentBinding(tx)),
                          Hex(LegacyBinding(tx)));
    }

    // A null hash with a real index is not a null prevout.
    {
        CTransaction tx = NonCoinbase();
        tx.vin[0].prevout.hash = 0;
        BOOST_CHECK(!tx.IsCoinBase());
        BOOST_CHECK_EQUAL(Hex(GetPrivacyVNextTransparentBinding(tx)),
                          Hex(LegacyBinding(tx)));
    }

    // A null prevout with no outputs is not a coinbase either; the fold keys on
    // IsCoinBase() and nothing looser.
    {
        CTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout.SetNull();
        tx.vin[0].scriptSig = CScript() << 8100000;
        BOOST_CHECK(!tx.IsCoinBase());
        BOOST_CHECK_EQUAL(Hex(GetPrivacyVNextTransparentBinding(tx)),
                          Hex(LegacyBinding(tx)));
    }
}

BOOST_AUTO_TEST_CASE(a_coinbase_binding_folds_its_height_push)
{
    // Every encoding CScript() << nHeight takes: OP_0, OP_1..OP_16, and one to four
    // little-endian bytes with the sign pad.
    static const int vHeights[] = {
        0, 1, 2, 16, 17, 127, 128, 255, 256, 32767, 32768, 8100000, 2147483647
    };
    const size_t nHeights = sizeof(vHeights) / sizeof(vHeights[0]);

    // The push AcceptBlock enforces is what is folded, and nothing wider.
    {
        const std::vector<unsigned char> push = Bytes(CScript() << 8100000);
        BOOST_REQUIRE_EQUAL(push.size(), (size_t)4);
        BOOST_CHECK_EQUAL(HexStr(push), "03a0987b");
    }

    std::vector<uint256> vBindings;
    for (size_t i = 0; i < nHeights; i++)
    {
        const CScript scriptSig = CScript() << vHeights[i];
        const CTransaction tx = Coinbase(scriptSig);
        const uint256 binding = GetPrivacyVNextTransparentBinding(tx);
        BOOST_CHECK_MESSAGE(binding == FoldedBinding(tx, Bytes(scriptSig)),
                            strprintf("height %d: binding is not the v2 preimage "
                                      "followed by its height push", vHeights[i]));
        BOOST_CHECK_MESSAGE(binding != LegacyBinding(tx),
                            strprintf("height %d: the fold is not in effect",
                                      vHeights[i]));
        vBindings.push_back(binding);
    }

    // Same outputs, same lock time, different heights: no two agree.
    for (size_t i = 0; i < vBindings.size(); i++)
        for (size_t j = i + 1; j < vBindings.size(); j++)
            BOOST_CHECK_MESSAGE(vBindings[i] != vBindings[j],
                                strprintf("heights %d and %d share a binding",
                                          vHeights[i], vHeights[j]));

    BOOST_CHECK_EQUAL(Hex(GetPrivacyVNextTransparentBinding(Coinbase(CScript() << 8100000))),
                      COINBASE_8100000_BINDING);
    BOOST_CHECK_EQUAL(Hex(GetPrivacyVNextTransparentBinding(Coinbase(CScript() << 8100001))),
                      COINBASE_8100001_BINDING);
}

BOOST_AUTO_TEST_CASE(mining_leaves_a_coinbase_binding_where_the_template_put_it)
{
    const int nHeight = 8100000;
    const uint256 base = GetPrivacyVNextTransparentBinding(Coinbase(CScript() << nHeight));

    CScript flags;
    {
        std::vector<unsigned char> vchTag;
        vchTag.push_back('/');
        vchTag.push_back('I');
        vchTag.push_back('N');
        vchTag.push_back('N');
        vchTag.push_back('/');
        flags << vchTag;
    }

    // IncrementExtraNonce's shape: height, extra nonce, flags.
    static const unsigned int vNonces[] = { 1, 2, 255, 256, 65536, 4000000000u };
    for (size_t i = 0; i < sizeof(vNonces) / sizeof(vNonces[0]); i++)
    {
        CScript scriptSig = CScript() << nHeight;
        scriptSig << CBigNum(vNonces[i]);
        BOOST_CHECK_MESSAGE(
            GetPrivacyVNextTransparentBinding(Coinbase(scriptSig + flags)) == base,
            strprintf("extra nonce %u moved the binding", vNonces[i]));
        BOOST_CHECK_MESSAGE(
            GetPrivacyVNextTransparentBinding(Coinbase(scriptSig + COINBASE_FLAGS)) == base,
            strprintf("extra nonce %u with COINBASE_FLAGS moved the binding", vNonces[i]));
    }

    // The proof-of-stake template's shape: height, flags.
    BOOST_CHECK(GetPrivacyVNextTransparentBinding(
                    Coinbase((CScript() << nHeight) + flags)) == base);

    // The genesis shape: OP_0, a number, a string.
    {
        const std::string strStamp = "a timestamp";
        const std::vector<unsigned char> vchStamp(strStamp.begin(), strStamp.end());
        const CScript scriptGenesis = CScript() << 0 << CBigNum(42) << vchStamp;
        BOOST_CHECK(GetPrivacyVNextTransparentBinding(Coinbase(scriptGenesis)) ==
                    GetPrivacyVNextTransparentBinding(Coinbase(CScript() << 0)));
    }
}

BOOST_AUTO_TEST_CASE(a_fee_note_copied_to_another_height_fails_the_binding_check)
{
    // The producer's coinbase, and the binding its fee note committed to.
    const CTransaction victim = Coinbase(CScript() << 8100000);
    const PrivacyVNextStateEffects effects = EffectsBinding(victim);
    std::string strError;
    BOOST_CHECK_MESSAGE(CheckPrivacyVNextTransparentBinding(victim, effects, strError),
                        strError);

    // The same outputs and the same note, one block later.
    {
        CTransaction rival = victim;
        rival.vin[0].scriptSig = CScript() << 8100001;
        BOOST_CHECK(!CheckPrivacyVNextTransparentBinding(rival, effects, strError));
        BOOST_CHECK(!strError.empty());
    }

    // Much later, with mining noise after the height.
    {
        CTransaction rival = victim;
        CScript scriptSig = CScript() << 8200000;
        scriptSig << CBigNum(1u);
        rival.vin[0].scriptSig = scriptSig + COINBASE_FLAGS;
        BOOST_CHECK(!CheckPrivacyVNextTransparentBinding(rival, effects, strError));
    }

    // The honest case at the note's own height: the template after
    // IncrementExtraNonce still carries its binding.
    {
        CTransaction mined = victim;
        CScript scriptSig = CScript() << 8100000;
        scriptSig << CBigNum(7u);
        mined.vin[0].scriptSig = scriptSig + COINBASE_FLAGS;
        BOOST_CHECK_MESSAGE(CheckPrivacyVNextTransparentBinding(mined, effects, strError),
                            strError);
    }

    // The output vector is still bound: a retargeted coinbase at the right height fails.
    {
        CTransaction retargeted = victim;
        retargeted.vout[0].nValue += 1;
        BOOST_CHECK(!CheckPrivacyVNextTransparentBinding(retargeted, effects, strError));
    }
}

BOOST_AUTO_TEST_CASE(a_malformed_height_push_still_yields_one_binding)
{
    // AcceptBlock refuses every one of these; the digest is still total and
    // deterministic over them.
    const std::vector<unsigned char> none;

    // Nothing to read.
    BOOST_CHECK(GetPrivacyVNextTransparentBinding(Coinbase(CScript())) ==
                FoldedBinding(Coinbase(CScript()), none));

    // A push whose length byte or data is cut off.
    {
        CScript truncated;
        truncated.push_back(OP_PUSHDATA1);
        BOOST_CHECK(GetPrivacyVNextTransparentBinding(Coinbase(truncated)) ==
                    FoldedBinding(Coinbase(truncated), none));
        truncated.push_back(0x01);
        BOOST_CHECK(GetPrivacyVNextTransparentBinding(Coinbase(truncated)) ==
                    FoldedBinding(Coinbase(truncated), none));
    }

    // A non-push opcode is a one-byte operation.
    {
        CScript opcodeOnly;
        opcodeOnly.push_back(OP_RETURN);
        std::vector<unsigned char> one;
        one.push_back(OP_RETURN);
        BOOST_CHECK(GetPrivacyVNextTransparentBinding(Coinbase(opcodeOnly)) ==
                    FoldedBinding(Coinbase(opcodeOnly), one));
    }

    // Bytes after the first operation are not read.
    {
        CScript noisy = CScript() << 5;
        noisy.push_back(0xff);
        noisy.push_back(0xfe);
        BOOST_CHECK(GetPrivacyVNextTransparentBinding(Coinbase(noisy)) ==
                    GetPrivacyVNextTransparentBinding(Coinbase(CScript() << 5)));
    }
}

BOOST_AUTO_TEST_SUITE_END()
