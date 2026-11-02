// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include "../key.h"
#include "../nyxcert.h"
#include "../nyxidentity.h"
#include "../nyxkeyring.h"
#include "../nyxsession.h"
#include "../util.h"
#include "../privacy_vnext/rust/include/nyx_pq.h"

#include <boost/lexical_cast.hpp>

#include <algorithm>
#include <set>
#include <string.h>

namespace {

const int64_t T0 = 1790000000;

bool nyx_x25519_wrap(const uint8_t* sk, const uint8_t* pk, uint8_t* out)
{
    return nyx_x25519(sk, pk, out) == 0;
}

NyxBytes Unhex(const char* s)
{
    const std::vector<unsigned char> v = ParseHex(s);
    return NyxBytes(v.begin(), v.end());
}

struct Party
{
    CKey key;
    uint8_t addr[20];
    NyxOwnDevice dev;
    NyxKeyring kr;
    NyxPinInput net;

    Party(uint8_t mode, bool fOpk)
    {
        key.MakeNewKey(true);
        const CKeyID id = key.GetPubKey().GetID();
        memcpy(addr, id.begin(), 20);
        uint8_t fp[32] = {5};
        BOOST_REQUIRE(NyxDeviceCreate(dev, addr, mode, fp));
        NyxCert c;
        BOOST_REQUIRE(NyxBuildCert(dev, key, T0, 1, NULL, c));
        dev.certBody = c.Serialize();
        memcpy(kr.addrHash, addr, 20);
        kr.mode = mode;
        kr.ts = T0;
        NyxKeyringEntry e;
        memcpy(e.deviceId, dev.deviceId, 16);
        NyxHash(dev.certBody, e.certHash);
        kr.live.push_back(e);
        BOOST_REQUIRE(NyxBuildKeyring(kr, key, NULL));
        dev.keyringBody = kr.Serialize();
        net.keyrings.push_back(dev.keyringBody);
        net.certs.push_back(dev.certBody);
        if (fOpk)
            BOOST_REQUIRE(NyxDeviceTopUpOpks(dev, T0));
    }

    NyxBundle Bundle()
    {
        NyxBundle b;
        BOOST_REQUIRE(NyxBuildBundle(dev, key, T0, b));
        return b;
    }

    NyxLocalSide Local()
    {
        NyxLocalSide me;
        me.dev = &dev;
        NyxHash(dev.certBody, me.certHash);
        me.epoch = kr.epoch;
        me.seq = kr.seq;
        me.addrKey = &key;
        return me;
    }

    NyxPin Pin() const
    {
        NyxPin p;
        memcpy(p.addrHash, addr, 20);
        BOOST_REQUIRE(NyxPinApply(p, net, T0 + 5) & NYX_PIN_PINNED);
        return p;
    }
};

NyxPeerSide PeerOf(const NyxPin& p)
{
    BOOST_REQUIRE_EQUAL(p.devices.size(), 1U);
    const NyxPinDevice& d = p.devices.begin()->second;
    NyxPeerSide ps;
    ps.cert = &d.cert;
    memcpy(ps.certHash, d.certHash, 32);
    ps.epoch = p.kr.epoch;
    ps.seq = p.kr.seq;
    return ps;
}

NyxBytes Pt(const std::string& s)
{
    return NyxBytes(s.begin(), s.end());
}

// A starts a session with B; B answers. Both sides' pins are made from the published objects.
struct Pair
{
    Party a, b;
    NyxPin pinB, pinA;   // A's pin of B, B's pin of A
    NyxSession sa, sb;
    uint32_t opkUsed;

    Pair(uint8_t mode = NYX_MODE_PQ, bool fOpk = true) : a(mode, false), b(mode, fOpk), pinB(b.Pin()), pinA(a.Pin())
    {
        NyxRatchet r;
        std::string err;
        BOOST_REQUIRE_MESSAGE(NyxHsInitiate(a.Local(), PeerOf(pinB), b.Bundle(), T0 + 10, r, err), err);
        sa.Push(r);
    }

    // Body from A (0x10 until acked).
    NyxBytes FromA(const std::string& s, int64_t t = T0 + 20)
    {
        NyxBytes body;
        BOOST_REQUIRE(NyxSessionSeal(sa.states[0], Pt(s), t, body));
        return body;
    }

    NyxBytes FromB(const std::string& s, int64_t t = T0 + 20)
    {
        NyxBytes body;
        BOOST_REQUIRE(NyxSessionSeal(sb.states[0], Pt(s), t, body));
        return body;
    }

    // B's receive path for a body from A; returns the NyxDrResult or 100 + handshake refusal.
    int ToB(const NyxBytes& body, NyxBytes& pt, int64_t t = T0 + 30)
    {
        if (body[0] == NYX_BODY_RATCHET)
        {
            NyxRatchetMsg m;
            if (NyxParseRatchetMsg(&body[0], body.size(), m) != 0)
                return NYX_DR_MALFORMED;
            return sb.Decrypt(m.tail, t, pt);
        }
        NyxHandshake hs;
        if (NyxParseHandshake(&body[0], body.size(), hs) != 0)
            return NYX_DR_MALFORMED;
        uint8_t id[32];
        NyxHsId(hs, id);
        if (sb.FindHs(id) >= 0)
            return sb.Decrypt(hs.tail, t, pt);
        NyxRatchet r;
        std::string err;
        if (!NyxHsRespond(b.Local(), PeerOf(pinA), hs, t, r, opkUsed, err))
            return 100;
        const int dr = NyxRatchetDecrypt(r, hs.tail, t, pt);
        if (dr != NYX_DR_OK)
            return dr;
        if (opkUsed != NYX_OPK_NONE)
            NyxDeviceEraseOpk(b.dev, opkUsed);
        sb.Push(r);
        return NYX_DR_OK;
    }

    int ToA(const NyxBytes& body, NyxBytes& pt, int64_t t = T0 + 30)
    {
        NyxRatchetMsg m;
        if (NyxParseRatchetMsg(&body[0], body.size(), m) != 0)
            return NYX_DR_MALFORMED;
        return sa.Decrypt(m.tail, t, pt);
    }
};

std::string S(const NyxBytes& v)
{
    return std::string(v.begin(), v.end());
}

} // namespace

BOOST_AUTO_TEST_SUITE(nyx_session_tests)

BOOST_AUTO_TEST_CASE(kdf_known_answers)
{
    // Vectors from contrib/test/nyx_session_kat.py (independent pure-Python RFC 5869 / RFC 7748).
    uint8_t ikA[32], ekA[32], ikB[32], spkB[32], opkB[32], ss[32], base[32] = {9};
    memset(ikA, 0x11, 32);
    memset(ekA, 0x22, 32);
    memset(ikB, 0x33, 32);
    memset(spkB, 0x44, 32);
    memset(opkB, 0x55, 32);
    memset(ss, 0x66, 32);
    uint8_t pIkB[32], pSpkB[32], pOpkB[32], dh[128];
    BOOST_REQUIRE(nyx_x25519_wrap(ikB, base, pIkB));
    BOOST_REQUIRE(nyx_x25519_wrap(spkB, base, pSpkB));
    BOOST_REQUIRE(nyx_x25519_wrap(opkB, base, pOpkB));
    BOOST_REQUIRE(nyx_x25519_wrap(ikA, pSpkB, dh));
    BOOST_REQUIRE(nyx_x25519_wrap(ekA, pIkB, dh + 32));
    BOOST_REQUIRE(nyx_x25519_wrap(ekA, pSpkB, dh + 64));
    BOOST_REQUIRE(nyx_x25519_wrap(ekA, pOpkB, dh + 96));
    BOOST_CHECK(NyxBytes(dh, dh + 32) == Unhex("b21afd23cc289c5c693adc6d9c7198657e590320fa4dd7a0aaf606e441a2ea46"));

    uint8_t out[96];
    BOOST_REQUIRE(NyxPqxdhKdf(dh, 4, ss, out));
    BOOST_CHECK(NyxBytes(out, out + 96) == Unhex("0595fe3427840b532ecffe21ef5d5c31621f784e987373afd6a80232beed2d5bddb53e6331a8b70c13df7a35359a8765c30a10d02b910b7cfbd1634fed738fd726feb73496bc6cdec8379eabd75fdaa02a8a184b2e230eda67228029e37c3770"));
    BOOST_REQUIRE(NyxPqxdhKdf(dh, 3, ss, out));
    BOOST_CHECK(NyxBytes(out, out + 96) == Unhex("b8b111225fb1a47a952fafafe58840a6d7ad9dd3f042432ae01ad4b5ec3de4a82a35350638cc38a4159602b30853810dc3e6292dd05952e2fbb21e6b28f9a17b46e2c3c0e6a8208994610f8a77345ce276db29b8ff1fa7b8ed2df8fa73fe2d2f"));
    BOOST_REQUIRE(NyxPqxdhKdf(dh, 4, NULL, out));
    BOOST_CHECK(NyxBytes(out, out + 96) == Unhex("c1b2004936ee6648a7501a0068ef201b312996b060a6f6903b9c73572a304a271be7a1e02a028509b0e438d4a5ed27e9113a729d0d2ac3a7e79b0b783ddc9389a47f5a38a37e117128b33d07f4c00d315e302b1d493ac10aa458add01e3be904"));

    // Both secrets matter: a zero KEM secret or a missing DH4 gives a different key.
    uint8_t zero[32] = {0}, alt[96];
    BOOST_REQUIRE(NyxPqxdhKdf(dh, 4, zero, alt));
    BOOST_CHECK(memcmp(alt, out, 96) != 0);

    uint8_t rk[32], dho[32];
    memset(rk, 0x77, 32);
    memset(dho, 0x88, 32);
    BOOST_REQUIRE(NyxKdfRk(rk, dho, out));
    BOOST_CHECK(NyxBytes(out, out + 96) == Unhex("ee704f4efa7cd913a6c2fa7b2571747d6a37a723cd5247cd05342449e98bf127a97aa90126719b68031fa0223bf2467d53ee83c026f231087f900c6dd7ab0584a0a20a2f076d80a3dc3b439e10fe776f60a38e710f4c7088cd0e8b6eb71a8855"));
    uint8_t ck[32], ck2[32], mk[32];
    memset(ck, 0x99, 32);
    BOOST_REQUIRE(NyxKdfCk(ck, ck2, mk));
    BOOST_CHECK(NyxBytes(ck2, ck2 + 32) == Unhex("bf31bdf94033a36e200122fcff5867bc4d679a13e25cc494d7a20247a59f0920"));
    BOOST_CHECK(NyxBytes(mk, mk + 32) == Unhex("2003bde44a17989c6e951d99339e75d1d213cc4617b106d66e9ca686e8f7f884"));
}

BOOST_AUTO_TEST_CASE(pq_handshake_with_opk_both_directions)
{
    Pair p;
    const NyxBytes h1 = p.FromA("hello");
    BOOST_CHECK_EQUAL(h1[0], NYX_BODY_HANDSHAKE);
    BOOST_CHECK_EQUAL(h1.size(), NYX_HS_FIXED_PQ + 12 + NYX_ENC_HDR_LEN + 12 + 5 + 16);
    BOOST_CHECK(p.sa.states[0].fOpk);
    const size_t nOpk = p.b.dev.opks.size();
    NyxBytes pt;
    BOOST_REQUIRE_EQUAL(p.ToB(h1, pt), NYX_DR_OK);
    BOOST_CHECK_EQUAL(S(pt), "hello");
    BOOST_CHECK_EQUAL(p.b.dev.opks.size(), nOpk - 1);
    BOOST_CHECK(memcmp(p.sa.states[0].T, p.sb.states[0].T, 32) == 0);

    // Still unacked: A repeats the handshake prefix; B routes it to the same session.
    const NyxBytes h2 = p.FromA("again");
    BOOST_CHECK_EQUAL(h2[0], NYX_BODY_HANDSHAKE);
    BOOST_REQUIRE_EQUAL(p.ToB(h2, pt), NYX_DR_OK);
    BOOST_CHECK_EQUAL(S(pt), "again");
    BOOST_CHECK_EQUAL(p.sb.states.size(), 1U);

    const NyxBytes r1 = p.FromB("hi back");
    BOOST_CHECK_EQUAL(r1[0], NYX_BODY_RATCHET);
    BOOST_REQUIRE_EQUAL(p.ToA(r1, pt), NYX_DR_OK);
    BOOST_CHECK_EQUAL(S(pt), "hi back");
    BOOST_CHECK(p.sa.states[0].fAcked);
    const NyxBytes m3 = p.FromA("now ratchet");
    BOOST_CHECK_EQUAL(m3[0], NYX_BODY_RATCHET);
    BOOST_REQUIRE_EQUAL(p.ToB(m3, pt), NYX_DR_OK);
    BOOST_CHECK_EQUAL(S(pt), "now ratchet");

    // Several DH ratchet turns.
    for (int i = 0; i < 6; ++i)
    {
        BOOST_REQUIRE_EQUAL(p.ToA(p.FromB("b" + std::string(1, '0' + i)), pt), NYX_DR_OK);
        BOOST_REQUIRE_EQUAL(p.ToB(p.FromA("a" + std::string(1, '0' + i)), pt), NYX_DR_OK);
        BOOST_CHECK_EQUAL(S(pt), "a" + std::string(1, '0' + i));
    }
}

BOOST_AUTO_TEST_CASE(handshake_without_opk_and_classical)
{
    Pair p(NYX_MODE_PQ, false);
    BOOST_CHECK(!p.sa.states[0].fOpk);
    NyxBytes pt;
    BOOST_REQUIRE_EQUAL(p.ToB(p.FromA("no opk"), pt), NYX_DR_OK);
    BOOST_CHECK_EQUAL(p.opkUsed, NYX_OPK_NONE);
    BOOST_REQUIRE_EQUAL(p.ToA(p.FromB("ok"), pt), NYX_DR_OK);

    Pair c(NYX_MODE_CLASSICAL, true);
    const NyxBytes h = c.FromA("classical");
    BOOST_CHECK_EQUAL(h.size(), NYX_HS_FIXED_CLASSICAL + 12 + NYX_ENC_HDR_LEN + 12 + 9 + 16);
    BOOST_REQUIRE_EQUAL(c.ToB(h, pt), NYX_DR_OK);
    BOOST_CHECK_EQUAL(S(pt), "classical");
    BOOST_REQUIRE_EQUAL(c.ToA(c.FromB("x3dh"), pt), NYX_DR_OK);
}

BOOST_AUTO_TEST_CASE(simultaneous_initiation_keeps_both_decryptable)
{
    Pair p;
    NyxRatchet rb;
    std::string err;
    // B also starts a session with A (A publishes OPKs too).
    BOOST_REQUIRE(NyxDeviceTopUpOpks(p.a.dev, T0));
    NyxBundle ba = p.a.Bundle();
    BOOST_REQUIRE(NyxHsInitiate(p.b.Local(), PeerOf(p.pinA), ba, T0 + 11, rb, err));
    p.sb.Push(rb);
    NyxBytes hb;
    BOOST_REQUIRE(NyxSessionSeal(p.sb.states[0], Pt("from b"), T0 + 12, hb));
    const NyxBytes ha = p.FromA("from a");

    NyxBytes pt;
    BOOST_REQUIRE_EQUAL(p.ToB(ha, pt), NYX_DR_OK);
    BOOST_CHECK_EQUAL(p.sb.states.size(), 2U);
    // A receives B's handshake on its own side.
    NyxHandshake hs;
    BOOST_REQUIRE_EQUAL(NyxParseHandshake(&hb[0], hb.size(), hs), 0);
    NyxRatchet ra;
    uint32_t opk;
    BOOST_REQUIRE(NyxHsRespond(p.a.Local(), PeerOf(p.pinB), hs, T0 + 30, ra, opk, err));
    BOOST_REQUIRE_EQUAL(NyxRatchetDecrypt(ra, hs.tail, T0 + 30, pt), NYX_DR_OK);
    BOOST_CHECK_EQUAL(S(pt), "from b");
    p.sa.Push(ra);

    // Each side sends on its current state; the other opens it on whichever state matches.
    for (int i = 0; i < 3; ++i)
    {
        BOOST_REQUIRE_EQUAL(p.ToB(p.FromA("a"), pt), NYX_DR_OK);
        BOOST_REQUIRE_EQUAL(p.ToA(p.FromB("b"), pt), NYX_DR_OK);
    }
}

BOOST_AUTO_TEST_CASE(out_of_order_and_skipped_bounds)
{
    Pair p;
    NyxBytes pt;
    BOOST_REQUIRE_EQUAL(p.ToB(p.FromA("start"), pt), NYX_DR_OK);
    BOOST_REQUIRE_EQUAL(p.ToA(p.FromB("ack"), pt), NYX_DR_OK);

    std::vector<NyxBytes> v;
    for (int i = 0; i < 60; ++i)
        v.push_back(p.FromA("m" + boost::lexical_cast<std::string>(i)));
    std::vector<size_t> order;
    for (size_t i = 0; i < v.size(); ++i)
        order.push_back(i);
    std::reverse(order.begin() + 10, order.end());
    std::swap(order[0], order[7]);
    for (size_t k = 0; k < order.size(); ++k)
    {
        BOOST_REQUIRE_EQUAL(p.ToB(v[order[k]], pt), NYX_DR_OK);
        BOOST_CHECK_EQUAL(S(pt), "m" + boost::lexical_cast<std::string>(order[k]));
    }
    BOOST_CHECK(p.sb.states[0].skipped.empty());

    // Out of order across a DH ratchet step: an old-chain message arrives after the new chain.
    const NyxBytes late = p.FromA("late");
    BOOST_REQUIRE_EQUAL(p.ToA(p.FromB("turn"), pt), NYX_DR_OK);
    const NyxBytes fresh = p.FromA("fresh");
    BOOST_REQUIRE_EQUAL(p.ToB(fresh, pt), NYX_DR_OK);
    BOOST_REQUIRE_EQUAL(p.ToB(late, pt), NYX_DR_OK);
    BOOST_CHECK_EQUAL(S(pt), "late");

    // More than NYX_MAX_SKIP ahead in one chain is refused and leaves the state usable.
    std::vector<NyxBytes> burst;
    for (uint32_t i = 0; i <= NYX_MAX_SKIP + 1; ++i)
        burst.push_back(p.FromA("x"));
    BOOST_CHECK_EQUAL(p.ToB(burst.back(), pt), NYX_DR_SKIP_LIMIT);
    BOOST_REQUIRE_EQUAL(p.ToB(burst[NYX_MAX_SKIP], pt), NYX_DR_OK);
    BOOST_CHECK_EQUAL(p.sb.states[0].skipped.size(), (size_t)NYX_MAX_SKIP);
    BOOST_REQUIRE_EQUAL(p.ToB(burst.back(), pt), NYX_DR_OK);

    // Session cap: skipped keys beyond NYX_MAX_SKIPPED evict the oldest.
    std::vector<NyxBytes> more;
    for (uint32_t i = 0; i <= NYX_MAX_SKIP; ++i)
        more.push_back(p.FromA("y"));
    BOOST_REQUIRE_EQUAL(p.ToB(more.back(), pt), NYX_DR_OK);
    BOOST_CHECK_EQUAL(p.sb.states[0].skipped.size(), NYX_MAX_SKIPPED);
    const NyxBytes e0 = p.FromA("e0"), e1 = p.FromA("e1");
    BOOST_REQUIRE_EQUAL(p.ToB(e1, pt), NYX_DR_OK);
    BOOST_CHECK_EQUAL(p.sb.states[0].skipped.size(), NYX_MAX_SKIPPED);
    BOOST_CHECK_EQUAL(p.ToB(burst[0], pt), NYX_DR_REPLAY);   // evicted
    BOOST_REQUIRE_EQUAL(p.ToB(burst[1], pt), NYX_DR_OK);

    // Skipped keys expire after NYX_SKIPPED_TTL.
    BOOST_CHECK_EQUAL(p.ToB(more[0], pt, T0 + 30 + NYX_SKIPPED_TTL + 1), NYX_DR_REPLAY);
}

BOOST_AUTO_TEST_CASE(replay_rejected)
{
    Pair p;
    NyxBytes pt;
    const NyxBytes h = p.FromA("one");
    BOOST_REQUIRE_EQUAL(p.ToB(h, pt), NYX_DR_OK);
    BOOST_CHECK_NE(p.ToB(h, pt), NYX_DR_OK);
    BOOST_REQUIRE_EQUAL(p.ToA(p.FromB("ack"), pt), NYX_DR_OK);
    const NyxBytes m1 = p.FromA("two"), m2 = p.FromA("three");
    BOOST_REQUIRE_EQUAL(p.ToB(m2, pt), NYX_DR_OK);
    BOOST_CHECK_EQUAL(p.ToB(m2, pt), NYX_DR_REPLAY);
    BOOST_REQUIRE_EQUAL(p.ToB(m1, pt), NYX_DR_OK);   // from skipped keys
    BOOST_CHECK_NE(p.ToB(m1, pt), NYX_DR_OK);
    // Replay of the first handshake after the DH ratchet moved on.
    BOOST_CHECK_NE(p.ToB(h, pt), NYX_DR_OK);
}

BOOST_AUTO_TEST_CASE(tampering_rejected_without_state_change)
{
    Pair p;
    NyxBytes pt;
    BOOST_REQUIRE_EQUAL(p.ToB(p.FromA("one"), pt), NYX_DR_OK);
    BOOST_REQUIRE_EQUAL(p.ToA(p.FromB("ack"), pt), NYX_DR_OK);
    const NyxBytes m = p.FromA("tamper me");
    const size_t pos[] = {33, 33 + 12, 33 + 40, 33 + 12 + NYX_ENC_HDR_LEN, 33 + 12 + NYX_ENC_HDR_LEN + 12,
                          m.size() - 1};
    for (size_t i = 0; i < sizeof(pos) / sizeof(pos[0]); ++i)
    {
        NyxBytes t = m;
        t[pos[i]] ^= 0x01;
        const std::string before = p.sb.Serialize();
        BOOST_CHECK_NE(p.ToB(t, pt), NYX_DR_OK);
        BOOST_CHECK(p.sb.Serialize() == before);
    }
    BOOST_REQUIRE_EQUAL(p.ToB(m, pt), NYX_DR_OK);
    BOOST_CHECK_EQUAL(S(pt), "tamper me");

    // Handshake field tampering breaks the signature or the derived keys.
    Pair q;
    const NyxBytes h = q.FromA("hs");
    const size_t hpos[] = {2, 30, 80, 110, 150, 180, 205, 220, 226, 300, 230 + 1088 + 2, 230 + 1088 + 9, NYX_HS_FIXED_PQ - 1,
                           NYX_HS_FIXED_PQ + 5};
    for (size_t i = 0; i < sizeof(hpos) / sizeof(hpos[0]); ++i)
    {
        NyxBytes t = h;
        t[hpos[i]] ^= 0x01;
        BOOST_CHECK_NE(q.ToB(t, pt), NYX_DR_OK);
        BOOST_CHECK(q.sb.states.empty());
    }
    BOOST_REQUIRE_EQUAL(q.ToB(h, pt), NYX_DR_OK);
}

BOOST_AUTO_TEST_CASE(wrong_device_and_transcript_misbinding)
{
    Pair p;
    Party other(NYX_MODE_PQ, true);
    const NyxBytes h = p.FromA("for b");
    NyxHandshake hs;
    BOOST_REQUIRE_EQUAL(NyxParseHandshake(&h[0], h.size(), hs), 0);
    NyxRatchet r;
    uint32_t opk;
    std::string err;
    BOOST_CHECK(!NyxHsRespond(other.Local(), PeerOf(p.pinA), hs, T0 + 30, r, opk, err));
    BOOST_CHECK(err.find("another device") != std::string::npos);

    // Re-addressing the handshake to another device breaks the signed transcript.
    memcpy(hs.devB, other.dev.deviceId, 16);
    memcpy(hs.addrB, other.addr, 20);
    NyxHash(other.dev.certBody, hs.certHashB);
    BOOST_CHECK(!NyxHsRespond(other.Local(), PeerOf(p.pinA), hs, T0 + 30, r, opk, err));
    BOOST_CHECK(err.find("signature") != std::string::npos);

    // A pinned cert that is not the initiator's.
    BOOST_REQUIRE_EQUAL(NyxParseHandshake(&h[0], h.size(), hs), 0);
    NyxPin wrong = other.Pin();
    BOOST_CHECK(!NyxHsRespond(p.b.Local(), PeerOf(wrong), hs, T0 + 30, r, opk, err));

    // Ratchet message from another session does not open.
    NyxBytes pt;
    BOOST_REQUIRE_EQUAL(p.ToB(h, pt), NYX_DR_OK);
    Pair q;
    BOOST_REQUIRE_EQUAL(q.ToB(q.FromA("q"), pt), NYX_DR_OK);
    BOOST_CHECK_EQUAL(p.ToA(q.FromB("not yours"), pt), NYX_DR_NO_HEADER);

    // Time window.
    Pair w;
    const NyxBytes hw = w.FromA("old");
    BOOST_CHECK_EQUAL(w.ToB(hw, pt, T0 + 10 + NYX_HS_WINDOW + 1), 100);
    BOOST_CHECK_EQUAL(w.ToB(hw, pt, T0 + 10 - NYX_HS_FUTURE - 1), 100);
}

BOOST_AUTO_TEST_CASE(downgrade_and_mode_mismatch_refused)
{
    Party a(NYX_MODE_PQ, false), c(NYX_MODE_CLASSICAL, true);
    NyxPin pinC = c.Pin();
    NyxRatchet r;
    std::string err;
    BOOST_CHECK(!NyxHsInitiate(a.Local(), PeerOf(pinC), c.Bundle(), T0 + 10, r, err));
    BOOST_CHECK(err.find("downgrade") != std::string::npos);
    NyxPin pinA = a.Pin();
    BOOST_CHECK(!NyxHsInitiate(c.Local(), PeerOf(pinA), a.Bundle(), T0 + 10, r, err));

    // A PQ handshake rewritten as classical does not parse into a valid classical one.
    Pair p;
    NyxBytes h = p.FromA("pq");
    h[1] = NYX_MODE_CLASSICAL;
    NyxBytes pt;
    BOOST_CHECK_NE(p.ToB(h, pt), NYX_DR_OK);

    // A bundle for B signed by someone else is refused.
    Pair q;
    NyxBundle forged = q.b.Bundle();
    forged.spk[0] ^= 1;
    BOOST_CHECK(!NyxHsInitiate(q.a.Local(), PeerOf(q.pinB), forged, T0 + 10, r, err));
    BOOST_CHECK(err.find("bundle") != std::string::npos);

    // Frozen pins cannot send.
    NyxPin frozen = pinA;
    frozen.fFrozen = true;
    BOOST_CHECK(!NyxPinCanSend(frozen));
}

BOOST_AUTO_TEST_CASE(opk_single_use_and_spk_rotation)
{
    Pair p;
    NyxBytes pt;
    const NyxBundle b1 = p.b.Bundle();
    BOOST_REQUIRE_EQUAL(p.ToB(p.FromA("x"), pt), NYX_DR_OK);
    // A second initiator that picks the same (now consumed) OPK is refused.
    NyxRatchet r;
    std::string err;
    NyxHandshake hs;
    for (int i = 0; i < 400; ++i)
    {
        BOOST_REQUIRE(NyxHsInitiate(p.a.Local(), PeerOf(p.pinB), b1, T0 + 40, r, err));
        NyxBytes h2;
        BOOST_REQUIRE(NyxSessionSeal(r, Pt("reuse"), T0 + 40, h2));
        BOOST_REQUIRE_EQUAL(NyxParseHandshake(&h2[0], h2.size(), hs), 0);
        if (hs.opkId == p.opkUsed)
            break;
    }
    BOOST_REQUIRE_EQUAL(hs.opkId, p.opkUsed);
    uint32_t opk;
    NyxRatchet rb;
    BOOST_CHECK(!NyxHsRespond(p.b.Local(), PeerOf(p.pinA), hs, T0 + 41, rb, opk, err));
    BOOST_CHECK(err.find("one-time") != std::string::npos);

    // OPK top-up: below the low mark it refills, within the daily mint budget.
    NyxOwnDevice& d = p.b.dev;
    while (d.opks.size() > 1)
        NyxDeviceEraseOpk(d, d.opks.back().id);
    BOOST_CHECK(!NyxDeviceTopUpOpks(d, T0 + 50));         // 8 already minted today
    BOOST_CHECK(NyxDeviceTopUpOpks(d, T0 + 60 * 60 * 25));
    BOOST_CHECK_EQUAL(d.opks.size(), (size_t)NYX_OPK_TARGET);

    // SPK rotation: the previous SPK and ML-KEM key serve in-flight handshakes for the grace period.
    Pair q(NYX_MODE_PQ, false);
    const NyxBytes hOld = q.FromA("before rotation");
    BOOST_REQUIRE(NyxDeviceRotateSpk(q.b.dev, T0 + 15, true));
    BOOST_CHECK_EQUAL(q.ToB(hOld, pt, T0 + 15 + NYX_SPK_GRACE + 1), 100);
    BOOST_REQUIRE_EQUAL(q.ToB(hOld, pt, T0 + 30), NYX_DR_OK);
    BOOST_CHECK_EQUAL(S(pt), "before rotation");
    // A new bundle carries the new SPK and ek.
    const NyxBundle nb = q.b.Bundle();
    BOOST_CHECK_EQUAL(nb.spkId, q.b.dev.spkId);
    BOOST_CHECK(nb.ek == q.b.dev.ek);
    BOOST_REQUIRE(NyxHsInitiate(q.a.Local(), PeerOf(q.pinB), nb, T0 + 40, r, err));
}

BOOST_AUTO_TEST_CASE(persistence_across_restart)
{
    Pair p;
    NyxBytes pt;
    BOOST_REQUIRE_EQUAL(p.ToB(p.FromA("one"), pt), NYX_DR_OK);
    BOOST_REQUIRE_EQUAL(p.ToA(p.FromB("two"), pt), NYX_DR_OK);
    const NyxBytes pending = p.FromA("in flight");
    const NyxBytes skippedMaker = p.FromA("ahead");
    BOOST_REQUIRE_EQUAL(p.ToB(skippedMaker, pt), NYX_DR_OK);

    // Restart: sessions and devices come back from their serialized records only.
    NyxSession sa2, sb2;
    BOOST_REQUIRE(sa2.Deserialize(p.sa.Serialize()));
    BOOST_REQUIRE(sb2.Deserialize(p.sb.Serialize()));
    BOOST_CHECK(sb2.Serialize() == p.sb.Serialize());
    BOOST_CHECK_EQUAL(sb2.states[0].skipped.size(), 1U);
    p.sa = sa2;
    p.sb = sb2;
    std::string devRec = p.b.dev.Serialize();
    NyxOwnDevice d2;
    BOOST_REQUIRE(d2.Deserialize(devRec));
    BOOST_CHECK_EQUAL(d2.opks.size(), p.b.dev.opks.size());
    BOOST_CHECK(d2.Serialize() == devRec);
    BOOST_CHECK_EQUAL(d2.spkId, p.b.dev.spkId);

    BOOST_REQUIRE_EQUAL(p.ToB(pending, pt), NYX_DR_OK);
    BOOST_CHECK_EQUAL(S(pt), "in flight");
    BOOST_REQUIRE_EQUAL(p.ToA(p.FromB("after restart"), pt), NYX_DR_OK);
    BOOST_CHECK_EQUAL(S(pt), "after restart");

    // Corrupt records are refused.
    std::string bad = p.sa.Serialize();
    BOOST_CHECK(!NyxSession().Deserialize(bad.substr(0, bad.size() - 1)));
    bad[1] = 9;
    BOOST_CHECK(!NyxSession().Deserialize(bad));
}

BOOST_AUTO_TEST_CASE(initiators_spread_over_one_time_prekeys)
{
    Pair p;
    const NyxBundle b = p.b.Bundle();
    BOOST_REQUIRE_EQUAL(b.opks.size(), (size_t)NYX_OPK_TARGET);
    std::set<uint32_t> ids;
    for (int i = 0; i < 24; ++i)
    {
        NyxRatchet r;
        std::string err;
        BOOST_REQUIRE(NyxHsInitiate(p.a.Local(), PeerOf(p.pinB), b, T0 + 10, r, err));
        NyxHandshake hs;
        NyxBytes body;
        BOOST_REQUIRE(NyxSessionSeal(r, Pt("x"), T0 + 10, body));
        BOOST_REQUIRE_EQUAL(NyxParseHandshake(&body[0], body.size(), hs), 0);
        ids.insert(hs.opkId);
    }
    BOOST_CHECK_GT(ids.size(), 1U);
}

BOOST_AUTO_TEST_CASE(session_bound_to_certs_and_epochs)
{
    Pair p;
    NyxBytes pt;
    BOOST_REQUIRE_EQUAL(p.ToB(p.FromA("x"), pt), NYX_DR_OK);
    const NyxPeerSide pb = PeerOf(p.pinB), pa = PeerOf(p.pinA);
    const NyxLocalSide la = p.a.Local(), lb = p.b.Local();
    BOOST_CHECK(memcmp(p.sa.states[0].remoteCert, pb.certHash, 32) == 0);
    BOOST_CHECK(memcmp(p.sa.states[0].localCert, la.certHash, 32) == 0);
    BOOST_CHECK(memcmp(p.sb.states[0].remoteCert, pa.certHash, 32) == 0);
    BOOST_CHECK(memcmp(p.sb.states[0].localCert, lb.certHash, 32) == 0);
    BOOST_CHECK_EQUAL(p.sb.states[0].remoteEpoch, pa.epoch);
    NyxSession s2;
    BOOST_REQUIRE(s2.Deserialize(p.sb.Serialize()));
    BOOST_CHECK(memcmp(s2.states[0].remoteCert, pa.certHash, 32) == 0);

    BOOST_REQUIRE_EQUAL(p.ToA(p.FromB("ack"), pt), NYX_DR_OK);
    const int64_t t = T0 + 40;
    BOOST_CHECK(!p.sa.NeedsHandshake(la.certHash, la.epoch, pb.certHash, pb.epoch, t));
    uint8_t other[32];
    memset(other, 0xAB, 32);
    BOOST_CHECK(p.sa.NeedsHandshake(other, la.epoch, pb.certHash, pb.epoch, t));
    BOOST_CHECK(p.sa.NeedsHandshake(la.certHash, la.epoch, other, pb.epoch, t));
    BOOST_CHECK(p.sa.NeedsHandshake(la.certHash, la.epoch + 1, pb.certHash, pb.epoch, t));
    BOOST_CHECK(p.sa.NeedsHandshake(la.certHash, la.epoch, pb.certHash, pb.epoch + 1, t));
    BOOST_CHECK(NyxSession().NeedsHandshake(la.certHash, la.epoch, pb.certHash, pb.epoch, t));
}

BOOST_AUTO_TEST_CASE(unanswered_sessions_restart_the_handshake)
{
    Pair p;
    const NyxLocalSide la = p.a.Local();
    const NyxPeerSide pb = PeerOf(p.pinB);
    // Unacked: a new handshake after NYX_HS_RETRY, not after the full window.
    BOOST_CHECK(!p.sa.NeedsHandshake(la.certHash, la.epoch, pb.certHash, pb.epoch, T0 + 10 + NYX_HS_RETRY));
    BOOST_CHECK(p.sa.NeedsHandshake(la.certHash, la.epoch, pb.certHash, pb.epoch, T0 + 11 + NYX_HS_RETRY));

    // Acked, but the peer lost its state: after NYX_RESYNC_SENDS sends with no reply a new handshake starts.
    NyxBytes pt;
    BOOST_REQUIRE_EQUAL(p.ToB(p.FromA("x"), pt), NYX_DR_OK);
    BOOST_REQUIRE_EQUAL(p.ToA(p.FromB("y"), pt), NYX_DR_OK);
    for (uint32_t i = 0; i + 1 < NYX_RESYNC_SENDS; ++i)
        p.FromA("z");
    BOOST_CHECK(!p.sa.NeedsHandshake(la.certHash, la.epoch, pb.certHash, pb.epoch, T0 + 50));
    BOOST_REQUIRE_EQUAL(p.ToB(p.FromA("z"), pt), NYX_DR_OK);
    BOOST_CHECK(p.sa.NeedsHandshake(la.certHash, la.epoch, pb.certHash, pb.epoch, T0 + 50));
    // A reply to the new chain resets the count.
    BOOST_REQUIRE_EQUAL(p.ToA(p.FromB("back"), pt), NYX_DR_OK);
    BOOST_CHECK(!p.sa.NeedsHandshake(la.certHash, la.epoch, pb.certHash, pb.epoch, T0 + 50));
}

BOOST_AUTO_TEST_CASE(seen_set_covers_the_acceptance_window)
{
    std::map<std::string, int64_t> seen;
    const int64_t now = T0;
    seen[std::string(32, 'a')] = now + NYX_HS_FUTURE;   // stamped ahead
    seen[std::string(32, 'b')] = now;
    BOOST_CHECK(NyxSeenPrune(seen, now + NYX_HS_WINDOW + 1));
    BOOST_CHECK_EQUAL(seen.size(), 1U);
    BOOST_CHECK(seen.count(std::string(32, 'a')));
    BOOST_CHECK(NyxSeenPrune(seen, now + NYX_HS_FUTURE + NYX_HS_WINDOW + 1));
    BOOST_CHECK(seen.empty());

    // Full of live entries: refused rather than evicting one that could then replay.
    for (size_t i = 0; i < NYX_SEEN_MAX; ++i)
        seen[std::string((const char*)&i, sizeof(i)) + std::string(32 - sizeof(i), 'x')] = now;
    BOOST_CHECK(!NyxSeenPrune(seen, now + 1));
    BOOST_CHECK_EQUAL(seen.size(), NYX_SEEN_MAX);
}

BOOST_AUTO_TEST_CASE(held_queue_caps_per_sender_and_unpinned)
{
    std::vector<NyxHeldTag> q;
    NyxHeldTag frozen = {"frozen", false};
    q.push_back(frozen);
    // Unpinned junk under random senders fills at most NYX_HELD_UNPINNED_MAX slots.
    for (int i = 0; i < 100; ++i)
    {
        NyxHeldTag t = {"junk" + boost::lexical_cast<std::string>(i), true};
        const size_t e = NyxHeldEvict(q, t);
        if (e < q.size())
            q.erase(q.begin() + e);
        q.push_back(t);
    }
    size_t nUnpinned = 0;
    for (size_t i = 0; i < q.size(); ++i)
        nUnpinned += q[i].fUnpinned;
    BOOST_CHECK_EQUAL(nUnpinned, NYX_HELD_UNPINNED_MAX);
    BOOST_CHECK(q.front().sender == "frozen");

    // One pinned sender keeps at most NYX_HELD_PER_SENDER.
    for (int i = 0; i < 100; ++i)
    {
        NyxHeldTag t = {"loud", false};
        const size_t e = NyxHeldEvict(q, t);
        if (e < q.size())
            q.erase(q.begin() + e);
        q.push_back(t);
    }
    size_t nLoud = 0;
    for (size_t i = 0; i < q.size(); ++i)
        nLoud += q[i].sender == "loud";
    BOOST_CHECK_EQUAL(nLoud, NYX_HELD_PER_SENDER);
    BOOST_CHECK(q.front().sender == "frozen");
    BOOST_CHECK_LE(q.size(), NYX_HELD_MAX);
}

BOOST_AUTO_TEST_CASE(previous_spk_wiped_after_grace)
{
    Party b(NYX_MODE_PQ, false);
    BOOST_REQUIRE(NyxDeviceRotateSpk(b.dev, T0 + 15, true));
    BOOST_CHECK(!NyxIsZero(b.dev.prevSpkSk, 32));
    BOOST_CHECK(!NyxDeviceExpirePrevSpk(b.dev, T0 + 15 + NYX_SPK_GRACE - 1));
    BOOST_CHECK(!NyxIsZero(b.dev.prevSpkSk, 32));
    BOOST_CHECK(NyxDeviceExpirePrevSpk(b.dev, T0 + 15 + NYX_SPK_GRACE));
    BOOST_CHECK(NyxIsZero(b.dev.prevSpkSk, 32));
    BOOST_CHECK(NyxIsZero(b.dev.prevKemSeed, 64));
    BOOST_CHECK(!NyxDeviceExpirePrevSpk(b.dev, T0 + 15 + NYX_SPK_GRACE + 1));
}

BOOST_AUTO_TEST_CASE(archived_state_is_receive_only_and_expires)
{
    Pair p;
    NyxBytes pt;
    BOOST_REQUIRE_EQUAL(p.ToB(p.FromA("x"), pt), NYX_DR_OK);
    BOOST_REQUIRE_EQUAL(p.ToA(p.FromB("ack"), pt), NYX_DR_OK);
    NyxSession old = p.sb;

    // A later handshake replaces the established session.
    const int64_t t1 = T0 + 3 * NYX_HS_RETRY;
    NyxBundle b;
    BOOST_REQUIRE(NyxBuildBundle(p.b.dev, p.b.key, t1, b));
    NyxRatchet r;
    std::string err;
    BOOST_REQUIRE_MESSAGE(NyxHsInitiate(p.a.Local(), PeerOf(p.pinB), b, t1, r, err), err);
    p.sa.Push(r);
    BOOST_REQUIRE_EQUAL(p.ToB(p.FromA("new", t1 + 1), pt, t1 + 2), NYX_DR_OK);
    BOOST_REQUIRE_EQUAL(p.ToA(p.FromB("ack2", t1 + 3), pt, t1 + 4), NYX_DR_OK);
    uint8_t cur[32];
    memcpy(cur, p.sa.states[0].hsId, 32);

    // A message on the old chain opens but does not move sends back onto it.
    NyxBytes body;
    BOOST_REQUIRE(NyxSessionSeal(old.states[0], Pt("old"), t1 + 5, body));
    size_t idx = 9;
    NyxRatchetMsg m;
    BOOST_REQUIRE_EQUAL(NyxParseRatchetMsg(&body[0], body.size(), m), 0);
    BOOST_REQUIRE_EQUAL(p.sa.Decrypt(m.tail, t1 + 6, pt, NULL, &idx), NYX_DR_OK);
    BOOST_CHECK_EQUAL(idx, 1U);
    BOOST_CHECK(memcmp(p.sa.states[0].hsId, cur, 32) == 0);

    // The archived state stops opening anything once it is past the TTL.
    BOOST_REQUIRE(NyxSessionSeal(old.states[0], Pt("late"), t1 + 7, body));
    BOOST_CHECK_EQUAL(p.ToA(body, pt, t1 + NYX_SKIPPED_TTL + 10), NYX_DR_NO_HEADER);
    BOOST_CHECK(memcmp(p.sa.states[0].hsId, cur, 32) == 0);
}

BOOST_AUTO_TEST_CASE(established_state_never_promoted_by_resync_tie_break)
{
    Pair p;
    NyxBytes pt;
    BOOST_REQUIRE_EQUAL(p.ToB(p.FromA("x"), pt), NYX_DR_OK);
    BOOST_REQUIRE_EQUAL(p.ToA(p.FromB("ack"), pt), NYX_DR_OK);
    BOOST_REQUIRE(p.sa.states[0].fAcked);
    NyxSession oldB = p.sb;

    // B starts a new session soon after; A answers it, archiving its acked initiator state.
    BOOST_REQUIRE(NyxDeviceTopUpOpks(p.a.dev, T0));
    NyxRatchet rb;
    std::string err;
    BOOST_REQUIRE(NyxHsInitiate(p.b.Local(), PeerOf(p.pinA), p.a.Bundle(), T0 + 40, rb, err));
    NyxBytes hb;
    BOOST_REQUIRE(NyxSessionSeal(rb, Pt("new"), T0 + 41, hb));
    NyxHandshake hs;
    BOOST_REQUIRE_EQUAL(NyxParseHandshake(&hb[0], hb.size(), hs), 0);
    NyxRatchet ra;
    uint32_t opk;
    BOOST_REQUIRE(NyxHsRespond(p.a.Local(), PeerOf(p.pinB), hs, T0 + 42, ra, opk, err));
    BOOST_REQUIRE_EQUAL(NyxRatchetDecrypt(ra, hs.tail, T0 + 42, pt), NYX_DR_OK);
    p.sa.Push(ra);
    uint8_t cur[32];
    memcpy(cur, p.sa.states[0].hsId, 32);

    // A message on the old chain opens on the archive whatever the hsId order, and sends stay on the new one.
    NyxBytes body;
    BOOST_REQUIRE(NyxSessionSeal(oldB.states[0], Pt("old"), T0 + 43, body));
    NyxRatchetMsg m;
    BOOST_REQUIRE_EQUAL(NyxParseRatchetMsg(&body[0], body.size(), m), 0);
    size_t idx = 9;
    BOOST_REQUIRE_EQUAL(p.sa.Decrypt(m.tail, T0 + 44, pt, NULL, &idx), NYX_DR_OK);
    BOOST_CHECK_EQUAL(idx, 1U);
    BOOST_CHECK(memcmp(p.sa.states[0].hsId, cur, 32) == 0);
}

BOOST_AUTO_TEST_CASE(decrypt_requires_matching_devices_certs_and_epochs)
{
    Pair p;
    NyxBytes pt;
    const NyxBytes h = p.FromA("x");
    BOOST_REQUIRE_EQUAL(p.ToB(h, pt), NYX_DR_OK);
    const NyxRatchet& rb = p.sb.states[0];
    NyxSessBind ok;
    memcpy(ok.localDev, rb.localDev, 16);
    memcpy(ok.localCert, rb.localCert, 32);
    ok.localEpoch = rb.localEpoch;
    memcpy(ok.remoteAddr, p.a.addr, 20);
    memcpy(ok.remoteDev, p.a.dev.deviceId, 16);
    memcpy(ok.remoteCert, rb.remoteCert, 32);
    ok.remoteEpoch = rb.remoteEpoch;
    BOOST_CHECK(ok.Matches(rb));

    // The repeated-handshake path: any mismatch leaves the state untouched.
    const NyxBytes h2 = p.FromA("y");
    NyxHandshake hs;
    BOOST_REQUIRE_EQUAL(NyxParseHandshake(&h2[0], h2.size(), hs), 0);
    const std::string before = p.sb.Serialize();
    for (int k = 0; k < 7; ++k)
    {
        NyxSessBind bad = ok;
        switch (k)
        {
        case 0: bad.localDev[0] ^= 1; break;
        case 1: bad.localCert[0] ^= 1; break;
        case 2: bad.localEpoch++; break;
        case 3: bad.remoteAddr[0] ^= 1; break;
        case 4: bad.remoteDev[0] ^= 1; break;
        case 5: bad.remoteCert[0] ^= 1; break;
        case 6: bad.remoteEpoch++; break;
        }
        BOOST_CHECK(!bad.Matches(rb));
        BOOST_CHECK_EQUAL(p.sb.Decrypt(hs.tail, T0 + 30, pt, &bad), NYX_DR_NO_HEADER);
        BOOST_CHECK(p.sb.Serialize() == before);
    }
    size_t idx = 9;
    BOOST_REQUIRE_EQUAL(p.sb.Decrypt(hs.tail, T0 + 30, pt, &ok, &idx), NYX_DR_OK);
    BOOST_CHECK_EQUAL(idx, 0U);
    BOOST_CHECK_EQUAL(S(pt), "y");
}

BOOST_AUTO_TEST_CASE(storage_commits_sync_and_inbox_keys_are_per_direction_and_peer)
{
    BOOST_CHECK(NyxIdSyncWrites());
    const std::string local(20, 'L');
    uint8_t id[16], peerA[20], peerB[20];
    memset(id, 7, 16);
    memset(peerA, 1, 20);
    memset(peerB, 2, 20);
    const std::string out = NyxInboxKey(local, T0, id, true, peerA);
    BOOST_CHECK(out != NyxInboxKey(local, T0, id, false, peerA));
    BOOST_CHECK(out != NyxInboxKey(local, T0, id, true, peerB));
    BOOST_CHECK(out == NyxInboxKey(local, T0, id, true, peerA));
    BOOST_CHECK(NyxInboxKey(local, T0, id, true, peerA) < NyxInboxKey(local, T0 + 1, id, false, peerA));
}

BOOST_AUTO_TEST_CASE(erased_keys_leave_no_copy_past_the_live_elements)
{
    Pair p;
    NyxBytes pt;
    BOOST_REQUIRE_EQUAL(p.ToB(p.FromA("start"), pt), NYX_DR_OK);
    BOOST_REQUIRE_EQUAL(p.ToA(p.FromB("ack"), pt), NYX_DR_OK);
    std::vector<NyxBytes> v;
    for (int i = 0; i < 4; ++i)
        v.push_back(p.FromA("m"));
    BOOST_REQUIRE_EQUAL(p.ToB(v[3], pt), NYX_DR_OK);
    std::vector<NyxSkippedKey>& sk = p.sb.states[0].skipped;
    BOOST_REQUIRE_EQUAL(sk.size(), 3U);
    BOOST_REQUIRE_EQUAL(p.ToB(v[0], pt), NYX_DR_OK);
    BOOST_REQUIRE_EQUAL(sk.size(), 2U);
    static const uint8_t zero[sizeof(NyxSkippedKey)] = {0};
    BOOST_CHECK(memcmp(sk.data() + sk.size(), zero, sizeof(NyxSkippedKey)) == 0);

    std::vector<NyxOpk>& o = p.b.dev.opks;
    BOOST_REQUIRE(o.size() >= 2);
    const size_t n = o.size();
    NyxDeviceEraseOpk(p.b.dev, o[0].id);
    BOOST_REQUIRE_EQUAL(o.size(), n - 1);
    static const uint8_t zo[sizeof(NyxOpk)] = {0};
    BOOST_CHECK(memcmp(o.data() + o.size(), zo, sizeof(NyxOpk)) == 0);
}

BOOST_AUTO_TEST_CASE(envelope_and_parsers)
{
    NyxEnvelope e;
    e.ctype = 0;
    memset(e.logicalId, 3, 16);
    memset(e.convAddr, 4, 20);
    e.text = "text";
    NyxEnvelope f;
    BOOST_REQUIRE(f.Parse(e.Serialize()));
    BOOST_CHECK_EQUAL(e.Serialize().size(), NYX_ENV_LEN + 4);
    BOOST_CHECK_EQUAL(f.text, "text");
    BOOST_CHECK(!f.Parse(NyxBytes(NYX_ENV_LEN - 1, 0)));

    Pair p;
    const NyxBytes h = p.FromA("x");
    NyxHandshake hs;
    for (size_t n = 0; n < NYX_HS_FIXED_PQ + NYX_TAIL_MIN; n += 97)
        BOOST_CHECK_NE(NyxParseHandshake(&h[0], n, hs), 0);
    BOOST_REQUIRE_EQUAL(NyxParseHandshake(&h[0], h.size(), hs), 0);
    NyxBytes rebuilt = hs.Fixed();
    rebuilt.insert(rebuilt.end(), hs.tail.begin(), hs.tail.end());
    BOOST_CHECK(rebuilt == h);
    NyxRatchetMsg m;
    NyxBytes short11(33 + NYX_TAIL_MIN - 1, 0);
    short11[0] = NYX_BODY_RATCHET;
    BOOST_CHECK_NE(NyxParseRatchetMsg(&short11[0], short11.size(), m), 0);
}

BOOST_AUTO_TEST_SUITE_END()
