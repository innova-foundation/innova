// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include "../key.h"
#include "../script.h"
#include "../keystore.h"
#include "../nyxcert.h"
#include "../nyxidentity.h"
#include "../nyxkeyring.h"
#include "../nyxpo.h"
#include "../util.h"

#include <string.h>

namespace {

const int64_t T0 = 1790000000;

struct Owner
{
    CKey key;
    uint8_t addr[20];
    std::vector<NyxOwnDevice> devs;
    NyxPinInput net;            // everything published so far
    NyxKeyring tip;
    NyxBytes tipBody;

    explicit Owner(uint8_t mode = NYX_MODE_PQ)
    {
        key.MakeNewKey(true);
        const CKeyID id = key.GetPubKey().GetID();
        memcpy(addr, id.begin(), 20);
        AddDevice(mode, NULL);
        NyxKeyring kr;
        memcpy(kr.addrHash, addr, 20);
        kr.mode = mode;
        kr.ts = T0;
        kr.live.push_back(Entry(0));
        BOOST_REQUIRE(NyxBuildKeyring(kr, key, NULL));
        Publish(kr);
    }

    NyxBytes& CertOf(size_t i) { return devs[i].certBody; }

    NyxKeyringEntry Entry(size_t i)
    {
        NyxKeyringEntry e;
        memcpy(e.deviceId, devs[i].deviceId, 16);
        NyxHash(devs[i].certBody, e.certHash);
        return e;
    }

    // New device whose cert is signed by the address key and, when signer is set, by that device.
    size_t AddDevice(uint8_t mode, const NyxOwnDevice* signer, int64_t created = T0, uint32_t krSeq = 1)
    {
        uint8_t fp[32] = {7};
        NyxOwnDevice d;
        BOOST_REQUIRE(NyxDeviceCreate(d, addr, mode, fp));
        NyxCert c;
        BOOST_REQUIRE(NyxBuildCert(d, key, created, krSeq, signer, c));
        d.certBody = c.Serialize();
        net.certs.push_back(d.certBody);
        devs.push_back(d);
        return devs.size() - 1;
    }

    void Publish(const NyxKeyring& kr)
    {
        tip = kr;
        tipBody = kr.Serialize();
        net.keyrings.push_back(tipBody);
    }

    // Next keyring from base, signed by devs[signer].
    NyxKeyring Next(const NyxKeyring& base, const NyxBytes& baseBody, size_t signer, int64_t ts)
    {
        NyxKeyring k = base;
        k.seq = base.seq + 1;
        NyxHash(baseBody, k.prevHash);
        k.ts = ts;
        k.revoked.clear();
        return k;
    }

    void Sign(NyxKeyring& k, size_t signer)
    {
        BOOST_REQUIRE(NyxBuildKeyring(k, key, &devs[signer]));
    }
};

bool HasFlag(int flags, int f)
{
    return (flags & f) != 0;
}

NyxRelayHeld Held(const NyxPinInput& in)
{
    NyxRelayHeld h;
    for (size_t i = 0; i < in.keyrings.size(); ++i)
    {
        NyxKeyring k;
        BOOST_REQUIRE_EQUAL(NyxParseKeyring(&in.keyrings[i][0], in.keyrings[i].size(), k), 0);
        uint8_t x[32];
        NyxHash(in.keyrings[i], x);
        h.keyrings.push_back(k);
        h.keyringHashes.push_back(NyxBytes(x, x + 32));
        h.revoked.insert(k.revoked.begin(), k.revoked.end());
    }
    for (size_t i = 0; i < in.certs.size(); ++i)
    {
        NyxCert c;
        BOOST_REQUIRE_EQUAL(NyxParseCert(&in.certs[i][0], in.certs[i].size(), c), 0);
        uint8_t x[32];
        NyxHash(in.certs[i], x);
        h.certs[NyxId(c.deviceId)] = c;
        h.certHashes[NyxId(c.deviceId)] = NyxBytes(x, x + 32);
    }
    return h;
}

NyxPin FreshPin(const Owner& o)
{
    NyxPin p;
    memcpy(p.addrHash, o.addr, 20);
    return p;
}

// Owner with two PQ devices at seq 2, pinned by a contact.
struct TwoDevices
{
    Owner o;
    NyxPin pin;
    TwoDevices() : pin(FreshPin(o))
    {
        BOOST_REQUIRE(HasFlag(NyxPinApply(pin, o.net, T0 + 10), NYX_PIN_PINNED));
        o.AddDevice(NYX_MODE_PQ, &o.devs[0], T0 + 20, 2);
        NyxKeyring k = o.Next(o.tip, o.tipBody, 0, T0 + 20);
        k.live.push_back(o.Entry(1));
        o.Sign(k, 0);
        o.Publish(k);
        BOOST_REQUIRE(HasFlag(NyxPinApply(pin, o.net, T0 + 30), NYX_PIN_UPDATED));
        BOOST_REQUIRE_EQUAL(pin.kr.seq, 2U);
        BOOST_REQUIRE_EQUAL(pin.devices.size(), 2U);
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(nyx_identity_tests)

BOOST_AUTO_TEST_CASE(cert_keyring_bundle_sign_verify_and_sizes)
{
    Owner o;
    NyxCert c;
    BOOST_REQUIRE_EQUAL(NyxParseCert(&o.CertOf(0)[0], o.CertOf(0).size(), c), 0);
    BOOST_CHECK_EQUAL(o.CertOf(0).size(), 2124U);
    BOOST_CHECK(NyxCertAddrValid(c));
    c.created += 1;
    BOOST_CHECK(!NyxCertAddrValid(c));

    BOOST_CHECK(NyxKeyringAddrValid(o.tip));
    NyxBundle b;
    BOOST_REQUIRE(NyxBuildBundle(o.devs[0], o.key, T0, b));
    const NyxBytes bb = b.Serialize();
    BOOST_CHECK_EQUAL(bb.size(), 4583U);   // PQ bundle with no OPKs
    NyxBundle b2;
    BOOST_REQUIRE_EQUAL(NyxParseBundle(&bb[0], bb.size(), b2), 0);
    NyxCert c0;
    NyxParseCert(&o.CertOf(0)[0], o.CertOf(0).size(), c0);
    BOOST_CHECK(NyxBundleValid(b2, c0));
    b2.spk[0] ^= 1;
    BOOST_CHECK(!NyxBundleValid(b2, c0));

    Owner cl(NYX_MODE_CLASSICAL);
    BOOST_CHECK_EQUAL(cl.CertOf(0).size(), 172U);
    NyxBundle cb;
    BOOST_REQUIRE(NyxBuildBundle(cl.devs[0], cl.key, T0, cb));
    NyxCert cc;
    NyxParseCert(&cl.CertOf(0)[0], cl.CertOf(0).size(), cc);
    BOOST_CHECK(NyxBundleValid(cb, cc));
    BOOST_CHECK(!NyxBundleValid(cb, c0));

    // Later PQ cert carries the co-signature: 5433 B.
    TwoDevices t;
    BOOST_CHECK_EQUAL(t.o.CertOf(1).size(), 5433U);
}

BOOST_AUTO_TEST_CASE(expiry_cap_and_expired_cert)
{
    Owner o;
    NyxCert c;
    NyxParseCert(&o.CertOf(0)[0], o.CertOf(0).size(), c);
    c.expiry = c.created + NYX_CERT_LIFE + 1;
    BOOST_REQUIRE(NyxAddrSign(o.key, NYX_TAG_CERT, c.Fields(), c.addrSig));
    const NyxBytes b = c.Serialize();
    NyxCert out;
    BOOST_CHECK(NyxParseCert(&b[0], b.size(), out) != 0);

    // A first pin at a time past the cert's expiry is refused.
    NyxPin p = FreshPin(o);
    const int f = NyxPinApply(p, o.net, T0 + NYX_CERT_LIFE + 10);
    BOOST_CHECK(!p.fPinned);
    BOOST_CHECK(f != 0);
}

BOOST_AUTO_TEST_CASE(first_pin_and_stale)
{
    Owner o;
    NyxPin p = FreshPin(o);
    BOOST_CHECK(HasFlag(NyxPinApply(p, o.net, T0 + NYX_FIRST_PIN_MAX_AGE + 1), NYX_PIN_STALE));
    BOOST_CHECK(!p.fPinned);
    BOOST_CHECK(HasFlag(NyxPinApply(p, o.net, T0 + 60), NYX_PIN_PINNED));
    BOOST_CHECK(p.fPinned && p.fPqSeen && NyxPinCanSend(p));
    BOOST_CHECK_EQUAL(NyxPinUsable(p, T0 + 60).size(), 1U);
    BOOST_CHECK_EQUAL(NyxPinUsable(p, T0 + NYX_CERT_LIFE + 1).size(), 0U);
}

BOOST_AUTO_TEST_CASE(address_key_only_device_refused_after_pq_pin)
{
    TwoDevices t;
    // Third device with an address-only cert (what a stolen wallet key or a quantum adversary can make).
    const size_t i = t.o.AddDevice(NYX_MODE_PQ, NULL, T0 + 40, 3);
    {
        NyxPinInput relay = t.o.net;
        relay.certs.pop_back();
        BOOST_CHECK_EQUAL(NyxRelayVerify(Held(relay), t.o.CertOf(i)), NYX_PO_UNVERIFIED);
    }
    NyxKeyring k = t.o.Next(t.o.tip, t.o.tipBody, 0, T0 + 40);
    k.live.push_back(t.o.Entry(i));
    t.o.Sign(k, 0);
    t.o.Publish(k);
    const int f = NyxPinApply(t.pin, t.o.net, T0 + 50);
    BOOST_CHECK(HasFlag(f, NYX_PIN_FORGERY));
    BOOST_CHECK_EQUAL(t.pin.kr.seq, 2U);

    // The same attacker signing the keyring with the unpinned device.
    Owner& o = t.o;
    NyxKeyring k2 = o.Next(t.pin.kr, t.pin.krBody, i, T0 + 41);
    k2.live.push_back(o.Entry(i));
    o.Sign(k2, i);
    BOOST_CHECK_EQUAL(NyxRelayVerify(Held(o.net), k2.Serialize()), NYX_PO_BAD);
    o.net.keyrings.push_back(k2.Serialize());
    BOOST_CHECK(HasFlag(NyxPinApply(t.pin, o.net, T0 + 51), NYX_PIN_FORGERY));
    BOOST_CHECK_EQUAL(t.pin.kr.seq, 2U);
}

BOOST_AUTO_TEST_CASE(rollback_and_seq_jump)
{
    TwoDevices t;
    NyxPinInput older;
    older.keyrings.push_back(t.o.net.keyrings[0]);
    older.certs = t.o.net.certs;
    BOOST_CHECK(HasFlag(NyxPinApply(t.pin, older, T0 + 60), NYX_PIN_ROLLBACK));
    BOOST_CHECK_EQUAL(t.pin.kr.seq, 2U);

    NyxKeyring k = t.o.Next(t.o.tip, t.o.tipBody, 0, T0 + 60);
    k.seq = t.o.tip.seq + NYX_KR_MAX_SEQ_JUMP + 1;
    t.o.Sign(k, 0);
    BOOST_CHECK_EQUAL(NyxRelayVerify(Held(t.o.net), k.Serialize()), NYX_PO_BAD);
    t.o.Publish(k);
    BOOST_CHECK(HasFlag(NyxPinApply(t.pin, t.o.net, T0 + 70), NYX_PIN_SEQ_JUMP));
    BOOST_CHECK_EQUAL(t.pin.kr.seq, 2U);

    // A jump within 16 that links to the pinned keyring is accepted.
    NyxKeyring k2 = t.o.Next(t.pin.kr, t.pin.krBody, 0, T0 + 61);
    k2.seq = t.pin.kr.seq + 5;
    t.o.Sign(k2, 0);
    t.o.Publish(k2);
    BOOST_CHECK(HasFlag(NyxPinApply(t.pin, t.o.net, T0 + 71), NYX_PIN_UPDATED));
    BOOST_CHECK_EQUAL(t.pin.kr.seq, 7U);
}

BOOST_AUTO_TEST_CASE(same_seq_fork_freezes_until_confirmed)
{
    TwoDevices t;
    const NyxKeyring base = t.pin.kr;
    const NyxBytes baseBody = t.pin.krBody;
    // Device 0 revokes device 1 while device 1 revokes device 0, both at seq 3.
    NyxKeyring a = t.o.Next(base, baseBody, 0, T0 + 100);
    a.live.erase(a.live.begin() + 1);
    a.revoked.push_back(NyxId(t.o.devs[1].deviceId));
    t.o.Sign(a, 0);
    NyxKeyring b = t.o.Next(base, baseBody, 1, T0 + 101);
    b.live.erase(b.live.begin());
    b.revoked.push_back(NyxId(t.o.devs[0].deviceId));
    t.o.Sign(b, 1);
    t.o.net.keyrings.push_back(a.Serialize());
    t.o.net.keyrings.push_back(b.Serialize());

    // Relays store and serve both.
    NyxPinInput relayView = t.o.net;
    relayView.keyrings.pop_back();
    relayView.keyrings.pop_back();
    BOOST_CHECK_EQUAL(NyxRelayVerify(Held(relayView), a.Serialize()), NYX_PO_OK);
    BOOST_CHECK_EQUAL(NyxRelayVerify(Held(relayView), b.Serialize()), NYX_PO_OK);

    const int f = NyxPinApply(t.pin, t.o.net, T0 + 110);
    BOOST_CHECK(HasFlag(f, NYX_PIN_FROZEN));
    BOOST_CHECK(t.pin.fFrozen);
    BOOST_CHECK(!NyxPinCanSend(t.pin));
    // Staying frozen on a re-apply with nothing new.
    BOOST_CHECK(HasFlag(NyxPinApply(t.pin, t.o.net, T0 + 111), NYX_PIN_FROZEN));

    // The owner confirms on device 0 only: seq 4 whose prev names keyring a.
    NyxKeyring c = t.o.Next(a, a.Serialize(), 0, T0 + 120);
    t.o.Sign(c, 0);
    t.o.net.keyrings.push_back(c.Serialize());
    const int g = NyxPinApply(t.pin, t.o.net, T0 + 130);
    BOOST_CHECK(HasFlag(g, NYX_PIN_UNFROZEN));
    BOOST_CHECK(!t.pin.fFrozen);
    BOOST_CHECK_EQUAL(t.pin.kr.seq, 4U);
    BOOST_CHECK_EQUAL(t.pin.devices.size(), 1U);
    BOOST_CHECK(t.pin.devices.count(NyxId(t.o.devs[0].deviceId)));
    BOOST_CHECK(NyxPinCanSend(t.pin));
}

BOOST_AUTO_TEST_CASE(identity_reset_needs_one_click_accept)
{
    TwoDevices t;
    const std::string sn1 = NyxSafetyNumber(t.o.addr, t.pin.kr.epoch, t.pin.devices);
    // Every device lost: epoch 2, seq 1, address-signed only, fresh device.
    const size_t i = t.o.AddDevice(NYX_MODE_PQ, NULL, T0 + 200, 1);
    NyxKeyring r;
    memcpy(r.addrHash, t.o.addr, 20);
    r.epoch = 2;
    r.seq = 1;
    NyxHash(t.pin.krBody, r.prevHash);
    r.ts = T0 + 200;
    r.live.push_back(t.o.Entry(i));
    BOOST_REQUIRE(NyxBuildKeyring(r, t.o.key, NULL));
    {
        // Relays take the reset keyring; its address-only cert waits until the keyring is held.
        NyxPinInput relay = t.o.net;
        relay.certs.pop_back();
        BOOST_CHECK_EQUAL(NyxRelayVerify(Held(relay), r.Serialize()), NYX_PO_OK);
        BOOST_CHECK_EQUAL(NyxRelayVerify(Held(relay), t.o.CertOf(i)), NYX_PO_UNVERIFIED);
        relay.keyrings.push_back(r.Serialize());
        BOOST_CHECK_EQUAL(NyxRelayVerify(Held(relay), t.o.CertOf(i)), NYX_PO_OK);
    }
    t.o.Publish(r);

    const int f = NyxPinApply(t.pin, t.o.net, T0 + 210);
    BOOST_CHECK(HasFlag(f, NYX_PIN_RESET));
    BOOST_CHECK(t.pin.fResetPending);
    BOOST_CHECK(!NyxPinCanSend(t.pin));
    BOOST_CHECK_EQUAL(t.pin.kr.epoch, 1U);

    std::string err;
    BOOST_REQUIRE(NyxPinAcceptReset(t.pin, false, err));
    BOOST_CHECK_EQUAL(t.pin.kr.epoch, 2U);
    BOOST_CHECK_EQUAL(t.pin.devices.size(), 1U);
    BOOST_CHECK(NyxPinCanSend(t.pin));
    BOOST_CHECK(NyxSafetyNumber(t.o.addr, t.pin.kr.epoch, t.pin.devices) != sn1);
    BOOST_CHECK(!NyxPinAcceptReset(t.pin, false, err));
}

BOOST_AUTO_TEST_CASE(downgrade_refused_after_pq)
{
    TwoDevices t;
    NyxKeyring k = t.o.Next(t.pin.kr, t.pin.krBody, 0, T0 + 300);
    k.mode = NYX_MODE_CLASSICAL;
    t.o.Sign(k, 0);
    t.o.Publish(k);
    BOOST_CHECK(HasFlag(NyxPinApply(t.pin, t.o.net, T0 + 310), NYX_PIN_DOWNGRADE));
    BOOST_CHECK_EQUAL(t.pin.kr.seq, 2U);
    NyxPinInput relay = t.o.net;
    relay.keyrings.pop_back();
    BOOST_CHECK_EQUAL(NyxRelayVerify(Held(relay), k.Serialize()), NYX_PO_BAD);

    // A classical reset needs the explicit downgrade flag.
    const size_t i = t.o.AddDevice(NYX_MODE_CLASSICAL, NULL, T0 + 320, 1);
    NyxKeyring r;
    memcpy(r.addrHash, t.o.addr, 20);
    r.epoch = 2;
    r.mode = NYX_MODE_CLASSICAL;
    r.ts = T0 + 320;
    r.live.push_back(t.o.Entry(i));
    BOOST_REQUIRE(NyxBuildKeyring(r, t.o.key, NULL));
    t.o.Publish(r);
    BOOST_CHECK(HasFlag(NyxPinApply(t.pin, t.o.net, T0 + 330), NYX_PIN_RESET));
    std::string err;
    BOOST_CHECK(!NyxPinAcceptReset(t.pin, false, err));
    BOOST_CHECK(NyxPinAcceptReset(t.pin, true, err));
    BOOST_CHECK_EQUAL(t.pin.kr.mode, NYX_MODE_CLASSICAL);
}

BOOST_AUTO_TEST_CASE(revoked_device_cannot_return)
{
    TwoDevices t;
    NyxKeyring k = t.o.Next(t.pin.kr, t.pin.krBody, 0, T0 + 400);
    k.live.pop_back();
    k.revoked.push_back(NyxId(t.o.devs[1].deviceId));
    t.o.Sign(k, 0);
    t.o.Publish(k);
    BOOST_REQUIRE(HasFlag(NyxPinApply(t.pin, t.o.net, T0 + 410), NYX_PIN_UPDATED));
    BOOST_CHECK_EQUAL(t.pin.devices.size(), 1U);
    BOOST_CHECK(t.pin.revoked.count(NyxId(t.o.devs[1].deviceId)));

    // Old cert of the revoked device replayed in a later keyring.
    NyxKeyring back = t.o.Next(k, k.Serialize(), 0, T0 + 420);
    back.live.push_back(t.o.Entry(1));
    t.o.Sign(back, 0);
    t.o.Publish(back);
    BOOST_CHECK(HasFlag(NyxPinApply(t.pin, t.o.net, T0 + 430), NYX_PIN_REVOKED));
    BOOST_CHECK_EQUAL(t.pin.kr.seq, 3U);

    // Relays refuse the revoked device's cert and bundle.
    NyxPinInput relay = t.o.net;
    relay.keyrings.pop_back();
    const NyxRelayHeld h = Held(relay);
    BOOST_CHECK_EQUAL(NyxRelayVerify(h, t.o.CertOf(1)), NYX_PO_BAD);
    NyxBundle b;
    BOOST_REQUIRE(NyxBuildBundle(t.o.devs[1], t.o.key, T0 + 430, b));
    BOOST_CHECK_EQUAL(NyxRelayVerify(h, b.Serialize()), NYX_PO_BAD);
    BOOST_CHECK_EQUAL(NyxRelayVerify(h, back.Serialize()), NYX_PO_BAD);
}

BOOST_AUTO_TEST_CASE(relay_continuity)
{
    Owner o;
    NyxRelayHeld empty;
    BOOST_CHECK_EQUAL(NyxRelayVerify(empty, o.tipBody), NYX_PO_OK);
    NyxPinInput held;
    held.keyrings.push_back(o.tipBody);
    BOOST_CHECK_EQUAL(NyxRelayVerify(Held(held), o.CertOf(0)), NYX_PO_OK);
    held.certs.push_back(o.CertOf(0));
    NyxBundle b;
    BOOST_REQUIRE(NyxBuildBundle(o.devs[0], o.key, T0, b));
    BOOST_CHECK_EQUAL(NyxRelayVerify(Held(held), b.Serialize()), NYX_PO_OK);
    b.sig[9] ^= 1;
    BOOST_CHECK_EQUAL(NyxRelayVerify(Held(held), b.Serialize()), NYX_PO_BAD);
    // A bundle before its cert waits unverified.
    NyxPinInput noCert;
    noCert.keyrings = held.keyrings;
    BOOST_REQUIRE(NyxBuildBundle(o.devs[0], o.key, T0, b));
    BOOST_CHECK_EQUAL(NyxRelayVerify(Held(noCert), b.Serialize()), NYX_PO_UNVERIFIED);

    // A co-signed cert and the keyring that adds it.
    const size_t i = o.AddDevice(NYX_MODE_PQ, &o.devs[0], T0 + 5, 2);
    BOOST_CHECK_EQUAL(NyxRelayVerify(Held(held), o.CertOf(i)), NYX_PO_OK);
    held.certs.push_back(o.CertOf(i));
    NyxKeyring k = o.Next(o.tip, o.tipBody, 0, T0 + 5);
    k.live.push_back(o.Entry(i));
    o.Sign(k, 0);
    BOOST_CHECK_EQUAL(NyxRelayVerify(Held(held), k.Serialize()), NYX_PO_OK);

    // Wrong prev hash with a seq inside the window: held back, not relayed.
    NyxKeyring orphan = k;
    orphan.prevHash[0] ^= 1;
    o.Sign(orphan, 0);
    BOOST_CHECK_EQUAL(NyxRelayVerify(Held(held), orphan.Serialize()), NYX_PO_UNVERIFIED);
    // Signed by a device not live in the predecessor.
    NyxKeyring bad = k;
    o.Sign(bad, i);
    BOOST_CHECK_EQUAL(NyxRelayVerify(Held(held), bad.Serialize()), NYX_PO_BAD);
    // Tampered ML-DSA signature.
    NyxBytes tb = k.Serialize();
    tb[tb.size() - 5] ^= 1;
    BOOST_CHECK_EQUAL(NyxRelayVerify(Held(held), tb), NYX_PO_BAD);
    // Address signature from another key.
    Owner other;
    NyxKeyring forged = k;
    BOOST_REQUIRE(NyxAddrSign(other.key, NYX_TAG_KEYRING, forged.Fields(), forged.addrSig));
    BOOST_CHECK_EQUAL(NyxRelayVerify(Held(held), forged.Serialize()), NYX_PO_BAD);
    // A higher epoch must start at seq 1.
    NyxKeyring jump = o.tip;
    jump.epoch = 2;
    jump.seq = 2;
    o.Sign(jump, 0);
    BOOST_CHECK_EQUAL(NyxRelayVerify(Held(held), jump.Serialize()), NYX_PO_BAD);
}

BOOST_AUTO_TEST_CASE(cert_renewal_keeps_pin)
{
    TwoDevices t;
    NyxCert rc;
    BOOST_REQUIRE(NyxBuildCert(t.o.devs[1], t.o.key, T0 + 500, 3, &t.o.devs[1], rc));
    t.o.devs[1].certBody = rc.Serialize();
    t.o.net.certs.push_back(t.o.devs[1].certBody);
    NyxKeyring k = t.o.Next(t.pin.kr, t.pin.krBody, 1, T0 + 500);
    k.live[1] = t.o.Entry(1);
    t.o.Sign(k, 1);
    t.o.Publish(k);
    BOOST_CHECK(HasFlag(NyxPinApply(t.pin, t.o.net, T0 + 510), NYX_PIN_UPDATED));
    BOOST_CHECK_EQUAL(t.pin.kr.seq, 3U);
    BOOST_CHECK_EQUAL(t.pin.devices[NyxId(t.o.devs[1].deviceId)].cert.created, (uint64_t)(T0 + 500));
}

BOOST_AUTO_TEST_CASE(pin_and_device_serialize)
{
    TwoDevices t;
    NyxPin p2;
    BOOST_REQUIRE(p2.Deserialize(t.pin.Serialize()));
    BOOST_CHECK(p2.fPinned && p2.fPqSeen);
    BOOST_CHECK_EQUAL(p2.kr.seq, 2U);
    BOOST_CHECK_EQUAL(p2.devices.size(), 2U);
    BOOST_CHECK(p2.krBody == t.pin.krBody);
    BOOST_CHECK(!p2.Deserialize(t.pin.Serialize().substr(0, 50)));

    NyxOwnDevice d2;
    BOOST_REQUIRE(d2.Deserialize(t.o.devs[0].Serialize()));
    BOOST_CHECK(d2.dsaPk == t.o.devs[0].dsaPk);
    BOOST_CHECK(d2.ek == t.o.devs[0].ek);
    BOOST_CHECK(memcmp(d2.ik, t.o.devs[0].ik, 32) == 0);
    BOOST_CHECK(memcmp(d2.deviceId, t.o.devs[0].deviceId, 16) == 0);
}

BOOST_AUTO_TEST_CASE(device_keys_are_random)
{
    Owner o;
    uint8_t fp[32] = {7};
    NyxOwnDevice a, b;
    BOOST_REQUIRE(NyxDeviceCreate(a, o.addr, NYX_MODE_PQ, fp));
    BOOST_REQUIRE(NyxDeviceCreate(b, o.addr, NYX_MODE_PQ, fp));
    BOOST_CHECK(memcmp(a.deviceId, b.deviceId, 16) != 0);
    BOOST_CHECK(memcmp(a.dsaSeed, b.dsaSeed, 32) != 0);
    BOOST_CHECK(memcmp(a.kemSeed, b.kemSeed, 64) != 0);
    BOOST_CHECK(memcmp(a.ikSk, b.ikSk, 32) != 0);
}

BOOST_AUTO_TEST_CASE(clone_detection)
{
    Owner o;
    NyxOwnDevice& d = o.devs[0];
    uint8_t fp[32];
    memcpy(fp, d.hostFp, 32);
    BOOST_CHECK(NyxCloneCheck(d, fp, NULL).empty());
    uint8_t other[32];
    memcpy(other, fp, 32);
    other[0] ^= 1;
    BOOST_CHECK(!NyxCloneCheck(d, other, NULL).empty());

    NyxBundle b;
    BOOST_REQUIRE(NyxBuildBundle(d, o.key, T0, b));
    const NyxBytes mine = d.lastBundle;
    BOOST_CHECK(NyxCloneCheck(d, fp, &mine).empty());

    // A copy of the datadir publishes its own next bundle.
    NyxOwnDevice clone = d;
    NyxBundle cb;
    BOOST_REQUIRE(NyxBuildBundle(clone, o.key, T0 + 1, cb));
    const NyxBytes theirs = clone.lastBundle;
    BOOST_CHECK(!NyxCloneCheck(d, fp, &theirs).empty());

    // Same seq, different bytes.
    NyxOwnDevice clone2 = o.devs[0];
    clone2.bundleSeq = d.bundleSeq - 1;
    NyxBundle cb2;
    BOOST_REQUIRE(NyxBuildBundle(clone2, o.key, T0 + 2, cb2));
    BOOST_CHECK(!NyxCloneCheck(d, fp, &clone2.lastBundle).empty());
}

BOOST_AUTO_TEST_CASE(storage_seal_open)
{
    uint8_t sk[32];
    memset(sk, 0x42, sizeof(sk));
    std::string a, b, out;
    BOOST_REQUIRE(NyxStoreSeal(sk, "nydkey", "secret record", a));
    BOOST_REQUIRE(NyxStoreSeal(sk, "nydkey", "secret record", b));
    BOOST_CHECK(a != b);
    BOOST_CHECK(a.substr(0, 12) != b.substr(0, 12));
    BOOST_REQUIRE(NyxStoreOpen(sk, "nydkey", a, out));
    BOOST_CHECK_EQUAL(out, "secret record");
    BOOST_CHECK(!NyxStoreOpen(sk, "nypkey", a, out));
    std::string t = a;
    t[20] ^= 1;
    BOOST_CHECK(!NyxStoreOpen(sk, "nydkey", t, out));
    sk[0] ^= 1;
    BOOST_CHECK(!NyxStoreOpen(sk, "nydkey", a, out));
    BOOST_CHECK(!NyxStoreOpen(sk, "nydkey", "short", out));
    sk[0] ^= 1;
    BOOST_REQUIRE(NyxStoreSeal(sk, "k", "", a));
    BOOST_CHECK(NyxStoreOpen(sk, "k", a, out) && out.empty());
}

namespace {
struct TestKeyStore : public CCryptoKeyStore
{
    bool Encrypt(CKeyingMaterial& m) { return EncryptKeys(m); }
    bool Open(const CKeyingMaterial& m) { return Unlock(m); }
};
}

BOOST_AUTO_TEST_CASE(storage_key_wrap_under_wallet_master_key)
{
    uint8_t sk[32], sk2[32];
    std::string rec, newRec, err;

    // Unencrypted wallet: stored raw, same posture as the wallet.
    TestKeyStore plain;
    BOOST_REQUIRE(NyxStorageKeyResolve(&plain, "", sk, newRec, err));
    BOOST_REQUIRE_EQUAL(newRec.size(), 33U);
    BOOST_CHECK_EQUAL(newRec[0], 0);
    rec = newRec;
    BOOST_REQUIRE(NyxStorageKeyResolve(&plain, rec, sk2, newRec, err));
    BOOST_CHECK(newRec.empty());
    BOOST_CHECK(memcmp(sk, sk2, 32) == 0);

    // Encrypted wallet: wrapped under the master key; the raw record is rewrapped.
    TestKeyStore ks;
    CKey k;
    k.MakeNewKey(true);
    BOOST_REQUIRE(ks.AddKeyPubKey(k, k.GetPubKey()));
    CKeyingMaterial master(32, 0x5a);
    BOOST_REQUIRE(ks.Encrypt(master));
    BOOST_REQUIRE(ks.Open(master));
    BOOST_REQUIRE(NyxStorageKeyResolve(&ks, rec, sk2, newRec, err));
    BOOST_CHECK(memcmp(sk, sk2, 32) == 0);
    BOOST_REQUIRE(!newRec.empty());
    BOOST_CHECK_EQUAL(newRec[0], 1);
    BOOST_CHECK(newRec.find(std::string((const char*)sk, 32)) == std::string::npos);
    rec = newRec;
    memset(sk2, 0, 32);
    BOOST_REQUIRE(NyxStorageKeyResolve(&ks, rec, sk2, newRec, err));
    BOOST_CHECK(newRec.empty());
    BOOST_CHECK(memcmp(sk, sk2, 32) == 0);

    // Locked: nothing comes out.
    BOOST_REQUIRE(ks.LockKeyStore());
    BOOST_CHECK(!NyxStorageKeyResolve(&ks, rec, sk2, newRec, err));
    BOOST_CHECK(!err.empty());

    // A different master key cannot unwrap it.
    TestKeyStore ks2;
    CKey k2;
    k2.MakeNewKey(true);
    BOOST_REQUIRE(ks2.AddKeyPubKey(k2, k2.GetPubKey()));
    CKeyingMaterial master2(32, 0x33);
    BOOST_REQUIRE(ks2.Encrypt(master2));
    BOOST_REQUIRE(ks2.Open(master2));
    memset(sk2, 0, 32);
    const bool fOpened = NyxStorageKeyResolve(&ks2, rec, sk2, newRec, err);
    BOOST_CHECK(!fOpened || memcmp(sk, sk2, 32) != 0);
}

BOOST_AUTO_TEST_CASE(keyring_parser_rejects_malformed)
{
    Owner o;
    NyxKeyring k;
    NyxBytes b = o.tipBody;
    BOOST_CHECK_EQUAL(NyxParseKeyring(&b[0], b.size(), k), 0);
    // Duplicate live device.
    NyxKeyring d = o.tip;
    d.live.push_back(d.live[0]);
    NyxBytes db = d.Serialize();
    BOOST_CHECK(NyxParseKeyring(&db[0], db.size(), k) != 0);
    // A device both live and revoked.
    NyxKeyring r = o.tip;
    r.revoked.push_back(NyxId(r.live[0].deviceId));
    NyxBytes rb = r.Serialize();
    BOOST_CHECK(NyxParseKeyring(&rb[0], rb.size(), k) != 0);
    // Epoch 1, seq 1 with a non-zero prev hash.
    NyxKeyring p = o.tip;
    p.prevHash[3] = 1;
    NyxBytes pb = p.Serialize();
    BOOST_CHECK(NyxParseKeyring(&pb[0], pb.size(), k) != 0);
    for (size_t n = 0; n < b.size(); n += 7)
        BOOST_CHECK(NyxParseKeyring(&b[0], n, k) != 0);
}

BOOST_AUTO_TEST_SUITE_END()
