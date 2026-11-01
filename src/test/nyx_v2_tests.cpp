// Nyx v2 wire layer: frames, multipart reassembly, v2 validation, per-peer-class bucket views
// and the public object channel.

#include <boost/test/unit_test.hpp>

#include "../init.h"
#include "../key.h"
#include "../main.h"
#include "../net.h"
#include "../nyxparts.h"
#include "../nyxkeyring.h"
#include "../nyxpo.h"
#include "../smessage.h"
#include "../util.h"
#include "../version.h"

#include <openssl/sha.h>

#include <cstring>
#include <string>
#include <vector>

namespace
{

struct V2Guard
{
    bool fWasV2, fWasEnabled;
    explicit V2Guard(bool fV2) : fWasV2(fNyxV2), fWasEnabled(fSecMsgEnabled)
    {
        fNyxV2 = fV2;
        fSecMsgEnabled = true;
    }
    ~V2Guard()
    {
        fNyxV2 = fWasV2;
        fSecMsgEnabled = fWasEnabled;
        NyxPoSetVerifyHook(NULL);
    }
};

std::vector<uint8_t> Body(size_t n, uint8_t seed = 1)
{
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i)
        v[i] = (uint8_t)(seed + i * 7 + (i >> 8));
    if (n)
        v[0] = 0x01;
    return v;
}

void MsgId(uint8_t id[16], uint8_t seed)
{
    for (int i = 0; i < 16; ++i)
        id[i] = (uint8_t)(seed * 31 + i);
}

std::vector<std::vector<uint8_t> > Split(const std::vector<uint8_t>& body, uint8_t seed = 1)
{
    uint8_t id[16];
    MsgId(id, seed);
    std::vector<std::vector<uint8_t> > frames;
    BOOST_REQUIRE(NyxSplit(body, frames, id));
    return frames;
}

NyxFrame Parse(const std::vector<uint8_t>& f)
{
    NyxFrame out;
    BOOST_REQUIRE_EQUAL(NyxParseFrame(&f[0], f.size(), out), (int)NYX_FRAME_OK);
    return out;
}

void PutLE32(uint8_t* p, uint32_t v)
{
    for (int i = 0; i < 4; ++i)
        p[i] = (uint8_t)(v >> (8 * i));
}

// Test peer with a send buffer and no socket.
struct Peer
{
    CNode node;
    Peer(int nPort, int nVersion, bool fV2) : node(INVALID_SOCKET, CAddress(CService("198.51.100.7", nPort)), "", false)
    {
        node.nVersion = nVersion;
        node.smsgData.fV2 = fV2;
        node.smsgData.fEnabled = true;
        node.smsgData.lastSeen = 1;
        node.smsgData.nWakeCounter = 100;
        node.smsgData.nPeerId = 900000 + nPort;
    }
};

const size_t nCommandOffset = (size_t)CMessageHeader::MESSAGE_SIZE_OFFSET - (size_t)CMessageHeader::COMMAND_SIZE;

// Payloads of every message with this command, in send order.
std::vector<std::vector<unsigned char> > Sent(CNode& node, const std::string& strCommand)
{
    std::vector<std::vector<unsigned char> > out;
    LOCK(node.cs_vSend);
    for (const CSerializeData& data : node.vSendMsg)
    {
        if (data.size() < (size_t)CMessageHeader::HEADER_SIZE)
            continue;
        const char* psz = &data[nCommandOffset];
        if (strncmp(psz, strCommand.c_str(), CMessageHeader::COMMAND_SIZE) != 0)
            continue;
        if (data.size() == (size_t)CMessageHeader::HEADER_SIZE)
        {
            out.push_back(std::vector<unsigned char>());
            continue;
        }
        CDataStream ss(&data[0] + CMessageHeader::HEADER_SIZE, &data[0] + data.size(), SER_NETWORK, PROTOCOL_VERSION);
        std::vector<unsigned char> v;
        ss >> v;
        out.push_back(v);
    }
    return out;
}

void Deliver(CNode& node, const std::string& strCommand, const std::vector<unsigned char>& v)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << v;
    SecureMsgReceiveData(&node, strCommand, ss);
}

// A stored object of the given version with a unique payload; returns its token key bytes.
std::vector<unsigned char> StoreObject(uint8_t v0, uint8_t v1, int64_t nTime, uint8_t seed)
{
    SecureMessage smsg;
    smsg.version[0] = v0;
    smsg.version[1] = v1;
    smsg.SetTimestamp(nTime);
    std::vector<unsigned char> payload(64);
    for (size_t i = 0; i < payload.size(); ++i)
        payload[i] = (unsigned char)(seed * 13 + i);
    smsg.nPayload = payload.size();
    BOOST_REQUIRE_EQUAL(SecureMsgStore(&smsg.hash[0], &payload[0], payload.size(), true), 0);
    std::vector<unsigned char> key(16);
    memcpy(&key[0], &nTime, 8);
    memcpy(&key[8], &payload[0], 8);
    return key;
}

void ClearBucket(int64_t nBucket)
{
    LOCK(cs_smsg);
    smsgBuckets.erase(nBucket);
}

// Searches for a nonce whose proof meets the v1 target, optionally requiring it to miss the public one.
bool FindNonce(SecureMessage& smsg, const unsigned char* p, uint32_t n, bool fPrivateOnly)
{
    for (uint32_t nonse = 0; nonse < 50000000; ++nonse)
    {
        memcpy(smsg.nonse, &nonse, 4);
        unsigned char h[32];
        if (!SecureMsgComputeProofHash(smsg, p, n, h))
            return false;
        if (!(h[31] == 0 && h[30] == 0 && ((~h[29]) & 7)))
            continue;
        const bool fPublic = (h[29] & 3) == 0;
        if (fPrivateOnly == fPublic)
            continue;
        memcpy(smsg.hash, h, 4);
        return true;
    }
    return false;
}

void PublicMac(SecureMessage& smsg, const unsigned char* p, uint32_t n)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, smsg.timestamp, 8);
    SHA256_Update(&ctx, p, n);
    SHA256_Final(smsg.mac, &ctx);
}

std::vector<uint8_t> ClassicalCert(uint8_t addrSeed, uint32_t krSeq = 1)
{
    std::vector<uint8_t> b(172, 0);
    b[0] = NYX_PO_CERT;
    b[1] = 1;
    b[2] = 0;
    for (int i = 0; i < 20; ++i)
        b[3 + i] = (uint8_t)(addrSeed + i);
    for (int i = 0; i < 16; ++i)
        b[23 + i] = (uint8_t)(0x40 + i);
    const uint64_t created = (uint64_t)GetTime() - 60, expiry = created + 86400;
    memcpy(&b[39], &created, 8);
    memcpy(&b[47], &expiry, 8);
    PutLE32(&b[55], krSeq);
    return b;
}

std::vector<uint8_t> Keyring(uint8_t addrSeed, uint32_t seq, uint8_t mode, uint8_t nLive, uint8_t nRev)
{
    std::vector<uint8_t> b(72, 0);
    b[0] = NYX_PO_KEYRING;
    b[1] = 2;
    for (int i = 0; i < 20; ++i)
        b[2 + i] = (uint8_t)(addrSeed + i);
    PutLE32(&b[22], 1);
    PutLE32(&b[26], seq);
    b[70] = mode;
    b[71] = nLive;
    b.resize(b.size() + nLive * 48, 0x11);
    b.push_back(nRev);
    b.resize(b.size() + nRev * 16 + 65, 0x22);
    b.resize(b.size() + 16, seq == 1 ? 0 : 0x33);
    if (mode == 1 && seq > 1)
        b.resize(b.size() + 3309, 0x44);
    return b;
}

std::vector<uint8_t> Bundle(uint8_t addrSeed, bool fPq, uint8_t nOpk)
{
    std::vector<uint8_t> b(86, 0);
    b[0] = NYX_PO_BUNDLE;
    b[1] = fPq ? 1 : 0;
    for (int i = 0; i < 20; ++i)
        b[2 + i] = (uint8_t)(addrSeed + i);
    if (fPq)
        b.resize(b.size() + 4 + 1184, 0x55);
    b.push_back(nOpk);
    b.resize(b.size() + nOpk * 36 + (fPq ? 3309 : 65), 0x66);
    return b;
}

int VerifyOk(const std::vector<uint8_t>&)
{
    return NYX_PO_OK;
}

int VerifyHeld(const std::vector<uint8_t>&)
{
    return NYX_PO_UNVERIFIED;
}

int nVerifyCalls = 0;
int VerifyCounting(const std::vector<uint8_t>&)
{
    nVerifyCalls++;
    return NYX_PO_UNVERIFIED;
}

bool PoListed(const std::vector<uint8_t>& body, bool& fRelayed)
{
    std::vector<NyxPoListEntry> v;
    SecureMsgPoList(v);
    NyxPoInfo info;
    BOOST_REQUIRE_EQUAL(NyxPoParse(&body[0], body.size(), info), 0);
    const std::string addr = HexStr(info.addrHash, info.addrHash + 20);
    for (size_t i = 0; i < v.size(); ++i)
        if (v[i].addrHash == addr && v[i].type == info.type)
        {
            fRelayed = v[i].fRelayed;
            return true;
        }
    return false;
}

size_t BucketTokens(int64_t nBucket, bool fV1Only)
{
    LOCK(cs_smsg);
    std::map<int64_t, SecMsgBucket>::iterator it = smsgBuckets.find(nBucket);
    return it == smsgBuckets.end() ? 0 : it->second.getTokenCount(fV1Only);
}

} // namespace

BOOST_AUTO_TEST_SUITE(nyx_v2_tests)

// ---- frame -------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(frame_round_trip_sizes)
{
    const size_t sizes[] = {1, 4224, 4225, 270336};
    for (size_t s = 0; s < 4; ++s)
    {
        const std::vector<uint8_t> body = Body(sizes[s], (uint8_t)s);
        std::vector<std::vector<uint8_t> > frames = Split(body, (uint8_t)s);
        BOOST_CHECK_EQUAL(frames.size(), (sizes[s] + 4223) / 4224);

        NyxReassembler ra(NYX_POOL_PRIVATE);
        std::vector<uint8_t> out;
        for (size_t i = 0; i < frames.size(); ++i)
        {
            BOOST_CHECK(frames[i].size() <= NYX_FRAME_PREFIX + NYX_PART_BODY_MAX);
            NyxFrame f = Parse(frames[i]);
            BOOST_CHECK_EQUAL(f.partIdx, i);
            BOOST_CHECK_EQUAL(f.totalLen, sizes[s]);
            NyxAddResult r = ra.Add("a", f, 100, out);
            BOOST_CHECK_EQUAL(r, i + 1 == frames.size() ? NYX_RA_COMPLETE : NYX_RA_STORED);
        }
        BOOST_CHECK(out == body);
        BOOST_CHECK_EQUAL(ra.NodeBytes(), 0U);
    }

    uint8_t id[16];
    MsgId(id, 9);
    std::vector<std::vector<uint8_t> > frames;
    BOOST_CHECK(!NyxSplit(Body(270337), frames, id));
    BOOST_CHECK(!NyxSplit(std::vector<uint8_t>(), frames, id));
    BOOST_CHECK(!NyxSplit(Body(4225), frames, id, 1));
}

BOOST_AUTO_TEST_CASE(frame_parse_rejections)
{
    std::vector<std::vector<uint8_t> > frames = Split(Body(10000));
    NyxFrame f;

    std::vector<uint8_t> x = frames[0];
    x[18] = 0;
    BOOST_CHECK_EQUAL(NyxParseFrame(&x[0], x.size(), f), (int)NYX_FRAME_COUNT);
    x[18] = 65;
    BOOST_CHECK_EQUAL(NyxParseFrame(&x[0], x.size(), f), (int)NYX_FRAME_COUNT);

    x = frames[0];
    x[17] = 3;
    BOOST_CHECK_EQUAL(NyxParseFrame(&x[0], x.size(), f), (int)NYX_FRAME_INDEX);

    x = frames[2];
    x.pop_back();
    BOOST_CHECK_EQUAL(NyxParseFrame(&x[0], x.size(), f), (int)NYX_FRAME_LENGTH);
    x = frames[2];
    x.push_back(0);
    BOOST_CHECK_EQUAL(NyxParseFrame(&x[0], x.size(), f), (int)NYX_FRAME_LENGTH);
    x = frames[0];
    x.pop_back();
    BOOST_CHECK_EQUAL(NyxParseFrame(&x[0], x.size(), f), (int)NYX_FRAME_LENGTH);

    // totalLen inconsistent with partCount.
    x = frames[0];
    PutLE32(&x[19], 2 * 4224);
    BOOST_CHECK_EQUAL(NyxParseFrame(&x[0], x.size(), f), (int)NYX_FRAME_TOTAL);
    PutLE32(&x[19], 3 * 4224 + 1);
    BOOST_CHECK_EQUAL(NyxParseFrame(&x[0], x.size(), f), (int)NYX_FRAME_TOTAL);
    PutLE32(&x[19], 270337);
    BOOST_CHECK_EQUAL(NyxParseFrame(&x[0], x.size(), f), (int)NYX_FRAME_TOTAL);

    x = frames[0];
    x[0] = 2;
    BOOST_CHECK_EQUAL(NyxParseFrame(&x[0], x.size(), f), (int)NYX_FRAME_TYPE);
    BOOST_CHECK_EQUAL(NyxParseFrame(&x[0], NYX_FRAME_PREFIX, f), (int)NYX_FRAME_SHORT);
    BOOST_CHECK_EQUAL(NyxParseFrame(NULL, 0, f), (int)NYX_FRAME_SHORT);
}

// ---- reassembly --------------------------------------------------------------

BOOST_AUTO_TEST_CASE(reassembly_out_of_order_and_duplicates)
{
    const std::vector<uint8_t> body = Body(5 * 4224 + 17);
    std::vector<std::vector<uint8_t> > frames = Split(body);
    NyxReassembler ra(NYX_POOL_PRIVATE);
    std::vector<uint8_t> out;

    const int order[] = {4, 1, 5, 0, 3};
    uint64_t nCharge = 0;
    for (int i = 0; i < 5; ++i)
    {
        BOOST_CHECK_EQUAL(ra.Add("a", Parse(frames[order[i]]), 10, out), NYX_RA_STORED);
        nCharge += frames[order[i]].size() - NYX_FRAME_PREFIX;
        BOOST_CHECK_EQUAL(ra.OwnerBytes("a"), nCharge);
        BOOST_CHECK_EQUAL(ra.Add("a", Parse(frames[order[i]]), 11, out), NYX_RA_DUPLICATE);
        BOOST_CHECK_EQUAL(ra.OwnerBytes("a"), nCharge);
        BOOST_CHECK_EQUAL(ra.NodeBytes(), nCharge);
    }
    BOOST_CHECK_EQUAL(ra.Add("a", Parse(frames[2]), 12, out), NYX_RA_COMPLETE);
    BOOST_CHECK(out == body);
    BOOST_CHECK_EQUAL(ra.SetCount(), 0U);
    BOOST_CHECK_EQUAL(ra.NodeBytes(), 0U);

    // The same msgid under a different owner is a separate set.
    BOOST_CHECK_EQUAL(ra.Add("a", Parse(frames[0]), 13, out), NYX_RA_STORED);
    BOOST_CHECK_EQUAL(ra.Add("b", Parse(frames[0]), 13, out), NYX_RA_STORED);
    BOOST_CHECK_EQUAL(ra.SetCount(), 2U);
}

BOOST_AUTO_TEST_CASE(reassembly_disagreement_and_bad_hash)
{
    const std::vector<uint8_t> body = Body(3 * 4224);
    std::vector<std::vector<uint8_t> > frames = Split(body);
    NyxReassembler ra(NYX_POOL_PUBLIC);
    std::vector<uint8_t> out;

    BOOST_CHECK_EQUAL(ra.Add("p1", Parse(frames[0]), 1, out), NYX_RA_STORED);
    std::vector<uint8_t> x = frames[1];
    x[23] ^= 1;     // totalHash differs from the set
    BOOST_CHECK_EQUAL(ra.Add("p1", Parse(x), 1, out), NYX_RA_MISMATCH);
    BOOST_CHECK_EQUAL(ra.SetCount(), 0U);
    BOOST_CHECK_EQUAL(ra.NodeBytes(), 0U);

    // partCount disagreement: a 4-part frame with the same msgid.
    std::vector<std::vector<uint8_t> > four = Split(Body(3 * 4224 + 1));
    BOOST_CHECK_EQUAL(ra.Add("p1", Parse(frames[0]), 2, out), NYX_RA_STORED);
    BOOST_CHECK_EQUAL(ra.Add("p1", Parse(four[3]), 2, out), NYX_RA_MISMATCH);
    BOOST_CHECK_EQUAL(ra.SetCount(), 0U);

    // Every part carries the same wrong totalHash: completes to BADHASH.
    std::vector<std::vector<uint8_t> > bad = frames;
    for (size_t i = 0; i < bad.size(); ++i)
        bad[i][40] ^= 0x80;
    BOOST_CHECK_EQUAL(ra.Add("p1", Parse(bad[0]), 3, out), NYX_RA_STORED);
    BOOST_CHECK_EQUAL(ra.Add("p1", Parse(bad[1]), 3, out), NYX_RA_STORED);
    BOOST_CHECK_EQUAL(ra.Add("p1", Parse(bad[2]), 3, out), NYX_RA_BADHASH);
    BOOST_CHECK(out.empty());
    BOOST_CHECK_EQUAL(ra.SetCount(), 0U);
    BOOST_CHECK_EQUAL(ra.NodeBytes(), 0U);
}

BOOST_AUTO_TEST_CASE(reassembly_caps_evict_oldest)
{
    NyxReassemblyLimits l;
    l.nOwnerBytes = 3 * 4224;
    l.nNodeBytes = 5 * 4224;
    l.nOwnerSets = 2;
    l.nTimeout = 1000;
    NyxReassembler ra(l);
    std::vector<uint8_t> out;

    std::vector<std::vector<uint8_t> > s1 = Split(Body(4 * 4224, 1), 1);
    std::vector<std::vector<uint8_t> > s2 = Split(Body(4 * 4224, 2), 2);
    std::vector<std::vector<uint8_t> > s3 = Split(Body(4 * 4224, 3), 3);

    // Set count: a third set of the same owner evicts that owner's oldest.
    BOOST_CHECK_EQUAL(ra.Add("a", Parse(s1[0]), 1, out), NYX_RA_STORED);
    BOOST_CHECK_EQUAL(ra.Add("a", Parse(s2[0]), 2, out), NYX_RA_STORED);
    BOOST_CHECK_EQUAL(ra.Add("a", Parse(s3[0]), 3, out), NYX_RA_STORED);
    BOOST_CHECK_EQUAL(ra.OwnerSetCount("a"), 2U);
    BOOST_CHECK_EQUAL(ra.OwnerBytes("a"), 2U * 4224);
    std::vector<NyxSetProgress> v;
    ra.List(v);
    for (size_t i = 0; i < v.size(); ++i)
        BOOST_CHECK(v[i].nFirstSeen != 1);

    // Owner bytes: a fourth part pushes "a" over 3 parts; the oldest set (s2) goes.
    BOOST_CHECK_EQUAL(ra.Add("a", Parse(s3[1]), 4, out), NYX_RA_STORED);
    BOOST_CHECK_EQUAL(ra.Add("a", Parse(s3[2]), 5, out), NYX_RA_STORED);
    BOOST_CHECK_EQUAL(ra.OwnerSetCount("a"), 1U);
    BOOST_CHECK_EQUAL(ra.OwnerBytes("a"), 3U * 4224);

    // A single set larger than the owner cap is refused.
    BOOST_CHECK_EQUAL(ra.Add("a", Parse(s3[3]), 6, out), NYX_RA_REFUSED);
    BOOST_CHECK_EQUAL(ra.OwnerBytes("a"), 0U);
    BOOST_CHECK_EQUAL(ra.NodeBytes(), 0U);

    // Node bytes: another owner's oldest set is evicted node-wide.
    BOOST_CHECK_EQUAL(ra.Add("a", Parse(s1[0]), 10, out), NYX_RA_STORED);
    BOOST_CHECK_EQUAL(ra.Add("a", Parse(s1[1]), 10, out), NYX_RA_STORED);
    BOOST_CHECK_EQUAL(ra.Add("b", Parse(s2[0]), 11, out), NYX_RA_STORED);
    BOOST_CHECK_EQUAL(ra.Add("b", Parse(s2[1]), 11, out), NYX_RA_STORED);
    BOOST_CHECK_EQUAL(ra.Add("c", Parse(s3[0]), 12, out), NYX_RA_STORED);
    BOOST_CHECK_EQUAL(ra.NodeBytes(), 5U * 4224);
    BOOST_CHECK_EQUAL(ra.Add("c", Parse(s3[1]), 13, out), NYX_RA_STORED);
    BOOST_CHECK_EQUAL(ra.OwnerBytes("a"), 0U);
    BOOST_CHECK_EQUAL(ra.NodeBytes(), 4U * 4224);
    BOOST_CHECK(ra.NodeBytes() <= l.nNodeBytes);
}

BOOST_AUTO_TEST_CASE(reassembly_expiry_and_owner_free)
{
    std::vector<std::vector<uint8_t> > s = Split(Body(2 * 4224));
    std::vector<uint8_t> out;

    NyxReassembler priv(NYX_POOL_PRIVATE);
    BOOST_CHECK_EQUAL(priv.Add("addr", Parse(s[0]), 1000, out), NYX_RA_STORED);
    priv.Expire(1000 + NYX_PRIV_SET_TIMEOUT - 1);
    BOOST_CHECK_EQUAL(priv.SetCount(), 1U);
    priv.Expire(1000 + 48 * 3600);
    BOOST_CHECK_EQUAL(priv.SetCount(), 0U);

    NyxReassembler pub(NYX_POOL_PUBLIC);
    BOOST_CHECK_EQUAL(pub.Add("p1", Parse(s[0]), 1000, out), NYX_RA_STORED);
    BOOST_CHECK_EQUAL(pub.Add("p2", Parse(s[0]), 1300, out), NYX_RA_STORED);
    pub.Expire(1599);
    BOOST_CHECK_EQUAL(pub.SetCount(), 2U);
    pub.Expire(1600);
    BOOST_CHECK_EQUAL(pub.SetCount(), 1U);
    pub.FreeOwner("p2");
    BOOST_CHECK_EQUAL(pub.SetCount(), 0U);
    BOOST_CHECK_EQUAL(pub.NodeBytes(), 0U);

    BOOST_CHECK_EQUAL(pub.Limits().nOwnerBytes, 1U << 20);
    BOOST_CHECK_EQUAL(pub.Limits().nNodeBytes, 16U << 20);
    BOOST_CHECK_EQUAL(pub.Limits().nOwnerSets, 32U);
    BOOST_CHECK_EQUAL(priv.Limits().nOwnerBytes, 4U << 20);
    BOOST_CHECK_EQUAL(priv.Limits().nNodeBytes, 32U << 20);
    BOOST_CHECK_EQUAL(priv.Limits().nOwnerSets, 64U);
}

BOOST_AUTO_TEST_CASE(reassembly_returns_raw_parts)
{
    std::vector<std::vector<uint8_t> > s = Split(Body(4300));
    NyxReassembler ra(NYX_POOL_PUBLIC);
    std::vector<uint8_t> out;
    std::vector<std::vector<uint8_t> > raws;
    std::vector<uint8_t> r0(10, 0xa0), r1(20, 0xa1);
    BOOST_CHECK_EQUAL(ra.Add("p", Parse(s[1]), 1, out, &r1, &raws), NYX_RA_STORED);
    BOOST_CHECK_EQUAL(ra.OwnerBytes("p"), s[1].size() - NYX_FRAME_PREFIX + 20);
    BOOST_CHECK_EQUAL(ra.Add("p", Parse(s[0]), 1, out, &r0, &raws), NYX_RA_COMPLETE);
    BOOST_REQUIRE_EQUAL(raws.size(), 2U);
    BOOST_CHECK(raws[0] == r0);
    BOOST_CHECK(raws[1] == r1);
}

// ---- validate ----------------------------------------------------------------

BOOST_AUTO_TEST_CASE(validate_v1_unchanged)
{
    // The canonical v1 vector pinned in smessage_hmac_tests.
    std::vector<unsigned char> payload = ParseHex(
        "00017f80ff63726f73732d6f70656e73736c2d7365637572652d6d6573736167"
        "652d766563746f72");
    SecureMessage smsg;
    smsg.version[0] = 1;
    smsg.flags = 0xa5;
    const unsigned char ts[8] = {0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
    memcpy(smsg.timestamp, ts, 8);
    for (size_t i = 0; i < 16; ++i)
        smsg.iv[i] = (unsigned char)i;
    smsg.cpkR[0] = 0x02;
    for (size_t i = 1; i < 33; ++i)
        smsg.cpkR[i] = (unsigned char)i;
    for (size_t i = 0; i < 32; ++i)
        smsg.mac[i] = (unsigned char)(0x80 + i);
    const unsigned char nonse[4] = {0xdd, 0x09, 0x02, 0x00};
    memcpy(smsg.nonse, nonse, 4);
    smsg.nPayload = payload.size();
    const unsigned char hash4[4] = {0x6a, 0x01, 0x99, 0xa8};
    memcpy(smsg.hash, hash4, 4);

    for (int v = 0; v < 2; ++v)
    {
        V2Guard g(v == 1);
        BOOST_CHECK_EQUAL(SecureMsgValidate(smsg.hash, &payload[0], payload.size()), 0);
        // v1 flags are not inspected, oversize keeps the v1 cap.
        std::vector<unsigned char> big(SMSG_MAX_MSG_WORST + 1, 0);
        BOOST_CHECK_EQUAL(SecureMsgValidate(smsg.hash, &big[0], big.size()), 5);
        std::vector<unsigned char> v2size(SMSG_V2_MAX_PAYLOAD, 0);
        BOOST_CHECK_EQUAL(SecureMsgValidate(smsg.hash, &v2size[0], v2size.size()), 5);
        payload[3] ^= 1;
        BOOST_CHECK_EQUAL(SecureMsgValidate(smsg.hash, &payload[0], payload.size()), 3);
        payload[3] ^= 1;
    }
}

BOOST_AUTO_TEST_CASE(validate_v2_rules)
{
    std::vector<unsigned char> payload(NYX_FRAME_PREFIX + 1, 0x5a);
    SecureMessage smsg;
    smsg.version[0] = 2;
    smsg.version[1] = 0;
    smsg.SetTimestamp(1700000000);
    smsg.cpkR[0] = 2;
    smsg.nPayload = payload.size();
    {
        V2Guard g(true);
        BOOST_REQUIRE_EQUAL(SecureMsgSetHash(smsg.hash, &payload[0], payload.size()), 0);
        BOOST_CHECK_EQUAL(SecureMsgValidate(smsg.hash, &payload[0], payload.size()), 0);
    }
    {
        V2Guard g(false);
        BOOST_CHECK_EQUAL(SecureMsgValidate(smsg.hash, &payload[0], payload.size()), 4);
    }

    V2Guard g(true);
    smsg.flags = 1;
    BOOST_CHECK_EQUAL(SecureMsgValidate(smsg.hash, &payload[0], payload.size()), 4);
    smsg.flags = 0;
    smsg.version[1] = 2;
    BOOST_CHECK_EQUAL(SecureMsgValidate(smsg.hash, &payload[0], payload.size()), 4);
    smsg.version[1] = 0;

    std::vector<unsigned char> big(SMSG_V2_MAX_PAYLOAD + 1, 0);
    BOOST_CHECK_EQUAL(SecureMsgValidate(smsg.hash, &big[0], big.size()), 5);
    BOOST_CHECK_EQUAL(SecureMsgValidate(smsg.hash, &payload[0], NYX_FRAME_PREFIX), 1);

    // Public object rules.
    SecureMessage pub;
    pub.version[0] = 2;
    pub.version[1] = 1;
    pub.SetTimestamp(1700000000);
    pub.nPayload = payload.size();
    PublicMac(pub, &payload[0], payload.size());
    BOOST_REQUIRE(FindNonce(pub, &payload[0], payload.size(), true));
    BOOST_CHECK_EQUAL(SecureMsgValidate(pub.hash, &payload[0], payload.size()), 2);
    BOOST_REQUIRE_EQUAL(SecureMsgSetHash(pub.hash, &payload[0], payload.size()), 0);
    BOOST_CHECK_EQUAL(SecureMsgValidate(pub.hash, &payload[0], payload.size()), 0);

    SecureMessage t;
    memcpy(t.hash, pub.hash, SMSG_HDR_LEN);
    t.mac[0] ^= 1;
    BOOST_REQUIRE_EQUAL(SecureMsgSetHash(t.hash, &payload[0], payload.size()), 0);
    BOOST_CHECK_EQUAL(SecureMsgValidate(t.hash, &payload[0], payload.size()), 3);

    memcpy(t.hash, pub.hash, SMSG_HDR_LEN);
    t.iv[3] = 1;
    BOOST_REQUIRE_EQUAL(SecureMsgSetHash(t.hash, &payload[0], payload.size()), 0);
    BOOST_CHECK_EQUAL(SecureMsgValidate(t.hash, &payload[0], payload.size()), 4);

    memcpy(t.hash, pub.hash, SMSG_HDR_LEN);
    t.cpkR[32] = 1;
    BOOST_REQUIRE_EQUAL(SecureMsgSetHash(t.hash, &payload[0], payload.size()), 0);
    BOOST_CHECK_EQUAL(SecureMsgValidate(t.hash, &payload[0], payload.size()), 4);

    // The version byte is covered by the proof: a {2,1} proof does not carry over to {2,0}.
    memcpy(t.hash, pub.hash, SMSG_HDR_LEN);
    t.version[1] = 0;
    BOOST_CHECK_EQUAL(SecureMsgValidate(t.hash, &payload[0], payload.size()), 3);

    BOOST_CHECK_EQUAL(SecureMsgPayloadCap(smsg.hash), SMSG_V2_MAX_PAYLOAD);
    smsg.version[0] = 1;
    BOOST_CHECK_EQUAL(SecureMsgPayloadCap(smsg.hash), SMSG_MAX_MSG_WORST);
}

// ---- buckets -----------------------------------------------------------------

BOOST_AUTO_TEST_CASE(bucket_dual_hash_and_counts)
{
    V2Guard g(true);
    unsigned char a[8] = {1, 1, 1, 1, 1, 1, 1, 1}, b[8] = {2, 2, 2, 2, 2, 2, 2, 2}, c[8] = {3, 3, 3, 3, 3, 3, 3, 3};

    SecMsgBucket mixed, v1only;
    mixed.insertToken(SecMsgToken(100, a, 8, 0, 1, 0));
    mixed.insertToken(SecMsgToken(101, b, 8, 0, 1, 1));
    mixed.insertToken(SecMsgToken(102, c, 8, 0, 1, 0));
    v1only.insertToken(SecMsgToken(100, a, 8, 0, 1, 0));
    v1only.insertToken(SecMsgToken(102, c, 8, 0, 1, 0));
    mixed.hashBucket();
    v1only.hashBucket();

    BOOST_CHECK_EQUAL(mixed.hashV1, v1only.hash);
    BOOST_CHECK(mixed.hash != mixed.hashV1);
    BOOST_CHECK_EQUAL(v1only.hash, v1only.hashV1);
    BOOST_CHECK_EQUAL(mixed.getTokenCount(), 3U);
    BOOST_CHECK_EQUAL(mixed.getTokenCount(true), 2U);

    // A v2-only arrival changes the v2 view only.
    mixed.timeChangedV1 = 5;
    unsigned char d[8] = {4, 4, 4, 4, 4, 4, 4, 4};
    mixed.insertToken(SecMsgToken(103, d, 8, 0, 1, 1));
    mixed.hashBucket();
    BOOST_CHECK_EQUAL(mixed.timeChangedV1, 5);
    BOOST_CHECK_EQUAL(mixed.hashV1, v1only.hash);
    unsigned char e[8] = {5, 5, 5, 5, 5, 5, 5, 5};
    mixed.insertToken(SecMsgToken(104, e, 8, 0, 1, 0));
    mixed.hashBucket();
    BOOST_CHECK(mixed.timeChangedV1 > 5);

    // Compaction keeps both counts.
    BOOST_CHECK(mixed.compact(0));
    BOOST_CHECK_EQUAL(mixed.getTokenCount(), 5U);
    BOOST_CHECK_EQUAL(mixed.getTokenCount(true), 3U);

    std::set<SecMsgToken>::iterator it = v1only.setTokens.begin();
    v1only.eraseToken(it);
    BOOST_CHECK_EQUAL(v1only.getTokenCount(true), 1U);

    // With v2 off every rehash is visible to v1 peers, as before.
    fNyxV2 = false;
    v1only.timeChangedV1 = 5;
    v1only.hashBucket();
    BOOST_CHECK_EQUAL(v1only.timeChangedV1, v1only.timeChanged);
}

BOOST_AUTO_TEST_CASE(peer_class_inv_show_want)
{
    V2Guard g(true);
    const int64_t now = GetTime();
    const int64_t nBucket = now - (now % SMSG_BUCKET_LEN);
    ClearBucket(nBucket);

    std::vector<unsigned char> k1 = StoreObject(1, 1, now, 1);
    std::vector<unsigned char> k2 = StoreObject(2, 0, now, 2);
    std::vector<unsigned char> k3 = StoreObject(1, 1, now, 3);
    BOOST_CHECK_EQUAL(BucketTokens(nBucket, false), 3U);
    BOOST_CHECK_EQUAL(BucketTokens(nBucket, true), 2U);

    Peer v1(31001, V52_PROTO_VERSION, false);
    Peer v2(31002, NYX_V2_PROTO, true);
    Peer helloless(31003, NYX_V2_PROTO, false);
    BOOST_CHECK(!SecureMsgPeerV2(&v1.node));
    BOOST_CHECK(SecureMsgPeerV2(&v2.node));
    BOOST_CHECK(!SecureMsgPeerV2(&helloless.node));

    uint32_t hashAll, hashV1;
    {
        LOCK(cs_smsg);
        hashAll = smsgBuckets[nBucket].hash;
        hashV1 = smsgBuckets[nBucket].hashV1;
    }

    // smsgInv: count and hash per class.
    SecureMsgSendData(&v1.node, false);
    SecureMsgSendData(&v2.node, false);
    std::vector<std::vector<unsigned char> > inv1 = Sent(v1.node, "smsgInv"), inv2 = Sent(v2.node, "smsgInv");
    BOOST_REQUIRE_EQUAL(inv1.size(), 1U);
    BOOST_REQUIRE_EQUAL(inv2.size(), 1U);
    bool fFound1 = false, fFound2 = false;
    for (size_t i = 4; i + 16 <= inv1[0].size(); i += 16)
    {
        int64_t t;
        uint32_t n, h;
        memcpy(&t, &inv1[0][i], 8);
        memcpy(&n, &inv1[0][i + 8], 4);
        memcpy(&h, &inv1[0][i + 12], 4);
        if (t == nBucket)
        {
            fFound1 = true;
            BOOST_CHECK_EQUAL(n, 2U);
            BOOST_CHECK_EQUAL(h, hashV1);
        }
    }
    for (size_t i = 4; i + 16 <= inv2[0].size(); i += 16)
    {
        int64_t t;
        uint32_t n, h;
        memcpy(&t, &inv2[0][i], 8);
        memcpy(&n, &inv2[0][i + 8], 4);
        memcpy(&h, &inv2[0][i + 12], 4);
        if (t == nBucket)
        {
            fFound2 = true;
            BOOST_CHECK_EQUAL(n, 3U);
            BOOST_CHECK_EQUAL(h, hashAll);
        }
    }
    BOOST_CHECK(fFound1 && fFound2);

    // A v1 peer advertising our v1 view of the bucket is matched, not asked for more.
    std::vector<unsigned char> inv(4 + 16);
    uint32_t one = 1, two = 2;
    memcpy(&inv[0], &one, 4);
    memcpy(&inv[4], &nBucket, 8);
    memcpy(&inv[12], &two, 4);
    memcpy(&inv[16], &hashV1, 4);
    Deliver(v1.node, "smsgInv", inv);
    BOOST_CHECK(Sent(v1.node, "smsgShow").empty());
    BOOST_CHECK_EQUAL(Sent(v1.node, "smsgMatch").size(), 1U);

    // smsgShow: v1 peers see v1 tokens only.
    std::vector<unsigned char> show(12);
    memcpy(&show[0], &one, 4);
    memcpy(&show[4], &nBucket, 8);
    Deliver(v1.node, "smsgShow", show);
    Deliver(v2.node, "smsgShow", show);
    std::vector<std::vector<unsigned char> > have1 = Sent(v1.node, "smsgHave"), have2 = Sent(v2.node, "smsgHave");
    BOOST_REQUIRE_EQUAL(have1.size(), 1U);
    BOOST_REQUIRE_EQUAL(have2.size(), 1U);
    BOOST_CHECK_EQUAL(have1[0].size(), 8U + 2 * 16);
    BOOST_CHECK_EQUAL(have2[0].size(), 8U + 3 * 16);
    for (size_t i = 8; i < have1[0].size(); i += 16)
        BOOST_CHECK(memcmp(&have1[0][i], &k2[0], 16) != 0);

    // smsgWant naming the v2 token: ignored for the v1 peer.
    std::vector<unsigned char> want(8);
    memcpy(&want[0], &nBucket, 8);
    want.insert(want.end(), k1.begin(), k1.end());
    want.insert(want.end(), k2.begin(), k2.end());
    want.insert(want.end(), k3.begin(), k3.end());
    Deliver(v1.node, "smsgWant", want);
    Deliver(v2.node, "smsgWant", want);
    std::vector<std::vector<unsigned char> > msg1 = Sent(v1.node, "smsgMsg"), msg2 = Sent(v2.node, "smsgMsg");
    BOOST_REQUIRE_EQUAL(msg1.size(), 1U);
    BOOST_REQUIRE_EQUAL(msg2.size(), 1U);
    uint32_t n1, n2;
    memcpy(&n1, &msg1[0][0], 4);
    memcpy(&n2, &msg2[0][0], 4);
    BOOST_CHECK_EQUAL(n1, 2U);
    BOOST_CHECK_EQUAL(n2, 3U);

    // The hello marks only a v2-capable peer, and only when v2 is on.
    Peer late(31004, NYX_V2_PROTO, false);
    Deliver(late.node, "smsgV2", std::vector<unsigned char>());
    BOOST_CHECK(late.node.smsgData.fV2);
    Peer old(31005, V52_PROTO_VERSION, false);
    Deliver(old.node, "smsgV2", std::vector<unsigned char>());
    BOOST_CHECK(!old.node.smsgData.fV2);

    // With v2 off nothing is offered as v2 and the views coincide.
    fNyxV2 = false;
    BOOST_CHECK(!SecureMsgPeerV2(&v2.node));
    ClearBucket(nBucket);
}

BOOST_AUTO_TEST_CASE(v1_peer_v2_object_dropped_without_penalty)
{
    V2Guard g(true);
    const int64_t now = GetTime();
    const int64_t nBucket = now - (now % SMSG_BUCKET_LEN);
    ClearBucket(nBucket);

    std::vector<unsigned char> payload(NYX_FRAME_PREFIX + 9, 0x31);
    SecureMessage smsg;
    smsg.version[0] = 2;
    smsg.SetTimestamp(now);
    smsg.cpkR[0] = 2;
    smsg.nPayload = payload.size();
    BOOST_REQUIRE_EQUAL(SecureMsgSetHash(smsg.hash, &payload[0], payload.size()), 0);

    std::vector<unsigned char> bunch(12);
    uint32_t one = 1;
    memcpy(&bunch[0], &one, 4);
    memcpy(&bunch[4], &nBucket, 8);
    bunch.insert(bunch.end(), smsg.hash, smsg.hash + SMSG_HDR_LEN);
    bunch.insert(bunch.end(), payload.begin(), payload.end());

    Peer v1(31011, V52_PROTO_VERSION, false);
    {
        LOCK(cs_smsg);
        smsgBuckets[nBucket];
    }
    SecureMsgReceive(&v1.node, bunch);
    BOOST_CHECK_EQUAL(v1.node.nMisbehavior, 0);
    BOOST_CHECK_EQUAL(BucketTokens(nBucket, false), 0U);

    Peer v2(31012, NYX_V2_PROTO, true);
    SecureMsgReceive(&v2.node, bunch);
    BOOST_CHECK_EQUAL(v2.node.nMisbehavior, 0);
    BOOST_CHECK_EQUAL(BucketTokens(nBucket, false), 1U);
    BOOST_CHECK_EQUAL(BucketTokens(nBucket, true), 0U);
    ClearBucket(nBucket);
}

BOOST_AUTO_TEST_CASE(reload_caps_by_version)
{
    const int64_t now = GetTime();
    const int64_t nBucket = now - (now % SMSG_BUCKET_LEN);
    uint32_t nBaseAll = 0, nBaseV1 = 0, nAll = 0, nV1 = 0;
    {
        V2Guard g(true);
        ClearBucket(nBucket);
        {
            LOCK(cs_smsg);
            SecMsgBucket& b0 = smsgBuckets[nBucket];
            b0.compact(nBucket);
            BOOST_REQUIRE(b0.expand(nBucket));
            nBaseAll = b0.getTokenCount();
            nBaseV1 = b0.getTokenCount(true);
        }
        ClearBucket(nBucket);

        // A 4352-byte v2 object survives compaction and reload.
        SecureMessage smsg;
        smsg.version[0] = 2;
        smsg.SetTimestamp(now);
        std::vector<unsigned char> payload(SMSG_V2_MAX_PAYLOAD, 0x7e);
        smsg.nPayload = payload.size();
        BOOST_REQUIRE_EQUAL(SecureMsgStore(smsg.hash, &payload[0], payload.size(), true), 0);
        StoreObject(1, 1, now, 40);

        LOCK(cs_smsg);
        SecMsgBucket& b = smsgBuckets[nBucket];
        BOOST_CHECK_EQUAL(b.getTokenCount(), 2U);
        b.compact(nBucket);
        BOOST_REQUIRE(b.expand(nBucket));
        // Earlier cases share this bucket's file; compare against what it held before.
        nAll = b.getTokenCount();
        nV1 = b.getTokenCount(true);
        BOOST_CHECK(nAll >= 2U);
        BOOST_CHECK_EQUAL(nAll - nV1, nBaseAll - nBaseV1 + 1);
        BOOST_CHECK_EQUAL(nV1, nBaseV1 + 1);

        // With v2 off the stored v2 objects are skipped, not deleted.
        fNyxV2 = false;
        b.compact(nBucket);
        BOOST_REQUIRE(b.expand(nBucket));
        BOOST_CHECK_EQUAL(b.getTokenCount(), nV1);
        fNyxV2 = true;
        b.compact(nBucket);
        BOOST_REQUIRE(b.expand(nBucket));
        BOOST_CHECK_EQUAL(b.getTokenCount(), nAll);
    }
    {
        V2Guard g(true);
        // A v1 record over SMSG_MAX_MSG_WORST stops the load at that record.
        SecureMessage smsg;
        smsg.version[0] = 1;
        smsg.SetTimestamp(now);
        std::vector<unsigned char> payload(SMSG_MAX_MSG_WORST + 1, 0x7f);
        smsg.nPayload = payload.size();
        BOOST_REQUIRE_EQUAL(SecureMsgStore(smsg.hash, &payload[0], payload.size(), true), 0);
        StoreObject(1, 1, now, 41);
        LOCK(cs_smsg);
        SecMsgBucket& b = smsgBuckets[nBucket];
        BOOST_CHECK_EQUAL(b.getTokenCount(), nAll + 2);
        b.compact(nBucket);
        BOOST_REQUIRE(b.expand(nBucket));
        BOOST_CHECK_EQUAL(b.getTokenCount(), nAll);
    }
    ClearBucket(nBucket);
}

BOOST_AUTO_TEST_CASE(private_send_reassembles_locally)
{
    V2Guard g(true);
    CKey key;
    key.MakeNewKey(true);
    BOOST_REQUIRE(pwalletMain->AddKeyPubKey(key, key.GetPubKey()));
    CPubKey pub = key.GetPubKey();
    const std::string addr = CBitcoinAddress(pub.GetID()).ToString();
    smsgAddresses.push_back(SecMsgAddress(addr, true, false));

    const std::vector<unsigned char> body = Body(4224 + 100, 3);
    std::string msgid, sError;
    BOOST_REQUIRE_MESSAGE(SecureMsgV2SendPrivate(addr, body, msgid, sError) == 0, sError);

    std::vector<NyxV2Delivered> v;
    SecureMsgV2Delivered(v);
    bool fFound = false;
    for (size_t i = 0; i < v.size(); ++i)
        if (v[i].msgid == msgid)
        {
            fFound = true;
            BOOST_CHECK_EQUAL(v[i].nLen, body.size());
            BOOST_CHECK_EQUAL(v[i].sAddrTo, addr);
            BOOST_CHECK_EQUAL(v[i].type, 0x01);
        }
    BOOST_CHECK(fFound);

    // Public body types are refused on the private path.
    std::vector<unsigned char> pubBody = ClassicalCert(9);
    BOOST_CHECK(SecureMsgV2SendPrivate(addr, pubBody, msgid, sError) != 0);
    smsgAddresses.pop_back();
}

// ---- public objects ----------------------------------------------------------

BOOST_AUTO_TEST_CASE(po_parse_bounds)
{
    NyxPoInfo info;
    std::vector<uint8_t> cert = ClassicalCert(1);
    BOOST_CHECK_EQUAL(NyxPoParse(&cert[0], cert.size(), info), 0);
    BOOST_CHECK_EQUAL(info.type, NYX_PO_CERT);
    BOOST_CHECK_EQUAL(info.addrHash[0], 1);
    cert.push_back(0);
    BOOST_CHECK(NyxPoParse(&cert[0], cert.size(), info) != 0);
    cert.resize(171);
    BOOST_CHECK(NyxPoParse(&cert[0], cert.size(), info) != 0);
    cert = ClassicalCert(1);
    uint64_t created, expiry;
    memcpy(&created, &cert[39], 8);
    expiry = created + 91 * 86400;
    memcpy(&cert[47], &expiry, 8);
    BOOST_CHECK(NyxPoParse(&cert[0], cert.size(), info) != 0);

    // PQ cert: first device 2124 B, later device 5433 B.
    std::vector<uint8_t> pq = ClassicalCert(2);
    pq[2] = 1;
    pq.resize(2124, 0);
    BOOST_CHECK_EQUAL(NyxPoParse(&pq[0], pq.size(), info), 0);
    pq[2124 - 1] = 1;     // non-zero signer needs the ML-DSA co-signature
    BOOST_CHECK(NyxPoParse(&pq[0], pq.size(), info) != 0);
    pq.resize(5433, 0);
    BOOST_CHECK_EQUAL(NyxPoParse(&pq[0], pq.size(), info), 0);

    std::vector<uint8_t> kr = Keyring(3, 1, 1, 4, 1);
    BOOST_CHECK_EQUAL(NyxPoParse(&kr[0], kr.size(), info), 0);
    BOOST_CHECK_EQUAL(info.seq, 1U);
    kr = Keyring(3, 2, 1, 4, 1);
    BOOST_CHECK_EQUAL(kr.size(), 3671U);
    BOOST_CHECK_EQUAL(NyxPoParse(&kr[0], kr.size(), info), 0);
    kr = Keyring(3, 2, 1, 16, 16);
    BOOST_CHECK_EQUAL(kr.size(), 4487U);
    BOOST_CHECK_EQUAL(NyxPoParse(&kr[0], kr.size(), info), 0);
    kr = Keyring(3, 2, 1, 17, 0);
    BOOST_CHECK(NyxPoParse(&kr[0], kr.size(), info) != 0);
    kr = Keyring(3, 2, 1, 4, 17);
    BOOST_CHECK(NyxPoParse(&kr[0], kr.size(), info) != 0);
    kr = Keyring(3, 2, 1, 0, 0);
    BOOST_CHECK(NyxPoParse(&kr[0], kr.size(), info) != 0);
    kr = Keyring(3, 2, 1, 4, 1);
    kr.pop_back();
    BOOST_CHECK(NyxPoParse(&kr[0], kr.size(), info) != 0);

    std::vector<uint8_t> bu = Bundle(4, false, 8);
    BOOST_CHECK_EQUAL(bu.size(), 440U);
    BOOST_CHECK_EQUAL(NyxPoParse(&bu[0], bu.size(), info), 0);
    bu = Bundle(4, true, 8);
    BOOST_CHECK_EQUAL(bu.size(), 4872U);
    BOOST_CHECK_EQUAL(NyxPoParse(&bu[0], bu.size(), info), 0);
    bu = Bundle(4, false, 9);
    BOOST_CHECK(NyxPoParse(&bu[0], bu.size(), info) != 0);
    bu = Bundle(4, true, 0);
    bu.push_back(0);
    BOOST_CHECK(NyxPoParse(&bu[0], bu.size(), info) != 0);

    const uint8_t other[3] = {0x01, 0x10, 0x11};
    for (int i = 0; i < 3; ++i)
        BOOST_CHECK(NyxPoParse(&other[i], 1, info) != 0);
    BOOST_CHECK(NyxPoParse(NULL, 0, info) != 0);
}

BOOST_AUTO_TEST_CASE(po_verify_cache_is_bounded)
{
    nVerifyCalls = 0;
    NyxPoSetVerifyHook(VerifyCounting);
    std::vector<uint8_t> b(8, 0);
    for (uint32_t i = 0; i < NYX_PO_CACHE_SIZE + 10; ++i)
    {
        memcpy(&b[0], &i, 4);
        BOOST_CHECK_EQUAL(NyxPoVerify(b), (int)NYX_PO_UNVERIFIED);
    }
    BOOST_CHECK_EQUAL(NyxPoCacheSize(), NYX_PO_CACHE_SIZE);
    const int nBefore = nVerifyCalls;
    NyxPoVerify(b);
    BOOST_CHECK_EQUAL(nVerifyCalls, nBefore);
    NyxPoSetVerifyHook(NULL);
    BOOST_CHECK_EQUAL(NyxPoCacheSize(), 0U);
}

BOOST_AUTO_TEST_CASE(po_store_keeps_newest_and_caps)
{
    NyxPoStore st(3000, 100);
    NyxPoInfo a;
    memset(&a, 0, sizeof(a));
    a.type = NYX_PO_KEYRING;
    a.addrHash[0] = 1;
    a.epoch = 1;
    a.seq = 2;
    std::vector<std::vector<uint8_t> > parts(1, std::vector<uint8_t>(1000, 1));
    BOOST_CHECK(st.Put(a, parts, 10));
    NyxPoInfo older = a;
    older.seq = 1;
    BOOST_CHECK(!st.Put(older, parts, 11));
    NyxPoInfo newer = a;
    newer.seq = 3;
    BOOST_CHECK(st.Put(newer, parts, 12));
    BOOST_CHECK_EQUAL(st.Count(), 1U);

    NyxPoInfo b = a, c = a;
    b.addrHash[0] = 2;
    c.addrHash[0] = 3;
    BOOST_CHECK(st.Put(b, parts, 13));
    BOOST_CHECK(st.Put(c, parts, 14));
    BOOST_CHECK_EQUAL(st.Count(), 3U);
    NyxPoInfo d = a;
    d.addrHash[0] = 4;
    BOOST_CHECK(st.Put(d, parts, 15));
    BOOST_CHECK_EQUAL(st.Count(), 3U);
    BOOST_CHECK(st.Bytes() <= 3000U);
    std::vector<const NyxPoStore::Record*> v;
    st.Get(a.addrHash, v);
    BOOST_CHECK(v.empty());     // least recently seen went first
    BOOST_CHECK_EQUAL(st.TakeErased().size(), 1U);

    st.Expire(15 + 99);
    BOOST_CHECK_EQUAL(st.Count(), 1U);
    st.Expire(15 + 100);
    BOOST_CHECK_EQUAL(st.Count(), 0U);
}

BOOST_AUTO_TEST_CASE(po_unverified_held_locally_verified_relayed)
{
    V2Guard g(true);
    const int64_t now = GetTime();
    const int64_t nBucket = now - (now % SMSG_BUCKET_LEN);
    ClearBucket(nBucket);
    std::string sError;
    bool fRelayed = true;

    NyxPoSetVerifyHook(VerifyHeld);
    std::vector<uint8_t> cert = ClassicalCert(0x70);
    BOOST_REQUIRE_MESSAGE(SecureMsgV2PublishPublic(cert, sError) == 0, sError);
    BOOST_REQUIRE(PoListed(cert, fRelayed));
    BOOST_CHECK(!fRelayed);
    BOOST_CHECK_EQUAL(BucketTokens(nBucket, false), 0U);

    NyxPoSetVerifyHook(VerifyOk);
    std::vector<uint8_t> cert2 = ClassicalCert(0x71);
    BOOST_REQUIRE_MESSAGE(SecureMsgV2PublishPublic(cert2, sError) == 0, sError);
    BOOST_REQUIRE(PoListed(cert2, fRelayed));
    BOOST_CHECK(fRelayed);
    BOOST_CHECK_EQUAL(BucketTokens(nBucket, false), 1U);
    BOOST_CHECK_EQUAL(BucketTokens(nBucket, true), 0U);

    // Served to a v2 peer that asks; nothing for an address with no relayed object.
    Peer v2(31021, NYX_V2_PROTO, true);
    std::vector<unsigned char> get(cert2.begin() + 3, cert2.begin() + 23);
    Deliver(v2.node, "smsgPoGet", get);
    std::vector<std::vector<unsigned char> > po = Sent(v2.node, "smsgPo");
    BOOST_REQUIRE_EQUAL(po.size(), 1U);
    uint32_t nObj;
    memcpy(&nObj, &po[0][20], 4);
    BOOST_CHECK_EQUAL(nObj, 1U);

    std::vector<unsigned char> get1(cert.begin() + 3, cert.begin() + 23);
    Deliver(v2.node, "smsgPoGet", get1);
    po = Sent(v2.node, "smsgPo");
    BOOST_REQUIRE_EQUAL(po.size(), 2U);
    memcpy(&nObj, &po[1][20], 4);
    BOOST_CHECK_EQUAL(nObj, 0U);

    // Wrong-size request is penalised; a v1 peer is ignored.
    Deliver(v2.node, "smsgPoGet", std::vector<unsigned char>(19, 0));
    BOOST_CHECK_EQUAL(v2.node.nMisbehavior, 1);
    Peer v1(31022, V52_PROTO_VERSION, false);
    Deliver(v1.node, "smsgPoGet", get);
    BOOST_CHECK(Sent(v1.node, "smsgPo").empty());

    // Each address is served once per window per peer; at most 20 requests per minute.
    Peer busy(31023, NYX_V2_PROTO, true);
    Deliver(busy.node, "smsgPoGet", get);
    Deliver(busy.node, "smsgPoGet", get);
    BOOST_CHECK_EQUAL(Sent(busy.node, "smsgPo").size(), 1U);
    for (int i = 0; i < 25; ++i)
    {
        std::vector<unsigned char> other(20, (unsigned char)(0xA0 + i));
        Deliver(busy.node, "smsgPoGet", other);
    }
    BOOST_CHECK_EQUAL(Sent(busy.node, "smsgPo").size(), 19U);     // the repeat counted
    BOOST_CHECK(busy.node.smsgData.nPoGetBytes <= NYX_PO_BYTES_PER_MIN);

    // The served response stores at a requester only when it asked for that address.
    std::vector<unsigned char> resp = Sent(busy.node, "smsgPo")[0];
    ClearBucket(nBucket);
    Peer src(31024, NYX_V2_PROTO, true);
    Deliver(src.node, "smsgPo", resp);
    BOOST_CHECK_EQUAL(BucketTokens(nBucket, false), 0U);
    src.node.smsgData.mapPoWanted[std::string(get.begin(), get.end())] = GetTime();
    Deliver(src.node, "smsgPo", resp);
    BOOST_CHECK_EQUAL(src.node.nMisbehavior, 0);
    BOOST_CHECK(src.node.smsgData.mapPoWanted.empty());
    BOOST_CHECK_EQUAL(BucketTokens(nBucket, false), 1U);
    ClearBucket(nBucket);
}

BOOST_AUTO_TEST_CASE(po_unverified_cannot_displace_verified)
{
    V2Guard g(true);
    const int64_t now = GetTime();
    const int64_t nBucket = now - (now % SMSG_BUCKET_LEN);
    ClearBucket(nBucket);
    std::string sError;
    bool fRelayed = false;

    NyxPoSetVerifyHook(VerifyOk);
    std::vector<uint8_t> good = ClassicalCert(0x72, 1);
    BOOST_REQUIRE_MESSAGE(SecureMsgV2PublishPublic(good, sError) == 0, sError);
    BOOST_REQUIRE(PoListed(good, fRelayed));
    BOOST_CHECK(fRelayed);

    // Same key, sender-chosen maximal seq, but unverified.
    NyxPoSetVerifyHook(VerifyHeld);
    std::vector<uint8_t> bad = ClassicalCert(0x72, 0xFFFFFFFF);
    BOOST_REQUIRE_MESSAGE(SecureMsgV2PublishPublic(bad, sError) == 0, sError);
    std::vector<NyxPoListEntry> v;
    SecureMsgPoList(v);
    const std::string addr = HexStr(&good[3], &good[23]);
    int nFound = 0;
    for (size_t i = 0; i < v.size(); ++i)
        if (v[i].addrHash == addr)
        {
            nFound++;
            BOOST_CHECK(v[i].fRelayed);
            BOOST_CHECK_EQUAL(v[i].seq, 1U);
        }
    BOOST_CHECK_EQUAL(nFound, 1);
    ClearBucket(nBucket);
}

BOOST_AUTO_TEST_CASE(po_store_quarantines_unverified)
{
    NyxPoStore st(8000, 1000);
    NyxPoInfo a;
    memset(&a, 0, sizeof(a));
    a.type = NYX_PO_KEYRING;
    a.addrHash[0] = 1;
    a.epoch = 1;
    a.seq = 2;
    std::vector<std::vector<uint8_t> > parts(1, std::vector<uint8_t>(400, 1));
    BOOST_CHECK(st.Put(a, parts, 10, true));
    NyxPoInfo hi = a;
    hi.seq = 0xFFFFFFFF;
    BOOST_CHECK(!st.Put(hi, parts, 11, false));
    std::vector<const NyxPoStore::Record*> v;
    st.Get(a.addrHash, v);
    BOOST_REQUIRE_EQUAL(v.size(), 1U);
    BOOST_CHECK(v[0]->fVerified);
    BOOST_CHECK_EQUAL(v[0]->info.seq, 2U);

    // A verified record replaces an unverified one regardless of seq.
    NyxPoInfo b = a;
    b.addrHash[0] = 2;
    b.seq = 0xFFFFFFFF;
    BOOST_CHECK(st.Put(b, parts, 12, false));
    b.seq = 1;
    BOOST_CHECK(st.Put(b, parts, 13, true));
    st.Get(b.addrHash, v);
    BOOST_REQUIRE_EQUAL(v.size(), 1U);
    BOOST_CHECK(v[0]->fVerified);
    BOOST_CHECK_EQUAL(st.UnverifiedBytes(), 0U);

    // Unverified records are held to an eighth of the cap and never evict verified ones.
    for (int i = 0; i < 20; ++i)
    {
        NyxPoInfo u = a;
        u.addrHash[0] = (uint8_t)(0x40 + i);
        st.Put(u, parts, 20 + i, false);
    }
    BOOST_CHECK(st.UnverifiedBytes() <= 1000U);
    st.Get(a.addrHash, v);
    BOOST_CHECK_EQUAL(v.size(), 1U);
    st.Get(b.addrHash, v);
    BOOST_CHECK_EQUAL(v.size(), 1U);
}

BOOST_AUTO_TEST_CASE(reassembler_evicts_least_complete_first)
{
    NyxReassemblyLimits l;
    l.nOwnerBytes = 64 * 4224;
    l.nNodeBytes = 64 * 4224;
    l.nOwnerSets = 2;
    l.nTimeout = 1000;
    NyxReassembler ra(l);
    std::vector<uint8_t> out;
    std::vector<std::vector<uint8_t> > s1 = Split(Body(4 * 4224, 1), 1);
    std::vector<std::vector<uint8_t> > s2 = Split(Body(4 * 4224, 2), 2);
    std::vector<std::vector<uint8_t> > s3 = Split(Body(4 * 4224, 3), 3);

    for (int i = 0; i < 3; ++i)
        BOOST_CHECK_EQUAL(ra.Add("a", Parse(s1[i]), 1, out), NYX_RA_STORED);
    BOOST_CHECK_EQUAL(ra.Add("a", Parse(s2[0]), 2, out), NYX_RA_STORED);
    // The older but nearly complete set survives a third set.
    BOOST_CHECK_EQUAL(ra.Add("a", Parse(s3[0]), 3, out), NYX_RA_STORED);
    BOOST_CHECK_EQUAL(ra.OwnerSetCount("a"), 2U);
    BOOST_CHECK_EQUAL(ra.Add("a", Parse(s1[3]), 4, out), NYX_RA_COMPLETE);
}

BOOST_AUTO_TEST_CASE(bucket_refused_public_parts_count_as_seen)
{
    unsigned char p1[8] = {1, 1, 1, 1, 1, 1, 1, 1}, p2[8] = {2, 2, 2, 2, 2, 2, 2, 2};
    SecMsgToken held(100, p1, 8, 0, 1, 1), refused(100, p2, 8, 0, 1, 1);

    SecMsgBucket peer;
    peer.insertToken(held);
    peer.insertToken(refused);
    peer.hashBucket();

    SecMsgBucket mine;
    mine.insertToken(held);
    mine.hashBucket();
    BOOST_CHECK(mine.getCmpCount() < peer.getTokenCount());
    BOOST_CHECK(mine.refuseToken(refused));
    BOOST_CHECK(!mine.refuseToken(refused));
    BOOST_CHECK(!mine.refuseToken(held));
    BOOST_CHECK_EQUAL(mine.getCmpCount(), peer.getTokenCount());
    BOOST_CHECK_EQUAL(mine.getCmpHash(), peer.hash);
    BOOST_CHECK_EQUAL(mine.getTokenCount(), 1U);

    // Storing it later drops it from the refused set.
    mine.insertToken(refused);
    mine.hashBucket();
    BOOST_CHECK(mine.setRefused.empty());
    BOOST_CHECK_EQUAL(mine.getCmpHash(), peer.hash);
}

BOOST_AUTO_TEST_CASE(smsg_validate_and_record_decode_smoke)
{
    const bool fSaved = fNyxV2;
    uint32_t r = 0x12345678;
    for (int mode = 0; mode < 2; ++mode)
    {
        fNyxV2 = mode == 1;
        for (int i = 0; i < 2000; ++i)
        {
            const size_t n = SMSG_HDR_LEN + (i % 300);
            std::vector<unsigned char> buf(n);
            for (size_t j = 0; j < n; ++j)
            {
                r = r * 1103515245 + 12345;
                buf[j] = (unsigned char)(r >> 16);
            }
            buf[0] = (unsigned char)(1 + (i & 1));
            SecureMessage* psmsg = (SecureMessage*)&buf[0];
            psmsg->version[0] = (unsigned char)(1 + (i & 1));
            psmsg->version[1] = (unsigned char)((i >> 1) & 1);
            psmsg->nPayload = n - SMSG_HDR_LEN;
            const int rv = SecureMsgValidate(&buf[0], &buf[0] + SMSG_HDR_LEN, n - SMSG_HDR_LEN);
            BOOST_CHECK(rv >= 1 && rv <= 5);

            NyxPoStore::Record rec;
            BOOST_CHECK(!SecureMsgPoDecodeRecord(std::string((const char*)&buf[0], n), rec));
        }
    }
    NyxPoStore::Record rec;
    BOOST_CHECK(!SecureMsgPoDecodeRecord(std::string(), rec));
    BOOST_CHECK(!SecureMsgPoDecodeRecord(std::string(9, '\0'), rec));
    std::string big(9, '\0');
    big[8] = 1;
    big.append("\xff\xff\xff\xff", 4);
    BOOST_CHECK(!SecureMsgPoDecodeRecord(big, rec));
    fNyxV2 = fSaved;
}

BOOST_AUTO_TEST_CASE(po_relay_verifies_identity_chain)
{
    V2Guard g(true);
    std::string sError;
    bool fRelayed = false;
    CKey key;
    key.MakeNewKey(true);
    uint8_t addr[20];
    memcpy(addr, key.GetPubKey().GetID().begin(), 20);
    uint8_t fp[32] = {1};
    NyxOwnDevice d;
    BOOST_REQUIRE(NyxDeviceCreate(d, addr, NYX_MODE_PQ, fp));
    const int64_t now = GetTime();
    NyxCert c;
    BOOST_REQUIRE(NyxBuildCert(d, key, now, 1, NULL, c));
    const NyxBytes cert = c.Serialize();
    NyxKeyring kr;
    memcpy(kr.addrHash, addr, 20);
    kr.ts = now;
    NyxKeyringEntry e;
    memcpy(e.deviceId, d.deviceId, 16);
    NyxHash(cert, e.certHash);
    kr.live.push_back(e);
    BOOST_REQUIRE(NyxBuildKeyring(kr, key, NULL));
    NyxBundle b;
    BOOST_REQUIRE(NyxBuildBundle(d, key, now, b));

    // Out of order: the bundle and the cert wait until the keyring arrives, then all relay.
    BOOST_REQUIRE_MESSAGE(SecureMsgV2PublishPublic(d.lastBundle, sError) == 0, sError);
    BOOST_REQUIRE(PoListed(d.lastBundle, fRelayed));
    BOOST_CHECK(!fRelayed);
    BOOST_REQUIRE_MESSAGE(SecureMsgV2PublishPublic(cert, sError) == 0, sError);
    BOOST_REQUIRE(PoListed(cert, fRelayed));
    BOOST_CHECK(fRelayed);  // no keyring held yet: an address-signed first cert
    BOOST_REQUIRE_MESSAGE(SecureMsgV2PublishPublic(kr.Serialize(), sError) == 0, sError);
    BOOST_REQUIRE(PoListed(kr.Serialize(), fRelayed));
    BOOST_CHECK(fRelayed);
    BOOST_REQUIRE(PoListed(d.lastBundle, fRelayed));
    BOOST_CHECK(fRelayed);

    // A keyring signed by a device the chain never admitted is dropped.
    NyxOwnDevice x;
    BOOST_REQUIRE(NyxDeviceCreate(x, addr, NYX_MODE_PQ, fp));
    NyxKeyring forged = kr;
    forged.seq = 2;
    NyxHash(kr.Serialize(), forged.prevHash);
    BOOST_REQUIRE(NyxBuildKeyring(forged, key, &x));
    BOOST_REQUIRE_MESSAGE(SecureMsgV2PublishPublic(forged.Serialize(), sError) == 0, sError);
    std::vector<NyxPoListEntry> v;
    SecureMsgPoList(v);
    const std::string sAddr = HexStr(addr, addr + 20);
    for (size_t i = 0; i < v.size(); ++i)
        if (v[i].addrHash == sAddr && v[i].type == NYX_PO_KEYRING)
            BOOST_CHECK_EQUAL(v[i].seq, 1U);

    // A garbage-signed cert for another address is refused outright.
    std::vector<uint8_t> junk = ClassicalCert(0x7a);
    BOOST_REQUIRE_MESSAGE(SecureMsgV2PublishPublic(junk, sError) == 0, sError);
    BOOST_CHECK(!PoListed(junk, fRelayed));
}

BOOST_AUTO_TEST_SUITE_END()
