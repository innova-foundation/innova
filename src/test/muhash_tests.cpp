// MuHash3072 known-answer vectors from Bitcoin Core's crypto_tests, plus
// order-independence, insert/remove and persistence checks.

#include <boost/test/unit_test.hpp>

#include "../muhash.h"
#include "../serialize.h"
#include "../util.h"
#include "../version.h"

#include <algorithm>
#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(muhash_tests)

namespace {

MuHash3072 FromInt(unsigned char i)
{
    unsigned char tmp[32] = {i, 0};
    return MuHash3072(tmp, sizeof(tmp));
}

std::string Digest(MuHash3072 h)
{
    uint256 out;
    h.Finalize(out);
    return out.GetHex();
}

std::string SerHex(const MuHash3072& h)
{
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << h;
    return HexStr(ss.begin(), ss.end());
}

struct XorShift
{
    uint64_t s;
    explicit XorShift(uint64_t seed) : s(seed) {}
    uint32_t Bits(int n)
    {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        return (uint32_t)(s >> 32) & ((1u << n) - 1);
    }
};

std::vector<unsigned char> Element(uint32_t n)
{
    std::vector<unsigned char> v(36, 0);
    for (int i = 0; i < 4; ++i) v[32 + i] = (unsigned char)(n >> (8 * i));
    v[0] = (unsigned char)(n * 7 + 1);
    return v;
}

const char* KAT_DIGEST = "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863";

} // namespace

BOOST_AUTO_TEST_CASE(known_answer_multiply_divide)
{
    MuHash3072 acc = FromInt(0);
    acc *= FromInt(1);
    acc /= FromInt(2);
    BOOST_CHECK_EQUAL(Digest(acc), KAT_DIGEST);
}

BOOST_AUTO_TEST_CASE(known_answer_insert_remove)
{
    MuHash3072 acc = FromInt(0);
    unsigned char tmp[32] = {1, 0};
    acc.Insert(tmp, sizeof(tmp));
    unsigned char tmp2[32] = {2, 0};
    acc.Remove(tmp2, sizeof(tmp2));
    BOOST_CHECK_EQUAL(Digest(acc), KAT_DIGEST);

    MuHash3072 acc2(std::vector<unsigned char>(32, 0));
    acc2.Insert(std::vector<unsigned char>(tmp, tmp + sizeof(tmp)));
    acc2.Remove(std::vector<unsigned char>(tmp2, tmp2 + sizeof(tmp2)));
    BOOST_CHECK_EQUAL(Digest(acc2), KAT_DIGEST);
}

BOOST_AUTO_TEST_CASE(known_answer_serialization)
{
    MuHash3072 serchk = FromInt(1);
    serchk *= FromInt(2);
    const std::string strExp = "1fa093295ea30a6a3acdc7b3f770fa538eff537528e990e2910e40bbcfd7f6696b1256901929094694b56316de342f593303dd12ac43e06dce1be1ff8301c845beb15468fff0ef002dbf80c29f26e6452bccc91b5cb9437ad410d2a67ea847887fa3c6a6553309946880fe20db2c73fe0641adbd4e86edfee0d9f8cd0ee1230898873dc13ed8ddcaf045c80faa082774279007a2253f8922ee3ef361d378a6af3ddaf180b190ac97e556888c36b3d1fb1c85aab9ccd46e3deaeb7b7cf5db067a7e9ff86b658cf3acd6662bbcce37232daa753c48b794356c020090c831a8304416e2aa7ad633c0ddb2f11be1be316a81be7f7e472071c042cb68faef549c221ebff209273638b741aba5a81675c45a5fa92fea4ca821d7a324cb1e1a2ccd3b76c4228ec8066dad2a5df6e1bd0de45c7dd5de8070bdb46db6c554cf9aefc9b7b2bbf9f75b1864d9f95005314593905c0109b71f703d49944ae94477b51dac10a816bb6d1c700bafabc8bd86fac8df24be519a2f2836b16392e18036cb13e48c5c010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    BOOST_CHECK_EQUAL(SerHex(serchk), strExp);
    BOOST_CHECK_EQUAL(::GetSerializeSize(serchk, SER_DISK, CLIENT_VERSION), MuHash3072::SERIALIZED_SIZE);

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << serchk;
    MuHash3072 deserchk;
    ss >> deserchk;
    BOOST_CHECK(ss.empty());
    BOOST_CHECK_EQUAL(Digest(deserchk), Digest(serchk));
}

BOOST_AUTO_TEST_CASE(known_answer_overflow_state)
{
    const std::vector<unsigned char> vMax = ParseHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    BOOST_REQUIRE_EQUAL(vMax.size(), MuHash3072::SERIALIZED_SIZE);
    CDataStream ss(vMax, SER_DISK, CLIENT_VERSION);
    MuHash3072 overflowchk;
    ss >> overflowchk;

    uint256 out;
    overflowchk.Finalize(out);
    BOOST_CHECK_EQUAL(HexStr(out.begin(), out.end()),
                      "3a31e6903aff0de9f62f9a9f7f8b861de76ce2cda09822b90014319ae5dc2271");
}

BOOST_AUTO_TEST_CASE(order_independence)
{
    XorShift rng(0x6d7568617368ULL);
    const std::string strEmpty = Digest(MuHash3072());

    for (int iter = 0; iter < 10; ++iter) {
        std::string strRes;
        int table[4];
        for (int i = 0; i < 4; ++i) table[i] = rng.Bits(3);
        for (int order = 0; order < 4; ++order) {
            MuHash3072 acc;
            for (int i = 0; i < 4; ++i) {
                int t = table[i ^ order];
                if (t & 4)
                    acc /= FromInt(t & 3);
                else
                    acc *= FromInt(t & 3);
            }
            const std::string strOut = Digest(acc);
            if (order == 0)
                strRes = strOut;
            else
                BOOST_CHECK_EQUAL(strRes, strOut);
        }

        MuHash3072 x = FromInt(rng.Bits(4));
        MuHash3072 y = FromInt(rng.Bits(4));
        MuHash3072 z;
        z *= x;
        z *= y;
        y *= x;
        z /= y;
        BOOST_CHECK_EQUAL(Digest(z), strEmpty);
    }
}

BOOST_AUTO_TEST_CASE(insert_remove_matches_fresh_set)
{
    const uint32_t N = 24;
    std::vector<uint32_t> vOrder;
    for (uint32_t i = 0; i < N; ++i) vOrder.push_back(i);

    MuHash3072 forward;
    for (uint32_t i = 0; i < N; ++i) forward.Insert(Element(i));

    std::reverse(vOrder.begin(), vOrder.end());
    std::swap(vOrder[3], vOrder[17]);
    MuHash3072 shuffled;
    for (size_t i = 0; i < vOrder.size(); ++i) shuffled.Insert(Element(vOrder[i]));
    BOOST_CHECK_EQUAL(Digest(forward), Digest(shuffled));

    // Remove the odd elements; the result must equal a set built from the evens only.
    for (uint32_t i = 1; i < N; i += 2) forward.Remove(Element(i));
    MuHash3072 evens;
    for (uint32_t i = 0; i < N; i += 2) evens.Insert(Element(i));
    BOOST_CHECK_EQUAL(Digest(forward), Digest(evens));
    BOOST_CHECK(Digest(forward) != Digest(shuffled));

    // Removing everything returns to the empty set.
    for (uint32_t i = 0; i < N; i += 2) forward.Remove(Element(i));
    BOOST_CHECK_EQUAL(Digest(forward), Digest(MuHash3072()));

    // Union and difference of partial accumulators.
    MuHash3072 lo, hi;
    for (uint32_t i = 0; i < N / 2; ++i) lo.Insert(Element(i));
    for (uint32_t i = N / 2; i < N; ++i) hi.Insert(Element(i));
    MuHash3072 both = lo;
    both *= hi;
    BOOST_CHECK_EQUAL(Digest(both), Digest(shuffled));
    both /= hi;
    BOOST_CHECK_EQUAL(Digest(both), Digest(lo));
}

BOOST_AUTO_TEST_CASE(insert_and_remove_are_distinct)
{
    MuHash3072 a, b;
    a.Insert(Element(1));
    b.Remove(Element(1));
    BOOST_CHECK(Digest(a) != Digest(b));
    BOOST_CHECK(Digest(a) != Digest(MuHash3072()));

    MuHash3072 twice;
    twice.Insert(Element(1)).Insert(Element(1));
    BOOST_CHECK(Digest(twice) != Digest(a));
}

BOOST_AUTO_TEST_CASE(persisted_state_resumes)
{
    MuHash3072 running;
    for (uint32_t i = 0; i < 8; ++i) running.Insert(Element(i));
    running.Remove(Element(2));

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << running;
    BOOST_CHECK_EQUAL(ss.size(), MuHash3072::SERIALIZED_SIZE);
    MuHash3072 restored;
    ss >> restored;

    running.Insert(Element(100)).Remove(Element(5));
    restored.Insert(Element(100)).Remove(Element(5));
    BOOST_CHECK_EQUAL(SerHex(running), SerHex(restored));
    BOOST_CHECK_EQUAL(Digest(running), Digest(restored));

    unsigned char buf[MuHash3072::SERIALIZED_SIZE];
    running.ToBytes(buf);
    MuHash3072 fromBytes;
    fromBytes.FromBytes(buf);
    BOOST_CHECK_EQUAL(Digest(fromBytes), Digest(running));
}

BOOST_AUTO_TEST_CASE(finalize_preserves_set)
{
    MuHash3072 h;
    h.Insert(Element(1)).Insert(Element(2)).Remove(Element(3));

    uint256 first, second;
    h.Finalize(first);
    h.Finalize(second);
    BOOST_CHECK(first == second);

    // Finalize normalizes the fraction to denominator 1.
    const std::string strSer = SerHex(h);
    BOOST_CHECK_EQUAL(strSer.substr(768), "01" + std::string(766, '0'));

    h.Insert(Element(3));
    MuHash3072 ref;
    ref.Insert(Element(2)).Insert(Element(1));
    BOOST_CHECK_EQUAL(Digest(h), Digest(ref));
}

BOOST_AUTO_TEST_SUITE_END()
