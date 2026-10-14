// Copyright (c) 2017-2022 The Bitcoin Core developers
// Copyright (c) 2026 The Innova developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "muhash.h"

#include <openssl/sha.h>

#include <assert.h>
#include <string.h>
#include <limits>

namespace {

using limb_t = Num3072::limb_t;
using double_limb_t = Num3072::double_limb_t;
constexpr int LIMB_SIZE = Num3072::LIMB_SIZE;
/** 2^3072 - 1103717, the largest 3072-bit safe prime number, is used as the modulus. */
constexpr limb_t MAX_PRIME_DIFF = 1103717;

/** Extract the lowest limb of [c0,c1,c2] into n, and left shift the number by 1 limb. */
inline void extract3(limb_t& c0, limb_t& c1, limb_t& c2, limb_t& n)
{
    n = c0;
    c0 = c1;
    c1 = c2;
    c2 = 0;
}

/** [c0,c1] = a * b */
inline void mul(limb_t& c0, limb_t& c1, const limb_t& a, const limb_t& b)
{
    double_limb_t t = (double_limb_t)a * b;
    c1 = t >> LIMB_SIZE;
    c0 = t;
}

/* [c0,c1,c2] += n * [d0,d1,d2]. c2 is 0 initially */
inline void mulnadd3(limb_t& c0, limb_t& c1, limb_t& c2, limb_t& d0, limb_t& d1, limb_t& d2, const limb_t& n)
{
    double_limb_t t = (double_limb_t)d0 * n + c0;
    c0 = t;
    t >>= LIMB_SIZE;
    t += (double_limb_t)d1 * n + c1;
    c1 = t;
    t >>= LIMB_SIZE;
    c2 = t + d2 * n;
}

/* [c0,c1] *= n */
inline void muln2(limb_t& c0, limb_t& c1, const limb_t& n)
{
    double_limb_t t = (double_limb_t)c0 * n;
    c0 = t;
    t >>= LIMB_SIZE;
    t += (double_limb_t)c1 * n;
    c1 = t;
}

/** [c0,c1,c2] += a * b */
inline void muladd3(limb_t& c0, limb_t& c1, limb_t& c2, const limb_t& a, const limb_t& b)
{
    double_limb_t t = (double_limb_t)a * b;
    limb_t th = t >> LIMB_SIZE;
    limb_t tl = t;

    c0 += tl;
    th += (c0 < tl) ? 1 : 0;
    c1 += th;
    c2 += (c1 < th) ? 1 : 0;
}

/** [c0,c1,c2] += 2 * a * b */
inline void muldbladd3(limb_t& c0, limb_t& c1, limb_t& c2, const limb_t& a, const limb_t& b)
{
    double_limb_t t = (double_limb_t)a * b;
    limb_t th = t >> LIMB_SIZE;
    limb_t tl = t;

    c0 += tl;
    limb_t tt = th + ((c0 < tl) ? 1 : 0);
    c1 += tt;
    c2 += (c1 < tt) ? 1 : 0;
    c0 += tl;
    th += (c0 < tl) ? 1 : 0;
    c1 += th;
    c2 += (c1 < th) ? 1 : 0;
}

/** [c0,c1] += a, then extract the lowest limb into n and shift right one limb. */
inline void addnextract2(limb_t& c0, limb_t& c1, const limb_t& a, limb_t& n)
{
    limb_t c2 = 0;

    c0 += a;
    if (c0 < a) {
        c1 += 1;

        // Handle case when c1 has overflown
        if (c1 == 0)
            c2 = 1;
    }

    n = c0;
    c0 = c1;
    c1 = c2;
}

/** in_out = in_out^(2^sq) * mul */
inline void square_n_mul(Num3072& in_out, const int sq, const Num3072& mul)
{
    for (int j = 0; j < sq; ++j) in_out.Square();
    in_out.Multiply(mul);
}

inline uint32_t ReadLE32(const unsigned char* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

inline void WriteLE32(unsigned char* p, uint32_t v)
{
    p[0] = (unsigned char)v;
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16);
    p[3] = (unsigned char)(v >> 24);
}

inline uint32_t Rotl32(uint32_t v, int c)
{
    return (v << c) | (v >> (32 - c));
}

inline void QuarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
{
    a += b; d = Rotl32(d ^ a, 16);
    c += d; b = Rotl32(b ^ c, 12);
    a += b; d = Rotl32(d ^ a, 8);
    c += d; b = Rotl32(b ^ c, 7);
}

/** ChaCha20 keystream (RFC 8439 block function), zero nonce, block counter from 0. */
void ChaCha20Keystream(const unsigned char key[32], unsigned char* out, size_t nBlocks)
{
    uint32_t input[16];
    input[0] = 0x61707865;
    input[1] = 0x3320646e;
    input[2] = 0x79622d32;
    input[3] = 0x6b206574;
    for (int i = 0; i < 8; ++i) input[4 + i] = ReadLE32(key + 4 * i);
    input[13] = input[14] = input[15] = 0;

    for (size_t n = 0; n < nBlocks; ++n) {
        input[12] = (uint32_t)n;
        uint32_t x[16];
        memcpy(x, input, sizeof(x));
        for (int r = 0; r < 10; ++r) {
            QuarterRound(x[0], x[4], x[8], x[12]);
            QuarterRound(x[1], x[5], x[9], x[13]);
            QuarterRound(x[2], x[6], x[10], x[14]);
            QuarterRound(x[3], x[7], x[11], x[15]);
            QuarterRound(x[0], x[5], x[10], x[15]);
            QuarterRound(x[1], x[6], x[11], x[12]);
            QuarterRound(x[2], x[7], x[8], x[13]);
            QuarterRound(x[3], x[4], x[9], x[14]);
        }
        for (int i = 0; i < 16; ++i) WriteLE32(out + 64 * n + 4 * i, x[i] + input[i]);
    }
}

} // namespace

/** Indicates whether d is larger than the modulus. */
bool Num3072::IsOverflow() const
{
    if (this->limbs[0] <= std::numeric_limits<limb_t>::max() - MAX_PRIME_DIFF) return false;
    for (int i = 1; i < LIMBS; ++i) {
        if (this->limbs[i] != std::numeric_limits<limb_t>::max()) return false;
    }
    return true;
}

void Num3072::FullReduce()
{
    limb_t c0 = MAX_PRIME_DIFF;
    limb_t c1 = 0;
    for (int i = 0; i < LIMBS; ++i) {
        addnextract2(c0, c1, this->limbs[i], this->limbs[i]);
    }
}

Num3072 Num3072::GetInverse() const
{
    // Sliding-window exponentiation with repunit precomputation (Brumley, Jarvinen 2008).

    Num3072 p[12]; // p[i] = a^(2^(2^i)-1)
    Num3072 out;

    p[0] = *this;

    for (int i = 0; i < 11; ++i) {
        p[i + 1] = p[i];
        for (int j = 0; j < (1 << i); ++j) p[i + 1].Square();
        p[i + 1].Multiply(p[i]);
    }

    out = p[11];

    square_n_mul(out, 512, p[9]);
    square_n_mul(out, 256, p[8]);
    square_n_mul(out, 128, p[7]);
    square_n_mul(out, 64, p[6]);
    square_n_mul(out, 32, p[5]);
    square_n_mul(out, 8, p[3]);
    square_n_mul(out, 2, p[1]);
    square_n_mul(out, 1, p[0]);
    square_n_mul(out, 5, p[2]);
    square_n_mul(out, 3, p[0]);
    square_n_mul(out, 2, p[0]);
    square_n_mul(out, 4, p[0]);
    square_n_mul(out, 4, p[1]);
    square_n_mul(out, 3, p[0]);

    return out;
}

void Num3072::Multiply(const Num3072& a)
{
    limb_t c0 = 0, c1 = 0, c2 = 0;
    Num3072 tmp;

    /* Compute limbs 0..N-2 of this*a into tmp, including one reduction. */
    for (int j = 0; j < LIMBS - 1; ++j) {
        limb_t d0 = 0, d1 = 0, d2 = 0;
        mul(d0, d1, this->limbs[1 + j], a.limbs[LIMBS + j - (1 + j)]);
        for (int i = 2 + j; i < LIMBS; ++i) muladd3(d0, d1, d2, this->limbs[i], a.limbs[LIMBS + j - i]);
        mulnadd3(c0, c1, c2, d0, d1, d2, MAX_PRIME_DIFF);
        for (int i = 0; i < j + 1; ++i) muladd3(c0, c1, c2, this->limbs[i], a.limbs[j - i]);
        extract3(c0, c1, c2, tmp.limbs[j]);
    }

    /* Compute limb N-1 of a*b into tmp. */
    assert(c2 == 0);
    for (int i = 0; i < LIMBS; ++i) muladd3(c0, c1, c2, this->limbs[i], a.limbs[LIMBS - 1 - i]);
    extract3(c0, c1, c2, tmp.limbs[LIMBS - 1]);

    /* Perform a second reduction. */
    muln2(c0, c1, MAX_PRIME_DIFF);
    for (int j = 0; j < LIMBS; ++j) {
        addnextract2(c0, c1, tmp.limbs[j], this->limbs[j]);
    }

    assert(c1 == 0);
    assert(c0 == 0 || c0 == 1);

    /* Up to two more reductions if the state overflowed or exceeds the modulus. */
    if (this->IsOverflow()) this->FullReduce();
    if (c0) this->FullReduce();
}

void Num3072::Square()
{
    limb_t c0 = 0, c1 = 0, c2 = 0;
    Num3072 tmp;

    /* Compute limbs 0..N-2 of this*this into tmp, including one reduction. */
    for (int j = 0; j < LIMBS - 1; ++j) {
        limb_t d0 = 0, d1 = 0, d2 = 0;
        for (int i = 0; i < (LIMBS - 1 - j) / 2; ++i) muldbladd3(d0, d1, d2, this->limbs[i + j + 1], this->limbs[LIMBS - 1 - i]);
        if ((j + 1) & 1) muladd3(d0, d1, d2, this->limbs[(LIMBS - 1 - j) / 2 + j + 1], this->limbs[LIMBS - 1 - (LIMBS - 1 - j) / 2]);
        mulnadd3(c0, c1, c2, d0, d1, d2, MAX_PRIME_DIFF);
        for (int i = 0; i < (j + 1) / 2; ++i) muldbladd3(c0, c1, c2, this->limbs[i], this->limbs[j - i]);
        if ((j + 1) & 1) muladd3(c0, c1, c2, this->limbs[(j + 1) / 2], this->limbs[j - (j + 1) / 2]);
        extract3(c0, c1, c2, tmp.limbs[j]);
    }

    assert(c2 == 0);
    for (int i = 0; i < LIMBS / 2; ++i) muldbladd3(c0, c1, c2, this->limbs[i], this->limbs[LIMBS - 1 - i]);
    extract3(c0, c1, c2, tmp.limbs[LIMBS - 1]);

    /* Perform a second reduction. */
    muln2(c0, c1, MAX_PRIME_DIFF);
    for (int j = 0; j < LIMBS; ++j) {
        addnextract2(c0, c1, tmp.limbs[j], this->limbs[j]);
    }

    assert(c1 == 0);
    assert(c0 == 0 || c0 == 1);

    /* Up to two more reductions if the state overflowed or exceeds the modulus. */
    if (this->IsOverflow()) this->FullReduce();
    if (c0) this->FullReduce();
}

void Num3072::SetToOne()
{
    this->limbs[0] = 1;
    for (int i = 1; i < LIMBS; ++i) this->limbs[i] = 0;
}

void Num3072::Divide(const Num3072& a)
{
    if (this->IsOverflow()) this->FullReduce();

    Num3072 inv{};
    if (a.IsOverflow()) {
        Num3072 b = a;
        b.FullReduce();
        inv = b.GetInverse();
    } else {
        inv = a.GetInverse();
    }

    this->Multiply(inv);
    if (this->IsOverflow()) this->FullReduce();
}

Num3072::Num3072(const unsigned char (&data)[NUM_BYTES])
{
    for (int i = 0; i < LIMBS; ++i) {
        limb_t v = 0;
        for (int b = (int)sizeof(limb_t) - 1; b >= 0; --b) {
            v = (limb_t)((v << 8) | data[i * sizeof(limb_t) + b]);
        }
        this->limbs[i] = v;
    }
}

void Num3072::ToBytes(unsigned char (&out)[NUM_BYTES]) const
{
    for (int i = 0; i < LIMBS; ++i) {
        limb_t v = this->limbs[i];
        for (size_t b = 0; b < sizeof(limb_t); ++b) {
            out[i * sizeof(limb_t) + b] = (unsigned char)v;
            v >>= 8;
        }
    }
}

Num3072 MuHash3072::ToNum3072(const unsigned char* data, size_t len)
{
    unsigned char hashed_in[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hashed_in);

    unsigned char tmp[Num3072::NUM_BYTES];
    static_assert(sizeof(tmp) % 64 == 0, "keystream must be whole ChaCha20 blocks");
    ChaCha20Keystream(hashed_in, tmp, sizeof(tmp) / 64);
    return Num3072(tmp);
}

MuHash3072::MuHash3072(const unsigned char* data, size_t len) noexcept
{
    m_numerator = ToNum3072(data, len);
}

MuHash3072::MuHash3072(const std::vector<unsigned char>& in) noexcept
    : MuHash3072(in.data(), in.size())
{
}

void MuHash3072::Finalize(uint256& out) noexcept
{
    m_numerator.Divide(m_denominator);
    m_denominator.SetToOne();

    unsigned char data[Num3072::NUM_BYTES];
    m_numerator.ToBytes(data);

    SHA256(data, sizeof(data), out.begin());
}

MuHash3072& MuHash3072::operator*=(const MuHash3072& mul) noexcept
{
    m_numerator.Multiply(mul.m_numerator);
    m_denominator.Multiply(mul.m_denominator);
    return *this;
}

MuHash3072& MuHash3072::operator/=(const MuHash3072& div) noexcept
{
    m_numerator.Multiply(div.m_denominator);
    m_denominator.Multiply(div.m_numerator);
    return *this;
}

MuHash3072& MuHash3072::Insert(const unsigned char* data, size_t len) noexcept
{
    m_numerator.Multiply(ToNum3072(data, len));
    return *this;
}

MuHash3072& MuHash3072::Insert(const std::vector<unsigned char>& in) noexcept
{
    return Insert(in.data(), in.size());
}

MuHash3072& MuHash3072::Remove(const unsigned char* data, size_t len) noexcept
{
    m_denominator.Multiply(ToNum3072(data, len));
    return *this;
}

MuHash3072& MuHash3072::Remove(const std::vector<unsigned char>& in) noexcept
{
    return Remove(in.data(), in.size());
}

void MuHash3072::ToBytes(unsigned char (&out)[SERIALIZED_SIZE]) const
{
    unsigned char num[Num3072::NUM_BYTES];
    m_numerator.ToBytes(num);
    memcpy(out, num, sizeof(num));
    m_denominator.ToBytes(num);
    memcpy(out + Num3072::NUM_BYTES, num, sizeof(num));
}

void MuHash3072::FromBytes(const unsigned char (&in)[SERIALIZED_SIZE])
{
    unsigned char num[Num3072::NUM_BYTES];
    memcpy(num, in, sizeof(num));
    m_numerator = Num3072(num);
    memcpy(num, in + Num3072::NUM_BYTES, sizeof(num));
    m_denominator = Num3072(num);
}
