// Copyright (c) 2017-2021 The Bitcoin Core developers
// Copyright (c) 2026 The Innova developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef INNOVA_MUHASH_H
#define INNOVA_MUHASH_H

#include "uint256.h"

#include <stddef.h>
#include <stdint.h>
#include <vector>

/** An integer modulo 2^3072 - 1103717, stored as little-endian limbs. */
class Num3072
{
private:
    void FullReduce();
    bool IsOverflow() const;
    Num3072 GetInverse() const;

public:
    static constexpr size_t NUM_BYTES = 384;

#ifdef __SIZEOF_INT128__
    typedef unsigned __int128 double_limb_t;
    typedef uint64_t limb_t;
    static constexpr int LIMBS = 48;
    static constexpr int LIMB_SIZE = 64;
#else
    typedef uint64_t double_limb_t;
    typedef uint32_t limb_t;
    static constexpr int LIMBS = 96;
    static constexpr int LIMB_SIZE = 32;
#endif
    limb_t limbs[LIMBS];

    static_assert(LIMB_SIZE * LIMBS == 3072, "Num3072 isn't 3072 bits");
    static_assert(sizeof(double_limb_t) == sizeof(limb_t) * 2, "bad size for double_limb_t");
    static_assert(sizeof(limb_t) * 8 == LIMB_SIZE, "LIMB_SIZE is incorrect");
    static_assert(sizeof(limb_t) == 4 || sizeof(limb_t) == 8, "bad size for limb_t");

    void Multiply(const Num3072& a);
    void Divide(const Num3072& a);
    void SetToOne();
    void Square();
    void ToBytes(unsigned char (&out)[NUM_BYTES]) const;

    Num3072() { this->SetToOne(); }
    explicit Num3072(const unsigned char (&data)[NUM_BYTES]);
};

/** Rolling multiset hash, byte-compatible with Bitcoin Core's MuHash3072. */
class MuHash3072
{
private:
    Num3072 m_numerator;
    Num3072 m_denominator;

    static Num3072 ToNum3072(const unsigned char* data, size_t len);

public:
    static constexpr size_t SERIALIZED_SIZE = 2 * Num3072::NUM_BYTES;

    MuHash3072() noexcept {}

    MuHash3072(const unsigned char* data, size_t len) noexcept;
    explicit MuHash3072(const std::vector<unsigned char>& in) noexcept;

    MuHash3072& Insert(const unsigned char* data, size_t len) noexcept;
    MuHash3072& Insert(const std::vector<unsigned char>& in) noexcept;

    MuHash3072& Remove(const unsigned char* data, size_t len) noexcept;
    MuHash3072& Remove(const std::vector<unsigned char>& in) noexcept;

    /* Union of the two sets. */
    MuHash3072& operator*=(const MuHash3072& mul) noexcept;

    /* Difference of the two sets. */
    MuHash3072& operator/=(const MuHash3072& div) noexcept;

    /* 32-byte digest. Normalizes the internal fraction; the set is unchanged. */
    void Finalize(uint256& out) noexcept;

    void ToBytes(unsigned char (&out)[SERIALIZED_SIZE]) const;
    void FromBytes(const unsigned char (&in)[SERIALIZED_SIZE]);

    unsigned int GetSerializeSize(int nType, int nVersion) const
    {
        return SERIALIZED_SIZE;
    }

    template<typename Stream>
    void Serialize(Stream& s, int nType, int nVersion) const
    {
        unsigned char buf[SERIALIZED_SIZE];
        ToBytes(buf);
        s.write((const char*)buf, sizeof(buf));
    }

    template<typename Stream>
    void Unserialize(Stream& s, int nType, int nVersion)
    {
        unsigned char buf[SERIALIZED_SIZE];
        s.read((char*)buf, sizeof(buf));
        FromBytes(buf);
    }
};

#endif // INNOVA_MUHASH_H
