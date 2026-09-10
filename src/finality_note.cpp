// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "finality_note.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <utility>

#include "finality.h"
#include "hash.h"
#include "main.h"
#include "privacy_vnext/iv5_protocol.h"
#include "zkproof.h"

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

namespace
{
void Fail(std::string* pstrError, const char* strReason)
{
    if (pstrError)
        *pstrError = strReason;
}

// ell = 2^252 + 27742317777372353535851937790883648493, big-endian.
const unsigned char ED25519_ORDER_BE[32] = {
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6,
    0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed
};

BIGNUM* NewOrder()
{
    return BN_bin2bn(ED25519_ORDER_BE, 32, NULL);
}

// uint256 keeps its bytes little-endian, which is the canonical scalar encoding, so the
// only conversion either direction is a byte reversal against OpenSSL's big-endian BN.
void ScalarToBN(const uint256& value, BIGNUM* out)
{
    unsigned char be[32];
    const unsigned char* le = value.begin();
    for (int i = 0; i < 32; i++)
        be[i] = le[31 - i];
    BN_bin2bn(be, 32, out);
    OPENSSL_cleanse(be, sizeof(be));
}

uint256 ScalarFromBN(const BIGNUM* value)
{
    unsigned char be[32];
    memset(be, 0, sizeof(be));
    const int nBytes = BN_num_bytes(value);
    if (nBytes > 32)
        return uint256(0);
    BN_bn2bin(value, be + (32 - nBytes));
    uint256 out = 0;
    unsigned char* le = out.begin();
    for (int i = 0; i < 32; i++)
        le[i] = be[31 - i];
    OPENSSL_cleanse(be, sizeof(be));
    return out;
}

uint256 ScalarBinary(const uint256& a, const uint256& b,
                     int (*op)(BIGNUM*, const BIGNUM*, const BIGNUM*, const BIGNUM*, BN_CTX*))
{
    uint256 result = 0;
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* bnA = BN_new();
    BIGNUM* bnB = BN_new();
    BIGNUM* bnOrder = NewOrder();
    BIGNUM* bnOut = BN_new();
    if (ctx && bnA && bnB && bnOrder && bnOut)
    {
        ScalarToBN(a, bnA);
        ScalarToBN(b, bnB);
        if (op(bnOut, bnA, bnB, bnOrder, ctx) == 1)
            result = ScalarFromBN(bnOut);
    }
    if (bnOut) BN_clear_free(bnOut);
    if (bnOrder) BN_free(bnOrder);
    if (bnB) BN_clear_free(bnB);
    if (bnA) BN_clear_free(bnA);
    if (ctx) BN_CTX_free(ctx);
    return result;
}


PrivacyVNextDigest ZeroDigest()
{
    PrivacyVNextDigest zero;
    zero.fill(0);
    return zero;
}

} // namespace

uint256 Ed25519ScalarReduce(const uint256& value)
{
    uint256 result = 0;
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* bn = BN_new();
    BIGNUM* bnOrder = NewOrder();
    if (ctx && bn && bnOrder)
    {
        ScalarToBN(value, bn);
        if (BN_nnmod(bn, bn, bnOrder, ctx) == 1)
            result = ScalarFromBN(bn);
    }
    if (bnOrder) BN_free(bnOrder);
    if (bn) BN_clear_free(bn);
    if (ctx) BN_CTX_free(ctx);
    return result;
}

uint256 Ed25519ScalarAdd(const uint256& a, const uint256& b)
{
    return ScalarBinary(a, b, BN_mod_add);
}

uint256 Ed25519ScalarSub(const uint256& a, const uint256& b)
{
    return ScalarBinary(a, b, BN_mod_sub);
}

uint256 Ed25519ScalarMul(const uint256& a, const uint256& b)
{
    return ScalarBinary(a, b, BN_mod_mul);
}

uint256 Ed25519ScalarNeg(const uint256& a)
{
    return Ed25519ScalarSub(uint256(0), a);
}

uint256 Ed25519ScalarInv(const uint256& a)
{
    uint256 result = 0;
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* bn = BN_new();
    BIGNUM* bnOrder = NewOrder();
    BIGNUM* bnOut = BN_new();
    if (ctx && bn && bnOrder && bnOut)
    {
        ScalarToBN(a, bn);
        if (BN_nnmod(bn, bn, bnOrder, ctx) == 1 && !BN_is_zero(bn) &&
            BN_mod_inverse(bnOut, bn, bnOrder, ctx) != NULL)
            result = ScalarFromBN(bnOut);
    }
    if (bnOut) BN_clear_free(bnOut);
    if (bnOrder) BN_free(bnOrder);
    if (bn) BN_clear_free(bn);
    if (ctx) BN_CTX_free(ctx);
    return result;
}

uint256 Ed25519ScalarFromUint64(uint64_t value)
{
    uint256 out = 0;
    unsigned char* le = out.begin();
    for (int i = 0; i < 8; i++)
        le[i] = (unsigned char)((value >> (8 * i)) & 0xff);
    return out;
}

uint256 Ed25519ScalarFromInt64(int64_t value)
{
    if (value >= 0)
        return Ed25519ScalarFromUint64((uint64_t)value);
    return Ed25519ScalarNeg(Ed25519ScalarFromUint64((uint64_t)(-(value + 1)) + 1));
}

bool Ed25519ScalarIsCanonical(const uint256& value)
{
    return Ed25519ScalarReduce(value) == value;
}

bool Ed25519ScalarToMoney(const uint256& value, int64_t& nOut)
{
    const unsigned char* le = value.begin();
    for (int i = 8; i < 32; i++)
    {
        if (le[i] != 0)
            return false;
    }
    uint64_t nValue = 0;
    for (int i = 0; i < 8; i++)
        nValue |= ((uint64_t)le[i]) << (8 * i);
    if (nValue > (uint64_t)MAX_MONEY)
        return false;
    nOut = (int64_t)nValue;
    return true;
}

PrivacyVNextDigest Ed25519ScalarToDigest(const uint256& value)
{
    PrivacyVNextDigest out;
    const uint256 reduced = Ed25519ScalarReduce(value);
    memcpy(out.data(), reduced.begin(), 32);
    return out;
}

uint256 Ed25519ScalarFromDigest(const PrivacyVNextDigest& digest)
{
    uint256 out = 0;
    memcpy(out.begin(), digest.data(), 32);
    return out;
}

uint256 CNoteFinalityVote::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CNoteFinalityVote::GetVoteTag() const
{
    uint256 tag = 0;
    if (vchTag.size() == FINALITY_NOTE_POINT_SIZE)
        memcpy(tag.begin(), &vchTag[0], FINALITY_NOTE_POINT_SIZE);
    return tag;
}

bool CNoteFinalityVote::IsValidBasic(std::string* pstrError) const
{
    if (nVersion != FINALITY_NOTE_VOTE_VERSION)
    {
        Fail(pstrError, "note vote version is not the payload-derived version");
        return false;
    }
    if (nEpoch < 0 || nHeight < 0)
    {
        Fail(pstrError, "note vote carries a negative epoch or height");
        return false;
    }
    // The boundary block the vote names, and the tag that dedups it. The tag is the
    // spent note's key image, which the payload published; a zero tag would collide
    // with every other zero tag in the counted set.
    if (hashBlock == 0)
    {
        Fail(pstrError, "note vote names no epoch boundary block");
        return false;
    }
    if (vchTag.size() != FINALITY_NOTE_POINT_SIZE)
    {
        Fail(pstrError, "note vote tag is not a point");
        return false;
    }
    bool fTagIsZero = true;
    for (size_t i = 0; i < vchTag.size(); ++i)
        if (vchTag[i] != 0)
        {
            fTagIsZero = false;
            break;
        }
    if (fTagIsZero)
    {
        Fail(pstrError, "note vote tag is zero");
        return false;
    }
    // Proof fields must be ABSENT: a v1 record cannot pass as v2, and a v2 record cannot
    // carry unverified proof fields. The proofs live in the operation-10 payload.
    if (!vchMembership.empty() || !vchSigma.empty() || !vchWeightFloorProof.empty())
    {
        Fail(pstrError, "note vote carries a proof field the payload owns");
        return false;
    }
    if (hashCurveRoot != 0 || hashNullifierRoot != 0 || committeeSetHash != 0)
    {
        Fail(pstrError, "note vote carries an anchor field the payload owns");
        return false;
    }
    return true;
}

// Height-keyed floor ladder. The last rung ends at the height type's maximum; a new floor
// sets that rung's last height and appends a rung.
static const CFinalityVoteWeightFloorRung vFinalityVoteWeightFloor[] = {
    { std::numeric_limits<int>::max(), iv5::NOTE_VOTE_MIN_WEIGHT },
};

int64_t GetFinalityMinVoteWeight(int nHeight)
{
    // A negative height is no chain position at all; answer with the rung a genesis-side
    // caller would get rather than reading past the table.
    const int nKey = (nHeight < 0) ? 0 : nHeight;
    for (size_t i = 0; i < ARRAYLEN(vFinalityVoteWeightFloor); ++i)
        if (nKey <= vFinalityVoteWeightFloor[i].nHeightLast)
            return vFinalityVoteWeightFloor[i].nMinWeight;
    // Unreachable while the last rung is open-ended; fails closed at the highest floor.
    return vFinalityVoteWeightFloor[ARRAYLEN(vFinalityVoteWeightFloor) - 1].nMinWeight;
}

bool CheckNoteVote(const CNoteFinalityVote& vote, std::string* pstrError)
{
    // The record carries no proofs; they are in the operation-10 payload and were
    // verified when it connected.
    return vote.IsValidBasic(pstrError);
}

