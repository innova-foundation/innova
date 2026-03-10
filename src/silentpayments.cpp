// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "silentpayments.h"
#include "hash.h"
#include "util.h"
#include "base58.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>
#include <string.h>

class CSPBNCtxGuard
{
public:
    BN_CTX* ctx;
    CSPBNCtxGuard() { ctx = BN_CTX_new(); }
    ~CSPBNCtxGuard() { if (ctx) BN_CTX_free(ctx); }
    operator BN_CTX*() { return ctx; }
};

class CSPECGroupGuard
{
public:
    EC_GROUP* group;
    CSPECGroupGuard() { group = EC_GROUP_new_by_curve_name(NID_secp256k1); }
    ~CSPECGroupGuard() { if (group) EC_GROUP_free(group); }
    operator EC_GROUP*() { return group; }
    operator const EC_GROUP*() const { return group; }
};

class CSPECPointGuard
{
public:
    EC_POINT* point;
    const EC_GROUP* group;
    CSPECPointGuard(const EC_GROUP* g) : group(g) { point = EC_POINT_new(group); }
    ~CSPECPointGuard() { if (point) EC_POINT_free(point); }
    operator EC_POINT*() { return point; }
    operator const EC_POINT*() const { return point; }
};

class CSPECKeyGuard
{
public:
    EC_KEY* key;
    CSPECKeyGuard() { key = EC_KEY_new_by_curve_name(NID_secp256k1); }
    ~CSPECKeyGuard() { if (key) EC_KEY_free(key); }
    operator EC_KEY*() { return key; }
};

static bool SPPointToBytes(const EC_GROUP* group, const EC_POINT* point,
                            std::vector<unsigned char>& vchOut, BN_CTX* ctx)
{
    size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    if (len == 0) return false;
    vchOut.resize(len);
    return EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED,
                               vchOut.data(), len, ctx) == len;
}

static bool SPBytesToPoint(const EC_GROUP* group, const std::vector<unsigned char>& vch,
                            EC_POINT* point, BN_CTX* ctx)
{
    if (vch.size() < 33) return false;
    return EC_POINT_oct2point(group, point, vch.data(), vch.size(), ctx) == 1;
}


std::string CSilentPaymentAddress::ToString() const
{
    if (IsNull()) return "";

    std::vector<unsigned char> vchData;
    vchData.push_back((unsigned char)SILENT_PAYMENT_VERSION);
    vchData.insert(vchData.end(), vchScanPubKey.begin(), vchScanPubKey.end());
    vchData.insert(vchData.end(), vchSpendPubKey.begin(), vchSpendPubKey.end());

    return EncodeBase58Check(vchData);
}

bool CSilentPaymentAddress::FromString(const std::string& str)
{
    std::vector<unsigned char> vchData;
    if (!DecodeBase58Check(str, vchData))
        return false;

    if (vchData.size() != 1 + 33 + 33)
        return false;

    if (vchData[0] != (unsigned char)SILENT_PAYMENT_VERSION)
        return false;

    vchScanPubKey.assign(vchData.begin() + 1, vchData.begin() + 34);
    vchSpendPubKey.assign(vchData.begin() + 34, vchData.begin() + 67);

    return true;
}


bool CSilentPaymentKey::GetAddress(CSilentPaymentAddress& addrOut) const
{
    if (IsNull()) return false;

    CSPECGroupGuard group;
    if (!group.group) return false;

    CSPBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    const EC_POINT* G = EC_GROUP_get0_generator(group);

    BIGNUM* bnScan = BN_bin2bn((const unsigned char*)skScan.data(), skScan.size(), NULL);
    if (!bnScan) return false;

    CSPECPointGuard Bscan(group);
    if (EC_POINT_mul(group, Bscan, NULL, G, bnScan, ctx) != 1)
    {
        BN_clear_free(bnScan);
        return false;
    }
    BN_clear_free(bnScan);

    if (!SPPointToBytes(group, Bscan, addrOut.vchScanPubKey, ctx))
        return false;

    BIGNUM* bnSpend = BN_bin2bn((const unsigned char*)skSpend.data(), skSpend.size(), NULL);
    if (!bnSpend) return false;

    CSPECPointGuard Bspend(group);
    if (EC_POINT_mul(group, Bspend, NULL, G, bnSpend, ctx) != 1)
    {
        BN_clear_free(bnSpend);
        return false;
    }
    BN_clear_free(bnSpend);

    if (!SPPointToBytes(group, Bspend, addrOut.vchSpendPubKey, ctx))
        return false;

    return true;
}

bool CSilentPaymentKey::Generate(CSilentPaymentKey& keyOut)
{
    keyOut.skScan.resize(32);
    if (RAND_bytes((unsigned char*)keyOut.skScan.data(), 32) != 1)
        return false;

    keyOut.skSpend.resize(32);
    if (RAND_bytes((unsigned char*)keyOut.skSpend.data(), 32) != 1)
    {
        OPENSSL_cleanse((unsigned char*)keyOut.skScan.data(), keyOut.skScan.size());
        keyOut.skScan.clear();
        keyOut.skSpend.clear();
        return false;
    }

    CSPECGroupGuard group;
    if (!group.group) return false;

    CSPBNCtxGuard ctx;
    const BIGNUM* order = EC_GROUP_get0_order(group);

    BIGNUM* bn = BN_bin2bn((const unsigned char*)keyOut.skScan.data(), 32, NULL);
    BN_mod(bn, bn, order, ctx);
    if (BN_is_zero(bn))
    {
        BN_clear_free(bn);
        OPENSSL_cleanse((unsigned char*)keyOut.skScan.data(), 32);
        OPENSSL_cleanse((unsigned char*)keyOut.skSpend.data(), 32);
        return false;
    }
    memset((unsigned char*)keyOut.skScan.data(), 0, 32);
    int nBytes = BN_num_bytes(bn);
    if (nBytes > 0) BN_bn2bin(bn, (unsigned char*)keyOut.skScan.data() + (32 - nBytes));
    BN_clear_free(bn);

    bn = BN_bin2bn((const unsigned char*)keyOut.skSpend.data(), 32, NULL);
    BN_mod(bn, bn, order, ctx);
    if (BN_is_zero(bn))
    {
        BN_clear_free(bn);
        OPENSSL_cleanse((unsigned char*)keyOut.skScan.data(), 32);
        OPENSSL_cleanse((unsigned char*)keyOut.skSpend.data(), 32);
        return false;
    }
    memset((unsigned char*)keyOut.skSpend.data(), 0, 32);
    nBytes = BN_num_bytes(bn);
    if (nBytes > 0) BN_bn2bin(bn, (unsigned char*)keyOut.skSpend.data() + (32 - nBytes));
    BN_clear_free(bn);

    return true;
}


static uint256 TaggedHash(const std::string& tag, const std::vector<unsigned char>& data)
{
    unsigned char tagHash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)tag.data(), tag.size(), tagHash);

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, tagHash, SHA256_DIGEST_LENGTH);
    SHA256_Update(&sha256, tagHash, SHA256_DIGEST_LENGTH);
    SHA256_Update(&sha256, data.data(), data.size());

    uint256 result;
    SHA256_Final(result.begin(), &sha256);
    return result;
}

static bool ComputeTweak(const std::vector<unsigned char>& vchSharedSecret,
                          uint32_t nOutputIndex,
                          BIGNUM* tweakOut, const BIGNUM* order, BN_CTX* ctx)
{
    std::vector<unsigned char> data;
    data.reserve(vchSharedSecret.size() + 4);
    data.insert(data.end(), vchSharedSecret.begin(), vchSharedSecret.end());
    data.push_back((nOutputIndex >>  0) & 0xFF);
    data.push_back((nOutputIndex >>  8) & 0xFF);
    data.push_back((nOutputIndex >> 16) & 0xFF);
    data.push_back((nOutputIndex >> 24) & 0xFF);

    uint256 hash = TaggedHash("Innova/silentpayment/tweak", data);

    BN_bin2bn(hash.begin(), 32, tweakOut);
    BN_mod(tweakOut, tweakOut, order, ctx);
    // PRIV-AUDIT-14: Zero tweak is invalid per BIP-352
    if (BN_is_zero(tweakOut))
        return false;
    return true;
}

bool DeriveSilentPaymentOutput(const std::vector<unsigned char>& vchSenderSecretSum,
                                const CSilentPaymentAddress& addr,
                                uint32_t nOutputIndex,
                                std::vector<unsigned char>& vchOutputPubKeyOut)
{
    if (vchSenderSecretSum.size() != 32) return false;
    if (addr.IsNull()) return false;

    CSPECGroupGuard group;
    if (!group.group) return false;

    CSPBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    const BIGNUM* order = EC_GROUP_get0_order(group);
    const EC_POINT* G = EC_GROUP_get0_generator(group);

    CSPECPointGuard Bscan(group);
    if (!SPBytesToPoint(group, addr.vchScanPubKey, Bscan, ctx))
        return false;

    BIGNUM* bnA = BN_bin2bn(vchSenderSecretSum.data(), 32, NULL);
    if (!bnA) return false;

    CSPECPointGuard sharedPoint(group);
    if (EC_POINT_mul(group, sharedPoint, NULL, Bscan, bnA, ctx) != 1)
    {
        BN_clear_free(bnA);
        return false;
    }
    BN_clear_free(bnA);
    if (EC_POINT_is_at_infinity(group, sharedPoint))
        return false;

    std::vector<unsigned char> vchSharedSecret;
    if (!SPPointToBytes(group, sharedPoint, vchSharedSecret, ctx))
        return false;

    BIGNUM* t = BN_new();
    if (!ComputeTweak(vchSharedSecret, nOutputIndex, t, order, ctx))
    {
        OPENSSL_cleanse(vchSharedSecret.data(), vchSharedSecret.size());
        BN_free(t);
        return false;
    }
    OPENSSL_cleanse(vchSharedSecret.data(), vchSharedSecret.size());

    CSPECPointGuard tG(group);
    if (EC_POINT_mul(group, tG, NULL, G, t, ctx) != 1)
    {
        BN_free(t);
        return false;
    }
    BN_free(t);

    CSPECPointGuard Bspend(group);
    if (!SPBytesToPoint(group, addr.vchSpendPubKey, Bspend, ctx))
        return false;

    CSPECPointGuard P(group);
    if (EC_POINT_add(group, P, Bspend, tG, ctx) != 1)
        return false;

    if (EC_POINT_is_on_curve(group, P, ctx) != 1)
        return false;
    if (EC_POINT_is_at_infinity(group, P))
        return false;

    return SPPointToBytes(group, P, vchOutputPubKeyOut, ctx);
}

bool DeriveSilentPaymentSpendKey(const CSilentPaymentKey& key,
                                  const std::vector<unsigned char>& vchSenderPubKeySum,
                                  uint32_t nOutputIndex,
                                  std::vector<unsigned char>& vchPrivKeyOut)
{
    if (key.IsNull()) return false;
    if (vchSenderPubKeySum.size() != 33) return false;

    CSPECGroupGuard group;
    if (!group.group) return false;

    CSPBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    const BIGNUM* order = EC_GROUP_get0_order(group);

    CSPECPointGuard A(group);
    if (!SPBytesToPoint(group, vchSenderPubKeySum, A, ctx))
        return false;

    BIGNUM* bnBscan = BN_bin2bn((const unsigned char*)key.skScan.data(), key.skScan.size(), NULL);
    if (!bnBscan) return false;

    CSPECPointGuard sharedPoint(group);
    if (EC_POINT_mul(group, sharedPoint, NULL, A, bnBscan, ctx) != 1)
    {
        BN_clear_free(bnBscan);
        return false;
    }
    BN_clear_free(bnBscan);

    std::vector<unsigned char> vchSharedSecret;
    if (!SPPointToBytes(group, sharedPoint, vchSharedSecret, ctx))
        return false;

    BIGNUM* t = BN_new();
    if (!ComputeTweak(vchSharedSecret, nOutputIndex, t, order, ctx))
    {
        OPENSSL_cleanse(vchSharedSecret.data(), vchSharedSecret.size());
        BN_free(t);
        return false;
    }
    OPENSSL_cleanse(vchSharedSecret.data(), vchSharedSecret.size());

    BIGNUM* bnBspend = BN_bin2bn((const unsigned char*)key.skSpend.data(), key.skSpend.size(), NULL);
    if (!bnBspend) { BN_free(t); return false; }

    BIGNUM* spendKey = BN_new();
    BN_mod_add(spendKey, bnBspend, t, order, ctx);

    BN_clear_free(bnBspend);
    BN_free(t);

    vchPrivKeyOut.resize(32, 0);
    int nBytes = BN_num_bytes(spendKey);
    if (nBytes > 0) BN_bn2bin(spendKey, vchPrivKeyOut.data() + (32 - nBytes));
    BN_clear_free(spendKey);

    return true;
}

bool ScanForSilentPayments(const CSilentPaymentKey& key,
                            const std::vector<unsigned char>& vchSenderPubKeySum,
                            const std::vector<std::vector<unsigned char>>& vTxOutputPubKeys,
                            std::vector<uint32_t>& vMatchedOut)
{
    if (key.IsNull()) return false;
    if (vchSenderPubKeySum.size() != 33) return false;

    vMatchedOut.clear();

    CSPECGroupGuard group;
    if (!group.group) return false;

    CSPBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    const BIGNUM* order = EC_GROUP_get0_order(group);
    const EC_POINT* G = EC_GROUP_get0_generator(group);

    CSPECPointGuard A(group);
    if (!SPBytesToPoint(group, vchSenderPubKeySum, A, ctx))
        return false;

    BIGNUM* bnBscan = BN_bin2bn((const unsigned char*)key.skScan.data(), key.skScan.size(), NULL);
    if (!bnBscan) return false;

    CSPECPointGuard sharedPoint(group);
    if (EC_POINT_mul(group, sharedPoint, NULL, A, bnBscan, ctx) != 1)
    {
        BN_clear_free(bnBscan);
        return false;
    }
    BN_clear_free(bnBscan);

    std::vector<unsigned char> vchSharedSecret;
    if (!SPPointToBytes(group, sharedPoint, vchSharedSecret, ctx))
        return false;

    CSPECPointGuard Bspend(group);
    BIGNUM* bnBspend = BN_bin2bn((const unsigned char*)key.skSpend.data(), key.skSpend.size(), NULL);
    if (!bnBspend) return false;
    if (EC_POINT_mul(group, Bspend, NULL, G, bnBspend, ctx) != 1)
    {
        BN_clear_free(bnBspend);
        return false;
    }
    BN_clear_free(bnBspend);

    for (uint32_t n = 0; n < (uint32_t)vTxOutputPubKeys.size(); n++)
    {
        BIGNUM* t = BN_new();
        if (!ComputeTweak(vchSharedSecret, n, t, order, ctx))
        {
            BN_free(t);
            continue;
        }

        CSPECPointGuard tG(group), expected(group);
        EC_POINT_mul(group, tG, NULL, G, t, ctx);
        EC_POINT_add(group, expected, Bspend, tG, ctx);
        BN_free(t);

        std::vector<unsigned char> vchExpected;
        if (!SPPointToBytes(group, expected, vchExpected, ctx))
            continue;

        if (vTxOutputPubKeys[n].size() == vchExpected.size() &&
            CRYPTO_memcmp(vTxOutputPubKeys[n].data(), vchExpected.data(), vchExpected.size()) == 0)
        {
            vMatchedOut.push_back(n);
        }
    }

    OPENSSL_cleanse(vchSharedSecret.data(), vchSharedSecret.size());

    return true;
}

bool ComputeInputPubKeySum(const std::vector<std::vector<unsigned char>>& vInputPubKeys,
                            std::vector<unsigned char>& vchSumOut)
{
    if (vInputPubKeys.empty()) return false;

    CSPECGroupGuard group;
    if (!group.group) return false;

    CSPBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    CSPECPointGuard sum(group);
    EC_POINT_set_to_infinity(group, sum);

    for (size_t i = 0; i < vInputPubKeys.size(); i++)
    {
        CSPECPointGuard pt(group);
        if (!SPBytesToPoint(group, vInputPubKeys[i], pt, ctx))
            return false;
        if (EC_POINT_is_on_curve(group, pt, ctx) != 1)
            return false;
        if (EC_POINT_add(group, sum, sum, pt, ctx) != 1)
            return false;
    }

    if (EC_POINT_is_at_infinity(group, sum))
        return false;

    return SPPointToBytes(group, sum, vchSumOut, ctx);
}

bool ComputeInputPrivKeySum(const std::vector<std::vector<unsigned char>>& vInputPrivKeys,
                             std::vector<unsigned char>& vchSumOut)
{
    if (vInputPrivKeys.empty()) return false;

    CSPECGroupGuard group;
    if (!group.group) return false;

    CSPBNCtxGuard ctx;
    if (!ctx.ctx) return false;

    const BIGNUM* order = EC_GROUP_get0_order(group);

    BIGNUM* sum = BN_new();
    BN_zero(sum);

    for (size_t i = 0; i < vInputPrivKeys.size(); i++)
    {
        if (vInputPrivKeys[i].size() != 32)
        {
            BN_clear_free(sum);
            return false;
        }
        BIGNUM* k = BN_bin2bn(vInputPrivKeys[i].data(), 32, NULL);
        if (!k)
        {
            BN_clear_free(sum);
            return false;
        }
        BN_mod_add(sum, sum, k, order, ctx);
        BN_clear_free(k);
    }

    if (BN_is_zero(sum))
    {
        BN_clear_free(sum);
        return false;
    }

    vchSumOut.resize(32, 0);
    int nBytes = BN_num_bytes(sum);
    if (nBytes > 0) BN_bn2bin(sum, vchSumOut.data() + (32 - nBytes));
    BN_clear_free(sum);

    return true;
}


bool DeriveSilentShieldedAddress(const std::vector<unsigned char>& vchOutputPubKey,
                                  std::vector<unsigned char>& vchDiversifierOut,
                                  std::vector<unsigned char>& vchPkDOut)
{
    if (vchOutputPubKey.size() != 33) return false;

    CHashWriter ssd(SER_GETHASH, 0);
    ssd << (uint8_t)0x71;
    for (size_t i = 0; i < vchOutputPubKey.size(); i++)
        ssd << vchOutputPubKey[i];
    uint256 dHash = ssd.GetHash();

    vchDiversifierOut.resize(11);
    memcpy(vchDiversifierOut.data(), dHash.begin(), 11);

    CHashWriter sspk(SER_GETHASH, 0);
    sspk << (uint8_t)0x72;
    for (size_t i = 0; i < vchOutputPubKey.size(); i++)
        sspk << vchOutputPubKey[i];
    uint256 pkdHash = sspk.GetHash();

    CSPECGroupGuard grpPkd;
    CSPBNCtxGuard ctxPkd;
    if (!grpPkd.group || !ctxPkd.ctx)
        return false;
    BIGNUM* bnPkdScalar = BN_new();
    BN_bin2bn(pkdHash.begin(), 32, bnPkdScalar);
    const BIGNUM* bnOrder = EC_GROUP_get0_order(grpPkd);
    BN_mod(bnPkdScalar, bnPkdScalar, bnOrder, ctxPkd);
    if (BN_is_zero(bnPkdScalar))
    {
        BN_free(bnPkdScalar);
        return false;
    }

    CSPECPointGuard ptPkd(grpPkd);
    EC_POINT_mul(grpPkd, ptPkd, bnPkdScalar, NULL, NULL, ctxPkd);
    BN_free(bnPkdScalar);

    size_t nPkdLen = EC_POINT_point2oct(grpPkd, ptPkd, POINT_CONVERSION_COMPRESSED, NULL, 0, ctxPkd);
    if (nPkdLen != 33)
        return false;
    vchPkDOut.resize(33);
    EC_POINT_point2oct(grpPkd, ptPkd, POINT_CONVERSION_COMPRESSED, vchPkDOut.data(), 33, ctxPkd);

    return true;
}
