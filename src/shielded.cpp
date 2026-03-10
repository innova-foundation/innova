// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "shielded.h"
#include "zkproof.h"
#include "hash.h"
#include "key.h"
#include "util.h"

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <string.h>

int64_t nShieldedPoolValue = 0;

std::vector<uint256> CIncrementalMerkleTree::vEmptyRoots;
bool CIncrementalMerkleTree::fEmptyRootsInitialized = false;
boost::once_flag CIncrementalMerkleTree::emptyRootsOnceFlag = BOOST_ONCE_INIT;

void CIncrementalMerkleTree::InitEmptyRoots()
{
    if (fEmptyRootsInitialized)
        return;

    vEmptyRoots.resize(SHIELDED_MERKLE_DEPTH + 1);

    vEmptyRoots[0] = uint256(0);

    for (int i = 1; i <= SHIELDED_MERKLE_DEPTH; i++)
    {
        vEmptyRoots[i] = HashCombine(i - 1, vEmptyRoots[i - 1], vEmptyRoots[i - 1]);
    }

    fEmptyRootsInitialized = true;
}

const uint256& CIncrementalMerkleTree::EmptyRoot(int nDepth)
{
    boost::call_once(&InitEmptyRoots, emptyRootsOnceFlag);

    if (nDepth < 0 || nDepth > SHIELDED_MERKLE_DEPTH)
    {
        static uint256 zero;
        return zero;
    }

    return vEmptyRoots[nDepth];
}

uint256 CIncrementalMerkleTree::HashCombine(int nDepth, const uint256& left, const uint256& right)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << (uint8_t)nDepth;
    ss << left;
    ss << right;
    return ss.GetHash();
}

bool CIncrementalMerkleTree::Append(const uint256& leaf)
{
    boost::call_once(&InitEmptyRoots, emptyRootsOnceFlag);

    if (nSize >= ((uint64_t)1 << SHIELDED_MERKLE_DEPTH))
    {
        printf("CIncrementalMerkleTree::Append() : tree is full\n");
        return false;
    }

    uint256 current = leaf;
    uint64_t pos = nSize;

    for (int nDepth = 0; nDepth < SHIELDED_MERKLE_DEPTH; nDepth++)
    {
        if ((pos & 1) == 0)
        {
            vLeft[nDepth] = current;
            vRight[nDepth] = uint256(0);
            nSize++;
            return true;
        }
        else
        {
            vRight[nDepth] = current;
            current = HashCombine(nDepth, vLeft[nDepth], current);
            pos >>= 1;
        }
    }

    nSize++;
    return true;
}

uint256 CIncrementalMerkleTree::Root() const
{
    boost::call_once(&InitEmptyRoots, emptyRootsOnceFlag);

    if (nSize == 0)
        return EmptyRoot(SHIELDED_MERKLE_DEPTH);

    uint256 current = uint256(0);
    bool fCurrentSet = false;
    uint64_t pos = nSize - 1;  // Position of last appended leaf

    for (int nDepth = 0; nDepth < SHIELDED_MERKLE_DEPTH; nDepth++)
    {
        uint256 left, right;

        if ((pos & 1) == 0)
        {
            left = fCurrentSet ? current : vLeft[nDepth];
            right = EmptyRoot(nDepth);
        }
        else
        {
            left = vLeft[nDepth];
            right = fCurrentSet ? current : vRight[nDepth];
        }

        current = HashCombine(nDepth, left, right);
        fCurrentSet = true;
        pos >>= 1;
    }

    return current;
}

bool CIncrementalMerkleTree::GetWitness(uint64_t nPosition, std::vector<uint256>& vPathOut) const
{
    vPathOut.clear();
    vPathOut.resize(SHIELDED_MERKLE_DEPTH);

    if (nPosition >= nSize)
    {
        printf("CIncrementalMerkleTree::GetWitness() : position %lu >= size %lu\n",
               (unsigned long)nPosition, (unsigned long)nSize);
        return false;
    }

    uint64_t pos = nPosition;

    for (int nDepth = 0; nDepth < SHIELDED_MERKLE_DEPTH; nDepth++)
    {
        if ((pos & 1) == 0)
        {
            if (vRight[nDepth] != uint256(0))
                vPathOut[nDepth] = vRight[nDepth];
            else
            {
                uint64_t rightSiblingStart = ((uint64_t)pos + 1) << nDepth;
                if (rightSiblingStart < nSize)
                {
                    printf("CIncrementalMerkleTree::GetWitness() : unexpected empty right sibling at depth %d for position %lu (tree size %lu)\n",
                           nDepth, (unsigned long)nPosition, (unsigned long)nSize);
                    return false;
                }
                vPathOut[nDepth] = EmptyRoot(nDepth);
            }
        }
        else
        {
            if (vLeft[nDepth] == uint256(0))
            {
                printf("CIncrementalMerkleTree::GetWitness() : missing left sibling at depth %d for position %lu\n",
                       nDepth, (unsigned long)nPosition);
                return false;
            }
            vPathOut[nDepth] = vLeft[nDepth];
        }

        pos >>= 1;
    }

    return true;
}


uint256 CShieldedNote::GetCommitment() const
{
    if (!CZKContext::IsInitialized())
    {
        printf("ERROR: CShieldedNote::GetCommitment() called before ZK context initialized\n");
        return uint256(0);
    }

    if (vchBlind.size() != BLINDING_FACTOR_SIZE)
    {
        printf("ERROR: CShieldedNote::GetCommitment() : invalid blinding factor size %u\n",
               (unsigned int)vchBlind.size());
        return uint256(0);
    }

    CPedersenCommitment pc;
    if (!CreatePedersenCommitment(nValue, vchBlind, pc))
    {
        printf("ERROR: CShieldedNote::GetCommitment() : CreatePedersenCommitment failed\n");
        return uint256(0);
    }

    return pc.GetHash();
}

bool CShieldedNote::GetPedersenCommitment(CPedersenCommitment& commitOut) const
{
    if (!CZKContext::IsInitialized()) return false;
    if (vchBlind.size() != BLINDING_FACTOR_SIZE) return false;
    return CreatePedersenCommitment(nValue, vchBlind, commitOut);
}

uint256 CShieldedNote::GetNullifier(const uint256& nk) const
{
    if (!CZKContext::IsInitialized())
    {
        printf("ERROR: CShieldedNote::GetNullifier() called before ZK context initialized\n");
        return uint256(0);
    }

    uint256 nf = PRF_nf(nk, rho);
    if (nf == 0)
    {
        printf("ERROR: CShieldedNote::GetNullifier() produced zero nullifier\n");
        return uint256(0);
    }
    return nf;
}

bool CShieldedNote::GenerateBlindingFactor()
{
    return ::GenerateBlindingFactor(vchBlind);
}


bool GenerateShieldedSpendingKey(CShieldedSpendingKey& skOut)
{
    unsigned char buf[32];

    if (RAND_bytes(buf, 32) != 1)
        return false;
    memcpy(skOut.skSpend.begin(), buf, 32);

    if (RAND_bytes(buf, 32) != 1)
        return false;
    memcpy(skOut.skPrf.begin(), buf, 32);

    if (RAND_bytes(buf, 32) != 1)
        return false;
    memcpy(skOut.ovk.begin(), buf, 32);

    OPENSSL_cleanse(buf, 32);
    return true;
}

bool DeriveShieldedFullViewingKey(const CShieldedSpendingKey& sk, CShieldedFullViewingKey& fvkOut)
{
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << (uint8_t)0x10; // ak domain
        ss << sk.skSpend;
        uint256 akHash = ss.GetHash();
        fvkOut.vchAk.resize(32);
        memcpy(fvkOut.vchAk.data(), akHash.begin(), 32);
    }

    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << (uint8_t)0x11; // nk domain
        ss << sk.skPrf;
        fvkOut.nk = ss.GetHash();
    }

    fvkOut.ovk = sk.ovk;

    return true;
}

bool DeriveShieldedIncomingViewingKey(const CShieldedFullViewingKey& fvk, CShieldedIncomingViewingKey& ivkOut)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << (uint8_t)0x12; // ivk domain

    for (size_t i = 0; i < fvk.vchAk.size(); i++)
        ss << fvk.vchAk[i];
    ss << fvk.nk;

    uint256 hashResult = ss.GetHash();

    BIGNUM* bnHash = BN_bin2bn(hashResult.begin(), 32, NULL);
    if (!bnHash) return false;

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) { BN_free(bnHash); return false; }

    const BIGNUM* order = EC_GROUP_get0_order(group);
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) { EC_GROUP_free(group); BN_free(bnHash); return false; }

    BIGNUM* bnReduced = BN_new();
    if (!bnReduced) { BN_CTX_free(ctx); EC_GROUP_free(group); BN_free(bnHash); return false; }

    BN_mod(bnReduced, bnHash, order, ctx);

    memset(ivkOut.ivk.begin(), 0, 32);
    int nBytes = BN_num_bytes(bnReduced);
    if (nBytes > 0 && nBytes <= 32)
        BN_bn2bin(bnReduced, ivkOut.ivk.begin() + (32 - nBytes));

    BN_free(bnReduced);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    BN_free(bnHash);

    return true;
}

bool DeriveShieldedPaymentAddress(const CShieldedIncomingViewingKey& ivk,
                                   const std::vector<unsigned char>& vchDiversifier,
                                   CShieldedPaymentAddress& addrOut)
{
    if (vchDiversifier.size() != SHIELDED_DIVERSIFIER_SIZE)
        return false;

    addrOut.vchDiversifier = vchDiversifier;

    CHashWriter ss(SER_GETHASH, 0);
    ss << (uint8_t)0x13; // pk_d domain
    ss << ivk.ivk;
    for (size_t i = 0; i < vchDiversifier.size(); i++)
        ss << vchDiversifier[i];
    uint256 ivkScalarHash = ss.GetHash();

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) return false;

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) { EC_GROUP_free(group); return false; }

    BIGNUM* ivkScalar = BN_bin2bn(ivkScalarHash.begin(), 32, NULL);
    const BIGNUM* order = EC_GROUP_get0_order(group);
    BN_mod(ivkScalar, ivkScalar, order, ctx);

    if (BN_is_zero(ivkScalar))
    {
        BN_free(ivkScalar);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        return false;
    }

    EC_POINT* pkd = EC_POINT_new(group);
    EC_POINT_mul(group, pkd, ivkScalar, NULL, NULL, ctx);

    if (EC_POINT_is_at_infinity(group, pkd))
    {
        EC_POINT_free(pkd);
        BN_free(ivkScalar);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        return false;
    }

    addrOut.vchPkD.resize(SHIELDED_PKD_SIZE);
    EC_POINT_point2oct(group, pkd, POINT_CONVERSION_COMPRESSED,
                       addrOut.vchPkD.data(), SHIELDED_PKD_SIZE, ctx);

    EC_POINT_free(pkd);
    BN_free(ivkScalar);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    return true;
}

bool GenerateShieldedDiversifier(std::vector<unsigned char>& vchDiversifierOut)
{
    vchDiversifierOut.resize(SHIELDED_DIVERSIFIER_SIZE);
    if (RAND_bytes(vchDiversifierOut.data(), SHIELDED_DIVERSIFIER_SIZE) != 1)
        return false;
    return true;
}


bool EncryptShieldedNote(const CShieldedNote& note,
                         const CShieldedPaymentAddress& addr,
                         std::vector<unsigned char>& vchEphemeralKeyOut,
                         std::vector<unsigned char>& vchEncCiphertextOut)
{
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) return false;

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) { EC_GROUP_free(group); return false; }

    const BIGNUM* order = EC_GROUP_get0_order(group);

    unsigned char eskBytes[32];
    if (RAND_bytes(eskBytes, 32) != 1)
    {
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        return false;
    }

    BIGNUM* esk = BN_bin2bn(eskBytes, 32, NULL);
    BN_mod(esk, esk, order, ctx);
    if (BN_is_zero(esk))
    {
        BN_free(esk);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        OPENSSL_cleanse(eskBytes, 32);
        return false;
    }

    EC_POINT* epk = EC_POINT_new(group);
    EC_POINT_mul(group, epk, esk, NULL, NULL, ctx);

    vchEphemeralKeyOut.resize(SHIELDED_EPHEMERAL_KEY_SIZE);
    EC_POINT_point2oct(group, epk, POINT_CONVERSION_COMPRESSED,
                       vchEphemeralKeyOut.data(), SHIELDED_EPHEMERAL_KEY_SIZE, ctx);
    EC_POINT_free(epk);

    EC_POINT* pkd = EC_POINT_new(group);
    if (EC_POINT_oct2point(group, pkd, addr.vchPkD.data(), addr.vchPkD.size(), ctx) != 1 ||
        EC_POINT_is_on_curve(group, pkd, ctx) != 1)
    {
        EC_POINT_free(pkd);
        BN_free(esk);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        OPENSSL_cleanse(eskBytes, 32);
        return false;
    }

    if (EC_POINT_is_at_infinity(group, pkd))
    {
        EC_POINT_free(pkd);
        BN_free(esk);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        OPENSSL_cleanse(eskBytes, 32);
        return false;
    }

    EC_POINT* sharedPoint = EC_POINT_new(group);
    EC_POINT_mul(group, sharedPoint, NULL, pkd, esk, ctx);

    if (EC_POINT_is_at_infinity(group, sharedPoint))
    {
        EC_POINT_free(sharedPoint);
        EC_POINT_free(pkd);
        BN_free(esk);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        OPENSSL_cleanse(eskBytes, 32);
        return false;
    }

    unsigned char sharedPointBytes[33];
    EC_POINT_point2oct(group, sharedPoint, POINT_CONVERSION_COMPRESSED,
                       sharedPointBytes, 33, ctx);

    EC_POINT_free(sharedPoint);
    EC_POINT_free(pkd);
    BN_free(esk);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    OPENSSL_cleanse(eskBytes, 32);

    CHashWriter ssShared(SER_GETHASH, 0);
    ssShared << (uint8_t)0x21;
    for (int i = 0; i < 33; i++)
        ssShared << sharedPointBytes[i];
    uint256 sharedSecret = ssShared.GetHash();
    OPENSSL_cleanse(sharedPointBytes, 33);

    CDataStream ssNote(SER_NETWORK, 0);
    ssNote << note;
    std::vector<unsigned char> vchPlaintext(ssNote.begin(), ssNote.end());

    std::vector<unsigned char> vchKey(sharedSecret.begin(), sharedSecret.begin() + 32);
    std::vector<unsigned char> vchAad(vchEphemeralKeyOut.begin(), vchEphemeralKeyOut.end());

    if (!ChaCha20Poly1305Encrypt(vchKey, vchPlaintext, vchAad, vchEncCiphertextOut))
    {
        OPENSSL_cleanse(vchKey.data(), vchKey.size());
        return false;
    }

    OPENSSL_cleanse(vchKey.data(), vchKey.size());
    return true;
}

bool DecryptShieldedNote(const std::vector<unsigned char>& vchEncCiphertext,
                         const std::vector<unsigned char>& vchEphemeralKey,
                         const CShieldedIncomingViewingKey& ivk,
                         CShieldedNote& noteOut)
{
    if (vchEncCiphertext.size() < 28) // 12 nonce + 16 tag minimum
        return false;

    // Use default zero diversifier to derive ivkScalar and pkD
    std::vector<unsigned char> vchDefaultDiversifier(SHIELDED_DIVERSIFIER_SIZE, 0);
    CShieldedPaymentAddress defaultAddr;
    if (!DeriveShieldedPaymentAddress(ivk, vchDefaultDiversifier, defaultAddr))
        return false;

    return DecryptShieldedNote(vchEncCiphertext, vchEphemeralKey,
                               defaultAddr.vchPkD, vchDefaultDiversifier,
                               ivk, noteOut);
}

bool DecryptShieldedNote(const std::vector<unsigned char>& vchEncCiphertext,
                         const std::vector<unsigned char>& vchEphemeralKey,
                         const std::vector<unsigned char>& vchPkD,
                         const CShieldedIncomingViewingKey& ivk,
                         CShieldedNote& noteOut)
{
    if (vchEncCiphertext.size() < 28)
        return false;

    // Use default zero diversifier for key derivation
    std::vector<unsigned char> vchDefaultDiversifier(SHIELDED_DIVERSIFIER_SIZE, 0);

    return DecryptShieldedNote(vchEncCiphertext, vchEphemeralKey,
                               vchPkD, vchDefaultDiversifier,
                               ivk, noteOut);
}

bool DecryptShieldedNote(const std::vector<unsigned char>& vchEncCiphertext,
                         const std::vector<unsigned char>& vchEphemeralKey,
                         const std::vector<unsigned char>& vchPkD,
                         const std::vector<unsigned char>& vchDiversifier,
                         const CShieldedIncomingViewingKey& ivk,
                         CShieldedNote& noteOut)
{
    if (vchEncCiphertext.size() < 28)
        return false;

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) return false;

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) { EC_GROUP_free(group); return false; }

    const BIGNUM* order = EC_GROUP_get0_order(group);

    CHashWriter ssScalar(SER_GETHASH, 0);
    ssScalar << (uint8_t)0x13;
    ssScalar << ivk.ivk;
    for (size_t i = 0; i < vchDiversifier.size(); i++)
        ssScalar << vchDiversifier[i];
    uint256 ivkScalarHash = ssScalar.GetHash();

    BIGNUM* ivkScalar = BN_bin2bn(ivkScalarHash.begin(), 32, NULL);
    BN_mod(ivkScalar, ivkScalar, order, ctx);

    if (BN_is_zero(ivkScalar))
    {
        BN_free(ivkScalar);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        return false;
    }

    EC_POINT* epk = EC_POINT_new(group);
    if (EC_POINT_oct2point(group, epk, vchEphemeralKey.data(), vchEphemeralKey.size(), ctx) != 1 ||
        EC_POINT_is_on_curve(group, epk, ctx) != 1)
    {
        EC_POINT_free(epk);
        BN_free(ivkScalar);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        return false;
    }

    if (EC_POINT_is_at_infinity(group, epk))
    {
        EC_POINT_free(epk);
        BN_free(ivkScalar);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        return false;
    }

    EC_POINT* sharedPoint = EC_POINT_new(group);
    EC_POINT_mul(group, sharedPoint, NULL, epk, ivkScalar, ctx);

    if (EC_POINT_is_at_infinity(group, sharedPoint))
    {
        EC_POINT_free(sharedPoint);
        EC_POINT_free(epk);
        BN_free(ivkScalar);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        return false;
    }

    unsigned char sharedPointBytes[33];
    EC_POINT_point2oct(group, sharedPoint, POINT_CONVERSION_COMPRESSED,
                       sharedPointBytes, 33, ctx);

    EC_POINT_free(sharedPoint);
    EC_POINT_free(epk);
    BN_free(ivkScalar);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);

    CHashWriter ssShared(SER_GETHASH, 0);
    ssShared << (uint8_t)0x21;
    for (int i = 0; i < 33; i++)
        ssShared << sharedPointBytes[i];
    uint256 sharedSecret = ssShared.GetHash();
    OPENSSL_cleanse(sharedPointBytes, 33);

    std::vector<unsigned char> vchKey(sharedSecret.begin(), sharedSecret.begin() + 32);
    std::vector<unsigned char> vchAad(vchEphemeralKey.begin(), vchEphemeralKey.end());
    std::vector<unsigned char> vchPlaintext;

    if (!ChaCha20Poly1305Decrypt(vchEncCiphertext, vchKey, vchAad, vchPlaintext))
    {
        OPENSSL_cleanse(vchKey.data(), vchKey.size());
        return false;
    }

    OPENSSL_cleanse(vchKey.data(), vchKey.size());

    try
    {
        CDataStream ssNote((const char*)&vchPlaintext[0],
                           (const char*)&vchPlaintext[0] + vchPlaintext.size(),
                           SER_NETWORK, 0);
        ssNote >> noteOut;
    }
    catch (...)
    {
        return false;
    }

    if (noteOut.addr.vchPkD != vchPkD || noteOut.addr.vchDiversifier != vchDiversifier)
        return false;

    return true;
}

bool EncryptShieldedNoteForSender(const CShieldedNote& note,
                                   const uint256& ovk,
                                   const uint256& cv,
                                   const uint256& cmu,
                                   const std::vector<unsigned char>& vchEphemeralKey,
                                   std::vector<unsigned char>& vchOutCiphertextOut)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << (uint8_t)0x23; // out ciphertext domain
    ss << ovk;
    ss << cv;
    ss << cmu;
    for (size_t i = 0; i < vchEphemeralKey.size(); i++)
        ss << vchEphemeralKey[i];
    uint256 outKey = ss.GetHash();

    CDataStream ssNote(SER_NETWORK, 0);
    ssNote << note.addr;
    ssNote << note.nValue;

    std::vector<unsigned char> vchPlaintext(ssNote.begin(), ssNote.end());

    std::vector<unsigned char> vchKey(outKey.begin(), outKey.begin() + 32);
    std::vector<unsigned char> vchAad(vchEphemeralKey.begin(), vchEphemeralKey.end());

    if (!ChaCha20Poly1305Encrypt(vchKey, vchPlaintext, vchAad, vchOutCiphertextOut))
    {
        OPENSSL_cleanse(vchKey.data(), vchKey.size());
        return false;
    }

    OPENSSL_cleanse(vchKey.data(), vchKey.size());
    return true;
}


bool DeriveStakingKey(const uint256& skSpend, uint256& skStakeOut)
{
    static const char* COLD_STAKE_KEY_DOMAIN = "Innova/ColdStake/Key/v1";
    unsigned int nLen = 32;
    unsigned char result[32];

    if (!HMAC(EVP_sha256(), COLD_STAKE_KEY_DOMAIN, strlen(COLD_STAKE_KEY_DOMAIN),
              skSpend.begin(), 32, result, &nLen))
    {
        return false;
    }

    memcpy(skStakeOut.begin(), result, 32);
    OPENSSL_cleanse(result, 32);
    return true;
}

bool DeriveStakingPubKey(const uint256& skStake, std::vector<unsigned char>& vchPkStakeOut)
{
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) return false;

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* bnSK = BN_new();

    unsigned char be[32];
    const unsigned char* le = skStake.begin();
    for (int i = 0; i < 32; i++)
        be[i] = le[31 - i];
    BN_bin2bn(be, 32, bnSK);

    BIGNUM* bnOrder = BN_new();
    EC_GROUP_get_order(group, bnOrder, ctx);
    BN_mod(bnSK, bnSK, bnOrder, ctx);

    if (BN_is_zero(bnSK))
    {
        BN_free(bnOrder);
        BN_free(bnSK);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        OPENSSL_cleanse(be, 32);
        return false;
    }

    EC_POINT* pk = EC_POINT_new(group);
    EC_POINT_mul(group, pk, bnSK, NULL, NULL, ctx);

    size_t len = EC_POINT_point2oct(group, pk, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    vchPkStakeOut.resize(len);
    EC_POINT_point2oct(group, pk, POINT_CONVERSION_COMPRESSED, vchPkStakeOut.data(), len, ctx);

    EC_POINT_free(pk);
    BN_free(bnOrder);
    BN_clear_free(bnSK);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);

    OPENSSL_cleanse(be, 32);
    return vchPkStakeOut.size() == 33;
}

uint256 CColdStakeDelegation::GetDelegationHash() const
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << (uint8_t)0x30;  // Domain separator for cold stake delegation
    ss << vchPkStake;
    ss << hashOwner;
    ss << nDelegateAmount;
    return ss.GetHash();
}

bool CColdStakeDelegation::VerifyOwnerSignature(const std::vector<unsigned char>& vchOwnerPubKey) const
{
    if (vchOwnerPubKey.empty() || vchOwnerSig.empty())
        return false;

    CPubKey pubkey(vchOwnerPubKey);
    if (!pubkey.IsValid())
        return false;

    CHashWriter ss(SER_GETHASH, 0);
    ss << vchPkStake;
    ss << vchPkOwner;
    ss << vchSkStakeEnc;
    ss << nDelegateAmount;
    ss << hashOwner;
    uint256 hash = ss.GetHash();

    return pubkey.Verify(hash, vchOwnerSig);
}
