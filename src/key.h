// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_KEY_H
#define BITCOIN_KEY_H

#include <stdexcept>
#include <vector>

#include "allocators.h"
#include "serialize.h"
#include "uint256.h"
#include "util.h"

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>

#include <openssl/ec.h> // for EC_KEY definition

#include <stdint.h>

// secp160k1
// const unsigned int PRIVATE_KEY_SIZE = 192;
// const unsigned int PUBLIC_KEY_SIZE  = 41;
// const unsigned int SIGNATURE_SIZE   = 48;
//
// secp192k1
// const unsigned int PRIVATE_KEY_SIZE = 222;
// const unsigned int PUBLIC_KEY_SIZE  = 49;
// const unsigned int SIGNATURE_SIZE   = 57;
//
// secp224k1
// const unsigned int PRIVATE_KEY_SIZE = 250;
// const unsigned int PUBLIC_KEY_SIZE  = 57;
// const unsigned int SIGNATURE_SIZE   = 66;
//
// secp256k1:
// const unsigned int PRIVATE_KEY_SIZE = 279;
// const unsigned int PUBLIC_KEY_SIZE  = 65;
// const unsigned int SIGNATURE_SIZE   = 72;
//
// see www.keylength.com
// script supports up to 75 for single byte push

class key_error : public std::runtime_error
{
public:
    explicit key_error(const std::string& str) : std::runtime_error(str) {}
};

/** A reference to a CKey: the Hash160 of its serialized public key */
class CKeyID : public uint160
{
public:
    CKeyID() : uint160(0) { }
    CKeyID(const uint160 &in) : uint160(in) { }
};

/** A reference to a CScript: the Hash160 of its serialization (see script.h) */
class CScriptID : public uint160
{
public:
    CScriptID() : uint160(0) { }
    CScriptID(const uint160 &in) : uint160(in) { }
};

/** An encapsulated public key. */
class CPubKey {
private:
    //std::vector<unsigned char> vchPubKey;
    //friend class CKey;
	// Just store the serialized data.
    // Its length can very cheaply be computed from the first byte.
    unsigned char vch[65];

	// Compute the length of a pubkey with a given first byte.
    unsigned int static GetLen(unsigned char chHeader) {
        if (chHeader == 2 || chHeader == 3)
            return 33;
        if (chHeader == 4 || chHeader == 6 || chHeader == 7)
            return 65;
        return 0;
    }

    // Set this key data to be invalid
    void Invalidate() {
        vch[0] = 0xFF;
    }

public:
    CPubKey() { Invalidate(); }

    // Initialize a public key using begin/end iterators to byte data.
    template<typename T>
    void Set(const T pbegin, const T pend) {
        int len = pend == pbegin ? 0 : GetLen(pbegin[0]);
        if (len && len == (pend-pbegin))
            memcpy(vch, (unsigned char*)&pbegin[0], len);
        else
            Invalidate();
    }

    // Construct a public key using begin/end iterators to byte data.
    template<typename T>
    CPubKey(const T pbegin, const T pend) {
        Set(pbegin, pend);
    }

    // Construct a public key from a byte vector.
    CPubKey(const std::vector<unsigned char> &vch) {
        Set(vch.begin(), vch.end());
    }

    CPubKey(const unsigned char* p, const int len)
    {
        if (len <= 65)
            memcpy(&vch[0], p, len);
        else
            Invalidate();
    }

	// Simple read-only vector-like interface to the pubkey data.
    unsigned int size() const { return GetLen(vch[0]); }
    const unsigned char *begin() const { return vch; }
    const unsigned char *end() const { return vch+size(); }
    const unsigned char &operator[](unsigned int pos) const { return vch[pos]; }

    // Comparator implementation.
    friend bool operator==(const CPubKey &a, const CPubKey &b) {
        return a.vch[0] == b.vch[0] &&
               memcmp(a.vch, b.vch, a.size()) == 0;
    }
    friend bool operator!=(const CPubKey &a, const CPubKey &b) {
        return !(a == b);
    }
    friend bool operator<(const CPubKey &a, const CPubKey &b) {
        return a.vch[0] < b.vch[0] ||
               (a.vch[0] == b.vch[0] && memcmp(a.vch, b.vch, a.size()) < 0);
    }

    // Implement serialization, as if this was a byte vector.
    unsigned int GetSerializeSize(int nType, int nVersion) const {
        return size() + 1;
    }
    template<typename Stream> void Serialize(Stream &s, int nType, int nVersion) const {
        unsigned int len = size();
        ::WriteCompactSize(s, len);
        s.write((char*)vch, len);
    }
    template<typename Stream> void Unserialize(Stream &s, int nType, int nVersion) {
        unsigned int len = ::ReadCompactSize(s);
        if (len <= 65) {
            s.read((char*)vch, len);
        } else {
            // invalid pubkey, skip available data
            char dummy;
            while (len--)
                s.read(&dummy, 1);
            Invalidate();
        }
    }

    // Get the KeyID of this public key (hash of its serialization)
    CKeyID GetID() const {
        return CKeyID(Hash160(vch, vch+size()));
    }

    // Get the 256-bit hash of this public key.
    uint256 GetHash() const {
        return Hash(vch, vch+size());
    }

    bool SetZero()
    {
        memset(&vch[0], 0, 65);
        return true;
    }

    // Check syntactic correctness.
    //
    // Note that this is consensus critical as CheckSig() calls it!
    bool IsValid() const {
        return size() > 0;
    }

     // fully validate whether this is a valid public key (more expensive than IsValid())
    bool IsFullyValid() const;

    // Check whether the public key corresponding to this private key is (to be) compressed.
    bool IsCompressed() const {
        return size() == 33;
    }
    // Verify a DER signature (~72 bytes).
    // If this public key is not fully valid, the return value will be false.
    bool Verify(const uint256 &hash, const std::vector<unsigned char>& vchSig) const;

    // Verify a compact signature (~65 bytes).
    // See CKey::SignCompact.
    bool VerifyCompact(const uint256 &hash, const std::vector<unsigned char>& vchSig) const;

    #ifdef WIN32
    #else
    /**
     * Check whether a signature is normalized (lower-S).
     */
    static bool CheckLowS(const std::vector<unsigned char>& vchSig);
    #endif

	// Recover a public key from a compact signature.
    bool RecoverCompact(const uint256 &hash, const std::vector<unsigned char>& vchSig);

    // Turn this public key into an uncompressed public key.
    bool Decompress();

    // Derive BIP32 child pubkey.
    bool Derive(CPubKey& pubkeyChild, unsigned char ccChild[32], unsigned int nChild, const unsigned char cc[32]) const;

    // Raw for stealth address
    std::vector<unsigned char> Raw() const {
	std::vector<unsigned char> r;
        r.insert(r.end(), vch, vch+size());
	return r;
    }
};


// secure_allocator is defined in allocators.h
// CPrivKey is a serialized private key, with all parameters included (279 bytes)
typedef std::vector<unsigned char, secure_allocator<unsigned char> > CPrivKey;
// CSecret is a serialization of just the secret parameter (32 bytes)
typedef std::vector<unsigned char, secure_allocator<unsigned char> > CSecret;

/** An encapsulated OpenSSL Elliptic Curve key (public and/or private) */
class CKey
{
protected:
    EC_KEY* pkey;
    bool fSet;
    bool fCompressedPubKey;

private:
    // Whether this private key is valid. We check for correctness when modifying the key
    // data, so fValid should always correspond to the actual state.
    bool fValid;
    // Whether the public key corresponding to this private key is (to be) compressed.
    bool fCompressed;
    // The actual byte data
    unsigned char vch[32];
    // Check whether the 32-byte array pointed to be vch is valid keydata.
	bool static Check(const unsigned char *vch);

public:
    void SetCompressedPubKey();
    void SetUnCompressedPubKey();

    // Construct an invalid private key.
    CKey();

    // Copy constructor. This is necessary because of memlocking.
    CKey(const CKey& b);

    // Destructor (again necessary because of memlocking).
    ~CKey();

    friend bool operator==(const CKey &a, const CKey &b) {
        return a.fCompressed == b.fCompressed && a.size() == b.size() &&
               memcmp(&a.vch[0], &b.vch[0], a.size()) == 0;
    }

	// Initialize using begin and end iterators to byte data.
    template<typename T>
    void Set(const T pbegin, const T pend, bool fCompressedIn) {
        if (pend - pbegin != 32) {
            fValid = false;
            return;
        }
        if (Check(&pbegin[0])) {
            memcpy(vch, (unsigned char*)&pbegin[0], 32);
            fValid = true;
            fCompressed = fCompressedIn;
        } else {
            fValid = false;
        }
    }

	// Simple read-only vector-like interface.
    unsigned int size() const { return (fValid ? 32 : 0); }
    const unsigned char *begin() const { return vch; }
    const unsigned char *end() const { return vch + size(); }

    // Check whether this private key is valid.
    bool IsValid() const;

    // Check whether the public key corresponding to this private key is (to be) compressed.
    bool IsCompressed() const;

    bool SetPubKey(const CPubKey& vchPubKey);

    // Initialize from a CPrivKey (serialized OpenSSL private key data).
    bool SetPrivKey(const CPrivKey& vchPrivKey,bool fCompressed);

    bool SetSecret(const CSecret& vchSecret, bool fCompressed = false);
    CSecret GetSecret(bool &fCompressed) const;

    // Generate a new private key using a cryptographic PRNG.
    void MakeNewKey(bool fCompressedIn);

    // Convert the private key to a CPrivKey (serialized OpenSSL private key data).
    // This is expensive.
    CPrivKey GetPrivKey() const;

    // Compute the public key from a private key.
    // This is expensive.
    CPubKey GetPubKey() const;

    // Create a DER-serialized signature.
    bool Sign(uint256 hash, std::vector<unsigned char>& vchSig)const ;

    // Create a compact signature (65 bytes), which allows reconstructing the used public key.
    // The format is one header byte, followed by two times 32 bytes for the serialized r and s values.
    // The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
    //                  0x1D = second key with even y, 0x1E = second key with odd y,
    //                  add 0x04 for compressed keys.
    bool SignCompact(const uint256 &hash, std::vector<unsigned char>& vchSig) const ;

    // Derive BIP32 child key.
    bool Derive(CKey& keyChild, unsigned char ccChild[32], unsigned int nChild, const unsigned char cc[32]) const;

    // Load private key and check that public key matches.
    bool Load(CPrivKey &privkey, CPubKey &vchPubKey, bool fSkipCheck);

    // Check whether an element of a signature (r or s) is valid.
    static bool CheckSignatureElement(const unsigned char *vch, int len, bool half);

    // Ensure that signature is DER-encoded
    static bool ReserealizeSignature(std::vector<unsigned char>& vchSig);

    // Why does this exist?
    EC_KEY* GetECKey();
};

// RAII Wrapper around OpenSSL's EC_KEY
class CECKey {
private:
    EC_KEY *pkey;

public:
    CECKey() {
        pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
        assert(pkey != NULL);
    }

    ~CECKey() {
        EC_KEY_free(pkey);
    }

    EC_KEY* GetECKey() {return pkey;};

    void GetSecretBytes(unsigned char vch[32]) const;

    void SetSecretBytes(const unsigned char vch[32]);

    void GetPrivKey(CPrivKey &privkey, bool fCompressed);

    bool SetPrivKey(const CPrivKey &privkey, bool fSkipCheck=false);

    void GetPubKey(CPubKey &pubkey, bool fCompressed);

    bool SetPubKey(const CPubKey &pubkey);

    bool Sign(const uint256 &hash, std::vector<unsigned char>& vchSig);

    bool Verify(const uint256 &hash, const std::vector<unsigned char>& vchSig);

    bool SignCompact(const uint256 &hash, unsigned char *p64, int &rec);

    // reconstruct public key from a compact signature
    // This is only slightly more CPU intensive than just verifying it.
    // If this function succeeds, the recovered public key is guaranteed to be valid
    // (the signature is a valid signature of the given data for that key)
    bool Recover(const uint256 &hash, const unsigned char *p64, int rec);

    static bool TweakSecret(unsigned char vchSecretOut[32], const unsigned char vchSecretIn[32], const unsigned char vchTweak[32]);

    bool TweakPublic(const unsigned char vchTweak[32]);
};

struct CExtPubKey {
    unsigned char nDepth;
    unsigned char vchFingerprint[4];
    unsigned int nChild;
    unsigned char vchChainCode[32];
    CPubKey pubkey;

    friend bool operator==(const CExtPubKey &a, const CExtPubKey &b) {
        return a.nDepth == b.nDepth && memcmp(&a.vchFingerprint[0], &b.vchFingerprint[0], 4) == 0 && a.nChild == b.nChild &&
               memcmp(&a.vchChainCode[0], &b.vchChainCode[0], 32) == 0 && a.pubkey == b.pubkey;
    }

    void Encode(unsigned char code[74]) const;
    void Decode(const unsigned char code[74]);
    bool Derive(CExtPubKey &out, unsigned int nChild) const;
};

struct CExtKey {
    unsigned char nDepth;
    unsigned char vchFingerprint[4];
    unsigned int nChild;
    unsigned char vchChainCode[32];
    CKey key;

    friend bool operator==(const CExtKey &a, const CExtKey &b) {
        return a.nDepth == b.nDepth && memcmp(&a.vchFingerprint[0], &b.vchFingerprint[0], 4) == 0 && a.nChild == b.nChild &&
               memcmp(&a.vchChainCode[0], &b.vchChainCode[0], 32) == 0 && a.key == b.key;
    }

    void Encode(unsigned char code[74]) const;
    void Decode(const unsigned char code[74]);
    bool Derive(CExtKey &out, unsigned int nChild) const;
    CExtPubKey Neuter() const;
    void SetMaster(const unsigned char *seed, unsigned int nSeedLen);
};

/** Check that required EC support is available at runtime */
bool ECC_InitSanityCheck(void);

bool TweakSecret(unsigned char vchSecretOut[32], const unsigned char vchSecretIn[32], const unsigned char vchTweak[32]);

#ifdef WIN32
#else
/** Users of this module must hold an ECCVerifyHandle. The constructor and
 *  destructor of these are not allowed to run in parallel, though. */
class ECCVerifyHandle
{
    static int refcount;

public:
    ECCVerifyHandle();
    ~ECCVerifyHandle();
};

struct ECCryptoClosure
{
    ECCVerifyHandle handle;
};

void static inline WriteLE32(unsigned char* ptr, uint32_t x)
{
    *((uint32_t*)ptr) = htole32(x);
}

/** Initialize the elliptic curve support. May not be called twice without calling ECC_Stop first. */
void ECC_Start(void);

/** Deinitialize the elliptic curve support. No-op if ECC_Start wasn't called first. */
void ECC_Stop(void);


// ECCryptoClosure instance_of_eccryptoclosure;
#endif

#endif
