// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef INNOVA_NYXCERT_H
#define INNOVA_NYXCERT_H

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

// Wire formats of the Nyx v2 identity objects (device cert 0x03, keyring 0x04, bundle 0x02).
// Parsing only; signatures are checked in nyxkeyring.

static const uint8_t NYX_MODE_CLASSICAL = 0;
static const uint8_t NYX_MODE_PQ = 1;
static const unsigned int NYX_KR_MAX_LIVE = 16;
static const unsigned int NYX_KR_MAX_REVOKED = 16;
static const unsigned int NYX_BUNDLE_MAX_OPK = 8;
static const unsigned int NYX_X25519_LEN = 32;
static const unsigned int NYX_MLDSA_SEED_LEN = 32;
static const unsigned int NYX_MLKEM_SEED_LEN = 64;
static const unsigned int NYX_ID_LEN = 16;

extern const char NYX_TAG_CERT[];
extern const char NYX_TAG_KEYRING[];
extern const char NYX_TAG_BUNDLE[];

typedef std::vector<uint8_t> NyxBytes;

struct NyxCert
{
    uint8_t mode;
    uint8_t addrHash[20];
    uint8_t deviceId[16];
    uint64_t created;
    uint64_t expiry;
    uint32_t keyringSeq;
    uint8_t ik[32];
    NyxBytes dsaPk;             // PQ only
    uint8_t addrSig[65];
    uint8_t signerId[16];       // zero: signed by the address key only
    NyxBytes signerSig;         // PQ with a nonzero signer only

    NyxCert();
    bool HasSigner() const;
    /** Bytes the address signature covers (tag excluded). */
    NyxBytes Fields() const;
    NyxBytes Signed() const;     // Fields() + signerId: what addrSig covers
    NyxBytes Serialize() const;
};

struct NyxKeyringEntry
{
    uint8_t deviceId[16];
    uint8_t certHash[32];
};

struct NyxKeyring
{
    uint32_t epoch;
    uint32_t seq;
    uint8_t addrHash[20];
    uint8_t prevHash[32];
    uint64_t ts;
    uint8_t mode;
    std::vector<NyxKeyringEntry> live;
    std::vector<std::string> revoked;   // 16-byte device ids
    uint8_t addrSig[65];
    uint8_t signerId[16];
    NyxBytes signerSig;                 // PQ with seq > 1

    NyxKeyring();
    bool IsLive(const uint8_t id[16]) const;
    const NyxKeyringEntry* Find(const uint8_t id[16]) const;
    NyxBytes Fields() const;
    NyxBytes Signed() const;
    NyxBytes Serialize() const;
};

struct NyxBundle
{
    uint8_t addrHash[20];
    uint8_t deviceId[16];
    uint64_t ts;
    uint32_t seq;
    uint32_t spkId;
    uint8_t spk[32];
    bool fPq;
    uint32_t kemId;
    NyxBytes ek;                        // PQ only
    std::vector<std::pair<uint32_t, NyxBytes> > opks;
    NyxBytes sig;                       // ML-DSA (PQ) or address ECDSA (classical)

    NyxBundle();
    NyxBytes Fields() const;
    NyxBytes Serialize() const;
};

/** 0 when the body parses exactly; >0 names the failed check. */
int NyxParseCert(const uint8_t* p, size_t n, NyxCert& out);
int NyxParseKeyring(const uint8_t* p, size_t n, NyxKeyring& out);
int NyxParseBundle(const uint8_t* p, size_t n, NyxBundle& out);

/** tag || fields, the message every signature in these objects is computed over. */
NyxBytes NyxTagged(const char* tag, const NyxBytes& fields);
void NyxHash(const NyxBytes& v, uint8_t out[32]);
bool NyxIsZero(const uint8_t* p, size_t n);
std::string NyxId(const uint8_t id[16]);

#endif // INNOVA_NYXCERT_H
