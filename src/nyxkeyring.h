// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef INNOVA_NYXKEYRING_H
#define INNOVA_NYXKEYRING_H

#include "nyxcert.h"

#include <map>
#include <set>
#include <string>
#include <vector>

class CKey;
class CPubKey;

static const int64_t NYX_FIRST_PIN_MAX_AGE = 60 * 60 * 60;
static const uint32_t NYX_KR_MAX_SEQ_JUMP = 16;
static const int64_t NYX_CERT_LIFE = 60 * 60 * 24 * 90;

/** Address signature over SHA256(tag || fields): compact recoverable ECDSA that must recover to addrHash. */
bool NyxAddrSign(const CKey& key, const char* tag, const NyxBytes& fields, uint8_t sig[65]);
bool NyxAddrVerify(const uint8_t addrHash[20], const char* tag, const NyxBytes& fields, const uint8_t sig[65]);
bool NyxDsaSign(const uint8_t seed[32], const NyxBytes& msg, NyxBytes& sig);
bool NyxDsaVerify(const NyxBytes& pk, const NyxBytes& msg, const NyxBytes& sig);

/** Message an ML-DSA co-signature covers: tag || fields || addrSig. */
NyxBytes NyxCertSignerMsg(const NyxCert& c);
NyxBytes NyxKeyringSignerMsg(const NyxKeyring& k);

bool NyxCertAddrValid(const NyxCert& c);
bool NyxCertSignerValid(const NyxCert& c, const NyxBytes& signerPk);
bool NyxKeyringAddrValid(const NyxKeyring& k);
bool NyxKeyringSignerValid(const NyxKeyring& k, const NyxBytes& signerPk);
bool NyxBundleValid(const NyxBundle& b, const NyxCert& cert);

// ---- Relay continuity (public object store) ----

struct NyxRelayHeld
{
    std::vector<NyxKeyring> keyrings;
    std::vector<NyxBytes> keyringHashes;       // SHA256 of each keyring body
    std::map<std::string, NyxCert> certs;      // verified certs by deviceId
    std::map<std::string, NyxBytes> certHashes;
    std::set<std::string> revoked;             // extra revocations; chain revocations are derived
};

/** held.revoked plus revocations shared by every highest-epoch branch tip. */
std::set<std::string> NyxRelayRevoked(const NyxRelayHeld& held);
/** NYX_PO_OK, NYX_PO_UNVERIFIED (store, do not relay) or NYX_PO_BAD for one public body against what a relay holds. */
int NyxRelayVerify(const NyxRelayHeld& held, const NyxBytes& body);

// ---- Contact pin ----

struct NyxPinDevice
{
    NyxCert cert;
    NyxBytes body;
    uint8_t certHash[32];
};

typedef std::map<std::string, NyxPinDevice> NyxDeviceMap;

enum NyxPinFlag
{
    NYX_PIN_UPDATED      = 1 << 0,
    NYX_PIN_FROZEN       = 1 << 1,   // two valid keyrings at one (epoch, seq)
    NYX_PIN_RESET        = 1 << 2,   // epoch+1 seen, waiting for accept
    NYX_PIN_DOWNGRADE    = 1 << 3,   // classical after PQ refused
    NYX_PIN_ROLLBACK     = 1 << 4,   // older keyring ignored
    NYX_PIN_SEQ_JUMP     = 1 << 5,   // more than 16 ahead, refused
    NYX_PIN_FORGERY      = 1 << 6,   // address-key-only device after a PQ pin, or a bad signer
    NYX_PIN_STALE        = 1 << 7,   // first pin older than 60 h
    NYX_PIN_REVOKED      = 1 << 8,   // a revoked device came back
    NYX_PIN_INCOMPLETE   = 1 << 9,   // certs or chain links missing
    NYX_PIN_UNFROZEN     = 1 << 10,
    NYX_PIN_PINNED       = 1 << 11,  // first pin made
};

struct NyxPin
{
    uint8_t addrHash[20];
    bool fPinned;
    bool fPqSeen;
    NyxBytes krBody;
    NyxKeyring kr;
    uint8_t krHash[32];
    NyxDeviceMap devices;
    NyxDeviceMap prevDevices;
    std::set<std::string> revoked;
    std::set<std::string> prevRevoked;
    bool fFrozen;
    NyxBytes conflictBody;
    NyxDeviceMap conflictDevices;
    bool fResetPending;
    NyxBytes resetBody;
    std::vector<NyxBytes> resetCerts;

    NyxPin();
    std::string Serialize() const;
    bool Deserialize(const std::string& s);
};

struct NyxPinInput
{
    std::vector<NyxBytes> keyrings;
    std::vector<NyxBytes> certs;
};

/** Apply every keyring and cert the network holds for pin.addrHash; returns NyxPinFlag bits. */
int NyxPinApply(NyxPin& pin, const NyxPinInput& in, int64_t now);
/** One-click accept of a pending identity reset; a classical reset after PQ also needs fAllowDowngrade. */
bool NyxPinAcceptReset(NyxPin& pin, bool fAllowDowngrade, int64_t now, std::string& sError);
/** Devices whose certs are unexpired at now. */
std::vector<std::string> NyxPinUsable(const NyxPin& pin, int64_t now);
bool NyxPinCanSend(const NyxPin& pin);
std::string NyxPinFlagsText(int flags);

/** 60-digit safety number over the address, epoch and every live device key. */
std::string NyxSafetyNumber(const uint8_t addrHash[20], uint32_t epoch, const NyxDeviceMap& devices);

// ---- Own device ----

static const unsigned int NYX_OPK_TARGET = 8;
static const unsigned int NYX_OPK_LOW = 3;
static const uint32_t NYX_OPK_MINT_PER_DAY = 8;
static const int64_t NYX_SPK_LIFE = 60 * 60 * 24 * 7;
static const int64_t NYX_SPK_GRACE = 60 * 60 * 49;   // previous SPK/KEM kept for in-flight handshakes

struct NyxOpk
{
    uint32_t id;
    uint8_t sk[32];
    uint8_t pk[32];
};

struct NyxOwnDevice
{
    uint8_t addrHash[20];
    uint8_t mode;
    uint8_t deviceId[16];
    uint8_t installNonce[16];
    uint8_t hostFp[32];
    uint8_t ikSk[32];
    uint8_t ik[32];
    uint8_t dsaSeed[32];
    NyxBytes dsaPk;
    uint8_t kemSeed[64];
    NyxBytes ek;
    uint8_t spkSk[32];
    uint8_t spk[32];
    uint32_t spkId;
    uint32_t bundleSeq;
    int64_t spkCreated;
    uint8_t prevSpkSk[32];
    uint8_t prevKemSeed[64];
    uint32_t prevSpkId;
    int64_t prevSpkUntil;
    std::vector<NyxOpk> opks;
    uint32_t opkNext;
    int64_t opkDay;
    uint32_t opkMinted;
    NyxBytes certBody;
    NyxBytes lastBundle;
    NyxBytes keyringBody;
    bool fCloneAlarm;
    std::string cloneReason;

    NyxOwnDevice();
    ~NyxOwnDevice();
    void Wipe();
    std::string Serialize() const;
    bool Deserialize(const std::string& s);
};

/** Fresh random device keys; nothing is derived from wallet material. */
bool NyxDeviceCreate(NyxOwnDevice& dev, const uint8_t addrHash[20], uint8_t mode, const uint8_t hostFp[32]);

/** Cert for dev signed by the address key and, when signer is set, co-signed by that device's ML-DSA key. */
bool NyxBuildCert(const NyxOwnDevice& dev, const CKey& addrKey, int64_t created, uint32_t keyringSeq,
                  const NyxOwnDevice* signer, NyxCert& out);
/** Cert for a device known only by its public keys (pairing approval). */
bool NyxBuildCertFor(uint8_t mode, const uint8_t addrHash[20], const uint8_t deviceId[16], const uint8_t ik[32],
                     const NyxBytes& dsaPk, const CKey& addrKey, int64_t created, uint32_t keyringSeq,
                     const NyxOwnDevice* signer, NyxCert& out);
bool NyxBuildKeyring(NyxKeyring& kr, const CKey& addrKey, const NyxOwnDevice* signer);
bool NyxBuildBundle(NyxOwnDevice& dev, const CKey& addrKey, int64_t ts, NyxBundle& out);
/** Mints OPKs up to NYX_OPK_TARGET once fewer than NYX_OPK_LOW remain, at most NYX_OPK_MINT_PER_DAY per day. */
bool NyxDeviceTopUpOpks(NyxOwnDevice& dev, int64_t now);
/** New SPK and ML-KEM prekey after NYX_SPK_LIFE; the previous pair stays for NYX_SPK_GRACE. */
bool NyxDeviceRotateSpk(NyxOwnDevice& dev, int64_t now, bool fForce = false);
/** Secret prekeys by id: current or unexpired previous SPK (and its ML-KEM seed), or an OPK. */
/** Wipes the previous SPK and ML-KEM seed once their grace period ends; true when it did. */
bool NyxDeviceExpirePrevSpk(NyxOwnDevice& dev, int64_t now);
bool NyxDeviceSpk(const NyxOwnDevice& dev, uint32_t spkId, int64_t now, uint8_t sk[32], const uint8_t** pKemSeed);
const NyxOpk* NyxDeviceOpk(const NyxOwnDevice& dev, uint32_t id);
void NyxDeviceEraseOpk(NyxOwnDevice& dev, uint32_t id);
bool NyxAddrRecover(const char* tag, const NyxBytes& fields, const uint8_t sig[65], CPubKey& out);

/** Non-empty reason when the device looks cloned: host fingerprint changed, or a bundle for its id it did not publish. */
std::string NyxCloneCheck(const NyxOwnDevice& dev, const uint8_t hostFpNow[32], const NyxBytes* pSeenBundle);

// ---- Storage key ----

/** nonce12 || ChaCha20-Poly1305(sk, nonce, plain, AD = dbkey); nonce random per record. */
bool NyxStoreSeal(const uint8_t sk[32], const std::string& dbkey, const std::string& plain, std::string& out);
bool NyxStoreOpen(const uint8_t sk[32], const std::string& dbkey, const std::string& sealed, std::string& out);

#endif // INNOVA_NYXKEYRING_H
