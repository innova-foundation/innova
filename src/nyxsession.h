// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef INNOVA_NYXSESSION_H
#define INNOVA_NYXSESSION_H

#include "nyxkeyring.h"

#include <map>
#include <string>
#include <vector>

// Nyx v2 1:1 sessions: PQXDH (X3DH in classical mode) handshake 0x10 and a
// header-encrypted Double Ratchet 0x11. Pure functions; node state lives in nyxidentity.

static const uint8_t NYX_BODY_HANDSHAKE = 0x10;
static const uint8_t NYX_BODY_RATCHET = 0x11;
static const uint32_t NYX_OPK_NONE = 0xFFFFFFFFu;
static const uint32_t NYX_MAX_SKIP = 1000;           // per receiving chain
static const size_t NYX_MAX_SKIPPED = 2000;          // per session
static const int64_t NYX_SKIPPED_TTL = 60 * 60 * 24 * 7;
static const int64_t NYX_HS_WINDOW = 60 * 60 * 48 + 60;
static const int64_t NYX_HS_FUTURE = 60;
static const int64_t NYX_HS_RETRY = 60 * 60;          // unacked initiator starts a new handshake
static const uint32_t NYX_RESYNC_SENDS = 32;         // sends with no reply before a new handshake
static const size_t NYX_SEEN_MAX = 4096;
static const size_t NYX_HELD_MAX = 32;
static const size_t NYX_HELD_PER_SENDER = 4;
static const size_t NYX_HELD_UNPINNED_MAX = 8;
static const size_t NYX_SESSION_STATES = 2;          // current + one archived
static const size_t NYX_HDR_LEN = 40;                // DHs 32 || PN 4 || N 4
static const size_t NYX_ENC_HDR_LEN = NYX_HDR_LEN + 16;
static const size_t NYX_TAIL_MIN = 12 + NYX_ENC_HDR_LEN + 12 + 16;
static const size_t NYX_HS_FIXED_CLASSICAL = 230 + 8 + 65;
static const size_t NYX_HS_FIXED_PQ = 230 + 1088 + 8 + 3309;
static const size_t NYX_ENV_LEN = 70;                // ctype 1, logicalId 16, convAddr 20, groupId 32, flags 1

extern const char NYX_TAG_HS[];

struct NyxHandshake
{
    uint8_t mode;
    uint8_t addrA[20];
    uint8_t addrB[20];
    uint8_t devB[16];
    uint8_t devA[16];
    uint8_t certHashA[32];
    uint8_t certHashB[32];
    uint8_t ikA[32];
    uint8_t ekA[32];
    uint32_t epochA, seqA, epochB, seqB;
    uint32_t spkId, opkId, kemId;
    NyxBytes ct;                // PQ only
    uint64_t ts;
    NyxBytes sig;
    NyxBytes tail;              // embedded ratchet message

    NyxHandshake();
    NyxBytes Fields() const;    // everything before sig
    NyxBytes Fixed() const;     // Fields() || sig
};

struct NyxRatchetMsg
{
    uint8_t devB[16];
    uint8_t devA[16];
    NyxBytes tail;
};

/** 0 when the body parses exactly; >0 names the failed check. */
int NyxParseHandshake(const uint8_t* p, size_t n, NyxHandshake& out);
int NyxParseRatchetMsg(const uint8_t* p, size_t n, NyxRatchetMsg& out);

/** SHA256 transcript binding both addresses, devices, identity keys, cert hashes and keyring (epoch, seq). */
void NyxTranscript(const NyxHandshake& hs, const uint8_t ikB[32], uint8_t out[32]);
/** Handshake replay key: SHA256(EK_A || devA). */
void NyxHsId(const NyxHandshake& hs, uint8_t out[32]);

/** PQXDH / X3DH combiner: HKDF(0^32, 0xFF^32 || dh1..dh3 [|| dh4] [|| ss], info) -> SK || HKa || NHKb. */
bool NyxPqxdhKdf(const uint8_t* dh, size_t nDh, const uint8_t* ss, uint8_t out[96]);
/** Root and chain KDFs of the ratchet (exposed for known-answer tests). */
bool NyxKdfRk(const uint8_t rk[32], const uint8_t dhOut[32], uint8_t out[96]);
bool NyxKdfCk(const uint8_t ck[32], uint8_t ckNext[32], uint8_t mk[32]);

struct NyxSkippedKey
{
    uint8_t hk[32];
    uint32_t n;
    uint8_t mk[32];
    int64_t ts;
};

struct NyxRatchet
{
    uint8_t mode;
    uint8_t T[32];
    uint8_t hsId[32];
    uint8_t remoteAddr[20];
    uint8_t remoteDev[16];
    uint8_t localDev[16];
    uint8_t localCert[32], remoteCert[32];
    uint32_t localEpoch, remoteEpoch;
    bool fInitiator;
    bool fAcked;                // initiator: a reply decrypted, stop re-sending the handshake
    bool fOpk;
    NyxBytes hsFixed;           // initiator, until acked
    int64_t created;
    int64_t lastUsed;
    uint8_t RK[32], CKs[32], CKr[32];
    bool fCKs, fCKr;
    uint8_t DHsSk[32], DHsPk[32], DHr[32];
    bool fDHr;
    uint8_t HKs[32], HKr[32], NHKs[32], NHKr[32];
    bool fHKs, fHKr;
    uint32_t Ns, Nr, PN;
    std::vector<NyxSkippedKey> skipped;

    NyxRatchet();
    NyxRatchet(const NyxRatchet& o);
    NyxRatchet& operator=(const NyxRatchet& o);
    ~NyxRatchet();
    void Wipe();
    void Serialize(std::string& s) const;
    bool Deserialize(const std::string& s, size_t& off);
};

enum NyxDrResult
{
    NYX_DR_OK = 0,
    NYX_DR_NO_HEADER = 1,       // no header key opens it: not this session, or an evicted/replayed message
    NYX_DR_REPLAY = 2,          // header opens but its key was already used
    NYX_DR_SKIP_LIMIT = 3,
    NYX_DR_AUTH = 4,            // body failed authentication
    NYX_DR_MALFORMED = 5,
};

/** tail = hnonce 12 || AEAD_HKs(header) 56 || mnonce 12 || AEAD_MK(pt, AD = T || encHeader || mnonce). */
bool NyxRatchetEncrypt(NyxRatchet& s, const NyxBytes& pt, int64_t now, NyxBytes& tail);
/** State changes only on NYX_DR_OK. */
int NyxRatchetDecrypt(NyxRatchet& s, const NyxBytes& tail, int64_t now, NyxBytes& pt);
/** Drops skipped keys older than NYX_SKIPPED_TTL. */
void NyxRatchetExpire(NyxRatchet& s, int64_t now);

/** Device, cert and keyring epoch of both ends a state must carry to be used. */
struct NyxSessBind
{
    uint8_t localDev[16], localCert[32];
    uint32_t localEpoch;
    uint8_t remoteAddr[20], remoteDev[16], remoteCert[32];
    uint32_t remoteEpoch;
    bool Matches(const NyxRatchet& r) const;
};

struct NyxSession
{
    std::vector<NyxRatchet> states;     // [0] current
    std::string Serialize() const;
    bool Deserialize(const std::string& s);
    /** Tries the states matching bind (all when NULL); idx is the one that opened it. Archived states are
     *  receive-only and expire NYX_SKIPPED_TTL after the current one was made; one replaces the current
     *  only as the tie-break of a simultaneous initiation (opposite directions, made within
     *  NYX_HS_RETRY, initiator side unacked, smaller hsId). */
    int Decrypt(const NyxBytes& tail, int64_t now, NyxBytes& pt, const NyxSessBind* bind = NULL,
                size_t* idx = NULL);
    /** New state becomes current; the oldest beyond NYX_SESSION_STATES is wiped. */
    void Push(const NyxRatchet& r);
    int FindHs(const uint8_t hsId[32]) const;
    /** True when the next send must start a new handshake. */
    bool NeedsHandshake(const uint8_t localCert[32], uint32_t localEpoch, const uint8_t remoteCert[32],
                        uint32_t remoteEpoch, int64_t now) const;
};

/** Seen handshake ids -> handshake ts. Drops entries past the acceptance window; false when still full. */
bool NyxSeenPrune(std::map<std::string, int64_t>& seen, int64_t now);

struct NyxHeldTag
{
    std::string sender;
    bool fUnpinned;
};
/** Index to evict before queueing t, q.size() when none is needed. */
size_t NyxHeldEvict(const std::vector<NyxHeldTag>& q, const NyxHeldTag& t);

struct NyxLocalSide
{
    const NyxOwnDevice* dev;
    uint8_t certHash[32];
    uint32_t epoch, seq;
    const CKey* addrKey;        // classical handshake signature
};

struct NyxPeerSide
{
    const NyxCert* cert;
    uint8_t certHash[32];
    uint32_t epoch, seq;
};

/** Initiator: checks the bundle against the pinned cert, derives the session and the signed handshake. */
bool NyxHsInitiate(const NyxLocalSide& me, const NyxPeerSide& peer, const NyxBundle& b, int64_t now,
                   NyxRatchet& out, std::string& sError);
/** Responder: every check of the handshake against this device and the pinned initiator cert.
 *  The used OPK is reported in opkUsed and must be erased by the caller once the first message opens. */
bool NyxHsRespond(const NyxLocalSide& me, const NyxPeerSide& peer, const NyxHandshake& hs, int64_t now,
                  NyxRatchet& out, uint32_t& opkUsed, std::string& sError);

/** Wire body for the next message of r: 0x10 while the initiator is unacked, else 0x11. */
bool NyxSessionSeal(NyxRatchet& r, const NyxBytes& pt, int64_t now, NyxBytes& body);

/** Plaintext envelope carried inside every ratchet message. */
struct NyxEnvelope
{
    uint8_t ctype;
    uint8_t logicalId[16];
    uint8_t convAddr[20];
    uint8_t groupId[32];
    uint8_t flags;
    std::string text;
    NyxEnvelope();
    NyxBytes Serialize() const;
    bool Parse(const NyxBytes& v);
};

#endif // INNOVA_NYXSESSION_H
