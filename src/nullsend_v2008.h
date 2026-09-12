// The v2008 mix round announcement. Kept apart from the legacy structures in nullsend.h,
// which serialize on a live wire until Boundary A.

#ifndef INNOVA_NULLSEND_V2008_H
#define INNOVA_NULLSEND_V2008_H

#include <string>
#include <vector>

#include "key.h"
#include "serialize.h"
#include "uint256.h"
#include "util.h"

/** How long an announcement stays joinable. */
static const int64_t MIX_ROUND_ANNOUNCE_TIMEOUT = 300;
/** Bound on the endpoint string, so a decoder cannot be made to hold an
 *  unbounded name. A v3 onion address is 62 characters. */
static const size_t MIX_ROUND_ENDPOINT_MAX = 255;

/** The commitment a round announcement carries to the coordinator's blind-signature key.
 *  Blind signatures do not bind the key to the round, so a participant refuses any key
 *  that does not open this commitment (prevents per-participant keys). */
uint256 MixRoundKeyCommitment(const std::vector<unsigned char>& vchRSA_N,
                              const std::vector<unsigned char>& vchRSA_E);

class CMixRoundAnnouncement
{
public:
    static const int CURRENT_VERSION = 1;

    int nVersion;
    uint256 hashRound;
    uint256 hashRoundKey;
    std::string strEndpoint;
    int nPort;
    int nParticipants;
    int64_t nTime;
    CPubKey pubkeyCoordinator;
    std::vector<unsigned char> vchSig;

    CMixRoundAnnouncement()
    {
        SetNull();
    }

    void SetNull()
    {
        nVersion = CURRENT_VERSION;
        hashRound = 0;
        hashRoundKey = 0;
        strEndpoint.clear();
        nPort = 0;
        nParticipants = 0;
        nTime = 0;
        pubkeyCoordinator = CPubKey();
        vchSig.clear();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nVersion);
        READWRITE(hashRound);
        READWRITE(hashRoundKey);
        READWRITE(strEndpoint);
        READWRITE(nPort);
        READWRITE(nParticipants);
        READWRITE(nTime);
        READWRITE(pubkeyCoordinator);
        READWRITE(vchSig);
    )

    /** Everything the coordinator commits to, which is every field but the
     *  signature. The key commitment is inside it: an announcement whose
     *  commitment could be edited in flight would commit to nothing. */
    uint256 GetSignatureHash() const;

    bool Sign(const CKey& key);
    bool CheckSignature() const;

    bool IsExpired(int64_t nNow) const { return (nNow - nTime) > MIX_ROUND_ANNOUNCE_TIMEOUT; }

    /** Shape only: nothing here reads the chain. */
    bool IsValidBasic(std::string* pstrError = NULL) const;

    /** Whether a key handed out later is the one this announcement named. The
     *  participant calls it before blinding anything. */
    bool KeyOpensCommitment(const std::vector<unsigned char>& vchRSA_N,
                            const std::vector<unsigned char>& vchRSA_E) const;
};

// Framing: typed, length-bounded frames only. No version handshake, address or clock, since
// the P2P handshake would leak the local address and time into the Tor circuit.

static const unsigned char MIX_FRAME_MAGIC[4] = { 0xA5, 0x1D, 0x5E, 0x01 };
static const size_t MIX_FRAME_HEADER_BYTES = 4 + 1 + 4;
/** A frame never has to be larger than the largest thing a phase sends, and a
 *  decoder that would allocate on a length it has not received is a free
 *  denial of service. */
static const uint32_t MIX_FRAME_MAX_PAYLOAD = 1 << 20;

enum MixFrameType
{
    MIX_FRAME_NONE            = 0,
    MIX_FRAME_JOIN            = 1,   // register an input, and the session key with it
    MIX_FRAME_KEY             = 2,   // the coordinator's blind-signature key
    MIX_FRAME_BLIND_REQUEST   = 3,
    MIX_FRAME_BLIND_SIGNATURE = 4,
    MIX_FRAME_OUTPUT          = 5,
    MIX_FRAME_TRANSACTION     = 6,
    MIX_FRAME_ABORT           = 7,
    MIX_FRAME_TYPE_MAX        = 7,
};

enum MixFrameDecode
{
    MIX_DECODE_OK = 0,
    MIX_DECODE_INCOMPLETE,   // not an error: the caller reads more and retries
    MIX_DECODE_INVALID,
};

/** Serialize one frame. Returns false for a type or size that has no encoding. */
bool BuildMixFrame(MixFrameType nType, const std::vector<unsigned char>& vchPayload,
                   std::vector<unsigned char>& vchOut);

/** Read one frame from the front of a buffer. nConsumedOut is set only on MIX_DECODE_OK.
 *  A length past the bound is INVALID, not INCOMPLETE. */
MixFrameDecode ReadMixFrame(const std::vector<unsigned char>& vchBuffer,
                            MixFrameType& nTypeOut,
                            std::vector<unsigned char>& vchPayloadOut,
                            size_t& nConsumedOut);

// Per-participant authentication: a participant registers a session key with its input and
// signs every later message, so each phase can use its own circuit. secp256k1 because no
// ed25519 signer is callable from C++ here.

/** What a participant signs: the round, the frame type and the payload. The round
 *  and type are inside it so a message cannot be replayed into another round or
 *  presented as another phase. */
uint256 MixSessionSigHash(const uint256& hashRound, MixFrameType nType,
                          const std::vector<unsigned char>& vchPayload);

bool SignMixSessionFrame(const CKey& key, const uint256& hashRound, MixFrameType nType,
                         const std::vector<unsigned char>& vchPayload,
                         std::vector<unsigned char>& vchSigOut);

bool CheckMixSessionFrame(const CPubKey& pubkey, const uint256& hashRound, MixFrameType nType,
                          const std::vector<unsigned char>& vchPayload,
                          const std::vector<unsigned char>& vchSig);

#endif // INNOVA_NULLSEND_V2008_H
